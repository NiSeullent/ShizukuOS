/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 "stage 0" PE32+ loader: maps AMD64 images into a process, applies base relocations, resolves imports
 * (including forwarders and API-set contracts), validates delay-load directories, initialises the load configuration
 * (security cookie, Control Flow Guard pointers), assigns TLS indices and publishes a Windows-shaped loader database
 * (PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY) for the user-mode ntdll to take over. It does not depend on any user-mode DLL.
 *
 * Image parsing/validation lives in shizukudos/win64/pe_parse.c (shared with host fuzz tests and the load simulator).
 * API-set contracts resolve through the generated table of kernel64/apiset.c (source: apiset_contracts.txt).
 * Anything the loader cannot verify is rejected with an NTSTATUS; nothing is silently stubbed.
 *
 * Mapping has two strategies, chosen by where the file lives:
 *   RAM-backed files (C:\, the initrd): eager. Headers and the file-backed part of every section are copied into
 *     fresh pages and relocated at load time (pe_apply_relocs); the rest of a section (uninitialised data,
 *     VirtualSize > SizeOfRawData) is committed demand-zero, so a 1 GiB .bss costs only the pages it touches.
 *   Disk-backed files (D:\ ...): lazy. The parser reads the file through a kernel file view (kwin.c: only the header
 *     and directory pages it touches are read), the image's sections become committed VK_IMAGE descriptors tied to an
 *     image_map_t, and ldr_image_fault() produces each page on its first touch: its bytes are read from the file into a
 *     private page, the base relocations of that page (and the tail of a fixup straddling in from the page before) are
 *     applied from a per-page index of the .reloc blocks, then it is mapped with the section's protection. A 334 MB DLL
 *     costs the pages that are really touched. Pages are private per process (no cross-process sharing).
 * Either way gaps between sections stay reserved (no other allocation can land inside an image), and images with
 * SectionAlignment < 4 KiB (FileAlignment == SectionAlignment) are mapped as one flat RWX view of the file.
 * Every write the loader makes into an image (IAT binding, fixups of RAM images, TLS index, security cookie, CFG
 * pointers, the header's ImageBase) goes through ONE path, vad.c image_poke()/image_kpage(): the page is produced like
 * a fault would produce it (lazy pages read and relocated first) and written whatever its protection, like the Windows
 * loader's temporary unprotect - an IAT inside read-only .rdata is normal for MSVC-linked images.
 *
 * ASLR: an image with IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE and a relocation directory is placed at a random 64 KiB
 * aligned base (RDRAND). An executable is placed per process; a DLL, as on Windows, once per boot: the base drawn for the
 * first process that loads it (keyed by path, SizeOfImage and CheckSum) is reused in every later process where that
 * range is free (debuggers and crash reporters such as crashpad read ntdll's and kernel32's data in other processes at
 * their own addresses). Windows-like entropy (Windows Internals 7th ed., part 1, ch. 5 "Address space
 * layout randomization"): HIGH_ENTROPY_VA DLLs 19 bits in [0x7ff8'0000'0000, 0x7fff'0000'0000), HIGH_ENTROPY_VA
 * executables 17 bits in [0x7ff6'0000'0000, 0x7ff8'0000'0000), other relocatable images 8 bits in
 * [0x7ff5'0000'0000, 0x7ff6'0000'0000); images that are not LARGE_ADDRESS_AWARE or carry 32-bit (HIGHLOW) fixups stay
 * below 2 GiB (8 bits in [0x1000'0000, 0x8000'0000)). Without RDRAND (or when no random slot is free) the preferred
 * base is used, and a relocatable image whose preferred range is occupied goes to the first free range.
 *
 * Load configuration (IMAGE_LOAD_CONFIG_DIRECTORY64): a security cookie that still holds the compiler's default value
 * (0x00002B992DDFA232) is replaced by a 48-bit RDRAND value, as the Windows loader does before the image runs (the MSVC
 * CRT then derives __security_cookie_complement from it); without RDRAND it stays default and the CRT generates one.
 * For CFG-instrumented images (GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED) the GuardCFCheckFunctionPointer,
 * GuardCFDispatchFunctionPointer and the XFG counterparts receive ntdll!ShzGuardCheckICall / ShzGuardDispatchICall:
 * a real, NON-ENFORCING check (ntdll/cfg.c) that validates the target against the GuardCFFunctionTable of its image,
 * counts and reports violations, and always lets the call proceed. Dynamic value relocations (DVRT) are optional
 * patches of already valid code and are ignored.
 *
 * DLL search order (the directories of one load request; LoadLibraryExW flags arrive through NtLoadImage):
 *   - a name with a path component is opened as given;
 *   - KnownDLLs (the Windows 11 KnownDLLs registry list below) and API-set hosts come from the system directory only;
 *   - LOAD_LIBRARY_SEARCH_* flags: [DLL load dir] [application dir] [user dirs (AddDllDirectory)] [system dir];
 *   - otherwise (SafeDllSearchMode): application dir (or the DLL's own dir with LOAD_WITH_ALTERED_SEARCH_PATH),
 *     [SetDllDirectory dir], system dir (\SHZ\SYS64), Windows dir (\SHZ), current dir (not with SetDllDirectory),
 *     PATH is not searched. Dependencies of the requested DLL are searched the same way.
 *
 * Diagnostics: a load that fails prints exactly ONE line,
 *   K64 ldr: <requested image> not loaded: <image> needs <dll>[ -> <host>]!<function>: <reason> [<status>]
 * naming the image whose import failed (the deepest one), the DLL it depends on and the missing function or ordinal.
 * Modules mapped by a failed attempt are unmapped again, so a later attempt starts from a clean state.
 */
#include "fs.h"
#include "auth_policy.h"
#include "kwin.h"
#include "apiset.h"
#include "ldr_lifetime.h"
#include "../win64/include/shz_loader_protocol.h"
#include "../win64/pe_parse.h"

#define SYS64_DIR "\\SHZ\\SYS64"
#define WINDOWS_DIR "\\SHZ"
#define MAX_DEPTH 24
#define PATH_CAP 256

/* LoadLibraryExW flags the loader interprets (winbase.h / libloaderapi.h values) */
#define LLF_ALTERED_SEARCH_PATH 0x00000008u
#define LLF_SEARCH_DLL_LOAD_DIR 0x00000100u
#define LLF_SEARCH_APPLICATION_DIR 0x00000200u
#define LLF_SEARCH_USER_DIRS 0x00000400u
#define LLF_SEARCH_SYSTEM32 0x00000800u
#define LLF_SEARCH_DEFAULT_DIRS 0x00001000u
#define LLF_SEARCH_MASK 0x00001f00u
/* ntdll -> kernel only (NtLoadImage flags, high bits) */
#define LDRS_DLL_DIRECTORY 0x80000000u      /* `dirs` is SetDllDirectory's directory (standard search order) */
#define LDRS_NO_CWD 0x40000000u             /* SetDllDirectory(""): the current directory is not searched */

#define PE_CHAR_RELOCS_STRIPPED 0x0001
#define PE_CHAR_LARGE_ADDRESS_AWARE 0x0020

typedef struct { uint32_t page, count; uint64_t off; } reloc_block_t;   /* one .reloc block: page RVA, entries, file offset */

/* A lazily mapped (disk-backed) image: its VK_IMAGE descriptors point here and ldr_image_fault() fills their pages. */
typedef struct image_map {
    shz_ldr_image_life_t life;           /* module owner plus active, possibly blocked, page-ins */
    fsnode_t *node;                     /* the file */
    kview_t *view;                      /* its kernel view (parser, relocation blocks) */
    const uint8_t *file;                /* view->base */
    uint64_t fsize;
    pe_info_t info;
    uint64_t base, delta;               /* mapped base; base - preferred */
    reloc_block_t *blocks;              /* sorted by page (relocated images only) */
    uint32_t nblocks;
    uint64_t highlow;                   /* 32-bit fixups seen while indexing (the image must then stay below 2 GiB) */
    uint64_t pages_in, reloc_pages, relocs_applied, bytes_read;
    char name[48];
} image_map_t;

typedef struct module {
    struct module *next;
    shz_ldr_life_t life;                /* explicit references, startup/pin roots and import edges */
    char name[64];                      /* lowercase base name, e.g. "kernel32.dll" */
    char path[PATH_CAP];
    char dir[PATH_CAP];                 /* directory of `path` (no trailing backslash) */
    const uint8_t *file;                /* RAM: the file data; disk: the kernel view of the file */
    uint64_t fsize;
    image_map_t *img;                   /* lazily mapped (disk-backed) image, else NULL */
    pe_info_t info;
    uint64_t base;
    int state;                          /* 0 loading, 1 mapped and linked, 2 prepared for retirement */
    int is_dll;
    int has_tls;
    uint32_t tls_index, tls_align;
    uint64_t tls_start, tls_end, tls_index_va, tls_callbacks_va;
    uint32_t tls_zero;
    uint32_t init_seq;
    uint32_t delay_imports;             /* thunks in the (validated) delay-load directory */
    int published;
    uint64_t entry_va;                  /* actual published PEB loader entry (batch storage retained) */
} module_t;

typedef struct {
    uint64_t token, owner_tid;
    unsigned count;
    module_t *nodes[];                  /* reverse dependency-completion order */
} ldr_retirement_t;

static void image_metadata_free(image_map_t *im)
{
    kfree(im->blocks);
    kfree(im);
}

static void image_owner_retire(image_map_t *im)
{
    uint64_t f;
    int release;
    if (!im) return;
    f = irq_save();
    release = shz_ldr_image_retire(&im->life);
    irq_restore(f);
    if (release) image_metadata_free(im);
}

static void module_edges_free(module_t *m)
{
    shz_ldr_edge_t *e = m->life.edges;
    while (e) { shz_ldr_edge_t *next = e->next; kfree(e); e = next; }
    m->life.edges = 0;
}

static void module_life_links(process_t *p)
{
    module_t *m;
    for (m = p->modules; m; m = m->next) m->life.next = m->next ? &m->next->life : 0;
}

static int32_t module_edge(module_t *from, module_t *to)
{
    shz_ldr_edge_t *e;
    if (to->life.retiring) return STATUS_DLL_NOT_FOUND;
    if (from == to || shz_ldr_life_has_edge(&from->life, &to->life)) return STATUS_SUCCESS;
    e = kzalloc(sizeof *e);
    if (!e) return STATUS_NO_MEMORY;
    e->to = &to->life; e->next = from->life.edges; from->life.edges = e;
    return STATUS_SUCCESS;
}

/* The first (deepest) failure of one load request; printed once by the entry point that started the request. */
typedef struct {
    int set;
    int32_t status;
    char image[64];                     /* the image whose import (or own mapping) failed */
    char dll[96];                       /* the DLL name as imported */
    char contract_host[48];             /* for API-set imports: the host DLL the contract resolved to */
    char func[96];                      /* function name, "#<ordinal>" or "" */
    char reason[96];
} ldr_error_t;

typedef struct {
    process_t *p;
    ldr_error_t err;
    const char *importer;               /* the image whose import table is being walked */
    const char *import_dll;             /* the DLL name it imports (as written) */
    const char *import_func;            /* the function being resolved ("" before the first one) */
    char import_ord[16];
    /* search order of this request */
    uint32_t flags;                     /* LLF_* | LDRS_* */
    char app_dir[PATH_CAP];
    char load_dir[PATH_CAP];            /* directory of the DLL named by path (DLL_LOAD_DIR / ALTERED_SEARCH_PATH) */
    const char *dep_dir;                /* DLL_LOAD_DIR: directory of the image whose imports are being resolved */
    char dirs[520];                     /* ';'-separated user directories (AddDllDirectory list or SetDllDirectory dir) */
    char cwd[PATH_CAP];
} ldr_ctx_t;

static char lower(char c) { return c >= 'A' && c <= 'Z' ? (char)(c + 32) : c; }

static void scopy(char *d, size_t cap, const char *s)
{
    size_t k = 0;
    if (!cap) return;
    for (; s && s[k] && k + 1 < cap; ++k) d[k] = s[k];
    d[k] = 0;
}

static void sappend(char *d, size_t cap, const char *s)
{
    size_t k = strlen(d);
    for (; s && *s && k + 1 < cap; ++s) d[k++] = *s;
    d[k] = 0;
}

static void fmt_dec(char *out, size_t cap, const char *prefix, uint64_t v)
{
    char tmp[24];
    int n = 0;
    scopy(out, cap, prefix);
    do { tmp[n++] = (char)('0' + v % 10); v /= 10; } while (v && n < 20);
    while (n) { char c[2] = { tmp[--n], 0 }; sappend(out, cap, c); }
}

/* Records the failure unless a deeper one was recorded already. `image`/`dll`/`func` may be NULL for "the import
 * currently being resolved". */
static int32_t fail(ldr_ctx_t *c, int32_t st, const char *image, const char *dll, const char *host, const char *func,
                    const char *reason)
{
    if (!c || c->err.set) return st;
    c->err.set = 1;
    c->err.status = st;
    scopy(c->err.image, sizeof c->err.image, image ? image : c->importer);
    scopy(c->err.dll, sizeof c->err.dll, dll ? dll : c->import_dll);
    scopy(c->err.contract_host, sizeof c->err.contract_host, host);
    scopy(c->err.func, sizeof c->err.func, func ? func : (c->import_func ? c->import_func : c->import_ord));
    scopy(c->err.reason, sizeof c->err.reason, reason);
    return st;
}

static void report(ldr_ctx_t *c, const char *what, int32_t st)
{
    ldr_error_t *e = &c->err;
    if (!e->set) {
        kprintf("K64 ldr: %s not loaded [%x]\n", what, (uint32_t)st);
        return;
    }
    if (!e->dll[0])                                         /* the image itself is unusable */
        kprintf("K64 ldr: %s not loaded: %s: %s [%x]\n", what, e->image, e->reason, (uint32_t)e->status);
    else
        kprintf("K64 ldr: %s not loaded: %s needs %s%s%s%s%s: %s [%x]\n", what, e->image[0] ? e->image : "?", e->dll,
                e->contract_host[0] ? " -> " : "", e->contract_host, e->func[0] ? "!" : "", e->func, e->reason,
                (uint32_t)e->status);
}

/* ---------------------------------------------------------------- hardware randomness */
/* RDRAND (CPUID.1:ECX bit 30) with the 10-attempt retry of Intel's DRNG guide. Returns 0 when unavailable. */
static int k_rdrand64(uint64_t *out)
{
    static int have = -1;
    unsigned i;
    if (have < 0) {
        uint32_t a = 1, b = 0, c = 0, d = 0;
        __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
        have = (int)((c >> 30) & 1u);
        if (!have) kprintf("K64 ldr: no RDRAND: images load at their preferred bases, security cookies stay default\n");
    }
    if (!have) return 0;
    for (i = 0; i < 10; ++i) {
        uint64_t v;
        unsigned char ok;
        __asm__ volatile("rdrand %0; setc %1" : "=r"(v), "=qm"(ok) : : "cc");
        if (ok) { *out = v; return 1; }
    }
    return 0;
}

/* ---------------------------------------------------------------- API-set contracts */
/* Maps an imported DLL name onto the DLL to load. Returns STATUS_SUCCESS with `out` = the host (or the name itself
 * when it is not an API-set name), or an error recorded in the context. */
static int32_t resolve_dll_name(ldr_ctx_t *c, const char *name, char *out, size_t cap, int *is_apiset)
{
    const apiset_entry_t *e = 0;
    const int r = apiset_lookup(name, &e);
    *is_apiset = r != APISET_NOT_APISET;
    if (r == APISET_NOT_APISET || r == APISET_OK) {
        scopy(out, cap, r == APISET_OK ? e->host : name);
        return STATUS_SUCCESS;
    }
    if (r == APISET_VERSION) {
        char why[96], v[16];
        scopy(why, sizeof why, "API-set contract version not provided (table has ");
        sappend(why, sizeof why, e->contract);
        fmt_dec(v, sizeof v, "-", e->major);
        sappend(why, sizeof why, v);
        fmt_dec(v, sizeof v, "-", e->minor);
        sappend(why, sizeof why, v);
        sappend(why, sizeof why, ")");
        return fail(c, STATUS_DLL_NOT_FOUND, 0, name, 0, 0, why);
    }
    return fail(c, STATUS_DLL_NOT_FOUND, 0, name, 0, 0,
                r == APISET_BAD_NAME ? "malformed API-set name" : "unknown API-set contract");
}

/* ---------------------------------------------------------------- module registry */
static int has_path(const char *s)
{
    for (; *s; ++s)
        if (*s == '\\' || *s == '/' || *s == ':') return 1;
    return 0;
}

static void base_name(const char *in, char *out, size_t cap)
{
    const char *s = in, *p;
    size_t n = 0;
    int has_ext = 0;
    for (p = in; *p; ++p)
        if (*p == '\\' || *p == '/' || *p == ':') s = p + 1;
    for (p = s; *p && n + 5 < cap; ++p) {
        out[n++] = lower(*p);
        if (*p == '.') has_ext = 1;
    }
    if (n && out[n - 1] == '.') { --n; has_ext = 1; }       /* "name." means "no extension" */
    else if (!has_ext) {
        memcpy(out + n, ".dll", 4);
        n += 4;
    }
    out[n] = 0;
}

static void dir_of(const char *path, char *out, size_t cap)
{
    size_t k, last = 0;
    for (k = 0; path[k]; ++k)
        if (path[k] == '\\' || path[k] == '/') last = k;
    if (last >= cap) last = cap - 1;
    memcpy(out, path, last);
    out[last] = 0;
}

static module_t *find_module(process_t *p, const char *name)
{
    module_t *m;
    for (m = p->modules; m; m = m->next)
        if (!strcmp(m->name, name)) return m;
    return 0;
}

/* Windows 11 KnownDLLs (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs, plus ntdll and kernelbase that
 * the section directory always holds): never taken from an application directory. */
static const char *const known_dlls[] = {
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll", "clbcatq.dll", "combase.dll", "comdlg32.dll",
    "coml2.dll", "difxapi.dll", "gdi32.dll", "gdiplus.dll", "imagehlp.dll", "imm32.dll", "msctf.dll", "msvcrt.dll",
    "normaliz.dll", "nsi.dll", "ole32.dll", "oleaut32.dll", "psapi.dll", "rpcrt4.dll", "sechost.dll", "setupapi.dll",
    "shcore.dll", "shell32.dll", "shlwapi.dll", "user32.dll", "wldap32.dll", "ws2_32.dll", 0
};

static int is_known_dll(const char *name)
{
    unsigned i;
    for (i = 0; known_dlls[i]; ++i)
        if (!strcmp(known_dlls[i], name)) return 1;
    return 0;
}

static fsnode_t *try_dir(const char *dir, size_t dlen, const char *name, char *found, size_t cap)
{
    char path[PATH_CAP];
    fsnode_t *n;
    if (!dlen || dlen + strlen(name) + 2 > sizeof path) return 0;
    memcpy(path, dir, dlen);
    path[dlen] = 0;
    if (path[dlen - 1] != '\\' && path[dlen - 1] != '/') sappend(path, sizeof path, "\\");
    sappend(path, sizeof path, name);
    n = fs_lookup(path);
    if (!n || n->is_dir) return 0;
    scopy(found, cap, path);
    return n;
}

static fsnode_t *try_list(const char *list, const char *name, char *found, size_t cap)
{
    const char *s = list;
    while (s && *s) {
        const char *e = s;
        fsnode_t *n;
        while (*e && *e != ';') ++e;
        n = try_dir(s, (size_t)(e - s), name, found, cap);
        if (n) return n;
        s = *e ? e + 1 : e;
    }
    return 0;
}

#define TRY(dir) do { if ((n = try_dir((dir), strlen(dir), name, found, cap))) return n; } while (0)

/* Finds the file of DLL `name` (a base name or a path) with the search order of request `c`. `system_only`: API-set
 * hosts and KnownDLLs. */
static fsnode_t *locate_file(ldr_ctx_t *c, const char *name, int system_only, char *found, size_t cap)
{
    fsnode_t *n;
    const uint32_t f = c->flags;
    if (has_path(name)) {
        const int absolute = name[0] == '\\' || name[0] == '/' || (name[0] && name[1] == ':');
        if (!absolute) {                                    /* relative path: current directory, then application dir */
            if (c->cwd[0]) TRY(c->cwd);
            TRY(c->app_dir);
            return 0;
        }
        n = fs_lookup(name);
        if (!n || n->is_dir) return 0;
        scopy(found, cap, name);
        return n;
    }
    if (system_only || is_known_dll(name)) {
        TRY(SYS64_DIR);
        return 0;
    }
    if (f & LLF_SEARCH_MASK) {
        const uint32_t s = (f & LLF_SEARCH_DEFAULT_DIRS) ?
                           (f | LLF_SEARCH_APPLICATION_DIR | LLF_SEARCH_USER_DIRS | LLF_SEARCH_SYSTEM32) : f;
        if (s & LLF_SEARCH_DLL_LOAD_DIR) {
            if (c->dep_dir && c->dep_dir[0]) TRY(c->dep_dir);
            else if (c->load_dir[0]) TRY(c->load_dir);
        }
        if (s & LLF_SEARCH_APPLICATION_DIR) TRY(c->app_dir);
        if ((s & LLF_SEARCH_USER_DIRS) && (n = try_list(c->dirs, name, found, cap))) return n;
        if (s & LLF_SEARCH_SYSTEM32) TRY(SYS64_DIR);
        return 0;
    }
    if ((f & LLF_ALTERED_SEARCH_PATH) && c->load_dir[0]) TRY(c->load_dir);
    else TRY(c->app_dir);
    if ((f & LDRS_DLL_DIRECTORY) && (n = try_list(c->dirs, name, found, cap))) return n;
    TRY(SYS64_DIR);
    TRY(WINDOWS_DIR);
    if (!(f & (LDRS_DLL_DIRECTORY | LDRS_NO_CWD)) && c->cwd[0]) TRY(c->cwd);
    return 0;
}
#undef TRY

/* ---------------------------------------------------------------- image memory (kernel access) */
/* All loader reads/writes of process memory go through vad.c image_peek()/image_poke() (see the header comment). */
static int kread(process_t *p, uint64_t va, void *dst, uint64_t n) { return image_peek(p, va, dst, n); }
static int kwrite(process_t *p, uint64_t va, const void *src, uint64_t n) { return image_poke(p, va, src, n); }
static int kwrite64(process_t *p, uint64_t va, uint64_t v) { return kwrite(p, va, &v, 8); }
static int uwrite(process_t *p, uint64_t va, const void *src, uint64_t n) { return copy_to_user(p, va, src, n); }
static int uwrite64(process_t *p, uint64_t va, uint64_t v) { return copy_to_user(p, va, &v, 8); }
static int uread64(process_t *p, uint64_t va, uint64_t *v) { return copy_from_user(p, v, va, 8); }

static uint32_t prot_from_section(uint32_t ch)
{
    const int r = (ch & PE_SCN_MEM_READ) != 0, w = (ch & PE_SCN_MEM_WRITE) != 0, x = (ch & PE_SCN_MEM_EXECUTE) != 0;
    if (x) return w ? PAGE_EXECUTE_READWRITE : (r ? PAGE_EXECUTE_READ : PAGE_EXECUTE);
    if (w) return PAGE_READWRITE;
    if (r) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

/* ---------------------------------------------------------------- base selection (ASLR) */
struct reloc_census { uint64_t highlow, total; };
static int census_cb(void *ctx, uint32_t rva, unsigned type)
{
    struct reloc_census *r = ctx;
    (void)rva;
    ++r->total;
    if ((type & 15) != 10) ++r->highlow;                    /* 32- or 16-bit absolute fixup */
    return 0;
}

/* Per-boot DLL bases (see the ASLR note at the top): key = FNV-1a of the lowercase path, SizeOfImage, CheckSum. */
#define BOOT_BASES 256
static struct { uint64_t key, base; } boot_bases[BOOT_BASES];
static unsigned boot_base_count;

static uint64_t boot_base_key(const module_t *m)
{
    uint64_t h = 0xcbf29ce484222325ull;
    const char *q;
    for (q = m->path; *q; ++q) {
        char ch = *q;
        if (ch >= 'A' && ch <= 'Z') ch = (char)(ch + 32);
        h = (h ^ (uint8_t)ch) * 0x100000001b3ull;
    }
    h = (h ^ m->info.size_of_image) * 0x100000001b3ull;
    return (h ^ m->info.checksum) * 0x100000001b3ull;
}

static uint64_t boot_base_get(uint64_t key)
{
    uint64_t f = irq_save(), base = 0;
    unsigned i;
    for (i = 0; i < boot_base_count; ++i) if (boot_bases[i].key == key) { base = boot_bases[i].base; break; }
    irq_restore(f);
    return base;
}

static void boot_base_put(uint64_t key, uint64_t base)
{
    uint64_t f = irq_save();
    unsigned i;
    for (i = 0; i < boot_base_count; ++i) if (boot_bases[i].key == key) break;
    if (i == boot_base_count && boot_base_count < BOOT_BASES) {
        boot_bases[i].key = key;
        boot_bases[i].base = base;
        ++boot_base_count;
    }
    irq_restore(f);
}

static uint64_t aslr_pick(process_t *p, const module_t *m, int low_only)
{
    const pe_info_t *pi = &m->info;
    const uint64_t size = ((uint64_t)pi->size_of_image + 0xffff) & ~0xffffull;
    uint64_t lo, hi, positions, slots, stride, r;
    unsigned bits, tries;
    if (low_only) { lo = 0x10000000ull; hi = 0x80000000ull; bits = 8; }
    else if (pi->dll_characteristics & PE_DLLCHAR_HIGH_ENTROPY_VA) {
        if (m->is_dll) { lo = 0x7ff800000000ull; hi = 0x7fff00000000ull; bits = 19; }
        else { lo = 0x7ff600000000ull; hi = 0x7ff800000000ull; bits = 17; }
    } else { lo = 0x7ff500000000ull; hi = 0x7ff600000000ull; bits = 8; }
    if (size >= hi - lo) return 0;
    positions = ((hi - lo - size) >> 16) + 1;               /* 64 KiB aligned bases that fit */
    slots = positions < (1ull << bits) ? positions : (1ull << bits);
    stride = positions / slots;
    for (tries = 0; tries < 32; ++tries) {
        uint64_t cand;
        if (!k_rdrand64(&r)) return 0;
        cand = lo + ((r % slots) * stride << 16);
        if (vad_range_is_free(p, cand, size)) return cand;
    }
    return 0;
}

/* ---------------------------------------------------------------- lazy (file-backed) mapping */
static int block_cmp_less(const reloc_block_t *a, const reloc_block_t *b) { return a->page < b->page || (a->page == b->page && a->off < b->off); }

/* Index of the .reloc blocks (page RVA -> file offset of its entries), read through the view. Lazily relocated images
 * support the fixup types AMD64 linkers emit: ABSOLUTE, HIGHLOW and DIR64 (HIGH/LOW/HIGHADJ are relocated only in the
 * eager path). Also counts the HIGHLOW fixups (an image with 32-bit fixups must stay below 2 GiB). */
static int32_t build_reloc_index(image_map_t *im)
{
    const pe_info_t *o = &im->info;
    uint32_t rva = o->dir_rva[5], remaining = o->dir_size[5], cap = 0, n = 0, i;
    reloc_block_t *b = 0;
    im->highlow = 0;
    while (remaining >= 8) {
        uint64_t off, avail;
        uint32_t page, size;
        if (pe_rva_to_offset(im->file, im->fsize, o, rva, &off, &avail) || avail < 8) break;
        page = *(const uint32_t *)(im->file + off);
        size = *(const uint32_t *)(im->file + off + 4);
        if (size < 8 || size > remaining || (size & 1) || page >= o->size_of_image || (page & 0xfff) || avail < size) break;
        if (n == cap) {
            const uint32_t ncap = cap ? cap * 2 : 64;
            reloc_block_t *nb = kmalloc((size_t)ncap * sizeof *nb);
            if (!nb) { kfree(b); return STATUS_NO_MEMORY; }
            if (b) { memcpy(nb, b, (size_t)n * sizeof *nb); kfree(b); }
            b = nb; cap = ncap;
        }
        b[n].page = page; b[n].count = (size - 8) / 2; b[n].off = off + 8;
        ++n;
        rva += size; remaining -= size;
    }
    if (remaining) { kfree(b); return STATUS_INVALID_IMAGE_FORMAT; }
    for (i = 1; i < n; ++i)                                        /* linkers emit ascending pages; keep it robust */
        if (block_cmp_less(&b[i], &b[i - 1])) {
            uint32_t j, k;
            for (j = 1; j < n; ++j)                                 /* insertion sort, only for unsorted input */
                for (k = j; k > 0 && block_cmp_less(&b[k], &b[k - 1]); --k) { reloc_block_t t = b[k]; b[k] = b[k - 1]; b[k - 1] = t; }
            break;
        }
    for (i = 0; i < n; ++i) {                                       /* entry types must be ABSOLUTE, HIGHLOW or DIR64 */
        uint32_t e;
        for (e = 0; e < b[i].count; ++e) {
            const uint16_t v = *(const uint16_t *)(im->file + b[i].off + 2ull * e);
            const unsigned type = v >> 12;
            if (type && type != 3 && type != 10) { kfree(b); return STATUS_INVALID_IMAGE_FORMAT; }
            if (type && (uint64_t)b[i].page + (v & 0xfff) + (type == 10 ? 8 : 4) > o->size_of_image) { kfree(b); return STATUS_INVALID_IMAGE_FORMAT; }
            if (type == 3) ++im->highlow;
        }
    }
    im->blocks = b;
    im->nblocks = n;
    return im->file && im->view->io_errors ? STATUS_IN_PAGE_ERROR : STATUS_SUCCESS;
}

/* Original (file) bytes of the image at [rva, rva+n): headers, raw section data, zeros elsewhere. */
static void image_orig(image_map_t *im, uint64_t rva, uint8_t *out, uint64_t n)
{
    while (n) {
        uint64_t off, avail, take;
        if (rva < 0x100000000ull && !pe_rva_to_offset(im->file, im->fsize, &im->info, (uint32_t)rva, &off, &avail) && avail) {
            take = avail < n ? avail : n;
            memcpy(out, im->file + off, take);
        } else {
            take = 1;
            *out = 0;
        }
        out += take; rva += take; n -= take;
    }
}

/* Applies the fixups of the .reloc block(s) for page `block_page` that land in the page at page_rva (content in `pg`):
 * called with the page itself and with the page before it (a fixup starting there may straddle into this page). */
static void relocate_page(image_map_t *im, uint64_t page_rva, uint8_t *pg, uint32_t block_page)
{
    uint32_t lo = 0, hi = im->nblocks;
    while (lo < hi) {                                               /* first block with page >= block_page */
        const uint32_t mid = (lo + hi) / 2;
        if (im->blocks[mid].page < block_page) lo = mid + 1; else hi = mid;
    }
    for (; lo < im->nblocks && im->blocks[lo].page == block_page; ++lo) {
        const reloc_block_t *b = &im->blocks[lo];
        uint32_t e;
        for (e = 0; e < b->count; ++e) {
            const uint16_t v = *(const uint16_t *)(im->file + b->off + 2ull * e);
            const unsigned type = v >> 12, width = type == 10 ? 8 : 4;
            const uint64_t at = (uint64_t)b->page + (v & 0xfff);
            uint8_t val[8];
            uint64_t x = 0, k;
            if (!type) continue;
            if (at + width <= page_rva || at >= page_rva + PAGE_SIZE) continue;      /* not in this page */
            if (at >= page_rva && at + width <= page_rva + PAGE_SIZE)
                memcpy(val, pg + (at - page_rva), width);           /* still the original: fixups never overlap */
            else
                image_orig(im, at, val, width);                     /* straddles the page edge: file bytes via the view */
            memcpy(&x, val, width);
            x = width == 8 ? x + im->delta : (uint64_t)(uint32_t)((uint32_t)x + (uint32_t)im->delta);
            memcpy(val, &x, width);
            for (k = 0; k < width; ++k)
                if (at + k >= page_rva && at + k < page_rva + PAGE_SIZE) pg[at + k - page_rva] = val[k];
            ++im->relocs_applied;
        }
    }
}

int ldr_image_fault(process_t *p, vad_t *v, uint64_t addr)
{
    image_map_t *im;
    const uint64_t va = addr & ~(PAGE_SIZE - 1);
    uint64_t rva, flags;
    const pe_info_t *o;
    int32_t result = 0;
    uint64_t pa, file_off = 0, n = 0, done = 0;
    uint8_t *pg;
    unsigned i;
    flags = irq_save();
    im = v->img;
    if (p->teardown || !im || shz_ldr_image_acquire(&im->life)) {
        irq_restore(flags);
        return STATUS_ACCESS_VIOLATION;
    }
    irq_restore(flags);
    rva = va - im->base;
    o = &im->info;
    if (va < im->base || rva >= o->size_of_image) { result = STATUS_ACCESS_VIOLATION; goto done; }
    if (rva < ((o->size_of_headers + 4095ull) & ~4095ull)) {       /* headers */
        file_off = rva;
        n = o->size_of_headers - rva < PAGE_SIZE ? o->size_of_headers - rva : PAGE_SIZE;
    } else {
        for (i = 0; i < o->nsections; ++i) {
            pe_section_t s;
            uint64_t vlen, raw;
            pe_get_section(im->file, o, i, &s);
            vlen = ((uint64_t)(s.vsize ? s.vsize : s.raw_size) + 4095ull) & ~4095ull;
            if (rva < s.rva || rva >= s.rva + vlen) continue;
            raw = s.raw_size < (s.vsize ? s.vsize : s.raw_size) ? s.raw_size : (s.vsize ? s.vsize : s.raw_size);
            if (rva - s.rva < raw) {
                file_off = s.raw_off + (rva - s.rva);
                n = raw - (rva - s.rva) < PAGE_SIZE ? raw - (rva - s.rva) : PAGE_SIZE;
            }
            break;
        }
    }
    pa = pmm_alloc();                                               /* zeroed: bss tails and gaps read as zero */
    if (!pa) { result = STATUS_NO_MEMORY; goto done; }
    pg = (uint8_t *)p2v(pa);
    if (n && (fs_read(im->node, file_off, pg, n, &done) || done != n)) {
        pmm_free(pa);
        kprintf("K64 ldr: %s: page rva %llx: read of %llu bytes at file offset %llx failed\n", im->name, rva, n, file_off);
        result = STATUS_IN_PAGE_ERROR; goto done;
    }
    if (im->delta && im->nblocks) {
        const uint64_t before = im->relocs_applied;
        relocate_page(im, rva, pg, (uint32_t)rva);
        if (rva) relocate_page(im, rva, pg, (uint32_t)(rva - PAGE_SIZE));   /* DIR64/HIGHLOW straddling in */
        if (im->relocs_applied != before) ++im->reloc_pages;
        if (im->view->io_errors) { pmm_free(pa); result = STATUS_IN_PAGE_ERROR; goto done; }
    }
    /* The reads may have blocked (volume mutex): another thread of the process may have faulted the page in, or changed
     * or freed the range (the descriptor array can even have been reallocated), so look the descriptor up again. */
    flags = irq_save();
    v = vad_find(p, va);
    if (p->teardown || im->life.retired || !v || v->img != im || v->state != VAD_COMMITTED) {
        pmm_free(pa); result = STATUS_ACCESS_VIOLATION;
    } else if (vm_lookup(p->pml4, va, 0)) pmm_free(pa);
    else if (vm_map(p->pml4, va, pa, prot_to_ptflags(v->prot))) { pmm_free(pa); result = STATUS_NO_MEMORY; }
    else { ++im->pages_in; im->bytes_read += n; }
    irq_restore(flags);
done:
    flags = irq_save();
    { int release = shz_ldr_image_release(&im->life);
      irq_restore(flags);
      if (release) image_metadata_free(im); }
    return result;
}

/* ---------------------------------------------------------------- mapping */
struct page_ctx { process_t *p; uint64_t base; };
static uint8_t *reloc_page(void *ctx, uint32_t page_rva)
{
    struct page_ctx *x = ctx;
    return image_kpage(x->p, x->base + page_rva);
}

/* Maps pages [va, va + len) as copies of file bytes [src, src + raw) (raw may be shorter than len: the rest is
 * demand-zero). NOACCESS pages are kept but not user-accessible, so a later VirtualProtect finds the data. */
static int32_t map_bytes(process_t *p, uint64_t va, uint64_t len, const uint8_t *src, uint64_t raw, uint32_t prot)
{
    uint64_t off;
    for (off = 0; off < len && off < raw; off += PAGE_SIZE) {
        const uint64_t n = raw - off < PAGE_SIZE ? raw - off : PAGE_SIZE;
        const uint64_t pa = pmm_alloc();
        if (!pa) return STATUS_NO_MEMORY;
        memcpy((void *)p2v(pa), src + off, n);
        if (vm_map(p->pml4, va + off, pa, (prot & 0xff) == PAGE_NOACCESS ? 0 : prot_to_ptflags(prot))) {
            pmm_free(pa);
            return STATUS_NO_MEMORY;
        }
    }
    return STATUS_SUCCESS;
}

/* One committed image descriptor: eager (pages copied now) or lazy (tied to the image map, filled on first touch). */
static int32_t map_range(process_t *p, module_t *m, uint64_t va, uint64_t len, const uint8_t *src, uint64_t raw,
                         uint32_t prot)
{
    int32_t st;
    if (m->img) return vad_insert_image(p, va, len, prot, m->base, m->img);
    st = vad_insert_fixed(p, va, len, VAD_COMMITTED, prot, VK_IMAGE, m->base);
    return st ? st : map_bytes(p, va, len, src, raw, prot);
}

static int32_t map_module(ldr_ctx_t *c, module_t *m)
{
    process_t *p = c->p;
    const pe_info_t *pi = &m->info;
    uint64_t base = 0;
    unsigned i;
    int32_t st;
    /* An image can be moved when it has a relocation directory; it is moved at random (ASLR) when it also asks for
     * DYNAMIC_BASE. An image without DYNAMIC_BASE loads at its preferred base and is relocated only when that range
     * is occupied, as on Windows. */
    const int has_relocs = pi->dir_rva[5] && pi->dir_size[5] && !(pi->characteristics & PE_CHAR_RELOCS_STRIPPED);
    /* A non-stripped DLL with an empty directory needs no fixups when its
     * preferred range is occupied. This does not opt it into ASLR, admit a
     * half-present directory, or make an empty-directory executable movable. */
    const int no_reloc_needed = m->is_dll && !pi->dir_rva[5] && !pi->dir_size[5] &&
                                !(pi->characteristics & PE_CHAR_RELOCS_STRIPPED);
    const int can_move = has_relocs || no_reloc_needed;
    const int randomize = has_relocs && (pi->dll_characteristics & PE_DLLCHAR_DYNAMIC_BASE);

    if (randomize) {
        uint64_t highlow;
        if (m->img) {                                               /* lazy: the per-page index also counts HIGHLOW */
            st = build_reloc_index(m->img);
            if (st) return fail(c, st, m->name, "", 0, "", "malformed base relocation directory");
            highlow = m->img->highlow;
        } else {
            struct reloc_census rc = { 0, 0 };
            if (pe_walk_relocs(m->file, m->fsize, pi, census_cb, &rc))
                return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, "", "malformed base relocation directory");
            highlow = rc.highlow;
        }
        {
            const int low_only = highlow || !(pi->characteristics & PE_CHAR_LARGE_ADDRESS_AWARE);
            const uint64_t key = m->is_dll ? boot_base_key(m) : 0, shared = key ? boot_base_get(key) : 0;
            if (shared && vad_range_is_free(p, shared, pi->size_of_image)) base = shared;
            else {
                base = aslr_pick(p, m, low_only);
                if (base && key && !shared) boot_base_put(key, base);
            }
        }
    }
    if (!base) {
        if (vad_range_is_free(p, pi->image_base, pi->size_of_image)) base = pi->image_base;
        else if (!can_move) return fail(c, STATUS_CONFLICTING_ADDRESSES, m->name, "", 0, "", "fixed-base image and its range is occupied");
        else {
            uint64_t sz = pi->size_of_image, b = 0, fs = 0;
            st = vad_alloc(p, &b, &sz, MEM_RESERVE | MEM_TOP_DOWN, PAGE_READONLY, VK_IMAGE);
            if (st) return fail(c, st, m->name, "", 0, "", "no free address range for the image");
            base = b;
            vad_free(p, &b, &fs, MEM_RELEASE);                /* only used to pick a free 64 KiB aligned range */
        }
    }
    m->base = base;
    if (m->img) {
        m->img->base = base;
        m->img->delta = base - pi->image_base;
        if (m->img->delta && !m->img->blocks && has_relocs) {
            st = build_reloc_index(m->img);
            if (st) return fail(c, st, m->name, "", 0, "", "malformed base relocation directory");
        }
    }

    if (pi->low_alignment) {
        /* one flat view of the file: every section sits at its file offset */
        const uint64_t len = ((uint64_t)pi->size_of_image + 4095) & ~4095ull;
        st = map_range(p, m, base, len, m->file, m->fsize < pi->size_of_image ? m->fsize : pi->size_of_image,
                       PAGE_EXECUTE_READWRITE);
        if (st) return fail(c, st, m->name, "", 0, "", "cannot map the image");
    } else {
        /* headers, each section, then reserved gaps: descriptors sharing one allocation base */
        uint64_t hdr = ((uint64_t)pi->size_of_headers + 4095) & ~4095ull, cursor, end;
        st = map_range(p, m, base, hdr, m->file, pi->size_of_headers, PAGE_READONLY);
        for (i = 0; !st && i < pi->nsections; ++i) {
            pe_section_t s;
            uint64_t vlen, raw;
            pe_get_section(m->file, pi, i, &s);
            vlen = (((uint64_t)(s.vsize ? s.vsize : s.raw_size)) + 4095) & ~4095ull;
            if (!vlen) continue;
            raw = s.raw_size < (s.vsize ? s.vsize : s.raw_size) ? s.raw_size : (s.vsize ? s.vsize : s.raw_size);
            st = map_range(p, m, base + s.rva, vlen, m->file + s.raw_off, raw, prot_from_section(s.characteristics));
        }
        if (st) return fail(c, st, m->name, "", 0, "", "cannot map the image (overlapping sections or out of memory)");
        /* every hole of [base, base + SizeOfImage) stays reserved and inaccessible */
        end = base + (((uint64_t)pi->size_of_image + 4095) & ~4095ull);
        for (cursor = base; cursor < end;) {
            vad_t *v = vad_find(p, cursor);
            if (v) { cursor = v->end; continue; }
            {
                uint64_t stop = cursor + PAGE_SIZE;
                while (stop < end && !vad_find(p, stop)) stop += PAGE_SIZE;
                if (vad_insert_fixed(p, cursor, stop - cursor, VAD_RESERVED, PAGE_NOACCESS, VK_IMAGE, base))
                    return fail(c, STATUS_NO_MEMORY, m->name, "", 0, "", "cannot reserve the image range");
                cursor = stop;
            }
        }
    }
    if (m->img)
        kprintf("K64 ldr: %s mapped lazily from %s at %llx (preferred %llx%s), %u pages in %u sections, %llu of %llu file "
                "pages read by the parser\n", m->name, m->path, base, pi->image_base, m->img->delta ? ", relocated per page" : "",
                pi->size_of_image / 4096, pi->nsections, m->img->view->resident, m->img->view->npages);

    if (base != pi->image_base) {
        struct page_ctx pc = { p, base };
        uint64_t applied = 0, hb = base;
        if (!can_move)
            return fail(c, STATUS_CONFLICTING_ADDRESSES, m->name, "", 0, "", "image cannot be relocated");
        /* RAM images are relocated now; lazy images page by page in ldr_image_fault() */
        if (!m->img && has_relocs && pe_apply_relocs(m->file, m->fsize, pi, base - pi->image_base, reloc_page, &pc, &applied))
            return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, "", "base relocation outside the image");
        /* the mapped header reports the actual base, as on Windows (OptionalHeader.ImageBase) */
        if (kwrite(p, base + pi->nt_offset + 24 + 24, &hb, 8))
            return fail(c, STATUS_NO_MEMORY, m->name, "", 0, "", "cannot update the mapped header");
    }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- exports and imports */
static int32_t load_dll(ldr_ctx_t *c, const char *name, int system_only, int depth, module_t **out);

static uint64_t ntdll_export(process_t *p, const char *sym);

static int32_t resolve_export(ldr_ctx_t *c, module_t *m, const char *sym, int ordinal, int depth, uint64_t *va)
{
    uint32_t rva;
    char fwd[128];
    int rc;
    if (depth > 8) return fail(c, STATUS_ENTRYPOINT_NOT_FOUND, 0, 0, 0, 0, "forwarder chain too long or circular");
    rc = pe_find_export(m->file, m->fsize, &m->info, sym, ordinal, &rva, fwd, sizeof fwd);
    if (rc == PE_E_NOT_FOUND) {
        char ord[16], why[96];
        if (!sym) fmt_dec(ord, sizeof ord, "#", (uint64_t)ordinal);
        if (depth) {                                        /* reached through a forwarder of the imported DLL */
            scopy(why, sizeof why, "forwarded to ");
            sappend(why, sizeof why, m->name);
            sappend(why, sizeof why, "!");
            sappend(why, sizeof why, sym ? sym : ord);
            sappend(why, sizeof why, ", which is not exported");
        }
        return fail(c, ordinal >= 0 ? STATUS_ORDINAL_NOT_FOUND : STATUS_ENTRYPOINT_NOT_FOUND, 0, 0, 0,
                    depth ? 0 : (sym ? sym : ord), depth ? why : "not exported by the DLL");
    }
    if (rc) return fail(c, STATUS_INVALID_IMAGE_FORMAT, 0, 0, 0, 0, "malformed export directory of the DLL");
    if (rva) {
        *va = m->base + rva;
        return STATUS_SUCCESS;
    }
    /* forwarder "DLL.Function" or "DLL.#ordinal"; the DLL part may itself be an API-set contract */
    {
        char dll[96], fn[96], nm[64], host[64];
        unsigned k = 0, j = 0;
        module_t *target;
        int32_t st;
        int is_api;
        /* the DLL name ends at the LAST dot: "api-ms-win-core-x-l1-1-0.Function" has dots only there */
        unsigned dot = 0, q;
        for (q = 0; fwd[q]; ++q) if (fwd[q] == '.') dot = q;
        if (!dot || dot + 5 >= sizeof dll) return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, fwd, "malformed forwarder");
        for (k = 0; k < dot; ++k) dll[k] = fwd[k];
        dll[k] = 0;
        ++k;
        while (fwd[k] && j + 1 < sizeof fn) fn[j++] = fwd[k++];
        fn[j] = 0;
        base_name(dll, nm, sizeof nm);
        st = resolve_dll_name(c, nm, host, sizeof host, &is_api);
        if (st) return st;
        st = load_dll(c, host, is_api, depth + 1, &target);
        if (st) return st;
        if (fn[0] == '#') {
            int ord = 0;
            for (q = 1; fn[q] >= '0' && fn[q] <= '9' && ord < 65536; ++q) ord = ord * 10 + (fn[q] - '0');
            if (fn[q] || q == 1) return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, fwd, "malformed forwarder");
            st = resolve_export(c, target, 0, ord, depth + 1, va);
        } else st = resolve_export(c, target, fn, -1, depth + 1, va);
        if (!st) st = module_edge(m, target);
        return st;
    }
}

/* After a failure of an API-set import: name the contract as the dependency and the host it resolved to. */
static void annotate_apiset(ldr_ctx_t *c, const char *importer, const char *contract, const char *host)
{
    if (!c->err.set || strcmp(c->err.image, importer)) return;       /* a deeper image failed: its record stands */
    if (!strcmp(c->err.dll, host)) {
        scopy(c->err.dll, sizeof c->err.dll, contract);
        if (c->err.status == STATUS_DLL_NOT_FOUND) scopy(c->err.reason, sizeof c->err.reason, "API-set host DLL not found");
    }
    if (!c->err.contract_host[0]) scopy(c->err.contract_host, sizeof c->err.contract_host, host);
}

struct impctx { ldr_ctx_t *c; module_t *m; int depth; int32_t st; };

static int import_cb(void *ctx, const char *dll, const char *name, uint16_t hint, int by_ord, uint32_t iat_rva)
{
    struct impctx *x = ctx;
    ldr_ctx_t *c = x->c;
    char nm[96], host[64];
    module_t *target;
    uint64_t va;
    int is_api;
    int32_t st;
    c->importer = x->m->name;
    c->import_dll = dll;
    c->import_func = by_ord ? 0 : name;
    fmt_dec(c->import_ord, sizeof c->import_ord, "#", hint);
    base_name(dll, nm, sizeof nm);
    st = resolve_dll_name(c, nm, host, sizeof host, &is_api);
    if (!st) {
        const char *saved_dir = c->dep_dir;
        c->dep_dir = x->m->dir;                             /* DLL_LOAD_DIR: dependencies of this image */
        st = load_dll(c, host, is_api, x->depth + 1, &target);
        c->dep_dir = saved_dir;
        if (!st) {
            /* restore the importer: loading `target` walked its own imports */
            c->importer = x->m->name;
            c->import_dll = dll;
            c->import_func = by_ord ? 0 : name;
            fmt_dec(c->import_ord, sizeof c->import_ord, "#", hint);
            st = resolve_export(c, target, name, by_ord ? hint : -1, 0, &va);
            if (!st) st = module_edge(x->m, target);
        }
        if (st && is_api) annotate_apiset(c, x->m->name, dll, host);
    }
    if (st) { x->st = st; return -1; }
    /* the IAT may live in a read-only section (.rdata of MSVC images): written through the kernel mapping */
    if (kwrite64(c->p, x->m->base + iat_rva, va)) { x->st = fail(c, STATUS_ACCESS_VIOLATION, x->m->name, dll, 0, 0, "IAT not mapped"); return -1; }
    return 0;
}

static int delay_count_cb(void *ctx, const pe_delay_desc_t *d, const char *name, uint16_t ord, int by_ord, uint32_t slot)
{
    (void)d; (void)name; (void)ord; (void)by_ord; (void)slot;
    ++*(uint32_t *)ctx;
    return 0;
}

/* Security cookie and Control Flow Guard pointers (see the header comment). */
static int32_t apply_load_config(ldr_ctx_t *c, module_t *m)
{
    process_t *p = c->p;
    pe_load_config_t lc;
    const uint64_t pref = m->info.image_base;
    if (pe_load_config(m->file, m->fsize, &m->info, &lc))
        return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, "", "malformed load configuration directory");
    if (!lc.size) return STATUS_SUCCESS;
    if (lc.security_cookie && !(lc.guard_flags & PE_GUARD_SECURITY_COOKIE_UNUSED)) {
        const uint64_t at = m->base + (lc.security_cookie - pref);
        uint64_t v = 0, r;
        if (kread(p, at, &v, 8)) return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, "", "security cookie not mapped");
        if (v == PE_DEFAULT_SECURITY_COOKIE_64 && k_rdrand64(&r)) {
            r &= 0x0000ffffffffffffull;                     /* x64 cookies keep the top 16 bits clear */
            if (r == PE_DEFAULT_SECURITY_COOKIE_64 || !r) r ^= 0x0000a5a5a5a5a5a5ull;
            kwrite64(p, at, r);
        }
    }
    if (lc.guard_flags & PE_GUARD_CF_INSTRUMENTED) {
        const uint64_t check = ntdll_export(p, "ShzGuardCheckICall"), dispatch = ntdll_export(p, "ShzGuardDispatchICall");
        const struct { uint64_t slot, fn; } w[] = {
            { lc.guard_cf_check_fptr, check }, { lc.guard_cf_dispatch_fptr, dispatch },
            { lc.guard_xfg_check_fptr, check }, { lc.guard_xfg_dispatch_fptr, dispatch },
            { lc.guard_xfg_table_dispatch_fptr, dispatch },
        };
        unsigned k;
        for (k = 0; k < sizeof w / sizeof w[0]; ++k)
            if (w[k].slot && w[k].fn && kwrite64(p, m->base + (w[k].slot - pref), w[k].fn))
                return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, "", "CFG pointer not mapped");
    }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- loading */
static uint32_t init_counter;

static int32_t link_module(ldr_ctx_t *c, module_t *m, int depth)
{
    process_t *p = c->p;
    struct impctx ic = { c, m, depth, 0 };
    int rc;
    int32_t st = apply_load_config(c, m);
    if (st) return st;
    m->delay_imports = 0;
    if (pe_walk_delay_imports(m->file, m->fsize, &m->info, delay_count_cb, &m->delay_imports))
        return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, "", "malformed delay-load import directory");
    rc = pe_walk_imports(m->file, m->fsize, &m->info, import_cb, &ic);
    if (rc) return ic.st ? ic.st : fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, "", "malformed import directory");
    /* TLS directory (IMAGE_TLS_DIRECTORY64: start, end, index VA, callbacks VA, zero fill, characteristics), read from
     * the mapped (relocated) image */
    if (m->info.dir_rva[9]) {
        uint64_t v[4];
        uint32_t tail[2];
        if (m->info.dir_size[9] < 40 || kread(p, m->base + m->info.dir_rva[9], v, 32) ||
            kread(p, m->base + m->info.dir_rva[9] + 32, tail, 8))
            return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, "", "malformed TLS directory");
        m->tls_start = v[0]; m->tls_end = v[1]; m->tls_index_va = v[2]; m->tls_callbacks_va = v[3]; m->tls_zero = tail[0];
        {
            const unsigned a = (tail[1] >> 20) & 15;        /* IMAGE_SCN_ALIGN_* encoding: 2^(a-1) bytes */
            m->tls_align = a ? 1u << (a - 1) : 16;
            if (m->tls_align < 64) m->tls_align = 64;
            if (m->tls_align > 8192) return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, "", "TLS alignment too large");
        }
        if (m->tls_end < m->tls_start || m->tls_end - m->tls_start > (1u << 24) || m->tls_zero > (1u << 24) ||
            m->tls_start < m->base || m->tls_end > m->base + m->info.size_of_image ||
            m->tls_index_va < m->base || m->tls_index_va + 4 > m->base + m->info.size_of_image)
            return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, "", "TLS directory out of the image");
        m->has_tls = 1;
        m->tls_index = p->tls_slots++;
        {
            uint32_t idx = m->tls_index;
            if (kwrite(p, m->tls_index_va, &idx, 4)) return fail(c, STATUS_ACCESS_VIOLATION, m->name, "", 0, "", "TLS index not mapped");
        }
    }
    return STATUS_SUCCESS;
}

static int32_t load_module_file(ldr_ctx_t *c, const char *name, fsnode_t *node, const char *path, int depth,
                                module_t **out)
{
    process_t *p = c->p;
    module_t *m = kzalloc(sizeof *m);
    int32_t st;
    int rc;
    if(!shz_auth_node_access(p,node,0)){kfree(m);return STATUS_ACCESS_DENIED;}
    if (!m) return fail(c, STATUS_NO_MEMORY, name, "", 0, "", "out of kernel memory");
    scopy(m->name, sizeof m->name, name);
    scopy(m->path, sizeof m->path, path);
    dir_of(m->path, m->dir, sizeof m->dir);
    if (node->backing == FSB_DISK) {                            /* lazy: parse through the kernel file view */
        kview_t *v = kview_get(node);
        if (v) m->img = kzalloc(sizeof *m->img);
        if (!v || !m->img) { kfree(m); return fail(c, STATUS_NO_MEMORY, name, "", 0, "", "no file view for the image"); }
        m->img->life.refs = 1;
        m->img->node = node;
        m->img->view = v;
        m->img->file = (const uint8_t *)v->base;
        m->img->fsize = node->size;
        scopy(m->img->name, sizeof m->img->name, name);
        m->file = m->img->file;
    } else {
        m->file = node->data;
    }
    m->fsize = node->size;
    rc = pe_parse(m->file, m->fsize, &m->info);
    if (!rc && m->img && m->img->view->io_errors) rc = PE_E_TRUNCATED;
    if (rc) {
        char why[48];
        const int32_t st2 = m->img && m->img->view->io_errors ? STATUS_IN_PAGE_ERROR : STATUS_INVALID_IMAGE_FORMAT;
        if (st2 == STATUS_IN_PAGE_ERROR) scopy(why, sizeof why, "I/O error while reading the image");
        else {
            fmt_dec(why, sizeof why, "not a valid AMD64 PE32+ image (pe error -", (uint64_t)-rc);
            sappend(why, sizeof why, ")");
        }
        kfree(m->img);
        kfree(m);
        return fail(c, st2, name, "", 0, "", why);
    }
    if (m->img) m->img->info = m->info;
    m->is_dll = (m->info.characteristics & PE_CHAR_DLL) != 0;
    m->state = 0;
    m->next = p->modules;
    m->life.next = m->next ? &m->next->life : 0;
    p->modules = m;                                             /* visible while loading: circular imports terminate */
    st = map_module(c, m);
    if (st) return st;
    st = link_module(c, m, depth);
    if (st) return st;
    m->state = 1;
    m->init_seq = ++init_counter;
    if (out) *out = m;
    return STATUS_SUCCESS;
}

static int32_t load_dll(ldr_ctx_t *c, const char *name, int system_only, int depth, module_t **out)
{
    char key[64], path[PATH_CAP];
    module_t *m;
    fsnode_t *node;
    base_name(name, key, sizeof key);
    m = find_module(c->p, key);
    if (m) {
        if (m->life.retiring) return fail(c, STATUS_DLL_NOT_FOUND, 0, key, 0, 0, "DLL is being unloaded");
        if (out) *out = m;
        return STATUS_SUCCESS;
    }
    if (depth > MAX_DEPTH) return fail(c, STATUS_DLL_NOT_FOUND, 0, key, 0, 0, "import nesting deeper than 24 levels");
    node = locate_file(c, name, system_only, path, sizeof path);
    if (!node) return fail(c, STATUS_DLL_NOT_FOUND, 0, key, 0, 0, has_path(name) ? "file not found" : "DLL not found");
    return load_module_file(c, key, node, path, depth, out);
}

/* Unmaps and forgets every module added after `mark` (the head of the list when the failed request started). */
static void module_incoming_remove(process_t *p, module_t *target)
{
    module_t *m;
    for (m = p->modules; m; m = m->next) {
        shz_ldr_edge_t **pp = &m->life.edges;
        while (*pp) {
            shz_ldr_edge_t *e = *pp;
            if (e->to == &target->life) { *pp = e->next; kfree(e); }
            else pp = &e->next;
        }
    }
}

static void rollback(process_t *p, module_t *mark, unsigned tls_mark)
{
    while (p->modules && p->modules != mark) {
        module_t *m = p->modules;
        p->modules = m->next;
        if (m->base) {
            uint64_t b = m->base, sz = 0;
            vad_free(p, &b, &sz, MEM_RELEASE);
        }
        module_incoming_remove(p, m);
        module_edges_free(m);
        image_owner_retire(m->img);
        kfree(m);
    }
    module_life_links(p);
    p->tls_slots = tls_mark;
}

/* Process teardown (proc.c): frees the loader's records; lazily mapped images report how much of them was used. */
void ldr_release_modules(process_t *p)
{
    module_t *m = p->modules, *next;
    p->modules = 0;                                     /* detached first: sysk32_proc.c reads the list of other processes */
    for (; m; m = next) {
        next = m->next;
        if (m->img) {
            kprintf("K64 ldr: %s (pid %d): %llu of %u image pages were made resident (%llu bytes read, %llu relocated "
                    "pages, %llu fixups); file view %llu of %llu pages\n", m->name, p->pid, m->img->pages_in,
                    m->info.size_of_image / 4096, m->img->bytes_read, m->img->reloc_pages, m->img->relocs_applied,
                    m->img->view->resident, m->img->view->npages);
            image_owner_retire(m->img);
        }
        module_edges_free(m);
        kfree(m);
    }
    kfree(p->ldr_retirement);
    p->ldr_retirement = 0;
    p->modules = 0;
}

/* ---------------------------------------------------------------- Windows-shaped loader database */
struct ustr { uint16_t length, maxlen; uint32_t pad; uint64_t buffer; };

#define LDR_ENTRY_SIZE 0x120
#define LDR_NEEDS_INIT 0x00000001u
#define LDR_IMAGE_DLL 0x00000004u
#define LDR_BASENAME_OFF 520                    /* strings: full path (PATH_CAP UTF-16 units max) then the base name */

static uint64_t alloc_user(process_t *p, uint64_t size)
{
    uint64_t base = 0, sz = size;
    if (vad_alloc(p, &base, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, VK_PRIVATE)) return 0;
    return base;
}

static int list_append(process_t *p, uint64_t head, uint64_t link)
{
    uint64_t blink;
    if (uread64(p, head + 8, &blink)) return -1;
    return uwrite64(p, link, head) || uwrite64(p, link + 8, blink) || uwrite64(p, blink, link) ||
           uwrite64(p, head + 8, link);
}

static int publish_module(process_t *p, module_t *m, uint64_t entry_va, uint64_t strings_va, int in_init_list, int is_exe)
{
    uint8_t entry[LDR_ENTRY_SIZE];
    uint16_t wfull[PATH_CAP], wbase[64];
    unsigned i, nf = 0, nb = 0;
    struct ustr uf, ub;
    memset(entry, 0, sizeof entry);
    /* FullDllName is fully qualified, as on Windows: a module of the boot volume ("\SHZ\SYS64\kernel32.dll") gets its
     * drive, C:, so that a program whose current drive is another one (chrome.exe on D:) can open the file by that name. */
    if (m->path[0] == '\\' && m->path[1] != '\\') { wfull[nf++] = 'C'; wfull[nf++] = ':'; }
    for (i = 0; m->path[i] && nf < PATH_CAP - 1; ++i) wfull[nf++] = (uint8_t)m->path[i];
    for (i = 0; m->name[i] && nb < 63; ++i) wbase[nb++] = (uint8_t)m->name[i];
    uf = (struct ustr){ (uint16_t)(nf * 2), (uint16_t)(nf * 2 + 2), 0, strings_va };
    ub = (struct ustr){ (uint16_t)(nb * 2), (uint16_t)(nb * 2 + 2), 0, strings_va + LDR_BASENAME_OFF };
    *(uint64_t *)(entry + 0x30) = m->base;
    *(uint64_t *)(entry + 0x38) = m->info.entry_rva ? m->base + m->info.entry_rva : 0;
    *(uint32_t *)(entry + 0x40) = m->info.size_of_image;
    memcpy(entry + 0x48, &uf, 16);
    memcpy(entry + 0x58, &ub, 16);
    *(uint32_t *)(entry + 0x68) = (m->is_dll ? LDR_IMAGE_DLL : 0) | (in_init_list ? LDR_NEEDS_INIT : 0);
    *(uint16_t *)(entry + 0x6c) = m->life.root || m->life.pinned ? 0xffff : (uint16_t)m->life.refs;                         /* load count */
    *(uint16_t *)(entry + 0x6e) = m->has_tls ? (uint16_t)m->tls_index : 0xffff;
    if (uwrite(p, entry_va, entry, sizeof entry) || uwrite(p, strings_va, wfull, nf * 2 + 2) ||
        uwrite(p, strings_va + LDR_BASENAME_OFF, wbase, nb * 2 + 2))
        return -1;
    if (list_append(p, p->ldr_va + 0x10, entry_va) || list_append(p, p->ldr_va + 0x20, entry_va + 0x10))
        return -1;
    if (in_init_list && !is_exe && list_append(p, p->ldr_va + 0x30, entry_va + 0x20)) return -1;
    m->published = 1;
    m->entry_va = entry_va;
    return 0;
}

#define LDR_SLOT (LDR_ENTRY_SIZE + 768)          /* entry, full path (<= 512 bytes), base name at +520 */

/* Publishes every module not yet visible to user mode: the executable first (if requested),
 * then the rest in dependency-completion order for the initialization list. */
static int32_t publish_all(process_t *p, module_t *exe)
{
    module_t *m, **order;
    unsigned n = 0, total = 0, i, j;
    uint64_t block;
    int32_t st = STATUS_SUCCESS;
    if (!p->ldr_va) {
        uint64_t l = alloc_user(p, 4096);
        uint8_t hdr[0x50];
        if (!l) return STATUS_NO_MEMORY;
        memset(hdr, 0, sizeof hdr);
        *(uint32_t *)hdr = 0x58;                             /* Length */
        *(uint32_t *)(hdr + 4) = 1;                          /* Initialized */
        uwrite(p, l, hdr, sizeof hdr);
        p->ldr_va = l;
        uwrite64(p, l + 0x10, l + 0x10); uwrite64(p, l + 0x18, l + 0x10);      /* empty circular lists */
        uwrite64(p, l + 0x20, l + 0x20); uwrite64(p, l + 0x28, l + 0x20);
        uwrite64(p, l + 0x30, l + 0x30); uwrite64(p, l + 0x38, l + 0x30);
        if (p->peb) {
            uwrite64(p, p->peb + 0x18, l);
        }
    }
    for (m = p->modules; m; m = m->next) ++total;
    order = kzalloc(sizeof *order * (total + 1));
    if (!order) return STATUS_NO_MEMORY;
    for (m = p->modules; m; m = m->next)
        if (!m->published && m->state == 1) order[n++] = m;
    if (!n) { kfree(order); return STATUS_SUCCESS; }
    /* sort ascending by init_seq (dependency completion order) */
    for (i = 0; i < n; ++i)
        for (j = i + 1; j < n; ++j)
            if (order[j]->init_seq < order[i]->init_seq) { m = order[i]; order[i] = order[j]; order[j] = m; }
    block = alloc_user(p, (uint64_t)n * LDR_SLOT + 4096);
    if (!block) { kfree(order); return STATUS_NO_MEMORY; }
    if (exe && publish_module(p, exe, block, block + LDR_ENTRY_SIZE, 0, 1)) st = STATUS_ACCESS_VIOLATION;
    else if (exe) block += LDR_SLOT;
    for (i = 0; !st && i < n; ++i) {
        if (order[i] == exe) continue;
        if (publish_module(p, order[i], block, block + LDR_ENTRY_SIZE, 1, 0)) st = STATUS_ACCESS_VIOLATION;
        block += LDR_SLOT;
    }
    kfree(order);
    return st;
}

/* ---------------------------------------------------------------- TLS */
/* Builds a ThreadLocalStoragePointer array with p->tls_slots entries: the first `keep` pointers are copied from the
 * thread's current array `old`, every TLS module whose index is >= keep gets a fresh copy of its template (the zero
 * fill stays demand-zero). Returns the array's address or 0. Loader lock held. */
static uint64_t build_tls_array(process_t *p, uint64_t old, unsigned keep)
{
    module_t *m;
    const unsigned slots = p->tls_slots;
    uint64_t total = ((uint64_t)slots * 8 + 63) & ~63ull, array, cursor;
    unsigned i;
    for (m = p->modules; m; m = m->next)
        if (m->has_tls && m->tls_index >= keep)
            total += m->tls_align + ((m->tls_end - m->tls_start + m->tls_zero + 63) & ~63ull);
    array = alloc_user(p, total);
    if (!array) return 0;
    for (i = 0; old && i < keep && i < slots; ++i) {
        uint64_t v = 0;
        if (kread(p, old + (uint64_t)i * 8, &v, 8) || kwrite64(p, array + (uint64_t)i * 8, v)) return 0;
    }
    cursor = array + (((uint64_t)slots * 8 + 63) & ~63ull);
    for (m = p->modules; m; m = m->next) {
        uint64_t len, off;
        uint8_t chunk[256];
        if (!m->has_tls || m->tls_index < keep) continue;
        cursor = (cursor + m->tls_align - 1) & ~((uint64_t)m->tls_align - 1);
        len = m->tls_end - m->tls_start;
        for (off = 0; off < len; off += sizeof chunk) {
            const uint64_t n = len - off < sizeof chunk ? len - off : sizeof chunk;
            if (kread(p, m->tls_start + off, chunk, n) || kwrite(p, cursor + off, chunk, n)) return 0;
        }
        if (kwrite64(p, array + (uint64_t)m->tls_index * 8, cursor)) return 0;
        cursor += (len + m->tls_zero + 63) & ~63ull;
    }
    return array;
}

void thread_user_tls_init(process_t *p, thread_t *t)
{
    uint64_t array;
    if (!t->teb) return;
    mutex_lock(&p->ldr_lock);
    if (p->tls_slots && (array = build_tls_array(p, 0, 0)) != 0) kwrite64(p, t->teb + 0x58, array);
    mutex_unlock(&p->ldr_lock);
}

/* After a runtime load assigned TLS indices >= old_slots: every existing thread gets an array that also covers them
 * (the old array stays valid for code that already read the pointer; it is released with the process). */
static void tls_extend_threads(process_t *p, unsigned old_slots)
{
    unsigned i;
    thread_t *t;
    if (p->tls_slots == old_slots) return;
    /* every live thread of the process, found by scheduler slot: thread ids come from the system-wide client-id
     * allocator (proc.c), so p->next_tid is not an upper bound of this process's ids (it IS the id of its newest thread) */
    for (i = 0; (t = thread_slot(i)) != 0; ++i) {
        uint64_t old = 0, array;
        if (t->proc != p || t->state == TS_FREE || t->state == TS_ZOMBIE) continue;
        if (!t->teb || kread(p, t->teb + 0x58, &old, 8)) continue;
        array = build_tls_array(p, old, old ? old_slots : 0);
        if (array) kwrite64(p, t->teb + 0x58, array);
    }
}

/* ---------------------------------------------------------------- process parameters */
static const char *const default_env[] = {
    "SystemRoot=C:\\SHZ", "SystemDrive=C:", "PATH=C:\\SHZ\\SYS64", "TEMP=C:\\TEMP", "TMP=C:\\TEMP",
    "COMPUTERNAME=SHZ-K64", "OS=Windows_NT", "PROCESSOR_ARCHITECTURE=AMD64", "NUMBER_OF_PROCESSORS=1", 0
};

static uint64_t put_wstr(process_t *p, uint64_t at, const char *s, uint16_t *len_bytes)
{
    uint16_t buf[300];
    unsigned n = 0;
    while (s[n] && n < 298) { buf[n] = (uint8_t)s[n]; ++n; }
    buf[n] = 0;
    uwrite(p, at, buf, n * 2 + 2);
    *len_bytes = (uint16_t)(n * 2);
    return at + n * 2 + 2;
}

/* Copies a caller-supplied UTF-16 string (IPC process creation) and NUL-terminates it. */
static uint64_t put_wraw(process_t *p, uint64_t at, const uint16_t *s, uint32_t chars, uint16_t *len_bytes)
{
    const uint16_t z = 0;
    uwrite(p, at, s, chars * 2ull);
    uwrite(p, at + chars * 2ull, &z, 2);
    *len_bytes = (uint16_t)(chars * 2);
    return at + chars * 2ull + 2;
}

static int build_params(process_t *p, const char *image, const char *cmdline, const char *cwd, const ldr_create_ex_t *ex,
                        const uint32_t std_h[3])
{
    const uint64_t extra = ex ? (ex->env_chars + ex->cmdline_chars + ex->cwd_chars) * 2ull : 0;
    uint64_t base = alloc_user(p, (16384 + extra + 4095) & ~4095ull), at, env_va;
    uint8_t hdr[0x400];
    struct ustr u;
    uint16_t len;
    unsigned i;
    if (!base) return -1;
    memset(hdr, 0, sizeof hdr);
    at = base + 0x400;
    /* environment block: UTF-16 "K=V\0...\0\0" */
    env_va = (at + 15) & ~15ull;
    at = env_va;
    if (ex && ex->env) {
        uwrite(p, at, ex->env, ex->env_chars * 2ull);
        at += ex->env_chars * 2ull;
    } else {
        for (i = 0; default_env[i]; ++i) {
            at = put_wstr(p, at, default_env[i], &len);
        }
        if (k64_cmdline_has("shz.k32trace")) at = put_wstr(p, at, "SHZ_K32TRACE=1", &len);   /* kernel32 k32_trace.c */
        { uint16_t z = 0; uwrite(p, at, &z, 2); at += 2; }
    }
    at = (at + 15) & ~15ull;
    *(uint32_t *)(hdr + 0x00) = 0x400;                      /* MaximumLength */
    *(uint32_t *)(hdr + 0x04) = 0x400;                      /* Length */
    *(uint32_t *)(hdr + 0x08) = 1;                          /* Flags: normalized */
    *(uint64_t *)(hdr + 0x20) = std_h[0];                   /* StandardInput  (the process's console objects) */
    *(uint64_t *)(hdr + 0x28) = std_h[1];                   /* StandardOutput */
    *(uint64_t *)(hdr + 0x30) = std_h[2];                   /* StandardError */
    if (ex && ex->use_std_handles) {
        *(uint64_t *)(hdr + 0x20) = ex->std_handles[0];
        *(uint64_t *)(hdr + 0x28) = ex->std_handles[1];
        *(uint64_t *)(hdr + 0x30) = ex->std_handles[2];
        *(uint32_t *)(hdr + 0xa4) = 0x100;                  /* WindowFlags: STARTF_USESTDHANDLES */
    }
    if (ex && ex->cwd) at = put_wraw(p, at, ex->cwd, ex->cwd_chars, &len);
    else at = put_wstr(p, at, cwd[0] ? cwd : "C:\\", &len);      /* CurrentDirectory.DosPath */
    u = (struct ustr){ len, (uint16_t)(len + 2), 0, at - len - 2 }; memcpy(hdr + 0x38, &u, 16);
    at = (at + 15) & ~15ull;
    at = put_wstr(p, at, image, &len);                      /* ImagePathName */
    u = (struct ustr){ len, (uint16_t)(len + 2), 0, at - len - 2 }; memcpy(hdr + 0x60, &u, 16);
    at = (at + 15) & ~15ull;
    if (ex && ex->cmdline) at = put_wraw(p, at, ex->cmdline, ex->cmdline_chars, &len);
    else at = put_wstr(p, at, cmdline[0] ? cmdline : image, &len);   /* CommandLine */
    u = (struct ustr){ len, (uint16_t)(len + 2), 0, at - len - 2 }; memcpy(hdr + 0x70, &u, 16);
    *(uint64_t *)(hdr + 0x80) = env_va;                     /* Environment */
    *(uint64_t *)(hdr + 0x3f0) = at - env_va;               /* EnvironmentSize (bytes, Windows 7+ field) */
    if (uwrite(p, base, hdr, sizeof hdr)) return -1;
    p->params_va = base;
    return 0;
}

/* The current directory of the process: RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath (UTF-16, ASCII kept). */
static void current_directory(process_t *p, char *out, size_t cap)
{
    struct ustr u;
    uint16_t w[PATH_CAP];
    unsigned i, n;
    out[0] = 0;
    if (!p->params_va || copy_from_user(p, &u, p->params_va + 0x38, sizeof u)) return;
    n = u.length / 2;
    if (!n || n >= PATH_CAP || n >= cap || copy_from_user(p, w, u.buffer, n * 2ull)) return;
    for (i = 0; i < n; ++i) out[i] = w[i] < 0x80 ? (char)w[i] : '?';
    out[n] = 0;
    if (n > 3 && (out[n - 1] == '\\' || out[n - 1] == '/')) out[n - 1] = 0;
}

extern kobject_t *console_object(int output);

/* ---------------------------------------------------------------- entry points */
static uint64_t ntdll_export(process_t *p, const char *sym)
{
    module_t *m = find_module(p, "ntdll.dll");
    uint64_t va = 0;
    ldr_ctx_t *c;
    if (!m || m->state != 1) return 0;
    c = kzalloc(sizeof *c);
    if (!c) return 0;
    c->p = p;
    if (resolve_export(c, m, sym, -1, 0, &va)) va = 0;
    kfree(c);
    return va;
}

uint64_t ldr_ntdll_export(process_t *p, const char *sym) { return ntdll_export(p, sym); }

static int32_t ldr_create_process_body(process_t *parent, const char *image_path, const char *cmdline, const char *cwd,
                                       const ldr_create_ex_t *ex, process_t *p, thread_t **out_thread);

int32_t ldr_create_process(process_t *parent, const char *image_path, const char *cmdline, const char *cwd,
                           process_t **out_proc, thread_t **out_thread)
{
    return ldr_create_process_ex(parent, image_path, cmdline, cwd, 0, out_proc, out_thread);
}

/* A process that failed to load never ran a thread: release it here (teardown + creation reference). */
int32_t ldr_create_process_ex(process_t *parent, const char *image_path, const char *cmdline, const char *cwd,
                              const ldr_create_ex_t *ex, process_t **out_proc, thread_t **out_thread)
{
    fsnode_t *node = fs_lookup(image_path);
    process_t *p;
    int32_t st;
    if (!node || node->is_dir) return STATUS_OBJECT_NAME_NOT_FOUND;
    p = process_create_empty("win64");
    if (!p) return STATUS_NO_MEMORY;
    mutex_init(&p->ldr_lock);
    p->parent_pid = parent ? (uint64_t)parent->pid : 0;
    if (parent) {                                                   /* evidence: which program started which */
        char shortcmd[161];
        size_t k2 = 0;
        int more;
        if (ex && ex->cmdline) {                                    /* CreateProcessW: the UTF-16 command line */
            for (; k2 < ex->cmdline_chars && k2 < 160; ++k2) shortcmd[k2] = ex->cmdline[k2] < 0x80 ? (char)ex->cmdline[k2] : '?';
            more = k2 < ex->cmdline_chars;
        } else {
            for (; cmdline[k2] && k2 < 160; ++k2) shortcmd[k2] = cmdline[k2];
            more = cmdline[k2] != 0;
        }
        shortcmd[k2] = 0;
        kprintf("K64 proc: pid %d (%s) creates pid %d: %s%s\n", parent->pid, parent->name, p->pid, shortcmd, more ? " ..." : "");
    }
    p->console_sink = parent ? parent->console_sink : 0;       /* bridged console follows the process tree */
    p->console_sink_gen = parent ? parent->console_sink_gen : 0;
    st = shz_auth_inherit(parent,p);
    if (!st) st = ldr_create_process_body(parent, image_path, cmdline, cwd, ex, p, out_thread);
    if (st) {
        process_terminate(p, st, 0);
        p->parent_pid = 0;                                          /* the creation reference is dropped right here */
        process_teardown(p);
        p->object->signaled = 1;
        ob_deref(p->object);                                        /* frees the slot (ipc_object_free) */
        return st;
    }
    shz_auth_process_ready(p);
    if (out_proc) *out_proc = p;
    return STATUS_SUCCESS;
}

static int32_t ldr_create_process_body(process_t *parent, const char *image_path, const char *cmdline, const char *cwd,
                                       const ldr_create_ex_t *ex, process_t *p, thread_t **out_thread)
{
    fsnode_t *node = fs_lookup(image_path);
    module_t *exe = 0;
    int32_t st;
    char nm[64];
    thread_t *t = 0;
    uint32_t std_h[3] = { 4, 8, 12 };
    unsigned k;
    ldr_ctx_t *c;
    c = kzalloc(sizeof *c);
    if (!c) return STATUS_NO_MEMORY;
    c->p = p;
    {
        /* short name for logs: last path component */
        const char *s = image_path, *q;
        for (q = image_path; *q; ++q) if (*q == '\\') s = q + 1;
        for (k = 0; s[k] && k < sizeof p->name - 1; ++k) p->name[k] = s[k];
        p->name[k] = 0;
    }
    (void)parent;                                   /* parent_pid and the console sink: ldr_create_process_ex */
    dir_of(image_path, c->app_dir, sizeof c->app_dir);          /* application directory: the executable's */
    scopy(c->cwd, sizeof c->cwd, cwd);
    proc_alloc_peb(p);
    if (ex && ex->prepare) {                        /* IPC process creation: inherited handles keep their values, jobs */
        st = ex->prepare(p, ex->prepare_ctx);
        if (st) goto failed;
    }
    /* Default console handles grant read/write access (GetStdHandle); inherited values remain unchanged. */
    {
        kobject_t *in = console_object(0), *outo = console_object(1), *err = console_object(1);
        if (!in || !outo || !err) { st = STATUS_NO_MEMORY; goto failed; }
        handle_insert(p, in, 0xc0000000u, &std_h[0]); ob_deref(in);
        handle_insert(p, outo, 0xc0000000u, &std_h[1]); ob_deref(outo);
        handle_insert(p, err, 0xc0000000u, &std_h[2]); ob_deref(err);
    }
    st = load_dll(c, "ntdll.dll", 1, 0, 0);
    if (st) goto report_failed;
    base_name(p->name, nm, sizeof nm);
    st = load_module_file(c, nm, node, image_path, 0, &exe);
    if (st) goto report_failed;
    if (exe->is_dll || !exe->info.entry_rva) {
        st = fail(c, STATUS_INVALID_IMAGE_FORMAT, nm, "", 0, "", exe->is_dll ? "a DLL cannot be started as a process" :
                  "the executable has no entry point");
        goto report_failed;
    }
    { module_t *root; for (root = p->modules; root; root = root->next) root->life.root = 1; }
    st = publish_all(p, exe);
    if (st) goto failed;
    if (build_params(p, image_path, cmdline, cwd, ex, std_h)) { st = STATUS_NO_MEMORY; goto failed; }
    /* PEB fields */
    {
        uint8_t peb[0x130];
        uint64_t pa = vm_lookup(p->pml4, p->peb, 0);
        memcpy(peb, (void *)p2v(pa), sizeof peb);
        *(uint64_t *)(peb + 0x10) = exe->base;                          /* ImageBaseAddress */
        *(uint64_t *)(peb + 0x18) = p->ldr_va;                          /* Ldr */
        *(uint64_t *)(peb + 0x20) = p->params_va;                       /* ProcessParameters */
        *(uint32_t *)(peb + 0xb8) = 1;                                  /* NumberOfProcessors */
        *(uint32_t *)(peb + 0x118) = 10;                                /* OSMajorVersion */
        *(uint32_t *)(peb + 0x11c) = 0;                                 /* OSMinorVersion */
        *(uint16_t *)(peb + 0x120) = 22631;                             /* OSBuildNumber: profile value, not a verified build */
        *(uint32_t *)(peb + 0x124) = 2;                                 /* VER_PLATFORM_WIN32_NT */
        *(uint32_t *)(peb + 0x128) = exe->info.subsystem;               /* ImageSubsystem */
        memcpy((void *)p2v(pa), peb, sizeof peb);
        *(uint32_t *)(p2v(pa) + 0x2c0) = 1;                             /* SessionId: the interactive session (the token's) */
    }
    p->image_base = exe->base;
    p->entry = exe->base + exe->info.entry_rva;
    p->ntdll_process_start = ntdll_export(p, "ShzProcessStart");
    p->ntdll_thread_start = ntdll_export(p, "ShzThreadStart");
    p->ntdll_exception_dispatcher = ntdll_export(p, "KiUserExceptionDispatcher");
    if (!p->ntdll_process_start || !p->ntdll_thread_start || !p->ntdll_exception_dispatcher) {
        kprintf("K64 ldr: ntdll.dll lacks the Shizuku process start exports\n");
        st = STATUS_ENTRYPOINT_NOT_FOUND;
        goto failed;
    }
    st = process_start_thread3(p, p->ntdll_process_start, p->entry, 0, exe->info.stack_reserve ? exe->info.stack_reserve : 0x100000,
                               ex && ex->suspended, &t);
    if (st) { st = STATUS_NO_MEMORY; goto failed; }
    kfree(c);
    if (out_thread) *out_thread = t;            /* the caller holds t until thread_creator_release() or proc_wait() */
    else thread_creator_release(t);
    return STATUS_SUCCESS;
report_failed:
    report(c, p->name, st);
failed:
    rollback(p, 0, 0);                          /* unmaps and forgets the modules; ldr_create_process_ex tears the rest down */
    kfree(c);
    return st;
}

/* Runtime LoadLibrary (NtLoadImage). `flags`: LoadLibraryExW flags plus LDRS_*; `dirs`: ';'-separated directories
 * (AddDllDirectory list, or SetDllDirectory's directory with LDRS_DLL_DIRECTORY), may be NULL. */
int32_t ldr_load_module_runtime(process_t *p, const char *name, uint32_t flags, const char *dirs, uint64_t *base_out)
{
    char nm[96], host[64];
    module_t *m = 0, *mark;
    unsigned tls_mark;
    int32_t st;
    int is_api, added_ref = 0;
    ldr_ctx_t *c = kzalloc(sizeof *c);
    if (!c) return STATUS_NO_MEMORY;
    if ((flags & LLF_SEARCH_DLL_LOAD_DIR) && !(name[0] == '\\' || (name[0] && name[1] == ':'))) {
        kfree(c);
        return STATUS_INVALID_PARAMETER;                    /* LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR needs an absolute path */
    }
    mutex_lock(&p->ldr_lock);
    mark = p->modules;
    tls_mark = p->tls_slots;
    c->p = p;
    c->importer = "LoadLibrary";
    c->import_dll = name;
    c->import_func = "";
    c->flags = flags;
    scopy(c->dirs, sizeof c->dirs, dirs);
    {
        module_t *exe = p->modules;
        for (; exe && exe->base != p->image_base; exe = exe->next) {}
        if (exe) scopy(c->app_dir, sizeof c->app_dir, exe->dir);
    }
    current_directory(p, c->cwd, sizeof c->cwd);
    if (has_path(name)) dir_of(name, c->load_dir, sizeof c->load_dir);
    base_name(name, nm, sizeof nm);
    st = resolve_dll_name(c, nm, host, sizeof host, &is_api);
    if (!st) {
        st = load_dll(c, is_api ? host : name, is_api, 0, &m);
        if (st && is_api) annotate_apiset(c, "LoadLibrary", nm, host);
    }
    if (!st) {
        if (m->life.refs >= 0xfffeu || shz_ldr_life_addref(&m->life, 0)) st = STATUS_NO_MEMORY;
        else added_ref = 1;
    }
    if (!st) st = publish_all(p, 0);
    if (st) {
        if (added_ref) --m->life.refs;
        report(c, nm, st);
        rollback(p, mark, tls_mark);
        mutex_unlock(&p->ldr_lock);
        kfree(c);
        return st;
    }
    { uint16_t count = m->life.root || m->life.pinned ? 0xffff : (uint16_t)m->life.refs;
      if (m->entry_va) uwrite(p, m->entry_va + 0x6c, &count, 2); }
    tls_extend_threads(p, tls_mark);
    mutex_unlock(&p->ldr_lock);
    kfree(c);
    *base_out = m->base;
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- dynamic lifetime
 * Startup images are roots. LoadLibrary/AddRef own explicit references; eager
 * imports and forwarded exports own unique graph edges. No kernel mutex spans
 * user callbacks: PREPARE reserves a set and COMMIT alone releases its images.
 * Static TLS retirement is explicitly unsupported in this first bounded port.
 */
static int module_loadcount(process_t *p, module_t *m)
{
    uint16_t count = m->life.root || m->life.pinned ? 0xffff : (uint16_t)m->life.refs;
    return m->entry_va ? uwrite(p, m->entry_va + 0x6c, &count, sizeof count) : 0;
}

static int module_lists_valid(process_t *p, module_t *m)
{
    unsigned i;
    vad_t *v = vad_find(p, m->base);
    if (!m->published || !m->entry_va || !v || v->alloc_base != m->base || v->kind == VK_VIEW) return -1;
    for (i = 0; i < 3; ++i) {
        uint64_t at = m->entry_va + i * 16, fl, bl, back;
        if (uread64(p, at, &fl) || uread64(p, at + 8, &bl) ||
            uread64(p, fl + 8, &back) || back != at || uread64(p, bl, &back) || back != at) return -1;
    }
    return 0;
}

static int module_lists_unlink(process_t *p, module_t *m)
{
    unsigned i;
    for (i = 0; i < 3; ++i) {
        uint64_t at = m->entry_va + i * 16, fl, bl;
        if (uread64(p, at, &fl) || uread64(p, at + 8, &bl) ||
            uwrite64(p, bl, fl) || uwrite64(p, fl + 8, bl) ||
            uwrite64(p, at, at) || uwrite64(p, at + 8, at)) return -1;
    }
    return 0;
}

int32_t ldr_lifetime_control(process_t *p, uint64_t op, uint64_t base, uint64_t out, uint64_t capacity)
{
    module_t *m, *root = 0;
    unsigned total = 0, count = 0, i, j, dropped = 0;
    ldr_retirement_t *tx = 0;
    shz_ldr_retire_buffer *buffer = 0;
    int32_t st = STATUS_SUCCESS;
    if (op > SHZ_LDR_PREPARE || (op == SHZ_LDR_PREPARE && capacity > SHZ_LDR_RETIRE_MAX)) return STATUS_INVALID_PARAMETER;
    mutex_lock(&p->ldr_lock);
    for (m = p->modules; m; m = m->next) { if (m->base == base) root = m; ++total; }
    if (!root || root->state != 1 || root->life.retiring) { st = STATUS_DLL_NOT_FOUND; goto done; }
    if (op != SHZ_LDR_PREPARE) {
        uint32_t refs_before = root->life.refs;
        unsigned pin_before = root->life.pinned;
        if (op == SHZ_LDR_ADDREF && root->life.refs >= 0xfffeu) { st = STATUS_NO_MEMORY; goto done; }
        if (shz_ldr_life_addref(&root->life, op == SHZ_LDR_PIN)) { st = STATUS_INVALID_PARAMETER; goto done; }
        if (module_loadcount(p, root)) {
            root->life.refs = refs_before; root->life.pinned = pin_before;
            st = STATUS_ACCESS_VIOLATION;
        }
        goto done;
    }
    if (p->ldr_retirement) { st = STATUS_NOT_SUPPORTED; goto done; } /* recursive retirement cannot duplicate callbacks */
    if (!root->life.refs && !root->life.root && !root->life.pinned) { st = STATUS_INVALID_PARAMETER; goto done; }
    if (total > SHZ_LDR_RETIRE_MAX || p->ldr_retire_sequence == UINT64_MAX) { st = STATUS_NOT_SUPPORTED; goto done; }
    tx = kzalloc(sizeof *tx + (uint64_t)total * sizeof *tx->nodes);
    buffer = kzalloc(sizeof *buffer + (uint64_t)total * sizeof *buffer->Entries);
    if (!tx || !buffer) { st = STATUS_NO_MEMORY; goto done; }
    if (root->life.refs) { --root->life.refs; dropped = 1; }
    shz_ldr_life_mark(&((module_t *)p->modules)->life);
    for (m = p->modules; m; m = m->next) {
        if (m->life.reachable || m->state != 1) continue;
        /* Existing per-thread TLS arrays and templates have shared allocation
         * ownership. Do not fabricate safe reclamation or silently pin them. */
        if (m->has_tls) { st = STATUS_NOT_SUPPORTED; goto restore; }
        if (module_lists_valid(p, m)) { st = STATUS_ACCESS_VIOLATION; goto restore; }
        { uint32_t flags;
          if (kread(p, m->entry_va + 0x68, &flags, sizeof flags)) { st = STATUS_ACCESS_VIOLATION; goto restore; }
          if (flags & 0x80000001u) { st = STATUS_NOT_SUPPORTED; goto restore; } } /* init pending or callback active */
        tx->nodes[count++] = m;
    }
    if (count > capacity) { st = STATUS_BUFFER_TOO_SMALL; goto restore; }
    for (i = 0; i < count; ++i)
        for (j = i + 1; j < count; ++j)
            if (tx->nodes[j]->init_seq > tx->nodes[i]->init_seq) { m = tx->nodes[i]; tx->nodes[i] = tx->nodes[j]; tx->nodes[j] = m; }
    tx->count = count;
    tx->owner_tid = thread_current()->tid;
    tx->token = count ? p->ldr_retire_sequence + 1 : 0;
    buffer->Token = tx->token; buffer->Count = count;
    for (i = 0; i < count; ++i) buffer->Entries[i] = tx->nodes[i]->entry_va;
    if (copy_to_user(p, out, buffer, sizeof *buffer + (uint64_t)count * sizeof *buffer->Entries)) {
        st = STATUS_ACCESS_VIOLATION; goto restore;
    }
    if (module_loadcount(p, root)) { st = STATUS_ACCESS_VIOLATION; goto restore; }
    if (count) {
        for (i = 0; i < count; ++i) { tx->nodes[i]->life.retiring = 1; tx->nodes[i]->state = 2; }
        p->ldr_retire_sequence = tx->token;
        p->ldr_retirement = tx;
        tx = 0;
    }
    goto done;
restore:
    if (dropped) ++root->life.refs;
    module_loadcount(p, root);
done:
    kfree(buffer); kfree(tx);
    mutex_unlock(&p->ldr_lock);
    return st;
}

int32_t ldr_lifetime_commit(process_t *p, uint64_t token)
{
    ldr_retirement_t *tx;
    unsigned i;
    int32_t st = STATUS_SUCCESS;
    mutex_lock(&p->ldr_lock);
    tx = p->ldr_retirement;
    if (!tx || !token || token != tx->token || tx->owner_tid != thread_current()->tid) {
        st = STATUS_INVALID_PARAMETER; goto done;
    }
    /* Callbacks may have appended unrelated modules. Revalidate actual links
     * before the first irreversible unlink; never accept caller-supplied lists. */
    for (i = 0; i < tx->count; ++i)
        if (tx->nodes[i] && module_lists_valid(p, tx->nodes[i])) { st = STATUS_ACCESS_VIOLATION; goto done; }
    for (i = 0; i < tx->count; ++i) {
        module_t *m = tx->nodes[i], **pp;
        uint64_t f, base, size = 0;
        if (!m) continue;
        base = m->base;
        if (module_lists_unlink(p, m)) { st = STATUS_ACCESS_VIOLATION; goto done; }
        st = vad_free(p, &base, &size, MEM_RELEASE);
        if (st) goto done;                  /* real failure is not an unload success */
        f = irq_save();
        for (pp = (module_t **)&p->modules; *pp && *pp != m; pp = &(*pp)->next) {}
        if (*pp) *pp = m->next;
        irq_restore(f);
        module_life_links(p);
        module_incoming_remove(p, m);
        module_edges_free(m);
        image_owner_retire(m->img);
        kfree(m);
        tx->nodes[i] = 0;
    }
    module_life_links(p);
    p->ldr_retirement = 0;
    kfree(tx);
done:
    mutex_unlock(&p->ldr_lock);
    return st;
}

uint64_t ldr_module_export(process_t *p, uint64_t base, const char *symbol, uint64_t ordinal)
{
    module_t *m;
    uint64_t va = 0;
    ldr_ctx_t *c = kzalloc(sizeof *c);
    if (!c) return 0;
    c->p = p;
    mutex_lock(&p->ldr_lock);
    for (m = p->modules; m; m = m->next)
        if (m->state == 1 && m->base == base && !resolve_export(c, m, symbol, symbol ? -1 : (int)ordinal, 0, &va))
            break;
    mutex_unlock(&p->ldr_lock);
    kfree(c);
    return m ? va : 0;
}

/* kernel32 support (sysk32_proc.c: toolhelp, GetMappedFileName, QueryFullProcessImageName): the index-th mapped module of p
 * in load order (the executable first). Returns 0 and fills the outputs, or -1 past the last module. */
int ldr_module_at(process_t *p, unsigned index, uint64_t *base, uint64_t *size, const char **name, const char **path)
{
    module_t *m;
    unsigned n = 0, want;
    for (m = p->modules; m; m = m->next)
        if (m->state == 1) ++n;
    if (index >= n) return -1;
    want = n - 1 - index;                                       /* the list is newest first */
    for (m = p->modules; m; m = m->next) {
        if (m->state != 1) continue;
        if (want-- == 0) {
            *base = m->base; *size = m->info.size_of_image; *name = m->name; *path = m->path;
            return 0;
        }
    }
    return -1;
}
