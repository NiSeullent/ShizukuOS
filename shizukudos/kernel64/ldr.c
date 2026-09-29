/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 "stage 0" PE32+ loader: maps AMD64 images into a process, applies base
 * relocations, resolves imports (including forwarders and API-set contracts), assigns TLS
 * indices and publishes a Windows-shaped loader database (PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY)
 * for the user-mode ntdll to take over. It does not depend on any user-mode DLL.
 *
 * Image parsing/validation lives in shizukudos/win64/pe_parse.c (shared with host fuzz tests).
 * Anything the loader cannot verify is rejected with an NTSTATUS; nothing is silently stubbed.
 *
 * Two mapping strategies:
 *   RAM-backed files (C:\, the initrd): every page is copied and relocated at load time (eager).
 *   Disk-backed files (D:\ ...): lazy. The parser reads the file through a kernel file view (kwin.c: only the header
 *   and directory pages it touches are read), the image's sections become committed VK_IMAGE descriptors tied to an
 *   image_map_t, and ldr_image_fault() produces each page on its first touch: its bytes are read straight from the
 *   file into a private page, base relocations of that page (and the tail of a relocation straddling in from the
 *   page before) are applied from a per-page index of the .reloc blocks, then it is mapped with the section's
 *   protection. A 334 MB DLL therefore costs the pages that are really touched. Pages are private per process
 *   (no cross-process sharing: FileAlignment 0x200 images do not have page-aligned file data anyway).
 *   The loader writes the IAT and TLS index with image_poke(), which ignores page protection like the Windows
 *   loader's temporary unprotect (an IAT inside read-only .rdata is normal for MSVC-linked images).
 * Search order for a DLL name: the directory of the importing module, the executable's directory, \SHZ\SYS64,
 * then the root of C:. A name with a path (LoadLibrary("D:\\dir\\x.dll")) is opened as given.
 */
#include "fs.h"
#include "kwin.h"
#include "../win64/pe_parse.h"

#define SYS64_DIR "\\SHZ\\SYS64\\"
#define MAX_DEPTH 24

typedef struct { uint32_t page, count; uint64_t off; } reloc_block_t;   /* one .reloc block: page RVA, entries, file offset */

typedef struct image_map {
    fsnode_t *node;                     /* the file (disk-backed) */
    kview_t *view;                      /* its kernel view (parser, relocation blocks) */
    const uint8_t *file;                /* view->base */
    uint64_t fsize;
    pe_info_t info;
    uint64_t base, delta;               /* mapped base; base - preferred */
    reloc_block_t *blocks;              /* sorted by page (relocated images only) */
    uint32_t nblocks;
    uint64_t pages_in, reloc_pages, relocs_applied, bytes_read;
    char name[48];
} image_map_t;

typedef struct module {
    struct module *next;
    char name[48];                      /* lowercase base name, e.g. "kernel32.dll" */
    char path[128];
    char dir[128];                      /* directory of the file ("D:\\chrome\\"), searched first for its imports */
    const uint8_t *file;
    uint64_t fsize;
    image_map_t *img;                   /* lazily mapped (disk-backed) image, else NULL */
    int32_t fail_status;                /* state -1: why loading failed (returned again instead of a half-loaded module) */
    pe_info_t info;
    uint64_t base;
    int state;                          /* 0 loading, 1 mapped and linked */
    int is_dll;
    int has_tls;
    uint32_t tls_index;
    uint64_t tls_start, tls_end, tls_index_va, tls_callbacks_va;
    uint32_t tls_zero;
    uint32_t init_seq;
    int published;
} module_t;

static char lower(char c) { return c >= 'A' && c <= 'Z' ? (char)(c + 32) : c; }

/* ---------------------------------------------------------------- API-set contract schema */
/* Contract name (lowercase, without version suffix match) -> hosting DLL. Only contracts whose
 * exports this system actually implements are listed; an unknown api-ms-* name fails with
 * STATUS_DLL_NOT_FOUND instead of being forwarded blindly to kernel32. */
static const struct { const char *prefix; const char *dll; } apiset_schema[] = {
    {"api-ms-win-core-synch-l1", "kernel32.dll"},
    {"api-ms-win-core-processthreads-l1", "kernel32.dll"},
    {"api-ms-win-core-libraryloader-l1", "kernel32.dll"},
    {"api-ms-win-core-memory-l1", "kernel32.dll"},
    {"api-ms-win-core-file-l1", "kernel32.dll"},
    {"api-ms-win-core-handle-l1", "kernel32.dll"},
    {"api-ms-win-core-errorhandling-l1", "kernel32.dll"},
    {"api-ms-win-core-heap-l1", "kernel32.dll"},
    {"api-ms-win-core-sysinfo-l1", "kernel32.dll"},
    {"api-ms-win-core-console-l1", "kernel32.dll"},
    {"api-ms-win-core-localization-l1", "kernel32.dll"},
    {"api-ms-win-core-timezone-l1", "kernel32.dll"},
    {"api-ms-win-core-string-l1", "kernel32.dll"},
    {"api-ms-win-core-profile-l1", "kernel32.dll"},
    {"api-ms-win-core-interlocked-l1", "kernel32.dll"},
    {"api-ms-win-core-rtlsupport-l1", "ntdll.dll"},
    {"api-ms-win-core-processenvironment-l1", "kernel32.dll"},
    /* registry / security -> advapi32.dll: entries go directly below this line (only for functions really exported) */
    {"api-ms-win-core-registry-l1", "advapi32.dll"},
    {"api-ms-win-core-registry-l2", "advapi32.dll"},
    {"api-ms-win-security-base-l1", "advapi32.dll"},
    {"api-ms-win-security-sddl-l1", "advapi32.dll"},
    {"api-ms-win-eventing-provider-l1", "advapi32.dll"},

    /* graphics / window -> user32.dll, gdi32.dll: contracts whose functions this system exports (the loader still resolves every
     * imported NAME against the DLL, so a function that is not exported fails with STATUS_ENTRYPOINT_NOT_FOUND, never a stub) */
    {"ext-ms-win-ntuser-window-l1", "user32.dll"},
    {"ext-ms-win-ntuser-message-l1", "user32.dll"},
    {"ext-ms-win-ntuser-windowclass-l1", "user32.dll"},
    {"ext-ms-win-ntuser-rectangle-ext-l1", "user32.dll"},
    {"ext-ms-win-ntuser-sysparams-ext-l1", "user32.dll"},
    {"ext-ms-win-gdi-dc-l1", "gdi32.dll"},
    {"ext-ms-win-gdi-dc-create-l1", "gdi32.dll"},
    {"ext-ms-win-gdi-draw-l1", "gdi32.dll"},
    {"ext-ms-win-gdi-font-l1", "gdi32.dll"},
    {"ext-ms-win-gdi-devcaps-l1", "gdi32.dll"},
    {"ext-ms-win-gdi-object-l1", "gdi32.dll"},
    {"ext-ms-win-gdi-render-l1", "gdi32.dll"},

    /* network -> ws2_32.dll: */

    /* everything else (ole, shell, crypto, version, ...): */
    {"api-ms-win-core-com-l1", "ole32.dll"},                    /* Co*, GUID text, task allocator: what ole32.dll really exports */
    {"api-ms-win-core-winrt-l1", "combase.dll"},                /* RoInitialize / RoUninitialize */
    {"api-ms-win-core-winrt-string-l1", "combase.dll"},         /* HSTRING */
    {"api-ms-win-core-shlwapi-legacy-l1", "shlwapi.dll"},
    {"api-ms-win-core-shlwapi-obsolete-l1", "shlwapi.dll"},
    {"api-ms-win-core-version-l1", "version.dll"},
    {"api-ms-win-mm-time-l1", "winmm.dll"},                     /* the multimedia timer API */

    {0, 0}
};

static const char *apiset_resolve(const char *name, int *is_apiset)
{
    unsigned i, n;
    *is_apiset = 0;
    if (!(name[0] == 'a' && name[1] == 'p' && name[2] == 'i' && name[3] == '-') &&
        !(name[0] == 'e' && name[1] == 'x' && name[2] == 't' && name[3] == '-'))
        return 0;
    *is_apiset = 1;
    for (i = 0; apiset_schema[i].prefix; ++i) {
        n = (unsigned)strlen(apiset_schema[i].prefix);
        if (!strncmp(name, apiset_schema[i].prefix, n) && name[n] == '-')
            return apiset_schema[i].dll;
    }
    return 0;
}

/* ---------------------------------------------------------------- module registry */
static void base_name(const char *in, char *out, size_t cap)
{
    const char *s = in, *p;
    size_t n = 0;
    int has_ext = 0;
    for (p = in; *p; ++p)
        if (*p == '\\' || *p == '/') s = p + 1;
    for (p = s; *p && n + 5 < cap; ++p) {
        out[n++] = lower(*p);
        if (*p == '.') has_ext = 1;
    }
    if (!has_ext) {
        memcpy(out + n, ".dll", 4);
        n += 4;
    }
    out[n] = 0;
}

static module_t *find_module(process_t *p, const char *name)
{
    module_t *m;
    for (m = p->modules; m; m = m->next)
        if (!strcmp(m->name, name)) return m;
    return 0;
}

/* Directory part of a path including the trailing backslash ("" when there is none). */
static void dir_of(const char *path, char *out, size_t cap)
{
    size_t k, last = 0;
    for (k = 0; path[k]; ++k) if (path[k] == '\\' || path[k] == '/') last = k + 1;
    if (last >= cap) last = 0;
    memcpy(out, path, last);
    out[last] = 0;
}

static fsnode_t *try_dir(const char *dir, const char *name, char *path, size_t cap)
{
    const size_t a = strlen(dir), b = strlen(name);
    fsnode_t *n;
    if (a + b + 1 > cap) return 0;
    memcpy(path, dir, a);
    memcpy(path + a, name, b + 1);
    n = fs_lookup(path);
    return n && !n->is_dir ? n : 0;
}

/* Search order: the importing module's directory, the executable's directory, \SHZ\SYS64, the root of C:. */
static fsnode_t *locate_file(const char *name, const char *importer_dir, const char *exe_dir, char *found_path, size_t cap)
{
    char path[256];
    fsnode_t *n = 0;
    size_t k;
    if (importer_dir && importer_dir[0]) n = try_dir(importer_dir, name, path, sizeof path);
    if (!n && exe_dir && exe_dir[0]) n = try_dir(exe_dir, name, path, sizeof path);
    if (!n) n = try_dir(SYS64_DIR, name, path, sizeof path);
    if (!n) n = try_dir("\\", name, path, sizeof path);
    if (n && found_path) {
        for (k = 0; path[k] && k + 1 < cap; ++k) found_path[k] = path[k];
        found_path[k] = 0;
    }
    return n;
}

/* ---------------------------------------------------------------- user memory helpers */
static int uwrite(process_t *p, uint64_t va, const void *src, uint64_t n) { return copy_to_user(p, va, src, n); }
static int uwrite64(process_t *p, uint64_t va, uint64_t v) { return copy_to_user(p, va, &v, 8); }
static int ipoke64(process_t *p, uint64_t va, uint64_t v) { return image_poke(p, va, &v, 8); }
static int uread64(process_t *p, uint64_t va, uint64_t *v) { return copy_from_user(p, v, va, 8); }

static uint32_t prot_from_section(uint32_t ch)
{
    const int r = (ch & PE_SCN_MEM_READ) != 0, w = (ch & PE_SCN_MEM_WRITE) != 0, x = (ch & PE_SCN_MEM_EXECUTE) != 0;
    if (x) return w ? PAGE_EXECUTE_READWRITE : (r ? PAGE_EXECUTE_READ : PAGE_EXECUTE);
    if (w) return PAGE_READWRITE;
    if (r) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

/* ---------------------------------------------------------------- lazy (file-backed) mapping */
static int block_cmp_less(const reloc_block_t *a, const reloc_block_t *b) { return a->page < b->page || (a->page == b->page && a->off < b->off); }

/* Index of the .reloc blocks (page RVA -> file offset of its entries), read through the view. */
static int32_t build_reloc_index(image_map_t *im)
{
    const pe_info_t *o = &im->info;
    uint32_t rva = o->dir_rva[5], remaining = o->dir_size[5], cap = 0, n = 0, i;
    reloc_block_t *b = 0;
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

/* Applies the relocations of block range [lo, hi) that touch the page at page_rva (page content in `pg`). */
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
    image_map_t *im = v->img;
    const uint64_t va = addr & ~(PAGE_SIZE - 1), rva = va - im->base;
    const pe_info_t *o = &im->info;
    uint64_t pa, file_off = 0, n = 0, done = 0;
    uint8_t *pg;
    unsigned i;
    if (va < im->base || rva >= o->size_of_image) return STATUS_ACCESS_VIOLATION;
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
    if (!pa) return STATUS_NO_MEMORY;
    pg = (uint8_t *)p2v(pa);
    if (n && (fs_read(im->node, file_off, pg, n, &done) || done != n)) {
        pmm_free(pa);
        kprintf("K64 ldr: %s: page rva %llx: read of %llu bytes at file offset %llx failed\n", im->name, rva, n, file_off);
        return STATUS_IN_PAGE_ERROR;
    }
    if (im->delta && im->nblocks) {
        const uint64_t before = im->relocs_applied;
        relocate_page(im, rva, pg, (uint32_t)rva);
        if (rva) relocate_page(im, rva, pg, (uint32_t)(rva - PAGE_SIZE));   /* DIR64/HIGHLOW straddling in */
        if (im->relocs_applied != before) ++im->reloc_pages;
        if (im->view->io_errors) { pmm_free(pa); return STATUS_IN_PAGE_ERROR; }
    }
    /* The reads may have blocked (volume mutex): another thread of the process may have faulted the page in, or changed
     * or freed the range (the descriptor array can even have been reallocated), so look the descriptor up again. */
    if (vm_lookup(p->pml4, va, 0)) { pmm_free(pa); return 0; }
    v = vad_find(p, va);
    if (!v || v->img != im || v->state != VAD_COMMITTED) { pmm_free(pa); return STATUS_ACCESS_VIOLATION; }
    if (vm_map(p->pml4, va, pa, prot_to_ptflags(v->prot))) { pmm_free(pa); return STATUS_NO_MEMORY; }
    ++im->pages_in;
    im->bytes_read += n;
    return 0;
}

static int32_t map_module_lazy(process_t *p, module_t *m, uint64_t base)
{
    const pe_info_t *pi = &m->info;
    image_map_t *im = m->img;
    unsigned i;
    int32_t st;
    uint64_t end;
    im->base = base;
    im->delta = base - pi->image_base;
    if (im->delta && pi->dir_rva[5] && pi->dir_size[5]) {
        st = build_reloc_index(im);
        if (st) return st;
    }
    st = vad_insert_image(p, base, pi->size_of_headers, PAGE_READONLY, base, im);
    if (st) return st;
    end = pi->size_of_headers;
    for (i = 0; i < pi->nsections; ++i) {
        pe_section_t s;
        uint64_t vlen;
        pe_get_section(m->file, pi, i, &s);
        vlen = ((uint64_t)(s.vsize ? s.vsize : s.raw_size) + 4095ull) & ~4095ull;
        if (!vlen) continue;
        st = vad_insert_image(p, base + s.rva, vlen, prot_from_section(s.characteristics), base, im);
        if (st) return st;
        if (s.rva + vlen > end) end = s.rva + vlen;
    }
    end = (end + 4095ull) & ~4095ull;
    if (end < pi->size_of_image)
        vad_insert_fixed(p, base + end, pi->size_of_image - end, VAD_RESERVED, PAGE_NOACCESS, VK_IMAGE, base);
    kprintf("K64 ldr: %s mapped lazily from %s at %llx (preferred %llx%s), %u pages in %u sections, %llu of %llu file "
            "pages read by the parser\n", m->name, m->path, base, pi->image_base, im->delta ? ", relocated per page" : "",
            pi->size_of_image / 4096, pi->nsections, im->view->resident, im->view->npages);
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- mapping */
static int32_t map_module(process_t *p, module_t *m)
{
    const pe_info_t *pi = &m->info;
    uint64_t base = pi->image_base, off, pa;
    unsigned i;
    int32_t st;
    int relocate = 0;

    if (!vad_range_is_free(p, base, pi->size_of_image)) {
        if (!(pi->dll_characteristics & PE_DLLCHAR_DYNAMIC_BASE) || !pi->dir_rva[5])
            return STATUS_CONFLICTING_ADDRESSES;             /* cannot move an image without relocations */
        {
            uint64_t sz = pi->size_of_image, b = 0;
            st = vad_alloc(p, &b, &sz, MEM_RESERVE, PAGE_READONLY, VK_IMAGE);
            if (st) return st;
            base = b;
            {
                uint64_t fb = b, fs = 0;
                vad_free(p, &fb, &fs, MEM_RELEASE);          /* only used to pick a free 64 KiB-aligned range */
            }
        }
        relocate = 1;
    }
    m->base = base;
    if (m->img) return map_module_lazy(p, m, base);

    /* headers, then each section, as separate descriptors sharing one allocation base */
    st = vad_insert_fixed(p, base, pi->size_of_headers, VAD_COMMITTED, PAGE_READONLY, VK_IMAGE, base);
    if (st) return st;
    for (off = 0; off < ((pi->size_of_headers + 4095ull) & ~4095ull); off += PAGE_SIZE) {
        uint64_t n = pi->size_of_headers - off < PAGE_SIZE ? pi->size_of_headers - off : PAGE_SIZE;
        pa = pmm_alloc();
        if (!pa || vm_map(p->pml4, base + off, pa, prot_to_ptflags(PAGE_READONLY))) return STATUS_NO_MEMORY;
        memcpy((void *)p2v(pa), m->file + off, n);
    }
    for (i = 0; i < pi->nsections; ++i) {
        pe_section_t s;
        uint64_t vlen, raw;
        uint32_t prot;
        pe_get_section(m->file, pi, i, &s);
        vlen = s.vsize ? s.vsize : s.raw_size;
        vlen = (vlen + 4095ull) & ~4095ull;
        if (!vlen) continue;
        prot = prot_from_section(s.characteristics);
        st = vad_insert_fixed(p, base + s.rva, vlen, VAD_COMMITTED, prot, VK_IMAGE, base);
        if (st) return st;
        raw = s.raw_size < (s.vsize ? s.vsize : s.raw_size) ? s.raw_size : (s.vsize ? s.vsize : s.raw_size);
        for (off = 0; off < vlen; off += PAGE_SIZE) {
            pa = pmm_alloc();
            if (!pa) return STATUS_NO_MEMORY;
            if (off < raw) {
                const uint64_t n = raw - off < PAGE_SIZE ? raw - off : PAGE_SIZE;
                memcpy((void *)p2v(pa), m->file + s.raw_off + off, n);
            }
            /* NOACCESS sections stay unmapped; their pages are released with the process. */
            if ((prot & 0xff) == PAGE_NOACCESS) { pmm_free(pa); continue; }
            if (vm_map(p->pml4, base + s.rva + off, pa, prot_to_ptflags(prot))) return STATUS_NO_MEMORY;
        }
    }
    /* padding between the last section and SizeOfImage stays reserved but inaccessible */
    {
        uint64_t end = pi->size_of_headers;
        for (i = 0; i < pi->nsections; ++i) {
            pe_section_t s;
            uint64_t e;
            pe_get_section(m->file, pi, i, &s);
            e = s.rva + (((s.vsize ? s.vsize : s.raw_size) + 4095ull) & ~4095ull);
            if (e > end) end = e;
        }
        end = (end + 4095ull) & ~4095ull;
        if (end < pi->size_of_image)
            vad_insert_fixed(p, base + end, pi->size_of_image - end, VAD_RESERVED, PAGE_NOACCESS, VK_IMAGE, base);
    }

    if (relocate) {
        struct rctx { process_t *p; uint64_t delta, base; int32_t st; } rc = { p, base - pi->image_base, base, 0 };
        int cb(void *c, uint32_t rva, unsigned type) {
            struct rctx *x = c;
            uint64_t v;
            uint64_t pa2 = vm_lookup(x->p->pml4, x->base + rva, 0);
            if (!pa2) { x->st = STATUS_INVALID_IMAGE_FORMAT; return -1; }
            if (type == 10) { memcpy(&v, (void *)p2v(pa2), 8); v += x->delta; memcpy((void *)p2v(pa2), &v, 8); }
            else { uint32_t w; memcpy(&w, (void *)p2v(pa2), 4); w += (uint32_t)x->delta; memcpy((void *)p2v(pa2), &w, 4); }
            return 0;
        }
        if (pe_walk_relocs(m->file, m->fsize, pi, cb, &rc)) return STATUS_INVALID_IMAGE_FORMAT;
    }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- exports and imports */
static int32_t load_dll(process_t *p, const char *name, int depth, module_t **out);
static int32_t load_dll_from(process_t *p, const char *name, const char *importer_dir, int depth, module_t **out);

static int32_t resolve_export(process_t *p, module_t *m, const char *sym, int ordinal, int depth, uint64_t *va)
{
    uint32_t rva;
    char fwd[128];
    int rc;
    if (depth > 8) return STATUS_ENTRYPOINT_NOT_FOUND;      /* forwarder cycle */
    rc = pe_find_export(m->file, m->fsize, &m->info, sym, ordinal, &rva, fwd, sizeof fwd);
    if (rc == PE_E_NOT_FOUND) return ordinal >= 0 ? STATUS_ORDINAL_NOT_FOUND : STATUS_ENTRYPOINT_NOT_FOUND;
    if (rc) return STATUS_INVALID_IMAGE_FORMAT;
    if (rva) {
        *va = m->base + rva;
        return STATUS_SUCCESS;
    }
    /* forwarder "DLL.Function" or "DLL.#ordinal" */
    {
        char dll[64], fn[80];
        unsigned k = 0, j = 0;
        module_t *target;
        int32_t st;
        while (fwd[k] && fwd[k] != '.' && k + 5 < sizeof dll) { dll[k] = fwd[k]; ++k; }
        if (fwd[k] != '.') return STATUS_INVALID_IMAGE_FORMAT;
        memcpy(dll + k, ".dll", 5);
        ++k;
        while (fwd[k] && j + 1 < sizeof fn) fn[j++] = fwd[k++];
        fn[j] = 0;
        {
            char nm[64];
            int is_api;
            const char *host;
            base_name(dll, nm, sizeof nm);
            host = apiset_resolve(nm, &is_api);
            if (is_api) {
                if (!host) return STATUS_DLL_NOT_FOUND;
                memcpy(nm, host, strlen(host) + 1);
            }
            st = load_dll_from(p, nm, m->dir, depth + 1, &target);
        }
        if (st) return st;
        if (fn[0] == '#') {
            int ord = 0;
            unsigned q;
            for (q = 1; fn[q]; ++q) ord = ord * 10 + (fn[q] - '0');
            return resolve_export(p, target, 0, ord, depth + 1, va);
        }
        return resolve_export(p, target, fn, -1, depth + 1, va);
    }
}

struct impctx { process_t *p; module_t *m; int depth; int32_t st; };

static int import_cb(void *c, const char *dll, const char *name, uint16_t hint, int by_ord, uint32_t iat_rva)
{
    struct impctx *x = c;
    char nm[64];
    module_t *target;
    uint64_t va;
    int is_api;
    const char *host;
    int32_t st;
    (void)hint;
    base_name(dll, nm, sizeof nm);
    host = apiset_resolve(nm, &is_api);
    if (is_api) {
        if (!host) { x->st = STATUS_DLL_NOT_FOUND; return -1; }     /* unknown contract: no blind forwarding */
        memcpy(nm, host, strlen(host) + 1);
    }
    st = load_dll_from(x->p, nm, x->m->dir, x->depth + 1, &target);
    if (st) {
        kprintf("K64 ldr: %s imports %s: cannot load it (%x)\n", x->m->name, nm, (uint32_t)st);
        x->st = st;
        return -1;
    }
    st = resolve_export(x->p, target, name, by_ord ? hint : -1, 0, &va);
    if (st) {
        kprintf("K64 ldr: %s imports %s!%s -> %x\n", x->m->name, nm, name ? name : "#ordinal", (uint32_t)st);
        x->st = st;
        return -1;
    }
    if (ipoke64(x->p, x->m->base + iat_rva, va)) { x->st = STATUS_ACCESS_VIOLATION; return -1; }
    return 0;
}

/* ---------------------------------------------------------------- loading */
static uint32_t init_counter;

static int32_t link_module(process_t *p, module_t *m, int depth)
{
    struct impctx ic = { p, m, depth, 0 };
    int rc = pe_walk_imports(m->file, m->fsize, &m->info, import_cb, &ic);
    if (rc) return ic.st ? ic.st : STATUS_INVALID_IMAGE_FORMAT;
    /* TLS directory (IMAGE_TLS_DIRECTORY64: start, end, index VA, callbacks VA, zero fill) */
    if (m->info.dir_rva[9]) {
        uint64_t off, avail;
        if (m->info.dir_size[9] < 40 || pe_rva_to_offset(m->file, m->fsize, &m->info, m->info.dir_rva[9], &off, &avail) || avail < 40)
            return STATUS_INVALID_IMAGE_FORMAT;
        {
            uint64_t v[4];
            uint32_t zero;
            uint8_t dir[36];
            if (copy_from_user(p, dir, m->base + m->info.dir_rva[9], sizeof dir)) return STATUS_INVALID_IMAGE_FORMAT;
            memcpy(v, dir, 32);
            memcpy(&zero, dir + 32, 4);
            m->tls_start = v[0]; m->tls_end = v[1]; m->tls_index_va = v[2]; m->tls_callbacks_va = v[3]; m->tls_zero = zero;
            if (m->tls_end < m->tls_start || m->tls_end - m->tls_start > (1u << 24) ||
                m->tls_start < m->base || m->tls_end > m->base + m->info.size_of_image ||
                m->tls_index_va < m->base || m->tls_index_va + 4 > m->base + m->info.size_of_image)
                return STATUS_INVALID_IMAGE_FORMAT;
            m->has_tls = 1;
            m->tls_index = p->tls_slots++;
            {
                uint32_t idx = m->tls_index;
                if (image_poke(p, m->tls_index_va, &idx, 4)) return STATUS_ACCESS_VIOLATION;
            }
        }
    }
    return STATUS_SUCCESS;
}

static int32_t load_module_file(process_t *p, const char *name, fsnode_t *node, const char *path, int depth,
                                module_t **out)
{
    module_t *m = kzalloc(sizeof *m);
    int32_t st;
    int rc;
    if (!m) return STATUS_NO_MEMORY;
    memcpy(m->name, name, strlen(name) + 1);
    {
        size_t k;
        for (k = 0; path[k] && k + 1 < sizeof m->path; ++k) m->path[k] = path[k];
    }
    dir_of(path, m->dir, sizeof m->dir);
    if (node->backing == FSB_DISK) {                            /* lazy: parse through the file view */
        kview_t *v = kview_get(node);
        if (!v) { kfree(m); return STATUS_NO_MEMORY; }
        m->img = kzalloc(sizeof *m->img);
        if (!m->img) { kfree(m); return STATUS_NO_MEMORY; }
        m->img->node = node;
        m->img->view = v;
        m->img->file = (const uint8_t *)v->base;
        m->img->fsize = node->size;
        memcpy(m->img->name, m->name, sizeof m->img->name);
        m->file = m->img->file;
    } else {
        m->file = node->data;
    }
    m->fsize = node->size;
    rc = pe_parse(m->file, m->fsize, &m->info);
    if (!rc && m->img && m->img->view->io_errors) rc = PE_E_TRUNCATED;
    if (rc) {
        const int32_t why = m->img && m->img->view->io_errors ? STATUS_IN_PAGE_ERROR : STATUS_INVALID_IMAGE_FORMAT;
        kprintf("K64 ldr: %s rejected (pe error %d)\n", name, rc);
        kfree(m->img);
        kfree(m);
        return why;
    }
    if (m->img) m->img->info = m->info;
    m->is_dll = (m->info.characteristics & PE_CHAR_DLL) != 0;
    m->state = 0;
    m->next = p->modules;
    p->modules = m;                                             /* visible while loading: circular imports terminate */
    st = map_module(p, m);
    if (!st) {
        st = link_module(p, m, depth);
        if (st) {                                               /* mapped but not linkable: give the range back */
            uint64_t b = m->base, sz = 0;
            vad_free(p, &b, &sz, MEM_RELEASE);
        }
    } else if (m->img && m->base) {                             /* a partial lazy mapping: only our own descriptors */
        vad_t *v = vad_find(p, m->base);
        uint64_t b = m->base, sz = 0;
        if (v && v->img == m->img && v->alloc_base == m->base) vad_free(p, &b, &sz, MEM_RELEASE);
    }
    if (st) {
        m->state = -1;                                          /* stays listed (circular imports saw it) but failed */
        m->fail_status = st;
        return st;
    }
    m->state = 1;
    m->init_seq = ++init_counter;
    if (out) *out = m;
    return STATUS_SUCCESS;
}

static const char *exe_dir(process_t *p)
{
    module_t *m;
    for (m = p->modules; m; m = m->next)
        if (!m->is_dll) return m->dir;                          /* the executable is the process's only non-DLL image */
    return 0;
}

static int32_t load_dll_from(process_t *p, const char *name, const char *importer_dir, int depth, module_t **out)
{
    module_t *m = find_module(p, name);
    fsnode_t *node;
    char path[256];
    if (m && m->state < 0) return m->fail_status;              /* an earlier attempt failed: same answer, no half module */
    if (m) { if (out) *out = m; return STATUS_SUCCESS; }
    if (depth > MAX_DEPTH) return STATUS_DLL_NOT_FOUND;
    node = locate_file(name, importer_dir, exe_dir(p), path, sizeof path);
    if (!node) return STATUS_DLL_NOT_FOUND;
    return load_module_file(p, name, node, path, depth, out);
}

static int32_t load_dll(process_t *p, const char *name, int depth, module_t **out)
{
    return load_dll_from(p, name, 0, depth, out);
}

/* ---------------------------------------------------------------- Windows-shaped loader database */
struct ustr { uint16_t length, maxlen; uint32_t pad; uint64_t buffer; };

#define LDR_ENTRY_SIZE 0x120
#define LDR_NEEDS_INIT 0x00000001u
#define LDR_IMAGE_DLL 0x00000004u

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
    uint16_t wfull[128], wbase[48];
    unsigned i, nf = 0, nb = 0;
    struct ustr uf, ub;
    memset(entry, 0, sizeof entry);
    for (i = 0; m->path[i] && nf < 127; ++i) wfull[nf++] = (uint8_t)m->path[i];
    for (i = 0; m->name[i] && nb < 47; ++i) wbase[nb++] = (uint8_t)m->name[i];
    uf = (struct ustr){ (uint16_t)(nf * 2), (uint16_t)(nf * 2 + 2), 0, strings_va };
    ub = (struct ustr){ (uint16_t)(nb * 2), (uint16_t)(nb * 2 + 2), 0, strings_va + 256 };
    *(uint64_t *)(entry + 0x30) = m->base;
    *(uint64_t *)(entry + 0x38) = m->info.entry_rva ? m->base + m->info.entry_rva : 0;
    *(uint32_t *)(entry + 0x40) = m->info.size_of_image;
    memcpy(entry + 0x48, &uf, 16);
    memcpy(entry + 0x58, &ub, 16);
    *(uint32_t *)(entry + 0x68) = (m->is_dll ? LDR_IMAGE_DLL : 0) | (in_init_list ? LDR_NEEDS_INIT : 0);
    *(uint16_t *)(entry + 0x6c) = 1;                         /* load count */
    *(uint16_t *)(entry + 0x6e) = m->has_tls ? (uint16_t)m->tls_index : 0xffff;
    if (uwrite(p, entry_va, entry, sizeof entry) || uwrite(p, strings_va, wfull, nf * 2 + 2) ||
        uwrite(p, strings_va + 256, wbase, nb * 2 + 2))
        return -1;
    if (list_append(p, p->ldr_va + 0x10, entry_va) || list_append(p, p->ldr_va + 0x20, entry_va + 0x10))
        return -1;
    if (in_init_list && !is_exe && list_append(p, p->ldr_va + 0x30, entry_va + 0x20)) return -1;
    m->published = 1;
    return 0;
}

/* Publishes every module not yet visible to user mode: the executable first (if requested),
 * then the rest in dependency-completion order for the initialization list. */
static int32_t publish_all(process_t *p, module_t *exe)
{
    module_t *m, *order[128];
    unsigned n = 0, i, j;
    uint64_t block;
    if (!p->ldr_va) {
        uint64_t l = alloc_user(p, 4096), init[2];
        uint8_t hdr[0x50];
        if (!l) return STATUS_NO_MEMORY;
        memset(hdr, 0, sizeof hdr);
        *(uint32_t *)hdr = 0x58;                             /* Length */
        *(uint32_t *)(hdr + 4) = 1;                          /* Initialized */
        uwrite(p, l, hdr, sizeof hdr);
        init[0] = init[1] = 0;
        p->ldr_va = l;
        uwrite64(p, l + 0x10, l + 0x10); uwrite64(p, l + 0x18, l + 0x10);      /* empty circular lists */
        uwrite64(p, l + 0x20, l + 0x20); uwrite64(p, l + 0x28, l + 0x20);
        uwrite64(p, l + 0x30, l + 0x30); uwrite64(p, l + 0x38, l + 0x30);
        if (p->peb) {
            uwrite64(p, p->peb + 0x18, l);
        }
    }
    for (m = p->modules; m; m = m->next)
        if (!m->published && m->state == 1 && n < 128) order[n++] = m;
    /* sort ascending by init_seq (dependency completion order) */
    for (i = 0; i < n; ++i)
        for (j = i + 1; j < n; ++j)
            if (order[j]->init_seq < order[i]->init_seq) { m = order[i]; order[i] = order[j]; order[j] = m; }
    block = alloc_user(p, (uint64_t)n * (LDR_ENTRY_SIZE + 512) + 4096);
    if (!block) return STATUS_NO_MEMORY;
    if (exe) {                                               /* the executable leads the load-order list */
        if (publish_module(p, exe, block, block + LDR_ENTRY_SIZE, 0, 1)) return STATUS_ACCESS_VIOLATION;
        block += LDR_ENTRY_SIZE + 512;
    }
    for (i = 0; i < n; ++i) {
        if (order[i] == exe) continue;
        if (publish_module(p, order[i], block, block + LDR_ENTRY_SIZE, 1, 0)) return STATUS_ACCESS_VIOLATION;
        block += LDR_ENTRY_SIZE + 512;
    }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- TLS for threads */
void thread_user_tls_init(process_t *p, thread_t *t)
{
    module_t *m;
    uint64_t array, cursor;
    unsigned slots = p->tls_slots;
    uint64_t total = 4096, sz;
    if (!slots || !t->teb) return;
    for (m = p->modules; m; m = m->next)
        if (m->has_tls) total += ((m->tls_end - m->tls_start + m->tls_zero) + 63) & ~63ull;
    sz = ((uint64_t)slots * 8 + total + 4095) & ~4095ull;
    array = alloc_user(p, sz);
    if (!array) return;
    cursor = array + ((uint64_t)slots * 8 + 63) / 64 * 64;
    for (m = p->modules; m; m = m->next) {
        uint64_t len, i;
        uint8_t chunk[256];
        if (!m->has_tls) continue;
        len = m->tls_end - m->tls_start;
        for (i = 0; i < len; i += sizeof chunk) {
            const uint64_t n = len - i < sizeof chunk ? len - i : sizeof chunk;
            if (copy_from_user(p, chunk, m->tls_start + i, n) || copy_to_user(p, cursor + i, chunk, n)) return;
        }
        uwrite64(p, array + (uint64_t)m->tls_index * 8, cursor);
        cursor += (len + m->tls_zero + 63) & ~63ull;
    }
    uwrite64(p, t->teb + 0x58, array);
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

static int build_params(process_t *p, const char *image, const char *cmdline, const char *cwd)
{
    uint64_t base = alloc_user(p, 16384), at, env_va;
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
    for (i = 0; default_env[i]; ++i) {
        at = put_wstr(p, at, default_env[i], &len);
    }
    { uint16_t z = 0; uwrite(p, at, &z, 2); at += 2; }
    at = (at + 15) & ~15ull;
    *(uint32_t *)(hdr + 0x00) = 0x400;                      /* MaximumLength */
    *(uint32_t *)(hdr + 0x04) = 0x400;                      /* Length */
    *(uint32_t *)(hdr + 0x08) = 1;                          /* Flags: normalized */
    *(uint64_t *)(hdr + 0x20) = 4;                          /* StandardInput  (first handle in the table) */
    *(uint64_t *)(hdr + 0x28) = 8;                          /* StandardOutput */
    *(uint64_t *)(hdr + 0x30) = 12;                         /* StandardError */
    at = put_wstr(p, at, cwd[0] ? cwd : "C:\\", &len);      /* CurrentDirectory.DosPath */
    u = (struct ustr){ len, (uint16_t)(len + 2), 0, at - len - 2 }; memcpy(hdr + 0x38, &u, 16);
    at = (at + 15) & ~15ull;
    at = put_wstr(p, at, image, &len);                      /* ImagePathName */
    u = (struct ustr){ len, (uint16_t)(len + 2), 0, at - len - 2 }; memcpy(hdr + 0x60, &u, 16);
    at = (at + 15) & ~15ull;
    at = put_wstr(p, at, cmdline[0] ? cmdline : image, &len);   /* CommandLine */
    u = (struct ustr){ len, (uint16_t)(len + 2), 0, at - len - 2 }; memcpy(hdr + 0x70, &u, 16);
    *(uint64_t *)(hdr + 0x80) = env_va;                     /* Environment */
    if (uwrite(p, base, hdr, sizeof hdr)) return -1;
    p->params_va = base;
    return 0;
}

extern kobject_t *console_object(int output);

/* ---------------------------------------------------------------- entry points */
static uint64_t ntdll_export(process_t *p, const char *sym)
{
    module_t *m = find_module(p, "ntdll.dll");
    uint64_t va = 0;
    if (!m || resolve_export(p, m, sym, -1, 0, &va)) return 0;
    return va;
}

int32_t ldr_create_process(process_t *parent, const char *image_path, const char *cmdline, const char *cwd,
                           process_t **out_proc, thread_t **out_thread)
{
    fsnode_t *node = fs_lookup(image_path);
    process_t *p;
    module_t *exe = 0;
    int32_t st;
    char nm[64];
    thread_t *t = 0;
    uint32_t h;
    unsigned k;
    if (!node || node->is_dir) return STATUS_OBJECT_NAME_NOT_FOUND;
    p = process_create_empty("win64");
    if (!p) return STATUS_NO_MEMORY;
    for (k = 0; image_path[k] && k < sizeof p->name - 1; ) { p->name[k] = image_path[k]; ++k; }
    {
        /* short name for logs: last path component */
        const char *s = image_path, *q;
        for (q = image_path; *q; ++q) if (*q == '\\') s = q + 1;
        for (k = 0; s[k] && k < sizeof p->name - 1; ++k) p->name[k] = s[k];
        p->name[k] = 0;
    }
    p->parent_pid = parent ? (uint64_t)parent->pid : 0;
    proc_alloc_peb(p);
    /* std handles occupy 4, 8 and 12 */
    {
        kobject_t *in = console_object(0), *outo = console_object(1), *err = console_object(1);
        if (!in || !outo || !err) return STATUS_NO_MEMORY;
        handle_insert(p, in, 0x80000000u, &h); ob_deref(in);
        handle_insert(p, outo, 0x40000000u, &h); ob_deref(outo);
        handle_insert(p, err, 0x40000000u, &h); ob_deref(err);
    }
    st = load_dll(p, "ntdll.dll", 0, 0);
    if (st) { kprintf("K64 ldr: cannot load ntdll.dll (%x)\n", (uint32_t)st); return st; }
    base_name(p->name, nm, sizeof nm);
    st = load_module_file(p, nm, node, image_path, 0, &exe);
    if (st) { kprintf("K64 ldr: %s failed to load (%x)\n", image_path, (uint32_t)st); return st; }
    if (exe->is_dll) return STATUS_INVALID_IMAGE_FORMAT;
    if (!exe->info.entry_rva) return STATUS_INVALID_IMAGE_FORMAT;
    st = publish_all(p, exe);
    if (st) return st;
    if (build_params(p, image_path, cmdline, cwd)) return STATUS_NO_MEMORY;
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
    }
    p->image_base = exe->base;
    p->entry = exe->base + exe->info.entry_rva;
    p->ntdll_process_start = ntdll_export(p, "ShzProcessStart");
    p->ntdll_thread_start = ntdll_export(p, "ShzThreadStart");
    p->ntdll_exception_dispatcher = ntdll_export(p, "KiUserExceptionDispatcher");
    if (!p->ntdll_process_start || !p->ntdll_thread_start || !p->ntdll_exception_dispatcher) {
        kprintf("K64 ldr: ntdll.dll lacks the Shizuku process start exports\n");
        return STATUS_ENTRYPOINT_NOT_FOUND;
    }
    st = process_start_thread2(p, p->ntdll_process_start, p->entry, 0, exe->info.stack_reserve ? exe->info.stack_reserve : 0x100000, &t);
    if (st) return STATUS_NO_MEMORY;
    if (out_proc) *out_proc = p;
    if (out_thread) *out_thread = t;
    return STATUS_SUCCESS;
}

int32_t ldr_load_module_runtime(process_t *p, const char *name, uint64_t *base_out)
{
    char nm[64];
    module_t *m;
    int32_t st;
    int is_api;
    const char *host, *q;
    int has_path = 0;
    for (q = name; *q; ++q) if (*q == '\\' || *q == '/' || *q == ':') has_path = 1;
    base_name(name, nm, sizeof nm);
    host = apiset_resolve(nm, &is_api);
    if (is_api) {
        if (!host) return STATUS_DLL_NOT_FOUND;
        memcpy(nm, host, strlen(host) + 1);
    }
    if (has_path && !is_api && !find_module(p, nm)) {           /* LoadLibrary("D:\\dir\\x.dll"): that file */
        fsnode_t *node = fs_lookup(name);
        char path[256];
        size_t k;
        if (!node || node->is_dir) return STATUS_DLL_NOT_FOUND;
        for (k = 0; name[k] && k + 1 < sizeof path; ++k) path[k] = name[k];
        path[k] = 0;
        st = load_module_file(p, nm, node, path, 0, &m);
        if (st) kprintf("K64 ldr: LoadLibrary %s failed (%x)\n", name, (uint32_t)st);
    } else {
        st = load_dll(p, nm, 0, &m);
    }
    if (st) return st;
    st = publish_all(p, 0);
    if (st) return st;
    *base_out = m->base;
    return STATUS_SUCCESS;
}

uint64_t ldr_module_export(process_t *p, uint64_t base, const char *symbol, uint64_t ordinal)
{
    module_t *m;
    uint64_t va = 0;
    for (m = p->modules; m; m = m->next)
        if (m->state == 1 && m->base == base && !resolve_export(p, m, symbol, symbol ? -1 : (int)ordinal, 0, &va))
            return va;
    return 0;
}

/* ---------------------------------------------------------------- teardown */
void ldr_release_modules(process_t *p)
{
    module_t *m = p->modules, *next;
    for (; m; m = next) {
        next = m->next;
        if (m->img) {
            kprintf("K64 ldr: %s (pid %d): %llu of %u image pages were made resident (%llu bytes read, %llu relocated "
                    "pages, %llu fixups); file view %llu of %llu pages\n", m->name, p->pid, m->img->pages_in,
                    m->info.size_of_image / 4096, m->img->bytes_read, m->img->reloc_pages, m->img->relocs_applied,
                    m->img->view->resident, m->img->view->npages);
            kfree(m->img->blocks);
            kfree(m->img);
        }
        kfree(m);
    }
    p->modules = 0;
}
