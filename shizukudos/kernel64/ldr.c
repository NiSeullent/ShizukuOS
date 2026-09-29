/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 "stage 0" PE32+ loader: maps AMD64 images into a process, applies base
 * relocations, resolves imports (including forwarders and API-set contracts), assigns TLS
 * indices and publishes a Windows-shaped loader database (PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY)
 * for the user-mode ntdll to take over. It does not depend on any user-mode DLL.
 *
 * Image parsing/validation lives in shizukudos/win64/pe_parse.c (shared with host fuzz tests).
 * API-set contracts resolve through the generated table of kernel64/apiset.c (source: apiset_contracts.txt).
 * Anything the loader cannot verify is rejected with an NTSTATUS; nothing is silently stubbed.
 *
 * Diagnostics: a load that fails prints exactly ONE line,
 *   K64 ldr: <requested image> not loaded: <image> needs <dll>[ = <contract> -> <host>]!<function>: <reason> [<status>]
 * naming the image whose import failed (the deepest one), the DLL it depends on and the missing function or ordinal.
 * Modules mapped by a failed attempt are unmapped again, so a later attempt starts from a clean state.
 */
#include "fs.h"
#include "apiset.h"
#include "../win64/pe_parse.h"

#define SYS64_DIR "\\SHZ\\SYS64\\"
#define MAX_DEPTH 24

typedef struct module {
    struct module *next;
    char name[64];                      /* lowercase base name, e.g. "kernel32.dll" */
    char path[160];
    const uint8_t *file;
    uint64_t fsize;
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

static fsnode_t *locate_file(const char *name, char *found_path, size_t cap)
{
    char path[160];
    fsnode_t *n;
    size_t k;
    /* search order: system directory, then the root (application directories are searched by the caller) */
    memcpy(path, SYS64_DIR, sizeof SYS64_DIR);
    k = strlen(SYS64_DIR);
    if (k + strlen(name) + 1 > sizeof path) return 0;
    memcpy(path + k, name, strlen(name) + 1);
    n = fs_lookup(path);
    if (!n) {
        path[0] = '\\';
        memcpy(path + 1, name, strlen(name) + 1);
        n = fs_lookup(path);
    }
    if (n && found_path) {
        for (k = 0; path[k] && k + 1 < cap; ++k) found_path[k] = path[k];
        found_path[k] = 0;
    }
    return n && !n->is_dir ? n : 0;
}

/* ---------------------------------------------------------------- user memory helpers */
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
static int32_t load_dll(ldr_ctx_t *c, const char *name, int depth, module_t **out);

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
        while (fwd[k] && fwd[k] != '.' && k + 5 < sizeof dll) { dll[k] = fwd[k]; ++k; }
        if (fwd[k] != '.' || !k) return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, fwd, "malformed forwarder");
        dll[k] = 0;
        ++k;
        while (fwd[k] && j + 1 < sizeof fn) fn[j++] = fwd[k++];
        fn[j] = 0;
        base_name(dll, nm, sizeof nm);
        st = resolve_dll_name(c, nm, host, sizeof host, &is_api);
        if (st) return st;
        st = load_dll(c, host, depth + 1, &target);
        if (st) return st;
        if (fn[0] == '#') {
            int ord = 0;
            unsigned q;
            for (q = 1; fn[q] >= '0' && fn[q] <= '9' && ord < 65536; ++q) ord = ord * 10 + (fn[q] - '0');
            if (fn[q] || q == 1) return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, fwd, "malformed forwarder");
            return resolve_export(c, target, 0, ord, depth + 1, va);
        }
        return resolve_export(c, target, fn, -1, depth + 1, va);
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
        st = load_dll(c, host, x->depth + 1, &target);
        if (!st) {
            /* restore the importer: loading `target` walked its own imports */
            c->importer = x->m->name;
            c->import_dll = dll;
            c->import_func = by_ord ? 0 : name;
            fmt_dec(c->import_ord, sizeof c->import_ord, "#", hint);
            st = resolve_export(c, target, name, by_ord ? hint : -1, 0, &va);
        }
        if (st && is_api) annotate_apiset(c, x->m->name, dll, host);
    }
    if (st) { x->st = st; return -1; }
    if (uwrite64(c->p, x->m->base + iat_rva, va)) { x->st = fail(c, STATUS_ACCESS_VIOLATION, x->m->name, dll, 0, 0, "IAT not writable"); return -1; }
    return 0;
}

/* ---------------------------------------------------------------- loading */
static uint32_t init_counter;

static int32_t link_module(ldr_ctx_t *c, module_t *m, int depth)
{
    process_t *p = c->p;
    struct impctx ic = { c, m, depth, 0 };
    int rc = pe_walk_imports(m->file, m->fsize, &m->info, import_cb, &ic);
    if (rc) return ic.st ? ic.st : fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, "", "malformed import directory");
    /* TLS directory (IMAGE_TLS_DIRECTORY64: start, end, index VA, callbacks VA, zero fill) */
    if (m->info.dir_rva[9]) {
        uint64_t off, avail;
        if (m->info.dir_size[9] < 40 || pe_rva_to_offset(m->file, m->fsize, &m->info, m->info.dir_rva[9], &off, &avail) || avail < 40)
            return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, "", "malformed TLS directory");
        {
            uint64_t v[4];
            uint32_t zero;
            uint64_t pa = vm_lookup(p->pml4, m->base + m->info.dir_rva[9], 0);
            if (!pa) return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, "", "TLS directory not mapped");
            memcpy(v, (void *)p2v(pa), 32);
            memcpy(&zero, (void *)p2v(pa + 32), 4);
            m->tls_start = v[0]; m->tls_end = v[1]; m->tls_index_va = v[2]; m->tls_callbacks_va = v[3]; m->tls_zero = zero;
            if (m->tls_end < m->tls_start || m->tls_end - m->tls_start > (1u << 24) ||
                m->tls_start < m->base || m->tls_end > m->base + m->info.size_of_image ||
                m->tls_index_va < m->base || m->tls_index_va + 4 > m->base + m->info.size_of_image)
                return fail(c, STATUS_INVALID_IMAGE_FORMAT, m->name, "", 0, "", "TLS directory out of the image");
            m->has_tls = 1;
            m->tls_index = p->tls_slots++;
            {
                uint32_t idx = m->tls_index;
                if (uwrite(p, m->tls_index_va, &idx, 4)) return fail(c, STATUS_ACCESS_VIOLATION, m->name, "", 0, "", "TLS index not writable");
            }
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
    if (!m) return fail(c, STATUS_NO_MEMORY, name, "", 0, "", "out of kernel memory");
    scopy(m->name, sizeof m->name, name);
    scopy(m->path, sizeof m->path, path);
    m->file = node->data;
    m->fsize = node->size;
    rc = pe_parse(m->file, m->fsize, &m->info);
    if (rc) {
        char why[48];
        fmt_dec(why, sizeof why, "not a valid AMD64 PE32+ image (pe error -", (uint64_t)-rc);
        sappend(why, sizeof why, ")");
        kfree(m);
        return fail(c, STATUS_INVALID_IMAGE_FORMAT, name, "", 0, "", why);
    }
    m->is_dll = (m->info.characteristics & PE_CHAR_DLL) != 0;
    m->state = 0;
    m->next = p->modules;
    p->modules = m;                                             /* visible while loading: circular imports terminate */
    st = map_module(p, m);
    if (st) return fail(c, st, name, "", 0, "", st == STATUS_CONFLICTING_ADDRESSES ? "fixed-base image and its range is occupied" :
                        "cannot map the image");
    st = link_module(c, m, depth);
    if (st) return st;
    m->state = 1;
    m->init_seq = ++init_counter;
    if (out) *out = m;
    return STATUS_SUCCESS;
}

static int32_t load_dll(ldr_ctx_t *c, const char *name, int depth, module_t **out)
{
    module_t *m = find_module(c->p, name);
    fsnode_t *node;
    char path[160];
    if (m) { if (out) *out = m; return STATUS_SUCCESS; }
    if (depth > MAX_DEPTH) return fail(c, STATUS_DLL_NOT_FOUND, 0, name, 0, 0, "import nesting deeper than 24 levels");
    node = locate_file(name, path, sizeof path);
    if (!node) return fail(c, STATUS_DLL_NOT_FOUND, 0, name, 0, 0, "DLL not found");
    return load_module_file(c, name, node, path, depth, out);
}

/* Unmaps and forgets every module added after `mark` (the head of the list when the failed request started). */
static void rollback(process_t *p, module_t *mark, unsigned tls_mark)
{
    while (p->modules && p->modules != mark) {
        module_t *m = p->modules;
        p->modules = m->next;
        if (m->base) {
            uint64_t b = m->base, sz = 0;
            vad_free(p, &b, &sz, MEM_RELEASE);
        }
        kfree(m);
    }
    p->tls_slots = tls_mark;
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
    uint16_t wfull[160], wbase[64];
    unsigned i, nf = 0, nb = 0;
    struct ustr uf, ub;
    memset(entry, 0, sizeof entry);
    for (i = 0; m->path[i] && nf < 159; ++i) wfull[nf++] = (uint8_t)m->path[i];
    for (i = 0; m->name[i] && nb < 63; ++i) wbase[nb++] = (uint8_t)m->name[i];
    uf = (struct ustr){ (uint16_t)(nf * 2), (uint16_t)(nf * 2 + 2), 0, strings_va };
    ub = (struct ustr){ (uint16_t)(nb * 2), (uint16_t)(nb * 2 + 2), 0, strings_va + 336 };
    *(uint64_t *)(entry + 0x30) = m->base;
    *(uint64_t *)(entry + 0x38) = m->info.entry_rva ? m->base + m->info.entry_rva : 0;
    *(uint32_t *)(entry + 0x40) = m->info.size_of_image;
    memcpy(entry + 0x48, &uf, 16);
    memcpy(entry + 0x58, &ub, 16);
    *(uint32_t *)(entry + 0x68) = (m->is_dll ? LDR_IMAGE_DLL : 0) | (in_init_list ? LDR_NEEDS_INIT : 0);
    *(uint16_t *)(entry + 0x6c) = 1;                         /* load count */
    *(uint16_t *)(entry + 0x6e) = m->has_tls ? (uint16_t)m->tls_index : 0xffff;
    if (uwrite(p, entry_va, entry, sizeof entry) || uwrite(p, strings_va, wfull, nf * 2 + 2) ||
        uwrite(p, strings_va + 336, wbase, nb * 2 + 2))
        return -1;
    if (list_append(p, p->ldr_va + 0x10, entry_va) || list_append(p, p->ldr_va + 0x20, entry_va + 0x10))
        return -1;
    if (in_init_list && !is_exe && list_append(p, p->ldr_va + 0x30, entry_va + 0x20)) return -1;
    m->published = 1;
    return 0;
}

#define LDR_SLOT (LDR_ENTRY_SIZE + 512)

/* Publishes every module not yet visible to user mode: the executable first (if requested),
 * then the rest in dependency-completion order for the initialization list. */
static int32_t publish_all(process_t *p, module_t *exe)
{
    module_t *m, *order[128];
    unsigned n = 0, i, j;
    uint64_t block;
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
    for (m = p->modules; m; m = m->next)
        if (!m->published && m->state == 1 && n < 128) order[n++] = m;
    /* sort ascending by init_seq (dependency completion order) */
    for (i = 0; i < n; ++i)
        for (j = i + 1; j < n; ++j)
            if (order[j]->init_seq < order[i]->init_seq) { m = order[i]; order[i] = order[j]; order[j] = m; }
    block = alloc_user(p, (uint64_t)n * LDR_SLOT + 4096);
    if (!block) return STATUS_NO_MEMORY;
    if (exe) {                                               /* the executable leads the load-order list */
        if (publish_module(p, exe, block, block + LDR_ENTRY_SIZE, 0, 1)) return STATUS_ACCESS_VIOLATION;
        block += LDR_SLOT;
    }
    for (i = 0; i < n; ++i) {
        if (order[i] == exe) continue;
        if (publish_module(p, order[i], block, block + LDR_ENTRY_SIZE, 1, 0)) return STATUS_ACCESS_VIOLATION;
        block += LDR_SLOT;
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
    ldr_ctx_t c;
    memset(&c, 0, sizeof c);
    c.p = p;
    if (!m || resolve_export(&c, m, sym, -1, 0, &va)) return 0;
    return va;
}

/* Frees a process whose creation failed before any thread ran (its address space, VADs, handles, modules). */
static void destroy_unstarted(process_t *p)
{
    rollback(p, 0, 0);
    handles_close_all(p);
    vm_free_space(p->pml4);
    vad_destroy(p);
    kfree(p->handles);
    ob_deref(p->object);
    p->used = 0;
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
    ldr_ctx_t *c;
    if (!node || node->is_dir) return STATUS_OBJECT_NAME_NOT_FOUND;
    c = kzalloc(sizeof *c);
    if (!c) return STATUS_NO_MEMORY;
    p = process_create_empty("win64");
    if (!p) { kfree(c); return STATUS_NO_MEMORY; }
    c->p = p;
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
        if (!in || !outo || !err) { st = STATUS_NO_MEMORY; goto failed; }
        handle_insert(p, in, 0x80000000u, &h); ob_deref(in);
        handle_insert(p, outo, 0x40000000u, &h); ob_deref(outo);
        handle_insert(p, err, 0x40000000u, &h); ob_deref(err);
    }
    st = load_dll(c, "ntdll.dll", 0, 0);
    if (st) goto report_failed;
    base_name(p->name, nm, sizeof nm);
    st = load_module_file(c, nm, node, image_path, 0, &exe);
    if (st) goto report_failed;
    if (exe->is_dll || !exe->info.entry_rva) {
        st = fail(c, STATUS_INVALID_IMAGE_FORMAT, nm, "", 0, "", exe->is_dll ? "a DLL cannot be started as a process" :
                  "the executable has no entry point");
        goto report_failed;
    }
    st = publish_all(p, exe);
    if (st) goto failed;
    if (build_params(p, image_path, cmdline, cwd)) { st = STATUS_NO_MEMORY; goto failed; }
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
        st = STATUS_ENTRYPOINT_NOT_FOUND;
        goto failed;
    }
    st = process_start_thread2(p, p->ntdll_process_start, p->entry, 0, exe->info.stack_reserve ? exe->info.stack_reserve : 0x100000, &t);
    if (st) { st = STATUS_NO_MEMORY; goto failed; }
    kfree(c);
    if (out_proc) *out_proc = p;
    if (out_thread) *out_thread = t;
    return STATUS_SUCCESS;
report_failed:
    report(c, p->name, st);
failed:
    destroy_unstarted(p);
    kfree(c);
    return st;
}

int32_t ldr_load_module_runtime(process_t *p, const char *name, uint64_t *base_out)
{
    char nm[96], host[64];
    module_t *m, *mark = p->modules;
    const unsigned tls_mark = p->tls_slots;
    int32_t st;
    int is_api;
    ldr_ctx_t *c = kzalloc(sizeof *c);
    if (!c) return STATUS_NO_MEMORY;
    c->p = p;
    c->importer = "LoadLibrary";
    c->import_dll = name;
    c->import_func = "";
    base_name(name, nm, sizeof nm);
    st = resolve_dll_name(c, nm, host, sizeof host, &is_api);
    if (!st) {
        st = load_dll(c, host, 0, &m);
        if (st && is_api) annotate_apiset(c, "LoadLibrary", nm, host);
    }
    if (!st) st = publish_all(p, 0);
    if (st) {
        report(c, nm, st);
        rollback(p, mark, tls_mark);
        kfree(c);
        return st;
    }
    kfree(c);
    *base_out = m->base;
    return STATUS_SUCCESS;
}

uint64_t ldr_module_export(process_t *p, uint64_t base, const char *symbol, uint64_t ordinal)
{
    module_t *m;
    uint64_t va = 0;
    ldr_ctx_t c;
    memset(&c, 0, sizeof c);
    c.p = p;
    for (m = p->modules; m; m = m->next)
        if (m->base == base && !resolve_export(&c, m, symbol, symbol ? -1 : (int)ordinal, 0, &va))
            return va;
    return 0;
}
