/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: kernel image loader. Loads an unmodified Windows x64 .sys
 * (PE32+, Machine AMD64) at a kernel virtual address, applies base relocations, resolves its
 * ntoskrnl.exe / hal.dll imports against the provider export tables and calls
 * DriverEntry(DriverObject, RegistryPath). The PE parsing/validation is the same overflow-safe
 * pe_parse.c the host fuzz tests hammer; anything it cannot verify is rejected, never stubbed.
 */
#include "ntdrv.h"
#include "fs.h"
#include "../win64/pe_parse.h"

extern NTSTATUS NTAPI ntdrv_default_dispatch(DEVICE_OBJECT *dev, IRP *irp);   /* ntdrv_io.c */

static ntdrv_driver_t *driver_list;
static uint64_t va_cursor = NTDRV_VA_BASE;
static ntdrv_driver_t *current_driver;

ntdrv_driver_t *ntdrv_current_driver(void) { return current_driver; }
void ntdrv_set_current_driver(ntdrv_driver_t *d) { current_driver = d; }

uint64_t ntdrv_alloc_image_va(uint64_t bytes)
{
    uint64_t va = va_cursor;
    bytes = (bytes + 0xffffull) & ~0xffffull;                 /* 64 KiB granularity, like Windows image bases */
    if (va + bytes > NTDRV_VA_END)
        return 0;
    va_cursor += bytes;
    return va;
}

/* ---- mapping ---- */
static uint32_t sect_ptflags(uint32_t ch)
{
    /* Bring-up host maps every image page writable (relocations and IAT patch happen in
     * place); execute permission (NX cleared) is granted to code sections only. */
    uint32_t f = PT_W;
    if (!(ch & PE_SCN_MEM_EXECUTE))
        f |= PT_NX;
    return f;
}

static int32_t map_image(const uint8_t *file, uint64_t size, const pe_info_t *pi, uint64_t base)
{
    uint64_t off, pa;
    unsigned i;
    /* headers */
    for (off = 0; off < ((pi->size_of_headers + 4095ull) & ~4095ull); off += PAGE_SIZE) {
        pa = pmm_alloc();
        if (!pa || vm_map(kernel_pml4(), base + off, pa, PT_W | PT_NX))
            return STATUS_NO_MEMORY;
        {
            uint64_t n = pi->size_of_headers - off;
            if (n > PAGE_SIZE) n = PAGE_SIZE;
            if (off < pi->size_of_headers)
                memcpy((void *)(base + off), file + off, n);
        }
    }
    for (i = 0; i < pi->nsections; ++i) {
        pe_section_t s;
        uint64_t vlen, raw;
        pe_get_section(file, pi, i, &s);
        vlen = ((s.vsize ? s.vsize : s.raw_size) + 4095ull) & ~4095ull;
        if (!vlen) continue;
        if ((uint64_t)s.rva + vlen > ((pi->size_of_image + 4095ull) & ~4095ull))
            return STATUS_INVALID_IMAGE_FORMAT;        /* a section (VirtualSize 0: its raw size) must fit the image slice */
        raw = s.raw_size < (s.vsize ? s.vsize : s.raw_size) ? s.raw_size : (s.vsize ? s.vsize : s.raw_size);
        for (off = 0; off < vlen; off += PAGE_SIZE) {
            pa = pmm_alloc();
            if (!pa || vm_map(kernel_pml4(), base + s.rva + off, pa, sect_ptflags(s.characteristics)))
                return STATUS_NO_MEMORY;
            if (off < raw) {
                uint64_t n = raw - off < PAGE_SIZE ? raw - off : PAGE_SIZE;
                if (s.raw_off + off + n <= size)
                    memcpy((void *)(base + s.rva + off), file + s.raw_off + off, n);
            }
        }
    }
    /* Every page of the image has to exist: relocation targets, IAT slots and export tables are only checked against
     * SizeOfImage, and a gap between sections or the tail past the last section must read as zero, not fault. */
    for (off = 0; off < ((pi->size_of_image + 4095ull) & ~4095ull); off += PAGE_SIZE)
        if (!vm_lookup(kernel_pml4(), base + off, 0)) {
            pa = pmm_alloc();
            if (!pa || vm_map(kernel_pml4(), base + off, pa, PT_W | PT_NX)) return STATUS_NO_MEMORY;
        }
    return STATUS_SUCCESS;
}

struct rctx { uint64_t delta, base; int32_t st; };
static int reloc_cb(void *c, uint32_t rva, unsigned type)
{
    struct rctx *x = c;
    if (type == 10) { uint64_t v; memcpy(&v, (void *)(x->base + rva), 8); v += x->delta; memcpy((void *)(x->base + rva), &v, 8); }
    else if (type == 3) { uint32_t v; memcpy(&v, (void *)(x->base + rva), 4); v += (uint32_t)x->delta; memcpy((void *)(x->base + rva), &v, 4); }
    else if (type == 0) { /* ABSOLUTE padding */ }
    else { x->st = STATUS_INVALID_IMAGE_FORMAT; return -1; }
    return 0;
}

/* ---- export drivers (an image another image imports from) ---- */
static int ci_eq(const char *a, const char *b)
{
    for (; *a && *b; ++a, ++b) {
        char ca = *a >= 'A' && *a <= 'Z' ? (char)(*a + 32) : *a, cb = *b >= 'A' && *b <= 'Z' ? (char)(*b + 32) : *b;
        if (ca != cb) return 0;
    }
    return *a == *b;
}
static int is_kernel_module(const char *dll)
{
    return ci_eq(dll, "ntoskrnl.exe") || ci_eq(dll, "ntkrnlpa.exe") || ci_eq(dll, "ntkrnlmp.exe") || ci_eq(dll, "hal.dll");
}
/* "ndis.sys" -> "ndis": the service/record name of an imported module is its file name without the extension */
static void module_service(const char *dll, char *out, unsigned cap)
{
    unsigned i;
    for (i = 0; dll[i] && dll[i] != '.' && i + 1 < cap; ++i) out[i] = dll[i];
    out[i] = 0;
}

ntdrv_driver_t *ntdrv_find_module(const char *dllname)
{
    char svc[64];
    ntdrv_driver_t *d;
    module_service(dllname, svc, sizeof svc);
    for (d = driver_list; d; d = d->next)
        if (d->started && ci_eq(d->name, svc)) return d;
    return 0;
}

/* Symbol lookup in a mapped image's export directory (IMAGE_EXPORT_DIRECTORY at export_rva: 40 bytes, then the
 * address/name/ordinal tables). Every RVA is bounds-checked against the image; forwarders are not supported. */
void *ntdrv_module_export(ntdrv_driver_t *m, const char *symbol)
{
    const uint8_t *base = (const uint8_t *)m->image_base;
    const uint32_t size = (uint32_t)m->image_size;
    const uint32_t *ed;
    uint32_t nfuncs, nnames, funcs, names, ords, i;
    if (!m->export_rva || m->export_rva + 40 > size) return 0;
    ed = (const uint32_t *)(base + m->export_rva);
    nfuncs = ed[5]; nnames = ed[6]; funcs = ed[7]; names = ed[8]; ords = ed[9];
    if ((uint64_t)names + 4ull * nnames > size || (uint64_t)ords + 2ull * nnames > size || (uint64_t)funcs + 4ull * nfuncs > size)
        return 0;
    for (i = 0; i < nnames; ++i) {
        const uint32_t nrva = ((const uint32_t *)(base + names))[i];
        const uint16_t ord = ((const uint16_t *)(base + ords))[i];
        uint32_t frva, k;
        if (nrva >= size) continue;
        for (k = 0; nrva + k < size && symbol[k] && base[nrva + k] == (uint8_t)symbol[k]; ++k) {}
        if (symbol[k] || nrva + k >= size || base[nrva + k]) continue;
        if (ord >= nfuncs) return 0;
        frva = ((const uint32_t *)(base + funcs))[ord];
        if (!frva || frva >= size) return 0;
        if (frva >= m->export_rva && frva < m->export_rva + m->export_size) {
            kprintf("K64 ntdrv: %s!%s is a forwarder (unsupported)\n", m->name, symbol);
            return 0;
        }
        return (void *)(base + frva);
    }
    return 0;
}

struct ictx {
    uint64_t base;
    unsigned unresolved;
    const char *service;
    ntdrv_driver_t *deps[16];           /* modules resolved against so far */
    unsigned ndeps;
    char missing[8][64];                /* imported modules that could not be loaded (reported once, never retried) */
    unsigned nmissing;
};

/* The module an import names: a kernel module (NULL, resolved from the provider tables), an already loaded image, or
 * \SHZ\SYS64\DRIVERS\<dll> loaded now on this image's behalf (the way a boot-start dependency is present on
 * Windows before the drivers that import it). */
/* Images currently being loaded (a stack, innermost last): an import cycle (A imports B imports A) or a runaway chain
 * is refused instead of recursing until the 32 KiB kernel stack is gone. */
#define NTDRV_MAX_LOAD_DEPTH 6
static const char *loading[NTDRV_MAX_LOAD_DEPTH];
static unsigned nloading;

static void note_missing(struct ictx *x, const char *key)
{
    unsigned i;
    if (x->nmissing >= 8) return;
    for (i = 0; key[i] && i + 1 < sizeof x->missing[0]; ++i) x->missing[x->nmissing][i] = key[i];
    x->missing[x->nmissing][i] = 0;
    ++x->nmissing;
}

static ntdrv_driver_t *dep_module(struct ictx *x, const char *dll, int *missing)
{
    ntdrv_driver_t *m;
    unsigned i;
    char path[96] = "\\SHZ\\SYS64\\DRIVERS\\", svc[64], key[64];
    fsnode_t *n;
    int32_t st;
    *missing = 0;
    for (i = 0; dll[i] && i + 1 < sizeof key; ++i) key[i] = dll[i];          /* the cache compares the same truncation it stores */
    key[i] = 0;
    for (i = 0; i < x->ndeps; ++i)
        if (ntdrv_find_module(dll) == x->deps[i]) return x->deps[i];
    for (i = 0; i < x->nmissing; ++i)
        if (ci_eq(x->missing[i], key)) { *missing = 1; return 0; }
    if (x->nmissing >= 8) { *missing = 1; return 0; }                      /* cache full: fail without loading again */
    module_service(dll, svc, sizeof svc);
    for (i = 0; i < nloading; ++i)
        if (ci_eq(loading[i], svc)) {
            kprintf("K64 ntdrv: %s imports %s, which is being loaded (import cycle): refused\n", x->service, dll);
            note_missing(x, key);
            *missing = 1;
            return 0;
        }
    m = ntdrv_find_module(dll);
    if (!m) {
        ntdrv_driver_t *saved = ntdrv_current_driver();
        if (nloading >= NTDRV_MAX_LOAD_DEPTH - 1) {
            kprintf("K64 ntdrv: %s imports %s: dependency chain deeper than %u: refused\n", x->service, dll, NTDRV_MAX_LOAD_DEPTH - 1);
            note_missing(x, key);
            *missing = 1;
            return 0;
        }
        { unsigned k = strlen(path); for (i = 0; dll[i] && k + 1 < sizeof path; ++i) path[k++] = dll[i]; path[k] = 0; }
        n = fs_lookup(path);
        if (!n || n->is_dir) {
            kprintf("K64 ntdrv: %s imports %s, which is not in \\SHZ\\SYS64\\DRIVERS\n", x->service, dll);
        } else {
            kprintf("K64 ntdrv: %s imports %s: loading it first\n", x->service, dll);
            st = ntdrv_load_node(n, svc, &m);
            ntdrv_set_current_driver(saved);
            if (st || !m || !m->started) {
                kprintf("K64 ntdrv: %s: dependency %s failed to load (%x)\n", x->service, dll, (uint32_t)st);
                m = 0;
            } else {
                m->dependency = 1;
            }
        }
        if (!m) { note_missing(x, key); *missing = 1; return 0; }
    }
    if (x->ndeps >= 16) {                       /* never bind an export of a module that is not reference-counted */
        kprintf("K64 ntdrv: %s imports from more than 16 modules: refused\n", x->service);
        *missing = 1;
        return 0;
    }
    x->deps[x->ndeps++] = m;
    ++m->users;
    return m;
}

static int import_cb(void *c, const char *dll, const char *name, uint16_t hint, int by_ord, uint32_t iat_rva)
{
    struct ictx *x = c;
    void *fn = 0;
    (void)hint;
    if (by_ord || !name) {
        kprintf("K64 ntdrv: unresolved import %s!#%u (ordinal imports unsupported)\n", dll, hint);
        ++x->unresolved;
    } else if (is_kernel_module(dll)) {
        fn = ntdrv_resolve_export(dll, name);
        if (!fn) {
            kprintf("K64 ntdrv: unresolved import %s!%s\n", dll, name);
            ++x->unresolved;
        }
    } else {
        int missing;
        ntdrv_driver_t *m = dep_module(x, dll, &missing);
        if (m) {
            fn = ntdrv_module_export(m, name);
            if (!fn) kprintf("K64 ntdrv: unresolved import %s!%s (not exported by the loaded %s)\n", dll, name, m->name);
        }
        if (!fn) ++x->unresolved;                 /* a missing module was reported once, by dep_module */
    }
    { uint64_t v = (uint64_t)fn; memcpy((void *)(x->base + iat_rva), &v, 8); }   /* 0 IAT slot faults cleanly if called */
    return 0;                                                                     /* keep going: report every miss */
}

static void drop_deps(ntdrv_driver_t **deps, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; ++i) if (deps[i]->users) --deps[i]->users;
}

/* ---- DRIVER_OBJECT ---- */
static void build_regpath(ntdrv_driver_t *d, const char *service)
{
    static const char *pfx = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
    char full[192];
    unsigned n = 0, i;
    for (i = 0; pfx[i] && n < sizeof full - 1; ++i) full[n++] = pfx[i];
    for (i = 0; service[i] && n < sizeof full - 1; ++i) full[n++] = service[i];
    full[n] = 0;
    ntdrv_ascii_to_wide(full, d->regpath_buf, sizeof d->regpath_buf / 2);
    d->regpath.Buffer = d->regpath_buf;
    d->regpath.Length = (uint16_t)(n * 2);
    d->regpath.MaximumLength = (uint16_t)(n * 2 + 2);
}

static int32_t load_image_impl(const uint8_t *image, uint64_t size, const char *service, ntdrv_driver_t **out)
{
    pe_info_t pi;
    int rc = pe_parse(image, size, &pi);
    uint64_t base;
    ntdrv_driver_t *d;
    DRIVER_OBJECT *drv;
    struct rctx rc2;
    struct ictx ic;
    int32_t st;
    unsigned i;
    NTSTATUS (NTAPI *entry)(DRIVER_OBJECT *, PUNICODE_STRING);

    if (rc) { kprintf("K64 ntdrv: %s rejected (pe error %d)\n", service, rc); return STATUS_INVALID_IMAGE_FORMAT; }
    if (pi.characteristics & PE_CHAR_DLL) { /* .sys is characteristically a DLL image; that is expected */ }
    if (!pi.entry_rva) { kprintf("K64 ntdrv: %s has no entry point\n", service); return STATUS_INVALID_IMAGE_FORMAT; }
    base = ntdrv_alloc_image_va(pi.size_of_image);
    if (!base) return STATUS_NO_MEMORY;
    st = map_image(image, size, &pi, base);
    if (st) return st;
    rc2.delta = base - pi.image_base; rc2.base = base; rc2.st = STATUS_SUCCESS;
    if (rc2.delta && pi.dir_rva[5]) {                          /* apply base relocations if the image carries them */
        if (pe_walk_relocs(image, size, &pi, reloc_cb, &rc2) || rc2.st) return STATUS_INVALID_IMAGE_FORMAT;
    } else if (rc2.delta) {
        /* No .reloc directory: the image is fully position-independent (RIP-relative), so it runs
         * unchanged at any base. ld emits a reloc for every absolute address, so an absent table
         * means none are needed. */
        kprintf("K64 ntdrv: %s is position-independent (no base relocations); mapped at %llx\n", service, base);
    }
    memset(&ic, 0, sizeof ic);
    ic.base = base; ic.service = service;
    if (pe_walk_imports(image, size, &pi, import_cb, &ic)) { drop_deps(ic.deps, ic.ndeps); return STATUS_INVALID_IMAGE_FORMAT; }
    if (ic.unresolved) {
        kprintf("K64 ntdrv: %s has %u unresolved import(s); not loaded\n", service, ic.unresolved);
        drop_deps(ic.deps, ic.ndeps);
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    d = kzalloc(sizeof *d);
    drv = kzalloc(SZ_DRV);
    if (!d || !drv) { kfree(d); kfree(drv); drop_deps(ic.deps, ic.ndeps); return STATUS_NO_MEMORY; }
    for (i = 0; service[i] && i < sizeof d->name - 1; ++i) d->name[i] = service[i];
    d->image_base = base; d->image_size = pi.size_of_image; d->drv = drv;
    d->export_rva = pi.dir_rva[0]; d->export_size = pi.dir_size[0];
    for (i = 0; i < ic.ndeps; ++i) d->deps[i] = ic.deps[i];
    d->ndeps = ic.ndeps;
    build_regpath(d, service);
    drv->Type = 4; drv->Size = SZ_DRV;
    drv->DriverStart = (void *)base;
    drv->DriverSize = pi.size_of_image;
    drv->DriverInit = (PDRIVER_INITIALIZE)(base + pi.entry_rva);
    drv->DriverSection = d;
    {   /* \Driver\<service>, the DRIVER_EXTENSION (AddDevice lives there; ServiceKeyName = the service) and
         * HardwareDatabase, as every DRIVER_OBJECT on Windows carries them */
        static const char pfx[] = "\\Driver\\";
        static uint16_t hwdb[] = { '\\','R','E','G','I','S','T','R','Y','\\','M','A','C','H','I','N','E','\\','H','A','R','D','W','A','R','E','\\',
                                   'D','E','S','C','R','I','P','T','I','O','N','\\','S','Y','S','T','E','M' };
        static UNICODE_STRING hwdb_us = { sizeof hwdb, sizeof hwdb, 0, hwdb };
        const unsigned svclen = (unsigned)strlen(service);
        uint16_t *wn = kzalloc((sizeof pfx + svclen) * 2), *ws = kzalloc((svclen + 1) * 2);
        DRIVER_EXTENSION *ext = kzalloc(0x40);                /* the public 0x28 bytes plus Windows' private tail */
        unsigned n = 0;
        if (!wn || !ws || !ext) { kfree(wn); kfree(ws); kfree(ext); kfree(d); kfree(drv); drop_deps(ic.deps, ic.ndeps); return STATUS_NO_MEMORY; }
        for (i = 0; pfx[i]; ++i) wn[n++] = (uint16_t)pfx[i];
        for (i = 0; service[i]; ++i) { wn[n++] = (uint16_t)service[i]; ws[i] = (uint16_t)service[i]; }
        drv->DriverName.Buffer = wn;
        drv->DriverName.Length = (uint16_t)(n * 2); drv->DriverName.MaximumLength = (uint16_t)(n * 2 + 2);
        ext->DriverObject = drv;
        ext->ServiceKeyName.Buffer = ws;
        ext->ServiceKeyName.Length = (uint16_t)(svclen * 2); ext->ServiceKeyName.MaximumLength = (uint16_t)(svclen * 2 + 2);
        drv->DriverExtension = ext;
        drv->HardwareDatabase = &hwdb_us;
    }
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
        drv->MajorFunction[i] = ntdrv_default_dispatch;
    d->next = driver_list; driver_list = d;

    ntdrv_ke_init();                                          /* DPC/timer service threads, on the first load only */
    entry = (void *)(base + pi.entry_rva);
    ntdrv_set_current_driver(d);
    kprintf("K64 ntdrv: %s mapped at %llx (%u bytes), calling DriverEntry\n", service, base, pi.size_of_image);
    st = entry(drv, &d->regpath);
    ntdrv_set_current_driver(0);
    if (st < 0) {                                             /* NT_SUCCESS: informational and success codes both mean loaded */
        kprintf("K64 ntdrv: %s DriverEntry returned %x\n", service, (uint32_t)st);
        /* leave the record so ntdrv_unload can reclaim VA/pages; mark not started */
        d->started = 0;
        ntdrv_release_claims(d);                              /* a BAR it mapped before failing is nobody's now */
        drop_deps(d->deps, d->ndeps);
        d->ndeps = 0;
        if (out) *out = d;
        return st;
    }
    d->started = 1;
    if (out) *out = d;
    return STATUS_SUCCESS;
}

int32_t ntdrv_load_image(const uint8_t *image, uint64_t size, const char *service, ntdrv_driver_t **out)
{
    int32_t st;
    if (nloading >= NTDRV_MAX_LOAD_DEPTH) return STATUS_INVALID_IMAGE_FORMAT;
    loading[nloading++] = service;
    st = load_image_impl(image, size, service, out);
    --nloading;
    return st;
}

ntdrv_driver_t *ntdrv_find_driver(const char *service)
{
    ntdrv_driver_t *d;
    for (d = driver_list; d; d = d->next)
        if (d->started && ci_eq(d->name, service)) return d;   /* service names are case-insensitive, like keys */
    return 0;
}
ntdrv_driver_t *ntdrv_drivers(void) { return driver_list; }

ntdrv_driver_t *ntdrv_driver_by_address(uint64_t va)
{
    ntdrv_driver_t *d;
    for (d = driver_list; d; d = d->next)
        if (va >= d->image_base && va < d->image_base + d->image_size) return d;
    return 0;
}

/* Load from a file-system node: initrd/RAM files are used in place; disk-backed files (D:, E: ...) are read into a
 * temporary buffer, which the loader no longer needs once the image is mapped (sections are copied into place). */
#define NTDRV_MAX_IMAGE (8ull << 20)
int32_t ntdrv_load_node(fsnode_t *n, const char *service, ntdrv_driver_t **out)
{
    uint8_t *buf;
    uint64_t got = 0;
    int32_t st;
    if (!n || n->is_dir) return STATUS_OBJECT_NAME_NOT_FOUND;
    if (n->backing == FSB_RAM && n->data) return ntdrv_load_image(n->data, n->size, service, out);
    if (!n->size || n->size > NTDRV_MAX_IMAGE) return STATUS_INVALID_IMAGE_FORMAT;
    buf = kmalloc(n->size);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
    if (fs_read(n, 0, buf, n->size, &got) || got != n->size) { kfree(buf); return STATUS_IN_PAGE_ERROR; }
    st = ntdrv_load_image(buf, n->size, service, out);
    kfree(buf);
    return st;
}

int32_t ntdrv_unload(ntdrv_driver_t *d)
{
    if (!d) return STATUS_INVALID_PARAMETER;
    if (d->started) {                                         /* devices go first (QUERY_REMOVE/REMOVE), then the driver */
        const int32_t rs = ntdrv_pnp_remove_devices(d);
        if (rs) return rs;
    }
    if (d->started && d->drv->DriverUnload) {
        ntdrv_set_current_driver(d);
        d->drv->DriverUnload(d->drv);
        ntdrv_set_current_driver(0);
    }
    /* image pages and the DRIVER_OBJECT are intentionally retained: the VA window is a
     * monotonically growing bring-up arena (a reload maps a fresh copy). The device namespace
     * entries the driver created were freed by IoDeleteDevice in unload. */
    d->started = 0;
    ntdrv_pnp_driver_unloading(d);
    ntdrv_release_claims(d);
    drop_deps(d->deps, d->ndeps);
    d->ndeps = 0;
    return STATUS_SUCCESS;
}

int32_t ntdrv_unload_service(const char *service)
{
    ntdrv_driver_t *d = ntdrv_find_driver(service);
    if (!d) return STATUS_OBJECT_NAME_NOT_FOUND;
    if (d->users) {
        kprintf("K64 ntdrv: %s is imported by %u loaded image(s); not unloaded\n", d->name, d->users);
        return STATUS_CONNECTION_IN_USE;
    }
    if (!d->drv->DriverUnload) {
        kprintf("K64 ntdrv: %s has no DriverUnload routine; it stays loaded\n", d->name);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    {   /* a device with a user handle open on it is referenced (ReferenceCount > 1, set by IoCreateDevice to 1): freeing it
         * would leave the handle pointing at freed memory, so the driver stays loaded until the handles are closed */
        DEVICE_OBJECT *dv;
        for (dv = d->drv->DeviceObject; dv; dv = dv->NextDevice)
            if (dv->ReferenceCount > 1) {
                kprintf("K64 ntdrv: %s has a device object with %d open handle(s); not unloaded\n", d->name, (int)dv->ReferenceCount - 1);
                return STATUS_CONNECTION_IN_USE;
            }
    }
    kprintf("K64 ntdrv: unloading %s\n", d->name);
    return ntdrv_unload(d);
}
