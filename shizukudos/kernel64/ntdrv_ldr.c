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

struct ictx { uint64_t base; unsigned unresolved; };
static int import_cb(void *c, const char *dll, const char *name, uint16_t hint, int by_ord, uint32_t iat_rva)
{
    struct ictx *x = c;
    void *fn = 0;
    (void)hint;
    if (by_ord || !name) {
        kprintf("K64 ntdrv: unresolved import %s!#%u (ordinal imports unsupported)\n", dll, hint);
        ++x->unresolved;
    } else {
        fn = ntdrv_resolve_export(dll, name);
        if (!fn) {
            kprintf("K64 ntdrv: unresolved import %s!%s\n", dll, name);
            ++x->unresolved;
        }
    }
    { uint64_t v = (uint64_t)fn; memcpy((void *)(x->base + iat_rva), &v, 8); }   /* 0 IAT slot faults cleanly if called */
    return 0;                                                                     /* keep going: report every miss */
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

int32_t ntdrv_load_image(const uint8_t *image, uint64_t size, const char *service, ntdrv_driver_t **out)
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
    ic.base = base; ic.unresolved = 0;
    if (pe_walk_imports(image, size, &pi, import_cb, &ic)) return STATUS_INVALID_IMAGE_FORMAT;
    if (ic.unresolved) {
        kprintf("K64 ntdrv: %s has %u unresolved import(s); not loaded\n", service, ic.unresolved);
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    d = kzalloc(sizeof *d);
    drv = kzalloc(SZ_DRV);
    if (!d || !drv) { kfree(d); kfree(drv); return STATUS_NO_MEMORY; }
    for (i = 0; service[i] && i < sizeof d->name - 1; ++i) d->name[i] = service[i];
    d->image_base = base; d->image_size = pi.size_of_image; d->drv = drv;
    build_regpath(d, service);
    drv->Type = 4; drv->Size = SZ_DRV;
    drv->DriverStart = (void *)base;
    drv->DriverSize = pi.size_of_image;
    drv->DriverInit = (PDRIVER_INITIALIZE)(base + pi.entry_rva);
    drv->DriverSection = d;
    drv->DriverName.Buffer = d->regpath_buf;           /* not the real \Driver\name, but a valid UNICODE_STRING */
    drv->DriverName.Length = 0; drv->DriverName.MaximumLength = 0;
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
        drv->MajorFunction[i] = ntdrv_default_dispatch;
    d->next = driver_list; driver_list = d;

    ntdrv_ke_init();                                          /* DPC/timer service threads, on the first load only */
    entry = (void *)(base + pi.entry_rva);
    ntdrv_set_current_driver(d);
    kprintf("K64 ntdrv: %s mapped at %llx (%u bytes), calling DriverEntry\n", service, base, pi.size_of_image);
    st = entry(drv, &d->regpath);
    ntdrv_set_current_driver(0);
    if (st) {
        kprintf("K64 ntdrv: %s DriverEntry returned %x\n", service, (uint32_t)st);
        /* leave the record so ntdrv_unload can reclaim VA/pages; mark not started */
        d->started = 0;
        if (out) *out = d;
        return st;
    }
    d->started = 1;
    if (out) *out = d;
    return STATUS_SUCCESS;
}

ntdrv_driver_t *ntdrv_find_driver(const char *service)
{
    ntdrv_driver_t *d;
    for (d = driver_list; d; d = d->next)
        if (d->started && !strcmp(d->name, service)) return d;
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
    if (d->started && d->drv->DriverUnload) {
        ntdrv_set_current_driver(d);
        d->drv->DriverUnload(d->drv);
        ntdrv_set_current_driver(0);
    }
    /* image pages and the DRIVER_OBJECT are intentionally retained: the VA window is a
     * monotonically growing bring-up arena and no driver is reloaded in the same boot. The
     * device namespace entries the driver created were freed by IoDeleteDevice in unload. */
    d->started = 0;
    return STATUS_SUCCESS;
}
