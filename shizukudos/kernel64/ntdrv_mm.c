/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: the Mm memory manager a driver calls -- MDLs, locked-page
 * mapping, I/O space mapping, contiguous and non-cached allocations and physical-address
 * translation. Contiguous/non-cached memory comes from the kernel heap, which is a
 * physically contiguous, direct-mapped region, so MmGetPhysicalAddress is exact. I/O space
 * mapping reuses the kernel's uncached MMIO mapper (pci.c).
 */
#include "ntdrv.h"

extern void *mmio_map(uint64_t pa, uint64_t size);              /* pci.c: uncached kernel mapping */
uint32_t NTAPI MmSizeOfMdl(void *va, uint32_t len);

/* All driver buffers here are non-paged kernel virtual addresses: the direct map and the kernel image alias translate
 * arithmetically; anything else (a loaded driver image, an MmMapLockedPages window, an MMIO window) goes through the
 * page tables. */
static uint64_t va_to_phys(uint64_t va)
{
    uint64_t pa, flags;
    if (va >= DIRECT_MAP && va < DIRECT_MAP + (256ull << 30)) return v2p_direct(va);
    if (va >= K64_VIRT_BASE) return kimage_v2p(va);
    pa = vm_lookup(kernel_pml4(), va & ~0xfffull, &flags);
    return pa ? pa | (va & 0xfff) : 0;
}
/* PFN array of an MDL (the ULONG_PTR entries after the header), when the MDL was allocated large enough for it. */
static uint64_t *mdl_pfns(MDL *m, uint32_t *npages)
{
    uint32_t n = (uint32_t)((m->ByteOffset + m->ByteCount + 4095) / 4096);
    *npages = n;
    return (unsigned)m->Size >= sizeof(MDL) + n * 8 ? (uint64_t *)(m + 1) : 0;
}
static void mdl_fill_pfns(MDL *m)
{
    uint32_t n, i;
    uint64_t *pfn = mdl_pfns(m, &n);
    if (!pfn || !m->StartVa) return;
    for (i = 0; i < n; ++i) pfn[i] = va_to_phys((uint64_t)m->StartVa + i * 4096) / 4096;
}
/* A page-list MDL (MmAllocatePagesForMdl, BuildMdlFromScatterGatherList) has no StartVa: map its pages contiguously
 * in the driver VA window so the driver gets one system address for the whole buffer. */
static void *mdl_map_pages(MDL *m)
{
    uint32_t n, i;
    uint64_t *pfn = mdl_pfns(m, &n), va;
    if (!pfn || !n) return 0;
    va = ntdrv_alloc_image_va((uint64_t)n * 4096);
    if (!va) return 0;
    for (i = 0; i < n; ++i)
        if (vm_map(kernel_pml4(), va + i * 4096, pfn[i] * 4096, PT_W | PT_NX)) return 0;
    m->StartVa = (void *)va;
    return (void *)(va + m->ByteOffset);
}

LARGE_INTEGER NTAPI MmGetPhysicalAddress(void *va)
{
    LARGE_INTEGER r;
    r.QuadPart = (int64_t)va_to_phys((uint64_t)va);
    return r;
}

void *NTAPI MmMapIoSpace(LARGE_INTEGER pa, uint64_t size, uint32_t cache)
{
    (void)cache;
    ntdrv_pci_note_mmio((uint64_t)pa.QuadPart, size);          /* a BAR mapping binds that PCI function to the driver */
    return mmio_map((uint64_t)pa.QuadPart, size);
}
void *NTAPI MmMapIoSpaceEx(LARGE_INTEGER pa, uint64_t size, uint32_t prot)
{
    (void)prot;
    ntdrv_pci_note_mmio((uint64_t)pa.QuadPart, size);
    return mmio_map((uint64_t)pa.QuadPart, size);
}
void NTAPI MmUnmapIoSpace(void *va, uint64_t size) { (void)va; (void)size; /* direct-map MMIO windows persist for the boot */ }

void *NTAPI MmAllocateContiguousMemory(uint64_t bytes, LARGE_INTEGER highest)
{
    (void)highest;                                             /* heap is well below 4 GiB physical */
    return kmalloc(bytes ? bytes : 1);
}
void *NTAPI MmAllocateContiguousMemorySpecifyCache(uint64_t bytes, LARGE_INTEGER low, LARGE_INTEGER high,
                                                   LARGE_INTEGER boundary, uint32_t cache)
{
    (void)low; (void)high; (void)boundary; (void)cache;
    return kmalloc(bytes ? bytes : 1);
}
void NTAPI MmFreeContiguousMemory(void *p) { kfree(p); }
void NTAPI MmFreeContiguousMemorySpecifyCache(void *p, uint64_t bytes, uint32_t cache) { (void)bytes; (void)cache; kfree(p); }
void *NTAPI MmAllocateNonCachedMemory(uint64_t bytes) { return kmalloc(bytes ? bytes : 1); }
void NTAPI MmFreeNonCachedMemory(void *p, uint64_t bytes) { (void)bytes; kfree(p); }
/* Kernel64 never pages a driver image out: every section stays resident for the life of the image, which is the state
 * MmResetDriverPaging requests and which MmPageEntireDriver merely permits. What remains of the contract is the return
 * value -- the handle of the image section containing the address, which is its base -- or NULL for an address that is
 * in no loaded driver. */
void *NTAPI MmPageEntireDriver(void *address_within_section)
{
    ntdrv_driver_t *d = ntdrv_driver_by_address((uint64_t)address_within_section);
    return d ? (void *)d->image_base : 0;
}
void NTAPI MmResetDriverPaging(void *address_within_section) { (void)address_within_section; }

uint8_t NTAPI MmIsAddressValid(void *va) { return va_to_phys((uint64_t)va) != 0; }

/* ---- MDLs ---- */
static MDL *mdl_init(MDL *m, void *va, uint32_t len)
{
    memset(m, 0, sizeof *m);
    m->Size = (int16_t)sizeof(MDL);
    m->StartVa = (void *)((uint64_t)va & ~0xfffull);
    m->ByteOffset = (uint32_t)((uint64_t)va & 0xfff);
    m->ByteCount = len;
    m->MappedSystemVa = va;
    return m;
}

/* MDLs carry their PFN array (MmGetMdlPfnArray is an inline over it), sized by MmSizeOfMdl. */
MDL *NTAPI IoAllocateMdl(void *va, uint32_t len, uint8_t secondary, uint8_t charge, IRP *irp)
{
    uint32_t size = MmSizeOfMdl(va, len);
    MDL *m = kzalloc(size);
    (void)charge;
    if (!m) return 0;
    mdl_init(m, va, len);
    m->Size = (int16_t)size;
    m->MappedSystemVa = 0;                                     /* not mapped until MmBuildMdl/MmGetSystemAddress */
    if (irp) {
        if (!secondary || !irp->MdlAddress) irp->MdlAddress = m;
        else { MDL *p = irp->MdlAddress; while (p->Next) p = p->Next; p->Next = m; }
    }
    return m;
}
void NTAPI IoFreeMdl(MDL *m) { kfree(m); }
void NTAPI MmBuildMdlForNonPagedPool(MDL *m)
{
    m->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA | MDL_PAGES_LOCKED | MDL_SOURCE_IS_NONPAGED_POOL;
    m->MappedSystemVa = (void *)((uint64_t)m->StartVa + m->ByteOffset);
    mdl_fill_pfns(m);
}
void NTAPI MmProbeAndLockPages(MDL *m, uint8_t mode, uint32_t op)
{
    (void)mode; (void)op;
    /* Non-paged kernel buffers are always resident; "locking" records the state and captures the page frames. */
    m->MdlFlags |= MDL_PAGES_LOCKED;
    mdl_fill_pfns(m);
}
void NTAPI MmProbeAndLockProcessPages(MDL *m, void *process, uint8_t mode, uint32_t op) { (void)process; MmProbeAndLockPages(m, mode, op); }
void NTAPI MmUnlockPages(MDL *m) { m->MdlFlags &= (int16_t)~MDL_PAGES_LOCKED; }
static void *mdl_system_va(MDL *m)
{
    if (!m->StartVa && !mdl_map_pages(m)) return 0;
    m->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
    m->MappedSystemVa = (void *)((uint64_t)m->StartVa + m->ByteOffset);
    return m->MappedSystemVa;
}
void *NTAPI MmMapLockedPages(MDL *m, uint8_t mode) { (void)mode; return mdl_system_va(m); }
void *NTAPI MmMapLockedPagesSpecifyCache(MDL *m, uint8_t mode, uint32_t cache, void *req, uint32_t bug, uint32_t pri)
{
    (void)mode; (void)cache; (void)req; (void)bug; (void)pri;
    return mdl_system_va(m);
}
void NTAPI MmUnmapLockedPages(void *va, MDL *m) { (void)va; m->MdlFlags &= (int16_t)~MDL_MAPPED_TO_SYSTEM_VA; }
void *NTAPI MmGetSystemAddressForMdlSafe(MDL *m, uint32_t pri)
{
    (void)pri;
    if (!(m->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA) || !m->MappedSystemVa) return mdl_system_va(m);
    return m->MappedSystemVa;
}
void *NTAPI MmMapLockedPagesWithReservedMapping(void *base, uint32_t tag, MDL *m, uint32_t cache) { (void)base; (void)tag; (void)cache; return mdl_system_va(m); }
void NTAPI MmUnmapReservedMapping(void *base, uint32_t tag, MDL *m) { (void)base; (void)tag; m->MdlFlags &= (int16_t)~MDL_MAPPED_TO_SYSTEM_VA; }
void *NTAPI MmAllocateMappingAddress(uint64_t bytes, uint32_t tag) { (void)tag; return (void *)ntdrv_alloc_image_va(bytes); }
void NTAPI MmFreeMappingAddress(void *base, uint32_t tag) { (void)base; (void)tag; }   /* the VA window is a bring-up arena (see ntdrv_ldr.c) */
void NTAPI MmPrepareMdlForReuse(MDL *m) { m->MdlFlags &= (int16_t)~(MDL_MAPPED_TO_SYSTEM_VA | MDL_PAGES_LOCKED); }
uint64_t NTAPI MmGetMdlByteCount(MDL *m) { return m->ByteCount; }             /* also a driver macro; exported for completeness */
void *NTAPI MmGetMdlVirtualAddress(MDL *m) { return (void *)((uint64_t)m->StartVa + m->ByteOffset); }

uint32_t NTAPI MmSizeOfMdl(void *va, uint32_t len)
{
    uint64_t start = (uint64_t)va & ~0xfffull, end = ((uint64_t)va + len + 0xfff) & ~0xfffull;
    return (uint32_t)(sizeof(MDL) + (end - start) / PAGE_SIZE * 8);
}
void NTAPI MmInitializeMdl(MDL *m, void *va, uint32_t len) { int16_t sz = m->Size; mdl_init(m, va, len); m->MappedSystemVa = 0; if (sz > (int16_t)sizeof(MDL)) m->Size = sz; }
/* A driver may also derive a buffer's physical pages itself. */
uint8_t NTAPI MmIsNonPagedSystemAddressValid(void *va) { return va_to_phys((uint64_t)va) != 0; }
/* MmGetPhysicalAddress of the driver VA window and MMIO windows go through vm_lookup above; MmGetVirtualForPhysical is the
 * direct map (every RAM page is mapped there). */
void *NTAPI MmGetVirtualForPhysical(LARGE_INTEGER pa) { return (void *)p2v((uint64_t)pa.QuadPart); }
