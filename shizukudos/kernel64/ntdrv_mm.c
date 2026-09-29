/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: the Mm memory manager a driver calls -- MDLs, locked-page
 * mapping, I/O space mapping, contiguous and non-cached allocations and physical-address
 * translation. Contiguous/non-cached memory comes from the kernel heap, which is a
 * physically contiguous, direct-mapped region, so MmGetPhysicalAddress is exact. I/O space
 * mapping reuses the kernel's uncached MMIO mapper (pci.c).
 */
#include "ntdrv.h"

extern void *mmio_map(uint64_t pa, uint64_t size);              /* pci.c: uncached kernel mapping */

/* All driver buffers here are non-paged kernel virtual addresses (direct map or image
 * alias), so a physical address is a direct arithmetic translation. */
static uint64_t va_to_phys(uint64_t va)
{
    if (va >= DIRECT_MAP && va < DIRECT_MAP + (256ull << 30)) return v2p_direct(va);
    if (va >= K64_VIRT_BASE) return kimage_v2p(va);
    return 0;
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
    return mmio_map((uint64_t)pa.QuadPart, size);
}
void *NTAPI MmMapIoSpaceEx(LARGE_INTEGER pa, uint64_t size, uint32_t prot) { (void)prot; return mmio_map((uint64_t)pa.QuadPart, size); }
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

MDL *NTAPI IoAllocateMdl(void *va, uint32_t len, uint8_t secondary, uint8_t charge, IRP *irp)
{
    MDL *m = kmalloc(sizeof(MDL));
    (void)secondary; (void)charge;
    if (!m) return 0;
    mdl_init(m, va, len);
    m->MappedSystemVa = 0;                                     /* not mapped until MmBuildMdl/MmGetSystemAddress */
    if (irp && !secondary) irp->MdlAddress = m;
    return m;
}
void NTAPI IoFreeMdl(MDL *m) { kfree(m); }
void NTAPI MmBuildMdlForNonPagedPool(MDL *m)
{
    m->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA | MDL_PAGES_LOCKED | MDL_SOURCE_IS_NONPAGED_POOL;
    m->MappedSystemVa = (void *)((uint64_t)m->StartVa + m->ByteOffset);
}
void NTAPI MmProbeAndLockPages(MDL *m, uint8_t mode, uint32_t op)
{
    (void)mode; (void)op;
    /* Non-paged kernel buffers are always resident; "locking" only records the state. */
    m->MdlFlags |= MDL_PAGES_LOCKED;
    if (!m->MappedSystemVa) m->MappedSystemVa = (void *)((uint64_t)m->StartVa + m->ByteOffset);
}
void NTAPI MmUnlockPages(MDL *m) { m->MdlFlags &= (int16_t)~MDL_PAGES_LOCKED; }
void *NTAPI MmMapLockedPages(MDL *m, uint8_t mode) { (void)mode; return (void *)((uint64_t)m->StartVa + m->ByteOffset); }
void *NTAPI MmMapLockedPagesSpecifyCache(MDL *m, uint8_t mode, uint32_t cache, void *req, uint32_t bug, uint32_t pri)
{
    (void)mode; (void)cache; (void)req; (void)bug; (void)pri;
    m->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
    m->MappedSystemVa = (void *)((uint64_t)m->StartVa + m->ByteOffset);
    return m->MappedSystemVa;
}
void NTAPI MmUnmapLockedPages(void *va, MDL *m) { (void)va; m->MdlFlags &= (int16_t)~MDL_MAPPED_TO_SYSTEM_VA; }
void *NTAPI MmGetSystemAddressForMdlSafe(MDL *m, uint32_t pri)
{
    (void)pri;
    if (!(m->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)) {
        m->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
        m->MappedSystemVa = (void *)((uint64_t)m->StartVa + m->ByteOffset);
    }
    return m->MappedSystemVa;
}
uint64_t NTAPI MmGetMdlByteCount(MDL *m) { return m->ByteCount; }             /* also a driver macro; exported for completeness */
void *NTAPI MmGetMdlVirtualAddress(MDL *m) { return (void *)((uint64_t)m->StartVa + m->ByteOffset); }

uint32_t NTAPI MmSizeOfMdl(void *va, uint32_t len)
{
    uint64_t start = (uint64_t)va & ~0xfffull, end = ((uint64_t)va + len + 0xfff) & ~0xfffull;
    return (uint32_t)(sizeof(MDL) + (end - start) / PAGE_SIZE * 8);
}
void NTAPI MmInitializeMdl(MDL *m, void *va, uint32_t len) { mdl_init(m, va, len); m->MappedSystemVa = 0; }
