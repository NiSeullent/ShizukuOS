/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_MODULE_RELOCATION_H
#define SHZ_MODULE_RELOCATION_H
#include <stdint.h>
#include "memholes.h"

/* Physical layout remains the existing Multiboot/Kernel64 ABI. */
#define SHZ_STUB_KERNEL_GPA 0x100000u
#define SHZ_STUB_KERNEL_END 0x300000u
#define SHZ_STUB_KERNEL_FILE_MAX 0x140000u /* file-only; image+BSS still ends below 3 MiB */
#define SHZ_STUB_IMAGE_GPA 0x400000u
#define SHZ_STUB_INITRD_GPA 0x2000000u

static inline int shz_stub_relocation_valid(const shz_memplan_t *ram_map, uint32_t ram,
        uint32_t stub_end, uint32_t kernel_start, uint32_t kernel_end,
        uint32_t initrd_start, uint32_t initrd_end, int has_initrd)
{
    uint32_t kernel_bytes, initrd_bytes;
    uint64_t destination_end;
    if (!ram_map || stub_end < SHZ_STUB_IMAGE_GPA || stub_end > SHZ_STUB_INITRD_GPA ||
        kernel_start < stub_end || kernel_end <= kernel_start || kernel_end > ram)
        return 0;
    kernel_bytes = kernel_end - kernel_start;
    if (kernel_bytes > SHZ_STUB_KERNEL_FILE_MAX ||
        !shz_memplan_covers(ram_map, kernel_start, kernel_end) ||
        !shz_memplan_covers(ram_map, SHZ_STUB_KERNEL_GPA, SHZ_STUB_KERNEL_END))
        return 0;
    if (!has_initrd) return 1;
    if (initrd_start < stub_end || initrd_end < initrd_start || initrd_end > ram)
        return 0;
    initrd_bytes = initrd_end - initrd_start;
    destination_end = (uint64_t)SHZ_STUB_INITRD_GPA + initrd_bytes;
    if (destination_end > ram || destination_end > UINT32_MAX ||
        (initrd_bytes && (!shz_memplan_covers(ram_map, initrd_start, initrd_end) ||
                         !shz_memplan_covers(ram_map, SHZ_STUB_INITRD_GPA, destination_end) ||
                         (kernel_start < initrd_end && initrd_start < kernel_end))))
        return 0;
    return 1;
}

/* No libc, allocation, DF changes or implicit vector alignment. Volatile byte
 * accesses preserve memmove semantics in the freestanding 32-bit build. The
 * caller checks both physical extents against the RAM plan before calling. */
static inline void shz_stub_move(volatile uint8_t *dst, const volatile uint8_t *src, uint32_t bytes)
{
    uint32_t i;
    if ((uintptr_t)dst > (uintptr_t)src && (uintptr_t)dst - (uintptr_t)src < bytes) {
        for (i = bytes; i; --i) dst[i - 1] = src[i - 1];
    } else {
        for (i = 0; i < bytes; ++i) dst[i] = src[i];
    }
}
#endif
