/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_MODULE_RELOCATION_H
#define SHZ_MODULE_RELOCATION_H
#include <stdint.h>
#include "memholes.h"

/* Physical layout of the Multiboot handoff. The kernel window is per kernel: Kernel64 uses
 * memholes.h [SHZ_K64_KERNEL_GPA, SHZ_K64_KERNEL_END) with SHZ_K64_KERNEL_FILE_MAX, Kernel32 keeps its historical
 * [1 MiB, 3 MiB) window and 1 MiB file limit (SHZ_STUB_K32_*). The stub image itself sits at 4 MiB, at or above every
 * kernel window end, so zeroing a window never touches the running stub. */
#define SHZ_STUB_KERNEL_GPA 0x100000u
#define SHZ_STUB_K32_KERNEL_END 0x300000u
#define SHZ_STUB_K32_FILE_MAX 0x100000u
#define SHZ_STUB_IMAGE_GPA 0x400000u
#define SHZ_STUB_INITRD_GPA 0x2000000u
_Static_assert(SHZ_STUB_KERNEL_GPA == SHZ_K64_KERNEL_GPA && SHZ_K64_KERNEL_END <= SHZ_STUB_IMAGE_GPA &&
               SHZ_STUB_K32_KERNEL_END <= SHZ_STUB_IMAGE_GPA &&
               SHZ_STUB_K32_FILE_MAX <= SHZ_STUB_K32_KERNEL_END - SHZ_STUB_KERNEL_GPA &&
               SHZ_K64_KERNEL_FILE_MAX <= SHZ_K64_KERNEL_END - SHZ_STUB_KERNEL_GPA,
               "stub kernel windows end at or below the stub image");

/* window_end: exclusive end of the zeroed kernel window; file_max: largest accepted kernel file. Both must be the
 * caller's per-kernel constants above; anything inconsistent (window past the stub image, file larger than the
 * window) is refused rather than trusted. */
static inline int shz_stub_relocation_valid(const shz_memplan_t *ram_map, uint32_t ram,
        uint32_t window_end, uint32_t file_max,
        uint32_t stub_end, uint32_t kernel_start, uint32_t kernel_end,
        uint32_t initrd_start, uint32_t initrd_end, int has_initrd)
{
    uint32_t kernel_bytes, initrd_bytes;
    uint64_t destination_end;
    if (!ram_map || window_end <= SHZ_STUB_KERNEL_GPA || window_end > SHZ_STUB_IMAGE_GPA || !file_max ||
        file_max > window_end - SHZ_STUB_KERNEL_GPA ||
        stub_end < SHZ_STUB_IMAGE_GPA || stub_end > SHZ_STUB_INITRD_GPA ||
        kernel_start < stub_end || kernel_end <= kernel_start || kernel_end > ram)
        return 0;
    kernel_bytes = kernel_end - kernel_start;
    if (kernel_bytes > file_max ||
        !shz_memplan_covers(ram_map, kernel_start, kernel_end) ||
        !shz_memplan_covers(ram_map, SHZ_STUB_KERNEL_GPA, window_end))
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
