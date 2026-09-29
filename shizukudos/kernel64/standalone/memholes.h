/* SPDX-License-Identifier: GPL-2.0-only
 * Firmware memory-map holes, handed from the standalone Multiboot stub (boot32.c) to Kernel64 built with
 * SHZ_STANDALONE (mem.c). Not part of the inter-kernel ABI: a Supervisor domain has flat RAM and never sees it.
 *
 * Why: on UEFI + CSMWrap the E820 map that SeaBIOS reports keeps OVMF's ACPI NVS at 8-9 MiB (S3 resume data),
 * so RAM is not one run from 1 MiB. The stub records every gap between usable ranges inside [1 MiB, ram_size),
 * page aligned outward, and Kernel64 keeps those pages out of its page allocator. The stub refuses a hole in the
 * fixed boot/kernel/heap area below 15 MiB or over the initrd, so only allocator pages are ever affected.
 */
#ifndef SHZ_MEMHOLES_H
#define SHZ_MEMHOLES_H
#include <stdint.h>

#define SHZ_MEMHOLES_GPA 0x6000u        /* free low page: stub page tables are 0x1000-0x4FFF, bootinfo 0x7000 */
#define SHZ_MEMHOLES_MAGIC 0x454c4f48u  /* "HOLE" */
#define SHZ_MEMHOLES_MAX 16

typedef struct {
    uint32_t magic;                     /* SHZ_MEMHOLES_MAGIC */
    uint32_t count;                     /* <= SHZ_MEMHOLES_MAX */
    struct {
        uint64_t gpa, size;
    } hole[SHZ_MEMHOLES_MAX];
    uint32_t check;                     /* ~(magic + count + every 32-bit word of hole[0..count)) */
    uint32_t reserved;
} shz_memholes_t;

static inline uint32_t shz_memholes_sum(const volatile shz_memholes_t *h)
{
    uint32_t sum = h->magic + h->count, i;
    for (i = 0; i < h->count && i < SHZ_MEMHOLES_MAX; ++i)
        sum += (uint32_t)h->hole[i].gpa + (uint32_t)(h->hole[i].gpa >> 32) + (uint32_t)h->hole[i].size +
               (uint32_t)(h->hole[i].size >> 32);
    return ~sum;
}
#endif
