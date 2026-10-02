/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_CPU_TLB_APERTURE_H
#define SHZ_CPU_TLB_APERTURE_H
#include "k64.h"
/* Private QA alias in the already shared direct-map PML4 slot. It must be
 * absent, including on machines whose RAM would cover this offset. */
#define SHZ_TLB_APERTURE_VA 0xffff802000000000ull
typedef int (*shz_tlb_owned_fn)(void *,uint64_t pa,uint64_t bytes);
typedef struct {
    uint64_t root,va,frame[2],table[4];
    uint64_t *leaf;
    unsigned prepared,added_tables;
} shz_tlb_aperture_t;
/* Before INIT and process-root cloning only. Owns and retains payload/table
 * allocations for this bounded domain's entire lifetime, including failure.
 * The callback supplies full RAM coverage AND actual live PMM provenance. */
int shz_tlb_aperture_prepare(shz_tlb_aperture_t *,uint64_t root,shz_tlb_owned_fn,void *);
int shz_tlb_aperture_valid(const shz_tlb_aperture_t *);
#endif
