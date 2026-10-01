/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_CPU_MEMORY_OWNER_H
#define SHZ_CPU_MEMORY_OWNER_H
#include "k64.h"
/* Read-only Task1 admission observer. BSP uses this with IRQs disabled before
 * AP release; APs do not allocate, free or mutate page tables in this phase.
 * The real bootinfo excludes initrd reservations; the PMM also excludes retained
 * firmware holes. This is not a cross-CPU allocator synchronization API. */
int shz_cpu_pmm_page_owned(uint64_t pa,const shz_bootinfo_t *boot);
#endif
