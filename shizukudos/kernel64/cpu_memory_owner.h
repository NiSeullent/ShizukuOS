/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_CPU_MEMORY_OWNER_H
#define SHZ_CPU_MEMORY_OWNER_H
#include "k64.h"
/* Read-only serialized allocation observer. Requires actual allocation
 * provenance, excludes bootinfo initrd/retained holes and rejects unknown CPUs.
 * This observes live state only; it does not pin a frame or supply page-table
 * mutation, translation shootdown or lifetime ownership. Admission callers
 * keep their table/resource allocations stable throughout validation. */
int shz_cpu_pmm_page_owned(uint64_t pa,const shz_bootinfo_t *boot);
#endif
