/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_CPU_TLB_STRESS_H
#define SHZ_CPU_TLB_STRESS_H
#include "cpu_tlb.h"
int shz_cpu_tlb_stress_prepare(unsigned count,shz_tlb_owned_fn,void *);
int shz_cpu_tlb_stress(unsigned cpu);
void shz_cpu_tlb_stress_report(void);
#endif
