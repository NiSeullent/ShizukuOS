/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_CPU_TLB_H
#define SHZ_CPU_TLB_H
#include "cpu_tlb_aperture.h"
#include "smp_boot.h"
enum { SHZ_TLB_SKIP_INVALIDATE=1,SHZ_TLB_WITHHOLD_ACK=2 };
typedef struct {
    uint64_t request,completed,ack,invalidations;
    uint32_t ready,target,poisoned;
} shz_cpu_tlb_observation_t;
/* Internal one-aperture QA domain, not a general address-space interface. */
int shz_cpu_tlb_prepare(const shz_tlb_aperture_t *,unsigned count,unsigned diagnostic);
int shz_cpu_tlb_enroll(void);
int shz_cpu_tlb_begin(unsigned frame_index,uint64_t *generation);
int shz_cpu_tlb_dispatch(uint64_t generation);
void shz_cpu_tlb_ipi(void);
/* 0 completed, 1 still pending, -1 invalid/poisoned. No frame is freed here. */
int shz_cpu_tlb_finish(uint64_t generation);
void shz_cpu_tlb_poison(uint64_t generation);
void shz_cpu_tlb_observe(unsigned cpu,shz_cpu_tlb_observation_t *);
#endif
