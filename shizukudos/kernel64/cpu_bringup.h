/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_CPU_BRINGUP_H
#define SHZ_CPU_BRINGUP_H
#include "k64.h"
/* Explicit shz.smp=dispatch defers INIT to verify after BSP preallocation.
 * Default private-worker startup/verification remains separate. */
void shz_cpu_bringup_prepare(const shz_bootinfo_t *,uint64_t initial_cr3);
void shz_cpu_bringup_verify(void);
/* Root-owned main consumer must call after unchanged UP QA. Start independently
 * checks actual queue/lifetime quiescence before first INIT; native only. */
int shz_cpu_workers_requested(void);
int shz_cpu_workers_start(void);
#endif
