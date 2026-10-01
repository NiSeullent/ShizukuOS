/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_CPU_MEMORY_STRESS_H
#define SHZ_CPU_MEMORY_STRESS_H
/* Opt-in normal-profile architectural worker control. No scheduler activation. */
int shz_cpu_memory_stress(unsigned cpu);
void shz_cpu_memory_stress_report(void);
#endif
