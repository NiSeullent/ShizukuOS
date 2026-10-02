/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_CPU_ARCH_BRINGUP_H
#define SHZ_CPU_ARCH_BRINGUP_H
#define SHZ_CPU_ARCH_SCHED_COHORT 1
#include "k64.h"
#include "smp_boot.h"
typedef struct __attribute__((packed)) { uint16_t limit; uint64_t base; } shz_cpu_dtr_t;
typedef struct __attribute__((packed)) {
    uint16_t lo,selector; uint8_t ist,type; uint16_t mid; uint32_t hi,zero;
} shz_cpu_gate_t;
typedef struct __attribute__((packed)) {
    uint32_t reserved0; uint64_t rsp[3],reserved1,ist[7],reserved2;
    uint16_t reserved3,iomap;
} shz_cpu_tss_t;
typedef struct {
    shz_cpu_gate_t idt[256]; uint64_t gdt[7]; shz_cpu_tss_t tss;
} shz_cpu_arch_tables_t;
_Static_assert(sizeof(shz_cpu_gate_t)==16 && sizeof(shz_cpu_tss_t)==104,"x86 descriptor formats");
_Static_assert(sizeof(shz_cpu_arch_tables_t)<=8192,"private AP tables fit two PMM pages");
int shz_cpu_arch_build_tables(shz_cpu_arch_tables_t *,uint64_t boot,uint64_t irq,uint64_t df);
int shz_cpu_arch_allocate(unsigned count);
int shz_cpu_arch_enter(unsigned cpu);
uint64_t shz_cpu_arch_resource(unsigned cpu);
int shz_cpu_arch_describe(unsigned cpu,uint64_t *gdt,uint64_t *idt,uint64_t *tss);
/* Explicit native kernel cohort only; private F1/IST1 stays unchanged. */
int shz_cpu_arch_sched_stack(unsigned cpu,uint64_t top,int bind);
int shz_cpu_arch_sched_install(unsigned cpu);
int shz_cpu_arch_sched_restore(unsigned cpu);
int shz_cpu_arch_sched_timer_prepare(volatile uint32_t *lapic);
int shz_cpu_arch_sched_timer(unsigned cpu,int enable);
void shz_cpu_arch_sched_irq(struct regs *frame);
void shz_cpu_arch_ipi(unsigned reason,uint64_t stack);
void shz_cpu_arch_fault(unsigned cpu);
#endif
