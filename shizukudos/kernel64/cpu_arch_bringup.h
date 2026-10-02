/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_CPU_ARCH_BRINGUP_H
#define SHZ_CPU_ARCH_BRINGUP_H
#define SHZ_CPU_ARCH_SCHED_COHORT 1
#include "k64.h"
#include "smp_boot.h"
#define SHZ_CPU_ARCH_NMI_BYTES 8192u
#define SHZ_CPU_ARCH_BYTES 16384u
#define SHZ_CPU_ARCH_PAGES (SHZ_CPU_ARCH_BYTES / PAGE_SIZE)
typedef struct __attribute__((packed)) { uint16_t limit; uint64_t base; } shz_cpu_dtr_t;
typedef struct __attribute__((packed)) {
    uint16_t lo,selector; uint8_t ist,type; uint16_t mid; uint32_t hi,zero;
} shz_cpu_gate_t;
typedef struct __attribute__((packed)) {
    uint32_t reserved0; uint64_t rsp[3],reserved1,ist[7],reserved2;
    uint16_t reserved3,iomap;
} shz_cpu_tss_t;
#define SHZ_AP_WORK_TRACE_SLOTS 32u
typedef struct {
    uint64_t sequence;
    uint32_t kind,cpu,thread,vector;
    uint64_t frame,rip,flags,rsp,base,top,eoi,complete,rsp0;
} shz_ap_work_trace_record_t;
typedef struct {
    uint64_t cr3,gdt,idt,tss,rsp0,gs,kernel_gs,efer,stack;
    uint32_t cpu,apic,tr,gdt_limit,idt_limit,count,dropped,done;
    uint64_t sequence,eoi,complete;
    shz_ap_work_trace_record_t record[SHZ_AP_WORK_TRACE_SLOTS];
} shz_ap_work_trace_t;
typedef struct {
    shz_cpu_gate_t idt[256]; uint64_t gdt[7]; shz_cpu_tss_t tss;
    uint8_t nmi_stack[SHZ_CPU_ARCH_NMI_BYTES] __attribute__((aligned(16)));
    shz_ap_work_trace_t work_trace;          /* owned AP writes; BSP reads only after done release */
} shz_cpu_arch_tables_t;
_Static_assert(sizeof(shz_cpu_gate_t)==16 && sizeof(shz_cpu_tss_t)==104,"x86 descriptor formats");
_Static_assert(sizeof(shz_cpu_arch_tables_t)<=SHZ_CPU_ARCH_BYTES,"private AP tables and NMI stack fit four PMM pages");
_Static_assert(SHZ_CPU_ARCH_PAGES==4 && offsetof(shz_cpu_arch_tables_t,nmi_stack)%16==0,"private NMI stack resource and alignment");
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
void shz_cpu_arch_work_enable(unsigned cpu); /* BSP pre-INIT only */
int shz_cpu_arch_work_available(unsigned count); /* no entered AP or prior resource lifetime */
uint64_t shz_cpu_arch_work_online_mask(void); /* BSP snapshot of entered/private gates/physical ONLINE */
void shz_cpu_arch_work_complete(unsigned cpu); /* destination stack, IF clear, no ticket */
void shz_cpu_arch_work_finish(unsigned cpu); /* bootstrap, IRQ gates restored */
int shz_cpu_arch_work_report(unsigned cpu);  /* BSP only, acquire done; no live AP reads */
int shz_cpu_arch_work_ready(unsigned cpu);
void shz_cpu_arch_ipi(unsigned reason,uint64_t stack);
void shz_cpu_arch_fault(unsigned cpu);
#endif
