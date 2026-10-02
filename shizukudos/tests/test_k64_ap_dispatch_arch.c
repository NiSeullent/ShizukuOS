/* SPDX-License-Identifier: GPL-2.0-only
 * Actual architecture/provider C. Only CPU instructions and table loads are
 * substituted; this checks publication/descriptor state, not hardware entry.
 */
#define _GNU_SOURCE
#define SHZ_STANDALONE
#include <stdio.h>
#include <sched.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#define irq_save native_irq_save
#define irq_restore native_irq_restore
#define rdmsr native_rdmsr
#define wrmsr native_wrmsr
#define read_cr0 native_read_cr0
#define write_cr0 native_write_cr0
#define read_cr4 native_read_cr4
#define write_cr4 native_write_cr4
#define read_cr2 native_read_cr2
#define read_cr3 native_read_cr3
#define shz_exit native_shz_exit
#define shz_evidence native_shz_evidence
#include "../kernel64/k64.h"
#undef irq_save
#undef irq_restore
#undef rdmsr
#undef wrmsr
#undef read_cr0
#undef write_cr0
#undef read_cr4
#undef write_cr4
#undef read_cr2
#undef read_cr3
#undef shz_exit
#undef shz_evidence
static uint64_t flags=0x46, control0,control4,gs=0xffff800011110000ull,kgs;
static uint64_t irq_save(void) { uint64_t f=flags;flags&=~0x200u;return f; }
static void irq_restore(uint64_t f) { flags=f; }
static uint64_t rdmsr(uint32_t m) { return m==MSR_GS_BASE?gs:m==MSR_KERNEL_GS_BASE?kgs:0; }
static void wrmsr(uint32_t m,uint64_t v) { if(m==MSR_GS_BASE)gs=v;if(m==MSR_KERNEL_GS_BASE)kgs=v; }
static uint64_t read_cr0(void) { return control0; }
static uint64_t read_cr4(void) { return control4; }
static void write_cr0(uint64_t v) { control0=v; }
static void write_cr4(uint64_t v) { control4=v; }
static uint64_t read_cr2(void) { return 0; }
static uint64_t read_cr3(void) { return 0; }
static jmp_buf terminal;
static unsigned driver_callbacks,fatal_entries,random_calls,tick_calls,reschedule_calls;
static int eoi_before_tick;
static thread_t irq_thread;
static volatile uint32_t fake_apic[1024];
static void shz_evidence(unsigned s,uint64_t v) { (void)s;(void)v; }
static void __attribute__((noreturn)) shz_exit(unsigned c) { (void)c;longjmp(terminal,1); }
#include "../kernel64/arch.c"
#include "../kernel64/smp_boot.c"
void load_gdt(void *p,uint16_t s) { (void)p;(void)s; }
void load_idt(void *p) { (void)p; }
void syscall_entry(void) { }
void kprintf(const char *f,...) { (void)f; }
void kpanic(const char *f,...) { (void)f;abort(); }
void standalone_eoi(void) { ++driver_callbacks; }
void standalone_eoi_irq(unsigned v) { (void)v;++driver_callbacks; }
void krandom_irq(uint64_t v,uint64_t rip) { (void)v;(void)rip;++random_calls; }
uint64_t pmm_alloc(void) { return 0; }
uint64_t kernel_pml4(void) { return 0; }
int vm_map(uint64_t p,uint64_t v,uint64_t a,uint64_t f) { (void)p;(void)v;(void)a;(void)f;return -1; }
int kwin_fault(uint64_t a) { (void)a;return 0; }
int user_page_fault(struct regs *r,uint64_t a) { (void)r;(void)a;return 0; }
int user_fault(struct regs *r) { (void)r;return 0; }
int ntdrv_kernel_exception(struct regs *r) { (void)r;++driver_callbacks;return 1; }
void ds_native_exception(const struct regs *r) { (void)r;++fatal_entries;longjmp(terminal,1); }
void sched_tick_from(int user) { (void)user;++tick_calls;eoi_before_tick=fake_apic[0xb0/4]==0; }
void sched_ap_reschedule(void) { ++reschedule_calls;eoi_before_tick=fake_apic[0xb0/4]==0; }
thread_t *thread_current(void) { return &irq_thread; }
int current_thread_must_stop(void) { return 0; }
void check_kill(void) { }
const uint64_t isr_stub_table[256]={[0xf0]=(uint64_t)syscall_entry,[0xf2]=(uint64_t)syscall_entry};
volatile int pma_sched_trace_enabled;
static unsigned checks,failures;
static void check(const char *n,int c) { ++checks;failures+=!c;printf("%s: %s\n",c?"PASS":"FAIL",n); }
static void identity(unsigned cpu)
{
    memset(&topology,0,sizeof topology);
    if(!cpu)return;
    const unsigned actual=initial_apic_id();topology.count=cpu==1?2:1;
    topology.apic_id[0]=actual^0xffu;if(cpu==1)topology.apic_id[1]=actual;
}

extern int shz_cpu_arch_sched_install(unsigned cpu) __attribute__((weak));
#include "../kernel64/cpu_arch_bringup.c"
void shz_cpu_arch_fault(unsigned cpu) { (void)cpu; }
void shz_cpu_arch_ipi(unsigned reason,uint64_t stack) { (void)reason;(void)stack; }
int main(void)
{
    cpu_set_t allowed,single;if(sched_getaffinity(0,sizeof allowed,&allowed))return 2;
    unsigned host;for(host=0;host<CPU_SETSIZE && !CPU_ISSET(host,&allowed);++host){}
    if(host==CPU_SETSIZE)return 2;CPU_ZERO(&single);CPU_SET(host,&single);
    if(sched_setaffinity(0,sizeof single,&single))return 2;
    identity(1);allocated_count=2;
    static shz_cpu_arch_tables_t private_tables;tables[1]=&private_tables;
    const uint64_t boot=0xffff800012348000ull, irq=boot+KSTACK_BYTES, df=irq+8192;
    check("real table builder accepts distinct retained private spans",!shz_cpu_arch_build_tables(tables[1],boot,irq,df));
    shz_cpu_gate_t f1=tables[1]->idt[SHZ_SMP_VEC_TLB];
    check("legacy private F0 is not a schedulable task-stack gate",tables[1]->idt[SHZ_SMP_VEC_RESCHEDULE].ist==1);
    shz_smp_cpus[1].state=SHZ_SMP_CPU_ONLINE;
#ifdef SHZ_CPU_ARCH_SCHED_COHORT
    entered_mask=2;
#endif
    check("prepared actual private owner can bind its own scheduler stack",!arch_sched_entry_bind(1,boot) && tables[1]->tss.rsp[0]==boot && kgs==(uintptr_t)&shz_smp_cpus[1]);
    check("binding never overwrites ordinary NT GS",gs==0xffff800011110000ull);
    volatile uintptr_t install=(uintptr_t)shz_cpu_arch_sched_install;
    int installed=install?((int (*)(unsigned))install)(1):-2;
    check("explicit private scheduler interrupt installation succeeds",installed==0);
    check("installed F0 and F2 use task stacks",tables[1]->idt[SHZ_SMP_VEC_RESCHEDULE].ist==0 && tables[1]->idt[SHZ_SMP_VEC_TIMER].ist==0);
    check("protected F1 descriptor and IST1 are unchanged",!memcmp(&f1,&tables[1]->idt[SHZ_SMP_VEC_TLB],sizeof f1) && f1.ist==1);
    const uint64_t prior=tables[1]->tss.rsp[0];flags=0x246;
    check("IF-on private stack update refuses without mutation",arch_sched_entry_set_stack(1,boot+16)==-1 && tables[1]->tss.rsp[0]==prior && flags==0x246);
    flags=0x46;check("invalid private stack refuses without mutation",arch_sched_entry_set_stack(1,boot+1)==-1 && tables[1]->tss.rsp[0]==prior);
    check("prepared actual private owner updates its own TSS",!arch_sched_entry_set_stack(1,boot+16) && tables[1]->tss.rsp[0]==boot+16 && gs==0xffff800011110000ull);
    struct regs frame={0};frame.cs=8;frame.vector=SHZ_SMP_VEC_TIMER;
    irq_thread.stack_base=((uintptr_t)&frame&~4095ull)-4096;frame.rsp=(uintptr_t)&frame+sizeof frame;
    irq_thread.ap_kernel_cohort=1;irq_thread.on_cpu=1;irq_thread.state=TS_RUNNING;irq_thread.cpu_mask=2;lapic=fake_apic;
    fake_apic[0xb0/4]=7;isr_dispatch(&frame);
    check("actual AP timer route acknowledges before dispatcher callback",tick_calls==1 && eoi_before_tick && shz_smp_cpus[1].timer_irqs==1);
    check("AP task IRQ bypasses shared entropy and device callbacks",random_calls==0 && driver_callbacks==0);
    frame.vector=SHZ_SMP_VEC_RESCHEDULE;fake_apic[0xb0/4]=9;isr_dispatch(&frame);
    check("actual AP F0 route acknowledges before reschedule",reschedule_calls==1 && eoi_before_tick && shz_smp_cpus[1].reschedule_ipis==1);
    check("cohort stop restores private F0 and retains exact F1",!shz_cpu_arch_sched_restore(1) && tables[1]->idt[SHZ_SMP_VEC_RESCHEDULE].ist==1 && !memcmp(&f1,&tables[1]->idt[SHZ_SMP_VEC_TLB],sizeof f1));
    const shz_cpu_gate_t stopped=tables[1]->idt[SHZ_SMP_VEC_TIMER];
    const uint64_t stopped_entry=stopped.lo|((uint64_t)stopped.mid<<16)|((uint64_t)stopped.hi<<32);
    check("masked but pending local timer has a non-scheduling private drain gate",stopped.ist==1 && stopped_entry!=(uintptr_t)fault_no_error);
    entered_mask=0;kgs=0;shz_smp_cpu_t untouched=shz_smp_cpus[1];
    check("architecture ONLINE without entered private table refuses",arch_sched_entry_bind(1,boot)==-2 && !memcmp(&untouched,&shz_smp_cpus[1],sizeof untouched) && !kgs);
    identity(32);check("unknown owner never borrows a private or BSP stack",arch_sched_entry_bind(1,boot)==-1 && arch_sched_entry_set_stack(0,boot)==-1);
    printf("checks=%u failures=%u scope=actual_arch_C_host_privileged_adapters_no_AP\n",checks,failures);return failures?1:0;
}
