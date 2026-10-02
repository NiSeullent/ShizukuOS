/* SPDX-License-Identifier: GPL-2.0-only
 * Actual architecture/provider C. Only CPU instructions and table loads are
 * substituted; this checks publication/descriptor state, not hardware entry.
 */
#define _GNU_SOURCE
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
static unsigned driver_callbacks,fatal_entries;
static void shz_evidence(unsigned s,uint64_t v) { (void)s;(void)v; }
static void __attribute__((noreturn)) shz_exit(unsigned c) { (void)c;longjmp(terminal,1); }
#include "../kernel64/arch.c"
#include "../kernel64/smp_boot.c"
void load_gdt(void *p,uint16_t s) { (void)p;(void)s; }
void load_idt(void *p) { (void)p; }
void syscall_entry(void) { }
void kprintf(const char *f,...) { (void)f; }
void kpanic(const char *f,...) { (void)f;abort(); }
void krandom_irq(uint64_t v,uint64_t rip) { (void)v;(void)rip; }
uint64_t pmm_alloc(void) { return 0; }
uint64_t kernel_pml4(void) { return 0; }
int vm_map(uint64_t p,uint64_t v,uint64_t a,uint64_t f) { (void)p;(void)v;(void)a;(void)f;return -1; }
int kwin_fault(uint64_t a) { (void)a;return 0; }
int user_page_fault(struct regs *r,uint64_t a) { (void)r;(void)a;return 0; }
int user_fault(struct regs *r) { (void)r;return 0; }
int ntdrv_kernel_exception(struct regs *r) { (void)r;++driver_callbacks;return 1; }
void ds_native_exception(const struct regs *r) { (void)r;++fatal_entries;longjmp(terminal,1); }
void sched_tick_from(int user) { (void)user; }
int current_thread_must_stop(void) { return 0; }
void check_kill(void) { }
const uint64_t isr_stub_table[256]={0};
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
int main(void)
{
    cpu_set_t allowed,single;if(sched_getaffinity(0,sizeof allowed,&allowed))return 2;
    unsigned host;for(host=0;host<CPU_SETSIZE && !CPU_ISSET(host,&allowed);++host){}
    if(host==CPU_SETSIZE)return 2;
    CPU_ZERO(&single);CPU_SET(host,&single);if(sched_setaffinity(0,sizeof single,&single))return 2;
    identity(0);arch_init();
    check("actual BSP NMI and DF have distinct retained ISTs",idt[2].ist==2 && idt[8].ist==1 && tss.ist[0]!=(uint64_t)0 && tss.ist[1]!=(uint64_t)0 && tss.ist[0]!=tss.ist[1]);
    check("actual timer and reschedule gates retain thread stack",idt[VEC_TIMER].ist==0 && idt[SHZ_SMP_VEC_RESCHEDULE].ist==0);
    const uint64_t top=0xffff800012348000ull,ordinary=gs;
    check("IF-off BSP binds real existing anchor",arch_sched_entry_bind(0,top)==0 && kgs==(uintptr_t)&shz_smp_cpus[0] && shz_smp_cpus[0].syscall_kstack==top && tss.rsp[0]==top);
    check("bind preserves ordinary NT GS",gs==ordinary && flags==0x46);
    shz_smp_cpu_t before=shz_smp_cpus[0];const uint64_t prior=tss.rsp[0];
    flags=0x246;check("IF-on bind refuses without publication",arch_sched_entry_bind(0,top+16)==-1 && !memcmp(&before,&shz_smp_cpus[0],sizeof before) && tss.rsp[0]==prior && flags==0x246);flags=0x46;
    check("invalid stack refuses without publication",arch_sched_entry_set_stack(0,top+1)==-1 && arch_sched_entry_set_stack(0,0xffff000000100000ull)==-1 && !memcmp(&before,&shz_smp_cpus[0],sizeof before) && tss.rsp[0]==prior);
    kgs=123;check("wrong anchor refuses without fallback",arch_sched_entry_set_stack(0,top+16)==-1 && tss.rsp[0]==prior && shz_smp_cpus[0].syscall_kstack==top);kgs=(uintptr_t)&shz_smp_cpus[0];
    check("stack setter publishes anchor and owning TSS together",arch_sched_entry_set_stack(0,top+16)==0 && tss.rsp[0]==top+16 && shz_smp_cpus[0].syscall_kstack==top+16 && gs==ordinary);
    shz_smp_cpu_t snapshot[SHZ_SMP_MAX_CPUS];memcpy(snapshot,shz_smp_cpus,sizeof snapshot);uint64_t saved=tss.rsp[0];
    identity(1);check("mapped AP never borrows BSP private TSS",arch_sched_entry_bind(1,top)==-2 && arch_sched_entry_set_stack(1,top)==-2 && arch_sched_entry_set_stack(0,top)==-1 && !memcmp(snapshot,shz_smp_cpus,sizeof snapshot) && tss.rsp[0]==saved);
    identity(32);check("unknown CPU never publishes anchor",arch_sched_entry_bind(0,top)==-1 && arch_sched_entry_bind(32,top)==-1 && !memcmp(snapshot,shz_smp_cpus,sizeof snapshot) && tss.rsp[0]==saved);
    struct regs r={0};r.cs=8;
    r.vector=2;driver_callbacks=fatal_entries=0;
    if(!setjmp(terminal))isr_dispatch(&r);
    check("NMI IST cannot enter shared driver recovery callbacks",driver_callbacks==0 && fatal_entries==1);
    r.vector=8;driver_callbacks=fatal_entries=0;
    if(!setjmp(terminal))isr_dispatch(&r);
    check("DF IST cannot enter shared driver recovery callbacks",driver_callbacks==0 && fatal_entries==1);
    printf("checks=%u failures=%u scope=actual_arch_C_privileged_boundaries_substituted\n",checks,failures);return failures?1:0;
}
