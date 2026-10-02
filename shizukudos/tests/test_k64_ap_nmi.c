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
static unsigned alloc_calls,free_calls,fail_after,request_pages[4],free_pages[4];
static uint64_t free_addresses[4];
uint64_t phys_base_va;
static uint8_t allocation[3][16384] __attribute__((aligned(4096)));
uint64_t pmm_alloc_contig(unsigned n)
{
    request_pages[alloc_calls]=n; ++alloc_calls;
    if(fail_after && alloc_calls==fail_after) return 0;
    return 0x100000+(alloc_calls-1)*16384;
}
void pmm_free_contig(uint64_t pa,unsigned n)
{ free_addresses[free_calls]=pa;free_pages[free_calls++]=n; }
static void reset_alloc(unsigned fail)
{
    allocated_count=0;memset(tables,0,sizeof tables);alloc_calls=free_calls=0;
    memset(request_pages,0,sizeof request_pages);memset(free_pages,0,sizeof free_pages);
    fail_after=fail;phys_base_va=(uintptr_t)allocation-0x100000;
}
int main(void)
{
    cpu_set_t allowed,single;if(sched_getaffinity(0,sizeof allowed,&allowed))return 2;
    unsigned host;for(host=0;host<CPU_SETSIZE && !CPU_ISSET(host,&allowed);++host){}
    if(host==CPU_SETSIZE)return 2;CPU_ZERO(&single);CPU_SET(host,&single);
    if(sched_setaffinity(0,sizeof single,&single))return 2;
    static shz_cpu_arch_tables_t t;
    const uint64_t boot=0xffff800012348000ull,irq=boot+KSTACK_BYTES,df=irq+8192;
    check("actual private table builder accepts distinct resources",!shz_cpu_arch_build_tables(&t,boot,irq,df));
    shz_cpu_gate_t f1=t.idt[SHZ_SMP_VEC_TLB],dfgate=t.idt[8];
    const uint64_t f1_top=t.tss.ist[0],df_top=t.tss.ist[1];
    check("actual NMI gate uses dedicated IST3 instead of F1 IST1",t.idt[2].ist==3 && t.tss.ist[2]!=0 && t.tss.ist[2]!=f1_top && t.tss.ist[2]!=df_top);
    check("actual retained table contains the additional private NMI stack",sizeof t>8192 && sizeof t<=16384);
#ifdef SHZ_CPU_ARCH_NMI_BYTES
    check("NMI top is the aligned actual embedded member end",t.tss.ist[2]==(uintptr_t)t.nmi_stack+sizeof t.nmi_stack && !(t.tss.ist[2]&15) && sizeof t.nmi_stack==8192);
    check("NMI span fits the fully retained descriptor resource",(uintptr_t)t.nmi_stack>=(uintptr_t)&t+sizeof t.idt+sizeof t.gdt+sizeof t.tss && t.tss.ist[2]<=(uintptr_t)&t+SHZ_CPU_ARCH_BYTES);
#else
    check("NMI top is the aligned actual embedded member end",0);
    check("NMI span fits the fully retained descriptor resource",0);
#endif
    check("F1 remains its original private handler on IST1",f1.ist==1 && t.tss.ist[0]==irq);
    check("DF remains its original private handler on IST2",dfgate.ist==2 && t.tss.ist[1]==df);
#ifdef SHZ_CPU_ARCH_NMI_BYTES
    uint8_t before[sizeof t];memcpy(before,&t,sizeof t);
    check("unaligned private resource refuses without table writes",shz_cpu_arch_build_tables((void *)((uintptr_t)&t+1),boot,irq,df)==-1 && !memcmp(before,&t,sizeof t));
    check("overlap with the actual boot stack refuses before writes",shz_cpu_arch_build_tables((void *)(uintptr_t)(boot-KSTACK_BYTES),boot,irq,df)==-1);
    check("overflowed private allocation extent refuses before writes",shz_cpu_arch_build_tables((void *)(uintptr_t)0xffffffffffffe000ull,boot,irq,df)==-1);
#else
    check("unaligned private resource refuses without table writes",0);
    check("overlap with the actual boot stack refuses before writes",0);
    check("overflowed private allocation extent refuses before writes",0);
#endif
    identity(1);tables[1]=&t;allocated_count=2;entered_mask=2;
    shz_smp_cpus[1].state=SHZ_SMP_CPU_ONLINE;kgs=(uintptr_t)&shz_smp_cpus[1];flags=0x46;
    check("cohort install retains dedicated NMI and exact F1/DF gates",!shz_cpu_arch_sched_install(1) && t.idt[2].ist==3 && !memcmp(&f1,&t.idt[SHZ_SMP_VEC_TLB],sizeof f1) && !memcmp(&dfgate,&t.idt[8],sizeof dfgate));
    check("cohort restore retains dedicated NMI and exact F1/DF gates",!shz_cpu_arch_sched_restore(1) && t.idt[2].ist==3 && !memcmp(&f1,&t.idt[SHZ_SMP_VEC_TLB],sizeof f1) && !memcmp(&dfgate,&t.idt[8],sizeof dfgate));
    reset_alloc(0);
    check("actual allocator admits two retained AP resources",!shz_cpu_arch_allocate(3) && alloc_calls==2 && allocated_count==3);
    check("actual PMM requests cover all four resource pages",request_pages[0]==4 && request_pages[1]==4 && !free_calls);
    check("actual resource physical identity is not fabricated",shz_cpu_arch_resource(1)==0x100000 && shz_cpu_arch_resource(2)==0x104000 && shz_cpu_arch_resource(0)==0 && shz_cpu_arch_resource(32)==0);
    const unsigned calls=alloc_calls;
    check("already allocated lifetime refuses reallocation",shz_cpu_arch_allocate(3)==-1 && alloc_calls==calls && !free_calls);
    reset_alloc(2);
    check("pre-INIT allocation failure rolls back full prior span",shz_cpu_arch_allocate(3)==-1 && allocated_count==0 && !tables[1] && free_calls==1 && free_addresses[0]==0x100000 && free_pages[0]==4);
    reset_alloc(0);
    check("invalid CPU count refuses without allocations",shz_cpu_arch_allocate(0)==-1 && shz_cpu_arch_allocate(33)==-1 && !alloc_calls && !free_calls);
    printf("checks=%u failures=%u scope=actual_AP_NMI_table_allocator_C_only_no_hardware_NMI\n",checks,failures);return failures?1:0;
}
