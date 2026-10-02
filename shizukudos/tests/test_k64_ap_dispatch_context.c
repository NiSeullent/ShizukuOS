/* SPDX-License-Identifier: GPL-2.0-only
 * Actual scheduler/provider C with privileged and stack boundaries substituted.
 * Logical online records below are fixtures, not AP admission or execution.
 */
#ifdef SHZ_DISPATCH_HOOK_OVERRIDE
/* A separate real translation unit supplies the strong override of sched.c's
 * weak external hook. The observer itself lives beside the actual scheduler. */
#include "../kernel64/k64.h"
extern void test_dispatch_observation(thread_t *, uint64_t);
void pma_sched_trace_dispatch(thread_t *t, uint64_t waited)
{
    test_dispatch_observation(t, waited);
}
#else
#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#define irq_save native_irq_save
#define irq_restore native_irq_restore
#define read_cr3 native_read_cr3
#define write_cr3 native_write_cr3
#define rdmsr native_rdmsr
#define wrmsr native_wrmsr
#include "../kernel64/k64.h"
#undef irq_save
#undef irq_restore
#undef read_cr3
#undef write_cr3
#undef rdmsr
#undef wrmsr
static uint64_t flags=0x246, cr3=0x1000;
static uint64_t irq_save(void) { uint64_t f=flags;flags&=~0x200u;return f; }
static void irq_restore(uint64_t f) { flags=f; }
static uint64_t read_cr3(void) { return cr3; }
static void write_cr3(uint64_t v) { cr3=v; }
static uint64_t rdmsr(uint32_t m) { (void)m;return 0; }
static void wrmsr(uint32_t m,uint64_t v) { (void)m;(void)v; }
extern void sched_set_current_kstack(uint64_t) __attribute__((weak));
#include "../kernel64/sched.c"
#undef ready_count
#include "../kernel64/smp_boot.c"
static unsigned checks, failures, freed, boundary_checks;
static unsigned dispatch_observations;
static thread_t *observe_next, *observe_outgoing;
static uint64_t observe_waited;
static int boundary_mode;
static thread_t pool[10] __attribute__((aligned(16)));
static void expect(const char *n,int c) { ++checks;printf("%s: %s\n",c?"PASS":"FAIL",n);failures+=!c; }
void test_dispatch_observation(thread_t *t,uint64_t waited)
{
    const unsigned cpu=sched_cpu_identity();uint32_t ticket;
    const int unlocked=pma_ticket_trylock(&runqueues.lock,&ticket);
    expect("external dispatch override can try-lock the real queue ticket",unlocked);
    expect("external dispatch observation retains IRQ-off caller state",!(flags&0x200));
    expect("dispatch observer receives the selected owner and original wait",t==observe_next && waited==observe_waited &&
           t==runqueues.cpu[cpu].current && t->state==TS_RUNNING && t->on_cpu==cpu && !t->ready_queued);
    expect("observation keeps outgoing live-stack ownership until completion",runqueues.cpu[cpu].outgoing==observe_outgoing &&
           (!observe_outgoing || (observe_outgoing->on_cpu==cpu && !observe_outgoing->ready_queued)) && current==&pool[0]);
    if(unlocked)k64_rq_unlock(&runqueues,ticket);
    ++dispatch_observations;
}
static void identity(unsigned cpu)
{
    const uint32_t actual=initial_apic_id();
    memset(&topology,0,sizeof topology);
    if(!cpu)return;
    topology.count=cpu<32?cpu+1:1;
    for(unsigned i=0;i<topology.count;i++)topology.apic_id[i]=actual^0xffu;
    if(cpu<32)topology.apic_id[cpu]=actual;
}
int ntdrv_gs_all;
uint64_t kernel_pml4(void) { return 0x1000; }
uint64_t proc_pml4(process_t *p) { (void)p;return 0x1000; }
void tss_set_rsp0(uint64_t top) { (void)top; }
int arch_sched_entry_bind(uint32_t cpu,uint64_t top) { shz_smp_cpus[cpu].syscall_kstack=top;return 0; }
int arch_sched_entry_set_stack(uint32_t cpu,uint64_t top) { shz_smp_cpus[cpu].syscall_kstack=top;return 0; }
void switch_stacks(uint64_t *saved,uint64_t dest)
{
    (void)dest;const unsigned cpu=sched_cpu_identity();
    thread_t *old=runqueues.cpu[cpu].outgoing;uint32_t ticket;
    int unlocked=pma_ticket_trylock(&runqueues.lock,&ticket);
    expect("selected CPU releases ticket before stack boundary",unlocked && !(flags&0x200));
    if(unlocked)k64_rq_unlock(&runqueues,ticket);
    expect("outgoing context retains selected CPU until stack saved",old && saved==&old->rsp && old->on_cpu==cpu && !old->ready_queued);
    if(boundary_mode==1) {
        identity(0);thread_wake(old);identity(cpu);
        expect("BSP wake during remote handoff remains withheld",old->state==TS_READY && old->on_cpu==cpu && !old->ready_queued);
    }
    if(boundary_mode==2)expect("terminal outgoing stack is not reapable",old->state==TS_ZOMBIE && !k64_rq_reapable_locked(&runqueues,old) && !freed);
    sched_switch_complete();
    expect("destination completion releases only its outgoing owner",old->on_cpu==K64_CPU_NONE && !runqueues.cpu[cpu].outgoing && !runqueues.cpu[0].outgoing);
    if(boundary_mode==1)expect("deferred wake publishes once to permitted CPU",old->ready_queued && old->ready_cpu==cpu && runqueues.cpu[cpu].ready_count==1);
    ++boundary_checks;
}
void kpanic(const char *f,...) { va_list a;va_start(a,f);vfprintf(stderr,f,a);va_end(a);abort(); }
void kprintf(const char *f,...) { (void)f; }
void thread_start(void) { abort(); }
uint64_t pmm_alloc_contig(unsigned n) { (void)n;return 0; }
void pmm_free_contig(uint64_t b,unsigned n) { (void)b;(void)n;++freed; }
uint64_t phys_base_va;
uint8_t kstack_top[KSTACK_BYTES];
static void setup(void)
{
    memset(pool,0,sizeof pool);threads=pool;thread_hi=10;k64_rq_init(&runqueues,pool,10,3);
    memset(shz_smp_cpus,0,sizeof shz_smp_cpus);jiffies=ready_order=switches=preemptions=wakeups=timeouts=0;flags=0x246;freed=boundary_checks=dispatch_observations=0;
    pma_sched_trace_enabled=pma_sched_observe_enabled=0;
    for(unsigned i=0;i<10;i++) {
        pool[i].id=i+1;pool[i].quantum_ticks=pool[i].quantum_left=1;pool[i].sched_priority=16;
        pool[i].cpu_mask=i<5?1:2;pool[i].ready_cpu=pool[i].on_cpu=K64_CPU_NONE;
        pool[i].stack_base=0xffff800000100000ull+i*KSTACK_BYTES;pool[i].rsp=pool[i].stack_base+KSTACK_BYTES-64;
        __asm__ volatile("fxsave (%0)"::"r"(pool[i].fx):"memory");
    }
    current=&pool[0];current->state=TS_RUNNING;current->on_cpu=0;runqueues.cpu[0].current=current;
    idle_thread=&pool[4];idle_thread->state=TS_READY;idle_thread->sched_priority=0;runqueues.cpu[0].idle=idle_thread;
    runqueues.cpu[1].current=&pool[5];pool[5].state=TS_RUNNING;pool[5].on_cpu=1;
    runqueues.cpu[1].idle=&pool[9];pool[9].state=TS_READY;pool[9].sched_priority=0;
    runqueues.cpu[0].idle_ticks=1;runqueues.cpu[0].kernel_ticks=2;runqueues.cpu[0].user_ticks=3;
    runqueues.cpu[1].idle_ticks=11;runqueues.cpu[1].kernel_ticks=22;runqueues.cpu[1].user_ticks=33;
    identity(1);
}

int main(void)
{
    cpu_set_t allowed,single;if(sched_getaffinity(0,sizeof allowed,&allowed))return 2;
    unsigned host;for(host=0;host<CPU_SETSIZE && !CPU_ISSET(host,&allowed);++host){}
    if(host==CPU_SETSIZE)return 2;CPU_ZERO(&single);CPU_SET(host,&single);
    if(sched_setaffinity(0,sizeof single,&single))return 2;
    setup();identity(1);runqueues.online_mask=1;
    memset(&runqueues.cpu[1],0,sizeof runqueues.cpu[1]);
    pool[9].state=TS_NEW;pool[9].on_cpu=K64_CPU_NONE;pool[9].cpu_mask=1;pool[9].ap_kernel_cohort=1;
#ifdef K64_AP_COHORT_QUEUE
    uint32_t ticket=k64_rq_lock(&runqueues);
    expect("unknown owner refuses cohort publication",k64_rq_admit_cohort_locked(&runqueues,32,&pool[9])==-1 && runqueues.online_mask==1);
    pool[9].proc=(void *)1;
    expect("process-owned thread cannot be AP idle",k64_rq_admit_cohort_locked(&runqueues,1,&pool[9])==-1 && runqueues.online_mask==1);
    pool[9].proc=0;pool[9].on_cpu=0;
    expect("live stack cannot be admitted twice",k64_rq_admit_cohort_locked(&runqueues,1,&pool[9])==-1 && runqueues.online_mask==1);
    pool[9].on_cpu=K64_CPU_NONE;
    expect("prepared idle publishes exactly its destination CPU",!k64_rq_admit_cohort_locked(&runqueues,1,&pool[9]) && runqueues.cpu[1].current==&pool[9] && runqueues.cpu[1].idle==&pool[9] && pool[9].on_cpu==1 && runqueues.online_mask==3);
    expect("repeat admission refuses without changing current",k64_rq_admit_cohort_locked(&runqueues,1,&pool[9])==-1 && pool[9].on_cpu==1);
    pool[6].state=TS_READY;pool[6].ap_kernel_cohort=1;pool[6].cpu_mask=2;
    expect("prepared saved worker enters actual priority queue",!k64_rq_enqueue_locked(&runqueues,&pool[6],1,0,++ready_order));
    expect("withdraw refuses queued worker and retains live idle",k64_rq_withdraw_cohort_locked(&runqueues,1)==-1 && runqueues.online_mask==3 && pool[9].on_cpu==1);
    expect("saved worker removal conserves ownership",!k64_rq_remove_locked(&runqueues,&pool[6]) && pool[6].on_cpu==K64_CPU_NONE);
    expect("destination bootstrap withdrawal clears only idle CPU",!k64_rq_withdraw_cohort_locked(&runqueues,1) && runqueues.online_mask==1 && pool[9].on_cpu==K64_CPU_NONE && pool[9].state==TS_NEW && current==&pool[0] && pool[0].on_cpu==0);
    k64_rq_unlock(&runqueues,ticket);
#else
    expect("prepared cohort admits on destination stack",0);
#endif
    expect("architecture identity alone never enables public AP admission",sched_cpu_register(1)==-2 && runqueues.online_mask==1);
    printf("checks=%u failures=%u scope=actual_C_cohort_ownership_only_no_AP\n",checks,failures);return failures?1:0;
}
#endif
