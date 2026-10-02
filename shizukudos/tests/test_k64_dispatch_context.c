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
    setvbuf(stdout,0,_IOLBF,0);cpu_set_t allowed,single;
    if(sched_getaffinity(0,sizeof allowed,&allowed))return 2;
    unsigned host;for(host=0;host<CPU_SETSIZE && !CPU_ISSET(host,&allowed);++host){}
    if(host==CPU_SETSIZE)return 2;
    CPU_ZERO(&single);CPU_SET(host,&single);
    if(sched_setaffinity(0,sizeof single,&single))return 2;
    setup();
    expect("actual mapped online context is not the CPU0 mirror",sched_cpu_identity()==1 && thread_current()==&pool[5] && current==&pool[0]);
    uint64_t idle,kernel,user;sched_processor_times(&idle,&kernel,&user);
    expect("processor accounting selects actual owner record",idle==11*TICK_US*10ull && kernel==33*TICK_US*10ull && user==33*TICK_US*10ull);
    volatile uintptr_t setter=(uintptr_t)sched_set_current_kstack;
    expect("new stack publication interface exists",setter!=0);
    if(setter) {
        ((void (*)(uint64_t))setter)(pool[5].stack_base+KSTACK_BYTES);
        expect("stack publication uses owner anchor and preserves CPU0",shz_smp_cpus[1].syscall_kstack==pool[5].stack_base+KSTACK_BYTES && !shz_smp_cpus[0].syscall_kstack);
    }
    if(thread_current()==&pool[5]) {
        pool[6].state=TS_READY;uint32_t ticket=k64_rq_lock(&runqueues);
        expect("actual next context admits only to owner queue",!k64_rq_enqueue_locked(&runqueues,&pool[6],1,3,++ready_order));k64_rq_unlock(&runqueues,ticket);
        jiffies=13;observe_next=&pool[6];observe_outgoing=&pool[5];observe_waited=10;pma_sched_trace_enabled=1;
        pool[5].state=TS_BLOCKED;boundary_mode=1;uint64_t f=irq_save();schedule(0);irq_restore(f);
        expect("actual schedule changes only owner current",runqueues.cpu[1].current==&pool[6] && pool[6].on_cpu==1 && current==&pool[0] && pool[0].on_cpu==0);
        observe_next=&pool[5];observe_outgoing=&pool[6];observe_waited=0;pma_sched_trace_enabled=0;pma_sched_observe_enabled=1;
        boundary_mode=2;pool[6].state=TS_ZOMBIE;f=irq_save();schedule(0);irq_restore(f);
        expect("second handoff resumes saved permitted context",runqueues.cpu[1].current==&pool[5] && boundary_checks==2);
        observe_outgoing=0;pma_sched_trace_enabled=1;f=irq_save();schedule(0);irq_restore(f);
        expect("changed trace, changed observe and unchanged combined flags each emit once",dispatch_observations==3 && boundary_checks==2 && flags==0x246);
        pma_sched_trace_enabled=pma_sched_observe_enabled=0;
        identity(0);expect("BSP join reclaims only completed terminal context",thread_join(&pool[6])==0 && freed==1 && pool[6].state==TS_FREE);identity(1);
        expect("multi-owner validator conserves running identities",sched_validate());
    } else puts("RED_DIAGNOSTIC: dispatch interleavings require owner-local current; not executed on missing foundation");
    runqueues.online_mask=1;uint64_t before=pool[0].run_ticks;sched_tick();
    expect("unonline mapped owner cannot charge or borrow BSP",!thread_current() && pool[0].run_ticks==before && sched_cpu_register(1)==-2);
    identity(32);expect("unknown physical owner rejects all current state",sched_cpu_identity()==UINT32_MAX && !thread_current());
    printf("checks=%u failures=%u scope=actual_C_logical_owner_boundary_only\n",checks,failures);return failures?1:0;
}
#endif
