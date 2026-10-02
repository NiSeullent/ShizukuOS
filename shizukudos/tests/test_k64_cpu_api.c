/* SPDX-License-Identifier: GPL-2.0-only
 * Actual production scheduler C; substitute privileged CPU and stack boundaries.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <setjmp.h>
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
static unsigned checks, failures, freed, allocations, switches_seen;
static int boundary_mode;
static ksem_t *boundary_sem;
static jmp_buf exit_boundary;
static void expect(const char *,int);
static uint64_t flags=0x246, cr3=0x1000;
static uint64_t irq_save(void) { uint64_t f=flags;flags&=~0x200u;return f; }
static void irq_restore(uint64_t f) {flags=f;}
static uint64_t read_cr3(void) {return cr3;}
static void write_cr3(uint64_t f) {cr3=f;}
static uint64_t rdmsr(uint32_t f) {(void)f;return 0;}
static void wrmsr(uint32_t f,uint64_t v) {(void)f;(void)v;}
extern uint32_t sched_cpu_identity(void) __attribute__((weak));
extern uint64_t sched_cpu_online_mask(void) __attribute__((weak));
extern int sched_cpu_register(uint32_t) __attribute__((weak));
#include "../kernel64/sched.c"
#define ready (runqueues.cpu[0].ready)
#define ready_count (runqueues.cpu[0].ready_count)
/* Real provider executes CPUID against a private immutable-map fixture. Only
 * topology setup is modeled; no duplicate CPU-ID body or fake AP execution. */
#include "../kernel64/smp_boot.c"
static void owner_identity(unsigned cpu)
{
    const uint32_t actual = initial_apic_id();
    memset(&topology,0,sizeof topology);
    if(cpu==0) return; /* explicit UP phase before topology publication */
    topology.count=cpu==1?2:1;
    topology.apic_id[0]=actual^0xffu;
    if(cpu==1)topology.apic_id[1]=actual;
}
int ntdrv_gs_all;
uint64_t kernel_pml4(void) {return 0x1000;}
uint64_t proc_pml4(process_t *p) {(void)p;return 0x1000;}
void tss_set_rsp0(uint64_t t) {(void)t;}
int arch_sched_entry_bind(uint32_t cpu,uint64_t top) {(void)cpu;(void)top;return 0;}
int arch_sched_entry_set_stack(uint32_t cpu,uint64_t top) {(void)cpu;(void)top;return 0;}
void switch_stacks(uint64_t *s,uint64_t t) {
    (void)t;++switches_seen;thread_t *old=runqueues.cpu[0].outgoing;uint32_t ticket;
    int unlocked=pma_ticket_trylock(&runqueues.lock,&ticket);
    expect("ticket absent at real stack boundary",unlocked && !(flags&0x200));
    if(unlocked)k64_rq_unlock(&runqueues,ticket);
    expect("outgoing live context stays unqueued",old && s==&old->rsp && old->on_cpu==0 && !old->ready_queued);
    if(boundary_mode==1) {
        sem_post(boundary_sem);
        expect("wake during handoff does not queue live context",old->state==TS_READY && old->on_cpu==0 && !old->ready_queued);
    }
    if(boundary_mode==2)expect("terminal outgoing stack is not reclaimable",old->state==TS_ZOMBIE && !k64_rq_reapable_locked(&runqueues,old) && !freed);
    sched_switch_complete();
    expect("completion releases outgoing CPU ownership",old->on_cpu==K64_CPU_NONE && !runqueues.cpu[0].outgoing);
    if(boundary_mode==1)expect("deferred wake publishes exactly once",old->ready_queued && ready_count==1 && ready[old->sched_priority].head==old && ready[old->sched_priority].tail==old);
    if(boundary_mode==2)longjmp(exit_boundary,1);
}
void kpanic(const char *f, ...) {va_list a;va_start(a,f);vfprintf(stderr,f,a);va_end(a);abort();}
void kprintf(const char *f, ...) {(void)f;}
void thread_start(void) {abort();}
uint64_t pmm_alloc_contig(unsigned n) {(void)n;++allocations;return 0;}
void pmm_free_contig(uint64_t b,unsigned n) {(void)b;(void)n;++freed;}
uint64_t phys_base_va;
uint8_t kstack_top[KSTACK_BYTES];
static void expect(const char *n,int c) {++checks;printf("%s: %s\n",c?"PASS":"FAIL",n);failures+=!c;}
static thread_t pool[8] __attribute__((aligned(16)));
static void setup(void)
{
    memset(pool,0,sizeof pool);threads=pool;thread_hi=8;k64_rq_init(&runqueues,pool,8,1);
    jiffies=ready_order=switches=preemptions=wakeups=timeouts=0;owner_identity(0);freed=allocations=switches_seen=0;flags=0x246;
    for(unsigned i=0;i<8;i++){pool[i].id=i+1;pool[i].quantum_ticks=pool[i].quantum_left=1;pool[i].cpu_mask=1;pool[i].sched_priority=16;pool[i].ready_cpu=pool[i].on_cpu=K64_CPU_NONE;pool[i].stack_base=0x10000u+i*KSTACK_BYTES;pool[i].rsp=0x101u+i;__asm__ volatile("fxsave (%0)"::"r"(pool[i].fx):"memory");}
    current=&pool[0];current->state=TS_RUNNING;current->on_cpu=0;runqueues.cpu[0].current=current;
    idle_thread=&pool[7];idle_thread->state=TS_READY;idle_thread->sched_priority=0;runqueues.cpu[0].idle=idle_thread;
}
int main(void)
{
    /* The real CPUID provider compares this host CPU to the immutable fixture.
     * Prevent host migration between publishing that map and querying it. This
     * affects this process only; the separate six-owner queue test stays free. */
    cpu_set_t allowed, single;
    if (sched_getaffinity(0, sizeof allowed, &allowed)) return 2;
    unsigned cpu;
    for (cpu = 0; cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &allowed); ++cpu) { }
    if (cpu == CPU_SETSIZE) return 2;
    CPU_ZERO(&single); CPU_SET(cpu, &single);
    if (sched_setaffinity(0, sizeof single, &single)) return 2;
    volatile uintptr_t api[]={(uintptr_t)sched_cpu_identity,(uintptr_t)sched_cpu_online_mask,(uintptr_t)sched_cpu_register};
    expect("production CPU API exists",api[0] && api[1] && api[2]);
    if(failures)return 1;
    setup();
    expect("owner-backed identity is consumed",sched_cpu_identity()==0 && sched_cpu_online_mask()==1);
    expect("AP registration stays unsupported",sched_cpu_register(1)==-2 && sched_cpu_register(32)==-1);
    owner_identity(32);
    expect("unknown physical CPU is not assigned BSP identity",sched_cpu_identity()==UINT32_MAX);
    owner_identity(1);
    expect("mapped AP identity is distinct from scheduler online",sched_cpu_identity()==1 && sched_cpu_register(1)==-2);
    owner_identity(0);pool[1].state=TS_READY;ready_enqueue(&pool[1]);
    expect("invalid policy leaves queued ownership unchanged",thread_set_sched_policy(&pool[1],32,1,1)==-1 && thread_set_sched_policy(&pool[1],16,0,1)==-1 && thread_set_sched_policy(&pool[1],16,17,1)==-1 && thread_set_sched_policy(&pool[1],16,1,2)==-1 && pool[1].ready_cpu==0 && pool[1].cpu_mask==1);
    expect("equal policy preserves FIFO and caller IRQ state",!thread_set_sched_policy(&pool[1],16,1,1) && ready[16].head==&pool[1] && flags==0x246);
    uint64_t now=jiffies,runs=current->run_ticks;owner_identity(1);sched_tick();
    expect("mapped unonline AP cannot charge BSP or mutate policy",jiffies==now && pool[0].run_ticks==runs && !switches_seen && thread_set_sched_policy(&pool[1],31,16,1)==-1 && pool[1].sched_priority==16);
    pool[2].state=TS_BLOCKED;pool[2].wake_tick=55;thread_wake(&pool[2]);
    expect("unsupported owner wake leaves blocked deadline intact",pool[2].state==TS_BLOCKED && pool[2].wake_tick==55);
    owner_identity(32);
    expect("unknown owner cannot borrow current or allocate",!thread_current() && !thread_create("unsupported",0,0) && !allocations);
    owner_identity(0);expect("BSP mirror and queue conservation agree",thread_current()==&pool[0] && sched_validate());
    uint64_t f=irq_save();ready_remove(&pool[1]);pool[1].state=TS_BLOCKED;
    ksem_t sem;sem_init(&sem,0);sem.waiters=current;current->state=TS_BLOCKED;current->wait_sem=&sem;
    boundary_sem=&sem;boundary_mode=1;schedule(0);irq_restore(f);
    expect("actual semaphore post conserves token",!sem.count && !sem.waiters && !pool[0].wait_sem);
    boundary_mode=0;f=irq_save();schedule(0);irq_restore(f);
    expect("saved context selected exactly once",current==&pool[0] && !pool[0].ready_queued && sched_validate());
    boundary_mode=2;if(!setjmp(exit_boundary))thread_exit(77);boundary_mode=0;irq_restore(0x246);
    expect("actual join reclaims only inactive terminal stack",thread_join(&pool[0])==77 && freed==1 && pool[0].state==TS_FREE);
    setup();current->quantum_ticks=16;current->quantum_left=1;current->aging_service_left=4;
    expect("running setter cannot refill either budget",!thread_set_sched_policy(current,31,16,1) && current->quantum_left==1 && current->aging_service_left==4);
    printf("checks=%u failures=%u\n",checks,failures);
    return failures?1:0;
}
