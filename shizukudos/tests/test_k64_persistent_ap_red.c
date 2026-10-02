/* Actual pristine finish/join/discard bodies, generated verbatim by the runner.
 * Architecture delivery is adapted; this witnesses withdrawal, not AP work. */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#define irq_save native_irq_save
#define irq_restore native_irq_restore
#include "../kernel64/k64.h"
#undef irq_save
#undef irq_restore
#include "../kernel64/sched_cpu.h"
#include "../kernel64/smp_boot.h"
static uint64_t flags=0x202,jiffies,ready_order;
static uint64_t irq_save(void) { uint64_t f=flags;flags&=~0x200ull;return f; }
static void irq_restore(uint64_t f) { flags=f; }
typedef struct { uint64_t flags;uint32_t ticket; } queue_guard_t;
static k64_runqueues_t runqueues;
static queue_guard_t queue_enter(void) { queue_guard_t g={irq_save(),k64_rq_lock(&runqueues)};return g; }
static void queue_leave(queue_guard_t g) { k64_rq_unlock(&runqueues,g.ticket);irq_restore(g.flags); }
static thread_t pool[4];
static unsigned ap_cohort_count=2,freed;
static uint32_t ap_cohort_stop;
static thread_t *ap_cohort_idle[K64_CPU_MAX];
static struct { thread_t *thread;uint64_t loops,seen;uint32_t hash; } ap_cohort_work[K64_CPU_MAX][2];
static int bsp_scheduler_owner(void) { return 1; }
uint64_t ticks_now(void) { return jiffies; }
uint64_t sched_cpu_online_mask(void) { return runqueues.online_mask; }
static void kstack_free(uint64_t base) { if(base) ++freed; }
static void schedule(int tick) { (void)tick;abort(); }
void kprintf(const char *s,...) { va_list a;va_start(a,s);vprintf(s,a);va_end(a); }
void kpanic(const char *s,...) { (void)s;abort(); }
int thread_set_sched_policy(thread_t *t,unsigned p,unsigned q,uint64_t m)
{ return k64_rq_policy_locked(&runqueues,t,p,q,m,jiffies,++ready_order); }
int shz_smp_send_ipi(unsigned cpu,unsigned vector)
{
    (void)vector;if(cpu!=1)abort();
    if(ap_cohort_stop) return k64_rq_withdraw_cohort_locked(&runqueues,cpu);
    /* Real production queue and live-stack completion, with a finite completed
     * worker context supplied at the hardware/stack boundary. */
    for(unsigned i=0;i<2;i++) {
        thread_t *t=ap_cohort_work[cpu][i].thread,*idle=ap_cohort_idle[cpu];
        idle->state=TS_READY;
        if(k64_rq_dispatch_locked(&runqueues,cpu,t,0,jiffies)!=1 ||
           k64_rq_complete_locked(&runqueues,cpu)!=idle)abort();
        t->run_ticks=16;runqueues.cpu[cpu].service_ticks+=16;
        ap_cohort_work[cpu][i].loops=2048;t->state=TS_ZOMBIE;
        if(k64_rq_dispatch_locked(&runqueues,cpu,idle,0,jiffies)!=1 ||
           k64_rq_complete_locked(&runqueues,cpu)!=t)abort();
    }
    runqueues.cpu[cpu].reschedule_ack=runqueues.cpu[cpu].reschedule_request;return 0;
}
#include "persistent-pristine-bodies.inc"
int main(void)
{
    k64_rq_init(&runqueues,pool,4,1);
    for(unsigned i=0;i<4;i++) {
        pool[i].state=TS_NEW;pool[i].on_cpu=pool[i].ready_cpu=K64_CPU_NONE;
        pool[i].cpu_mask=1;pool[i].quantum_ticks=pool[i].quantum_left=1;
        pool[i].sched_priority=16;pool[i].stack_base=0x100000+i*KSTACK_BYTES;
        pool[i].ap_kernel_cohort=1;
    }
    ap_cohort_idle[1]=&pool[1];
    for(unsigned i=0;i<2;i++)ap_cohort_work[1][i].thread=&pool[2+i];
    if(k64_rq_admit_cohort_locked(&runqueues,1,&pool[1]))abort();
    int rc=sched_ap_cohort_finish();
    printf("PRISTINE_FINISH: rc=%d mask=%llu retained_count=%u freed=%u\n",rc,
           (unsigned long long)runqueues.online_mask,ap_cohort_count,freed);
    int persistent=rc==0 && runqueues.online_mask==3 && ap_cohort_count==2 && freed==0;
    printf("PERSISTENT_SECOND_GENERATION_EMPTY_INTERVAL: %s\n",persistent?"PASS":"FAIL");
    return persistent?0:1;
}
