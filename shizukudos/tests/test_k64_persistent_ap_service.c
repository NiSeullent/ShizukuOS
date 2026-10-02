/* Verbatim service/cohort API bodies; hardware/stack completion is adapted.
 * This exercises actual admission/retention, not real AP/IRQ execution. */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#define irq_save native_irq_save
#define irq_restore native_irq_restore
#define read_cr3 native_read_cr3
#include "../kernel64/k64.h"
#undef irq_save
#undef irq_restore
#undef read_cr3
#include "../kernel64/sched_cpu.h"
#include "../kernel64/smp_boot.h"
#include "../kernel64/kernel_ap_work.h"
static uint64_t flags=0x202,jiffies,ready_order,architecture;
uint64_t phys_base_va;
static unsigned checks,failures,freed,withhold,send_error,cpu_identity,done,callbacks_unlocked;
static uint64_t irq_save(void) { uint64_t f=flags;flags&=~0x200ull;return f; }
static void irq_restore(uint64_t f) { flags=f; }
static uint64_t read_cr3(void) { return 0x1000; }
uint64_t kernel_pml4(void) { return 0x1000; }
static thread_t table[10],*threads=table;static unsigned thread_hi=10;
static k64_runqueues_t runqueues;
typedef struct { uint64_t flags;uint32_t ticket; } queue_guard_t;
static queue_guard_t queue_enter(void) { queue_guard_t g={irq_save(),k64_rq_lock(&runqueues)};return g; }
static void queue_leave(queue_guard_t g) { k64_rq_unlock(&runqueues,g.ticket);irq_restore(g.flags); }
static shz_ap_work_pool_t storage __attribute__((aligned(4096))),*ap_work_pool;
static unsigned ap_cohort_count;static uint32_t ap_cohort_stop;
static thread_t *ap_cohort_idle[K64_CPU_MAX];
static struct { thread_t *thread;uint64_t loops,seen,completed_count,completed_cpu_mask;uint32_t hash; } ap_cohort_work[K64_CPU_MAX][2];
#define AP_WORK_PAGES ((sizeof(shz_ap_work_pool_t)+PAGE_SIZE-1)/PAGE_SIZE)
static int bsp_scheduler_owner(void) { return cpu_identity==0; }
static int restricted_slot(const thread_t *t) { return t->ap_kernel_cohort==K64_AP_WORKER_CLASS; }
static int general_admission_closed(void) { return ap_work_pool!=0; }
uint64_t ticks_now(void) { return jiffies++; } /* hardware clock boundary adapter for bounded failure controls */
uint64_t sched_cpu_online_mask(void) { return runqueues.online_mask; }
static void kstack_free(uint64_t base) { if(runqueues.online_mask!=1)abort();if(base)++freed; }
void pmm_free_contig(uint64_t base,unsigned pages) { (void)base;(void)pages;if(runqueues.online_mask!=1)abort();++freed; }
static void schedule(int why) { (void)why;abort(); }
static unsigned visited;
static void visitor(thread_t *t,void *ctx) { (void)ctx;if(restricted_slot(t))abort();++visited; }
static int owned(uint64_t pa,uint64_t bytes)
{ uint32_t ticket;if(!pma_ticket_trylock(&runqueues.lock,&ticket))abort();k64_rq_unlock(&runqueues,ticket);return pa && bytes && !(pa&4095) && !(bytes&4095); }
void kprintf(const char *fmt,...) { (void)fmt; }
void kpanic(const char *fmt,...) { (void)fmt;abort(); }
uint64_t shz_cpu_arch_work_online_mask(void) { uint32_t ticket;if(!pma_ticket_trylock(&runqueues.lock,&ticket))abort();k64_rq_unlock(&runqueues,ticket);return cpu_identity?0:architecture; }
int shz_cpu_arch_work_ready(unsigned cpu) { return cpu && cpu<ap_cohort_count && done; }
int shz_cpu_arch_work_report(unsigned cpu) { return shz_cpu_arch_work_ready(cpu)?0:-1; }
static int ap_work_complete_locked(unsigned origin,unsigned which,unsigned slot,uint64_t cookie,unsigned cpu,uint64_t digest);
int shz_smp_send_ipi(unsigned cpu,unsigned vector)
{
    if(!cpu || cpu>=ap_cohort_count || vector!=SHZ_SMP_VEC_RESCHEDULE)abort();uint32_t ticket;
    if(!pma_ticket_trylock(&runqueues.lock,&ticket))abort();++callbacks_unlocked;k64_rq_unlock(&runqueues,ticket);
    if(send_error)return -1;if(withhold)return 0;
    ticket=k64_rq_lock(&runqueues);thread_t *idle=ap_cohort_idle[cpu];
    for(unsigned c=1;c<ap_cohort_count;c++)for(unsigned i=0;i<2;i++) {
        thread_t *t=ap_cohort_work[c][i].thread;
        if(t->state!=TS_READY || !(t->cpu_mask&(1ull<<cpu)))continue;
        idle->state=TS_READY;
        if(k64_rq_dispatch_locked(&runqueues,cpu,t,0,jiffies)!=1 || k64_rq_complete_locked(&runqueues,cpu)!=idle)abort();
        unsigned slot;
        while(shz_ap_work_claim_locked(ap_work_pool,cpu,t->id,&slot)) {
            shz_ap_work_job_t *j=&ap_work_pool->job[slot];uint64_t value=shz_ap_work_digest(j->payload,j->bytes);
            if(ap_work_complete_locked(c,i,slot,j->cookie,cpu,value))abort();
        }
        ap_cohort_work[c][i].seen|=1ull<<cpu;
        if(ap_work_pool->state==SHZ_AP_WORK_DRAINING)t->state=TS_ZOMBIE;
        else if(k64_rq_work_park_locked(&runqueues,cpu,t))abort();
        if(k64_rq_dispatch_locked(&runqueues,cpu,idle,0,jiffies)!=1 || k64_rq_complete_locked(&runqueues,cpu)!=t)abort();
    }
    runqueues.cpu[cpu].reschedule_ack=runqueues.cpu[cpu].reschedule_request;
    if(ap_cohort_stop) { if(k64_rq_withdraw_cohort_locked(&runqueues,cpu))abort();done=1; }
    k64_rq_unlock(&runqueues,ticket);return 0;
}
#include "persistent-service-bodies.inc"
static void check(const char *n,int ok) { ++checks;failures+=!ok;printf("%s: %s\n",ok?"PASS":"FAIL",n); }
static void setup(int active)
{
    memset(table,0,sizeof table);memset(&storage,0,sizeof storage);k64_rq_init(&runqueues,table,10,1);
    flags=0x202;jiffies=ready_order=0;cpu_identity=freed=withhold=send_error=done=callbacks_unlocked=0;ap_cohort_count=ap_cohort_stop=0;ap_work_pool=0;architecture=0;memset(ap_cohort_work,0,sizeof ap_cohort_work);
    for(unsigned i=0;i<10;i++) { table[i].id=i+1;table[i].on_cpu=table[i].ready_cpu=K64_CPU_NONE;table[i].cpu_mask=1;table[i].quantum_ticks=1;table[i].sched_priority=16;table[i].stack_base=0x100000+i*KSTACK_BYTES; }
    table[0].state=TS_RUNNING;table[0].on_cpu=0;runqueues.cpu[0].current=&table[0];table[1].state=TS_READY;runqueues.cpu[0].idle=&table[1];
    if(active) {
        ap_cohort_count=2;architecture=2;ap_cohort_idle[1]=&table[2];
        for(unsigned i=2;i<5;i++) { table[i].state=TS_NEW;table[i].ap_kernel_cohort=K64_AP_WORKER_CLASS; }
        for(unsigned i=0;i<2;i++)ap_cohort_work[1][i].thread=&table[3+i];
        if(k64_rq_admit_cohort_locked(&runqueues,1,&table[2]))abort();
        ap_work_pool=&storage;shz_ap_work_init(ap_work_pool,2);
    }
}
int main(void)
{
    setup(0);check("actual BSP main/idle only is quiescent",!sched_ap_work_quiescent());
    table[5].state=TS_BLOCKED;check("residual blocked lifetime refuses first INIT",sched_ap_work_quiescent()==-1);table[5].state=TS_FREE;
    table[0].wait_multi=(void *)1;check("current wait/object owner refuses admission",sched_ap_work_quiescent()==-1);table[0].wait_multi=0;
    runqueues.cpu[0].outgoing=&table[5];check("unfinished stack handoff refuses admission",sched_ap_work_quiescent()==-1);
    setup(1);if(k64_rq_withdraw_cohort_locked(&runqueues,1))abort();
    check("pre-INIT full owned worker/pool spans are admitted without ticket callback",!sched_ap_cohort_resources(owned));
    check("external bootstrap/table overlap with any worker is refused",sched_ap_work_overlaps(table[3].stack_base,KSTACK_BYTES)==-1);
    check("external disjoint resource remains eligible",!sched_ap_work_overlaps(0x200000,KSTACK_BYTES));
    uint64_t prior_stack=table[3].stack_base;table[3].stack_base=(uintptr_t)&storage;
    check("pool and worker overlap is refused before INIT",sched_ap_cohort_resources(owned)==-1);table[3].stack_base=prior_stack;
    thread_discard(&table[3]);check("public discard cannot reclaim retained pre-INIT service lifetime",table[3].state==TS_NEW && !freed);
    setup(1);check("actual service API keeps workers online after initial empty interval",!sched_ap_work_start() && runqueues.online_mask==3 && ap_cohort_count==2 && !freed && table[3].state==TS_BLOCKED && table[3].on_cpu==K64_CPU_NONE);
    table[3].proc=(void *)1;table[3].tid=99;visited=0;sched_for_each_thread(visitor,0);
    check("immutable class excludes restricted TCB before arbitrary visitor",visited==2);
    check("immutable class excludes process lookup and slot exposure",!thread_find_tid((void *)1,99) && !thread_slot(3));table[3].proc=0;
    table[3].creator_hold=1;thread_creator_release(&table[3]);check("generic creator release cannot mutate AP owner fields",table[3].creator_hold==1);table[3].creator_hold=0;
    check("generic policy cannot migrate or alter restricted lifetime",thread_set_sched_policy(&table[3],31,16,2)==-1 && table[3].sched_priority==16 && table[3].cpu_mask==2);
    uint64_t cookie=0,value=0;uint8_t data[]={1,2,3};
    check("first generation goes through real BSP submit/claim/complete",!sched_ap_work_submit(data,3,2,&cookie) && sched_ap_work_poll(cookie,&value)==1);
    uint64_t prior=cookie;check("release keeps actual scheduler online",!sched_ap_work_release(cookie) && runqueues.online_mask==3 && !freed);
    check("second generation survives another empty interval",!sched_ap_work_submit(data,3,2,&cookie) && cookie!=prior && sched_ap_work_poll(cookie,&value)==1 && runqueues.online_mask==3);
    check("stale actual API release refuses successor",sched_ap_work_release(prior)==-1);
    check("stop drains but retains unconsumed result and stacks",sched_ap_work_stop()==-2 && storage.state==SHZ_AP_WORK_DRAINING && runqueues.online_mask==3 && !freed && ap_work_pool==&storage);
    check("retained DONE can be released after drain",!sched_ap_work_release(cookie));
    check("only real ACK and inactive owner permit stop/reclaim",!sched_ap_work_stop() && runqueues.online_mask==1 && !ap_work_pool && !ap_cohort_count && freed==4 && done);
    check("external IPI calls never own real queue ticket",callbacks_unlocked>=6 && flags==0x202);
    setup(1);withhold=1;check("withheld F0 cannot pass via timer/progress substitution",sched_ap_work_start()==-1 && storage.state==SHZ_AP_WORK_FAILED && runqueues.online_mask==3 && ap_work_pool==&storage && !freed);
    setup(1);check("healthy empty service starts again in fresh fixture",!sched_ap_work_start());send_error=1;
    check("failed actual send retains accepted cookie and all live resources",sched_ap_work_submit(data,3,2,&cookie)==-1 && storage.state==SHZ_AP_WORK_FAILED && storage.occupied==1 && ap_work_pool==&storage && !freed);
    check("FAILED stop refuses reclamation",sched_ap_work_stop()==-1 && runqueues.online_mask==3 && !freed);
    cpu_identity=1;check("AP cannot submit poll release stop through BSP API",sched_ap_work_submit(data,3,2,&cookie)==-1 && sched_ap_work_poll(cookie,&value)==-1 && sched_ap_work_release(cookie)==-1 && sched_ap_work_stop()==-1);
    cpu_identity=32;check("unknown owner never falls back to BSP service API",sched_ap_work_start()==-1 && sched_ap_work_submit(data,3,2,&cookie)==-1 && sched_ap_work_stop()==-1);
    printf("checks=%u failures=%u scope=actual_C_service_API_hardware_adapted_no_AP\n",checks,failures);return failures?1:0;
}
