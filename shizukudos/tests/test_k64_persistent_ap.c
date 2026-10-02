/* Real descriptor and ready-queue C. Host owners are fixtures, not APs. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include "../kernel64/k64.h"
#include "../kernel64/sched_cpu.h"
#include "../kernel64/kernel_ap_work.h"
static unsigned checks,failures;
static shz_ap_work_pool_t pool;
static thread_t table[8];
static k64_runqueues_t rq;
static void check(const char *name,int ok) { ++checks;failures+=!ok;printf("%s: %s\n",ok?"PASS":"FAIL",name); }
void kpanic(const char *f,...) { (void)f;abort(); }
static void descriptors(void)
{
    uint64_t cookie=0,out=0;unsigned slot=0;uint8_t data[4096];memset(data,0x5a,sizeof data);
    shz_ap_work_init(&pool,6);
    check("prepared pool rejects submission before actual online handoff",shz_ap_work_submit_locked(&pool,data,1,2,&cookie)==-1);
    check("start requires exact real AP mask",shz_ap_work_start_locked(&pool,2)==-1 && pool.state==SHZ_AP_WORK_PREPARED);
    check("actual online cohort activates descriptors",!shz_ap_work_start_locked(&pool,6));
    check("invalid CPU0 affinity does not consume descriptor",shz_ap_work_submit_locked(&pool,data,1,1,&cookie)==-1 && pool.occupied==0);
    check("unonline affinity is refused",shz_ap_work_submit_locked(&pool,data,1,8,&cookie)==-1);
    check("empty and oversized inputs refused",shz_ap_work_submit_locked(&pool,data,0,2,&cookie)==-1 && shz_ap_work_submit_locked(&pool,data,4097,2,&cookie)==-1);
    check("first exact cookie publishes copied immutable payload",!shz_ap_work_submit_locked(&pool,data,4096,2,&cookie) && cookie==16 && pool.occupied==1);
    data[0]=0;check("caller mutation cannot change owned payload",pool.job[0].payload[0]==0x5a);
    check("wrong real CPU cannot claim restricted affinity",shz_ap_work_claim_locked(&pool,2,33,&slot)==0);
    check("actual worker claims once",shz_ap_work_claim_locked(&pool,1,33,&slot)==1 && slot==0 && pool.job[slot].state==SHZ_AP_JOB_RUNNING);
    check("double claim cannot repeat running descriptor",shz_ap_work_claim_locked(&pool,1,33,&slot)==0);
    check("poll does not expose running result",shz_ap_work_poll_locked(&pool,cookie,&out)==0);
    check("release cannot reclaim running payload",shz_ap_work_release_locked(&pool,cookie)==-1);
    const uint64_t h=shz_ap_work_digest(pool.job[0].payload,4096);
    check("closed fixed digest matches frozen independent reference vector",h==0x7b360da38fa22325ull);
    check("wrong cookie cannot complete",shz_ap_work_complete_locked(&pool,0,cookie+16,1,33,h)==-1);
    check("wrong CPU and worker cannot complete",shz_ap_work_complete_locked(&pool,0,cookie,2,33,h)==-1 && shz_ap_work_complete_locked(&pool,0,cookie,1,34,h)==-1);
    check("exact claimed identity completes once",!shz_ap_work_complete_locked(&pool,0,cookie,1,33,h));
    check("double completion is rejected",shz_ap_work_complete_locked(&pool,0,cookie,1,33,h)==-1);
    check("DONE result retains exact cookie",shz_ap_work_poll_locked(&pool,cookie,&out)==1 && out==h);
    check("release returns descriptor only after completion",!shz_ap_work_release_locked(&pool,cookie) && pool.occupied==0);
    check("stale cookie no longer polls or releases",shz_ap_work_poll_locked(&pool,cookie,&out)==-1 && shz_ap_work_release_locked(&pool,cookie)==-1);
    uint64_t next=0;check("second generation remains online across empty interval",!shz_ap_work_submit_locked(&pool,data,1,2,&next) && next==cookie+16 && pool.state==SHZ_AP_WORK_RUNNING);
    check("prior generation cannot consume successor",shz_ap_work_poll_locked(&pool,cookie,&out)==-1);
    shz_ap_work_fail_locked(&pool);
    check("failure closes submission and retains allocated job",shz_ap_work_submit_locked(&pool,data,1,2,&cookie)==-1 && pool.occupied==1 && pool.state==SHZ_AP_WORK_FAILED);
    shz_ap_work_init(&pool,6);shz_ap_work_start_locked(&pool,6);
    for(unsigned i=0;i<16;i++)if(shz_ap_work_submit_locked(&pool,data,1,6,&cookie))abort();
    check("all sixteen descriptors are bounded",pool.occupied==16 && shz_ap_work_submit_locked(&pool,data,1,6,&cookie)==-2);
    check("drain closes new submission but preserves queued work",!shz_ap_work_drain_locked(&pool) && shz_ap_work_submit_locked(&pool,data,1,6,&cookie)==-1);
    unsigned done=0;while(shz_ap_work_claim_locked(&pool,1,33,&slot)==1) {
        shz_ap_work_job_t *j=&pool.job[slot];if(shz_ap_work_complete_locked(&pool,slot,j->cookie,1,33,shz_ap_work_digest(j->payload,j->bytes)))abort();++done;
    }
    check("closed drain executes every queued job",done==16 && shz_ap_work_pending_locked(&pool)==0 && pool.occupied==16);
    check("DONE payload remains until explicit release",pool.job[0].state==SHZ_AP_JOB_DONE);
    shz_ap_work_init(&pool,2);shz_ap_work_start_locked(&pool,2);pool.job[0].generation=SHZ_AP_WORK_MAX_GENERATION;
    check("nonwrapping cookies skip exhausted slot",!shz_ap_work_submit_locked(&pool,data,1,2,&cookie) && (cookie&15)==1);
    for(unsigned i=0;i<16;i++)pool.job[i].generation=SHZ_AP_WORK_MAX_GENERATION;
    check("exhausted generations never alias old cookies",shz_ap_work_submit_locked(&pool,data,1,2,&cookie)==-2);
}
static void queue_lifetime(void)
{
    memset(table,0,sizeof table);k64_rq_init(&rq,table,8,3);
    for(unsigned i=0;i<8;i++) { table[i].on_cpu=table[i].ready_cpu=K64_CPU_NONE;table[i].ap_kernel_cohort=K64_AP_WORKER_CLASS;table[i].cpu_mask=2;table[i].quantum_ticks=1;table[i].sched_priority=16; }
    thread_t *idle=&table[0],*a=&table[1];idle->state=TS_READY;rq.cpu[1].idle=idle;a->state=TS_RUNNING;a->on_cpu=1;rq.cpu[1].current=a;
    check("unknown and BSP cannot conditionally park AP worker",k64_rq_work_park_locked(&rq,32,a)==-1 && k64_rq_work_park_locked(&rq,0,a)==-1 && a->state==TS_RUNNING);
    check("conditional park keeps active stack owned",!k64_rq_work_park_locked(&rq,1,a) && a->state==TS_BLOCKED && a->on_cpu==1 && !a->ready_queued);
    check("wake before selection changes state without queueing live stack",!k64_rq_work_wake_locked(&rq,a,10,1) && a->state==TS_READY && !a->ready_queued);
    check("same-context selection consumes wake without stack handoff",k64_rq_dispatch_locked(&rq,1,a,0,10)==0 && a->state==TS_RUNNING && !rq.cpu[1].outgoing);
    check("second park retains owner",!k64_rq_work_park_locked(&rq,1,a));
    check("dispatch to idle withholds outgoing blocked stack",k64_rq_dispatch_locked(&rq,1,idle,0,11)==1 && rq.cpu[1].outgoing==a && a->on_cpu==1);
    check("BSP wake between selection and ESP save is deferred",!k64_rq_work_wake_locked(&rq,a,11,2) && !a->ready_queued && a->on_cpu==1);
    check("repeat wake cannot double publish",k64_rq_work_wake_locked(&rq,a,11,3)==0 && rq.cpu[1].ready_count==0);
    check("destination completion alone publishes saved READY worker",k64_rq_complete_locked(&rq,1)==a && a->on_cpu==K64_CPU_NONE && a->ready_queued && rq.cpu[1].ready_count==1);
    check("repeat completion does not release another owner",!k64_rq_complete_locked(&rq,1));
    check("park and wake conserved real queues",!k64_rq_validate_locked(&rq));
    check("withdraw cannot reclaim queued service",k64_rq_withdraw_cohort_locked(&rq,1)==-1 && rq.online_mask==3);
    k64_rq_remove_locked(&rq,a);a->state=TS_BLOCKED;
    check("inactive parked worker wakes once on its actual allowed CPU",!k64_rq_work_wake_locked(&rq,a,12,4) && a->ready_cpu==1 && rq.cpu[1].ready_count==1);
    k64_rq_remove_locked(&rq,a);a->state=TS_BLOCKED;a->proc=(void *)1;
    check("process-owned waiter cannot enter closed park/wake",k64_rq_work_wake_locked(&rq,a,12,5)==-1 && !a->ready_queued);
}
/* Six actual host owners serialize the production pool with its real ticket;
 * useful instruction/preemption/physical identity are outside this control. */
static pma_ticketlock_t owner_lock;
static unsigned produced,released,concurrent_bad;
static void *owner(void *arg)
{
    const unsigned id=(unsigned)(uintptr_t)arg;uint8_t data[16];memset(data,0x39,sizeof data);
    for(unsigned iteration=0;iteration<100000;iteration++) {
        uint32_t ticket=pma_ticket_lock(&owner_lock);
        if(released==300) { pma_ticket_unlock(&owner_lock,ticket);break; }
        if(id==0 && produced<300) { uint64_t c;if(!shz_ap_work_submit_locked(&pool,data,sizeof data,30,&c))++produced; }
        else if(id==5) for(unsigned i=0;i<16;i++)if(pool.job[i].state==SHZ_AP_JOB_DONE) { if(shz_ap_work_release_locked(&pool,pool.job[i].cookie))++concurrent_bad;else ++released; }
        unsigned slot=0;int claimed=id>0 && id<5 ? shz_ap_work_claim_locked(&pool,id,id+100,&slot):0;
        uint64_t c=claimed?pool.job[slot].cookie:0;
        pma_ticket_unlock(&owner_lock,ticket);
        if(claimed) {
            uint64_t h=shz_ap_work_digest(pool.job[slot].payload,pool.job[slot].bytes);
            ticket=pma_ticket_lock(&owner_lock);
            if(shz_ap_work_complete_locked(&pool,slot,c,id,id+100,h))++concurrent_bad;
            pma_ticket_unlock(&owner_lock,ticket);
        } else sched_yield(); /* do not let an empty producer/releaser finish before workers */
    }
    return 0;
}
int main(void)
{
    descriptors();queue_lifetime();shz_ap_work_init(&pool,30);shz_ap_work_start_locked(&pool,30);pma_ticket_init(&owner_lock);
    pthread_t owners[6];for(unsigned i=0;i<6;i++)if(pthread_create(&owners[i],0,owner,(void *)(uintptr_t)i))return 2;
    for(unsigned i=0;i<6;i++)if(pthread_join(owners[i],0))return 2;
    printf("HOST-OWNERS: produced=%u released=%u occupied=%u submitted=%llu completed=%llu bad=%u\n",produced,released,pool.occupied,(unsigned long long)pool.submitted,(unsigned long long)pool.completed,concurrent_bad);
    check("six real host owners finish fixed job generations without duplicate completion",produced==300 && released==300 && !concurrent_bad && !pool.occupied && pool.submitted==300 && pool.completed==300);
    printf("checks=%u failures=%u scope=actual_C_pool_queue_host_owners_no_AP\n",checks,failures);return failures?1:0;
}
