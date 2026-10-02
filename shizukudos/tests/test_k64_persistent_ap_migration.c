/* Actual saved queue and production service bodies; AP delivery is adapted. */
#define main original_service_controls
#include "test_k64_persistent_ap_service.c"
#undef main
static void setup_three(void)
{
    setup(1);
    ap_cohort_count=3;architecture=6;ap_cohort_idle[2]=&table[6];
    for(unsigned i=6;i<9;i++) { table[i].state=TS_NEW;table[i].ap_kernel_cohort=K64_AP_WORKER_CLASS; }
    ap_cohort_work[2][0].thread=&table[7];ap_cohort_work[2][1].thread=&table[8];
    if(k64_rq_admit_cohort_locked(&runqueues,2,&table[6]))abort();
    shz_ap_work_init(&storage,6);if(shz_ap_work_start_locked(&storage,6))abort();
    for(unsigned c=1;c<3;c++)for(unsigned i=0;i<2;i++) {
        thread_t *t=ap_cohort_work[c][i].thread;t->state=TS_BLOCKED;t->cpu_mask=1ull<<c;
    }
}
int main(void)
{
    setup_three();thread_t *t=ap_cohort_work[1][0].thread;
#ifdef PERSISTENT_MIGRATION_BASELINE
    const int rc=thread_set_sched_policy(t,t->sched_priority,t->quantum_ticks,4);
    printf("PRISTINE_PARKED_POLICY: rc=%d source_mask=%llu state=%u live=%u queued=%u online=%llu\n",rc,(unsigned long long)t->cpu_mask,t->state,t->on_cpu,t->ready_queued,(unsigned long long)runqueues.online_mask);
    check("saved persistent worker can migrate through admitted private operation",rc==0 && t->cpu_mask==4);
#else
    check("self destination refuses without queue or policy mutation",sched_ap_work_migrate(1,0,1)==-1 && t->cpu_mask==2 && !t->ready_queued);
    check("BSP unknown offline slot and invalid origin refuse",sched_ap_work_migrate(1,0,0)==-1 && sched_ap_work_migrate(1,0,3)==-1 && sched_ap_work_migrate(1,2,2)==-1 && sched_ap_work_migrate(0,0,2)==-1);
    architecture=2;check("physical destination private gates are required",sched_ap_work_migrate(1,0,2)==-1 && t->cpu_mask==2);architecture=4;
    check("physical source private gates are required",sched_ap_work_migrate(1,0,2)==-1 && t->cpu_mask==2);architecture=6;
    runqueues.online_mask=3;check("architecture alone cannot replace scheduler online",sched_ap_work_migrate(1,0,2)==-1 && t->cpu_mask==2);runqueues.online_mask=7;
    t->state=TS_RUNNING;t->on_cpu=1;runqueues.cpu[1].current=t;
    check("current live stack cannot migrate",sched_ap_work_migrate(1,0,2)==K64_AP_WORK_BUSY && t->on_cpu==1 && t->cpu_mask==2);
    t->state=TS_BLOCKED;runqueues.cpu[1].current=ap_cohort_idle[1];runqueues.cpu[1].outgoing=t;
    check("blocked outgoing stack remains owned until actual completion",sched_ap_work_migrate(1,0,2)==K64_AP_WORK_BUSY && t->on_cpu==1 && !t->ready_queued);
    check("real destination completion releases parked source owner",k64_rq_complete_locked(&runqueues,1)==t && t->on_cpu==K64_CPU_NONE && !t->ready_queued);
    check("BUSY does not change requests or ready identities",runqueues.cpu[1].reschedule_request==0 && runqueues.cpu[2].reschedule_request==0 && !runqueues.cpu[1].ready_count && !runqueues.cpu[2].ready_count);
    unsigned claimed=0;uint8_t data[]={9,8};uint64_t cookie=0,value=0;
    if(shz_ap_work_submit_locked(&storage,data,2,2,&cookie) || !shz_ap_work_claim_locked(&storage,1,t->id,&claimed))abort();
    check("exact running job reference prevents parked migration",sched_ap_work_migrate(1,0,2)==-1 && t->cpu_mask==2);
    uint64_t digest=shz_ap_work_digest(storage.job[claimed].payload,storage.job[claimed].bytes);
    t->state=TS_RUNNING;t->on_cpu=1;runqueues.cpu[1].current=t;
    check("wrong actual CPU cannot publish useful completion",ap_work_complete_locked(1,0,claimed,cookie,2,digest)==-1 && !ap_cohort_work[1][0].completed_count && !ap_cohort_work[1][0].completed_cpu_mask && storage.job[claimed].state==SHZ_AP_JOB_RUNNING);
    ap_cohort_work[1][0].completed_count=UINT64_MAX;
    check("completion counter cannot wrap or consume exact claim",ap_work_complete_locked(1,0,claimed,cookie,1,digest)==-1 && storage.job[claimed].state==SHZ_AP_JOB_RUNNING && !storage.completed);ap_cohort_work[1][0].completed_count=0;
    check("exact CPU cookie and worker publish useful origin record once",!ap_work_complete_locked(1,0,claimed,cookie,1,digest) && ap_cohort_work[1][0].completed_count==1 && ap_cohort_work[1][0].completed_cpu_mask==2);
    check("double completion cannot increment useful origin counters",ap_work_complete_locked(1,0,claimed,cookie,1,digest)==-1 && ap_cohort_work[1][0].completed_count==1);
    t->state=TS_BLOCKED;t->on_cpu=K64_CPU_NONE;runqueues.cpu[1].current=ap_cohort_idle[1];
    check("retained DONE reference prevents migration until release",sched_ap_work_migrate(1,0,2)==-1 && storage.occupied==1 && t->cpu_mask==2);
    check("stale cookie cannot release migration reference",sched_ap_work_release(cookie+16)==-1 && sched_ap_work_migrate(1,0,2)==-1);
    if(sched_ap_work_release(cookie))abort();
    check("saved parked worker follows target wake dispatch and repark",!sched_ap_work_migrate(1,0,2) && t->cpu_mask==4 && t->state==TS_BLOCKED && t->on_cpu==K64_CPU_NONE && !t->ready_queued && (ap_cohort_work[1][0].seen&4) && runqueues.cpu[1].reschedule_ack==runqueues.cpu[1].reschedule_request && runqueues.cpu[2].reschedule_ack==runqueues.cpu[2].reschedule_request);
    check("released prior cookie cannot complete after movement",shz_ap_work_complete_locked(&storage,claimed,cookie,2,t->id,0)==-1 && !storage.occupied);
    uint64_t next=0;if(shz_ap_work_submit_locked(&storage,data,2,2,&next))abort();
    check("last source worker cannot strand queued source-only descriptor",sched_ap_work_migrate(1,1,2)==-1 && ap_cohort_work[1][1].thread->cpu_mask==2 && storage.job[next&15].state==SHZ_AP_JOB_QUEUED);
    if(ap_work_signal(2,0) || sched_ap_work_release(next))abort();
    check("both origin workers may move leaving a real idle-only source",!sched_ap_work_migrate(1,1,2) && ap_cohort_work[1][0].thread->cpu_mask==4 && ap_cohort_work[1][1].thread->cpu_mask==4 && runqueues.cpu[1].current==ap_cohort_idle[1] && !runqueues.cpu[1].ready_count);
    cookie=0xabcdef;uint64_t submitted=storage.submitted;
    check("zero-worker eligibility refuses before cookie publication",sched_ap_work_submit(data,2,2,&cookie)==-1 && cookie==0xabcdef && storage.submitted==submitted && !storage.occupied);
    check("moved workers process next generation on destination",!sched_ap_work_submit(data,2,4,&cookie) && sched_ap_work_poll(cookie,&value)==1 && value==shz_ap_work_digest(data,2));
    if(sched_ap_work_release(cookie))abort();
    check("moved origin records completed work on actual destination",ap_cohort_work[1][0].completed_count==2 && ap_cohort_work[1][0].completed_cpu_mask==6);
    thread_t *prior=ap_cohort_work[2][0].thread;ap_cohort_work[2][0].thread=t;
    check("duplicate origin lifetime refuses migration and submit",sched_ap_work_migrate(1,0,1)==-1 && sched_ap_work_submit(data,2,4,&next)==-1);ap_cohort_work[2][0].thread=prior;
    t->cpu_mask=12;check("invalid multi-owner mask refuses without mutation",sched_ap_work_migrate(1,0,1)==-1 && t->cpu_mask==12);t->cpu_mask=4;
    cpu_identity=1;check("AP and unknown identities cannot migrate BSP service",sched_ap_work_migrate(1,0,1)==-1);cpu_identity=32;check("unknown identity never borrows BSP migration authority",sched_ap_work_migrate(1,0,1)==-1);cpu_identity=0;
    check("actual saved owner can move back independent of origin argument",!sched_ap_work_migrate(1,0,1) && t->cpu_mask==2 && (ap_cohort_work[1][0].seen&6)==6);
    check("generic thread policy remains closed after private migration",thread_set_sched_policy(t,31,16,4)==-1 && t->cpu_mask==2 && t->sched_priority==16);
    storage.state=SHZ_AP_WORK_FAILED;check("FAILED pool refuses any saved movement",sched_ap_work_migrate(1,0,2)==-1);storage.state=SHZ_AP_WORK_RUNNING;
    check("stop drains and reaps every origin lifetime once after movement",!sched_ap_work_stop() && runqueues.online_mask==1 && !ap_work_pool && freed==7 && table[3].state==TS_FREE && table[4].state==TS_FREE && table[7].state==TS_FREE && table[8].state==TS_FREE);
    check("stale stopped pool cannot admit successor migration",sched_ap_work_migrate(1,0,2)==-1 && !ap_cohort_count);
    setup_three();withhold=1;t=ap_cohort_work[1][0].thread;
    check("withheld target F0 retains moved saved stack and descriptors",sched_ap_work_migrate(1,0,2)==-1 && storage.state==SHZ_AP_WORK_FAILED && t->cpu_mask==4 && t->state==TS_READY && t->ready_cpu==2 && !freed && runqueues.online_mask==7);
    check("failed moved lifetime cannot reclaim through stop",sched_ap_work_stop()==-1 && !freed && ap_work_pool==&storage);
#endif
    printf("checks=%u failures=%u scope=actual_C_parked_migration_no_AP\n",checks,failures);return failures?1:0;
}
