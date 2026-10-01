/* SPDX-License-Identifier: GPL-2.0-only
 * Actual internal priority queues under concurrent logical owners, no AP proof.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "../kernel64/k64.h"
#if __has_include("../kernel64/sched_cpu.h")
#include "../kernel64/sched_cpu.h"
void kpanic(const char *f, ...) {va_list a;va_start(a,f);vfprintf(stderr,f,a);va_end(a);abort();}
static k64_runqueues_t rq;
static thread_t pool[48];
static unsigned failures, consumed[48];
static uint64_t order;
static void expect(const char *n,int c) {printf("%s: %s\n",c?"PASS":"FAIL",n);failures+=!c;}
static void setup(void)
{
    memset(pool,0,sizeof pool);memset(consumed,0,sizeof consumed);order=0;k64_rq_init(&rq,pool,48,7);
    for(unsigned i=0;i<48;i++){pool[i].state=TS_READY;pool[i].cpu_mask=7;pool[i].quantum_ticks=pool[i].quantum_left=1;pool[i].sched_priority=16;pool[i].ready_cpu=pool[i].on_cpu=K64_CPU_NONE;}
}
static void *owner(void *p)
{
    unsigned id=(unsigned)(uintptr_t)p;
    for(unsigned i=0;i<2000;i++){
        uint32_t token=k64_rq_lock(&rq);int aged=0;
        thread_t *t=k64_rq_pick_locked(&rq,id,100,&aged);
        if(t){if(k64_rq_remove_locked(&rq,t))abort();++consumed[t-pool];if(k64_rq_enqueue_locked(&rq,t,(id+1)%3,100,++order))abort();}
        k64_rq_unlock(&rq,token);
    }
    return 0;
}
int main(void)
{
    setvbuf(stdout,0,_IOLBF,0);
    setup();uint32_t token=k64_rq_lock(&rq);int aged;
    pool[1].sched_priority=31;
    expect("real priority queue admissions succeed",!k64_rq_enqueue_locked(&rq,&pool[0],0,0,++order) && !k64_rq_enqueue_locked(&rq,&pool[1],0,0,++order) && !k64_rq_enqueue_locked(&rq,&pool[2],0,0,++order));
    expect("higher priority selects first before aging",k64_rq_pick_locked(&rq,0,31,&aged)==&pool[1] && !aged);
    expect("32 tick aging selects oldest FIFO head",k64_rq_pick_locked(&rq,0,32,&aged)==&pool[0] && aged);
    expect("FIFO equal priority successor is retained",!k64_rq_remove_locked(&rq,&pool[0]) && rq.cpu[0].ready[16].head==&pool[2]);
    expect("duplicate enqueue rejects",k64_rq_enqueue_locked(&rq,&pool[1],0,0,++order)==-1);
    thread_t foreign=pool[0];
    expect("foreign TCB and offline CPU reject",k64_rq_enqueue_locked(&rq,&foreign,0,0,++order)==-1 && k64_rq_enqueue_locked(&rq,&pool[0],3,0,++order)==-1);
    pool[0].on_cpu=0;
    expect("live outgoing context remains unreachable",k64_rq_enqueue_locked(&rq,&pool[0],0,0,++order)==-1);
    pool[0].on_cpu=K64_CPU_NONE;
    expect("policy migration chooses permitted CPU",!k64_rq_policy_locked(&rq,&pool[2],5,4,2,10,++order) && pool[2].ready_cpu==1 && pool[2].sched_priority==5);
    expect("offline affinity failure preserves policy",k64_rq_policy_locked(&rq,&pool[2],8,1,8,10,++order)==-1 && pool[2].cpu_mask==2 && pool[2].sched_priority==5);
    pool[0].state=TS_RUNNING;pool[0].on_cpu=0;pool[0].quantum_left=1;pool[0].aging_service_left=4;
    expect("policy cannot refill running quantum or aged allocation",!k64_rq_policy_locked(&rq,&pool[0],31,16,1,10,++order) && pool[0].quantum_left==1 && pool[0].aging_service_left==4);
    expect("running CPU cannot be excluded",k64_rq_policy_locked(&rq,&pool[0],16,1,2,10,++order)==-1 && pool[0].cpu_mask==1);
    expect("priority queues conserve membership",!k64_rq_validate_locked(&rq));
    k64_rq_unlock(&rq,token);
    setup();token=k64_rq_lock(&rq);for(unsigned i=0;i<48;i++)if(k64_rq_enqueue_locked(&rq,&pool[i],i%3,100,++order))abort();k64_rq_unlock(&rq,token);
    puts("HOST_CONCURRENCY_BEGIN: owners=6 attempts=12000");
    pthread_t workers[6];for(unsigned i=0;i<6;i++)if(pthread_create(&workers[i],0,owner,(void *)(uintptr_t)(i%3)))abort();for(unsigned i=0;i<6;i++)pthread_join(workers[i],0);
    token=k64_rq_lock(&rq);unsigned total=0,seen=0;
    for(unsigned c=0;c<3;c++){thread_t *t;while((t=k64_rq_pick_locked(&rq,c,100,&aged))){if(consumed[t-pool])++seen;++total;if(k64_rq_remove_locked(&rq,t))abort();}}
    expect("six concurrent owners conserve all48 thread identities",total==48 && seen==48 && !k64_rq_validate_locked(&rq));
    k64_rq_unlock(&rq,token);puts("HOST_CONCURRENCY_END: all owners joined");return failures?1:0;
}
#else
int main(void) {puts("FAIL: production perCPU priority queue interface absent");return 1;}
#endif
