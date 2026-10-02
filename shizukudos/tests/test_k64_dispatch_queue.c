/* SPDX-License-Identifier: GPL-2.0-only
 * Real dispatch/completion primitives under six host logical owners. No AP or
 * privileged context switch is executed. Each owner releases the ticket across
 * its modeled saved-stack handoff, allowing genuinely concurrent admissions.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include "../kernel64/k64.h"
#include "../kernel64/sched_cpu.h"
enum { OWNERS=6, THREADS=96, EPOCHS=2000 };
static k64_runqueues_t rq;
static thread_t pool[THREADS];
static unsigned failures,checks,dispatches[THREADS];
static uint64_t order;
static uint32_t completed[OWNERS];
static uint32_t last_step[OWNERS],last_current[OWNERS],last_outgoing[OWNERS];
static int watchdog_control;
static void watchdog(int signal)
{
    (void)signal;
    /* Async-signal-safe bounded diagnostic. No ticket acquisition or stdio. */
    char text[512];size_t at=0;const char prefix[]="HOST_TIMEOUT_PROGRESS:";
    memcpy(text,prefix,sizeof prefix-1);at=sizeof prefix-1;
    for(unsigned i=0;i<OWNERS*4+3;i++) {
        const unsigned cpu=i/4,field=i%4;
        uint32_t v=i<OWNERS*4?__atomic_load_n(field==0?&completed[cpu]:field==1?&last_step[cpu]:field==2?&last_current[cpu]:&last_outgoing[cpu],__ATOMIC_RELAXED):
            i==OWNERS*4?__atomic_load_n(&rq.lock.owner,__ATOMIC_RELAXED):
            i==OWNERS*4+1?__atomic_load_n(&rq.lock.next,__ATOMIC_RELAXED):__atomic_load_n(&rq.lock.reservation,__ATOMIC_RELAXED);
        char digits[10];unsigned count=0;text[at++]=' ';
        do { digits[count++]=(char)('0'+v%10);v/=10; } while(v);
        while(count)text[at++]=digits[--count];
    }
    text[at++]='\n';(void)write(STDERR_FILENO,text,at);_exit(124);
}
void kpanic(const char *f,...) { va_list a;va_start(a,f);vfprintf(stderr,f,a);va_end(a);abort(); }
static void check(const char *n,int c) { ++checks;failures+=!c;printf("%s: %s\n",c?"PASS":"FAIL",n); }
static void setup(void)
{
    memset(pool,0,sizeof pool);memset(dispatches,0,sizeof dispatches);order=0;k64_rq_init(&rq,pool,THREADS,63);
    for(unsigned i=0;i<THREADS;i++) {
        pool[i].state=TS_READY;pool[i].cpu_mask=63;pool[i].sched_priority=16;
        pool[i].quantum_ticks=pool[i].quantum_left=1;pool[i].ready_cpu=pool[i].on_cpu=K64_CPU_NONE;
    }
    for(unsigned c=0;c<OWNERS;c++) {
        rq.cpu[c].current=&pool[c];pool[c].state=TS_RUNNING;pool[c].on_cpu=c;
        rq.cpu[c].idle=&pool[OWNERS+c];pool[OWNERS+c].cpu_mask=1ull<<c;pool[OWNERS+c].sched_priority=0;
    }
}
static void *owner(void *arg)
{
    const unsigned cpu=(uintptr_t)arg;
    for(unsigned epoch=0;epoch<EPOCHS;epoch++) {
        uint32_t ticket=k64_rq_lock(&rq);thread_t *prev=rq.cpu[cpu].current;int aged=0;
        prev->state=TS_READY;prev->ready_since=100;prev->ready_order=++order;
        thread_t *next=k64_rq_pick_locked(&rq,cpu,100,&aged);
        if(!next || k64_rq_dispatch_locked(&rq,cpu,next,aged,100)!=1 || next->on_cpu!=cpu ||
           prev->on_cpu!=cpu || prev->ready_queued || rq.cpu[cpu].outgoing!=prev)abort();
        ++dispatches[next-pool];k64_rq_unlock(&rq,ticket);
        __atomic_store_n(&last_current[cpu],(uint32_t)(next-pool)+1,__ATOMIC_RELAXED);
        __atomic_store_n(&last_outgoing[cpu],(uint32_t)(prev-pool)+1,__ATOMIC_RELAXED);
        __atomic_store_n(&last_step[cpu],1,__ATOMIC_RELAXED);
        if(watchdog_control && !cpu && !epoch)watchdog(0);
        /* Another real host thread can acquire the production ticket now. */
        ticket=k64_rq_lock(&rq);
        if(k64_rq_enqueue_locked(&rq,prev,(cpu+1)%OWNERS,100,++order)!=-1 ||
           k64_rq_reapable_locked(&rq,prev) ||
           k64_rq_policy_locked(&rq,prev,16,16,63,100,++order) ||
           k64_rq_complete_locked(&rq,cpu)!=prev || prev->on_cpu!=K64_CPU_NONE ||
           !prev->ready_queued || rq.cpu[cpu].outgoing)abort();
        k64_rq_unlock(&rq,ticket);
        __atomic_store_n(&last_outgoing[cpu],0,__ATOMIC_RELAXED);
        __atomic_store_n(&last_step[cpu],2,__ATOMIC_RELAXED);
        __atomic_store_n(&completed[cpu],epoch+1,__ATOMIC_RELAXED);
    }
    return 0;
}
int main(void)
{
    setvbuf(stdout,0,_IOLBF,0);setup();uint32_t ticket=k64_rq_lock(&rq);int aged=0;
    for(unsigned i=2*OWNERS;i<THREADS;i++)if(k64_rq_enqueue_locked(&rq,&pool[i],i%OWNERS,100,++order))abort();
    thread_t foreign=pool[12];k64_cpu_sched_t before=rq.cpu[0];
    check("foreign dispatch rejects without current mutation",k64_rq_dispatch_locked(&rq,0,&foreign,0,100)==-1 && !memcmp(&before,&rq.cpu[0],sizeof before));
    check("offline completion and absent handoff reject",!k64_rq_complete_locked(&rq,6) && !k64_rq_complete_locked(&rq,0));
    pool[0].state=TS_READY;thread_t *next=k64_rq_pick_locked(&rq,0,132,&aged);
    check("actual aged dispatch allocates unchanged fixed4",aged && k64_rq_dispatch_locked(&rq,0,next,aged,132)==1 && next->aging_service_left==4 && next->quantum_left==1);
    k64_cpu_sched_t own=rq.cpu[0];
    check("second dispatch cannot overwrite live handoff",k64_rq_dispatch_locked(&rq,0,rq.cpu[0].idle,0,132)==-1 && !memcmp(&own,&rq.cpu[0],sizeof own));
    check("policy refresh cannot renew service allocation",!k64_rq_policy_locked(&rq,next,16,16,63,132,++order) && next->aging_service_left==4 && next->quantum_left==1);
    check("completion releases and enqueues former owner once",k64_rq_complete_locked(&rq,0)==&pool[0] && pool[0].on_cpu==K64_CPU_NONE && pool[0].ready_queued && !k64_rq_complete_locked(&rq,0));
    next->aging_service_left=0;k64_rq_unlock(&rq,ticket);
    puts("HOST_CONTEXT_CONCURRENCY_BEGIN: owners=6 epochs=12000");
    puts("HOST_PROGRESS_FIELDS: each_owner=completed,last_step,last_locked_current_plus1,last_locked_outgoing_plus1 then=serving,next,reservation");
    watchdog_control=getenv("SHZ_DISPATCH_WATCHDOG_CONTROL")!=0;
    struct timespec started,finished;clock_gettime(CLOCK_MONOTONIC,&started);
    signal(SIGALRM,watchdog);alarm(50);
    pthread_t workers[OWNERS];for(unsigned c=0;c<OWNERS;c++)if(pthread_create(&workers[c],0,owner,(void *)(uintptr_t)c))abort();
    for(unsigned c=0;c<OWNERS;c++)pthread_join(workers[c],0);
    alarm(0);
    clock_gettime(CLOCK_MONOTONIC,&finished);
    printf("HOST_CONTEXT_SECONDS: %.6f completed=",(double)(finished.tv_sec-started.tv_sec)+(double)(finished.tv_nsec-started.tv_nsec)/1000000000.0);
    for(unsigned c=0;c<OWNERS;c++)printf("%s%u",c?",":"",__atomic_load_n(&completed[c],__ATOMIC_RELAXED));
    puts("");
    ticket=k64_rq_lock(&rq);unsigned ready=0,ran=0;uint8_t seen[THREADS]={0};int valid=!k64_rq_validate_locked(&rq);
    for(unsigned c=0;c<OWNERS;c++) {
        thread_t *t=rq.cpu[c].current;
        valid &= t && t->state==TS_RUNNING && t->on_cpu==c && !t->ready_queued && !rq.cpu[c].outgoing && !seen[t-pool]++;
        ready+=rq.cpu[c].ready_count;
    }
    for(unsigned i=0;i<THREADS;i++) {
        ran+=!!dispatches[i];
        if(i>=OWNERS && i<2*OWNERS)valid &= !pool[i].ready_queued && pool[i].on_cpu==K64_CPU_NONE;
        else valid &= (!!pool[i].ready_queued + (pool[i].on_cpu!=K64_CPU_NONE))==1;
    }
    check("six concurrent saved-stack handoffs conserve every identity",valid && ready==THREADS-2*OWNERS && ran==THREADS-OWNERS);
    k64_rq_unlock(&rq,ticket);puts("HOST_CONTEXT_CONCURRENCY_END: all owners joined");
    printf("checks=%u failures=%u scope=actual_queue_context_host_only\n",checks,failures);return failures?1:0;
}
