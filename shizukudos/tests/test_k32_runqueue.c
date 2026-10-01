/* SPDX-License-Identifier: GPL-2.0-only
 * Real internal production queue, concurrent logical owners; no AP execution.
 */
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../kernel32/k32.h"
#if __has_include("../kernel32/sched_cpu.h")
#include "../kernel32/sched_cpu.h"
void kpanic(const char *f, ...) { va_list a;va_start(a,f);vfprintf(stderr,f,a);va_end(a);abort(); }
static k32_runqueues_t rq;
static thread_t pool[48];
static unsigned failures, consumed[48], rounds=2000;
static void expect(const char *n,int c) { printf("%s: %s\n",c?"PASS":"FAIL",n); failures+=!c; }
static void setup(uint32_t mask) { memset(pool,0,sizeof pool); k32_rq_init(&rq,pool,48,mask); for(unsigned i=0;i<48;i++){pool[i].state=1;pool[i].affinity_mask=mask;pool[i].ready_cpu=pool[i].on_cpu=K32_CPU_NONE;} }
static void *owner(void *p) {
    unsigned id=(unsigned)(uintptr_t)p;
    for(unsigned r=0;r<rounds;r++) {
        uint32_t ticket=k32_rq_lock(&rq);
        thread_t *t=k32_rq_pop_locked(&rq,id);
        if(t) { unsigned n=(unsigned)(t-pool); ++consumed[n]; t->state=1; if(k32_rq_enqueue_locked(&rq,t,(id+1)%3)) abort(); }
        k32_rq_unlock(&rq,ticket);
    }
    return 0;
}
int main(void) {
    setup(7); uint32_t ticket=k32_rq_lock(&rq);
    expect("FIFO admission accepts legitimate READY TCBs", !k32_rq_enqueue_locked(&rq,&pool[0],0) && !k32_rq_enqueue_locked(&rq,&pool[1],0));
    expect("duplicate admission fails", k32_rq_enqueue_locked(&rq,&pool[0],0)==-1);
    thread_t foreign={0}; foreign.state=1;foreign.affinity_mask=7;foreign.ready_cpu=foreign.on_cpu=K32_CPU_NONE;
    expect("foreign and unonline CPU admission fail", k32_rq_enqueue_locked(&rq,&foreign,0)==-1 && k32_rq_enqueue_locked(&rq,&pool[2],3)==-1);
    expect("FIFO selects each once", k32_rq_pop_locked(&rq,0)==&pool[0] && k32_rq_pop_locked(&rq,0)==&pool[1] && !k32_rq_pop_locked(&rq,0));
    pool[0].on_cpu=0;
    expect("live outgoing context cannot be enqueued", k32_rq_enqueue_locked(&rq,&pool[0],0)==-1);
    pool[0].on_cpu=K32_CPU_NONE;pool[0].affinity_mask=2;
    expect("affinity restricts queue selection", k32_rq_enqueue_locked(&rq,&pool[0],0)==-1 && !k32_rq_enqueue_locked(&rq,&pool[0],1));
    expect("queued affinity moves atomically to permitted CPU", !k32_rq_affinity_locked(&rq,&pool[0],4) && pool[0].ready_cpu==2 && !rq.cpu[1].queued && rq.cpu[2].head==&pool[0]);
    expect("offline affinity rejection preserves queue and policy", k32_rq_affinity_locked(&rq,&pool[0],8)==-1 && pool[0].affinity_mask==4 && rq.cpu[2].head==&pool[0]);
    expect("equal affinity retains FIFO position", !k32_rq_affinity_locked(&rq,&pool[0],4) && rq.cpu[2].head==&pool[0]);
    pool[1].state=2;pool[1].on_cpu=0;
    expect("running ownership blocks remote affinity", k32_rq_affinity_locked(&rq,&pool[1],2)==-1 && pool[1].affinity_mask==7);
    pool[1].on_cpu=32;
    expect("invalid active owner rejects before shift", k32_rq_affinity_locked(&rq,&pool[1],7)==-1);
    expect("queue invariants hold after rejection", k32_rq_validate_locked(&rq)==0);
    k32_rq_unlock(&rq,ticket);
    setup(7);ticket=k32_rq_lock(&rq);
    for(unsigned i=0;i<48;i++) if(k32_rq_enqueue_locked(&rq,&pool[i],i%3)) abort();
    k32_rq_unlock(&rq,ticket);
    pthread_t workers[6];for(unsigned i=0;i<6;i++) if(pthread_create(&workers[i],0,owner,(void *)(uintptr_t)(i%3))) abort();
    for(unsigned i=0;i<6;i++) pthread_join(workers[i],0);
    ticket=k32_rq_lock(&rq); unsigned seen=0,total=0;
    for(unsigned c=0;c<3;c++) {thread_t *t;while((t=k32_rq_pop_locked(&rq,c))) {unsigned n=(unsigned)(t-pool);if(consumed[n]) ++seen;++total;}}
    expect("concurrent producer/consumer transfer conserves all 48 identities", total==48 && seen==48 && k32_rq_validate_locked(&rq)==0);
    expect("online masks reject impossible bit selection", !k32_rq_cpu_online(&rq,32) && !k32_rq_cpu_online(&rq,3));
    k32_rq_unlock(&rq,ticket);
    return failures?1:0;
}
#else
int main(void) { puts("FAIL: production per-CPU queue interface absent"); return 1; }
#endif
