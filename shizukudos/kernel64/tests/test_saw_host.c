/* SPDX-License-Identifier: GPL-2.0-only
 * Actual saw.c, process_terminate and process_teardown with explicit host
 * scheduler/VM adapters. Corrupt states are injected here, never on the host OS.
 */
#include "../ipc.h"
#include "../saw.h"
#include <assert.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static pthread_mutex_t irq_mutex=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local unsigned irq_depth;
static uint64_t host_irq(void){unsigned old=irq_depth++;if(!old)assert(!pthread_mutex_lock(&irq_mutex));return old;}
static void host_restore(uint64_t old){assert(irq_depth==old+1);if(!--irq_depth)assert(!pthread_mutex_unlock(&irq_mutex));}
#define irq_save host_irq
#define irq_restore host_restore
static uint64_t host_cr3;
static uint64_t host_read_cr3(void){return host_cr3;}
static void host_write_cr3(uint64_t v){host_cr3=v;}
#define read_cr3 host_read_cr3
#define write_cr3 host_write_cr3
void ipc_process_teardown(process_t *);
void audio_process_teardown(process_t *);
void setup_native_process_teardown(process_t *);
typedef struct {int pending;} binding;
static binding *find(process_t *,int);
int shz_auth_process_access(process_t *,process_t *);
/* Runner inserts exact named production definitions and records their hash. */
#include "saw_process_bodies.h"
#include "../saw.c"

static process_t slots[65];static kobject_t objects[65];static thread_t threads[128];
static binding bindings[65];
static binding *find(process_t *p,int create){(void)create;return p>=slots&&p<slots+65?&bindings[p-slots]:0;}
static unsigned high_thread,termination_count,teardown_count,space_count,close_count,ipc_count,panic_count;
static unsigned restricted_thread=UINT32_MAX;
static unsigned order[64],order_count;static uint64_t tick;
static int allow_force,deny_pid,auto_exit=1;static jmp_buf fatal;
process_t *process_slot(unsigned i){return i>0&&i<65?&slots[i]:0;}
process_t *process_by_pid(int pid){for(unsigned i=1;i<65;i++)if(slots[i].used&&slots[i].pid==pid)return &slots[i];return 0;}
thread_t *thread_slot(unsigned i){return i<high_thread&&i!=restricted_thread?&threads[i]:0;}
void sched_for_each_thread(void(*fn)(thread_t*,void*),void *opaque){assert(irq_depth);for(unsigned i=0;i<high_thread;i++)
    if(i!=restricted_thread&&threads[i].state!=TS_FREE)fn(&threads[i],opaque);}
uint64_t kernel_pml4(void){return 0x1000;}
uint64_t ticks_now(void){return tick;}
int shz_auth_process_access(process_t *a,process_t *b){return b&&b->pid!=deny_pid&&(a==b||!find(b,0)->pending);}
int shz_auth_saw_force_allowed(process_t *p){(void)p;return allow_force;}
void ob_ref(kobject_t *o){assert(irq_depth&&o&&o->refs);++o->refs;}
void ob_deref(kobject_t *o){assert(o&&o->refs);if(!--o->refs){assert(o->u.proc.p->teardown==2);o->u.proc.p->used=0;}}
void ob_release_check(kobject_t *o){assert(irq_depth&&o->signaled);}
void sem_post(ksem_t *s){assert(!irq_depth);++s->count;}
void ipc_process_terminating(process_t *p){++termination_count;assert(p->terminated);order[order_count++]=(unsigned)p->pid;}
void ipc_process_teardown(process_t *p){assert(!irq_depth);++teardown_count;if(p->ipc)++ipc_count;p->ipc=0;}
void audio_process_teardown(process_t *p){(void)p;assert(!irq_depth);}
void setup_native_process_teardown(process_t *p){(void)p;assert(!irq_depth);}
void handles_close_all(process_t *p){assert(!irq_depth);if(p->handle_count)++close_count;p->handle_count=0;}
void vm_free_space(uint64_t old){assert(!irq_depth&&old&&old!=kernel_pml4());++space_count;}
void ldr_release_modules(process_t *p){assert(!irq_depth);p->modules=0;}
void thread_reap_process(const void *proc){assert(!irq_depth);for(unsigned i=0;i<high_thread;i++)
    if(threads[i].proc==proc&&threads[i].state==TS_ZOMBIE){threads[i].state=TS_FREE;threads[i].proc=0;ob_deref(((process_t*)proc)->object);}}
void thread_sleep_ms(uint64_t ms){assert(!irq_depth);tick+=ms;for(unsigned i=0;i<high_thread;i++) {
    thread_t *t=&threads[i];if(auto_exit&&t->proc&&t->proc->terminated&&!t->wait_sem&&t->state!=TS_ZOMBIE&&t->state!=TS_FREE){
        --t->proc->threads_alive;t->state=TS_ZOMBIE;
    }
}}
void kpanic(const char *s,...){assert(strstr(s,"CHARBOMBA"));++panic_count;longjmp(fatal,1);}
void *kzalloc(size_t n){return calloc(1,n);}void kfree(void *p){free(p);}
int copy_from_user(process_t *p,void *out,uint64_t in,uint64_t n){(void)p;if(!in)return -1;memcpy(out,(void*)(uintptr_t)in,n);return 0;}
int copy_to_user(process_t *p,uint64_t out,const void *in,uint64_t n){(void)p;if(!out)return -1;memcpy((void*)(uintptr_t)out,in,n);return 0;}

static void reset(void){memset(slots,0,sizeof slots);memset(objects,0,sizeof objects);memset(threads,0,sizeof threads);
    memset(bindings,0,sizeof bindings);
    high_thread=termination_count=teardown_count=space_count=close_count=ipc_count=panic_count=order_count=0;
    allow_force=deny_pid=0;auto_exit=1;tick=0;restricted_thread=UINT32_MAX;host_cr3=kernel_pml4();assert(!irq_depth);}
static process_t *make(unsigned slot,const char *name){process_t *p=&slots[slot];p->used=1;p->pid=(int)(slot*4);
    p->saw_generation=1000+slot;p->pml4=0x10000+slot*0x1000;p->object=&objects[slot];
    p->object->type=OB_PROCESS;p->object->refs=2;p->object->u.proc.p=p;
    strncpy(p->name,name,sizeof p->name-1);return p;}
static thread_t *live(process_t *p,unsigned state){thread_t *t=&threads[high_thread++];t->proc=p;t->state=state;
    t->object=(kobject_t*)(uintptr_t)1;++p->threads_alive;++p->object->refs;return t;}
static shz_saw_request query(void){shz_saw_request q={SHZ_SAW_VERSION,sizeof q,SHZ_SAW_QUERY,0,0,0,0,0,0};return q;}
static shz_saw_request operation(process_t *p,unsigned op){shz_saw_request q=query();q.operation=op;q.pid=(uint64_t)p->pid;q.generation=p->saw_generation;q.wait_ms=20;return q;}
static shz_saw_reply result;
static unsigned cases;
#define CASE() do{++cases;reset();}while(0)
static void cases_basic(void){process_t *actor,*p;shz_saw_request q;thread_t *t;
    CASE();actor=make(1,"CHAINSAW");p=make(2,"ordinary");live(p,TS_READY);p->handle_count=3;p->ipc=(void*)1;
    q=operation(p,SHZ_SAW_SINGLE);assert(saw_execute(actor,&q,&result)==0);assert(result.completed==1&&result.rows[0].lifecycle==SHZ_SAW_EXITED);
    assert(result.rows[0].steps==31&&termination_count==1&&space_count==1&&close_count==1&&ipc_count==1);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"residual");p->terminated=1;q=query();
    assert(saw_execute(actor,&q,&result)==0&&result.rows[1].classification==SHZ_SAW_ZOMBIE);
    q=operation(p,SHZ_SAW_SINGLE);assert(saw_execute(actor,&q,&result)==0&&result.completed==1);
    assert(result.rows[0].steps==(SHZ_SAW_STEP_TERMINATION_REQUESTED|SHZ_SAW_STEP_MEMORY_RELEASED));
    CASE();actor=make(1,"CHAINSAW");p=make(2,"retained");p->terminated=1;p->teardown=2;p->pml4=kernel_pml4();p->object->signaled=1;
    q=query();assert(saw_execute(actor,&q,&result)==0&&result.rows[1].classification==SHZ_SAW_ADMISSED);
    q=operation(p,SHZ_SAW_SINGLE);assert(saw_execute(actor,&q,&result)==0&&(result.flags&SHZ_SAW_REPLY_ADMITTED));
    assert(!termination_count&&!teardown_count&&!result.completed&&p->object->refs==2);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"suspended");t=live(p,TS_BLOCKED);t->suspend_count=1;q=query();
    assert(saw_execute(actor,&q,&result)==0&&result.rows[1].classification==SHZ_SAW_NORMAL&&!result.rows[1].reasons);
    t->wait_sem=(ksem_t*)(uintptr_t)1;t->suspend_count=0;q=operation(p,SHZ_SAW_SINGLE);
    assert(saw_execute(actor,&q,&result)==STATUS_PENDING&&result.flags&SHZ_SAW_REPLY_PENDING);
    assert(result.rows[0].classification==SHZ_SAW_NORMAL&&result.rows[0].reasons&SHZ_SAW_REASON_KERNEL_WAIT&&!result.completed);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"corrupt");p->terminated=1;p->teardown=2;q=operation(p,SHZ_SAW_SINGLE);
    assert(saw_execute(actor,&q,&result)==STATUS_UNSUCCESSFUL&&result.rows[0].classification==SHZ_SAW_ARMORED);
    assert(!termination_count&&!panic_count&&!p->saw_fenced);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"kernel-exit-tail");live(p,TS_RUNNING);p->threads_alive=0;
    p->terminated=1;p->teardown=2;p->pml4=kernel_pml4();p->object->signaled=1;q=query();
    assert(saw_execute(actor,&q,&result)==0&&result.rows[1].classification==SHZ_SAW_ADMISSED);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"constructing-child");p->saw_constructing=1;
    assert(!process_attach_parent(actor,p));bindings[2].pending=1;
    q=operation(p,SHZ_SAW_SINGLE);assert(saw_execute(actor,&q,&result)==STATUS_PENDING);
    assert(!teardown_count&&!space_count&&result.rows[0].classification==SHZ_SAW_NORMAL&&result.rows[0].reasons&SHZ_SAW_REASON_TEARDOWN_BUSY);
    /* The loader fails its fenced publication and then owns rollback/teardown. */
    p->saw_constructing=0;bindings[2].pending=0;process_teardown(p);p->object->signaled=1;
    q=query();assert(saw_execute(actor,&q,&result)==0&&result.rows[1].classification==SHZ_SAW_ADMISSED);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"after-restricted-ap-hole");
    threads[high_thread++].state=TS_READY;restricted_thread=0;live(p,TS_READY);q=query();
    assert(!thread_slot(0));assert(saw_execute(actor,&q,&result)==0&&result.rows[1].threads==1);
}
static void cases_boundaries(void){process_t *actor,*p,*child;shz_saw_request q;
    CASE();actor=make(1,"CHAINSAW");p=make(2,"root");live(p,TS_READY);process_saw_protect(p,SHZ_SAW_PROTECT_ROOT);q=operation(p,SHZ_SAW_NUKE);
    assert(saw_execute(actor,&q,&result)==STATUS_ACCESS_DENIED&&result.flags&SHZ_SAW_REPLY_PROTECTED);
    assert(result.rows[0].classification==SHZ_SAW_NORMAL&&!termination_count);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"root");child=make(3,"protected-child");assert(!process_attach_parent(p,child));
    process_saw_protect(child,SHZ_SAW_PROTECT_CRITICAL);q=operation(p,SHZ_SAW_NUKE);
    assert(saw_execute(actor,&q,&result)==STATUS_ACCESS_DENIED&&!p->saw_fenced&&!child->saw_fenced&&!termination_count);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"reused-pid");q=operation(p,SHZ_SAW_SINGLE);++p->saw_generation;
    assert(saw_execute(actor,&q,&result)==STATUS_INVALID_CID&&!termination_count);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"root");child=make(3,"foreign-child");assert(!process_attach_parent(p,child));deny_pid=child->pid;
    q=operation(p,SHZ_SAW_NUKE);assert(saw_execute(actor,&q,&result)==STATUS_ACCESS_DENIED&&!termination_count);
    assert(!result.rows[1].name[0]&&!result.rows[1].pid&&result.rows[1].reasons==SHZ_SAW_REASON_ACCESS);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"root");q=operation(p,SHZ_SAW_CHARBOMBA);allow_force=1;
    assert(saw_execute(actor,&q,&result)==STATUS_ACCESS_DENIED&&!termination_count);
    q.acknowledgement=SHZ_SAW_DESTRUCTIVE_ACK;allow_force=0;assert(saw_execute(actor,&q,&result)==STATUS_ACCESS_DENIED&&!termination_count);
    allow_force=1;process_saw_protect(p,SHZ_SAW_PROTECT_ROOT);assert(saw_execute(actor,&q,&result)==0&&result.flags&SHZ_SAW_REPLY_FORCED&&result.completed==1);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"corrupt-root");p->terminated=1;p->teardown=2;allow_force=1;
    q=operation(p,SHZ_SAW_CHARBOMBA);q.acknowledgement=SHZ_SAW_DESTRUCTIVE_ACK;
    if(!setjmp(fatal)){saw_execute(actor,&q,&result);assert(0);}assert(panic_count==1);
    CASE();actor=make(1,"CHAINSAW");q=operation(actor,SHZ_SAW_SINGLE);assert(saw_execute(actor,&q,&result)==STATUS_INVALID_PARAMETER&&!termination_count);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"zero-ref-tail");p->object->refs=0;q=operation(p,SHZ_SAW_SINGLE);
    assert(saw_execute(actor,&q,&result)==STATUS_INVALID_CID&&!termination_count);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"kernel-pml4-corruption");p->pml4=kernel_pml4();p->terminated=1;
    q=operation(p,SHZ_SAW_SINGLE);assert(saw_execute(actor,&q,&result)==STATUS_UNSUCCESSFUL&&!space_count&&!teardown_count);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"pending-endpoint");p->saw_constructing=1;bindings[2].pending=1;
    q=operation(p,SHZ_SAW_SINGLE);assert(saw_execute(actor,&q,&result)==STATUS_ACCESS_DENIED&&!termination_count);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"pending-child");assert(!process_attach_parent(actor,p));
    p->saw_constructing=1;bindings[2].pending=1;++p->parent_generation;
    q=operation(p,SHZ_SAW_SINGLE);assert(saw_execute(actor,&q,&result)==STATUS_ACCESS_DENIED&&!termination_count);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"pending-a");child=make(3,"pending-b");
    assert(!process_attach_parent(p,child)&&!process_attach_parent(child,p));p->saw_constructing=child->saw_constructing=1;
    bindings[2].pending=bindings[3].pending=1;assert(!shz_auth_saw_process_access(actor,p));
}
typedef struct {process_t *parent,*child;pthread_barrier_t *barrier;int32_t status;} spawn_race;
static void *spawn(void *value){spawn_race *r=value;int rc=pthread_barrier_wait(r->barrier);assert(!rc||rc==PTHREAD_BARRIER_SERIAL_THREAD);
    r->status=process_attach_parent(r->parent,r->child);return 0;}
static void cases_trees(void){process_t *actor,*p,*child,*grand;shz_saw_request q;
    CASE();actor=make(1,"CHAINSAW");p=make(2,"root");child=make(3,"child");grand=make(4,"grandchild");
    assert(!process_attach_parent(p,child)&&!process_attach_parent(child,grand));live(p,TS_READY);live(child,TS_READY);live(grand,TS_READY);
    q=operation(p,SHZ_SAW_NUKE);assert(saw_execute(actor,&q,&result)==0&&result.completed==3&&result.targets==3);
    assert(order[0]==16&&order[1]==12&&order[2]==8);assert(p->saw_fenced&&child->saw_fenced&&grand->saw_fenced);
    assert(process_attach_parent(p,make(5,"late-child"))==STATUS_PROCESS_IS_TERMINATING);
    CASE();actor=make(1,"CHAINSAW");p=make(2,"reused-parent");child=make(3,"unrelated");
    child->parent_pid=p->pid;child->parent_generation=p->saw_generation-1;q=operation(p,SHZ_SAW_NUKE);
    assert(saw_execute(actor,&q,&result)==0&&result.targets==1&&!child->terminated&&!child->saw_fenced);
    for(unsigned iteration=0;iteration<128;iteration++) {
        CASE();actor=make(1,"CHAINSAW");p=make(2,"race-root");child=make(3,"racing-child");
        pthread_t worker;pthread_barrier_t barrier;assert(!pthread_barrier_init(&barrier,0,2));spawn_race r={p,child,&barrier,0};
        assert(!pthread_create(&worker,0,spawn,&r));int rc=pthread_barrier_wait(&barrier);assert(!rc||rc==PTHREAD_BARRIER_SERIAL_THREAD);
        q=operation(p,SHZ_SAW_NUKE);assert(saw_execute(actor,&q,&result)==0);assert(!pthread_join(worker,0));
        if(r.status==0)assert(child->terminated&&child->saw_fenced&&result.targets==2);
        else assert(r.status==STATUS_PROCESS_IS_TERMINATING&&!child->parent_pid&&result.targets==1);
        assert(!pthread_barrier_destroy(&barrier));
    }
}
int main(void){cases_basic();cases_boundaries();cases_trees();printf("SAW host: %u cases, 128 actual pthread spawn/fence races PASS\n",cases);return 0;}
