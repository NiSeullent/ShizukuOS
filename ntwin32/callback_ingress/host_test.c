/* SPDX-License-Identifier: GPL-2.0-only -- real existing TLS engine controls */
#define _POSIX_C_SOURCE 200809L
#include "ingress.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

static _Atomic unsigned checks;
#define CHECK(x) do { atomic_fetch_add(&checks,1); if(!(x)) { fprintf(stderr,"line %u: %s\n",__LINE__,#x); abort(); } } while(0)
static _Thread_local void *slots[80];
static _Thread_local uint32_t owner=1;
typedef struct backend {
    unsigned used[80], allocations, frees, live, publishes;
    unsigned fail_allocate, fail_publish, fail_clear;
    unsigned attach[128], detach[128], notification_reentry, corrupt_attach;
    void *corrupted_owned;
    ni_manager *manager;
} backend;
static pthread_mutex_t loader_lock=PTHREAD_MUTEX_INITIALIZER;
static uint32_t reserve(void *context)
{
    backend *b=context; unsigned i;
    for(i=0;i<79;i++) if(!b->used[i]) { b->used[i]=1; return i; }
    return NTW_TLS_NO_SLOT;
}
static int release(void *context,uint32_t i)
{
    backend *b=context; CHECK(i<79 && b->used[i] && !slots[i]); b->used[i]=0; return 1;
}
static void *allocate(void *context,uint32_t bytes)
{
    backend *b=context; void *p;
    if(++b->allocations==b->fail_allocate) return NULL;
    p=malloc(bytes); CHECK(p); memset(p,0xa5,bytes); b->live++; return p;
}
static void deallocate(void *context,void *p)
{
    backend *b=context; CHECK(p && b->live); b->live--; b->frees++; free(p);
}
static uint32_t current(void *context) { (void)context; return owner; }
static int read_slot(void *context,uint32_t i,void **out)
{
    backend *b=context; CHECK(i<79 && b->used[i]); *out=slots[i]; return 1;
}
static int publish(void *context,uint32_t i,void *p)
{
    backend *b=context; CHECK(i<79 && b->used[i]);
    if(++b->publishes==b->fail_publish || (!p && b->fail_clear)) return 0;
    slots[i]=p; return 1;
}
static void notice(void *context,uint32_t reason,const ntw_tls_thread *tls)
{
    backend *b=context; unsigned i; CHECK(owner<128 && tls->owner==owner && tls->active);
    for(i=0;i<tls->published;i++) CHECK(slots[tls->plan->module[i].slot]==tls->data[i]);
    if(reason==NI_THREAD_ATTACH) {
        b->attach[owner]++;
        for(i=0;i<tls->count;i++) CHECK(*(uint32_t *)tls->data[i]==0x1234abcd);
    } else { CHECK(reason==NI_THREAD_DETACH); b->detach[owner]++; }
    CHECK(ni_begin_close(b->manager)==NI_NOTIFICATION_ACTIVE);
    CHECK(ni_finish(b->manager)==NI_NOTIFICATION_ACTIVE); b->notification_reentry++;
    if(reason==NI_THREAD_ATTACH && b->corrupt_attach && tls->published) {
        uint32_t i=tls->plan->module[0].slot;
        b->corrupted_owned=slots[i]; slots[i]=(void *)(uintptr_t)0x9988;
    }
}
static void setup(backend *b,ntw_tls_plan *p,ni_manager *m,uint32_t count,uint32_t *indices)
{
    uint32_t i,word=0x1234abcd; ntw_tls_spec spec[3]; const char *error=NULL;
    ntw_tls_ops ops={b,reserve,release,allocate,deallocate,current,read_slot,publish};
    memset(b,0,sizeof(*b)); memset(p,0,sizeof(*p)); memset(m,0,sizeof(*m)); memset(slots,0,sizeof(slots));
    slots[79]=(void *)(uintptr_t)0x5678; owner=1; b->manager=m;
    for(i=0;i<count;i++) { indices[i]=91+i; spec[i]=(ntw_tls_spec){&word,4,28,64,&indices[i]}; }
    CHECK(ntw_tls_prepare(p,spec,count,&ops,&error)); CHECK(ni_manager_init(m,p,notice,b)==NI_OK);
}
static void finish(backend *b,ntw_tls_plan *p,ni_manager *m,uint32_t count,const uint32_t *indices)
{
    const char *error=NULL; unsigned i;
    CHECK(ni_begin_close(m)==NI_OK); CHECK(ni_finish(m)==NI_OK);
    CHECK(ni_manager_init(m,p,notice,b)==NI_NOT_OPEN); CHECK(ntw_tls_dispose(p,&error));
    CHECK(!b->live && !p->live_threads && slots[79]==(void *)(uintptr_t)0x5678);
    for(i=0;i<count;i++) CHECK(indices[i]==91+i);
}
static void controls(void)
{
    backend b; ntw_tls_plan p; ni_manager *m=calloc(1,sizeof(*m)); uint32_t index[3];
    ni_handle h={77,88,NULL},old; ni_frame f={0},g={0},sentinel; unsigned i;
    CHECK(m);
    setup(&b,&p,m,3,index); CHECK(ni_finish(m)==NI_BUSY);
    CHECK(ni_worker_start(m,&h)==NI_OK); old=h; CHECK(m->live_workers==1 && p.live_threads==1);
    CHECK(b.attach[1]==1 && b.detach[1]==0);
    CHECK(ni_worker_start(m,&old)==NI_DUPLICATE_THREAD);
    CHECK(ni_callback_enter(m,&h,&f)==NI_OK); *(uint32_t *)slots[index[0]]=0xcafebabe;
    CHECK(ni_callback_enter(m,&h,&g)==NI_OK); CHECK(ni_worker_stop(m,&h)==NI_BUSY);
    CHECK(ni_callback_leave(m,&f)==NI_FRAME_ORDER); CHECK(m->live_calls==2);
    owner=2; CHECK(ni_callback_leave(m,&g)==NI_WRONG_THREAD); CHECK(ni_worker_stop(m,&h)==NI_WRONG_THREAD); owner=1;
    CHECK(ni_callback_leave(m,&g)==NI_OK); CHECK(ni_callback_leave(m,&g)==NI_FRAME_ORDER);
    CHECK(ni_callback_leave(m,&f)==NI_OK); CHECK(ni_callback_leave(m,&f)==NI_FRAME_ORDER);
    CHECK(ni_callback_enter(m,&h,&g)==NI_OK); CHECK(*(uint32_t *)slots[index[0]]==0xcafebabe);
    CHECK(ni_callback_leave(m,&f)==NI_FRAME_ORDER); CHECK(ni_callback_leave(m,&g)==NI_OK);
    CHECK(b.attach[1]==1 && b.detach[1]==0);
    memcpy(&sentinel,&g,sizeof(g)); CHECK(ni_callback_enter(m,&h,(ni_frame *)(void *)&m->worker[0])==NI_OUTPUT_ALIAS);
    CHECK(ni_callback_enter(m,&h,(ni_frame *)(void *)slots[index[0]])==NI_OUTPUT_ALIAS);
    CHECK(ni_worker_start(m,(ni_handle *)(void *)p.module[0].initial)==NI_OUTPUT_ALIAS);
    CHECK(ni_callback_enter(m,&h,(ni_frame *)(void *)&h)==NI_OUTPUT_ALIAS);
    CHECK(*(uint32_t *)slots[index[0]]==0xcafebabe);
    { void *owned=slots[index[0]]; slots[index[0]]=(void *)(uintptr_t)0x99;
      CHECK(ni_callback_enter(m,&h,&g)==NI_TLS_IDENTITY); CHECK(!memcmp(&sentinel,&g,sizeof(g)));
      CHECK(ni_worker_stop(m,&h)==NI_TLS_IDENTITY); CHECK(m->live_workers==1 && b.detach[1]==0);
      CHECK(slots[index[0]]==(void *)(uintptr_t)0x99); slots[index[0]]=owned; }
    { ni_frame deep[NI_DEPTH];
      for(i=0;i<NI_DEPTH;i++) CHECK(ni_callback_enter(m,&h,&deep[i])==NI_OK);
      CHECK(ni_callback_enter(m,&h,&g)==NI_LIMIT);
      for(i=NI_DEPTH;i;i--) CHECK(ni_callback_leave(m,&deep[i-1])==NI_OK); }
    m->worker[h.slot].serial=UINT32_MAX; CHECK(ni_callback_enter(m,&h,&g)==NI_LIMIT);
    CHECK(ni_worker_stop(m,&h)==NI_OK); CHECK(b.detach[1]==1 && !p.live_threads);
    CHECK(ni_worker_start(m,&h)==NI_OK); CHECK(h.generation!=old.generation);
    CHECK(ni_callback_enter(m,&old,&g)==NI_HANDLE); CHECK(ni_worker_stop(m,&old)==NI_HANDLE);
    CHECK(ni_callback_enter(m,&h,&g)==NI_OK); CHECK(ni_begin_close(m)==NI_OK); CHECK(ni_begin_close(m)==NI_OK);
    CHECK(ni_callback_enter(m,&h,&f)==NI_CLOSING); CHECK(ni_worker_start(m,&old)==NI_CLOSING);
    CHECK(ni_finish(m)==NI_BUSY); CHECK(ni_worker_stop(m,&h)==NI_BUSY);
    CHECK(ni_callback_leave(m,&g)==NI_OK); CHECK(ni_worker_stop(m,&h)==NI_OK);
    CHECK(b.attach[1]==2 && b.detach[1]==2); finish(&b,&p,m,3,index);

    /* Real TLS allocation/publication fault paths, including retained rollback. */
    for(i=1;i<=3;i++) {
        setup(&b,&p,m,3,index); b.fail_allocate=b.allocations+i; old=(ni_handle){77,88,NULL};
        CHECK(ni_worker_start(m,&old)==NI_TLS_ATTACH); CHECK(old.slot==77 && old.generation==88);
        CHECK(!m->live_workers && !p.live_threads && b.live==3); finish(&b,&p,m,3,index);
    }
    setup(&b,&p,m,3,index); b.fail_publish=b.publishes+2; b.fail_clear=1;
    CHECK(ni_worker_start(m,&h)==NI_TLS_RETAINED); CHECK(m->live_workers==1 && p.live_threads==1);
    CHECK(b.attach[1]==0 && slots[index[0]] && !slots[index[1]]);
    CHECK(ni_callback_enter(m,&h,&g)==NI_BUSY); CHECK(ni_worker_stop(m,&h)==NI_TLS_DETACH);
    CHECK(ni_begin_close(m)==NI_OK && ni_finish(m)==NI_BUSY); b.fail_clear=0;
    CHECK(ni_worker_stop(m,&h)==NI_OK); CHECK(b.detach[1]==0); finish(&b,&p,m,3,index);
    setup(&b,&p,m,3,index); CHECK(ni_worker_start(m,&h)==NI_OK); b.fail_publish=b.publishes+2;
    CHECK(ni_worker_stop(m,&h)==NI_TLS_DETACH); CHECK(b.detach[1]==1);
    CHECK(m->worker[h.slot].tls.published==2 && m->live_workers==1);
    CHECK(ni_callback_enter(m,&h,&g)==NI_BUSY); CHECK(ni_worker_stop(m,&h)==NI_OK);
    CHECK(b.detach[1]==1); finish(&b,&p,m,3,index);
    /* A notification or callback must not silently replace the native vector.
     * Detect foreign values, retain the worker/frame, and never clear them. */
    setup(&b,&p,m,1,index); b.corrupt_attach=1;
    CHECK(ni_worker_start(m,&h)==NI_TLS_IDENTITY && h.manager==m);
    CHECK(ni_callback_enter(m,&h,&g)==NI_BUSY && m->live_workers==1);
    CHECK(ni_worker_stop(m,&h)==NI_TLS_IDENTITY && slots[index[0]]==(void *)(uintptr_t)0x9988);
    slots[index[0]]=b.corrupted_owned; b.corrupt_attach=0;
    CHECK(ni_worker_stop(m,&h)==NI_OK && b.attach[1]==1 && b.detach[1]==1);
    finish(&b,&p,m,1,index);
    setup(&b,&p,m,1,index); CHECK(ni_worker_start(m,&h)==NI_OK); CHECK(ni_callback_enter(m,&h,&f)==NI_OK);
    { void *owned=slots[index[0]]; slots[index[0]]=(void *)(uintptr_t)0x7788;
      CHECK(ni_callback_leave(m,&f)==NI_TLS_IDENTITY && m->live_calls==1);
      CHECK(ni_worker_stop(m,&h)==NI_BUSY && slots[index[0]]==(void *)(uintptr_t)0x7788);
      CHECK(ni_begin_close(m)==NI_OK && ni_finish(m)==NI_BUSY); slots[index[0]]=owned; }
    CHECK(ni_callback_leave(m,&f)==NI_OK && ni_worker_stop(m,&h)==NI_OK); finish(&b,&p,m,1,index);
    /* Occupied slot refusal never overwrites an unrelated native value. */
    setup(&b,&p,m,1,index); slots[index[0]]=(void *)(uintptr_t)0x44;
    CHECK(ni_worker_start(m,&h)==NI_TLS_ATTACH && slots[index[0]]==(void *)(uintptr_t)0x44);
    slots[index[0]]=NULL; finish(&b,&p,m,1,index);
    /* Exhaustion uses a zero-module plan to isolate admission, not simulate TLS. */
    setup(&b,&p,m,0,index);
    { ni_handle handles[NI_WORKERS];
      for(i=0;i<NI_WORKERS;i++) { owner=i+1; CHECK(ni_worker_start(m,&handles[i])==NI_OK); }
      owner=100; CHECK(ni_worker_start(m,&h)==NI_LIMIT); CHECK(ni_begin_close(m)==NI_OK);
      for(i=0;i<NI_WORKERS;i++) { owner=i+1; CHECK(ni_worker_stop(m,&handles[i])==NI_OK); }
      owner=1; finish(&b,&p,m,0,index); }
    setup(&b,&p,m,0,index); m->worker[0].generation=UINT32_MAX;
    CHECK(ni_worker_start(m,&h)==NI_OK && h.slot==1); CHECK(ni_worker_stop(m,&h)==NI_OK); finish(&b,&p,m,0,index);
    /* Independent managers can admit this same native thread into distinct
     * TLS plans. Equal local slot/generation/depth/serial must remain foreign. */
    setup(&b,&p,m,1,index);
    { ni_manager *other=calloc(1,sizeof(*other)); ntw_tls_plan second={0};
      uint32_t word=0x1234abcd,index2=94; const char *error=NULL;
      ntw_tls_spec spec={&word,4,28,64,&index2}; ntw_tls_ops ops=p.ops;
      ni_handle a,bh; ni_frame af,bf,before;
      CHECK(other && ntw_tls_prepare(&second,&spec,1,&ops,&error));
      CHECK(ni_manager_init(other,&second,notice,&b)==NI_OK);
      CHECK(ni_worker_start(m,&a)==NI_OK); b.manager=other;
      CHECK(ni_worker_start(other,&bh)==NI_OK && a.slot==bh.slot && a.generation==bh.generation);
      CHECK(ni_callback_enter(m,&a,&af)==NI_OK && ni_callback_enter(other,&bh,&bf)==NI_OK); memcpy(&before,&bf,sizeof(bf));
      CHECK(ni_callback_enter(other,&a,&bf)==NI_HANDLE && !memcmp(&bf,&before,sizeof(bf)));
      CHECK(ni_callback_leave(other,&af)==NI_HANDLE && other->live_calls==1);
      CHECK(ni_worker_stop(other,&a)==NI_HANDLE && other->live_workers==1);
      CHECK(ni_callback_leave(m,&bf)==NI_HANDLE && m->live_calls==1);
      CHECK(ni_callback_leave(other,&bf)==NI_OK && ni_callback_leave(m,&af)==NI_OK);
      CHECK(ni_worker_stop(other,&bh)==NI_OK && ni_begin_close(other)==NI_OK && ni_finish(other)==NI_OK);
      CHECK(ntw_tls_dispose(&second,&error) && index2==94); b.manager=m;
      CHECK(ni_worker_stop(m,&a)==NI_OK); finish(&b,&p,m,1,index); free(other); }
    CHECK(!strcmp(ni_status_name(NI_TLS_RETAINED),"TLS_RETAINED")); CHECK(!strcmp(ni_status_name((ni_status)99),"UNKNOWN"));
    /* A valid prepared slot-zero index can leave manager's initial state zero.
     * Reject this ownership collision before changing that live index word. */
    setup(&b,&p,m,0,index);
    CHECK(ni_begin_close(m)==NI_OK && ni_finish(m)==NI_OK);
    { const char *error=NULL; uint32_t word=0x1234abcd;
      ntw_tls_spec spec={&word,4,0,16,&m->state}; ntw_tls_ops ops=p.ops;
      CHECK(ntw_tls_dispose(&p,&error)); memset(m,0,sizeof(*m));
      CHECK(ntw_tls_prepare(&p,&spec,1,&ops,&error) && m->state==0);
      CHECK(ni_manager_init(m,&p,notice,&b)==NI_OUTPUT_ALIAS && m->state==0 && !m->self);
      CHECK(ntw_tls_dispose(&p,&error) && !b.live); }
    free(m);
}
static backend parallel_backend;
static ntw_tls_plan parallel_plan;
static ni_manager parallel_manager;
static uint32_t parallel_indices[3];
static void *reused_worker(void *argument)
{
    uint32_t n=(uint32_t)(uintptr_t)argument,iteration; ni_handle h; ni_frame f,g; void *data;
    owner=n; slots[79]=(void *)(uintptr_t)(1000+n);
    CHECK(!pthread_mutex_lock(&loader_lock)); CHECK(ni_worker_start(&parallel_manager,&h)==NI_OK);
    data=slots[parallel_indices[0]]; CHECK(data && *(uint32_t *)data==0x1234abcd);
    CHECK(!pthread_mutex_unlock(&loader_lock));
    for(iteration=0;iteration<1000;iteration++) {
        CHECK(!pthread_mutex_lock(&loader_lock)); CHECK(ni_callback_enter(&parallel_manager,&h,&f)==NI_OK);
        CHECK(ni_callback_enter(&parallel_manager,&h,&g)==NI_OK); CHECK(!pthread_mutex_unlock(&loader_lock));
        CHECK(slots[parallel_indices[0]]==data); CHECK(*(uint32_t *)data==(iteration? n*10000+iteration-1 : 0x1234abcd));
        *(uint32_t *)data=n*10000+iteration;
        CHECK(!pthread_mutex_lock(&loader_lock)); CHECK(ni_callback_leave(&parallel_manager,&g)==NI_OK);
        CHECK(ni_callback_leave(&parallel_manager,&f)==NI_OK); CHECK(!pthread_mutex_unlock(&loader_lock));
    }
    CHECK(!pthread_mutex_lock(&loader_lock)); CHECK(ni_worker_stop(&parallel_manager,&h)==NI_OK);
    CHECK(slots[79]==(void *)(uintptr_t)(1000+n)); CHECK(!pthread_mutex_unlock(&loader_lock)); return NULL;
}
int main(void)
{
    pthread_t threads[8]; unsigned i; controls();
    setup(&parallel_backend,&parallel_plan,&parallel_manager,3,parallel_indices);
    for(i=0;i<8;i++) CHECK(!pthread_create(&threads[i],NULL,reused_worker,(void *)(uintptr_t)(i+2)));
    for(i=0;i<8;i++) CHECK(!pthread_join(threads[i],NULL));
    CHECK(!parallel_manager.live_workers && !parallel_manager.live_calls && !parallel_plan.live_threads);
    for(i=2;i<10;i++) CHECK(parallel_backend.attach[i]==1 && parallel_backend.detach[i]==1);
    finish(&parallel_backend,&parallel_plan,&parallel_manager,3,parallel_indices);
    printf("PASS CHECKS=%u REAL_PTHREAD_WORKERS=8 REUSED_CALLBACKS=8000\nNATIVE_EXECUTED=0 APPLICATION_SUCCESS=0\n",atomic_load(&checks));
    return 0;
}
