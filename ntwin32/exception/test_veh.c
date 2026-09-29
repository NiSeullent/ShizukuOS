/* SPDX-License-Identifier: GPL-2.0-only
 * Original synthetic host concurrency/lifetime tests, not native VEH tests.
 */
#define _POSIX_C_SOURCE 200809L
#include "veh.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static atomic_ulong checks,callbacks,allocations,releases;
#define C(x) do{atomic_fetch_add(&checks,1);if(!(x)){fprintf(stderr,"line %u: %s\n",__LINE__,#x);abort();}}while(0)
static _Thread_local unsigned lock_depth;
typedef struct env {
    ntwe_registry r;
    pthread_mutex_t mutex;
    atomic_uint fail_alloc;
    unsigned release_reenter,release_expect_dispatch;
} env;
static void *allocate(void *user,size_t bytes){env *e=user;void *p;C(lock_depth==0);if(atomic_exchange(&e->fail_alloc,0))return NULL;p=malloc(bytes);C(p!=NULL);atomic_fetch_add(&allocations,1);memset(p,0xa5,bytes);return p;}
static void release(void *user,void *p,size_t bytes){env *e=user;ntwe_stats s;C(lock_depth==0&&p&&bytes>0);if(e->release_reenter){C(ntwe_get_stats(&e->r,&s)==NTWE_OK);if(e->release_expect_dispatch)C(s.dispatches>0);}memset(p,0xdd,bytes);free(p);atomic_fetch_add(&releases,1);}
static void lock(void *user){env *e=user;C(lock_depth==0);C(!pthread_mutex_lock(&e->mutex));++lock_depth;}
static void unlock(void *user){env *e=user;C(lock_depth==1);--lock_depth;C(!pthread_mutex_unlock(&e->mutex));}
static void init(env *e){ntwe_ops ops;memset(e,0,sizeof(*e));atomic_init(&e->fail_alloc,0);C(!pthread_mutex_init(&e->mutex,NULL));ops=(ntwe_ops){e,allocate,release,lock,unlock};C(ntwe_init(&e->r,&ops)==NTWE_OK);}
static void finish(env *e){ntwe_stats s;C(ntwe_close(&e->r)==NTWE_OK);C(ntwe_get_stats(&e->r,&s)==NTWE_OK);C(!s.exception_count&&!s.continue_count&&!s.dispatches&&s.closed);C(!pthread_mutex_destroy(&e->mutex));}

typedef struct item {env *e;unsigned id;int32_t response;ntwe_handle handle;int *order;unsigned *used;} item;
static int32_t handler(ntwe_pointers *p,void *user){item *i=user;C(lock_depth==0&&p&&p->exception_record&&p->context_record);atomic_fetch_add(&callbacks,1);if(i->order){i->order[(*i->used)++]=(int)i->id;}return i->response;}
static ntwe_handle add(env *e,enum ntwe_kind kind,int first,item *i){ntwe_handle h=0;C(ntwe_add(&e->r,kind,first,handler,i,&h)==NTWE_OK&&h);i->handle=h;return h;}
static int32_t dispatch(env *e,enum ntwe_kind kind){int record=17,context=19;int32_t result=123;C(ntwe_dispatch(&e->r,kind,&record,&context,&result)==NTWE_OK);return result;}

static void basic(void){
 env e;item i[4];int order[16];unsigned used=0,n;ntwe_stats s;ntwe_handle h=0x12345678;int32_t result=77;
 init(&e);memset(i,0,sizeof(i));for(n=0;n<4;++n){i[n].e=&e;i[n].id=n+1;i[n].order=order;i[n].used=&used;}
 C(dispatch(&e,NTWE_EXCEPTION)==0);add(&e,NTWE_EXCEPTION,0,&i[0]);add(&e,NTWE_EXCEPTION,2,&i[1]);add(&e,NTWE_EXCEPTION,-1,&i[2]);add(&e,NTWE_CONTINUE,0,&i[3]);
 C(dispatch(&e,NTWE_EXCEPTION)==0&&used==3&&order[0]==3&&order[1]==2&&order[2]==1);
 used=0;i[1].response=-1;C(dispatch(&e,NTWE_EXCEPTION)==-1&&used==2&&order[0]==3&&order[1]==2);
 used=0;i[3].response=-1;C(dispatch(&e,NTWE_CONTINUE)==-1&&used==1&&order[0]==4);
 C(ntwe_remove(&e.r,NTWE_CONTINUE,i[0].handle)==NTWE_NOT_FOUND);
 C(ntwe_remove(&e.r,NTWE_EXCEPTION,i[0].handle)==NTWE_OK);
 C(ntwe_remove(&e.r,NTWE_EXCEPTION,i[0].handle)==NTWE_NOT_FOUND);
 C(ntwe_remove(&e.r,NTWE_EXCEPTION,0)==NTWE_NOT_FOUND);
 C(ntwe_add(&e.r,(enum ntwe_kind)2,0,handler,i,&h)==NTWE_INVALID&&h==0x12345678);
 C(ntwe_add(&e.r,NTWE_EXCEPTION,0,NULL,i,&h)==NTWE_INVALID&&h==0x12345678);
 atomic_store(&e.fail_alloc,1);C(ntwe_add(&e.r,NTWE_EXCEPTION,0,handler,i,&h)==NTWE_NO_MEMORY&&h==0x12345678);
 C(ntwe_dispatch(&e.r,NTWE_EXCEPTION,NULL,i,&result)==NTWE_INVALID&&result==77);
 C(ntwe_get_stats(&e.r,&s)==NTWE_OK&&s.exception_count==2&&s.continue_count==1);
 C(ntwe_close(&e.r)==NTWE_OK);C(ntwe_add(&e.r,NTWE_EXCEPTION,0,handler,i,&h)==NTWE_CLOSED);
 C(ntwe_dispatch(&e.r,NTWE_EXCEPTION,i,i,&result)==NTWE_CLOSED&&result==77);
 finish(&e);
}

typedef struct reentry {env *e;ntwe_handle self,next,added;item replacement;unsigned calls,deep;int record,context,stop;} reentry;
static int32_t reentrant(ntwe_pointers *p,void *user){
 reentry *x=user;int32_t result;C(lock_depth==0);++x->calls;atomic_fetch_add(&callbacks,1);
 C(p->exception_record==&x->record&&p->context_record==&x->context);++x->record;
 C(ntwe_remove(&x->e->r,NTWE_EXCEPTION,x->self)==NTWE_PENDING);
 C(ntwe_remove(&x->e->r,NTWE_EXCEPTION,x->self)==NTWE_NOT_FOUND);
 C(ntwe_remove(&x->e->r,NTWE_EXCEPTION,x->next)==NTWE_PENDING);
 C(ntwe_add(&x->e->r,NTWE_EXCEPTION,1,handler,&x->replacement,&x->added)==NTWE_OK);
 if(x->deep)C(ntwe_dispatch(&x->e->r,NTWE_EXCEPTION,&x->record,&x->context,&result)==NTWE_OK);
 return x->stop?-1:0;
}
static void reentry_cases(void){
 unsigned deep;
 for(deep=0;deep<3;++deep){env e;reentry x;item removed={0},tail={0};int order[16];unsigned used=0;int32_t result;
  init(&e);memset(&x,0,sizeof(x));x.e=&e;x.deep=deep==1;x.stop=deep==2;x.replacement=(item){&e,3,0,0,order,&used};
  removed=(item){&e,2,0,0,order,&used};tail=(item){&e,4,0,0,order,&used};
  C(ntwe_add(&e.r,NTWE_EXCEPTION,0,reentrant,&x,&x.self)==NTWE_OK);
  x.next=add(&e,NTWE_EXCEPTION,0,&removed);add(&e,NTWE_EXCEPTION,0,&tail);e.release_reenter=1;e.release_expect_dispatch=1;
  C(ntwe_dispatch(&e.r,NTWE_EXCEPTION,&x.record,&x.context,&result)==NTWE_OK&&result==(x.stop?-1:0)&&x.calls==1&&x.record==1);
  e.release_expect_dispatch=0;
  if(deep==1)C(used==3&&order[0]==3&&order[1]==4&&order[2]==4);else if(deep==2)C(used==0);else C(used==1&&order[0]==4);
  used=0;C(dispatch(&e,NTWE_EXCEPTION)==0&&used==2&&order[0]==3&&order[1]==4);
  finish(&e);
 }
}

static int32_t close_callback(ntwe_pointers *p,void *user){env *e=user;C(p&&lock_depth==0);C(ntwe_close(&e->r)==NTWE_PENDING);C(ntwe_close(&e->r)==NTWE_PENDING);return -1;}
static void close_reentry(void){env e;ntwe_handle h;item i={0};unsigned long freed;ntwe_stats s;init(&e);C(ntwe_add(&e.r,NTWE_EXCEPTION,0,close_callback,&e,&h)==NTWE_OK);add(&e,NTWE_EXCEPTION,0,&i);add(&e,NTWE_CONTINUE,0,&i);freed=atomic_load(&releases);C(dispatch(&e,NTWE_EXCEPTION)==-1);C(atomic_load(&releases)==freed+3);C(ntwe_get_stats(&e.r,&s)==NTWE_OK&&!s.dispatches&&s.closed);finish(&e);}

typedef struct gate {env *e;pthread_mutex_t mutex;pthread_cond_t cond;unsigned entered,leave;int32_t status,result;} gate;
static int32_t blocking(ntwe_pointers *p,void *user){gate *g=user;C(lock_depth==0&&p);atomic_fetch_add(&callbacks,1);C(!pthread_mutex_lock(&g->mutex));g->entered=1;C(!pthread_cond_broadcast(&g->cond));while(!g->leave)C(!pthread_cond_wait(&g->cond,&g->mutex));C(!pthread_mutex_unlock(&g->mutex));return 0;}
static void *dispatch_thread(void *user){gate *g=user;int a=1,b=2;g->status=ntwe_dispatch(&g->e->r,NTWE_EXCEPTION,&a,&b,&g->result);return NULL;}
static void concurrent_cases(void){
 unsigned closing;
 for(closing=0;closing<2;++closing){env e;gate g;pthread_t thread;ntwe_handle first,next;item tail={0};ntwe_stats s;unsigned long freed;
  init(&e);memset(&g,0,sizeof(g));g.e=&e;C(!pthread_mutex_init(&g.mutex,NULL));C(!pthread_cond_init(&g.cond,NULL));
  C(ntwe_add(&e.r,NTWE_EXCEPTION,0,blocking,&g,&first)==NTWE_OK);next=add(&e,NTWE_EXCEPTION,0,&tail);add(&e,NTWE_EXCEPTION,0,&tail);
  C(!pthread_create(&thread,NULL,dispatch_thread,&g));C(!pthread_mutex_lock(&g.mutex));while(!g.entered)C(!pthread_cond_wait(&g.cond,&g.mutex));C(!pthread_mutex_unlock(&g.mutex));
  freed=atomic_load(&releases);
  C(ntwe_remove(&e.r,NTWE_EXCEPTION,first)==NTWE_PENDING);
  C(ntwe_remove(&e.r,NTWE_EXCEPTION,first)==NTWE_NOT_FOUND);
  C(ntwe_remove(&e.r,NTWE_EXCEPTION,next)==NTWE_PENDING);
  if(closing)C(ntwe_close(&e.r)==NTWE_PENDING);else C(dispatch(&e,NTWE_EXCEPTION)==0);
  C(atomic_load(&releases)==freed);C(ntwe_get_stats(&e.r,&s)==NTWE_OK&&s.dispatches==1);
  C(!pthread_mutex_lock(&g.mutex));g.leave=1;C(!pthread_cond_signal(&g.cond));C(!pthread_mutex_unlock(&g.mutex));
  C(!pthread_join(thread,NULL));C(g.status==NTWE_OK&&g.result==0);C(atomic_load(&releases)==freed+(closing?3u:2u));
  finish(&e);C(!pthread_cond_destroy(&g.cond));C(!pthread_mutex_destroy(&g.mutex));
 }
}

typedef struct depth {env *e;unsigned calls,limits;} depth;
static int32_t recurse(ntwe_pointers *p,void *user){depth *d=user;int32_t result=42;int status;++d->calls;C(lock_depth==0);status=ntwe_dispatch(&d->e->r,NTWE_EXCEPTION,p->exception_record,p->context_record,&result);if(status==NTWE_LIMIT){++d->limits;C(result==42);}else C(status==NTWE_OK&&result==0);return 0;}
static void limits(void){
 env e;item i={0};ntwe_handle handles[NTWE_MAX_HANDLERS],h=55;unsigned n;depth d;
 init(&e);for(n=0;n<NTWE_MAX_HANDLERS;++n)handles[n]=add(&e,(enum ntwe_kind)(n&1u),0,&i);
 C(ntwe_add(&e.r,NTWE_EXCEPTION,0,handler,&i,&h)==NTWE_LIMIT&&h==55);
 for(n=0;n<NTWE_MAX_HANDLERS;++n)C(ntwe_remove(&e.r,(enum ntwe_kind)(n&1u),handles[n])==NTWE_OK);
 e.r.next_handle=0xffffffffu;h=add(&e,NTWE_EXCEPTION,0,&i);C(h==0xffffffffu);
 C(ntwe_remove(&e.r,NTWE_EXCEPTION,h)==NTWE_OK);C(ntwe_add(&e.r,NTWE_EXCEPTION,0,handler,&i,&h)==NTWE_LIMIT&&h==0xffffffffu);
 finish(&e);init(&e);d=(depth){&e,0,0};C(ntwe_add(&e.r,NTWE_EXCEPTION,0,recurse,&d,&h)==NTWE_OK);
 C(dispatch(&e,NTWE_EXCEPTION)==0&&d.calls==NTWE_MAX_DISPATCHES&&d.limits==1);finish(&e);
}

typedef struct stress {env *e;item *shared;unsigned index;} stress;
static void *stress_thread(void *user){stress *s=user;unsigned n;for(n=0;n<500;++n){ntwe_handle h;int status;int32_t result;int a=1,b=2;enum ntwe_kind kind=(enum ntwe_kind)(s->index&1u);
 C(ntwe_add(&s->e->r,kind,(int)(n&1u),handler,s->shared,&h)==NTWE_OK);
 C(ntwe_dispatch(&s->e->r,kind,&a,&b,&result)==NTWE_OK&&result==0);
 status=ntwe_remove(&s->e->r,kind,h);C(status==NTWE_OK||status==NTWE_PENDING);
 C(ntwe_remove(&s->e->r,kind,h)==NTWE_NOT_FOUND);
 }return NULL;}
static void threaded_stress(void){env e;item shared={0};stress s[4];pthread_t threads[4];unsigned i;init(&e);for(i=0;i<4;++i){s[i]=(stress){&e,&shared,i};C(!pthread_create(&threads[i],NULL,stress_thread,&s[i]));}for(i=0;i<4;++i)C(!pthread_join(threads[i],NULL));finish(&e);}

int main(void){
 ntwe_registry r;ntwe_ops bad={0};ntwe_registry sentinel;
 memset(&r,0xa5,sizeof(r));sentinel=r;C(ntwe_init(&r,&bad)==NTWE_INVALID&&memcmp(&r,&sentinel,sizeof(r))==0);
 basic();reentry_cases();close_reentry();concurrent_cases();limits();threaded_stress();
 C(atomic_load(&allocations)==atomic_load(&releases));
 printf("{\"passed\":true,\"checks\":%lu,\"callbacks\":%lu,\"allocations\":%lu,\"releases\":%lu,\"stress_threads\":4,\"stress_iterations_each\":500}\n",atomic_load(&checks),atomic_load(&callbacks),atomic_load(&allocations),atomic_load(&releases));return 0;
}
