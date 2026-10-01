/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "address_wait.h"
#include "api_contract.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
typedef struct event {pthread_mutex_t lock;pthread_cond_t cond;int signaled;} event;
typedef struct backend {pthread_mutex_t lock;unsigned opens,closes,live;atomic_int fail_create,fail_signal,fail_wait,fail_close,early_wake,timeout_after_wake;aw_context *context;void *address;} backend;
static _Thread_local uint32_t last_error;
static atomic_uint checks;
static void check(int condition,const char *label){atomic_fetch_add(&checks,1);if(!condition){fprintf(stderr,"FAIL %s\n",label);exit(1);}}
static void enter(void *p){check(!pthread_mutex_lock(&((backend *)p)->lock),"mutex enter");}
static void leave(void *p){check(!pthread_mutex_unlock(&((backend *)p)->lock),"mutex leave");}
static uintptr_t create(void *p)
{
 backend *b=p;event *e;pthread_condattr_t attr;
 if(atomic_exchange(&b->fail_create,0)){last_error=101;return 0;}
 e=calloc(1,sizeof(*e));check(e!=0,"allocate event");
 check(!pthread_mutex_init(&e->lock,0),"event mutex");check(!pthread_condattr_init(&attr),"cond attr");
 check(!pthread_condattr_setclock(&attr,CLOCK_MONOTONIC),"monotonic event");
 check(!pthread_cond_init(&e->cond,&attr),"event cond");check(!pthread_condattr_destroy(&attr),"cond attr free");
 b->opens++;b->live++;return (uintptr_t)e;
}
static int signal(void *p,uintptr_t handle)
{
 backend *b=p;event *e=(event *)handle;
 if(atomic_exchange(&b->fail_signal,0)){last_error=102;return 0;}
 check(!pthread_mutex_lock(&e->lock),"signal mutex");e->signaled=1;
 check(!pthread_cond_signal(&e->cond),"signal condition");check(!pthread_mutex_unlock(&e->lock),"signal unlock");return 1;
}
static uint32_t wait_event(void *p,uintptr_t handle,uint32_t timeout)
{
 backend *b=p;event *e=(event *)handle;struct timespec end;int result=0;
 if(atomic_exchange(&b->early_wake,0)){uint32_t error;check(aw_wake(b->context,b->address,0,&error),"wake before real event wait");}
 if(atomic_exchange(&b->fail_wait,0)){last_error=103;return AW_WAIT_FAILED;}
 if(atomic_exchange(&b->timeout_after_wake,0))return 258;
 check(!clock_gettime(CLOCK_MONOTONIC,&end),"monotonic time");
 end.tv_sec+=timeout/1000;end.tv_nsec+=(long)(timeout%1000)*1000000L;
 if(end.tv_nsec>=1000000000L){end.tv_sec++;end.tv_nsec-=1000000000L;}
 check(!pthread_mutex_lock(&e->lock),"wait mutex");
 while(!e->signaled&&!result)result=timeout==UINT32_MAX?pthread_cond_wait(&e->cond,&e->lock):pthread_cond_timedwait(&e->cond,&e->lock,&end);
 if(e->signaled){e->signaled=0;result=0;}
 check(result==0||result==ETIMEDOUT,"actual condition wait");check(!pthread_mutex_unlock(&e->lock),"wait unlock");return result?258:0;
}
static int close_event(void *p,uintptr_t handle)
{
 backend *b=p;event *e=(event *)handle;
 if(atomic_exchange(&b->fail_close,0)){last_error=104;return 0;}
 check(!pthread_mutex_destroy(&e->lock),"destroy event mutex");check(!pthread_cond_destroy(&e->cond),"destroy event cond");free(e);b->closes++;b->live--;return 1;
}
static uint32_t error(void *p){(void)p;return last_error;}
typedef struct job {aw_context *context;void *address;uint32_t compare,error;atomic_int done;int result;} job;
static void *worker(void *p){job *j=p;j->result=aw_wait(j->context,j->address,&j->compare,4,5000,&j->error);atomic_store(&j->done,1);return 0;}
static void pending(aw_context *c,unsigned expected)
{
 unsigned i;struct timespec pause={0,1000000};
 for(i=0;i<3000;i++){if(aw_pending(c)==expected)return;nanosleep(&pause,0);}check(0,"bounded waiter registration");
}
static void wait_done(job *j)
{
 unsigned i;struct timespec pause={0,1000000};
 for(i=0;i<3000;i++){if(atomic_load(&j->done))return;nanosleep(&pause,0);}check(0,"bounded signaled completion");
}
static void api_controls(const char *path)
{
 FILE *f=fopen(path,"rb");long length;uint8_t *bytes;ac_target target;ac_route route;
 check(f!=0,"open preserved Chromium root");check(!fseek(f,0,SEEK_END),"root length seek");length=ftell(f);check(length>0,"root length");check(!fseek(f,0,SEEK_SET),"root rewind");bytes=malloc((size_t)length);check(bytes!=0,"root private buffer");check(fread(bytes,1,(size_t)length,f)==(size_t)length,"read original root");check(!fclose(f),"close original root");
 check(ac_init(&target,bytes,(size_t)length),"exact original SHA256 target accepted");
 check(ac_lookup(&target,"api-ms-win-core-synch-l1-2-0.dll","WaitOnAddress",0,&route)&&route.kind==AC_PRIVATE_ADDRESS,"exact synch wait contract");
 check(ac_lookup(&target,"API-MS-WIN-CORE-SYNCH-L1-2-0.DLL","WakeByAddressSingle",0,&route)&&route.kind==AC_PRIVATE_ADDRESS,"exact synch single contract");
 check(ac_lookup(&target,"API-MS-WIN-CORE-SYNCH-L1-2-0.DLL","WakeByAddressAll",0,&route)&&route.kind==AC_PRIVATE_ADDRESS,"exact synch all contract");
 check(ac_lookup(&target,"API-MS-WIN-POWER-BASE-L1-1-0.DLL","CallNtPowerInformation",0,&route)&&route.kind==AC_NATIVE_POWER,"exact native power contract");
 check(!ac_lookup(&target,"API-MS-WIN-CORE-SYNCH-L1-2-1.DLL","WaitOnAddress",0,&route)&&!route.kind,"different contract version rejected");
 check(!ac_lookup(&target,"C:\\API-MS-WIN-CORE-SYNCH-L1-2-0.DLL","WaitOnAddress",0,&route),"contract paths rejected");
 check(!ac_lookup(&target,"API-MS-WIN-CORE-SYNCH-L1-2-0.DLL","waitonaddress",0,&route),"symbol casing is exact");
 check(!ac_lookup(&target,"API-MS-WIN-CORE-SYNCH-L1-2-0.DLL","WaitOnAddress",1,&route),"ordinal alias rejected");
 bytes[64]^=1;check(!ac_init(&target,bytes,(size_t)length)&&!target.magic,"modified target rejected before routes");
 check(!ac_lookup(&target,"API-MS-WIN-CORE-SYNCH-L1-2-0.DLL","WaitOnAddress",0,&route),"failed identity has no candidate");
 free(bytes);
}
int main(int argc,char **argv)
{
 aw_context context;backend b={0};aw_ops ops={&b,enter,leave,create,signal,wait_event,close_event,error};
 uint64_t a=0,compare=0;uint32_t e;unsigned i;pthread_t threads[AW_CAPACITY];job jobs[AW_CAPACITY];
 check(argc==2,"one preserved Chromium input");check(!pthread_mutex_init(&b.lock,0),"backend mutex");check(aw_init(&context,&ops),"production core init");b.context=&context;b.address=&a;
 for(i=1;i<=8;i*=2){check(!aw_wait(&context,&a,&compare,i,0,&e)&&e==AW_TIMEOUT,"equal value zero timeout");compare=1;check(aw_wait(&context,&a,&compare,i,5000,&e)&&!b.opens,"different value no event");compare=0;}
 check(!aw_wait(&context,&a,&compare,3,1,&e)&&e==AW_INVALID_PARAMETER,"bad size rejected");
 check(!aw_wait(&context,0,&compare,4,1,&e)&&e==AW_INVALID_PARAMETER,"null address rejected");
 check(!aw_cleanup(&context,0,&e)&&e==AW_BUSY,"quiescence required");
 atomic_store(&b.fail_create,1);check(!aw_wait(&context,&a,&compare,4,1,&e)&&e==101&&!b.live,"actual create failure no handle");
 atomic_store(&b.fail_wait,1);check(!aw_wait(&context,&a,&compare,4,10,&e)&&e==103&&!b.live,"actual wait failure closes handle");
 check(!aw_wait(&context,&a,&compare,4,3,&e)&&e==AW_TIMEOUT&&!b.live,"actual monotonic timeout");
 atomic_store(&b.early_wake,1);check(aw_wait(&context,&a,&compare,4,100,&e)&&!b.live,"queue publication avoids lost wake before wait");
 atomic_store(&b.early_wake,1);atomic_store(&b.timeout_after_wake,1);
 check(aw_wait(&context,&a,&compare,4,100,&e)&&!b.live,"committed wake wins simultaneous backend timeout");
 atomic_store(&b.early_wake,1);atomic_store(&b.fail_wait,1);
 check(!aw_wait(&context,&a,&compare,4,100,&e)&&e==103&&!b.live,"actual wait failure remains failure despite committed wake");
 check(aw_wake(&context,&a,1,&e),"wake without registered waiters succeeds");
 check(!aw_wait(&context,&a,&compare,4,2,&e)&&e==AW_TIMEOUT,"old empty wake is not stored for future waiter");
 atomic_store(&b.fail_close,1);check(!aw_wait(&context,&a,&compare,4,1,&e)&&e==104&&b.live==1&&context.retained==1,"close failure retains real event");
 atomic_store(&b.fail_close,1);check(!aw_cleanup(&context,1,&e)&&e==104&&b.live==1,"cleanup failure retains ownership");
 check(aw_cleanup(&context,1,&e)&&!b.live&&!context.retained,"cleanup retry releases event");
 for(i=0;i<AW_CAPACITY;i++){
  jobs[i]=(job){.context=&context,.address=&a};check(!pthread_create(&threads[i],0,worker,&jobs[i]),"real waiter thread created");pending(&context,i+1);
 }
 check(!aw_cleanup(&context,1,&e)&&e==AW_BUSY,"live waiters cannot be cleaned");
 check(!aw_wait(&context,&a,&compare,4,1,&e)&&e==AW_NO_MEMORY,"full bounded queue fails explicitly");
 check(aw_wake(&context,&compare,1,&e)&&aw_pending(&context)==AW_CAPACITY,"different address wakes nobody");
 atomic_store(&b.fail_signal,1);check(!aw_wake(&context,&a,0,&e)&&e==102,"signal failure leaves waiter queued");
 check(aw_wake(&context,&a,0,&e),"single actual event wake");wait_done(&jobs[0]);
 check(jobs[0].result&&!atomic_load(&jobs[1].done),"first registered waiter alone wakes");pending(&context,AW_CAPACITY-1);
 check(aw_wake(&context,&a,1,&e),"all actual events wake");
 for(i=0;i<AW_CAPACITY;i++){check(!pthread_join(threads[i],0),"real waiter joined");check(jobs[i].result&&!jobs[i].error,"worker wait succeeded");}
 check(!aw_pending(&context)&&!b.live&&b.opens==b.closes,"all event ownership balanced");
 check(aw_cleanup(&context,1,&e),"quiescent final cleanup");check(!pthread_mutex_destroy(&b.lock),"backend mutex freed");
 api_controls(argv[1]);printf("PASS %u checks; real host event waits; native_executed=false; application_executed=false\n",atomic_load(&checks));return 0;
}
