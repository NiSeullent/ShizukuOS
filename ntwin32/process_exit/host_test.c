/* SPDX-License-Identifier: GPL-2.0-only */
#include "exit_registry.h"
#include "main_image.h"
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
typedef struct context {unsigned id,called;uint32_t reason;uintptr_t reserved;} context;
typedef struct backend {
 px_registry *registry;int reject;
 pthread_mutex_t mutex;pthread_cond_t condition;int pause,waiting,release;
} backend;
static unsigned sequence[PX_CALLBACKS],sequence_count;
static void callback(void *p,uint32_t reason,uintptr_t reserved)
{context *c=p;c->called++;c->reason=reason;c->reserved=reserved;if(sequence_count<PX_CALLBACKS)sequence[sequence_count++]=c->id;}
static uint32_t load(void *p,volatile uint32_t *a){(void)p;return __atomic_load_n(a,__ATOMIC_ACQUIRE);}
static uint32_t cas(void *p,volatile uint32_t *a,uint32_t before,uint32_t after)
{
 backend *b=p;
 if(b->pause&&a==&b->registry->current&&!(after&PX_CLOSED)){
  pthread_mutex_lock(&b->mutex);b->waiting=1;pthread_cond_signal(&b->condition);
  while(!b->release)pthread_cond_wait(&b->condition,&b->mutex);
  pthread_mutex_unlock(&b->mutex);
 }
 __atomic_compare_exchange_n(a,&before,after,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);return before;
}
static int validate(void *p,px_callback cb,void *c,size_t n){backend *b=p;return !b->reject&&cb==callback&&c&&n==sizeof(context);}
static void fresh(px_registry *r,backend *b)
{
 px_ops ops={b,load,cas,validate};memset(b,0,sizeof(*b));b->registry=r;
 CHECK(!pthread_mutex_init(&b->mutex,0));CHECK(!pthread_cond_init(&b->condition,0));CHECK(px_init(r,&ops));
 sequence_count=0;
}
static void dispose(backend *b){CHECK(!pthread_mutex_destroy(&b->mutex));CHECK(!pthread_cond_destroy(&b->condition));}
static void simple(void)
{
 px_registry *r=malloc(sizeof(*r));backend b;context c[9]={{0}};uint32_t token[9]={0},error,i,unchanged=999;
 CHECK(r);CHECK(!px_init(r,0));fresh(r,&b);
 CHECK(!px_register(0,callback,c,sizeof(c[0]),&unchanged,&error)&&error==PX_INVALID&&unchanged==999);
 CHECK(!px_register(r,0,c,sizeof(c[0]),&unchanged,&error)&&error==PX_INVALID);
 CHECK(!px_register(r,callback,0,sizeof(c[0]),&unchanged,&error)&&error==PX_INVALID);
 CHECK(!px_register(r,callback,c,0,&unchanged,&error)&&error==PX_INVALID);
 CHECK(!px_register(r,callback,c,sizeof(c[0]),0,&error)&&error==PX_INVALID);
 CHECK(!px_unregister(r,0,&error)&&error==PX_INVALID);CHECK(!px_unregister(r,777,&error)&&error==PX_NOT_FOUND);
 b.reject=1;CHECK(!px_register(r,callback,c,sizeof(c[0]),&unchanged,&error)&&error==PX_INVALID&&unchanged==999);b.reject=0;
 for(i=0;i<8;i++){c[i].id=i;CHECK(px_register(r,callback,&c[i],sizeof(c[i]),&token[i],&error)&&!error&&token[i]);CHECK(px_count(r)==i+1);}
 CHECK(!px_register(r,callback,&c[8],sizeof(c[8]),&unchanged,&error)&&error==PX_NO_MEMORY&&unchanged==999);
 CHECK(px_unregister(r,token[3],&error)&&!error&&px_count(r)==7);
 CHECK(!px_unregister(r,token[3],&error)&&error==PX_NOT_FOUND);
 CHECK(!px_terminate(r,1,1,&error)&&error==PX_INVALID);
 CHECK(!px_terminate(r,0,0,&error)&&error==PX_INVALID&&!sequence_count);
 CHECK(px_terminate(r,0,0x1234,&error)&&!error&&sequence_count==7);
 for(i=0;i<8;i++)CHECK(c[i].called==(i!=3)&&(!c[i].called||(c[i].reason==0&&c[i].reserved==0x1234)));
 CHECK(sequence[0]==7&&sequence[1]==6&&sequence[2]==5&&sequence[3]==4&&sequence[4]==2&&sequence[5]==1&&sequence[6]==0);
 CHECK(!px_terminate(r,0,1,&error)&&error==PX_BUSY&&sequence_count==7);
 CHECK(!px_register(r,callback,c,sizeof(c[0]),&unchanged,&error)&&error==PX_BUSY);
 CHECK(!px_unregister(r,token[0],&error)&&error==PX_BUSY);
 dispose(&b);free(r);
}
static void exhaustion(void)
{
 px_registry *r=malloc(sizeof(*r));backend b;context c={42,0,0,0};uint32_t token=0,error,i;
 CHECK(r);fresh(r,&b);
 for(i=0;i<63;i++){CHECK(px_register(r,callback,&c,sizeof(c),&token,&error));CHECK(px_unregister(r,token,&error));CHECK(!px_count(r));}
 CHECK(px_register(r,callback,&c,sizeof(c),&token,&error)&&px_count(r)==1);
 CHECK(!px_unregister(r,token,&error)&&error==PX_NO_MEMORY&&px_count(r)==1);
 CHECK(px_terminate(r,0,9,&error)&&c.called==1);dispose(&b);free(r);
}
typedef struct publisher {px_registry *r;context c;uint32_t token,error;int result;} publisher;
static void *publish(void *p){publisher *x=p;x->result=px_register(x->r,callback,&x->c,sizeof(x->c),&x->token,&x->error);return 0;}
static void stopped_publication(void)
{
 px_registry *r=malloc(sizeof(*r));backend b;context retained={1,0,0,0};uint32_t token,error;pthread_t thread;publisher worker;
 CHECK(r);fresh(r,&b);CHECK(px_register(r,callback,&retained,sizeof(retained),&token,&error));
 memset(&worker,0,sizeof(worker));worker.r=r;worker.c.id=2;worker.token=999;b.pause=1;
 CHECK(!pthread_create(&thread,0,publish,&worker));pthread_mutex_lock(&b.mutex);
 while(!b.waiting)pthread_cond_wait(&b.condition,&b.mutex);pthread_mutex_unlock(&b.mutex);
 CHECK(__atomic_load_n(&r->mutating,__ATOMIC_ACQUIRE)==1);
 CHECK(px_terminate(r,0,9,&error)&&retained.called==1&&!worker.c.called&&px_count(r)==1);
 pthread_mutex_lock(&b.mutex);b.release=1;pthread_cond_signal(&b.condition);pthread_mutex_unlock(&b.mutex);
 CHECK(!pthread_join(thread,0));CHECK(!worker.result&&worker.error==PX_BUSY&&worker.token==999&&!worker.c.called);
 CHECK(px_count(r)==1&&sequence_count==1);dispose(&b);free(r);
}
typedef struct racer {px_registry *r;context c;unsigned done,busy;} racer;
static void *race(void *p)
{
 racer *x=p;unsigned i;uint32_t token,error;
 for(i=0;i<10;i++){
  while(!px_register(x->r,callback,&x->c,sizeof(x->c),&token,&error)){if(error!=PX_BUSY)return (void *)1;x->busy++;sched_yield();}
  while(!px_unregister(x->r,token,&error)){if(error!=PX_BUSY)return (void *)2;x->busy++;sched_yield();}x->done++;
 }
 return 0;
}
static void concurrency(void)
{
 px_registry *r=malloc(sizeof(*r));backend b;pthread_t t[4];racer x[4];unsigned i;void *result;uint32_t error;
 CHECK(r);fresh(r,&b);memset(x,0,sizeof(x));
 for(i=0;i<4;i++){x[i].r=r;x[i].c.id=i;CHECK(!pthread_create(&t[i],0,race,&x[i]));}
 for(i=0;i<4;i++){CHECK(!pthread_join(t[i],&result));CHECK(!result&&x[i].done==10&&!x[i].c.called);}
 CHECK(!px_count(r));CHECK(px_terminate(r,0,1,&error)&&!sequence_count);dispose(&b);free(r);
}
static void w16(unsigned char *p,uint16_t x){p[0]=(unsigned char)x;p[1]=(unsigned char)(x>>8);}
static void w32(unsigned char *p,uint32_t x){unsigned i;for(i=0;i<4;i++)p[i]=(unsigned char)(x>>(i*8));}
static void image_fixture(unsigned char *p)
{
 memset(p,0,512);w16(p,0x5a4d);w32(p+60,64);w32(p+64,0x4550);w16(p+68,0x14c);w16(p+70,2);w16(p+84,96);w16(p+86,2);
 w16(p+88,0x10b);w32(p+144,0x3000);w32(p+148,512);
 w32(p+192,0x100);w32(p+196,0x1000);w32(p+220,0x60000000);
 w32(p+232,0x100);w32(p+236,0x2000);w32(p+260,0xc0000000);
}
static void image_controls(void)
{
 unsigned char p[512];px_image m;unsigned i;const uintptr_t base=0x10000000;
 image_fixture(p);CHECK(px_main_image(&m,p,sizeof(p),base));
 CHECK(px_main_callback(&m,base+0x1000,base+0x2000,256));
 CHECK(px_main_callback(&m,base+0x10ff,base+0x20ff,1));
 CHECK(!px_main_callback(&m,base+0x1100,base+0x2000,1));
 CHECK(!px_main_callback(&m,base+0x1000,base+0x20ff,2));
 CHECK(!px_main_callback(&m,base+0x1000,base+0x2000,0));
 CHECK(!px_main_callback(&m,base+0x1000,base+0x2000,SIZE_MAX));
 CHECK(!px_main_callback(&m,base+0x2000,base+0x1000,1));
 CHECK(!px_main_callback(&m,base+0x1000,base-1,1));
 for(i=0;i<512;i++)CHECK(!px_main_image(&m,p,i,base));
 CHECK(!px_main_image(&m,p,512,UINTPTR_MAX-4095));
 image_fixture(p);w16(p+86,0x2002);CHECK(!px_main_image(&m,p,512,base));
 image_fixture(p);w16(p+68,0x8664);CHECK(!px_main_image(&m,p,512,base));
 image_fixture(p);w16(p+88,0x20b);CHECK(!px_main_image(&m,p,512,base));
 image_fixture(p);w16(p+70,33);CHECK(!px_main_image(&m,p,512,base));
 image_fixture(p);w32(p+196,0x1f00);w32(p+192,0x200);CHECK(!px_main_image(&m,p,512,base));
 image_fixture(p);w32(p+196,0x100);CHECK(!px_main_image(&m,p,512,base));
 image_fixture(p);w32(p+232,0x2000);CHECK(!px_main_image(&m,p,512,base));
 image_fixture(p);w32(p+220,0xe0000000);CHECK(px_main_image(&m,p,512,base)&&!px_main_callback(&m,base+0x1000,base+0x2000,1));
 image_fixture(p);w32(p+260,0xe0000000);CHECK(px_main_image(&m,p,512,base)&&!px_main_callback(&m,base+0x1000,base+0x2000,1));
 image_fixture(p);w32(p+220,0x62000000);CHECK(px_main_image(&m,p,512,base)&&!px_main_callback(&m,base+0x1000,base+0x2000,1));
 image_fixture(p);w32(p+260,0xc2000000);CHECK(px_main_image(&m,p,512,base)&&!px_main_callback(&m,base+0x1000,base+0x2000,1));
}
int main(void)
{simple();exhaustion();stopped_publication();concurrency();image_controls();printf("PASS %u checks; immutable exit snapshots and real host concurrency; native_executed=false; application_executed=false\n",checks);return 0;}
