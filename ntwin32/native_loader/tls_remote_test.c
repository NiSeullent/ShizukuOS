/* SPDX-License-Identifier: GPL-2.0-only
 * Actual engine ownership and atomic publication fault controls, not ABI proof.
 */
#include "tls_remote.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct state {
    void *slots[3][80];unsigned char used[80];unsigned current,live,allocs,frees;
} state;
typedef struct target {
    state *host;unsigned index,admitted,calls,fail1,fail2;
} target;
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"line %u: %s\n",__LINE__,#x);exit(1);}}while(0)
static uint32_t reserve(void *c)
{state *s=c;unsigned i,j;for(i=0;i<80;i++)if(!s->used[i]){s->used[i]=1;for(j=0;j<3;j++)s->slots[j][i]=NULL;return i;}return NTW_TLS_NO_SLOT;}
static int release(void *c,uint32_t i)
{state *s=c;unsigned j;CHECK(i<80&&s->used[i]);for(j=0;j<3;j++)CHECK(s->slots[j][i]==NULL);s->used[i]=0;return 1;}
static void *allocate(void *c,uint32_t n)
{state *s=c;void *p=malloc(n);CHECK(p!=NULL);s->live++;s->allocs++;return p;}
static void deallocate(void *c,void *p)
{state *s=c;CHECK(p&&s->live);s->live--;s->frees++;free(p);}
static uint32_t current(void *c)
{state *s=c;return 100+s->current;}
static int read_current(void *c,uint32_t i,void **p)
{state *s=c;CHECK(i<80&&s->used[i]);*p=s->slots[s->current][i];return 1;}
static int publish_current(void *c,uint32_t i,void *p)
{state *s=c;CHECK(i<80&&s->used[i]);s->slots[s->current][i]=p;return 1;}
static int read_target(void *c,uint32_t i,void **p)
{target *t=c;if(!t->admitted)return 0;CHECK(i<80&&t->host->used[i]);*p=t->host->slots[t->index][i];return 1;}
static int replace(void *c,uint32_t i,void *expected,void *replacement)
{
    target *t=c;void **slot;if(!t->admitted)return 0;CHECK(i<80&&t->host->used[i]);
    t->calls++;if(t->calls==t->fail1||t->calls==t->fail2)return 0;
    slot=&t->host->slots[t->index][i];if(*slot!=expected)return 0;*slot=replacement;return 1;
}
static ntw_tls_ops ops(state *s)
{ntw_tls_ops o={s,reserve,release,allocate,deallocate,current,read_current,publish_current};return o;}
static ntw_tls_remote_io io(target *t)
{ntw_tls_remote_io o={t,100+t->index,read_target,replace};return o;}
static void preserved(state *s,ntw_tls_plan *old,ntw_tls_thread *a,ntw_tls_thread *b)
{
    CHECK(old->live_threads==2&&a->active&&b->active);
    CHECK(s->slots[0][old->module[0].slot]==a->data[0]&&s->slots[1][old->module[0].slot]==b->data[0]);
    CHECK(*(unsigned *)a->data[0]==0xa0&&*(unsigned *)b->data[0]==0xb0);
    CHECK(s->slots[0][0]==(void *)1&&s->slots[1][0]==(void *)2&&s->slots[2][0]==(void *)3);
}
int main(void)
{
    state s={0};target one={&s,1,1,0,0,0},two={&s,2,1,0,0,0};
    ntw_tls_ops o=ops(&s);ntw_tls_remote_io r1=io(&one),r2=io(&two);
    ntw_tls_plan old={0},extension={0};ntw_tls_thread main_thread={0},worker={0},remote1={0},remote2={0};
    unsigned template=0x1234abcd,index=71,indices[2]={91,92},i,before;
    ntw_tls_spec original={&template,4,12,16,&index};
    ntw_tls_spec extra[2]={{&template,4,28,64,&indices[0]},{NULL,0,8,16,&indices[1]}};
    const char *error=NULL;s.used[0]=1;s.slots[0][0]=(void *)1;s.slots[1][0]=(void *)2;s.slots[2][0]=(void *)3;
    CHECK(ntw_tls_prepare(&old,&original,1,&o,&error));CHECK(ntw_tls_attach(&old,&main_thread,&error));
    *(unsigned *)main_thread.data[0]=0xa0;s.current=1;CHECK(ntw_tls_attach(&old,&worker,&error));*(unsigned *)worker.data[0]=0xb0;s.current=0;
    CHECK(ntw_tls_prepare(&extension,extra,2,&o,&error));
    CHECK(ntw_tls_remote_attach(&extension,&remote1,&r1,&error));
    CHECK(remote1.plan==&extension&&remote1.owner==101&&extension.live_threads==1);
    CHECK(*(unsigned *)remote1.data[0]==template&&(uintptr_t)remote1.data[0]%64==0);
    for(i=4;i<32;i++)CHECK(((unsigned char *)remote1.data[0])[i]==0);
    CHECK(!s.slots[0][indices[0]]&&s.slots[1][indices[0]]==remote1.data[0]);
    CHECK(ntw_tls_remote_attach(&extension,&remote2,&r2,&error));
    CHECK(remote1.data[0]!=remote2.data[0]&&extension.live_threads==2);
    CHECK(!ntw_tls_remote_attach(&old,&remote1,&r1,&error));CHECK(remote1.plan==&extension&&old.live_threads==2);
    CHECK(!ntw_tls_remote_detach(&remote1,&r2,&error));CHECK(remote1.plan==&extension&&extension.live_threads==2);
    preserved(&s,&old,&main_thread,&worker);
    /* An admitted target can consume its extension and detach on its own ABI. */
    s.current=1;CHECK(*(unsigned *)s.slots[1][indices[0]]==template);CHECK(ntw_tls_detach(&remote1,&error));s.current=0;
    CHECK(ntw_tls_remote_detach(&remote2,&r2,&error));CHECK(extension.live_threads==0);
    CHECK(ntw_tls_dispose(&extension,&error));CHECK(indices[0]==91&&indices[1]==92);preserved(&s,&old,&main_thread,&worker);
    /* Failed atomic publication leaves all prior modules and slots untouched. */
    for(i=1;i<=2;i++){
        one.calls=0;one.fail1=i;one.fail2=0;
        CHECK(ntw_tls_prepare(&extension,extra,2,&o,&error));
        CHECK(!ntw_tls_remote_attach(&extension,&remote1,&r1,&error));
        CHECK(!remote1.active&&extension.live_threads==0&&!s.slots[1][indices[0]]&&!s.slots[1][indices[1]]);
        CHECK(ntw_tls_dispose(&extension,&error));preserved(&s,&old,&main_thread,&worker);
    }
    /* Publication plus rollback clear failure retains live storage for retry. */
    one.calls=0;one.fail1=2;one.fail2=3;
    CHECK(ntw_tls_prepare(&extension,extra,2,&o,&error));
    CHECK(!ntw_tls_remote_attach(&extension,&remote1,&r1,&error));
    CHECK(remote1.active&&remote1.plan==&extension&&remote1.published==1&&extension.live_threads==1);
    CHECK(s.slots[1][indices[0]]==remote1.data[0]);CHECK(!ntw_tls_dispose(&extension,&error));
    one.fail1=one.fail2=0;CHECK(ntw_tls_remote_detach(&remote1,&r1,&error));CHECK(ntw_tls_dispose(&extension,&error));
    /* Clear/revocation failures never release a still-published block. */
    CHECK(ntw_tls_prepare(&extension,extra,2,&o,&error));CHECK(ntw_tls_remote_attach(&extension,&remote1,&r1,&error));
    before=s.frees;one.fail1=one.calls+1;
    CHECK(!ntw_tls_remote_detach(&remote1,&r1,&error));CHECK(s.frees==before&&remote1.active&&remote1.plan==&extension);
    one.fail1=0;one.admitted=0;CHECK(!ntw_tls_remote_detach(&remote1,&r1,&error));
    CHECK(s.frees==before&&remote1.active&&!ntw_tls_dispose(&extension,&error));
    one.admitted=1;CHECK(ntw_tls_remote_detach(&remote1,&r1,&error));CHECK(ntw_tls_dispose(&extension,&error));
    /* Occupied and revoked target slots are rejected before allocations. */
    CHECK(ntw_tls_prepare(&extension,extra,2,&o,&error));before=s.allocs;
    s.slots[1][indices[0]]=(void *)9;CHECK(!ntw_tls_remote_attach(&extension,&remote1,&r1,&error));
    CHECK(s.allocs==before&&s.slots[1][indices[0]]==(void *)9);s.slots[1][indices[0]]=NULL;
    one.admitted=0;CHECK(!ntw_tls_remote_attach(&extension,&remote1,&r1,&error));CHECK(s.allocs==before);one.admitted=1;
    CHECK(ntw_tls_dispose(&extension,&error));preserved(&s,&old,&main_thread,&worker);
    s.current=1;CHECK(ntw_tls_detach(&worker,&error));s.current=0;CHECK(ntw_tls_detach(&main_thread,&error));
    CHECK(ntw_tls_dispose(&old,&error));CHECK(index==71&&s.live==0);
    printf("TLS_REMOTE_HOST_CHECKS=%u\nNATIVE_WIN98_REMOTE_ABI_VERIFIED=0\n",checks);return 0;
}
