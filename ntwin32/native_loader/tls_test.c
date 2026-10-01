/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise the real runtime engine with fault injection, not Windows ABI proof.
 */
#include "tls_runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct test_state {
    void *slot[2][80];unsigned char used[80];
    unsigned current,reserves,allocations,publishes,frees,releases,live;
    unsigned fail_reserve,fail_allocate,fail_publish;
} test_state;
static unsigned checks;
#define CHECK(condition) do{checks++;if(!(condition)){fprintf(stderr,"line %u: %s\n",__LINE__,#condition);exit(1);}}while(0)
static uint32_t reserve(void *context)
{
    test_state *state=context;unsigned i;state->reserves++;
    if(state->reserves==state->fail_reserve)return NTW_TLS_NO_SLOT;
    for(i=0;i<80;i++)if(!state->used[i]){state->used[i]=1;state->slot[0][i]=state->slot[1][i]=NULL;return i;}
    return NTW_TLS_NO_SLOT;
}
static int release(void *context,uint32_t index)
{test_state *state=context;CHECK(index<80&&state->used[index]);CHECK(!state->slot[0][index]&&!state->slot[1][index]);state->used[index]=0;state->releases++;return 1;}
static void *allocate(void *context,uint32_t bytes)
{test_state *state=context;void *p;state->allocations++;if(state->allocations==state->fail_allocate)return NULL;p=malloc(bytes);CHECK(p!=NULL);state->live++;memset(p,0xaa,bytes);return p;}
static void deallocate(void *context,void *memory)
{test_state *state=context;CHECK(memory!=NULL&&state->live>0);state->live--;state->frees++;free(memory);}
static uint32_t thread_id(void *context)
{test_state *state=context;return state->current+1;}
static int read_slot(void *context,uint32_t index,void **value)
{test_state *state=context;CHECK(index<80&&state->used[index]);*value=state->slot[state->current][index];return 1;}
static int publish(void *context,uint32_t index,void *value)
{test_state *state=context;CHECK(index<80&&state->used[index]);state->publishes++;if(state->publishes==state->fail_publish)return 0;state->slot[state->current][index]=value;return 1;}
static ntw_tls_ops operations(test_state *state)
{ntw_tls_ops ops={state,reserve,release,allocate,deallocate,thread_id,read_slot,publish};return ops;}
static void reset(test_state *state)
{memset(state,0,sizeof(*state));state->used[0]=state->used[3]=1;state->slot[0][0]=(void *)1;state->slot[1][0]=(void *)2;}
static void guards(test_state *state)
{CHECK(state->used[0]&&state->used[3]);CHECK(state->slot[0][0]==(void *)1&&state->slot[1][0]==(void *)2);}
int main(void)
{
    test_state state;ntw_tls_plan plan={0};ntw_tls_thread first={0},second={0};
    unsigned char initial[5]={1,2,3,4,5};uint32_t index[3]={91,92,93};const char *error=NULL;
    ntw_tls_spec specs[3]={{initial,5,11,64,&index[0]},{NULL,0,32,16,&index[1]},{NULL,0,0,0,&index[2]}};
    ntw_tls_ops ops;unsigned i,failure;
    reset(&state);ops=operations(&state);
    CHECK(ntw_tls_prepare(&plan,specs,3,&ops,&error));CHECK(index[0]==1&&index[1]==2&&index[2]==4);
    CHECK(!ntw_tls_prepare(&plan,specs,3,&ops,&error));
    CHECK(ntw_tls_attach(&plan,&first,&error));CHECK(!ntw_tls_attach(&plan,&first,&error));
    CHECK(plan.live_threads==1&&!ntw_tls_dispose(&plan,&error));
    CHECK((uintptr_t)first.data[0]%64==0&&!memcmp(first.data[0],initial,5));
    for(i=5;i<16;i++)CHECK(((unsigned char *)first.data[0])[i]==0);
    for(i=0;i<32;i++)CHECK(((unsigned char *)first.data[1])[i]==0);
    ((unsigned char *)first.data[0])[0]=44;initial[0]=99;
    state.current=1;CHECK(ntw_tls_attach(&plan,&second,&error));
    CHECK(first.data[0]!=second.data[0]&&((unsigned char *)second.data[0])[0]==1);
    CHECK(!ntw_tls_detach(&first,&error));CHECK(ntw_tls_detach(&second,&error));
    state.current=0;CHECK(((unsigned char *)first.data[0])[0]==44);CHECK(ntw_tls_detach(&first,&error));
    CHECK(!ntw_tls_detach(&first,&error));CHECK(ntw_tls_dispose(&plan,&error));
    CHECK(index[0]==91&&index[1]==92&&index[2]==93&&state.live==0);guards(&state);

    /* Every template-copy and slot-reservation failure is atomic. */
    for(failure=1;failure<=3;failure++){
        reset(&state);ops=operations(&state);state.fail_reserve=failure;
        CHECK(!ntw_tls_prepare(&plan,specs,3,&ops,&error));
        CHECK(plan.count==0&&!plan.ready&&state.live==0&&index[0]==91);guards(&state);
    }
    reset(&state);ops=operations(&state);state.fail_allocate=1;
    CHECK(!ntw_tls_prepare(&plan,specs,3,&ops,&error));CHECK(state.live==0&&plan.count==0);guards(&state);

    /* Fail every per-thread allocation/publication; earlier slots are cleared. */
    for(failure=1;failure<=6;failure++){
        reset(&state);ops=operations(&state);CHECK(ntw_tls_prepare(&plan,specs,3,&ops,&error));
        if(failure<=3)state.fail_allocate=state.allocations+failure;
        else state.fail_publish=failure-3;
        CHECK(!ntw_tls_attach(&plan,&first,&error));CHECK(!first.active&&plan.live_threads==0);
        CHECK(ntw_tls_dispose(&plan,&error));CHECK(state.live==0&&index[0]==91);guards(&state);
    }
    /* Clear failure retains memory and ownership until same-thread retry. */
    reset(&state);ops=operations(&state);CHECK(ntw_tls_prepare(&plan,specs,3,&ops,&error));
    CHECK(ntw_tls_attach(&plan,&first,&error));state.fail_publish=state.publishes+2;
    CHECK(!ntw_tls_detach(&first,&error));CHECK(first.active&&first.published==2&&plan.live_threads==1);
    CHECK(!ntw_tls_dispose(&plan,&error));CHECK(ntw_tls_detach(&first,&error));
    CHECK(ntw_tls_dispose(&plan,&error)&&state.live==0);guards(&state);
    /* Reject an occupied reserved slot; never overwrite another thread value. */
    reset(&state);ops=operations(&state);CHECK(ntw_tls_prepare(&plan,specs,3,&ops,&error));
    state.slot[0][index[0]]=(void *)9;CHECK(!ntw_tls_attach(&plan,&first,&error));
    CHECK(state.slot[0][index[0]]==(void *)9&&!first.active);state.slot[0][index[0]]=NULL;
    CHECK(ntw_tls_dispose(&plan,&error));guards(&state);
    /* Strict size, pointer and alignment validation occurs before side effects. */
    for(failure=0;failure<6;failure++){
        ntw_tls_spec bad=specs[0];reset(&state);ops=operations(&state);
        if(failure==0)bad.alignment=3;
        if(failure==1)bad.alignment=16384;
        if(failure==2)bad.initial=NULL;
        if(failure==3)bad.index_address=NULL;
        if(failure==4)bad.initialized_bytes=UINT32_MAX;
        if(failure==5)bad.zero_bytes=UINT32_MAX;
        CHECK(!ntw_tls_prepare(&plan,&bad,1,&ops,&error));CHECK(state.allocations==0&&state.reserves==0);
    }
    specs[1].index_address=&index[0];CHECK(!ntw_tls_prepare(&plan,specs,2,&ops,&error));
    printf("TLS_RUNTIME_HOST_CHECKS=%u\nNATIVE_WIN98_ABI_VERIFIED=0\n",checks);
    return 0;
}
