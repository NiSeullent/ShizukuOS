/* SPDX-License-Identifier: GPL-2.0-only -- original fault-injection tests. */
#include "../bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks, step, failure, locked, unlocks, writes, protected_now;
static uint32_t held_alias[2], last_unlocked[4], permission = 7, physical_xor;
static unsigned char buffers[2][8192];
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"line %u: %s\n",(unsigned)__LINE__,#x); exit(1); } } while(0)
static int fail(void) { return ++step == failure; }
static uintptr_t enter(void *p) { (void)p; CHECK(!protected_now); protected_now=1; return 0x202; }
static void leave(void *p,uintptr_t saved) { (void)p; CHECK(protected_now && saved==0x202); protected_now=0; }
static uint32_t check_range(uint32_t page,uint32_t count,uint32_t flags)
{ CHECK(!protected_now && flags==0 && count==2 && (page==0x500 || page==0x600)); return fail()?count-1:count; }
static uint32_t lock_range(uint32_t page,uint32_t count,uint32_t flags)
{ CHECK(!protected_now && count==2 && flags==NTWV_MAP_GLOBAL); if(fail()) return 0; unsigned b=page==0x500?0u:1u;CHECK(!held_alias[b]);held_alias[b]=1;++locked; return page==0x500?0xc1000000:0xc2000000; }
static uint32_t unlock_range(uint32_t page,uint32_t count,uint32_t flags)
{ CHECK(!protected_now && count==2 && flags==NTWV_MAP_GLOBAL && locked>0 && unlocks<4);unsigned b=page==0xc1000?0u:1u;CHECK(held_alias[b]);last_unlocked[unlocks++]=page;if(fail())return 0;--locked;held_alias[b]=0;return 1; }
static uint32_t ptes(uint32_t page,uint32_t count,uint32_t *out,uint32_t flags)
{ unsigned i; CHECK(protected_now && count==2 && flags==0);if(fail())return 0;for(i=0;i<count;++i)out[i]=((page==0x500||page==0xc1000)?0x00100000u:0x00200000u)+i*4096u+permission;
  if(page>=0xc0000)out[0]^=physical_xor;return 1; }
static void write_alias(uint32_t address,const void *source,uint32_t bytes)
{ uint32_t base=address&0xffff0000u;CHECK(protected_now && locked==2 && (base==0xc1000000||base==0xc2000000));CHECK((address&0xffff)+bytes<=8192);++writes;memcpy(buffers[base==0xc1000000?0:1]+(address&0xffff),source,bytes); }
static void read_alias(void *destination,uint32_t address,uint32_t bytes)
{ (void)destination;(void)address;(void)bytes;CHECK(0); /* the query path never reads application memory */ }
static const struct ntwv_pages ops={check_range,lock_range,unlock_range,ptes,enter,leave,write_alias,read_alias};
static void reset(void) { CHECK(!locked);step=failure=unlocks=writes=protected_now=0;permission=7;physical_xor=0;memset(buffers,0xa5,sizeof(buffers)); }
int main(void)
{
    const struct ntw_lock_ops locks={enter,leave,0};
    struct ntwv_dioc request={0};
    struct ntwv_query reply;
    unsigned total,which;
    uint32_t bytes;
    CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_NOT_READY);
    CHECK(ntwv_initialize(&locks));CHECK(!ntwv_initialize(&locks));
    CHECK(ntwv_dioc(&request,&ops)==0);
    request.code=UINT32_MAX;CHECK(ntwv_dioc(&request,&ops)==1);
    request.code=5;CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_NOT_SUPPORTED);
    request.code=NTWV_IOCTL_QUERY;request.output=0x00500ff0;request.output_bytes=32;request.returned=0x00600ffe;
    reset();CHECK(ntwv_dioc(&request,&ops)==0);total=step;
    CHECK(!locked && unlocks==2 && writes==2 && !protected_now);
    CHECK(last_unlocked[0]==0xc2000 && last_unlocked[1]==0xc1000);
    memcpy(&reply,buffers[0]+0xff0,32);memcpy(&bytes,buffers[1]+0xffe,4);
    CHECK(bytes==32 && reply.magic==NTWV_QUERY_MAGIC && reply.abi==1 && reply.core_abi==NTW_ABI_VERSION && reply.max_objects==NTW_MAX_OBJECTS && reply.initialized==1 && reply.selftest==1 && reply.features==1);
    for(which=1;which<=total;++which) {
        reset();failure=which;CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_NOACCESS);
        CHECK(!protected_now);
        if(which<=8)CHECK(writes==0);
        if(unlocks==2)CHECK(last_unlocked[0]==0xc2000 && last_unlocked[1]==0xc1000);
        if(locked){failure=0;step=unlocks=writes=0;CHECK(ntwv_dioc(&request,&ops)==0 && !locked);}
    }
    reset();permission=5;CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_NOACCESS && !writes && !locked);
    reset();permission=3;CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_NOACCESS && !writes && !locked);
    reset();permission=6;CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_NOACCESS && !writes && !locked);
    reset();physical_xor=0x1000;CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_NOACCESS && !writes && !locked);
    reset();request.output_bytes=31;CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_INSUFFICIENT_BUFFER && !step);request.output_bytes=32;
    request.input=1;CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_INVALID_PARAMETER);request.input=0;
    request.input_bytes=1;CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_INVALID_PARAMETER);request.input_bytes=0;
    request.overlapped=1;CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_INVALID_PARAMETER);request.overlapped=0;
    request.returned=request.output+4;CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_INVALID_PARAMETER);request.returned=0x00600ffe;
    request.output=0;CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_INVALID_PARAMETER);
    request.output=0xc0000000;CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_INVALID_PARAMETER);
    request.output=0x7ffffff0;CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_INVALID_PARAMETER);
    request.output=0xfffffff0;CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_INVALID_PARAMETER);
    request.output=0x00500ff0;CHECK(ntwv_dioc(&request,0)==NTWV_ERROR_NOT_SUPPORTED);
    CHECK(ntwv_dioc(0,&ops)==NTWV_ERROR_INVALID_PARAMETER);
    CHECK(ntwv_shutdown());CHECK(!ntwv_shutdown());
    CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_NOT_READY);
    CHECK(ntwv_initialize(&locks));CHECK(ntwv_shutdown());
    printf("PASS: VxD bridge %u assertions; failed aliases retained until real release\n",checks);
    return 0;
}
