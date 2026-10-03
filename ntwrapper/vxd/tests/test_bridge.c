/* SPDX-License-Identifier: GPL-2.0-only -- original fault-injection tests. */
#include "../bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks, step, failure, locked, unlocks, writes, protected_now;
static unsigned sticky_unlock, hv_calls, clock_calls, signature = 1, nested;
static int32_t abi_status, clock_status;
static uint32_t hv_version = (SHZ_ABI_MAJOR << 16) | SHZ_ABI_MINOR;
static uint64_t clock_value = UINT64_C(0x12345678ffffffff);
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
{ CHECK(!protected_now && count==2 && flags==NTWV_MAP_GLOBAL && locked>0 && unlocks<4);unsigned b=page==0xc1000?0u:1u;CHECK(held_alias[b]);last_unlocked[unlocks++]=page;if(fail() || sticky_unlock)return 0;--locked;held_alias[b]=0;return 1; }
static uint32_t ptes(uint32_t page,uint32_t count,uint32_t *out,uint32_t flags)
{ unsigned i; CHECK(protected_now && count==2 && flags==0);if(fail())return 0;for(i=0;i<count;++i)out[i]=((page==0x500||page==0xc1000)?0x00100000u:0x00200000u)+i*4096u+permission;
  if(page>=0xc0000) { out[0]^=physical_xor; }
  return 1; }
static void write_alias(uint32_t address,const void *source,uint32_t bytes)
{ uint32_t base=address&0xffff0000u;CHECK(protected_now && locked==2 && (base==0xc1000000||base==0xc2000000));CHECK((address&0xffff)+bytes<=8192);++writes;memcpy(buffers[base==0xc1000000?0:1]+(address&0xffff),source,bytes); }
static void read_alias(void *destination,uint32_t address,uint32_t bytes)
{ (void)destination;(void)address;(void)bytes;CHECK(0); /* the query path never reads application memory */ }
static const struct ntwv_pages ops={check_range,lock_range,unlock_range,ptes,enter,leave,write_alias,read_alias};
static void reset(void) { CHECK(!locked);step=failure=unlocks=writes=protected_now=0;permission=7;physical_xor=0;memset(buffers,0xa5,sizeof(buffers)); }
static int hv_present(void) { return (int)signature; }
static int32_t clock_sample(void *opaque, uint64_t *value)
{ CHECK(!opaque && !protected_now && locked == 2); ++clock_calls; *value=clock_value; return clock_status; }
static int32_t hcall(uint32_t op,uint32_t a,uint32_t b,uint32_t *low,uint32_t *high);
static const struct ntwv_hv hv={hv_present,hcall,0,0};
static struct ntwv_dioc clock_request;
static int32_t hcall(uint32_t op,uint32_t a,uint32_t b,uint32_t *low,uint32_t *high)
{
    uint64_t lo=0,hi=0; int32_t result;
    CHECK(!protected_now); ++hv_calls;
    if(op==SHZ_HC_ABI_VERSION){CHECK(!a && !b && low && !high);*low=hv_version;return abi_status;}
    CHECK(op==SHZ_HC_CLOCK_SPLIT && a==SHZ_CLOCK_VERSION && !b && low && high);
    if(nested){CHECK(ntwv_dioc_ex(&clock_request,&ops,&hv)==NTWV_ERROR_BUSY);CHECK(!ntwv_shutdown());}
    result=shz_clock_split(a,b,clock_sample,0,&lo,&hi);
    if(!result){*low=(uint32_t)lo;*high=(uint32_t)hi;}return result;
}
static void clock_tests(struct ntwv_dioc *request)
{
    shz_clock_reply_t reply; struct ntwv_hv missing;
    uint32_t returned; unsigned total,which;
    request->code=NTWV_IOCTL_CLOCK; clock_request=*request;
    reset();hv_calls=clock_calls=0;nested=1;
    CHECK(ntwv_dioc_ex(request,&ops,&hv)==0);total=step;nested=0;
    memcpy(&reply,buffers[0]+0xff0,sizeof(reply));memcpy(&returned,buffers[1]+0xffe,4);
    CHECK(hv_calls==2 && clock_calls==1 && returned==32 && reply.size==32 &&
          reply.magic==SHZ_CLOCK_MAGIC && reply.version==1 && !reply.reserved &&
          reply.counter==clock_value && reply.frequency==SHZ_CLOCK_FREQUENCY && !locked);
    clock_value++; reset();CHECK(ntwv_dioc_ex(request,&ops,&hv)==0);
    memcpy(&reply,buffers[0]+0xff0,sizeof(reply));CHECK(reply.counter==UINT64_C(0x1234567900000000));
    for(which=1;which<=total;++which){
        reset();failure=which;CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_NOACCESS);
        CHECK(!protected_now);if(which<=8)CHECK(!writes);
        if(locked){failure=0;step=unlocks=writes=0;CHECK(ntwv_dioc_ex(request,&ops,&hv)==0 && !locked);}
    }
    reset();hv_calls=clock_calls=0;signature=0;
    CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_NOT_SUPPORTED && !hv_calls && !step && !writes);signature=1;
    CHECK(ntwv_dioc_ex(request,&ops,0)==NTWV_ERROR_NOT_SUPPORTED);
    missing=hv;missing.hypervisor_present=0;CHECK(ntwv_dioc_ex(request,&ops,&missing)==NTWV_ERROR_NOT_SUPPORTED);
    missing=hv;missing.hcall=0;CHECK(ntwv_dioc_ex(request,&ops,&missing)==NTWV_ERROR_NOT_SUPPORTED);
    abi_status=SHZ_E_DENIED;CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_GEN_FAILURE && !clock_calls);abi_status=0;
    hv_version=2u<<16;CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_REVISION_MISMATCH && !clock_calls);hv_version=(SHZ_ABI_MAJOR<<16)|SHZ_ABI_MINOR;
    clock_status=SHZ_E_UNSUPPORTED;CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_NOT_SUPPORTED && !writes && !locked);
    clock_status=SHZ_E_DENIED;reset();CHECK(ntwv_dioc_ex(request,&ops,&hv)==5 && !writes && !locked);
    clock_status=SHZ_E_INVALID;reset();CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_GEN_FAILURE && !writes && !locked);clock_status=0;
    clock_value=UINT64_MAX;reset();CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_GEN_FAILURE && !writes && !locked);clock_value=5000000000ULL;
    reset();permission=5;CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_NOACCESS && !writes);
    reset();physical_xor=0x1000;CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_NOACCESS && !writes);
    reset();sticky_unlock=1;CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_NOACCESS && locked==2 && writes==2);
    step=unlocks=0;CHECK(!ntwv_shutdown() && locked==2);
    step=unlocks=0;hv_calls=0;CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_NOACCESS && !hv_calls && locked==2);
    sticky_unlock=0;step=unlocks=0;CHECK(ntwv_dioc_ex(request,&ops,&hv)==0 && !locked);
    reset();hv_calls=0;request->input=1;CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_INVALID_PARAMETER);request->input=0;
    request->input_bytes=1;CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_INVALID_PARAMETER);request->input_bytes=0;
    request->overlapped=1;CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_INVALID_PARAMETER);request->overlapped=0;
    request->output_bytes=31;CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_INSUFFICIENT_BUFFER);request->output_bytes=32;
    request->returned=request->output+4;CHECK(ntwv_dioc_ex(request,&ops,&hv)==NTWV_ERROR_INVALID_PARAMETER);request->returned=0x00600ffe;
    CHECK(!hv_calls && !step && !writes);
}
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
    clock_tests(&request);
    CHECK(ntwv_dioc(0,&ops)==NTWV_ERROR_INVALID_PARAMETER);
    CHECK(ntwv_shutdown());CHECK(!ntwv_shutdown());
    CHECK(ntwv_dioc(&request,&ops)==NTWV_ERROR_NOT_READY);
    CHECK(ntwv_initialize(&locks));CHECK(ntwv_shutdown());
    printf("PASS: VxD bridge %u assertions; failed aliases retained until real release\n",checks);
    return 0;
}
