/* SPDX-License-Identifier: GPL-2.0-only */
/* Runtime wire negotiation only: mocked calls grant no kernel authority. */
#include "../../win64/setup/native_runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint64_t ceiling,sim_bytes;static unsigned admitted,opens,closes,checks,failures;
#define CHECK(x) do{checks++;if(!(x)){failures++;fprintf(stderr,"FAIL %u %s\n",(unsigned)__LINE__,#x);}}while(0)
void shz_native_call_init(shz_native_call_v1 *r,uint32_t op)
{memset(r,0,sizeof *r);r->version=1;r->bytes=sizeof *r;r->operation=op;}
static void identity(shz_native_call_v1 *r,unsigned role)
{memset(&r->source,0,sizeof r->source);r->source.bytes=role?sim_bytes:1;r->source.id[0]=(uint8_t)(role+1);r->source.generation=role+1;r->source.sha256[0]=(uint8_t)(role+1);}
int32_t shz_native_call(shz_native_call_v1 *r)
{
 if(r->operation==SHZ_NATIVE_CAPS){r->producer_admission_available=admitted;r->max_source_bytes=ceiling;r->max_io_bytes=65536;return 0;}
 if(r->operation==SHZ_NATIVE_RELEASE_INFO){identity(r,r->index);return 0;}
 if(r->operation==SHZ_NATIVE_OPEN){unsigned role=opens++;identity(r,role);r->handle=role+1;return 0;}
 if(r->operation==SHZ_NATIVE_ADMIT){identity(r,r->index);return 0;}
 if(r->operation==SHZ_NATIVE_CLOSE){closes++;return 0;}
 return -1;
}
static void *alloc(void *ctx,size_t n){(void)ctx;return calloc(1,n);}
static void dealloc(void *ctx,void *p){(void)ctx;free(p);}
static int random_bytes(void *ctx,void *p,uint32_t n){(void)ctx;memset(p,1,n);return 0;}
static unsigned count(void *ctx){(void)ctx;return 0;}
static int info(void *ctx,unsigned i,plat_disk_t *out){(void)ctx;(void)i;(void)out;return -1;}
int main(void)
{
 plat_t base={0};shz_native_runtime value,zero={0};uint8_t digest[32];
 base.alloc=alloc;base.free=dealloc;base.random=random_bytes;base.disk_count=count;base.disk_info=info;
 admitted=1;sim_bytes=(257ull<<20);
 for(unsigned i=0;i<3;i++){
  ceiling=i==0?(256ull<<20):i==1?(320ull<<20):SHZ_NATIVE_SYS_SOURCE_PROTOCOL_MAX;
  memset(&value,0,sizeof value);opens=closes=0;
  CHECK(shz_native_runtime_init(&value,&base)==0);CHECK(value.max_source_bytes==ceiling);
  if(i==0){
   CHECK(shz_native_runtime_preview(&value,"C:\\HOST\\MANIFEST","C:\\HOST\\SIM",digest)!=0);
   CHECK(opens==0&&closes==0); /* release pins bounded before either OPEN */
  }else{
   CHECK(shz_native_runtime_preview(&value,"C:\\HOST\\MANIFEST","C:\\HOST\\SIM",digest)==0);
   CHECK(value.source[1].identity.bytes>(256ull<<20));
   CHECK(shz_native_runtime_preview_close(&value)==0);CHECK(opens==2&&closes==2);
  }
 }
 ceiling=(256ull<<20);memset(&value,0,sizeof value);opens=1;closes=0;
 CHECK(shz_native_runtime_init(&value,&base)==0);
 {void *handle=0;uint64_t length=0;
 CHECK(value.provider.base.file_open(value.provider.base.ctx,"C:\\HOST\\OVERSIZE",&handle,&length)!=0);
 CHECK(!handle&&length==0);CHECK(opens==2&&closes==1);CHECK(value.opened==0&&!value.source[0].live);
 }
 for(unsigned i=0;i<2;i++){
  ceiling=i?SHZ_NATIVE_SYS_SOURCE_PROTOCOL_MAX+1:0;memset(&value,0,sizeof value);opens=closes=0;
  CHECK(shz_native_runtime_init(&value,&base)==-1);CHECK(!memcmp(&value,&zero,sizeof zero));CHECK(!opens&&!closes);
 }
 for(unsigned state=2;state<=3;state++){
  admitted=state;ceiling=(256ull<<20);memset(&value,0,sizeof value);opens=closes=0;
  CHECK(shz_native_runtime_init(&value,&base)==-1);CHECK(!memcmp(&value,&zero,sizeof zero));CHECK(!opens&&!closes);
 }
 admitted=0;ceiling=SHZ_NATIVE_SYS_SOURCE_PROTOCOL_MAX;memset(&value,0,sizeof value);
 CHECK(shz_native_runtime_init(&value,&base)==-2);CHECK(!memcmp(&value,&zero,sizeof zero));CHECK(!opens&&!closes);
 printf("NATIVE_CAPACITY_NEGOTIATION checks=%u failures=%u wire440=1 syscall_mocked=1 large_source_allocated=0 producer_approved=0 VM_executed=0\n",checks,failures);
 return failures?1:0;
}
