/* SPDX-License-Identifier: GPL-2.0-only
 * Real fixed-page memory regressions through the unchanged numeric C ABI. */
#include "m98_wasm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wasm_memory_fixtures.h"
static unsigned checks;static uint32_t store,active_instance;static unsigned callbacks;
static unsigned char page_bytes[65536];
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL %u line %u: %s\n",checks,__LINE__,#x);exit(1);}}while(0)
extern void m98_wasm_test_fail_allocation_after(uint32_t);
extern uint32_t m98_wasm_test_accounted_bytes(void);
static uint32_t load(const unsigned char *p,unsigned n){uint32_t m=0;CHECK(m98_wasm_load(store,p,n,&m)==0&&m!=0);return m;}
static uint32_t instantiate(uint32_t m){uint32_t i=0;CHECK(m98_wasm_instantiate(store,m,&i)==0&&i!=0);return i;}
static void close_pair(uint32_t m,uint32_t i){CHECK(m98_wasm_instance_close(store,i)==0);CHECK(m98_wasm_unload(store,m)==0);}
static uint32_t pages(uint32_t i,uint32_t index){uint32_t n=UINT32_MAX;CHECK(m98_wasm_memory_size(store,i,index,&n)==0);return n;}
static int32_t grow(uint32_t i,uint32_t index,uint32_t delta){int32_t n=INT32_MIN;CHECK(m98_wasm_memory_grow(store,i,index,delta,&n)==0);return n;}
static void zero_page(uint32_t i,uint32_t offset){unsigned j,nonzero=0;memset(page_bytes,0xff,sizeof(page_bytes));CHECK(m98_wasm_memory_read(store,i,0,offset,page_bytes,sizeof(page_bytes))==0);for(j=0;j<sizeof(page_bytes);j++)nonzero|=page_bytes[j];CHECK(nonzero==0);}
static void exact_pages(const unsigned char *bytes,unsigned length,unsigned initial,unsigned maximum){
 uint32_t m=load(bytes,length),i=instantiate(m),n;unsigned char a=0xab,b=0;
 CHECK(pages(i,0)==initial);CHECK(grow(i,0,0)==(int32_t)initial);
 for(n=0;n<initial;n++)zero_page(i,n*65536);
 CHECK(m98_wasm_memory_write(store,i,0,initial*65536-1,&a,1)==0);
 CHECK(m98_wasm_memory_read(store,i,0,initial*65536-1,&b,1)==0&&b==a);
 CHECK(m98_wasm_memory_read(store,i,0,initial*65536,&b,1)==M98_WASM_RANGE);
 CHECK(m98_wasm_memory_read(store,i,0,initial*65536,NULL,0)==0);
 CHECK(m98_wasm_memory_read(store,i,0,initial*65536+1,NULL,0)==M98_WASM_RANGE);
 CHECK(grow(i,0,1)==(int32_t)initial);CHECK(pages(i,0)==initial+1);
 zero_page(i,initial*65536);
 for(n=initial*65536;n<(initial+1)*65536;n+=4096){b=0xff;CHECK(m98_wasm_memory_read(store,i,0,n,&b,1)==0&&b==0);}
 b=0xff;CHECK(m98_wasm_memory_read(store,i,0,(initial+1)*65536-1,&b,1)==0&&b==0);
 CHECK(m98_wasm_memory_read(store,i,0,(initial+1)*65536,&b,1)==M98_WASM_RANGE);
 CHECK(m98_wasm_memory_read(store,i,0,initial*65536-1,&b,1)==0&&b==a);
 CHECK(grow(i,0,maximum-initial-1)==(int32_t)initial+1);CHECK(pages(i,0)==maximum);
 CHECK(grow(i,0,1)==-1&&pages(i,0)==maximum);CHECK(grow(i,0,UINT32_MAX)==-1);
 CHECK(m98_wasm_memory_read(store,i,0,UINT32_MAX,&b,1)==M98_WASM_RANGE);
 CHECK(m98_wasm_memory_size(store,i,99,&n)==M98_WASM_RANGE);close_pair(m,i);
}
/* The frozen fault setter is intentionally pre-open only. Search bounded
 * one-shot allocation points until the actual linear-memory realloc fails;
 * earlier init/load/instantiate failures must also leave no tracked memory. */
static void allocator_recovery(const m98_wasm_options *options,const unsigned char *bytes,unsigned length,unsigned initial){
 unsigned point,found=0;unsigned char a=0x6d,b=0;uint32_t m,i;int r;int32_t old;m98_wasm_info before,after;
 for(point=1;point<=192&&!found;point++){
  store=m=i=0;m98_wasm_test_fail_allocation_after(point);r=m98_wasm_open(options,NULL,0,&store);
  if(!r)r=m98_wasm_load(store,bytes,length,&m);if(!r)r=m98_wasm_instantiate(store,m,&i);
  if(!r){CHECK(m98_wasm_memory_write(store,i,0,initial*65536-1,&a,1)==0);CHECK(m98_wasm_inspect(store,&before)==0);
   old=grow(i,0,1);CHECK(m98_wasm_inspect(store,&after)==0);
   if(old==-1){found=1;CHECK(pages(i,0)==initial);CHECK(after.denied_allocations==before.denied_allocations+1&&after.used_bytes==before.used_bytes);
    CHECK(m98_wasm_memory_read(store,i,0,initial*65536-1,&b,1)==0&&b==a);
    CHECK(grow(i,0,1)==(int32_t)initial&&pages(i,0)==initial+1);CHECK(m98_wasm_memory_read(store,i,0,initial*65536-1,&b,1)==0&&b==a);
    b=0xff;CHECK(m98_wasm_memory_read(store,i,0,initial*65536,&b,1)==0&&b==0);
    printf("REAL_REALLOC_RECOVERY initial=%u allocation_point=%u\n",initial,point);
   }else CHECK(old==(int32_t)initial);
  }
  if(store)CHECK(m98_wasm_close(store)==0);CHECK(m98_wasm_test_accounted_bytes()==0);
 }
 CHECK(found==1);m98_wasm_test_fail_allocation_after(0);
}
static void zero_and_multiple(void){uint32_t m,i;unsigned char b=1;
 m=load(fixture_zero,sizeof(fixture_zero));i=instantiate(m);CHECK(pages(i,0)==0&&grow(i,0,0)==0);
 CHECK(m98_wasm_memory_read(store,i,0,0,&b,1)==M98_WASM_RANGE);CHECK(grow(i,0,1)==0&&pages(i,0)==1);
 CHECK(m98_wasm_memory_read(store,i,0,65535,&b,1)==0&&b==0);CHECK(grow(i,0,1)==1&&pages(i,0)==2);CHECK(grow(i,0,1)==-1);close_pair(m,i);
 m=load(fixture_multi,sizeof(fixture_multi));i=instantiate(m);CHECK(pages(i,0)==1&&pages(i,1)==2);
 CHECK(grow(i,0,1)==1&&pages(i,0)==2&&pages(i,1)==2);CHECK(grow(i,1,1)==2&&pages(i,1)==3&&pages(i,0)==2);close_pair(m,i);
}
static void fp_state(void){unsigned k;uint32_t m=load(fixture_two,sizeof(fixture_two)),i=instantiate(m);int r;int32_t old;
 unsigned short cw;unsigned char prior[108],before[108],after[108];
 __asm__ volatile("fnsave %0":"=m"(prior)::"memory");
 for(k=0;k<4;k++){cw=(unsigned short)(0x027f|(k<<10));memset(before,0,108);memset(after,0,108);
  __asm__ volatile("fninit\n\tfldcw %0\n\tfldz\n\tfldz\n\tfdivp\n\tfld1"::"m"(cw):"memory");
  __asm__ volatile("fnsave %0\n\tfrstor %0":"+m"(before)::"memory");
  r=m98_wasm_memory_grow(store,i,0,k?0:1,&old);
  __asm__ volatile("fnsave %0":"=m"(after)::"memory");
  CHECK(r==0&&old==(k?3:2));CHECK(memcmp(before,after,108)==0&&((after[4]&1)!=0));
 }
 __asm__ volatile("frstor %0"::"m"(prior):"memory");close_pair(m,i);
}
static int visit(void *user,const m98_wasm_value *args,uint32_t count,m98_wasm_value *out){uint32_t p=0;int32_t old=99;m98_wasm_info info;(void)user;
 callbacks++;CHECK(count==1&&args[0].kind==M98_WASM_I32);CHECK(m98_wasm_memory_size(store,active_instance,0,&p)==M98_WASM_BUSY&&p==0);
 CHECK(m98_wasm_memory_grow(store,active_instance,0,1,&old)==M98_WASM_BUSY&&old==99);CHECK(m98_wasm_inspect(store,&info)==M98_WASM_BUSY);
 out->kind=M98_WASM_I32;out->bits=args[0].bits+1;return 0;
}
static void controls(void){uint32_t m,i;int32_t old;m98_wasm_value arg={M98_WASM_I32,41},out;unsigned char b; m98_wasm_info info;
 m=load(fixture_callback,sizeof(fixture_callback));i=instantiate(m);active_instance=i;
 CHECK(m98_wasm_call(store,i,"invoke",&arg,1,&out,1)==0&&out.kind==M98_WASM_I32&&out.bits==42&&callbacks==1);CHECK(pages(i,0)==1&&grow(i,0,1)==1);close_pair(m,i);
 m=load(fixture_loop,sizeof(fixture_loop));i=instantiate(m);CHECK(m98_wasm_call(store,i,"loop",NULL,0,NULL,0)==M98_WASM_TRAP);
 CHECK(m98_wasm_inspect(store,&info)==0&&strstr(info.diagnostic,"instruction limit exceeded"));CHECK(grow(i,0,1)==1);close_pair(m,i);
 m=load(fixture_bulk,sizeof(fixture_bulk));i=instantiate(m);CHECK(grow(i,0,1)==1);
 CHECK(m98_wasm_call(store,i,"copy",NULL,0,NULL,0)==0);CHECK(m98_wasm_memory_read(store,i,0,65536,&b,1)==0&&b==0xab);
 CHECK(m98_wasm_call(store,i,"oob",NULL,0,NULL,0)==M98_WASM_TRAP);CHECK(grow(i,0,1)==-1);close_pair(m,i);
 CHECK(m98_wasm_memory_grow(store,i,0,1,&old)==M98_WASM_RANGE); /* frozen ABI range on stale memory access */
}
static void large_and_tables(void){uint32_t m,i;unsigned k;unsigned char a=0x71,b=0;m98_wasm_value arg={M98_WASM_I32,65535},out;m98_wasm_info before,after;
 m=load(fixture_largegrow,sizeof(fixture_largegrow));i=instantiate(m);CHECK(m98_wasm_memory_write(store,i,0,65535,&a,1)==0);CHECK(m98_wasm_inspect(store,&before)==0);
 CHECK(m98_wasm_call(store,i,"grow",&arg,1,&out,1)==0&&out.kind==M98_WASM_I32&&out.bits==UINT32_MAX);CHECK(pages(i,0)==1);
 CHECK(m98_wasm_inspect(store,&after)==0&&after.used_bytes==before.used_bytes&&after.denied_allocations==before.denied_allocations);CHECK(m98_wasm_memory_read(store,i,0,65535,&b,1)==0&&b==a);
 arg.bits=UINT32_MAX;CHECK(m98_wasm_call(store,i,"grow",&arg,1,&out,1)==0&&out.bits==UINT32_MAX&&pages(i,0)==1);
 arg.bits=1;CHECK(m98_wasm_call(store,i,"grow",&arg,1,&out,1)==0&&out.bits==1&&pages(i,0)==2);zero_page(i,65536);close_pair(m,i);
 m=load(fixture_largeinitial,sizeof(fixture_largeinitial));i=0;CHECK(m98_wasm_inspect(store,&before)==0);
 CHECK(m98_wasm_instantiate(store,m,&i)==M98_WASM_LINK&&i==0);CHECK(m98_wasm_inspect(store,&after)==0&&after.used_bytes==before.used_bytes);CHECK(m98_wasm_unload(store,m)==0);
 for(k=0;k<2;k++){m=k?load(fixture_tableszero,sizeof(fixture_tableszero)):load(fixture_tables,sizeof(fixture_tables));i=instantiate(m);
  CHECK(m98_wasm_call(store,i,"invoke",NULL,0,&out,1)==0&&out.kind==M98_WASM_I32&&out.bits==42);CHECK(pages(i,0)==1&&grow(i,0,1)==1);zero_page(i,65536);close_pair(m,i);}
 /* Dirty a complete page, tear down and instantiate afresh: initial bytes
  * must be zero even if the real allocator reuses an earlier linear block. */
 m=load(fixture_one,sizeof(fixture_one));i=instantiate(m);memset(page_bytes,0xdb,sizeof(page_bytes));CHECK(m98_wasm_memory_write(store,i,0,0,page_bytes,sizeof(page_bytes))==0);CHECK(m98_wasm_instance_close(store,i)==0);
 i=instantiate(m);zero_page(i,0);close_pair(m,i);
}
int main(void){m98_wasm_options options={8*1024*1024,65536,2000,4};m98_wasm_import import={"env","visit","(i)i",visit,NULL};m98_wasm_info info;
 CHECK(m98_wasm_open(&options,&import,1,&store)==0);exact_pages(fixture_one,sizeof(fixture_one),1,3);exact_pages(fixture_two,sizeof(fixture_two),2,4);
 exact_pages(fixture_aux,sizeof(fixture_aux),2,4);zero_and_multiple();fp_state();controls();large_and_tables();
 CHECK(m98_wasm_inspect(store,&info)==0&&info.modules==0&&info.instances==0&&info.peak_bytes<=options.memory_bytes);CHECK(m98_wasm_close(store)==0);CHECK(m98_wasm_test_accounted_bytes()==0);
 allocator_recovery(&options,fixture_one,sizeof(fixture_one),1);allocator_recovery(&options,fixture_two,sizeof(fixture_two),2);
 options.memory_bytes=262144;CHECK(m98_wasm_open(&options,NULL,0,&store)==0);
 {uint32_t m=load(fixture_one,sizeof(fixture_one)),i=instantiate(m);unsigned char a=0x5c,b=0;int32_t old;m98_wasm_info before,after;CHECK(m98_wasm_memory_write(store,i,0,1,&a,1)==0);
  CHECK(m98_wasm_inspect(store,&before)==0);CHECK(m98_wasm_memory_grow(store,i,0,2,&old)==0&&old==-1);CHECK(m98_wasm_inspect(store,&after)==0);
  CHECK(after.used_bytes==before.used_bytes&&after.denied_allocations==before.denied_allocations+1);CHECK(pages(i,0)==1);CHECK(m98_wasm_memory_read(store,i,0,1,&b,1)==0&&b==a);close_pair(m,i);}
 CHECK(m98_wasm_close(store)==0&&m98_wasm_test_accounted_bytes()==0);printf("MEMORY_RESULT %u %u 0\n",checks,checks);return 0;
}
