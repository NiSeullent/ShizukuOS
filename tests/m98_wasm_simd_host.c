/* SPDX-License-Identifier: GPL-2.0-only */
/* Project literal fixtures and independently computed byte/lane oracles. */
#include "m98_wasm.h"
#include "wasm_simd_fixtures.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned total, passed, failed, visits;
static uint32_t store, instance;
extern void m98_wasm_test_fail_allocation_after(uint32_t);
extern uint32_t m98_wasm_test_accounted_bytes(void);
#define CHECK(x) do { total++; if (x) passed++; else { failed++; fprintf(stderr,"FAIL %u line %u: %s\n",total,(unsigned)__LINE__,#x); } } while (0)
static uint32_t word(const unsigned char *p) { return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static void put(unsigned char *p,uint32_t n) { unsigned j; for(j=0;j<4;j++)p[j]=(unsigned char)(n>>(8*j)); }
static int invoke(const char *name,const uint32_t *values,unsigned count,unsigned results,uint32_t *result) {
 m98_wasm_value args[8],out[2]={{0,0},{0,0}};unsigned j;int r;
 for(j=0;j<count;j++){args[j].kind=M98_WASM_I32;args[j].bits=values[j];}
 r=m98_wasm_call(store,instance,name,args,count,out,results);
 if(!r&&results){CHECK(out[0].kind==M98_WASM_I32);if(result)*result=(uint32_t)out[0].bits;}
 return r;
}
static int visit(void *user,const m98_wasm_value *args,uint32_t count,m98_wasm_value *out) {
 m98_wasm_info info;uint32_t pages=0;(void)user;visits++;
 CHECK(count==1&&args[0].kind==M98_WASM_I32);
 CHECK(m98_wasm_inspect(store,&info)==M98_WASM_BUSY);
 CHECK(m98_wasm_instance_close(store,instance)==M98_WASM_BUSY);
 CHECK(m98_wasm_memory_size(store,instance,0,&pages)==M98_WASM_BUSY);
 out->kind=M98_WASM_I32;out->bits=(uint32_t)args[0].bits+1;return 0;
}
static uint32_t load_instance(const unsigned char *bytes,unsigned length) {
 uint32_t module=0;CHECK(m98_wasm_load(store,bytes,length,&module)==0);CHECK(m98_wasm_instantiate(store,module,&instance)==0);return module;
}
static void unload(uint32_t module) { CHECK(m98_wasm_instance_close(store,instance)==0);CHECK(m98_wasm_unload(store,module)==0);instance=0; }
static void match(const unsigned char expected[16]) { unsigned char actual[16];CHECK(m98_wasm_memory_read(store,instance,0,4097,actual,16)==0);CHECK(!memcmp(actual,expected,16)); }
int main(void) {
 m98_wasm_options options={8*1024*1024,65536,100000,32};m98_wasm_import import={"env","visit","(i)i",visit,NULL};
 unsigned trial,j,k;uint32_t module,args[4],result,pages;unsigned char a[16],b[16],mask[16],expected[16],prefix[32],after[32];m98_wasm_info info;
 CHECK(m98_wasm_open(&options,&import,1,&store)==0);module=load_instance(fixture_main,sizeof(fixture_main));
 args[0]=4097;args[1]=17;args[2]=49;args[3]=81;
 for(trial=0;trial<64;trial++) {
  for(j=0;j<16;j++){a[j]=(unsigned char)(trial*73+j*19);b[j]=(unsigned char)(trial*31+j*117);mask[j]=(unsigned char)(trial*23+j*11);}
  CHECK(m98_wasm_memory_write(store,instance,0,17,a,16)==0);CHECK(m98_wasm_memory_write(store,instance,0,49,b,16)==0);CHECK(m98_wasm_memory_write(store,instance,0,81,mask,16)==0);
  for(k=0;k<5;k++) {
   const char *names[]={"and","andnot","or","xor","add"};
   if(k==4)for(j=0;j<4;j++)put(expected+4*j,word(a+4*j)+word(b+4*j));
   else for(j=0;j<16;j++)expected[j]=k==0?a[j]&b[j]:k==1?a[j]&~b[j]:k==2?a[j]|b[j]:a[j]^b[j];
   CHECK(invoke(names[k],args,3,0,NULL)==0);match(expected);
  }
  for(j=0;j<16;j++)expected[j]=(unsigned char)~a[j];CHECK(invoke("not",args,2,0,NULL)==0);match(expected);
  for(j=0;j<16;j++)expected[j]=(a[j]&mask[j])|(b[j]&~mask[j]);CHECK(invoke("bitselect",args,4,0,NULL)==0);match(expected);
  for(j=0;j<16;j++)expected[j]=b[j]<16?a[b[j]]:0;CHECK(invoke("swizzle",args,3,0,NULL)==0);match(expected);
  for(j=0;j<16;j++){unsigned lane=(j*7+3)%32;expected[j]=lane<16?a[lane]:b[lane-16];}CHECK(invoke("shuffle",args,3,0,NULL)==0);match(expected);
  for(j=0;j<4;j++){char name[32];uint32_t pair[]={17,0xf1234567u+trial};snprintf(name,sizeof(name),"extract%u",j);CHECK(invoke(name,pair,1,1,&result)==0&&result==word(a+4*j));snprintf(name,sizeof(name),"replace%u",j);memcpy(expected,a,16);put(expected+4*j,pair[1]);uint32_t replace[]={4097,17,pair[1]};CHECK(invoke(name,replace,3,0,NULL)==0);match(expected);}
  {uint32_t splat[]={4097,0xffffffffu-trial};for(j=0;j<4;j++)put(expected+4*j,splat[1]);CHECK(invoke("splat",splat,2,0,NULL)==0);match(expected);}
  for(k=0;k<2;k++) {
   uint32_t select[]={4097,17,49,k};memcpy(expected,k?a:b,16);CHECK(invoke("select",select,4,0,NULL)==0);match(expected);CHECK(invoke("typedselect",select,4,0,NULL)==0);match(expected);
   uint32_t control[]={4097,17,k};memcpy(expected,a,16);CHECK(invoke("control",control,3,0,NULL)==0);match(expected);
  }
  memcpy(expected,a,16);CHECK(invoke("local",args,2,0,NULL)==0);match(expected);CHECK(invoke("gwrite",args+1,1,0,NULL)==0);CHECK(invoke("gread",args,1,0,NULL)==0);match(expected);
  for(j=0;j<4;j++)put(expected+4*j,word(a+4*j)+(j+1));CHECK(invoke("calls",args,2,0,NULL)==0);match(expected);
 }
 {uint32_t values[]={4097,17,4000};CHECK(invoke("gc",values,3,1,&result)==0&&result==61);CHECK(m98_wasm_memory_read(store,instance,0,4097,after,16)==0&&!memcmp(after,a,16));}
 {uint32_t values[]={4097,17,99};CHECK(invoke("callback",values,3,1,&result)==0&&result==100&&visits==1);match(a);}
 {uint32_t values[]={4097,17};CHECK(invoke("tail",values,2,0,NULL)==0);match(a);}
 /* All 16 memory bytes must be checked before a store; unsigned overflow traps. */
 memset(prefix,0x5a,sizeof(prefix));CHECK(m98_wasm_memory_write(store,instance,0,65504,prefix,32)==0);
 {uint32_t values[]={65521,17};CHECK(invoke("not",values,2,0,NULL)==M98_WASM_TRAP);CHECK(m98_wasm_memory_read(store,instance,0,65504,after,32)==0&&!memcmp(prefix,after,32));values[0]=4097;values[1]=0xfffffff8u;CHECK(invoke("not",values,2,0,NULL)==M98_WASM_TRAP);values[1]=65520;CHECK(invoke("local",values,2,0,NULL)==0);values[1]=65521;CHECK(invoke("local",values,2,0,NULL)==M98_WASM_TRAP);}
 /* Load completes before overlapping writes and must preserve its snapshot. */
 {uint32_t values[]={18,17};CHECK(invoke("local",values,2,0,NULL)==0);CHECK(m98_wasm_memory_read(store,instance,0,18,after,16)==0&&!memcmp(after,a,16));}
 CHECK(m98_wasm_memory_size(store,instance,0,&pages)==0&&pages==1);unload(module);
 module=load_instance(fixture_start,sizeof(fixture_start));{unsigned char literal[16];for(j=0;j<4;j++)put(literal+j*4,j+7);CHECK(m98_wasm_memory_read(store,instance,0,0,after,16)==0&&!memcmp(after,literal,16));}unload(module);
 module=load_instance(fixture_multi,sizeof(fixture_multi));{uint32_t values[]={4097,17};CHECK(m98_wasm_memory_write(store,instance,1,17,a,16)==0);CHECK(invoke("move",values,2,0,NULL)==0);CHECK(m98_wasm_memory_read(store,instance,0,4097,after,16)==0&&!memcmp(after,a,16));}unload(module);
 module=load_instance(fixture_loop,sizeof(fixture_loop));CHECK(invoke("loop",NULL,0,0,NULL)==M98_WASM_TRAP);unload(module);
 CHECK(m98_wasm_inspect(store,&info)==0&&info.modules==0&&info.instances==0);CHECK(m98_wasm_close(store)==0);CHECK(m98_wasm_test_accounted_bytes()==0);
 /* Genuine one-shot allocator failures at initialization/load/start/instantiate. */
 for(trial=1;trial<=48;trial++) {
  int r;uint32_t m=0,i=0;store=0;m98_wasm_test_fail_allocation_after(trial);r=m98_wasm_open(&options,NULL,0,&store);
  if(!r){r=m98_wasm_load(store,fixture_start,sizeof(fixture_start),&m);if(!r){r=m98_wasm_instantiate(store,m,&i);if(!r)CHECK(m98_wasm_instance_close(store,i)==0);CHECK(m98_wasm_unload(store,m)==0);}CHECK(m98_wasm_close(store)==0);}
  else CHECK(r==M98_WASM_LIMIT);CHECK(m98_wasm_test_accounted_bytes()==0);
 }
 m98_wasm_test_fail_allocation_after(0);CHECK(m98_wasm_open(&options,NULL,0,&store)==0);module=load_instance(fixture_start,sizeof(fixture_start));unload(module);CHECK(m98_wasm_close(store)==0&&m98_wasm_test_accounted_bytes()==0);
 printf("SIMD_RESULT %u %u %u\n",total,passed,failed);return failed?1:0;
}
