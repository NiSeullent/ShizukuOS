/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <pthread.h>
#include "m98_wasm.h"
#include "m98_wasm_math.h"
#include "wasm_original_fixtures.h"
extern char *m98_wasm_strtok_r(char *,const char *,char **);
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL %u line %u: %s\n",checks,__LINE__,#x);exit(1);}}while(0)
static uint32_t store,active_instance;
static unsigned callbacks,callback_failure;
extern void m98_wasm_test_fail_allocation_after(uint32_t);
extern void m98_wasm_test_platform_ready_mode(unsigned);
extern uint32_t m98_wasm_test_accounted_bytes(void);
static m98_wasm_value i32(uint32_t x){m98_wasm_value v={M98_WASM_I32,x};return v;}
static m98_wasm_value i64(uint64_t x){m98_wasm_value v={M98_WASM_I64,x};return v;}
static m98_wasm_value f64(double x){m98_wasm_value v={M98_WASM_F64,0};memcpy(&v.bits,&x,8);return v;}
static m98_wasm_value f32(float x){m98_wasm_value v={M98_WASM_F32,0};memcpy(&v.bits,&x,4);return v;}
static uint64_t dbits(double x){uint64_t v;memcpy(&v,&x,8);return v;}
static int host_sum(void *user,const m98_wasm_value *args,uint32_t count,m98_wasm_value *out){m98_wasm_info info;unsigned short changed=0x077f,current;(void)user;
 callbacks++;CHECK(count==2&&args[0].kind==M98_WASM_I32&&args[1].kind==M98_WASM_I32);
 CHECK(m98_wasm_inspect(store,&info)==M98_WASM_BUSY);
 CHECK(m98_wasm_instance_close(store,active_instance)==M98_WASM_BUSY);
 __asm__ volatile("fnstcw %0":"=m"(current));CHECK(current==0x0a7f); /* caller PC53/upward */
 __asm__ volatile("fldcw %0"::"m"(changed):"memory");
 *out=i32((uint32_t)args[0].bits+(uint32_t)args[1].bits);return callback_failure?1:0;
}
static void *foreign(void *p){m98_wasm_info info;(void)p;CHECK(m98_wasm_inspect(store,&info)==M98_WASM_THREAD);CHECK(m98_wasm_close(store)==M98_WASM_THREAD);return NULL;}
static uint32_t load(const void *p,size_t n){uint32_t m=0;int r=m98_wasm_load(store,p,(uint32_t)n,&m);if(r){m98_wasm_info info;m98_wasm_inspect(store,&info);fprintf(stderr,"load status %d: %s\n",r,info.diagnostic);}CHECK(r==0);CHECK(m!=0);return m;}
static uint32_t instantiate(uint32_t m){uint32_t i=0;CHECK(m98_wasm_instantiate(store,m,&i)==0);CHECK(i!=0);return i;}
static void call(uint32_t i,const char *name,const m98_wasm_value *args,uint32_t count,m98_wasm_value *out,uint32_t results){CHECK(m98_wasm_call(store,i,name,args,count,out,results)==0);}
/* Deliberate test-only provider FP clobber: not native provider evidence. */
static void platform_fp_boundary(void){unsigned mode;uint32_t s;int r;m98_wasm_options options={4194304,16384,2000,4};unsigned short upward=0x0a7f;
 unsigned char prior[108] __attribute__((aligned(16))),before[108] __attribute__((aligned(16))),after[108] __attribute__((aligned(16)));
 __asm__ volatile("fnsave %0":"=m"(prior)::"memory");
 for(mode=1;mode<=2;mode++){
  memset(before,0,sizeof(before));memset(after,0,sizeof(after));m98_wasm_test_platform_ready_mode(mode);s=UINT32_C(0x13579bdf);
  __asm__ volatile("fninit\n\tfldcw %0\n\tfldz\n\tfldz\n\tfdivp\n\tfld1"::"m"(upward):"memory");
  __asm__ volatile("fnsave %0\n\tfrstor %0":"+m"(before)::"memory");
  r=m98_wasm_open(&options,NULL,0,&s);
  __asm__ volatile("fnsave %0":"=m"(after)::"memory");
  CHECK(memcmp(before,after,sizeof(before))==0);CHECK((after[4]&1)!=0);
  if(mode==1){CHECK(r==0&&s!=UINT32_C(0x13579bdf));CHECK(m98_wasm_close(s)==0);}
  else CHECK(r==M98_WASM_PLATFORM&&s==UINT32_C(0x13579bdf));
  CHECK(m98_wasm_test_accounted_bytes()==0);
 }
 m98_wasm_test_platform_ready_mode(0);__asm__ volatile("frstor %0"::"m"(prior):"memory");
}
static void platform_helpers(void){char a[]="//a//b/",b[]="x:y:z",*ap=NULL,*bp=NULL;unsigned n;
 CHECK(!strcmp(m98_wasm_strtok_r(a,"/",&ap),"a"));CHECK(!strcmp(m98_wasm_strtok_r(b,":",&bp),"x"));
 CHECK(!strcmp(m98_wasm_strtok_r(NULL,"/",&ap),"b"));CHECK(!strcmp(m98_wasm_strtok_r(NULL,":",&bp),"y"));
 CHECK(m98_wasm_strtok_r(NULL,"/",&ap)==NULL);CHECK(!strcmp(m98_wasm_strtok_r(NULL,":",&bp),"z"));
 CHECK(m98_wasm_strtok_r(NULL,":",&bp)==NULL);CHECK(__ctzdi2(0)==64);
 for(n=0;n<64;n++)CHECK(__ctzdi2(UINT64_C(1)<<n)==(int)n);CHECK(__ctzdi2(UINT64_MAX)==0);
}
static void numeric_tests(void){uint32_t m,i; m98_wasm_value args[2],result[2];unsigned n;
 m=load(wasm_arithmetic,sizeof(wasm_arithmetic));i=instantiate(m);
 for(n=0;n<100;n++){args[0]=i32(UINT32_MAX-n);args[1]=i32(n+2);call(i,"add",args,2,result,1);CHECK(result[0].kind==M98_WASM_I32&&result[0].bits==1);}
 args[0]=i64(UINT64_C(0x123456789abcdef0));args[1]=i64(UINT64_C(0xffffffffffffffff));call(i,"wide",args,2,result,1);CHECK(result[0].kind==M98_WASM_I64&&result[0].bits==UINT64_C(0x123456789abcdeef));
 args[0]=i32(17);call(i,"pair",args,1,result,2);CHECK(result[0].bits==17&&result[1].bits==17);
 args[0]=i32(6);args[1]=i32(3);call(i,"div",args,2,result,1);CHECK(result[0].bits==2);
 args[1]=i32(0);CHECK(m98_wasm_call(store,i,"div",args,2,result,1)==M98_WASM_TRAP);
 args[0]=i32(0x80000000);args[1]=i32(UINT32_MAX);CHECK(m98_wasm_call(store,i,"div",args,2,result,1)==M98_WASM_TRAP);
 args[0]=i32(8);args[1]=i32(2);call(i,"div",args,2,result,1);CHECK(result[0].bits==4); /* trap clears, instance remains usable */
 args[0]=i64(1);CHECK(m98_wasm_call(store,i,"add",args,2,result,1)==M98_WASM_TYPE);
 CHECK(m98_wasm_call(store,i,"add",args,1,result,1)==M98_WASM_TYPE);
 CHECK(m98_wasm_call(store,i,"missing",args,2,result,1)==M98_WASM_ARGUMENT);
 CHECK(m98_wasm_unload(store,m)==M98_WASM_BUSY);CHECK(m98_wasm_instance_close(store,i)==0);CHECK(m98_wasm_instance_close(store,i)==M98_WASM_STALE);CHECK(m98_wasm_unload(store,m)==0);CHECK(m98_wasm_instantiate(store,m,&i)==M98_WASM_STALE);
}
static void memory_tests(void){uint32_t m,i,pages,n;int32_t old;m98_wasm_value args[3],result;unsigned char b[64],zero[64];
 m=load(wasm_memory,sizeof(wasm_memory));i=instantiate(m);CHECK(m98_wasm_memory_size(store,i,0,&pages)==0&&pages==1);
 CHECK(m98_wasm_memory_read(store,i,0,0,b,6)==0&&memcmp(b,"Wasm98",6)==0);
 for(n=0;n<64;n++)b[n]=(unsigned char)n;
 CHECK(m98_wasm_memory_write(store,i,0,65500,b,36)==0);CHECK(m98_wasm_memory_read(store,i,0,65500,zero,36)==0&&memcmp(b,zero,36)==0);
 CHECK(m98_wasm_memory_read(store,i,0,65500,b,37)==M98_WASM_RANGE);
 CHECK(m98_wasm_memory_read(store,i,0,UINT32_MAX,b,2)==M98_WASM_RANGE);
 CHECK(m98_wasm_memory_write(store,i,0,65536,NULL,0)==0);
 CHECK(m98_wasm_memory_size(store,i,3,&pages)==M98_WASM_RANGE);
 args[0]=i32(7);args[1]=i32(0x78563412);call(i,"store",args,2,NULL,0);call(i,"load",args,1,&result,1);CHECK(result.bits==0x78563412);
 args[0]=i32(65534);CHECK(m98_wasm_call(store,i,"load",args,1,&result,1)==M98_WASM_TRAP);
 CHECK(m98_wasm_memory_grow(store,i,0,1,&old)==0&&old==1);CHECK(m98_wasm_memory_size(store,i,0,&pages)==0&&pages==2);
 CHECK(m98_wasm_memory_read(store,i,0,65500,zero,36)==0&&memcmp(b,zero,36)==0);
 CHECK(m98_wasm_memory_read(store,i,0,65536,zero,64)==0);for(n=0;n<64;n++)CHECK(zero[n]==0);
 args[0]=i32(2);call(i,"grow",args,1,&result,1);CHECK(result.bits==2);CHECK(m98_wasm_memory_size(store,i,0,&pages)==0&&pages==4);
 args[0]=i32(1);call(i,"grow",args,1,&result,1);CHECK(result.bits==UINT32_MAX);CHECK(m98_wasm_memory_size(store,i,0,&pages)==0&&pages==4);
 CHECK(m98_wasm_memory_grow(store,i,0,UINT32_MAX,&old)==0&&old==-1);
 args[0]=i32(20);args[1]=i32(7);args[2]=i32(4);call(i,"copy",args,3,NULL,0);CHECK(m98_wasm_memory_read(store,i,0,20,b,4)==0&&b[0]==0x12&&b[3]==0x78);
 args[0]=i32(30);args[1]=i32(0xa5);args[2]=i32(64);call(i,"fill",args,3,NULL,0);CHECK(m98_wasm_memory_read(store,i,0,30,b,64)==0);for(n=0;n<64;n++)CHECK(b[n]==0xa5);
 CHECK(m98_wasm_instance_close(store,i)==0);CHECK(m98_wasm_unload(store,m)==0);
 m=load(wasm_multimemory,sizeof(wasm_multimemory));i=instantiate(m);call(i,"size",NULL,0,&result,1);CHECK(result.bits==2);CHECK(m98_wasm_memory_grow(store,i,1,1,&old)==0&&old==2);CHECK(m98_wasm_memory_size(store,i,0,&pages)==0&&pages==1);CHECK(m98_wasm_instance_close(store,i)==0);CHECK(m98_wasm_unload(store,m)==0);
}
static void imports_and_meter(void){uint32_t m,i;m98_wasm_value args[2],result;unsigned short original,current,upward=0x0a7f;m98_wasm_info info;
 unsigned char prior[108] __attribute__((aligned(16))),before[108] __attribute__((aligned(16))),after[108] __attribute__((aligned(16)));
 m=load(wasm_imports,sizeof(wasm_imports));i=instantiate(m);active_instance=i;args[0]=i32(20);args[1]=i32(22);
 memset(before,0,sizeof(before));memset(after,0,sizeof(after));
 __asm__ volatile("fnstcw %0\n\tfnsave %1\n\tfldcw %2\n\tfldz\n\tfldz\n\tfdivp\n\tfld1":"=m"(original),"=m"(prior):"m"(upward):"memory");
 __asm__ volatile("fnsave %0\n\tfrstor %0":"+m"(before)::"memory");
 call(i,"invoke",args,2,&result,1);CHECK(result.bits==42&&callbacks==1);__asm__ volatile("fnstcw %0":"=m"(current));CHECK(current==upward);
 __asm__ volatile("fnsave %0":"=m"(after)::"memory");CHECK(memcmp(before,after,sizeof(before))==0);CHECK((after[4]&1)!=0);__asm__ volatile("frstor %0\n\tfldcw %1"::"m"(prior),"m"(upward):"memory");
 callback_failure=1;CHECK(m98_wasm_call(store,i,"invoke",args,2,&result,1)==M98_WASM_TRAP);callback_failure=0;__asm__ volatile("fnstcw %0":"=m"(current));CHECK(current==upward);__asm__ volatile("fldcw %0"::"m"(original):"memory");
 CHECK(m98_wasm_instance_close(store,i)==0);CHECK(m98_wasm_unload(store,m)==0);
 m=load(wasm_infinite,sizeof(wasm_infinite));i=instantiate(m);CHECK(m98_wasm_call(store,i,"loop",NULL,0,NULL,0)==M98_WASM_TRAP);CHECK(m98_wasm_inspect(store,&info)==0&&strstr(info.diagnostic,"instruction limit exceeded"));CHECK(m98_wasm_instance_close(store,i)==0);CHECK(m98_wasm_unload(store,m)==0);
 m=load(wasm_tail_infinite,sizeof(wasm_tail_infinite));i=instantiate(m);CHECK(m98_wasm_call(store,i,"tail_loop",NULL,0,NULL,0)==M98_WASM_TRAP);CHECK(m98_wasm_inspect(store,&info)==0&&strstr(info.diagnostic,"instruction limit exceeded"));CHECK(m98_wasm_instance_close(store,i)==0);CHECK(m98_wasm_unload(store,m)==0);
 m=load(wasm_recursion,sizeof(wasm_recursion));i=instantiate(m);CHECK(m98_wasm_call(store,i,"recurse",NULL,0,NULL,0)==M98_WASM_TRAP);CHECK(m98_wasm_inspect(store,&info)==0&&strstr(info.diagnostic,"stack"));CHECK(m98_wasm_instance_close(store,i)==0);CHECK(m98_wasm_unload(store,m)==0);
 m=load(wasm_start_infinite,sizeof(wasm_start_infinite));CHECK(m98_wasm_instantiate(store,m,&i)==M98_WASM_LINK);CHECK(m98_wasm_inspect(store,&info)==0&&strstr(info.diagnostic,"instruction limit exceeded"));CHECK(m98_wasm_unload(store,m)==0);
 m=load(wasm_start_trap,sizeof(wasm_start_trap));CHECK(m98_wasm_instantiate(store,m,&i)==M98_WASM_LINK);CHECK(m98_wasm_unload(store,m)==0);
 m=load(wasm_unreachable,sizeof(wasm_unreachable));i=instantiate(m);CHECK(m98_wasm_call(store,i,"trap",NULL,0,NULL,0)==M98_WASM_TRAP);CHECK(m98_wasm_instance_close(store,i)==0);CHECK(m98_wasm_unload(store,m)==0);
 m=load(wasm_missing_import,sizeof(wasm_missing_import));CHECK(m98_wasm_instantiate(store,m,&i)==M98_WASM_LINK);CHECK(m98_wasm_unload(store,m)==0);
 m=load(wasm_tail,sizeof(wasm_tail));i=instantiate(m);args[0]=i32(41);call(i,"first",args,1,&result,1);CHECK(result.bits==42);CHECK(m98_wasm_instance_close(store,i)==0);CHECK(m98_wasm_unload(store,m)==0);
}
static void floating(void){const double values[]={0.0,-0.0,0.25,-0.25,0.5,-0.5,1.5,2.5,-1.5,-2.5,1.999,4503599627370495.5,4503599627370496.0,INFINITY,-INFINITY};uint32_t m,i,k;m98_wasm_value args[2],result;
 for(k=0;k<sizeof(values)/sizeof(values[0]);k++){CHECK(dbits(m98_wasm_ceil(values[k]))==dbits(ceil(values[k])));CHECK(dbits(m98_wasm_floor(values[k]))==dbits(floor(values[k])));CHECK(dbits(m98_wasm_trunc(values[k]))==dbits(trunc(values[k])));CHECK(dbits(m98_wasm_rint(values[k]))==dbits(rint(values[k])));}
 m=load(wasm_float,sizeof(wasm_float));i=instantiate(m);
 for(k=0;k<sizeof(values)/sizeof(values[0]);k++){args[0]=f64(values[k]);call(i,"nearest",args,1,&result,1);CHECK(result.bits==dbits(rint(values[k])));args[0]=f32((float)values[k]);call(i,"fnearest",args,1,&result,1);CHECK(result.bits==f32(rintf((float)values[k])).bits);}
 args[0]=f64(4.0);call(i,"sqrt",args,1,&result,1);CHECK(result.bits==dbits(2.0));args[0]=f32(4.0f);call(i,"fsqrt",args,1,&result,1);CHECK(result.bits==f32(2.0f).bits);
 args[0]=f64(0.0);args[1]=f64(-0.0);call(i,"min",args,2,&result,1);CHECK(result.bits==dbits(-0.0));call(i,"max",args,2,&result,1);CHECK(result.bits==dbits(0.0));
 CHECK(m98_wasm_instance_close(store,i)==0);CHECK(m98_wasm_unload(store,m)==0);
}
static void validate_and_lifetime(void){uint32_t m,i,n,handles[8],is[8];m98_wasm_info before,after;
 CHECK(m98_wasm_inspect(store,&before)==0);
 for(n=sizeof(wasm_arithmetic)-12;n<sizeof(wasm_arithmetic);n++)CHECK(m98_wasm_load(store,wasm_arithmetic,n,&m)==M98_WASM_VALIDATE);
 CHECK(m98_wasm_load(store,wasm_bad_magic,sizeof(wasm_bad_magic),&m)==M98_WASM_VALIDATE);CHECK(m98_wasm_load(store,wasm_bad_type,sizeof(wasm_bad_type),&m)==M98_WASM_VALIDATE);CHECK(m98_wasm_load(store,wasm_truncated,sizeof(wasm_truncated),&m)==M98_WASM_VALIDATE);
 CHECK(m98_wasm_inspect(store,&after)==0&&after.used_bytes==before.used_bytes);
 for(n=0;n<8;n++)handles[n]=load(wasm_arithmetic,sizeof(wasm_arithmetic));CHECK(m98_wasm_load(store,wasm_arithmetic,sizeof(wasm_arithmetic),&m)==M98_WASM_LIMIT);
 for(n=0;n<8;n++)is[n]=instantiate(handles[0]);CHECK(m98_wasm_instantiate(store,handles[0],&i)==M98_WASM_LIMIT);
 CHECK(m98_wasm_instance_close(store,handles[0])==M98_WASM_STALE);CHECK(m98_wasm_unload(store,is[0])==M98_WASM_STALE);
 for(n=0;n<8;n++)CHECK(m98_wasm_instance_close(store,is[n])==0);
 for(n=0;n<8;n++)CHECK(m98_wasm_unload(store,handles[n])==0);
 m=load(wasm_too_much_memory,sizeof(wasm_too_much_memory));CHECK(m98_wasm_instantiate(store,m,&i)==M98_WASM_LINK);CHECK(m98_wasm_unload(store,m)==0);CHECK(m98_wasm_inspect(store,&after)==0&&after.used_bytes==before.used_bytes&&after.denied_allocations>0);
 m=load(wasm_arithmetic,sizeof(wasm_arithmetic));i=instantiate(m);CHECK(m98_wasm_close(store)==0);CHECK(m98_wasm_close(store)==M98_WASM_STALE);CHECK(m98_wasm_call(store,i,"pair",NULL,0,NULL,0)==M98_WASM_STALE);
}
static void allocation_faults(void){uint32_t profile,point,s,m,i;int r;unsigned failures;m98_wasm_options options={4194304,16384,2000,4};m98_wasm_import im={"host","sum","(ii)i",host_sum,NULL};
 for(profile=0;profile<2;profile++){
  failures=0;
  for(point=1;point<=96;point++){
   m98_wasm_test_fail_allocation_after(point);s=m=i=0;r=m98_wasm_open(&options,profile?&im:NULL,profile,&s);
   if(!r){r=m98_wasm_load(s,profile?wasm_imports:wasm_arithmetic,profile?sizeof(wasm_imports):sizeof(wasm_arithmetic),&m);if(!r)r=m98_wasm_instantiate(s,m,&i);
    if(r){CHECK(r==M98_WASM_LIMIT||r==M98_WASM_LINK||r==M98_WASM_VALIDATE);failures++;}
    CHECK(m98_wasm_close(s)==0);
   }else{CHECK(r==M98_WASM_LIMIT||r==M98_WASM_LINK);failures++;}
   CHECK(m98_wasm_test_accounted_bytes()==0);
  }
  CHECK(failures>=20);
 }
 m98_wasm_test_fail_allocation_after(0);CHECK(m98_wasm_open(&options,NULL,0,&s)==0);CHECK(m98_wasm_close(s)==0);CHECK(m98_wasm_test_accounted_bytes()==0);
}
int main(void){m98_wasm_options options={4194304,16384,2000,4};m98_wasm_import import={"host","sum","(ii)i",host_sum,NULL};uint32_t other,m,i;pthread_t thread;m98_wasm_info info;
 platform_fp_boundary();
 CHECK(m98_wasm_open(NULL,NULL,0,&store)==M98_WASM_ARGUMENT);CHECK(m98_wasm_open(&options,&import,1,&store)==0);CHECK(m98_wasm_open(&options,NULL,0,&other)==M98_WASM_BUSY);
 CHECK(pthread_create(&thread,NULL,foreign,NULL)==0);CHECK(pthread_join(thread,NULL)==0);
 platform_helpers();numeric_tests();memory_tests();imports_and_meter();floating();CHECK(m98_wasm_inspect(store,&info)==0&&info.modules==0&&info.instances==0&&info.peak_bytes<=options.memory_bytes);validate_and_lifetime();
 CHECK(m98_wasm_open(&options,NULL,0,&other)==0&&other!=store);CHECK(m98_wasm_inspect(store,&info)==M98_WASM_STALE);
 CHECK(m98_wasm_load(other,wasm_imports,sizeof(wasm_imports),&m)==0);CHECK(m98_wasm_instantiate(other,m,&i)==M98_WASM_LINK);CHECK(m98_wasm_unload(other,m)==0);CHECK(m98_wasm_close(other)==0);
 allocation_faults();
 printf("WAMR actual standalone tests: %u assertions; browser/native/full-Wasm false\n",checks);return 0;
}
