/* SPDX-License-Identifier: GPL-2.0-only */
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include "delay_fixture.h"
static atomic_uint checks;
#define CHECK(x) do{atomic_fetch_add_explicit(&checks,1,memory_order_relaxed);if(!(x)){fprintf(stderr,"FAIL:%u:%s\n",__LINE__,#x);exit(1);}}while(0)
typedef struct mock {
 pthread_mutex_t mutex;
 unsigned opens,finds,closes,live;
 int missing,deny_open,deny_close,deny_lock,reenter,mutate_open,mutate_find,mutate_close;
} mock;
static ntw_delay_context ctx;
static uint8_t file[DF_FILE_BYTES],mapped[DF_IMAGE_BYTES];
static np_image image;
static mock state;
static const char *error;
static int lock(void *p){mock *m=p;return !m->deny_lock&&pthread_mutex_lock(&m->mutex)==0;}
static void unlock(void *p){mock *m=p;CHECK(!pthread_mutex_unlock(&m->mutex));}
static void mutate(int kind)
{if(kind==1)df_put32(mapped+DF_IAT+4,0xdeadbeef);if(kind==2)df_put32(mapped+DF_HANDLE,0xbadcafe);if(kind==3)mapped[DF_DESCRIPTOR]=0;}
static uint32_t open_dll(void *p,const char *name){mock *m=p;m->opens++;CHECK(!strcmp(name,"KERNEL32.DLL"));if(m->mutate_open)mutate(m->mutate_open);if(m->deny_open)return 0;m->live++;return 0x10000;}
static uint32_t find(void *p,uint32_t handle,const char *name,uint16_t ordinal)
{mock *m=p;m->finds++;CHECK(handle==0x10000);if(m->mutate_find)mutate(m->mutate_find);if(m->reenter){uint32_t address;const char *why;m->reenter=0;CHECK(!ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT,&address,&why)&&!strcmp(why,"DELAY_REENTRANT_UNSUPPORTED"));CHECK(!ntw_delay_dispose(&ctx,1,&why)&&!strcmp(why,"DELAY_REENTRANT_UNSUPPORTED"));}if(m->missing)return 0;if(ordinal){CHECK(!name&&ordinal==7);return 0x30020;}CHECK(name);return !strcmp(name,"GetTickCount")?0x30000:!strcmp(name,"lstrlenA")?0x30010:0;}
static int close_dll(void *p,uint32_t handle){mock *m=p;m->closes++;CHECK(handle==0x10000&&m->live);if(m->mutate_close)mutate(m->mutate_close);if(m->deny_close)return 0;m->live--;return 1;}
static ntw_delay_ops operations;
static void fresh(void)
{
 pthread_mutexattr_t attr;CHECK(!ctx.magic);memset(&state,0,sizeof(state));CHECK(!pthread_mutexattr_init(&attr));CHECK(!pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE));CHECK(!pthread_mutex_init(&state.mutex,&attr));CHECK(!pthread_mutexattr_destroy(&attr));
 operations=(ntw_delay_ops){&state,lock,unlock,open_dll,find,close_dll};df_build(file,mapped,0x500000);
 CHECK(np_parse(&image,file,sizeof(file),&error));
}
static void ended(void){CHECK(!state.live);CHECK(!pthread_mutex_destroy(&state.mutex));}
static int initialize(void){return ntw_delay_init(&ctx,&image,mapped,sizeof(mapped),0x500000,&operations,&error);}
static uint32_t resolve(uint32_t index)
{uint32_t address=0;CHECK(ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT+index*4,&address,&error));return address;}
static void *thread(void *p)
{unsigned i;uint32_t result,index=(uint32_t)(uintptr_t)p;for(i=0;i<100;i++)if(!ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT+index*4,&result,0)||result!=0x30000+index*0x10)abort();return 0;}
static void official(const char *path)
{
 FILE *input;long bytes;uint8_t *data,*mapping;np_image original;unsigned index;ntw_delay_context *candidate;const char *why=0;int accepted;
 input=fopen(path,"rb");CHECK(input);CHECK(!fseek(input,0,SEEK_END));bytes=ftell(input);CHECK(bytes>=64&&bytes<=NP_FILE_LIMIT);CHECK(!fseek(input,0,SEEK_SET));
 data=malloc((size_t)bytes);candidate=calloc(1,sizeof(*candidate));CHECK(data&&candidate);CHECK(fread(data,1,(size_t)bytes,input)==(size_t)bytes);CHECK(!fclose(input));
 CHECK(np_parse(&original,data,(uint32_t)bytes,&why));mapping=calloc(1,original.size);CHECK(mapping);memcpy(mapping,data,original.headers);
 for(index=0;index<original.sections;index++){np_section *section=&original.section[index];if(section->bytes)memcpy(mapping+section->va,data+section->raw,section->bytes);}
 fresh();accepted=ntw_delay_init(candidate,&original,mapping,original.size,original.base,&operations,&why);
 printf("OFFICIAL delay_directory_accepted=%d modules=%u slots=%u open_calls=%u error=%s path=%s\n",accepted,candidate->module_count,candidate->entry_count,state.opens,why?why:"none",path);
 CHECK(accepted);CHECK(!state.opens);CHECK(ntw_delay_dispose(candidate,1,&why));ended();free(mapping);free(data);free(candidate);
}
int main(int argc,char **argv)
{
 uint32_t address,i;uint8_t before[DF_IMAGE_BYTES];pthread_t workers[12];
 fresh();CHECK(initialize());CHECK(!state.opens&&ctx.entry_count==3&&ctx.module_count==1);
 CHECK(resolve(0)==0x30000);CHECK(np_u32(mapped+DF_IAT)==0x30000&&np_u32(mapped+DF_HANDLE)==0x10000);
 CHECK(resolve(0)==0x30000&&state.finds==1);CHECK(resolve(1)==0x30010);CHECK(resolve(2)==0x30020);CHECK(state.opens==1&&state.finds==3);
 CHECK(!ntw_delay_dispose(&ctx,0,&error));CHECK(state.live==1);CHECK(ntw_delay_dispose(&ctx,1,&error));CHECK(np_u32(mapped+DF_HANDLE)==0&&np_u32(mapped+DF_IAT)==0x501000);ended();
 fresh();CHECK(initialize());for(i=0;i<12;i++)CHECK(!pthread_create(&workers[i],0,thread,(void *)(uintptr_t)(i%3)));for(i=0;i<12;i++)CHECK(!pthread_join(workers[i],0));CHECK(state.opens==1&&state.finds==3);CHECK(ntw_delay_dispose(&ctx,1,&error));ended();
 fresh();CHECK(initialize());memcpy(before,mapped,sizeof(before));state.missing=1;CHECK(!ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT,&address,&error));CHECK(address==0&&!memcmp(before,mapped,sizeof(before))&&state.closes==1&&!state.live);state.missing=0;CHECK(resolve(0)==0x30000);CHECK(ntw_delay_dispose(&ctx,1,&error));ended();
 fresh();CHECK(initialize());memcpy(before,mapped,sizeof(before));state.deny_open=1;CHECK(!ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT,&address,&error));CHECK(!state.finds&&!state.closes&&!memcmp(before,mapped,sizeof(before)));CHECK(ntw_delay_dispose(&ctx,1,&error));ended();
 fresh();CHECK(initialize());state.missing=state.deny_close=1;memcpy(before,mapped,sizeof(before));CHECK(!ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT,&address,&error));CHECK(!strcmp(error,"DELAY_ROLLBACK_CLOSE_FAILED")&&state.live==1&&ctx.state==1&&!memcmp(before,mapped,sizeof(before)));CHECK(!ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT,&address,&error));state.deny_close=0;CHECK(ntw_delay_dispose(&ctx,1,&error));ended();
 fresh();CHECK(initialize());CHECK(resolve(0)==0x30000);state.deny_close=1;CHECK(!ntw_delay_dispose(&ctx,1,&error));CHECK(ctx.state==2&&np_u32(mapped+DF_IAT)==0x501000&&np_u32(mapped+DF_HANDLE)==0);state.deny_close=0;CHECK(ntw_delay_dispose(&ctx,1,&error));ended();
 fresh();CHECK(initialize());state.deny_lock=1;CHECK(!ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT,&address,&error));CHECK(!state.opens);state.deny_lock=0;CHECK(!ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT+12,&address,&error));CHECK(!state.opens);CHECK(ntw_delay_dispose(&ctx,1,&error));ended();
 fresh();CHECK(initialize());df_put32(mapped+DF_HANDLE,0x9999);CHECK(!ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT,&address,&error));CHECK(!state.opens);CHECK(!ntw_delay_dispose(&ctx,1,&error));df_put32(mapped+DF_HANDLE,0);CHECK(ntw_delay_dispose(&ctx,1,&error));ended();
 fresh();CHECK(initialize());mapped[DF_DESCRIPTOR]=0;CHECK(!ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT,&address,&error));CHECK(!state.opens);CHECK(!ntw_delay_dispose(&ctx,1,&error));mapped[DF_DESCRIPTOR]=1;CHECK(ntw_delay_dispose(&ctx,1,&error));ended();
 fresh();CHECK(initialize());file[1024+0x182]='!';CHECK(resolve(0)==0x30000);CHECK(ntw_delay_dispose(&ctx,1,&error));ended(); /* Names are copied into the context. */
 fresh();CHECK(initialize());state.reenter=1;CHECK(resolve(0)==0x30000);CHECK(!ctx.busy&&state.opens==1&&state.finds==1);CHECK(ntw_delay_dispose(&ctx,1,&error));ended();
 for(i=0;i<6;i++){
  fresh();CHECK(initialize());if(i<3)state.mutate_open=(int)i+1;else state.mutate_find=(int)i-2;
  CHECK(!ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT,&address,&error)&&!strcmp(error,"DELAY_MAPPING_CHANGED"));
  CHECK(!address&&ctx.state==1&&!ctx.entry[0].address&&np_u32(mapped+DF_IAT)==0x501000);
  CHECK(state.opens==1&&state.finds==(i<3?0u:1u)&&state.closes==1&&!state.live);
  CHECK(!ntw_delay_dispose(&ctx,1,&error)&&!strcmp(error,"DELAY_MAPPING_CHANGED"));
  df_build(file,mapped,0x500000);CHECK(ntw_delay_dispose(&ctx,1,&error));ended();
 }
 fresh();CHECK(initialize());state.mutate_open=1;state.deny_close=1;CHECK(!ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT,&address,&error)&&!strcmp(error,"DELAY_ROLLBACK_CLOSE_FAILED"));CHECK(!address&&ctx.state==1&&state.live==1&&ctx.module[0].handle==0x10000&&!ctx.module[0].published&&!ctx.entry[0].address);state.deny_close=0;df_put32(mapped+DF_IAT+4,0x501001);CHECK(ntw_delay_dispose(&ctx,1,&error));ended();
 fresh();CHECK(initialize());state.mutate_open=2;state.deny_open=1;CHECK(!ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT,&address,&error)&&!strcmp(error,"DELAY_MAPPING_CHANGED"));CHECK(!address&&ctx.state==1&&!state.live&&!state.finds&&!state.closes);df_put32(mapped+DF_HANDLE,0);CHECK(ntw_delay_dispose(&ctx,1,&error));ended();
 fresh();memcpy(before,mapped,sizeof(before));CHECK(!ntw_delay_init(&ctx,&image,mapped+1,sizeof(mapped),0x500000,&operations,&error)&&!strcmp(error,"DELAY_ARGUMENT"));CHECK(!ctx.magic&&!state.opens&&!memcmp(before,mapped,sizeof(before)));ended();
 fresh();CHECK(initialize());state.missing=1;state.mutate_close=1;CHECK(!ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT,&address,&error)&&!strcmp(error,"DELAY_MAPPING_CHANGED"));CHECK(!address&&ctx.state==1&&!state.live&&state.closes==1&&!ctx.entry[0].address);df_put32(mapped+DF_IAT+4,0x501001);CHECK(ntw_delay_dispose(&ctx,1,&error));ended();
 fresh();CHECK(initialize());CHECK(resolve(0)==0x30000);state.mutate_close=1;CHECK(!ntw_delay_dispose(&ctx,1,&error)&&!strcmp(error,"DELAY_MAPPING_CHANGED"));CHECK(ctx.state==2&&!state.live&&state.closes==1&&!ctx.module[0].published);CHECK(!ntw_delay_dispose(&ctx,1,&error)&&!strcmp(error,"DELAY_MAPPING_CHANGED"));df_put32(mapped+DF_IAT+4,0x501001);CHECK(ntw_delay_dispose(&ctx,1,&error));ended();
 fresh();CHECK(initialize());CHECK(resolve(0)==0x30000);state.mutate_find=1;CHECK(!ntw_delay_resolve(&ctx,DF_DESCRIPTOR,DF_IAT+8,&address,&error)&&!strcmp(error,"DELAY_MAPPING_CHANGED"));CHECK(ctx.state==1&&state.opens==1&&!state.closes&&state.live==1&&np_u32(mapped+DF_IAT+8)==0x501002);df_put32(mapped+DF_IAT+4,0x501001);CHECK(ntw_delay_dispose(&ctx,1,&error));ended();
 for(i=0;i<8;i++){
  fresh();
  if(i==0){df_put32(file+1024+20,0x2200);df_put32(mapped+DF_DESCRIPTOR+20,0x2200);}
  if(i==1){df_put32(file+1024+24,0x2200);df_put32(mapped+DF_DESCRIPTOR+24,0x2200);}
  if(i==2){df_put32(file+1024+8,DF_IAT);df_put32(mapped+DF_DESCRIPTOR+8,DF_IAT);}
  if(i==3){df_put32(file+1024+8,0x2160);df_put32(mapped+DF_DESCRIPTOR+8,0x2160);df_put32(file+1024+0x160,0);df_put32(mapped+0x2160,0);}
  if(i==4){df_put32(mapped+DF_IAT,0x600000);}
  if(i==5){df_put32(file+0x178+76,0x40000040);}
  if(i==6){df_put32(file+1024+0x128,0x80010007);}
  if(i==7){df_put32(file+1024+0x120,0x2fff);}
  CHECK(np_parse(&image,file,sizeof(file),&error));memcpy(before,mapped,sizeof(before));CHECK(!initialize());CHECK(!ctx.magic&&!state.opens&&!memcmp(before,mapped,sizeof(before)));ended();
 }
 for(i=1;i<(uint32_t)argc;i++)official(argv[i]);
 printf("PASS %u checks; host mock resolver only; native_executed=false\n",atomic_load(&checks));return 0;
}
