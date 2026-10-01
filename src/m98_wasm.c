/* SPDX-License-Identifier: GPL-2.0-only
 * Real WAMR embedding with one bounded, explicitly owned store. */
#include "m98_wasm.h"
#include "wasm_export.h"
#include "m98_wasm_platform_internal.h"
#define SLOTS 8
#define IMPORTS 16
#define GENERATIONS UINT32_C(0x03ffffff)
#define ALLOCATION_TAG UINT32_C(0x57393841)
typedef union allocation { struct {uint32_t size,tag;} h;long double align;void *pointer;uint64_t integer; } allocation;
typedef struct {uint32_t generation;wasm_module_t module;uint8_t *bytes;uint32_t instances;} module_slot;
typedef struct {uint32_t generation,module_index;wasm_module_inst_t instance;wasm_exec_env_t env;} instance_slot;
typedef struct {char module[64],name[64],signature[16];m98_wasm_import_fn callback;void *user;NativeSymbol symbol;} import_slot;
static volatile uint32_t gate;
static uint32_t owner,store_generation,store_token;
static m98_wasm_options options;
static m98_wasm_info info;
static module_slot modules[SLOTS];
static instance_slot instances[SLOTS];
static import_slot imports[IMPORTS];
static uint32_t import_count;
#ifdef M98_WASM_TESTING
static uint32_t test_failure_after;
void m98_wasm_test_fail_allocation_after(uint32_t n){if(__sync_bool_compare_and_swap(&gate,0,1)){if(!store_token)test_failure_after=n;__sync_lock_release(&gate);}}
uint32_t m98_wasm_test_accounted_bytes(void){uint32_t n;if(!__sync_bool_compare_and_swap(&gate,0,1))return UINT32_MAX;n=info.used_bytes;__sync_lock_release(&gate);return n;}
static int allocation_fault(void){if(test_failure_after&&!--test_failure_after)return 1;return 0;}
#else
static int allocation_fault(void){return 0;}
#endif
static unsigned char caller_fp[108] __attribute__((aligned(16)));
static void save_fp(void *p){unsigned short cw=0x027f;__asm__ volatile("fnsave %0\n\tfldcw %1":"=m"(*(unsigned char (*)[108])p):"m"(cw):"memory");}
static void restore_fp(const void *p){__asm__ volatile("frstor %0"::"m"(*(const unsigned char (*)[108])p):"memory");}
static void leave(void){restore_fp(caller_fp);__sync_lock_release(&gate);}
static int enter(uint32_t token){
 if(!__sync_bool_compare_and_swap(&gate,0,1))return M98_WASM_BUSY;
 if(!store_token||token!=store_token){__sync_lock_release(&gate);return M98_WASM_STALE;}
 if(owner!=m98_wasm_thread_id()){__sync_lock_release(&gate);return M98_WASM_THREAD;}
 save_fp(caller_fp);return 0;
}
static int done(int r){leave();return r;}
static void diagnostic(const char *s){size_t n=0;if(s)while(n<sizeof(info.diagnostic)-1&&s[n])n++;if(n)memcpy(info.diagnostic,s,n);info.diagnostic[n]=0;}
static int numeric(uint32_t k){return k<=M98_WASM_F64;}
static uint32_t generation_handle(uint32_t generation,uint32_t index,uint32_t type){return (generation<<4)|(index+1)|type;}
static int module_index(uint32_t h){uint32_t i=(h&15);if((h&UINT32_C(0xc0000000))!=UINT32_C(0x40000000)||!i||i>SLOTS)return -1;i--;return modules[i].module&&modules[i].generation==((h&UINT32_C(0x3fffffff))>>4)?(int)i:-1;}
static int instance_index(uint32_t h){uint32_t i=(h&15);if((h&UINT32_C(0xc0000000))!=UINT32_C(0x80000000)||!i||i>SLOTS)return -1;i--;return instances[i].instance&&instances[i].generation==((h&UINT32_C(0x3fffffff))>>4)?(int)i:-1;}
static void *bounded_malloc(mem_alloc_usage_t usage,void *user,unsigned n){allocation *a;uint32_t total;(void)user;
 if(allocation_fault())goto deny;
 if(n>UINT32_MAX-sizeof(*a))goto deny;
 total=n+(uint32_t)sizeof(*a);
 if((usage==Alloc_For_LinearMemory&&n>options.linear_memory_pages*65536u+16u)||total>options.memory_bytes-info.used_bytes)goto deny;
 a=malloc(total);if(!a)goto deny;a->h.size=total;a->h.tag=ALLOCATION_TAG;
 info.used_bytes+=total;if(info.used_bytes>info.peak_bytes)info.peak_bytes=info.used_bytes;return a+1;
deny:info.denied_allocations++;return NULL;
}
static void bounded_free(mem_alloc_usage_t usage,void *user,void *p){allocation *a;(void)usage;(void)user;if(!p)return;a=(allocation *)p-1;
 /* Only VM-produced allocations enter this private callback. */
 if(a->h.tag!=ALLOCATION_TAG||a->h.size>info.used_bytes)abort();
 info.used_bytes-=a->h.size;a->h.tag=0;free(a);
}
static void *bounded_realloc(mem_alloc_usage_t usage,bool mapped,void *user,void *p,unsigned n){allocation *a,*b;uint32_t total,old;(void)mapped;
 if(!p)return bounded_malloc(usage,user,n);if(!n){bounded_free(usage,user,p);return NULL;}
 if(allocation_fault())goto deny;
 a=(allocation *)p-1;if(a->h.tag!=ALLOCATION_TAG)abort();old=a->h.size;
 if(n>UINT32_MAX-sizeof(*a))goto deny;total=n+(uint32_t)sizeof(*a);
 if((usage==Alloc_For_LinearMemory&&n>options.linear_memory_pages*65536u+16u)||total>options.memory_bytes-(info.used_bytes-old))goto deny;
 b=realloc(a,total);if(!b)goto deny;b->h.size=total;b->h.tag=ALLOCATION_TAG;info.used_bytes=info.used_bytes-old+total;
 if(info.used_bytes>info.peak_bytes)info.peak_bytes=info.used_bytes;return b+1;
deny:info.denied_allocations++;return NULL;
}
static int signature(const char *s){size_t i=1;if(!s||s[0]!='(')return 0;while(i<=8&&s[i]&&strchr("iIfF",s[i]))i++;
 if(s[i]!=')')return 0;i++;return !s[i]||(strchr("iIfF",s[i])&&s[i+1]==0);
}
static int letter_kind(char c){static const char letters[]="iIfF";const char *p=strchr(letters,c);return p?(int)(p-letters):-1;}
static int bounded_name(const char *s,size_t capacity){size_t i;if(!s)return 0;for(i=0;i<capacity;i++)if(!s[i])return i>0;return 0;}
static void host_import(wasm_exec_env_t env,uint64_t *raw){import_slot *im=wasm_runtime_get_function_attachment(env);m98_wasm_value args[8],result;uint32_t i,count=0;int r;
 unsigned char internal[108] __attribute__((aligned(16))),discard[108] __attribute__((aligned(16)));
 if(!im||!im->callback||owner!=m98_wasm_thread_id()){wasm_runtime_set_exception(wasm_runtime_get_module_inst(env),"invalid owner import");return;}
 for(i=1;im->signature[i]!=')';i++){args[count].kind=(uint32_t)letter_kind(im->signature[i]);args[count].bits=raw[count];if(args[count].kind==M98_WASM_I32||args[count].kind==M98_WASM_F32)args[count].bits&=UINT32_MAX;count++;}
 result.kind=im->signature[i+1]?(uint32_t)letter_kind(im->signature[i+1]):M98_WASM_I32;result.bits=0;
 save_fp(internal);restore_fp(caller_fp);r=im->callback(im->user,args,count,&result);save_fp(discard);restore_fp(internal);
 if(r||(im->signature[i+1]&&(!numeric(result.kind)||result.kind!=(uint32_t)letter_kind(im->signature[i+1])||((result.kind==M98_WASM_I32||result.kind==M98_WASM_F32)&&result.bits>UINT32_MAX))))
  wasm_runtime_set_exception(wasm_runtime_get_module_inst(env),"host import rejected");
 else if(im->signature[i+1])raw[0]=result.bits;
}
int m98_wasm_start_budget(void){return (int)options.instruction_limit;}
int m98_wasm_open(const m98_wasm_options *o,const m98_wasm_import *im,uint32_t count,uint32_t *out){RuntimeInitArgs args;uint32_t i,j;
 if(!out||!o||count>IMPORTS||(count&&!im)||o->memory_bytes<262144||o->memory_bytes>33554432||o->stack_bytes<16384||o->stack_bytes>262144||!o->instruction_limit||o->instruction_limit>10000000||!o->linear_memory_pages||o->linear_memory_pages>256)return M98_WASM_ARGUMENT;
 for(i=0;i<count;i++){if(!bounded_name(im[i].module_name,64)||!bounded_name(im[i].name,64)||!signature(im[i].signature)||!im[i].callback)return M98_WASM_ARGUMENT;
  for(j=0;j<i;j++)if(!strcmp(im[i].module_name,im[j].module_name)&&!strcmp(im[i].name,im[j].name))return M98_WASM_ARGUMENT;}
 if(!__sync_bool_compare_and_swap(&gate,0,1))return M98_WASM_BUSY;
 if(store_token){__sync_lock_release(&gate);return M98_WASM_BUSY;}
 if(store_generation==GENERATIONS){__sync_lock_release(&gate);return M98_WASM_LIMIT;}
 save_fp(caller_fp);
 if(m98_wasm_platform_ready())return done(M98_WASM_PLATFORM);
 owner=m98_wasm_thread_id();options=*o;memset(&info,0,sizeof(info));memset(&args,0,sizeof(args));
 args.mem_alloc_type=Alloc_With_Allocator;args.mem_alloc_option.allocator.malloc_func=(void *)bounded_malloc;
 args.mem_alloc_option.allocator.realloc_func=(void *)bounded_realloc;args.mem_alloc_option.allocator.free_func=(void *)bounded_free;
 args.gc_heap_size=65536;args.running_mode=Mode_Interp;import_count=0;
 if(!wasm_runtime_full_init(&args)){memset(imports,0,sizeof(imports));diagnostic("runtime initialization failed");return done(M98_WASM_LIMIT);}
 for(i=0;i<count;i++){import_slot *p=&imports[i];memset(p,0,sizeof(*p));strcpy(p->module,im[i].module_name);strcpy(p->name,im[i].name);strcpy(p->signature,im[i].signature);p->callback=im[i].callback;p->user=im[i].user;
  p->symbol.symbol=p->name;p->symbol.func_ptr=(void *)host_import;p->symbol.signature=p->signature;p->symbol.attachment=p;
  if(!wasm_runtime_register_natives_raw(p->module,&p->symbol,1)){wasm_runtime_destroy();import_count=0;memset(imports,0,sizeof(imports));diagnostic("import registration failed");return done(M98_WASM_LINK);}import_count++;}
 store_generation++;store_token=generation_handle(store_generation,0,0);*out=store_token;return done(0);
}
static void close_instance(uint32_t i){instance_slot *p=&instances[i];if(p->env)wasm_runtime_destroy_exec_env(p->env);if(p->instance)wasm_runtime_deinstantiate(p->instance);
 if(p->instance){modules[p->module_index].instances--;info.instances--;}p->instance=NULL;p->env=NULL;
}
static void unload_module(uint32_t i){module_slot *p=&modules[i];if(p->module)wasm_runtime_unload(p->module);if(p->bytes)bounded_free(Alloc_For_Runtime,NULL,p->bytes);p->module=NULL;p->bytes=NULL;info.modules--;}
int m98_wasm_close(uint32_t h){uint32_t i;int r=enter(h);if(r)return r;
 for(i=0;i<SLOTS;i++)if(instances[i].instance)close_instance(i);
 for(i=0;i<SLOTS;i++)if(modules[i].module)unload_module(i);
 for(i=0;i<import_count;i++)wasm_runtime_unregister_natives(imports[i].module,&imports[i].symbol);
 wasm_runtime_destroy();store_token=0;import_count=0;memset(imports,0,sizeof(imports));diagnostic(info.used_bytes?"VM allocation leak after teardown":"");return done(info.used_bytes?M98_WASM_LIMIT:0);
}
int m98_wasm_load(uint32_t h,const void *bytes,uint32_t length,uint32_t *out){uint32_t i;LoadArgs args;int r=enter(h);if(r)return r;
 if(!out||!bytes||length<8||length>1048576)return done(M98_WASM_ARGUMENT);
 for(i=0;i<SLOTS;i++)if(!modules[i].module&&modules[i].generation<GENERATIONS)break;
 if(i==SLOTS)return done(M98_WASM_LIMIT);memset(&args,0,sizeof(args));args.no_resolve=true;
 modules[i].bytes=bounded_malloc(Alloc_For_Runtime,NULL,length);if(!modules[i].bytes)return done(M98_WASM_LIMIT);
 memcpy(modules[i].bytes,bytes,length);diagnostic("");modules[i].module=wasm_runtime_load_ex(modules[i].bytes,length,&args,info.diagnostic,sizeof(info.diagnostic));
 if(!modules[i].module){bounded_free(Alloc_For_Runtime,NULL,modules[i].bytes);modules[i].bytes=NULL;return done(M98_WASM_VALIDATE);}
 modules[i].generation++;modules[i].instances=0;info.modules++;*out=generation_handle(modules[i].generation,i,UINT32_C(0x40000000));return done(0);
}
int m98_wasm_unload(uint32_t h,uint32_t m){int i,r=enter(h);if(r)return r;i=module_index(m);if(i<0)return done(M98_WASM_STALE);if(modules[i].instances)return done(M98_WASM_BUSY);unload_module((uint32_t)i);return done(0);}
int m98_wasm_instantiate(uint32_t h,uint32_t m,uint32_t *out){int mi,r=enter(h);uint32_t i;if(r)return r;mi=module_index(m);if(mi<0)return done(M98_WASM_STALE);if(!out)return done(M98_WASM_ARGUMENT);
 for(i=0;i<SLOTS;i++)if(!instances[i].instance&&instances[i].generation<GENERATIONS)break;if(i==SLOTS)return done(M98_WASM_LIMIT);
 {
  int32_t count=wasm_runtime_get_import_count(modules[mi].module),j;wasm_import_t im;
  if(count<0){diagnostic("import descriptor unavailable");return done(M98_WASM_LINK);}
  if(!wasm_runtime_resolve_symbols(modules[mi].module)){diagnostic("import resolution failed");return done(M98_WASM_LINK);}
  for(j=0;j<count;j++){uint32_t k;memset(&im,0,sizeof(im));wasm_runtime_get_import_type(modules[mi].module,j,&im);
   if(im.kind!=WASM_IMPORT_EXPORT_KIND_FUNC||!im.linked){diagnostic("missing or unsupported import");return done(M98_WASM_LINK);}
   for(k=0;k<import_count;k++)if(!strcmp(imports[k].module,im.module_name)&&!strcmp(imports[k].name,im.name))break;
   if(k==import_count){diagnostic("import is not an explicit registered callback");return done(M98_WASM_LINK);}
  }
 }
 diagnostic("");instances[i].instance=wasm_runtime_instantiate(modules[mi].module,options.stack_bytes,0,info.diagnostic,sizeof(info.diagnostic));
 if(!instances[i].instance)return done(M98_WASM_LINK);
 instances[i].env=wasm_runtime_create_exec_env(instances[i].instance,options.stack_bytes);
 if(!instances[i].env){wasm_runtime_deinstantiate(instances[i].instance);instances[i].instance=NULL;return done(M98_WASM_LIMIT);}
 instances[i].module_index=(uint32_t)mi;instances[i].generation++;modules[mi].instances++;info.instances++;*out=generation_handle(instances[i].generation,i,UINT32_C(0x80000000));return done(0);
}
int m98_wasm_instance_close(uint32_t h,uint32_t instance){int i,r=enter(h);if(r)return r;i=instance_index(instance);if(i<0)return done(M98_WASM_STALE);close_instance((uint32_t)i);return done(0);}
int m98_wasm_call(uint32_t h,uint32_t instance,const char *name,const m98_wasm_value *in,uint32_t count,m98_wasm_value *out,uint32_t results){int i,r=enter(h);uint32_t k;wasm_function_inst_t f;wasm_val_t args[8],values[8];wasm_valkind_t types[8];bool ok;
 if(r)return r;i=instance_index(instance);if(i<0)return done(M98_WASM_STALE);
 if(!bounded_name(name,128)||count>8||results>8||(count&&!in)||(results&&!out))return done(M98_WASM_ARGUMENT);
 f=wasm_runtime_lookup_function(instances[i].instance,name);if(!f)return done(M98_WASM_ARGUMENT);
 if(wasm_func_get_param_count(f,instances[i].instance)!=count||wasm_func_get_result_count(f,instances[i].instance)!=results)return done(M98_WASM_TYPE);
 wasm_func_get_param_types(f,instances[i].instance,types);
 for(k=0;k<count;k++){if(!numeric(in[k].kind)||types[k]!=(wasm_valkind_t)in[k].kind||((in[k].kind==M98_WASM_I32||in[k].kind==M98_WASM_F32)&&in[k].bits>UINT32_MAX))return done(M98_WASM_TYPE);args[k].kind=(wasm_valkind_t)in[k].kind;memset(&args[k].of,0,sizeof(args[k].of));memcpy(&args[k].of,&in[k].bits,in[k].kind==M98_WASM_I32||in[k].kind==M98_WASM_F32?4:8);}
 wasm_func_get_result_types(f,instances[i].instance,types);for(k=0;k<results;k++)if(!numeric((uint32_t)types[k]))return done(M98_WASM_TYPE);
 diagnostic("");wasm_runtime_clear_exception(instances[i].instance);wasm_runtime_set_instruction_count_limit(instances[i].env,(int)options.instruction_limit);
 ok=wasm_runtime_call_wasm_a(instances[i].env,f,results,values,count,args);
 if(!ok){diagnostic(wasm_runtime_get_exception(instances[i].instance));return done(M98_WASM_TRAP);}
 for(k=0;k<results;k++){out[k].kind=(uint32_t)values[k].kind;out[k].bits=0;memcpy(&out[k].bits,&values[k].of,out[k].kind==M98_WASM_I32||out[k].kind==M98_WASM_F32?4:8);}return done(0);
}
static wasm_memory_inst_t memory(uint32_t inst,uint32_t index){int i=instance_index(inst);if(i<0)return NULL;return wasm_runtime_get_memory(instances[i].instance,index);}
int m98_wasm_memory_size(uint32_t h,uint32_t inst,uint32_t index,uint32_t *pages){wasm_memory_inst_t m;int r=enter(h);if(r)return r;if(!pages)return done(M98_WASM_ARGUMENT);m=memory(inst,index);if(!m)return done(M98_WASM_RANGE);*pages=(uint32_t)wasm_memory_get_cur_page_count(m);return done(0);}
int m98_wasm_memory_grow(uint32_t h,uint32_t inst,uint32_t index,uint32_t pages,int32_t *old){wasm_memory_inst_t m;uint64_t current;int r=enter(h);if(r)return r;if(!old)return done(M98_WASM_ARGUMENT);m=memory(inst,index);if(!m)return done(M98_WASM_RANGE);current=wasm_memory_get_cur_page_count(m);*old=-1;
 if(current+pages<=options.linear_memory_pages&&wasm_memory_enlarge(m,pages))*old=(int32_t)current;return done(0);
}
static int transfer(uint32_t h,uint32_t inst,uint32_t index,uint32_t offset,void *p,uint32_t length,int write){wasm_memory_inst_t m;uint64_t size;uint8_t *base;int r=enter(h);if(r)return r;if(length&&!p)return done(M98_WASM_ARGUMENT);m=memory(inst,index);if(!m)return done(M98_WASM_RANGE);
 size=wasm_memory_get_cur_page_count(m)*wasm_memory_get_bytes_per_page(m);if((uint64_t)offset+length>size)return done(M98_WASM_RANGE);base=wasm_memory_get_base_address(m);
 if(length){if(write)memcpy(base+offset,p,length);else memcpy(p,base+offset,length);}return done(0);
}
int m98_wasm_memory_read(uint32_t h,uint32_t inst,uint32_t index,uint32_t offset,void *p,uint32_t length){return transfer(h,inst,index,offset,p,length,0);}
int m98_wasm_memory_write(uint32_t h,uint32_t inst,uint32_t index,uint32_t offset,const void *p,uint32_t length){return transfer(h,inst,index,offset,(void *)p,length,1);}
int m98_wasm_inspect(uint32_t h,m98_wasm_info *out){int r=enter(h);if(r)return r;if(!out)return done(M98_WASM_ARGUMENT);*out=info;return done(0);}
