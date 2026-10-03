/* SPDX-License-Identifier: GPL-2.0-only
 * Production VM entry/typed ref/handle lifecycle bodies and complete schemas.
 * IRQ/current thread, account admission and caller-copy timing are adapters.
 * The locked VAD boundary records arguments and supplies controlled results;
 * this checks API admission and lifetime, not a page allocator or Windows98.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntsys.h"
#include "layouts.inc"
#define CURRENT_PROCESS_HANDLE UINT64_MAX
#define CURRENT_THREAD_HANDLE UINT64_C(0xfffffffffffffffe)
static unsigned checks,failures,irq_depth,reads,writes,vad_calls,live_allocations;
#define CHECK(x) do { ++checks; if(!(x)){++failures;fprintf(stderr,"line %d: %s\n",__LINE__,#x);} } while(0)
#define KASSERT(x) CHECK(x)
static process_t caller,target;
static thread_t caller_thread;
static kobject_t *target_object,*named_head,*timers_head[16];
static unsigned timer_count,op,fail_read,fail_write,departure,depart_read;
static unsigned held_input,held_output,held_vad,guard_vad;
static uint32_t handle;
static int deny_account,target_root;
static int32_t vad_result;
static uint64_t base,size;
static uint32_t old;
static const uint64_t input_base=0x12345,input_size=0x2345;
static const uint64_t out_base=0x70000,out_size=0x6000;
static const uint32_t out_old=0x20;
enum { CLOSE=1,TEARDOWN,DETACH,REUSE,SPACE_CHANGE,EXIT,OUTPUT_DETACH };
void ob_ref(kobject_t *o);
void ob_deref(kobject_t *o);
int32_t handle_close(process_t *p,uint64_t h);
void vad_destroy(process_t *p);
static uint64_t irq_save(void){return irq_depth++;}
static void irq_restore(uint64_t f){CHECK(irq_depth==f+1);irq_depth=(unsigned)f;}
static thread_t *thread_current(void){return &caller_thread;}
static void *kzalloc(size_t n){void*p=calloc(1,n);CHECK(p!=NULL);if(p)++live_allocations;return p;}
static void kfree(void*p){if(p){CHECK(live_allocations>0);--live_allocations;free(p);}}
static void kprintf(const char*fmt,...){(void)fmt;CHECK(0);}
static void reg_key_object_free(kobject_t*o){(void)o;CHECK(0);}
static void token_object_free(kobject_t*o){(void)o;CHECK(0);}
static void ipc_handle_closed(process_t*p,kobject_t*o){(void)p;(void)o;}
static void file_object_closed(kobject_t*o){(void)o;CHECK(0);}
static void net_socket_handle_closing(kobject_t*o){(void)o;CHECK(0);}
static void ntdrv_device_handle_closing(kobject_t*o){(void)o;CHECK(0);}
static void shz_auth_process_gone(process_t*p){(void)p;}
static int shz_auth_process_access(process_t*a,process_t*b){return b&&(!deny_account||a==b);}
static int shz_auth_thread_access(process_t*p,uint64_t pid){return pid==(uint64_t)caller.pid&&p==&caller;}
static int shz_auth_special_allowed(process_t*p,uint32_t type){(void)p;(void)type;return 0;}
static int shz_auth_handle_allowed(process_t*p,kobject_t*o){return o->type==OB_PROCESS?shz_auth_process_access(p,o->u.proc.p):1;}
/* @OBJECT_FREE@ */
/* @OBJECT_BODIES@ */
/* @IPC_BODIES@ */
static void depart(unsigned mode){
    if(mode==CLOSE)CHECK(handle_close(&caller,handle)==0);
    if(mode==TEARDOWN)target.teardown=1;
    if(mode==EXIT)target.terminated=1;
    if(mode==SPACE_CHANGE)target.pml4=0x99000;
    if(mode==REUSE)target.object=caller.object;
    if(mode==DETACH||mode==OUTPUT_DETACH){
        target.teardown=2;target.pml4=0;
        CHECK(handle_close(&caller,handle)==0);
        ob_deref(target_object);target_root=0;
    }
}
static int copy_from_user(process_t*p,void*dst,uint64_t src,uint64_t n){
    (void)p;CHECK(!irq_depth);++reads;
    if(reads==1)held_input=target_object->refs;
    if(departure&&reads==depart_read){unsigned mode=departure;departure=0;depart(mode);}
    if(fail_read==reads||!src)return -1;
    memcpy(dst,(const void*)(uintptr_t)src,(size_t)n);return 0;
}
static int copy_to_user(process_t*p,uint64_t dst,const void*src,uint64_t n){
    (void)p;CHECK(!irq_depth);++writes;held_output=target.used&&target.object==target_object?target_object->refs:0;
    if(departure==OUTPUT_DETACH){departure=0;depart(OUTPUT_DETACH);}
    if(fail_write==writes||!dst)return -1;
    memcpy((void*)(uintptr_t)dst,src,(size_t)n);return 0;
}
static int32_t boundary(process_t*p,uint64_t*b,uint64_t*s,uint32_t type,uint32_t prot,uint32_t kind,uint32_t*before){
    ++vad_calls;guard_vad=irq_depth;held_vad=p->used&&p->object==target_object?target_object->refs:0;
    CHECK(p==&target||p==&caller);CHECK(p->used);CHECK(!p->teardown&&!p->terminated&&p->pml4);
    CHECK(*b==input_base&&*s==input_size);CHECK(type==(op==1?0x8000u:0x3000u));
    if(op!=1)CHECK(prot==4);
    if(op==0)CHECK(kind==VK_PRIVATE);
    *b=out_base;*s=out_size;if(before)*before=out_old;
    return vad_result;
}
static int32_t vad_alloc_locked(process_t*p,uint64_t*b,uint64_t*s,uint32_t type,uint32_t prot,uint32_t kind){return boundary(p,b,s,type,prot,kind,NULL);}
static int32_t vad_free_locked(process_t*p,uint64_t*b,uint64_t*s,uint32_t type){return boundary(p,b,s,type,0,0,NULL);}
static int32_t vad_protect_locked(process_t*p,uint64_t*b,uint64_t*s,uint32_t prot,uint32_t*before){return boundary(p,b,s,0x3000,prot,0,before);}
/* @VAD_BODIES@ */
/* @VM_BODIES@ */
static int32_t call(uint64_t h){
    if(op==0)return sys_allocate_vm(&caller,h,(uintptr_t)&base,0x123,(uintptr_t)&size,UINT64_C(0x100003000),UINT64_C(0x100000004));
    if(op==1)return sys_free_vm(&caller,h,(uintptr_t)&base,(uintptr_t)&size,UINT64_C(0x100008000));
    return sys_protect_vm(&caller,h,(uintptr_t)&base,(uintptr_t)&size,UINT64_C(0x100000004),(uintptr_t)&old);
}
static void init(void){
    memset(&caller,0,sizeof caller);memset(&target,0,sizeof target);memset(&caller_thread,0,sizeof caller_thread);
    reads=writes=vad_calls=irq_depth=held_input=held_output=held_vad=guard_vad=0;
    deny_account=0;departure=depart_read=fail_read=fail_write=0;vad_result=0;target_root=1;
    caller.used=target.used=1;caller.pid=4;target.pid=8;caller.pml4=0x1000;target.pml4=0x2000;
    caller.handles=kzalloc(sizeof(handle_entry_t)*4);caller.handle_cap=4;
    caller.object=ob_create(OB_PROCESS,NULL);caller.object->u.proc.p=&caller;
    target.object=ob_create(OB_PROCESS,NULL);target.object->u.proc.p=&target;target_object=target.object;
    caller_thread.proc=&caller;caller_thread.object=ob_create(OB_THREAD,NULL);
    caller_thread.object->u.thr.pid=(uint64_t)caller.pid;
    CHECK(handle_insert(&caller,target.object,8,&handle)==0);
    base=input_base;size=input_size;old=0xfeed;
}
static void finish(void){
    target.object=target_object;
    for(unsigned i=0;i<caller.handle_cap;++i)if(caller.handles[i].obj)CHECK(handle_close(&caller,(i+1)*4u)==0);
    if(target_root){target.teardown=2;ob_deref(target_object);}
    ob_deref(caller_thread.object);caller.teardown=2;ob_deref(caller.object);
    CHECK(!irq_depth);CHECK(!live_allocations);
}
static void denied(int32_t wanted,uint64_t h){CHECK(call(h)==wanted);CHECK(!reads&&!writes&&!vad_calls);CHECK(base==input_base&&size==input_size&&old==0xfeed);CHECK(target_object->refs==2);}
static void run_case(const char*name){
    init();unsigned refs=2;
    if(!strcmp(name,"zero")||!strcmp(name,"query")||!strcmp(name,"read")||!strcmp(name,"write")||!strcmp(name,"sync")){
        caller.handles[0].access=!strcmp(name,"zero")?0:!strcmp(name,"query")?0x400:!strcmp(name,"read")?0x10:!strcmp(name,"write")?0x20:0x100000;
        denied(STATUS_ACCESS_DENIED,handle);
    }else if(!strcmp(name,"foreign")){deny_account=1;denied(STATUS_ACCESS_DENIED,handle);
    }else if(!strcmp(name,"typed")){uint32_t h;CHECK(handle_insert(&caller,caller_thread.object,8,&h)==0);denied(STATUS_OBJECT_TYPE_MISMATCH,h);
    }else if(!strcmp(name,"invalid")){denied(STATUS_INVALID_HANDLE,128);
    }else if(!strcmp(name,"stale")){target.object=caller.object;denied(STATUS_INVALID_HANDLE,handle);
    }else if(!strcmp(name,"space-zero")){target.pml4=0;denied(STATUS_INVALID_HANDLE,handle);
    }else if(!strcmp(name,"pre-teardown")){target.teardown=1;denied(STATUS_PROCESS_IS_TERMINATING,handle);
    }else if(!strcmp(name,"in1")||!strcmp(name,"in2")){
        fail_read=!strcmp(name,"in1")?1:2;CHECK(call(handle)==STATUS_ACCESS_VIOLATION);CHECK(reads==fail_read&&!vad_calls&&!writes);CHECK(held_input==3);CHECK(target_object->refs==refs);
    }else if(!strcmp(name,"out1")||!strcmp(name,"out2")||!strcmp(name,"out-old")){
        fail_write=!strcmp(name,"out1")?1:!strcmp(name,"out2")?2:(op==2?3:2);CHECK(call(handle)==STATUS_ACCESS_VIOLATION);CHECK(vad_calls==1&&writes==fail_write);CHECK(held_input==3&&held_output==3);CHECK(target_object->refs==refs);
    }else if(!strcmp(name,"vad-error")){
        vad_result=STATUS_INVALID_PARAMETER;CHECK(call(handle)==vad_result);CHECK(vad_calls==1&&!writes);CHECK(held_input==3&&held_vad==3);CHECK(target_object->refs==refs);
    }else if(!strcmp(name,"teardown1")||!strcmp(name,"teardown2")||!strcmp(name,"detach")||!strcmp(name,"reuse")||!strcmp(name,"space-change")||!strcmp(name,"exit")){
        departure=!strcmp(name,"detach")?DETACH:!strcmp(name,"reuse")?REUSE:!strcmp(name,"space-change")?SPACE_CHANGE:!strcmp(name,"exit")?EXIT:TEARDOWN;
        depart_read=!strcmp(name,"teardown1")?1:2;
        CHECK(call(handle)==(!strcmp(name,"reuse")||!strcmp(name,"space-change")?STATUS_INVALID_HANDLE:STATUS_PROCESS_IS_TERMINATING));CHECK(!vad_calls&&!writes);CHECK(held_input==3);
        if(target_root)CHECK(target_object->refs==refs);else CHECK(!target.used);
    }else if(!strcmp(name,"close")||!strcmp(name,"out-detach")||!strcmp(name,"valid")||!strcmp(name,"tagged")||!strcmp(name,"pseudo")){
        if(!strcmp(name,"close")){departure=CLOSE;depart_read=1;refs=1;}
        if(!strcmp(name,"out-detach"))departure=OUTPUT_DETACH;
        uint64_t h=!strcmp(name,"pseudo")?CURRENT_PROCESS_HANDLE:!strcmp(name,"tagged")?handle|1u:handle;
        CHECK(call(h)==0);CHECK(vad_calls==1&&reads==2&&writes==(op==2?3u:2u));CHECK(base==out_base&&size==out_size);CHECK(old==(op==2?out_old:0xfeed));CHECK(guard_vad>=2);
        if(strcmp(name,"pseudo")){CHECK(held_input==3&&held_vad>=2);if(target_root)CHECK(target_object->refs==refs);else CHECK(!target.used);}
    }else CHECK(0);
    finish();
}
int main(void){
    static const char*cases[]={"zero","query","read","write","sync","foreign","typed","invalid","stale","space-zero","pre-teardown","in1","in2","out1","out2","out-old","vad-error","teardown1","teardown2","detach","reuse","space-change","exit","close","out-detach","valid","tagged","pseudo"};
    for(op=0;op<3;++op)for(unsigned i=0;i<sizeof cases/sizeof cases[0];++i){unsigned before=failures;run_case(cases[i]);if(failures!=before)fprintf(stderr,"VM case %u %s failed\n",op,cases[i]);}
    printf("VM_OPERATION_HOST: %u cases, %u checks, %u failures\n",3u*(unsigned)(sizeof cases/sizeof cases[0]),checks,failures);
    return failures?1:0;
}
