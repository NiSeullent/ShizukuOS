/* SPDX-License-Identifier: GPL-2.0-only
 * Actual GetContextThread, object/handle reference and thread-detach bodies.
 * IRQ/current-thread, account admission, heap and user-copy boundaries are
 * host adapters. Real heap frees expose missing object holds under ASan.
 * This is UP Kernel64 component evidence, not native Windows98 acceptance.
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
static unsigned checks, failures, irq_depth, reads, writes, live_objects;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; fprintf(stderr,"line %d: %s\n",__LINE__,#x); } } while (0)
#define KASSERT(x) CHECK(x)
static process_t caller, owner;
static thread_t caller_t, target_t, *current;
static handle_entry_t entries[4];
static kobject_t *named_head, *timers_head[16];
static unsigned timer_count;
static uint32_t target_handle;
static int fail_in, fail_out, deny_account, departure;
static unsigned held_at_copy;
static uint8_t context[0x4d0], original[0x4d0];
static uint8_t stack[32768] __attribute__((aligned(16)));
enum { CLOSE=1, DETACH, ZOMBIE, FREE_SLOT, REUSE_SLOT, WRONG_OWNER, OWNER_EXIT };
void ob_ref(kobject_t *o);
void ob_deref(kobject_t *o);
void thread_object_detach(thread_t *t);
int32_t handle_close(process_t *p,uint64_t h);
static uint64_t irq_save(void) { return irq_depth++; }
static void irq_restore(uint64_t f) { CHECK(irq_depth==f+1); irq_depth=(unsigned)f; }
static thread_t *thread_current(void) { return current; }
static void *kzalloc(size_t n) { void *p=calloc(1,n); CHECK(p!=NULL); if(p)++live_objects; return p; }
static void kfree(void *p) { if(p) { CHECK(live_objects>0); --live_objects; free(p); } }
static void reg_key_object_free(kobject_t *o) { (void)o; CHECK(0); }
static void token_object_free(kobject_t *o) { (void)o; CHECK(0); }
static void ipc_object_free(kobject_t *o) { (void)o; }
static void ipc_handle_closed(process_t *p,kobject_t *o) { (void)p;(void)o; }
static void file_object_closed(kobject_t *o) { (void)o; CHECK(0); }
static void net_socket_handle_closing(kobject_t *o) { (void)o; CHECK(0); }
static void ntdrv_device_handle_closing(kobject_t *o) { (void)o; CHECK(0); }
static int shz_auth_process_access(process_t *p,process_t *q) { return q && (!deny_account || p==q); }
static int shz_auth_thread_access(process_t *p,uint64_t pid) { return shz_auth_process_access(p,pid==(uint64_t)owner.pid?&owner:pid==(uint64_t)caller.pid?&caller:NULL); }
static int shz_auth_handle_allowed(process_t *p,kobject_t *o) {
    return o->type==OB_THREAD?shz_auth_thread_access(p,o->u.thr.pid):o->type==OB_PROCESS?shz_auth_process_access(p,o->u.proc.p):1;
}
static int shz_auth_special_allowed(process_t *p,uint32_t type) { (void)p;(void)type; return 0; }
static void depart(void) {
    int mode=departure; departure=0;
    if(mode==CLOSE) CHECK(handle_close(&caller,target_handle)==0);
    if(mode==DETACH) {
        CHECK(handle_close(&caller,target_handle)==0);
        thread_object_detach(&target_t);
        target_t.state=TS_FREE;
    }
    if(mode==ZOMBIE) target_t.state=TS_ZOMBIE;
    if(mode==FREE_SLOT) target_t.state=TS_FREE;
    if(mode==REUSE_SLOT) { target_t.object=caller_t.object; target_t.proc=&caller; target_t.tid=caller_t.tid; }
    if(mode==WRONG_OWNER) target_t.proc=&caller;
    if(mode==OWNER_EXIT) owner.terminated=1;
}
static int copy_from_user(process_t *p,void *dst,uint64_t src,uint64_t n) {
    (void)p; CHECK(!irq_depth); ++reads;
    if(target_t.object) held_at_copy=target_t.object->refs;
    if(departure) depart();
    if(fail_in || !src)return -1;
    memcpy(dst,(const void*)(uintptr_t)src,(size_t)n);return 0;
}
static int copy_to_user(process_t *p,uint64_t dst,const void *src,uint64_t n) {
    (void)p; CHECK(!irq_depth); ++writes;
    if(fail_out || !dst)return -1;
    memcpy((void*)(uintptr_t)dst,src,(size_t)n);return 0;
}
/* @OBJECT_BODIES@ */
/* @IPC_REF_BODY@ */
/* @CONTEXT_BODY@ */

static void init(uint32_t rights) {
    memset(&caller,0,sizeof caller);memset(&owner,0,sizeof owner);
    memset(&caller_t,0,sizeof caller_t);memset(&target_t,0,sizeof target_t);
    memset(entries,0,sizeof entries);memset(stack,0,sizeof stack);
    reads=writes=irq_depth=held_at_copy=0;fail_in=fail_out=deny_account=departure=0;
    caller.used=owner.used=1;caller.pid=4;owner.pid=12;
    caller.handles=entries;caller.handle_cap=4;
    caller.object=ob_create(OB_PROCESS,NULL);caller.object->u.proc.p=&caller;
    owner.object=ob_create(OB_PROCESS,NULL);owner.object->u.proc.p=&owner;
    caller_t.proc=&caller;caller_t.state=TS_RUNNING;caller_t.tid=8;caller_t.teb=0x10000;
    caller_t.object=ob_create(OB_THREAD,NULL);caller_t.object->u.thr.t=&caller_t;
    caller_t.object->u.thr.pid=(uint64_t)caller.pid;caller_t.object->u.thr.tid=caller_t.tid;
    ob_ref(caller.object);
    target_t.proc=&owner;target_t.state=TS_BLOCKED;target_t.tid=16;target_t.teb=0x20000;
    target_t.object=ob_create(OB_THREAD,NULL);target_t.object->u.thr.t=&target_t;
    target_t.object->u.thr.pid=(uint64_t)owner.pid;target_t.object->u.thr.tid=target_t.tid;
    ob_ref(owner.object);
    current=&caller_t;target_t.stack_base=(uintptr_t)stack;target_t.cycles=1;
    caller_t.stack_base=(uintptr_t)stack;
    struct regs f={0};uint64_t *words=(uint64_t*)&f;
    for(unsigned i=0;i<sizeof f/8;++i)words[i]=UINT64_C(0x1100000000000000)+i;
    f.cs=0x23;f.ss=0x1b;f.rflags=0x246;
    memcpy(stack+sizeof stack-sizeof f,&f,sizeof f);
    for(unsigned i=0;i<sizeof target_t.fx;++i)target_t.fx[i]=(uint8_t)(i*7+3);
    CHECK(handle_insert(&caller,target_t.object,rights,&target_handle)==0);
    memset(context,0xa5,sizeof context);uint32_t flags=0x10001f;memcpy(context+0x30,&flags,4);
    memcpy(original,context,sizeof original);
}
static void finish(void) {
    for(unsigned i=0;i<caller.handle_cap;++i)if(entries[i].obj)CHECK(handle_close(&caller,(i+1)*4u)==0);
    /* A synthetic reciprocal/owner mismatch is restored only for real detach. */
    if(target_t.object==caller_t.object)target_t.object=NULL;
    if(target_t.object) {target_t.proc=&owner;thread_object_detach(&target_t);}
    thread_object_detach(&caller_t);
    ob_deref(owner.object);ob_deref(caller.object);
    CHECK(!irq_depth);CHECK(!live_objects);
}
static int32_t call(uint64_t h) {return k32_get_context_thread(&caller,h,(uintptr_t)context);}
static void unchanged(int32_t wanted,uint64_t h) {CHECK(call(h)==wanted);CHECK(!writes);CHECK(!memcmp(context,original,sizeof context));}
static void oracle(uint8_t out[0x4d0],unsigned flags,int initial) {
    memcpy(out,original,sizeof original);
    struct regs f;memcpy(&f,stack+sizeof stack-sizeof f,sizeof f);
    if(initial){memset(&f,0,sizeof f);f.rip=target_t.user_rip;f.rsp=target_t.user_rsp;f.rcx=target_t.user_arg;f.rdx=target_t.user_arg2;f.rflags=0x202;}
    if(flags&1){uint16_t v=0x23;memcpy(out+0x38,&v,2);v=0x1b;memcpy(out+0x42,&v,2);uint32_t rf=(uint32_t)f.rflags;memcpy(out+0x44,&rf,4);memcpy(out+0x98,&f.rsp,8);memcpy(out+0xf8,&f.rip,8);}
    if(flags&2){const unsigned offsets[]={0x78,0x80,0x88,0x90,0xa0,0xa8,0xb0,0xb8,0xc0,0xc8,0xd0,0xd8,0xe0,0xe8,0xf0};const uint64_t values[]={f.rax,f.rcx,f.rdx,f.rbx,f.rbp,f.rsi,f.rdi,f.r8,f.r9,f.r10,f.r11,f.r12,f.r13,f.r14,f.r15};for(unsigned i=0;i<15;++i)memcpy(out+offsets[i],values+i,8);}
    if(flags&4){uint16_t v=0x1b;for(unsigned i=0;i<4;++i)memcpy(out+0x3a+i*2,&v,2);}
    if(flags&8){memcpy(out+0x34,target_t.fx+24,4);memcpy(out+0x100,target_t.fx,512);}
    if(flags&16)memset(out+0x48,0,48);
}
static void run_case(const char *name) {
    const uint32_t get=8u;init(get);
    kobject_t *target_object=target_t.object;
    if(!strcmp(name,"zero")||!strcmp(name,"query")||!strcmp(name,"sync")) {
        entries[0].access=!strcmp(name,"zero")?0:!strcmp(name,"query")?0x40u:0x100000u;
        unchanged(STATUS_ACCESS_DENIED,target_handle);CHECK(!reads);CHECK(target_object->refs==2);
    } else if(!strcmp(name,"typed")) {
        uint32_t h;CHECK(handle_insert(&caller,caller.object,get,&h)==0);unchanged(STATUS_OBJECT_TYPE_MISMATCH,h);CHECK(!reads);
    } else if(!strcmp(name,"invalid")) {
        unchanged(STATUS_INVALID_HANDLE,256);CHECK(!reads);
    } else if(!strcmp(name,"foreign")) {
        deny_account=1;unchanged(STATUS_ACCESS_DENIED,target_handle);CHECK(!reads);CHECK(target_object->refs==2);
    } else if(!strcmp(name,"input-fault")) {
        fail_in=1;unchanged(STATUS_ACCESS_VIOLATION,target_handle);CHECK(held_at_copy==3);CHECK(target_object->refs==2);
    } else if(!strcmp(name,"output-fault")) {
        fail_out=1;CHECK(call(target_handle)==STATUS_ACCESS_VIOLATION);CHECK(writes==1);CHECK(!memcmp(context,original,sizeof context));CHECK(held_at_copy==3);CHECK(target_object->refs==2);
    } else if(!strcmp(name,"flags")) {
        uint32_t v=0x1f;memcpy(context+0x30,&v,4);memcpy(original,context,sizeof original);
        unchanged(STATUS_INVALID_PARAMETER,target_handle);CHECK(held_at_copy==3);CHECK(target_object->refs==2);
    } else if(!strcmp(name,"close")) {
        uint8_t expect[sizeof context];oracle(expect,31,0);departure=CLOSE;CHECK(call(target_handle)==0);CHECK(held_at_copy==3);CHECK(target_object->refs==1);CHECK(!memcmp(context,expect,sizeof context));
    } else if(!strcmp(name,"detach")) {
        departure=DETACH;unchanged(STATUS_THREAD_IS_TERMINATING,target_handle);CHECK(held_at_copy==3);
    } else if(!strcmp(name,"zombie")||!strcmp(name,"free")||!strcmp(name,"reuse")||!strcmp(name,"owner")||!strcmp(name,"owner-exit")) {
        departure=!strcmp(name,"zombie")?ZOMBIE:!strcmp(name,"free")?FREE_SLOT:!strcmp(name,"reuse")?REUSE_SLOT:!strcmp(name,"owner")?WRONG_OWNER:OWNER_EXIT;
        unchanged(!strcmp(name,"zombie")||!strcmp(name,"owner-exit")?STATUS_THREAD_IS_TERMINATING:STATUS_INVALID_HANDLE,target_handle);CHECK(held_at_copy==3);CHECK(target_object->refs==2);
        if(!strcmp(name,"reuse")) {target_t.object=target_object;target_t.proc=&owner;}
    } else if(!strcmp(name,"pseudo-owner")||!strcmp(name,"pseudo-type")||!strcmp(name,"pseudo-null")) {
        if(!strcmp(name,"pseudo-owner"))caller_t.proc=&owner;
        else if(!strcmp(name,"pseudo-type"))caller_t.object->type=OB_EVENT;
        else current=NULL;
        unchanged(!strcmp(name,"pseudo-type")?STATUS_OBJECT_TYPE_MISMATCH:STATUS_INVALID_HANDLE,CURRENT_THREAD_HANDLE);CHECK(!reads);
        current=&caller_t;caller_t.proc=&caller;caller_t.object->type=OB_THREAD;
    } else if(!strcmp(name,"valid")||!strcmp(name,"initial")||!strcmp(name,"masked")) {
        unsigned mask=!strcmp(name,"masked")?2u:31u;uint32_t flags=0x100000u|mask;memcpy(context+0x30,&flags,4);memcpy(original,context,sizeof original);
        int initial=!strcmp(name,"initial");if(initial){target_t.cycles=0;target_t.user_rip=0x400123;target_t.user_rsp=0x7ff012;target_t.user_arg=0x11;target_t.user_arg2=0x22;}
        uint8_t expect[sizeof context];oracle(expect,mask,initial);CHECK(call(target_handle)==0);CHECK(held_at_copy==3);CHECK(reads==1&&writes==1);CHECK(target_object->refs==2);CHECK(!memcmp(context,expect,sizeof context));
    } else CHECK(0);
    finish();
}
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    run_case(argv[1]);
    printf("GET_CONTEXT_HOST %s: %u checks, %u failures\n",argv[1],checks,failures);
    return failures?1:0;
}
