/* SPDX-License-Identifier: GPL-2.0-only */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef WINVER
#define WINVER 0x0410
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif
#endif
#include "tls_remote.h"

static int fail(const char **error,const char *reason)
{if(error)*error=reason;return 0;}
static void copy(void *out,const void *in,uint32_t bytes)
{uint32_t i;for(i=0;i<bytes;i++)((unsigned char *)out)[i]=((const unsigned char *)in)[i];}
typedef struct remote_context {
    const ntw_tls_ops *original;
    const ntw_tls_remote_io *io;
    ntw_tls_plan *plan;
    ntw_tls_thread *thread;
} remote_context;
static void *allocate(void *opaque,uint32_t bytes)
{remote_context *c=opaque;return c->original->allocate(c->original->context,bytes);}
static void deallocate(void *opaque,void *data)
{remote_context *c=opaque;c->original->deallocate(c->original->context,data);}
static uint32_t owner(void *opaque)
{remote_context *c=opaque;return c->io->owner;}
static int read_slot(void *opaque,uint32_t index,void **value)
{remote_context *c=opaque;return c->io->read(c->io->context,index,value);}
static int publish(void *opaque,uint32_t index,void *value)
{
    remote_context *c=opaque;uint32_t i;
    for(i=0;i<c->plan->count;i++)if(c->plan->module[i].slot==index){
        void *data=c->thread->data[i];
        if(!data||(value&&value!=data))return 0;
        return c->io->replace(c->io->context,index,value?NULL:data,value);
    }
    return 0;
}
static int proxy_plan(ntw_tls_plan *plan,ntw_tls_plan *proxy,remote_context *context,
                      ntw_tls_thread *thread,const ntw_tls_remote_io *io,const char **error)
{
    if(!plan||!plan->ready||plan->count>NTW_TLS_MODULES||!thread||!io||!io->owner||
       !io->read||!io->replace||!plan->ops.allocate||!plan->ops.deallocate)
        return fail(error,"TLS_REMOTE_INVALID_PLAN_OR_TARGET");
    copy(proxy,plan,sizeof(*proxy));
    context->original=&plan->ops;context->io=io;context->plan=plan;context->thread=thread;
    proxy->ops.context=context;proxy->ops.allocate=allocate;proxy->ops.deallocate=deallocate;
    proxy->ops.thread_id=owner;proxy->ops.read=read_slot;proxy->ops.publish=publish;
    /* Reservation and disposal remain exclusively on the actual plan backend.
     * The proxy is borrowed only by attach/detach, never prepare or dispose.
     */
    proxy->ops.reserve=NULL;proxy->ops.release=NULL;
    return 1;
}
int ntw_tls_remote_attach(ntw_tls_plan *plan,ntw_tls_thread *thread,
                         const ntw_tls_remote_io *io,const char **error)
{
    ntw_tls_plan proxy;remote_context context;int result;
    if(!thread||thread->active)return fail(error,"TLS_REMOTE_THREAD_ALREADY_ATTACHED_OR_NULL");
    if(!proxy_plan(plan,&proxy,&context,thread,io,error))return 0;
    result=ntw_tls_attach(&proxy,thread,error);
    plan->live_threads=proxy.live_threads;
    /* The engine can retain active storage after a failed rollback. Never
     * leave its plan pointing at a stack proxy, even on that failure path.
     */
    if(thread->active)thread->plan=plan;
    return result;
}
int ntw_tls_remote_detach(ntw_tls_thread *thread,const ntw_tls_remote_io *io,const char **error)
{
    ntw_tls_plan *plan,proxy;remote_context context;int result;
    if(!thread||!thread->active||!thread->plan||!io||thread->owner!=io->owner)
        return fail(error,"TLS_REMOTE_WRONG_OR_INACTIVE_TARGET");
    plan=thread->plan;
    if(!plan->live_threads)return fail(error,"TLS_REMOTE_INVALID_LIVE_COUNT");
    if(!proxy_plan(plan,&proxy,&context,thread,io,error))return 0;
    thread->plan=&proxy;result=ntw_tls_detach(thread,error);
    plan->live_threads=proxy.live_threads;
    if(thread->active)thread->plan=plan;
    return result;
}

#ifdef _WIN32
#include <windows.h>
_Static_assert(sizeof(void *)==4,"remote Win98 TLS requires PE32");
static int native_address(ntw_tls_native_target *target,uint32_t index,void ***slot)
{
    uint32_t vector;SIZE_T got=0;MEMORY_BASIC_INFORMATION region;uintptr_t address;
    if(!target||!target->admitted||!target->owner||index>=80||
       target->tib>UINT32_MAX-0x88||target->vector!=target->tib+0x88||
       target->vector>UINT32_MAX-80*4||
       !ReadProcessMemory(GetCurrentProcess(),(void *)(UINT_PTR)(target->tib+0x2c),
                          &vector,4,&got)||got!=4||vector!=target->vector)return 0;
    address=vector+4*index;
    if(address%4||VirtualQuery((void *)address,&region,sizeof(region))!=sizeof(region)||
       region.State!=MEM_COMMIT||(region.Protect&PAGE_GUARD)||
       !((region.Protect&0xff)==PAGE_READWRITE||(region.Protect&0xff)==PAGE_WRITECOPY||
         (region.Protect&0xff)==PAGE_EXECUTE_READWRITE||(region.Protect&0xff)==PAGE_EXECUTE_WRITECOPY)||
       (uintptr_t)region.BaseAddress>address||region.RegionSize<4||
       address-(uintptr_t)region.BaseAddress>region.RegionSize-4)return 0;
    *slot=(void **)address;return 1;
}
static int native_read(void *opaque,uint32_t index,void **value)
{
    void **slot;SIZE_T got=0;
    if(!value||!native_address(opaque,index,&slot))return 0;
    return ReadProcessMemory(GetCurrentProcess(),slot,value,4,&got)&&got==4;
}
static int native_replace(void *opaque,uint32_t index,void *expected,void *replacement)
{
    void **slot,*observed;SIZE_T got=0;LONG prior;
    if(!native_address(opaque,index,&slot))return 0;
    prior=InterlockedCompareExchange((LONG *)slot,(LONG)(UINT_PTR)replacement,(LONG)(UINT_PTR)expected);
    if((void *)(UINT_PTR)(DWORD)prior!=expected)return 0;
    if(ReadProcessMemory(GetCurrentProcess(),slot,&observed,4,&got)&&got==4&&observed==replacement)return 1;
    /* Failure must restore the previous value before the engine frees memory.
     * Stop the private process if this explicit native ownership contract was
     * violated; never free memory that could remain visible to a target.
     */
    prior=InterlockedCompareExchange((LONG *)slot,(LONG)(UINT_PTR)expected,(LONG)(UINT_PTR)replacement);
    if((void *)(UINT_PTR)(DWORD)prior!=replacement||
       !ReadProcessMemory(GetCurrentProcess(),slot,&observed,4,&got)||got!=4||observed!=expected)
        ExitProcess(126);
    return 0;
}
int ntw_tls_capture_current_target(ntw_tls_native_target *target,const char **error)
{
    ntw_tls_ops ops;uint32_t tib,vector;SIZE_T got=0;
    if(!target||target->admitted)return fail(error,"TLS_TARGET_ALREADY_ADMITTED_OR_NULL");
    if(!ntw_tls_native_ops(&ops))return fail(error,"TLS_TARGET_NATIVE_ABI_UNSUPPORTED");
    __asm__ volatile("movl %%fs:0x18,%0":"=r"(tib));
    if(tib>UINT32_MAX-0x88||!ReadProcessMemory(GetCurrentProcess(),(void *)(UINT_PTR)(tib+0x2c),
       &vector,4,&got)||got!=4||vector!=tib+0x88||vector>UINT32_MAX-80*4)
        return fail(error,"TLS_TARGET_NATIVE_VECTOR_UNSUPPORTED");
    target->owner=GetCurrentThreadId();target->tib=tib;target->vector=vector;target->admitted=1;
    if(error)*error=NULL;return 1;
}
int ntw_tls_native_remote_io(ntw_tls_native_target *target,ntw_tls_remote_io *io,const char **error)
{
    ntw_tls_ops ops;void **slot;
    if(!io||!ntw_tls_native_ops(&ops)||!native_address(target,0,&slot))
        return fail(error,"TLS_TARGET_RETIRED_OR_NATIVE_ABI_UNSUPPORTED");
    io->context=target;io->owner=target->owner;io->read=native_read;io->replace=native_replace;
    if(error)*error=NULL;return 1;
}
void ntw_tls_retire_target(ntw_tls_native_target *target)
{if(target){target->admitted=0;target->owner=0;target->tib=0;target->vector=0;}}
#endif
