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
#include "tls_runtime.h"
static int fail(const char **error,const char *reason)
{if(error)*error=reason;return 0;}
static void bytes_copy(void *out,const void *in,uint32_t count)
{uint32_t i;for(i=0;i<count;i++)((unsigned char *)out)[i]=((const unsigned char *)in)[i];}
static void bytes_zero(void *out,uint32_t count)
{uint32_t i;for(i=0;i<count;i++)((unsigned char *)out)[i]=0;}

int ntw_tls_dispose(ntw_tls_plan *plan,const char **error)
{
    uint32_t i;
    if(!plan)return fail(error,"TLS_PLAN_NULL");
    if(plan->live_threads)return fail(error,"TLS_THREADS_STILL_ATTACHED");
    for(i=plan->count;i;i--){
        ntw_tls_module *module=&plan->module[i-1];
        if(module->slot!=NTW_TLS_NO_SLOT){
            if(!plan->ops.release(plan->ops.context,module->slot))return fail(error,"TLS_NATIVE_SLOT_RELEASE");
            module->slot=NTW_TLS_NO_SLOT;
            if(plan->ready)*module->index_address=module->old_index;
        }
        if(module->initial){plan->ops.deallocate(plan->ops.context,module->initial);module->initial=NULL;}
        plan->count--;
    }
    plan->ready=0;
    if(error)*error=NULL;
    return 1;
}
int ntw_tls_prepare(ntw_tls_plan *plan,const ntw_tls_spec *spec,uint32_t count,
                    const ntw_tls_ops *ops,const char **error)
{
    uint32_t i;
    if(!plan||!ops||(!spec&&count)||count>NTW_TLS_MODULES||!ops->reserve||!ops->release||
       !ops->allocate||!ops->deallocate||!ops->thread_id||!ops->read||!ops->publish)
        return fail(error,"TLS_INVALID_PLAN");
    if(plan->ready||plan->count||plan->live_threads)return fail(error,"TLS_PLAN_ALREADY_OWNED");
    for(i=0;i<count;i++){
        uint32_t alignment=spec[i].alignment;uint32_t j;
        if(!spec[i].index_address||(uintptr_t)spec[i].index_address%4||
           (!spec[i].initial&&spec[i].initialized_bytes)||spec[i].initialized_bytes>NTW_TLS_BYTES||
           spec[i].zero_bytes>NTW_TLS_BYTES-spec[i].initialized_bytes||
           (alignment&&(alignment>8192||(alignment&(alignment-1)))))
            return fail(error,"TLS_INVALID_TEMPLATE");
        for(j=0;j<i;j++)if(spec[i].index_address==spec[j].index_address)
            return fail(error,"TLS_DUPLICATE_INDEX_ADDRESS");
    }
    plan->ops=*ops;
    for(i=0;i<count;i++){
        ntw_tls_module *module=&plan->module[i];
        module->slot=NTW_TLS_NO_SLOT;module->initial=NULL;plan->count=i+1;
        module->bytes=spec[i].initialized_bytes;module->zero=spec[i].zero_bytes;
        module->alignment=spec[i].alignment?spec[i].alignment:16;
        module->index_address=spec[i].index_address;module->old_index=*spec[i].index_address;
        if(module->bytes){
            module->initial=ops->allocate(ops->context,module->bytes);
            if(!module->initial)goto allocation_failed;
            bytes_copy(module->initial,spec[i].initial,module->bytes);
        }
        module->slot=ops->reserve(ops->context);
        if(module->slot==NTW_TLS_NO_SLOT)goto slot_failed;
        {uint32_t j;for(j=0;j<i;j++)if(plan->module[j].slot==module->slot){
            /* A broken backend must not release another module's owned slot. */
            module->slot=NTW_TLS_NO_SLOT;goto slot_failed;
        }}
    }
    for(i=0;i<count;i++)*plan->module[i].index_address=plan->module[i].slot;
    plan->ready=1;
    if(error)*error=NULL;
    return 1;
allocation_failed:
    if(!ntw_tls_dispose(plan,error))return 0;
    return fail(error,"TLS_TEMPLATE_ALLOCATION");
slot_failed:
    if(!ntw_tls_dispose(plan,error))return 0;
    return fail(error,"TLS_NATIVE_SLOT_ALLOCATION");
}

int ntw_tls_detach(ntw_tls_thread *thread,const char **error)
{
    ntw_tls_plan *plan;uint32_t i;
    if(!thread||!thread->active||!thread->plan)return fail(error,"TLS_THREAD_NOT_ATTACHED");
    plan=thread->plan;
    if(plan->ops.thread_id(plan->ops.context)!=thread->owner)return fail(error,"TLS_WRONG_THREAD");
    /* A failed clear retains all still-published storage for a safe retry. */
    while(thread->published){
        i=thread->published-1;
        if(!plan->ops.publish(plan->ops.context,plan->module[i].slot,NULL))
            return fail(error,"TLS_NATIVE_SLOT_CLEAR");
        thread->published--;
    }
    for(i=0;i<thread->count;i++)if(thread->allocation[i]){
        plan->ops.deallocate(plan->ops.context,thread->allocation[i]);
        thread->allocation[i]=NULL;thread->data[i]=NULL;
    }
    plan->live_threads--;thread->active=0;thread->count=0;thread->plan=NULL;
    if(error)*error=NULL;
    return 1;
}
int ntw_tls_attach(ntw_tls_plan *plan,ntw_tls_thread *thread,const char **error)
{
    uint32_t i;
    if(!plan||!plan->ready||!thread||thread->active||plan->live_threads==UINT32_MAX)
        return fail(error,"TLS_INVALID_THREAD_ATTACH");
    for(i=0;i<plan->count;i++){
        void *old=NULL;
        if(!plan->ops.read(plan->ops.context,plan->module[i].slot,&old)||old)
            return fail(error,"TLS_NATIVE_SLOT_ALREADY_OCCUPIED");
    }
    thread->plan=plan;thread->owner=plan->ops.thread_id(plan->ops.context);
    thread->count=0;thread->published=0;thread->active=1;plan->live_threads++;
    for(i=0;i<plan->count;i++){
        ntw_tls_module *module=&plan->module[i];
        uint32_t size=module->bytes+module->zero,allocation;
        uintptr_t address;
        if(!size)size=1;
        allocation=size+module->alignment-1;
        thread->allocation[i]=plan->ops.allocate(plan->ops.context,allocation);
        thread->data[i]=NULL;thread->count=i+1;
        if(!thread->allocation[i])goto failed;
        address=(uintptr_t)thread->allocation[i];
        if(address>UINTPTR_MAX-(module->alignment-1))goto failed;
        address=(address+module->alignment-1)&~(uintptr_t)(module->alignment-1);
        thread->data[i]=(void *)address;
        bytes_zero(thread->data[i],size);
        bytes_copy(thread->data[i],module->initial,module->bytes);
    }
    for(i=0;i<plan->count;i++){
        if(!plan->ops.publish(plan->ops.context,plan->module[i].slot,thread->data[i]))goto failed;
        thread->published++;
    }
    if(error)*error=NULL;
    return 1;
failed:
    if(!ntw_tls_detach(thread,error))return 0;
    return fail(error,"TLS_THREAD_ALLOCATION_OR_PUBLICATION");
}

#ifdef _WIN32
#include <windows.h>
_Static_assert(sizeof(void *)==4,"native Win98 TLS requires PE32");
static int native_slot(uint32_t index,void **value)
{
    uintptr_t self;DWORD vector;SIZE_T got=0;void *api;
    DWORD saved=GetLastError();int ok=0;
    __asm__ volatile("movl %%fs:0x18,%0":"=r"(self));
    /* Pinned KernelEx common/kstructs.h: TIB at TDB+8; TlsSlots at TDB+0x90.
     * This is an explicit Win98 ABI check, not a general TlsAlloc assumption.
     */
    if(index>=80||self>UINT32_MAX-0x88||
       !ReadProcessMemory(GetCurrentProcess(),(void *)(self+0x2c),&vector,4,&got)||got!=4||
       vector!=self+0x88||
       !ReadProcessMemory(GetCurrentProcess(),(void *)(UINT_PTR)(vector+4*index),value,4,&got)||got!=4)
        goto done;
    SetLastError(0);api=TlsGetValue(index);
    if(GetLastError()==0&&api==*value)ok=1;
done:
    SetLastError(saved);return ok;
}
static uint32_t native_reserve(void *context)
{
    DWORD index=TlsAlloc();void *value=NULL;(void)context;
    if(index==TLS_OUT_OF_INDEXES)return NTW_TLS_NO_SLOT;
    if(!native_slot(index,&value)||value){TlsFree(index);SetLastError(ERROR_NOT_SUPPORTED);return NTW_TLS_NO_SLOT;}
    return index;
}
static int native_release(void *context,uint32_t index)
{(void)context;return TlsFree(index)!=FALSE;}
static void *native_allocate(void *context,uint32_t bytes)
{return HeapAlloc((HANDLE)context,0,bytes);}
static void native_deallocate(void *context,void *memory)
{HeapFree((HANDLE)context,0,memory);}
static uint32_t native_thread_id(void *context)
{(void)context;return GetCurrentThreadId();}
static int native_read(void *context,uint32_t index,void **value)
{(void)context;return native_slot(index,value);}
static int native_publish(void *context,uint32_t index,void *value)
{
    void *before=NULL,*after=NULL;(void)context;
    if(!native_slot(index,&before))return 0;
    if(!TlsSetValue(index,value))return 0;
    if(native_slot(index,&after)&&after==value)return 1;
    /* Failed publication must leave the prior native value intact. If a broken
     * native ABI cannot restore it, stop this private process rather than free
     * a block still referenced by the actual thread's TLS slot.
     */
    if(!TlsSetValue(index,before)||!native_slot(index,&after)||after!=before)ExitProcess(126);
    SetLastError(ERROR_NOT_SUPPORTED);return 0;
}
int ntw_tls_native_ops(ntw_tls_ops *ops)
{
    OSVERSIONINFOA version;uintptr_t self;DWORD vector;SIZE_T got=0;
    if(!ops){SetLastError(ERROR_INVALID_PARAMETER);return 0;}
    bytes_zero(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
    if(!GetVersionExA(&version)||version.dwPlatformId!=VER_PLATFORM_WIN32_WINDOWS||
       version.dwMajorVersion!=4||version.dwMinorVersion!=10){SetLastError(ERROR_NOT_SUPPORTED);return 0;}
    __asm__ volatile("movl %%fs:0x18,%0":"=r"(self));
    if(self>UINT32_MAX-0x88||
       !ReadProcessMemory(GetCurrentProcess(),(void *)(self+0x2c),&vector,4,&got)||got!=4||
       vector!=self+0x88){SetLastError(ERROR_NOT_SUPPORTED);return 0;}
    ops->context=GetProcessHeap();ops->reserve=native_reserve;ops->release=native_release;
    ops->allocate=native_allocate;ops->deallocate=native_deallocate;ops->thread_id=native_thread_id;
    ops->read=native_read;ops->publish=native_publish;return 1;
}
#endif
