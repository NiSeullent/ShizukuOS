/* SPDX-License-Identifier: GPL-2.0-only
 * Native 8-byte one-time initialization state and documented callback retry.
 * State contracts follow pinned Wine sync.c (db11d0fe6a...), but actual waiting
 * uses this runtime's Nt alert/thread-backed RtlWaitOnAddress provider rather
 * than unavailable keyed events. No kernel32 dependency or fabricated success. */
#ifdef SHZ_RTL_BOOTSTRAP_HOST
#include "../tests/rtl_bootstrap_host_contract.h"
#else
#include "nt.h"
#endif

/* Existing native providers, locally declared to keep shared headers intact. */
NTSTATUS NTAPI RtlWaitOnAddress(volatile VOID *,PVOID,SIZE_T,PLARGE_INTEGER);
VOID NTAPI RtlWakeAddressAll(PVOID);

#define ONCE_BUCKETS 64u
typedef struct once_waiter {struct once_waiter *next;RTL_RUN_ONCE *once;} once_waiter;
static struct {volatile LONG lock;once_waiter *head;} once_buckets[ONCE_BUCKETS];
static unsigned once_bucket(const RTL_RUN_ONCE *once){return (unsigned)(((uintptr_t)once>>3)%ONCE_BUCKETS);}
static void once_lock(unsigned b){while(__atomic_exchange_n(&once_buckets[b].lock,1,__ATOMIC_ACQUIRE))NtYieldExecution();}
static void once_unlock(unsigned b){__atomic_store_n(&once_buckets[b].lock,0,__ATOMIC_RELEASE);}
static ULONG_PTR once_load(RTL_RUN_ONCE *once){return (ULONG_PTR)__atomic_load_n(&once->Ptr,__ATOMIC_ACQUIRE);}
static int once_cas(RTL_RUN_ONCE *once,ULONG_PTR before,ULONG_PTR after){PVOID expected=(PVOID)before;return __atomic_compare_exchange_n(&once->Ptr,&expected,(PVOID)after,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);}

static NTSTATUS once_wait(RTL_RUN_ONCE *once,ULONG_PTR observed)
{
    unsigned b=once_bucket(once);
    once_waiter node={0,once},**link;
    NTSTATUS status;
    once_lock(b);
    if(once_load(once)!=observed){once_unlock(b);return STATUS_SUCCESS;}
    node.next=once_buckets[b].head;once_buckets[b].head=&node;
    once_unlock(b);
    status=RtlWaitOnAddress(&once->Ptr,&observed,sizeof observed,0);
    once_lock(b);
    for(link=&once_buckets[b].head;*link && *link!=&node;link=&(*link)->next){}
    if(*link)*link=node.next;
    once_unlock(b);
    return status;
}

static NTSTATUS once_complete(RTL_RUN_ONCE *once,PVOID context,int failed)
{
    unsigned b=once_bucket(once);
    SIZE_T count=0;
    if((ULONG_PTR)context&3)return STATUS_INVALID_PARAMETER;
    once_lock(b);
    if(!once_cas(once,1,failed?0:((ULONG_PTR)context|2))){once_unlock(b);return STATUS_UNSUCCESSFUL;}
    for(once_waiter *w=once_buckets[b].head;w;w=w->next)if(w->once==once)++count;
    /* Existing wake-all removes at most 64 parking nodes per call. Registered
     * waiters cannot unlink until this lock is released; late parkers validate
     * the published state, so ceil(count/64) calls drain every actual waiter. */
    do{RtlWakeAddressAll(&once->Ptr);if(count<=64)break;count-=64;}while(1);
    once_unlock(b);
    return STATUS_SUCCESS;
}

SHZ_EXPORT VOID NTAPI RtlRunOnceInitialize(PRTL_RUN_ONCE once)
{
    __atomic_store_n(&once->Ptr,0,__ATOMIC_RELEASE);
}

SHZ_EXPORT NTSTATUS NTAPI RtlRunOnceExecuteOnce(PRTL_RUN_ONCE once,PRTL_RUN_ONCE_INIT_FN callback,PVOID parameter,PVOID *context)
{
    if(!once)return STATUS_INVALID_PARAMETER;
    for(;;) {
        ULONG_PTR state=once_load(once);
        switch(state&3) {
        case 0:
            if(!once_cas(once,0,1))break;
            if(!callback){once_complete(once,0,1);return STATUS_INVALID_PARAMETER;}
            if(!callback(once,parameter,context)){once_complete(once,0,1);return STATUS_UNSUCCESSFUL;}
            return once_complete(once,context?*context:0,0);
        case 1: {
            NTSTATUS status=once_wait(once,state);
            if(!NT_SUCCESS(status))return status;
            break;
        }
        case 2:
            if(context)*context=(PVOID)(state&~(ULONG_PTR)3);
            return STATUS_SUCCESS;
        default:return STATUS_INVALID_PARAMETER;
        }
    }
}
