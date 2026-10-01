/* SPDX-License-Identifier: GPL-2.0-only
 * Actual Ex event/semaphore creation and a bounded uniprocessor full barrier.
 * Kernel64 sysx.c enforces requested rights and inheritance for these objects.
 * Supplied security descriptors fail explicitly until their DACL is enforced.
 * Original project source; Wine11/ReactOS synchronization contracts reviewed.
 */
#include "k32_ipc.h"
static DWORD office_sync_attributes(LPCWSTR name,LPSECURITY_ATTRIBUTES sa,SHZ_OBJECT_ATTRIBUTES *oa,SHZ_UNICODE_STRING *us)
{
    if(sa && sa->nLength!=sizeof *sa)return ERROR_INVALID_PARAMETER;
    if(sa && sa->lpSecurityDescriptor)return ERROR_NOT_SUPPORTED;
    return k32_ipc_oa(name,sa && sa->bInheritHandle,TRUE,oa,us);
}
K32API HANDLE WINAPI CreateEventExW(LPSECURITY_ATTRIBUTES sa,LPCWSTR name,DWORD flags,DWORD access)
{
    SHZ_OBJECT_ATTRIBUTES oa;SHZ_UNICODE_STRING us;HANDLE h=NULL;NTSTATUS st;DWORD error;
    if(flags & ~(DWORD)(CREATE_EVENT_MANUAL_RESET|CREATE_EVENT_INITIAL_SET)){shz_set_last_error(ERROR_INVALID_PARAMETER);return NULL;}
    error=office_sync_attributes(name,sa,&oa,&us);if(error){shz_set_last_error(error);return NULL;}
    st=NtCreateEvent(&h,access,&oa,(flags&CREATE_EVENT_MANUAL_RESET)?0:1,(flags&CREATE_EVENT_INITIAL_SET)!=0);
    if(st==STATUS_OBJECT_NAME_EXISTS){shz_set_last_error(ERROR_ALREADY_EXISTS);return h;}
    if(st){k32_nt_error(st);return NULL;}shz_set_last_error(0);return h;
}
K32API HANDLE WINAPI CreateSemaphoreExW(LPSECURITY_ATTRIBUTES sa,LONG initial,LONG maximum,LPCWSTR name,DWORD flags,DWORD access)
{
    SHZ_OBJECT_ATTRIBUTES oa;SHZ_UNICODE_STRING us;HANDLE h=NULL;NTSTATUS st;DWORD error;
    if(flags || maximum<=0 || initial<0 || initial>maximum){shz_set_last_error(ERROR_INVALID_PARAMETER);return NULL;}
    error=office_sync_attributes(name,sa,&oa,&us);if(error){shz_set_last_error(error);return NULL;}
    st=NtCreateSemaphore(&h,access,&oa,initial,maximum);
    if(st==STATUS_OBJECT_NAME_EXISTS){shz_set_last_error(ERROR_ALREADY_EXISTS);return h;}
    if(st){k32_nt_error(st);return NULL;}shz_set_last_error(0);return h;
}
K32API void WINAPI FlushProcessWriteBuffers(void)
{
    /* sched.c runs every user thread on the single boot CPU. A full fence
     * drains that CPU's store buffer, including stores from previous threads.
     * Future SMP needs a kernel rendezvous before this API can return. */
    if(GetActiveProcessorCount(0)!=1){RaiseException((DWORD)STATUS_NOT_SUPPORTED,EXCEPTION_NONCONTINUABLE,0,NULL);return;}
    __asm__ volatile("mfence" ::: "memory");
}
