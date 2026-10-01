/* SPDX-License-Identifier: GPL-2.0-only: actual Kernel32 scheduling contracts. */
#include "k32test.h"
struct api {
    PTP_WORK (WINAPI *create_work)(PTP_WORK_CALLBACK,PVOID,PTP_CALLBACK_ENVIRON);
    void (WINAPI *submit)(PTP_WORK);void (WINAPI *wait_work)(PTP_WORK,BOOL);void (WINAPI *close_work)(PTP_WORK);
    void (WINAPI *defer_free)(PTP_CALLBACK_INSTANCE,HMODULE);
    PTP_TIMER (WINAPI *create_timer)(PTP_TIMER_CALLBACK,PVOID,PTP_CALLBACK_ENVIRON);
    void (WINAPI *set_timer)(PTP_TIMER,PFILETIME,DWORD,DWORD);void (WINAPI *wait_timer)(PTP_TIMER,BOOL);void (WINAPI *close_timer)(PTP_TIMER);
    PTP_WAIT (WINAPI *create_wait)(PTP_WAIT_CALLBACK,PVOID,PTP_CALLBACK_ENVIRON);
    void (WINAPI *set_wait)(PTP_WAIT,HANDLE,PFILETIME);void (WINAPI *wait_wait)(PTP_WAIT,BOOL);void (WINAPI *close_wait)(PTP_WAIT);
};
static struct api api;
struct context { volatile LONG calls,status,bad_object; HANDLE entered,release; HMODULE module; PVOID expected; };
static void common(PTP_CALLBACK_INSTANCE instance,struct context *context,PVOID object,DWORD status)
{
    if(object!=context->expected)InterlockedIncrement(&context->bad_object);
    InterlockedExchange(&context->status,(LONG)status);
    if(context->module)api.defer_free(instance,context->module);
    InterlockedIncrement(&context->calls);
    if(context->entered)SetEvent(context->entered);
    if(context->release)WaitForSingleObject(context->release,5000);
}
static void CALLBACK work_callback(PTP_CALLBACK_INSTANCE instance,PVOID context,PTP_WORK work){common(instance,context,work,0);}
static void CALLBACK timer_callback(PTP_CALLBACK_INSTANCE instance,PVOID context,PTP_TIMER timer){common(instance,context,timer,0);}
static void CALLBACK wait_callback(PTP_CALLBACK_INSTANCE instance,PVOID context,PTP_WAIT wait,TP_WAIT_RESULT status){common(instance,context,wait,status);}
static BOOL await(volatile LONG *count,LONG target){DWORD i;for(i=0;i<3000;++i){if(InterlockedCompareExchange(count,0,0)>=target)return TRUE;Sleep(1);}return FALSE;}
static FILETIME relative(DWORD ms){ULONGLONG value=0-(ULONGLONG)ms*10000;FILETIME time={(DWORD)value,(DWORD)(value>>32)};return time;}
int main(void)
{
    HMODULE module=GetModuleHandleW(L"kernel32.dll");struct context work={0},timer={0},wait={0},blocked={0};
    PTP_WORK w;PTP_TIMER t;PTP_WAIT q;HANDLE event,first,second;FILETIME due;LONG before;DWORD i;
#define RESOLVE(member,name) api.member=(void *)GetProcAddress(module,name)
    RESOLVE(create_work,"CreateThreadpoolWork");RESOLVE(submit,"SubmitThreadpoolWork");RESOLVE(wait_work,"WaitForThreadpoolWorkCallbacks");RESOLVE(close_work,"CloseThreadpoolWork");RESOLVE(defer_free,"FreeLibraryWhenCallbackReturns");
    RESOLVE(create_timer,"CreateThreadpoolTimer");RESOLVE(set_timer,"SetThreadpoolTimer");RESOLVE(wait_timer,"WaitForThreadpoolTimerCallbacks");RESOLVE(close_timer,"CloseThreadpoolTimer");
    RESOLVE(create_wait,"CreateThreadpoolWait");RESOLVE(set_wait,"SetThreadpoolWait");RESOLVE(wait_wait,"WaitForThreadpoolWaitCallbacks");RESOLVE(close_wait,"CloseThreadpoolWait");
#undef RESOLVE
    CHECK(api.create_work&&api.submit&&api.wait_work&&api.close_work&&api.defer_free&&api.create_timer&&api.set_timer&&api.wait_timer&&api.close_timer&&api.create_wait&&api.set_wait&&api.wait_wait&&api.close_wait,"all real lifecycle exports resolve");
    if(!api.create_work||!api.submit||!api.wait_work||!api.close_work||!api.defer_free||!api.create_timer||!api.set_timer||!api.wait_timer||!api.close_timer||!api.create_wait||!api.set_wait||!api.wait_wait||!api.close_wait)return 1;
    CHECK(!api.create_work(NULL,NULL,NULL)&&GetLastError()==ERROR_INVALID_PARAMETER,"null callback fails honestly");
    w=api.create_work(work_callback,&work,NULL);CHECK(w!=NULL,"actual work object creates workers");if(!w)return 1;work.expected=w;
    for(i=0;i<40;++i){api.submit(w);}
    api.wait_work(w,FALSE);CHECK(work.calls==40&&!work.bad_object,"every submission invokes callback with correct actual object");api.close_work(w);
    blocked.entered=CreateEventW(NULL,TRUE,FALSE,NULL);blocked.release=CreateEventW(NULL,TRUE,FALSE,NULL);blocked.module=LoadLibraryW(L"version.dll");
    CHECK(blocked.module!=NULL,"load actual module for deferred callback release");
    w=api.create_work(work_callback,&blocked,NULL);CHECK(w!=NULL,"create actual blocked work object");if(!w)return 1;blocked.expected=w;api.submit(w);
    CHECK(WaitForSingleObject(blocked.entered,3000)==WAIT_OBJECT_0,"callback actually enters before close");api.close_work(w);
    CHECK(GetModuleHandleW(L"version.dll")!=NULL,"close preserves callback-owned module until return");SetEvent(blocked.release);
    for(i=0;i<3000&&GetModuleHandleW(L"version.dll");++i)Sleep(1);
    CHECK(!GetModuleHandleW(L"version.dll"),"real module unload occurs after callback return");CloseHandle(blocked.entered);CloseHandle(blocked.release);
    t=api.create_timer(timer_callback,&timer,NULL);CHECK(t!=NULL,"actual timer object creates scheduler");if(!t)return 1;timer.expected=t;
    due=relative(20);api.set_timer(t,&due,0,0);Sleep(2);CHECK(!timer.calls,"timer does not fire early");CHECK(await(&timer.calls,1),"relative timer callback actually executes");api.wait_timer(t,FALSE);
    due=relative(2);api.set_timer(t,&due,5,0);CHECK(await(&timer.calls,4),"periodic timer actually queues callbacks");api.set_timer(t,NULL,0,0);api.wait_timer(t,TRUE);before=timer.calls;Sleep(20);CHECK(timer.calls==before&&!timer.bad_object,"timer disarm and cancel stop future callbacks");api.close_timer(t);
    event=CreateEventW(NULL,FALSE,FALSE,NULL);q=api.create_wait(wait_callback,&wait,NULL);CHECK(q!=NULL,"actual wait object creates native wait bucket");if(!q)return 1;wait.expected=q;api.set_wait(q,event,NULL);SetEvent(event);
    CHECK(await(&wait.calls,1)&&wait.status==WAIT_OBJECT_0,"real signaled status delivered to callback");api.wait_wait(q,FALSE);CHECK(WaitForSingleObject(event,0)==WAIT_TIMEOUT,"native wait consumed auto-reset signal");
    SetEvent(event);Sleep(10);CHECK(wait.calls==1,"wait remains one shot until rearmed");CHECK(WaitForSingleObject(event,0)==WAIT_OBJECT_0,"unregistered new signal remains available");
    due=relative(10);api.set_wait(q,event,&due);CHECK(await(&wait.calls,2)&&wait.status==WAIT_TIMEOUT,"real timeout status delivered to callback");api.set_wait(q,NULL,(PFILETIME)(ULONG_PTR)1);api.wait_wait(q,FALSE);
    first=CreateEventW(NULL,FALSE,FALSE,NULL);second=CreateEventW(NULL,FALSE,FALSE,NULL);api.set_wait(q,first,NULL);Sleep(5);api.set_wait(q,second,NULL);SetEvent(first);Sleep(10);CHECK(wait.calls==2,"stale wait snapshot cannot dispatch replacement generation");SetEvent(second);CHECK(await(&wait.calls,3),"replacement actual object dispatches correctly");
    api.set_wait(q,NULL,NULL);api.wait_wait(q,TRUE);api.close_wait(q);CHECK(!wait.bad_object,"all wait callbacks received correct actual object");CloseHandle(first);CloseHandle(second);CloseHandle(event);
    return k32t_finish("T_OFFICE_THREADPOOL");
}
