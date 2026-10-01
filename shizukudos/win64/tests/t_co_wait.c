/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine event/APC and real HWND/message-filter CoWait contracts.
 * No RPC, ASTA, publisher or native Win98 functionality is inferred. */
#include "k32test.h"
#define COBJMACROS
#include <objbase.h>
#include <oleidl.h>
#include <dde.h>

static HANDLE signal_event;
static volatile LONG received, dde_received, apcs;
static DWORD filter_mode, pending_calls, filter_alive;
static LONG filter_refs = 1;
static IMessageFilter message_filter;
static const GUID iid_unknown = {0,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID iid_filter = {0x16,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static HRESULT WINAPI filter_query(IMessageFilter *self, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (memcmp(iid, &iid_unknown, sizeof *iid) && memcmp(iid, &iid_filter, sizeof *iid)) return E_NOINTERFACE;
    *out = self; InterlockedIncrement(&filter_refs); return S_OK;
}
static ULONG WINAPI filter_addref(IMessageFilter *self) { (void)self; return (ULONG)InterlockedIncrement(&filter_refs); }
static ULONG WINAPI filter_release(IMessageFilter *self) { (void)self; return (ULONG)InterlockedDecrement(&filter_refs); }
static DWORD WINAPI filter_incoming(IMessageFilter *self, DWORD kind, HTASK task, DWORD elapsed, LPINTERFACEINFO info)
{ (void)self; (void)kind; (void)task; (void)elapsed; (void)info; return SERVERCALL_ISHANDLED; }
static DWORD WINAPI filter_retry(IMessageFilter *self, HTASK task, DWORD elapsed, DWORD rejected)
{ (void)self; (void)task; (void)elapsed; (void)rejected; return (DWORD)-1; }
static DWORD WINAPI filter_pending(IMessageFilter *self, HTASK task, DWORD elapsed, DWORD kind)
{
    (void)self; (void)task; (void)elapsed; (void)kind;
    ++pending_calls;
    if (filter_mode == PENDINGMSG_CANCELCALL) {
        /* Drop registration's reference during the active callback. The real
         * modal-loop snapshot must keep this object alive until return. */
        HRESULT status = CoRegisterMessageFilter(NULL, NULL);
        filter_alive = status == S_OK && filter_refs >= 2;
    }
    return filter_mode;
}
static IMessageFilterVtbl filter_vtable = {
    filter_query, filter_addref, filter_release, filter_incoming, filter_retry, filter_pending
};
static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wp, LPARAM lp)
{
    if (message == WM_DDE_INITIATE) {
        InterlockedIncrement(&dde_received);
        SetEvent(signal_event);
        return 43;
    }
    if (message == WM_USER + 101 || message == WM_USER + 102) {
        InterlockedIncrement(&received);
        SetEvent(signal_event);
        return 42;
    }
    return DefWindowProcW(window, message, wp, lp);
}
static DWORD WINAPI send_worker(void *context)
{
    Sleep(10);
    return SendMessageW((HWND)context, WM_USER + 101, 0, 0) == 42 ? 0 : 1;
}
static DWORD WINAPI abandon_worker(void *context)
{
    /* Return while genuinely owning the mutex. Thread teardown must mark it
     * abandoned; the CoWait implementation cannot manufacture that state. */
    return WaitForSingleObject((HANDLE)context, 5000) == WAIT_OBJECT_0 ? 0 : 1;
}
static void CALLBACK apc(ULONG_PTR value) { InterlockedExchange(&apcs, (LONG)value); }
int main(void)
{
    HANDLE objects[2] = {NULL, NULL}, worker = NULL;
    HWND window = NULL;
    WNDCLASSEXW cls = {0};
    MSG message;
    struct { DWORD before, index, after; } output = {0x12345678u,MAXDWORD,0x87654321u};
    DWORD exit_code = MAXDWORD, mask;
    HRESULT status;
    int sta = 0;

    printf("CoWait genuine local handles/APCs/STA messages; COM RPC/ASTA/seen-input/STA WAITALL unsupported\n");
    CHECK(CoWaitForMultipleHandles(0,0,1,NULL,&output.index)==E_INVALIDARG && !output.index,
          "missing handle array rejects and clears bounded DWORD index");
    CHECK(CoWaitForMultipleHandles(0,0,1,objects,NULL)==E_INVALIDARG, "missing index rejects without dereference");
    CHECK(CoWaitForMultipleHandles(0,0,0,objects,&output.index)==RPC_E_NO_SYNC, "zero handles report no synchronization target");
    CHECK(CoWaitForMultipleHandles(0x20,0,1,objects,&output.index)==E_INVALIDARG, "unknown wait flags are rejected");
    CHECK(CoWaitForMultipleHandles(0,0,MAXIMUM_WAIT_OBJECTS+1,objects,&output.index)==E_INVALIDARG,
          "oversized handle count rejects before reading beyond array");
    CHECK(CoWaitForMultipleHandles(COWAIT_INPUTAVAILABLE,0,1,objects,&output.index)==E_NOTIMPL,
          "unavailable seen-input generations do not claim supported behavior");
    objects[0]=CreateEventW(NULL,TRUE,FALSE,NULL);
    objects[1]=CreateEventW(NULL,TRUE,TRUE,NULL);
    CHECK(objects[0] && objects[1], "actual unsignaled and signaled kernel event handles create");
    if (!objects[0] || !objects[1]) goto done;
    CHECK(CoWaitForMultipleHandles(COWAIT_DISPATCH_CALLS,0,2,objects,&output.index)==S_OK && output.index==1,
          "actual uninitialized local-object wait selects signaled event1 with LibreOffice bit8");
    status=CoInitializeEx(NULL,COINIT_MULTITHREADED);
    CHECK(status==S_OK, "real MTA bookkeeping initializes");
    if (status!=S_OK) goto done;
    CHECK(CoWaitForMultipleHandles(0,0,2,objects,&output.index)==S_OK && output.index==1,
          "real MTA zero-time poll returns actual signaled handle index");
    CHECK(CoWaitForMultipleHandles(COWAIT_WAITALL,0,2,objects,&output.index)==RPC_S_CALLPENDING,
          "real MTA WAITALL does not succeed while one event remains unsignaled");
    CHECK(SetEvent(objects[0]), "signal actual first event");
    CHECK(CoWaitForMultipleHandles(COWAIT_WAITALL,0,2,objects,&output.index)==S_OK && output.index==0,
          "real MTA WAITALL completes only with all actual objects signaled");
    CHECK(ResetEvent(objects[0]), "restore unsignaled event");
    {
        ULONGLONG started=GetTickCount64(), elapsed;
        status=CoWaitForMultipleHandles(0,5,1,objects,&output.index);
        elapsed=GetTickCount64()-started;
        CHECK(status==RPC_S_CALLPENDING && elapsed>=5,
              "actual finite wait observes genuine elapsed deadline before RPC_S_CALLPENDING");
    }
    {
        HANDLE abandoned=CreateMutexW(NULL,FALSE,NULL), owner=NULL;
        HANDLE abandoned_objects[2]={objects[0],abandoned};
        CHECK(abandoned!=NULL, "actual initially unowned mutex creates for abandonment");
        if (abandoned) owner=CreateThread(NULL,0,abandon_worker,abandoned,0,NULL);
        CHECK(owner!=NULL, "actual worker acquires and exits owning the real mutex");
        if (owner && WaitForSingleObject(owner,5000)==WAIT_OBJECT_0) {
            CHECK(GetExitCodeThread(owner,&exit_code) && exit_code==0,
                  "actual terminated owner reports acquisition and observed exit0");
            CHECK(CoWaitForMultipleHandles(0,0,2,abandoned_objects,&output.index)==S_OK
                  && output.index==WAIT_ABANDONED_0+1,
                  "actual abandoned mutex preserves WAIT_ABANDONED_0 plus array index1");
            CHECK(ReleaseMutex(abandoned), "caller releases actual mutex ownership obtained by abandoned wait");
            CHECK(CloseHandle(owner), "joined real abandonment worker handle closes");
        } else if (owner) {
            CHECK(FALSE, "abandonment owner must join before any owned context cleanup");
            return k32t_finish("T_CO_WAIT");
        }
        if (abandoned) CHECK(CloseHandle(abandoned), "caller closes its actual abandonment mutex");
    }
    {
        HANDLE bad=(HANDLE)(uintptr_t)0x7fff0001u; /* -1 is a valid process pseudo handle on Windows. */
        CHECK(CoWaitForMultipleHandles(0,0,1,&bad,&output.index)==HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE),
              "real native invalid-handle failure becomes its exact HRESULT");
    }
    CHECK(QueueUserAPC(apc,GetCurrentThread(),7)!=0, "queue a genuine user APC to this thread");
    CHECK(CoWaitForMultipleHandles(COWAIT_ALERTABLE,1000,1,objects,&output.index)==S_OK
          && output.index==WAIT_IO_COMPLETION && apcs==7,
          "real alertable CoWait dispatches actual APC and returns documented wait index");
    CoUninitialize();
    status=CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);
    CHECK(status==S_OK, "actual STA bookkeeping initializes");
    if (status!=S_OK) goto done;
    sta=1;
    CHECK(CoWaitForMultipleHandles(COWAIT_WAITALL,0,2,objects,&output.index)==E_NOTIMPL,
          "STA atomic matching-input WAITALL absence is explicit rather than fabricated success");
    CHECK(CoWaitForMultipleHandles(COWAIT_DISPATCH_CALLS,0,2,objects,&output.index)==S_OK && output.index==1,
          "STA LibreOffice bit8 polls actual signaled event before any queue wait");
    cls.cbSize=sizeof cls;cls.hInstance=GetModuleHandleW(NULL);cls.lpfnWndProc=window_proc;
    cls.lpszClassName=L"ShzCoWaitActual";
    CHECK(RegisterClassExW(&cls)!=0, "actual message-only window class registers");
    window=CreateWindowExW(0,cls.lpszClassName,L"CoWait",0,0,0,0,0,HWND_MESSAGE,NULL,cls.hInstance,NULL);
    CHECK(window!=NULL, "actual message-only HWND creates");
    if (!window) goto done;
    signal_event=objects[0];
    CHECK(MsgWaitForMultipleObjectsEx(1,&objects[1],0,QS_ALLINPUT,0)==WAIT_OBJECT_0,
          "genuine user32 zero-time prerequisite polls an already signaled object");
    CHECK(MsgWaitForMultipleObjectsEx(1,&objects[0],0,QS_ALLINPUT,0)==WAIT_TIMEOUT,
          "genuine user32 zero-time unsignaled object/empty queue still times out");
    CHECK(PostMessageW(window,WM_USER+102,0,0), "post a real arbitrary window message");
    CHECK(MsgWaitForMultipleObjectsEx(1,&objects[1],0,QS_ALLINPUT,0)==WAIT_OBJECT_0,
          "ready kernel object retains array priority over simultaneous actual queue input");
    CHECK(CoWaitForMultipleHandles(COWAIT_DISPATCH_CALLS,10,1,objects,&output.index)==RPC_S_CALLPENDING && received==0,
          "default STA mode leaves arbitrary posted app message queued without false object completion");
    CHECK(PeekMessageW(&message,window,WM_USER+102,WM_USER+102,PM_REMOVE) && message.message==WM_USER+102,
          "non-dispatched app message genuinely remains retrievable");
    CHECK(PostMessageW(window,WM_DDE_INITIATE,0,0), "post genuine DDE message into actual posted-message queue");
    CHECK(CoWaitForMultipleHandles(COWAIT_DISPATCH_CALLS,1000,1,objects,&output.index)==S_OK
          && output.index==0 && dde_received==1 && received==0,
          "default STA posted-message mask dispatches actual DDE callback that genuinely signals waited event");
    CHECK(ResetEvent(objects[0]), "restore real unsignaled event after actual DDE callback");
    worker=CreateThread(NULL,0,send_worker,window,0,NULL);
    CHECK(worker!=NULL, "actual worker starts cross-thread SendMessage");
    if (!worker) goto done;
    CHECK(CoWaitForMultipleHandles(COWAIT_DISPATCH_CALLS,2000,1,objects,&output.index)==S_OK && output.index==0 && received==1,
          "default STA modal loop services real sent callback that actually signals waited event");
    if (WaitForSingleObject(worker,5000)!=WAIT_OBJECT_0) {
        CHECK(FALSE, "worker must join before HWND/context cleanup");
        return k32t_finish("T_CO_WAIT");
    }
    CHECK(GetExitCodeThread(worker,&exit_code) && exit_code==0, "real sender completed with observed callback return42");
    CHECK(CloseHandle(worker), "joined actual worker handle closes");worker=NULL;

    message_filter.lpVtbl=&filter_vtable;
    CHECK(ResetEvent(objects[0]), "reset real event for filter policy tests");
    filter_mode=PENDINGMSG_WAITNOPROCESS;pending_calls=0;
    CHECK(CoRegisterMessageFilter(&message_filter,NULL)==S_OK && filter_refs==2,
          "register actual per-thread COM message-filter reference");
    CHECK(PostMessageW(window,WM_USER+102,0,0), "queue actual callback for WAITNOPROCESS policy");
    CHECK(CoWaitForMultipleHandles(COWAIT_DISPATCH_WINDOW_MESSAGES,10,1,objects,&output.index)==RPC_S_CALLPENDING
          && pending_calls>0 && received==1 && filter_refs==2,
          "registered WAITNOPROCESS policy suppresses real window dispatch while snapshot references balance");
    CHECK(PeekMessageW(&message,window,WM_USER+102,WM_USER+102,PM_REMOVE), "suppressed actual message remains queued");
    CHECK(CoRegisterMessageFilter(NULL,NULL)==S_OK && filter_refs==1, "unregister actual filter and release only owned registration reference");
    filter_mode=PENDINGMSG_CANCELCALL;pending_calls=0;filter_alive=0;
    CHECK(CoRegisterMessageFilter(&message_filter,NULL)==S_OK, "register reentrant cancellation filter");
    CHECK(PostMessageW(window,WM_USER+102,0,0), "queue real message to invoke cancellation filter");
    CHECK(CoWaitForMultipleHandles(COWAIT_DISPATCH_WINDOW_MESSAGES,1000,1,objects,&output.index)==RPC_E_CALL_CANCELED
          && pending_calls==1 && filter_alive && filter_refs==1,
          "reentrant filter unregistration cancels wait and remains alive until owned callback snapshot releases");
    CHECK(PeekMessageW(&message,window,WM_USER+102,WM_USER+102,PM_REMOVE), "canceled wait leaves real unprocessed message queued");
    filter_mode=PENDINGMSG_WAITDEFPROCESS;pending_calls=0;
    CHECK(CoRegisterMessageFilter(&message_filter,NULL)==S_OK, "register default-processing filter");
    CHECK(PostMessageW(window,WM_USER+102,0,0), "post real dispatch-enabled callback");
    CHECK(CoWaitForMultipleHandles(COWAIT_DISPATCH_WINDOW_MESSAGES,1000,1,objects,&output.index)==S_OK
          && output.index==0 && received==2 && pending_calls>0,
          "explicit STA window dispatch runs actual callback and completes its genuine event");
    CHECK(CoRegisterMessageFilter(NULL,NULL)==S_OK && filter_refs==1, "default filter registration releases actual reference");
    CHECK(ResetEvent(objects[0]), "reset event before quit preservation test");
    PostQuitMessage(73);
    CHECK(CoWaitForMultipleHandles(COWAIT_DISPATCH_CALLS,5,1,objects,&output.index)==RPC_S_CALLPENDING,
          "WM_QUIT does not manufacture kernel-object success");
    CHECK(PeekMessageW(&message,NULL,WM_QUIT,WM_QUIT,PM_REMOVE) && message.message==WM_QUIT && message.wParam==73,
          "actual WM_QUIT is reposted with its original exit code");
    CHECK(GetHandleInformation(objects[0],&mask), "CoWait never closes caller-owned event handle");
    CHECK(output.before==0x12345678u && output.after==0x87654321u, "all CoWait results stay within DWORD output guards");
done:
    if (worker) CloseHandle(worker);
    if (window) CHECK(DestroyWindow(window), "actual message HWND destroys after all worker/callback activity");
    if (cls.lpszClassName) CHECK(UnregisterClassW(cls.lpszClassName,cls.hInstance), "owned class unregisters");
    if (sta) CoUninitialize();
    if (objects[0]) CHECK(CloseHandle(objects[0]), "caller closes its real first event");
    if (objects[1]) CHECK(CloseHandle(objects[1]), "caller closes its real second event");
    return k32t_finish("T_CO_WAIT");
}
