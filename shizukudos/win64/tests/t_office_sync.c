/* SPDX-License-Identifier: GPL-2.0-only */
#include "k32test.h"
typedef HANDLE (WINAPI *event_ex_fn)(LPSECURITY_ATTRIBUTES,LPCWSTR,DWORD,DWORD);
typedef HANDLE (WINAPI *sem_ex_fn)(LPSECURITY_ATTRIBUTES,LONG,LONG,LPCWSTR,DWORD,DWORD);
typedef void (WINAPI *flush_fn)(void);
int main(int argc,char **argv)
{
    HMODULE module;event_ex_fn event;sem_ex_fn semaphore;flush_fn flush;
    HANDLE h,other;DWORD flags,error,result;BOOL ok;SECURITY_ATTRIBUTES sa;
    WCHAR self[512],command[1024];char narrow[512],text[1024];PROCESS_INFORMATION pi;STARTUPINFOW startup;
    if(argc==3 && !strcmp(argv[1],"--inherit")){
        ULONG_PTR number=0;const char *digit=argv[2];HANDLE inherited;
        for(;*digit;++digit){if(*digit<'0'||*digit>'9'||number>0xffffffffu/10)return 1;number=number*10+(unsigned)(*digit-'0');}
        inherited=(HANDLE)number;
        return !GetHandleInformation(inherited,&flags) || !(flags&HANDLE_FLAG_INHERIT) || !SetEvent(inherited);
    }
    module=GetModuleHandleW(L"kernel32.dll");
    event=module?(event_ex_fn)GetProcAddress(module,"CreateEventExW"):NULL;
    semaphore=module?(sem_ex_fn)GetProcAddress(module,"CreateSemaphoreExW"):NULL;
    flush=module?(flush_fn)GetProcAddress(module,"FlushProcessWriteBuffers"):NULL;
    CHECK(event&&semaphore&&flush,"all three actual synchronization exports resolve");if(!event||!semaphore||!flush)return 1;
    h=event(NULL,NULL,CREATE_EVENT_INITIAL_SET,SYNCHRONIZE);CHECK(h!=NULL,"synchronize-only event actually created");
    CHECK(WaitForSingleObject(h,0)==WAIT_OBJECT_0&&WaitForSingleObject(h,0)==WAIT_TIMEOUT,"initial auto-reset state consumed once");
    ok=SetEvent(h);error=GetLastError();CHECK(!ok&&error==ERROR_ACCESS_DENIED,"synchronize-only event denies modification");CloseHandle(h);
    h=event(NULL,NULL,CREATE_EVENT_INITIAL_SET,0);CHECK(h!=NULL,"exact zero desired access retained");
    result=WaitForSingleObject(h,0);error=GetLastError();CHECK(result==WAIT_FAILED&&error==ERROR_ACCESS_DENIED,"zero access denies nonalertable wait");
    result=WaitForSingleObjectEx(h,0,TRUE);error=GetLastError();CHECK(result==WAIT_FAILED&&error==ERROR_ACCESS_DENIED,"zero access denies alertable wait");
    result=WaitForMultipleObjects(1,&h,FALSE,0);error=GetLastError();CHECK(result==WAIT_FAILED&&error==ERROR_ACCESS_DENIED,"zero access denies multiple-object wait");
    result=WaitForMultipleObjectsEx(1,&h,FALSE,0,TRUE);error=GetLastError();CHECK(result==WAIT_FAILED&&error==ERROR_ACCESS_DENIED,"zero access denies alertable multiple-object wait");CloseHandle(h);
    h=event(NULL,NULL,CREATE_EVENT_MANUAL_RESET|CREATE_EVENT_INITIAL_SET,GENERIC_READ);CHECK(h!=NULL,"generic read mapped to real event rights");
    CHECK(WaitForSingleObject(h,0)==WAIT_OBJECT_0&&WaitForSingleObject(h,0)==WAIT_OBJECT_0,"manual-reset event retains signaled state");
    ok=ResetEvent(h);error=GetLastError();CHECK(!ok&&error==ERROR_ACCESS_DENIED,"generic read does not grant modification");CloseHandle(h);
    h=event(NULL,NULL,0,EVENT_MODIFY_STATE);CHECK(h&&SetEvent(h)&&ResetEvent(h),"modify-only event changes actual state");
    result=WaitForSingleObject(h,0);error=GetLastError();CHECK(result==WAIT_FAILED&&error==ERROR_ACCESS_DENIED,"modify-only event does not grant synchronization");CloseHandle(h);
    h=event(NULL,L"SHZ_OFFICE_SYNC_EVENT",CREATE_EVENT_MANUAL_RESET,EVENT_ALL_ACCESS);CHECK(h!=NULL,"named event created");
    other=event(NULL,L"SHZ_OFFICE_SYNC_EVENT",CREATE_EVENT_INITIAL_SET,SYNCHRONIZE);error=GetLastError();
    CHECK(other&&error==ERROR_ALREADY_EXISTS,"named reopen reports existing real object");CHECK(WaitForSingleObject(other,0)==WAIT_TIMEOUT,"reopen preserves original state");
    CHECK(SetEvent(h)&&WaitForSingleObject(other,0)==WAIT_OBJECT_0,"different handles refer to same actual named event");
    CHECK(!semaphore(NULL,0,1,L"SHZ_OFFICE_SYNC_EVENT",0,SEMAPHORE_ALL_ACCESS),"named semaphore rejects actual event type collision");CloseHandle(other);CloseHandle(h);
    CHECK(!event(NULL,NULL,4,EVENT_ALL_ACCESS)&&GetLastError()==ERROR_INVALID_PARAMETER,"invalid event flags rejected");
    CHECK(!semaphore(NULL,0,1,NULL,1,SEMAPHORE_ALL_ACCESS)&&GetLastError()==ERROR_INVALID_PARAMETER,"reserved semaphore flags rejected");
    CHECK(!semaphore(NULL,2,1,NULL,0,SEMAPHORE_ALL_ACCESS)&&GetLastError()==ERROR_INVALID_PARAMETER,"invalid semaphore counts rejected");
    h=semaphore(NULL,1,2,NULL,0,SYNCHRONIZE);CHECK(h&&WaitForSingleObject(h,0)==WAIT_OBJECT_0&&WaitForSingleObject(h,0)==WAIT_TIMEOUT,"real semaphore acquisition consumes initial count");
    ok=ReleaseSemaphore(h,1,NULL);error=GetLastError();CHECK(!ok&&error==ERROR_ACCESS_DENIED,"synchronize-only semaphore denies release");CloseHandle(h);
    h=semaphore(NULL,1,0x7fffffff,NULL,0,SEMAPHORE_ALL_ACCESS);CHECK(h!=NULL,"maximum semaphore count created");
    ok=ReleaseSemaphore(h,0x7fffffff,NULL);error=GetLastError();CHECK(!ok&&error==ERROR_TOO_MANY_POSTS,"overflowing semaphore increment fails without signed overflow");CloseHandle(h);
    memset(&sa,0,sizeof sa);sa.nLength=sizeof sa;sa.bInheritHandle=TRUE;
    h=event(&sa,NULL,CREATE_EVENT_MANUAL_RESET,EVENT_ALL_ACCESS);CHECK(h&&GetHandleInformation(h,&flags)&&(flags&HANDLE_FLAG_INHERIT),"requested inherit flag exists in actual handle table");
    CHECK(GetModuleFileNameW(NULL,self,512)>0&&WideCharToMultiByte(CP_ACP,0,self,-1,narrow,sizeof narrow,NULL,NULL)>0,"obtain actual inherited-child executable path");
    snprintf(text,sizeof text,"\"%s\" --inherit %u",narrow,(unsigned)(ULONG_PTR)h);CHECK(MultiByteToWideChar(CP_ACP,0,text,-1,command,1024)>0,"prepare actual child command line");
    memset(&pi,0,sizeof pi);memset(&startup,0,sizeof startup);startup.cb=sizeof startup;
    ok=CreateProcessW(self,command,NULL,NULL,TRUE,0,NULL,NULL,&startup,&pi);CHECK(ok,"start actual child with handle inheritance enabled");
    if(ok){CHECK(WaitForSingleObject(pi.hProcess,5000)==WAIT_OBJECT_0,"real inherited child finishes");CHECK(GetExitCodeProcess(pi.hProcess,&flags)&&flags==0,"child observes inherit flag and signals actual shared object");CHECK(WaitForSingleObject(h,0)==WAIT_OBJECT_0,"parent receives signal through inherited object");CloseHandle(pi.hThread);CloseHandle(pi.hProcess);}CloseHandle(h);
    sa.lpSecurityDescriptor=(void *)1;CHECK(!event(&sa,NULL,0,EVENT_ALL_ACCESS)&&GetLastError()==ERROR_NOT_SUPPORTED,"unsupported caller DACL fails explicitly before access");
    CHECK(GetActiveProcessorCount(0)==1,"actual profile has one active processor");flush();CHECK(TRUE,"full store-buffer barrier returns in supported single-processor profile");
    return k32t_finish("T_OFFICE_SYNC");
}
