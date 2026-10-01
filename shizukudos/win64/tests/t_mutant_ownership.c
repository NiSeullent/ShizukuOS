/* SPDX-License-Identifier: GPL-2.0-only
 * Actual Win32 mutex ownership, closed handles and real thread/process exit.
 * WAIT_ABANDONED is accepted only from the kernel wait, never manufactured. */
#include "k32test.h"
static const WCHAR process_mutex[] = L"Local\\ShzMutantProcessExitV1";
static const WCHAR initial_mutex[] = L"Local\\ShzMutantInitialExitV1";
static const WCHAR process_ready[] = L"Local\\ShzMutantProcessReadyV1";
static const WCHAR process_exit[] = L"Local\\ShzMutantProcessExitGateV1";
typedef struct { HANDLE mutex, ready, leave; BOOL initial; } worker_context;
static DWORD WINAPI worker(void *opaque)
{
    worker_context *c = opaque;
    HANDLE mutex = c->initial ? CreateMutexW(NULL,TRUE,initial_mutex) : c->mutex;
    if (!mutex) return 1;
    if (!c->initial && WaitForSingleObject(mutex,5000)!=WAIT_OBJECT_0) return 2;
    if (WaitForSingleObject(mutex,0)!=WAIT_OBJECT_0) return 3; /* recursion */
    if (!CloseHandle(mutex)) return 4;
    if (!SetEvent(c->ready)) return 5;
    if (WaitForSingleObject(c->leave,5000)!=WAIT_OBJECT_0) return 6;
    return 0;                            /* genuinely still owns a closed handle */
}
static int child(void)
{
    HANDLE mutex=CreateMutexW(NULL,FALSE,process_mutex);
    HANDLE ready=CreateEventW(NULL,TRUE,FALSE,process_ready);
    HANDLE leave=CreateEventW(NULL,TRUE,FALSE,process_exit);
    if(!mutex||!ready||!leave)return 11;
    if(WaitForSingleObject(mutex,5000)!=WAIT_OBJECT_0)return 12;
    if(WaitForSingleObject(mutex,0)!=WAIT_OBJECT_0)return 13;
    if(!CloseHandle(mutex)||!SetEvent(ready))return 14;
    if(WaitForSingleObject(leave,5000)!=WAIT_OBJECT_0)return 15;
    CloseHandle(ready);CloseHandle(leave);
    return 0;                            /* actual process exit abandons recursion */
}
static void thread_case(BOOL initial)
{
    worker_context c={0}; HANDLE thread=NULL, parent=NULL; DWORD code=MAXDWORD;
    c.initial=initial;c.ready=CreateEventW(NULL,TRUE,FALSE,NULL);c.leave=CreateEventW(NULL,TRUE,FALSE,NULL);
    if(!initial){
        parent=CreateMutexW(NULL,FALSE,NULL);
        CHECK(parent&&DuplicateHandle(GetCurrentProcess(),parent,GetCurrentProcess(),&c.mutex,0,FALSE,DUPLICATE_SAME_ACCESS),
              "duplicate handle names the same genuine mutex");
    }
    CHECK(c.ready&&c.leave&&(initial||c.mutex),"actual thread test resources create");
    if(!c.ready||!c.leave||(!initial&&!c.mutex))goto done;
    thread=CreateThread(NULL,0,worker,&c,0,NULL);
    CHECK(thread&&WaitForSingleObject(c.ready,5000)==WAIT_OBJECT_0,"worker owns recursively and closes its only handle");
    if(!thread)goto done;
    if(initial) {
        parent=CreateMutexW(NULL,TRUE,initial_mutex);
        CHECK(parent&&GetLastError()==ERROR_ALREADY_EXISTS,"closed initial-owner handle still keeps the named object alive");
    }
    CHECK(parent&&WaitForSingleObject(parent,0)==WAIT_TIMEOUT,"other thread cannot acquire the closed-handle owned object");
    CHECK(parent&&!ReleaseMutex(parent)&&GetLastError()==ERROR_NOT_OWNER,"another thread cannot release its ownership");
    CHECK(SetEvent(c.leave)&&WaitForSingleObject(thread,5000)==WAIT_OBJECT_0,"real owning thread exits and signals its object");
    CHECK(GetExitCodeThread(thread,&code)&&code==0,"owning worker completed real acquisitions and close");
    CHECK(parent&&WaitForSingleObject(parent,0)==WAIT_ABANDONED,"thread signal observes prior genuine abandonment");
    CHECK(parent&&WaitForSingleObject(parent,0)==WAIT_OBJECT_0,"abandonment is consumed once and new owner can recurse");
    CHECK(parent&&ReleaseMutex(parent)&&ReleaseMutex(parent),"new owner releases its own two acquisitions");
    CHECK(parent&&!ReleaseMutex(parent)&&GetLastError()==ERROR_NOT_OWNER,"final release drops ownership exactly once");
done:
    if(thread)CloseHandle(thread);
    if(parent)CloseHandle(parent);
    if(c.ready)CloseHandle(c.ready);
    if(c.leave)CloseHandle(c.leave);
}
int main(int argc,char **argv)
{
    HANDLE mutex,ready,leave; STARTUPINFOW startup={0};PROCESS_INFORMATION process={0};
    WCHAR path[MAX_PATH],command[MAX_PATH+32];DWORD n,code=MAXDWORD;unsigned i;
    if(argc>1&&argv[1]&&!strcmp(argv[1],"--child"))return child();
    thread_case(FALSE);thread_case(TRUE);
    mutex=CreateMutexW(NULL,FALSE,process_mutex);ready=CreateEventW(NULL,TRUE,FALSE,process_ready);
    leave=CreateEventW(NULL,TRUE,FALSE,process_exit);
    CHECK(mutex&&ready&&leave,"actual cross-process named resources create");
    n=GetModuleFileNameW(NULL,path,MAX_PATH);CHECK(n&&n<MAX_PATH,"actual executable path resolves for a child process");
    if(!mutex||!ready||!leave||!n||n>=MAX_PATH)goto done;
    command[0]='"';for(i=0;i<n;++i)command[i+1]=path[i];
    { const WCHAR suffix[]=L"\" --child";unsigned j;for(j=0;j<sizeof suffix/sizeof suffix[0];++j)command[n+1+j]=suffix[j]; }
    startup.cb=sizeof startup;
    CHECK(CreateProcessW(path,command,NULL,NULL,FALSE,0,NULL,NULL,&startup,&process),"genuine child process starts with an independent handle table");
    if(!process.hProcess)goto done;
    CHECK(WaitForSingleObject(ready,5000)==WAIT_OBJECT_0,"child owns the shared mutex after closing its local handle");
    CHECK(WaitForSingleObject(mutex,0)==WAIT_TIMEOUT,"parent wait observes the child ownership across processes");
    CHECK(!ReleaseMutex(mutex)&&GetLastError()==ERROR_NOT_OWNER,"parent cannot release the child ownership");
    CHECK(SetEvent(leave)&&WaitForSingleObject(process.hProcess,5000)==WAIT_OBJECT_0,"actual child exits");
    CHECK(GetExitCodeProcess(process.hProcess,&code)&&code==0,"child completed both acquisitions and local close");
    CHECK(WaitForSingleObject(mutex,5000)==WAIT_ABANDONED,"actual child exit abandons the cross-process mutex");
    CHECK(ReleaseMutex(mutex),"parent releases the ownership granted by abandoned wait");
    CHECK(WaitForSingleObject(mutex,0)==WAIT_OBJECT_0&&ReleaseMutex(mutex),"later acquisition succeeds without sticky abandonment");
done:
    if(process.hThread)CloseHandle(process.hThread);
    if(process.hProcess)CloseHandle(process.hProcess);
    if(mutex)CloseHandle(mutex);
    if(ready)CloseHandle(ready);
    if(leave)CloseHandle(leave);
    return k32t_finish("T_MUTANT_OWNERSHIP");
}
