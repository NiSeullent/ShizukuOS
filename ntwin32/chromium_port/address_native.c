/* SPDX-License-Identifier: GPL-2.0-only */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "address_wait.h"
static CRITICAL_SECTION lock;
static aw_context context;
static void enter(void *p){(void)p;EnterCriticalSection(&lock);}
static void leave(void *p){(void)p;LeaveCriticalSection(&lock);}
static uintptr_t create(void *p){(void)p;return (uintptr_t)CreateEventA(0,FALSE,FALSE,0);}
static int signal(void *p,uintptr_t h){(void)p;return SetEvent((HANDLE)h)!=0;}
static uint32_t wait(void *p,uintptr_t h,uint32_t t){(void)p;return WaitForSingleObject((HANDLE)h,t);}
static int close_event(void *p,uintptr_t h){(void)p;return CloseHandle((HANDLE)h)!=0;}
static uint32_t error(void *p){(void)p;return GetLastError();}
BOOL WINAPI m98_wait(volatile void *a,void *b,SIZE_T size,DWORD timeout)
{uint32_t e;int result=aw_wait(&context,a,b,size,timeout,&e);if(!result)SetLastError(e);return result;}
void WINAPI m98_single(void *a){uint32_t e;if(!aw_wake(&context,a,0,&e))SetLastError(e);}
void WINAPI m98_all(void *a){uint32_t e;if(!aw_wake(&context,a,1,&e))SetLastError(e);}
BOOL WINAPI m98_cleanup(DWORD quiescent){uint32_t e;int result=aw_cleanup(&context,quiescent,&e);if(!result)SetLastError(e);return result;}
DWORD WINAPI m98_pending(void){return aw_pending(&context);}
BOOL WINAPI dll_entry(HINSTANCE instance,DWORD reason,LPVOID reserved)
{
 (void)instance;(void)reserved;
 if(reason==DLL_PROCESS_ATTACH){aw_ops ops={0,enter,leave,create,signal,wait,close_event,error};InitializeCriticalSection(&lock);return aw_init(&context,&ops);}
 /* Unload is permitted only after calling threads join and cleanup succeeds.
  * Process termination releases OS-owned handles; DllMain never joins workers. */
 if(reason==DLL_PROCESS_DETACH)DeleteCriticalSection(&lock);
 return TRUE;
}
