/* SPDX-License-Identifier: GPL-2.0-only
 * Own OS-managed notification DLL, Kernel32-only, without a CRT or static TLS.
 * This never intercepts or emulates ExitProcess.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "exit_registry.h"
#include "main_image.h"
#include "original_kernel.h"
#include "win98_guard.h"
static HMODULE own,pin;static px_image main_image;static px_registry registry;
static volatile LONG initialized;
#ifdef PX_TEST_DYNAMIC_UNLOAD
static DWORD *observation;
#endif
static uint32_t load(void *opaque,volatile uint32_t *p){(void)opaque;return (uint32_t)InterlockedCompareExchange((volatile LONG *)p,0,0);}
static uint32_t cas(void *opaque,volatile uint32_t *p,uint32_t before,uint32_t after){(void)opaque;return (uint32_t)InterlockedCompareExchange((volatile LONG *)p,(LONG)after,(LONG)before);}
static int readable(DWORD p){return !(p&(PAGE_GUARD|PAGE_NOACCESS))&&(p&(PAGE_READONLY|PAGE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY));}
static int validate(void *opaque,px_callback cb,void *context,size_t bytes)
{
 MEMORY_BASIC_INFORMATION code,data;px_page cp,dp;(void)opaque;
 if(!px_main_callback(&main_image,(uintptr_t)cb,(uintptr_t)context,bytes)||
    VirtualQuery((void *)(UINT_PTR)cb,&code,sizeof(code))!=sizeof(code)||VirtualQuery(context,&data,sizeof(data))!=sizeof(data))return 0;
 cp.allocation=(uintptr_t)code.AllocationBase;cp.base=(uintptr_t)code.BaseAddress;cp.bytes=code.RegionSize;cp.state=code.State;cp.protection=code.Protect;
 dp.allocation=(uintptr_t)data.AllocationBase;dp.base=(uintptr_t)data.BaseAddress;dp.bytes=data.RegionSize;dp.state=data.State;dp.protection=data.Protect;
 /* initialized requires the actual original Win98 version query first. */
 return readable(code.Protect)&&px_guard_code(&main_image,(uintptr_t)cb,&cp,1)&&px_guard_data(&main_image,(uintptr_t)context,bytes,&dp);
}
BOOL WINAPI M98ExitInitialize(void)
{
 HMODULE main;MEMORY_BASIC_INFORMATION info;px_ops ops={0,load,cas,validate};
#ifndef PX_TEST_DYNAMIC_UNLOAD
 char path[MAX_PATH];DWORD n;
#endif
 LONG prior=InterlockedCompareExchange(&initialized,1,0);
 if(prior==2)return TRUE;if(prior){SetLastError(ERROR_BUSY);return FALSE;}
 main=GetModuleHandleA(NULL);
 if(!px_original_win98()||!main||VirtualQuery(main,&info,sizeof(info))!=sizeof(info)||
    info.AllocationBase!=main||info.BaseAddress!=main||info.State!=MEM_COMMIT||!readable(info.Protect)||
    !px_main_image(&main_image,main,info.RegionSize,(uintptr_t)main))goto invalid;
#ifndef PX_TEST_DYNAMIC_UNLOAD
 n=GetModuleFileNameA(own,path,sizeof(path));if(!n||n>=sizeof(path))goto invalid;
 pin=LoadLibraryA(path);if(pin!=own){if(pin)FreeLibrary(pin);pin=NULL;goto invalid;}
#endif
 if(!px_init(&registry,&ops)){FreeLibrary(pin);pin=NULL;goto invalid;}
 InterlockedExchange(&initialized,2);return TRUE;
invalid:
 InterlockedExchange(&initialized,0);SetLastError(ERROR_INVALID_PARAMETER);return FALSE;
}
BOOL WINAPI M98ExitRegister(px_callback cb,void *context,DWORD bytes,DWORD *token)
{uint32_t error=0;BOOL okay;if(InterlockedCompareExchange(&initialized,2,2)!=2){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
 okay=px_register(&registry,cb,context,bytes,(uint32_t *)token,&error);if(!okay)SetLastError(error);return okay;}
BOOL WINAPI M98ExitUnregister(DWORD token)
{uint32_t error=0;BOOL okay;if(InterlockedCompareExchange(&initialized,2,2)!=2){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
 okay=px_unregister(&registry,token,&error);if(!okay)SetLastError(error);return okay;}
DWORD WINAPI M98ExitCount(void)
{return InterlockedCompareExchange(&initialized,2,2)==2?px_count(&registry):0;}
#ifdef PX_TEST_DYNAMIC_UNLOAD
/* This export and the absent pin exist ONLY in the distinct PXUNLD fixture.
 * Production M98EXIT has neither behavior. Test context still belongs to EXE.
 */
BOOL WINAPI PXTestObserve(DWORD *state)
{uint32_t index;if(InterlockedCompareExchange(&initialized,2,2)!=2)return FALSE;index=load(NULL,&registry.current);
 if((index&PX_CLOSED)||!registry.snapshots[index].count||!validate(NULL,registry.snapshots[index].records[0].callback,state,3*sizeof(*state)))return FALSE;
 observation=state;return TRUE;}
#endif
BOOL WINAPI dll_entry(HINSTANCE instance,DWORD reason,void *reserved)
{
 if(reason==DLL_PROCESS_ATTACH)own=instance;
#ifdef PX_TEST_DYNAMIC_UNLOAD
 if(reason==DLL_PROCESS_DETACH&&observation){observation[0]=reason;observation[1]=reserved!=NULL;observation[2]=0x50584431u;}
#endif
 if(reason==DLL_PROCESS_DETACH&&reserved&&InterlockedCompareExchange(&initialized,2,2)==2){uint32_t error;
  /* No mutator lock, resource reclamation, load/unload, or worker wait. */
  px_terminate(&registry,reason,(uintptr_t)reserved,&error);
 }
 return TRUE;
}
