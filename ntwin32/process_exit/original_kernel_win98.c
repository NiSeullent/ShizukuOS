/* SPDX-License-Identifier: GPL-2.0-only
 * SDK contract: KernelEx 31cdfc3560fc116637ee8ed7be31b12f3aacf5d1
 * common/kexcoresdk.h:262 and core/kexcoresdk.cpp:329 (cdecl, two arguments).
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include "original_kernel.h"
#include "win98_guard.h"
typedef FARPROC (__cdecl *original_fn)(HMODULE,const char *);
static HMODULE owned_core;
static int verified_win98;
static FARPROC lookup_original(const char *name,int *used)
{
 HMODULE kernel=GetModuleHandleA("KERNEL32.DLL"),core=GetModuleHandleA("KERNELEX.DLL");FARPROC result;
 if(used)*used=0;if(!kernel)return NULL;
 if(core){union {FARPROC generic;original_fn typed;} resolver;
  /* Explicit init is serialized by the consumer; never called in DllMain.
   * This owned native core reference is intentionally process lifetime. */
  if(!owned_core){char path[MAX_PATH];DWORD n=GetModuleFileNameA(core,path,sizeof(path));HMODULE ref;
   if(!n||n>=sizeof(path))return NULL;ref=LoadLibraryA(path);if(ref!=core){if(ref)FreeLibrary(ref);return NULL;}owned_core=ref;
  }
  if(owned_core!=core)return NULL;resolver.generic=GetProcAddress(owned_core,"kexGetProcAddress");
  if(!resolver.generic)return NULL;result=resolver.typed(kernel,name);if(used)*used=1;
 }else result=GetProcAddress(kernel,name);
 return result;
}
static int kernel_code(FARPROC code)
{
 HMODULE kernel=GetModuleHandleA("KERNEL32.DLL");MEMORY_BASIC_INFORMATION head,info;px_image image;px_page page;size_t available;
 if(!kernel||!code||VirtualQuery(kernel,&head,sizeof(head))!=sizeof(head)||head.AllocationBase!=kernel||head.BaseAddress!=kernel||
    head.State!=MEM_COMMIT||(head.Protect!=PAGE_READONLY&&head.Protect!=PAGE_EXECUTE_READ)||!head.RegionSize)return 0;
 available=head.RegionSize<4096?head.RegionSize:4096;
 if(!px_kernel_image(&image,kernel,available,(uintptr_t)kernel)||VirtualQuery((void *)(UINT_PTR)code,&info,sizeof(info))!=sizeof(info))return 0;
 page.allocation=(uintptr_t)info.AllocationBase;page.base=(uintptr_t)info.BaseAddress;page.bytes=info.RegionSize;page.state=info.State;page.protection=info.Protect;
 /* Used before the full version query ONLY for its exact original named
  * GetVersionExA export, rooted in the native Kernel32 executable PE section.
  * Ordinary export/callback admission requires the completed version check. */
 return px_guard_code(&image,(uintptr_t)code,&page,1);
}
FARPROC px_original_kernel(const char *name,int *used)
{
 FARPROC result;if(used)*used=0;
 if(!verified_win98&&!px_original_win98())return NULL;
 result=lookup_original(name,used);return kernel_code(result)?result:NULL;
}

int px_original_win98(void)
{
 typedef BOOL (WINAPI *version_fn)(OSVERSIONINFOA *);version_fn query=(version_fn)lookup_original("GetVersionExA",NULL);OSVERSIONINFOA os;unsigned i;
 for(i=0;i<sizeof(os);i++)((BYTE *)&os)[i]=0;os.dwOSVersionInfoSize=sizeof(os);
 verified_win98=0;
 if(!kernel_code((FARPROC)query)||!query(&os)||os.dwPlatformId!=VER_PLATFORM_WIN32_WINDOWS||os.dwMajorVersion!=4||os.dwMinorVersion!=10||(os.dwBuildNumber&65535u)!=2222)return 0;
 verified_win98=1;return 1;
}
