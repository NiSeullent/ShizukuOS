/* SPDX-License-Identifier: GPL-2.0-only
 * SDK contract: KernelEx 31cdfc3560fc116637ee8ed7be31b12f3aacf5d1
 * common/kexcoresdk.h:262 and core/kexcoresdk.cpp:329 (cdecl, two arguments).
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include "original_kernel.h"
typedef FARPROC (__cdecl *original_fn)(HMODULE,const char *);
static HMODULE owned_core;
FARPROC px_original_kernel(const char *name,int *used)
{
 HMODULE kernel=GetModuleHandleA("KERNEL32.DLL"),core=GetModuleHandleA("KERNELEX.DLL");FARPROC result;MEMORY_BASIC_INFORMATION info;
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
 if(!result||VirtualQuery((const void *)(UINT_PTR)result,&info,sizeof(info))!=sizeof(info)||info.AllocationBase!=kernel||info.State!=MEM_COMMIT||
    (info.Protect&(PAGE_GUARD|PAGE_NOACCESS))||!(info.Protect&(PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)))return NULL;
 return result;
}
int px_original_win98(void)
{
 typedef BOOL (WINAPI *version_fn)(OSVERSIONINFOA *);version_fn query=(version_fn)px_original_kernel("GetVersionExA",NULL);OSVERSIONINFOA os;unsigned i;
 for(i=0;i<sizeof(os);i++)((BYTE *)&os)[i]=0;os.dwOSVersionInfoSize=sizeof(os);
 return query&&query(&os)&&os.dwPlatformId==VER_PLATFORM_WIN32_WINDOWS&&os.dwMajorVersion==4&&os.dwMinorVersion==10&&(os.dwBuildNumber&65535u)==2222;
}
