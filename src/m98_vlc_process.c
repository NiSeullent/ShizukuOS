/* SPDX-License-Identifier: GPL-2.0-only
 * KernelEx service signatures/Win98 object fields follow the pinned
 * 31cdfc3560fc116637ee8ed7be31b12f3aacf5d1 common/kexcoresdk.h,
 * common/kstructs.h and core/kexcoresdk.cpp. No internal function scanning,
 * Windows binary patching, PDB writes or invented thread/process identities.
 */
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include "m98_vlc_process.h"
#include "kex_abi.h"
#include <stddef.h>
typedef FARPROC (__cdecl *native_lookup)(HMODULE,const char *);
typedef BOOL (WINAPI *version_query)(LPOSVERSIONINFOA);
typedef HANDLE (__cdecl *open_thread_service)(DWORD,BOOL,DWORD);
typedef void *(__cdecl *object_service)(HANDLE,WORD,DWORD);
typedef DWORD (__cdecl *access_service)(HANDLE);
typedef void (__cdecl *lock_service)(void);
typedef struct {
 HMODULE core;
 native_lookup lookup;
 object_service object;
 access_service access;
 lock_service enter,leave;
} services;
static native_lookup as_lookup(FARPROC p){union { FARPROC generic;native_lookup typed; } u;u.generic=p;return u.typed;}
static object_service as_object(FARPROC p){union { FARPROC generic;object_service typed; } u;u.generic=p;return u.typed;}
static open_thread_service as_open_thread(FARPROC p){union { FARPROC generic;open_thread_service typed; } u;u.generic=p;return u.typed;}
static void bytes_zero(void *p,unsigned n){unsigned i;for(i=0;i<n;i++)((BYTE *)p)[i]=0;}
static void services_close(services *s){if(s->core)FreeLibrary(s->core);}
static int services_open(services *s){HMODULE resident,kernel;char path[MAX_PATH];DWORD count;OSVERSIONINFOA v;version_query query;
 bytes_zero(s,sizeof(*s));resident=GetModuleHandleA("KERNELEX.DLL");kernel=GetModuleHandleA("KERNEL32.DLL");
 if(!kernel){SetLastError(ERROR_CALL_NOT_IMPLEMENTED);return 0;}
 if(resident){
  count=GetModuleFileNameA(resident,path,MAX_PATH);
  if(!count||count>=MAX_PATH){SetLastError(ERROR_CALL_NOT_IMPLEMENTED);return 0;}
  s->core=LoadLibraryA(path);
  if(!s->core||s->core!=resident){services_close(s);s->core=NULL;SetLastError(ERROR_CALL_NOT_IMPLEMENTED);return 0;}
  s->lookup=as_lookup(GetProcAddress(s->core,"kexGetProcAddress"));
 }
 /* KernelEx's exported resolver deliberately retrieves original Kernel32
  * exports. The host ABI guard must not consume a configured WINXP version
  * facade in the target application. */
 query=(version_query)(s->lookup?s->lookup(kernel,"GetVersionExA"):GetProcAddress(kernel,"GetVersionExA"));
 bytes_zero(&v,sizeof(v));v.dwOSVersionInfoSize=sizeof(v);
 if(!query||!query(&v)||v.dwPlatformId!=VER_PLATFORM_WIN32_WINDOWS||v.dwMajorVersion!=4||v.dwMinorVersion!=10||(v.dwBuildNumber&65535)!=2222){services_close(s);s->core=NULL;SetLastError(ERROR_CALL_NOT_IMPLEMENTED);return 0;}
 if(s->core){
  s->object=as_object(GetProcAddress(s->core,"kexGetHandleObject"));
  s->access=(access_service)GetProcAddress(s->core,"kexGetHandleAccess");
  s->enter=(lock_service)GetProcAddress(s->core,"kexGrabKrnl32Lock");
  s->leave=(lock_service)GetProcAddress(s->core,"kexReleaseKrnl32Lock");
 }
 return 1;
}
static FARPROC original(const services *s,const char *name){HMODULE kernel=GetModuleHandleA("KERNEL32.DLL");return s->lookup?s->lookup(kernel,name):GetProcAddress(kernel,name);}
static void *current_pdb(void){void *value;__asm__ __volatile__("movl %%fs:0x30,%0":"=r"(value));return value;}
static void *process_object(services *s,HANDLE h){void *p;DWORD rights;
 if(!s->object||!s->access||!s->enter||!s->leave){SetLastError(ERROR_CALL_NOT_IMPLEMENTED);return NULL;}
 s->enter();rights=s->access(h);
 if(!(rights&PROCESS_QUERY_INFORMATION)){s->leave();SetLastError(ERROR_ACCESS_DENIED);return NULL;}
 p=s->object(h,6,0);
 if(!p||IsBadReadPtr(p,0xc4)||*(BYTE *)p!=6){s->leave();SetLastError(ERROR_INVALID_HANDLE);return NULL;}
 /* Return with the real Kernel32 lock held until the caller copies fields. */
 return p;
}
DWORD WINAPI m98_vlc_GetProcessId(HANDLE h){services s;DWORD result;void *p;
 if(!h||h==INVALID_HANDLE_VALUE){SetLastError(ERROR_INVALID_HANDLE);return 0;}
 if(!services_open(&s))return 0;
 if(h==GetCurrentProcess()){typedef DWORD (WINAPI *getid)(void);getid api=(getid)original(&s,"GetCurrentProcessId");result=api?api():0;if(!api)SetLastError(ERROR_CALL_NOT_IMPLEMENTED);services_close(&s);return result;}
 p=process_object(&s,h);if(!p){DWORD e=GetLastError();services_close(&s);SetLastError(e);return 0;}
 /* Win98 IDs encode the genuine PDB pointer using the native current-ID
  * obfuscator, exactly as the pinned KernelEx GetProcessId implementation. */
 result=(DWORD)(UINT_PTR)p^(DWORD)(UINT_PTR)current_pdb()^GetCurrentProcessId();s.leave();services_close(&s);return result;
}
HANDLE WINAPI m98_vlc_OpenThread(DWORD access,BOOL inherit,DWORD id){services s;open_thread_service api;HANDLE result=NULL;DWORD error;
 if(!id){SetLastError(ERROR_INVALID_PARAMETER);return NULL;}
 if(!services_open(&s))return NULL;
 api=s.core?as_open_thread(GetProcAddress(s.core,"kexOpenThread")):NULL;
 if(api)result=api(access,inherit,id);
 else if(id==GetCurrentThreadId()){
  if(!DuplicateHandle(GetCurrentProcess(),GetCurrentThread(),GetCurrentProcess(),&result,access,inherit,0))result=NULL;
 }else SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
 error=GetLastError();services_close(&s);if(!result)SetLastError(error);return result;
}
BOOL WINAPI m98_vlc_CheckRemoteDebuggerPresent(HANDLE h,PBOOL output){services s;void *p;BOOL value;
 if(!output||IsBadWritePtr(output,sizeof(*output))){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
 if(!h||h==INVALID_HANDLE_VALUE){SetLastError(ERROR_INVALID_HANDLE);return FALSE;}
 if(!services_open(&s))return FALSE;
 if(h==GetCurrentProcess()){
  typedef BOOL (WINAPI *debugged)(void);debugged api=(debugged)original(&s,"IsDebuggerPresent");
  if(!api){services_close(&s);SetLastError(ERROR_CALL_NOT_IMPLEMENTED);return FALSE;}value=api();
 }else{
  p=process_object(&s,h);if(!p){DWORD e=GetLastError();services_close(&s);SetLastError(e);return FALSE;}
  /* The native OEM IsDebuggerPresent export checks PDB98.DebuggeeCB (+54). */
  value=*(DWORD *)((BYTE *)p+0x54)!=0;s.leave();
 }
 services_close(&s);*output=value;return TRUE;
}
_Static_assert(offsetof(CONTEXT,Eax)==0xb0&&offsetof(CONTEXT,Eip)==0xb8&&offsetof(CONTEXT,Esp)==0xc4,"x86 context ABI required");
__attribute__((naked)) VOID WINAPI m98_vlc_RtlCaptureContext(PCONTEXT record __attribute__((unused))){
 /* Snapshot before scratch-register use. At SP after pushf/pusha: saved
  * EDI/ESI/EBP/SP/EBX/EDX/ECX/EAX, flags, return EIP, argument pointer.
  * Captured ESP is the actual caller's post-stdcall-return stack position;
  * captured EBP is the caller register, without assuming a frame pointer. */
 __asm__ __volatile__(
  "pushfl\n\tpushal\n\tmovl 40(%esp),%edx\n\t"
  "movl 28(%esp),%eax\n\tmovl %eax,0xb0(%edx)\n\t"
  "movl 24(%esp),%eax\n\tmovl %eax,0xac(%edx)\n\t"
  "movl 20(%esp),%eax\n\tmovl %eax,0xa8(%edx)\n\t"
  "movl 16(%esp),%eax\n\tmovl %eax,0xa4(%edx)\n\t"
  "movl 8(%esp),%eax\n\tmovl %eax,0xb4(%edx)\n\t"
  "movl 4(%esp),%eax\n\tmovl %eax,0xa0(%edx)\n\t"
  "movl 0(%esp),%eax\n\tmovl %eax,0x9c(%edx)\n\t"
  "movl 12(%esp),%eax\n\taddl $12,%eax\n\tmovl %eax,0xc4(%edx)\n\t"
  "movl 32(%esp),%eax\n\tmovl %eax,0xc0(%edx)\n\t"
  "movl 36(%esp),%eax\n\tmovl %eax,0xb8(%edx)\n\t"
  "xorl %eax,%eax\n\tmovw %cs,%ax\n\tmovl %eax,0xbc(%edx)\n\t"
  "movw %ds,%ax\n\tmovl %eax,0x98(%edx)\n\t"
  "movw %es,%ax\n\tmovl %eax,0x94(%edx)\n\t"
  "movw %fs,%ax\n\tmovl %eax,0x90(%edx)\n\t"
  "movw %gs,%ax\n\tmovl %eax,0x8c(%edx)\n\t"
  "movw %ss,%ax\n\tmovl %eax,0xc8(%edx)\n\t"
  "movl $0x10007,0(%edx)\n\tpopal\n\tpopfl\n\tret $4\n\t");
}
static const m98_named_api names[]={
 {"CheckRemoteDebuggerPresent",(unsigned long)m98_vlc_CheckRemoteDebuggerPresent},
 {"GetProcessId",(unsigned long)m98_vlc_GetProcessId},
 {"OpenThread",(unsigned long)m98_vlc_OpenThread},
 {"RtlCaptureContext",(unsigned long)m98_vlc_RtlCaptureContext}
};
static const m98_api_table tables[]={{"KERNEL32.DLL",names,4,NULL,0},{NULL,NULL,0,NULL,0}};
const m98_api_table *__cdecl get_api_table(void){return tables;}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved){(void)module;(void)reason;(void)reserved;return TRUE;}
