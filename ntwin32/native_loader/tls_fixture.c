/* SPDX-License-Identifier: GPL-2.0-only
 * Real MS-ABI static TLS directory, callbacks and native target thread control.
 * This is an own-built fixture; it is never evidence of latest-app success.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
extern unsigned ntw_tls_compiler_word;
extern unsigned ntw_tls_compiler_read(void);
extern void ntw_tls_compiler_write(unsigned);
DWORD _tls_index=0xdeadbeefu;
static HINSTANCE attached;
static HANDLE output;
static DWORD checks,failures,process_callback,thread_callback,thread_entry,thread_detach,process_detach;
static unsigned length(const char *s){unsigned n=0;while(s[n])n++;return n;}
static void check(const char *name,int ok)
{
 char line[160];DWORD written;unsigned n=0,k=0;const char *prefix=ok?"TLSFIX_PASS=":"TLSFIX_FAIL=";
 InterlockedIncrement((LONG *)&checks);if(!ok)InterlockedIncrement((LONG *)&failures);
 while(prefix[k])line[n++]=prefix[k++];k=0;while(name[k]&&n<150)line[n++]=name[k++];line[n++]='\r';line[n++]='\n';
 if(!WriteFile(output?output:GetStdHandle(STD_OUTPUT_HANDLE),line,n,&written,NULL)||written!=n)InterlockedIncrement((LONG *)&failures);
}
static void WINAPI callback(void *base,DWORD reason,void *reserved)
{
 check("CALLBACK_RESERVED_NULL",reserved==NULL);
 if(reason==DLL_PROCESS_ATTACH){
  check("CALLBACK_INITIAL_TEMPLATE",ntw_tls_compiler_read()==0x1234abcdu);
  check("CALLBACK_LOGICAL_MODULE_IDENTITY",GetModuleHandleA("PE32TLS.DLL")==base);
  process_callback=1;
 }else if(reason==DLL_THREAD_ATTACH){
  check("THREAD_CALLBACK_INITIAL_TEMPLATE",ntw_tls_compiler_read()==0x1234abcdu);
  ntw_tls_compiler_write(0x11111111u);InterlockedIncrement((LONG *)&thread_callback);
 }else if(reason==DLL_THREAD_DETACH){
  check("THREAD_CALLBACK_FINAL_VALUE",ntw_tls_compiler_read()==0xbadc0ffeu);
  InterlockedIncrement((LONG *)&thread_detach);
 }else if(reason==DLL_PROCESS_DETACH){
  check("PROCESS_CALLBACK_FINAL_VALUE",ntw_tls_compiler_read()==0xcafebabeu);
  check("PROCESS_CALLBACK_THREAD_COUNTS",thread_callback==1&&thread_entry==1&&thread_detach==1);
  process_detach=1;
 }
}
static PIMAGE_TLS_CALLBACK callbacks[]={callback,NULL};
const IMAGE_TLS_DIRECTORY32 _tls_used={
 (DWORD)(UINT_PTR)&ntw_tls_compiler_word,(DWORD)(UINT_PTR)&ntw_tls_compiler_word+4,
 (DWORD)(UINT_PTR)&_tls_index,(DWORD)(UINT_PTR)callbacks,28,0x00700000u
};
BOOL WINAPI DllMain(HINSTANCE base,DWORD reason,void *reserved)
{
 (void)reserved;
 if(reason==DLL_PROCESS_ATTACH){attached=base;check("DLLMAIN_AFTER_PROCESS_TLS_CALLBACK",process_callback==1);}
 if(reason==DLL_THREAD_ATTACH){check("DLLMAIN_AFTER_THREAD_TLS_CALLBACK",ntw_tls_compiler_read()==0x11111111u);InterlockedIncrement((LONG *)&thread_entry);}
 if(reason==DLL_THREAD_DETACH){check("DLLMAIN_AFTER_THREAD_TLS_DETACH_CALLBACK",thread_detach==1);check("DLLMAIN_THREAD_TLS_STILL_PUBLISHED",ntw_tls_compiler_read()==0xbadc0ffeu);}
 if(reason==DLL_PROCESS_DETACH){check("DLLMAIN_AFTER_PROCESS_TLS_DETACH_CALLBACK",process_detach==1);check("DLLMAIN_MAIN_TLS_STILL_PUBLISHED",ntw_tls_compiler_read()==0xcafebabeu);attached=NULL;}
 return TRUE;
}
static DWORD WINAPI target_worker(void *argument)
{
 check("WORKER_ARGUMENT",argument==(void *)(UINT_PTR)0x2468aceu);
 check("WORKER_CALLBACK_VALUE",ntw_tls_compiler_read()==0x11111111u);
 check("WORKER_ACTUAL_PROCESS_MAIN_IDENTITY",GetModuleHandleA(NULL)!=NULL&&GetModuleHandleA(NULL)!=attached);
 ntw_tls_compiler_write(0xbadc0ffeu);check("WORKER_COMPILER_WRITE_READ",ntw_tls_compiler_read()==0xbadc0ffeu);
 return 0;
}
DWORD WINAPI NtwPeFixture(HINSTANCE base,HANDLE report)
{
 char path[MAX_PATH];WCHAR wide[MAX_PATH];DWORD n,id,exit=STILL_ACTIVE;HANDLE thread;HMODULE loaded;
 output=report;check("ACTUAL_MAPPED_BASE_DLLMAIN",attached==base);
 check("MAIN_COMPILER_TEMPLATE",ntw_tls_compiler_read()==0x1234abcdu);
 check("DLL_SELF_DISTINCT_FROM_ACTUAL_PROCESS_MAIN",GetModuleHandleA(NULL)!=NULL&&GetModuleHandleA(NULL)!=base);
 n=GetModuleFileNameA(NULL,path,sizeof(path));check("ACTUAL_PROCESS_MAIN_FILENAME_EXE",n>4&&n<sizeof(path)&&path[n-4]=='.'&&(path[n-3]=='E'||path[n-3]=='e')&&(path[n-2]=='X'||path[n-2]=='x')&&(path[n-1]=='E'||path[n-1]=='e'));
 check("LOGICAL_DLL_HANDLE_WIDE",GetModuleHandleW(L"PE32TLS.DLL")==base);
 n=GetModuleFileNameA(base,path,sizeof(path));check("LOGICAL_MODULE_FILENAME",n>12&&n<sizeof(path)&&GetModuleHandleA(path)==base);
 check("LOGICAL_MODULE_FILENAME_WIDE",GetModuleFileNameW(base,wide,MAX_PATH)==n);
 check("VALIDATED_MAPPED_EXPORT",GetProcAddress(base,"NtwPeFixture")== (FARPROC)(void *)NtwPeFixture);
 check("INVALID_MODULE_HANDLE_REJECTED",GetProcAddress((HMODULE)(UINT_PTR)0x12340000,"NtwPeFixture")==NULL);
 loaded=LoadLibraryA("PE32TLS.DLL");check("EXISTING_MODULE_REFERENCE",loaded==base);
 check("OWNED_REFERENCE_RELEASE",FreeLibrary(loaded));check("BORROWED_HANDLE_RELEASE_REJECTED",!FreeLibrary(base));
 check("UNIMPLEMENTED_GRAPH_EXTENSION_REJECTED",LoadLibraryA("UNOWNED.DLL")==NULL);
 check("ACTUAL_HOST_COMMAND_LINE",GetCommandLineA()[0]=='"'&&length(GetCommandLineA())>12);
 ntw_tls_compiler_write(0xcafebabeu);
 thread=CreateThread(NULL,0,target_worker,(void *)(UINT_PTR)0x2468aceu,0,&id);check("ACTUAL_TARGET_THREAD_CREATE",thread!=NULL);
 if(thread){DWORD wait=WaitForSingleObject(thread,10000);check("ACTUAL_TARGET_THREAD_JOIN",wait==WAIT_OBJECT_0);
  if(wait!=WAIT_OBJECT_0)return 44;
  check("ACTUAL_TARGET_THREAD_EXIT_QUERY",GetExitCodeThread(thread,&exit));check("ACTUAL_TARGET_THREAD_EXIT_ZERO",exit==0);CloseHandle(thread);
 }
 check("MAIN_COMPILER_VALUE_ISOLATED",ntw_tls_compiler_read()==0xcafebabeu);
 check("THREAD_NOTIFICATION_COUNTS",thread_callback==1&&thread_entry==1&&thread_detach==1);
 return failures?31:0;
}
