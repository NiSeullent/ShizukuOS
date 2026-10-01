/* SPDX-License-Identifier: GPL-2.0-only
 * Entry/start/actual-exit observer for the unchanged read-only Chromium helper.
 * No Chromium entry/TLS/import execution and no large-stager policy changes.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "../process_exit/original_kernel.h"
#include "sha256.h"
typedef BOOL (WINAPI *create_fn)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
typedef DWORD (WINAPI *wait_fn)(HANDLE,DWORD);
typedef BOOL (WINAPI *exit_fn)(HANDLE,LPDWORD);
typedef BOOL (WINAPI *terminate_fn)(HANDLE,UINT);
static HANDLE report=INVALID_HANDLE_VALUE;
static DWORD io_failed;
static void value(const char *name,DWORD v)
{
 char out[128];DWORD n=0,w=0;unsigned i;
 while(*name&&n<sizeof(out)-12)out[n++]=*name++;
 out[n++]='=';for(i=0;i<8;i++)out[n++]="0123456789ABCDEF"[(v>>(28-i*4))&15];out[n++]='\r';out[n++]='\n';
 if(!WriteFile(report,out,n,&w,NULL)||w!=n||!FlushFileBuffers(report))io_failed=1;
}
static int absent(const char *name)
{
 DWORD error;if(GetFileAttributesA(name)!=INVALID_FILE_ATTRIBUTES)return 0;
 error=GetLastError();return error==ERROR_FILE_NOT_FOUND;
}
static int readable_report(const char *name)
{
 HANDLE h;BYTE byte;DWORD bytes=0,error;int okay=1;
 h=CreateFileA(name,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(h==INVALID_HANDLE_VALUE){error=GetLastError();value("INNER_REPORT_OPEN_ERROR",error);return 0;}
 if(!ReadFile(h,&byte,1,&bytes,NULL)){error=GetLastError();value("INNER_REPORT_READ_ERROR",error);okay=0;}
 if(bytes!=1){value("INNER_REPORT_EMPTY_OR_UNREADABLE",1);okay=0;}
 if(!CloseHandle(h)){error=GetLastError();value("INNER_REPORT_CLOSE_ERROR",error);okay=0;}
 return okay;
}
static int helper_pin(void)
{
 static const char expected[]="034fdb8f3a1a0e1f83471d6606f092892db622ae862553a3a9bbfd7b50dcad2c";
 BYTE block[1024],digest[32];char actual[65];sha256_ctx hash;HANDLE h;DWORD bytes=0,n,error;unsigned i;int okay=1;
 h=CreateFileA("C:\\CHRLAB\\CHLWAIT.EXE",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(h==INVALID_HANDLE_VALUE){value("HELPER_OPEN_ERROR",GetLastError());return 0;}
 sha256_init(&hash);
 for(;;){
  if(!ReadFile(h,block,sizeof(block),&n,NULL)){error=GetLastError();value("HELPER_READ_ERROR",error);okay=0;break;}
  if(!n)break;
  if(bytes>8951u||n>8951u-bytes){okay=0;break;}
  bytes+=n;sha256_update(&hash,block,n);
 }
 if(!CloseHandle(h)){error=GetLastError();value("HELPER_CLOSE_ERROR",error);okay=0;}
 sha256_final(&hash,digest);sha256_hex(digest,actual);
 for(i=0;i<64;i++)if(actual[i]!=expected[i])okay=0;
 value("HELPER_ACTUAL_BYTES",bytes);value("HELPER_EXACT_SHA_AND_BYTES",okay&&bytes==8951u);
 return okay&&bytes==8951u&&!io_failed;
}
void WINAPI entry(void)
{
 create_fn create;wait_fn wait_for;exit_fn query_exit;terminate_fn terminate;
 STARTUPINFOA start={0};PROCESS_INFORMATION child={0};char command[]="C:\\CHRLAB\\CHLWAIT.EXE";
 DWORD wait,error,code=STILL_ACTIVE,result=3;int resolver=0,observer_report,structure_report;BOOL stopped;
 report=CreateFileA("C:\\VXDLAB\\CHLRUN.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
 value("OUTER_ENTRY_REACHED",1);value("CHROMIUM_TARGET_ENTRY_CALLS",0);value("CHROMIUM_APPLICATION_ACCEPTED",0);
 value("ACTUAL_ORIGINAL_WIN98_GUARD",px_original_win98());
 create=(create_fn)(void *)px_original_kernel("CreateProcessA",&resolver);
 wait_for=(wait_fn)(void *)px_original_kernel("WaitForSingleObject",NULL);
 query_exit=(exit_fn)(void *)px_original_kernel("GetExitCodeProcess",NULL);
 terminate=(terminate_fn)(void *)px_original_kernel("TerminateProcess",NULL);
 value("ORIGINAL_KERNEL_RESOLVER",resolver);
 if(!create||!wait_for||!query_exit||!terminate||io_failed)goto done;
 if(!absent("C:\\CHRLAB\\CHLWAIT.LOG")||!absent("C:\\CHRLAB\\CHRLARGE.LOG")){
  value("INNER_REPORT_FRESHNESS_FAILED",1);goto done;
 }
 if(!helper_pin())goto done;
 start.cb=sizeof(start);
 if(!create("C:\\CHRLAB\\CHLWAIT.EXE",command,NULL,NULL,FALSE,0,NULL,"C:\\CHRLAB",&start,&child)){
  error=GetLastError();value("CREATE_HELPER_ERROR",error);goto done;
 }
 value("ACTUAL_HELPER_PID",child.dwProcessId);value("HELPER_PROCESS_CREATED",1);
 if(!CloseHandle(child.hThread)){error=GetLastError();value("CLOSE_HELPER_THREAD_ERROR",error);io_failed=1;}
 wait=wait_for(child.hProcess,340000);error=wait==WAIT_FAILED?GetLastError():0;
 value("ACTUAL_HELPER_WAIT",wait);value("ACTUAL_HELPER_WAIT_ERROR",error);
 if(wait==WAIT_OBJECT_0&&query_exit(child.hProcess,&code)){
  value("ACTUAL_HELPER_OS_EXIT",code);
  if(code==0&&!io_failed)result=0;
 }else{
  if(wait==WAIT_OBJECT_0){error=GetLastError();value("HELPER_EXIT_QUERY_ERROR",error);}
  stopped=terminate(child.hProcess,122);error=stopped?0:GetLastError();
  value("GUARD_TERMINATE_HELPER",stopped);value("GUARD_TERMINATE_HELPER_ERROR",error);
  wait=wait_for(child.hProcess,5000);error=wait==WAIT_FAILED?GetLastError():0;
  value("GUARD_HELPER_REAP_WAIT",wait);value("GUARD_HELPER_REAP_ERROR",error);result=5;
 }
 if(!CloseHandle(child.hProcess)){error=GetLastError();value("CLOSE_HELPER_PROCESS_ERROR",error);io_failed=1;}
 observer_report=readable_report("C:\\CHRLAB\\CHLWAIT.LOG");
 structure_report=readable_report("C:\\CHRLAB\\CHRLARGE.LOG");
 value("INNER_OBSERVER_LOG_READABLE",observer_report);
 value("INNER_STRUCTURE_LOG_READABLE",structure_report);
 if(result==0&&(!observer_report||!structure_report))result=6;
done:
 if(io_failed)result=31;
 value("OUTER_SELECTED_RESULT",result);value("OUTER_OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER",1);
 if(!CloseHandle(report))io_failed=1;ExitProcess(io_failed?31:result);
}
