/* SPDX-License-Identifier: GPL-2.0-only -- actual OWN probe process observer. */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "../process_exit/original_kernel.h"
#include "sha256.h"
#include "probe_pins.h"
static HANDLE report=INVALID_HANDLE_VALUE;
static int io_failed;
static void value(const char *name,DWORD v)
{
 char out[128];DWORD n=0,w=0;unsigned i;
 while(*name&&n<sizeof(out)-12)out[n++]=*name++;
 out[n++]='=';for(i=0;i<8;i++)out[n++]="0123456789ABCDEF"[(v>>(28-i*4))&15];out[n++]='\r';out[n++]='\n';
 if(!WriteFile(report,out,n,&w,NULL)||w!=n||!FlushFileBuffers(report))io_failed=1;
}
static int pin_probe(void)
{
 HANDLE file;BYTE block[1024],digest[32];char actual[65];sha256_ctx hash;
 DWORD n,total=0,error;unsigned i;int okay=1;
 file=CreateFileA("C:\\VXDLAB\\RRPROBE.EXE",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(file==INVALID_HANDLE_VALUE){error=GetLastError();value("PROBE_OPEN_ERROR",error);return 0;}
 sha256_init(&hash);
 for(;;){if(!ReadFile(file,block,sizeof(block),&n,NULL)){error=GetLastError();value("PROBE_READ_ERROR",error);okay=0;break;}
  if(!n)break;if(total>RR_PROBE_BYTES||n>RR_PROBE_BYTES-total){okay=0;break;}total+=n;sha256_update(&hash,block,n);}
 if(!CloseHandle(file)){error=GetLastError();value("PROBE_CLOSE_ERROR",error);okay=0;}
 sha256_final(&hash,digest);sha256_hex(digest,actual);
 for(i=0;i<64;i++)if(actual[i]!=RR_PROBE_SHA[i])okay=0;
 value("PROBE_ACTUAL_BYTES",total);value("PROBE_EXACT_SHA_AND_EOF",okay&&total==RR_PROBE_BYTES);
 return okay&&total==RR_PROBE_BYTES&&!io_failed;
}
static int readable_log(void)
{
 HANDLE file;BYTE first;DWORD got,error;int okay=1;
 file=CreateFileA("C:\\VXDLAB\\RRPROBE.LOG",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(file==INVALID_HANDLE_VALUE){error=GetLastError();value("PROBE_LOG_OPEN_ERROR",error);return 0;}
 if(!ReadFile(file,&first,1,&got,NULL)){error=GetLastError();value("PROBE_LOG_READ_ERROR",error);okay=0;}
 else if(got!=1)okay=0;
 if(!CloseHandle(file)){error=GetLastError();value("PROBE_LOG_CLOSE_ERROR",error);io_failed=1;okay=0;}
 return okay;
}
void WINAPI entry(void)
{
 typedef BOOL (WINAPI *create_fn)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
 typedef DWORD (WINAPI *wait_fn)(HANDLE,DWORD);
 typedef BOOL (WINAPI *query_fn)(HANDLE,LPDWORD);
 typedef BOOL (WINAPI *terminate_fn)(HANDLE,UINT);
 create_fn create;wait_fn wait;query_fn query;terminate_fn terminate;
 STARTUPINFOA start={0};PROCESS_INFORMATION child={0};char command[]="C:\\VXDLAB\\RRPROBE.EXE";
 DWORD attrs,error,waited,exit_code=STILL_ACTIVE,result=3;BOOL stopped;
 report=CreateFileA("C:\\VXDLAB\\RRWAIT.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
 value("OUTER_RESOURCE_OBSERVER_ENTRY",1);value("CHROMIUM_APPLICATION_ACCEPTED",0);
 if(!px_original_win98()){value("ACTUAL_ORIGINAL_WIN98_GUARD",0);goto done;}value("ACTUAL_ORIGINAL_WIN98_GUARD",1);
 create=(create_fn)(void *)px_original_kernel("CreateProcessA",NULL);
 wait=(wait_fn)(void *)px_original_kernel("WaitForSingleObject",NULL);
 query=(query_fn)(void *)px_original_kernel("GetExitCodeProcess",NULL);
 terminate=(terminate_fn)(void *)px_original_kernel("TerminateProcess",NULL);
 if(!create||!wait||!query||!terminate||io_failed)goto done;
 attrs=GetFileAttributesA("C:\\VXDLAB\\RRPROBE.LOG");error=attrs==INVALID_FILE_ATTRIBUTES?GetLastError():0;
 value("PROBE_LOG_BEFORE_ERROR",error);if(attrs!=INVALID_FILE_ATTRIBUTES||error!=ERROR_FILE_NOT_FOUND||!pin_probe())goto done;
 start.cb=sizeof(start);
 if(!create(command,command,NULL,NULL,FALSE,0,NULL,"C:\\VXDLAB",&start,&child)){error=GetLastError();value("CREATE_PROBE_ERROR",error);goto done;}
 value("ACTUAL_PROBE_PID",child.dwProcessId);
 if(!CloseHandle(child.hThread)){error=GetLastError();value("THREAD_CLOSE_ERROR",error);io_failed=1;}
 waited=wait(child.hProcess,30000);error=waited==WAIT_FAILED?GetLastError():0;
 value("ACTUAL_PROBE_WAIT",waited);value("ACTUAL_PROBE_WAIT_ERROR",error);
 if(waited==WAIT_OBJECT_0&&query(child.hProcess,&exit_code)){
  value("ACTUAL_PROBE_OS_EXIT",exit_code);if(!exit_code&&!io_failed)result=0;
 }else{
  if(waited==WAIT_OBJECT_0){error=GetLastError();value("EXIT_QUERY_ERROR",error);}
  stopped=terminate(child.hProcess,123);error=stopped?0:GetLastError();
  value("GUARD_TERMINATE_PROBE",stopped);value("GUARD_TERMINATE_ERROR",error);
  waited=wait(child.hProcess,5000);error=waited==WAIT_FAILED?GetLastError():0;
  value("GUARD_REAP_WAIT",waited);value("GUARD_REAP_ERROR",error);result=5;
 }
 if(!CloseHandle(child.hProcess)){error=GetLastError();value("PROCESS_CLOSE_ERROR",error);io_failed=1;}
 attrs=GetFileAttributesA("C:\\VXDLAB\\RRPROBE.LOG");error=attrs==INVALID_FILE_ATTRIBUTES?GetLastError():0;
 value("PROBE_LOG_AFTER_ERROR",error);value("PROBE_FRESH_LOG_PRESENT",attrs!=INVALID_FILE_ATTRIBUTES&&!(attrs&FILE_ATTRIBUTE_DIRECTORY));
 if(attrs==INVALID_FILE_ATTRIBUTES||(attrs&FILE_ATTRIBUTE_DIRECTORY)||!readable_log())result=3;
done:
 if(io_failed)result=31;value("OUTER_RESOURCE_SELECTED_RESULT",result);value("OUTER_OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER",1);
 if(!CloseHandle(report))io_failed=1;ExitProcess(io_failed?31:result);
}
