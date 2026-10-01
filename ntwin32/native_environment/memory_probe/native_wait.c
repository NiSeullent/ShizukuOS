/* SPDX-License-Identifier: GPL-2.0-only -- real own child process observer. */
#include "native_common.h"
#include "sha256.h"
#include "memory_pins.h"
static mp_report report;
static int pin_probe(void)
{
 HANDLE file;BYTE block[1024],digest[32];char actual[65];sha256_ctx hash;DWORD n,total=0,error;unsigned i;int okay=1;
 file=CreateFileA("C:\\VXDLAB\\MEMSTAT.EXE",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(file==INVALID_HANDLE_VALUE){error=GetLastError();mp_value(&report,"PROBE_OPEN_ERROR",error);return 0;}
 sha256_init(&hash);
 for(;;){if(!ReadFile(file,block,sizeof(block),&n,NULL)){error=GetLastError();mp_value(&report,"PROBE_READ_ERROR",error);okay=0;break;}
  if(!n)break;if(total>MP_PROBE_BYTES||n>MP_PROBE_BYTES-total){okay=0;break;}total+=n;sha256_update(&hash,block,n);}
 if(!CloseHandle(file)){error=GetLastError();mp_value(&report,"PROBE_CLOSE_ERROR",error);okay=0;}
 sha256_final(&hash,digest);sha256_hex(digest,actual);for(i=0;i<64;i++)if(actual[i]!=MP_PROBE_SHA[i])okay=0;
 mp_value(&report,"PROBE_ACTUAL_BYTES",total);mp_value(&report,"PROBE_EXACT_SHA_AND_EOF",okay&&total==MP_PROBE_BYTES);
 return okay&&total==MP_PROBE_BYTES&&!report.failed;
}
static int readable_log(void)
{
 HANDLE file;BYTE block[256];DWORD got,error,total=0;int okay=1;
 file=CreateFileA("C:\\VXDLAB\\MEMSTAT.LOG",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(file==INVALID_HANDLE_VALUE){error=GetLastError();mp_value(&report,"PROBE_LOG_OPEN_ERROR",error);return 0;}
 for(;;){if(!ReadFile(file,block,sizeof(block),&got,NULL)){error=GetLastError();mp_value(&report,"PROBE_LOG_READ_ERROR",error);okay=0;break;}
  if(!got)break;if(got>16384u-total){okay=0;break;}total+=got;}
 if(!CloseHandle(file)){error=GetLastError();mp_value(&report,"PROBE_LOG_CLOSE_ERROR",error);report.failed=1;okay=0;}
 mp_value(&report,"PROBE_LOG_READABLE_BYTES",total);return okay&&total>0;
}
void WINAPI entry(void)
{
 typedef BOOL (WINAPI *create_fn)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
 typedef DWORD (WINAPI *wait_fn)(HANDLE,DWORD);
 typedef BOOL (WINAPI *query_fn)(HANDLE,LPDWORD);
 typedef BOOL (WINAPI *terminate_fn)(HANDLE,UINT);
 create_fn create;wait_fn wait;query_fn query;terminate_fn terminate;mp_api_identity id;
 STARTUPINFOA start={0};PROCESS_INFORMATION child={0};char command[]="C:\\VXDLAB\\MEMSTAT.EXE";
 DWORD attrs,error,waited,exit_code=STILL_ACTIVE,result=3,last,sentinel=0x51a2b3c4u;BOOL okay;
 if(!mp_report_open(&report,"C:\\VXDLAB\\MEMWAIT.LOG"))ExitProcess(21);
 mp_value(&report,"OUTER_MEMORY_OBSERVER_ENTRY",1);mp_value(&report,"APPLICATION_SUCCESS",0);
#define RESOLVE(tag,target,type,name) do {SetLastError(sentinel);target=(type)(void *)mp_original(name,&id);last=GetLastError();mp_value(&report,tag,last);if(!target||last!=sentinel)goto done;mp_identity(&report,&id);} while(0)
 RESOLVE("CREATE_RESOLVER_LAST_ERROR",create,create_fn,"CreateProcessA");
 RESOLVE("WAIT_RESOLVER_LAST_ERROR",wait,wait_fn,"WaitForSingleObject");
 RESOLVE("QUERY_RESOLVER_LAST_ERROR",query,query_fn,"GetExitCodeProcess");
 RESOLVE("TERMINATE_RESOLVER_LAST_ERROR",terminate,terminate_fn,"TerminateProcess");
#undef RESOLVE
 mp_value(&report,"ACTUAL_ORIGINAL_WIN98_GUARD",1);if(report.failed)goto done;
 attrs=GetFileAttributesA("C:\\VXDLAB\\MEMSTAT.LOG");error=attrs==INVALID_FILE_ATTRIBUTES?GetLastError():0;
 mp_value(&report,"PROBE_LOG_BEFORE_ERROR",error);if(attrs!=INVALID_FILE_ATTRIBUTES||error!=ERROR_FILE_NOT_FOUND||!pin_probe())goto done;
 start.cb=sizeof(start);
 okay=create(command,command,NULL,NULL,FALSE,0,NULL,"C:\\VXDLAB",&start,&child);error=okay?0:GetLastError();
 mp_value(&report,"ACTUAL_CREATE_ERROR",error);if(!okay)goto done;mp_value(&report,"ACTUAL_PROBE_PID",child.dwProcessId);
 if(!CloseHandle(child.hThread)){error=GetLastError();mp_value(&report,"THREAD_CLOSE_ERROR",error);report.failed=1;}
 waited=wait(child.hProcess,30000);error=waited==WAIT_FAILED?GetLastError():0;
 mp_value(&report,"ACTUAL_PROBE_WAIT",waited);mp_value(&report,"ACTUAL_PROBE_WAIT_ERROR",error);
 if(waited==WAIT_OBJECT_0){okay=query(child.hProcess,&exit_code);error=okay?0:GetLastError();
  mp_value(&report,"ACTUAL_EXIT_QUERY_ERROR",error);mp_value(&report,"ACTUAL_PROBE_OS_EXIT",exit_code);
  if(okay&&exit_code==0&&!report.failed)result=0;
 }else{
  okay=terminate(child.hProcess,124);error=okay?0:GetLastError();mp_value(&report,"GUARD_TERMINATE_PROBE",okay);mp_value(&report,"GUARD_TERMINATE_ERROR",error);
  waited=wait(child.hProcess,5000);error=waited==WAIT_FAILED?GetLastError():0;mp_value(&report,"GUARD_REAP_WAIT",waited);mp_value(&report,"GUARD_REAP_ERROR",error);result=5;
 }
 if(!CloseHandle(child.hProcess)){error=GetLastError();mp_value(&report,"PROCESS_CLOSE_ERROR",error);report.failed=1;}
 attrs=GetFileAttributesA("C:\\VXDLAB\\MEMSTAT.LOG");error=attrs==INVALID_FILE_ATTRIBUTES?GetLastError():0;
 mp_value(&report,"PROBE_LOG_AFTER_ERROR",error);mp_value(&report,"PROBE_FRESH_LOG_PRESENT",attrs!=INVALID_FILE_ATTRIBUTES&&!(attrs&FILE_ATTRIBUTE_DIRECTORY));
 if(attrs==INVALID_FILE_ATTRIBUTES||(attrs&FILE_ATTRIBUTE_DIRECTORY)||!readable_log())result=3;
done:
 if(report.failed)result=31;mp_value(&report,"OUTER_MEMORY_SELECTED_RESULT",result);mp_value(&report,"OUTER_OWN_OS_EXIT_REQUIRES_OBSERVER",1);
 if(!mp_report_close(&report))result=31;ExitProcess(result);
}
