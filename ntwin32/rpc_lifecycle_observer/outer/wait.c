/* SPDX-License-Identifier: GPL-2.0-only
 * Independent ordinary parent: observes the debugger's real OS exit.
 * Timeout never terminates or detaches the debugger/its child.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#ifdef RPC_WAIT_HOST
#include "mock_windows.h"
#else
#include <windows.h>
#endif
static HANDLE report=INVALID_HANDLE_VALUE;
static unsigned io_failed;
static void put(const char *s){DWORD count=0,wrote=0;while(s[count])count++;if(!WriteFile(report,s,count,&wrote,NULL)||wrote!=count)io_failed=1;}
static void number(const char *label,DWORD value){char text[11];unsigned i;put(label);for(i=0;i<8;i++)text[i]="0123456789ABCDEF"[(value>>(28-i*4))&15];text[8]='\r';text[9]='\n';text[10]=0;put(text);}
static int nonempty(const char *path,DWORD maximum,const char *label){HANDLE h;DWORD high=0,size=0,got=0,error=0,close_error=0;BYTE byte;BOOL read=FALSE,closed=FALSE;int ok;
 h=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(h==INVALID_HANDLE_VALUE)error=GetLastError();
 else{size=GetFileSize(h,&high);if(size==INVALID_FILE_SIZE)error=GetLastError();
  if(!error&&!high&&size&&size<=maximum){read=ReadFile(h,&byte,1,&got,NULL);if(!read)error=GetLastError();}
  closed=CloseHandle(h);if(!closed)close_error=GetLastError();
 }
 ok=h!=INVALID_HANDLE_VALUE&&!error&&!high&&size&&size<=maximum&&read&&got==1&&closed;
 put("REPORT=");put(label);put("\r\n");number("REPORT_BYTES=",size);number("REPORT_HIGH=",high);number("REPORT_ERROR=",error);number("REPORT_CLOSE_ERROR=",close_error);number("REPORT_READ_ONE_BYTE=",read&&got==1);number("REPORT_AVAILABLE=",ok);return ok;
}
#ifdef RPC_WAIT_HOST
void rpc_wait_host_reset(void){io_failed=0;report=INVALID_HANDLE_VALUE;}
#endif
void WINAPI entry(void){STARTUPINFOA si={0};PROCESS_INFORMATION pi={0};OSVERSIONINFOA os={0};DWORD selected=3,wait=WAIT_FAILED,wait_error=0,exit_code=0xffffffff,query_error=0,create_error=0,thread_error=0,process_error=0;BOOL created=FALSE,queried=FALSE,thread_closed=FALSE,process_closed=FALSE;
 char command[]="C:\\VXDLAB\\RPCOBS.EXE --fixture --log C:\\VXDLAB\\RPCDBG.LOG";
 report=CreateFileA("C:\\VXDLAB\\RPCWAIT.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(report==INVALID_HANDLE_VALUE)ExitProcess(20);
 put("HELPER=OWNED_RPC_OBSERVER_NATIVE_PARENT\r\nNO_CHILD_TERMINATION_OR_RESULT_FORCED=1\r\nFULL_INNER_PROTOCOL_REVIEW_PENDING=1\r\nAPPLICATION_PASS=0\r\nOUTER_OWN_OS_EXIT_UNOBSERVED=1\r\n");
 os.dwOSVersionInfoSize=sizeof(os);if(!GetVersionExA(&os)||os.dwMajorVersion!=4||os.dwMinorVersion!=10||(os.dwBuildNumber&65535)!=2222||os.dwPlatformId!=1){put("ERROR=ORIGINAL_NATIVE_WIN98_ABI_REQUIRED\r\n");selected=21;goto finish;}
 si.cb=sizeof(si);created=CreateProcessA("C:\\VXDLAB\\RPCOBS.EXE",command,NULL,NULL,FALSE,0,NULL,"C:\\VXDLAB",&si,&pi);if(!created)create_error=GetLastError();
 number("CREATED=",created);number("CREATE_ERROR=",create_error);if(!created)goto finish;
 number("OBSERVER_PID=",pi.dwProcessId);number("OBSERVER_TID=",pi.dwThreadId);
 thread_closed=CloseHandle(pi.hThread);if(!thread_closed)thread_error=GetLastError();
 wait=WaitForSingleObject(pi.hProcess,300000);if(wait==WAIT_FAILED)wait_error=GetLastError();else if(wait==WAIT_TIMEOUT)wait_error=ERROR_TIMEOUT;
 if(wait==WAIT_OBJECT_0){queried=GetExitCodeProcess(pi.hProcess,&exit_code);if(!queried)query_error=GetLastError();}
 process_closed=CloseHandle(pi.hProcess);if(!process_closed)process_error=GetLastError();
 /* Capture native API results/errors before any report I/O can alter them. */
 number("WAIT_RESULT=",wait);number("WAIT_ERROR=",wait_error);number("EXIT_QUERY=",queried);number("EXIT_QUERY_ERROR=",query_error);number("ACTUAL_OBSERVER_OS_EXIT=",exit_code);number("THREAD_CLOSE=",thread_closed);number("THREAD_CLOSE_ERROR=",thread_error);number("PROCESS_CLOSE=",process_closed);number("PROCESS_CLOSE_ERROR=",process_error);
 if(wait!=WAIT_OBJECT_0){put("OBSERVER_EXIT_UNOBSERVED=1\r\nOBSERVER_MAY_REMAIN_ALIVE_OUTER_VM_CAP_REQUIRED=1\r\n");selected=4;}
 else if(!queried)selected=5;
 else if(exit_code)selected=6;
 else if(!thread_closed||!process_closed)selected=7;
 else{int first=nonempty("C:\\VXDLAB\\RPCDBG.LOG",1024u*1024u,"RPCDBG"),second=nonempty("C:\\VXDLAB\\RPCFIX.LOG",65536,"RPCFIX");selected=first&&second?0:8;}
finish:
 number("OUTER_SELECTED_EXIT=",io_failed?32:selected);put("FULL_INNER_PROTOCOL_REVIEW_PENDING=1\r\nAPPLICATION_PASS=0\r\nOUTER_OWN_OS_EXIT_UNOBSERVED=1\r\n");if(!FlushFileBuffers(report))io_failed=1;if(!CloseHandle(report))io_failed=1;ExitProcess(io_failed?32:selected);
}
