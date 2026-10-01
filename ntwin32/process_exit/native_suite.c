/* SPDX-License-Identifier: GPL-2.0-only
 * Native parent owns child watches. No synchronization occurs inside DllMain.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
static HANDLE report=INVALID_HANDLE_VALUE;static unsigned failures,completed;static int io_failed;
static char contents[32768];
static void text(const char *s){DWORD n=0,written;while(s[n])n++;if(!WriteFile(report,s,n,&written,NULL)||written!=n)io_failed=1;}
static void value(const char *label,DWORD v){char b[9];unsigned i;for(i=0;i<8;i++)b[i]="0123456789ABCDEF"[(v>>(28-4*i))&15];b[8]=0;text(label);text(b);text("\r\n");}
static void zero(void *p,unsigned n){unsigned i;for(i=0;i<n;i++)((BYTE *)p)[i]=0;}
static unsigned occurrences(const char *haystack,const char *needle)
{unsigned count=0,i,j;for(i=0;haystack[i];i++){for(j=0;needle[j]&&haystack[i+j]==needle[j];j++){}if(!needle[j])count++;}return count;}
static int read(const char *path)
{HANDLE file=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);DWORD size,high,got;int okay=0;
 if(file==INVALID_HANDLE_VALUE)return 0;size=GetFileSize(file,&high);
 if(!high&&size<sizeof(contents)&&ReadFile(file,contents,size,&got,NULL)&&got==size){contents[size]=0;okay=1;}CloseHandle(file);return okay;}
static int ready(const char *path)
{DWORD start=GetTickCount();do{if(read(path)&&occurrences(contents,"READY_FOR_TERMINATE=1\r\n")==1)return 1;Sleep(10);}while(GetTickCount()-start<5000);return 0;}
void WINAPI entry(void)
{
 static const char *const modes[]={"--main-import","--main-native","--worker-import","--worker-native","--unregistered","--terminated","--dynamic-unload"};
 static const char *const logs[]={"C:\\VXDLAB\\PXMI.LOG","C:\\VXDLAB\\PXMN.LOG","C:\\VXDLAB\\PXWI.LOG","C:\\VXDLAB\\PXWN.LOG","C:\\VXDLAB\\PXUN.LOG","C:\\VXDLAB\\PXTM.LOG","C:\\VXDLAB\\PXDYN.LOG"};
 unsigned i;int unconfirmed=0;
 report=CreateFileA("C:\\VXDLAB\\PXSUIT.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(report==INVALID_HANDLE_VALUE)ExitProcess(20);
 text("SCOPE=OWNED_NATIVE_EXIT_NOTIFICATION_NOT_APPLICATION_ACCEPTANCE\r\nAPPLICATION_EXECUTED=0\r\n");
 for(i=0;i<7;i++){
  STARTUPINFOA startup;PROCESS_INFORMATION child;char command[96]="C:\\VXDLAB\\PXPROBE.EXE ";unsigned n=22,j=0;DWORD wait,code=STILL_ACTIVE;int okay=1,watchdog=0;
  while(modes[i][j])command[n++]=modes[i][j++];command[n]=0;
  zero(&startup,sizeof(startup));zero(&child,sizeof(child));startup.cb=sizeof(startup);text("PROBE_MODE=");text(modes[i]);text("\r\n");
  if(!CreateProcessA(NULL,command,NULL,NULL,FALSE,0,NULL,"C:\\VXDLAB",&startup,&child)){value("CREATE_ERROR=",GetLastError());failures++;continue;}
  value("OWNED_CHILD_PID=",child.dwProcessId);
  if(i==5){
   if(!ready(logs[i])){text("FAIL termination control ready evidence\r\n");okay=0;}
   if(!TerminateProcess(child.hProcess,74)){value("CONTROL_TERMINATE_ERROR=",GetLastError());okay=0;}
  }
  wait=WaitForSingleObject(child.hProcess,15000);value("ACTUAL_WAIT=",wait);
  if(wait!=WAIT_OBJECT_0){text("FAIL owned child bounded termination\r\n");okay=0;watchdog=1;
   if(!TerminateProcess(child.hProcess,1460))value("WATCHDOG_TERMINATE_ERROR=",GetLastError());
   if(WaitForSingleObject(child.hProcess,5000)!=WAIT_OBJECT_0){text("OWNED_CHILD_CLOSURE=UNCONFIRMED\r\n");unconfirmed=1;}
  }
  if(!GetExitCodeProcess(child.hProcess,&code)){value("EXIT_QUERY_ERROR=",GetLastError());okay=0;}value("ACTUAL_EXIT=",code);
  if(code!=(i==5?74u:73u)||watchdog)okay=0;
  if(!read(logs[i])){text("FAIL final child evidence read\r\n");okay=0;}
  else if(occurrences(contents,"REPORT_FLUSH_FAILED=")||occurrences(contents,"OBSERVER_IO_FAILED=")){text("FAIL child report I/O evidence\r\n");okay=0;}
  else if(i<4){
   if(occurrences(contents,"STATUS=SCOPED_NATIVE_EXIT_NOTIFICATION_PASS\r\n")!=1||occurrences(contents,"CALLBACK=B\r\n")!=1||occurrences(contents,"CALLBACK=A\r\n")!=1||
      occurrences(contents,"CALLBACK=REMOVED")||occurrences(contents,"FAIL ")||
      occurrences(contents,"PASS other worker terminated before notification\r\n")!=2||
      occurrences(contents,"NATIVE_DEPENDENCY_DETACH=A REASON=0 RESERVED_NONNULL=1\r\n")!=1||
      occurrences(contents,"NATIVE_DEPENDENCY_DETACH=B REASON=0 RESERVED_NONNULL=1\r\n")!=1)okay=0;
  }else if(i==4){
   if(occurrences(contents,"STATUS=UNREGISTERED_BEFORE_EXIT\r\n")!=1||occurrences(contents,"CALLBACK=")||occurrences(contents,"FAIL ")||
      occurrences(contents,"NATIVE_DEPENDENCY_DETACH=A REASON=0 RESERVED_NONNULL=1\r\n")!=1||
      occurrences(contents,"NATIVE_DEPENDENCY_DETACH=B REASON=0 RESERVED_NONNULL=1\r\n")!=1)okay=0;
  }else if(i==5){if(occurrences(contents,"READY_FOR_TERMINATE=1\r\n")!=1||occurrences(contents,"CALLBACK=")||occurrences(contents,"NATIVE_DEPENDENCY_DETACH=")||occurrences(contents,"FAIL "))okay=0;}
  else if(occurrences(contents,"STATUS=ACTUAL_DYNAMIC_UNLOAD_CONTROL_PASS\r\n")!=1||
          occurrences(contents,"PASS actual DLL_PROCESS_DETACH has NULL reserved\r\n")!=1||occurrences(contents,"CALLBACK=")||occurrences(contents,"FAIL ")||
          occurrences(contents,"NATIVE_DEPENDENCY_DETACH=A REASON=0 RESERVED_NONNULL=1\r\n")!=1||occurrences(contents,"NATIVE_DEPENDENCY_DETACH=B"))okay=0;
  if(!CloseHandle(child.hThread)){value("THREAD_HANDLE_CLOSE_ERROR=",GetLastError());okay=0;}
  if(!CloseHandle(child.hProcess)){value("PROCESS_HANDLE_CLOSE_ERROR=",GetLastError());okay=0;}
  text(okay?"STATUS_CHILD=SCOPED_PASS\r\n":"STATUS_CHILD=FAIL\r\n");if(okay)completed++;else failures++;FlushFileBuffers(report);if(unconfirmed)break;
 }
 value("ACTUAL_SCOPED_PASS_MODES=",completed);value("FAILURES=",failures);
 text(failures||completed!=7||io_failed?"STATUS=FAIL\r\n":"STATUS=SCOPED_NATIVE_EXIT_NOTIFICATION_SUITE_PASS\r\n");
 if(!FlushFileBuffers(report))io_failed=1;if(!CloseHandle(report))io_failed=1;ExitProcess(failures||completed!=7||io_failed?31:0);
}
