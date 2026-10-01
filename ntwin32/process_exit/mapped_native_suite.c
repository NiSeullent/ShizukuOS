/* SPDX-License-Identifier: GPL-2.0-only -- actual wait plus post-detach verdict */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
static HANDLE report=INVALID_HANDLE_VALUE;static DWORD io_failed;
static void text(const char *s){DWORD n=0,w=0;while(s[n])n++;if(!WriteFile(report,s,n,&w,NULL)||w!=n||!FlushFileBuffers(report))io_failed=1;}
static void number(const char *name,DWORD value){char h[9];unsigned i;for(i=0;i<8;i++)h[i]="0123456789ABCDEF"[(value>>(28-i*4))&15];h[8]=0;text(name);text("=");text(h);text("\r\n");}
static int contains(const char *s,const char *wanted){unsigned i,j;for(i=0;s[i];i++){for(j=0;wanted[j]&&s[i+j]==wanted[j];j++);if(!wanted[j])return 1;}return 0;}
static unsigned count_line(const char *s,const char *wanted)
{
 unsigned count=0,j;while(*s){const char *end=s;while(*end&&*end!='\r'&&*end!='\n')end++;
  if(end[0]!='\r'||end[1]!='\n')return 0xffffffffu;
  for(j=0;wanted[j]&&s+j<end&&s[j]==wanted[j];j++);if(!wanted[j]&&s+j==end)count++;s=end+2;
 }return count;
}
static int absent(const char *path){DWORD e;if(GetFileAttributesA(path)!=INVALID_FILE_ATTRIBUTES)return 0;e=GetLastError();return e==ERROR_FILE_NOT_FOUND;}
static int child_log(const char *path,unsigned mode)
{
 static char raw[8193];HANDLE h;DWORD high=0,bytes,read,n;int okay;
 h=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);if(h==INVALID_HANDLE_VALUE)return 0;
 bytes=GetFileSize(h,&high);if(high||bytes<100||bytes>8192){CloseHandle(h);return 0;}
 okay=ReadFile(h,raw,bytes,&read,NULL)&&read==bytes;if(!CloseHandle(h))okay=0;if(!okay)return 0;
 if(raw[bytes-2]!='\r'||raw[bytes-1]!='\n')return 0;for(n=0;n<bytes;n++)if(!raw[n]||(unsigned char)raw[n]>127)return 0;raw[bytes]=0;
 if(contains(raw,"MAPPED_DIAGNOSTIC_FAIL")||contains(raw,"MAPPED_DIAGNOSTIC_PREPARATION_FAIL")||contains(raw,"REPORT_FLUSH_FAILED")||contains(raw,"OBSERVER_IO_FAILED"))return 0;
 if(count_line(raw,"SNAPSHOT=IMMUTABLE_NATIVE_EXE_BSS_AFTER_FULL_ATTACH")!=1||count_line(raw,"NOTIFICATION=ACTUAL_NATIVE_PROCESS_DETACH")!=1||count_line(raw,"PHYSICAL_WORKER_CESSATION_ESTABLISHED=0")!=1||count_line(raw,"DISPATCH_IO_FAILED=00000000")!=1||count_line(raw,"DISPATCH_REASON=00000000")!=1||count_line(raw,"DISPATCH_RESERVED_NONNULL=00000001")!=1)return 0;
 if(count_line(raw,"MODE=--main")!=(mode==0)||count_line(raw,"MODE=--worker")!=(mode==1)||count_line(raw,"MODE=--missing")!=(mode==2)||count_line(raw,"MODE=--dependency")!=(mode==3))return 0;
 if(mode==2)return count_line(raw,"REFUSAL=PREEXISTING_DISPATCHER_TLS_ABSENT")==1&&count_line(raw,"DISPATCH_GUARD=00000006")==1&&count_line(raw,"DISPATCH_EXISTING_TLS_DATA=00000000")==1&&count_line(raw,"OWN_MAPPED_CODE_INVOKED=0")==1&&count_line(raw,"OWN_MAPPED_CODE_INVOKED=1")==0&&count_line(raw,"STATUS=MAPPED_DISPATCH_REFUSED")==1;
 if(mode==3)return count_line(raw,"REFUSAL=ACTUAL_NATIVE_DEPENDENCY_ALREADY_DETACHED")==1&&count_line(raw,"DISPATCH_GUARD=00000007")==1&&count_line(raw,"DEPENDENCY_B_ALREADY_DETACHED=00000001")==1&&count_line(raw,"OWN_MAPPED_CODE_INVOKED=0")==1&&count_line(raw,"OWN_MAPPED_CODE_INVOKED=1")==0&&count_line(raw,"STATUS=MAPPED_DISPATCH_REFUSED")==1;
 return count_line(raw,"STATUS=MAPPED_OWN_NOTIFICATION_PASS")==1&&count_line(raw,"STATUS=MAPPED_DISPATCH_REFUSED")==0&&count_line(raw,"DISPATCH_GUARD=00000000")==1&&count_line(raw,"OWN_MAPPED_CODE_INVOKED=1")==1&&count_line(raw,"OWN_MAPPED_CODE_INVOKED=0")==0&&count_line(raw,"ACTUAL_MAPPED_TLS_DETACH_COUNT=00000001")==1&&count_line(raw,"ACTUAL_MAPPED_DLL_DETACH_COUNT=00000001")==1&&count_line(raw,"ACTUAL_MAPPED_TLS_RESERVED_NONNULL=00000000")==1&&count_line(raw,"ACTUAL_MAPPED_DLL_RESERVED_NONNULL=00000001")==1&&count_line(raw,"ACTUAL_MAPPED_FAILURES=00000000")==1;
}
void WINAPI entry(void)
{
 const char *modes[]={"--main","--worker","--missing","--dependency"};
 const char *logs[]={"C:\\VXDLAB\\MXMA.LOG","C:\\VXDLAB\\MXWO.LOG","C:\\VXDLAB\\MXNO.LOG","C:\\VXDLAB\\MXDP.LOG"};
 unsigned n;DWORD failures=0;
 for(n=0;n<4;n++)if(!absent(logs[n]))ExitProcess(21);
 report=CreateFileA("C:\\VXDLAB\\MXSUIT.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
 text("SCOPE=OWN_MAPPED_NOTIFICATION_ONLY\r\nAPPLICATION_SUCCESS=0\r\nPHYSICAL_WORKER_CESSATION_ESTABLISHED=0\r\n");
 for(n=0;n<4;n++){
  STARTUPINFOA start={0};PROCESS_INFORMATION child={0};char command[96]="C:\\VXDLAB\\MXPROBE.EXE ";unsigned k=0,j=0;DWORD wait,error,code=STILL_ACTIVE;int accepted=0;
  while(command[k])k++;while(modes[n][j])command[k++]=modes[n][j++];command[k]=0;
  text("PROBE_MODE=");text(modes[n]);text("\r\n");start.cb=sizeof(start);
  if(!CreateProcessA("C:\\VXDLAB\\MXPROBE.EXE",command,NULL,NULL,FALSE,0,NULL,"C:\\VXDLAB",&start,&child)){number("CREATE_ERROR",GetLastError());failures++;continue;}
  number("ACTUAL_CHILD_PID",child.dwProcessId);if(!CloseHandle(child.hThread)){failures++;number("CLOSE_THREAD_ERROR",GetLastError());}
  wait=WaitForSingleObject(child.hProcess,45000);error=wait==WAIT_FAILED?GetLastError():0;number("ACTUAL_WAIT",wait);number("ACTUAL_WAIT_ERROR",error);
  if(wait==WAIT_OBJECT_0&&GetExitCodeProcess(child.hProcess,&code)){
   number("ACTUAL_CHILD_OS_EXIT",code);accepted=code==73&&child_log(logs[n],n);
  }else{
   BOOL stopped;error=wait==WAIT_OBJECT_0?GetLastError():0;number("EXIT_QUERY_ERROR",error);stopped=TerminateProcess(child.hProcess,119);error=stopped?0:GetLastError();number("GUARD_TERMINATE",stopped);number("GUARD_TERMINATE_ERROR",error);wait=WaitForSingleObject(child.hProcess,5000);number("GUARD_REAP_WAIT",wait);
  }
  if(!CloseHandle(child.hProcess)){accepted=0;number("CLOSE_PROCESS_ERROR",GetLastError());}
  text(accepted?"STATUS_CHILD=POST_DETACH_SCOPE_PASS\r\n":"STATUS_CHILD=FAIL\r\n");if(!accepted)failures++;
 }
 number("FAILURES",failures);text(failures||io_failed?"STATUS=OWN_MAPPED_DIAGNOSTIC_SUITE_FAIL\r\n":"STATUS=OWN_MAPPED_DIAGNOSTIC_SUITE_PASS\r\n");text("SUITE_OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=1\r\n");
 if(!FlushFileBuffers(report))io_failed=1;if(!CloseHandle(report))io_failed=1;ExitProcess(io_failed?31:(failures?3:0));
}
