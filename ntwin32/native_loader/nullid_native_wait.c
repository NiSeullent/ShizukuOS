/* SPDX-License-Identifier: GPL-2.0-only -- real native helper exit observer. */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
static HANDLE report;
static int failed;
static void value(const char *name,DWORD v) {
 char out[128];DWORD n=0,w=0;unsigned i;
 while(*name&&n<sizeof(out)-12)out[n++]=*name++;
 out[n++]='=';for(i=0;i<8;i++)out[n++]="0123456789ABCDEF"[(v>>(28-i*4))&15];out[n++]='\r';out[n++]='\n';
 if(!WriteFile(report,out,n,&w,NULL)||w!=n||!FlushFileBuffers(report))failed=1;
}
void WINAPI entry(void) {
 STARTUPINFOA start={0};PROCESS_INFORMATION child={0};const char *application="C:\\VXDLAB\\NTWNULL.EXE";
 char command[]="C:\\VXDLAB\\NTWNULL.EXE --run-runtime C:\\VXDLAB\\TLSNULL.DLL --log C:\\VXDLAB\\PENULL.LOG";
 DWORD wait,error,code=STILL_ACTIVE,result=3;BOOL terminated;OSVERSIONINFOA os={0};
 report=CreateFileA("C:\\VXDLAB\\PENWAIT.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
 if(GetFileAttributesA("C:\\VXDLAB\\PENULL.LOG")!=INVALID_FILE_ATTRIBUTES)goto done;
 error=GetLastError();value("FRESH_REPORT_ERROR",error);if(error!=ERROR_FILE_NOT_FOUND||failed)goto done;
 os.dwOSVersionInfoSize=sizeof(os);
 if(!GetVersionExA(&os)||os.dwPlatformId!=VER_PLATFORM_WIN32_WINDOWS||os.dwMajorVersion!=4||os.dwMinorVersion!=10||(os.dwBuildNumber&65535u)!=2222)goto done;
 value("NATIVE_OS_PLATFORM",os.dwPlatformId);value("NATIVE_OS_MAJOR",os.dwMajorVersion);value("NATIVE_OS_MINOR",os.dwMinorVersion);value("NATIVE_OS_BUILD",os.dwBuildNumber&65535u);
 start.cb=sizeof(start);
 if(!CreateProcessA(application,command,NULL,NULL,FALSE,0,NULL,"C:\\VXDLAB",&start,&child)){
  value("CREATE_CHILD_ERROR",GetLastError());goto done;
 }
 value("ACTUAL_CHILD_PID",child.dwProcessId);if(!CloseHandle(child.hThread))failed=1;
 wait=WaitForSingleObject(child.hProcess,90000);error=wait==WAIT_FAILED?GetLastError():0;
 value("ACTUAL_WAIT_RESULT",wait);value("ACTUAL_WAIT_ERROR",error);
 if(wait==WAIT_OBJECT_0&&GetExitCodeProcess(child.hProcess,&code)){
  value("ACTUAL_CHILD_OS_EXIT",code);if(code==0&&!failed)result=0;
 }else{
  if(wait==WAIT_OBJECT_0)value("EXIT_QUERY_ERROR",GetLastError());
  terminated=TerminateProcess(child.hProcess,119);error=terminated?0:GetLastError();
  value("GUARD_TERMINATE",terminated);value("GUARD_TERMINATE_ERROR",error);
  wait=WaitForSingleObject(child.hProcess,5000);error=wait==WAIT_FAILED?GetLastError():0;
  value("GUARD_REAP_RESULT",wait);value("GUARD_REAP_ERROR",error);result=5;
 }
 if(!CloseHandle(child.hProcess))failed=1;
done:
 if(failed)result=31;value("OBSERVER_SELECTED_RESULT",result);
 if(!CloseHandle(report))result=31;ExitProcess(failed?31:result);
}
