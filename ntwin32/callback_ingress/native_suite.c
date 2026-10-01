/* SPDX-License-Identifier: GPL-2.0-only -- actual native child exit observer */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include <stdint.h>
static HANDLE report=INVALID_HANDLE_VALUE;
static DWORD io_failed;
static void text(const char *s) { DWORD n=0,w=0; while(s[n])n++; if(!WriteFile(report,s,n,&w,NULL) || w!=n)io_failed=1; }
static void number(const char *key,DWORD value) { char b[9];unsigned i;for(i=0;i<8;i++)b[i]="0123456789ABCDEF"[(value>>(28-4*i))&15];b[8]=0;text(key);text("=");text(b);text("\r\n"); }
static unsigned line_count(const char *s,const char *want)
{
    unsigned count=0,j; while(*s) { const char *end=s; while(*end && *end!='\r' && *end!='\n')end++;
        if(end[0]!='\r' || end[1]!='\n')return UINT32_MAX;
        for(j=0;want[j] && s+j<end && s[j]==want[j];j++); if(!want[j] && s+j==end)count++; s=end+2;
    } return count;
}
static int child_log(void)
{
    static char raw[16385]; HANDLE f; DWORD high=0,bytes,got,n; int valid;
    f=CreateFileA("C:\\VXDLAB\\CIWRK.LOG",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(f==INVALID_HANDLE_VALUE)return 0; bytes=GetFileSize(f,&high);
    if(high || bytes<100 || bytes>16384) { CloseHandle(f); return 0; }
    valid=ReadFile(f,raw,bytes,&got,NULL) && got==bytes; if(!CloseHandle(f))valid=0; if(!valid)return 0;
    for(n=0;n<bytes;n++)if(!raw[n] || (BYTE)raw[n]>127)return 0; raw[bytes]=0;
    if(line_count(raw,"STATUS=PASS")!=1 || line_count(raw,"STATUS=FAIL")!=0 || line_count(raw,"FAILURES=00000000")!=1)return 0;
    return line_count(raw,"PASS=REUSED_MAPPED_COMPILER_TLS_128_CALLS")==2 &&
        line_count(raw,"PASS=ACTUAL_PROVIDER_THREAD_EXIT_ZERO")==2 &&
        line_count(raw,"PASS=PLAN_DISPOSED_AFTER_REAL_WORKER_JOIN")==1 &&
        line_count(raw,"PASS=MAPPED_IMAGE_RELEASED_AFTER_JOIN")==1 &&
        line_count(raw,"PASS=ORIGINAL_FIXTURE_UNCHANGED")==1 &&
        line_count(raw,"PRODUCTION_PROVIDER_INTEGRATED=0")==1;
}
void WINAPI entry(void)
{
    STARTUPINFOA start={0}; PROCESS_INFORMATION child={0}; DWORD wait,code=STILL_ACTIVE,result=3; int accepted=0;
    char command[]="C:\\VXDLAB\\CIWRK.EXE";
    if(GetFileAttributesA("C:\\VXDLAB\\CIWRK.LOG")!=INVALID_FILE_ATTRIBUTES || GetLastError()!=ERROR_FILE_NOT_FOUND)ExitProcess(21);
    report=CreateFileA("C:\\VXDLAB\\CISUIT.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL); if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
    text("SCOPE=OWN_MAPPED_PROVIDER_INGRESS_OBSERVER\r\nAPPLICATION_SUCCESS=0\r\n"); start.cb=sizeof(start);
    if(!CreateProcessA(command,command,NULL,NULL,FALSE,0,NULL,"C:\\VXDLAB",&start,&child)) { number("CREATE_ERROR",GetLastError()); goto finish; }
    number("ACTUAL_CHILD_PID",child.dwProcessId); if(!CloseHandle(child.hThread))io_failed=1;
    wait=WaitForSingleObject(child.hProcess,45000); number("ACTUAL_WAIT",wait);
    if(wait==WAIT_OBJECT_0 && GetExitCodeProcess(child.hProcess,&code)) {
        number("ACTUAL_CHILD_OS_EXIT",code); accepted=code==0 && child_log();
    } else {
        text("REFUSAL=CHILD_NOT_OBSERVED_COMPLETE\r\n"); number("GUARD_TERMINATED",TerminateProcess(child.hProcess,119));
        number("GUARD_REAP_WAIT",WaitForSingleObject(child.hProcess,5000));
    }
    if(!CloseHandle(child.hProcess))accepted=0; if(accepted && !io_failed)result=0;
finish:
    text(result?"STATUS=FAIL\r\n":"STATUS=SCOPED_NATIVE_INGRESS_PASS\r\n"); text("SUITE_OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=1\r\n");
    if(!FlushFileBuffers(report))result=31; if(!CloseHandle(report))result=31; ExitProcess(result);
}
