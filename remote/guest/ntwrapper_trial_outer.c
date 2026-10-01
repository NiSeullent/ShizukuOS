/* SPDX-License-Identifier: GPL-2.0-only
 * Observe the real NTWVSUIT process exit. No claim about this outer process's
 * own OS exit is inferred from its final report.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
static HANDLE report;
static int failed;
static void record(const char *label, DWORD value)
{
    char out[160]; DWORD n=0, written=0, i;
    while (*label && n<sizeof(out)-12) out[n++]=*label++;
    out[n++]='=';
    for (i=0;i<8;++i) out[n++]="0123456789ABCDEF"[(value>>(28-4*i))&15];
    out[n++]='\r';out[n++]='\n';
    if (!WriteFile(report,out,n,&written,NULL)||written!=n||!FlushFileBuffers(report)) failed=1;
}
void WINAPI entry(void)
{
    STARTUPINFOA start={0};PROCESS_INFORMATION process={0};
    char command[]="C:\\VXDLAB\\NTWVSUIT.EXE";
    DWORD wait, error, code=0xFFFFFFFF, result=31;
    report=CreateFileA("C:\\VXDLAB\\NTWOUT.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if (report==INVALID_HANDLE_VALUE) ExitProcess(21);
    if (GetFileAttributesA("C:\\VXDLAB\\NTWOBS.LOG")!=INVALID_FILE_ATTRIBUTES) goto finish;
    error=GetLastError();record("FRESH_INNER_REPORT_ERROR",error);
    if (error!=ERROR_FILE_NOT_FOUND||failed) goto finish;
    start.cb=sizeof(start);
    if (!CreateProcessA("C:\\VXDLAB\\NTWVSUIT.EXE",command,NULL,NULL,FALSE,0,NULL,
                        "C:\\VXDLAB",&start,&process)) {
        error=GetLastError();record("CREATE_ERROR",error);goto finish;
    }
    record("INNER_PID",process.dwProcessId);
    if (!CloseHandle(process.hThread)) failed=1;
    wait=WaitForSingleObject(process.hProcess,45000);
    error=wait==WAIT_FAILED?GetLastError():0;
    record("INNER_WAIT",wait);record("INNER_WAIT_ERROR",error);
    if (wait==WAIT_OBJECT_0) {
        if (!GetExitCodeProcess(process.hProcess,&code)) {
            error=GetLastError();failed=1;record("EXIT_QUERY_ERROR",error);
        }
        record("INNER_ACTUAL_OS_EXIT",code);
        if (!code&&!failed) result=0;
    } else {
        record("GUARD_TERMINATE",TerminateProcess(process.hProcess,44));
        record("GUARD_WAIT",WaitForSingleObject(process.hProcess,5000));
        /* Any guard leaves the trial failed, irrespective of later exitcode. */
    }
    if (!CloseHandle(process.hProcess)) failed=1;
finish:
    if (failed) result=21;
    record("OUTER_SELECTED_RESULT",result);
    if (failed) result=21;
    if (!CloseHandle(report)) result=21;
    ExitProcess(result);
}
