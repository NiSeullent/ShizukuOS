/* SPDX-License-Identifier: GPL-2.0-only
 * Record the actual bounded native child exit, separately from its checks.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
static HANDLE log_file;
static void number(const char *label,DWORD value)
{
    char out[10];unsigned i;DWORD wrote,n=(DWORD)lstrlenA(label);
    if(!WriteFile(log_file,label,n,&wrote,NULL)||wrote!=n)ExitProcess(12);
    for(i=0;i<8;i++)out[i]="0123456789ABCDEF"[(value>>(28-4*i))&15];
    out[8]='\r';out[9]='\n';
    if(!WriteFile(log_file,out,10,&wrote,NULL)||wrote!=10)ExitProcess(12);
}
void mainCRTStartup(void)
{
    STARTUPINFOA startup={0};PROCESS_INFORMATION process={0};
    char command[]="C:\\VXDLAB\\NTWPRB.EXE";
    DWORD result=WAIT_FAILED,code=0xffffffff,error=0;BOOL created;
    log_file=CreateFileA("C:\\VXDLAB\\NPVEXIT.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(log_file==INVALID_HANDLE_VALUE)ExitProcess(11);
    startup.cb=sizeof(startup);
    created=CreateProcessA(NULL,command,NULL,NULL,FALSE,0,NULL,"C:\\VXDLAB",&startup,&process);
    if(!created)error=GetLastError();
    number("CREATED=",created);number("CREATE_ERROR=",error);
    if(created){
        CloseHandle(process.hThread);result=WaitForSingleObject(process.hProcess,30000);
        number("WAIT_RESULT=",result);
        if(result==WAIT_OBJECT_0){if(!GetExitCodeProcess(process.hProcess,&code))error=GetLastError();}
        else if(result==WAIT_TIMEOUT){TerminateProcess(process.hProcess,124);WaitForSingleObject(process.hProcess,5000);error=ERROR_TIMEOUT;}
        else error=GetLastError();
        number("PROCESS_EXIT=",code);number("PROCESS_ERROR=",error);CloseHandle(process.hProcess);
    }
    if(!FlushFileBuffers(log_file))ExitProcess(13);
    CloseHandle(log_file);
    ExitProcess(created&&result==WAIT_OBJECT_0&&code==0&&error==0?0:1);
}
