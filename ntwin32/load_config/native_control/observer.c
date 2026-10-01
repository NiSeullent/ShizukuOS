/* SPDX-License-Identifier: GPL-2.0-only -- real child process exit observation */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "../../../platform/freestanding/memory.h"
#include "protocol.h"
#include "pin.h"
static HANDLE joint=INVALID_HANDLE_VALUE,api=INVALID_HANDLE_VALUE;
static DWORD io_failed;
static char raw[16385];
static void text(HANDLE f,const char *s)
{ DWORD n=0,w=0;while(s[n])n++;if(!WriteFile(f,s,n,&w,NULL)||w!=n)io_failed=1; }
static void number(HANDLE f,const char *key,DWORD value)
{ char b[9];unsigned n;for(n=0;n<8;n++)b[n]="0123456789ABCDEF"[(value>>(28-4*n))&15];b[8]=0;text(f,key);text(f,"=");text(f,b);text(f,"\r\n"); }
static unsigned length(const char *s)
{ unsigned n=0;while(s[n])n++;return n; }
static int prefix(const char *s,const char *want)
{ while(*want){if(*s++!=*want++)return 0;}return 1; }
static int field(const char *s,const char *key,const char *value)
{
    unsigned n=length(key),v=length(value),count=0;int valid=1;
    while(*s){const char *end=s;while(*end&&*end!='\r')end++;
        if(prefix(s,key)&&s[n]=='='){
            count++;if((unsigned)(end-s)!=n+1+v||memcmp(s+n+1,value,v))valid=0;
        }
        if(end[0]!='\r'||end[1]!='\n')return 0;s=end+2;
    }return valid&&count==1;
}
static int hex_field(const char *s,const char *key,DWORD value)
{ char b[9];unsigned n;for(n=0;n<8;n++)b[n]="0123456789ABCDEF"[(value>>(28-4*n))&15];b[8]=0;return field(s,key,b); }
static int nonzero_pid(const char *s)
{
    unsigned count=0;DWORD pid=0;
    while(*s){const char *end=s;unsigned i;while(*end&&*end!='\r')end++;
        if(prefix(s,"ACTUAL_CHILD_PID=")){
            if(end-s!=25)return 0;count++;pid=0;
            for(i=17;i<25;i++){char c=s[i];if(c>='0'&&c<='9')pid=(pid<<4)+(c-'0');else if(c>='A'&&c<='F')pid=(pid<<4)+(c-'A'+10);else return 0;}
        }if(end[0]!='\r'||end[1]!='\n')return 0;s=end+2;
    }return count==1&&pid!=0;
}
static int no_contradiction(const char *s)
{
    while(*s){const char *end=s;while(*end&&*end!='\r')end++;
        if(prefix(s,"FAIL=")||prefix(s,"REFUSAL=")||prefix(s,"PREPARATION_FAILED=")||prefix(s,"GUARD_"))return 0;
        if(end[0]!='\r'||end[1]!='\n')return 0;s=end+2;
    }return 1;
}
static int semantics(const char *s,const lc_row *expected,unsigned count)
{
    uint32_t seen[128]={0},total=0,i;const char *p=s;
    if(count>128)return 0;
    while(*p){const char *end=p;while(*end&&*end!='\r')end++;
        if(prefix(p,"FAIL=")||prefix(p,"REFUSAL=")||prefix(p,"PREPARATION_FAILED=")||prefix(p,"GUARD_"))return 0;
        if(prefix(p,"PASS=")){
            int found=0;
            for(i=0;i<count;i++)if((unsigned)(end-p)==5+length(expected[i].name)&&!memcmp(p+5,expected[i].name,end-p-5)){
                if(++seen[i]>expected[i].count)return 0;found=1;break;
            }if(!found)return 0;
        }
        if(end[0]!='\r'||end[1]!='\n')return 0;p=end+2;
    }
    for(i=0;i<count;i++){if(seen[i]!=expected[i].count)return 0;total+=seen[i];}
    return hex_field(s,"CHECKS",total)&&hex_field(s,"FAILURES",0)&&field(s,"STATUS","PASS");
}
static int read_report(const char *path)
{
    HANDLE f;DWORD high=0,bytes,got,n;int ok;
    f=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(f==INVALID_HANDLE_VALUE)return 0;bytes=GetFileSize(f,&high);
    if(high||bytes<100||bytes>16384){CloseHandle(f);return 0;}
    ok=ReadFile(f,raw,bytes,&got,NULL)&&got==bytes;if(!CloseHandle(f))ok=0;if(!ok)return 0;
    for(n=0;n<bytes;n++){
        if(!raw[n]||(BYTE)raw[n]>126||((BYTE)raw[n]<32&&raw[n]!='\r'&&raw[n]!='\n'))return 0;
        if(raw[n]=='\r'&&(n+1>=bytes||raw[n+1]!='\n'))return 0;
        if(raw[n]=='\n'&&(n==0||raw[n-1]!='\r'))return 0;
    }
    if(bytes<2||raw[bytes-2]!='\r'||raw[bytes-1]!='\n')return 0;raw[bytes]=0;return 1;
}
static int callback_reports(void)
{
    if(!read_report("C:\\VXDLAB\\CIWRK.LOG")||!semantics(raw,LC_CB_ROWS,LC_ARRAY_COUNT(LC_CB_ROWS))||
       !field(raw,"SCOPE","OWN_MAPPED_TLS_PROVIDER_WORKER_INGRESS")||!field(raw,"APPLICATION_SUCCESS","0")||
       !field(raw,"PRODUCTION_PROVIDER_INTEGRATED","0")||!hex_field(raw,"ORIGINAL_FIXTURE_BYTES",LC_CB_BYTES)||
       !hex_field(raw,"ORIGINAL_FIXTURE_FNV1A",LC_CB_FNV)||!field(raw,"OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER","1"))return 0;
    if(!read_report("C:\\VXDLAB\\CISUIT.LOG")||!field(raw,"SCOPE","OWN_MAPPED_PROVIDER_INGRESS_OBSERVER")||
       !field(raw,"APPLICATION_SUCCESS","0")||!field(raw,"STATUS","SCOPED_NATIVE_INGRESS_PASS")||
       !hex_field(raw,"ACTUAL_WAIT",0)||!hex_field(raw,"ACTUAL_CHILD_OS_EXIT",0)||
       !field(raw,"SUITE_OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER","1"))return 0;
    return no_contradiction(raw)&&nonzero_pid(raw);
}
static int api_report(void)
{
    return read_report("C:\\VXDLAB\\LCWORK.LOG")&&semantics(raw,lc_rows,LC_ARRAY_COUNT(lc_rows))&&
        field(raw,"SCOPE","LOAD_CONFIG_NATIVE_DLL_API_ABI")&&field(raw,"APPLICATION_SUCCESS","0")&&
        field(raw,"MITIGATIONS_IMPLEMENTED","0")&&field(raw,"SYNTHETIC_CODE_EXECUTED","0")&&
        field(raw,"ENTROPY_SOURCE_VERIFIED","0")&&hex_field(raw,"ORIGINAL_DLL_BYTES",LC_PIN_BYTES)&&
        hex_field(raw,"ORIGINAL_DLL_FNV1A",LC_PIN_FNV)&&field(raw,"OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER","1");
}
static int child(char *command,const char *prefix_name,HANDLE report)
{
    STARTUPINFOA start={0};PROCESS_INFORMATION p={0};DWORD wait,code=STILL_ACTIVE;int ok=0;
    start.cb=sizeof(start);text(report,"CHILD=");text(report,prefix_name);text(report,"\r\n");
    if(!CreateProcessA(command,command,NULL,NULL,FALSE,0,NULL,"C:\\VXDLAB",&start,&p)){
        number(report,"CREATE_ERROR",GetLastError());return 0;
    }
    number(report,"ACTUAL_CHILD_PID",p.dwProcessId);if(!CloseHandle(p.hThread))io_failed=1;
    wait=WaitForSingleObject(p.hProcess,60000);number(report,"ACTUAL_WAIT",wait);
    if(wait==WAIT_OBJECT_0&&GetExitCodeProcess(p.hProcess,&code)){
        number(report,"ACTUAL_CHILD_OS_EXIT",code);ok=code==0;
    }else{
        text(report,"REFUSAL=CHILD_EXIT_NOT_OBSERVED\r\n");number(report,"GUARD_TERMINATED",TerminateProcess(p.hProcess,119));
        number(report,"GUARD_REAP_WAIT",WaitForSingleObject(p.hProcess,5000));
        text(report,"DESCENDANT_EXIT_UNVERIFIED=1\r\n");
    }
    if(!CloseHandle(p.hProcess))ok=0;return ok&&!io_failed;
}
void WINAPI entry(void)
{
    static const char *const outputs[]={"C:\\VXDLAB\\CIWRK.LOG","C:\\VXDLAB\\CISUIT.LOG","C:\\VXDLAB\\LCWORK.LOG","C:\\VXDLAB\\LCOBS.LOG","C:\\VXDLAB\\LCJOIN.LOG"};
    char callback[]="C:\\VXDLAB\\CISUIT.EXE",worker[]="C:\\VXDLAB\\LCWORK.EXE";
    DWORD n,result=3,pid=GetCurrentProcessId();int callback_ok=0,api_ok=0;
    for(n=0;n<LC_ARRAY_COUNT(outputs);n++)if(GetFileAttributesA(outputs[n])!=INVALID_FILE_ATTRIBUTES||GetLastError()!=ERROR_FILE_NOT_FOUND)ExitProcess(21);
    joint=CreateFileA(outputs[4],GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(joint==INVALID_HANDLE_VALUE)ExitProcess(21);
    api=CreateFileA(outputs[3],GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(api==INVALID_HANDLE_VALUE){CloseHandle(joint);ExitProcess(21);}
    text(joint,"SCOPE=JOINT_CALLBACK_LOAD_CONFIG_NATIVE_OBSERVER\r\nAPPLICATION_SUCCESS=0\r\nPRODUCTION_LOADER_INTEGRATED=0\r\nPRODUCTION_PROVIDER_INTEGRATED=0\r\n");number(joint,"ACTUAL_OBSERVER_PID",pid);
    text(api,"SCOPE=LOAD_CONFIG_NATIVE_API_CHILD_OBSERVER\r\nAPPLICATION_SUCCESS=0\r\n");number(api,"ACTUAL_OBSERVER_PID",pid);
    text(joint,"OBSERVATION_SECTION=CALLBACK_SUITE\r\n");
    callback_ok=child(callback,"CISUIT",joint)&&callback_reports();text(joint,callback_ok?"CALLBACK_COMPLETE_LOGS_AND_OUTER_EXIT=PASS\r\n":"CALLBACK_COMPLETE_LOGS_AND_OUTER_EXIT=FAIL\r\n");
    if(!callback_ok)goto finish;
    text(joint,"OBSERVATION_SECTION=LOAD_CONFIG_WORKER\r\n");
    api_ok=child(worker,"LCWORK",api)&&api_report();text(api,api_ok?"FRESH_COMPLETE_API_SEMANTICS=PASS\r\n":"FRESH_COMPLETE_API_SEMANTICS=FAIL\r\n");
    if(api_ok&&!io_failed)result=0;
finish:
    text(api,api_ok?"STATUS=SCOPED_NATIVE_API_CHILD_PASS\r\n":"STATUS=FAIL\r\n");text(api,"OBSERVER_OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=1\r\n");
    text(joint,result?"STATUS=FAIL\r\n":"STATUS=SCOPED_JOINT_NATIVE_CHILD_PROOF_PASS\r\n");text(joint,"API_OBSERVER_SAME_PROCESS=1\r\nOBSERVER_OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=1\r\n");
    if(!FlushFileBuffers(api))result=31;if(!FlushFileBuffers(joint))result=31;
    if(!CloseHandle(api))result=31;if(!CloseHandle(joint))result=31;ExitProcess(result);
}
