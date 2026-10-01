/* SPDX-License-Identifier: GPL-2.0-only */
#include "mock_windows.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern void entry(void);extern void rpc_wait_host_reset(void);
static jmp_buf jump;
static unsigned checks;static int scenario;static DWORD error,selected;static unsigned opened[40],closed[40],reads,queried,waited;
static char output[8192];static size_t used;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL line%u scenario%d %s\n",__LINE__,scenario,#x);exit(1);}}while(0)
HANDLE CreateFileA(const char *p,DWORD access,DWORD share,void *security,DWORD action,DWORD attr,HANDLE template){(void)security;(void)template;CHECK(attr==FILE_ATTRIBUTE_NORMAL);
 if(!strcmp(p,"C:\\VXDLAB\\RPCWAIT.LOG")){CHECK(action==CREATE_NEW&&access==GENERIC_WRITE&&share==0);if(scenario==1)return INVALID_HANDLE_VALUE;opened[1]++;return 1;}
 CHECK(action==OPEN_EXISTING&&access==GENERIC_READ&&share==FILE_SHARE_READ);CHECK(!strcmp(p,"C:\\VXDLAB\\RPCDBG.LOG")||!strcmp(p,"C:\\VXDLAB\\RPCFIX.LOG"));
 if(scenario==9){error=9009;return INVALID_HANDLE_VALUE;}HANDLE h=strstr(p,"RPCDBG")?30:31;opened[h]++;return h;
}
BOOL WriteFile(HANDLE h,const void *p,DWORD n,DWORD *got,void *overlap){(void)overlap;CHECK(h==1);CHECK(used+n<sizeof(output));memcpy(output+used,p,n);used+=n;output[used]=0;*got=scenario==15?n-1:n;error=0xbadc0de;return scenario!=15;}
BOOL ReadFile(HANDLE h,void *p,DWORD n,DWORD *got,void *overlap){(void)overlap;CHECK(h==30||h==31);CHECK(n==1);reads++;*(BYTE *)p=0x52;*got=scenario==12?0:1;if(scenario==11){error=9011;return FALSE;}return TRUE;}
BOOL FlushFileBuffers(HANDLE h){CHECK(h==1);return scenario!=16;}
BOOL CloseHandle(HANDLE h){CHECK(h==1||h==10||h==11||h==30||h==31);CHECK(++closed[h]<=1);
 if((scenario==7&&h==11)||(scenario==8&&h==10)||(scenario==13&&(h==30||h==31))||(scenario==17&&h==1)){error=7777;return FALSE;}return TRUE;}
DWORD GetFileSize(HANDLE h,DWORD *high){CHECK(h==30||h==31);*high=scenario==14?1:0;if(scenario==10)return 0;if(scenario==19){error=7019;return INVALID_FILE_SIZE;}if(scenario==20)return 2*1024*1024;return 12;}
BOOL GetVersionExA(OSVERSIONINFOA *os){os->dwMajorVersion=scenario==2?5:4;os->dwMinorVersion=10;os->dwBuildNumber=2222;os->dwPlatformId=1;return TRUE;}
BOOL CreateProcessA(const char *a,char *command,void *p,void *t,BOOL inherit,DWORD flags,void *env,const char *cwd,STARTUPINFOA *s,PROCESS_INFORMATION *pi){(void)p;(void)t;(void)env;(void)s;
 CHECK(!strcmp(a,"C:\\VXDLAB\\RPCOBS.EXE"));CHECK(!strcmp(command,"C:\\VXDLAB\\RPCOBS.EXE --fixture --log C:\\VXDLAB\\RPCDBG.LOG"));CHECK(!strcmp(cwd,"C:\\VXDLAB"));CHECK(!inherit&&!flags);
 if(scenario==3){error=7003;return FALSE;}pi->hProcess=10;pi->hThread=11;pi->dwProcessId=100;pi->dwThreadId=101;opened[10]++;opened[11]++;return TRUE;}
DWORD GetLastError(void){return error;}
DWORD WaitForSingleObject(HANDLE h,DWORD n){CHECK(h==10&&n==300000);waited++;if(scenario==4)return WAIT_TIMEOUT;if(scenario==5){error=7005;return WAIT_FAILED;}return WAIT_OBJECT_0;}
BOOL GetExitCodeProcess(HANDLE h,DWORD *code){CHECK(h==10);queried++;if(scenario==6){error=7006;return FALSE;}*code=scenario==18?31:0;return TRUE;}
_Noreturn void ExitProcess(DWORD code){selected=code;longjmp(jump,1);}
int main(void){unsigned i;static const DWORD want[]={0,20,21,3,4,4,5,7,7,8,8,8,8,8,8,32,32,32,6,8,8};
 for(scenario=0;scenario<21;scenario++){
  used=0;output[0]=0;error=0;reads=queried=waited=0;memset(opened,0,sizeof(opened));memset(closed,0,sizeof(closed));rpc_wait_host_reset();
  if(!setjmp(jump))entry();CHECK(selected==want[scenario]);
  if(scenario==0){CHECK(reads==2&&queried==1);CHECK(strstr(output,"ACTUAL_OBSERVER_OS_EXIT=00000000"));CHECK(strstr(output,"OUTER_OWN_OS_EXIT_UNOBSERVED=1"));}
  if(scenario==3)CHECK(strstr(output,"CREATE_ERROR=00001B5B"));
  if(scenario==4||scenario==5){CHECK(!queried);CHECK(strstr(output,"OBSERVER_MAY_REMAIN_ALIVE_OUTER_VM_CAP_REQUIRED=1"));}
  if(scenario==5)CHECK(strstr(output,"WAIT_ERROR=00001B5D"));
  if(scenario==6)CHECK(strstr(output,"EXIT_QUERY_ERROR=00001B5E"));
  if(scenario==7||scenario==8||scenario==13)CHECK(strstr(output,"00001E61"));
  if(scenario==9)CHECK(strstr(output,"REPORT_ERROR=00002331"));
  if(scenario==11)CHECK(strstr(output,"REPORT_ERROR=00002333"));
  if(scenario==10||scenario==14)CHECK(!reads);
  if(scenario==19){CHECK(!reads);CHECK(strstr(output,"REPORT_ERROR=00001B6B"));}
  if(scenario==20)CHECK(!reads);
  for(i=1;i<40;i++)if(opened[i])CHECK(closed[i]==1);
 }
 printf("PASS actual outer C:21 scenarios/%u checks; native pending\n",checks);return 0;}
