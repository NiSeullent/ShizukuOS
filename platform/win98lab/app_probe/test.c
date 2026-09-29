/* Original scripted WinAPI model. Synthetic host tests, never native evidence. */
#include "mock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
void mainCRTStartup(void);
static unsigned long checks,scenarios,faults;
static struct {
    unsigned calls,fault,fired,writes,short_write,flushes,created,stopped,terminated;
    unsigned waits,slices,posted,post_accepted,terminate_accepted,enumerated,owner_calls[2],close_calls[12],live[12];
    unsigned log_exists,wrong_path,version_fail,launch_error,exit_error;
    unsigned early_slices,close_stops,terminate_fail,stop_unknown,wait_fail,enum_fail;
    unsigned owner_changes,post_fail,text_mode,foreign_only,too_many,freeze_clock,back_clock;
    unsigned mode_calls,mode_changed,mode_restored;
    DWORD last_error,final_exit,os_platform,os_major,os_minor,ticks,error_mode,child_exit;
    char log[262144]; size_t log_size;
    jmp_buf jump;
} m;
#define C(x) do {++checks;if(!(x)){fprintf(stderr,"line %u %s (scenario %lu call %u fault %u)\n",__LINE__,#x,scenarios,m.calls,m.fault);exit(1);}}while(0)
static int call(void){++m.calls;if(m.calls==m.fault){m.fired=1;m.last_error=0xd0000000u+m.calls;return 1;}return 0;}
static void reset(void){memset(&m,0,sizeof(m));m.os_platform=1;m.os_major=4;m.os_minor=10;m.error_mode=2;m.early_slices=2;}
static int has(const char *s){return strstr(m.log,s)!=NULL;}
DWORD GetLastError(void){return m.last_error;}
void SetLastError(DWORD value){m.last_error=value;}
DWORD GetModuleFileNameA(void *module,char *out,DWORD cap){
 const char *s=m.wrong_path?"C:\\OTHER\\NTWAPP.EXE":"C:\\NTWLAB\\NTWAPP.EXE";
 C(!module&&cap==260);if(call())return 0;memcpy(out,s,strlen(s)+1);return (DWORD)strlen(s);
}
HANDLE CreateFileA(const char *path,DWORD access,DWORD share,void *sa,DWORD mode,DWORD attr,void *template){
 C(!strcmp(path,"C:\\NTWLAB\\NTWAPP.LOG")&&access==GENERIC_WRITE&&share==FILE_SHARE_READ&&!sa&&mode==CREATE_NEW&&attr==FILE_ATTRIBUTE_NORMAL&&!template);
 if(call()||m.log_exists)return INVALID_HANDLE_VALUE;
 m.live[1]=1;return 1;
}
BOOL WriteFile(HANDLE h,const void *data,DWORD size,DWORD *written,void *overlap){
 C(h==1&&m.live[1]&&written&&!overlap&&size<256);++m.writes;
 if(call())return FALSE;
 if(m.short_write==m.writes){*written=size?size-1:0;return TRUE;}
 C(m.log_size+size<sizeof(m.log));memcpy(m.log+m.log_size,data,size);m.log_size+=size;m.log[m.log_size]=0;*written=size;m.last_error=0xaabbccddu;return TRUE;
}
BOOL FlushFileBuffers(HANDLE h){C(h==1&&m.live[1]);++m.flushes;return !call();}
BOOL CloseHandle(HANDLE h){C(h<12&&m.live[h]);++m.close_calls[h];if(call())return FALSE;m.live[h]=0;return TRUE;}
BOOL GetVersionExA(OSVERSIONINFOA *v){C(v->dwOSVersionInfoSize==sizeof(*v));if(call()||m.version_fail){m.last_error=87;return FALSE;}v->dwPlatformId=m.os_platform;v->dwMajorVersion=m.os_major;v->dwMinorVersion=m.os_minor;v->dwBuildNumber=0x040a08aeu;return TRUE;}
UINT SetErrorMode(UINT value){DWORD prior=m.error_mode;++m.mode_calls;if(m.mode_calls==1){C(value==0x8001);m.mode_changed=1;}else{C(m.mode_calls==2&&value==2);m.mode_restored=1;}m.error_mode=value;return prior;}
DWORD GetTickCount(void){if(m.back_clock)m.ticks-=1;return m.ticks;}
BOOL CreateProcessA(const char *app,char *command,void *pa,void *ta,BOOL inherit,DWORD flags,void *env,const char *cwd,STARTUPINFOA *si,PROCESS_INFORMATION *pi){
 unsigned i;
#ifdef NTWAPP_CD_SOURCE
 C(!strcmp(app,"D:\\CHROME\\CHROME.EXE")&&!strcmp(command,"\"D:\\CHROME\\CHROME.EXE\"")&&!strcmp(cwd,"D:\\CHROME"));
#else
 C(!strcmp(app,"C:\\CHROMIUM\\CHROME.EXE")&&!strcmp(command,"\"C:\\CHROMIUM\\CHROME.EXE\"")&&!strcmp(cwd,"C:\\CHROMIUM"));
#endif
 C(!pa&&!ta&&!inherit&&!flags&&!env&&si->cb==sizeof(*si)&&m.error_mode==0x8001);
 for(i=0;i<sizeof(si->remaining);++i)C(si->remaining[i]==0);
 C(!pi->hProcess&&!pi->hThread&&!pi->dwProcessId&&!pi->dwThreadId);
 if(call())return FALSE;
 if(m.launch_error){m.last_error=m.launch_error;return FALSE;}
 C(!m.created);m.created=1;m.live[10]=1;m.live[11]=1;pi->hProcess=10;pi->hThread=11;pi->dwProcessId=77;pi->dwThreadId=88;command[0]='!';return TRUE;
}
DWORD WaitForSingleObject(HANDLE h,DWORD timeout){
 C(h==10&&m.live[10]&&(timeout==0||timeout<=500u||timeout==5000u));++m.waits;
 if(call()||m.wait_fail){m.last_error=6;return WAIT_FAILED;}
 if(m.stopped)return WAIT_OBJECT_0;
 if(timeout<=500u&&m.early_slices&&m.slices>=m.early_slices){m.stopped=1;return WAIT_OBJECT_0;}
 if(timeout==5000u){
  if((m.post_accepted&&m.close_stops)||(m.terminate_accepted&&!m.stop_unknown)){m.stopped=1;return WAIT_OBJECT_0;}
 }else if(timeout){++m.slices;if(!m.freeze_clock)m.ticks+=timeout;}
 return WAIT_TIMEOUT;
}
BOOL GetExitCodeProcess(HANDLE h,DWORD *value){C(h==10&&m.live[10]&&m.stopped);if(call()||m.exit_error){m.last_error=6;return FALSE;}*value=m.child_exit;return TRUE;}
BOOL TerminateProcess(HANDLE h,DWORD code){C(h==10&&m.live[10]&&code==0x4e544101u);++m.terminated;if(call()||m.terminate_fail){m.last_error=5;return FALSE;}++m.terminate_accepted;return TRUE;}
BOOL EnumWindows(BOOL (CALLBACK *fn)(HWND,LPARAM),LPARAM arg){
 unsigned i,count=m.too_many?300:3;++m.enumerated;if(call()||m.enum_fail){m.last_error=123;return FALSE;}
 for(i=0;i<count;++i){HWND h=m.too_many?(m.too_many==2?101:100):(HWND)(100+i);if(!fn(h,arg))return FALSE;}return TRUE;
}
DWORD GetWindowThreadProcessId(HWND h,DWORD *pid){
 C(h>=100&&h<=102);if(call())return 0;
 if(h==100||m.foreign_only){*pid=999;return 111;}
 ++m.owner_calls[h-101];*pid=(m.owner_changes&&m.owner_calls[h-101]>41)?999:77;return 88;
}
BOOL IsWindowVisible(HWND h){C(h==101||h==102);return h==101;}
static int text(HWND h,char *out,int cap,int title){
 static const char title_value[]="Chromium\r\nFAKE=PASS\x81\xfe";
 const char *s=title?title_value:"Chrome_WidgetWin_1";size_t n=strlen(s);
 C((h==101||h==102)&&cap==(title?96:64));
 if(call()){m.last_error=6;return 0;}
 if(m.text_mode==1){memset(out,'X',(size_t)cap-1u);out[cap-1]=0;return cap-1;}
 if(m.text_mode==2)return -1;
 if(m.text_mode==3)return cap;
 if(m.text_mode==4)return 0;
 memcpy(out,s,n+1);return (int)n;
}
int GetWindowTextA(HWND h,char *out,int cap){return text(h,out,cap,1);}
int GetClassNameA(HWND h,char *out,int cap){return text(h,out,cap,0);}
BOOL PostMessageA(HWND h,UINT msg,WPARAM w,LPARAM l){C((h==101||h==102)&&msg==WM_CLOSE&&!w&&!l);++m.posted;if(call()||m.post_fail){m.last_error=5;return FALSE;}++m.post_accepted;return TRUE;}
_Noreturn void ExitProcess(DWORD code){m.final_exit=code;longjmp(m.jump,1);}
static void run_case(void){
 ++scenarios;if(!setjmp(m.jump)){mainCRTStartup();C(0);}
 C(m.close_calls[1]<=1);
 if(m.writes)C(m.close_calls[1]==1);
 if(m.mode_changed)C(m.mode_restored&&m.error_mode==2&&m.mode_calls==2);
 if(m.created){C(m.close_calls[10]==1&&m.close_calls[11]==1);C(m.enumerated<=41&&m.slices<=40&&m.terminated<=1);}
 else C(!m.terminated&&!m.posted&&!m.close_calls[10]&&!m.close_calls[11]);
 C(!has("BROWSER_COMPATIBILITY=PASS")&&!has("PAGE_FUNCTIONALITY=PASS"));
 if(!m.stopped)C(!has("OWNED_PROCESS_STOPPED=1\r\n"));
 if(m.final_exit==0){C(has("DIAGNOSTIC_COMPLETE=1\r\n")&&has("END=BEFORE_LOG_CLOSE\r\n"));C(!m.live[1]&&!m.live[10]&&!m.live[11]);if(m.created)C(m.stopped);}
}
int main(void){
 unsigned baseline_calls,baseline_writes,i,mode;
 reset();run_case();C(m.final_exit==0&&m.created&&!m.terminated&&m.stopped);
 C(has("OS_BUILD_RAW=67766446\r\n")&&has("OS_BUILD_LOW=2222\r\n"));
 C(has("PROCESS_ID=77\r\n")&&has("WINDOW_PID=77\r\n")&&!has("WINDOW_PID=999\r\n"));
 C(has("TITLE_HEX=4368726F6D69756D0D0A46414B453D5041535381FE\r\n")&&!has("\r\nFAKE=PASS"));
 C(has("CHILD_EXIT_DWORD=0\r\n")&&has("ERROR_MODE_RESTORE_RETURN=32769\r\n"));
 baseline_calls=m.calls;baseline_writes=m.writes;
 for(i=1;i<=baseline_calls;++i){reset();m.fault=i;run_case();C(m.fired);++faults;}
 for(i=1;i<=baseline_writes;++i){reset();m.short_write=i;run_case();C(m.final_exit==3);++faults;}
 for(mode=0;mode<3;++mode){reset();if(mode==0)m.os_platform=2;else if(mode==1)m.os_major=5;else m.os_minor=90;run_case();C(!m.created&&!m.mode_changed&&m.final_exit==1);}
 reset();m.wrong_path=1;run_case();C(m.final_exit==2&&!m.live[1]);
 reset();m.log_exists=1;strcpy(m.log,"old evidence");run_case();C(m.final_exit==2&&!strcmp(m.log,"old evidence"));
 reset();m.version_fail=1;run_case();C(m.final_exit==1&&!m.mode_changed&&has("WIN32_ERROR=87\r\n"));
 for(i=0;i<4;++i){static const DWORD values[]={193,1150,127,0xffffffffu};reset();m.launch_error=values[i];run_case();C(m.final_exit==0&&!m.created&&has("OBSERVATION=LAUNCH_FAILED\r\n"));if(i==3)C(has("CREATEPROCESS_ERROR=4294967295\r\n"));}
 for(i=0;i<3;++i){static const DWORD exits[]={259,0xc0000005u,0xffffffffu};reset();m.child_exit=exits[i];run_case();C(m.final_exit==0);if(i==2)C(has("CHILD_EXIT_DWORD=4294967295\r\n"));}
 for(i=0;i<5;++i){reset();m.text_mode=i;run_case();C(m.final_exit==0);if(i==1)C(has("TITLE_AT_CAP=1\r\n"));if(i==2||i==3)C(has("TITLE_INVALID_RETURN=1\r\n"));}
 reset();m.early_slices=0;run_case();C(m.slices==40&&m.terminated==1&&m.posted==2&&m.final_exit==0);
 baseline_calls=m.calls;
 for(i=1;i<=baseline_calls;++i){
  /* Full fault sweep also reaches closing enumeration/WM_CLOSE/termination. */
  reset();m.early_slices=0;m.fault=i;run_case();C(m.fired);++faults;
 }
 reset();m.early_slices=0;m.close_stops=1;run_case();C(!m.terminated&&m.posted==2&&m.final_exit==0);
 reset();m.early_slices=0;m.foreign_only=1;run_case();C(!m.posted&&m.terminated==1&&!has("WINDOW_HANDLE="));
 reset();m.early_slices=0;m.owner_changes=1;run_case();C(!m.posted&&m.terminated==1&&has("WM_CLOSE_SKIPPED=OWNER_CHANGED\r\n"));
 reset();m.early_slices=0;m.freeze_clock=1;run_case();C(m.slices==40&&m.terminated==1&&m.final_exit==0);
 reset();m.early_slices=0;m.back_clock=1;run_case();C(m.slices==0&&m.terminated==1&&m.final_exit==0);
 reset();m.ticks=0xfffffff0u;run_case();C(m.final_exit==0&&!m.terminated);
 reset();m.too_many=1;run_case();C(has("ENUM_SCANNED=256\r\n")&&has("ENUM_STOPPED_BY_LIMIT_OR_IO=1\r\n"));
 reset();m.too_many=2;run_case();C(has("ENUM_OWNED=8\r\n")&&has("ENUM_STOPPED_BY_LIMIT_OR_IO=1\r\n"));
 reset();m.enum_fail=1;run_case();C(has("ENUM_ERROR=123\r\n")&&m.final_exit==0);
 reset();m.early_slices=0;m.post_fail=1;run_case();C(has("WM_CLOSE_ERROR=5\r\n")&&m.terminated==1);
 reset();m.early_slices=0;m.post_fail=1;m.close_stops=1;run_case();C(m.terminated==1&&m.post_accepted==0&&m.terminate_accepted==1);
 reset();m.early_slices=0;m.terminate_fail=1;run_case();C(m.final_exit==1&&has("OWNED_PROCESS_STOPPED=0\r\n"));
 reset();m.early_slices=0;m.stop_unknown=1;run_case();C(m.final_exit==1&&has("OWNED_PROCESS_STOPPED=0\r\n"));
 reset();m.wait_fail=1;run_case();C(m.final_exit==1&&m.terminated==1);
 reset();m.exit_error=1;run_case();C(m.final_exit==1&&has("API_ERROR_STAGE=GetExitCodeProcess\r\n"));
 printf("{\"checks\":%lu,\"scenarios\":%lu,\"injected_faults\":%lu,\"passed\":true}\n",checks,scenarios,faults);
 return 0;
}
