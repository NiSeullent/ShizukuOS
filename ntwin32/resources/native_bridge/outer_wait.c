/* SPDX-License-Identifier: GPL-2.0-only -- actual closed bridge child observer. */
#ifdef RBWAIT_HOST_TEST
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#define WINAPI
typedef uint32_t DWORD;typedef int BOOL;typedef unsigned int UINT;typedef unsigned char BYTE;
typedef void *HANDLE;typedef const char *LPCSTR;typedef char *LPSTR;typedef void *LPVOID;
typedef void *LPSECURITY_ATTRIBUTES;typedef DWORD *LPDWORD;
typedef struct {DWORD cb;} STARTUPINFOA,*LPSTARTUPINFOA;
typedef struct {HANDLE hProcess,hThread;DWORD dwProcessId,dwThreadId;} PROCESS_INFORMATION,*LPPROCESS_INFORMATION;
typedef void (*FARPROC)(void);
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define GENERIC_WRITE 0x40000000u
#define GENERIC_READ 0x80000000u
#define CREATE_NEW 1u
#define OPEN_EXISTING 3u
#define FILE_ATTRIBUTE_NORMAL 128u
#define FILE_ATTRIBUTE_DIRECTORY 16u
#define FILE_SHARE_READ 1u
#define INVALID_FILE_ATTRIBUTES UINT32_MAX
#define ERROR_FILE_NOT_FOUND 2u
#define STILL_ACTIVE 259u
#define WAIT_FAILED UINT32_MAX
#define WAIT_TIMEOUT 258u
#define WAIT_OBJECT_0 0u
#define FALSE 0
static DWORD GetLastError(void);static HANDLE CreateFileA(LPCSTR,DWORD,DWORD,LPVOID,DWORD,DWORD,HANDLE);
static BOOL ReadFile(HANDLE,LPVOID,DWORD,LPDWORD,LPVOID);static BOOL WriteFile(HANDLE,const void *,DWORD,LPDWORD,LPVOID);
static BOOL FlushFileBuffers(HANDLE);static BOOL CloseHandle(HANDLE);static DWORD GetFileAttributesA(LPCSTR);
static void ExitProcess(UINT);static int px_original_win98(void);static FARPROC px_original_kernel(const char *,int *);
#else
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "../../process_exit/original_kernel.h"
_Static_assert(sizeof(void *)==4&&sizeof(STARTUPINFOA)==68&&sizeof(PROCESS_INFORMATION)==16,"PE32 process ABI");
#endif
#include "sha256.h"
#include "rbwait_pins.h"
static HANDLE report=INVALID_HANDLE_VALUE;static int io_failed;
static void value(const char *name,DWORD v)
{
 char out[128];DWORD n=0,written=0;unsigned i;
 while(*name&&n<sizeof(out)-12)out[n++]=*name++;
 if(*name){io_failed=1;return;}
 out[n++]='=';for(i=0;i<8;i++)out[n++]="0123456789ABCDEF"[(v>>(28-i*4))&15];out[n++]='\r';out[n++]='\n';
 if(!WriteFile(report,out,n,&written,NULL)||written!=n||!FlushFileBuffers(report))io_failed=1;
}
static int pin_probe(void)
{
 HANDLE file;BYTE block[1024],digest[32];char actual[65];sha256_ctx hash;DWORD n,total=0,error;unsigned i;int okay=1;
 file=CreateFileA("C:\\VXDLAB\\RBPROBE.EXE",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(file==INVALID_HANDLE_VALUE){error=GetLastError();value("PROBE_OPEN_ERROR",error);return 0;}
 sha256_init(&hash);
 for(;;){if(!ReadFile(file,block,sizeof(block),&n,NULL)){error=GetLastError();value("PROBE_READ_ERROR",error);okay=0;break;}
  if(!n)break;if(total>RB_PROBE_BYTES||n>RB_PROBE_BYTES-total){okay=0;break;}total+=n;sha256_update(&hash,block,n);}
 if(!CloseHandle(file)){error=GetLastError();value("PROBE_CLOSE_ERROR",error);okay=0;}
 sha256_final(&hash,digest);sha256_hex(digest,actual);for(i=0;i<64;i++)if(actual[i]!=RB_PROBE_SHA[i])okay=0;
 value("PROBE_ACTUAL_BYTES",total);value("PROBE_EXACT_SHA_AND_EOF",okay&&total==RB_PROBE_BYTES);
 return okay&&total==RB_PROBE_BYTES&&!io_failed;
}
typedef struct child_report {DWORD stage,bits,selected,outer_required;int bad;} child_report;
static int equal_line(const char *a,const char *b)
{while(*a&&*a==*b){a++;b++;}return *a==*b;}
static int numeric_line(const char *row,const char *prefix,DWORD *v)
{
 DWORD n=0;unsigned digits=0;
 while(*prefix){if(*row++!=*prefix++)return 0;}
 while(*row>='0'&&*row<='9'){DWORD d=(DWORD)(*row++-'0');if(n>429496729u||(n==429496729u&&d>5))return -1;n=n*10+d;digits++;}
 if(!digits||*row)return -1;*v=n;return 1;
}
static void child_line(child_report *s,const char *row)
{
 static const char *const labels[]={"RESOURCE_LOCK_ENTER_LAST_ERROR=","RESOURCE_LOCK_LEAVE_LAST_ERROR=",
  "BRIDGE_FIND_EX_A_LAST_ERROR=","BRIDGE_FIND_A_LAST_ERROR=","BRIDGE_FIND_EX_W_LAST_ERROR=","BRIDGE_FIND_W_LAST_ERROR=",
  "BRIDGE_SIZE_LAST_ERROR=","BRIDGE_LOAD_LAST_ERROR=","BRIDGE_LOCK_LAST_ERROR=","BRIDGE_FREE_LAST_ERROR=",
  "BRIDGE_REPEAT_FREE_LAST_ERROR=","BRIDGE_RETAINED_LOCK_LAST_ERROR="};
 const DWORD sentinel=0x51a2b3c4u,complete=0x7ffffu;DWORD v=0,bit=0;int matched;unsigned i;
 matched=numeric_line(row,"DEFAULT_RUNTIME_RESOURCE_RESULT=",&v);
 if(matched){if(matched<0||s->stage||v!=20)s->bad=1;else s->stage=1;return;}
 for(i=0;i<12;i++){matched=numeric_line(row,labels[i],&v);if(matched){bit=1u<<i;if(matched<0||v!=sentinel)s->bad=1;break;}}
 if(!bit){matched=numeric_line(row,"MAPPED_APP_NULL_IDENTITY_LAST_ERROR=",&v);if(matched){bit=1u<<12;if(matched<0||s->stage!=1||v!=sentinel)s->bad=1;}}
 if(!bit){matched=numeric_line(row,"NATIVE_HOST_NULL_IDENTITY_LAST_ERROR=",&v);if(matched){bit=1u<<12;if(matched<0||s->stage!=2||v!=sentinel)s->bad=1;}}
 if(!bit){matched=numeric_line(row,"BRIDGE_NULL_RESOURCE_SELECTED_ERROR=",&v);if(matched){bit=1u<<13;if(matched<0||(s->stage==1?v!=sentinel:!v||v==sentinel))s->bad=1;}}
 if(!bit){matched=numeric_line(row,"BRIDGE_NATIVE_LAST_ERROR_CONTROLS=",&v);if(matched){bit=1u<<14;if(matched<0||v!=14||(s->bits&0x3fffu)!=0x3fffu)s->bad=1;}}
 if(!bit){matched=numeric_line(row,"RESOURCE_APP_CHECKS=",&v);if(matched){bit=1u<<15;if(matched<0||s->stage!=1||v<35)s->bad=1;}}
 if(!bit){matched=numeric_line(row,"FIXTURE_RETURN=",&v);if(matched){bit=1u<<15;if(matched<0||s->stage!=2||v)s->bad=1;}}
 if(!bit){matched=numeric_line(row,"RESOURCE_DETACH_SUCCESSES=",&v);if(matched){bit=1u<<16;if(matched<0||v!=4)s->bad=1;}}
 if(!bit){matched=numeric_line(row,"RESOURCE_DETACH_FAILURES=",&v);if(matched){bit=1u<<17;if(matched<0||v)s->bad=1;}}
 if(!bit&&equal_line(row,"RESOURCES=UNREGISTERED_BEFORE_MAPPING_RELEASE"))bit=1u<<18;
 if(bit){if((s->stage!=1&&s->stage!=2)||(s->bits&bit))s->bad=1;s->bits|=bit;return;}
 matched=numeric_line(row,"AFTER_APPLICATION_CLEANUP_HANDLE_ERROR=",&v);
 if(matched){if(matched<0||s->stage!=1||s->bits!=complete||v!=6)s->bad=1;else{s->stage=2;s->bits=0;}return;}
 matched=numeric_line(row,"AFTER_DLL_ROOT_CLEANUP_HANDLE_ERROR=",&v);
 if(matched){if(matched<0||s->stage!=2||s->bits!=complete||v!=6)s->bad=1;else{s->stage=3;s->bits=0;}return;}
 matched=numeric_line(row,"RESOURCE_DIAGNOSTIC_SELECTED_RESULT=",&v);
 if(matched){if(matched<0||s->stage!=3||s->selected||v)s->bad=1;else s->selected=1;return;}
 matched=numeric_line(row,"OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=",&v);
 if(matched){if(matched<0||s->stage!=3||!s->selected||s->outer_required||v!=1)s->bad=1;else s->outer_required=1;}
}
static int readable_log(void)
{
 HANDLE file;BYTE block[1024];char row[512];DWORD got,error,total=0;unsigned used=0,i;int okay=1,cr=0;child_report state={0};
 file=CreateFileA("C:\\VXDLAB\\RBPROBE.LOG",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(file==INVALID_HANDLE_VALUE){error=GetLastError();value("PROBE_LOG_OPEN_ERROR",error);return 0;}
 for(;;){if(!ReadFile(file,block,sizeof(block),&got,NULL)){error=GetLastError();value("PROBE_LOG_READ_ERROR",error);okay=0;break;}
  if(!got)break;if(got>1024u*1024u-total){okay=0;break;}total+=got;
  for(i=0;i<got;i++){BYTE c=block[i];
   if(cr){if(c!='\n'){okay=0;break;}row[used]=0;child_line(&state,row);used=0;cr=0;}
   else if(c=='\r')cr=1;else if(!c||c=='\n'||used>=sizeof(row)-1){okay=0;break;}else row[used++]=(char)c;
  }if(!okay)break;
 }
 if(!CloseHandle(file)){error=GetLastError();value("PROBE_LOG_CLOSE_ERROR",error);io_failed=1;okay=0;}
 value("PROBE_LOG_READABLE_BYTES",total);okay=okay&&total>0&&!used&&!cr&&!state.bad&&state.stage==3&&state.selected&&state.outer_required;
 value("FULL_DEFAULT_AND_BOTH_RESOURCE_GRAPHS",okay);value("FULL_NATIVE_SENTINEL_CONTROLS",okay?28:0);return okay;
}
void WINAPI entry(void)
{
 typedef BOOL (WINAPI *create_fn)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
 typedef DWORD (WINAPI *wait_fn)(HANDLE,DWORD);typedef BOOL (WINAPI *query_fn)(HANDLE,LPDWORD);typedef BOOL (WINAPI *terminate_fn)(HANDLE,UINT);
 create_fn create;wait_fn wait;query_fn query;terminate_fn terminate;int route;
 STARTUPINFOA start={0};PROCESS_INFORMATION child={0};char command[]="C:\\VXDLAB\\RBPROBE.EXE";
 DWORD attrs,error,waited,exit_code=STILL_ACTIVE,result=3;BOOL okay;
 report=CreateFileA("C:\\VXDLAB\\RBWAIT.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
 value("OUTER_BRIDGE_OBSERVER_ENTRY",1);value("APPLICATION_SUCCESS",0);
 if(!px_original_win98()){value("ACTUAL_ORIGINAL_WIN98_GUARD",0);goto done;}value("ACTUAL_ORIGINAL_WIN98_GUARD",1);
#define RESOLVE(tag,target,type,name) do {route=0;target=(type)(void *)px_original_kernel(name,&route);value(tag,(DWORD)(uintptr_t)target);value("ORIGINAL_RESOLVER_SDK_ROUTE",(DWORD)route);if(!target)goto done;} while(0)
 RESOLVE("ORIGINAL_CREATE_PROCESS_POINTER",create,create_fn,"CreateProcessA");
 RESOLVE("ORIGINAL_WAIT_POINTER",wait,wait_fn,"WaitForSingleObject");
 RESOLVE("ORIGINAL_EXIT_QUERY_POINTER",query,query_fn,"GetExitCodeProcess");
 RESOLVE("ORIGINAL_TERMINATE_POINTER",terminate,terminate_fn,"TerminateProcess");
#undef RESOLVE
 if(io_failed)goto done;
 attrs=GetFileAttributesA("C:\\VXDLAB\\RBPROBE.LOG");error=attrs==INVALID_FILE_ATTRIBUTES?GetLastError():0;
 value("PROBE_LOG_BEFORE_ERROR",error);if(attrs!=INVALID_FILE_ATTRIBUTES||error!=ERROR_FILE_NOT_FOUND||!pin_probe())goto done;
 start.cb=sizeof(start);
 okay=create(command,command,NULL,NULL,FALSE,0,NULL,"C:\\VXDLAB",&start,&child);error=okay?0:GetLastError();
 value("ACTUAL_CREATE_ERROR",error);if(!okay)goto done;value("ACTUAL_PROBE_PID",child.dwProcessId);
 if(!CloseHandle(child.hThread)){error=GetLastError();value("THREAD_CLOSE_ERROR",error);io_failed=1;}
 waited=wait(child.hProcess,30000);error=waited==WAIT_FAILED?GetLastError():0;
 value("ACTUAL_PROBE_WAIT",waited);value("ACTUAL_PROBE_WAIT_ERROR",error);
 if(waited==WAIT_OBJECT_0){okay=query(child.hProcess,&exit_code);error=okay?0:GetLastError();
  value("ACTUAL_EXIT_QUERY_ERROR",error);value("ACTUAL_PROBE_OS_EXIT",exit_code);if(okay&&!exit_code&&!io_failed)result=0;
 }else{
  okay=terminate(child.hProcess,125);error=okay?0:GetLastError();value("GUARD_TERMINATE_PROBE",okay);value("GUARD_TERMINATE_ERROR",error);
  waited=wait(child.hProcess,5000);error=waited==WAIT_FAILED?GetLastError():0;value("GUARD_REAP_WAIT",waited);value("GUARD_REAP_ERROR",error);result=5;
 }
 if(!CloseHandle(child.hProcess)){error=GetLastError();value("PROCESS_CLOSE_ERROR",error);io_failed=1;}
 attrs=GetFileAttributesA("C:\\VXDLAB\\RBPROBE.LOG");error=attrs==INVALID_FILE_ATTRIBUTES?GetLastError():0;
 value("PROBE_LOG_AFTER_ERROR",error);value("PROBE_FRESH_LOG_PRESENT",attrs!=INVALID_FILE_ATTRIBUTES&&!(attrs&FILE_ATTRIBUTE_DIRECTORY));
 if(attrs==INVALID_FILE_ATTRIBUTES||(attrs&FILE_ATTRIBUTE_DIRECTORY)||!readable_log())result=3;
done:
 if(io_failed)result=31;value("OUTER_BRIDGE_SELECTED_RESULT",result);value("OUTER_OWN_OS_EXIT_REQUIRES_OBSERVER",1);
 if(!CloseHandle(report))io_failed=1;ExitProcess(io_failed?31:result);
}

#ifdef RBWAIT_HOST_TEST
/* Host executes only these own API mocks. Reads the actual frozen child bytes
 * for hash/EOF controls; never executes the PE child. Every mock clobbers the
 * last-error state so capture-before-report failures are visible. */
static jmp_buf stopped;static BYTE *probe;static DWORD probe_length,probe_at,log_at,error_state,selected;
static char output[8192];static size_t output_at;static unsigned checks,cases,creates,waits,terminations;
static int scenario;
enum {GOOD,OS_REFUSED,RESOLVER_REFUSED,REPORT_OPEN,STALE_LOG,BAD_BEFORE_ERROR,PROBE_OPEN,PROBE_READ,PROBE_SHORT,PROBE_EXTRA,PROBE_HASH,
 PROBE_CLOSE,CREATE_FAILED,THREAD_CLOSE,WAIT_TIMED_OUT,WAIT_BAD,WAIT_UNEXPECTED,QUERY_FAILED,CHILD_NONZERO,PROCESS_CLOSE,
 LOG_MISSING,LOG_DIRECTORY,LOG_OPEN,LOG_EMPTY,LOG_READ,LOG_CLOSE,REPORT_WRITE,REPORT_SHORT,REPORT_FLUSH,REPORT_CLOSE,TERMINATE_FAILED,REAP_FAILED,
 LOG_MISSING_FIRST_GRAPH,LOG_BAD_FIRST_SENTINEL,LOG_BAD_FIRST_DETACH,LOG_MISSING_SECOND_GRAPH,LOG_DUPLICATE_DEFAULT,LOG_NO_FINAL_ROW,LOG_INCOMPLETE_LINE,LOG_OVERLONG_ROW};
static const char good_log[]=
 "DEFAULT_RUNTIME_RESOURCE_RESULT=20\r\n"
 "RESOURCE_LOCK_ENTER_LAST_ERROR=1369617348\r\nRESOURCE_LOCK_LEAVE_LAST_ERROR=1369617348\r\n"
 "MAPPED_APP_NULL_IDENTITY_LAST_ERROR=1369617348\r\n"
 "BRIDGE_FIND_EX_A_LAST_ERROR=1369617348\r\nBRIDGE_FIND_A_LAST_ERROR=1369617348\r\n"
 "BRIDGE_FIND_EX_W_LAST_ERROR=1369617348\r\nBRIDGE_FIND_W_LAST_ERROR=1369617348\r\n"
 "BRIDGE_SIZE_LAST_ERROR=1369617348\r\nBRIDGE_LOAD_LAST_ERROR=1369617348\r\n"
 "BRIDGE_LOCK_LAST_ERROR=1369617348\r\nBRIDGE_FREE_LAST_ERROR=1369617348\r\n"
 "BRIDGE_REPEAT_FREE_LAST_ERROR=1369617348\r\nBRIDGE_RETAINED_LOCK_LAST_ERROR=1369617348\r\n"
 "BRIDGE_NULL_RESOURCE_SELECTED_ERROR=1369617348\r\nBRIDGE_NATIVE_LAST_ERROR_CONTROLS=14\r\n"
 "RESOURCE_APP_CHECKS=40\r\nRESOURCE_DETACH_SUCCESSES=4\r\nRESOURCE_DETACH_FAILURES=0\r\n"
 "RESOURCES=UNREGISTERED_BEFORE_MAPPING_RELEASE\r\nAFTER_APPLICATION_CLEANUP_HANDLE_ERROR=6\r\n"
 "RESOURCE_LOCK_ENTER_LAST_ERROR=1369617348\r\nRESOURCE_LOCK_LEAVE_LAST_ERROR=1369617348\r\n"
 "NATIVE_HOST_NULL_IDENTITY_LAST_ERROR=1369617348\r\n"
 "BRIDGE_FIND_EX_A_LAST_ERROR=1369617348\r\nBRIDGE_FIND_A_LAST_ERROR=1369617348\r\n"
 "BRIDGE_FIND_EX_W_LAST_ERROR=1369617348\r\nBRIDGE_FIND_W_LAST_ERROR=1369617348\r\n"
 "BRIDGE_SIZE_LAST_ERROR=1369617348\r\nBRIDGE_LOAD_LAST_ERROR=1369617348\r\n"
 "BRIDGE_LOCK_LAST_ERROR=1369617348\r\nBRIDGE_FREE_LAST_ERROR=1369617348\r\n"
 "BRIDGE_REPEAT_FREE_LAST_ERROR=1369617348\r\nBRIDGE_RETAINED_LOCK_LAST_ERROR=1369617348\r\n"
 "BRIDGE_NULL_RESOURCE_SELECTED_ERROR=1813\r\nBRIDGE_NATIVE_LAST_ERROR_CONTROLS=14\r\n"
 "FIXTURE_RETURN=0\r\nRESOURCE_DETACH_SUCCESSES=4\r\nRESOURCE_DETACH_FAILURES=0\r\n"
 "RESOURCES=UNREGISTERED_BEFORE_MAPPING_RELEASE\r\nAFTER_DLL_ROOT_CLEANUP_HANDLE_ERROR=6\r\n"
 "RESOURCE_DIAGNOSTIC_SELECTED_RESULT=0\r\nOWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=1\r\n";
static char child_log[4096];static DWORD child_log_size;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"scenario %d line %u: %s\n",scenario,__LINE__,#x);exit(1);}} while(0)
static DWORD GetLastError(void){return error_state;}
static HANDLE CreateFileA(LPCSTR p,DWORD access,DWORD share,LPVOID security,DWORD disposition,DWORD attrs,HANDLE template)
{(void)security;(void)attrs;(void)template;error_state=1001;
 if(!strcmp(p,"C:\\VXDLAB\\RBWAIT.LOG")){CHECK(disposition==CREATE_NEW&&access==GENERIC_WRITE&&share==0);return scenario==REPORT_OPEN?INVALID_HANDLE_VALUE:(HANDLE)(uintptr_t)1;}
 CHECK(disposition==OPEN_EXISTING&&access==GENERIC_READ&&share==FILE_SHARE_READ);
 if(!strcmp(p,"C:\\VXDLAB\\RBPROBE.EXE"))return scenario==PROBE_OPEN?INVALID_HANDLE_VALUE:(HANDLE)(uintptr_t)2;
 CHECK(!strcmp(p,"C:\\VXDLAB\\RBPROBE.LOG"));return scenario==LOG_OPEN?INVALID_HANDLE_VALUE:(HANDLE)(uintptr_t)3;}
static BOOL ReadFile(HANDLE h,LPVOID bytes,DWORD size,LPDWORD got,LPVOID overlapped)
{DWORD remaining,n;(void)overlapped;error_state=1002;
 if(h==(HANDLE)(uintptr_t)2){if(scenario==PROBE_READ)return 0;remaining=probe_length-probe_at;
  if(scenario==PROBE_SHORT&&remaining>0)remaining--;n=remaining<size?remaining:size;
  if(n){memcpy(bytes,probe+probe_at,n);if(scenario==PROBE_HASH&&probe_at==0)((BYTE *)bytes)[0]^=1;probe_at+=n;}
  else if(scenario==PROBE_EXTRA&&probe_at==probe_length){((BYTE *)bytes)[0]=1;n=1;probe_at++;}
  *got=n;return 1;}
 CHECK(h==(HANDLE)(uintptr_t)3);if(scenario==LOG_READ)return 0;remaining=scenario==LOG_EMPTY?0:child_log_size-log_at;n=remaining<size?remaining:size;
 if(n){memcpy(bytes,child_log+log_at,n);log_at+=n;}*got=n;return 1;}
static BOOL WriteFile(HANDLE h,const void *bytes,DWORD n,LPDWORD written,LPVOID unused)
{(void)unused;CHECK(h==(HANDLE)(uintptr_t)1);error_state=2001;CHECK(n<sizeof(output)-output_at);
 memcpy(output+output_at,bytes,n);output_at+=n;output[output_at]=0;*written=scenario==REPORT_SHORT?n-1:n;return scenario!=REPORT_WRITE;}
static BOOL FlushFileBuffers(HANDLE h){CHECK(h==(HANDLE)(uintptr_t)1);error_state=2002;return scenario!=REPORT_FLUSH;}
static BOOL CloseHandle(HANDLE h)
{error_state=1003;return !((scenario==REPORT_CLOSE&&h==(HANDLE)(uintptr_t)1)||(scenario==PROBE_CLOSE&&h==(HANDLE)(uintptr_t)2)||(scenario==LOG_CLOSE&&h==(HANDLE)(uintptr_t)3)||(scenario==THREAD_CLOSE&&h==(HANDLE)(uintptr_t)5)||(scenario==PROCESS_CLOSE&&h==(HANDLE)(uintptr_t)4));}
static DWORD GetFileAttributesA(LPCSTR p)
{CHECK(!strcmp(p,"C:\\VXDLAB\\RBPROBE.LOG"));error_state=ERROR_FILE_NOT_FOUND;
 if(!creates){if(scenario==STALE_LOG)return FILE_ATTRIBUTE_NORMAL;if(scenario==BAD_BEFORE_ERROR)error_state=5;return INVALID_FILE_ATTRIBUTES;}
 if(scenario==LOG_MISSING)return INVALID_FILE_ATTRIBUTES;return scenario==LOG_DIRECTORY?FILE_ATTRIBUTE_DIRECTORY:FILE_ATTRIBUTE_NORMAL;}
static BOOL mock_create(LPCSTR app,LPSTR command,LPSECURITY_ATTRIBUTES a,LPSECURITY_ATTRIBUTES b,BOOL inherit,DWORD flags,LPVOID env,LPCSTR directory,LPSTARTUPINFOA start,LPPROCESS_INFORMATION child)
{CHECK(!strcmp(app,"C:\\VXDLAB\\RBPROBE.EXE")&&!strcmp(command,app)&&!strcmp(directory,"C:\\VXDLAB"));CHECK(!a&&!b&&!inherit&&!flags&&!env&&start->cb==sizeof(*start));creates++;error_state=1004;
 child->hProcess=(HANDLE)(uintptr_t)4;child->hThread=(HANDLE)(uintptr_t)5;child->dwProcessId=123;return scenario!=CREATE_FAILED;}
static DWORD mock_wait(HANDLE h,DWORD milliseconds)
{CHECK(h==(HANDLE)(uintptr_t)4);waits++;CHECK(milliseconds==(waits==1?30000u:5000u));error_state=1005;
 if(waits>1)return scenario==REAP_FAILED?WAIT_FAILED:WAIT_OBJECT_0;
 if(scenario==WAIT_TIMED_OUT||scenario==TERMINATE_FAILED||scenario==REAP_FAILED)return WAIT_TIMEOUT;
 if(scenario==WAIT_BAD)return WAIT_FAILED;if(scenario==WAIT_UNEXPECTED)return 128;return WAIT_OBJECT_0;}
static BOOL mock_query(HANDLE h,LPDWORD code){CHECK(h==(HANDLE)(uintptr_t)4);error_state=1006;*code=scenario==CHILD_NONZERO?17:0;return scenario!=QUERY_FAILED;}
static BOOL mock_terminate(HANDLE h,UINT code){CHECK(h==(HANDLE)(uintptr_t)4&&code==125);terminations++;error_state=1007;return scenario!=TERMINATE_FAILED;}
static void ExitProcess(UINT code){selected=code;longjmp(stopped,1);}
static int px_original_win98(void){error_state=1008;return scenario!=OS_REFUSED;}
static FARPROC px_original_kernel(const char *name,int *route)
{error_state=1009;*route=1;if(scenario==RESOLVER_REFUSED)return NULL;
 if(!strcmp(name,"CreateProcessA"))return (FARPROC)mock_create;if(!strcmp(name,"WaitForSingleObject"))return (FARPROC)mock_wait;
 if(!strcmp(name,"GetExitCodeProcess"))return (FARPROC)mock_query;CHECK(!strcmp(name,"TerminateProcess"));return (FARPROC)mock_terminate;}
int main(int argc,char **argv)
{FILE *f;long length;int s;CHECK(argc==2);f=fopen(argv[1],"rb");CHECK(f!=NULL);CHECK(fseek(f,0,SEEK_END)==0);length=ftell(f);CHECK(length==(long)RB_PROBE_BYTES);CHECK(fseek(f,0,SEEK_SET)==0);
 probe=malloc((size_t)length);CHECK(probe!=NULL&&fread(probe,1,(size_t)length,f)==(size_t)length);CHECK(fclose(f)==0);probe_length=(DWORD)length;
 for(s=GOOD;s<=LOG_OVERLONG_ROW;s++){char *at;scenario=s;cases++;creates=waits=terminations=0;probe_at=log_at=0;output_at=0;output[0]=0;io_failed=0;selected=UINT32_MAX;
  memcpy(child_log,good_log,sizeof(good_log));child_log_size=sizeof(good_log)-1;
  if(s==LOG_MISSING_FIRST_GRAPH){at=strstr(child_log,"RESOURCE_APP_CHECKS=");*at='X';}
  if(s==LOG_BAD_FIRST_SENTINEL){at=strstr(child_log,"1369617348");*at='0';}
  if(s==LOG_BAD_FIRST_DETACH){at=strstr(child_log,"RESOURCE_DETACH_FAILURES=0");at[strlen("RESOURCE_DETACH_FAILURES=")]='1';}
  if(s==LOG_MISSING_SECOND_GRAPH){at=strstr(child_log,"FIXTURE_RETURN=");*at='X';}
  if(s==LOG_DUPLICATE_DEFAULT){memmove(child_log+sizeof("DEFAULT_RUNTIME_RESOURCE_RESULT=20\r\n")-1,child_log,child_log_size);memcpy(child_log,"DEFAULT_RUNTIME_RESOURCE_RESULT=20\r\n",sizeof("DEFAULT_RUNTIME_RESOURCE_RESULT=20\r\n")-1);child_log_size+=sizeof("DEFAULT_RUNTIME_RESOURCE_RESULT=20\r\n")-1;}
  if(s==LOG_NO_FINAL_ROW){at=strstr(child_log,"RESOURCE_DIAGNOSTIC_SELECTED_RESULT=");*at='X';}
  if(s==LOG_INCOMPLETE_LINE)child_log_size--;
  if(s==LOG_OVERLONG_ROW){memset(child_log,'X',513);child_log[513]='\r';child_log[514]='\n';child_log_size=515;}
  if(!setjmp(stopped))entry();CHECK(s==GOOD?selected==0:selected!=0);
  if(s==WAIT_TIMED_OUT||s==WAIT_BAD||s==WAIT_UNEXPECTED||s==TERMINATE_FAILED||s==REAP_FAILED)CHECK(terminations==1&&waits==2&&selected!=0);
  if(s==WAIT_BAD)CHECK(strstr(output,"ACTUAL_PROBE_WAIT_ERROR=000003ED\r\n")!=NULL);
  if(s==QUERY_FAILED)CHECK(strstr(output,"ACTUAL_EXIT_QUERY_ERROR=000003EE\r\n")!=NULL);
  if(s==CREATE_FAILED)CHECK(strstr(output,"ACTUAL_CREATE_ERROR=000003EC\r\n")!=NULL);
  if(s==TERMINATE_FAILED)CHECK(strstr(output,"GUARD_TERMINATE_ERROR=000003EF\r\n")!=NULL);
  if(s<=PROBE_CLOSE&&s!=GOOD)CHECK(creates==0);
 }
 free(probe);printf("RESULT PASS cases=%u checks=%u clobbering_callbacks=true actual_child_executed=false\n",cases,checks);return 0;}
#endif
