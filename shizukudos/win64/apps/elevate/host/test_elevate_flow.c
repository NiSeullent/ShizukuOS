/* SPDX-License-Identifier: GPL-2.0-only
 * Host control for the actual elevate client + prompt bodies: success, kernel
 * refusal, cancel, consent expiry (timer and acceptance-time, tick wrap),
 * undisplayable, and inconsistent-success replies. USER/GDI/clock/IPC are
 * explicit host adapters; this proves client flow and cleanup only, not
 * credential validation, kernel process creation or native GUI behavior. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "windows.h"
#include "../consent.h"
#define main actual_elevate_main
#include "../main.c"
#undef main
#include "../prompt.c"

static unsigned checks,failures,ipc_calls,launch_calls,query_calls,request_wipes,timers_live,set_timer_fail;
static WNDPROC window_proc;
static MSG messages[96];static DWORD message_tick[96];static unsigned queued,next_message;
static int closed;
static DWORD tick;
static shz_auth_request transmitted;static uint32_t transmitted_op;
static NTSTATUS launch_status,query_status;
static shz_auth_reply launch_reply,query_reply;
static int zero(const void *p,size_t n){const unsigned char *b=p;while(n--)if(*b++)return 0;return 1;}
#define C(name,v) do{++checks;if(!(v)){++failures;fprintf(stderr,"FAIL %s line%u\n",name,(unsigned)__LINE__);}}while(0)
void *SecureZeroMemory(void *p,size_t n){
 volatile unsigned char *b=p;size_t size=n;while(n--)*b++=0;
 if(size==sizeof(shz_auth_request))++request_wipes;
 return p;
}
NTSTATUS NtShzToken(ULONG_PTR op,ULONG_PTR input,ULONG_PTR bytes,ULONG_PTR output){
 ++ipc_calls;
 if(op==SHZ_AUTH_QUERY){
  ++query_calls;if(input||bytes!=sizeof(shz_auth_reply))return (NTSTATUS)0xc000000du;
  if(!query_status)memcpy((void *)output,&query_reply,sizeof query_reply);
  return query_status;
 }
 ++launch_calls;transmitted_op=(uint32_t)op;
 if(input&&bytes==sizeof transmitted)memcpy(&transmitted,(void *)input,sizeof transmitted);
 if(!launch_status)memcpy((void *)output,&launch_reply,sizeof launch_reply);
 return launch_status;
}
int MultiByteToWideChar(UINT cp,DWORD flags,const char *s,int n,WCHAR *w,int cap){
 int i;(void)flags;if(cp!=CP_UTF8||!s)return 0;if(n<0)n=(int)strlen(s)+1;if(n>cap)return 0;
 for(i=0;i<n;i++)w[i]=(unsigned char)s[i];
 return n;
}
int WideCharToMultiByte(UINT cp,DWORD flags,const WCHAR *w,int n,char *s,int cap,const char *def,BOOL *used){
 int i;(void)flags;(void)def;(void)used;if(cp!=CP_UTF8||n>cap)return 0;
 for(i=0;i<n;i++){if(w[i]>127)return 0;s[i]=(char)w[i];}return n;
}
BOOL InvalidateRect(HWND w,const RECT *r,BOOL e){(void)w;(void)r;(void)e;return TRUE;}
BOOL DestroyWindow(HWND w){(void)w;closed=1;return TRUE;}
HDC BeginPaint(HWND w,PAINTSTRUCT *p){(void)w;p->hdc=(HDC)1;return p->hdc;}
BOOL EndPaint(HWND w,const PAINTSTRUCT *p){(void)w;(void)p;return TRUE;}
int SetBkMode(HDC d,int m){(void)d;return m;}
BOOL Rectangle(HDC d,int a,int b,int c,int e){(void)d;(void)a;(void)b;(void)c;(void)e;return TRUE;}
BOOL GetClientRect(HWND w,RECT *r){(void)w;*r=(RECT){0,0,624,406};return TRUE;}
int DrawTextW(HDC dc,const WCHAR *t,int n,RECT *r,UINT f){(void)dc;(void)t;(void)n;(void)f;return r->bottom>r->top?16:0;}
LRESULT DefWindowProcW(HWND w,UINT m,WPARAM p,LPARAM l){(void)w;(void)m;(void)p;(void)l;return 0;}
HINSTANCE GetModuleHandleW(const WCHAR *s){(void)s;return (HINSTANCE)1;}
HCURSOR LoadCursorW(HINSTANCE h,const WCHAR *s){(void)h;(void)s;return (HCURSOR)1;}
unsigned short RegisterClassW(const WNDCLASSW *c){window_proc=c->lpfnWndProc;return 1;}
DWORD GetLastError(void){return 0;}
HWND CreateWindowExW(DWORD ex,const WCHAR *c,const WCHAR *t,DWORD s,int x,int y,int w,int h,HWND p,HMENU m,HINSTANCE i,void *v){
 (void)ex;(void)c;(void)t;(void)s;(void)x;(void)y;(void)w;(void)h;(void)p;(void)m;(void)i;(void)v;return (HWND)1;}
BOOL ShowWindow(HWND w,int n){(void)w;(void)n;return TRUE;}
HWND SetFocus(HWND w){return w;}
uintptr_t SetTimer(HWND w,uintptr_t id,UINT ms,TIMERPROC p){(void)w;(void)ms;(void)p;if(set_timer_fail)return 0;++timers_live;return id;}
BOOL KillTimer(HWND w,uintptr_t id){(void)w;(void)id;if(timers_live)--timers_live;return TRUE;}
DWORD GetTickCount(void){return tick;}
int GetMessageW(MSG *m,HWND w,UINT lo,UINT hi){
 (void)w;(void)lo;(void)hi;if(closed||next_message==queued)return 0;
 tick=message_tick[next_message];*m=messages[next_message++];return 1;
}
BOOL TranslateMessage(const MSG *m){(void)m;return TRUE;}
LRESULT DispatchMessageW(const MSG *m){return window_proc(m->hwnd,m->message,m->wParam,m->lParam);}
static void queue_at(DWORD t,UINT m,WPARAM w,LPARAM l){message_tick[queued]=t;messages[queued++]=(MSG){(HWND)1,m,w,l};}
static void password_at(DWORD t){const char *p="correct horse";while(*p)queue_at(t,WM_CHAR,(unsigned char)*p++,0);}
static void reset(DWORD start){
 ipc_calls=launch_calls=query_calls=request_wipes=queued=next_message=timers_live=set_timer_fail=0;closed=0;tick=start;
 memset(&transmitted,0,sizeof transmitted);transmitted_op=0;launch_status=query_status=0;
 memset(&launch_reply,0,sizeof launch_reply);memset(&query_reply,0,sizeof query_reply);
 /* Kernel-shaped replies (sysk32_auth.c): caller is the anonymous medium subject. */
 query_reply.version=1;query_reply.subject.integrity=0x2000;query_reply.subject.auth_id=0x4e7;
 launch_reply.version=1;launch_reply.child_pid=42;launch_reply.subject.uid=1;launch_reply.subject.session=7;
 launch_reply.subject.integrity=0x3000;launch_reply.subject.roles=SHZ_ROLE_ADMIN;launch_reply.subject.auth_id=((uint64_t)1<<32)|7;
}
static void submit(DWORD at){queue_at(at,WM_PAINT,0,0);password_at(at);queue_at(at,WM_CHAR,13,0);}
static char *args[]={"elevate","admin","C:\\SHZ\\TOOL.EXE","TOOL.EXE /apply",0};
static void no_ipc(const char *name,int r,int expected){
 C(name,r==expected);C("no kernel request",ipc_calls==0);C("secret erased",zero(&secret,sizeof secret));
 C("labels erased",zero(account_label,sizeof account_label)&&zero(command_label,sizeof command_label));
 C("request wiped",request_wipes>=1);C("timer released",timers_live==0);
}
int main(void){
 int r;
 /* success: one exact launch request, then a self query proving caller unchanged */
 reset(1000);submit(1000);r=actual_elevate_main(4,args);
 C("success exit",r==SHZ_ELEVATE_EXIT_OK);C("one launch + one self query",launch_calls==1&&query_calls==1);
 C("elevate op",transmitted_op==SHZ_AUTH_ELEVATE_LAUNCH);
 C("exact executable",!strcmp(transmitted.image,args[2])&&!strcmp(transmitted.command,args[3]));
 C("exact entry",transmitted.password_bytes==13&&!memcmp(transmitted.password,"correct horse",13));
 C("request wiped after IPC",request_wipes>=1);C("timer released",timers_live==0);C("secret erased",zero(&secret,sizeof secret));
 /* failed: kernel refusal is not retried and not turned into success */
 reset(1000);submit(1000);launch_status=(NTSTATUS)0xc0000022u;r=actual_elevate_main(4,args);
 C("refused exit",r==SHZ_ELEVATE_EXIT_REFUSED);C("single attempt, no query",launch_calls==1&&query_calls==0);
 /* canceled: Esc, Cancel button, window close */
 reset(1000);queue_at(1000,WM_PAINT,0,0);password_at(1000);queue_at(1000,WM_CHAR,27,0);no_ipc("esc cancel",actual_elevate_main(4,args),SHZ_ELEVATE_EXIT_CANCELED);
 reset(1000);queue_at(1000,WM_PAINT,0,0);password_at(1000);queue_at(1000,WM_LBUTTONUP,0,(LPARAM)((380u<<16)|550u));no_ipc("button cancel",actual_elevate_main(4,args),SHZ_ELEVATE_EXIT_CANCELED);
 reset(1000);queue_at(1000,WM_PAINT,0,0);password_at(1000);queue_at(1000,WM_CLOSE,0,0);no_ipc("close cancel",actual_elevate_main(4,args),SHZ_ELEVATE_EXIT_CANCELED);
 /* expired at acceptance (timer delayed) and by timer tick */
 reset(1000);queue_at(1000,WM_PAINT,0,0);password_at(1000);queue_at(1000+SHZ_ELEVATE_CONSENT_MS,WM_CHAR,13,0);
 no_ipc("accept after deadline",actual_elevate_main(4,args),SHZ_ELEVATE_EXIT_EXPIRED);
 reset(1000);queue_at(1000,WM_PAINT,0,0);password_at(1000);queue_at(1000+SHZ_ELEVATE_CONSENT_MS+5,WM_TIMER,1,0);queue_at(1000+SHZ_ELEVATE_CONSENT_MS+6,WM_CHAR,13,0);
 no_ipc("timer expiry",actual_elevate_main(4,args),SHZ_ELEVATE_EXIT_EXPIRED);
 reset(1000);queue_at(1000,WM_PAINT,0,0);password_at(1000);queue_at(2000,WM_TIMER,1,0);queue_at(1000+SHZ_ELEVATE_CONSENT_MS-1,WM_CHAR,13,0);
 C("last valid millisecond accepted",actual_elevate_main(4,args)==0&&launch_calls==1);
 reset(0xffffff00u);submit(0xffffff00u+1000u);
 C("tick wraparound not expired",actual_elevate_main(4,args)==0&&launch_calls==1);
 reset(0xffffff00u);queue_at(0xffffff00u,WM_PAINT,0,0);password_at(0xffffff00u);queue_at(0xffffff00u+SHZ_ELEVATE_CONSENT_MS,WM_CHAR,13,0);
 no_ipc("wrapped deadline expires",actual_elevate_main(4,args),SHZ_ELEVATE_EXIT_EXPIRED);
 /* no expiry timer => refuse rather than open an unbounded consent */
 reset(1000);set_timer_fail=1;submit(1000);no_ipc("timer unavailable",actual_elevate_main(4,args),SHZ_ELEVATE_EXIT_UNDISPLAYABLE);
 /* inconsistent success replies are reported, never as started */
 reset(1000);submit(1000);launch_reply.subject.integrity=0x2000;C("elevate reply without high integrity",actual_elevate_main(4,args)==SHZ_ELEVATE_EXIT_INCONSISTENT);
 reset(1000);submit(1000);query_reply.subject=launch_reply.subject;C("caller acquired child authority",actual_elevate_main(4,args)==SHZ_ELEVATE_EXIT_INCONSISTENT);
 reset(1000);submit(1000);query_status=(NTSTATUS)0xc0000022u;C("self query refused",actual_elevate_main(4,args)==SHZ_ELEVATE_EXIT_INCONSISTENT);
 reset(1000);submit(1000);launch_reply.child_pid=0;C("no child pid",actual_elevate_main(4,args)==SHZ_ELEVATE_EXIT_INCONSISTENT);
 reset(1000);submit(1000);launch_reply.subject.roles=0;C("non-admin elevated reply",actual_elevate_main(4,args)==SHZ_ELEVATE_EXIT_INCONSISTENT);
 /* login and sandbox successes */
 {char *v[]={"elevate","--login","member","C:\\SHZ\\TOOL.EXE",0};
  reset(1000);submit(1000);launch_reply.subject.integrity=0x2000;launch_reply.subject.roles=0;
  C("login success",actual_elevate_main(4,v)==0&&transmitted_op==SHZ_AUTH_LOGIN_LAUNCH&&!strcmp(transmitted.command,v[3]));}
 {char *v[]={"elevate","--sandbox","C:\\SHZ\\TOOL.EXE",0};
  reset(1000);query_reply.subject.uid=5;launch_reply.subject=query_reply.subject;launch_reply.subject.integrity=0x1000;
  launch_reply.subject.flags=SHZ_SUBJECT_SANDBOX;launch_reply.subject.roles=0;
  C("sandbox success without prompt",actual_elevate_main(3,v)==0&&launch_calls==1&&transmitted.password_bytes==0&&!transmitted.user[0]);
  reset(1000);query_reply.subject.uid=5;launch_reply.subject=query_reply.subject;launch_reply.subject.flags=SHZ_SUBJECT_SANDBOX;
  C("sandbox reply at caller integrity rejected",actual_elevate_main(3,v)==SHZ_ELEVATE_EXIT_INCONSISTENT);}
 /* pure policy */
 C("expiry boundary",!shz_consent_expired(10,10+SHZ_ELEVATE_CONSENT_MS-1,SHZ_ELEVATE_CONSENT_MS)&&shz_consent_expired(10,10+SHZ_ELEVATE_CONSENT_MS,SHZ_ELEVATE_CONSENT_MS));
 C("refusal text never success",strstr(shz_refusal_message(0xc0000022u),"denied")!=0);
 /* boot enrollment caller policy (autorun.c handoff) */
 C("enroll ok",shz_enroll_next(SHZ_ELEVATE_EXIT_OK,0,1)==1);
 C("enroll fault stops even with exit 0",shz_enroll_next(SHZ_ELEVATE_EXIT_OK,1,1)==-1);
 C("enroll cancel re-offered",shz_enroll_next(SHZ_ELEVATE_EXIT_CANCELED,0,1)==0);
 C("enroll expiry re-offered",shz_enroll_next(SHZ_ELEVATE_EXIT_EXPIRED,0,2)==0);
 C("enroll retries bounded",shz_enroll_next(SHZ_ELEVATE_EXIT_EXPIRED,0,SHZ_ELEVATE_ENROLL_ATTEMPTS)==-1&&
   shz_enroll_next(SHZ_ELEVATE_EXIT_CANCELED,0,SHZ_ELEVATE_ENROLL_ATTEMPTS)==-1);
 C("enroll kernel refusal stops",shz_enroll_next(SHZ_ELEVATE_EXIT_REFUSED,0,1)==-1);
 C("enroll undisplayable stops",shz_enroll_next(SHZ_ELEVATE_EXIT_UNDISPLAYABLE,0,1)==-1);
 C("enroll usage/unknown/negative stop",shz_enroll_next(SHZ_ELEVATE_EXIT_USAGE,0,1)==-1&&
   shz_enroll_next(99,0,1)==-1&&shz_enroll_next(-1,0,1)==-1&&shz_enroll_next(SHZ_ELEVATE_EXIT_INCONSISTENT,0,1)==-1);
 C("enroll names distinct",!strcmp(shz_elevate_exit_name(3),"cancelled")&&!strcmp(shz_elevate_exit_name(4),"expired")&&
   !strcmp(shz_elevate_exit_name(5),"undisplayable")&&!strcmp(shz_elevate_exit_name(1),"refused")&&
   !strcmp(shz_elevate_exit_name(42),"unknown"));
 printf("elevate flow: %u controls, %u failures; actual main/prompt/consent/secret bodies, host USER/GDI/clock/IPC adapters, no credential validation, kernel launch or native GUI\n",checks,failures);
 return failures?2:0;
}
