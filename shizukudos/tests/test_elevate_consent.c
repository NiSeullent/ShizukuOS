/* SPDX-License-Identifier: GPL-2.0-only
 * Literal main/prompt/secret/consent bodies; USER/GDI/UTF conversion and IPC
 * boundaries are modeled. IPC ALWAYS refuses: this never validates a password.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "host/elevate_consent/windows.h"
#include "../win64/apps/elevate/consent.h"
#ifndef SHZ_ELEVATE_MAIN_SOURCE
#define SHZ_ELEVATE_MAIN_SOURCE "../win64/apps/elevate/main.c"
#endif
#ifndef SHZ_ELEVATE_PROMPT_SOURCE
#define SHZ_ELEVATE_PROMPT_SOURCE "../win64/apps/elevate/prompt.c"
#endif
#define main actual_elevate_main
#include SHZ_ELEVATE_MAIN_SOURCE
#undef main
#include SHZ_ELEVATE_PROMPT_SOURCE
static unsigned checks,failures,ipc_calls,request_wipes;
static WNDPROC window_proc;
static MSG messages[64];static unsigned queued,next_message;
static int closed,clip,draw_fail,convert_fail,create_fail,account_clip,plaintext_painted,small_client;
static UINT metadata_format;
static int mask_painted;
static char displayed[1024];
static char displayed_account[32];
static shz_auth_request transmitted;
static uint32_t transmitted_op;
static char *mutate_argv;
static int zero(const void *p,size_t n){const unsigned char *b=p;while(n--)if(*b++)return 0;return 1;}
#define C(name,v) do{++checks;if(!(v)){++failures;fprintf(stderr,"FAIL %s line%u\n",name,(unsigned)__LINE__);}}while(0)
void *SecureZeroMemory(void *p,size_t n){
 volatile unsigned char *b=p;size_t size=n;while(n--)*b++=0;
 if(size==sizeof(shz_auth_request)){++request_wipes;C("actual client request wipe",zero(p,size));}
 return p;
}
NTSTATUS NtShzToken(ULONG_PTR op,ULONG_PTR input,ULONG_PTR bytes,ULONG_PTR output){
 (void)output;++ipc_calls;transmitted_op=(uint32_t)op;
 if(input&&bytes==sizeof transmitted)memcpy(&transmitted,(void *)input,sizeof transmitted);
 return (NTSTATUS)0xc0000022u; /* Real backend is not substituted with success. */
}
int MultiByteToWideChar(UINT cp,DWORD flags,const char *s,int n,WCHAR *w,int cap){
 int i;(void)flags;if(cp!=CP_UTF8||!s||convert_fail)return 0;
 if(n<0)n=(int)strlen(s)+1;
 if(n>cap)return 0;
 for(i=0;i<n;i++)w[i]=(unsigned char)s[i];
 return n;
}
int WideCharToMultiByte(UINT cp,DWORD flags,const WCHAR *w,int n,char *s,int cap,const char *def,BOOL *used){
 int i;(void)flags;(void)def;(void)used;if(cp!=CP_UTF8||n>cap)return 0;
 for(i=0;i<n;i++){if(w[i]>127)return 0;s[i]=(char)w[i];}return n;
}
BOOL InvalidateRect(HWND w,const RECT *r,BOOL erase){(void)w;(void)r;(void)erase;return TRUE;}
BOOL DestroyWindow(HWND w){(void)w;closed=1;return TRUE;}
HDC BeginPaint(HWND w,PAINTSTRUCT *p){(void)w;p->hdc=(HDC)1;return p->hdc;}
BOOL EndPaint(HWND w,const PAINTSTRUCT *p){(void)w;(void)p;return TRUE;}
int SetBkMode(HDC d,int m){(void)d;return m;}
BOOL Rectangle(HDC d,int a,int b,int c,int e){(void)d;(void)a;(void)b;(void)c;(void)e;return TRUE;}
BOOL GetClientRect(HWND w,RECT *r){(void)w;*r=(RECT){0,0,small_client?400:624,406};return TRUE;}
static int wide_contains(const WCHAR *text,unsigned n,const char *needle){
 size_t length=strlen(needle);unsigned i,j;
 for(i=0;i+length<=n;i++){for(j=0;j<length&&text[i+j]==(unsigned char)needle[j];j++){}if(j==length)return 1;}
 return 0;
}
int DrawTextW(HDC dc,const WCHAR *text,int length,RECT *r,UINT format){
 unsigned n=0,col=0,lines=1,max=0,width=(unsigned)(r->right-r->left)/8;
 (void)dc;if(draw_fail)return 0;
 if(!width)return 0;
 while((length<0?text[n]!=0:n<(unsigned)length)){
  if(text[n]=='\n'&&!(format&DT_SINGLELINE)){if(col>max)max=col;col=0;++lines;}
  else if(++col>width&&(format&DT_WORDBREAK)){if(col-1>max)max=col-1;col=1;++lines;}
  ++n;
 }
 if(col>max)max=col;
 if(wide_contains(text,n,"correct horse"))plaintext_painted=1;
 if(n==13){unsigned i;for(i=0;i<n&&text[i]=='*';i++){}if(i==n)mask_painted=1;}
 if(text==account_label){
  if(account_clip)max=100;
  if(!(format&DT_CALCRECT)){
   unsigned i;for(i=0;i<n&&i<sizeof displayed_account-1;i++)displayed_account[i]=(char)text[i];
   displayed_account[i]=0;
  }
 }
 if(text==command_label){
  if(!(format&DT_CALCRECT)){
   unsigned j=0;metadata_format=format;
   for(unsigned i=0;i<n&&j<sizeof displayed-1;i++){
    if(text[i]=='&'&&!(format&DT_NOPREFIX))continue;
    displayed[j++]=(char)text[i];
   }
   displayed[j]=0;
  }
  if(clip)lines=40;
 }
 if(format&DT_CALCRECT){r->right=r->left+(int)max*8;r->bottom=r->top+(int)lines*16;}
 return (int)lines*16;
}
LRESULT DefWindowProcW(HWND w,UINT m,WPARAM p,LPARAM l){(void)w;(void)m;(void)p;(void)l;return 0;}
HINSTANCE GetModuleHandleW(const WCHAR *s){(void)s;return (HINSTANCE)1;}
HCURSOR LoadCursorW(HINSTANCE h,const WCHAR *s){(void)h;(void)s;return (HCURSOR)1;}
unsigned short RegisterClassW(const WNDCLASSW *c){window_proc=c->lpfnWndProc;return 1;}
DWORD GetLastError(void){return 0;}
HWND CreateWindowExW(DWORD ex,const WCHAR *c,const WCHAR *title,DWORD style,int x,int y,int w,int h,HWND parent,HMENU menu,HINSTANCE inst,void *p){
 (void)ex;(void)c;(void)style;(void)x;(void)y;(void)w;(void)h;(void)parent;(void)menu;(void)inst;(void)p;
 {unsigned n=0;while(title[n])++n;if(wide_contains(title,n,"correct horse"))plaintext_painted=1;}
 return create_fail?0:(HWND)1;
}
BOOL ShowWindow(HWND w,int n){(void)w;(void)n;return TRUE;}
/* Consent expiry clock: constant here; expiry paths are covered by
 * shizukudos/win64/apps/elevate/host/test_elevate_flow.c. */
uintptr_t SetTimer(HWND w,uintptr_t id,UINT ms,TIMERPROC p){(void)w;(void)ms;(void)p;return id;}
BOOL KillTimer(HWND w,uintptr_t id){(void)w;(void)id;return TRUE;}
DWORD GetTickCount(void){return 1000;}
HWND SetFocus(HWND w){return w;}
int GetMessageW(MSG *m,HWND w,UINT low,UINT high){
 (void)w;(void)low;(void)high;
 if(mutate_argv){strcpy(mutate_argv,"SPOOF.EXE --mutated-after-entry");mutate_argv=0;}
 if(closed||next_message==queued)return 0;
 *m=messages[next_message++];return 1;
}
BOOL TranslateMessage(const MSG *m){(void)m;return TRUE;}
LRESULT DispatchMessageW(const MSG *m){return window_proc(m->hwnd,m->message,m->wParam,m->lParam);}
static void queue(UINT m,WPARAM w,LPARAM l){messages[queued++]=(MSG){(HWND)1,m,w,l};}
static void password(void){const char *p="correct horse";while(*p)queue(WM_CHAR,(unsigned char)*p++,0);}
static void reset(void){
 ipc_calls=request_wipes=queued=next_message=0;closed=clip=draw_fail=convert_fail=create_fail=0;
 account_clip=plaintext_painted=small_client=mask_painted=0;
 displayed[0]=displayed_account[0]=0;metadata_format=0;mutate_argv=0;memset(&transmitted,0,sizeof transmitted);
}
static void entry(int before_paint,int cancel){
 if(!before_paint)queue(WM_PAINT,0,0);
 password();if(!before_paint)queue(WM_PAINT,0,0);queue(WM_CHAR,cancel?27:13,0);
 if(before_paint){queue(WM_PAINT,0,0);queue(WM_CHAR,27,0);}
}
static void expect_no_launch(char **argv,int argc){
 int r=actual_elevate_main(argc,argv);C("request refused/cancelled",r!=0);C("no IPC without consent",ipc_calls==0);
 C("password entry erased",zero(&secret,sizeof secret));
}
int main(void){
 char *args[]={"elevate","admin","C:\\SHZ\\REAL.EXE","PRETEND.EXE --read & preserve",0};
 reset();entry(0,0);C("IPC refusal remains refusal",actual_elevate_main(4,args)==1);
 C("one request after entry",ipc_calls==1&&transmitted_op==SHZ_AUTH_ELEVATE_LAUNCH);
 C("selected executable displayed",strstr(displayed,"Selected executable: C:\\SHZ\\REAL.EXE")!=0);
 C("different argv0 never substituted as executable",!strcmp(transmitted.image,args[2]));
 C("complete literal argument string displayed",strstr(displayed,"Command line: PRETEND.EXE --read & preserve")!=0);
 C("operation displayed",strstr(displayed,"Operation: Run as administrator")!=0);
 C("selected account displayed",!strcmp(displayed_account,"admin")&&!strcmp(transmitted.user,"admin"));
 C("ampersands literal",metadata_format&DT_NOPREFIX);
 C("plaintext password never painted or used as title",!plaintext_painted);
 C("actual password paint uses mask",mask_painted);
 C("actual entry bytes transmitted",transmitted.password_bytes==13&&!memcmp(transmitted.password,"correct horse",13));
 C("caller clears request after refused IPC",request_wipes==1);
 C("static secret erased",zero(&secret,sizeof secret));
 C("retired metadata erased",zero(account_label,sizeof account_label)&&zero(command_label,sizeof command_label));
 reset();entry(0,1);expect_no_launch(args,4);
 reset();entry(1,0);expect_no_launch(args,4);
 reset();clip=1;entry(0,0);expect_no_launch(args,4);
 reset();draw_fail=1;entry(0,0);expect_no_launch(args,4);
 reset();convert_fail=1;entry(0,0);expect_no_launch(args,4);
 reset();create_fail=1;entry(0,0);expect_no_launch(args,4);
 reset();account_clip=1;entry(0,0);expect_no_launch(args,4);
 reset();small_client=1;entry(0,0);expect_no_launch(args,4);
 reset();queue(WM_PAINT,0,0);password();queue(WM_SIZE,0,0);queue(WM_CHAR,13,0);queue(WM_CHAR,27,0);expect_no_launch(args,4);
 reset();queue(WM_PAINT,0,0);queue(WM_CHAR,'a',0);queue(WM_CHAR,13,0);queue(WM_CHAR,27,0);expect_no_launch(args,4);
 reset();queue(WM_PAINT,0,0);password();queue(WM_LBUTTONUP,0,(LPARAM)((380u<<16)|550u));expect_no_launch(args,4);
 reset();queue(WM_PAINT,0,0);password();queue(WM_LBUTTONUP,0,(LPARAM)((380u<<16)|440u));
 C("authenticate button issues one refused request",actual_elevate_main(4,args)==1&&ipc_calls==1);
 C("mouse entry never paints plaintext",!plaintext_painted);
 {char *spoof[]={"elevate","admin",args[2],"REAL.EXE\nOperation: Sign in",0};reset();entry(0,0);expect_no_launch(spoof,4);}
 {const char *controls[]={"\xd8\x9c","\xe2\x80\x8e","\xe2\x80\x8f","\xe2\x80\xa8","\xe2\x80\xa9", "\xe2\x80\xaa","\xe2\x80\xab","\xe2\x80\xac","\xe2\x80\xad","\xe2\x80\xae",
                         "\xe2\x81\xa6","\xe2\x81\xa7","\xe2\x81\xa8","\xe2\x81\xa9","\xc2\x85"};
  for(unsigned i=0;i<sizeof controls/sizeof controls[0];i++){
   char command[64];char *v[]={"elevate","admin",args[2],command,0};
   snprintf(command,sizeof command,"REAL.EXE %s hidden-argument",controls[i]);reset();entry(0,0);expect_no_launch(v,4);
  }}
 {char *v[]={"elevate","admin",args[2],"REAL.EXE \xf0\x80\x80\x80",0};reset();entry(0,0);expect_no_launch(v,4);}
 {char changed[64]="PRETEND.EXE --frozen";char *v[]={"elevate","admin",args[2],changed,0};
  reset();mutate_argv=changed;entry(0,0);C("entry snapshot still refused",actual_elevate_main(4,v)==1);
  C("command snapshot immune to argv mutation",ipc_calls==1&&!strcmp(transmitted.command,"PRETEND.EXE --frozen"));
  C("paint uses immutable request snapshot",strstr(displayed,"Command line: PRETEND.EXE --frozen")!=0);}
 {char cmd[512];char *v[]={"elevate","admin",args[2],cmd,0};memset(cmd,'a',511);cmd[511]=0;
  reset();entry(0,0);C("ABI maximum command entry",actual_elevate_main(4,v)==1);
  C("ABI maximum command untruncated",ipc_calls==1&&strlen(transmitted.command)==511&&strstr(displayed,cmd)!=0);}
 {char cmd[513];char *v[]={"elevate","admin",args[2],cmd,0};memset(cmd,'a',512);cmd[512]=0;
  reset();entry(0,0);expect_no_launch(v,4);}
 {char *v[]={"elevate","--login","admin",args[2],args[3],0};reset();entry(0,0);actual_elevate_main(5,v);
  C("login operation distinct",ipc_calls==1&&transmitted_op==SHZ_AUTH_LOGIN_LAUNCH&&strstr(displayed,"Operation: Sign in and run")!=0);}
 {char *v[]={"elevate","--enroll","admin",0};reset();entry(0,0);actual_elevate_main(3,v);
  C("enrollment purpose distinct",ipc_calls==1&&transmitted_op==SHZ_AUTH_REGISTER&&strstr(displayed,"Enroll administrator")!=0);}
 {char *v[]={"elevate","--register","member",0};reset();entry(0,0);actual_elevate_main(3,v);
  C("ordinary registration purpose distinct",ipc_calls==1&&transmitted_op==SHZ_AUTH_REGISTER&&!transmitted.roles&&strstr(displayed,"Register account")!=0);}
 {shz_auth_request r={0};char text[32];strcpy(r.user,"admin");strcpy(r.image,"image.exe");strcpy(r.command,"image.exe");
  C("bounded builder never returns truncated approval",!shz_elevate_consent(SHZ_AUTH_ELEVATE_LAUNCH,&r,text,sizeof text)&&!text[0]);
  memset(r.command,'a',sizeof r.command);C("unterminated request refused",!shz_elevate_consent(SHZ_AUTH_ELEVATE_LAUNCH,&r,text,sizeof text));}
 {shz_auth_request r={0};char text[1024];const char *bad[]={"\xc0\xaf","\xed\xa0\x80","\xf4\x90\x80\x80","\xe2\x80","\xe2\x28\xa1"};
  strcpy(r.user,"admin");strcpy(r.image,"image.exe");
  for(unsigned i=0;i<sizeof bad/sizeof bad[0];i++){
   strcpy(r.command,bad[i]);C("actual builder rejects malformed UTF8",!shz_elevate_consent(SHZ_AUTH_ELEVATE_LAUNCH,&r,text,sizeof text)&&!text[0]);
  }
  strcpy(r.image,"C:\\" "\xed\x95\x9c\xea\xb8\x80" ".exe");strcpy(r.command,"app " "\xf0\x9f\x98\x80");
  C("normal Korean path and Unicode argument remain literal",shz_elevate_consent(SHZ_AUTH_ELEVATE_LAUNCH,&r,text,sizeof text)&&strstr(text,r.image)&&strstr(text,r.command));
 }
 printf("elevation consent: %u controls, %u failures; actual client/UI bodies, modeled USER/GDI/UTF/IPC boundaries, no credential validation or native Windows98\n",checks,failures);
 return failures?2:0;
}
