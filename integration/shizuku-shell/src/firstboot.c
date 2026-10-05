/* SPDX-License-Identifier: GPL-2.0-only
 * Native Shell cohosted setup/logon UI. Account authority, profile creation and
 * protected setup progress remain in the EXISTING kernel authentication layer.
 * Password fields reuse elevate/secret.c. No password is passed in argv/logs.
 * Direct Unicode WM_CHAR is supported; a physical Korean IME is not provided.
 */
#define UNICODE 1
#define _UNICODE 1
#include "nt.h"
#include "shzcrt.h"
#include "shell.h"
#include "layout.h"
#include "firstboot.h"
#include "secret.h"
#include "shz_auth.h"
#include "shz_firstboot.h"
#include <string.h>
#define FB_CLASS L"ShizukuFirstBoot"
#define FB_TIMER 74
#define FB_QUERY 1
#define FB_LOGIN 2
#define FB_COMPLETE 3
#define FB_IMAGE "C:\\SHZ\\SYS64\\SHZDESK.EXE"
#define FB_COMMAND "SHZDESK.EXE --firstboot-complete"
typedef struct {
    int operation,enroll,was_done;
    NTSTATUS status,query_status;
    DWORD error;
    shz_auth_request request;
    shz_auth_reply auth;
    shz_firstboot_reply setup;
} FB_JOB;
typedef struct {
    HWND window;
    HANDLE thread;
    FB_JOB *job;
    int complete,ready,initialized,focus,result,language,request_enter;
    NTSTATUS status;
    DWORD error;
    WCHAR user[32],message[240];
    shz_secret password,confirm;
    shz_firstboot_reply setup;
} FB_VIEW;
static FB_VIEW *view;
static const WCHAR *Words(FB_VIEW *v,const WCHAR *ko,const WCHAR *en) {return v->language==SHZ_FIRSTBOOT_LANG_EN?en:ko;}
static int AuthValid(const shz_auth_reply *a) {
    return a->version==SHZ_AUTH_VERSION&&!a->reserved&&!(a->flags&~SHZ_AUTH_VOLATILE)&&a->accounts<=16;
}
static int NameValid(const char *s) {
    unsigned n=0;for(;n<32&&s[n];n++)if(!((s[n]>='a'&&s[n]<='z')||(s[n]>='0'&&s[n]<='9')||s[n]=='_'||s[n]=='-'))return 0;
    return n>0&&n<32;
}
static int HomeValid(const char *s,uint32_t uid) {
    unsigned n=0;uint64_t id=0;
    if(s[0]<'D'||s[0]>'Z'||memcmp(s+1,":\\Users\\",8))return 0;
    for(n=9;n<48&&s[n];n++){if(s[n]<'0'||s[n]>'9')return 0;id=id*10+(unsigned)(s[n]-'0');if(id>0xffffffffu)return 0;}
    return n>9&&n<48&&id==uid;
}
static int SetupValid(const shz_firstboot_reply *s) {
    if(s->version!=SHZ_FIRSTBOOT_VERSION||s->size!=sizeof *s||s->phase>SHZ_FIRSTBOOT_EXISTING||
       s->store_flags!=SHZ_FIRSTBOOT_STORE_PERSISTENT||s->accounts>16||
       (s->language!=SHZ_FIRSTBOOT_LANG_KO&&s->language!=SHZ_FIRSTBOOT_LANG_EN)||s->keyboard!=SHZ_FIRSTBOOT_KEYBOARD_US)return 0;
    if(s->phase==SHZ_FIRSTBOOT_NEW)return !s->accounts&&!s->uid&&!s->user[0]&&!s->home[0];
    return s->accounts&&s->uid>=1000&&NameValid(s->user)&&HomeValid(s->home,s->uid);
}
static int StandardSubject(const shz_auth_reply *a) {
    const shz_subject *s=&a->subject;
    return AuthValid(a)&&!a->flags&&s->uid>=1000&&s->uid!=0xffffffffu&&s->session&&s->auth_id==(((uint64_t)s->uid<<32)|s->session)&&
           s->integrity==0x2000&&!s->roles&&!s->flags&&!s->reserved;
}
static NTSTATUS Query(FB_JOB *job) {
    NTSTATUS st;
    memset(&job->auth,0,sizeof job->auth);memset(&job->setup,0,sizeof job->setup);
    st=NtShzToken(SHZ_AUTH_QUERY,0,sizeof job->auth,(ULONG_PTR)&job->auth);
    if(st)return st;
    if(!AuthValid(&job->auth))return STATUS_DATA_ERROR;
    st=NtShzToken(SHZ_FIRSTBOOT_QUERY,0,sizeof job->setup,(ULONG_PTR)&job->setup);
    if(st)return st;
    if(!SetupValid(&job->setup)||job->auth.accounts!=job->setup.accounts||(job->auth.flags&SHZ_AUTH_VOLATILE))return STATUS_DATA_ERROR;
    return STATUS_SUCCESS;
}
/* Strict UTF-16 -> UTF-8 for credentials, independent of providers that ignore
 * conversion flags. Limit is the authority's 128 BYTES, not 128 characters. */
static int PasswordBytes(const shz_secret *secret,uint8_t out[128]) {
    unsigned i=0,n=0;
    while(i<secret->length) {
        uint32_t c=secret->chars[i++];unsigned need;
        if(c>=0xd800&&c<=0xdbff) {
            uint32_t d;if(i==secret->length)return 0;d=secret->chars[i++];
            if(d<0xdc00||d>0xdfff)return 0;
            c=0x10000+((c-0xd800)<<10)+(d-0xdc00);
        } else if(c>=0xdc00&&c<=0xdfff)return 0;
        if(c<32||c==127)return 0;
        need=c<0x80?1:c<0x800?2:c<0x10000?3:4;
        if(need>128-n)return 0;
        if(need==1)out[n++]=(uint8_t)c;
        else {
            if(need==2)out[n++]=(uint8_t)(0xc0|(c>>6));
            else if(need==3){out[n++]=(uint8_t)(0xe0|(c>>12));out[n++]=(uint8_t)(0x80|((c>>6)&63));}
            else {out[n++]=(uint8_t)(0xf0|(c>>18));out[n++]=(uint8_t)(0x80|((c>>12)&63));out[n++]=(uint8_t)(0x80|((c>>6)&63));}
            out[n++]=(uint8_t)(0x80|(c&63));
        }
    }
    return n>=8?(int)n:0;
}
static DWORD WINAPI Worker(void *ptr) {
    FB_JOB *job=ptr;shz_auth_reply result;NTSTATUS st;shz_firstboot_request complete;
    memset(&result,0,sizeof result);memset(&complete,0,sizeof complete);
    st=Query(job);job->query_status=st;
    if(st)goto done;
    if(job->operation==FB_QUERY)goto done;
    if(job->operation==FB_LOGIN) {
        if(job->enroll) {
            /* Requery is essential: committed enrollment must never be retried
             * after interrupted progress, a copyout fault, or a restart. */
            if(job->setup.accounts||job->setup.phase!=SHZ_FIRSTBOOT_NEW){st=STATUS_ACCESS_DENIED;goto done;}
            job->request.roles=SHZ_ROLE_ADMIN;
            st=NtShzToken(SHZ_AUTH_REGISTER,(ULONG_PTR)&job->request,sizeof job->request,(ULONG_PTR)&result);
            job->query_status=Query(job);
            if(st)goto done;
            if(job->query_status){st=job->query_status;goto done;}
            if(!AuthValid(&result)||job->setup.accounts!=1){st=STATUS_DATA_ERROR;goto done;}
        }
        job->request.roles=0;
        memcpy(job->request.image,FB_IMAGE,sizeof FB_IMAGE);memcpy(job->request.command,FB_COMMAND,sizeof FB_COMMAND);
        memset(&result,0,sizeof result);
        st=NtShzToken(SHZ_AUTH_LOGIN_LAUNCH,(ULONG_PTR)&job->request,sizeof job->request,(ULONG_PTR)&result);
        if(!st&&(!StandardSubject(&result)||!result.child_pid))st=STATUS_DATA_ERROR;
        if(!st)job->auth=result;
    } else if(job->operation==FB_COMPLETE) {
        WCHAR environment[48];unsigned i;DWORD n;
        if(!StandardSubject(&job->auth)||job->setup.uid!=job->auth.subject.uid){st=STATUS_ACCESS_DENIED;goto done;}
        n=GetEnvironmentVariableW(L"USERPROFILE",environment,48);
        if(!n||n>=48){st=STATUS_ACCESS_DENIED;goto done;}
        for(i=0;i<=n;i++)if(environment[i]!=(unsigned char)job->setup.home[i])break;
        if(i<=n){st=STATUS_ACCESS_DENIED;goto done;}
        job->was_done=job->setup.phase==SHZ_FIRSTBOOT_DONE;
        complete.version=SHZ_FIRSTBOOT_VERSION;complete.size=sizeof complete;
        complete.uid=job->auth.subject.uid;complete.language=job->setup.language;complete.keyboard=job->setup.keyboard;
        st=NtShzToken(SHZ_FIRSTBOOT_COMPLETE,(ULONG_PTR)&complete,sizeof complete,(ULONG_PTR)&job->setup);
        if(!st&&(!SetupValid(&job->setup)||job->setup.phase!=SHZ_FIRSTBOOT_DONE||job->setup.uid!=complete.uid))st=STATUS_DATA_ERROR;
    } else st=STATUS_INVALID_PARAMETER;
done:
    job->status=st;
    SecureZeroMemory(&job->request,sizeof job->request);SecureZeroMemory(&result,sizeof result);SecureZeroMemory(&complete,sizeof complete);
    return 0;
}
static void Notice(FB_VIEW *v,const WCHAR *ko,const WCHAR *en) {
    ShzWcsCopy(v->message,240,Words(v,ko,en));InvalidateRect(v->window,NULL,FALSE);
}
static void Layout(FB_VIEW *v,RECT fields[3],RECT *button,RECT *close) {
    RECT client;int width,y,i;
    GetClientRect(v->window,&client);width=client.right; y=client.bottom<520?155:185;
    for(i=0;i<3;i++){fields[i].left=48;fields[i].right=width-48;fields[i].top=y+i*(client.bottom<520?62:70);fields[i].bottom=fields[i].top+(client.bottom<520?32:38);}
    button->left=width-240;button->right=width-48;button->top=client.bottom-70;button->bottom=client.bottom-30;
    close->left=48;close->right=180;close->top=button->top;close->bottom=button->bottom;
}
static void Text(HDC dc,const WCHAR *text,RECT rc,UINT format,uint32_t color) {
    SetTextColor(dc,TC(color));ShzDrawText(dc,text,&rc,format);
}
static void Fill(HDC dc,const RECT *r,uint32_t color) {
    HBRUSH b=CreateSolidBrush(TC(color));if(b){FillRect(dc,r,b);DeleteObject(b);}
}
static void Paint(FB_VIEW *v,HDC dc) {
    RECT client,fields[3],button,close,r;WCHAR mask[129],diagnostic[100],code[32];int i,count;
    const SHZ_THEME *theme=TH();GetClientRect(v->window,&client);Layout(v,fields,&button,&close);
    Fill(dc,&client,theme->background_surface);
    r=client;r.bottom=client.bottom<520?90:110;ShzFillGradientV(dc,&r,TC(theme->titlebar_active_top),TC(theme->titlebar_active_bottom));
    r.left=48;r.top=18;r.bottom=52;Text(dc,L"ShizukuOS",r,DT_SINGLELINE|DT_VCENTER,theme->titlebar_text_active);
    r.top=client.bottom<520?50:58;r.bottom=client.bottom<520?80:90;Text(dc,Words(v,v->complete?L"준비 마무리":v->setup.accounts?L"로그인":L"시작하기",
                                        v->complete?L"Getting ready":v->setup.accounts?L"Sign in":L"Let's get started"),r,DT_SINGLELINE|DT_VCENTER,theme->titlebar_text_active);
    r.left=48;r.right=client.right-48;r.top=client.bottom<520?98:125;r.bottom=client.bottom<520?133:170;
    Text(dc,Words(v,v->complete?L"계정과 저장 위치를 확인하고 있습니다.":v->setup.accounts?L"기존 로컬 계정의 암호를 입력하세요.":L"이 컴퓨터에서 사용할 로컬 계정을 만드세요.",
                 v->complete?L"Checking your account and storage.":v->setup.accounts?L"Enter your existing local account password.":L"Create a local account for this computer."),r,DT_WORDBREAK,theme->background_surface_text);
    count=v->complete?0:v->setup.accounts?2:3;
    for(i=0;i<count;i++) {
        r=fields[i];r.top-=24;r.bottom=r.top+22;
        Text(dc,Words(v,i==0?L"계정 ID":i==1?L"암호":L"암호 확인",i==0?L"Account ID":i==1?L"Password":L"Confirm password"),r,DT_SINGLELINE,theme->background_surface_dim_text);
        Fill(dc,&fields[i],theme->background_input_bg);ShzFrame(dc,&fields[i],TC(v->focus==i&&!v->thread?theme->border_focus:theme->background_input_border),1);
        r=fields[i];r.left+=12;r.right-=12;
        if(!i)Text(dc,v->user,r,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS,theme->background_surface_text);
        else {shz_secret_mask(i==1?&v->password:&v->confirm,(uint16_t *)mask);Text(dc,mask,r,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS,theme->background_surface_text);SecureZeroMemory(mask,sizeof mask);}
    }
    if(v->complete) {
        r.left=48;r.right=client.right-48;r.top=185;r.bottom=245;
        Text(dc,v->ready?Words(v,L"준비되었습니다. 시작하면 데스크톱으로 이동합니다.",L"You're ready. Start to open your desktop."):
                       Words(v,L"프로필과 완료 상태를 저장하는 중…",L"Saving your profile and setup state…"),r,DT_WORDBREAK,theme->background_surface_text);
        r.top=260;r.bottom=310;
        if(v->ready) {WCHAR home[48];for(i=0;i<48;i++){home[i]=(unsigned char)v->setup.home[i];if(!home[i])break;}Text(dc,home,r,DT_WORDBREAK,theme->background_surface_dim_text);}
    }
    r.left=48;r.right=client.right-48;r.top=client.bottom-(client.bottom<520?135:155);r.bottom=r.top+40;
    Text(dc,Words(v,L"계정 ID: 영문·숫자·_·-  |  암호: UTF-8 8–128바이트\n물리 키보드: US · 한글 IME 미제공",
                   L"Account ID: a–z, 0–9, _ and -  |  Password: 8–128 UTF-8 bytes\nPhysical keyboard: US · Korean IME unavailable"),r,DT_WORDBREAK,theme->background_surface_dim_text);
    r.top=client.bottom-112;r.bottom=client.bottom-74;
    Text(dc,v->thread?Words(v,L"확인 중…",L"Checking…"):v->message,r,DT_WORDBREAK,v->status?theme->files_error_text:theme->background_surface_text);
    if(v->status||v->error) {
        /* Diagnostics contain only actual error codes, never entered secrets. */
        unsigned err=v->status?(unsigned)v->status:(unsigned)v->error;
        char digits[11];snprintf(digits,sizeof digits,"%08x",err);for(i=0;i<9;i++)code[i]=(unsigned char)digits[i];
        ShzWcsCopy(diagnostic,100,L"Error: ");ShzWcsCat(diagnostic,100,code);r.right=client.right-48;r.left=r.right-180;r.top=112;r.bottom=135;
        Text(dc,diagnostic,r,DT_SINGLELINE|DT_RIGHT,theme->files_error_text);
    }
    if(!v->thread&&(v->ready||v->initialized||v->status||v->error)) {
        Fill(dc,&button,theme->buttons_active_top);ShzFrame(dc,&button,TC(theme->border_focus),1);
        Text(dc,Words(v,v->ready?L"시작":v->complete||!v->initialized?L"다시 시도":v->setup.accounts?L"로그인":L"계정 만들기",v->ready?L"Start":v->complete||!v->initialized?L"Try again":v->setup.accounts?L"Sign in":L"Create account"),button,DT_SINGLELINE|DT_VCENTER|DT_CENTER,theme->buttons_text);
    }
    Text(dc,Words(v,L"닫기",L"Close"),close,DT_SINGLELINE|DT_VCENTER|DT_CENTER,theme->background_surface_dim_text);
}
static int StartJob(FB_VIEW *v,int operation) {
    FB_JOB *job;unsigned i,n;int bytes;
    if(v->thread)return 0;
    job=calloc(1,sizeof *job);if(!job){v->error=ERROR_NOT_ENOUGH_MEMORY;Notice(v,L"메모리가 부족합니다.",L"Not enough memory.");return 0;}
    job->operation=operation;
    if(operation==FB_LOGIN) {
        n=(unsigned)ShzWcsLen(v->user);
        if(!n||n>31)goto invalid;
        for(i=0;i<n;i++){WCHAR c=v->user[i];if(c>='A'&&c<='Z')c+=32;job->request.user[i]=(char)c;}
        if(!NameValid(job->request.user))goto invalid;
        job->request.version=SHZ_AUTH_VERSION;bytes=PasswordBytes(&v->password,job->request.password);if(!bytes)goto invalid;
        job->request.password_bytes=(uint32_t)bytes;job->enroll=!v->setup.accounts;
        if(job->enroll&&(v->password.length!=v->confirm.length||memcmp(v->password.chars,v->confirm.chars,v->password.length*sizeof(uint16_t))))goto mismatch;
    }
    v->status=0;v->error=0;v->message[0]=0;
    v->thread=CreateThread(NULL,0,Worker,job,0,NULL);
    if(!v->thread){v->error=GetLastError();SecureZeroMemory(job,sizeof *job);free(job);Notice(v,L"확인 작업을 시작할 수 없습니다.",L"Could not start the operation.");return 0;}
    v->job=job;shz_secret_reset(&v->password);shz_secret_reset(&v->confirm);InvalidateRect(v->window,NULL,FALSE);return 1;
mismatch:
    Notice(v,L"입력한 암호가 서로 다릅니다.",L"The passwords do not match.");goto reject;
invalid:
    Notice(v,L"계정 ID와 암호 길이를 확인하세요.",L"Check the account ID and password length.");
reject:
    SecureZeroMemory(job,sizeof *job);free(job);return 0;
}
static void Poll(FB_VIEW *v) {
    FB_JOB *job;DWORD waited;if(!v->thread)return;waited=WaitForSingleObject(v->thread,0);
    if(waited==WAIT_TIMEOUT)return;
    if(waited!=WAIT_OBJECT_0){v->error=GetLastError();return;}
    CloseHandle(v->thread);v->thread=NULL;job=v->job;v->job=NULL;
    v->status=job->status;
    if(!job->query_status&&SetupValid(&job->setup)) {
        v->setup=job->setup;v->language=(int)job->setup.language;v->initialized=1;
        if(job->operation==FB_QUERY||job->enroll)for(unsigned i=0;i<32;i++){v->user[i]=(unsigned char)job->setup.user[i];if(!v->user[i])break;}
    }
    printf("SHZ-FIRSTBOOT operation=%d status=%x phase=%u accounts=%u\n",job->operation,(unsigned)job->status,v->setup.phase,v->setup.accounts);
    if(!job->status&&job->operation==FB_LOGIN) {v->result=0;SecureZeroMemory(job,sizeof *job);free(job);DestroyWindow(v->window);return;}
    if(!job->status&&job->operation==FB_COMPLETE) {
        v->ready=1;
        if(job->was_done){v->result=0;SecureZeroMemory(job,sizeof *job);free(job);DestroyWindow(v->window);return;}
    }
    if(job->status)Notice(v,job->enroll&&v->setup.accounts?L"계정은 생성되었습니다. 기존 암호로 로그인하세요.":L"인증 또는 저장을 완료하지 못했습니다. 오류를 확인하세요.",
                         job->enroll&&v->setup.accounts?L"Your account was created. Sign in with its password.":L"Authentication or storage failed. Check the error.");
    SecureZeroMemory(job,sizeof *job);free(job);InvalidateRect(v->window,NULL,FALSE);
}
static LRESULT CALLBACK WindowProc(HWND hwnd,UINT message,WPARAM wparam,LPARAM lparam) {
    FB_VIEW *v=view;
    if(!v)return DefWindowProcW(hwnd,message,wparam,lparam);
    switch(message) {
    case WM_CREATE:v->window=hwnd;return SetTimer(hwnd,FB_TIMER,80,NULL)?0:-1;
    case WM_TIMER:if(wparam==FB_TIMER)Poll(v);return 0;
    case WM_ERASEBKGND:return 1;
    case WM_PAINT:{PAINTSTRUCT ps;HDC dc=BeginPaint(hwnd,&ps);if(dc)Paint(v,dc);EndPaint(hwnd,&ps);return 0;}
    case WM_SIZE:InvalidateRect(hwnd,NULL,FALSE);return 0;
    case WM_LBUTTONDOWN:{RECT fields[3],button,close;POINT p={(short)LOWORD(lparam),(short)HIWORD(lparam)};
        Layout(v,fields,&button,&close);SetFocus(hwnd);
        if(v->thread)return 0;
        if(PtInRect(&close,p)){SendMessageW(hwnd,WM_CLOSE,0,0);return 0;}
        if(PtInRect(&button,p)) {if(v->ready){v->result=0;DestroyWindow(hwnd);}else StartJob(v,v->complete?FB_COMPLETE:v->initialized?FB_LOGIN:FB_QUERY);return 0;}
        for(int i=0;i<(v->setup.accounts?2:3)&&!v->complete;i++)if(PtInRect(&fields[i],p)){v->focus=i;InvalidateRect(hwnd,NULL,FALSE);break;}
        return 0;}
    case WM_KEYDOWN:
        if(v->thread)return 0;
        if(wparam==VK_TAB&&!v->complete){v->focus=(v->focus+1)%(v->setup.accounts?2:3);InvalidateRect(hwnd,NULL,FALSE);return 0;}
        if(wparam==VK_RETURN){v->request_enter=1;if(v->ready){v->result=0;DestroyWindow(hwnd);}else StartJob(v,v->complete?FB_COMPLETE:v->initialized?FB_LOGIN:FB_QUERY);return 0;}
        if(wparam==VK_ESCAPE){SendMessageW(hwnd,WM_CLOSE,0,0);return 0;}
        break;
    case WM_CHAR:
        if(wparam==L'\r'||wparam==L'\n'){v->request_enter=0;return 0;}
        if(v->thread||v->complete||!v->initialized)return 0;
        if(v->focus==0) {
            SIZE_T n=ShzWcsLen(v->user);WCHAR c=(WCHAR)wparam;
            if(c==8){if(n)v->user[n-1]=0;}
            else if(n<31&&((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-')){v->user[n]=c;v->user[n+1]=0;}
        } else shz_secret_key(v->focus==1?&v->password:&v->confirm,(uint16_t)wparam);
        InvalidateRect(hwnd,NULL,FALSE);return 0;
    case WM_CLOSE:
        if(v->thread){Notice(v,L"작업이 끝난 뒤 닫을 수 있습니다.",L"Wait for the operation before closing.");return 0;}
        DestroyWindow(hwnd);return 0;
    case WM_DESTROY:KillTimer(hwnd,FB_TIMER);v->window=NULL;PostQuitMessage(v->result);return 0;
    default:break;
    }
    return DefWindowProcW(hwnd,message,wparam,lparam);
}
static int Run(int complete) {
    FB_VIEW local;WNDCLASSW klass;MSG msg;BOOL got;int width,height,x,y,result;
    memset(&local,0,sizeof local);memset(&klass,0,sizeof klass);
    local.complete=complete;local.result=1;local.language=SHZ_FIRSTBOOT_LANG_KO;view=&local;
    klass.style=CS_HREDRAW|CS_VREDRAW;klass.lpfnWndProc=WindowProc;klass.hInstance=g_shell.inst;klass.hCursor=LoadCursorW(NULL,IDC_ARROW);klass.lpszClassName=FB_CLASS;
    if(!RegisterClassW(&klass)&&GetLastError()!=ERROR_CLASS_ALREADY_EXISTS){view=NULL;return 1;}
    width=GetSystemMetrics(SM_CXSCREEN);height=GetSystemMetrics(SM_CYSCREEN);
    x=(width-760)/2;y=(height-570)/2;if(x<0)x=0;if(y<0)y=0;
    local.window=CreateWindowExW(0,FB_CLASS,L"ShizukuOS",WS_POPUP|WS_CAPTION|WS_SYSMENU,
                x,y,width<760?width:760,height<570?height:570,NULL,NULL,g_shell.inst,NULL);
    if(!local.window){view=NULL;return 1;}
    ShowWindow(local.window,SW_SHOW);SetForegroundWindow(local.window);SetFocus(local.window);UpdateWindow(local.window);
    StartJob(&local,complete?FB_COMPLETE:FB_QUERY);
    while((got=GetMessageW(&msg,NULL,0,0))>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
    if(got<0)local.result=1;
    /* No worker refers to the stack view. If the message provider itself failed,
     * reap the independently-owned secret job before font/window shutdown. */
    if(local.thread){WaitForSingleObject(local.thread,INFINITE);CloseHandle(local.thread);SecureZeroMemory(local.job,sizeof *local.job);free(local.job);}
    if(local.window)DestroyWindow(local.window);
    result=local.result;
    shz_secret_reset(&local.password);shz_secret_reset(&local.confirm);SecureZeroMemory(&local,sizeof local);view=NULL;
    return got<0?1:result;
}
int ShzFirstBootRun(void){return Run(0);}
BOOL ShzFirstBootComplete(void){return Run(1)==0;}
