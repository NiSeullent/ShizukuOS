/* SPDX-License-Identifier: GPL-2.0-only
 * Actual Windows 98 ANSI system-palette selector. No DLL injection, font or
 * non-client metric changes, dynamic startup DLL or app-local probe execution.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "native_backend.h"

#define ID_CLASSIC 101u
#define ID_SHIZUKUOS 102u
#define REFRESH_STATUS (WM_APP+41u)
#define REFRESH_RETRY 74u
static shz_theme_native theme;
static HINSTANCE instance;
static HWND main_window,classic_button,shizuku_button,saved_label,current_label,status_label;
static unsigned busy,blocked,refresh_pending;

static void clear(void *memory,SIZE_T size)
{ unsigned char *p=memory;SIZE_T i;for(i=0;i<size;++i)p[i]=0; }
static void text_append(char *buffer,unsigned *used,const char *text)
{ unsigned i;for(i=0;text[i] && *used<255;++i)buffer[(*used)++]=text[i];buffer[*used]=0; }
static void number_append(char *buffer,unsigned *used,uint32_t value)
{
    char digits[10],text[11];unsigned i=0,n=0;
    do{digits[n++]=(char)('0'+value%10u);value/=10u;}while(value && n<10);
    while(n){text[i++]=digits[--n];}
    text[i]=0;text_append(buffer,used,text);
}
static void failure_text(const shz_theme_result *result,char buffer[256])
{
    unsigned used=0;buffer[0]=0;
    text_append(buffer,&used,result->status==SHZ_THEME_ROLLBACK_FAILED?
        "Theme change failed; rollback incomplete. ":
        result->rollback_attempted?"Theme change failed; previous state restored. ":
        result->colors_attempted || result->profile_attempted || result->run_attempted?
        "Theme operation failed after changes; verify actual settings. ":"Theme change refused before palette writes. ");
    text_append(buffer,&used,"Phase ");number_append(buffer,&used,(uint32_t)result->phase);
    text_append(buffer,&used,", error ");number_append(buffer,&used,result->error);
    if(result->rollback_failed){text_append(buffer,&used,", rollback failures ");number_append(buffer,&used,result->rollback_failed);
        text_append(buffer,&used,", rollback error ");number_append(buffer,&used,result->rollback_error);}
}
static void refresh_status(void)
{
    shz_theme_snapshot snapshot;shz_theme_result result;blocked=1;
    if(refresh_pending){KillTimer(main_window,REFRESH_RETRY);refresh_pending=0;}
    if(!shz_theme_native_snapshot(&theme,&snapshot,&result)){
        SetWindowTextA(saved_label,"Saved theme: invalid, unreadable or busy; selection disabled");
        SetWindowTextA(current_label,"Current session: existing system colors left untouched");
        SetWindowTextA(status_label,"Theme state could not be validated. No palette or startup values were changed.");
        if(result.phase==SHZ_THEME_PHASE_PROFILE_SNAPSHOT && result.error==ERROR_TIMEOUT){
            /* A queued color broadcast can arrive before the sender finishes
             * saving and releases its mutex. Retry reads without waiting. */
            refresh_pending=SetTimer(main_window,REFRESH_RETRY,250,NULL)!=0;
            SetWindowTextA(status_label,refresh_pending?"Another theme operation is active. Checking again shortly.":
                "Another theme operation is active; refresh unavailable. Reopen this window.");
        }
    }else{
        SetWindowTextA(saved_label,!snapshot.saved?"Saved theme: none (baseline captured; nothing applied yet)":
            snapshot.saved_style==SHZ_THEME_CLASSIC?"Saved theme: Classic":"Saved theme: ShizukuOS");
        SetWindowTextA(current_label,snapshot.current==SHZ_THEME_CURRENT_CLASSIC?"Current session: Classic baseline":
            snapshot.current==SHZ_THEME_CURRENT_SHIZUKUOS?"Current session: ShizukuOS":"Current session: custom system colors");
        blocked=0;
    }
    EnableWindow(classic_button,!blocked && !busy);EnableWindow(shizuku_button,!blocked && !busy);
}
static void choose_theme(uint32_t style)
{
    shz_theme_result result;char message[256];int success;
    if(busy || blocked)return;
    busy=1;EnableWindow(classic_button,FALSE);EnableWindow(shizuku_button,FALSE);
    success=shz_theme_native_apply(&theme,style,&result);
    busy=0;refresh_status();
    if(success)SetWindowTextA(status_label,"Theme applied and saved for the next Windows startup.");
    else {failure_text(&result,message);SetWindowTextA(status_label,message);OutputDebugStringA(message);
        MessageBoxA(main_window,message,"ShizukuOS theme change failed",MB_OK|MB_ICONERROR);}
}
static HWND control(const char *kind,const char *text,DWORD style,int x,int y,int width,int height,unsigned id,HWND parent)
{ return CreateWindowExA(0,kind,text,WS_CHILD|WS_VISIBLE|style,x,y,width,height,parent,(HMENU)(ULONG_PTR)id,instance,NULL); }
static LRESULT CALLBACK window_proc(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
    switch(message){
    case WM_CREATE:
        classic_button=control("BUTTON","Classic",BS_PUSHBUTTON|WS_TABSTOP,18,18,160,32,ID_CLASSIC,window);
        shizuku_button=control("BUTTON","ShizukuOS",BS_PUSHBUTTON|WS_TABSTOP,194,18,160,32,ID_SHIZUKUOS,window);
        saved_label=control("STATIC","Saved theme: reading...",0,18,66,500,24,0,window);
        current_label=control("STATIC","Current session: reading...",0,18,98,500,24,0,window);
        status_label=control("STATIC","Select a theme to apply and save system colors.",0,18,134,500,64,0,window);
        if(!classic_button || !shizuku_button || !saved_label || !current_label || !status_label)return -1;
        return 0;
    case WM_COMMAND:
        if(HIWORD(wparam)==BN_CLICKED){if(LOWORD(wparam)==ID_CLASSIC)choose_theme(SHZ_THEME_CLASSIC);
            else if(LOWORD(wparam)==ID_SHIZUKUOS)choose_theme(SHZ_THEME_SHIZUKUOS);}
        return 0;
    case WM_SYSCOLORCHANGE:
        /* Never acquire our mutex in a synchronous broadcast from another
         * selector. Queue a refresh after SetSysColors finishes instead. */
        PostMessageA(window,REFRESH_STATUS,0,0);break;
    case REFRESH_STATUS:
        if(!busy){refresh_status();}
        return 0;
    case WM_TIMER:
        if(wparam==REFRESH_RETRY && refresh_pending && !busy)refresh_status();
        return 0;
    case WM_CLOSE:DestroyWindow(window);return 0;
    case WM_DESTROY:KillTimer(window,REFRESH_RETRY);PostQuitMessage(0);return 0;
    }
    return DefWindowProcA(window,message,wparam,lparam);
}
static DWORD run_selector(void)
{
    WNDCLASSA cls;MSG message;char failure[256];
    const char *command=GetCommandLineA();uint32_t error;DWORD code=1;size_t command_bytes=0;int mode,get;
    shz_theme_result result;
    while(command && command_bytes<1024 && command[command_bytes])++command_bytes;
    mode=shz_theme_command_mode(command,command_bytes);
    if(mode<0){OutputDebugStringA("ShizukuOS theme selector: only no arguments or exact /restore are accepted.");return 1;}
    if(!shz_theme_native_open(&theme,&error)){
        OutputDebugStringA("ShizukuOS theme selector: native Win98 theme backend unavailable; no changes.");return 1;}
    if(mode==1){
        if(shz_theme_native_restore(&theme,&result))code=0;
        else {failure_text(&result,failure);OutputDebugStringA(failure);code=result.status==SHZ_THEME_ROLLBACK_FAILED?2:1;}
        if(!shz_theme_native_close(&theme))code=1;
        return code; /* /restore never opens a window. */
    }
    instance=GetModuleHandleA(NULL);clear(&cls,sizeof(cls));
    cls.lpfnWndProc=window_proc;cls.hInstance=instance;cls.hCursor=LoadCursorA(NULL,IDC_ARROW);
    cls.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);cls.lpszClassName="ShizukuOSThemeSelector";
    if(!RegisterClassA(&cls)){error=GetLastError();shz_theme_native_close(&theme);return error?error:1;}
    main_window=CreateWindowExA(WS_EX_CONTROLPARENT,cls.lpszClassName,"ShizukuOS Themes",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        CW_USEDEFAULT,CW_USEDEFAULT,550,244,NULL,NULL,instance,NULL);
    if(!main_window){shz_theme_native_close(&theme);return 1;}
    refresh_status();ShowWindow(main_window,SW_SHOWNORMAL);UpdateWindow(main_window);
    while((get=GetMessageA(&message,NULL,0,0))>0){if(!IsDialogMessageA(main_window,&message)){TranslateMessage(&message);DispatchMessageA(&message);}}
    return !shz_theme_native_close(&theme) || get<0?1:0;
}
void mainCRTStartup(void){ExitProcess(run_selector());}
