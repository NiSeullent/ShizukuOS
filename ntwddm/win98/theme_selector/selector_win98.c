/* SPDX-License-Identifier: GPL-2.0-only
 * Actual Windows 98 ANSI system-palette selector. No DLL injection, font or
 * non-client metric changes, dynamic startup DLL or app-local probe execution.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "selector_core.h"

#define ID_CLASSIC 101u
#define ID_SHIZUKUOS 102u
#define REFRESH_STATUS (WM_APP+41u)
static const char profile_key[]="Software\\ShizukuOS\\Theme";
static const char run_key[]="Software\\Microsoft\\Windows\\CurrentVersion\\Run";
static const char profile_name[]="Profile";
static const char run_name[]="ShizukuOSTheme";
static const char mutex_name[]="ShizukuOS.Win98.ThemeSelector.v1";
static HANDLE selector_mutex;
static HINSTANCE instance;
static HWND main_window,classic_button,shizuku_button,saved_label,current_label,status_label;
static uint32_t initial_baseline[SHZ_THEME_COLORS];
static shz_theme_value startup_command;
static unsigned busy,blocked,baseline_captured;

static void clear(void *memory,SIZE_T size)
{ unsigned char *p=memory;SIZE_T i;for(i=0;i<size;++i)p[i]=0; }
static int same_colors(const uint32_t *a,const uint32_t *b)
{ unsigned i;for(i=0;i<SHZ_THEME_COLORS;++i)if(a[i]!=b[i])return 0;return 1; }
static int key_names(unsigned target,const char **key,const char **name,uint32_t *error)
{
    if(target>SHZ_THEME_RUN_VALUE){*error=ERROR_INVALID_PARAMETER;return 0;}
    *key=target==SHZ_THEME_PROFILE_VALUE?profile_key:run_key;
    *name=target==SHZ_THEME_PROFILE_VALUE?profile_name:run_name;return 1;
}
static int close_key(HKEY key,LONG result,uint32_t *error)
{
    LONG closed=RegCloseKey(key);
    if(result==ERROR_SUCCESS)result=closed;
    if(result!=ERROR_SUCCESS){*error=(uint32_t)result;return 0;}return 1;
}
static int read_registry(void *context,unsigned target,shz_theme_value *out,uint32_t *error)
{
    HKEY key;const char *path,*name;LONG result;DWORD type=0,bytes=0,read_type,read_bytes;
    (void)context;clear(out,sizeof(*out));
    if(!key_names(target,&path,&name,error))return 0;
    result=RegOpenKeyExA(HKEY_CURRENT_USER,path,0,KEY_QUERY_VALUE,&key);
    if(result==ERROR_FILE_NOT_FOUND || result==ERROR_PATH_NOT_FOUND)return 1;
    if(result!=ERROR_SUCCESS){*error=(uint32_t)result;return 0;}
    result=RegQueryValueExA(key,name,NULL,&type,NULL,&bytes);
    if(result==ERROR_FILE_NOT_FOUND)return close_key(key,ERROR_SUCCESS,error);
    if(result!=ERROR_SUCCESS)return close_key(key,result,error);
    if(bytes>SHZ_THEME_VALUE_BYTES)return close_key(key,ERROR_MORE_DATA,error);
    read_type=type;read_bytes=bytes;
    result=RegQueryValueExA(key,name,NULL,&read_type,out->data,&read_bytes);
    if(result==ERROR_SUCCESS && (read_type!=type || read_bytes!=bytes))result=ERROR_INVALID_DATA;
    if(result==ERROR_SUCCESS){out->present=1;out->type=type;out->bytes=bytes;}
    return close_key(key,result,error);
}
static int write_registry(void *context,unsigned target,const shz_theme_value *value,uint32_t *error)
{
    HKEY key;const char *path,*name;LONG result;DWORD disposition;
    (void)context;
    if(!key_names(target,&path,&name,error))return 0;
    if(value->bytes>SHZ_THEME_VALUE_BYTES || value->present>1){*error=ERROR_INVALID_PARAMETER;return 0;}
    if(value->present){
        result=RegCreateKeyExA(HKEY_CURRENT_USER,path,0,NULL,REG_OPTION_NON_VOLATILE,KEY_SET_VALUE,NULL,&key,&disposition);
        if(result!=ERROR_SUCCESS){*error=(uint32_t)result;return 0;}
        result=RegSetValueExA(key,name,0,value->type,value->data,value->bytes);
    }else{
        result=RegOpenKeyExA(HKEY_CURRENT_USER,path,0,KEY_SET_VALUE,&key);
        if(result==ERROR_FILE_NOT_FOUND || result==ERROR_PATH_NOT_FOUND)return 1;
        if(result!=ERROR_SUCCESS){*error=(uint32_t)result;return 0;}
        result=RegDeleteValueA(key,name);
        if(result==ERROR_FILE_NOT_FOUND)result=ERROR_SUCCESS;
    }
    return close_key(key,result,error);
}
static int flush_registry(void *context,unsigned target,uint32_t *error)
{
    HKEY key;const char *path,*name;LONG result;(void)context;
    if(!key_names(target,&path,&name,error))return 0;
    (void)name;
    result=RegOpenKeyExA(HKEY_CURRENT_USER,path,0,KEY_QUERY_VALUE,&key);
    if(result==ERROR_FILE_NOT_FOUND || result==ERROR_PATH_NOT_FOUND)return 1;
    if(result!=ERROR_SUCCESS){*error=(uint32_t)result;return 0;}
    return close_key(key,RegFlushKey(key),error);
}
static int get_system_colors(void *context,uint32_t *colors,uint32_t *error)
{
    unsigned i;(void)context;
    for(i=0;i<SHZ_THEME_COLORS;++i){colors[i]=(uint32_t)GetSysColor((int)i);
        if(colors[i]&0xff000000u){*error=ERROR_INVALID_DATA;return 0;}}
    return 1;
}
static int set_system_colors(void *context,const uint32_t *colors,uint32_t *error)
{
    int indices[SHZ_THEME_COLORS];COLORREF values[SHZ_THEME_COLORS];unsigned i;
    (void)context;
    for(i=0;i<SHZ_THEME_COLORS;++i){indices[i]=(int)i;values[i]=(COLORREF)colors[i];}
    if(!SetSysColors(SHZ_THEME_COLORS,indices,values)){*error=GetLastError();return 0;}return 1;
}
static const shz_theme_ops operations={NULL,get_system_colors,set_system_colors,read_registry,write_registry,flush_registry};

static int acquire(uint32_t *error)
{
    DWORD result=WaitForSingleObject(selector_mutex,5000);
    if(result==WAIT_OBJECT_0)return 1;
    if(result==WAIT_ABANDONED){ReleaseMutex(selector_mutex);*error=ERROR_INVALID_DATA;return 0;}
    *error=result==WAIT_TIMEOUT?ERROR_TIMEOUT:GetLastError();return 0;
}
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
        result->rollback_attempted?"Theme change failed; previous state restored. ":"Theme change refused before palette writes. ");
    text_append(buffer,&used,"Phase ");number_append(buffer,&used,(uint32_t)result->phase);
    text_append(buffer,&used,", error ");number_append(buffer,&used,result->error);
    if(result->rollback_failed){text_append(buffer,&used,", rollback failures ");number_append(buffer,&used,result->rollback_failed);
        text_append(buffer,&used,", rollback error ");number_append(buffer,&used,result->rollback_error);}
}
static void simple_error(enum shz_theme_phase phase,uint32_t error,shz_theme_result *out)
{ clear(out,sizeof(*out));out->status=SHZ_THEME_FAILED;out->phase=phase;out->error=error?error:ERROR_GEN_FAILURE; }

static void refresh_status(void)
{
    shz_theme_value value;shz_theme_profile profile,modern;uint32_t colors[SHZ_THEME_COLORS],error=0;
    int readable,valid;blocked=1;
    if(!acquire(&error)){SetWindowTextA(status_label,"Another theme operation is active or incomplete. Try reopening this window.");goto buttons;}
    readable=read_registry(NULL,SHZ_THEME_PROFILE_VALUE,&value,&error);
    valid=readable && (!value.present || (value.type==SHZ_THEME_REG_BINARY && shz_theme_decode(value.data,value.bytes,&profile)));
    if(!valid){
        SetWindowTextA(saved_label,"Saved theme: invalid or unreadable; selection disabled");
        SetWindowTextA(current_label,"Current session: existing system colors left untouched");
        SetWindowTextA(status_label,"Saved settings require repair. No palette or startup values were changed.");
    }else if(!get_system_colors(NULL,colors,&error)){
        SetWindowTextA(status_label,"System colors could not be captured. No changes were made.");
    }else{
        unsigned i;
        if(value.present){for(i=0;i<SHZ_THEME_COLORS;++i)initial_baseline[i]=profile.baseline[i];baseline_captured=1;}
        else if(!baseline_captured){for(i=0;i<SHZ_THEME_COLORS;++i)initial_baseline[i]=colors[i];baseline_captured=1;}
        SetWindowTextA(saved_label,!value.present?"Saved theme: none (baseline captured; nothing applied yet)":
            profile.style==SHZ_THEME_CLASSIC?"Saved theme: Classic":"Saved theme: ShizukuOS");
        if(same_colors(colors,initial_baseline))SetWindowTextA(current_label,"Current session: Classic baseline");
        else if(shz_theme_make(SHZ_THEME_SHIZUKUOS,initial_baseline,&modern) && same_colors(colors,modern.selected))SetWindowTextA(current_label,"Current session: ShizukuOS");
        else SetWindowTextA(current_label,"Current session: custom system colors");
        blocked=0;
    }
    ReleaseMutex(selector_mutex);
buttons:
    EnableWindow(classic_button,!blocked && !busy);EnableWindow(shizuku_button,!blocked && !busy);
}
static void choose_theme(uint32_t style)
{
    shz_theme_result result;char message[256];uint32_t error=0;int success;
    if(busy || blocked)return;
    busy=1;EnableWindow(classic_button,FALSE);EnableWindow(shizuku_button,FALSE);
    if(!acquire(&error)){simple_error(SHZ_THEME_PHASE_PROFILE_SNAPSHOT,error,&result);success=0;}
    else {success=shz_theme_apply(&operations,initial_baseline,style,&startup_command,&result);ReleaseMutex(selector_mutex);}
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
    case WM_CLOSE:DestroyWindow(window);return 0;
    case WM_DESTROY:PostQuitMessage(0);return 0;
    }
    return DefWindowProcA(window,message,wparam,lparam);
}
static DWORD run_selector(void)
{
    OSVERSIONINFOA version;WNDCLASSA cls;MSG message;char module[MAX_PATH],failure[256];
    const char *command=GetCommandLineA();DWORD length,error,code=1;size_t command_bytes=0;int mode,get;
    shz_theme_result result;
    while(command && command_bytes<1024 && command[command_bytes])++command_bytes;
    mode=shz_theme_command_mode(command,command_bytes);
    if(mode<0){OutputDebugStringA("ShizukuOS theme selector: only no arguments or exact /restore are accepted.");return 1;}
    clear(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
    if(!GetVersionExA(&version) || version.dwPlatformId!=VER_PLATFORM_WIN32_WINDOWS || version.dwMajorVersion!=4 || version.dwMinorVersion!=10){
        OutputDebugStringA("ShizukuOS theme selector: actual Windows 98 is required; no colors or registry values were changed.");return 1;}
    length=GetModuleFileNameA(NULL,module,MAX_PATH);
    if(!length || length>=MAX_PATH || module[length] || !shz_theme_startup_value(module,length,&startup_command)){
        OutputDebugStringA("ShizukuOS theme selector: executable path is missing, truncated or unsafe; no changes.");return 1;}
    selector_mutex=CreateMutexA(NULL,FALSE,mutex_name);
    if(!selector_mutex){OutputDebugStringA("ShizukuOS theme selector: coordination mutex unavailable; no changes.");return 1;}
    if(mode==1){
        uint32_t native_error=0;
        if(!acquire(&native_error))simple_error(SHZ_THEME_PHASE_PROFILE_SNAPSHOT,native_error,&result);
        else {if(shz_theme_restore(&operations,&result))code=0;ReleaseMutex(selector_mutex);}
        if(code){failure_text(&result,failure);OutputDebugStringA(failure);code=result.status==SHZ_THEME_ROLLBACK_FAILED?2:1;}
        CloseHandle(selector_mutex);return code; /* /restore never opens a window. */
    }
    instance=GetModuleHandleA(NULL);clear(&cls,sizeof(cls));
    cls.lpfnWndProc=window_proc;cls.hInstance=instance;cls.hCursor=LoadCursorA(NULL,IDC_ARROW);
    cls.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);cls.lpszClassName="ShizukuOSThemeSelector";
    if(!RegisterClassA(&cls)){error=GetLastError();CloseHandle(selector_mutex);return error?error:1;}
    main_window=CreateWindowExA(WS_EX_CONTROLPARENT,cls.lpszClassName,"ShizukuOS Themes",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        CW_USEDEFAULT,CW_USEDEFAULT,550,244,NULL,NULL,instance,NULL);
    if(!main_window){CloseHandle(selector_mutex);return 1;}
    refresh_status();ShowWindow(main_window,SW_SHOWNORMAL);UpdateWindow(main_window);
    while((get=GetMessageA(&message,NULL,0,0))>0){if(!IsDialogMessageA(main_window,&message)){TranslateMessage(&message);DispatchMessageA(&message);}}
    CloseHandle(selector_mutex);return get<0?1:0;
}
void mainCRTStartup(void){ExitProcess(run_selector());}
