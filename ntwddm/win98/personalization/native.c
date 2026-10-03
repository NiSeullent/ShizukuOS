/* SPDX-License-Identifier: GPL-2.0-only
 * Original Win98 application. Explorer retains the desktop, icons and taskbar.
 * ActiveDesktop/GDI failures are reported; no credentials or elevation claimed.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#define _WIN32_IE 0x0400
#define CINTERFACE
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <wininet.h> /* SDK exposes legacy IActiveDesktop types under _WININET_. No WinINet calls. */
#include <shlobj.h>
#include <shlguid.h>
#include <string.h>
#include "core.h"
#include "store.h"
#include "profile.h"
#include "../adapter.h"

#define PREVIEW_W 320u
#define PREVIEW_H 180u
enum { ID_SCENE=100,ID_RATE,ID_LANGUAGE,ID_PAUSE,ID_BATTERY,ID_SAVE,ID_ANIMATE,ID_STATIC,ID_STATUS };
typedef struct backend { HWND window;HDC memory,painting;HBITMAP bitmap;HGDIOBJ previous; } backend;
static backend native;
static ntwg98_view view;
static pz98_preferences preferences;
static HWND main_window,scene_box,rate_box,language_box,pause_box,battery_box,status_box;
static HWND scene_label,rate_label,language_label,save_button,animate_button,static_button;
static HWND companion_label;
static HINSTANCE instance;
static char prefs_path[MAX_PATH],bmp_path[MAX_PATH],html_path[MAX_PATH];
static uint32_t phase,last_frame,last_power;
static int suspended,ac=-1,desktop_requested,desktop_running,com_ready,paths_ready;
static int korean_available;
static DWORD startup_error,load_error;
static const GUID active_class={0x75048700,0xef1f,0x11d0,{0x98,0x88,0x00,0x60,0x97,0xde,0xac,0xf9}};
static const GUID active_interface={0xf490eb00,0x1240,0x11d1,{0x98,0x88,0x00,0x60,0x97,0xde,0xac,0xf9}};

static const char *text(const char *en,const char *ko)
{
    return preferences.language && korean_available?ko:en;
}
/* Win98 USER32 uses ANSI. Use the real system code page; do not import W UI APIs. */
static int ansi_text(const char *utf8,char *out,unsigned capacity)
{
    WCHAR wide[512];BOOL substituted=FALSE;
    int n=MultiByteToWideChar(CP_UTF8,0,utf8,-1,wide,512);
    if(!n || !WideCharToMultiByte(CP_ACP,0,wide,-1,out,(int)capacity,NULL,&substituted) || substituted)return 0;
    return 1;
}
static void caption(HWND window,const char *en,const char *ko)
{
    char value[1024];const char *chosen=text(en,ko);
    if(!ansi_text(chosen,value,sizeof value))chosen=en;
    if(chosen==en)lstrcpynA(value,en,sizeof value);
    SetWindowTextA(window,value);
}
static void status(const char *en,const char *ko) { caption(status_box,en,ko); }
static void failure(const char *operation,DWORD error)
{
    char value[240];wsprintfA(value,"%s failed (0x%08lx). No success was reported.",operation,error);
    SetWindowTextA(status_box,value);
}
static int initialize_paths(void)
{
    pz98_paths paths;
    if(!pz98_profile_paths(&paths))return 0;
    memcpy(prefs_path,paths.preferences,sizeof prefs_path);
    memcpy(bmp_path,paths.bitmap,sizeof bmp_path);
    memcpy(html_path,paths.html,sizeof html_path);return 1;
}
static void *allocate(void *u,size_t bytes) { (void)u;return HeapAlloc(GetProcessHeap(),0,bytes); }
static void deallocate(void *u,void *p,size_t bytes) { (void)u;(void)bytes;HeapFree(GetProcessHeap(),0,p); }
static int synchronize(void *u) { (void)u;return GdiFlush()!=0; }
static int create_dib(void *u,uint32_t width,uint32_t height,ntwg98_dib *dib)
{
    backend *b=u;BITMAPINFO info={0};HDC screen=GetDC(b->window);
    if(!screen)return 0;
    b->memory=CreateCompatibleDC(screen);ReleaseDC(b->window,screen);
    if(!b->memory)return 0;
    dib->handle=b;
    info.bmiHeader.biSize=sizeof info.bmiHeader;info.bmiHeader.biWidth=(LONG)width;
    info.bmiHeader.biHeight=-(LONG)height;info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;
    info.bmiHeader.biCompression=BI_RGB;
    b->bitmap=CreateDIBSection(b->memory,&info,DIB_RGB_COLORS,&dib->pixels,NULL,0);
    if(!b->bitmap || !dib->pixels)return 0;
    dib->pitch=width*4u;dib->bytes=(size_t)dib->pitch*height;
    b->previous=SelectObject(b->memory,b->bitmap);
    if(!b->previous || b->previous==HGDI_ERROR){b->previous=NULL;return 0;}
    return 1;
}
static int paint_dib(void *u,const ntwg98_dib *dib,uint32_t width,uint32_t height)
{
    backend *b=u;
    return dib->handle==b && b->painting &&
           BitBlt(b->painting,24,48,(int)width,(int)height,b->memory,0,0,SRCCOPY) && GdiFlush();
}
static int release_dib(void *u,ntwg98_dib *dib)
{
    backend *b=u;
    if(b->previous) { HGDIOBJ old=SelectObject(b->memory,b->previous);if(!old || old==HGDI_ERROR)return 0;b->previous=NULL; }
    if(b->bitmap) { if(!DeleteObject(b->bitmap))return 0;b->bitmap=NULL;dib->pixels=NULL; }
    if(b->memory) { if(!DeleteDC(b->memory))return 0;b->memory=NULL; }
    dib->handle=NULL;return 1;
}
static const ntwg98_ops graphics={allocate,deallocate,create_dib,synchronize,paint_dib,release_dib};
static int render_preview(void)
{
    ntwg_mapping map;ntwg_fence fence;int ok;
    if(ntwg_surface_map(view.core,view.surface,&map)!=NTWG_OK)return 0;
    ok=pz98_render(map.pixels,map.byte_length,map.width,map.height,map.pitch_bytes,phase,preferences.scene);
    if(ntwg_surface_unmap(view.core,view.surface)!=NTWG_OK)ok=0;
    if(!ok || ntwg98_present(&view,NULL,0,0,&fence)!=NTWG_OK)return 0;
    return InvalidateRect(main_window,NULL,FALSE)!=0;
}
static int write_bitmap(void)
{
    struct { BITMAPFILEHEADER file;BITMAPINFOHEADER info; } header;
    unsigned width=(unsigned)GetSystemMetrics(SM_CXSCREEN),height=(unsigned)GetSystemMetrics(SM_CYSCREEN);
    DWORD bytes;unsigned char *pixels;int ok;
    if(!width || !height || width>1920 || height>1080){SetLastError(ERROR_NOT_SUPPORTED);return 0;}
    bytes=width*height*4u;pixels=HeapAlloc(GetProcessHeap(),0,bytes);
    if(!pixels){SetLastError(ERROR_NOT_ENOUGH_MEMORY);return 0;}
    memset(&header,0,sizeof header);
    /* Serialize the two headers separately: enclosing struct may add padding. */
    header.file.bfType=0x4d42;header.file.bfOffBits=sizeof header.file+sizeof header.info;
    header.file.bfSize=header.file.bfOffBits+bytes;
    header.info.biSize=sizeof header.info;header.info.biWidth=(LONG)width;header.info.biHeight=-(LONG)height;
    header.info.biPlanes=1;header.info.biBitCount=32;header.info.biCompression=BI_RGB;header.info.biSizeImage=bytes;
    ok=pz98_render(pixels,bytes,width,height,width*4u,phase,preferences.scene);
    if(ok) {
        unsigned char encoded[54];
        memcpy(encoded,&header.file,sizeof header.file);memcpy(encoded+sizeof header.file,&header.info,sizeof header.info);
        ok=pz98_store_write(bmp_path,encoded,sizeof encoded,pixels,bytes);
    }
    HeapFree(GetProcessHeap(),0,pixels);return ok;
}
static HRESULT active_wallpaper(const char *path,int animated)
{
    IActiveDesktop *desktop=NULL;WCHAR wide[MAX_PATH];WALLPAPEROPT placement={sizeof placement,WPSTYLE_STRETCH};
    COMPONENTSOPT options={sizeof options,FALSE,FALSE};HRESULT result;
    if(!com_ready)return E_NOINTERFACE;
    if(!MultiByteToWideChar(CP_ACP,0,path,-1,wide,MAX_PATH))return HRESULT_FROM_WIN32(GetLastError());
    result=CoCreateInstance(&active_class,NULL,CLSCTX_INPROC_SERVER,&active_interface,(void **)&desktop);
    if(FAILED(result))return result;
    if(animated) {
        result=desktop->lpVtbl->GetDesktopItemOptions(desktop,&options,0);
        if(SUCCEEDED(result)) {
            options.fActiveDesktop=TRUE; /* Preserve unrelated components' enable state. */
            result=desktop->lpVtbl->SetDesktopItemOptions(desktop,&options,0);
        }
    }
    if(SUCCEEDED(result))result=desktop->lpVtbl->SetWallpaper(desktop,wide,0);
    if(SUCCEEDED(result))result=desktop->lpVtbl->SetWallpaperOptions(desktop,&placement,0);
    if(SUCCEEDED(result))result=desktop->lpVtbl->ApplyChanges(desktop,AD_APPLY_ALL);
    desktop->lpVtbl->Release(desktop);return result;
}
static int apply_static(void)
{
    HRESULT result;
    if(!paths_ready || !write_bitmap()){failure("Write wallpaper BMP",GetLastError());desktop_requested=0;return 0;}
    result=active_wallpaper(bmp_path,0);
    if(FAILED(result) && !SystemParametersInfoA(SPI_SETDESKWALLPAPER,0,bmp_path,SPIF_UPDATEINIFILE|SPIF_SENDCHANGE)) {
        failure("Static wallpaper / ActiveDesktop",GetLastError());desktop_requested=0;return 0;
    }
    desktop_running=0;return 1;
}
static int apply_animation(void)
{
    char html[PZ98_HTML_BYTES];HRESULT result;
    if(!paths_ready || !pz98_html(&preferences,html,sizeof html) ||
       !pz98_store_write(html_path,html,(DWORD)lstrlenA(html),NULL,0)) {
        failure("Write local wallpaper HTML",GetLastError());desktop_requested=0;return 0;
    }
    result=active_wallpaper(html_path,1);
    if(FAILED(result)) {
        DWORD error=(DWORD)result;
        desktop_requested=0; /* Failure requires a new Apply click, never a timer retry storm. */
        if(apply_static()){char message[220];wsprintfA(message,"Animated wallpaper unavailable (0x%08lx). Static wallpaper applied.",error);SetWindowTextA(status_box,message);}
        return 0;
    }
    desktop_running=1;return 1;
}
static void update_power(void)
{
    SYSTEM_POWER_STATUS power;
    ac=GetSystemPowerStatus(&power)?(power.ACLineStatus==1?1:power.ACLineStatus==0?0:-1):-1;
}
static void update_policy(void)
{
    int run=!!pz98_interval(&preferences,ac,suspended,1);
    if(desktop_requested && run!=desktop_running) {
        if(run) { if(apply_animation())status("Animated wallpaper applied. It pauses after five minutes.","움직이는 배경화면을 적용했습니다. 5분 뒤 자동으로 멈춥니다."); }
        else if(apply_static())status("Wallpaper paused by the power or pause setting.","전원 또는 일시정지 설정에 따라 배경화면을 멈췄습니다.");
    }
}
static void read_controls(void)
{
    LRESULT selected;
    selected=SendMessageA(scene_box,CB_GETCURSEL,0,0);if(selected>=0)preferences.scene=(unsigned)selected;
    selected=SendMessageA(rate_box,CB_GETCURSEL,0,0);if(selected>=0)preferences.fps=selected==0?5u:selected==1?10u:20u;
    selected=SendMessageA(language_box,CB_GETCURSEL,0,0);if(selected>=0)preferences.language=(unsigned)selected;
    preferences.paused=SendMessageA(pause_box,BM_GETCHECK,0,0)==BST_CHECKED;
    preferences.battery_saver=SendMessageA(battery_box,BM_GETCHECK,0,0)==BST_CHECKED;
}
static void labels(void)
{
    char value[200];
    caption(main_window,"Shizuku Personalization","Shizuku 개인화");
    caption(scene_label,"Scene","배경");caption(rate_label,"Frames per second","초당 프레임");caption(language_label,"Language","언어");
    caption(pause_box,"Pause animation","애니메이션 일시정지");caption(battery_box,"Pause on battery or unknown power","배터리 사용 또는 전원 확인 불가 시 정지");
    caption(save_button,"Save settings","설정 저장");caption(animate_button,"Apply animated","움직이는 배경 적용");caption(static_button,"Apply static","정적 배경 적용");
    caption(companion_label,"Accounts / elevation: NTW64 bridge is not configured.","계정 / 권한 상승: NTW64 연결이 아직 설정되지 않았습니다.");
    SendMessageA(scene_box,CB_RESETCONTENT,0,0);
    ansi_text(text("Aurora","오로라"),value,sizeof value);SendMessageA(scene_box,CB_ADDSTRING,0,(LPARAM)value);
    ansi_text(text("Starlight","별빛"),value,sizeof value);SendMessageA(scene_box,CB_ADDSTRING,0,(LPARAM)value);
    SendMessageA(scene_box,CB_SETCURSEL,preferences.scene,0);
    if(preferences.language && !korean_available)status("Korean needs a Korean system code page. English is used on this system.","");
}
static HWND control(const char *class_name,DWORD style,int x,int y,int width,int height,unsigned id)
{
    HWND window=CreateWindowExA(0,class_name,"",WS_CHILD|WS_VISIBLE|style,x,y,width,height,main_window,(HMENU)(UINT_PTR)id,instance,NULL);
    if(window)SendMessageA(window,WM_SETFONT,(WPARAM)GetStockObject(DEFAULT_GUI_FONT),FALSE);
    return window;
}
static int create_controls(void)
{
    scene_label=control("STATIC",0,374,48,230,20,0);scene_box=control("COMBOBOX",CBS_DROPDOWNLIST|WS_VSCROLL|WS_TABSTOP,374,72,230,120,ID_SCENE);
    rate_label=control("STATIC",0,374,110,230,20,0);rate_box=control("COMBOBOX",CBS_DROPDOWNLIST|WS_TABSTOP,374,134,100,90,ID_RATE);
    language_label=control("STATIC",0,374,170,230,20,0);language_box=control("COMBOBOX",CBS_DROPDOWNLIST|WS_TABSTOP,374,194,230,90,ID_LANGUAGE);
    pause_box=control("BUTTON",BS_AUTOCHECKBOX|WS_TABSTOP,24,256,290,24,ID_PAUSE);
    battery_box=control("BUTTON",BS_AUTOCHECKBOX|WS_TABSTOP,24,290,580,24,ID_BATTERY);
    save_button=control("BUTTON",BS_PUSHBUTTON|WS_TABSTOP,24,340,170,32,ID_SAVE);
    animate_button=control("BUTTON",BS_PUSHBUTTON|WS_TABSTOP,210,340,190,32,ID_ANIMATE);
    static_button=control("BUTTON",BS_PUSHBUTTON|WS_TABSTOP,416,340,190,32,ID_STATIC);
    companion_label=control("STATIC",0,24,380,585,20,0);
    status_box=control("STATIC",0,24,400,585,68,ID_STATUS);
    if(!scene_label || !scene_box || !rate_label || !rate_box || !language_label || !language_box ||
       !pause_box || !battery_box || !save_button || !animate_button || !static_button || !companion_label || !status_box)return 0;
    SendMessageA(rate_box,CB_ADDSTRING,0,(LPARAM)"5");SendMessageA(rate_box,CB_ADDSTRING,0,(LPARAM)"10");SendMessageA(rate_box,CB_ADDSTRING,0,(LPARAM)"20");
    SendMessageA(rate_box,CB_SETCURSEL,preferences.fps==5?0:preferences.fps==10?1:2,0);
    SendMessageA(language_box,CB_ADDSTRING,0,(LPARAM)"English");
    { char korean[80];if(!ansi_text("Korean / 한국어",korean,sizeof korean))lstrcpyA(korean,"Korean");SendMessageA(language_box,CB_ADDSTRING,0,(LPARAM)korean); }
    SendMessageA(language_box,CB_SETCURSEL,preferences.language,0);
    SendMessageA(pause_box,BM_SETCHECK,preferences.paused?BST_CHECKED:BST_UNCHECKED,0);
    SendMessageA(battery_box,BM_SETCHECK,preferences.battery_saver?BST_CHECKED:BST_UNCHECKED,0);labels();return 1;
}
static LRESULT CALLBACK window_proc(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
    switch(message) {
    case WM_PAINT: {
        PAINTSTRUCT paint;native.painting=BeginPaint(window,&paint);
        if(native.painting) { if(view.image_ready && ntwg98_paint(&view)!=NTWG_OK)failure("Preview paint",GetLastError());EndPaint(window,&paint); }
        native.painting=NULL;return 0;
    }
    case WM_COMMAND:
        read_controls();
        if(LOWORD(wparam)==ID_LANGUAGE && HIWORD(wparam)==CBN_SELCHANGE)labels();
        if(LOWORD(wparam)==ID_SAVE) {
            unsigned char record[PZ98_RECORD_BYTES];
            if(paths_ready && pz98_encode(&preferences,record,sizeof record) && pz98_store_write(prefs_path,record,sizeof record,NULL,0))
                status("Settings saved and verified.","설정을 저장하고 확인했습니다.");
            else failure("Save settings",GetLastError());
        } else if(LOWORD(wparam)==ID_ANIMATE) {
            desktop_requested=1;
            if(pz98_interval(&preferences,ac,suspended,1)) {
                if(apply_animation())status("Animated wallpaper applied. Reapply to restart after five minutes.","움직이는 배경화면을 적용했습니다. 5분 뒤 다시 적용하면 재시작됩니다.");
            } else if(apply_static())status("Static wallpaper applied while animation is paused.","애니메이션 정지 중에는 정적 배경화면을 적용합니다.");
        } else if(LOWORD(wparam)==ID_STATIC) {
            desktop_requested=0;if(apply_static())status("Static wallpaper applied.","정적 배경화면을 적용했습니다.");
        }
        update_policy();render_preview();return 0;
    case WM_TIMER: {
        DWORD now=GetTickCount();unsigned interval;
        if((DWORD)(now-last_power)>=1000u){last_power=now;update_power();update_policy();}
        interval=pz98_interval(&preferences,ac,suspended,!IsIconic(window));
        if(interval && (DWORD)(now-last_frame)>=interval) { last_frame=now;++phase;if(!render_preview())failure("Preview rendering",GetLastError()); }
        return 0;
    }
    case WM_POWERBROADCAST:
        if(wparam==PBT_APMSUSPEND)suspended=1;
        else if(wparam==PBT_APMRESUMESUSPEND || wparam==PBT_APMRESUMECRITICAL)suspended=0;
        update_power();update_policy();return TRUE;
    case WM_CLOSE:
        KillTimer(window,1);
        if(desktop_requested && desktop_running && !apply_static())
            MessageBoxA(window,"Wallpaper could not be frozen. Its offline timer will stop within five minutes.","Shizuku",MB_OK|MB_ICONEXCLAMATION);
        DestroyWindow(window);return 0;
    case WM_DESTROY:PostQuitMessage(0);return 0;
    }
    return DefWindowProcA(window,message,wparam,lparam);
}
void __attribute__((stdcall)) WinMainCRTStartup(void)
{
    WNDCLASSA window_class={0};MSG message;RECT rect={0,0,640,490};char converted[64];int opened=0,code=1;
    HRESULT initialized;
    instance=GetModuleHandleA(NULL);pz98_defaults(&preferences);
    korean_available=ansi_text("한국어",converted,sizeof converted);
    if((GetUserDefaultLangID()&0x3ff)==LANG_KOREAN)preferences.language=1;
    initialized=CoInitialize(NULL);com_ready=SUCCEEDED(initialized);
    paths_ready=initialize_paths();
    if(!paths_ready)startup_error=GetLastError();
    else if(!pz98_store_preferences(prefs_path,&preferences)) {
        load_error=GetLastError();
        if(load_error==ERROR_FILE_NOT_FOUND || load_error==ERROR_PATH_NOT_FOUND)load_error=0;
    }
    window_class.lpfnWndProc=window_proc;window_class.hInstance=instance;
    window_class.hCursor=LoadCursorA(NULL,IDC_ARROW);window_class.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
    window_class.lpszClassName="ShizukuPersonalization98";
    if(!RegisterClassA(&window_class))goto cleanup;
    if(!AdjustWindowRect(&rect,WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,FALSE))goto cleanup;
    main_window=CreateWindowExA(0,window_class.lpszClassName,"Shizuku Personalization",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        CW_USEDEFAULT,CW_USEDEFAULT,rect.right-rect.left,rect.bottom-rect.top,NULL,NULL,instance,NULL);
    if(!main_window || !create_controls())goto cleanup;
    native.window=main_window;
    if(ntwg98_open(&view,&graphics,&native,PREVIEW_W,PREVIEW_H)!=NTWG_OK)goto cleanup;
    opened=1;update_power();
    if(!render_preview() || !SetTimer(main_window,1,50,NULL))goto cleanup;
    status("Preview ready. Apply chooses the actual Windows wallpaper.","미리보기가 준비되었습니다. 적용을 누르면 Windows 배경화면을 바꿉니다.");
    if(!paths_ready)failure("Settings folder",startup_error);
    else if(load_error)failure("Load settings (defaults retained)",load_error);
    else if(preferences.language && !korean_available)status("Korean needs a Korean system code page. English is used on this system.","");
    ShowWindow(main_window,SW_SHOWNORMAL);UpdateWindow(main_window);
    for(;;) {
        BOOL next=GetMessageA(&message,NULL,0,0);
        if(next==-1){code=1;break;}if(!next){code=0;break;}
        if(!IsDialogMessageA(main_window,&message)){TranslateMessage(&message);DispatchMessageA(&message);}
    }
cleanup:
    if(opened && ntwg98_close(&view)!=NTWG_OK)code=1;
    if(main_window && IsWindow(main_window))DestroyWindow(main_window);
    if(com_ready)CoUninitialize();
    ExitProcess((UINT)code);
}
