/* SPDX-License-Identifier: GPL-2.0-only
 * Native GDI acceptance probe. Building it is not evidence of guest execution.
 * Uses a unique DLL name and explicit opt-in, so no system mapping is changed.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <uxtheme.h>
#include <vssym32.h>
#ifdef M98_THEME_STATIC
__declspec(dllimport) HRESULT WINAPI M98SetThemeStyle(DWORD);
__declspec(dllimport) HTHEME WINAPI OpenThemeData(HWND,LPCWSTR);
__declspec(dllimport) HRESULT WINAPI CloseThemeData(HTHEME);
__declspec(dllimport) BOOL WINAPI IsThemeActive(void);
__declspec(dllimport) BOOL WINAPI IsAppThemed(void);
__declspec(dllimport) HRESULT WINAPI DrawThemeBackground(HTHEME,HDC,int,int,const RECT *,const RECT *);
__declspec(dllimport) HRESULT WINAPI DrawThemeTextEx(HTHEME,HDC,int,int,LPCWSTR,int,DWORD,RECT *,const DTTOPTS *);
__declspec(dllimport) HRESULT WINAPI GetThemeColor(HTHEME,int,int,int,COLORREF *);
__declspec(dllimport) HRESULT WINAPI GetThemeMargins(HTHEME,HDC,int,int,int,RECT *,MARGINS *);
__declspec(dllimport) HRESULT WINAPI GetThemeBackgroundContentRect(HTHEME,HDC,int,int,const RECT *,RECT *);
__declspec(dllimport) HRESULT WINAPI GetThemeFont(HTHEME,HDC,int,int,int,LOGFONTW *);
__declspec(dllimport) HRESULT WINAPI SetWindowTheme(HWND,LPCWSTR,LPCWSTR);
__declspec(dllimport) HTHEME WINAPI GetWindowTheme(HWND);
#endif
typedef HRESULT (WINAPI *style_fn)(DWORD);
typedef HTHEME (WINAPI *open_fn)(HWND, LPCWSTR);
typedef HRESULT (WINAPI *close_fn)(HTHEME);
typedef BOOL (WINAPI *active_fn)(void);
typedef HRESULT (WINAPI *draw_fn)(HTHEME,HDC,int,int,const RECT *,const RECT *);
typedef HRESULT (WINAPI *text_fn)(HTHEME,HDC,int,int,LPCWSTR,int,DWORD,RECT *,const DTTOPTS *);
typedef HRESULT (WINAPI *color_fn)(HTHEME,int,int,int,COLORREF *);
typedef HRESULT (WINAPI *margins_fn)(HTHEME,HDC,int,int,int,RECT *,MARGINS *);
typedef HRESULT (WINAPI *content_fn)(HTHEME,HDC,int,int,const RECT *,RECT *);
typedef HRESULT (WINAPI *font_fn)(HTHEME,HDC,int,int,int,LOGFONTW *);
typedef HRESULT (WINAPI *window_fn)(HWND,LPCWSTR,LPCWSTR);
typedef HTHEME (WINAPI *get_fn)(HWND);
static style_fn style;
static open_fn open_theme;
static close_fn close_theme;
static draw_fn draw;
static text_fn draw_text;
static unsigned notifications;
static void say(const char *s) { DWORD n=0,w; while(s[n])++n; WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),s,n,&w,NULL); }
static void fail(const char *s) { say("FAIL: "); say(s); say("\r\n"); ExitProcess(1); }
#define CHECK(c,s) do { if (!(c)) fail(s); } while (0)
static LRESULT CALLBACK window_proc(HWND window, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_THEMECHANGED) ++notifications;
    if (msg == WM_PAINT) {
        PAINTSTRUCT paint; HDC dc = BeginPaint(window,&paint); unsigned i;
        for (i=0;i<2;++i) {
            HTHEME h; RECT r = {16+(LONG)i*180,20,176+(LONG)i*180,100};
            CHECK(style(i ? 2 : 1)==S_OK,"select visible style");
            h=open_theme(NULL,L"Button"); CHECK(h,"open visible theme");
            CHECK(draw(h,dc,1,1,&r,NULL)==S_OK,"visible GDI background");
            CHECK(draw_text(h,dc,1,1,i?L"Modern theme":L"Classic theme",-1,
                             DT_CENTER|DT_VCENTER|DT_SINGLELINE,&r,NULL)==S_OK,"visible GDI label");
            CHECK(close_theme(h)==S_OK,"close visible theme");
        }
        EndPaint(window,&paint); return 0;
    }
    return DefWindowProcA(window,msg,wp,lp);
}
void mainCRTStartup(void)
{
#ifdef M98_THEME_STATIC
    HMODULE dll=GetModuleHandleA("M98THEME.DLL");
    const char *title="Classic and Modern - M98THEME static import";
#else
    HMODULE dll=LoadLibraryA("M98THEME.DLL");
    const char *title="Classic and Modern - M98THEME direct DLL";
#endif
    active_fn active, app;
    color_fn color; margins_fn margins; content_fn content; font_fn font;
    window_fn set_window; get_fn get_window;
    HTHEME h, stale; HDC screen,memory; HBITMAP bitmap,previous;
    BITMAPINFO info={0}; void *bits; RECT r={2,2,30,30},clip={8,8,16,16},out={0};
    MARGINS m; COLORREF c=RGB(1,2,3); LOGFONTW f;
    WNDCLASSA wc={0}; HWND window; MSG message; DWORD start; int old_mode;
    OSVERSIONINFOA version={sizeof(version),0,0,0,0,{0}};
    CHECK(dll,"load unique application-owned DLL");
    CHECK(GetVersionExA(&version),"read native OS identity");
    if(version.dwPlatformId==VER_PLATFORM_WIN32_WINDOWS&&version.dwMajorVersion==4&&version.dwMinorVersion==10)
        say("WIN98_IDENTIFIED=1\r\n");
    else say("WIN98_IDENTIFIED=0\r\n");
#ifdef M98_THEME_STATIC
    say("PROBE_MODE=static-import\r\n");
#define RESOLVE(v,n) do { v=n; CHECK(v,#n); } while(0)
#else
    say("PROBE_MODE=direct-dll\r\n");
#define RESOLVE(v,n) do { v=(void *)GetProcAddress(dll,#n); CHECK(v,#n); } while(0)
#endif
    RESOLVE(style,M98SetThemeStyle); RESOLVE(open_theme,OpenThemeData);
    RESOLVE(close_theme,CloseThemeData); RESOLVE(active,IsThemeActive);
    RESOLVE(app,IsAppThemed); RESOLVE(draw,DrawThemeBackground);
    RESOLVE(draw_text,DrawThemeTextEx); RESOLVE(color,GetThemeColor);
    RESOLVE(margins,GetThemeMargins); RESOLVE(content,GetThemeBackgroundContentRect);
    RESOLVE(font,GetThemeFont); RESOLVE(set_window,SetWindowTheme); RESOLVE(get_window,GetWindowTheme);
    CHECK(!active()&&!app()&&!open_theme(NULL,L"BUTTON"),"provider begins disabled");
    CHECK(style(2)==S_OK&&active()&&app(),"opt-in modern theme");
    CHECK(!open_theme(NULL,L"SCROLLBAR"),"unsupported class rejected");
    h=open_theme(NULL,L"Unknown;Button"); CHECK(h,"ordered case-insensitive class list");
    CHECK(color(h,1,1,TMT_BORDERCOLOR,&c)==S_OK&&c==RGB(0,120,215),"modern border color byte order");
    CHECK(color(h,1,2,TMT_FILLCOLOR,&c)==S_OK&&c==RGB(229,241,251),"hot state color");
    CHECK(margins(h,NULL,1,1,TMT_CONTENTMARGINS,NULL,&m)==S_OK&&m.cxLeftWidth==1&&m.cyBottomHeight==1,"content margins");
    CHECK(content(h,NULL,1,1,&r,&out)==S_OK&&out.left==3&&out.right==29,"content rect");
    CHECK(font(h,NULL,1,1,TMT_FONT,&f)==S_OK&&f.lfFaceName[0],"real system message font");
    screen=GetDC(NULL); memory=CreateCompatibleDC(screen);
    info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);info.bmiHeader.biWidth=32;info.bmiHeader.biHeight=-32;
    info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;
    bitmap=CreateDIBSection(screen,&info,DIB_RGB_COLORS,&bits,NULL,0);
    CHECK(screen&&memory&&bitmap&&bits,"create native 32-bit DIB"); previous=SelectObject(memory,bitmap);
    CHECK(previous&&GdiFlush(),"select and synchronize native DIB");
    CHECK(PatBlt(memory,0,0,32,32,BLACKNESS)&&GdiFlush(),"clear native DIB");
    CHECK(draw(h,memory,1,1,&r,&clip)==S_OK,"native clipped painter");
    CHECK(GetPixel(memory,10,10)==RGB(240,240,240)&&GetPixel(memory,4,4)==RGB(0,0,0),"clipped pixels and untouched outside");
    old_mode=SetBkMode(memory,OPAQUE);c=SetTextColor(memory,RGB(203,44,61));
    CHECK(draw_text(h,memory,1,1,L"Theme: A&B!",-1,DT_CALCRECT|DT_SINGLELINE,&r,NULL)==S_OK&&r.right>r.left,"formatted punctuation text sizing");
    CHECK(GetBkMode(memory)==OPAQUE&&GetTextColor(memory)==RGB(203,44,61),"text restores caller DC");
    if(GetACP()==949) {
        say("ACP=949\r\n");
        CHECK(draw_text(h,memory,1,1,L"\xd14c\xb9c8",-1,DT_CALCRECT|DT_SINGLELINE,&r,NULL)==S_OK,"exact Korean ACP text");
    }
    if(GetACP()==1252)
        CHECK(draw_text(h,memory,1,1,L"\x2212",1,DT_CALCRECT,&r,NULL)==HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION),"reject silent best-fit minus mapping");
    if(GetACP()!=65001)
        CHECK(draw_text(h,memory,1,1,L"\xd83d\xde00",2,DT_CALCRECT,&r,NULL)==HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION),"reject lossy unsupported emoji");
    SetBkMode(memory,old_mode);SetTextColor(memory,c);
    stale=h; CHECK(style(1)==S_OK&&draw(stale,memory,1,1,&r,NULL)==E_HANDLE,"style switch rejects stale draw");
    CHECK(close_theme(stale)==S_OK&&close_theme(stale)==E_HANDLE,"stale handle close and double-close rejection");
    wc.lpfnWndProc=window_proc;wc.hInstance=GetModuleHandleA(NULL);wc.lpszClassName="M98ThemeAcceptance";
    wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);CHECK(RegisterClassA(&wc),"register visible window");
    window=CreateWindowExA(0,wc.lpszClassName,title,WS_OVERLAPPEDWINDOW,
                           30,30,400,190,NULL,NULL,wc.hInstance,NULL);CHECK(window,"create visible window");
    h=open_theme(window,L"BUTTON");CHECK(h&&get_window(window)==h,"window theme association");
    CHECK(set_window(window,L"",L"")==S_OK&&notifications==1&&!open_theme(window,L"BUTTON"),"per-window disable and WM_THEMECHANGED");
    CHECK(set_window(window,NULL,NULL)==S_OK&&notifications==2,"reset per-window override");
    CHECK(close_theme(h)==S_OK&&!get_window(window),"close clears window association");
    ShowWindow(window,SW_SHOWNORMAL);UpdateWindow(window); start=GetTickCount();
    /* Keep each bounded comparison visible across the guest capture interval. */
    while(GetTickCount()-start<15000) { while(PeekMessageA(&message,NULL,0,0,PM_REMOVE)){TranslateMessage(&message);DispatchMessageA(&message);}Sleep(10); }
    DestroyWindow(window);UnregisterClassA(wc.lpszClassName,wc.hInstance);
    SelectObject(memory,previous);DeleteObject(bitmap);DeleteDC(memory);ReleaseDC(NULL,screen);
    CHECK(style(0)==S_OK&&!active()&&!app(),"disable provider");
#ifndef M98_THEME_STATIC
    FreeLibrary(dll);
#endif
    say("PASS: native GDI theme, colors, margins, font, text, handles and visible comparison\r\n");ExitProcess(0);
}
