/* SPDX-License-Identifier: GPL-2.0-only
 * Actual Windows-ABI acceptance of the private shared theme painter.
 * Expected palette/geometry are declared independently here. No mock GDI,
 * CRT, process exit substitution, or system theme registration is used.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <uxtheme.h>
#include <vssym32.h>
#include "trial_nonce.h"

typedef HRESULT (WINAPI *set_style_fn)(DWORD);
typedef DWORD (WINAPI *get_style_fn)(void);
typedef BOOL (WINAPI *active_fn)(void);
typedef HTHEME (WINAPI *open_fn)(HWND, LPCWSTR);
typedef HRESULT (WINAPI *close_fn)(HTHEME);
typedef HRESULT (WINAPI *color_fn)(HTHEME,int,int,int,COLORREF*);
typedef HRESULT (WINAPI *margin_fn)(HTHEME,HDC,int,int,int,const RECT*,MARGINS*);
typedef HRESULT (WINAPI *content_fn)(HTHEME,HDC,int,int,const RECT*,RECT*);
typedef HRESULT (WINAPI *size_fn)(HTHEME,HDC,int,int,RECT*,enum THEMESIZE,SIZE*);
typedef HRESULT (WINAPI *draw_fn)(HTHEME,HDC,int,int,const RECT*,const RECT*);
typedef HRESULT (WINAPI *draw_ex_fn)(HTHEME,HDC,int,int,const RECT*,const DTBGOPTS*);
static set_style_fn select_style;
static get_style_fn current_style;
static active_fn active;
static open_fn open_theme;
static close_fn close_theme;
static color_fn get_color;
static margin_fn get_margins;
static content_fn get_content;
static size_fn get_size;
static draw_fn draw;
static draw_ex_fn draw_ex;
static unsigned checks, failures, paints;
static void * volatile relocation_anchor=&checks;
static HANDLE output;
static int output_ok=1;
static char line_buffer[1024];
static unsigned line_used;
static void zero(void *p, SIZE_T n) { unsigned char *b=p; while(n--) *b++=0; }
static void write_text(const char *s) {
    while(*s) {
        DWORD done=0; char c=*s++;
        if(line_used==sizeof line_buffer){output_ok=0;line_used=0;}
        line_buffer[line_used++]=c;
        if(c=='\n') {
            if(!WriteFile(output,line_buffer,line_used,&done,0)||done!=line_used)output_ok=0;
            line_used=0;
        }
    }
}
static void check(int value, const char *name) {
    ++checks; if(!value) ++failures;
    write_text(value ? "TP64 PASS " : "TP64 FAIL "); write_text(name); write_text("\r\n");
}
static void number(unsigned n) {
    char b[12]; unsigned i=0,j; do { b[i++]=(char)('0'+n%10); n/=10; }while(n);
    for(j=0;j<i/2;++j) { char t=b[j]; b[j]=b[i-1-j]; b[i-1-j]=t; } b[i]=0;write_text(b);
}
static FARPROC symbol(HMODULE m,const char *name) {
    FARPROC p=GetProcAddress(m,name); check(p!=0,name); return p;
}
#define LOAD(variable,type,name) do { union { FARPROC raw; type typed; } fn; fn.raw=symbol(module,name); variable=fn.typed; if(!variable)goto done; }while(0)
static int region(HDC dc,int l,int t,int r,int b,COLORREF c) {
    int x,y; for(y=t;y<b;++y) for(x=l;x<r;++x) if(GetPixel(dc,x,y)!=c) return 0; return 1;
}
static int clear(HDC dc,COLORREF color) {
    HBRUSH brush=CreateSolidBrush(color); HGDIOBJ old;
    if(!brush) return 0;
    old=SelectObject(dc,brush);
    if(!old||old==HGDI_ERROR) { DeleteObject(brush);return 0; }
    { BOOL ok=PatBlt(dc,0,0,64,48,PATCOPY); SelectObject(dc,old); return DeleteObject(brush)&&ok&&GdiFlush(); }
}
static void memory_trial(void) {
    BITMAPINFO bi; HDC dc=0; HBITMAP bitmap=0; HGDIOBJ old=0; unsigned *bits=0;
    RECT r={8,6,40,30}, clip={12,9,24,19}, content;
    COLORREF sentinel=RGB(11,22,33), c=0; HTHEME theme=0, stale;
    MARGINS margins; SIZE size; DTBGOPTS opts; DWORD style; unsigned y,x;
    zero(&bi,sizeof bi); bi.bmiHeader.biSize=sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth=64;bi.bmiHeader.biHeight=-48;bi.bmiHeader.biPlanes=1;
    bi.bmiHeader.biBitCount=32;bi.bmiHeader.biCompression=BI_RGB;
    dc=CreateCompatibleDC(0); check(dc!=0,"create_memory_dc"); if(!dc)goto cleanup;
    bitmap=CreateDIBSection(dc,&bi,DIB_RGB_COLORS,(void**)&bits,0,0);
    check(bitmap&&bits,"create_top_down_dib"); if(!bitmap||!bits)goto cleanup;
    old=SelectObject(dc,bitmap);check(old&&old!=HGDI_ERROR,"select_dib"); if(!old||old==HGDI_ERROR)goto cleanup;
    check(clear(dc,sentinel),"baseline_fill");
    check(GetPixel(dc,5,5)==sentinel && (bits[5*64+5]&0xffffff)==0x0b1621,"gdi_and_dib_memory_agree");
    check(current_style()==2 && active(),"frozen_provider_defaults_modern");
    check(select_style(0)==S_OK && current_style()==0 && !active(),"explicit_style_off");
    check(open_theme(0,L"BUTTON")==0,"off_does_not_open_theme");
    for(style=1;style<=2;++style) {
        COLORREF border=style==1?RGB(128,128,128):RGB(0,120,215);
        COLORREF fill=style==1?RGB(192,192,192):RGB(240,240,240);
        check(select_style(style)==S_OK && current_style()==style && active(),style==1?"select_classic":"select_modern");
        theme=open_theme(0,L"BUTTON");check(theme!=0,"open_button");if(!theme)continue;
        check(get_color(theme,1,1,TMT_BORDERCOLOR,&c)==S_OK&&c==border,"independent_border_palette");
        check(get_color(theme,1,1,TMT_FILLCOLOR,&c)==S_OK&&c==fill,"independent_fill_palette");
        zero(&margins,sizeof margins);
        check(get_margins(theme,dc,1,1,TMT_CONTENTMARGINS,&r,&margins)==S_OK&&margins.cxLeftWidth==1&&margins.cxRightWidth==1&&margins.cyTopHeight==1&&margins.cyBottomHeight==1,"one_pixel_content_margins");
        zero(&content,sizeof content);
        check(get_content(theme,dc,1,1,&r,&content)==S_OK&&content.left==9&&content.top==7&&content.right==39&&content.bottom==29,"content_rect_insets");
        size.cx=77;size.cy=88;
        check(get_size(theme,dc,1,1,&r,TS_MIN,&size)==S_OK&&size.cx==2&&size.cy==2,"minimum_borderfill_size");
        check(get_size(theme,dc,1,1,&r,TS_TRUE,&size)==S_OK&&size.cx==3&&size.cy==3,"true_borderfill_size");
        check(clear(dc,sentinel)&&draw(theme,dc,1,1,&r,0)==S_OK,"actual_dib_renderer");
        check(region(dc,9,7,39,29,fill),"all_interior_pixels");
        check(region(dc,8,6,40,7,border)&&region(dc,8,29,40,30,border)&&region(dc,8,7,9,29,border)&&region(dc,39,7,40,29,border),"all_border_pixels");
        check(GetPixel(dc,7,6)==sentinel&&GetPixel(dc,40,29)==sentinel&&GetPixel(dc,39,30)==sentinel,"exclusive_right_bottom_bounds");
        check(clear(dc,sentinel)&&draw(theme,dc,1,1,&r,&clip)==S_OK,"actual_clip_renderer");
        check(region(dc,12,9,24,19,fill)&&GetPixel(dc,11,9)==sentinel&&GetPixel(dc,24,18)==sentinel&&GetPixel(dc,23,19)==sentinel,"clip_exclusive_bounds");
        check(SetPixel(dc,2,2,RGB(90,80,70))==RGB(90,80,70)&&GetPixel(dc,2,2)==RGB(90,80,70),"clip_state_restored_after_draw");
        zero(&opts,sizeof opts);opts.dwSize=sizeof opts;opts.dwFlags=DTBG_CLIPRECT;opts.rcClip=clip;
        check(clear(dc,sentinel)&&draw_ex(theme,dc,1,1,&r,&opts)==S_OK&&region(dc,12,9,24,19,fill)&&GetPixel(dc,11,9)==sentinel,"draw_ex_real_clip");
        opts.dwFlags=DTBG_OMITBORDER;
        check(clear(dc,sentinel)&&draw_ex(theme,dc,1,1,&r,&opts)==E_NOTIMPL&&region(dc,0,0,64,48,sentinel),"unsupported_draw_ex_does_not_write");
        size.cx=77;size.cy=88;
        check(get_size(theme,dc,1,1,&r,(enum THEMESIZE)99,&size)==E_INVALIDARG&&size.cx==77&&size.cy==88,"invalid_size_keeps_output");
        c=123;
        check(get_color((HTHEME)((ULONG_PTR)theme|((ULONG_PTR)1<<32)),1,1,TMT_FILLCOLOR,&c)==E_HANDLE&&c==123,"amd64_upper_handle_bits_rejected");
        stale=theme;check(close_theme(theme)==S_OK,"close_button");theme=0;c=123;
        check(get_color(stale,1,1,TMT_FILLCOLOR,&c)==E_HANDLE&&c==123&&close_theme(stale)==E_HANDLE,"stale_cookie_rejected");
    }
    theme=open_theme(0,L"BUTTON");check(theme!=0,"open_before_style_change");
    check(select_style(1)==S_OK,"style_change_with_open_cookie");c=123;
    check(get_color(theme,1,1,TMT_FILLCOLOR,&c)==E_HANDLE&&c==123,"style_change_invalidates_cookie");theme=0;
    check(select_style(2)==S_OK,"restore_modern");
    /* Real WINDOW gradient pixels, including every interior row. */
    theme=open_theme(0,L"WINDOW");check(theme!=0,"open_window_gradient");
    if(theme) {
        check(clear(dc,sentinel)&&draw(theme,dc,1,1,&r,0)==S_OK,"render_window_gradient");
        check(GetPixel(dc,9,7)==RGB(0,120,215)&&GetPixel(dc,38,7)==RGB(0,90,158),"independent_gradient_endpoints");
        x=0;for(y=7;y<29;++y)if(GetPixel(dc,9,y)!=RGB(0,120,215)||GetPixel(dc,38,y)!=RGB(0,90,158))++x;
        check(!x,"gradient_rows_consistent");check(close_theme(theme)==S_OK,"close_window_gradient");theme=0;
    }
cleanup:
    if(theme)check(close_theme(theme)==S_OK,"cleanup_theme");
    if(old&&old!=HGDI_ERROR)check(SelectObject(dc,old)==bitmap,"restore_original_bitmap");
    if(bitmap)check(DeleteObject(bitmap)!=0,"delete_dib");
    if(dc)check(DeleteDC(dc)!=0,"delete_memory_dc");
}
static LRESULT CALLBACK window_proc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp) {
    if(msg==WM_PAINT) {
        PAINTSTRUCT ps;HDC dc=BeginPaint(hwnd,&ps);RECT r={20,50,160,110};HTHEME t;
        if(!dc){check(0,"begin_window_paint");return 0;}
        check(select_style(1)==S_OK,"visible_select_classic");t=open_theme(0,L"BUTTON");
        check(t&&draw(t,dc,1,1,&r,0)==S_OK,"visible_classic_button");if(t)check(close_theme(t)==S_OK,"visible_close_classic");
        r.left=210;r.right=350;check(select_style(2)==S_OK,"visible_select_modern");t=open_theme(0,L"BUTTON");
        check(t&&draw(t,dc,1,1,&r,0)==S_OK,"visible_modern_button");if(t)check(close_theme(t)==S_OK,"visible_close_modern");
        check(GdiFlush()&&EndPaint(hwnd,&ps),"end_window_paint");++paints;return 0;
    }
    if(msg==WM_TIMER&&wp==7){PostQuitMessage(0);return 0;}
    return DefWindowProcW(hwnd,msg,wp,lp);
}
static void visible_trial(void) {
    WNDCLASSEXW wc;HINSTANCE instance=GetModuleHandleW(0);HWND window;MSG msg;int result;
    zero(&wc,sizeof wc);wc.cbSize=sizeof wc;wc.lpfnWndProc=window_proc;wc.hInstance=instance;
    wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);wc.lpszClassName=L"ThemeProbe64";
    check(GetSystemMetrics(SM_CXSCREEN)>=640&&GetSystemMetrics(SM_CYSCREEN)>=480,"real_display_available");
    if(!RegisterClassExW(&wc)){check(0,"register_probe_class");return;}check(1,"register_probe_class");
    window=CreateWindowExW(0,wc.lpszClassName,L"Shared theme: Classic / Modern",WS_OVERLAPPEDWINDOW|WS_VISIBLE,100,80,400,230,0,0,instance,0);
    check(window!=0,"create_visible_window");if(!window)goto unregister;
    check(UpdateWindow(window)&&paints>0,"dispatch_real_window_paint");
    check(SetTimer(window,7,5000,0)==7,"start_capture_timer");
    write_text("TP64 GUI READY ");write_text(TRIAL_NONCE);write_text("\r\n");
    while((result=GetMessageW(&msg,0,0,0))>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
    check(result==0&&msg.message==WM_QUIT&&msg.wParam==0,"normal_gui_loop_end");
    check(KillTimer(window,7)!=0,"remove_capture_timer");
    check(DestroyWindow(window)&&!IsWindow(window),"destroy_visible_window");
unregister:
    check(UnregisterClassW(wc.lpszClassName,instance)!=0,"unregister_probe_class");
}
void WINAPI ThemeProbeEntry(void) {
    HMODULE module=0;output=GetStdHandle(STD_OUTPUT_HANDLE);
    write_text("TP64 BEGIN ");write_text(TRIAL_NONCE);write_text("\r\n");
    check(relocation_anchor==&checks,"relocated_probe_anchor");
    module=LoadLibraryW(L"C:\\SHZ\\SYS64\\UXTHEME.DLL");check(module!=0,"load_frozen_theme_provider");if(!module)goto done;
    LOAD(select_style,set_style_fn,"M98SetThemeStyle");LOAD(current_style,get_style_fn,"M98GetThemeStyle");
    LOAD(active,active_fn,"IsThemeActive");LOAD(open_theme,open_fn,"OpenThemeData");LOAD(close_theme,close_fn,"CloseThemeData");
    LOAD(get_color,color_fn,"GetThemeColor");LOAD(get_margins,margin_fn,"GetThemeMargins");LOAD(get_content,content_fn,"GetThemeBackgroundContentRect");
    LOAD(get_size,size_fn,"GetThemePartSize");LOAD(draw,draw_fn,"DrawThemeBackground");LOAD(draw_ex,draw_ex_fn,"DrawThemeBackgroundEx");
    { union { FARPROC raw; draw_ex_fn typed; } fn; fn.typed=draw_ex;
      check(GetProcAddress(module,(LPCSTR)47)==fn.raw,"ordinal_47_matches_name"); }
    memory_trial();visible_trial();check(select_style(0)==S_OK&&!active(),"final_explicit_theme_off");
done:
    if(module)check(FreeLibrary(module)!=0,"unload_theme_provider");
    write_text("TP64 COUNTS checks=");number(checks);write_text(" failures=");number(failures);write_text(" paints=");number(paints);write_text("\r\n");
    write_text(failures||!output_ok?"TP64 FINAL FAIL ":"TP64 FINAL PASS ");write_text(TRIAL_NONCE);write_text("\r\n");
    ExitProcess(failures||!output_ok?1:0);
}
