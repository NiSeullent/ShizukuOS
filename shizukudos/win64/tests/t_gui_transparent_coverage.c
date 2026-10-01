/* SPDX-License-Identifier: GPL-2.0-only
 * Real HWND ownership and kernel compositor readback. The transparent child
 * intentionally erases/paints no pixels until an explicit real submission.
 * These are positive and negative raster contracts, not app/native98 proof.
 */
#include "k32test.h"
#include "shzgfx.h"
#define WIDTH 24
#define HEIGHT 18
#define MAXSIDE 64
#define DARK 0xff1e1f22u
#define GREEN 0xff224466u
#define RED 0xff102030u
#define BLUE 0xffabcdefu
#define FACE 0x00c0c0c0u
static DWORD view[WIDTH*HEIGHT];
static LRESULT CALLBACK window_proc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp)
{
    if (msg==WM_ERASEBKGND) return 1;
    if (msg==WM_PAINT) { PAINTSTRUCT ps; BeginPaint(hwnd,&ps); EndPaint(hwnd,&ps); return 0; }
    return DefWindowProcW(hwnd,msg,wp,lp);
}
static int32_t submit(HWND hwnd,DWORD color,int x,int y,int width,int height)
{
    DWORD pixels[MAXSIDE*MAXSIDE]; RECT client; shz_present_t p; unsigned i,n;
    if (!GetClientRect(hwnd,&client) || client.right<=0 || client.bottom<=0 ||
        client.right>MAXSIDE || client.bottom>MAXSIDE) return (int32_t)0xc000000du;
    n=(unsigned)client.right*(unsigned)client.bottom;
    for(i=0;i<n;++i) pixels[i]=color;
    memset(&p,0,sizeof p);p.hwnd=(uint64_t)(uintptr_t)hwnd;
    p.bits=(uint64_t)(uintptr_t)pixels;p.surf_w=client.right;p.surf_h=client.bottom;
    p.x=x;p.y=y;p.w=width;p.h=height;p.stride=(DWORD)client.right*4;
    return NtGdiPresent(&p);
}
static int snapshot(HWND hwnd)
{
    shz_winop_t o;
    memset(view,0x55,sizeof view);memset(&o,0,sizeof o);
    o.op=SHZ_WOP_PRINT;o.hwnd=(uint64_t)(uintptr_t)hwnd;o.flags=1;
    o.bits=(uint64_t)(uintptr_t)view;o.stride=WIDTH*4;o.w=WIDTH;o.h=HEIGHT;
    return NtUserWindowOp(&o)==0 && o.w==WIDTH && o.h==HEIGHT;
}
static DWORD pixel(int x,int y) { return view[y*WIDTH+x]; }
int main(void)
{
    WNDCLASSEXW wc; HWND parent=NULL,child=NULL,normal=NULL; DWORD old;
    DWORD *pages=NULL; shz_present_t bad; LONG_PTR previous;
    if (!GetSystemMetrics(SM_CXSCREEN)) { printf("T_GUI_TRANSPARENT_COVERAGE: no display; not executed\n");return 2; }
    memset(&wc,0,sizeof wc);wc.cbSize=sizeof wc;wc.hInstance=GetModuleHandleW(NULL);
    wc.lpfnWndProc=window_proc;wc.lpszClassName=L"ShzCoverageContract";
    CHECK(RegisterClassExW(&wc)!=0,"real no-background window class registers");
    parent=CreateWindowExW(0,wc.lpszClassName,L"Coverage",WS_POPUP|WS_VISIBLE,
        30,30,WIDTH,HEIGHT,NULL,NULL,wc.hInstance,NULL);
    CHECK(parent!=NULL,"actual visible parent HWND creates");if(!parent) goto done;
    CHECK(submit(parent,DARK,0,0,WIDTH,HEIGHT)==0,"actual parent receives dark caller-owned pixels");
    child=CreateWindowExW(WS_EX_TRANSPARENT,wc.lpszClassName,L"No paint",
        WS_CHILD|WS_VISIBLE,2,2,12,10,parent,NULL,wc.hInstance,NULL);
    CHECK(child!=NULL,"actual transparent child creates without submitted client pixels");if(!child) goto done;
    CHECK(snapshot(parent) && pixel(3,3)==DARK,
        "untouched transparent child preserves already drawn parent pixels");
    normal=CreateWindowExW(0,wc.lpszClassName,L"Opaque control",
        WS_CHILD|WS_VISIBLE,2,2,12,10,parent,NULL,wc.hInstance,NULL);
    CHECK(normal && snapshot(parent) && pixel(3,3)==FACE,
        "ordinary untouched child retains genuine opaque initial surface");
    if(normal) { CHECK(DestroyWindow(normal),"opaque negative control destroys");normal=NULL; }
    CHECK(submit(child,RED,2,2,3,2)==0,"transparent child submits a real partial colored rectangle");
    CHECK(snapshot(parent) && pixel(4,4)==RED && pixel(8,7)==DARK,
        "actual child pixels remain visible while untouched client area stays transparent");
    CHECK(submit(parent,GREEN,0,0,WIDTH,HEIGHT)==0 && snapshot(parent) &&
        pixel(4,4)==RED && pixel(8,7)==GREEN,
        "parent redraw updates untouched child areas and preserves actual child drawing");
    CHECK(submit(child,FACE,0,0,1,1)==0 && snapshot(parent) && pixel(2,2)==FACE,
        "explicit gray child pixel is genuine drawing rather than transparent color key");
    CHECK(submit(child,BLUE,11,9,1,1)==0,"actual old edge pixel submits before resizing");
    CHECK(SetWindowPos(child,NULL,2,2,16,12,SWP_NOZORDER|SWP_NOACTIVATE) && snapshot(parent) &&
        pixel(13,11)==BLUE && pixel(17,13)==GREEN,
        "grow preserves real overlap pixels and leaves new transparent area unpainted");
    CHECK(SetWindowPos(child,NULL,2,2,8,6,SWP_NOZORDER|SWP_NOACTIVATE) &&
        SetWindowPos(child,NULL,2,2,16,12,SWP_NOZORDER|SWP_NOACTIVATE) && snapshot(parent) &&
        pixel(4,4)==RED && pixel(13,11)==GREEN,
        "shrink then grow discards old clipped coverage and preserves surviving drawing");
    previous=SetWindowLongPtrW(child,GWL_EXSTYLE,0);
    CHECK((previous&WS_EX_TRANSPARENT) && snapshot(parent) && pixel(17,13)==FACE,
        "clearing transparent style restores actual opaque surface behavior");
    SetWindowLongPtrW(child,GWL_EXSTYLE,WS_EX_TRANSPARENT);
    CHECK(snapshot(parent) && pixel(17,13)==GREEN && pixel(4,4)==RED,
        "restoring transparent style retains real written coverage rather than inventing a full frame");
    pages=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    CHECK(pages!=NULL,"actual readable source and protected second row allocate");
    if(pages) {
        DWORD *row=(DWORD *)((BYTE *)pages+4096-16*4);unsigned i;
        for(i=0;i<16;++i) row[i]=BLUE;
        CHECK(VirtualProtect((BYTE *)pages+4096,4096,PAGE_NOACCESS,&old),"later source row becomes genuinely inaccessible");
        memset(&bad,0,sizeof bad);bad.hwnd=(uint64_t)(uintptr_t)child;
        bad.bits=(uint64_t)(uintptr_t)row;bad.surf_w=16;bad.surf_h=12;bad.stride=16*4;
        bad.x=6;bad.w=bad.h=2;
        CHECK(NtGdiPresent(&bad)==(int32_t)0xc0000005u && snapshot(parent) && pixel(8,2)==GREEN,
            "failed later-row staging writes no child pixels or phantom coverage");
        CHECK(VirtualFree(pages,0,MEM_RELEASE),"protected caller source releases");pages=NULL;
    }
    CHECK(DestroyWindow(child),"transparent child releases real window and retained drawing");child=NULL;
    CHECK(snapshot(parent) && pixel(4,4)==GREEN && pixel(2,2)==GREEN,
        "destroyed child leaves only actual underlying parent pixels");
done:
    if(pages) VirtualFree(pages,0,MEM_RELEASE);
    if(normal) DestroyWindow(normal);
    if(child) DestroyWindow(child);
    if(parent) CHECK(DestroyWindow(parent),"parent HWND destroys");
    CHECK(UnregisterClassW(wc.lpszClassName,wc.hInstance),"owned class unregisters");
    return k32t_finish("T_GUI_TRANSPARENT_COVERAGE");
}
