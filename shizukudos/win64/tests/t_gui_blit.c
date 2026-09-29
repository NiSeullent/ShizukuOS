/* SPDX-License-Identifier: GPL-2.0-only
 * GUI: the raster operations on a WINDOW DC end to end (gdi32 backing bitmap -> NtGdiPresent -> kernel surface -> compositor
 * -> QEMU display). A frameless popup window at screen (100,100), 500x360, is painted with the scene below; the host runner
 * (run_k64_gui.py, scene "gdi") recomputes every pixel from this description and compares. Reports SKIP without a display.
 *
 * Client coordinates (white background from the class brush):
 *  A  BitBlt of a 256x64 DIB section at (10,10): pixel (x,y) = RGB(x, 255-x, 128)
 *  B  StretchBlt of the same bitmap to 128x32 at (10,90) (nearest neighbour)
 *  C  StretchDIBits of a bottom-up 4x4 24 bpp DIB to 32x32 at (300,10): source pixel (u,v from the top) = RGB(60u, 60v, 200)
 *  D  SetDIBitsToDevice of a top-down 8x8 32 bpp DIB at (300,60): pixel (u,v) = RGB(32u, 32v, 32(u^v))
 *  E  "Scale2" in a 32-pixel font (scale 2), opaque, black on RGB(255,255,192), at (10,140); "Bold" weight 700 at (10,180)
 *  F  an L-shaped clip region {(200,150)-(300,250)} + {(200,250)-(400,300)} and a PatBlt of the whole client with RGB(200,0,0)
 *  G  ten-pixel blue/yellow stripes over (10,240)-(110,300), then BitBlt(dc, 10,230, 100,60, dc, 10,240) scrolls them up by 10
 *  H  R2_XORPEN with a 1-pixel red pen over white (= cyan): a line (10,320)-(110,320); and a line (10,330)-(110,330) followed
 *     by the same line drawn back from the other end, (110,330)-(10,330): LineTo leaves out the last pixel, so only the two end
 *     pixels (10,330) and (110,330) stay cyan, the pixels between were XORed twice and are white again
 *  I  a triangle (420,20) (485,20) (452,73) filled RGB(255,128,0) with a NULL pen
 *  J  an ellipse in [420,480) x [100,160) filled RGB(0,200,255) with a NULL pen
 *  K  a box (450,300)-(470,320) RGB(255,0,255) drawn through GetDC/ReleaseDC outside WM_PAINT
 *  L  a box (5,5)-(25,25) RGB(128,255,0) drawn on the DESKTOP through GetDC(NULL) */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

static int bad;
#define CHECK(cond, name) do { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s (line %d)\n", name, __LINE__); ++bad; } } while (0)

static void fill(HDC dc, int l, int t, int r, int b, COLORREF c)
{
    HBRUSH br = CreateSolidBrush(c), old = SelectObject(dc, br);
    PatBlt(dc, l, t, r - l, b - t, PATCOPY);
    SelectObject(dc, old);
    DeleteObject(br);
}

static void scene(HDC dc)
{
    HDC mem = CreateCompatibleDC(dc);
    BITMAPINFO bi;
    unsigned *bits = 0;
    HBITMAP dib, old;
    int x, y;
    memset(&bi, 0, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = 256;
    bi.bmiHeader.biHeight = 64;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    dib = CreateDIBSection(mem, &bi, DIB_RGB_COLORS, (void **)&bits, 0, 0);
    old = SelectObject(mem, dib);
    for (y = 0; y < 64; ++y)
        for (x = 0; x < 256; ++x) bits[(63 - y) * 256 + x] = ((unsigned)x << 16) | ((unsigned)(255 - x) << 8) | 128u;
    BitBlt(dc, 10, 10, 256, 64, mem, 0, 0, SRCCOPY);                                                 /* A */
    StretchBlt(dc, 10, 90, 128, 32, mem, 0, 0, 256, 64, SRCCOPY);                                    /* B */
    SelectObject(mem, old);
    DeleteObject(dib);
    DeleteDC(mem);
    {                                                                                                /* C */
        struct { BITMAPINFOHEADER h; } bc;
        unsigned char rows[4 * 12];                                 /* 4 pixels x 3 bytes = 12 bytes per row, no padding needed */
        int u, v;
        memset(&bc, 0, sizeof bc);
        bc.h.biSize = sizeof bc.h; bc.h.biWidth = 4; bc.h.biHeight = 4; bc.h.biPlanes = 1; bc.h.biBitCount = 24;
        for (v = 0; v < 4; ++v)
            for (u = 0; u < 4; ++u) {
                unsigned char *p = &rows[(3 - v) * 12 + u * 3];     /* bottom-up: the top row (v=0) is stored last */
                p[0] = 200; p[1] = (unsigned char)(60 * v); p[2] = (unsigned char)(60 * u);
            }
        StretchDIBits(dc, 300, 10, 32, 32, 0, 0, 4, 4, rows, (BITMAPINFO *)&bc, DIB_RGB_COLORS, SRCCOPY);
    }
    {                                                                                                /* D */
        BITMAPINFO bd;
        unsigned px[64];
        int u, v;
        memset(&bd, 0, sizeof bd);
        bd.bmiHeader.biSize = sizeof bd.bmiHeader; bd.bmiHeader.biWidth = 8; bd.bmiHeader.biHeight = -8;
        bd.bmiHeader.biPlanes = 1; bd.bmiHeader.biBitCount = 32; bd.bmiHeader.biCompression = BI_RGB;
        for (v = 0; v < 8; ++v)
            for (u = 0; u < 8; ++u) px[v * 8 + u] = ((unsigned)(32 * u) << 16) | ((unsigned)(32 * v) << 8) | (unsigned)(32 * (u ^ v));
        SetDIBitsToDevice(dc, 300, 60, 8, 8, 0, 0, 0, 8, px, &bd, DIB_RGB_COLORS);
    }
    {                                                                                                /* E */
        HFONT f2 = CreateFontW(32, 0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0, 0, 0, L"any"), fb = CreateFontW(16, 0, 0, 0, FW_BOLD, 0, 0, 0, 0, 0, 0, 0, 0, L"any"), of;
        of = SelectObject(dc, f2);
        SetBkMode(dc, OPAQUE);
        SetBkColor(dc, RGB(255, 255, 192));
        SetTextColor(dc, RGB(0, 0, 0));
        TextOutW(dc, 10, 140, L"Scale2", 6);
        SelectObject(dc, fb);
        SetBkMode(dc, TRANSPARENT);
        TextOutW(dc, 10, 180, L"Bold", 4);
        SelectObject(dc, of);
        DeleteObject(f2);
        DeleteObject(fb);
    }
    {                                                                                                /* F */
        HRGN a = CreateRectRgn(200, 150, 300, 250), b = CreateRectRgn(200, 250, 400, 300), u = CreateRectRgn(0, 0, 1, 1);
        CombineRgn(u, a, b, RGN_OR);
        SelectClipRgn(dc, u);
        fill(dc, 0, 0, 500, 360, RGB(200, 0, 0));
        SelectClipRgn(dc, 0);
        DeleteObject(a); DeleteObject(b); DeleteObject(u);
    }
    for (y = 240; y < 300; ++y) fill(dc, 10, y, 110, y + 1, ((y - 240) / 10) % 2 == 0 ? RGB(0, 0, 255) : RGB(255, 255, 0));   /* G */
    BitBlt(dc, 10, 230, 100, 60, dc, 10, 240, SRCCOPY);
    {                                                                                                /* H */
        HPEN pen = CreatePen(PS_SOLID, 1, RGB(255, 0, 0)), op = SelectObject(dc, pen);
        SetROP2(dc, R2_XORPEN);
        MoveToEx(dc, 10, 320, 0); LineTo(dc, 110, 320);
        MoveToEx(dc, 10, 330, 0); LineTo(dc, 110, 330);
        MoveToEx(dc, 110, 330, 0); LineTo(dc, 10, 330);
        SetROP2(dc, R2_COPYPEN);
        SelectObject(dc, op);
        DeleteObject(pen);
    }
    {                                                                                                /* I, J */
        HBRUSH orange = CreateSolidBrush(RGB(255, 128, 0)), cyan = CreateSolidBrush(RGB(0, 200, 255)), ob;
        HPEN op = SelectObject(dc, GetStockObject(NULL_PEN));
        POINT tri[3] = { { 420, 20 }, { 485, 20 }, { 452, 73 } };
        ob = SelectObject(dc, orange);
        Polygon(dc, tri, 3);
        SelectObject(dc, cyan);
        Ellipse(dc, 420, 100, 480, 160);
        SelectObject(dc, ob);
        SelectObject(dc, op);
        DeleteObject(orange);
        DeleteObject(cyan);
    }
}

static LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        scene(dc);
        EndPaint(h, &ps);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

static void pump_ms(UINT ms)
{
    MSG msg;
    UINT_PTR id = SetTimer(0, 0, ms, 0);
    while (GetMessageW(&msg, 0, 0, 0) > 0) {
        if (msg.message == WM_TIMER && msg.hwnd == 0 && msg.wParam == id) break;
        DispatchMessageW(&msg);
    }
    KillTimer(0, id);
}

int main(void)
{
    WNDCLASSW wc;
    HWND h;
    HDC dc;
    HINSTANCE inst = GetModuleHandleW(0);
    if (GetSystemMetrics(SM_CXSCREEN) == 0) { printf("SKIP: no display device\n"); return 0; }
    memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = proc;
    wc.hInstance = inst;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ShzBlit";
    RegisterClassW(&wc);
    h = CreateWindowExW(0, L"ShzBlit", L"", WS_POPUP | WS_VISIBLE, 100, 100, 500, 360, 0, 0, inst, 0);
    CHECK(h != 0, "frameless popup window");
    if (!h) return 1;
    UpdateWindow(h);
    dc = GetDC(h);                                                                                   /* K */
    fill(dc, 450, 300, 470, 320, RGB(255, 0, 255));
    CHECK(GetPixel(dc, 460, 310) == RGB(255, 0, 255) && GetPixel(dc, 10, 10) == RGB(0, 255, 128), "GetPixel on the window DC reads what was drawn (backing bitmap)");
    ReleaseDC(h, dc);
    dc = GetDC(0);                                                                                   /* L */
    CHECK(dc != 0, "GetDC(NULL): the desktop DC");
    fill(dc, 5, 5, 25, 25, RGB(128, 255, 0));
    ReleaseDC(0, dc);
    {
        HDC probe = GetDC(h);
        CHECK(GetPixel(probe, 460, 310) == RGB(255, 0, 255), "a second DC of the same window sees the first one's drawing");
        ReleaseDC(h, probe);
    }
    printf("GUI-READY: gdi\n");
    pump_ms(1500);
    CHECK(DestroyWindow(h), "DestroyWindow");
    dc = GetDC(0);                                                   /* the desktop DC draws on the shared desktop: undo box L for the programs that follow */
    fill(dc, 5, 5, 25, 25, RGB(0, 128, 128));
    ReleaseDC(0, dc);
    printf("%s: window DC raster test\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
