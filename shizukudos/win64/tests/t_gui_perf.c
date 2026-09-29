/* SPDX-License-Identifier: GPL-2.0-only
 * GUI: the paths a software compositor (Chromium's software output device) uses to put frames on a window, measured and
 * checked for exactness: BitBlt from a DIB-section memory DC, StretchDIBits and SetDIBitsToDevice at 1:1, many small
 * dirty rectangles per frame, and a 2x StretchBlt. Every timing line is "PERF: <what> <ms per frame>" (TCG timings are
 * only comparable within one machine); every result is checked pixel by pixel against the source through PrintWindow
 * (what the compositor really holds), plus GetPixel spot checks. Reports SKIP without a display. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

static int bad;
#define CHECK(cond, name) do { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s (line %d)\n", name, __LINE__); ++bad; } } while (0)

#define FW 640
#define FH 480
#define FRAMES 12

static uint32_t src_px(int x, int y, int frame) { return (uint32_t)((x * 3 + frame * 17) & 255) << 16 | (uint32_t)((y * 5 + frame) & 255) << 8 | (uint32_t)((x ^ y) & 255); }

static void fill_frame(uint32_t *bits, int frame)
{
    int x, y;
    for (y = 0; y < FH; ++y)
        for (x = 0; x < FW; ++x) bits[y * FW + x] = src_px(x, y, frame);
}

/* the window's client pixels as the compositor holds them, compared with frame `frame` */
static int client_matches(HWND hwnd, int frame, int *bad_x, int *bad_y)
{
    HDC sdc = GetDC(0), mem = CreateCompatibleDC(sdc);
    BITMAPINFO bi;
    uint32_t *bits = 0;
    HBITMAP dib, old;
    int x, y, ok = 1;
    memset(&bi, 0, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = FW;
    bi.bmiHeader.biHeight = -FH;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    dib = CreateDIBSection(sdc, &bi, DIB_RGB_COLORS, (void **)&bits, 0, 0);
    old = SelectObject(mem, dib);
    if (!PrintWindow(hwnd, mem, PW_CLIENTONLY)) ok = 0;
    for (y = 0; y < FH && ok; ++y)
        for (x = 0; x < FW; ++x)
            if ((bits[y * FW + x] & 0xffffff) != src_px(x, y, frame)) { ok = 0; *bad_x = x; *bad_y = y; break; }
    SelectObject(mem, old);
    DeleteObject(dib);
    DeleteDC(mem);
    ReleaseDC(0, sdc);
    return ok;
}

static void report(const char *what, DWORD ms, int frames)
{
    printf("PERF: %s %u.%02u ms/frame\n", what, (unsigned)(ms / frames), (unsigned)((ms % frames) * 100 / frames));
}

int main(void)
{
    WNDCLASSEXW wc;
    HWND hwnd;
    HDC sdc, mem, wdc;
    BITMAPINFO bi;
    uint32_t *bits = 0;
    HBITMAP dib, old;
    DWORD t0, t;
    int f, bx = -1, by = -1;
    RECT wr;
    if (GetSystemMetrics(SM_CXSCREEN) == 0) { printf("SKIP: no display device\n"); return 0; }
    memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(0);
    wc.lpszClassName = L"ShzPerf";
    RegisterClassExW(&wc);
    wr.left = 0; wr.top = 0; wr.right = FW; wr.bottom = FH;
    AdjustWindowRectEx(&wr, WS_OVERLAPPEDWINDOW, FALSE, 0);
    hwnd = CreateWindowExW(0, L"ShzPerf", L"Frames", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 40, 40, wr.right - wr.left, wr.bottom - wr.top, 0, 0, wc.hInstance, 0);
    if (!hwnd) { printf("FAIL: CreateWindowExW\n"); return 1; }
    UpdateWindow(hwnd);
    sdc = GetDC(0);
    memset(&bi, 0, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = FW;
    bi.bmiHeader.biHeight = -FH;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    dib = CreateDIBSection(sdc, &bi, DIB_RGB_COLORS, (void **)&bits, 0, 0);
    mem = CreateCompatibleDC(sdc);
    old = SelectObject(mem, dib);

    /* 1. BitBlt of whole frames from the DIB section (Chromium's SoftwareOutputDeviceWin path) */
    t0 = GetTickCount();
    for (f = 0; f < FRAMES; ++f) {
        fill_frame(bits, f);
        wdc = GetDC(hwnd);
        BitBlt(wdc, 0, 0, FW, FH, mem, 0, 0, SRCCOPY);
        ReleaseDC(hwnd, wdc);
    }
    t = GetTickCount() - t0;
    report("BitBlt 640x480 SRCCOPY (incl. filling the source)", t, FRAMES);
    CHECK(client_matches(hwnd, FRAMES - 1, &bx, &by), "BitBlt: the compositor holds the last frame exactly");

    /* 2. StretchDIBits at 1:1 from the same memory */
    t0 = GetTickCount();
    for (f = 0; f < FRAMES; ++f) {
        fill_frame(bits, f + 100);
        wdc = GetDC(hwnd);
        StretchDIBits(wdc, 0, 0, FW, FH, 0, 0, FW, FH, bits, &bi, DIB_RGB_COLORS, SRCCOPY);
        ReleaseDC(hwnd, wdc);
    }
    t = GetTickCount() - t0;
    report("StretchDIBits 640x480 1:1", t, FRAMES);
    CHECK(client_matches(hwnd, FRAMES - 1 + 100, &bx, &by), "StretchDIBits 1:1: exact");

    /* 3. SetDIBitsToDevice with a bottom-up DIB */
    {
        BITMAPINFO bu = bi;
        uint32_t *up = HeapAlloc(GetProcessHeap(), 0, (size_t)FW * FH * 4);
        int y;
        bu.bmiHeader.biHeight = FH;
        t0 = GetTickCount();
        for (f = 0; f < FRAMES; ++f) {
            fill_frame(bits, f + 200);
            for (y = 0; y < FH; ++y) memcpy(up + (size_t)(FH - 1 - y) * FW, bits + (size_t)y * FW, FW * 4);
            wdc = GetDC(hwnd);
            SetDIBitsToDevice(wdc, 0, 0, FW, FH, 0, 0, 0, FH, up, &bu, DIB_RGB_COLORS);
            ReleaseDC(hwnd, wdc);
        }
        t = GetTickCount() - t0;
        report("SetDIBitsToDevice 640x480 bottom-up", t, FRAMES);
        CHECK(client_matches(hwnd, FRAMES - 1 + 200, &bx, &by), "SetDIBitsToDevice bottom-up: exact");
        HeapFree(GetProcessHeap(), 0, up);
    }

    /* 4. many small damaged rectangles per frame (a blinking caret, a spinner, ...): 16 tiles of 24x24 */
    {
        int k;
        fill_frame(bits, 300);
        wdc = GetDC(hwnd);
        BitBlt(wdc, 0, 0, FW, FH, mem, 0, 0, SRCCOPY);
        ReleaseDC(hwnd, wdc);
        t0 = GetTickCount();
        for (f = 0; f < FRAMES * 4; ++f) {
            wdc = GetDC(hwnd);
            for (k = 0; k < 16; ++k) {
                const int x = (k * 157 + f * 31) % (FW - 24), y = (k * 97 + f * 13) % (FH - 24);
                BitBlt(wdc, x, y, 24, 24, mem, x, y, SRCCOPY);
            }
            ReleaseDC(hwnd, wdc);
        }
        t = GetTickCount() - t0;
        report("16 scattered 24x24 BitBlts", t, FRAMES * 4);
        CHECK(client_matches(hwnd, 300, &bx, &by), "scattered small BitBlts: exact");
    }

    /* 5. a 2x StretchBlt (nearest neighbour) of a quarter frame */
    {
        HDC w2;
        int x, y, ok = 1;
        fill_frame(bits, 400);
        t0 = GetTickCount();
        for (f = 0; f < FRAMES; ++f) {
            w2 = GetDC(hwnd);
            StretchBlt(w2, 0, 0, FW, FH, mem, 0, 0, FW / 2, FH / 2, SRCCOPY);
            ReleaseDC(hwnd, w2);
        }
        t = GetTickCount() - t0;
        report("StretchBlt 320x240 -> 640x480", t, FRAMES);
        w2 = GetDC(hwnd);
        for (y = 0; y < FH && ok; y += 7)
            for (x = 0; x < FW; x += 5)
                if ((GetPixel(w2, x, y) & 0xffffff) != (COLORREF)(((src_px(x / 2, y / 2, 400) >> 16) & 255) | (src_px(x / 2, y / 2, 400) & 0xff00) |
                                                                 ((src_px(x / 2, y / 2, 400) & 255) << 16))) { ok = 0; bx = x; by = y; break; }
        ReleaseDC(hwnd, w2);
        CHECK(ok, "StretchBlt 2x: every sampled pixel is its nearest source pixel");
    }
    if (bx >= 0) printf("first mismatch at (%d,%d)\n", bx, by);
    SelectObject(mem, old);
    DeleteObject(dib);
    DeleteDC(mem);
    ReleaseDC(0, sdc);
    DestroyWindow(hwnd);
    printf("%s: frame paths\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
