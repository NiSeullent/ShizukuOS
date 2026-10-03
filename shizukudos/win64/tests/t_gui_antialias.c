/* SPDX-License-Identifier: GPL-2.0-only
 * Guest-side grayscale text acceptance. Exercises public Win32 calls and
 * independently compares DIB pixels; no host screenshot smoothing. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

#define W 320
#define H 64
static int failures;
static int painted;
static const WCHAR sample[] = L"Shizuku \uD55C\uAE00 \uC624\uB958";
#define CHECK(c, label) do { \
    int check_ok = !!(c); \
    printf("SHZ-AA %s %s\n", check_ok ? "PASS" : "FAIL", label); \
    if (!check_ok) ++failures; \
} while (0)

static HFONT make_font(int height, BYTE quality)
{
    return CreateFontW(-height, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, quality,
        DEFAULT_PITCH, L"Shizuku Sans");
}

static unsigned channel(unsigned p, int shift) { return (p >> shift) & 255; }
static int near_channel(unsigned got, unsigned expected)
{
    return got == expected || got + 1 == expected || got == expected + 1;
}

static void memory_check(int height, int bottom_up)
{
    BITMAPINFO info;
    HDC dc = CreateCompatibleDC(0);
    HBITMAP bm = 0, old_bm = 0;
    HFONT font = make_font(height, ANTIALIASED_QUALITY), old_font = 0;
    unsigned *bits = 0;
    static unsigned alpha[W * H];
    int i, gray = 0, black = 0, white = 0, composed = 1, clipped = 1, clip_ink = 0;
    SIZE extent;
    const unsigned background = 0x173149, foreground = 0xcbe5ff;
    memset(&info, 0, sizeof info);
    info.bmiHeader.biSize = sizeof info.bmiHeader;
    info.bmiHeader.biWidth = W;
    info.bmiHeader.biHeight = bottom_up ? H : -H;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    if (dc) bm = CreateDIBSection(dc, &info, DIB_RGB_COLORS, (void **)&bits, 0, 0);
    if (!dc || !bm || !bits || !font) {
        CHECK(0, "memory-DC allocation");
        goto cleanup;
    }
    old_bm = (HBITMAP)SelectObject(dc, bm);
    old_font = (HFONT)SelectObject(dc, font);
    if (!old_bm || old_bm == (HBITMAP)HGDI_ERROR || !old_font || old_font == (HFONT)HGDI_ERROR) {
        CHECK(0, "select target and font");
        goto cleanup;
    }
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(255, 255, 255));
    for (i = 0; i < W * H; ++i) bits[i] = 0;
    CHECK(TextOutW(dc, 8, 8, sample, (int)lstrlenW(sample)), "TextOutW ASCII and Hangul");
    GdiFlush();
    for (i = 0; i < W * H; ++i) {
        unsigned p = bits[i] & 0xffffff;
        alpha[i] = channel(p, 0);
        if (!p) ++black;
        else if (p == 0xffffff) ++white;
        else if (channel(p, 16) == alpha[i] && channel(p, 8) == alpha[i]) ++gray;
        else composed = 0;
    }
    CHECK(gray > 0 && black > 0 && white > 0 && composed, "real grayscale edge coverage 1..254");
    CHECK(GetTextExtentPoint32W(dc, sample, (int)lstrlenW(sample), &extent) &&
          extent.cx > 0 && extent.cx <= W - 8 && extent.cy > 0 && extent.cy <= H - 8,
          "text measurement fits actual render target");
    for (i = 0; i < W * H; ++i) bits[i] = 0xa5000000u | background;
    SetTextColor(dc, RGB(203, 229, 255));
    CHECK(TextOutW(dc, 8, 8, sample, (int)lstrlenW(sample)), "transparent draw over colored destination");
    GdiFlush();
    composed = 1;
    for (i = 0; i < W * H; ++i) {
        int shift;
        if ((bits[i] >> 24) != 0xa5) composed = 0;
        for (shift = 0; shift <= 16; shift += 8) {
            unsigned a = alpha[i], expected = (channel(foreground, shift) * a +
                channel(background, shift) * (255 - a) + 127) / 255;
            if (!near_channel(channel(bits[i], shift), expected)) composed = 0;
        }
    }
    CHECK(composed, "coverage blends actual RGB and preserves destination high byte");
    for (i = 0; i < W * H; ++i) bits[i] = background;
    IntersectClipRect(dc, 12, 9, 96, 30);
    CHECK(TextOutW(dc, 8, 8, sample, (int)lstrlenW(sample)), "clipped AA text draw");
    GdiFlush();
    for (i = 0; i < W * H; ++i) {
        int x = i % W, y = bottom_up ? H - 1 - i / W : i / W;
        if ((x < 12 || x >= 96 || y < 9 || y >= 30) && (bits[i] & 0xffffff) != background) clipped = 0;
        if (x >= 12 && x < 96 && y >= 9 && y < 30 && (bits[i] & 0xffffff) != background) ++clip_ink;
    }
    CHECK(clipped && clip_ink > 0, "AA respects clipping and paints inside clip in both DIB directions");
    printf("SHZ-AA PIXELS height=%d bottom_up=%d intermediate=%d\n", height, bottom_up, gray);
cleanup:
    if (old_font && old_font != (HFONT)HGDI_ERROR) SelectObject(dc, old_font);
    if (old_bm && old_bm != (HBITMAP)HGDI_ERROR) SelectObject(dc, old_bm);
    if (font) DeleteObject(font);
    if (bm) DeleteObject(bm);
    if (dc) DeleteDC(dc);
}

static LRESULT CALLBACK scene(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        RECT bounds;
        HBRUSH brush = CreateSolidBrush(RGB(23, 49, 73));
        HFONT font = make_font(20, ANTIALIASED_QUALITY), old;
        GetClientRect(hwnd, &bounds);
        FillRect(dc, &bounds, brush);
        DeleteObject(brush);
        old = (HFONT)SelectObject(dc, font);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, RGB(203, 229, 255));
        TextOutW(dc, 24, 24, sample, (int)lstrlenW(sample));
        SelectObject(dc, old);
        DeleteObject(font);
        font = make_font(28, ANTIALIASED_QUALITY);
        old = (HFONT)SelectObject(dc, font);
        {
            static const WCHAR title[] = L"ShizukuOS \uC548\uD2F0\uC5D0\uC77C\uB9AC\uC5B4\uC2F1";
            TextOutW(dc, 24, 80, title, (int)lstrlenW(title));
        }
        SelectObject(dc, old);
        DeleteObject(font);
        if (EndPaint(hwnd, &ps)) {
            ++painted;
            printf("SHZ-AA PAINT count=%d\n", painted);
        }
        return 0;
    }
    if (msg == WM_TIMER || msg == WM_CLOSE) { DestroyWindow(hwnd); return 0; }
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int main(void)
{
    WNDCLASSW wc;
    HWND hwnd;
    MSG msg;
    memory_check(20, 0);
    memory_check(28, 1);
    printf("SHZ-AA RESULT failures=%d\n", failures);
    if (failures) return 1;
    memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = scene;
    wc.hInstance = GetModuleHandleW(0);
    wc.lpszClassName = L"ShizukuAaAcceptance";
    if (!RegisterClassW(&wc)) return 2;
    hwnd = CreateWindowExW(0, wc.lpszClassName, L"ShizukuOS - Grayscale AA", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        48, 48, 560, 240, 0, 0, wc.hInstance, 0);
    if (!hwnd) return 3;
    UpdateWindow(hwnd);
    if (!painted) { DestroyWindow(hwnd); return 5; }
    if (!SetTimer(hwnd, 1, 12000, 0)) { DestroyWindow(hwnd); return 4; }
    printf("SHZ-AA SCENE READY\n");
    while (GetMessageW(&msg, 0, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return 0;
}
