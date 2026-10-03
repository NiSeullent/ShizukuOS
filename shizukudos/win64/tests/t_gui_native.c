/* SPDX-License-Identifier: GPL-2.0-only
 * T_GUI_NATIVE: PE32+ interaction fixture for the native W64 GUI frame pull (abi/shz_w64_gui.h). A 160x96 client
 * window paints a known scene (blue field, white band, black text); each key or left click toggles the band to
 * red and repaints (input coupling is visible in the next pulled frame). WM_CLOSE -> DestroyWindow ->
 * WM_DESTROY -> PostQuitMessage(7): exit code 7 means the application itself handled the close request. A 45 s
 * timer bounds the run (exit code 3). Not evidence by itself; root runs it under the presenter in a VM.
 * Display requirement: the run is valid only over a real K64 display, i.e. a gfx_fb scanout backend or the
 * w64-hosted private back buffer (the presenter reports which via NTW64_GUI_VIEW.display_backend). Without one the
 * fixture fails explicitly (0x20 no screen, 0x22 no window); it never claims software GOP or acceleration. */
#include <windows.h>
#include "shzcrt.h"

static int toggled, presses;

static LRESULT CALLBACK proc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    switch (m) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        RECT r = { 0, 0, 160, 96 }, band = { 0, 32, 160, 64 };
        HDC dc = BeginPaint(h, &ps);
        HBRUSH blue = CreateSolidBrush(RGB(0, 0, 255)), b2 = CreateSolidBrush(toggled ? RGB(255, 0, 0) : RGB(255, 255, 255));
        FillRect(dc, &r, blue);
        FillRect(dc, &band, b2);
        SetBkMode(dc, TRANSPARENT);
        TextOutW(dc, 4, 40, toggled ? L"PRESSED" : L"READY", toggled ? 7 : 5);
        DeleteObject(blue);
        DeleteObject(b2);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_KEYDOWN: case WM_LBUTTONDOWN:
        toggled = !toggled; ++presses;
        InvalidateRect(h, NULL, FALSE);
        return 0;
    case WM_TIMER:
        PostQuitMessage(3);
        return 0;
    case WM_CLOSE: DestroyWindow(h); return 0;
    case WM_DESTROY: PostQuitMessage(7); return 0;
    }
    return DefWindowProcW(h, m, wp, lp);
}

int main(int argc, char **argv)
{
    WNDCLASSW wc;
    RECT rc = { 0, 0, 160, 96 };
    HWND h;
    MSG msg;
    (void)argc; (void)argv;
    if (GetSystemMetrics(SM_CXSCREEN) < 160 || GetSystemMetrics(SM_CYSCREEN) < 96) {
        printf("T_GUI_NATIVE FAIL no K64 display (scanout or hosted-private backend required)\n");
        return 0x20;
    }
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = proc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"TGuiNative";
    if (!RegisterClassW(&wc)) return 0x21;
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);
    h = CreateWindowExW(0, wc.lpszClassName, L"T_GUI_NATIVE", WS_OVERLAPPEDWINDOW, 40, 40, rc.right - rc.left,
                        rc.bottom - rc.top, NULL, NULL, wc.hInstance, NULL);
    if (!h) { printf("T_GUI_NATIVE FAIL CreateWindowExW (no display/window manager)\n"); return 0x22; }
    ShowWindow(h, SW_SHOWNORMAL);
    UpdateWindow(h);
    SetTimer(h, 1, 45000, NULL);
    while (GetMessageW(&msg, NULL, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    printf("T_GUI_NATIVE exit=%d presses=%d\n", (int)msg.wParam, presses);
    return (int)msg.wParam;
}
