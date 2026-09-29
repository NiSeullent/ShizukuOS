/* SPDX-License-Identifier: GPL-2.0-only
 * GUI: one overlapped window, class registration, creation message order, WM_PAINT drawing a known scene (rectangles, a line,
 * text), a WM_TIMER that ends the message loop. The scene is left on screen for the host runner (run_k64_gui.py), which
 * verifies the pixels QEMU shows against its own computation of the scene documented in the paint routine below.
 * Reports SKIP and exits 0 when there is no display. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

static int bad;
#define CHECK(cond, name) do { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s (line %d)\n", name, __LINE__); ++bad; } } while (0)

static UINT g_log[64];
static int g_nlog, g_paints, g_destroy, g_ncdestroy, g_timers;
static int index_of(UINT m) { int i; for (i = 0; i < g_nlog; ++i) if (g_log[i] == m) return i; return -1; }

/* Scene, in client coordinates (client area of the window is 392 x 273):
 *   background white (class brush COLOR_WINDOW+1, erased through WM_ERASEBKGND by BeginPaint)
 *   red   rectangle [20,120) x [20,80)   (FillRect, RGB 255,0,0)
 *   blue  rectangle [150,250) x [20,80)  (FillRect, RGB 0,0,255)
 *   green 1-pixel line from (20,200) to (120,200), end point excluded (RGB 0,160,0)
 *   black text "Hello GUI" at (20,100), transparent background, built-in 8x16 font
 *   gray  rectangle [300,380) x [200,260) drawn with a 2-pixel dark-gray pen and a light-gray brush via Rectangle() */
static void paint_scene(HDC dc)
{
    RECT r;
    HBRUSH b;
    HPEN pen, op;
    HBRUSH lb, ob;
    r.left = 20; r.top = 20; r.right = 120; r.bottom = 80;
    b = CreateSolidBrush(RGB(255, 0, 0));
    FillRect(dc, &r, b);
    DeleteObject(b);
    r.left = 150; r.right = 250;
    b = CreateSolidBrush(RGB(0, 0, 255));
    FillRect(dc, &r, b);
    DeleteObject(b);
    pen = CreatePen(PS_SOLID, 1, RGB(0, 160, 0));
    op = SelectObject(dc, pen);
    MoveToEx(dc, 20, 200, 0);
    LineTo(dc, 120, 200);
    SelectObject(dc, op);
    DeleteObject(pen);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(0, 0, 0));
    TextOutW(dc, 20, 100, L"Hello GUI", 9);
    pen = CreatePen(PS_SOLID, 2, RGB(64, 64, 64));
    lb = CreateSolidBrush(RGB(200, 200, 200));
    op = SelectObject(dc, pen);
    ob = SelectObject(dc, lb);
    Rectangle(dc, 300, 200, 380, 260);
    SelectObject(dc, op);
    SelectObject(dc, ob);
    DeleteObject(pen);
    DeleteObject(lb);
}

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_NCCREATE: case WM_CREATE: case WM_SIZE: case WM_MOVE: case WM_SHOWWINDOW:
        if (g_nlog < 64) g_log[g_nlog++] = m;
        break;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        paint_scene(dc);
        EndPaint(h, &ps);
        ++g_paints;
        return 0;
    }
    case WM_TIMER:
        ++g_timers;
        if (w == 7) PostQuitMessage(42);
        return 0;
    case WM_DESTROY: ++g_destroy; return 0;
    case WM_NCDESTROY: ++g_ncdestroy; break;
    }
    return DefWindowProcW(h, m, w, l);
}

int main(void)
{
    WNDCLASSEXW wc;
    HWND hwnd;
    RECT wr, cr, ar;
    MSG msg;
    ATOM atom;
    int r;
    HINSTANCE inst = GetModuleHandleW(0);
    if (GetSystemMetrics(SM_CXSCREEN) == 0) { printf("SKIP: no display device\n"); return 0; }
    CHECK(GetSystemMetrics(SM_CXSCREEN) == 1024 && GetSystemMetrics(SM_CYSCREEN) == 768, "GetSystemMetrics reports the 1024x768 display");
    memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ShzGuiWindow";
    atom = RegisterClassExW(&wc);
    CHECK(atom != 0, "RegisterClassExW");
    CHECK(RegisterClassExW(&wc) == 0 && GetLastError() == ERROR_CLASS_ALREADY_EXISTS, "registering the class twice fails with ERROR_CLASS_ALREADY_EXISTS");
    hwnd = CreateWindowExW(0, L"ShzGuiWindow", L"Shizuku Test", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 80, 400, 300, 0, 0, inst, 0);
    CHECK(hwnd != 0, "CreateWindowExW");
    if (!hwnd) return 1;
    CHECK(index_of(WM_NCCREATE) == 0 && index_of(WM_CREATE) == 1 && index_of(WM_SIZE) > index_of(WM_CREATE) && index_of(WM_MOVE) > index_of(WM_CREATE) &&
          index_of(WM_SHOWWINDOW) > index_of(WM_SIZE), "creation messages arrive as NCCREATE, CREATE, SIZE, MOVE, SHOWWINDOW");
    GetWindowRect(hwnd, &wr);
    GetClientRect(hwnd, &cr);
    CHECK(wr.left == 100 && wr.top == 80 && wr.right == 500 && wr.bottom == 380, "GetWindowRect is the requested rectangle");
    CHECK(cr.left == 0 && cr.top == 0 && cr.right == 392 && cr.bottom == 273, "client area = window minus 4 px frame and 19 px caption");
    ar.left = 0; ar.top = 0; ar.right = 392; ar.bottom = 273;
    AdjustWindowRectEx(&ar, WS_OVERLAPPEDWINDOW, FALSE, 0);
    CHECK(ar.right - ar.left == 400 && ar.bottom - ar.top == 300, "AdjustWindowRectEx is the inverse of the client computation");
    CHECK(IsWindow(hwnd) && IsWindowVisible(hwnd) && GetForegroundWindow() == hwnd && GetActiveWindow() == hwnd, "the new visible window is active and foreground");
    {
        WCHAR t[32];
        WCHAR cn[32];
        DWORD pid = 0;
        CHECK(GetWindowTextW(hwnd, t, 32) == 12 && t[0] == 'S' && t[11] == 't', "GetWindowTextW");
        CHECK(GetClassNameW(hwnd, cn, 32) == 12 && cn[0] == 'S', "GetClassNameW");
        CHECK(GetWindowThreadProcessId(hwnd, &pid) == GetCurrentThreadId() && pid == GetCurrentProcessId(), "GetWindowThreadProcessId");
    }
    r = UpdateWindow(hwnd);
    CHECK(r && g_paints == 1, "UpdateWindow delivers the pending WM_PAINT synchronously");
    CHECK(!GetUpdateRect(hwnd, &ar, FALSE), "the update region is empty after painting");
    CHECK(SetTimer(hwnd, 7, 1500, 0) == 7, "SetTimer with an explicit id returns that id");
    printf("GUI-READY: window\n");
    while ((r = GetMessageW(&msg, 0, 0, 0)) > 0) {                 /* the host takes its screendump while we sit here */
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    CHECK(r == 0 && msg.message == WM_QUIT && msg.wParam == 42, "GetMessage returns 0 for WM_QUIT with the exit code in wParam");
    CHECK(g_timers == 1, "the 1500 ms timer fired exactly once before the loop ended");
    CHECK(g_paints == 1, "the window was painted exactly once");
    CHECK(DestroyWindow(hwnd) && g_destroy == 1 && g_ncdestroy == 1 && !IsWindow(hwnd), "DestroyWindow sends WM_DESTROY and WM_NCDESTROY and invalidates the handle");
    CHECK(UnregisterClassW(L"ShzGuiWindow", inst), "UnregisterClassW after the last window is gone");
    printf("%s: window test\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
