/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS native Win64 GUI frontend: actual Windows 98 HWND, DIB section present, input capture, exit.
 * Original code. Pixels only ever reach the DIB through szwin_present of a complete CRC-verified frame. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "szwin_w98.h"

#define CLASS_NAME "ShizukuW64View"

static struct {
    szwin_table table;
    szwin_handle handle;
    szwin_fb fb;
    szwin_w98_result *result;
    HWND hwnd;
    HDC memory_dc;
    HBITMAP dib, old_bitmap;
    void *dib_bits;
    uint32_t *buffers;
    uint32_t width, height;
    int active;
} g;

static void fail(int status, int platform)
{
    if (g.result->status != SZWIN_OK) return;
    g.result->status = status;
    if (platform) g.result->platform_error = GetLastError();
}

static uint32_t modifier_flags(void)
{
    uint32_t f = 0;
    if (GetKeyState(VK_SHIFT) < 0) f |= SZWIN_EVF_SHIFT;
    if (GetKeyState(VK_CONTROL) < 0) f |= SZWIN_EVF_CTRL;
    if (GetKeyState(VK_MENU) < 0) f |= SZWIN_EVF_ALT;
    return f;
}

static void queue_event(uint32_t kind, LPARAM lp, WPARAM wp, int is_key)
{
    szwin_event ev;
    int r;
    ev.kind = kind; ev.flags = modifier_flags(); ev.sequence = 0; ev.clock_ms = GetTickCount();
    if (is_key) {
        ev.x = ev.y = 0;
        ev.key = (uint32_t)(wp & 0xFFu);
        ev.scancode = (uint32_t)((lp >> 16) & 0x1FFu);
        if (!ev.key) return;
    } else {
        ev.x = (int32_t)(short)LOWORD(lp);
        ev.y = (int32_t)(short)HIWORD(lp);
        ev.key = ev.scancode = 0;
    }
    r = szwin_input_push(&g.table, g.handle, &ev, 0);
    if (r == SZWIN_OK) { ++g.result->inputs_queued; return; }
    /* CLOSING refuses new input by design; anything else (queue full, stale) is an observable failure */
    if (r != SZWIN_E_STATE) fail(r, 0);
}

static LRESULT CALLBACK view_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (!g.active || hwnd != g.hwnd) return DefWindowProcA(hwnd, msg, wp, lp);
    switch (msg) {
    case WM_MOUSEMOVE:   queue_event(SZWIN_EV_MOVE, lp, wp, 0); return 0;
    case WM_LBUTTONDOWN: queue_event(SZWIN_EV_LDOWN, lp, wp, 0); return 0;
    case WM_LBUTTONUP:   queue_event(SZWIN_EV_LUP, lp, wp, 0); return 0;
    case WM_RBUTTONDOWN: queue_event(SZWIN_EV_RDOWN, lp, wp, 0); return 0;
    case WM_RBUTTONUP:   queue_event(SZWIN_EV_RUP, lp, wp, 0); return 0;
    case WM_KEYDOWN: case WM_SYSKEYDOWN: queue_event(SZWIN_EV_KEYDOWN, lp, wp, 1); return 0;
    case WM_KEYUP:   case WM_SYSKEYUP:   queue_event(SZWIN_EV_KEYUP, lp, wp, 1); return 0;
    case WM_CLOSE: {
        int r = szwin_close_request(&g.table, g.handle);
        if (r != SZWIN_OK && r != SZWIN_E_STATE) fail(r, 0);
        return 0;                               /* the W64 application decides its own lifetime */
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        if (!dc) { fail(SZWIN_W98_E_PLATFORM, 1); return 0; }
        if (szwin_lookup(&g.table, g.handle) && szwin_lookup(&g.table, g.handle)->has_frame) {
            if (!BitBlt(dc, 0, 0, (int)g.width, (int)g.height, g.memory_dc, 0, 0, SRCCOPY) || !GdiFlush())
                fail(SZWIN_W98_E_PLATFORM, 1);
            else ++g.result->presents;
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    default:
        return DefWindowProcA(hwnd, msg, wp, lp);
    }
}

static int open_view(const char *title, uint32_t width, uint32_t height)
{
    WNDCLASSA wc;
    RECT rc;
    BITMAPINFO bi;
    HDC screen;
    HANDLE heap = GetProcessHeap();
    uint32_t pixels = width * height;
    int r;

    g.buffers = (uint32_t *)HeapAlloc(heap, HEAP_ZERO_MEMORY, (SIZE_T)pixels * 8u);
    if (!g.buffers) { fail(SZWIN_W98_E_PLATFORM, 1); return 0; }
    r = szwin_create(&g.table, width, height, 0, 0, g.buffers, g.buffers + pixels, (size_t)pixels * 4u, &g.handle);
    if (r != SZWIN_OK) { fail(r, 0); return 0; }

    wc.style = 0; wc.lpfnWndProc = view_proc; wc.cbClsExtra = wc.cbWndExtra = 0;
    wc.hInstance = GetModuleHandleA(NULL); wc.hIcon = NULL; wc.hCursor = LoadCursorA(NULL, (LPCSTR)IDC_ARROW);
    wc.hbrBackground = NULL; wc.lpszMenuName = NULL; wc.lpszClassName = CLASS_NAME;
    if (!RegisterClassA(&wc)) { fail(SZWIN_W98_E_PLATFORM, 1); return 0; }

    rc.left = rc.top = 0; rc.right = (LONG)width; rc.bottom = (LONG)height;
    if (!AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX), FALSE)) {
        fail(SZWIN_W98_E_PLATFORM, 1); return 0;
    }
    g.active = 1;
    g.hwnd = CreateWindowExA(0, CLASS_NAME, title ? title : "Shizuku Win64",
                             WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX), CW_USEDEFAULT, CW_USEDEFAULT,
                             rc.right - rc.left, rc.bottom - rc.top, NULL, NULL, wc.hInstance, NULL);
    if (!g.hwnd) { fail(SZWIN_W98_E_PLATFORM, 1); return 0; }

    screen = GetDC(g.hwnd);
    if (!screen) { fail(SZWIN_W98_E_PLATFORM, 1); return 0; }
    g.memory_dc = CreateCompatibleDC(screen);
    ReleaseDC(g.hwnd, screen);
    if (!g.memory_dc) { fail(SZWIN_W98_E_PLATFORM, 1); return 0; }
    {
        uint8_t *p = (uint8_t *)&bi;
        size_t i;
        for (i = 0; i < sizeof bi; ++i) p[i] = 0;
    }
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = (LONG)width;
    bi.bmiHeader.biHeight = -(LONG)height;           /* top-down, matches the frame layout */
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    g.dib = CreateDIBSection(g.memory_dc, &bi, DIB_RGB_COLORS, &g.dib_bits, NULL, 0);
    if (!g.dib || !g.dib_bits) { fail(SZWIN_W98_E_PLATFORM, 1); return 0; }
    g.old_bitmap = (HBITMAP)SelectObject(g.memory_dc, g.dib);
    if (!g.old_bitmap) { fail(SZWIN_W98_E_PLATFORM, 1); return 0; }
    r = szwin_fb_bind(&g.fb, g.dib_bits, (size_t)pixels * 4u, width, height, width * 4u, SZWIN_FMT_BGRX32);
    if (r != SZWIN_OK) { fail(r, 0); return 0; }
    ShowWindow(g.hwnd, SW_SHOWNORMAL);
    if (!UpdateWindow(g.hwnd)) { fail(SZWIN_W98_E_PLATFORM, 1); return 0; }
    return 1;
}

/* Releases in reverse order; a failing release is recorded but the remaining owned resources are still released. */
static void close_view(void)
{
    MSG msg;
    if (g.hwnd) {
        g.active = 0;
        if (!DestroyWindow(g.hwnd)) fail(SZWIN_W98_E_PLATFORM, 1);
        g.hwnd = NULL;
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) DispatchMessageA(&msg);
    }
    if (g.memory_dc && g.old_bitmap) SelectObject(g.memory_dc, g.old_bitmap);
    if (g.dib && !DeleteObject(g.dib)) fail(SZWIN_W98_E_PLATFORM, 1);
    if (g.memory_dc && !DeleteDC(g.memory_dc)) fail(SZWIN_W98_E_PLATFORM, 1);
    g.dib = NULL; g.memory_dc = NULL; g.old_bitmap = NULL; g.dib_bits = NULL;
    UnregisterClassA(CLASS_NAME, GetModuleHandleA(NULL));
    if (g.handle) {
        if (szwin_lookup(&g.table, g.handle)) {
            szwin_window *w = szwin_lookup(&g.table, g.handle);
            if (w->state != SZWIN_EXITED) szwin_note_exit(&g.table, g.handle, 0xFFFFFFFFu);  /* frontend record only */
            szwin_destroy(&g.table, g.handle);
        }
        g.handle = 0;
    }
    if (g.buffers && !HeapFree(GetProcessHeap(), 0, g.buffers)) fail(SZWIN_W98_E_PLATFORM, 1);
    g.buffers = NULL;
}

int szwin_w98_run(const szwin_transport *tp, void *ctx, const char *title, uint32_t width, uint32_t height,
                  uint32_t deadline_ms, szwin_w98_result *result)
{
    DWORD start;
    MSG msg;
    if (!result) return SZWIN_E_INVALID;
    {
        uint8_t *p = (uint8_t *)result;
        size_t i;
        for (i = 0; i < sizeof *result; ++i) p[i] = 0;
    }
    if (g.result || !tp || !width || !height || width > SZWIN_MAX_WIDTH || height > SZWIN_MAX_HEIGHT || !deadline_ms)
        return result->status = SZWIN_E_INVALID;
    g.result = result;
    szwin_table_init(&g.table);
    g.width = width; g.height = height;
    start = GetTickCount();
    if (open_view(title, width, height)) {
        for (;;) {
            int changed = 0, r;
            szwin_window *w;
            while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessageA(&msg); }
            if (result->status != SZWIN_OK) break;
            r = szwin_session_step(&g.table, g.handle, tp, ctx, 8u, &changed);
            if (r != SZWIN_OK) { fail(r, 0); break; }
            w = szwin_lookup(&g.table, g.handle);
            if (w && w->state == SZWIN_EXITED) {
                result->exited = 1; result->exit_code = w->exit_code;
                break;
            }
            if (changed) {
                ++result->frames;
                GdiFlush();                         /* no pending GDI work may race the CPU write into the DIB */
                if (szwin_present(&g.table, g.handle, &g.fb, NULL) < 0) { fail(SZWIN_E_STATE, 0); break; }
                if (!InvalidateRect(g.hwnd, NULL, FALSE)) { fail(SZWIN_W98_E_PLATFORM, 1); break; }
            }
            if (GetTickCount() - start > deadline_ms) { fail(SZWIN_E_TRANSPORT, 0); break; }
            Sleep(10);
        }
    }
    close_view();
    g.result = NULL;
    return result->status;
}
