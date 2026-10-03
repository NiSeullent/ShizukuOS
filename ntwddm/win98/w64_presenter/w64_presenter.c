/* SPDX-License-Identifier: GPL-2.0-only
 * NTW64GUI.EXE: native Windows 98 presenter for a Kernel64 Win64 GUI process. Original code; PE32 4.10, no CRT.
 * Path: NtwCreateProcess64W -> NtwQueryGui64 (own view) -> szwin_session_step pulls an immutable snapshot in
 * 128-byte chunks with CRC check -> committed frame copied into the mapped NTWG surface -> unmap ->
 * ntwg98_present into the DIB section -> InvalidateRect -> WM_PAINT ntwg98_paint (BitBlt + GdiFlush).
 * A failed/partial frame is never presented; the previous complete DIB stays. WndProc only queues bounded input
 * (szwin queue: pointer moves coalesced, overflow is a visible failure). WM_CLOSE becomes a window-scoped CLOSE
 * input; the HWND is destroyed after the process exits, a failure, or the deadline. No fake desktop/pattern.
 * DIB ownership callbacks follow ntwddm/win98/probe.c (same reviewed CreateDIBSection/GdiFlush/BitBlt body). */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#define WINVER 0x0400
#include <windows.h>
#include "../adapter.h"
#include "../../../shizukudos/win64/native_window/szwin.h"
#include "../../../ntwin32/win64/ntw64.h"
#include "../../../ntwin32/win64/ntw64_gui.h"
#include "../../../shizukudos/abi/shz_w64_gui.h"

#define DEADLINE_MS 45000u
#define WAIT_WINDOW_MS 15000u
typedef struct { HDC memory, painting; HBITMAP bitmap; HGDIOBJ previous; HWND window; } native_backend;

static native_backend native;
static ntwg98_view view;
static szwin_table table;
static szwin_handle win;
static HANDLE proc;
static int input_failed;

static void *allocate(void *u, size_t n) { (void)u; return HeapAlloc(GetProcessHeap(), 0, n); }
static void deallocate(void *u, void *m, size_t n) { (void)u; (void)n; HeapFree(GetProcessHeap(), 0, m); }
static int synchronize(void *u) { (void)u; return GdiFlush() != 0; }
static int create_dib(void *user, uint32_t width, uint32_t height, ntwg98_dib *dib)
{
    native_backend *b = user;
    BITMAPINFO info;
    HDC screen = GetDC(b->window);
    ZeroMemory(&info, sizeof info);
    if (!screen) return 0;
    b->memory = CreateCompatibleDC(screen);
    ReleaseDC(b->window, screen);
    if (!b->memory) return 0;
    dib->handle = b;
    info.bmiHeader.biSize = sizeof(info.bmiHeader);
    info.bmiHeader.biWidth = (LONG)width;
    info.bmiHeader.biHeight = -(LONG)height;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    b->bitmap = CreateDIBSection(b->memory, &info, DIB_RGB_COLORS, &dib->pixels, NULL, 0);
    if (!b->bitmap || !dib->pixels) return 0;
    dib->pitch = width * 4u; dib->bytes = (size_t)dib->pitch * height;
    b->previous = SelectObject(b->memory, b->bitmap);
    if (!b->previous || b->previous == HGDI_ERROR) { b->previous = NULL; return 0; }
    return 1;
}
static int paint_dib(void *user, const ntwg98_dib *dib, uint32_t width, uint32_t height)
{
    native_backend *b = user;
    if (dib->handle != b || !b->painting || !b->bitmap) return 0;
    if (!BitBlt(b->painting, 0, 0, (int)width, (int)height, b->memory, 0, 0, SRCCOPY)) return 0;
    return GdiFlush() != 0;
}
static int release_dib(void *user, ntwg98_dib *dib)
{
    native_backend *b = user;
    if (b->previous) { HGDIOBJ old = SelectObject(b->memory, b->previous); if (!old || old == HGDI_ERROR) return 0; b->previous = NULL; }
    if (b->bitmap) { if (!DeleteObject(b->bitmap)) return 0; b->bitmap = NULL; dib->pixels = NULL; }
    if (b->memory) { if (!DeleteDC(b->memory)) return 0; b->memory = NULL; }
    dib->handle = NULL;
    return 1;
}
static const ntwg98_ops operations = { allocate, deallocate, create_dib, synchronize, paint_dib, release_dib };

/* ---------------------------------------------------------------- szwin transport over the NTW32 GUI exports */
static int t_acquire(void *c, szwin_frame_info *o)
{
    NTW64_GUI_FRAME f;
    (void)c;
    if (!NtwAcquireGuiFrame64(proc, &f)) return SZWIN_E_TRANSPORT;
    o->snapshot_id = f.snapshot_id; o->width = f.width; o->height = f.height; o->stride = f.stride;
    o->byte_length = f.byte_length; o->pixel_format = SZWIN_FMT_BGRX32; o->pixels_crc32 = f.pixels_crc32;
    return SZWIN_OK;
}
static int t_read(void *c, uint64_t id, uint32_t off, uint32_t len, uint8_t *out)
{ (void)c; return NtwReadGuiFrame64(proc, id, off, len, out) ? SZWIN_OK : SZWIN_E_TRANSPORT; }
static int t_release(void *c, uint64_t id) { (void)c; return NtwReleaseGuiFrame64(proc, id) ? SZWIN_OK : SZWIN_E_TRANSPORT; }
static int t_input(void *c, const szwin_event *e)
{
    NTW64_GUI_INPUT in;
    static const DWORD kinds[9] = { 0, SHZ_W64_GUI_IN_MOVE, SHZ_W64_GUI_IN_LDOWN, SHZ_W64_GUI_IN_LUP, SHZ_W64_GUI_IN_RDOWN,
                                    SHZ_W64_GUI_IN_RUP, SHZ_W64_GUI_IN_KEYDOWN, SHZ_W64_GUI_IN_KEYUP, SHZ_W64_GUI_IN_CLOSE };
    (void)c;
    if (e->kind < 1 || e->kind > 8) return SZWIN_E_INVALID;
    in.kind = kinds[e->kind]; in.flags = e->flags; in.x = e->x; in.y = e->y; in.key = e->key; in.scancode = e->scancode;
    in.clock_ms = e->clock_ms;
    return NtwSendGuiInput64(proc, &in, NULL) ? SZWIN_OK : SZWIN_E_TRANSPORT;
}
static int t_poll_exit(void *c, uint32_t *code)
{
    int exited = 0;
    DWORD x = 0;
    (void)c;
    if (!ntw64_gui_poll_exit(proc, &exited, &x)) return SZWIN_E_TRANSPORT;
    if (exited) *code = x;
    return exited;
}
static const szwin_transport transport = { t_acquire, t_read, t_release, t_input, t_poll_exit };

/* Frontend failure classes (distinct from a remote exit code only by being >= 0x100). */
static UINT classify_error(DWORD e, UINT dflt)
{
    switch (e) {
    case 50: case 55: case 1306: return 0x110;       /* bridge unavailable / ABI mismatch */
    case 5: case 288: case 1314: return 0x111;       /* access denied: foreign or unauthorized owner */
    case 6: return 0x112;                            /* handle/channel revoked */
    default: return dflt;
    }
}
static void report(UINT code, DWORD error)
{
    const char *m;
    switch (code) {
    case 0x101: m = "Cannot start the Win64 process (image not found or refused)."; break;
    case 0x102: m = "Kernel64 refused the GUI view for this process."; break;
    case 0x103: m = "The Win64 process never presented a visible window."; break;
    case 0x10b: m = "The Win64 window did not finish before the deadline; the process was ended."; break;
    case 0x10c: m = "Kernel64 has no GUI route (no derived-owner build or no scanout/hosted display)."; break;
    case 0x110: m = "The Shizuku bridge is unavailable (NTWRAP9X.VXD, Supervisor or Kernel64 channel missing, or ABI mismatch)."; break;
    case 0x111: m = "Access denied: this process does not own the Win64 channel or process."; break;
    case 0x112: m = "The Win64 channel or process handle was revoked."; break;
    default: m = "NTW64GUI failed while presenting the Win64 window."; break;
    }
    (void)error;
    MessageBoxA(NULL, m, "NTW64GUI", MB_OK | MB_ICONERROR);
}

static void push(uint32_t kind, LPARAM lp, WPARAM wp)
{
    szwin_event e;
    ZeroMemory(&e, sizeof e);
    e.kind = kind;
    e.x = (int16_t)LOWORD(lp); e.y = (int16_t)HIWORD(lp);
    if (kind == SZWIN_EV_KEYDOWN || kind == SZWIN_EV_KEYUP) { e.x = e.y = 0; e.key = (uint32_t)wp & 0xffu; e.scancode = ((uint32_t)lp >> 16) & 0x1ffu; }
    e.flags = (GetKeyState(VK_SHIFT) < 0 ? SZWIN_EVF_SHIFT : 0) | (GetKeyState(VK_CONTROL) < 0 ? SZWIN_EVF_CTRL : 0);
    e.clock_ms = GetTickCount();
    if (szwin_input_push(&table, win, &e, NULL) != SZWIN_OK) input_failed = 1;   /* observable, not silent */
}

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    switch (m) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        native.painting = BeginPaint(h, &ps);
        if (native.painting && view.image_ready) ntwg98_paint(&view);
        native.painting = NULL;
        EndPaint(h, &ps);
        return 0;
    }
    case WM_MOUSEMOVE: push(SZWIN_EV_MOVE, lp, wp); return 0;
    case WM_LBUTTONDOWN: push(SZWIN_EV_LDOWN, lp, wp); return 0;
    case WM_LBUTTONUP: push(SZWIN_EV_LUP, lp, wp); return 0;
    case WM_RBUTTONDOWN: push(SZWIN_EV_RDOWN, lp, wp); return 0;
    case WM_RBUTTONUP: push(SZWIN_EV_RUP, lp, wp); return 0;
    case WM_KEYDOWN: push(SZWIN_EV_KEYDOWN, lp, wp); return 0;
    case WM_KEYUP: push(SZWIN_EV_KEYUP, lp, wp); return 0;
    case WM_CLOSE: szwin_close_request(&table, win); return 0;     /* the W64 app decides its lifetime */
    }
    return DefWindowProcA(h, m, wp, lp);
}

/* Copies the committed szwin frame into the NTWG surface and presents it into the DIB. */
static int publish(void)
{
    szwin_window *w = szwin_lookup(&table, win);
    ntwg_mapping map;
    ntwg_rect r;
    uint32_t y;
    if (!w || !w->has_frame) return 0;
    if (ntwg_surface_map(view.core, view.surface, &map) != NTWG_OK) return -1;
    if (map.width != w->width || map.height != w->height) { ntwg_surface_unmap(view.core, view.surface); return -1; }
    for (y = 0; y < w->height; ++y)
        CopyMemory((uint8_t *)map.pixels + (size_t)y * map.pitch_bytes, w->front + (size_t)y * w->width, w->width * 4u);
    if (ntwg_surface_unmap(view.core, view.surface) != NTWG_OK) return -1;
    r.x = 0; r.y = 0; r.width = w->width; r.height = w->height;
    if (ntwg98_present(&view, &r, 0, 0, NULL) != NTWG_OK) return -1;
    return InvalidateRect(native.window, NULL, FALSE) ? 1 : -1;
}

static UINT run(LPCWSTR path)
{
    NTW64_GUI_VIEW v;
    NTW64_GUI_FRAME f;
    WNDCLASSA wc;
    RECT rc;
    MSG msg;
    uint32_t *front, *staging, exit_code = 0;
    DWORD start;
    int exited = 0, failed = 0;
    if (!NtwCreateProcess64W(path, path, NULL, &proc)) {
        const DWORD e = GetLastError();
        const UINT why = classify_error(e, 0x101);
        report(why, e);
        return why;
    }
    /* 0x10c: the K64 refused the view as not supported (no GUI route: no derived-owner build, or no scanout/hosted
     * display). 0x102: any other refusal. No fallback in either case. */
    if (!NtwQueryGui64(proc, &v)) {
        const DWORD e = GetLastError();
        const UINT why = e == ERROR_NOT_SUPPORTED ? 0x10cu : classify_error(e, 0x102u);
        NtwKillProcess64(proc, why); NtwCloseProcess64(proc); report(why, e); return why;
    }
    if (!shz_w64_gui_display_valid(v.display_backend)) { failed = 0x10c; goto teardown; }
    /* Geometry: acquire+release once the app has a visible window (bounded wait). */
    start = GetTickCount();
    while (!NtwAcquireGuiFrame64(proc, &f)) {
        if (GetTickCount() - start >= WAIT_WINDOW_MS) { failed = 0x103; goto teardown; }
        Sleep(20);
    }
    if (!NtwReleaseGuiFrame64(proc, f.snapshot_id)) { failed = 0x104; goto teardown; }
    front = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, f.byte_length);
    staging = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, f.byte_length);
    szwin_table_init(&table);
    if (!front || !staging || szwin_create(&table, f.width, f.height, 0, 0, front, staging, f.byte_length, &win) != SZWIN_OK)
    { failed = 0x105; goto teardown; }
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = wndproc; wc.hInstance = GetModuleHandleA(NULL); wc.hCursor = LoadCursorA(NULL, (LPCSTR)IDC_ARROW);
    wc.lpszClassName = "ShizukuW64Gui";
    rc.left = 0; rc.top = 0; rc.right = (LONG)f.width; rc.bottom = (LONG)f.height;
    if (!RegisterClassA(&wc) || !AdjustWindowRect(&rc, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, FALSE)) { failed = 0x106; goto teardown; }
    native.window = CreateWindowExA(0, wc.lpszClassName,
                                    v.display_backend == SHZ_W64_GUI_DISPLAY_SCANOUT ? "Shizuku Win64 [K64 scanout]" :
                                    "Shizuku Win64 [K64 hosted-private, no scanout]", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                                    CW_USEDEFAULT, CW_USEDEFAULT, rc.right - rc.left, rc.bottom - rc.top, NULL, NULL,
                                    wc.hInstance, NULL);
    if (!native.window || ntwg98_open(&view, &operations, &native, f.width, f.height) != NTWG_OK) { failed = 0x107; goto teardown; }
    ShowWindow(native.window, SW_SHOWNORMAL);
    start = GetTickCount();
    while (!exited && !failed) {
        int changed = 0, st;
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessageA(&msg); }
        if (input_failed) { failed = 0x108; break; }
        st = szwin_session_step(&table, win, &transport, NULL, 8, &changed);
        if (st < 0 && st != SZWIN_E_TRANSPORT && st != SZWIN_E_CRC) { failed = 0x109; break; }
        if (changed && publish() < 0) { failed = 0x10a; break; }
        { szwin_window *w = szwin_lookup(&table, win); if (w && w->state == SZWIN_EXITED) { exited = 1; exit_code = w->exit_code; } }
        if (GetTickCount() - start >= DEADLINE_MS) { failed = 0x10b; break; }
        Sleep(10);
    }
teardown:
    if (!exited) { DWORD c = 0; if (!NtwWaitProcess64(proc, 0, &c)) NtwKillProcess64(proc, 0xdead); else { exited = 1; exit_code = c; } }
    NtwCloseGui64(proc);
    ntwg98_close(&view);
    if (native.window) DestroyWindow(native.window);
    NtwWaitProcess64(proc, 5000, NULL);
    NtwCloseProcess64(proc);
    if (failed) report((UINT)failed, 0);
    return failed ? (UINT)failed : (UINT)exit_code;   /* exit code only when the app really exited */
}

void __stdcall mainCRTStartup(void)
{
    /* Win98 has no real GetCommandLineW: widen the ANSI tail (ASCII path) into a bounded UTF-16 buffer. */
    static WCHAR path[260];
    LPSTR cmd = GetCommandLineA();
    unsigned n = 0;
    if (*cmd == '"') { ++cmd; while (*cmd && *cmd != '"') ++cmd; if (*cmd) ++cmd; }
    else while (*cmd && *cmd != ' ') ++cmd;
    while (*cmd == ' ') ++cmd;
    while (cmd[n] && n < 259u) { if ((unsigned char)cmd[n] >= 0x80u) ExitProcess(0x100); path[n] = (WCHAR)cmd[n]; ++n; }
    path[n] = 0;
    ExitProcess(n && !cmd[n] ? run(path) : 0x100);
}
