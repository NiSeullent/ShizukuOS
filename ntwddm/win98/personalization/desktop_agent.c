/* SPDX-License-Identifier: GPL-2.0-only
 * SHZWALL.EXE: original Win98 (i486, USER32/GDI32/KERNEL32/ADVAPI32 only)
 * procedural animated wallpaper agent. It paints into Explorer's own desktop
 * SysListView32 through the window DC, excluding every icon's LVIR_BOUNDS
 * rectangle, so icons, labels, selection and the taskbar stay Explorer-owned.
 * Any pause or stop invalidates the list view so Explorer repaints its own
 * static wallpaper (the static fallback). ActiveDesktop hosts and systems
 * without the Win9x shared arena are refused truthfully, never emulated.
 * Usage: SHZWALL [/enable | /disable | /stop]. Settings live under
 * HKCU\Software\ShizukuOS\Personalization\DesktopWallpaper (REG_DWORD).
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#define _WIN32_IE 0x0400
#include <windows.h>
#include <string.h>
#include "desktop_agent.h"
#include "agent_ctl.h"

#define AGENT_CLASS "ShizukuOSWallpaperAgent"
#define AGENT_MUTEX "ShizukuOSWallpaperAgent.Instance."
#define USER_POLL_MS 1000u
#define WM_AGENT_RELOAD (WM_APP + 7u)
#define LVM_GETITEMCOUNT_ 0x1004u
#define LVM_GETITEMRECT_ 0x100Eu
#define LVIR_BOUNDS_ 0
#define TIMER_ID 1u
#define IDLE_POLL_MS 500u
#define ICON_REFRESH_MS 1000u
#define HOST_TIMEOUT_MS 200u
#define SHARED_BYTES 4096u

typedef struct agent {
    HWND window, progman, listview;
    HANDLE mapping; RECT *shared;
    HDC memory; HBITMAP bitmap; HGDIOBJ previous; void *bits;
    uint32_t rw, rh;
    szw_settings settings; szw_pacer pacer; szw_state state;
    szw_reason reason; int painted;
    szw_rect icons[SZW_MAX_ICONS]; uint32_t icon_count; DWORD icons_at;
    int exit_code;
    char user_tag[9], title[40]; DWORD user_at;
} agent;
static agent A;

static void current_tag(char tag[9])
{
    char name[128]; DWORD size = sizeof name;
    /* Win98 profiles: the logged-on user name changes with logoff/logon. A failed
     * lookup (no logon, profiles off) hashes as the empty name, which is stable. */
    if (!GetUserNameA(name, &size)) name[0] = 0;
    szw_user_tag(name, tag);
}

static void init_identity(void)
{
    current_tag(A.user_tag);
    lstrcpyA(A.title, "Shizuku wallpaper "); lstrcatA(A.title, A.user_tag);
}

static void debug(const char *what, DWORD value)
{
    char line[200];
    wsprintfA(line, "SHZWALL: %s (%lu)\r\n", what, (unsigned long)value);
    OutputDebugStringA(line);
}

static int host_call(UINT message, WPARAM w, LPARAM l, DWORD *result)
{
    DWORD_PTR r = 0;
    if (!SendMessageTimeoutA(A.listview, message, w, l, SMTO_ABORTIFHUNG | SMTO_BLOCK, HOST_TIMEOUT_MS, &r)) {
        A.state.host_hung = 1; return 0;
    }
    A.state.host_hung = 0; *result = (DWORD)r; return 1;
}

static void discover_host(void)
{
    HWND defview;
    A.state.host_ok = 0; A.listview = NULL;
    A.progman = FindWindowA("Progman", NULL);
    defview = A.progman ? FindWindowExA(A.progman, NULL, "SHELLDLL_DefView", NULL) : NULL;
    if (!defview) return;
    /* ActiveDesktop renders the background in an HTML host; painting into
     * the list view there would fight Internet Explorer. Refuse it. */
    if (FindWindowExA(defview, NULL, "Internet Explorer_Server", NULL)) return;
    A.listview = FindWindowExA(defview, NULL, "SysListView32", NULL);
    A.state.host_ok = A.listview && A.shared;
    A.icons_at = GetTickCount() - ICON_REFRESH_MS - 1u;
}

static void refresh_icons(void)
{
    DWORD count = 0, i, ok; RECT client; szw_rect raw[SZW_MAX_ICONS];
    if (GetTickCount() - A.icons_at < ICON_REFRESH_MS) return;
    if (!host_call(LVM_GETITEMCOUNT_, 0, 0, &count)) return;
    if (count > SZW_MAX_ICONS) count = SZW_MAX_ICONS;
    for (i = 0; i < count; i++) {
        /* The list view writes this RECT in Explorer's context; the Win9x
         * shared arena makes the same address valid there. */
        A.shared[i].left = LVIR_BOUNDS_; A.shared[i].top = A.shared[i].right = A.shared[i].bottom = 0;
        if (!host_call(LVM_GETITEMRECT_, i, (LPARAM)&A.shared[i], &ok)) return;
        if (!ok) { A.shared[i].left = A.shared[i].right = 0; }
        raw[i].left = A.shared[i].left; raw[i].top = A.shared[i].top;
        raw[i].right = A.shared[i].right; raw[i].bottom = A.shared[i].bottom;
    }
    if (!GetClientRect(A.listview, &client)) { A.state.host_ok = 0; return; }
    A.icon_count = szw_clip_icons(raw, count, client.right, client.bottom, 2, A.icons, SZW_MAX_ICONS);
    A.icons_at = GetTickCount();
}

static void release_surface(void)
{
    if (A.memory) { SelectObject(A.memory, A.previous); DeleteDC(A.memory); A.memory = NULL; }
    if (A.bitmap) { DeleteObject(A.bitmap); A.bitmap = NULL; }
    A.bits = NULL;
}

static int create_surface(void)
{
    BITMAPINFO info; HDC screen;
    release_surface();
    if (!szw_render_size((uint32_t)GetSystemMetrics(SM_CXSCREEN), (uint32_t)GetSystemMetrics(SM_CYSCREEN), &A.rw, &A.rh))
        return 0;
    memset(&info, 0, sizeof info);
    info.bmiHeader.biSize = sizeof info.bmiHeader; info.bmiHeader.biWidth = (LONG)A.rw;
    info.bmiHeader.biHeight = -(LONG)A.rh; info.bmiHeader.biPlanes = 1; info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    screen = GetDC(NULL);
    if (!screen) return 0;
    A.bitmap = CreateDIBSection(screen, &info, DIB_RGB_COLORS, &A.bits, NULL, 0);
    A.memory = A.bitmap ? CreateCompatibleDC(screen) : NULL;
    ReleaseDC(NULL, screen);
    if (!A.bitmap || !A.memory || !A.bits) { debug("DIB section creation failed", GetLastError()); release_surface(); return 0; }
    A.previous = SelectObject(A.memory, A.bitmap);
    return 1;
}

static void restore_static(void)
{
    /* Explorer repaints its own wallpaper and icons. */
    if (A.painted && A.listview && IsWindow(A.listview)) InvalidateRect(A.listview, NULL, TRUE);
    A.painted = 0;
}

static void sample_state(void)
{
    SYSTEM_POWER_STATUS power; BOOL saver = FALSE; HWND fg; RECT r;
    A.state.ac = GetSystemPowerStatus(&power) ? (power.ACLineStatus == 1 ? 1 : power.ACLineStatus == 0 ? 0 : -1) : -1;
    A.state.screensaver = SystemParametersInfoA(SPI_GETSCREENSAVERRUNNING, 0, &saver, 0) && saver;
    fg = GetForegroundWindow(); A.state.fullscreen = 0;
    if (fg && fg != A.window && fg != A.progman && GetWindowRect(fg, &r)) {
        char name[32];
        if (!GetClassNameA(fg, name, sizeof name) || lstrcmpA(name, "Shell_TrayWnd"))
            A.state.fullscreen = r.left <= 0 && r.top <= 0 && r.right >= GetSystemMetrics(SM_CXSCREEN) &&
                                 r.bottom >= GetSystemMetrics(SM_CYSCREEN);
    }
    if (GetTickCount() - A.user_at >= USER_POLL_MS) {
        char now[9]; current_tag(now); A.user_at = GetTickCount();
        if (lstrcmpA(now, A.user_tag)) A.state.profile_changed = 1;  /* stale agent of another profile */
    }
    if (!A.listview || !IsWindow(A.listview)) discover_host();
}

static void paint_frame(void)
{
    HDC dc; RECT client; uint32_t i; DWORD start = GetTickCount(); int slow;
    if (!A.memory && !create_surface()) { A.state.host_ok = 0; return; }
    refresh_icons();
    if (A.state.host_hung || !A.state.host_ok) return;
    if (!szw_frame(A.bits, (size_t)A.rw * A.rh * 4u, A.rw, A.rh, A.settings.scene, szw_phase(&A.pacer))) return;
    GdiFlush();
    if (!GetClientRect(A.listview, &client) || !(dc = GetDC(A.listview))) { A.state.host_ok = 0; return; }
    for (i = 0; i < A.icon_count; i++)
        ExcludeClipRect(dc, A.icons[i].left, A.icons[i].top, A.icons[i].right, A.icons[i].bottom);
    SetStretchBltMode(dc, COLORONCOLOR);
    if (StretchBlt(dc, 0, 0, client.right, client.bottom, A.memory, 0, 0, (int)A.rw, (int)A.rh, SRCCOPY)) A.painted = 1;
    ReleaseDC(A.listview, dc);
    slow = szw_pacer_cost(&A.pacer, GetTickCount() - start);
    if (slow < 0) A.state.too_slow = 1;
    else if (slow > 0) debug("frame cost high; rate lowered to fps", A.pacer.fps);
}

static void step(void)
{
    uint32_t delay = IDLE_POLL_MS; szw_reason reason;
    sample_state();
    reason = szw_decide(&A.settings, &A.state);
    if (reason != A.reason) { debug(szw_reason_text(reason), reason); if (reason != SZW_RUN) restore_static(); }
    A.reason = reason;
    if (szw_reason_is_stop(reason)) {
        A.exit_code = reason == SZW_STOP_PROFILE ? 6 : reason == SZW_STOP_HOST ? 3 : reason == SZW_STOP_TOO_SLOW ? 4 : 0;
        DestroyWindow(A.window); return;
    }
    if (reason == SZW_RUN) {
        if (szw_pacer_tick(&A.pacer, GetTickCount(), &delay)) paint_frame();
    } else A.pacer.started = 0; /* resume re-anchors without a catch-up burst */
    SetTimer(A.window, TIMER_ID, delay ? delay : 1u, NULL);
}

static void reload(void)
{
    szw_settings s; DWORD error = szw_load_settings(&s);
    if (error != ERROR_SUCCESS) { debug("settings unreadable or invalid; stopping", error); s.enabled = 0; s.scene = 0; s.fps = 10; s.battery_pause = 1; s.fullscreen_pause = 1; }
    A.settings = s;
    szw_pacer_init(&A.pacer, s.fps);
}

static LRESULT CALLBACK agent_proc(HWND window, UINT message, WPARAM w, LPARAM l)
{
    switch (message) {
    case WM_TIMER: if (w == TIMER_ID) step(); return 0;
    case WM_AGENT_RELOAD: reload(); step(); return 0;
    case WM_DISPLAYCHANGE: release_surface(); A.icons_at = GetTickCount() - ICON_REFRESH_MS - 1u; return 0;
    case WM_POWERBROADCAST:
        if (w == PBT_APMSUSPEND) { A.state.suspended = 1; restore_static(); }
        else if (w == PBT_APMRESUMESUSPEND || w == PBT_APMRESUMECRITICAL || w == PBT_APMRESUMEAUTOMATIC) A.state.suspended = 0;
        return TRUE;
    case WM_ENDSESSION: if (w) { A.state.ending = 1; restore_static(); } return 0;
    case WM_CLOSE: DestroyWindow(window); return 0;
    case WM_DESTROY: KillTimer(window, TIMER_ID); restore_static(); PostQuitMessage(A.exit_code); return 0;
    }
    return DefWindowProcA(window, message, w, l);
}

static const char *argument(void)
{
    const char *p = GetCommandLineA();
    if (*p == '"') { p++; while (*p && *p != '"') p++; if (*p) p++; }
    else while (*p && *p != ' ' && *p != '\t') p++;
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

static int notify_running(UINT message)
{
    /* Only the agent of the current user is addressed; another user's stale agent
     * (different title) stops itself on its own user-change poll. */
    HWND running;
    init_identity();
    running = FindWindowA(AGENT_CLASS, A.title);
    return running ? PostMessageA(running, message, 0, 0) != 0 : 0;
}

static UINT run_agent(void)
{
    WNDCLASSA wc; MSG msg; HANDLE mutex; DWORD error; UINT code;
    error = szw_load_settings(&A.settings);
    if (error != ERROR_SUCCESS) { debug("settings unreadable or invalid", error); return 2; }
    if (!A.settings.enabled) { debug("disabled; static wallpaper unchanged", 0); return 0; }
    init_identity();
    { char name[sizeof AGENT_MUTEX + 8]; lstrcpyA(name, AGENT_MUTEX); lstrcatA(name, A.user_tag);
      mutex = CreateMutexA(NULL, TRUE, name); }
    if (!mutex) { debug("instance mutex failed", GetLastError()); return 5; }
    if (GetLastError() == ERROR_ALREADY_EXISTS) { CloseHandle(mutex); notify_running(WM_AGENT_RELOAD); return 0; }
    szw_pacer_init(&A.pacer, A.settings.fps);
    A.reason = SZW_RUN; A.state.ac = -1;
    /* Win9x places pagefile-backed views in the shared arena 0x80000000..
     * 0xBFFFFFFF that every process (Explorer included) can address. */
    if (GetVersion() & 0x80000000u) {
        A.mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SHARED_BYTES, NULL);
        A.shared = A.mapping ? (RECT *)MapViewOfFile(A.mapping, FILE_MAP_WRITE, 0, 0, SHARED_BYTES) : NULL;
        if (A.shared && ((DWORD)(DWORD_PTR)A.shared < 0x80000000u || (DWORD)(DWORD_PTR)A.shared >= 0xC0000000u)) {
            UnmapViewOfFile(A.shared); A.shared = NULL;
        }
    }
    if (!A.shared) debug("no Win9x shared arena for cross-process icon query", GetLastError());
    discover_host();
    memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = agent_proc; wc.hInstance = GetModuleHandleA(NULL); wc.lpszClassName = AGENT_CLASS;
    if (!RegisterClassA(&wc) ||
        !(A.window = CreateWindowExA(WS_EX_TOOLWINDOW, AGENT_CLASS, A.title, WS_POPUP, 0, 0, 0, 0,
                                     NULL, NULL, wc.hInstance, NULL))) {
        debug("agent window failed", GetLastError()); code = 5;
    } else {
        SetTimer(A.window, TIMER_ID, 1, NULL);
        while (GetMessageA(&msg, NULL, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageA(&msg); }
        code = (UINT)msg.wParam;
    }
    release_surface();
    if (A.shared) UnmapViewOfFile(A.shared);
    if (A.mapping) CloseHandle(A.mapping);
    ReleaseMutex(mutex); CloseHandle(mutex);
    return code;
}

void __attribute__((stdcall)) WinMainCRTStartup(void)
{
    const char *arg = argument(); UINT code; DWORD error;
    if (!*arg) code = run_agent();
    else if (!lstrcmpiA(arg, "/stop")) code = notify_running(WM_CLOSE) ? 0 : 1;
    else if (!lstrcmpiA(arg, "/enable") || !lstrcmpiA(arg, "/disable")) {
        int enable = arg[1] == 'e' || arg[1] == 'E';
        szw_settings s;
        error = szw_load_settings(&s);
        if (error == ERROR_SUCCESS) { s.enabled = (uint32_t)enable; error = szw_save_settings(&s); }
        if (error == ERROR_SUCCESS) error = szw_set_startup(enable);
        if (error != ERROR_SUCCESS) { debug(enable ? "enable failed" : "disable failed", error); code = 2; }
        else if (!enable) { notify_running(WM_CLOSE); code = 0; }
        else code = notify_running(WM_AGENT_RELOAD) ? 0 : run_agent();
    } else { debug("usage: SHZWALL [/enable|/disable|/stop]", ERROR_INVALID_PARAMETER); code = 87; }
    ExitProcess(code);
}
