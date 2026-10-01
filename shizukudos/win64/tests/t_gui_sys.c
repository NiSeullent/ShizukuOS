/* SPDX-License-Identifier: GPL-2.0-only
 * GUI: the user32 surface beyond windows and input, self-checking, plus one pixel scene.
 *
 * Scene "sys-layer" (verified by tests/run_k64_gui.py from the documented blend formulas): an UpdateLayeredWindow popup
 * with per-pixel premultiplied alpha, a SetLayeredWindowAttributes(LWA_ALPHA) popup, a colour-keyed popup and a popup
 * shaped by SetWindowRgn, over the bare desktop. Checked here too: layered/region hit testing, PrintWindow.
 *
 * Self-checks: clipboard (formats, synthesis, sequence numbers, listeners, another thread locked out, delayed rendering,
 * CF_BITMAP), menus (state, templates, TrackPopupMenuEx driven by real key input from a helper thread, submenus,
 * mnemonics), MessageBox and a resource dialog (driven the same way), hooks (WH_GETMESSAGE, WH_KEYBOARD, WH_CBT,
 * WH_CALLWNDPROC, chaining), WinEvents, DPI (fixed 96), display modes/devices/CCD, SendNotifyMessage /
 * SendMessageCallback / ShowWindowAsync across threads, resources (strings, icons, accelerators), raw input, window
 * station/desktop, scroll information, ScrollWindowEx, DrawEdge/DrawFrameControl, GetGuiResources.
 * Reports SKIP and exits 0 when there is no display. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"
__declspec(dllimport) BOOL WINAPI SetShellWindow(HWND hwnd);

static int bad;
#define CHECK(cond, name) do { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s (line %d)\n", name, __LINE__); ++bad; } } while (0)

static HINSTANCE g_inst;
static HWND g_main;
static int g_clipupdates, g_renderformat, g_cbt_create, g_getmsg_seen, g_callwnd_seen, g_kbd_hook;
static UINT g_custom_fmt;

static void pump(void)
{
    MSG m;
    while (PeekMessageW(&m, 0, 0, 0, PM_REMOVE)) { TranslateMessage(&m); DispatchMessageW(&m); }
}
static void pump_ms(DWORD ms)
{
    const DWORD t = GetTickCount();
    while (GetTickCount() - t < ms) { MsgWaitForMultipleObjects(0, 0, FALSE, 20, QS_ALLINPUT); pump(); }
}

static LRESULT CALLBACK main_proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_CLIPBOARDUPDATE: ++g_clipupdates; return 0;
    case WM_RENDERFORMAT:
        if (w == g_custom_fmt) {
            HGLOBAL g = GlobalAlloc(GMEM_FIXED, 6);
            memcpy(g, "later", 6);
            SetClipboardData(g_custom_fmt, g);
            ++g_renderformat;
        }
        return 0;
    case WM_USER + 7: return (LRESULT)(w * 3);
    default: break;
    }
    return DefWindowProcW(h, m, w, l);
}

static HWND popup(LPCWSTR cls, DWORD ex, int x, int y, int w, int h)
{
    return CreateWindowExW(ex, cls, L"", WS_POPUP, x, y, w, h, 0, 0, g_inst, 0);
}

/* Shell registration crosses the process boundary; child modes use the real
 * kernel window table, not a DLL-local imitation of GetShellWindow. */
static int shell_child(int owner)
{
    HWND shell = GetShellWindow(), own;
    HANDLE release;
    DWORD pid = 0;
    if (!owner) {
        CHECK(shell && IsWindow(shell) && GetWindowThreadProcessId(shell, &pid) && pid != GetCurrentProcessId(),
              "shell child observes another process's real window");
        SetLastError(0);
        CHECK(!SetShellWindow(shell) && GetLastError() == ERROR_ACCESS_DENIED,
              "shell child cannot register another process's window");
        own = popup(L"ShzSys", 0, 1, 1, 10, 10);
        CHECK(own != 0, "shell child creates owned window");
        SetLastError(0);
        CHECK(own && !SetShellWindow(own) && GetLastError() == ERROR_ACCESS_DENIED && GetShellWindow() == shell,
              "shell child cannot replace the existing shell");
        if (own) DestroyWindow(own);
        return bad ? 1 : 0;
    }
    release = OpenEventW(SYNCHRONIZE, FALSE, L"ShzGuiShellRelease");
    own = popup(L"ShzSys", 0, 1, 1, 10, 10);
    CHECK(release && own && !shell && SetShellWindow(own) && GetShellWindow() == own,
          "shell child registers owned window");
    if (release) {
        CHECK(WaitForSingleObject(release, 5000) == WAIT_OBJECT_0, "shell child release event");
        CloseHandle(release);
    }
    /* Intentionally leave the window alive: process/thread cleanup must remove
     * its registration even without a user-mode DestroyWindow call. */
    return bad ? 1 : 0;
}

static int launch_shell_child(LPCWSTR mode, PROCESS_INFORMATION *pi)
{
    WCHAR exe[MAX_PATH], cmd[MAX_PATH + 40];
    STARTUPINFOW si;
    DWORD n = GetModuleFileNameW(0, exe, MAX_PATH);
    if (!n || n >= MAX_PATH) return 0;
    lstrcpyW(cmd, L"\""); lstrcatW(cmd, exe); lstrcatW(cmd, L"\" "); lstrcatW(cmd, mode);
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    memset(pi, 0, sizeof *pi);
    if (!CreateProcessW(exe, cmd, 0, 0, FALSE, 0, 0, 0, &si, pi)) return 0;
    CloseHandle(pi->hThread);
    pi->hThread = 0;
    return 1;
}

static void check_shell_child_exit(PROCESS_INFORMATION *pi, const char *name)
{
    DWORD code = STILL_ACTIVE;
    int ended = WaitForSingleObject(pi->hProcess, 6000) == WAIT_OBJECT_0;
    CHECK(ended && GetExitCodeProcess(pi->hProcess, &code) && code == 0, name);
    CloseHandle(pi->hProcess);
}

static void test_shell_registration(void)
{
    HWND a, b, child, topmost, shell;
    PROCESS_INFORMATION pi;
    HANDLE release;
    DWORD started, pid = 0;
    CHECK(GetShellWindow() == 0, "shell initially absent");
    SetLastError(0);
    CHECK(!SetShellWindow((HWND)(uintptr_t)0xdeadbeef) && GetLastError() == ERROR_INVALID_WINDOW_HANDLE,
          "shell invalid HWND rejected with window error");
    SetLastError(0);
    CHECK(!SetShellWindow(0) && GetLastError() == ERROR_INVALID_WINDOW_HANDLE,
          "shell null HWND rejected with window error");
    a = popup(L"ShzSys", 0, 1, 1, 10, 10);
    b = popup(L"ShzSys", 0, 2, 2, 10, 10);
    CHECK(a && b, "shell test windows created");
    if (!a || !b) { if (a) DestroyWindow(a); if (b) DestroyWindow(b); return; }
    child = CreateWindowExW(0, L"ShzSys", L"", WS_CHILD, 0, 0, 4, 4, a, 0, g_inst, 0);
    topmost = popup(L"ShzSys", WS_EX_TOPMOST, 3, 3, 10, 10);
    SetLastError(0);
    CHECK(child && !SetShellWindow(child) && GetLastError() == ERROR_ACCESS_DENIED && !GetShellWindow(),
          "shell child window rejected");
    SetLastError(0);
    CHECK(topmost && !SetShellWindow(topmost) && GetLastError() == ERROR_ACCESS_DENIED && !GetShellWindow(),
          "shell topmost window rejected");
    if (topmost) DestroyWindow(topmost);
    SetLastError(0x1357);
    CHECK(SetShellWindow(a) && GetShellWindow() == a && GetLastError() == 0x1357,
          "shell owned top-level registered without clearing last error");
    CHECK(GetWindow(b, GW_HWNDLAST) == a, "shell begins below ordinary windows");
    CHECK(SetWindowPos(a, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE) &&
          GetWindow(b, GW_HWNDLAST) == a, "shell remains bottom after raise request");
    CHECK(SetWindowPos(b, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE) &&
          GetWindow(b, GW_HWNDLAST) == a, "ordinary HWND_BOTTOM stays above shell");
    CHECK(SetWindowPos(b, a, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE) &&
          GetWindow(b, GW_HWNDLAST) == a, "insertion after shell stays above shell");
    SetLastError(0);
    CHECK(!SetWindowPos(a, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE) &&
          GetLastError() == ERROR_ACCESS_DENIED && !(GetWindowLongW(a, GWL_EXSTYLE) & WS_EX_TOPMOST),
          "registered shell cannot become topmost");
    SetLastError(0);
    CHECK(!SetShellWindow(b) && GetLastError() == ERROR_ACCESS_DENIED && GetShellWindow() == a,
          "shell second owned HWND rejected without replacing first");
    if (launch_shell_child(L"--shell-observer", &pi)) check_shell_child_exit(&pi, "shell cross-process observer exits successfully");
    else CHECK(0, "shell cross-process observer launches");
    CHECK(DestroyWindow(a) && !GetShellWindow(), "shell destruction clears registration");
    SetLastError(0);
    CHECK(!SetShellWindow(a) && GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "shell stale HWND rejected");
    CHECK(SetShellWindow(b) && GetShellWindow() == b, "shell replacement allowed after destruction");
    CHECK(DestroyWindow(b) && !GetShellWindow(), "shell replacement destruction clears registration");
    release = CreateEventW(0, TRUE, FALSE, L"ShzGuiShellRelease");
    CHECK(release != 0, "shell process cleanup release event created");
    if (release && launch_shell_child(L"--shell-owner", &pi)) {
        started = GetTickCount();
        do { shell = GetShellWindow(); if (shell) break; Sleep(10); } while (GetTickCount() - started < 4000);
        CHECK(shell && GetWindowThreadProcessId(shell, &pid) && pid == pi.dwProcessId,
              "shell owner child window visible to parent");
        SetLastError(0);
        CHECK(shell && !SetShellWindow(shell) && GetLastError() == ERROR_ACCESS_DENIED,
              "parent cannot register child process's window");
        SetEvent(release);
        check_shell_child_exit(&pi, "shell owner child exits without destroying window");
        CHECK(!GetShellWindow(), "shell process death clears registration");
    } else CHECK(0, "shell owner child launches");
    if (release) CloseHandle(release);
}

/* ---------------------------------------------------------------- layered windows and regions: the pixel scene */
static void test_layers(void)
{
    BITMAPINFO bi;
    void *bits = 0;
    HDC sdc = GetDC(0), mem;
    HBITMAP dib, old;
    HWND ulw, attr, key, rgnw;
    POINT src = { 0, 0 }, dst = { 100, 100 };
    SIZE sz = { 200, 150 };
    BLENDFUNCTION bf = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    int x, y;
    uint32_t *px;
    COLORREF ck;
    BYTE a;
    DWORD fl;
    memset(&bi, 0, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = 200;
    bi.bmiHeader.biHeight = -150;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    dib = CreateDIBSection(sdc, &bi, DIB_RGB_COLORS, &bits, 0, 0);
    mem = CreateCompatibleDC(sdc);
    old = SelectObject(mem, dib);
    px = bits;
    for (y = 0; y < 150; ++y)                                          /* premultiplied BGRA */
        for (x = 0; x < 200; ++x)
            px[y * 200 + x] = y >= 140 ? 0x00000000u : x < 100 ? 0xffff0000u : 0x80000080u;
    ulw = popup(L"ShzSys", WS_EX_LAYERED, 100, 100, 200, 150);
    CHECK(ulw && UpdateLayeredWindow(ulw, sdc, &dst, &sz, mem, &src, 0, &bf, ULW_ALPHA), "UpdateLayeredWindow with per-pixel alpha");
    ShowWindow(ulw, SW_SHOWNA);
    CHECK(!GetLayeredWindowAttributes(ulw, &ck, &a, &fl), "GetLayeredWindowAttributes fails for an UpdateLayeredWindow window");
    CHECK(!SetLayeredWindowAttributes(ulw, 0, 128, LWA_ALPHA), "SetLayeredWindowAttributes is refused while in UpdateLayeredWindow mode");

    attr = popup(L"ShzSysWhite", WS_EX_LAYERED, 400, 100, 200, 150);
    CHECK(SetLayeredWindowAttributes(attr, 0, 128, LWA_ALPHA) && GetLayeredWindowAttributes(attr, &ck, &a, &fl) && a == 128 && fl == LWA_ALPHA,
          "SetLayeredWindowAttributes / GetLayeredWindowAttributes (alpha 128)");
    ShowWindow(attr, SW_SHOWNA);

    key = popup(L"ShzSysKey", WS_EX_LAYERED, 400, 300, 200, 150);
    CHECK(SetLayeredWindowAttributes(key, RGB(255, 0, 255), 0, LWA_COLORKEY), "LWA_COLORKEY (magenta)");
    ShowWindow(key, SW_SHOWNA);

    rgnw = popup(L"ShzSysRed", 0, 100, 300, 200, 150);
    {
        HRGN r1 = CreateRectRgn(0, 0, 200, 50), r2 = CreateRectRgn(0, 0, 50, 150), q;
        RECT box;
        CombineRgn(r1, r1, r2, RGN_OR);
        DeleteObject(r2);
        CHECK(SetWindowRgn(rgnw, r1, TRUE), "SetWindowRgn (an L shape)");
        q = CreateRectRgn(0, 0, 0, 0);
        CHECK(GetWindowRgn(rgnw, q) == COMPLEXREGION && GetRgnBox(q, &box) && box.right == 200 && box.bottom == 150, "GetWindowRgn returns the region");
        DeleteObject(q);
    }
    ShowWindow(rgnw, SW_SHOWNA);
    pump_ms(300);
    {
        POINT p1 = { 150, 120 }, p2 = { 150, 245 }, p3 = { 500, 360 }, p4 = { 460, 310 }, p5 = { 200, 400 }, p6 = { 120, 400 };
        CHECK(WindowFromPoint(p1) == ulw && WindowFromPoint(p2) != ulw, "per-pixel alpha: opaque pixels hit the window, alpha-0 rows do not");
        CHECK(WindowFromPoint(p3) != key && WindowFromPoint(p4) == key, "colour key: keyed pixels are transparent to hit testing");
        CHECK(WindowFromPoint(p5) != rgnw && WindowFromPoint(p6) == rgnw, "window region: points outside it do not hit the window");
    }
    {                                                                   /* PrintWindow of the red region window: its own pixels */
        HDC pdc = CreateCompatibleDC(sdc);
        HBITMAP pb = CreateCompatibleBitmap(sdc, 200, 150), po = SelectObject(pdc, pb);
        CHECK(PrintWindow(rgnw, pdc, 0) && GetPixel(pdc, 10, 10) == RGB(255, 0, 0) && GetPixel(pdc, 150, 120) == RGB(255, 0, 0),
              "PrintWindow renders the window alone (the region does not clip it)");
        SelectObject(pdc, po);
        DeleteObject(pb);
        DeleteDC(pdc);
    }
    printf("GUI-READY: sys-layer\n");
    pump_ms(2000);
    DestroyWindow(ulw);
    DestroyWindow(attr);
    DestroyWindow(key);
    DestroyWindow(rgnw);
    SelectObject(mem, old);
    DeleteObject(dib);
    DeleteDC(mem);
    ReleaseDC(0, sdc);
    pump();
}

static LRESULT CALLBACK solid_proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_ERASEBKGND) {
        RECT r;
        HDC dc = (HDC)w;
        WCHAR cls[32];
        HBRUSH b;
        GetClassNameW(h, cls, 32);
        GetClientRect(h, &r);
        b = CreateSolidBrush(cls[6] == 'W' ? RGB(255, 255, 255) : cls[6] == 'K' ? RGB(0, 160, 0) : RGB(255, 0, 0));
        FillRect(dc, &r, b);
        DeleteObject(b);
        if (cls[6] == 'K') {                                            /* the magenta square that the key removes */
            RECT k = { 50, 50, 150, 100 };
            b = CreateSolidBrush(RGB(255, 0, 255));
            FillRect(dc, &k, b);
            DeleteObject(b);
        }
        return 1;
    }
    return DefWindowProcW(h, m, w, l);
}

/* ---------------------------------------------------------------- ONE helper thread that types once a window appears */
/* (one thread for every job: exited threads keep their kernel stacks until the process is reaped, so a test should not
 * spend them freely) */
typedef struct { LPCWSTR cls; WORD keys[8]; int n; } typer_t;
static typer_t g_job;
static HANDLE g_job_ready, g_job_done;
static volatile LONG g_job_kind;                                        /* 1 type keys, 2 try to open the clipboard, 3 quit */
static volatile LONG g_clip_result;

static void type_keys(const typer_t *t)
{
    int i, tries;
    for (tries = 0; tries < 400; ++tries) {                             /* up to 8 s */
        HWND f = FindWindowW(t->cls, 0);
        if (f && IsWindowVisible(f)) break;
        Sleep(20);
    }
    Sleep(100);
    for (i = 0; i < t->n; ++i) {
        INPUT in[2];
        memset(in, 0, sizeof in);
        in[0].type = in[1].type = INPUT_KEYBOARD;
        if (t->keys[i] & 0x8000) {                                      /* a character via KEYEVENTF_UNICODE */
            in[0].ki.wScan = in[1].ki.wScan = t->keys[i] & 0x7fff;
            in[0].ki.dwFlags = KEYEVENTF_UNICODE;
            in[1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        } else {
            in[0].ki.wVk = in[1].ki.wVk = t->keys[i];
            in[1].ki.dwFlags = KEYEVENTF_KEYUP;
        }
        SendInput(2, in, sizeof in[0]);
        Sleep(60);
    }
}

static DWORD WINAPI helper(LPVOID p)
{
    (void)p;
    for (;;) {
        WaitForSingleObject(g_job_ready, INFINITE);
        if (g_job_kind == 3) break;
        if (g_job_kind == 1) type_keys(&g_job);
        else if (g_job_kind == 2) {
            const LONG r = OpenClipboard(0) ? 1 : (GetLastError() == ERROR_ACCESS_DENIED ? 2 : 3);
            if (r == 1) CloseClipboard();
            g_clip_result = r;
        }
        SetEvent(g_job_done);
    }
    SetEvent(g_job_done);
    return 0;
}

static void start_job(LONG kind, LPCWSTR cls, const WORD *keys, int n)
{
    memset(&g_job, 0, sizeof g_job);
    g_job.cls = cls;
    g_job.n = n;
    if (n) memcpy(g_job.keys, keys, (size_t)n * sizeof(WORD));
    g_job_kind = kind;
    SetEvent(g_job_ready);
}
static void wait_job(void) { WaitForSingleObject(g_job_done, 10000); }

/* ---------------------------------------------------------------- clipboard */
static void test_clipboard(void)
{
    HGLOBAL g;
    DWORD seq0, seq1;
    WCHAR name[64];
    CHECK(AddClipboardFormatListener(g_main), "AddClipboardFormatListener");
    seq0 = GetClipboardSequenceNumber();
    CHECK(OpenClipboard(g_main) && EmptyClipboard(), "OpenClipboard + EmptyClipboard");
    start_job(2, 0, 0, 0);
    wait_job();
    CHECK(g_clip_result == 2, "another thread cannot open the clipboard while it is open (ERROR_ACCESS_DENIED)");
    g = GlobalAlloc(GMEM_FIXED, 12);
    memcpy(g, L"Hello", 12);
    CHECK(SetClipboardData(CF_UNICODETEXT, g) == g, "SetClipboardData(CF_UNICODETEXT)");
    g_custom_fmt = RegisterClipboardFormatW(L"ShzTest Format");
    CHECK(g_custom_fmt >= 0xC000 && GetClipboardFormatNameW(g_custom_fmt, name, 64) == 14 && name[0] == 'S' && name[13] == 't',
          "RegisterClipboardFormatW / GetClipboardFormatNameW");
    SetClipboardData(g_custom_fmt, 0);                                  /* delayed rendering */
    CHECK(GetClipboardOwner() == g_main && GetOpenClipboardWindow() == g_main, "owner and open window");
    CHECK(CloseClipboard(), "CloseClipboard");
    seq1 = GetClipboardSequenceNumber();
    CHECK(seq1 > seq0, "the sequence number grows");
    pump_ms(50);
    CHECK(g_clipupdates >= 1, "the listener got WM_CLIPBOARDUPDATE");
    CHECK(IsClipboardFormatAvailable(CF_UNICODETEXT) && IsClipboardFormatAvailable(CF_TEXT) && IsClipboardFormatAvailable(CF_OEMTEXT) &&
          IsClipboardFormatAvailable(g_custom_fmt) && !IsClipboardFormatAvailable(CF_DIB), "available formats (text synthesised)");
    CHECK(OpenClipboard(0), "OpenClipboard(NULL)");
    {
        const char *a = (const char *)GetClipboardData(CF_TEXT);
        const WCHAR *w = (const WCHAR *)GetClipboardData(CF_UNICODETEXT);
        const char *later = (const char *)GetClipboardData(g_custom_fmt);
        CHECK(w && w[0] == 'H' && w[4] == 'o' && w[5] == 0, "GetClipboardData(CF_UNICODETEXT)");
        CHECK(a && a[0] == 'H' && a[4] == 'o' && a[5] == 0, "CF_TEXT is synthesised from CF_UNICODETEXT");
        CHECK(later && !strcmp(later, "later") && g_renderformat == 1, "delayed rendering: WM_RENDERFORMAT to the owner, then the data");
    }
    {
        UINT f = 0, n = 0, first = EnumClipboardFormats(0);
        for (f = first; f; f = EnumClipboardFormats(f)) ++n;
        CHECK(first == CF_UNICODETEXT && n == (UINT)CountClipboardFormats() && n >= 5, "EnumClipboardFormats / CountClipboardFormats");
    }
    CloseClipboard();
    {                                                                   /* CF_BITMAP travels as CF_DIB */
        HDC dc = GetDC(0), m = CreateCompatibleDC(dc);
        HBITMAP b = CreateCompatibleBitmap(dc, 4, 3), o = SelectObject(m, b), got;
        SetPixel(m, 1, 1, RGB(10, 20, 30));
        SelectObject(m, o);
        OpenClipboard(g_main);
        EmptyClipboard();
        CHECK(SetClipboardData(CF_BITMAP, b) != 0, "SetClipboardData(CF_BITMAP)");
        CloseClipboard();
        CHECK(IsClipboardFormatAvailable(CF_DIB) && IsClipboardFormatAvailable(CF_BITMAP), "CF_BITMAP is kept as CF_DIB and synthesised back");
        OpenClipboard(0);
        got = (HBITMAP)GetClipboardData(CF_BITMAP);
        o = SelectObject(m, got);
        CHECK(got && GetPixel(m, 1, 1) == RGB(10, 20, 30), "the bitmap comes back with its pixels");
        SelectObject(m, o);
        CloseClipboard();
        DeleteDC(m);
        ReleaseDC(0, dc);
    }
    CHECK(RemoveClipboardFormatListener(g_main) && !RemoveClipboardFormatListener(g_main), "RemoveClipboardFormatListener");
}

/* ---------------------------------------------------------------- menus */
static void test_menus(void)
{
    HMENU m = CreatePopupMenu(), sub = CreatePopupMenu(), res;
    MENUITEMINFOW mi;
    WCHAR buf[64];
    int r;
    AppendMenuW(m, MF_STRING, 10, L"&Alpha");
    AppendMenuW(m, MF_STRING | MF_GRAYED, 11, L"&Beta");
    AppendMenuW(m, MF_SEPARATOR, 0, 0);
    AppendMenuW(m, MF_STRING, 12, L"&Gamma\tCtrl+G");
    AppendMenuW(sub, MF_STRING, 20, L"Sub &One");
    AppendMenuW(sub, MF_STRING, 21, L"Sub &Two");
    AppendMenuW(m, MF_POPUP, (UINT_PTR)sub, L"&More");
    AppendMenuW(m, MF_STRING, 13, L"E&xit");
    CHECK(GetMenuItemCount(m) == 6 && GetMenuItemID(m, 0) == 10 && GetSubMenu(m, 4) == sub && GetMenuItemID(m, 4) == (UINT)-1, "menu structure");
    CHECK((GetMenuState(m, 11, MF_BYCOMMAND) & MF_GRAYED) && (GetMenuState(m, 2, MF_BYPOSITION) & MF_SEPARATOR), "GetMenuState");
    CHECK(CheckMenuItem(m, 12, MF_CHECKED) == MF_UNCHECKED && (GetMenuState(m, 12, MF_BYCOMMAND) & MF_CHECKED), "CheckMenuItem");
    CHECK(EnableMenuItem(m, 11, MF_ENABLED) == MF_GRAYED && !(GetMenuState(m, 11, MF_BYCOMMAND) & MF_GRAYED), "EnableMenuItem returns the previous state");
    EnableMenuItem(m, 11, MF_GRAYED);
    CHECK(GetMenuStringW(m, 12, buf, 64, MF_BYCOMMAND) == 13 && buf[0] == '&', "GetMenuStringW");
    CHECK(GetMenuStringW(m, 20, buf, 64, MF_BYCOMMAND) == 8, "items of submenus are found by command id");
    CHECK(SetMenuDefaultItem(m, 13, FALSE) && GetMenuDefaultItem(m, FALSE, 0) == 13, "SetMenuDefaultItem / GetMenuDefaultItem");
    memset(&mi, 0, sizeof mi);
    mi.cbSize = sizeof mi;
    mi.fMask = MIIM_STRING;
    mi.dwTypeData = (LPWSTR)L"&Alpha 2";
    CHECK(SetMenuItemInfoW(m, 0, TRUE, &mi), "SetMenuItemInfoW");
    mi.fMask = MIIM_STRING | MIIM_ID | MIIM_STATE | MIIM_FTYPE;
    mi.dwTypeData = buf;
    mi.cch = 64;
    CHECK(GetMenuItemInfoW(m, 0, TRUE, &mi) && mi.wID == 10 && mi.cch == 8 && buf[7] == '2', "GetMenuItemInfoW");

    {                                                                   /* keyboard through the popup: Down x2 skips the grey item */
        static const WORD k1[] = { VK_DOWN, VK_DOWN, VK_RETURN };
        start_job(1, L"#32768", k1, 3);
        r = TrackPopupMenuEx(m, TPM_RETURNCMD | TPM_NONOTIFY, 300, 200, g_main, 0);
        wait_job();
        CHECK(r == 12, "TrackPopupMenuEx: Down, Down (over the greyed item and the separator), Enter -> 12");
    }
    {
        static const WORD k3[] = { VK_UP, VK_UP, VK_RIGHT, VK_DOWN, VK_DOWN, VK_RETURN };   /* Up from nothing = last (Exit), Up = More */
        start_job(1, L"#32768", k3, 6);
        r = TrackPopupMenuEx(m, TPM_RETURNCMD, 300, 200, g_main, 0);
        wait_job();
        CHECK(r == 21, "submenu: Up, Up, Right opens it, Down, Down, Enter -> 21");
    }
    {
        static const WORD k4[] = { 0x8000 | 'x' };
        start_job(1, L"#32768", k4, 1);
        r = TrackPopupMenuEx(m, TPM_RETURNCMD, 300, 200, g_main, 0);
        wait_job();
        CHECK(r == 13, "a mnemonic chooses E&xit -> 13");
    }
    {
        static const WORD k5[] = { VK_ESCAPE };
        start_job(1, L"#32768", k5, 1);
        r = TrackPopupMenuEx(m, TPM_RETURNCMD, 300, 200, g_main, 0);
        wait_job();
        CHECK(r == 0, "Escape cancels -> 0");
    }
    CHECK(DestroyMenu(m) && !IsMenu(m) && !IsMenu(sub), "DestroyMenu destroys the submenus too");
    res = LoadMenuW(g_inst, MAKEINTRESOURCEW(300));
    CHECK(res && GetMenuItemCount(res) == 2 && GetMenuItemCount(GetSubMenu(res, 0)) == 3 && GetMenuItemID(GetSubMenu(res, 0), 2) == 302 &&
          (GetMenuState(GetSubMenu(res, 0), 1, MF_BYPOSITION) & MF_SEPARATOR) && GetMenuItemID(res, 1) == 303, "LoadMenuW (RT_MENU template)");
    if (res) DestroyMenu(res);
    {
        HMENU sm = GetSystemMenu(g_main, FALSE);
        CHECK(sm && GetMenuItemCount(sm) == 7 && GetMenuItemID(sm, 6) == SC_CLOSE && GetSystemMenu(g_main, FALSE) == sm, "GetSystemMenu");
    }
}

/* ---------------------------------------------------------------- MessageBox and dialogs */
static INT_PTR CALLBACK res_dlg(HWND h, UINT m, WPARAM w, LPARAM l)
{
    (void)l;
    if (m == WM_INITDIALOG) return TRUE;
    if (m == WM_COMMAND && LOWORD(w) == IDOK) { EndDialog(h, IsDlgButtonChecked(h, 401) == BST_CHECKED ? 100 : 101); return TRUE; }
    if (m == WM_COMMAND && LOWORD(w) == IDCANCEL) { EndDialog(h, 102); return TRUE; }
    return FALSE;
}

static void test_dialogs(void)
{
    int r;
    {
        static const WORD k[] = { VK_RETURN };
        start_job(1, L"#32770", k, 1);
        r = MessageBoxW(g_main, L"Press Enter", L"Shizuku", MB_OKCANCEL | MB_ICONINFORMATION);
        wait_job();
        CHECK(r == IDOK, "MessageBoxW(MB_OKCANCEL): Enter chooses the default button OK");
        CHECK(IsWindowEnabled(g_main), "the owner is enabled again");
    }
    {
        static const WORD k[] = { VK_ESCAPE };
        start_job(1, L"#32770", k, 1);
        r = MessageBoxW(g_main, L"Press Escape", L"Shizuku", MB_YESNOCANCEL | MB_DEFBUTTON2);
        wait_job();
        CHECK(r == IDCANCEL, "MessageBoxW(MB_YESNOCANCEL): Escape -> IDCANCEL");
    }
    {
        static const WORD k[] = { VK_RETURN };
        start_job(1, L"#32770", k, 1);
        r = MessageBoxW(g_main, L"Second is default", L"Shizuku", MB_YESNO | MB_DEFBUTTON2);
        wait_job();
        CHECK(r == IDNO, "MessageBoxW(MB_YESNO | MB_DEFBUTTON2): Enter -> IDNO");
    }
    {                                                                   /* the resource dialog: Space checks the box, Enter = OK */
        static const WORD k[] = { VK_SPACE, VK_RETURN };
        start_job(1, L"#32770", k, 2);
        r = (int)DialogBoxParamW(g_inst, MAKEINTRESOURCEW(400), g_main, res_dlg, 0);
        wait_job();
        CHECK(r == 100, "DialogBoxParamW (RT_DIALOG DIALOGEX): the focused auto check box toggled by Space, Enter -> OK -> 100");
    }
    {
        static const WORD k[] = { VK_TAB, VK_TAB, VK_TAB, VK_RETURN };  /* Tab: box -> OK -> Cancel -> box; Enter on the box = default (OK) */
        start_job(1, L"#32770", k, 4);
        r = (int)DialogBoxParamW(g_inst, MAKEINTRESOURCEW(400), g_main, res_dlg, 0);
        wait_job();
        if (r != 101) printf("dialog result %d\n", r);
        CHECK(r == 101, "Tab cycles through the three tab stops; Enter on the check box presses the default button -> 101");
    }
}

/* ---------------------------------------------------------------- hooks and WinEvents */
static HHOOK g_h1, g_h2, g_hk;
static LRESULT CALLBACK getmsg_hook(int c, WPARAM w, LPARAM l) { MSG *m = (MSG *)l; if (m->message == WM_USER + 9) ++g_getmsg_seen; return CallNextHookEx(g_h1, c, w, l); }
static LRESULT CALLBACK getmsg_hook2(int c, WPARAM w, LPARAM l) { MSG *m = (MSG *)l; if (m->message == WM_USER + 9) g_getmsg_seen += 10; return CallNextHookEx(g_h2, c, w, l); }
static LRESULT CALLBACK cbt_hook(int c, WPARAM w, LPARAM l) { if (c == HCBT_CREATEWND) ++g_cbt_create; return CallNextHookEx(0, c, w, l); }
static LRESULT CALLBACK cwp_hook(int c, WPARAM w, LPARAM l) { const CWPSTRUCT *s = (const CWPSTRUCT *)l; if (s->message == WM_USER + 7) ++g_callwnd_seen; return CallNextHookEx(0, c, w, l); }
static LRESULT CALLBACK kbd_hook(int c, WPARAM w, LPARAM l) { if (c == HC_ACTION && w == 'Q') { ++g_kbd_hook; return 1; } return CallNextHookEx(g_hk, c, w, l); }
static int g_wev_create, g_wev_custom;
static HWND g_wev_hwnd;
static void CALLBACK wev_proc(HWINEVENTHOOK h, DWORD ev, HWND hwnd, LONG obj, LONG child, DWORD tid, DWORD t)
{
    (void)h; (void)obj; (void)child; (void)tid; (void)t;
    if (ev == EVENT_OBJECT_CREATE) { ++g_wev_create; g_wev_hwnd = hwnd; }
    if (ev == 0x0200000 + 1) ++g_wev_custom;                          /* an application-defined event id */
}

static void test_hooks(void)
{
    HWND w;
    HHOOK hc, hw;
    HWINEVENTHOOK we;
    MSG m;
    g_h1 = SetWindowsHookExW(WH_GETMESSAGE, getmsg_hook, 0, GetCurrentThreadId());
    g_h2 = SetWindowsHookExW(WH_GETMESSAGE, getmsg_hook2, 0, GetCurrentThreadId());
    PostMessageW(g_main, WM_USER + 9, 0, 0);
    pump();
    CHECK(g_h1 && g_h2 && g_getmsg_seen == 11, "WH_GETMESSAGE: both hooks see the message (newest first, CallNextHookEx chains)");
    UnhookWindowsHookEx(g_h1);
    UnhookWindowsHookEx(g_h2);
    CHECK(!UnhookWindowsHookEx(g_h1), "a hook cannot be removed twice");
    hc = SetWindowsHookExW(WH_CBT, cbt_hook, 0, GetCurrentThreadId());
    hw = SetWindowsHookExW(WH_CALLWNDPROC, cwp_hook, 0, GetCurrentThreadId());
    we = SetWinEventHook(EVENT_OBJECT_CREATE, EVENT_OBJECT_CREATE, 0, wev_proc, 0, 0, WINEVENT_OUTOFCONTEXT);
    w = popup(L"ShzSys", 0, 0, 0, 10, 10);
    CHECK(g_cbt_create == 1, "WH_CBT sees HCBT_CREATEWND");
    CHECK(SendMessageW(g_main, WM_USER + 7, 5, 0) == 15 && g_callwnd_seen == 1, "WH_CALLWNDPROC sees a sent message");
    CHECK(IsWinEventHookInstalled(EVENT_OBJECT_CREATE) && !IsWinEventHookInstalled(EVENT_OBJECT_DESTROY), "IsWinEventHookInstalled");
    pump();
    CHECK(g_wev_create == 1 && g_wev_hwnd == w, "an out-of-context WinEvent hook gets EVENT_OBJECT_CREATE from the message loop");
    UnhookWinEvent(we);
    we = SetWinEventHook(0x0200000 + 1, 0x0200000 + 1, 0, wev_proc, 0, 0, WINEVENT_OUTOFCONTEXT);
    NotifyWinEvent(0x0200000 + 1, g_main, OBJID_CLIENT, CHILDID_SELF);
    pump();
    CHECK(g_wev_custom == 1, "NotifyWinEvent reaches the hook");
    UnhookWinEvent(we);
    DestroyWindow(w);
    UnhookWindowsHookEx(hc);
    UnhookWindowsHookEx(hw);
    g_hk = SetWindowsHookExW(WH_KEYBOARD, kbd_hook, 0, GetCurrentThreadId());
    SetForegroundWindow(g_main);
    SetFocus(g_main);
    keybd_event('Q', 0, 0, 0);
    keybd_event('Q', 0, KEYEVENTF_KEYUP, 0);
    {
        int keydowns = 0;
        while (PeekMessageW(&m, 0, 0, 0, PM_REMOVE)) { if (m.message == WM_KEYDOWN && m.wParam == 'Q') ++keydowns; DispatchMessageW(&m); }
        CHECK(g_kbd_hook >= 1 && keydowns == 0, "WH_KEYBOARD: a hook returning nonzero discards the key message");
    }
    UnhookWindowsHookEx(g_hk);
    CHECK(!SetWindowsHookExW(WH_KEYBOARD_LL, kbd_hook, g_inst, 0) && GetLastError() == ERROR_NOT_SUPPORTED, "low-level hooks are refused (not supported)");
}

/* ---------------------------------------------------------------- DPI, display, monitors */
static int g_monitors;
static BOOL CALLBACK mon_cb(HMONITOR m, HDC dc, LPRECT r, LPARAM l)
{
    (void)m; (void)dc; (void)l;
    if (r->left == 0 && r->top == 0 && r->right == GetSystemMetrics(SM_CXSCREEN) && r->bottom == GetSystemMetrics(SM_CYSCREEN)) ++g_monitors;
    return TRUE;
}

static void test_display(void)
{
    DEVMODEW dm;
    DISPLAY_DEVICEW dd;
    MONITORINFOEXW mi;
    UINT32 np = 0, nm = 0;
    DISPLAYCONFIG_PATH_INFO paths[2];
    DISPLAYCONFIG_MODE_INFO modes[4];
    RECT r = { 0, 0, 100, 100 };
    const int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    CHECK(GetDpiForWindow(g_main) == 96 && GetDpiForSystem() == 96, "GetDpiForWindow / GetDpiForSystem: 96");
    CHECK(SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2), "SetProcessDpiAwarenessContext(PMv2)");
    CHECK(!SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_SYSTEM_AWARE) && GetLastError() == ERROR_ACCESS_DENIED, "it can be set only once");
    CHECK(AreDpiAwarenessContextsEqual(GetThreadDpiAwarenessContext(), DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) && IsProcessDPIAware(),
          "the thread follows the process context");
    CHECK(GetAwarenessFromDpiAwarenessContext(DPI_AWARENESS_CONTEXT_SYSTEM_AWARE) == DPI_AWARENESS_SYSTEM_AWARE, "GetAwarenessFromDpiAwarenessContext");
    CHECK(GetSystemMetricsForDpi(SM_CXVSCROLL, 192) == 34 && GetSystemMetricsForDpi(SM_CXSCREEN, 192) == sw, "GetSystemMetricsForDpi scales sizes, not the screen");
    CHECK(AdjustWindowRectExForDpi(&r, WS_OVERLAPPEDWINDOW, FALSE, 0, 96) && r.left == -4 && r.top == -23 && r.right == 104, "AdjustWindowRectExForDpi");
    memset(&dm, 0, sizeof dm);
    dm.dmSize = sizeof dm;
    CHECK(EnumDisplaySettingsW(0, ENUM_CURRENT_SETTINGS, &dm) && (int)dm.dmPelsWidth == sw && (int)dm.dmPelsHeight == sh && dm.dmBitsPerPel == 32,
          "EnumDisplaySettingsW: the current mode (the screen size), 32 bpp");
    CHECK(!EnumDisplaySettingsW(0, 1, &dm), "exactly one mode is listed");
    CHECK(ChangeDisplaySettingsW(&dm, 0) == DISP_CHANGE_SUCCESSFUL, "ChangeDisplaySettingsW to the current mode succeeds");
    dm.dmPelsWidth = (DWORD)sw + 16;
    CHECK(ChangeDisplaySettingsW(&dm, CDS_TEST) == DISP_CHANGE_BADMODE, "any other mode is DISP_CHANGE_BADMODE");
    memset(&dd, 0, sizeof dd);
    dd.cb = sizeof dd;
    CHECK(EnumDisplayDevicesW(0, 0, &dd, 0) && dd.DeviceName[4] == 'D' && (dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) && !EnumDisplayDevicesW(0, 1, &dd, 0),
          "EnumDisplayDevicesW: one adapter \\\\.\\DISPLAY1");
    CHECK(GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, &np, &nm) == ERROR_SUCCESS && np == 1 && nm == 2, "GetDisplayConfigBufferSizes");
    np = 2; nm = 4;
    CHECK(QueryDisplayConfig(QDC_ONLY_ACTIVE_PATHS, &np, paths, &nm, modes, 0) == ERROR_SUCCESS && np == 1 &&
          (int)modes[paths[0].sourceInfo.modeInfoIdx].sourceMode.width == sw, "QueryDisplayConfig");
    {
        DISPLAYCONFIG_SOURCE_DEVICE_NAME sn;
        memset(&sn, 0, sizeof sn);
        sn.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME;
        sn.header.size = sizeof sn;
        sn.header.adapterId = paths[0].sourceInfo.adapterId;
        sn.header.id = paths[0].sourceInfo.id;
        CHECK(DisplayConfigGetDeviceInfo(&sn.header) == ERROR_SUCCESS && sn.viewGdiDeviceName[11] == '1', "DisplayConfigGetDeviceInfo(source name)");
    }
    mi.cbSize = sizeof mi;
    CHECK(GetMonitorInfoW(MonitorFromWindow(g_main, MONITOR_DEFAULTTONULL), (LPMONITORINFO)&mi) && mi.rcMonitor.right == sw && (mi.dwFlags & MONITORINFOF_PRIMARY),
          "MonitorFromWindow / GetMonitorInfoW");
    CHECK(EnumDisplayMonitors(0, 0, mon_cb, 0) && g_monitors == 1, "EnumDisplayMonitors: one monitor");
}

/* ---------------------------------------------------------------- cross-thread notifications */
static HWND g_worker;
static volatile LONG g_worker_ready, g_worker_quit;
static LRESULT CALLBACK worker_proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_USER + 1) return (LRESULT)(w + 1000);
    return DefWindowProcW(h, m, w, l);
}
static DWORD WINAPI worker(LPVOID p)
{
    MSG m;
    (void)p;
    g_worker = CreateWindowExW(0, L"ShzSysWorker", L"w", WS_OVERLAPPED, 700, 500, 100, 80, 0, 0, g_inst, 0);
    g_worker_ready = 1;
    while (!g_worker_quit) { while (PeekMessageW(&m, 0, 0, 0, PM_REMOVE)) DispatchMessageW(&m); Sleep(5); }
    DestroyWindow(g_worker);
    return 0;
}
static LRESULT g_cb_result;
static int g_cb_calls;
static HWND g_cb_hwnd;
static void CALLBACK send_cb(HWND h, UINT m, ULONG_PTR data, LRESULT r) { (void)m; if (data == 77) { ++g_cb_calls; g_cb_result = r; g_cb_hwnd = h; } }

static void test_cross_thread(void)
{
    HANDLE t = CreateThread(0, 0, worker, 0, 0, 0);
    int i;
    for (i = 0; i < 200 && !g_worker_ready; ++i) Sleep(10);
    CHECK(SendNotifyMessageW(g_worker, WM_USER + 1, 1, 0), "SendNotifyMessageW to another thread returns at once");
    CHECK(SendMessageCallbackW(g_worker, WM_USER + 1, 5, 0, send_cb, 77), "SendMessageCallbackW");
    for (i = 0; i < 100 && !g_cb_calls; ++i) pump_ms(20);
    CHECK(g_cb_calls == 1 && g_cb_result == 1005 && g_cb_hwnd == g_worker, "the callback runs on the sender's message loop with the result");
    CHECK(SendMessageCallbackW(g_main, WM_USER + 7, 2, 0, send_cb, 77) && g_cb_calls == 2 && g_cb_result == 6, "same thread: the callback runs at once");
    CHECK(!IsWindowVisible(g_worker) && ShowWindowAsync(g_worker, SW_SHOWNA), "ShowWindowAsync to another thread's window");
    for (i = 0; i < 100 && !IsWindowVisible(g_worker); ++i) Sleep(10);
    CHECK(IsWindowVisible(g_worker), "the owner thread shows it from its message loop");
    g_worker_quit = 1;
    WaitForSingleObject(t, 5000);
    CloseHandle(t);
}

/* ---------------------------------------------------------------- resources, raw input, the rest */
static void test_misc(void)
{
    WCHAR buf[64];
    const WCHAR *ro = 0;
    HICON ic;
    ICONINFO ii;
    BITMAP bm;
    HACCEL acc;
    CHECK(LoadStringW(g_inst, 101, buf, 64) == 15 && buf[0] == 'H' && buf[14] == 's', "LoadStringW");
    CHECK(LoadStringW(g_inst, 117, (LPWSTR)&ro, 0) == 9 && ro && ro[0] == 'S', "LoadStringW with cchBufferMax 0 returns a read-only pointer");
    CHECK(!LoadStringW(g_inst, 999, buf, 64) && buf[0] == 0, "a missing string");
    ic = (HICON)LoadImageW(g_inst, MAKEINTRESOURCEW(2), IMAGE_ICON, 8, 8, 0);
    CHECK(ic && GetIconInfo(ic, &ii) && GetObjectW(ii.hbmColor, sizeof bm, &bm) && bm.bmWidth == 8 && bm.bmHeight == 8, "LoadImageW(RT_GROUP_ICON) at its own size");
    if (ic) {
        HDC dc = CreateCompatibleDC(0);
        HBITMAP o = SelectObject(dc, ii.hbmColor);
        CHECK(GetPixel(dc, 3, 1) == RGB(255, 0, 0) && GetPixel(dc, 3, 6) == RGB(0, 0, 255), "the icon's pixels (top red, bottom blue)");
        SelectObject(dc, o);
        DeleteDC(dc);
        DeleteObject(ii.hbmColor);
        DeleteObject(ii.hbmMask);
        DestroyIcon(ic);
    }
    ic = LoadIconW(g_inst, MAKEINTRESOURCEW(2));
    CHECK(ic && GetIconInfo(ic, &ii) && GetObjectW(ii.hbmColor, sizeof bm, &bm) && bm.bmWidth == 32, "LoadIconW scales to SM_CXICON");
    if (ic) { DeleteObject(ii.hbmColor); DeleteObject(ii.hbmMask); }
    acc = LoadAcceleratorsW(g_inst, MAKEINTRESOURCEW(500));
    {
        ACCEL a[4];
        CHECK(acc && CopyAcceleratorTableW(acc, 0, 0) == 2 && CopyAcceleratorTableW(acc, a, 4) == 2 && a[0].cmd == 501 && (a[0].fVirt & FCONTROL) &&
              a[1].key == VK_F5, "LoadAcceleratorsW / CopyAcceleratorTableW");
    }
    {
        MSG m;
        int got = 0;
        memset(&m, 0, sizeof m);
        m.hwnd = g_main;
        m.message = WM_KEYDOWN;
        m.wParam = VK_F5;
        CHECK(TranslateAcceleratorW(g_main, acc, &m) == 1, "TranslateAcceleratorW turns F5 into WM_COMMAND");
        (void)got;
        DestroyAcceleratorTable(acc);
    }
    {                                                                   /* raw input */
        RAWINPUTDEVICE rd[2];
        RAWINPUTDEVICELIST dl[4];
        UINT n = 4, sz;
        MSG m;
        int kbd = 0, mouse = 0;
        RAWINPUT ri;
        CHECK(GetRawInputDeviceList(dl, &n, sizeof dl[0]) == 2, "GetRawInputDeviceList: the PS/2 keyboard and mouse");
        sz = 64;
        CHECK(GetRawInputDeviceInfoW(dl[0].hDevice, RIDI_DEVICENAME, buf, &sz) > 10 && buf[0] == '\\', "GetRawInputDeviceInfoW(RIDI_DEVICENAME)");
        rd[0].usUsagePage = 1; rd[0].usUsage = 6; rd[0].dwFlags = 0; rd[0].hwndTarget = g_main;
        rd[1].usUsagePage = 1; rd[1].usUsage = 2; rd[1].dwFlags = 0; rd[1].hwndTarget = g_main;
        CHECK(RegisterRawInputDevices(rd, 2, sizeof rd[0]), "RegisterRawInputDevices(keyboard, mouse)");
        n = 4;
        CHECK(GetRegisteredRawInputDevices(rd, &n, sizeof rd[0]) == 2, "GetRegisteredRawInputDevices");
        SetForegroundWindow(g_main);
        keybd_event('A', 0, 0, 0);
        keybd_event('A', 0, KEYEVENTF_KEYUP, 0);
        mouse_event(MOUSEEVENTF_MOVE, 7, -3, 0, 0);
        while (PeekMessageW(&m, 0, 0, 0, PM_REMOVE)) {
            if (m.message == WM_INPUT) {
                sz = sizeof ri;
                if (GetRawInputData((HRAWINPUT)m.lParam, RID_INPUT, &ri, &sz, sizeof(RAWINPUTHEADER)) != (UINT)-1) {
                    if (ri.header.dwType == RIM_TYPEKEYBOARD && ri.data.keyboard.VKey == 'A' && ri.data.keyboard.MakeCode == 0x1e &&
                        !(ri.data.keyboard.Flags & RI_KEY_BREAK) && ri.data.keyboard.Message == WM_KEYDOWN && ri.header.hDevice == 0 && m.wParam == RIM_INPUT)
                        ++kbd;
                    if (ri.header.dwType == RIM_TYPEMOUSE && ri.data.mouse.lLastX == 7 && ri.data.mouse.lLastY == -3) ++mouse;
                }
            }
            DispatchMessageW(&m);
        }
        CHECK(kbd == 1 && mouse == 1, "WM_INPUT: raw keyboard (make code 0x1E, VK 'A', WM_KEYDOWN, injected = device 0) and raw mouse (+7,-3)");
        rd[0].dwFlags = rd[1].dwFlags = RIDEV_REMOVE; rd[0].hwndTarget = rd[1].hwndTarget = 0;
        n = 4;
        CHECK(RegisterRawInputDevices(rd, 2, sizeof rd[0]) && GetRegisteredRawInputDevices(0, &n, sizeof rd[0]) == 0 && n == 0, "RIDEV_REMOVE");
    }
    {                                                                   /* window station / desktop */
        WCHAR nm[32];
        DWORD need = 0;
        HDESK d = OpenInputDesktop(0, FALSE, GENERIC_READ);
        CHECK(GetUserObjectInformationW(GetProcessWindowStation(), UOI_NAME, nm, sizeof nm, &need) && nm[0] == 'W' && nm[6] == '0',
              "the window station is WinSta0");
        CHECK(GetUserObjectInformationW(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, nm, sizeof nm, &need) && nm[0] == 'D', "the desktop is Default");
        CHECK(d && CloseDesktop(d) && !CreateDesktopW(L"Other", 0, 0, 0, GENERIC_ALL, 0), "OpenInputDesktop / CloseDesktop; no second desktop");
    }
    {                                                                   /* scroll information */
        SCROLLINFO si;
        si.cbSize = sizeof si;
        si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
        si.nMin = 0; si.nMax = 100; si.nPage = 10; si.nPos = 95;
        CHECK(SetScrollInfo(g_main, SB_VERT, &si, TRUE) == 91, "SetScrollInfo clamps the position to nMax - nPage + 1");
        si.fMask = SIF_ALL;
        CHECK(GetScrollInfo(g_main, SB_VERT, &si) && si.nPos == 91 && si.nPage == 10 && GetScrollPos(g_main, SB_VERT) == 91, "GetScrollInfo / GetScrollPos");
    }
    {                                                                   /* ScrollWindowEx on real pixels */
        HDC dc = GetDC(g_main);
        RECT r = { 0, 0, 50, 10 }, upd;
        HBRUSH b = CreateSolidBrush(RGB(200, 0, 0));
        HRGN u = CreateRectRgn(0, 0, 0, 0);
        FillRect(dc, &r, b);
        DeleteObject(b);
        ReleaseDC(g_main, dc);
        CHECK(ScrollWindowEx(g_main, 0, 20, 0, 0, u, &upd, 0) != ERROR && upd.top == 0 && upd.bottom == 20, "ScrollWindowEx reports the uncovered strip");
        dc = GetDC(g_main);
        CHECK(GetPixel(dc, 10, 25) == RGB(200, 0, 0) && GetPixel(dc, 10, 35) != RGB(200, 0, 0), "the pixels moved down by 20");
        ReleaseDC(g_main, dc);
        DeleteObject(u);
    }
    {                                                                   /* DrawEdge / DrawFrameControl */
        HDC dc = CreateCompatibleDC(0);
        HBITMAP bmp = CreateBitmap(20, 20, 1, 32, 0), o = SelectObject(dc, bmp);
        RECT r = { 0, 0, 20, 20 };
        CHECK(DrawEdge(dc, &r, EDGE_RAISED, BF_RECT | BF_MIDDLE) && GetPixel(dc, 0, 0) == GetSysColor(COLOR_3DLIGHT) &&
              GetPixel(dc, 19, 19) == GetSysColor(COLOR_3DDKSHADOW) && GetPixel(dc, 1, 1) == GetSysColor(COLOR_3DHIGHLIGHT) &&
              GetPixel(dc, 10, 10) == GetSysColor(COLOR_3DFACE), "DrawEdge(EDGE_RAISED): the four bevel colours and the face");
        CHECK(DrawFrameControl(dc, &r, DFC_BUTTON, DFCS_BUTTONPUSH | DFCS_PUSHED) && GetPixel(dc, 0, 0) == GetSysColor(COLOR_3DSHADOW), "DrawFrameControl(pushed button)");
        SelectObject(dc, o);
        DeleteObject(bmp);
        DeleteDC(dc);
    }
    {
        const DWORD g0 = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
        HPEN p = CreatePen(PS_SOLID, 1, 0);
        CHECK(GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS) == g0 + 1 && GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS) >= 1,
              "GetGuiResources counts GDI and USER objects");
        DeleteObject(p);
    }
    CHECK(GetWindowDisplayAffinity(g_main, &(DWORD){ 5 }) && SetWindowDisplayAffinity(g_main, WDA_MONITOR), "Get/SetWindowDisplayAffinity");
    {
        CHANGEFILTERSTRUCT cf;
        cf.cbSize = sizeof cf;
        CHECK(ChangeWindowMessageFilterEx(g_main, WM_COPYDATA, MSGFLT_ALLOW, &cf) && cf.ExtStatus == MSGFLTINFO_NONE, "ChangeWindowMessageFilterEx (no UIPI)");
    }
    {
        UINT32 n = 7;
        CHECK(GetPointerDevices(&n, 0) && n == 0, "no pointer (touch/pen) devices");
    }
}

int main(int argc, char **argv)
{
    WNDCLASSEXW wc;
    static const struct { LPCWSTR name; WNDPROC proc; } classes[] = {
        { L"ShzSysMain", main_proc }, { L"ShzSys", 0 }, { L"ShzSysWhite", solid_proc }, { L"ShzSysKey", solid_proc }, { L"ShzSysRed", solid_proc },
        { L"ShzSysWorker", worker_proc } };
    unsigned i;
    g_inst = GetModuleHandleW(0);
    if (GetSystemMetrics(SM_CXSCREEN) == 0) { printf("SKIP: no display device\n"); return 0; }
    for (i = 0; i < sizeof classes / sizeof classes[0]; ++i) {
        memset(&wc, 0, sizeof wc);
        wc.cbSize = sizeof wc;
        wc.lpfnWndProc = classes[i].proc ? classes[i].proc : DefWindowProcW;
        wc.hInstance = g_inst;
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = classes[i].name;
        if (!RegisterClassExW(&wc)) { printf("FAIL: RegisterClassExW\n"); return 1; }
    }
    if (argc > 1 && !strcmp(argv[1], "--shell-observer")) return shell_child(0);
    if (argc > 1 && !strcmp(argv[1], "--shell-owner")) return shell_child(1);
    test_shell_registration();
    g_job_ready = CreateEventW(0, FALSE, FALSE, 0);
    g_job_done = CreateEventW(0, FALSE, FALSE, 0);
    {
        HANDLE h = CreateThread(0, 0, helper, 0, 0, 0);
        if (h) CloseHandle(h);
    }
    test_layers();
    g_main = CreateWindowExW(0, L"ShzSysMain", L"System Test", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 600, 500, 300, 200, 0, 0, g_inst, 0);
    if (!g_main) { printf("FAIL: CreateWindowExW\n"); return 1; }
    UpdateWindow(g_main);
    test_clipboard();
    test_menus();
    test_dialogs();
    test_hooks();
    test_display();
    test_cross_thread();
    test_misc();
    start_job(3, 0, 0, 0);
    wait_job();
    DestroyWindow(g_main);
    SetCursorPos(GetSystemMetrics(SM_CXSCREEN) - 1, GetSystemMetrics(SM_CYSCREEN) - 1);   /* back where T_GUI_INPUT parked it */
    printf("INPUT-PARKED: %d %d\n", GetSystemMetrics(SM_CXSCREEN) - 1, GetSystemMetrics(SM_CYSCREEN) - 1);
    printf("%s: system test\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
