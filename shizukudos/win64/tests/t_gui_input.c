/* SPDX-License-Identifier: GPL-2.0-only
 * GUI: keyboard and mouse input (kernel64/gfx_input.c + win64/dlls/user32/user32_input.c).
 *
 * Part 1, self-checking through SendInput (the same kernel decoding/routing path the PS/2 hardware uses): key messages and
 * their lParam layout, WM_CHAR from TranslateMessage with Shift/CapsLock/Ctrl, VK_PACKET, WM_SYSKEY*, extended keys,
 * scan-code injection, auto-repeat bits, GetKeyState/GetAsyncKeyState/GetKeyboardState, hot keys, the US layout functions;
 * mouse moves (relative, absolute, SetCursorPos), clicks and double clicks (CS_DBLCLKS), WM_SETCURSOR/HTCLIENT, the
 * non-client forms (HTCAPTION, HTRIGHT and the sizing cursor), capture, WM_CONTEXTMENU, the wheel, TrackMouseEvent
 * (leave and hover), ClipCursor, GetMessageExtraInfo, the caption drag loop of DefWindowProc.
 *
 * Part 2, pixels: the pointer sprite over the window (GUI-READY: input-ptr) and hidden by ShowCursor(FALSE) (input-noptr).
 *
 * Part 3, driven by the HOST through QEMU's PS/2 keyboard and mouse (tests/run_k64_gui.py sends QMP send-key and
 * input-send-event when it reads the INPUT-WAIT markers): every input message received is echoed as an "INPUT:" line which
 * the host compares with what it typed; after the mouse phase the pointer drawn at the moved position is checked in a
 * screendump (GUI-READY: input-hwptr). Without a host driver those phases report SKIP.
 *
 * Finally the pointer is parked at the bottom-right pixel (INPUT-PARKED), where the host expects it in later scenes.
 * Reports SKIP and exits 0 when there is no display. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

static int bad;
#define CHECK(cond, name) do { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s (line %d)\n", name, __LINE__); ++bad; } } while (0)

typedef struct { UINT msg; WPARAM wp; LPARAM lp; LPARAM extra; SHORT shift, lshift, lbtn; DWORD pos; } ev_t;
static ev_t g_ev[512];
static int g_nev, g_echo;
static HWND g_hwnd;
static HCURSOR g_arrow;

static const char *mname(UINT m)
{
    switch (m) {
    case WM_KEYDOWN: return "KEYDOWN"; case WM_KEYUP: return "KEYUP"; case WM_CHAR: return "CHAR";
    case WM_SYSKEYDOWN: return "SYSKEYDOWN"; case WM_SYSKEYUP: return "SYSKEYUP"; case WM_SYSCHAR: return "SYSCHAR";
    case WM_MOUSEMOVE: return "MOVE"; case WM_LBUTTONDOWN: return "LDOWN"; case WM_LBUTTONUP: return "LUP";
    case WM_LBUTTONDBLCLK: return "LDBL"; case WM_RBUTTONDOWN: return "RDOWN"; case WM_RBUTTONUP: return "RUP";
    case WM_MOUSEWHEEL: return "WHEEL"; case WM_NCMOUSEMOVE: return "NCMOVE"; default: return 0;
    }
}

static void record(UINT m, WPARAM w, LPARAM l)
{
    ev_t *e;
    if (g_nev >= 512) return;
    e = &g_ev[g_nev++];
    e->msg = m; e->wp = w; e->lp = l;
    e->extra = GetMessageExtraInfo();
    e->shift = GetKeyState(VK_SHIFT);
    e->lshift = GetKeyState(VK_LSHIFT);
    e->lbtn = GetKeyState(VK_LBUTTON);
    e->pos = GetMessagePos();
    if (g_echo && mname(m))
        printf("INPUT: %s wp=%llx lp=%08lx\n", mname(m), (unsigned long long)w, (unsigned long)(DWORD)l);
}

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if ((m >= WM_KEYFIRST && m <= WM_KEYLAST) || (m >= WM_MOUSEFIRST && m <= WM_MOUSELAST) || (m >= WM_NCMOUSEMOVE && m <= WM_NCXBUTTONDBLCLK) ||
        m == WM_HOTKEY || m == WM_MOUSELEAVE || m == WM_MOUSEHOVER || m == WM_CONTEXTMENU || m == WM_SETCURSOR || m == WM_CAPTURECHANGED ||
        m == WM_ENTERSIZEMOVE || m == WM_EXITSIZEMOVE || m == WM_MOUSEACTIVATE)
        record(m, w, l);
    return DefWindowProcW(h, m, w, l);
}

static void drain(void)
{
    MSG msg;
    while (PeekMessageW(&msg, 0, 0, 0, PM_REMOVE)) {
        if (!msg.hwnd) record(msg.message, msg.wParam, msg.lParam);
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

static void pump_ms(DWORD ms)
{
    const DWORD start = GetTickCount();
    while (GetTickCount() - start < ms) {
        MsgWaitForMultipleObjects(0, 0, FALSE, 20, QS_ALLINPUT);
        drain();
    }
}

static int find(UINT m, int from)
{
    int i;
    for (i = from < 0 ? 0 : from; i < g_nev; ++i) if (g_ev[i].msg == m) return i;
    return -1;
}
static int count(UINT m) { int i, n = 0; for (i = 0; i < g_nev; ++i) n += g_ev[i].msg == m; return n; }
static void reset(void) { drain(); g_nev = 0; }

static void key(WORD vk, WORD scan, DWORD flags)
{
    INPUT i;
    memset(&i, 0, sizeof i);
    i.type = INPUT_KEYBOARD;
    i.ki.wVk = vk;
    i.ki.wScan = scan;
    i.ki.dwFlags = flags;
    SendInput(1, &i, sizeof i);
}
static void tap(WORD vk) { key(vk, 0, 0); key(vk, 0, KEYEVENTF_KEYUP); }

static void mouse(DWORD flags, LONG dx, LONG dy, DWORD data, ULONG_PTR extra)
{
    INPUT i;
    memset(&i, 0, sizeof i);
    i.type = INPUT_MOUSE;
    i.mi.dx = dx;
    i.mi.dy = dy;
    i.mi.mouseData = data;
    i.mi.dwFlags = flags;
    i.mi.dwExtraInfo = extra;
    SendInput(1, &i, sizeof i);
}

#define LPX(l) ((int)(short)LOWORD(l))
#define LPY(l) ((int)(short)HIWORD(l))
/* window (200,150)-(600,450), WS_OVERLAPPEDWINDOW: client origin (204,173), client 392x273 */
#define CX0 204
#define CY0 173

static void test_keyboard(void)
{
    int i, j;
    BYTE ks[256], ks2[256];
    WCHAR buf[32];
    reset();
    tap('A');
    drain();
    i = find(WM_KEYDOWN, 0);
    CHECK(i >= 0 && g_ev[i].wp == 'A' && (DWORD)g_ev[i].lp == 0x001e0001u, "SendInput 'A': WM_KEYDOWN vk 0x41, lParam repeat 1 / scan 0x1E");
    j = find(WM_CHAR, i);
    CHECK(j > i && g_ev[j].wp == 'a', "TranslateMessage posts WM_CHAR 'a'");
    j = find(WM_KEYUP, i);
    CHECK(j > i && g_ev[j].wp == 'A' && (DWORD)g_ev[j].lp == 0xc01e0001u, "WM_KEYUP has the previous-state and transition bits (0xC01E0001)");

    reset();
    key(VK_SHIFT, 0, 0); tap('A'); key(VK_SHIFT, 0, KEYEVENTF_KEYUP);
    drain();
    i = find(WM_KEYDOWN, 0);
    CHECK(i >= 0 && g_ev[i].wp == VK_SHIFT && (DWORD)g_ev[i].lp == 0x002a0001u, "Shift arrives as WM_KEYDOWN VK_SHIFT with the left-shift scan code 0x2A");
    i = find(WM_KEYDOWN, i + 1);
    CHECK(i >= 0 && g_ev[i].wp == 'A' && g_ev[i].shift < 0 && g_ev[i].lshift < 0, "GetKeyState(VK_SHIFT/VK_LSHIFT) is down while the 'A' key message is handled");
    j = find(WM_CHAR, 0);
    CHECK(j >= 0 && g_ev[j].wp == 'A', "Shift+A gives WM_CHAR 'A'");
    CHECK(GetKeyState(VK_SHIFT) >= 0 && (GetAsyncKeyState(VK_SHIFT) & 0x8000) == 0, "Shift is up again afterwards (thread and async state)");

    reset();
    key(0, 0xe9, KEYEVENTF_UNICODE); key(0, 0xe9, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP);
    drain();
    i = find(WM_KEYDOWN, 0);
    j = find(WM_CHAR, 0);
    CHECK(i >= 0 && LOWORD(g_ev[i].wp) == VK_PACKET && j > i && g_ev[j].wp == 0xe9, "KEYEVENTF_UNICODE: WM_KEYDOWN VK_PACKET, then WM_CHAR U+00E9");

    reset();
    tap(VK_CAPITAL); tap('B');
    drain();
    j = find(WM_CHAR, 0);
    CHECK((GetKeyState(VK_CAPITAL) & 1) && j >= 0 && g_ev[j].wp == 'B', "Caps Lock toggles (GetKeyState bit 0) and makes 'b' upper case");
    reset();
    tap(VK_CAPITAL); tap('B');
    drain();
    j = find(WM_CHAR, 0);
    CHECK(!(GetKeyState(VK_CAPITAL) & 1) && j >= 0 && g_ev[j].wp == 'b', "a second Caps Lock press untoggles it");

    reset();
    key(VK_CONTROL, 0, 0); tap('C'); key(VK_CONTROL, 0, KEYEVENTF_KEYUP);
    drain();
    j = find(WM_CHAR, 0);
    CHECK(j >= 0 && g_ev[j].wp == 3, "Ctrl+C gives WM_CHAR 0x03");

    reset();
    key(VK_MENU, 0, 0); tap('X'); key(VK_MENU, 0, KEYEVENTF_KEYUP);
    drain();
    i = find(WM_SYSKEYDOWN, 0);
    j = find(WM_SYSKEYDOWN, i + 1);
    CHECK(i >= 0 && g_ev[i].wp == VK_MENU && j > i && g_ev[j].wp == 'X' && ((DWORD)g_ev[j].lp & (1u << 29)) && find(WM_KEYDOWN, 0) < 0,
          "Alt+X: WM_SYSKEYDOWN VK_MENU, WM_SYSKEYDOWN 'X' with the context bit 29, no WM_KEYDOWN");
    j = find(WM_SYSCHAR, 0);
    CHECK(j >= 0 && g_ev[j].wp == 'x' && count(WM_CHAR) == 0, "Alt+X: TranslateMessage posts WM_SYSCHAR 'x' (no WM_CHAR)");
    CHECK(count(WM_SYSKEYUP) == 2, "Alt+X: both releases are WM_SYSKEYUP");

    reset();
    key(VK_RIGHT, 0, KEYEVENTF_EXTENDEDKEY); key(VK_RIGHT, 0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP);
    key(0, 0x10, KEYEVENTF_SCANCODE); key(0, 0x10, KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP);
    drain();
    i = find(WM_KEYDOWN, 0);
    CHECK(i >= 0 && g_ev[i].wp == VK_RIGHT && (DWORD)g_ev[i].lp == 0x014d0001u, "extended key: VK_RIGHT with scan 0x4D and the extended bit 24");
    i = find(WM_KEYDOWN, i + 1);
    CHECK(i >= 0 && g_ev[i].wp == 'Q' && (DWORD)g_ev[i].lp == 0x00100001u, "KEYEVENTF_SCANCODE 0x10: the layout maps it to 'Q'");

    reset();
    key('D', 0, 0); key('D', 0, 0);
    CHECK((GetAsyncKeyState('D') & 0x8001) == 0x8001 && (GetAsyncKeyState('D') & 0x8001) == 0x8000,
          "GetAsyncKeyState: down, 'pressed since last call' reported once");
    key('D', 0, KEYEVENTF_KEYUP);
    drain();
    i = find(WM_KEYDOWN, 0);
    j = find(WM_KEYDOWN, i + 1);
    CHECK(i >= 0 && j > i && !((DWORD)g_ev[i].lp & (1u << 30)) && ((DWORD)g_ev[j].lp & (1u << 30)), "auto-repeat: the second WM_KEYDOWN has the previous-state bit 30");
    CHECK((GetAsyncKeyState('D') & 0x8000) == 0, "released keys are up in the async state");

    reset();
    CHECK(RegisterHotKey(g_hwnd, 7, MOD_CONTROL, 'K'), "RegisterHotKey(Ctrl+K)");
    CHECK(!RegisterHotKey(0, 8, MOD_CONTROL, 'K') && GetLastError() == ERROR_HOTKEY_ALREADY_REGISTERED, "the same hot key cannot be registered twice");
    key(VK_CONTROL, 0, 0); tap('K'); key(VK_CONTROL, 0, KEYEVENTF_KEYUP);
    drain();
    i = find(WM_HOTKEY, 0);
    CHECK(i >= 0 && g_ev[i].wp == 7 && (DWORD)g_ev[i].lp == MAKELPARAM(MOD_CONTROL, 'K'), "Ctrl+K arrives as WM_HOTKEY id 7, lParam MOD_CONTROL | 'K' << 16");
    for (j = 0, i = 0; i < g_nev; ++i) if (g_ev[i].msg == WM_KEYDOWN && g_ev[i].wp == 'K') j = 1;
    CHECK(!j, "a hot key does not produce WM_KEYDOWN for its key");
    CHECK(UnregisterHotKey(g_hwnd, 7) && !UnregisterHotKey(g_hwnd, 7) && GetLastError() == ERROR_HOTKEY_NOT_REGISTERED, "UnregisterHotKey, twice fails");

    CHECK(GetKeyboardState(ks), "GetKeyboardState");
    memcpy(ks2, ks, 256);
    ks2['Z'] = 0x81;
    CHECK(SetKeyboardState(ks2) && GetKeyState('Z') < 0 && (GetKeyState('Z') & 1), "SetKeyboardState changes the thread's key state");
    SetKeyboardState(ks);
    CHECK(GetKeyState('Z') >= 0, "and can restore it");
    CHECK(MapVirtualKeyW('A', MAPVK_VK_TO_VSC) == 0x1e && MapVirtualKeyW(0x1e, MAPVK_VSC_TO_VK) == 'A' && MapVirtualKeyW('A', MAPVK_VK_TO_CHAR) == 'A' &&
          MapVirtualKeyW(0x36, MAPVK_VSC_TO_VK_EX) == VK_RSHIFT && MapVirtualKeyW(VK_RIGHT, MAPVK_VK_TO_VSC_EX) == 0xe04d,
          "MapVirtualKeyW (VK<->scan, char, _EX forms)");
    CHECK(VkKeyScanW('a') == 'A' && VkKeyScanW('A') == 0x141 && VkKeyScanW('!') == 0x131 && VkKeyScanW('\r') == VK_RETURN, "VkKeyScanW");
    memset(ks2, 0, 256);
    ks2[VK_SHIFT] = 0x80;
    CHECK(ToUnicode('2', 0x03, ks2, buf, 32, 0) == 1 && buf[0] == '@' && ToUnicode('2', 0x8003, ks2, buf, 32, 0) == 0, "ToUnicode (Shift+2 = '@', key up = nothing)");
    CHECK(GetKeyNameTextW(0x1e0001, buf, 32) == 1 && buf[0] == 'A' && GetKeyNameTextW(0x011c0001, buf, 32) == 9 && buf[4] == 'E', "GetKeyNameTextW");
    CHECK(GetKeyboardLayout(0) == (HKL)(ULONG_PTR)0x04090409 && GetKeyboardLayoutNameW(buf) && buf[5] == '4' && buf[7] == '9', "US keyboard layout 00000409");
}

static void test_mouse(void)
{
    POINT p;
    RECT r;
    CURSORINFO ci;
    TRACKMOUSEEVENT t;
    int i, j;
    reset();
    CHECK(SetCursorPos(CX0 + 100, CY0 + 100) && GetCursorPos(&p) && p.x == CX0 + 100 && p.y == CY0 + 100, "SetCursorPos / GetCursorPos");
    drain();
    i = find(WM_MOUSEMOVE, 0);
    CHECK(i >= 0 && LPX(g_ev[i].lp) == 100 && LPY(g_ev[i].lp) == 100 && LOWORD(g_ev[i].pos) == CX0 + 100 && HIWORD(g_ev[i].pos) == CY0 + 100,
          "WM_MOUSEMOVE in client coordinates, GetMessagePos in screen coordinates");
    j = find(WM_SETCURSOR, 0);
    CHECK(j >= 0 && j < i && (HWND)g_ev[j].wp == g_hwnd && LOWORD(g_ev[j].lp) == HTCLIENT && HIWORD(g_ev[j].lp) == WM_MOUSEMOVE,
          "WM_SETCURSOR(HTCLIENT, WM_MOUSEMOVE) precedes the move");
    CHECK(GetCursor() == g_arrow, "DefWindowProc(WM_SETCURSOR) selected the class cursor");
    ci.cbSize = sizeof ci;
    CHECK(GetCursorInfo(&ci) && (ci.flags & CURSOR_SHOWING) && ci.hCursor == g_arrow && ci.ptScreenPos.x == CX0 + 100, "GetCursorInfo: showing, the class cursor, the position");

    reset();
    mouse(MOUSEEVENTF_MOVE, 10, 5, 0, 0);
    drain();
    i = find(WM_MOUSEMOVE, 0);
    CHECK(i >= 0 && LPX(g_ev[i].lp) == 110 && LPY(g_ev[i].lp) == 105, "relative SendInput move (+10,+5)");
    reset();
    {                                                                               /* 65536ths of the screen: (404,323) */
        const int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
        mouse(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, (404 * 65536 + sw - 1) / sw, (323 * 65536 + sh - 1) / sh, 0, 0);
    }
    drain();
    i = find(WM_MOUSEMOVE, 0);
    CHECK(i >= 0 && LPX(g_ev[i].lp) == 404 - CX0 && LPY(g_ev[i].lp) == 323 - CY0 && GetCursorPos(&p) && p.x == 404 && p.y == 323,
          "absolute SendInput move lands on (404,323)");

    reset();
    mouse(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0x5a5a); mouse(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0x5a5a);
    mouse(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0); mouse(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
    mouse(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0); mouse(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
    drain();
    i = find(WM_LBUTTONDOWN, 0);
    CHECK(i >= 0 && (g_ev[i].wp & MK_LBUTTON) && LPX(g_ev[i].lp) == 200 && LPY(g_ev[i].lp) == 150 && g_ev[i].lbtn < 0 && g_ev[i].extra == 0x5a5a,
          "WM_LBUTTONDOWN: MK_LBUTTON, client position, GetKeyState(VK_LBUTTON) down, GetMessageExtraInfo = dwExtraInfo");
    j = find(WM_LBUTTONDBLCLK, i);
    CHECK(j > i && count(WM_LBUTTONDBLCLK) == 1 && count(WM_LBUTTONDOWN) == 2 && count(WM_LBUTTONUP) == 3,
          "CS_DBLCLKS: down, dblclk, down for three quick clicks (every click has its WM_LBUTTONUP)");

    reset();
    mouse(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0); mouse(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0);
    drain();
    i = find(WM_RBUTTONUP, 0);
    j = find(WM_CONTEXTMENU, i);
    CHECK(i >= 0 && j > i && (HWND)g_ev[j].wp == g_hwnd && LPX(g_ev[j].lp) == 404 && LPY(g_ev[j].lp) == 323,
          "DefWindowProc(WM_RBUTTONUP) sends WM_CONTEXTMENU with screen coordinates");

    reset();
    mouse(MOUSEEVENTF_WHEEL, 0, 0, 120, 0); mouse(MOUSEEVENTF_WHEEL, 0, 0, (DWORD)-240, 0);
    drain();
    i = find(WM_MOUSEWHEEL, 0);
    j = find(WM_MOUSEWHEEL, i + 1);
    CHECK(i >= 0 && GET_WHEEL_DELTA_WPARAM(g_ev[i].wp) == 120 && j > i && GET_WHEEL_DELTA_WPARAM(g_ev[j].wp) == -240 && LPX(g_ev[i].lp) == 404,
          "the wheel: WM_MOUSEWHEEL +120 and -240 with screen coordinates");

    reset();
    SetCursorPos(300, 160);                                                       /* the caption */
    drain();
    i = find(WM_NCMOUSEMOVE, 0);
    CHECK(i >= 0 && g_ev[i].wp == HTCAPTION && LPX(g_ev[i].lp) == 300 && LPY(g_ev[i].lp) == 160 && find(WM_MOUSEMOVE, 0) < 0,
          "over the caption: WM_NCMOUSEMOVE(HTCAPTION) with screen coordinates");
    reset();
    SetCursorPos(598, 300);                                                       /* the right sizing border */
    drain();
    i = find(WM_NCMOUSEMOVE, 0);
    CHECK(i >= 0 && g_ev[i].wp == HTRIGHT && GetCursor() == LoadCursorW(0, (LPCWSTR)IDC_SIZEWE), "over the right border: HTRIGHT and the IDC_SIZEWE cursor");

    reset();
    SetCapture(g_hwnd);
    SetCursorPos(100, 100);                                                       /* outside the window */
    drain();
    i = find(WM_MOUSEMOVE, 0);
    CHECK(i >= 0 && LPX(g_ev[i].lp) == 100 - CX0 && LPY(g_ev[i].lp) == 100 - CY0 && find(WM_SETCURSOR, 0) < 0,
          "with capture a move outside the window comes as WM_MOUSEMOVE with negative client coordinates, no WM_SETCURSOR");
    ReleaseCapture();
    drain();
    CHECK(find(WM_CAPTURECHANGED, 0) >= 0 && GetCapture() == 0, "ReleaseCapture sends WM_CAPTURECHANGED");
    reset();
    SetCursorPos(90, 90);
    drain();
    CHECK(g_nev == 0, "without capture the desktop gets the move, not our window");

    reset();
    SetCursorPos(CX0 + 50, CY0 + 50);
    drain();
    t.cbSize = sizeof t; t.dwFlags = TME_LEAVE; t.hwndTrack = g_hwnd; t.dwHoverTime = 0;
    CHECK(TrackMouseEvent(&t), "TrackMouseEvent(TME_LEAVE)");
    t.dwFlags = TME_QUERY;
    CHECK(TrackMouseEvent(&t) && t.hwndTrack == g_hwnd && (t.dwFlags & TME_LEAVE), "TME_QUERY reports the tracking");
    SetCursorPos(50, 50);
    drain();
    CHECK(count(WM_MOUSELEAVE) == 1, "leaving the client area posts WM_MOUSELEAVE once");
    reset();
    SetCursorPos(CX0 + 60, CY0 + 60);
    drain();
    t.dwFlags = TME_HOVER; t.hwndTrack = g_hwnd; t.dwHoverTime = 100;
    TrackMouseEvent(&t);
    pump_ms(400);
    i = find(WM_MOUSEHOVER, 0);
    CHECK(i >= 0 && count(WM_MOUSEHOVER) == 1 && LPX(g_ev[i].lp) == 60 && LPY(g_ev[i].lp) == 60, "TME_HOVER: WM_MOUSEHOVER once after the hover time, client coordinates");

    r.left = 250; r.top = 200; r.right = 300; r.bottom = 250;
    CHECK(ClipCursor(&r) && SetCursorPos(0, 0) && GetCursorPos(&p) && p.x == 250 && p.y == 200 && SetCursorPos(1000, 700) && GetCursorPos(&p) &&
          p.x == 299 && p.y == 249, "ClipCursor confines the pointer");
    CHECK(GetClipCursor(&r) && r.left == 250 && r.bottom == 250 && ClipCursor(0) && GetClipCursor(&r) && r.right == GetSystemMetrics(SM_CXSCREEN) &&
          r.bottom == GetSystemMetrics(SM_CYSCREEN),
          "GetClipCursor / releasing the clip");

    reset();
    SetCursorPos(300, 160);
    drain();
    reset();
    mouse(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
    mouse(MOUSEEVENTF_MOVE, 30, 20, 0, 0);
    mouse(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
    drain();
    CHECK(GetWindowRect(g_hwnd, &r) && r.left == 230 && r.top == 170 && r.right == 630 && r.bottom == 470 && find(WM_ENTERSIZEMOVE, 0) >= 0 &&
          find(WM_EXITSIZEMOVE, 0) > find(WM_ENTERSIZEMOVE, 0), "dragging the caption moves the window by (30,20) (DefWindowProc move loop)");
    SetWindowPos(g_hwnd, 0, 200, 150, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    drain();
}

/* host-driven phases: echo everything and wait (at most `ms`) until `done` returns nonzero */
static int wait_host(const char *marker, DWORD ms, int (*done)(void))
{
    const DWORD start = GetTickCount();
    reset();
    g_echo = 1;
    printf("INPUT-WAIT: %s\n", marker);
    while (!done() && GetTickCount() - start < ms) {
        MsgWaitForMultipleObjects(0, 0, FALSE, 20, QS_ALLINPUT);
        drain();
    }
    pump_ms(200);                                                                 /* whatever else is still on its way */
    g_echo = 0;
    return done();
}

static int keys_done(void) { int i; for (i = 0; i < g_nev; ++i) if (g_ev[i].msg == WM_KEYUP && g_ev[i].wp == VK_RETURN) return 1; return 0; }
static int mouse_done(void) { return find(WM_LBUTTONUP, 0) >= 0; }
static int wheel_done(void) { return count(WM_MOUSEWHEEL) >= 2; }

static void test_host(void)
{
    int i, j;
    char m[64];
    static const struct { UINT msg; WPARAM wp; DWORD lp; } want[] = {
        { WM_KEYDOWN, VK_SHIFT, 0x002a0001 }, { WM_KEYDOWN, 'H', 0x00230001 }, { WM_CHAR, 'H', 0x00230001 }, { WM_KEYUP, 'H', 0xc0230001 },
        { WM_KEYUP, VK_SHIFT, 0xc02a0001 }, { WM_KEYDOWN, 'I', 0x00170001 }, { WM_CHAR, 'i', 0x00170001 }, { WM_KEYUP, 'I', 0xc0170001 },
        { WM_KEYDOWN, VK_RIGHT, 0x014d0001 }, { WM_KEYUP, VK_RIGHT, 0xc14d0001 }, { WM_KEYDOWN, VK_RETURN, 0x001c0001 },
        { WM_CHAR, '\r', 0x001c0001 }, { WM_KEYUP, VK_RETURN, 0xc01c0001 } };
    SetForegroundWindow(g_hwnd);
    SetFocus(g_hwnd);
    if (!wait_host("keys", 15000, keys_done)) {
        printf("SKIP: no host keyboard input arrived (run under tests/run_k64_gui.py)\n");
    } else {
        int ok = 1;
        for (i = 0, j = 0; i < g_nev && j < (int)(sizeof want / sizeof want[0]); ++i) {
            if (!mname(g_ev[i].msg)) continue;
            if (g_ev[i].msg != want[j].msg || g_ev[i].wp != want[j].wp || (DWORD)g_ev[i].lp != want[j].lp) { ok = 0; break; }
            ++j;
        }
        CHECK(ok && j == (int)(sizeof want / sizeof want[0]), "PS/2 keyboard (host send-key Shift+H, I, Right, Enter): exact key/char message sequence");
    }
    SetCursorPos(404, 323);
    drain();
    snprintf(m, sizeof m, "mouse %d %d", 404, 323);
    if (!wait_host(m, 15000, mouse_done)) {
        printf("SKIP: no host mouse input arrived (run under tests/run_k64_gui.py)\n");
    } else {
        POINT p;
        i = find(WM_LBUTTONDOWN, 0);
        j = find(WM_MOUSEMOVE, 0);
        CHECK(j >= 0 && i > j && LPX(g_ev[i].lp) == 404 + 40 - CX0 && LPY(g_ev[i].lp) == 323 + 30 - CY0 && GetCursorPos(&p) && p.x == 444 && p.y == 353,
              "PS/2 mouse (host relative move +40,+30 then a left click): WM_MOUSEMOVE, WM_LBUTTONDOWN at the moved position");
        printf("GUI-READY: input-hwptr\n");
        pump_ms(2000);
    }
    if (!wait_host("wheel", 15000, wheel_done)) {
        printf("SKIP: no host wheel input arrived (run under tests/run_k64_gui.py)\n");
    } else {
        i = find(WM_MOUSEWHEEL, 0);
        j = find(WM_MOUSEWHEEL, i + 1);
        CHECK(GET_WHEEL_DELTA_WPARAM(g_ev[i].wp) == 120 && GET_WHEEL_DELTA_WPARAM(g_ev[j].wp) == -120,
              "PS/2 IntelliMouse wheel (host wheel-up, wheel-down): WM_MOUSEWHEEL +120 then -120");
    }
}

int main(void)
{
    WNDCLASSEXW wc;
    HINSTANCE inst = GetModuleHandleW(0);
    CURSORINFO ci;
    POINT p;
    if (GetSystemMetrics(SM_CXSCREEN) == 0) { printf("SKIP: no display device\n"); return 0; }
    CHECK(GetSystemMetrics(SM_MOUSEPRESENT) && GetSystemMetrics(SM_CMOUSEBUTTONS) == 3 && GetSystemMetrics(SM_MOUSEWHEELPRESENT),
          "the PS/2 mouse (with wheel) was detected");
    g_arrow = LoadCursorW(0, (LPCWSTR)IDC_ARROW);
    memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.style = CS_DBLCLKS;
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.hCursor = g_arrow;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ShzInput";
    CHECK(RegisterClassExW(&wc) != 0, "RegisterClassExW");
    g_hwnd = CreateWindowExW(0, L"ShzInput", L"Input Test", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 200, 150, 400, 300, 0, 0, inst, 0);
    if (!g_hwnd) { printf("FAIL: CreateWindowExW\n"); return 1; }
    UpdateWindow(g_hwnd);
    CHECK(GetForegroundWindow() == g_hwnd && GetFocus() == g_hwnd, "the window is foreground and has the focus");
    test_keyboard();
    test_mouse();

    SetCursorPos(404, 323);                                                       /* part 2: the pointer sprite */
    drain();
    printf("GUI-READY: input-ptr\n");
    pump_ms(2000);
    CHECK(ShowCursor(FALSE) == -1, "ShowCursor(FALSE) returns -1");
    ci.cbSize = sizeof ci;
    CHECK(GetCursorInfo(&ci) && !(ci.flags & CURSOR_SHOWING), "GetCursorInfo: not showing while the count is negative");
    printf("GUI-READY: input-noptr\n");
    pump_ms(2000);
    CHECK(ShowCursor(TRUE) == 0, "ShowCursor(TRUE) returns 0");

    test_host();

    SetCursorPos(GetSystemMetrics(SM_CXSCREEN) - 1, GetSystemMetrics(SM_CYSCREEN) - 1);   /* the bottom-right pixel */
    drain();
    GetCursorPos(&p);
    printf("INPUT-PARKED: %ld %ld\n", (long)p.x, (long)p.y);
    CHECK(DestroyWindow(g_hwnd), "DestroyWindow");
    printf("%s: input test\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
