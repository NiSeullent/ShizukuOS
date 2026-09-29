/* SPDX-License-Identifier: GPL-2.0-only
 * GUI: messages and window management semantics, self-checking (no pixels): posted-message order and filtering, same-thread
 * and cross-thread SendMessage (the window procedure runs on the OWNING thread, in both directions), SendMessageTimeout,
 * thread messages, WM_QUIT, timers (window, thread and TIMERPROC), one WM_PAINT for many InvalidateRects with region
 * arithmetic, child windows and destruction order, window longs/extra bytes/properties, focus, class operations.
 * Reports SKIP and exits 0 when there is no display. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

static int bad;
#define CHECK(cond, name) do { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s (line %d)\n", name, __LINE__); ++bad; } } while (0)

static HINSTANCE g_inst;
static WPARAM g_seq[32];
static int g_nseq;
static DWORD g_handler_tid, g_worker_tid;
static int g_paints, g_timer_hits, g_proc_hits, g_ndestroy, g_style_changed, g_setfocus, g_killfocus;
static RECT g_last_paint;
static HWND g_destroy_order[8];

#define WM_T1 (WM_APP + 1)
#define WM_T20 (WM_APP + 20)
#define WM_T30 (WM_APP + 30)
#define WM_T31 (WM_APP + 31)
#define WM_T40 (WM_APP + 40)
#define WM_T50 (WM_APP + 50)

static LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_T1 + 0: case WM_T1 + 1: case WM_T1 + 2: case WM_T1 + 3: case WM_T1 + 4:
        if (g_nseq < 32) g_seq[g_nseq++] = w;
        return 0;
    case WM_T20: g_handler_tid = GetCurrentThreadId(); return (LRESULT)(w * 10 + l);
    case WM_T30: g_handler_tid = GetCurrentThreadId(); return (LRESULT)(w * 100 + l);
    case WM_T31: PostQuitMessage((int)w); return 0;
    case WM_T40: g_handler_tid = GetCurrentThreadId(); return (LRESULT)(w * 10 + l);
    case WM_T50: return 0;
    case WM_TIMER:
        if (w == 1) ++g_timer_hits;
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        BeginPaint(h, &ps);
        g_last_paint = ps.rcPaint;
        EndPaint(h, &ps);
        ++g_paints;
        return 0;
    }
    case WM_STYLECHANGED: ++g_style_changed; return 0;
    case WM_SETFOCUS: ++g_setfocus; return 0;
    case WM_KILLFOCUS: ++g_killfocus; return 0;
    case WM_DESTROY:
        if (g_ndestroy < 8) g_destroy_order[g_ndestroy++] = h;
        return 0;
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    case WM_NCDESTROY:
        if (GetWindowLongPtrW(h, GWLP_USERDATA) == 0x51) PostQuitMessage(9);       /* the worker window ends its own loop */
        break;
    }
    return DefWindowProcW(h, m, w, l);
}

static void CALLBACK timerproc(HWND h, UINT m, UINT_PTR id, DWORD t) { (void)h; (void)m; (void)id; (void)t; ++g_proc_hits; }
static BOOL CALLBACK count_cb(HWND h, LPARAM lp) { (void)h; ++*(int *)lp; return TRUE; }
static BOOL CALLBACK find_cb(HWND h, LPARAM lp) { if (h == ((HWND *)lp)[0]) ((HWND *)lp)[1] = h; return TRUE; }

/* dispatch everything that is queued right now */
static int drain(void)
{
    MSG msg;
    int n = 0;
    while (PeekMessageW(&msg, 0, 0, 0, PM_REMOVE)) { DispatchMessageW(&msg); ++n; }
    return n;
}

/* pump for `ms`; a 10 ms thread timer is the heartbeat that lets WaitMessage return (its ticks are ignored by DispatchMessage) */
static void pump_for(DWORD ms)
{
    const DWORD t0 = GetTickCount();
    MSG msg;
    const UINT_PTR beat = SetTimer(0, 0, 10, 0);
    while (GetTickCount() - t0 < ms) {
        if (PeekMessageW(&msg, 0, 0, 0, PM_REMOVE)) DispatchMessageW(&msg);
        else WaitMessage();
    }
    KillTimer(0, beat);
}

static HANDLE g_ready, g_go;
static HWND g_main_hwnd, g_worker_hwnd, g_stuck_hwnd;
static LRESULT g_worker_result;
static int g_worker_ok;

/* worker 1: sends to a window of the main thread (which is pumping) */
static DWORD WINAPI worker_send(LPVOID arg)
{
    WCHAR t[32];
    DWORD err;
    (void)arg;
    g_worker_result = SendMessageW(g_main_hwnd, WM_T30, 5, 7);
    g_worker_ok = g_worker_result == 507;
    SetLastError(0);
    SetWindowTextW(g_main_hwnd, L"changed by worker");                /* WM_SETTEXT with a pointer into this thread's stack */
    GetWindowTextW(g_main_hwnd, t, 32);
    g_worker_ok = g_worker_ok && t[0] == 'c' && t[1] == 'h';
    SetLastError(0);
    err = DestroyWindow(g_main_hwnd) ? 0 : GetLastError();
    g_worker_ok = g_worker_ok && err == ERROR_ACCESS_DENIED;         /* only the owning thread may destroy a window */
    PostMessageW(g_main_hwnd, WM_T31, 3, 0);
    return 0;
}

/* worker 2: owns a window and pumps; main sends into it */
static DWORD WINAPI worker_pump(LPVOID arg)
{
    MSG msg;
    int r;
    (void)arg;
    g_worker_tid = GetCurrentThreadId();       /* not the id CreateThread returns: NtQueryInformationThread reports t->id*4, the TEB has t->tid (kernel bug, not ours) */
    g_worker_hwnd = CreateWindowExW(0, L"ShzMsg", L"worker", WS_OVERLAPPED, 0, 0, 50, 50, HWND_MESSAGE, 0, g_inst, 0);
    if (!g_worker_hwnd) return 100;
    SetWindowLongPtrW(g_worker_hwnd, GWLP_USERDATA, 0x51);
    SetEvent(g_ready);
    while ((r = GetMessageW(&msg, 0, 0, 0)) > 0) {
        if (msg.hwnd == 0 && msg.message == WM_APP + 60) { g_seq[31] = msg.wParam; continue; }
        DispatchMessageW(&msg);
    }
    return (DWORD)msg.wParam;
}

/* worker 4: after a delay, posts to the main thread and signals an event (for the MsgWaitForMultipleObjects tests) */
static HANDLE g_evt;
static DWORD g_main_tid;
static DWORD g_delay_ms;
static int g_do_post, g_do_event;
static DWORD WINAPI worker_delayed(LPVOID arg)
{
    (void)arg;
    Sleep(g_delay_ms);
    if (g_do_post) PostThreadMessageW(g_main_tid, WM_APP + 70, 1, 0);
    if (g_do_event) SetEvent(g_evt);
    return 0;
}

/* worker 3: owns a window but does not pump for a while */
static DWORD WINAPI worker_stuck(LPVOID arg)
{
    (void)arg;
    g_stuck_hwnd = CreateWindowExW(0, L"ShzMsg", L"stuck", WS_OVERLAPPED, 0, 0, 50, 50, HWND_MESSAGE, 0, g_inst, 0);
    SetEvent(g_ready);
    WaitForSingleObject(g_go, 5000);                                  /* not pumping */
    DestroyWindow(g_stuck_hwnd);
    return 0;
}

int main(void)
{
    WNDCLASSEXW wc;
    HWND w, v, p, c;
    MSG msg;
    int i, r;
    HANDLE th;
    DWORD code = 0, t0, tid;
    RECT rc, rc2, pc;
    g_inst = GetModuleHandleW(0);
    if (GetSystemMetrics(SM_CXSCREEN) == 0) { printf("SKIP: no display device\n"); return 0; }
    memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = proc;
    wc.hInstance = g_inst;
    wc.cbWndExtra = 16;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"ShzMsg";
    CHECK(RegisterClassExW(&wc) != 0, "RegisterClassExW(ShzMsg)");
    g_ready = CreateEventW(0, TRUE, FALSE, 0);
    g_go = CreateEventW(0, TRUE, FALSE, 0);

    /* ---- a message-only window: never shown, only receives messages */
    w = CreateWindowExW(0, L"ShzMsg", L"msgonly", WS_OVERLAPPED, 0, 0, 0, 0, HWND_MESSAGE, 0, g_inst, 0);
    g_main_hwnd = w;
    CHECK(w && !IsWindowVisible(w) && IsWindow(w), "HWND_MESSAGE window: created, exists, never visible");
    CHECK(GetParent(w) == 0, "GetParent of a top-level window is NULL");

    /* ---- posted messages keep order; filters; thread messages; queue status */
    for (i = 0; i < 5; ++i) PostMessageW(w, WM_T1 + i, (WPARAM)(i + 1), 0);
    CHECK((GetQueueStatus(QS_POSTMESSAGE) & QS_POSTMESSAGE) != 0, "GetQueueStatus reports queued posted messages");
    drain();
    CHECK(g_nseq == 5 && g_seq[0] == 1 && g_seq[1] == 2 && g_seq[2] == 3 && g_seq[3] == 4 && g_seq[4] == 5, "posted messages are dispatched in order");
    CHECK(GetQueueStatus(QS_POSTMESSAGE) == 0, "the queue is empty afterwards");
    PostMessageW(w, WM_T50, 10, 0);
    PostMessageW(w, WM_T50 + 1, 11, 0);
    CHECK(PeekMessageW(&msg, 0, WM_T50 + 1, WM_T50 + 1, PM_REMOVE) && msg.wParam == 11 && msg.hwnd == w, "PeekMessage with a message range skips earlier messages");
    CHECK(PeekMessageW(&msg, 0, 0, 0, PM_NOREMOVE) && msg.wParam == 10, "PM_NOREMOVE leaves the message in the queue");
    CHECK(PeekMessageW(&msg, w, 0, 0, PM_REMOVE) && msg.wParam == 10 && !PeekMessageW(&msg, 0, 0, 0, PM_REMOVE), "PM_REMOVE takes it out; the queue is then empty");
    PostMessageW(0, WM_APP + 60, 77, 0);
    CHECK(PeekMessageW(&msg, 0, 0, 0, PM_REMOVE) && msg.hwnd == 0 && msg.message == WM_APP + 60 && msg.wParam == 77, "PostMessage(NULL) posts a thread message to the caller");
    CHECK(PostThreadMessageW(GetCurrentThreadId(), WM_APP + 61, 5, 0) && PeekMessageW(&msg, 0, 0, 0, PM_REMOVE) && msg.message == WM_APP + 61, "PostThreadMessage to our own thread");
    CHECK(SendMessageW(w, WM_T20, 3, 4) == 34 && g_handler_tid == GetCurrentThreadId(), "SendMessage to a window of the calling thread calls the procedure directly");

    /* ---- PostQuitMessage / WM_QUIT */
    PostQuitMessage(7);
    PostMessageW(w, WM_T50, 1, 0);
    r = GetMessageW(&msg, 0, 0, 0);
    CHECK(r > 0 && msg.message == WM_T50, "a posted message is delivered before WM_QUIT");
    r = GetMessageW(&msg, 0, 0, 0);
    CHECK(r == 0 && msg.message == WM_QUIT && msg.wParam == 7, "then GetMessage returns 0 with WM_QUIT and the exit code");

    /* ---- cross-thread SendMessage: worker sends to us while we pump */
    th = CreateThread(0, 0, worker_send, 0, 0, &tid);
    CHECK(th != 0, "CreateThread(worker_send)");
    t0 = GetTickCount();
    while (GetTickCount() - t0 < 5000 && (r = GetMessageW(&msg, 0, 0, 0)) > 0) DispatchMessageW(&msg);
    CHECK(r == 0 && msg.wParam == 3, "the worker's posted WM_APP+31 ended our loop");
    WaitForSingleObject(th, 5000);
    GetExitCodeThread(th, &code);
    CloseHandle(th);
    CHECK(g_worker_ok, "worker: SendMessage result 507, SetWindowText across threads, DestroyWindow refused with ERROR_ACCESS_DENIED");
    CHECK(g_handler_tid == GetCurrentThreadId(), "the window procedure ran on the thread that owns the window");
    {
        WCHAR t[32];
        GetWindowTextW(w, t, 32);
        CHECK(t[0] == 'c' && t[1] == 'h' && t[16] == 'r' && t[17] == 0, "the title changed by the worker is visible here");
    }

    /* ---- the other direction: we send into a window owned by a pumping worker */
    th = CreateThread(0, 0, worker_pump, 0, 0, &tid);
    WaitForSingleObject(g_ready, 5000);
    tid = g_worker_tid;
    CHECK(g_worker_hwnd && GetWindowThreadProcessId(g_worker_hwnd, 0) == tid && tid != GetCurrentThreadId(), "worker window exists and belongs to the worker thread");
    r = (int)SendMessageW(g_worker_hwnd, WM_T40, 1, 2);
    CHECK(r == 12 && g_handler_tid == tid, "SendMessage into another thread's window runs there and returns its result");
    PostThreadMessageW(tid, WM_APP + 60, 555, 0);
    Sleep(50);
    PostMessageW(g_worker_hwnd, WM_CLOSE, 0, 0);
    WaitForSingleObject(th, 5000);
    GetExitCodeThread(th, &code);
    CloseHandle(th);
    CHECK(code == 9, "the worker's loop ended through WM_CLOSE, DestroyWindow, WM_NCDESTROY and its own PostQuitMessage(9)");
    CHECK(g_seq[31] == 555, "PostThreadMessage delivered a thread message to the worker's GetMessage");
    CHECK(!IsWindow(g_worker_hwnd), "the worker's window is gone");

    /* ---- SendMessageTimeout to a thread that does not pump */
    ResetEvent(g_ready);
    th = CreateThread(0, 0, worker_stuck, 0, 0, &tid);
    WaitForSingleObject(g_ready, 5000);
    {
        DWORD_PTR res = 123;
        DWORD t1 = GetTickCount(), el;
        SetLastError(0);
        r = (int)SendMessageTimeoutW(g_stuck_hwnd, WM_T50, 0, 0, SMTO_NORMAL, 150, &res);
        el = GetTickCount() - t1;
        CHECK(r == 0 && GetLastError() == ERROR_TIMEOUT && el >= 120 && el < 1500, "SendMessageTimeout to a busy thread times out with ERROR_TIMEOUT");
    }
    SetEvent(g_go);
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
    CHECK(!IsWindow(g_stuck_hwnd), "a window is gone when its thread destroyed it");

    /* ---- timers */
    g_timer_hits = 0;
    CHECK(SetTimer(w, 1, 30, 0) == 1, "SetTimer(hwnd, 1, 30 ms)");
    pump_for(400);
    CHECK(g_timer_hits >= 4 && g_timer_hits <= 14, "a 30 ms window timer fires repeatedly");
    CHECK(KillTimer(w, 1), "KillTimer");
    i = g_timer_hits;
    pump_for(150);
    CHECK(g_timer_hits == i, "no more ticks after KillTimer");
    CHECK(!KillTimer(w, 99), "KillTimer of an unknown timer fails");
    {
        UINT_PTR id = SetTimer(0, 0, 30, timerproc);
        g_proc_hits = 0;
        CHECK(id != 0, "SetTimer(NULL, 0, ..., TIMERPROC) returns a new thread timer id");
        pump_for(300);
        KillTimer(0, id);
        CHECK(g_proc_hits >= 3, "DispatchMessage calls the TIMERPROC of a thread timer");
    }

    /* ---- MsgWaitForMultipleObjects: waits for handles and for queue input */
    g_evt = CreateEventW(0, TRUE, FALSE, 0);
    g_main_tid = GetCurrentThreadId();
    {
        DWORD t1 = GetTickCount(), el;
        r = (int)MsgWaitForMultipleObjects(1, &g_evt, FALSE, 120, QS_ALLINPUT);
        el = GetTickCount() - t1;
        CHECK(r == WAIT_TIMEOUT && el >= 100 && el < 1500, "MsgWaitForMultipleObjects times out when neither the handle nor the queue is signalled");
        g_do_post = 1; g_do_event = 0; g_delay_ms = 80;
        th = CreateThread(0, 0, worker_delayed, 0, 0, &tid);
        t1 = GetTickCount();
        r = (int)MsgWaitForMultipleObjects(1, &g_evt, FALSE, 3000, QS_POSTMESSAGE);
        el = GetTickCount() - t1;
        CHECK(r == WAIT_OBJECT_0 + 1 && el >= 50 && el < 2000 && PeekMessageW(&msg, 0, 0, 0, PM_REMOVE) && msg.message == WM_APP + 70,
              "a message posted by another thread wakes the wait (index = handle count)");
        WaitForSingleObject(th, 3000);
        CloseHandle(th);
        CHECK(MsgWaitForMultipleObjects(1, &g_evt, FALSE, 30, QS_ALLINPUT) == WAIT_TIMEOUT, "and after removing it the queue no longer wakes the wait");
        g_do_post = 0; g_do_event = 1; g_delay_ms = 80;
        th = CreateThread(0, 0, worker_delayed, 0, 0, &tid);
        r = (int)MsgWaitForMultipleObjects(1, &g_evt, FALSE, 3000, QS_ALLINPUT);
        CHECK(r == WAIT_OBJECT_0, "a signalled handle wakes the wait with its own index");
        WaitForSingleObject(th, 3000);
        CloseHandle(th);
        ResetEvent(g_evt);
        SetTimer(w, 5, 70, 0);
        t1 = GetTickCount();
        r = (int)MsgWaitForMultipleObjects(1, &g_evt, FALSE, 3000, QS_TIMER);
        el = GetTickCount() - t1;
        CHECK(r == WAIT_OBJECT_0 + 1 && el >= 40 && el < 2000, "a timer becoming due wakes a QS_TIMER wait");
        KillTimer(w, 5);
        PostMessageW(w, WM_T50, 0, 0);
        CHECK(MsgWaitForMultipleObjects(0, 0, FALSE, 0, QS_ALLINPUT) == WAIT_OBJECT_0, "already-queued input satisfies the wait immediately");
        drain();
        CloseHandle(g_evt);
    }

    /* ---- window messages ids, atoms, classes */
    {
        UINT a = RegisterWindowMessageW(L"ShzTestMessage"), b2 = RegisterWindowMessageW(L"shztestmessage"), c2 = RegisterWindowMessageW(L"ShzOther");
        CHECK(a >= 0xC000 && a == b2 && c2 != a && c2 >= 0xC000, "RegisterWindowMessageW: same name same id (case-insensitive), ids in 0xC000..");
    }
    {
        WNDCLASSEXW q;
        memset(&q, 0, sizeof q);
        q.cbSize = sizeof q;
        CHECK(GetClassInfoExW(g_inst, L"ShzMsg", &q) && q.lpfnWndProc == proc && q.cbWndExtra == 16 && q.hbrBackground == (HBRUSH)(COLOR_BTNFACE + 1),
              "GetClassInfoExW returns what was registered");
        CHECK((WNDPROC)GetClassLongPtrW(w, GCLP_WNDPROC) == proc && GetClassLongW(w, GCL_CBWNDEXTRA) == 16, "GetClassLongPtr(GCLP_WNDPROC) and GCL_CBWNDEXTRA");
        CHECK(!UnregisterClassW(L"ShzMsg", g_inst) && GetLastError() == ERROR_CLASS_HAS_WINDOWS, "UnregisterClass with live windows fails with ERROR_CLASS_HAS_WINDOWS");
        CHECK(CreateWindowExW(0, L"NoSuchClass", L"x", 0, 0, 0, 1, 1, 0, 0, g_inst, 0) == 0 && GetLastError() == ERROR_CANNOT_FIND_WND_CLASS, "unknown class: ERROR_CANNOT_FIND_WND_CLASS");
    }

    /* ---- window longs, extra bytes, properties, styles */
    CHECK(SetWindowLongPtrW(w, 0, 0x1122334455667788ll) == 0 && SetWindowLongPtrW(w, 8, 0x99) == 0 && GetWindowLongPtrW(w, 0) == 0x1122334455667788ll &&
          GetWindowLongPtrW(w, 8) == 0x99, "cbWndExtra bytes round-trip (two 64-bit slots)");
    GetWindowLongPtrW(w, 16);
    CHECK(GetLastError() == ERROR_INVALID_INDEX, "an index beyond cbWndExtra is ERROR_INVALID_INDEX");
    CHECK(SetWindowLongPtrW(w, GWLP_USERDATA, 0x4242) == 0 && GetWindowLongPtrW(w, GWLP_USERDATA) == 0x4242, "GWLP_USERDATA");
    CHECK(SetWindowLongPtrW(w, GWLP_ID, 77) == 0 && GetWindowLongPtrW(w, GWLP_ID) == 77, "GWLP_ID");
    g_style_changed = 0;
    SetWindowLongPtrW(w, GWL_STYLE, GetWindowLongPtrW(w, GWL_STYLE) | WS_BORDER);
    CHECK(g_style_changed == 1 && (GetWindowLongPtrW(w, GWL_STYLE) & WS_BORDER), "SetWindowLong(GWL_STYLE) sends WM_STYLECHANGED");
    {
        WNDPROC old = (WNDPROC)SetWindowLongPtrW(w, GWLP_WNDPROC, (LONG_PTR)DefWindowProcW);
        CHECK(old == proc && (WNDPROC)GetWindowLongPtrW(w, GWLP_WNDPROC) == DefWindowProcW, "GWLP_WNDPROC subclassing");
        SetWindowLongPtrW(w, GWLP_WNDPROC, (LONG_PTR)proc);
    }
    CHECK(SetPropW(w, L"ShzProp", (HANDLE)0x1234) && GetPropW(w, L"ShzProp") == (HANDLE)0x1234 && GetPropW(w, L"shzprop") == (HANDLE)0x1234,
          "SetProp/GetProp with a string key (case-insensitive)");
    CHECK(RemovePropW(w, L"ShzProp") == (HANDLE)0x1234 && GetPropW(w, L"ShzProp") == 0, "RemoveProp");
    CHECK(SetPropW(w, (LPCWSTR)(ULONG_PTR)0xC123, (HANDLE)5) && GetPropW(w, (LPCWSTR)(ULONG_PTR)0xC123) == (HANDLE)5, "SetProp/GetProp with an atom key");

    /* ---- one WM_PAINT for many InvalidateRects; regions; priority */
    v = CreateWindowExW(0, L"ShzMsg", L"paint", WS_OVERLAPPED | WS_VISIBLE, 600, 20, 260, 160, 0, 0, g_inst, 0);
    CHECK(v != 0, "visible window for the paint tests");
    drain();
    CHECK(GetFocus() == v && g_setfocus == 1 && GetActiveWindow() == v, "activating the new window gave it the focus (DefWindowProc(WM_ACTIVATE) -> SetFocus -> WM_SETFOCUS)");
    g_paints = 0;
    CHECK(GetUpdateRect(v, &rc, FALSE) == FALSE, "no update region after the first paint cycle");
    rc.left = 0; rc.top = 0; rc.right = 100; rc.bottom = 50;
    rc2.left = 60; rc2.top = 30; rc2.right = 160; rc2.bottom = 80;
    InvalidateRect(v, &rc, FALSE);
    InvalidateRect(v, &rc2, FALSE);
    InvalidateRect(v, &rc, TRUE);
    CHECK(GetUpdateRect(v, &pc, FALSE) && pc.left == 0 && pc.top == 0 && pc.right == 160 && pc.bottom == 80, "GetUpdateRect is the bounding box of the invalidated rectangles");
    PostMessageW(v, WM_T50, 0, 0);
    r = GetMessageW(&msg, 0, 0, 0);
    CHECK(r > 0 && msg.message == WM_T50, "a posted message is retrieved before WM_PAINT");
    DispatchMessageW(&msg);
    r = GetMessageW(&msg, 0, 0, 0);
    CHECK(r > 0 && msg.message == WM_PAINT && msg.hwnd == v, "then WM_PAINT arrives");
    DispatchMessageW(&msg);
    CHECK(g_paints == 1 && g_last_paint.left == 0 && g_last_paint.top == 0 && g_last_paint.right == 160 && g_last_paint.bottom == 80,
          "three InvalidateRects produced exactly one WM_PAINT covering their union");
    CHECK(!PeekMessageW(&msg, 0, 0, 0, PM_REMOVE), "and nothing else is pending");
    InvalidateRect(v, &rc, FALSE);
    rc2.left = 0; rc2.top = 0; rc2.right = 100; rc2.bottom = 25;
    ValidateRect(v, &rc2);
    CHECK(GetUpdateRect(v, &pc, FALSE) && pc.left == 0 && pc.top == 25 && pc.right == 100 && pc.bottom == 50, "ValidateRect removes part of the update region");
    ValidateRect(v, 0);
    CHECK(!GetUpdateRect(v, &pc, FALSE) && !PeekMessageW(&msg, 0, 0, 0, PM_REMOVE), "ValidateRect(NULL) clears it, no WM_PAINT");
    {
        HRGN rg = CreateRectRgn(10, 10, 60, 40);
        g_paints = 0;
        InvalidateRgn(v, rg, FALSE);
        CHECK(GetUpdateRect(v, &pc, FALSE) && pc.left == 10 && pc.top == 10 && pc.right == 60 && pc.bottom == 40, "InvalidateRgn");
        RedrawWindow(v, 0, 0, RDW_UPDATENOW);
        CHECK(g_paints == 1 && !GetUpdateRect(v, &pc, FALSE), "RedrawWindow(RDW_UPDATENOW) paints synchronously");
        DeleteObject(rg);
    }
    /* Invalidating a hidden window and a resize */
    ShowWindow(v, SW_HIDE);
    CHECK(!PeekMessageW(&msg, 0, 0, 0, PM_REMOVE), "hidden windows generate no WM_PAINT");
    ShowWindow(v, SW_SHOW);
    g_paints = 0;
    drain();
    CHECK(g_paints == 1, "showing a hidden window repaints it once");
    g_paints = 0;
    SetWindowPos(v, 0, 0, 0, 300, 160, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    GetClientRect(v, &rc);
    CHECK(rc.right == 300 && rc.bottom == 160, "a WS_OVERLAPPED window (no frame, no caption) has client = window size");
    CHECK(GetUpdateRect(v, &pc, FALSE) && pc.left == 260 && pc.top == 0 && pc.right == 300 && pc.bottom == 160,
          "growing a window of a class without CS_HREDRAW invalidates only the newly exposed strip");
    drain();
    CHECK(g_paints == 1 && g_last_paint.left == 260 && g_last_paint.right == 300, "and paints just that strip");

    /* ---- focus and activation */
    CHECK(GetFocus() == v && g_setfocus == 2 && g_killfocus == 1, "hide + show: hiding cleared the focus (WM_KILLFOCUS), showing re-activated it and DefWindowProc set it again (WM_SETFOCUS)");
    CHECK(SetActiveWindow(v) == v && GetActiveWindow() == v && GetForegroundWindow() == v, "SetActiveWindow returns the previously active window");
    CHECK(SetCapture(v) == 0 && GetCapture() == v && ReleaseCapture() && GetCapture() == 0, "SetCapture/ReleaseCapture");

    /* ---- hierarchy: children, coordinates, enumeration, destruction order */
    p = CreateWindowExW(0, L"ShzMsg", L"parent", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 40, 40, 300, 200, 0, 0, g_inst, 0);
    c = CreateWindowExW(0, L"ShzMsg", L"child", WS_CHILD | WS_VISIBLE, 10, 20, 50, 40, p, (HMENU)5, g_inst, 0);
    CHECK(p && c, "parent and child windows");
    CHECK(GetParent(c) == p && IsChild(p, c) && !IsChild(c, p) && GetTopWindow(p) == c && GetWindowLongPtrW(c, GWLP_ID) == 5, "parent/child relations and the child id");
    GetWindowRect(c, &rc);
    pc.left = 0; pc.top = 0;
    ClientToScreen(p, (POINT *)&pc);
    CHECK(rc.left == pc.left + 10 && rc.top == pc.top + 20 && rc.right == rc.left + 50 && rc.bottom == rc.top + 40, "a child's screen rectangle is offset from its parent's client origin");
    {
        POINT pt = { 5, 5 };
        MapWindowPoints(c, p, &pt, 1);
        CHECK(pt.x == 15 && pt.y == 25, "MapWindowPoints child -> parent client coordinates");
        pt.x = pc.left + 15; pt.y = pc.top + 25;
        CHECK(ChildWindowFromPointEx(p, (POINT){ 15, 25 }, 0) == c && WindowFromPoint(pt) == c, "ChildWindowFromPoint and WindowFromPoint find the child");
    }
    {
        int count = 0, top = 0, thr = 0;
        HWND look[2];
        EnumChildWindows(p, count_cb, (LPARAM)&count);
        CHECK(count == 1, "EnumChildWindows finds the one child");
        EnumWindows(count_cb, (LPARAM)&top);
        EnumThreadWindows(GetCurrentThreadId(), count_cb, (LPARAM)&thr);
        CHECK(top >= 3 && thr >= 3, "EnumWindows and EnumThreadWindows list the top-level windows");
        look[0] = p; look[1] = 0;
        EnumWindows(find_cb, (LPARAM)look);
        CHECK(look[1] == p, "EnumWindows reports the new parent window");
    }
    g_ndestroy = 0;
    CHECK(DestroyWindow(p) && !IsWindow(p) && !IsWindow(c), "DestroyWindow(parent) destroys the child too");
    CHECK(g_ndestroy == 2 && g_destroy_order[0] == p && g_destroy_order[1] == c, "WM_DESTROY reaches the parent first, then the child");

    /* ---- enumeration and lookup */
    CHECK(FindWindowW(L"ShzMsg", L"paint") == v, "FindWindow by class and title");
    CHECK(FindWindowW(L"ShzMsg", L"nothing") == 0, "FindWindow with an unknown title");
    CHECK(FindWindowW(L"shzmsg", 0) != 0, "FindWindow by class name only, case-insensitive");
    CHECK(GetWindowLongPtrW(GetDesktopWindow(), GWL_STYLE) != 0 && GetParent(GetDesktopWindow()) == 0 && GetAncestor(v, GA_PARENT) == GetDesktopWindow(),
          "the desktop window is the parent of top-level windows");

    /* ---- clean up */
    CHECK(DestroyWindow(v) && DestroyWindow(w), "destroy the remaining windows");
    CHECK(UnregisterClassW(L"ShzMsg", g_inst), "UnregisterClass succeeds once no window uses the class");
    CloseHandle(g_ready);
    CloseHandle(g_go);
    printf("%s: message test\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
