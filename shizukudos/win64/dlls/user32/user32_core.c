/* SPDX-License-Identifier: GPL-2.0-only
 * user32: message plumbing. GetMessage/PeekMessage/DispatchMessage/SendMessage/PostMessage, timers, DefWindowProc.
 *
 * Window procedures run here, in user mode, on the thread that owns the window. A message SENT to a window of another
 * thread waits in the owner's kernel queue; the owner gets it back as a shz_callback_t from GetMessage/PeekMessage (or from
 * its own SendMessage wait), runs the procedure (u32_service) and answers with NtUserReplyMessage. */
#include "user32_int.h"

/* ---------------------------------------------------------------- display, errors, helpers */
static volatile int g_disp_state;
static shz_display_info_t g_disp;
static DWORD g_tls = TLS_OUT_OF_INDEXES;

int u32_display(shz_display_info_t *out)
{
    if (!g_disp_state) {
        shz_display_info_t i;
        memset(&i, 0, sizeof i);
        i.size = sizeof i;
        if (NtUserQueryDisplay(&i, SHZ_DISP_QUERY) >= 0) { g_disp = i; g_disp_state = 1; } else g_disp_state = -1;
    }
    if (g_disp_state > 0 && out) *out = g_disp;
    return g_disp_state > 0;
}

DWORD u32_err(int32_t st)
{
    DWORD e;
    switch ((uint32_t)st) {
    case 0xC0000008: e = ERROR_INVALID_WINDOW_HANDLE; break;        /* STATUS_INVALID_HANDLE */
    case 0xC0000022: e = ERROR_ACCESS_DENIED; break;
    case 0xC000000E: e = ERROR_NOT_SUPPORTED; break;                /* no display device */
    case 0xC0000017: e = ERROR_NOT_ENOUGH_MEMORY; break;
    case 0xC000000D: e = ERROR_INVALID_PARAMETER; break;
    case 0xC0000034: e = ERROR_CANNOT_FIND_WND_CLASS; break;
    case 0xC0000035: e = ERROR_CLASS_ALREADY_EXISTS; break;
    case 0xC0000044: e = ERROR_NOT_ENOUGH_QUOTA; break;
    case 0xC000000B: e = ERROR_INVALID_THREAD_ID; break;
    case 0xC00000BB: e = ERROR_NOT_SUPPORTED; break;
    case 0xC000010A: e = ERROR_PROCESS_ABORTED; break;
    default: e = RtlNtStatusToDosError((NTSTATUS)st);
    }
    SetLastError(e);
    return e;
}

int u32_wq(HWND hwnd, uint32_t what, int32_t index, shz_wnd_t *q)
{
    int32_t st;
    memset(q, 0, sizeof *q);
    q->hwnd = H2U(hwnd);
    q->what = what;
    q->index = index;
    st = NtUserWindowQuery(q);
    if (st < 0) { u32_err(st); return 0; }
    return 1;
}

HWND u32_desktop(void)
{
    shz_wnd_t q;
    if (!u32_display(0)) return 0;
    return u32_wq(0, SHZ_WQ_DESKTOP, 0, &q) ? U2H(q.v0) : 0;
}

LRESULT u32_call(uint64_t proc, HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    return ((WNDPROC)(uintptr_t)proc)(hwnd, msg, wp, lp);
}

static void u32_service(const shz_callback_t *cb)
{
    const LRESULT r = u32_call_wndproc_hooked(cb->wndproc, U2H(cb->hwnd), cb->message, cb->wparam, (LPARAM)cb->lparam);
    NtUserReplyMessage(cb->id, (uint64_t)r);
}

LRESULT u32_send(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, DWORD timeout_ms, int *failed)
{
    shz_send_t s;
    const DWORD start = GetTickCount();
    memset(&s, 0, sizeof s);
    s.hwnd = H2U(hwnd);
    s.message = msg;
    s.wparam = wp;
    s.lparam = (int64_t)lp;
    s.timeout_ms = timeout_ms;
    if (failed) *failed = 0;
    for (;;) {
        const int32_t st = NtUserSendMessage(&s);
        if (st < 0) { u32_err(st); if (failed) *failed = 1; return 0; }
        switch (s.result_kind) {
        case SHZ_SEND_SAME_THREAD: return u32_call_wndproc_hooked(s.wndproc, hwnd, msg, wp, lp);
        case SHZ_SEND_DONE: return (LRESULT)s.result;
        case SHZ_SEND_CALLBACK:
            u32_service(&s.cb);
            if (timeout_ms) {
                const DWORD el = GetTickCount() - start;
                s.timeout_ms = el >= timeout_ms ? 1 : timeout_ms - el;
            }
            break;
        case SHZ_SEND_TIMEOUT: SetLastError(ERROR_TIMEOUT); if (failed) *failed = 1; return 0;
        default: SetLastError(ERROR_INVALID_WINDOW_HANDLE); if (failed) *failed = 1; return 0;
        }
    }
}

u32_thread_t *u32_ts(void)
{
    u32_thread_t *m;
    if (g_tls == TLS_OUT_OF_INDEXES) return 0;
    m = TlsGetValue(g_tls);
    if (!m) {
        m = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *m);
        if (m) TlsSetValue(g_tls, m);
    }
    return m;
}
static void note_message(const shz_msg_t *m)
{
    u32_thread_t *i = u32_ts();
    if (i) { i->time = m->time; i->pt.x = m->pt.x; i->pt.y = m->pt.y; i->extra = (LPARAM)(LONG)m->pad1; }
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID res)
{
    (void)h; (void)res;
    if (reason == DLL_PROCESS_ATTACH) g_tls = TlsAlloc();
    return TRUE;
}

/* ---------------------------------------------------------------- retrieval */
static int retrieve(MSG *msg, HWND hwnd, UINT mn, UINT mx, UINT flags)
{
    for (;;) {
        shz_getmsg_t g;
        int32_t st;
        memset(&g, 0, sizeof g);
        g.hwnd = H2U(hwnd);
        g.min = mn;
        g.max = mx;
        g.flags = flags;
        st = NtUserGetMessage(&g);
        if (st < 0) { u32_err(st); return -1; }
        if (g.result == SHZ_GM_RES_CALLBACK) { u32_service(&g.cb); continue; }
        if (g.result == SHZ_GM_RES_NONE) return 0;
        if (g.msg.message >= SHZ_WM_WINEVENT && g.msg.message <= SHZ_WM_SENDCB) {   /* user32's own: consume, never return */
            if (!(flags & PM_REMOVE)) {
                shz_getmsg_t r;
                for (;;) {                                        /* take exactly this one out (sent messages are served first) */
                    memset(&r, 0, sizeof r);
                    r.hwnd = g.msg.hwnd;
                    r.min = r.max = g.msg.message;
                    r.flags = PM_REMOVE;
                    if (NtUserGetMessage(&r) < 0 || r.result != SHZ_GM_RES_CALLBACK) break;
                    u32_service(&r.cb);
                }
                if (r.result != SHZ_GM_RES_MESSAGE) continue;
                g.msg = r.msg;
            }
            u32_private_message(&g.msg);
            continue;
        }
        if (g.msg.pad0 & SHZ_MSGF_MOUSE) {                         /* screen-coordinate mouse input: hit test and translate */
            const int rm = (flags & PM_REMOVE) != 0;
            if (!u32_mouse_translate(&g.msg, rm) || ((mn || mx) && (g.msg.message < mn || g.msg.message > mx))) {
                if (rm) continue;                                     /* swallowed, or its final form is outside the filter */
                return 0;
            }
        }
        note_message(&g.msg);
        g.msg.pad0 = 0;
        g.msg.pad1 = 0;
        {
            MSG m;
            memcpy(&m, &g.msg, sizeof m);
            if (u32_call_msg_hooks(&m, (flags & PM_REMOVE) != 0)) {     /* WH_KEYBOARD / WH_MOUSE discarded it */
                if (flags & PM_REMOVE) continue;
                return 0;
            }
            if (msg) *msg = m;
        }
        return 1;
    }
}

DLLAPI BOOL WINAPI GetMessageW(LPMSG msg, HWND hwnd, UINT mn, UINT mx)
{
    int r;
    if (!msg) { SetLastError(ERROR_NOACCESS); return -1; }
    U32_NEED_GFX(-1);
    ShzGdiFlushAll();                                              /* nothing may stay undrawn while we wait */
    r = retrieve(msg, hwnd, mn, mx, PM_REMOVE | SHZ_GM_WAIT);
    if (r < 0) return -1;
    return msg->message != WM_QUIT;
}

DLLAPI BOOL WINAPI PeekMessageW(LPMSG msg, HWND hwnd, UINT mn, UINT mx, UINT remove)
{
    int r;
    U32_NEED_GFX(FALSE);
    r = retrieve(msg, hwnd, mn, mx, remove & ~SHZ_GM_WAIT);
    if (r <= 0) { if (r == 0) ShzGdiFlushAll(); return FALSE; }
    return TRUE;
}

DLLAPI BOOL WINAPI WaitMessage(void)
{
    int r;
    U32_NEED_GFX(FALSE);
    ShzGdiFlushAll();
    r = retrieve(0, 0, 0, 0, PM_NOREMOVE | SHZ_GM_WAIT);
    return r > 0;
}

DLLAPI LRESULT WINAPI DispatchMessageW(const MSG *msg)
{
    shz_wnd_t q;
    if (!msg) return 0;
    if (msg->message == WM_TIMER && msg->lParam) {
        ((TIMERPROC)(uintptr_t)msg->lParam)(msg->hwnd, WM_TIMER, msg->wParam, GetTickCount());
        return 0;
    }
    if (!msg->hwnd) return 0;
    if (!u32_wq(msg->hwnd, SHZ_WQ_WNDPROC, 0, &q)) return 0;
    return u32_call(q.v0, msg->hwnd, msg->message, msg->wParam, msg->lParam);
}

DLLAPI DWORD WINAPI GetQueueStatus(UINT flags)
{
    shz_threadop_t t;
    int32_t st;
    U32_NEED_GFX(0);
    memset(&t, 0, sizeof t);
    t.op = SHZ_TOP_QUEUESTATUS;
    t.a = flags;
    st = NtUserThreadOp(&t);
    if (st < 0) { u32_err(st); return 0; }
    return (DWORD)t.out0 | ((DWORD)t.out0 << 16);
}

DLLAPI BOOL WINAPI InSendMessage(void)
{
    shz_threadop_t t;
    if (!u32_display(0)) return FALSE;
    memset(&t, 0, sizeof t);
    t.op = SHZ_TOP_INSEND;
    return NtUserThreadOp(&t) >= 0 && t.out0;
}

DLLAPI LONG WINAPI GetMessageTime(void) { u32_thread_t *i = u32_ts(); return i ? (LONG)i->time : 0; }
DLLAPI LPARAM WINAPI GetMessageExtraInfo(void) { u32_thread_t *i = u32_ts(); return i ? i->extra : 0; }
DLLAPI DWORD WINAPI GetMessagePos(void)
{
    u32_thread_t *i = u32_ts();
    return i ? MAKELONG((WORD)i->pt.x, (WORD)i->pt.y) : 0;
}

/* ---------------------------------------------------------------- posting and sending */
static void top_level_windows(HWND *out, int max, int *n)
{
    shz_enum_t e;
    uint64_t list[64];
    int i, m = max < 64 ? max : 64;
    *n = 0;
    memset(&e, 0, sizeof e);
    e.out = (uint64_t)(uintptr_t)list;
    e.max = (uint64_t)m;
    if (NtUserEnumWindows(&e) < 0) return;
    for (i = 0; i < (int)e.count && i < m; ++i) out[(*n)++] = U2H(list[i]);
}

DLLAPI BOOL WINAPI PostMessageW(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    int32_t st;
    U32_NEED_GFX(FALSE);
    if (hwnd == HWND_BROADCAST) {
        HWND tl[64];
        int n, i;
        top_level_windows(tl, 64, &n);
        for (i = 0; i < n; ++i) NtUserPostMessage(H2U(tl[i]), msg, wp, (uint64_t)lp);
        return TRUE;
    }
    st = NtUserPostMessage(H2U(hwnd), msg, wp, (uint64_t)lp);
    if (st < 0) { u32_err(st); return FALSE; }
    return TRUE;
}

DLLAPI BOOL WINAPI PostThreadMessageW(DWORD tid, UINT msg, WPARAM wp, LPARAM lp)
{
    shz_threadop_t t;
    int32_t st;
    U32_NEED_GFX(FALSE);
    memset(&t, 0, sizeof t);
    t.op = SHZ_TOP_POSTTHREAD;
    t.a = tid; t.b = msg; t.c = wp; t.d = (uint64_t)lp;
    st = NtUserThreadOp(&t);
    if (st < 0) { u32_err(st); return FALSE; }
    return TRUE;
}

DLLAPI VOID WINAPI PostQuitMessage(int code)
{
    shz_threadop_t t;
    if (!u32_display(0)) return;
    memset(&t, 0, sizeof t);
    t.op = SHZ_TOP_POSTQUIT;
    t.a = (uint64_t)(uint32_t)code;
    NtUserThreadOp(&t);
}

DLLAPI LRESULT WINAPI SendMessageW(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    U32_NEED_GFX(0);
    if (hwnd == HWND_BROADCAST) {
        HWND tl[64];
        int n, i;
        top_level_windows(tl, 64, &n);
        for (i = 0; i < n; ++i) u32_send(tl[i], msg, wp, lp, 0, 0);
        return 1;
    }
    return u32_send(hwnd, msg, wp, lp, 0, 0);
}

DLLAPI LRESULT WINAPI SendMessageTimeoutW(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, UINT flags, UINT timeout, PDWORD_PTR result)
{
    int failed = 0;
    LRESULT r;
    (void)flags;
    U32_NEED_GFX(0);
    r = u32_send(hwnd, msg, wp, lp, timeout ? timeout : 1, &failed);
    if (failed) { if (result) *result = 0; return 0; }
    if (result) *result = (DWORD_PTR)r;
    return 1;
}

DLLAPI LRESULT WINAPI CallWindowProcW(WNDPROC proc, HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (!proc) return 0;
    return proc(hwnd, msg, wp, lp);
}

DLLAPI UINT WINAPI RegisterWindowMessageW(LPCWSTR name)
{
    shz_atom_t a;
    int32_t st;
    if (!name) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    U32_NEED_GFX(0);
    memset(&a, 0, sizeof a);
    a.op = SHZ_ATOM_ADD;
    a.name = (uint64_t)(uintptr_t)name;
    a.name_len = (uint32_t)wcslen(name);
    st = NtUserAtom(&a);
    if (st < 0) { u32_err(st); return 0; }
    return a.atom;
}

/* ---------------------------------------------------------------- timers */
DLLAPI UINT_PTR WINAPI SetTimer(HWND hwnd, UINT_PTR id, UINT elapse, TIMERPROC proc)
{
    shz_timer_t t;
    int32_t st;
    U32_NEED_GFX(0);
    memset(&t, 0, sizeof t);
    t.op = SHZ_TIMER_SET;
    t.elapse = elapse;
    t.hwnd = H2U(hwnd);
    t.id = id;
    t.proc = (uint64_t)(uintptr_t)proc;
    st = NtUserTimer(&t);
    if (st < 0) { u32_err(st); return 0; }
    return (UINT_PTR)t.out_id;
}

DLLAPI BOOL WINAPI KillTimer(HWND hwnd, UINT_PTR id)
{
    shz_timer_t t;
    int32_t st;
    U32_NEED_GFX(FALSE);
    memset(&t, 0, sizeof t);
    t.op = SHZ_TIMER_KILL;
    t.hwnd = H2U(hwnd);
    t.id = id;
    st = NtUserTimer(&t);
    if (st < 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return TRUE;
}

/* ---------------------------------------------------------------- DefWindowProc */
static void nc_insets_of(HWND hwnd, int *l, int *t, int *r, int *b)
{
    shz_wnd_t q;
    int32_t a, c, d, e;
    uint32_t style = 0, ex = 0;
    if (u32_wq(hwnd, SHZ_WQ_STYLE, 0, &q)) style = (uint32_t)q.v0;
    if (u32_wq(hwnd, SHZ_WQ_EXSTYLE, 0, &q)) ex = (uint32_t)q.v0;
    shz_nc_insets(style, ex, &a, &c, &d, &e);
    *l = a; *t = c; *r = d; *b = e;
}

static LRESULT def_nchittest(HWND hwnd, LPARAM lp)
{
    shz_wnd_t q;
    const int x = (short)LOWORD(lp), y = (short)HIWORD(lp);
    int l, t, r, b;
    RECT wr;
    if (!u32_wq(hwnd, SHZ_WQ_RECT, 0, &q)) return HTNOWHERE;
    wr.left = q.rect.left; wr.top = q.rect.top; wr.right = q.rect.right; wr.bottom = q.rect.bottom;
    if (x < wr.left || x >= wr.right || y < wr.top || y >= wr.bottom) return HTNOWHERE;
    nc_insets_of(hwnd, &l, &t, &r, &b);
    if (x >= wr.left + l && x < wr.right - r && y >= wr.top + t && y < wr.bottom - b) return HTCLIENT;
    {
        shz_wnd_t s;
        const uint32_t style = u32_wq(hwnd, SHZ_WQ_STYLE, 0, &s) ? (uint32_t)s.v0 : 0;
        if ((style & WS_THICKFRAME) && !(style & (WS_MAXIMIZE | WS_MINIMIZE))) {   /* the sizing frame (4 px) with its corners */
            const int f = 4, cs = f + u32_metric(SM_CXSIZE);
            const int L = x < wr.left + f, R = x >= wr.right - f, T = y < wr.top + f, B = y >= wr.bottom - f;
            if (T || B) {
                if (x < wr.left + cs) return T ? HTTOPLEFT : HTBOTTOMLEFT;
                if (x >= wr.right - cs) return T ? HTTOPRIGHT : HTBOTTOMRIGHT;
                return T ? HTTOP : HTBOTTOM;
            }
            if (L || R) {
                if (y < wr.top + cs) return L ? HTTOPLEFT : HTTOPRIGHT;
                if (y >= wr.bottom - cs) return L ? HTBOTTOMLEFT : HTBOTTOMRIGHT;
                return L ? HTLEFT : HTRIGHT;
            }
        }
    }
    if (y < wr.top + t && t >= SHZ_CAPTION_H && y >= wr.top + (t - SHZ_CAPTION_H)) return HTCAPTION;
    return HTBORDER;
}

DLLAPI LRESULT WINAPI DefWindowProcW(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    {
        int handled;
        const LRESULT r = u32_def_mouse(hwnd, msg, wp, lp, &handled);
        if (handled) return r;
    }
    switch (msg) {
    case WM_NCCREATE: return TRUE;
    case WM_NCACTIVATE: return TRUE;
    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        BeginPaint(hwnd, &ps);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND: {
        HBRUSH br = (HBRUSH)GetClassLongPtrW(hwnd, GCLP_HBRBACKGROUND);
        RECT rc;
        if (!br) return 0;
        if ((ULONG_PTR)br <= 32) br = u32_sysbrush((int)(ULONG_PTR)br - 1);
        if (!br || !GetClientRect(hwnd, &rc)) return 0;
        FillRect((HDC)wp, &rc, br);
        return 1;
    }
    case WM_NCHITTEST: return def_nchittest(hwnd, lp);
    case WM_SETTEXT: {
        shz_wnd_t s;
        int ok;
        memset(&s, 0, sizeof s);
        s.hwnd = H2U(hwnd);
        s.what = SHZ_WS_SET_TEXT;
        s.buf = (uint64_t)lp;
        s.buf_len = lp ? (uint32_t)wcslen((LPCWSTR)lp) : 0;
        ok = NtUserWindowSet(&s) >= 0;
        if (ok) u32_winevent(EVENT_OBJECT_NAMECHANGE, hwnd, OBJID_WINDOW, CHILDID_SELF);
        return ok;
    }
    case WM_GETTEXT: {
        shz_wnd_t q;
        if (!wp || !lp) return 0;
        memset(&q, 0, sizeof q);
        q.hwnd = H2U(hwnd);
        q.what = SHZ_WQ_TEXT;
        q.buf = (uint64_t)lp;
        q.buf_len = (uint32_t)wp;
        if (NtUserWindowQuery(&q) < 0) return 0;
        return (LRESULT)q.buf_len;
    }
    case WM_GETTEXTLENGTH: {
        shz_wnd_t q;
        return u32_wq(hwnd, SHZ_WQ_TEXT, 0, &q) ? (LRESULT)q.v0 : 0;
    }
    case WM_WINDOWPOSCHANGED: {
        const WINDOWPOS *wpos = (const WINDOWPOS *)lp;
        if (wpos) u32_send_size_move(hwnd, !(wpos->flags & SWP_NOMOVE), !(wpos->flags & SWP_NOSIZE));
        return 0;
    }
    case WM_SYSCOMMAND:
        switch (wp & 0xfff0) {
        case SC_CLOSE: SendMessageW(hwnd, WM_CLOSE, 0, 0); break;
        case SC_MINIMIZE: ShowWindow(hwnd, SW_MINIMIZE); break;
        case SC_MAXIMIZE: ShowWindow(hwnd, SW_MAXIMIZE); break;
        case SC_RESTORE: ShowWindow(hwnd, SW_RESTORE); break;
        case SC_MOVE: case SC_SIZE: u32_sys_move_size(hwnd, wp); break;
        default: break;
        }
        return 0;
    case WM_ACTIVATE:
        if (LOWORD(wp) != WA_INACTIVE && !IsIconic(hwnd)) {
            HWND f = GetFocus();
            if (!f || (f != hwnd && !IsChild(hwnd, f))) SetFocus(hwnd);
        }
        return 0;
    case WM_MOUSEACTIVATE: return MA_ACTIVATE;
    case WM_QUERYENDSESSION: return TRUE;
    case WM_NCCALCSIZE:
        if (wp && lp) {
            NCCALCSIZE_PARAMS *p = (NCCALCSIZE_PARAMS *)lp;
            int l, t, r, b;
            nc_insets_of(hwnd, &l, &t, &r, &b);
            p->rgrc[0].left += l; p->rgrc[0].top += t; p->rgrc[0].right -= r; p->rgrc[0].bottom -= b;
        }
        return 0;
    default: return 0;
    }
}

/* ---------------------------------------------------------------- waiting for objects and messages */
/* The queue has an event that is signalled while anything can be retrieved (NtUserThreadOp QUEUEEVENT). Only that "something
 * is pending" level is known, not which kind arrived since the last call: an unremoved message that does not match `mask`
 * makes the wait poll every millisecond instead of blocking, and MWMO_INPUTAVAILABLE is therefore always in effect. */
DLLAPI DWORD WINAPI MsgWaitForMultipleObjectsEx(DWORD n, const HANDLE *handles, DWORD ms, DWORD mask, DWORD flags)
{
    HANDLE all[MAXIMUM_WAIT_OBJECTS];
    shz_threadop_t t;
    const DWORD start = GetTickCount();
    HANDLE qe;
    if (n > MAXIMUM_WAIT_OBJECTS - 1 || (n && !handles)) { SetLastError(ERROR_INVALID_PARAMETER); return WAIT_FAILED; }
    U32_NEED_GFX(WAIT_FAILED);
    memset(&t, 0, sizeof t);
    t.op = SHZ_TOP_QUEUEEVENT;
    { const int32_t st = NtUserThreadOp(&t); if (st < 0) { u32_err(st); return WAIT_FAILED; } }
    qe = (HANDLE)(uintptr_t)t.out0;
    if (n) memcpy(all, handles, n * sizeof(HANDLE));
    all[n] = qe;
    for (;;) {
        DWORD timeout = ms, r;
        int timer_limited = 0;
        memset(&t, 0, sizeof t);
        t.op = SHZ_TOP_QUEUESTATUS;
        t.a = mask;
        if (NtUserThreadOp(&t) < 0) return WAIT_FAILED;
        if (t.out0 && !(flags & MWMO_WAITALL)) return WAIT_OBJECT_0 + n;
        if (ms != INFINITE) {
            const DWORD el = GetTickCount() - start;
            if (el >= ms) return WAIT_TIMEOUT;
            timeout = ms - el;
        }
        if (t.out1 != 0xffffffffull && (timeout == INFINITE || t.out1 + 1 < timeout)) { timeout = (DWORD)t.out1 + 1; timer_limited = 1; }
        r = WaitForMultipleObjectsEx(n + 1, all, (flags & MWMO_WAITALL) != 0, timeout, (flags & MWMO_ALERTABLE) != 0);
        if (r == WAIT_OBJECT_0 + n) {
            memset(&t, 0, sizeof t);
            t.op = SHZ_TOP_QUEUESTATUS;
            t.a = mask;
            if (NtUserThreadOp(&t) >= 0 && t.out0) return r;
            Sleep(1);                                              /* something is pending, but not what the caller asked for */
            continue;
        }
        if (r == WAIT_TIMEOUT && timer_limited) continue;          /* a timer became due: it shows up in the queue status */
        return r;
    }
}

DLLAPI DWORD WINAPI MsgWaitForMultipleObjects(DWORD n, const HANDLE *handles, BOOL wait_all, DWORD ms, DWORD mask)
{
    return MsgWaitForMultipleObjectsEx(n, handles, ms, mask, wait_all ? MWMO_WAITALL : 0);
}
