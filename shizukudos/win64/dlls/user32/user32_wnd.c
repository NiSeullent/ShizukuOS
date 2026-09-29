/* SPDX-License-Identifier: GPL-2.0-only
 * user32: windows. Creation and destruction message sequences, show/position with the notification messages, window
 * long accessors, hierarchy queries and enumeration, focus/activation, properties. The kernel keeps the state (see
 * kernel64/gfx_wm.c); the messages a window procedure must see are sent from here, in the owning thread. */
#include "user32_int.h"

static int u32_style(HWND hwnd, uint32_t *style, uint32_t *ex)
{
    shz_wnd_t q;
    if (!u32_wq(hwnd, SHZ_WQ_STYLE, 0, &q)) return 0;
    if (style) *style = (uint32_t)q.v0;
    if (ex) { shz_wnd_t e; *ex = u32_wq(hwnd, SHZ_WQ_EXSTYLE, 0, &e) ? (uint32_t)e.v0 : 0; }
    return 1;
}

/* ---------------------------------------------------------------- creation */
DLLAPI HWND WINAPI CreateWindowExW(DWORD exstyle, LPCWSTR cls, LPCWSTR title, DWORD style, int x, int y, int w, int h, HWND parent,
                                   HMENU menu, HINSTANCE inst, LPVOID param)
{
    static volatile LONG cascade;
    shz_display_info_t di;
    shz_createdef_t d;
    CREATESTRUCTW cs;
    int32_t st;
    HWND hwnd;
    LRESULT r;
    if (!cls) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    U32_NEED_GFX(0);
    u32_display(&di);
    if (!(style & WS_CHILD)) {
        const int n = (int)(InterlockedIncrement(&cascade) - 1) % 10;
        if (x == CW_USEDEFAULT) x = 24 + n * 24;
        if (y == CW_USEDEFAULT) y = 24 + n * 24;
        if (w == CW_USEDEFAULT) w = (int)di.width - x < 640 ? (int)di.width - x : 640;
        if (h == CW_USEDEFAULT) h = (int)di.height - y < 480 ? (int)di.height - y : 480;
    } else {
        if (x == CW_USEDEFAULT) x = 0;
        if (y == CW_USEDEFAULT) y = 0;
        if (w == CW_USEDEFAULT) w = 0;
        if (h == CW_USEDEFAULT) h = 0;
    }
    memset(&d, 0, sizeof d);
    if ((ULONG_PTR)cls < 0x10000) d.class_atom = (uint32_t)(ULONG_PTR)cls;
    else { d.class_name = (uint64_t)(uintptr_t)cls; d.class_name_len = (uint32_t)wcslen(cls); }
    if (title) { d.title = (uint64_t)(uintptr_t)title; d.title_len = (uint32_t)wcslen(title); }
    d.style = style;
    d.exstyle = exstyle;
    d.x = x; d.y = y; d.w = w; d.h = h;
    d.parent = H2U(parent);
    d.id = (uint64_t)(uintptr_t)menu;
    d.hinstance = (uint64_t)(uintptr_t)inst;
    d.param = (uint64_t)(uintptr_t)param;
    st = NtUserCreateWindow(&d);
    if (st < 0) { u32_err(st); return 0; }
    hwnd = U2H(d.hwnd_out);
    memset(&cs, 0, sizeof cs);
    cs.lpCreateParams = param; cs.hInstance = inst; cs.hMenu = menu; cs.hwndParent = parent;
    cs.cy = h; cs.cx = w; cs.y = y; cs.x = x; cs.style = (LONG)style; cs.lpszName = title; cs.lpszClass = cls; cs.dwExStyle = exstyle;
    r = u32_send(hwnd, WM_NCCREATE, 0, (LPARAM)&cs, 0, 0);
    if (!r) {
        u32_send(hwnd, WM_NCDESTROY, 0, 0, 0, 0);
        ShzGdiWindowGone(hwnd);
        NtUserDestroyWindow(H2U(hwnd));
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    r = u32_send(hwnd, WM_CREATE, 0, (LPARAM)&cs, 0, 0);
    if (r == -1) {
        u32_send(hwnd, WM_DESTROY, 0, 0, 0, 0);
        u32_send(hwnd, WM_NCDESTROY, 0, 0, 0, 0);
        ShzGdiWindowGone(hwnd);
        NtUserDestroyWindow(H2U(hwnd));
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (!IsWindow(hwnd)) return 0;                                  /* the WM_CREATE handler destroyed it */
    u32_send_size_move(hwnd, 1, 1);
    if (style & WS_VISIBLE) ShowWindow(hwnd, SW_SHOW);
    return hwnd;
}

static void destroy_tree(HWND hwnd)
{
    shz_enum_t e;
    uint64_t list[64];
    unsigned i;
    u32_send(hwnd, WM_DESTROY, 0, 0, 0, 0);
    memset(&e, 0, sizeof e);
    e.parent = H2U(hwnd);
    e.out = (uint64_t)(uintptr_t)list;
    e.max = 64;
    if (NtUserEnumWindows(&e) >= 0)
        for (i = 0; i < (unsigned)e.count && i < 64; ++i) {
            shz_wnd_t q;
            if (u32_wq(U2H(list[i]), SHZ_WQ_THREAD, 0, &q) && q.v0 == GetCurrentThreadId()) destroy_tree(U2H(list[i]));
        }
    u32_send(hwnd, WM_NCDESTROY, 0, 0, 0, 0);
    ShzGdiWindowGone(hwnd);
}

DLLAPI BOOL WINAPI DestroyWindow(HWND hwnd)
{
    shz_wnd_t q;
    shz_show_t s;
    int32_t st;
    U32_NEED_GFX(FALSE);
    if (!u32_wq(hwnd, SHZ_WQ_THREAD, 0, &q)) return FALSE;
    if (q.v0 != GetCurrentThreadId()) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    memset(&s, 0, sizeof s);
    s.hwnd = H2U(hwnd);
    s.cmd = SW_HIDE;
    NtUserShowWindow(&s);                                          /* leaves the screen before the handlers run */
    destroy_tree(hwnd);
    st = NtUserDestroyWindow(H2U(hwnd));
    if (st < 0 && (uint32_t)st != 0xC0000008) { u32_err(st); return FALSE; }
    return TRUE;
}

/* ---------------------------------------------------------------- show / position / size */
void u32_send_size_move(HWND hwnd, int moved, int sized)
{
    shz_wnd_t q, par;
    uint32_t style = 0;
    if (moved && u32_wq(hwnd, SHZ_WQ_CLIENT_ORG, 0, &q)) {
        int x = q.rect.left, y = q.rect.top;
        shz_wnd_t p;
        if (u32_wq(hwnd, SHZ_WQ_STYLE, 0, &p) && (p.v0 & WS_CHILD) && u32_wq(hwnd, SHZ_WQ_PARENT, 0, &par) && par.v0 &&
            u32_wq(U2H(par.v0), SHZ_WQ_CLIENT_ORG, 0, &p)) {
            x -= p.rect.left;
            y -= p.rect.top;
        }
        u32_send(hwnd, WM_MOVE, 0, MAKELPARAM((WORD)x, (WORD)y), 0, 0);
    }
    if (sized && u32_wq(hwnd, SHZ_WQ_CLIENT, 0, &q)) {
        WPARAM type = SIZE_RESTORED;
        if (u32_style(hwnd, &style, 0)) type = (style & WS_MINIMIZE) ? SIZE_MINIMIZED : (style & WS_MAXIMIZE) ? SIZE_MAXIMIZED : SIZE_RESTORED;
        u32_send(hwnd, WM_SIZE, type, MAKELPARAM((WORD)q.rect.right, (WORD)q.rect.bottom), 0, 0);
    }
}

void u32_notify_activation(uint64_t now, uint64_t prev)
{
    if (prev && prev != now && IsWindow(U2H(prev))) {
        u32_send(U2H(prev), WM_NCACTIVATE, FALSE, 0, 0, 0);
        u32_send(U2H(prev), WM_ACTIVATE, WA_INACTIVE, (LPARAM)now, 0, 0);
    }
    if (now && IsWindow(U2H(now))) {
        u32_send(U2H(now), WM_NCACTIVATE, TRUE, 0, 0, 0);
        u32_send(U2H(now), WM_ACTIVATE, WA_ACTIVE, (LPARAM)prev, 0, 0);
    }
}

DLLAPI BOOL WINAPI ShowWindow(HWND hwnd, int cmd)
{
    shz_show_t s;
    shz_wnd_t q0, q1, p0, p1;
    uint32_t style;
    int had_client, had_pos;
    int32_t st;
    U32_NEED_GFX(FALSE);
    if (!u32_style(hwnd, &style, 0)) return FALSE;
    if (cmd == SW_HIDE && (style & WS_VISIBLE)) u32_send(hwnd, WM_SHOWWINDOW, FALSE, 0, 0, 0);
    else if (cmd != SW_HIDE && !(style & WS_VISIBLE) && cmd != SW_MINIMIZE && cmd != SW_SHOWMINIMIZED && cmd != SW_SHOWMINNOACTIVE &&
             cmd != SW_FORCEMINIMIZE)
        u32_send(hwnd, WM_SHOWWINDOW, TRUE, 0, 0, 0);
    had_client = u32_wq(hwnd, SHZ_WQ_CLIENT, 0, &q0);
    had_pos = u32_wq(hwnd, SHZ_WQ_POS, 0, &p0);
    memset(&s, 0, sizeof s);
    s.hwnd = H2U(hwnd);
    s.cmd = (uint32_t)cmd;
    st = NtUserShowWindow(&s);
    if (st < 0) { u32_err(st); return FALSE; }
    if (had_pos && u32_wq(hwnd, SHZ_WQ_POS, 0, &p1) && (p0.rect.left != p1.rect.left || p0.rect.top != p1.rect.top))
        u32_send_size_move(hwnd, 1, 0);
    if (had_client && u32_wq(hwnd, SHZ_WQ_CLIENT, 0, &q1) &&
        (q0.rect.right != q1.rect.right || q0.rect.bottom != q1.rect.bottom))
        u32_send_size_move(hwnd, 0, 1);
    else if (cmd == SW_MINIMIZE || cmd == SW_SHOWMINIMIZED || cmd == SW_SHOWMINNOACTIVE || cmd == SW_FORCEMINIMIZE)
        u32_send(hwnd, WM_SIZE, SIZE_MINIMIZED, 0, 0, 0);
    if (s.activated) u32_notify_activation(H2U(hwnd), s.prev_active);
    return s.was_visible != 0;
}

DLLAPI BOOL WINAPI SetWindowPos(HWND hwnd, HWND after, int x, int y, int cx, int cy, UINT flags)
{
    shz_setpos_t p;
    WINDOWPOS wp;
    int32_t st;
    U32_NEED_GFX(FALSE);
    if (!IsWindow(hwnd)) return FALSE;
    memset(&wp, 0, sizeof wp);
    wp.hwnd = hwnd; wp.hwndInsertAfter = after; wp.x = x; wp.y = y; wp.cx = cx; wp.cy = cy; wp.flags = flags;
    if (!(flags & SWP_NOSENDCHANGING)) {
        u32_send(hwnd, WM_WINDOWPOSCHANGING, 0, (LPARAM)&wp, 0, 0);
        if (!IsWindow(hwnd)) return FALSE;
    }
    memset(&p, 0, sizeof p);
    p.hwnd = H2U(hwnd);
    p.insert_after = (uint64_t)(uintptr_t)wp.hwndInsertAfter;
    p.x = wp.x; p.y = wp.y; p.cx = wp.cx; p.cy = wp.cy;
    p.flags = wp.flags;
    st = NtUserSetWindowPos(&p);
    if (st < 0) { u32_err(st); return FALSE; }
    wp.x = p.new_rect.left; wp.y = p.new_rect.top; wp.cx = p.new_rect.right - p.new_rect.left; wp.cy = p.new_rect.bottom - p.new_rect.top;
    wp.flags = flags;
    if (!(p.changed & SHZ_POS_MOVED)) wp.flags |= SWP_NOMOVE;
    if (!(p.changed & SHZ_POS_SIZED)) wp.flags |= SWP_NOSIZE;
    if (p.changed & SHZ_POS_SHOWN) wp.flags |= SWP_SHOWWINDOW;
    if (p.changed & SHZ_POS_HIDDEN) wp.flags |= SWP_HIDEWINDOW;
    if (IsWindow(hwnd) && p.changed) u32_send(hwnd, WM_WINDOWPOSCHANGED, 0, (LPARAM)&wp, 0, 0);
    if (p.prev_active) u32_notify_activation(H2U(hwnd), p.prev_active);
    return TRUE;
}

DLLAPI BOOL WINAPI MoveWindow(HWND hwnd, int x, int y, int w, int h, BOOL repaint)
{
    return SetWindowPos(hwnd, 0, x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE | (repaint ? 0 : SWP_NOREDRAW));
}

DLLAPI BOOL WINAPI BringWindowToTop(HWND hwnd)
{
    return SetWindowPos(hwnd, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}

DLLAPI BOOL WINAPI AdjustWindowRectEx(LPRECT rc, DWORD style, BOOL menu, DWORD ex)
{
    int32_t l, t, r, b;
    (void)menu;                                                     /* there are no menus: nothing to add */
    if (!rc) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    shz_nc_insets(style, ex, &l, &t, &r, &b);
    rc->left -= l; rc->top -= t; rc->right += r; rc->bottom += b;
    return TRUE;
}

DLLAPI BOOL WINAPI AdjustWindowRect(LPRECT rc, DWORD style, BOOL menu) { return AdjustWindowRectEx(rc, style, menu, 0); }

DLLAPI BOOL WINAPI GetWindowRect(HWND hwnd, LPRECT rc)
{
    shz_wnd_t q;
    U32_NEED_GFX(FALSE);
    if (!rc || !u32_wq(hwnd, SHZ_WQ_RECT, 0, &q)) return FALSE;
    rc->left = q.rect.left; rc->top = q.rect.top; rc->right = q.rect.right; rc->bottom = q.rect.bottom;
    return TRUE;
}

DLLAPI BOOL WINAPI GetClientRect(HWND hwnd, LPRECT rc)
{
    shz_wnd_t q;
    U32_NEED_GFX(FALSE);
    if (!rc || !u32_wq(hwnd, SHZ_WQ_CLIENT, 0, &q)) return FALSE;
    rc->left = q.rect.left; rc->top = q.rect.top; rc->right = q.rect.right; rc->bottom = q.rect.bottom;
    return TRUE;
}

DLLAPI BOOL WINAPI ClientToScreen(HWND hwnd, LPPOINT pt)
{
    shz_wnd_t q;
    if (!pt || !u32_wq(hwnd, SHZ_WQ_CLIENT_ORG, 0, &q)) return FALSE;
    pt->x += q.rect.left;
    pt->y += q.rect.top;
    return TRUE;
}

DLLAPI BOOL WINAPI ScreenToClient(HWND hwnd, LPPOINT pt)
{
    shz_wnd_t q;
    if (!pt || !u32_wq(hwnd, SHZ_WQ_CLIENT_ORG, 0, &q)) return FALSE;
    pt->x -= q.rect.left;
    pt->y -= q.rect.top;
    return TRUE;
}

DLLAPI int WINAPI MapWindowPoints(HWND from, HWND to, LPPOINT pts, UINT n)
{
    shz_wnd_t a, b;
    int dx = 0, dy = 0;
    UINT i;
    if (from) { if (!u32_wq(from, SHZ_WQ_CLIENT_ORG, 0, &a)) return 0; dx += a.rect.left; dy += a.rect.top; }
    if (to) { if (!u32_wq(to, SHZ_WQ_CLIENT_ORG, 0, &b)) return 0; dx -= b.rect.left; dy -= b.rect.top; }
    for (i = 0; i < n; ++i) { pts[i].x += dx; pts[i].y += dy; }
    return MAKELONG((WORD)dx, (WORD)dy);
}

/* ---------------------------------------------------------------- state queries */
DLLAPI BOOL WINAPI IsWindow(HWND hwnd)
{
    shz_wnd_t q;
    if (!hwnd || !u32_display(0)) return FALSE;
    memset(&q, 0, sizeof q);
    q.hwnd = H2U(hwnd);
    q.what = SHZ_WQ_EXISTS;
    return NtUserWindowQuery(&q) >= 0 && q.v0;
}

DLLAPI BOOL WINAPI IsWindowVisible(HWND hwnd)
{
    shz_wnd_t q;
    if (!u32_display(0)) return FALSE;
    return u32_wq(hwnd, SHZ_WQ_VISIBLE, 0, &q) && q.v0;
}

DLLAPI BOOL WINAPI IsWindowEnabled(HWND hwnd)
{
    shz_wnd_t q;
    if (!u32_display(0)) return FALSE;
    return u32_wq(hwnd, SHZ_WQ_ENABLED, 0, &q) && q.v0;
}

DLLAPI BOOL WINAPI EnableWindow(HWND hwnd, BOOL enable)
{
    shz_wnd_t s;
    int32_t st;
    uint32_t style;
    U32_NEED_GFX(FALSE);
    if (!u32_style(hwnd, &style, 0)) return FALSE;
    memset(&s, 0, sizeof s);
    s.hwnd = H2U(hwnd);
    s.what = SHZ_WS_SET_ENABLED;
    s.v0 = enable != 0;
    st = NtUserWindowSet(&s);
    if (st < 0) { u32_err(st); return FALSE; }
    if ((s.v1 != 0) == (enable != 0)) u32_send(hwnd, WM_ENABLE, enable != 0, 0, 0, 0);
    return s.v1 != 0;
}

DLLAPI BOOL WINAPI IsChild(HWND parent, HWND child)
{
    shz_wnd_t q;
    if (!u32_display(0)) return FALSE;
    memset(&q, 0, sizeof q);
    q.hwnd = H2U(child);
    q.what = SHZ_WQ_ISCHILD;
    q.v0 = H2U(parent);
    return NtUserWindowQuery(&q) >= 0 && q.v0;
}

DLLAPI BOOL WINAPI IsIconic(HWND hwnd) { uint32_t s; return u32_display(0) && u32_style(hwnd, &s, 0) && (s & WS_MINIMIZE) != 0; }
DLLAPI BOOL WINAPI IsZoomed(HWND hwnd) { uint32_t s; return u32_display(0) && u32_style(hwnd, &s, 0) && (s & WS_MAXIMIZE) != 0; }
DLLAPI BOOL WINAPI IsWindowUnicode(HWND hwnd) { return IsWindow(hwnd); }

DLLAPI DWORD WINAPI GetWindowThreadProcessId(HWND hwnd, LPDWORD pid)
{
    shz_wnd_t q;
    if (!u32_display(0) || !u32_wq(hwnd, SHZ_WQ_THREAD, 0, &q)) return 0;
    if (pid) *pid = (DWORD)q.v1;
    return (DWORD)q.v0;
}

/* ---------------------------------------------------------------- hierarchy */
static HWND relation(HWND hwnd, uint32_t what, int index)
{
    shz_wnd_t q;
    if (!u32_display(0) || !u32_wq(hwnd, what, index, &q)) return 0;
    return U2H(q.v0);
}

DLLAPI HWND WINAPI GetDesktopWindow(void) { return u32_desktop(); }
DLLAPI HWND WINAPI GetParent(HWND hwnd) { return relation(hwnd, SHZ_WQ_PARENT, 0); }
DLLAPI HWND WINAPI GetAncestor(HWND hwnd, UINT flags) { return relation(hwnd, SHZ_WQ_ANCESTOR, (int)flags); }
DLLAPI HWND WINAPI GetWindow(HWND hwnd, UINT cmd) { return relation(hwnd, SHZ_WQ_GW, (int)cmd); }

DLLAPI HWND WINAPI GetTopWindow(HWND hwnd)
{
    if (!hwnd) hwnd = u32_desktop();
    return relation(hwnd, SHZ_WQ_GW, GW_CHILD);
}

DLLAPI HWND WINAPI SetParent(HWND child, HWND parent)
{
    shz_wnd_t s;
    int32_t st;
    U32_NEED_GFX(0);
    memset(&s, 0, sizeof s);
    s.hwnd = H2U(child);
    s.what = SHZ_WS_SET_PARENT;
    s.v0 = H2U(parent);
    st = NtUserWindowSet(&s);
    if (st < 0) { u32_err(st); return 0; }
    return U2H(s.v1);
}

static BOOL enum_generic(HWND parent, WNDENUMPROC proc, LPARAM lp, uint32_t flags, uint32_t tid)
{
    shz_enum_t e;
    uint64_t list[GFX_ENUM_MAX];
    unsigned i;
    int32_t st;
    BOOL r = TRUE;
    if (!proc) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    U32_NEED_GFX(FALSE);
    memset(&e, 0, sizeof e);
    e.parent = H2U(parent);
    e.flags = flags;
    e.tid = tid;
    e.out = (uint64_t)(uintptr_t)list;
    e.max = GFX_ENUM_MAX;
    st = NtUserEnumWindows(&e);
    if (st < 0) { u32_err(st); return FALSE; }
    for (i = 0; i < (unsigned)e.count && i < GFX_ENUM_MAX; ++i) {
        if (!IsWindow(U2H(list[i]))) continue;                      /* destroyed meanwhile by an earlier callback */
        r = proc(U2H(list[i]), lp);
        if (!r) break;
    }
    return r;
}

DLLAPI BOOL WINAPI EnumWindows(WNDENUMPROC proc, LPARAM lp) { return enum_generic(0, proc, lp, 0, 0); }
DLLAPI BOOL WINAPI EnumChildWindows(HWND parent, WNDENUMPROC proc, LPARAM lp)
{
    if (!parent) parent = u32_desktop();
    return enum_generic(parent, proc, lp, SHZ_ENUM_RECURSE, 0);
}
DLLAPI BOOL WINAPI EnumThreadWindows(DWORD tid, WNDENUMPROC proc, LPARAM lp) { return enum_generic(0, proc, lp, SHZ_ENUM_THREAD, tid); }

static int text_of(HWND hwnd, WCHAR *buf, int cap)
{
    shz_wnd_t q;
    memset(&q, 0, sizeof q);
    q.hwnd = H2U(hwnd);
    q.what = SHZ_WQ_TEXT;
    q.buf = (uint64_t)(uintptr_t)buf;
    q.buf_len = (uint32_t)cap;
    if (NtUserWindowQuery(&q) < 0) return -1;
    return (int)q.buf_len;
}

static int wieq(const WCHAR *a, const WCHAR *b)
{
    for (;; ++a, ++b) {
        WCHAR x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = (WCHAR)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (WCHAR)(y + 32);
        if (x != y) return 0;
        if (!x) return 1;
    }
}

static int class_matches(HWND hwnd, LPCWSTR cls)
{
    shz_wnd_t q;
    WCHAR name[64];
    if (!cls) return 1;
    if ((ULONG_PTR)cls < 0x10000) return u32_wq(hwnd, SHZ_WQ_CLASS_ATOM, 0, &q) && q.v0 == (ULONG_PTR)cls;
    if (GetClassNameW(hwnd, name, 64) <= 0) return 0;
    return wieq(name, cls);
}

DLLAPI HWND WINAPI FindWindowExW(HWND parent, HWND after, LPCWSTR cls, LPCWSTR title)
{
    shz_enum_t e;
    uint64_t list[GFX_ENUM_MAX];
    unsigned i;
    int seen = after == 0;
    U32_NEED_GFX(0);
    memset(&e, 0, sizeof e);
    e.parent = H2U(parent);
    e.out = (uint64_t)(uintptr_t)list;
    e.max = GFX_ENUM_MAX;
    if (NtUserEnumWindows(&e) < 0) return 0;
    for (i = 0; i < (unsigned)e.count && i < GFX_ENUM_MAX; ++i) {
        HWND h = U2H(list[i]);
        if (!seen) { if (h == after) seen = 1; continue; }
        if (!class_matches(h, cls)) continue;
        if (title) {
            WCHAR t[256];
            if (text_of(h, t, 256) < 0 || !wieq(t, title)) continue;
        }
        return h;
    }
    SetLastError(ERROR_SUCCESS);
    return 0;
}

DLLAPI HWND WINAPI FindWindowW(LPCWSTR cls, LPCWSTR title) { return FindWindowExW(0, 0, cls, title); }

DLLAPI HWND WINAPI WindowFromPoint(POINT pt)
{
    uint64_t h = 0;
    if (!u32_display(0) || NtUserHitTest(pt.x, pt.y, &h) < 0) return 0;
    return U2H(h);
}

DLLAPI HWND WINAPI ChildWindowFromPointEx(HWND parent, POINT pt, UINT flags)
{
    shz_wnd_t q, c, pos;
    HWND ch;
    if (!u32_display(0) || !u32_wq(parent, SHZ_WQ_CLIENT, 0, &q)) return 0;
    if (pt.x < 0 || pt.y < 0 || pt.x >= q.rect.right || pt.y >= q.rect.bottom) return 0;
    for (ch = GetWindow(parent, GW_CHILD); ch; ch = GetWindow(ch, GW_HWNDNEXT)) {
        uint32_t st = 0;
        if (!u32_style(ch, &st, 0)) break;
        if ((flags & CWP_SKIPINVISIBLE) && !(st & WS_VISIBLE)) continue;
        if ((flags & CWP_SKIPDISABLED) && (st & WS_DISABLED)) continue;
        if (!u32_wq(ch, SHZ_WQ_POS, 0, &pos)) continue;
        if (pt.x >= pos.rect.left && pt.x < pos.rect.right && pt.y >= pos.rect.top && pt.y < pos.rect.bottom) return ch;
    }
    (void)c;
    return parent;
}

/* ---------------------------------------------------------------- window longs, text, properties */
static int32_t wset(HWND hwnd, uint32_t what, int index, uint64_t v0, uint32_t size, uint64_t *prev)
{
    shz_wnd_t s;
    int32_t st;
    memset(&s, 0, sizeof s);
    s.hwnd = H2U(hwnd);
    s.what = what;
    s.index = index;
    s.v0 = v0;
    s.buf_len = size;
    st = NtUserWindowSet(&s);
    if (st < 0) u32_err(st);
    else if (prev) *prev = s.v1;
    return st;
}

static int64_t wget(HWND hwnd, int index, uint32_t size, int *ok)
{
    shz_wnd_t q;
    uint32_t what;
    switch (index) {
    case GWL_STYLE: what = SHZ_WQ_STYLE; break;
    case GWL_EXSTYLE: what = SHZ_WQ_EXSTYLE; break;
    case GWLP_WNDPROC: what = SHZ_WQ_WNDPROC; break;
    case GWLP_HINSTANCE: what = SHZ_WQ_HINSTANCE; break;
    case GWLP_HWNDPARENT: what = SHZ_WQ_OWNER; break;
    case GWLP_USERDATA: what = SHZ_WQ_USERDATA; break;
    case GWLP_ID: what = SHZ_WQ_ID; break;
    default:
        if (index >= 0) {
            memset(&q, 0, sizeof q);
            q.hwnd = H2U(hwnd);
            q.what = SHZ_WQ_EXTRA;
            q.index = index;
            q.buf_len = size;
            if (NtUserWindowQuery(&q) < 0) { *ok = 0; SetLastError(ERROR_INVALID_INDEX); return 0; }
            *ok = 1;
            return (int64_t)q.v0;
        }
        *ok = 0;
        SetLastError(ERROR_INVALID_INDEX);
        return 0;
    }
    *ok = u32_wq(hwnd, what, 0, &q);
    if (what == SHZ_WQ_OWNER && *ok && !q.v0) { shz_wnd_t p; if (u32_wq(hwnd, SHZ_WQ_PARENT, 0, &p)) q.v0 = p.v0; }
    return *ok ? (int64_t)q.v0 : 0;
}

DLLAPI LONG_PTR WINAPI GetWindowLongPtrW(HWND hwnd, int index)
{
    int ok;
    U32_NEED_GFX(0);
    return (LONG_PTR)wget(hwnd, index, 8, &ok);
}

DLLAPI LONG WINAPI GetWindowLongW(HWND hwnd, int index)
{
    int ok;
    U32_NEED_GFX(0);
    return (LONG)wget(hwnd, index, 4, &ok);
}

static LONG_PTR wlong_set(HWND hwnd, int index, LONG_PTR v, uint32_t size)
{
    uint64_t prev = 0;
    uint32_t what;
    int32_t st;
    U32_NEED_GFX(0);
    switch (index) {
    case GWL_STYLE: case GWL_EXSTYLE: {
        STYLESTRUCT ss;
        uint32_t cur;
        const int ex = index == GWL_EXSTYLE;
        if (!(ex ? (u32_style(hwnd, 0, &cur)) : u32_style(hwnd, &cur, 0))) return 0;
        ss.styleOld = cur;
        ss.styleNew = (DWORD)v;
        u32_send(hwnd, WM_STYLECHANGING, (WPARAM)index, (LPARAM)&ss, 0, 0);
        st = wset(hwnd, ex ? SHZ_WS_SET_EXSTYLE : SHZ_WS_SET_STYLE, 0, ss.styleNew, 0, &prev);
        if (st >= 0) { ss.styleOld = (DWORD)prev; u32_send(hwnd, WM_STYLECHANGED, (WPARAM)index, (LPARAM)&ss, 0, 0); }
        return st >= 0 ? (LONG_PTR)prev : 0;
    }
    case GWLP_WNDPROC: what = SHZ_WS_SET_WNDPROC; break;
    case GWLP_HINSTANCE: what = SHZ_WS_SET_HINSTANCE; break;
    case GWLP_HWNDPARENT: what = SHZ_WS_SET_OWNER; break;
    case GWLP_USERDATA: what = SHZ_WS_SET_USERDATA; break;
    case GWLP_ID: what = SHZ_WS_SET_ID; break;
    default:
        if (index < 0) { SetLastError(ERROR_INVALID_INDEX); return 0; }
        what = SHZ_WS_SET_EXTRA;
        st = wset(hwnd, what, index, (uint64_t)v, size, &prev);
        return st >= 0 ? (LONG_PTR)prev : 0;
    }
    st = wset(hwnd, what, 0, (uint64_t)v, 0, &prev);
    return st >= 0 ? (LONG_PTR)prev : 0;
}

DLLAPI LONG_PTR WINAPI SetWindowLongPtrW(HWND hwnd, int index, LONG_PTR v) { return wlong_set(hwnd, index, v, 8); }
DLLAPI LONG WINAPI SetWindowLongW(HWND hwnd, int index, LONG v) { return (LONG)wlong_set(hwnd, index, (LONG_PTR)v, 4); }

DLLAPI int WINAPI GetWindowTextLengthW(HWND hwnd)
{
    U32_NEED_GFX(0);
    return (int)SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0);
}

DLLAPI int WINAPI GetWindowTextW(HWND hwnd, LPWSTR buf, int max)
{
    U32_NEED_GFX(0);
    if (!buf || max <= 0) return 0;
    buf[0] = 0;
    return (int)SendMessageW(hwnd, WM_GETTEXT, (WPARAM)max, (LPARAM)buf);
}

DLLAPI BOOL WINAPI SetWindowTextW(HWND hwnd, LPCWSTR text)
{
    static const WCHAR empty[1] = { 0 };
    U32_NEED_GFX(FALSE);
    return SendMessageW(hwnd, WM_SETTEXT, 0, (LPARAM)(text ? text : empty)) != 0;
}

static uint64_t prop_key(LPCWSTR s, int create)
{
    shz_atom_t a;
    if ((ULONG_PTR)s < 0x10000) return (uint64_t)(ULONG_PTR)s;
    memset(&a, 0, sizeof a);
    a.op = create ? SHZ_ATOM_ADD : SHZ_ATOM_FIND;
    a.name = (uint64_t)(uintptr_t)s;
    a.name_len = (uint32_t)wcslen(s);
    return NtUserAtom(&a) >= 0 ? a.atom : 0;
}

static HANDLE prop_op(HWND hwnd, LPCWSTR key, uint32_t op, HANDLE value, int create)
{
    shz_prop_t p;
    uint64_t k;
    int32_t st;
    U32_NEED_GFX(0);
    if (!key) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    k = prop_key(key, create);
    if (!k) return 0;
    memset(&p, 0, sizeof p);
    p.op = op;
    p.hwnd = H2U(hwnd);
    p.key = k;
    p.value = (uint64_t)(uintptr_t)value;
    st = NtUserProp(&p);
    if (st < 0) { u32_err(st); return 0; }
    return (HANDLE)(uintptr_t)p.value;
}

DLLAPI BOOL WINAPI SetPropW(HWND hwnd, LPCWSTR key, HANDLE data)
{
    shz_prop_t p;
    uint64_t k;
    int32_t st;
    U32_NEED_GFX(FALSE);
    if (!key) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    k = prop_key(key, 1);
    if (!k) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    memset(&p, 0, sizeof p);
    p.op = SHZ_PROP_SET;
    p.hwnd = H2U(hwnd);
    p.key = k;
    p.value = (uint64_t)(uintptr_t)data;
    st = NtUserProp(&p);
    if (st < 0) { u32_err(st); return FALSE; }
    return TRUE;
}
DLLAPI HANDLE WINAPI GetPropW(HWND hwnd, LPCWSTR key) { return prop_op(hwnd, key, SHZ_PROP_GET, 0, 0); }
DLLAPI HANDLE WINAPI RemovePropW(HWND hwnd, LPCWSTR key) { return prop_op(hwnd, key, SHZ_PROP_REMOVE, 0, 0); }

/* ---------------------------------------------------------------- focus, activation, capture */
static int32_t focus_op(uint32_t op, HWND hwnd, shz_focus_t *f)
{
    memset(f, 0, sizeof *f);
    f->op = op;
    f->hwnd = H2U(hwnd);
    return NtUserFocusOp(f);
}

DLLAPI HWND WINAPI GetFocus(void) { shz_focus_t f; if (!u32_display(0)) return 0; return focus_op(SHZ_FOCUS_GETFOCUS, 0, &f) >= 0 ? U2H(f.result) : 0; }
DLLAPI HWND WINAPI GetActiveWindow(void) { shz_focus_t f; if (!u32_display(0)) return 0; return focus_op(SHZ_FOCUS_GETACTIVE, 0, &f) >= 0 ? U2H(f.result) : 0; }
DLLAPI HWND WINAPI GetForegroundWindow(void) { shz_focus_t f; if (!u32_display(0)) return 0; return focus_op(SHZ_FOCUS_GETFOREGROUND, 0, &f) >= 0 ? U2H(f.result) : 0; }
DLLAPI HWND WINAPI GetCapture(void) { shz_focus_t f; if (!u32_display(0)) return 0; return focus_op(SHZ_FOCUS_GETCAPTURE, 0, &f) >= 0 ? U2H(f.result) : 0; }

DLLAPI HWND WINAPI SetFocus(HWND hwnd)
{
    shz_focus_t f;
    int32_t st;
    U32_NEED_GFX(0);
    st = focus_op(SHZ_FOCUS_SETFOCUS, hwnd, &f);
    if (st < 0) { u32_err(st); return 0; }
    if (f.result != H2U(hwnd)) {
        if (f.result && IsWindow(U2H(f.result))) u32_send(U2H(f.result), WM_KILLFOCUS, (WPARAM)hwnd, 0, 0, 0);
        if (hwnd && IsWindow(hwnd)) u32_send(hwnd, WM_SETFOCUS, (WPARAM)U2H(f.result), 0, 0, 0);
    }
    return U2H(f.result);
}

DLLAPI HWND WINAPI SetActiveWindow(HWND hwnd)
{
    shz_focus_t f;
    int32_t st;
    U32_NEED_GFX(0);
    st = focus_op(SHZ_FOCUS_SETACTIVE, hwnd, &f);
    if (st < 0) { u32_err(st); return 0; }
    u32_notify_activation(H2U(GetAncestor(hwnd, GA_ROOT)), f.result2);
    return U2H(f.result);
}

DLLAPI BOOL WINAPI SetForegroundWindow(HWND hwnd)
{
    shz_focus_t f;
    int32_t st;
    U32_NEED_GFX(FALSE);
    st = focus_op(SHZ_FOCUS_SETFOREGROUND, hwnd, &f);
    if (st < 0) { u32_err(st); return FALSE; }
    u32_notify_activation(f.result, f.result2);
    return TRUE;
}

/* No foreground lock exists here, so every process may already take the foreground. */
DLLAPI BOOL WINAPI AllowSetForegroundWindow(DWORD pid) { (void)pid; return TRUE; }

DLLAPI HWND WINAPI SetCapture(HWND hwnd)
{
    shz_focus_t f;
    int32_t st;
    U32_NEED_GFX(0);
    st = focus_op(SHZ_FOCUS_SETCAPTURE, hwnd, &f);
    if (st < 0) { u32_err(st); return 0; }
    if (f.result && f.result != H2U(hwnd) && IsWindow(U2H(f.result))) u32_send(U2H(f.result), WM_CAPTURECHANGED, 0, (LPARAM)hwnd, 0, 0);
    return U2H(f.result);
}

DLLAPI BOOL WINAPI ReleaseCapture(void)
{
    shz_focus_t f;
    U32_NEED_GFX(FALSE);
    if (focus_op(SHZ_FOCUS_SETCAPTURE, 0, &f) < 0) return FALSE;
    if (f.result && IsWindow(U2H(f.result))) u32_send(U2H(f.result), WM_CAPTURECHANGED, 0, 0, 0, 0);
    return TRUE;
}

/* ---------------------------------------------------------------- placement */
DLLAPI BOOL WINAPI GetWindowPlacement(HWND hwnd, WINDOWPLACEMENT *wp)
{
    shz_wnd_t q;
    uint32_t style;
    if (!wp || wp->length != sizeof *wp) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    U32_NEED_GFX(FALSE);
    if (!u32_style(hwnd, &style, 0) || !u32_wq(hwnd, SHZ_WQ_RESTORE, 0, &q)) return FALSE;
    wp->flags = 0;
    wp->showCmd = (style & WS_MINIMIZE) ? SW_SHOWMINIMIZED : (style & WS_MAXIMIZE) ? SW_SHOWMAXIMIZED : SW_SHOWNORMAL;
    wp->ptMinPosition.x = wp->ptMinPosition.y = -1;
    wp->ptMaxPosition.x = wp->ptMaxPosition.y = -1;
    wp->rcNormalPosition.left = q.rect.left; wp->rcNormalPosition.top = q.rect.top;
    wp->rcNormalPosition.right = q.rect.right; wp->rcNormalPosition.bottom = q.rect.bottom;
    return TRUE;
}

DLLAPI BOOL WINAPI SetWindowPlacement(HWND hwnd, const WINDOWPLACEMENT *wp)
{
    if (!wp || wp->length != sizeof *wp) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    U32_NEED_GFX(FALSE);
    if (!SetWindowPos(hwnd, 0, wp->rcNormalPosition.left, wp->rcNormalPosition.top, wp->rcNormalPosition.right - wp->rcNormalPosition.left,
                      wp->rcNormalPosition.bottom - wp->rcNormalPosition.top, SWP_NOZORDER | SWP_NOACTIVATE))
        return FALSE;
    ShowWindow(hwnd, (int)wp->showCmd);
    return TRUE;
}
