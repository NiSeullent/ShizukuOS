/* SPDX-License-Identifier: GPL-2.0-only
 * user32: classic drawing helpers and scrolling.
 *
 *  - DrawEdge and DrawFrameControl paint the Windows 2000 style bevels, buttons, check boxes, radio buttons, caption
 *    buttons, scroll arrows and menu glyphs with GDI and the system colours.
 *  - ScrollDC / ScrollWindowEx move pixels inside a DC / a window's client area (BitBlt within the same bitmap) and report
 *    or invalidate the uncovered area; SW_SCROLLCHILDREN moves the child windows too.
 *  - Scroll bar data (SetScrollInfo & co.) is kept per window and bar with the exact clamping rules of Windows
 *    (nPos within [nMin, nMax - max(nPage - 1, 0)]); the non-client painter does not draw scroll bars, so a WS_VSCROLL /
 *    WS_HSCROLL window shows none (a gap, not hidden behaviour).
 */
#include "user32_int.h"

static void fill(HDC dc, int l, int t, int r, int b, int color)
{
    RECT rc;
    rc.left = l; rc.top = t; rc.right = r; rc.bottom = b;
    FillRect(dc, &rc, GetSysColorBrush(color));
}

static void line_h(HDC dc, int x0, int x1, int y, int color) { fill(dc, x0, y, x1, y + 1, color); }
static void line_v(HDC dc, int x, int y0, int y1, int color) { fill(dc, x, y0, x + 1, y1, color); }

DLLAPI BOOL WINAPI DrawEdge(HDC dc, LPRECT rc, UINT edge, UINT flags)
{
    RECT r;
    int outer_tl, outer_br, inner_tl, inner_br;
    if (!rc) return FALSE;
    r = *rc;
    /* outer: raised = light top-left / dark bottom-right; inner likewise, with the other two shades */
    outer_tl = (edge & BDR_RAISEDOUTER) ? COLOR_3DLIGHT : (edge & BDR_SUNKENOUTER) ? COLOR_3DSHADOW : -1;
    outer_br = (edge & BDR_RAISEDOUTER) ? COLOR_3DDKSHADOW : (edge & BDR_SUNKENOUTER) ? COLOR_3DHIGHLIGHT : -1;
    inner_tl = (edge & BDR_RAISEDINNER) ? COLOR_3DHIGHLIGHT : (edge & BDR_SUNKENINNER) ? COLOR_3DDKSHADOW : -1;
    inner_br = (edge & BDR_RAISEDINNER) ? COLOR_3DSHADOW : (edge & BDR_SUNKENINNER) ? COLOR_3DLIGHT : -1;
    if (flags & BF_FLAT) { outer_tl = outer_br = outer_tl >= 0 ? COLOR_3DSHADOW : -1; inner_tl = inner_br = inner_tl >= 0 ? COLOR_3DFACE : -1; }
    if (flags & BF_MONO) { outer_tl = outer_br = outer_tl >= 0 ? COLOR_WINDOWFRAME : -1; inner_tl = inner_br = inner_tl >= 0 ? COLOR_WINDOW : -1; }
    {
        const int pass_tl[2] = { outer_tl, inner_tl }, pass_br[2] = { outer_br, inner_br };
        int k;
        for (k = 0; k < 2; ++k) {
            if (pass_tl[k] < 0 && pass_br[k] < 0) continue;
            if (pass_tl[k] >= 0) {
                if (flags & BF_TOP) line_h(dc, r.left, r.right, r.top, pass_tl[k]);
                if (flags & BF_LEFT) line_v(dc, r.left, r.top, r.bottom, pass_tl[k]);
            }
            if (pass_br[k] >= 0) {
                if (flags & BF_BOTTOM) line_h(dc, r.left, r.right, r.bottom - 1, pass_br[k]);
                if (flags & BF_RIGHT) line_v(dc, r.right - 1, r.top, r.bottom, pass_br[k]);
            }
            if (flags & BF_LEFT) ++r.left;
            if (flags & BF_TOP) ++r.top;
            if (flags & BF_RIGHT) --r.right;
            if (flags & BF_BOTTOM) --r.bottom;
        }
    }
    if (flags & BF_MIDDLE) FillRect(dc, &r, GetSysColorBrush((flags & BF_MONO) ? COLOR_WINDOW : COLOR_3DFACE));
    if (flags & BF_ADJUST) *rc = r;
    return TRUE;
}

static void glyph_check(HDC dc, int cx, int cy, int color)
{
    int k;
    for (k = 0; k < 3; ++k) fill(dc, cx - 3 + k, cy - 1 + k, cx - 2 + k, cy + 2 + k, color);
    for (k = 0; k < 4; ++k) fill(dc, cx + k, cy + 1 - k, cx + 1 + k, cy + 4 - k, color);
}

static void glyph_arrow(HDC dc, int cx, int cy, int dir, int size, int color)   /* 0 up 1 down 2 left 3 right */
{
    int k;
    for (k = 0; k < size; ++k) {
        switch (dir) {
        case 0: fill(dc, cx - k, cy - size / 2 + k, cx + k + 1, cy - size / 2 + k + 1, color); break;
        case 1: fill(dc, cx - (size - 1 - k), cy - size / 2 + k, cx + (size - 1 - k) + 1, cy - size / 2 + k + 1, color); break;
        case 2: fill(dc, cx - size / 2 + k, cy - k, cx - size / 2 + k + 1, cy + k + 1, color); break;
        default: fill(dc, cx - size / 2 + k, cy - (size - 1 - k), cx - size / 2 + k + 1, cy + (size - 1 - k) + 1, color); break;
        }
    }
}

DLLAPI BOOL WINAPI DrawFrameControl(HDC dc, LPRECT rc, UINT type, UINT state)
{
    RECT r;
    int cx, cy;
    const int pushed = (state & (DFCS_PUSHED | DFCS_CHECKED)) != 0, inactive = (state & DFCS_INACTIVE) != 0;
    const int fg = inactive ? COLOR_GRAYTEXT : COLOR_BTNTEXT;
    if (!rc) return FALSE;
    r = *rc;
    cx = (r.left + r.right) / 2;
    cy = (r.top + r.bottom) / 2;
    switch (type) {
    case DFC_BUTTON:
        switch (state & 0xff) {
        case DFCS_BUTTONCHECK: case DFCS_BUTTON3STATE: {
            const int s = (r.bottom - r.top) < (r.right - r.left) ? r.bottom - r.top : r.right - r.left;
            RECT b = { r.left, cy - s / 2, r.left + s, cy - s / 2 + s };
            DrawEdge(dc, &b, EDGE_SUNKEN, BF_RECT | BF_ADJUST);
            FillRect(dc, &b, GetSysColorBrush((state & DFCS_INACTIVE) || (state & DFCS_PUSHED) ? COLOR_3DFACE : COLOR_WINDOW));
            if (state & DFCS_CHECKED) glyph_check(dc, (b.left + b.right) / 2, (b.top + b.bottom) / 2 - 1, fg);
            return TRUE;
        }
        case DFCS_BUTTONRADIO: case DFCS_BUTTONRADIOIMAGE: case DFCS_BUTTONRADIOMASK: {
            const int s = 12, x0 = r.left, y0 = cy - s / 2;
            static const char *const ring[12] = { "    DDDD    ", "  DD    DD  ", " D        L ", " D        L ", "D          L", "D          L",
                                                  "D          L", "D          L", " D        L ", " D        L ", "  LL    LL  ", "    LLLL    " };
            int y, x;
            for (y = 0; y < s; ++y) {
                for (x = 0; x < s; ++x) {
                    const char c = ring[y][x];
                    if (c == 'D') fill(dc, x0 + x, y0 + y, x0 + x + 1, y0 + y + 1, COLOR_3DSHADOW);
                    else if (c == 'L') fill(dc, x0 + x, y0 + y, x0 + x + 1, y0 + y + 1, COLOR_3DHIGHLIGHT);
                }
                if (y >= 1 && y <= 10) {                                /* the inside */
                    const int in = y < 2 || y > 9 ? 3 : y < 4 || y > 7 ? 2 : 1;
                    fill(dc, x0 + in, y0 + y, x0 + s - in - 1, y0 + y + 1, inactive || (state & DFCS_PUSHED) ? COLOR_3DFACE : COLOR_WINDOW);
                }
            }
            if (state & DFCS_CHECKED) fill(dc, x0 + 4, y0 + 4, x0 + 8, y0 + 8, fg);
            return TRUE;
        }
        default:                                                        /* DFCS_BUTTONPUSH */
            DrawEdge(dc, &r, pushed ? EDGE_SUNKEN : EDGE_RAISED, BF_RECT | BF_MIDDLE | ((state & DFCS_FLAT) ? BF_FLAT : 0) | (state & DFCS_ADJUSTRECT ? BF_ADJUST : 0));
            if (state & DFCS_ADJUSTRECT) *rc = r;
            return TRUE;
        }
    case DFC_CAPTION: case DFC_SCROLL: {
        const int s = ((r.bottom - r.top) < (r.right - r.left) ? r.bottom - r.top : r.right - r.left) / 4 + 1;
        DrawEdge(dc, &r, pushed ? EDGE_SUNKEN : EDGE_RAISED, BF_RECT | BF_MIDDLE | ((state & DFCS_FLAT) ? BF_FLAT : 0));
        if (pushed) { ++cx; ++cy; }
        if (type == DFC_SCROLL) {
            const int dir = (state & 0xff) == DFCS_SCROLLUP ? 0 : (state & 0xff) == DFCS_SCROLLDOWN ? 1 : (state & 0xff) == DFCS_SCROLLLEFT ? 2 :
                            (state & 0xff) == DFCS_SCROLLRIGHT ? 3 : (state & 0xff) == DFCS_SCROLLCOMBOBOX ? 1 : -1;
            if (dir >= 0) glyph_arrow(dc, cx, cy, dir, s, fg);
            return TRUE;
        }
        switch (state & 0xff) {
        case DFCS_CAPTIONCLOSE: {
            int k;
            for (k = -s; k <= s; ++k) { fill(dc, cx + k, cy + k, cx + k + 2, cy + k + 1, fg); fill(dc, cx + k, cy - k, cx + k + 2, cy - k + 1, fg); }
            return TRUE;
        }
        case DFCS_CAPTIONMIN: fill(dc, cx - s, cy + s - 1, cx + s, cy + s + 1, fg); return TRUE;
        case DFCS_CAPTIONMAX: {
            RECT f = { cx - s, cy - s, cx + s + 1, cy + s + 1 };
            FrameRect(dc, &f, GetSysColorBrush(fg));
            fill(dc, f.left, f.top + 1, f.right, f.top + 2, fg);
            return TRUE;
        }
        case DFCS_CAPTIONRESTORE: {
            RECT a = { cx - s + 2, cy - s, cx + s + 1, cy + s - 2 }, b = { cx - s, cy - s + 3, cx + s - 2, cy + s + 1 };
            FrameRect(dc, &a, GetSysColorBrush(fg));
            FillRect(dc, &b, GetSysColorBrush(COLOR_3DFACE));
            FrameRect(dc, &b, GetSysColorBrush(fg));
            return TRUE;
        }
        case DFCS_CAPTIONHELP: {
            WCHAR q = '?';
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, GetSysColor(fg));
            TextOutW(dc, cx - 4, cy - 8, &q, 1);
            return TRUE;
        }
        default: return TRUE;
        }
    }
    case DFC_MENU: case DFC_POPUPMENU:
        switch (state & 0xff) {
        case DFCS_MENUCHECK: glyph_check(dc, cx, cy - 1, COLOR_MENUTEXT); return TRUE;
        case DFCS_MENUBULLET: fill(dc, cx - 2, cy - 2, cx + 2, cy + 2, COLOR_MENUTEXT); return TRUE;
        case DFCS_MENUARROW: glyph_arrow(dc, cx, cy, 3, 4, COLOR_MENUTEXT); return TRUE;
        case DFCS_MENUARROWRIGHT: glyph_arrow(dc, cx, cy, 2, 4, COLOR_MENUTEXT); return TRUE;
        default: return TRUE;
        }
    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
}

/* ---------------------------------------------------------------- scrolling pixels */
DLLAPI BOOL WINAPI ScrollDC(HDC dc, int dx, int dy, const RECT *scroll, const RECT *clip, HRGN update, LPRECT upd_rect)
{
    RECT src, dst, box;
    HRGN u;
    if (!dc) return FALSE;
    if (scroll) src = *scroll; else if (GetClipBox(dc, &src) == ERROR) return FALSE;
    if (clip) { if (!IntersectRect(&box, &src, clip)) box = *clip; } else box = src;
    dst = src;
    OffsetRect(&dst, dx, dy);
    {
        RECT vis;
        if (IntersectRect(&vis, &dst, clip ? clip : &src)) {
            RECT from = vis;
            OffsetRect(&from, -dx, -dy);
            BitBlt(dc, vis.left, vis.top, vis.right - vis.left, vis.bottom - vis.top, dc, from.left, from.top, SRCCOPY);
        }
    }
    /* uncovered = (clip-bounded area) minus the moved rectangle */
    u = CreateRectRgnIndirect(clip ? clip : &src);
    if (u) {
        HRGN moved = CreateRectRgnIndirect(&dst);
        if (moved) { CombineRgn(u, u, moved, RGN_DIFF); DeleteObject(moved); }
        if (update) CombineRgn(update, u, 0, RGN_COPY);
        if (upd_rect) GetRgnBox(u, upd_rect);
        DeleteObject(u);
    }
    return TRUE;
}

typedef struct { HWND parent; int dx, dy; const RECT *scroll; } sc_ctx_t;
static BOOL CALLBACK move_child(HWND h, LPARAM lp)
{
    const sc_ctx_t *c = (const sc_ctx_t *)lp;
    RECT r;
    if (GetParent(h) != c->parent || !GetWindowRect(h, &r)) return TRUE;
    MapWindowPoints(0, c->parent, (POINT *)&r, 2);
    if (c->scroll) { RECT t; if (!IntersectRect(&t, &r, c->scroll)) return TRUE; }
    SetWindowPos(h, 0, r.left + c->dx, r.top + c->dy, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    return TRUE;
}

DLLAPI int WINAPI ScrollWindowEx(HWND hwnd, int dx, int dy, const RECT *scroll, const RECT *clip, HRGN update, LPRECT upd_rect, UINT flags)
{
    RECT cr, area;
    HDC dc;
    HRGN u;
    int type = ERROR;
    if (!GetClientRect(hwnd, &cr)) return ERROR;
    area = scroll ? *scroll : cr;
    if (clip) IntersectRect(&area, &area, clip);
    IntersectRect(&area, &area, &cr);
    u = CreateRectRgn(0, 0, 0, 0);
    if (!u) return ERROR;
    dc = GetDC(hwnd);
    if (dc) {
        ScrollDC(dc, dx, dy, scroll ? scroll : &cr, &area, u, 0);
        ReleaseDC(hwnd, dc);
    }
    {                                                                   /* a pending update region moves with the pixels */
        HRGN pend = CreateRectRgn(0, 0, 0, 0);
        if (pend && GetUpdateRgn(hwnd, pend, FALSE) > NULLREGION) {
            HRGN a = CreateRectRgnIndirect(&area);
            OffsetRgn(pend, dx, dy);
            if (a) { CombineRgn(pend, pend, a, RGN_AND); CombineRgn(u, u, pend, RGN_OR); DeleteObject(a); }
        }
        if (pend) DeleteObject(pend);
    }
    if (flags & SW_SCROLLCHILDREN) {
        sc_ctx_t c;
        c.parent = hwnd; c.dx = dx; c.dy = dy; c.scroll = scroll;
        EnumChildWindows(hwnd, move_child, (LPARAM)&c);
    }
    if (update) CombineRgn(update, u, 0, RGN_COPY);
    if (upd_rect) GetRgnBox(u, upd_rect);
    if (flags & (SW_INVALIDATE | SW_ERASE)) InvalidateRgn(hwnd, u, (flags & SW_ERASE) != 0);
    {
        RECT b;
        type = GetRgnBox(u, &b);
    }
    DeleteObject(u);
    return type;
}

DLLAPI BOOL WINAPI ScrollWindow(HWND hwnd, int dx, int dy, const RECT *scroll, const RECT *clip)
{
    return ScrollWindowEx(hwnd, dx, dy, scroll, clip, 0, 0, SW_INVALIDATE | SW_ERASE | (scroll ? 0 : SW_SCROLLCHILDREN)) != ERROR;
}

/* ---------------------------------------------------------------- scroll bar data */
typedef struct { HWND hwnd; int bar; SCROLLINFO si; int shown, disabled; } sbar_t;
#define NSBARS 128
static sbar_t g_sb[NSBARS];
static CRITICAL_SECTION g_sb_lock;
static volatile LONG g_sb_init;

static void sb_lock(void)
{
    if (InterlockedCompareExchange(&g_sb_init, 1, 0) == 0) { InitializeCriticalSection(&g_sb_lock); g_sb_init = 2; }
    while (g_sb_init != 2) Sleep(0);
    EnterCriticalSection(&g_sb_lock);
}

static sbar_t *sb_get(HWND hwnd, int bar, int create)
{
    int i, free_i = -1;
    for (i = 0; i < NSBARS; ++i) {
        if (g_sb[i].hwnd == hwnd && g_sb[i].bar == bar) {
            if (IsWindow(hwnd)) return &g_sb[i];
            g_sb[i].hwnd = 0;                                          /* a window that is gone */
        }
        if (free_i < 0 && (!g_sb[i].hwnd || !IsWindow(g_sb[i].hwnd))) free_i = i;
    }
    if (!create || free_i < 0) return 0;
    memset(&g_sb[free_i], 0, sizeof g_sb[free_i]);
    g_sb[free_i].hwnd = hwnd;
    g_sb[free_i].bar = bar;
    g_sb[free_i].si.cbSize = sizeof(SCROLLINFO);
    g_sb[free_i].si.nMax = bar == SB_CTL ? 0 : 100;                    /* Windows' defaults for window scroll bars: 0..100 */
    return &g_sb[free_i];
}

static void sb_clamp(SCROLLINFO *s)
{
    int maxpos;
    if (s->nMax < s->nMin) s->nMax = s->nMin;
    if (s->nPage > (UINT)(s->nMax - s->nMin + 1)) s->nPage = (UINT)(s->nMax - s->nMin + 1);
    maxpos = s->nMax - (s->nPage ? (int)s->nPage - 1 : 0);
    if (s->nPos > maxpos) s->nPos = maxpos;
    if (s->nPos < s->nMin) s->nPos = s->nMin;
    if (s->nTrackPos > maxpos) s->nTrackPos = maxpos;
    if (s->nTrackPos < s->nMin) s->nTrackPos = s->nMin;
}

DLLAPI int WINAPI SetScrollInfo(HWND hwnd, int bar, LPCSCROLLINFO si, BOOL redraw)
{
    sbar_t *b;
    int pos;
    (void)redraw;
    if (!si || (si->cbSize != sizeof *si && si->cbSize != sizeof *si - sizeof si->nTrackPos) || !IsWindow(hwnd) || bar < SB_HORZ || bar > SB_CTL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    sb_lock();
    b = sb_get(hwnd, bar, 1);
    if (!b) { LeaveCriticalSection(&g_sb_lock); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    if (si->fMask & SIF_RANGE) { b->si.nMin = si->nMin; b->si.nMax = si->nMax; }
    if (si->fMask & SIF_PAGE) b->si.nPage = si->nPage;
    if (si->fMask & SIF_POS) b->si.nPos = si->nPos;
    sb_clamp(&b->si);
    if ((si->fMask & SIF_DISABLENOSCROLL) == 0 && (si->fMask & (SIF_RANGE | SIF_PAGE))) b->shown = b->si.nMax > b->si.nMin && (int)b->si.nPage <= b->si.nMax - b->si.nMin;
    pos = b->si.nPos;
    LeaveCriticalSection(&g_sb_lock);
    return pos;
}

DLLAPI BOOL WINAPI GetScrollInfo(HWND hwnd, int bar, LPSCROLLINFO si)
{
    sbar_t *b;
    if (!si || (si->cbSize != sizeof *si && si->cbSize != sizeof *si - sizeof si->nTrackPos)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (bar == SB_CTL) return (BOOL)SendMessageW(hwnd, SBM_GETSCROLLINFO, 0, (LPARAM)si);
    sb_lock();
    b = sb_get(hwnd, bar, 0);
    if (!b) { LeaveCriticalSection(&g_sb_lock); SetLastError(ERROR_NO_SCROLLBARS); return FALSE; }
    if (si->fMask & SIF_RANGE) { si->nMin = b->si.nMin; si->nMax = b->si.nMax; }
    if (si->fMask & SIF_PAGE) si->nPage = b->si.nPage;
    if (si->fMask & SIF_POS) si->nPos = b->si.nPos;
    if ((si->fMask & SIF_TRACKPOS) && si->cbSize == sizeof *si) si->nTrackPos = b->si.nTrackPos;
    LeaveCriticalSection(&g_sb_lock);
    return TRUE;
}

DLLAPI int WINAPI SetScrollPos(HWND hwnd, int bar, int pos, BOOL redraw)
{
    SCROLLINFO si;
    int old;
    si.cbSize = sizeof si;
    si.fMask = SIF_POS;
    old = GetScrollInfo(hwnd, bar, &si) ? si.nPos : 0;
    si.fMask = SIF_POS;
    si.nPos = pos;
    SetScrollInfo(hwnd, bar, &si, redraw);
    return old;
}

DLLAPI int WINAPI GetScrollPos(HWND hwnd, int bar)
{
    SCROLLINFO si;
    si.cbSize = sizeof si;
    si.fMask = SIF_POS;
    return GetScrollInfo(hwnd, bar, &si) ? si.nPos : 0;
}

DLLAPI BOOL WINAPI SetScrollRange(HWND hwnd, int bar, int mn, int mx, BOOL redraw)
{
    SCROLLINFO si;
    if (mx - mn > 0x7fff || mn > mx) { SetLastError(ERROR_INVALID_SCROLLBAR_RANGE); return FALSE; }
    si.cbSize = sizeof si;
    si.fMask = SIF_RANGE;
    si.nMin = mn;
    si.nMax = mx;
    SetScrollInfo(hwnd, bar, &si, redraw);
    return TRUE;
}

DLLAPI BOOL WINAPI GetScrollRange(HWND hwnd, int bar, LPINT mn, LPINT mx)
{
    SCROLLINFO si;
    si.cbSize = sizeof si;
    si.fMask = SIF_RANGE;
    if (!GetScrollInfo(hwnd, bar, &si)) { if (mn) *mn = 0; if (mx) *mx = 0; return FALSE; }
    if (mn) *mn = si.nMin;
    if (mx) *mx = si.nMax;
    return TRUE;
}

DLLAPI BOOL WINAPI ShowScrollBar(HWND hwnd, int bar, BOOL show)
{
    sbar_t *b;
    int k;
    if (!IsWindow(hwnd)) { SetLastError(ERROR_INVALID_WINDOW_HANDLE); return FALSE; }
    sb_lock();
    for (k = SB_HORZ; k <= SB_VERT; ++k) {
        if (bar != SB_BOTH && bar != k) continue;
        b = sb_get(hwnd, k, 1);
        if (b) b->shown = show != 0;
    }
    LeaveCriticalSection(&g_sb_lock);
    return TRUE;
}

DLLAPI BOOL WINAPI EnableScrollBar(HWND hwnd, UINT bar, UINT arrows)
{
    sbar_t *b;
    int k, changed = 0;
    if (!IsWindow(hwnd)) { SetLastError(ERROR_INVALID_WINDOW_HANDLE); return FALSE; }
    sb_lock();
    for (k = SB_HORZ; k <= SB_CTL; ++k) {
        if (bar != SB_BOTH && (int)bar != k) continue;
        if (bar == SB_BOTH && k == SB_CTL) continue;
        b = sb_get(hwnd, k, 1);
        if (b && b->disabled != (int)arrows) { b->disabled = (int)arrows; changed = 1; }
    }
    LeaveCriticalSection(&g_sb_lock);
    return changed;                                                     /* FALSE: the state was already the requested one */
}

DLLAPI BOOL WINAPI GetScrollBarInfo(HWND hwnd, LONG obj, PSCROLLBARINFO sbi)
{
    SCROLLINFO si;
    sbar_t *b;
    const int bar = obj == OBJID_HSCROLL ? SB_HORZ : obj == OBJID_VSCROLL ? SB_VERT : obj == OBJID_CLIENT ? SB_CTL : -1;
    if (!sbi || sbi->cbSize != sizeof *sbi || bar < 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    si.cbSize = sizeof si;
    si.fMask = SIF_ALL;
    if (!GetScrollInfo(hwnd, bar, &si)) return FALSE;
    memset(&sbi->rcScrollBar, 0, sizeof *sbi - offsetof(SCROLLBARINFO, rcScrollBar));
    sb_lock();
    b = sb_get(hwnd, bar, 0);
    sbi->rgstate[0] = (!b || !b->shown) ? STATE_SYSTEM_INVISIBLE : (b->disabled ? STATE_SYSTEM_UNAVAILABLE : 0);
    LeaveCriticalSection(&g_sb_lock);
    return TRUE;
}
