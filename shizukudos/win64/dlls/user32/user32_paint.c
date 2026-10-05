/* SPDX-License-Identifier: GPL-2.0-only
 * user32: painting (device contexts of windows, BeginPaint/EndPaint, invalidation), rectangle helpers, the drawing helpers
 * that Windows implements in user32 (FillRect, FrameRect, InvertRect, DrawFocusRect, DrawText), system metrics and colours,
 * and the single-monitor display queries. Window DCs come from gdi32 (ShzGdiWindowDC); every DC obtained here is flushed to
 * the kernel window manager when it is released. */
#include "user32_int.h"
#include "user32_text_layout.h"

/* ---------------------------------------------------------------- DCs and paint cycle */
DLLAPI HDC WINAPI GetDC(HWND hwnd)
{
    shz_wnd_t q;
    U32_NEED_GFX(0);
    if (!hwnd) hwnd = u32_desktop();
    if (!u32_wq(hwnd, SHZ_WQ_CLIENT, 0, &q)) return 0;
    return ShzGdiWindowDC(hwnd, q.rect.right, q.rect.bottom, 0, 0);
}

DLLAPI int WINAPI ReleaseDC(HWND hwnd, HDC hdc)
{
    (void)hwnd;
    return ShzGdiWindowDCRelease(hdc) ? 1 : 0;
}

DLLAPI HDC WINAPI BeginPaint(HWND hwnd, LPPAINTSTRUCT ps)
{
    shz_paint_t p;
    shz_wnd_t q;
    HDC hdc;
    int32_t st;
    if (!ps) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    U32_NEED_GFX(0);
    memset(&p, 0, sizeof p);
    p.op = SHZ_PAINT_BEGIN;
    p.hwnd = H2U(hwnd);
    st = NtUserPaint(&p);
    if (st < 0) { u32_err(st); return 0; }
    if (!u32_wq(hwnd, SHZ_WQ_CLIENT, 0, &q)) return 0;
    hdc = ShzGdiWindowDC(hwnd, q.rect.right, q.rect.bottom, (const RECT *)p.rects, (int)p.nrects);
    if (!hdc) return 0;
    memset(ps, 0, sizeof *ps);
    ps->hdc = hdc;
    ps->rcPaint.left = p.bbox.left; ps->rcPaint.top = p.bbox.top; ps->rcPaint.right = p.bbox.right; ps->rcPaint.bottom = p.bbox.bottom;
    if (p.erase) ps->fErase = SendMessageW(hwnd, WM_ERASEBKGND, (WPARAM)hdc, 0) == 0;
    return hdc;
}

DLLAPI BOOL WINAPI EndPaint(HWND hwnd, const PAINTSTRUCT *ps)
{
    (void)hwnd;
    if (!ps) return FALSE;
    return ShzGdiWindowDCRelease(ps->hdc);
}

static BOOL inval(HWND hwnd, const RECT *rects, unsigned n, uint32_t flags)
{
    shz_inval_t iv;
    int32_t st;
    memset(&iv, 0, sizeof iv);
    iv.hwnd = H2U(hwnd);
    iv.flags = flags;
    iv.nrects = n;
    iv.rects = (uint64_t)(uintptr_t)rects;
    st = NtUserInvalidate(&iv);
    if (st < 0) { u32_err(st); return FALSE; }
    return TRUE;
}

static BOOL inval_all(uint32_t flags)
{
    shz_enum_t e;
    uint64_t list[GFX_ENUM_MAX];
    unsigned i;
    memset(&e, 0, sizeof e);
    e.out = (uint64_t)(uintptr_t)list;
    e.max = GFX_ENUM_MAX;
    if (NtUserEnumWindows(&e) < 0) return FALSE;
    for (i = 0; i < (unsigned)e.count && i < GFX_ENUM_MAX; ++i) inval(U2H(list[i]), 0, 0, flags | SHZ_INV_CHILDREN);
    return TRUE;
}

DLLAPI BOOL WINAPI InvalidateRect(HWND hwnd, const RECT *rc, BOOL erase)
{
    U32_NEED_GFX(FALSE);
    if (!hwnd) return inval_all(erase ? SHZ_INV_ERASE : 0);
    return inval(hwnd, rc, rc ? 1 : 0, erase ? SHZ_INV_ERASE : 0);
}

DLLAPI BOOL WINAPI ValidateRect(HWND hwnd, const RECT *rc)
{
    U32_NEED_GFX(FALSE);
    if (!hwnd) return inval_all(SHZ_INV_VALIDATE);
    return inval(hwnd, rc, rc ? 1 : 0, SHZ_INV_VALIDATE);
}

static BOOL rgn_op(HWND hwnd, HRGN rgn, uint32_t flags)
{
    RECT r[64];
    int n;
    if (!rgn) return inval(hwnd, 0, 0, flags);
    n = ShzGdiRegionRects(rgn, r, 64);
    if (n < 0) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (n == 0) return TRUE;
    return inval(hwnd, r, (unsigned)n, flags);
}

DLLAPI BOOL WINAPI InvalidateRgn(HWND hwnd, HRGN rgn, BOOL erase) { U32_NEED_GFX(FALSE); return rgn_op(hwnd, rgn, erase ? SHZ_INV_ERASE : 0); }
DLLAPI BOOL WINAPI ValidateRgn(HWND hwnd, HRGN rgn) { U32_NEED_GFX(FALSE); return rgn_op(hwnd, rgn, SHZ_INV_VALIDATE); }

static int get_update(HWND hwnd, shz_paint_t *p)
{
    int32_t st;
    memset(p, 0, sizeof *p);
    p->op = SHZ_PAINT_GETUPDATE;
    p->hwnd = H2U(hwnd);
    st = NtUserPaint(p);
    if (st < 0) { u32_err(st); return 0; }
    return 1;
}

DLLAPI BOOL WINAPI GetUpdateRect(HWND hwnd, LPRECT rc, BOOL erase)
{
    shz_paint_t p;
    U32_NEED_GFX(FALSE);
    if (!get_update(hwnd, &p)) return FALSE;
    if (rc) { rc->left = p.bbox.left; rc->top = p.bbox.top; rc->right = p.bbox.right; rc->bottom = p.bbox.bottom; }
    if (erase && p.erase && p.nrects) {
        HDC hdc = GetDC(hwnd);
        if (hdc) { SendMessageW(hwnd, WM_ERASEBKGND, (WPARAM)hdc, 0); ReleaseDC(hwnd, hdc); }
    }
    return p.nrects != 0;
}

DLLAPI int WINAPI GetUpdateRgn(HWND hwnd, HRGN rgn, BOOL erase)
{
    shz_paint_t p;
    U32_NEED_GFX(ERROR);
    (void)erase;
    if (!get_update(hwnd, &p)) return ERROR;
    if (!ShzGdiRegionSetRects(rgn, (const RECT *)p.rects, (int)p.nrects)) { SetLastError(ERROR_INVALID_HANDLE); return ERROR; }
    return p.nrects == 0 ? NULLREGION : p.nrects == 1 ? SIMPLEREGION : COMPLEXREGION;
}

DLLAPI BOOL WINAPI UpdateWindow(HWND hwnd)
{
    shz_paint_t p;
    U32_NEED_GFX(FALSE);
    if (!get_update(hwnd, &p)) return FALSE;
    if (p.nrects && IsWindowVisible(hwnd)) SendMessageW(hwnd, WM_PAINT, 0, 0);
    return TRUE;
}

DLLAPI BOOL WINAPI RedrawWindow(HWND hwnd, const RECT *rc, HRGN rgn, UINT flags)
{
    uint32_t f = 0;
    BOOL ok = TRUE;
    U32_NEED_GFX(FALSE);
    if (!hwnd) hwnd = u32_desktop();
    if (flags & RDW_ALLCHILDREN) f |= SHZ_INV_CHILDREN;
    if (flags & RDW_INVALIDATE) {
        uint32_t ff = f | ((flags & RDW_ERASE) ? SHZ_INV_ERASE : 0);
        ok = rgn ? rgn_op(hwnd, rgn, ff) : inval(hwnd, rc, rc ? 1 : 0, ff);
    } else if (flags & RDW_VALIDATE) {
        ok = rgn ? rgn_op(hwnd, rgn, f | SHZ_INV_VALIDATE) : inval(hwnd, rc, rc ? 1 : 0, f | SHZ_INV_VALIDATE);
    }
    if (ok && (flags & (RDW_UPDATENOW | RDW_ERASENOW))) ok = UpdateWindow(hwnd);
    return ok;
}

/* ---------------------------------------------------------------- rectangles */
DLLAPI BOOL WINAPI SetRect(LPRECT r, int l, int t, int rr, int b) { if (!r) return FALSE; r->left = l; r->top = t; r->right = rr; r->bottom = b; return TRUE; }
DLLAPI BOOL WINAPI SetRectEmpty(LPRECT r) { return SetRect(r, 0, 0, 0, 0); }
DLLAPI BOOL WINAPI CopyRect(LPRECT d, const RECT *s) { if (!d || !s) return FALSE; *d = *s; return TRUE; }
DLLAPI BOOL WINAPI IsRectEmpty(const RECT *r) { return !r || r->left >= r->right || r->top >= r->bottom; }
DLLAPI BOOL WINAPI EqualRect(const RECT *a, const RECT *b) { return a && b && a->left == b->left && a->top == b->top && a->right == b->right && a->bottom == b->bottom; }
DLLAPI BOOL WINAPI InflateRect(LPRECT r, int dx, int dy) { if (!r) return FALSE; r->left -= dx; r->right += dx; r->top -= dy; r->bottom += dy; return TRUE; }
DLLAPI BOOL WINAPI OffsetRect(LPRECT r, int dx, int dy) { if (!r) return FALSE; r->left += dx; r->right += dx; r->top += dy; r->bottom += dy; return TRUE; }
DLLAPI BOOL WINAPI PtInRect(const RECT *r, POINT p) { return r && p.x >= r->left && p.x < r->right && p.y >= r->top && p.y < r->bottom; }

DLLAPI BOOL WINAPI IntersectRect(LPRECT out, const RECT *a, const RECT *b)
{
    RECT t;
    if (!out || !a || !b) return FALSE;
    t.left = a->left > b->left ? a->left : b->left;
    t.top = a->top > b->top ? a->top : b->top;
    t.right = a->right < b->right ? a->right : b->right;
    t.bottom = a->bottom < b->bottom ? a->bottom : b->bottom;
    if (t.left >= t.right || t.top >= t.bottom) { out->left = out->top = out->right = out->bottom = 0; return FALSE; }
    *out = t;
    return TRUE;
}

DLLAPI BOOL WINAPI UnionRect(LPRECT out, const RECT *a, const RECT *b)
{
    if (!out || !a || !b) return FALSE;
    if (IsRectEmpty(a) && IsRectEmpty(b)) { out->left = out->top = out->right = out->bottom = 0; return FALSE; }
    if (IsRectEmpty(a)) { *out = *b; return TRUE; }
    if (IsRectEmpty(b)) { *out = *a; return TRUE; }
    out->left = a->left < b->left ? a->left : b->left;
    out->top = a->top < b->top ? a->top : b->top;
    out->right = a->right > b->right ? a->right : b->right;
    out->bottom = a->bottom > b->bottom ? a->bottom : b->bottom;
    return TRUE;
}

/* ---------------------------------------------------------------- colours and brushes */
static const COLORREF classic_colors[31] = {
    RGB(192, 192, 192), RGB(0, 128, 128), RGB(0, 0, 128), RGB(128, 128, 128), RGB(192, 192, 192), RGB(255, 255, 255), RGB(0, 0, 0),
    RGB(0, 0, 0), RGB(0, 0, 0), RGB(255, 255, 255), RGB(192, 192, 192), RGB(192, 192, 192), RGB(128, 128, 128), RGB(0, 0, 128),
    RGB(255, 255, 255), RGB(192, 192, 192), RGB(128, 128, 128), RGB(128, 128, 128), RGB(0, 0, 0), RGB(192, 192, 192),
    RGB(255, 255, 255), RGB(0, 0, 0), RGB(223, 223, 223), RGB(0, 0, 0), RGB(255, 255, 225), RGB(192, 192, 192), RGB(0, 0, 255),
    RGB(16, 132, 208), RGB(181, 181, 181), RGB(0, 0, 128), RGB(192, 192, 192)
};

COLORREF u32_syscolor(int index)
{
    return index >= 0 && index < 31 ? classic_colors[index] : 0;
}

static HBRUSH g_sysbrush[31];
HBRUSH u32_sysbrush(int index)
{
    if (index < 0 || index >= 31) return 0;
    if (!g_sysbrush[index]) g_sysbrush[index] = ShzGdiCreateStockSolidBrush(classic_colors[index]);
    return g_sysbrush[index];
}

DLLAPI DWORD WINAPI GetSysColor(int index)
{
    if (index < 0 || index >= 31) return 0;
    return classic_colors[index];
}

DLLAPI HBRUSH WINAPI GetSysColorBrush(int index) { return u32_sysbrush(index); }

/* ---------------------------------------------------------------- drawing helpers */
DLLAPI int WINAPI FillRect(HDC hdc, const RECT *rc, HBRUSH br)
{
    HBRUSH old;
    if (!rc) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if ((ULONG_PTR)br > 0 && (ULONG_PTR)br <= 32) br = u32_sysbrush((int)(ULONG_PTR)br - 1);
    if (!br) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
    old = SelectObject(hdc, br);
    if (!old) return 0;
    PatBlt(hdc, rc->left, rc->top, rc->right - rc->left, rc->bottom - rc->top, PATCOPY);
    SelectObject(hdc, old);
    return 1;
}

DLLAPI int WINAPI FrameRect(HDC hdc, const RECT *rc, HBRUSH br)
{
    RECT r;
    if (!rc) return 0;
    r = *rc;
    if (r.right - r.left < 2 || r.bottom - r.top < 2) return FillRect(hdc, rc, br);
    { RECT t = { r.left, r.top, r.right, r.top + 1 }; FillRect(hdc, &t, br); }
    { RECT t = { r.left, r.bottom - 1, r.right, r.bottom }; FillRect(hdc, &t, br); }
    { RECT t = { r.left, r.top + 1, r.left + 1, r.bottom - 1 }; FillRect(hdc, &t, br); }
    { RECT t = { r.right - 1, r.top + 1, r.right, r.bottom - 1 }; FillRect(hdc, &t, br); }
    return 1;
}

DLLAPI BOOL WINAPI InvertRect(HDC hdc, const RECT *rc)
{
    if (!rc) return FALSE;
    return PatBlt(hdc, rc->left, rc->top, rc->right - rc->left, rc->bottom - rc->top, DSTINVERT);
}

DLLAPI BOOL WINAPI DrawFocusRect(HDC hdc, const RECT *rc)
{
    int x, y;
    if (!rc) return FALSE;
    for (x = rc->left; x < rc->right; ++x) {                       /* dotted XOR rectangle: every other pixel inverted */
        if (!((x - rc->left) & 1)) { PatBlt(hdc, x, rc->top, 1, 1, DSTINVERT); PatBlt(hdc, x, rc->bottom - 1, 1, 1, DSTINVERT); }
    }
    for (y = rc->top + 1; y < rc->bottom - 1; ++y) {
        if (!((y - rc->top) & 1)) { PatBlt(hdc, rc->left, y, 1, 1, DSTINVERT); PatBlt(hdc, rc->right - 1, y, 1, 1, DSTINVERT); }
    }
    return TRUE;
}

/* DrawText: variable-width layout over the DC's current font. All widths come from GetTextExtentPoint32W /
 * GetTextExtentExPointW (the same metrics ExtTextOutW draws with), not from count * tmAveCharWidth; the algorithm is the
 * portable user32_text_layout.c (also compiled into the host controls). Honoured: DT_LEFT/CENTER/RIGHT, TOP/VCENTER/BOTTOM
 * (VCENTER/BOTTOM with SINGLELINE only, as Windows documents), SINGLELINE, WORDBREAK, EXPANDTABS/TABSTOP, NOCLIP, NOPREFIX,
 * HIDEPREFIX, PREFIXONLY, CALCRECT, END/PATH/WORD_ELLIPSIS, MODIFYSTRING, EDITCONTROL, EXTERNALLEADING,
 * NOFULLWIDTHCHARBREAK, INTERNAL (system stock font is selected for the call). DT_RTLREADING and undefined bits fail with
 * ERROR_NOT_SUPPORTED (no bidi reordering exists). See user32_text_layout.h for the documented simplifications. A failed
 * measurement or draw call makes DrawTextW return 0 with that call's last error. */
#define DT_ASSERT(a, b) _Static_assert((a) == (b), "DT_* value drifted from user32_text_layout.h")
DT_ASSERT(DT_CENTER, SHZ_TL_DT_CENTER); DT_ASSERT(DT_RIGHT, SHZ_TL_DT_RIGHT); DT_ASSERT(DT_VCENTER, SHZ_TL_DT_VCENTER);
DT_ASSERT(DT_BOTTOM, SHZ_TL_DT_BOTTOM); DT_ASSERT(DT_WORDBREAK, SHZ_TL_DT_WORDBREAK); DT_ASSERT(DT_SINGLELINE, SHZ_TL_DT_SINGLELINE);
DT_ASSERT(DT_EXPANDTABS, SHZ_TL_DT_EXPANDTABS); DT_ASSERT(DT_TABSTOP, SHZ_TL_DT_TABSTOP); DT_ASSERT(DT_NOCLIP, SHZ_TL_DT_NOCLIP);
DT_ASSERT(DT_EXTERNALLEADING, SHZ_TL_DT_EXTERNALLEADING); DT_ASSERT(DT_CALCRECT, SHZ_TL_DT_CALCRECT);
DT_ASSERT(DT_NOPREFIX, SHZ_TL_DT_NOPREFIX); DT_ASSERT(DT_INTERNAL, SHZ_TL_DT_INTERNAL); DT_ASSERT(DT_EDITCONTROL, SHZ_TL_DT_EDITCONTROL);
DT_ASSERT(DT_PATH_ELLIPSIS, SHZ_TL_DT_PATH_ELLIPSIS); DT_ASSERT(DT_END_ELLIPSIS, SHZ_TL_DT_END_ELLIPSIS);
DT_ASSERT(DT_MODIFYSTRING, SHZ_TL_DT_MODIFYSTRING); DT_ASSERT(DT_RTLREADING, SHZ_TL_DT_RTLREADING);
DT_ASSERT(DT_WORD_ELLIPSIS, SHZ_TL_DT_WORD_ELLIPSIS); DT_ASSERT(DT_NOFULLWIDTHCHARBREAK, SHZ_TL_DT_NOFULLWIDTHCHARBREAK);
DT_ASSERT(DT_HIDEPREFIX, SHZ_TL_DT_HIDEPREFIX); DT_ASSERT(DT_PREFIXONLY, SHZ_TL_DT_PREFIXONLY);

typedef struct { HDC hdc; DWORD err; } dt_ctx_t;

static int dt_fail(dt_ctx_t *c)
{
    const DWORD e = GetLastError();
    c->err = e ? e : ERROR_GEN_FAILURE;
    return 0;
}

static int dt_measure(void *ctx, const uint16_t *s, int n, int *w)
{
    dt_ctx_t *c = ctx;
    SIZE sz;
    SetLastError(0);
    if (!GetTextExtentPoint32W(c->hdc, (LPCWSTR)s, n, &sz)) return dt_fail(c);
    *w = (int)sz.cx;
    return 1;
}

static int dt_fit(void *ctx, const uint16_t *s, int n, int maxw, int *fit, int *w)
{
    dt_ctx_t *c = ctx;
    SIZE sz;
    int f = 0;
    SetLastError(0);
    if (!GetTextExtentExPointW(c->hdc, (LPCWSTR)s, n, maxw, &f, NULL, &sz)) return dt_fail(c);
    if (f < 0 || f > n) { SetLastError(ERROR_INVALID_DATA); return dt_fail(c); }
    *fit = f;
    return dt_measure(ctx, s, f, w);
}

static void *dt_alloc(void *ctx, size_t bytes) { (void)ctx; return HeapAlloc(GetProcessHeap(), 0, bytes); }
static void dt_free(void *ctx, void *p) { (void)ctx; if (p) HeapFree(GetProcessHeap(), 0, p); }

static LONG dt_clamp(LONGLONG v) { return v > 0x7fffffffLL ? 0x7fffffff : v < -0x7fffffffLL ? -0x7fffffff : (LONG)v; }

static BOOL dt_underline(HDC hdc, const RECT *rc, UINT fmt, int x, int w, int y, int lh, int ascent)
{
    RECT u;
    HBRUSH br;
    int thick = lh / 16 > 1 ? lh / 16 : 1, ret;
    u.left = dt_clamp((LONGLONG)rc->left + x);
    u.right = dt_clamp((LONGLONG)u.left + w);
    u.top = dt_clamp((LONGLONG)rc->top + y + ascent + 1);
    if (u.top + thick > dt_clamp((LONGLONG)rc->top + y + lh)) u.top = dt_clamp((LONGLONG)rc->top + y + lh - thick);
    u.bottom = u.top + thick;
    if (!(fmt & DT_NOCLIP)) {
        if (u.left < rc->left) u.left = rc->left;
        if (u.right > rc->right) u.right = rc->right;
        if (u.top < rc->top) u.top = rc->top;
        if (u.bottom > rc->bottom) u.bottom = rc->bottom;
    }
    if (u.left >= u.right || u.top >= u.bottom) return TRUE;
    br = CreateSolidBrush(GetTextColor(hdc));
    if (!br) return FALSE;
    ret = FillRect(hdc, &u, br);
    DeleteObject(br);
    return ret != 0;
}

DLLAPI int WINAPI DrawTextW(HDC hdc, LPCWSTR text, int len, LPRECT rc, UINT fmt)
{
    TEXTMETRICW tm;
    shz_tl_params_t p;
    shz_tl_layout_t L;
    dt_ctx_t cx;
    HGDIOBJ oldfont = 0;
    LONGLONG rw, rh;
    int st, i, ret = 0, drawn_ok = 1;
    DWORD err = 0;
    cx.hdc = hdc; cx.err = 0;
    if (!text || !rc) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (fmt & DT_INTERNAL) {
        HGDIOBJ sys = GetStockObject(SYSTEM_FONT);
        if (!sys || !(oldfont = SelectObject(hdc, sys))) return 0;
    }
    if (!GetTextMetricsW(hdc, &tm)) { err = GetLastError(); goto restore; }
    memset(&p, 0, sizeof p);
    p.measure = dt_measure; p.fit = dt_fit; p.alloc = dt_alloc; p.release = dt_free; p.ctx = &cx;
    p.line_height = tm.tmHeight; p.external_leading = tm.tmExternalLeading; p.ascent = tm.tmAscent;
    p.avg_char_width = tm.tmAveCharWidth;
    rw = (LONGLONG)rc->right - rc->left; rh = (LONGLONG)rc->bottom - rc->top;
    rw = rw < 0 ? 0 : rw > 0x7fffffffLL ? 0x7fffffffLL : rw;
    rh = rh < 0 ? 0 : rh > 0x7fffffffLL ? 0x7fffffffLL : rh;
    st = shz_tl_layout(&p, (const uint16_t *)text, len, (int)rw, (int)rh, fmt, &L);
    if (st != SHZ_TL_OK) {
        switch (st) {
        case SHZ_TL_E_NOMEM: err = ERROR_NOT_ENOUGH_MEMORY; break;
        case SHZ_TL_E_MEASURE: err = cx.err ? cx.err : ERROR_GEN_FAILURE; break;
        case SHZ_TL_E_TOOBIG: err = ERROR_BUFFER_OVERFLOW; break;
        case SHZ_TL_E_UNSUPPORTED: err = ERROR_NOT_SUPPORTED; break;
        default: err = ERROR_INVALID_PARAMETER; break;
        }
        goto restore;
    }
    if (fmt & DT_CALCRECT) {
        rc->right = dt_clamp((LONGLONG)rc->left + L.max_width);
        rc->bottom = dt_clamp((LONGLONG)rc->top + L.height);
        ret = L.height;
        shz_tl_free(&L);
        goto restore;
    }
    for (i = 0; i < L.nlines && drawn_ok; ++i) {
        const shz_tl_line_t *ln = &L.lines[i];
        shz_tl_iter_t it;
        shz_tl_run_t run;
        int ux = 0, uw = 0;
        if (!ln->visible) continue;
        if (!(fmt & DT_PREFIXONLY)) {
            shz_tl_iter_begin(&L, i, &it);
            while ((st = shz_tl_iter_next(&it, &run)) > 0) {
                if (!ExtTextOutW(hdc, dt_clamp((LONGLONG)rc->left + run.x), dt_clamp((LONGLONG)rc->top + ln->y),
                                 (fmt & DT_NOCLIP) ? 0 : ETO_CLIPPED, (fmt & DT_NOCLIP) ? NULL : rc, (LPCWSTR)run.p,
                                 (UINT)run.n, NULL)) {
                    err = GetLastError(); if (!err) err = ERROR_GEN_FAILURE;
                    drawn_ok = 0;
                    break;
                }
            }
            if (drawn_ok && st < 0) { err = cx.err ? cx.err : ERROR_GEN_FAILURE; drawn_ok = 0; }
        }
        if (drawn_ok && L.ul_index >= 0) {
            if (shz_tl_underline(&L, i, &ux, &uw)) {
                if (!dt_underline(hdc, rc, fmt, ux, uw, ln->y, L.line_h, tm.tmAscent)) {
                    err = GetLastError(); if (!err) err = ERROR_GEN_FAILURE;
                    drawn_ok = 0;
                }
            } else if (cx.err) { err = cx.err; drawn_ok = 0; }
        }
    }
    if (drawn_ok && (fmt & DT_MODIFYSTRING) && (fmt & (DT_END_ELLIPSIS | DT_PATH_ELLIPSIS)) && L.modified && L.nlines == 1) {
        /* the caller's buffer is never grown: it is rewritten only when the displayed text fits the original length */
        const int orig = len < 0 ? (int)wcslen(text) : len;
        const int need = shz_tl_displayed_text(&L, NULL, 0);
        if (need >= 0 && need <= orig) {
            shz_tl_displayed_text(&L, (uint16_t *)(ULONG_PTR)text, need);
            if (need < orig || len < 0) ((WCHAR *)(ULONG_PTR)text)[need] = 0;
        }
    }
    if (drawn_ok) ret = L.height;
    shz_tl_free(&L);
restore:
    if (oldfont && !SelectObject(hdc, oldfont) && ret) { err = GetLastError(); ret = 0; }
    if (!ret && err) SetLastError(err);
    return ret;
}

/* ---------------------------------------------------------------- metrics */
int u32_metric(int index)
{
    shz_display_info_t di;
    int w = 0, h = 0;
    if (u32_display(&di)) { w = (int)di.width; h = (int)di.height; }
    switch (index) {
    case SM_CXSCREEN: case SM_CXFULLSCREEN: case SM_CXVIRTUALSCREEN: return w;
    case SM_CYSCREEN: case SM_CYVIRTUALSCREEN: return h;
    case SM_CYFULLSCREEN: return h ? h - SHZ_CAPTION_H : 0;
    case SM_CXVSCROLL: case SM_CYHSCROLL: case SM_CYVSCROLL: case SM_CXHSCROLL: case SM_CYVTHUMB: case SM_CXHTHUMB: return 17;
    case SM_CYCAPTION: return SHZ_CAPTION_H;
    case SM_CXBORDER: case SM_CYBORDER: return 1;
    case SM_CXDLGFRAME: case SM_CYDLGFRAME: return 3;
    case SM_CXICON: case SM_CYICON: case SM_CXCURSOR: case SM_CYCURSOR: return 32;
    case SM_CYMENU: return 19;
    case SM_MOUSEPRESENT: return (u32_input_info() & SHZ_INFO_MOUSE) != 0;   /* the PS/2 mouse answered (kernel64/gfx_input.c) */
    case SM_CMOUSEBUTTONS: return (u32_input_info() & SHZ_INFO_MOUSE) ? 3 : 0;
    case SM_MOUSEWHEELPRESENT: return (u32_input_info() & SHZ_INFO_WHEEL) != 0;
    case SM_MOUSEHORIZONTALWHEELPRESENT: return 0;
    case SM_SWAPBUTTON: return 0;
    case SM_CXMIN: return 112;
    case SM_CYMIN: return 27;
    case SM_CXSIZE: case SM_CYSIZE: return 18;
    case SM_CXFRAME: case SM_CYFRAME: return 4;
    case SM_CXMINTRACK: return 112;
    case SM_CYMINTRACK: return 27;
    case SM_CXDOUBLECLK: case SM_CYDOUBLECLK: case SM_CXDRAG: case SM_CYDRAG: return 4;
    case SM_CXICONSPACING: case SM_CYICONSPACING: return 75;
    case SM_CXEDGE: case SM_CYEDGE: return 2;
    case SM_CXMINSPACING: return 160;
    case SM_CYMINSPACING: return 24;
    case SM_CXSMICON: case SM_CYSMICON: return 16;
    case SM_CYSMCAPTION: return 15;
    case SM_CXSMSIZE: case SM_CYSMSIZE: return 15;
    case SM_CXMENUSIZE: case SM_CYMENUSIZE: return 18;
    case SM_ARRANGE: return 8;
    case SM_CXMINIMIZED: return 160;
    case SM_CYMINIMIZED: return 24;
    case SM_CXMAXTRACK: case SM_CXMAXIMIZED: return w ? w + 8 : 0;
    case SM_CYMAXTRACK: case SM_CYMAXIMIZED: return h ? h + 8 : 0;
    case SM_CXMENUCHECK: case SM_CYMENUCHECK: return 13;
    case SM_CMONITORS: return w ? 1 : 0;
    case SM_SAMEDISPLAYFORMAT: return 1;
    case SM_CXFOCUSBORDER: case SM_CYFOCUSBORDER: return 1;
    case SM_CXPADDEDBORDER: return 0;
    default: return 0;
    }
}

DLLAPI int WINAPI GetSystemMetrics(int index) { return u32_metric(index); }

/* 1 when a font created from lf is realised by gdi32 as a "Noto Sans*" face (GetTextFaceW reports the ACTUAL face);
 * otherwise 0 with ERROR_FILE_NOT_FOUND (or the failing call's error). Never reports the requested name as the actual one. */
static int u32_system_font_realised(const LOGFONTW *lf)
{
    static const WCHAR want[] = { 'N', 'o', 't', 'o', ' ', 'S', 'a', 'n', 's' };
    WCHAR face[LF_FACESIZE];
    HDC dc;
    HFONT f;
    HGDIOBJ old;
    DWORD err = 0;
    int ok = 0, n;
    dc = CreateCompatibleDC(0);
    if (!dc) return 0;
    f = CreateFontIndirectW(lf);
    if (!f) { err = GetLastError(); DeleteDC(dc); if (err) SetLastError(err); return 0; }
    old = SelectObject(dc, f);
    if (old) {
        memset(face, 0, sizeof face);
        n = GetTextFaceW(dc, LF_FACESIZE, face);
        ok = n > 0 && memcmp(face, want, sizeof want) == 0;
        SelectObject(dc, old);
    } else err = GetLastError();
    DeleteObject(f);
    DeleteDC(dc);
    if (!ok) SetLastError(err ? err : ERROR_FILE_NOT_FOUND);
    return ok;
}

DLLAPI BOOL WINAPI SystemParametersInfoW(UINT action, UINT param, PVOID pv, UINT winini)
{
    shz_display_info_t di;
    (void)winini;
    switch (action) {
    case SPI_GETWORKAREA:
        if (!pv || !u32_display(&di)) { SetLastError(pv ? ERROR_NOT_SUPPORTED : ERROR_INVALID_PARAMETER); return FALSE; }
        ((RECT *)pv)->left = 0; ((RECT *)pv)->top = 0; ((RECT *)pv)->right = (LONG)di.width; ((RECT *)pv)->bottom = (LONG)di.height;
        return TRUE;
    case SPI_GETWHEELSCROLLLINES:
        if (!pv) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        *(UINT *)pv = 3;
        return TRUE;
    case SPI_GETHIGHCONTRAST:
        if (!pv || ((HIGHCONTRASTW *)pv)->cbSize != sizeof(HIGHCONTRASTW)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        ((HIGHCONTRASTW *)pv)->dwFlags = 0;
        ((HIGHCONTRASTW *)pv)->lpszDefaultScheme = 0;
        return TRUE;
    case SPI_GETNONCLIENTMETRICS: {
        NONCLIENTMETRICSW *m = pv;
        LOGFONTW lf;
        if (!m || m->cbSize < sizeof *m) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        /* System default: Noto Sans, regular weight 400 (Hangul and other scripts fall back to Noto Sans KR inside the one
         * font provider). The values are the REQUESTED font; they are returned only after the DC font realisation proves the
         * face was really created, so a missing asset fails visibly instead of reporting a fixed-cell fallback. The pixel
         * height (-16) is the current 16 px cell contract of gdi32; arbitrary pixel sizes need the GDI lane's provider API. */
        memset(&lf, 0, sizeof lf);
        lf.lfHeight = -16; lf.lfWeight = FW_NORMAL; lf.lfCharSet = DEFAULT_CHARSET; lf.lfPitchAndFamily = VARIABLE_PITCH | FF_SWISS;
        memcpy(lf.lfFaceName, L"Noto Sans", sizeof L"Noto Sans");
        if (!u32_system_font_realised(&lf)) return FALSE;
        m->iBorderWidth = 1; m->iScrollWidth = 17; m->iScrollHeight = 17; m->iCaptionWidth = 18; m->iCaptionHeight = 18;
        m->lfCaptionFont = lf; m->iSmCaptionWidth = 15; m->iSmCaptionHeight = 15; m->lfSmCaptionFont = lf;
        m->iMenuWidth = 18; m->iMenuHeight = 19; m->lfMenuFont = lf; m->lfStatusFont = lf; m->lfMessageFont = lf;
        return TRUE;
    }
    default:
        (void)param;
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
}

/* ---------------------------------------------------------------- the single monitor */
#define THE_MONITOR ((HMONITOR)(ULONG_PTR)1)

DLLAPI HMONITOR WINAPI MonitorFromPoint(POINT pt, DWORD flags)
{
    shz_display_info_t di;
    if (!u32_display(&di)) return 0;
    if (pt.x >= 0 && pt.y >= 0 && pt.x < (LONG)di.width && pt.y < (LONG)di.height) return THE_MONITOR;
    return flags == MONITOR_DEFAULTTONULL ? 0 : THE_MONITOR;
}

DLLAPI HMONITOR WINAPI MonitorFromRect(const RECT *rc, DWORD flags)
{
    shz_display_info_t di;
    if (!rc || !u32_display(&di)) return 0;
    if (rc->right > 0 && rc->bottom > 0 && rc->left < (LONG)di.width && rc->top < (LONG)di.height) return THE_MONITOR;
    return flags == MONITOR_DEFAULTTONULL ? 0 : THE_MONITOR;
}

DLLAPI HMONITOR WINAPI MonitorFromWindow(HWND hwnd, DWORD flags)
{
    RECT r;
    if (!u32_display(0)) return 0;
    if (GetWindowRect(hwnd, &r)) return MonitorFromRect(&r, flags);
    return flags == MONITOR_DEFAULTTONULL ? 0 : THE_MONITOR;
}

DLLAPI BOOL WINAPI GetMonitorInfoW(HMONITOR mon, LPMONITORINFO mi)
{
    shz_display_info_t di;
    if (!mi || mon != THE_MONITOR || mi->cbSize < sizeof(MONITORINFO) || !u32_display(&di)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    mi->rcMonitor.left = 0; mi->rcMonitor.top = 0; mi->rcMonitor.right = (LONG)di.width; mi->rcMonitor.bottom = (LONG)di.height;
    mi->rcWork = mi->rcMonitor;                                     /* no taskbar */
    mi->dwFlags = MONITORINFOF_PRIMARY;
    if (mi->cbSize >= sizeof(MONITORINFOEXW)) memcpy(((MONITORINFOEXW *)mi)->szDevice, L"\\\\.\\DISPLAY1", sizeof L"\\\\.\\DISPLAY1");
    return TRUE;
}

DLLAPI BOOL WINAPI EnumDisplayMonitors(HDC hdc, LPCRECT clip, MONITORENUMPROC proc, LPARAM lp)
{
    shz_display_info_t di;
    RECT r;
    (void)hdc;
    if (!proc || !u32_display(&di)) { SetLastError(proc ? ERROR_NOT_SUPPORTED : ERROR_INVALID_PARAMETER); return FALSE; }
    r.left = 0; r.top = 0; r.right = (LONG)di.width; r.bottom = (LONG)di.height;
    if (clip && !IntersectRect(&r, &r, clip)) return TRUE;
    return proc(THE_MONITOR, hdc, &r, lp);
}

/* ---------------------------------------------------------------- character helpers */
static WCHAR up(WCHAR c)
{
    if (c >= 'a' && c <= 'z') return (WCHAR)(c - 32);
    if ((c >= 0xe0 && c <= 0xfe && c != 0xf7)) return (WCHAR)(c - 32);
    if (c == 0xff) return 0x178;
    return c;
}
static WCHAR down(WCHAR c)
{
    if (c >= 'A' && c <= 'Z') return (WCHAR)(c + 32);
    if ((c >= 0xc0 && c <= 0xde && c != 0xd7)) return (WCHAR)(c + 32);
    return c;
}

/* ASCII and Latin-1 only; other letters are returned unchanged. */
DLLAPI LPWSTR WINAPI CharUpperW(LPWSTR s)
{
    LPWSTR p;
    if ((ULONG_PTR)s < 0x10000) return (LPWSTR)(ULONG_PTR)up((WCHAR)(ULONG_PTR)s);
    for (p = s; *p; ++p) *p = up(*p);
    return s;
}
DLLAPI LPWSTR WINAPI CharLowerW(LPWSTR s)
{
    LPWSTR p;
    if ((ULONG_PTR)s < 0x10000) return (LPWSTR)(ULONG_PTR)down((WCHAR)(ULONG_PTR)s);
    for (p = s; *p; ++p) *p = down(*p);
    return s;
}
DLLAPI DWORD WINAPI CharUpperBuffW(LPWSTR s, DWORD n) { DWORD i; if (!s) return 0; for (i = 0; i < n; ++i) s[i] = up(s[i]); return n; }
DLLAPI DWORD WINAPI CharLowerBuffW(LPWSTR s, DWORD n) { DWORD i; if (!s) return 0; for (i = 0; i < n; ++i) s[i] = down(s[i]); return n; }
