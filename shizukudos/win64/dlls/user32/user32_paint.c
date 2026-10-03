/* SPDX-License-Identifier: GPL-2.0-only
 * user32: painting (device contexts of windows, BeginPaint/EndPaint, invalidation), rectangle helpers, the drawing helpers
 * that Windows implements in user32 (FillRect, FrameRect, InvertRect, DrawFocusRect, DrawText), system metrics and colours,
 * and the single-monitor display queries. Window DCs come from gdi32 (ShzGdiWindowDC); every DC obtained here is flushed to
 * the kernel window manager when it is released. */
#include "user32_int.h"

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

/* DrawText: DT_LEFT/CENTER/RIGHT/TOP/VCENTER/BOTTOM, SINGLELINE, WORDBREAK, EXPANDTABS, NOCLIP, NOPREFIX, CALCRECT and
 * END_ELLIPSIS. Every width is measured with GetTextExtentPoint32W, the same per-character advances ExtTextOutW draws
 * with (ASCII 8 px, Hangul and other full-width glyphs 16 px at scale 1). '&' prefixes are removed but no underline is
 * drawn. */
static int dt_width(HDC hdc, const WCHAR *s, int n)
{
    SIZE sz;
    return n > 0 && GetTextExtentPoint32W(hdc, s, n, &sz) ? sz.cx : 0;
}

/* Menus and message boxes measure before they have a DC; they draw with the default font, so a private memory DC
 * that keeps the default font gives the same per-character advances (ASCII 8, Hangul 16) gdi32 draws with. */
int u32_text_px(LPCWSTR s, int n)
{
    static HDC measure_dc;
    HDC dc = measure_dc;
    if (!dc) {
        HDC fresh = CreateCompatibleDC(0);
        if (!fresh) return n * 8;                                  /* no GDI: the built-in font's ASCII advance */
        if (InterlockedCompareExchangePointer((PVOID *)&measure_dc, fresh, 0) != 0) DeleteDC(fresh);
        dc = measure_dc;
    }
    return dt_width(dc, s, n);
}

DLLAPI int WINAPI DrawTextW(HDC hdc, LPCWSTR text, int len, LPRECT rc, UINT fmt)
{
    TEXTMETRICW tm;
    WCHAR *buf, *lines[64];
    int lens[64], nl = 0, i, n, cw, lh, maxw = 0, y, rw;
    if (!text || !rc || !GetTextMetricsW(hdc, &tm)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    n = len < 0 ? (int)wcslen(text) : len;
    buf = HeapAlloc(GetProcessHeap(), 0, (size_t)(n + 1) * sizeof(WCHAR) * 2);
    if (!buf) return 0;
    cw = tm.tmAveCharWidth;
    lh = tm.tmHeight;
    rw = rc->right - rc->left;
    {
        WCHAR *o = buf;
        lines[0] = o;
        for (i = 0; i < n && nl < 63; ++i) {
            WCHAR c = text[i];
            if (c == '&' && !(fmt & DT_NOPREFIX)) {
                if (i + 1 < n && text[i + 1] == '&') { *o++ = '&'; ++i; }
                continue;
            }
            if (c == '\r') continue;
            if (c == '\n' && !(fmt & DT_SINGLELINE)) {
                lens[nl] = (int)(o - lines[nl]);
                lines[++nl] = o;
                continue;
            }
            if (c == '\t' && (fmt & DT_EXPANDTABS)) {
                int col = (int)(o - lines[nl]), pad = 8 - (col & 7);
                while (pad--) *o++ = ' ';
                continue;
            }
            if (c == '\t' || c == '\n') c = ' ';
            *o++ = c;
            if ((fmt & DT_WORDBREAK) && !(fmt & DT_SINGLELINE) && rw >= cw && dt_width(hdc, lines[nl], (int)(o - lines[nl])) > rw) {
                WCHAR *sp = o - 1;
                while (sp > lines[nl] && *sp != ' ') --sp;
                if (sp > lines[nl]) {                              /* wrap after the last blank */
                    const int keep = (int)(sp - lines[nl]), tail = (int)(o - sp - 1);
                    WCHAR *nx = lines[nl] + keep + 1;
                    lens[nl] = keep;
                    lines[nl + 1] = nx;
                    ++nl;
                    o = nx + tail;
                } else {                                           /* one long word: break inside it */
                    lens[nl] = (int)(o - 1 - lines[nl]);
                    lines[nl + 1] = o - 1;
                    ++nl;
                }
            }
        }
        lens[nl] = (int)(o - lines[nl]);
        ++nl;
    }
    for (i = 0; i < nl; ++i) { const int w = dt_width(hdc, lines[i], lens[i]); if (w > maxw) maxw = w; }
    if (fmt & DT_CALCRECT) {
        rc->right = rc->left + maxw;
        if (fmt & DT_SINGLELINE) rc->bottom = rc->top + lh; else rc->bottom = rc->top + nl * lh;
        HeapFree(GetProcessHeap(), 0, buf);
        return nl * lh;
    }
    y = rc->top;
    if (fmt & DT_SINGLELINE) {
        if (fmt & DT_VCENTER) y = rc->top + (rc->bottom - rc->top - lh) / 2;
        else if (fmt & DT_BOTTOM) y = rc->bottom - lh;
    }
    for (i = 0; i < nl; ++i, y += lh) {
        int x = rc->left, w = dt_width(hdc, lines[i], lens[i]);
        WCHAR dots[3] = { '.', '.', '.' };
        const int dw = dt_width(hdc, dots, 3);
        if ((fmt & DT_END_ELLIPSIS) && (fmt & DT_SINGLELINE) && w > rw && rw >= dw) {
            int keep = lens[i];
            while (keep > 0 && dt_width(hdc, lines[i], keep) + dw > rw) --keep;
            ExtTextOutW(hdc, x, y, (fmt & DT_NOCLIP) ? 0 : ETO_CLIPPED, rc, lines[i], (UINT)keep, 0);
            ExtTextOutW(hdc, x + dt_width(hdc, lines[i], keep), y, (fmt & DT_NOCLIP) ? 0 : ETO_CLIPPED, rc, dots, 3, 0);
            continue;
        }
        if ((fmt & DT_CENTER) == DT_CENTER) x = rc->left + (rw - w) / 2;
        else if ((fmt & DT_RIGHT)) x = rc->right - w;
        ExtTextOutW(hdc, x, y, (fmt & DT_NOCLIP) ? 0 : ETO_CLIPPED, rc, lines[i], (UINT)lens[i], 0);
        if (!(fmt & DT_SINGLELINE) && y + lh > rc->bottom && !(fmt & DT_NOCLIP)) break;
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return nl * lh;
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
        memset(&lf, 0, sizeof lf);
        lf.lfHeight = -16; lf.lfWeight = FW_NORMAL; lf.lfCharSet = ANSI_CHARSET; lf.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
        memcpy(lf.lfFaceName, L"Shizuku Fixed 8x16", sizeof L"Shizuku Fixed 8x16");
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
