/* SPDX-License-Identifier: GPL-2.0-only
 * gdi32 rasteriser: pixels, lines, rectangles, ellipses, polygons, raster operations (PatBlt/BitBlt/StretchBlt) and the DIB
 * transfer functions. Everything draws into 32 bpp bitmaps; every primitive is clipped against the DC's effective clip
 * (a list of disjoint rectangles) and reports what it changed so window DCs can present exactly that area.
 *
 * Deliberate simplifications (each one is a gap, not a hidden behaviour): pens wider than one pixel have flat ends and no
 * joins; dashed styles apply to one-pixel pens only (as on Windows for cosmetic pens, wider ones are solid); hatch brushes
 * are approximations of the classic patterns; stretching is nearest-neighbour whatever the stretch mode; there are no
 * arcs, rounded rectangles or palettes. Paths, Bezier curves and the (translation-only) world transform are in gdi_path.c:
 * while a path is being recorded, MoveToEx/LineTo/Polyline/Polygon/Rectangle/Ellipse add to it and draw nothing.
 */
#include "gdi_internal.h"

static void fill32(uint32_t *p, uint32_t v, size_t n) { __asm__ volatile("rep stosl" : "+D"(p), "+c"(n) : "a"(v) : "memory"); }

/* ---------------------------------------------------------------- raster operations */
uint32_t gdi_rop3(uint32_t rop3, uint32_t p, uint32_t s, uint32_t d)
{
    uint32_t r = 0;
    unsigned i;
    for (i = 0; i < 8; ++i)
        if ((rop3 >> i) & 1)
            r |= ((i & 4) ? p : ~p) & ((i & 2) ? s : ~s) & ((i & 1) ? d : ~d);
    return (r & 0x00ffffffu) | (d & 0xff000000u);
}

uint32_t gdi_rop2(int rop2, uint32_t p, uint32_t d)
{
    uint32_t r;
    switch (rop2) {
    case R2_BLACK: r = 0; break;
    case R2_NOTMERGEPEN: r = ~(d | p); break;
    case R2_MASKNOTPEN: r = ~p & d; break;
    case R2_NOTCOPYPEN: r = ~p; break;
    case R2_MASKPENNOT: r = p & ~d; break;
    case R2_NOT: r = ~d; break;
    case R2_XORPEN: r = p ^ d; break;
    case R2_NOTMASKPEN: r = ~(p & d); break;
    case R2_MASKPEN: r = p & d; break;
    case R2_NOTXORPEN: r = ~(p ^ d); break;
    case R2_NOP: r = d; break;
    case R2_MERGENOTPEN: r = ~p | d; break;
    case R2_MERGEPEN: r = p | d; break;
    case R2_MERGEPENNOT: r = p | ~d; break;
    case R2_WHITE: r = 0xffffff; break;
    default: r = p; break;
    }
    return (r & 0x00ffffffu) | (d & 0xff000000u);
}

/* ---------------------------------------------------------------- drawing context */
static const uint8_t hatch_bits[6][8] = {
    { 0, 0, 0, 0xff, 0, 0, 0, 0 },                                  /* HS_HORIZONTAL */
    { 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08 },             /* HS_VERTICAL */
    { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 },             /* HS_FDIAGONAL */
    { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 },             /* HS_BDIAGONAL */
    { 0x08, 0x08, 0x08, 0xff, 0x08, 0x08, 0x08, 0x08 },             /* HS_CROSS */
    { 0x81, 0x42, 0x24, 0x18, 0x18, 0x24, 0x42, 0x81 }              /* HS_DIAGCROSS */
};

int gctx_begin(gctx_t *g, dc_t *dc)
{
    pen_t *pen;
    brush_t *br;
    COLORREF c;
    memset(g, 0, sizeof *g);
    g->dc = dc;
    g->bm = gdi_dc_target(dc);
    if (!g->bm || !g->bm->bits) return 0;
    g->clip = gdi_dc_clip(dc);
    pen = gdi_obj_get((HGDIOBJ)dc->pen, OBJ_PEN, 0);
    if (pen) {
        g->pstyle = (int)pen->lp.lopnStyle;
        g->pwidth = pen->lp.lopnWidth.x > 0 ? pen->lp.lopnWidth.x : 1;
        c = dc->pen == g_stock[DC_PEN] ? dc->dcpen : pen->lp.lopnColor;
    } else {
        g->pstyle = PS_SOLID;
        g->pwidth = 1;
        c = 0;
    }
    g->pnull = g->pstyle == PS_NULL;
    g->ppix = colorref_to_pixel(c);
    br = gdi_obj_get((HGDIOBJ)dc->brush, OBJ_BRUSH, 0);
    if (br) {
        c = dc->brush == g_stock[DC_BRUSH] ? dc->dcbrush : br->lb.lbColor;
        g->bkind = br->lb.lbStyle == BS_NULL ? 0 : br->lb.lbStyle == BS_HATCHED ? 2 : 1;
        g->bhatch = (int)br->lb.lbHatch;
    } else {
        c = 0xffffff;
        g->bkind = 1;
    }
    g->bpix = colorref_to_pixel(c);
    g->bbg = colorref_to_pixel(dc->bk_color);
    g->bopaque = dc->bkmode == OPAQUE;
    return 1;
}

static void mark(gctx_t *g, int x0, int y0, int x1, int y1)
{
    if (!g->has_dirty) { g->dirty.left = x0; g->dirty.top = y0; g->dirty.right = x1; g->dirty.bottom = y1; g->has_dirty = 1; return; }
    if (x0 < g->dirty.left) g->dirty.left = x0;
    if (y0 < g->dirty.top) g->dirty.top = y0;
    if (x1 > g->dirty.right) g->dirty.right = x1;
    if (y1 > g->dirty.bottom) g->dirty.bottom = y1;
}

void gctx_end(gctx_t *g)
{
    if (g->has_dirty) gdi_dc_touch(g->dc, &g->dirty);
}

void gctx_span_rop2(gctx_t *g, int x0, int x1, int y, uint32_t v, int rop2)
{
    int i;
    for (i = 0; i < g->clip->n; ++i) {
        const RECT *c = &g->clip->r[i];
        int a = x0 > c->left ? x0 : c->left, b = x1 < c->right ? x1 : c->right;
        uint32_t *row;
        if (y < c->top || y >= c->bottom || a >= b) continue;
        row = bm_px(g->bm, a, y);
        if (rop2 == R2_COPYPEN) fill32(row, v, (size_t)(b - a));
        else { int x; for (x = 0; x < b - a; ++x) row[x] = gdi_rop2(rop2, v, row[x]); }
        mark(g, a, y, b, y + 1);
    }
}

void gctx_pixel(gctx_t *g, int x, int y, uint32_t v, int rop2) { gctx_span_rop2(g, x, x + 1, y, v, rop2); }

/* One device scanline of the current brush over [x0,x1). */
void gctx_span_brush(gctx_t *g, int x0, int x1, int y)
{
    int i;
    if (g->bkind == 1) { gctx_span_rop2(g, x0, x1, y, g->bpix, R2_COPYPEN); return; }
    if (g->bkind != 2) return;
    for (i = 0; i < g->clip->n; ++i) {
        const RECT *c = &g->clip->r[i];
        int a = x0 > c->left ? x0 : c->left, b = x1 < c->right ? x1 : c->right, x;
        uint32_t *row;
        if (y < c->top || y >= c->bottom || a >= b) continue;
        row = bm_px(g->bm, a, y);
        for (x = a; x < b; ++x) {
            const int hh = g->bhatch >= 0 && g->bhatch < 6 ? g->bhatch : 0;
            const int px = (x - g->dc->brush_org.x) & 7, py = (y - g->dc->brush_org.y) & 7;
            const int on = (hatch_bits[hh][py] >> px) & 1;
            if (on) row[x - a] = g->bpix;
            else if (g->bopaque) row[x - a] = g->bbg;
        }
        mark(g, a, y, b, y + 1);
    }
}

static void fill_rect_brush(gctx_t *g, int l, int t, int r, int b)
{
    int y;
    for (y = t; y < b; ++y) gctx_span_brush(g, l, r, y);
}
static void fill_rect_solid(gctx_t *g, int l, int t, int r, int b, uint32_t v, int rop2)
{
    int y;
    for (y = t; y < b; ++y) gctx_span_rop2(g, l, r, y, v, rop2);
}

/* ---------------------------------------------------------------- pixels */
DLLAPI COLORREF WINAPI SetPixel(HDC hdc, int x, int y, COLORREF c)
{
    dc_t *dc;
    gctx_t g;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(CLR_INVALID); }
    if (!gctx_begin(&g, dc)) RET(CLR_INVALID);
    x = dc_lx(dc, x); y = dc_ly(dc, y);
    { int vis = 0, i; for (i = 0; i < g.clip->n; ++i) if (x >= g.clip->r[i].left && x < g.clip->r[i].right && y >= g.clip->r[i].top && y < g.clip->r[i].bottom) vis = 1; if (!vis) RET(CLR_INVALID); }
    gctx_pixel(&g, x, y, colorref_to_pixel(c), R2_COPYPEN);
    gctx_end(&g);
    RET(c & 0xffffff);
}

DLLAPI BOOL WINAPI SetPixelV(HDC hdc, int x, int y, COLORREF c)
{
    return SetPixel(hdc, x, y, c) != CLR_INVALID;
}

DLLAPI COLORREF WINAPI GetPixel(HDC hdc, int x, int y)
{
    dc_t *dc;
    bitmap_t *bm;
    const rlist_t *clip;
    int i;
    COLORREF c = CLR_INVALID;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(CLR_INVALID); }
    bm = gdi_dc_target(dc);
    if (!bm || !bm->bits) RET(CLR_INVALID);
    clip = gdi_dc_clip(dc);
    x = dc_lx(dc, x); y = dc_ly(dc, y);
    for (i = 0; i < clip->n; ++i)
        if (x >= clip->r[i].left && x < clip->r[i].right && y >= clip->r[i].top && y < clip->r[i].bottom) {
            c = pixel_to_colorref(*bm_px(bm, x, y));
            break;
        }
    RET(c);
}

/* ---------------------------------------------------------------- lines */
static uint32_t isqrt64(uint64_t v)
{
    uint64_t r = 0, bit = 1ull << 62;
    while (bit > v) bit >>= 2;
    while (bit) {
        if (v >= r + bit) { v -= r + bit; r = (r >> 1) + bit; } else r >>= 1;
        bit >>= 2;
    }
    return (uint32_t)r;
}

static int iceil(double v) { int i = (int)v; return v > (double)i ? i + 1 : i; }

/* Scanline fill of `nfig` closed polygons (counts[f] device-coordinate vertices each, stored one after the other) under the
 * ALTERNATE or WINDING rule, with a callback that paints [x0,x1) on row y. A pixel is inside when its centre is. */
void gdi_poly_fill(gctx_t *g, const POINT *pts, const int *counts, int nfig, int winding, gdi_span_fn fn, void *ctx)
{
    int miny, maxy, y, i, k, n = 0, f;
    struct cross { double x; int dir; } *xs;
    struct edge { POINT a, b; } *es;
    int ne = 0;
    for (f = 0; f < nfig; ++f) n += counts[f];
    if (n < 3) return;
    xs = gdi_alloc((size_t)n * sizeof *xs);
    es = gdi_alloc((size_t)n * sizeof *es);
    if (!xs || !es) { gdi_free(xs); gdi_free(es); return; }
    miny = maxy = pts[0].y;
    for (f = 0, k = 0; f < nfig; k += counts[f++])
        for (i = 0; i < counts[f]; ++i) {
            const POINT a = pts[k + i], b = pts[k + (i + 1) % counts[f]];
            if (a.y < miny) miny = a.y;
            if (a.y > maxy) maxy = a.y;
            if (a.y != b.y) { es[ne].a = a; es[ne].b = b; ++ne; }
        }
    for (y = miny; y < maxy; ++y) {
        int nx = 0;
        const double yc = y + 0.5;
        for (i = 0; i < ne; ++i) {
            const POINT a = es[i].a, b = es[i].b;
            double x;
            int j;
            if (!((a.y <= y && b.y > y) || (b.y <= y && a.y > y))) continue;
            x = a.x + (yc - a.y) * (double)(b.x - a.x) / (double)(b.y - a.y);
            j = nx++;
            while (j > 0 && xs[j - 1].x > x) { xs[j] = xs[j - 1]; --j; }
            xs[j].x = x;
            xs[j].dir = b.y > a.y ? 1 : -1;
        }
        if (winding) {
            int w = 0;
            for (k = 0; k + 1 < nx; ++k) {
                w += xs[k].dir;
                if (w != 0) fn(g, iceil(xs[k].x - 0.5), iceil(xs[k + 1].x - 0.5), y, ctx);
            }
        } else {
            for (k = 0; k + 1 < nx; k += 2) fn(g, iceil(xs[k].x - 0.5), iceil(xs[k + 1].x - 0.5), y, ctx);
        }
    }
    gdi_free(xs);
    gdi_free(es);
}

static void poly_fill(gctx_t *g, const POINT *pts, int n, int winding, gdi_span_fn fn, void *ctx)
{
    gdi_poly_fill(g, pts, &n, 1, winding, fn, ctx);
}

void gdi_span_pen(gctx_t *g, int x0, int x1, int y, void *ctx) { (void)ctx; if (x0 < x1) gctx_span_rop2(g, x0, x1, y, g->ppix, g->dc->rop2); }
void gdi_span_brush(gctx_t *g, int x0, int x1, int y, void *ctx) { (void)ctx; if (x0 < x1) gctx_span_brush(g, x0, x1, y); }
#define span_pen gdi_span_pen
#define span_br gdi_span_brush

static const uint8_t dash_pat[5][6] = { { 0 }, { 18, 6 }, { 3, 3 }, { 9, 3, 3, 3 }, { 9, 3, 3, 3, 3, 3 } };
static const uint8_t dash_n[5] = { 0, 2, 2, 4, 6 };

/* Draws a line between device points. `last` includes the end pixel (LineTo excludes it). */
void gdi_line(gctx_t *g, int x0, int y0, int x1, int y1, int last)
{
    const int rop2 = g->dc->rop2;
    if (g->pnull) return;
    if (g->pwidth > 1) {
        const int w = g->pwidth, h1 = w / 2, h2 = w - h1;
        if (x0 == x1 && y0 == y1) { if (last) fill_rect_solid(g, x0 - h1, y0 - h1, x0 + h2, y0 + h2, g->ppix, rop2); return; }
        if (y0 == y1) {
            const int a = x0 < x1 ? x0 : x1, b = x0 < x1 ? x1 : x0;
            fill_rect_solid(g, a, y0 - h1, last ? b + 1 : b, y0 + h2, g->ppix, rop2);
            return;
        }
        if (x0 == x1) {
            const int a = y0 < y1 ? y0 : y1, b = y0 < y1 ? y1 : y0;
            fill_rect_solid(g, x0 - h1, a, x0 + h2, last ? b + 1 : b, g->ppix, rop2);
            return;
        }
        {
            const int64_t dx = x1 - x0, dy = y1 - y0;
            const int64_t len = isqrt64((uint64_t)(dx * dx + dy * dy));
            const int64_t nx = -dy * w * 32768 / (len ? len : 1), ny = dx * w * 32768 / (len ? len : 1);   /* half width, 16.16 */
            POINT p[4];
            p[0].x = (LONG)(x0 + (nx >> 16)); p[0].y = (LONG)(y0 + (ny >> 16));
            p[1].x = (LONG)(x1 + (nx >> 16)); p[1].y = (LONG)(y1 + (ny >> 16));
            p[2].x = (LONG)(x1 - (nx >> 16)); p[2].y = (LONG)(y1 - (ny >> 16));
            p[3].x = (LONG)(x0 - (nx >> 16)); p[3].y = (LONG)(y0 - (ny >> 16));
            poly_fill(g, p, 4, 1, span_pen, 0);
        }
        return;
    }
    {
        int dx = x1 > x0 ? x1 - x0 : x0 - x1, dy = y1 > y0 ? y0 - y1 : y1 - y0;
        const int sx = x0 < x1 ? 1 : -1, sy = y0 < y1 ? 1 : -1;
        int err = dx + dy, x = x0, y = y0, seg = 0, left = 0;
        const int st = g->pstyle >= PS_DASH && g->pstyle <= PS_DASHDOTDOT ? g->pstyle : 0;
        if (st) left = dash_pat[st][0];
        for (;;) {
            const int done = x == x1 && y == y1;
            if (!done || last) {
                const int on = st == 0 || !(seg & 1);
                if (on) gctx_pixel(g, x, y, g->ppix, rop2);
                else if (g->dc->bkmode == OPAQUE) gctx_pixel(g, x, y, g->bbg, R2_COPYPEN);
            }
            if (done) break;
            if (st && --left <= 0) { seg = (seg + 1) % dash_n[st]; left = dash_pat[st][seg]; }
            {
                const int e2 = 2 * err;
                if (e2 >= dy) { err += dy; x += sx; }
                if (e2 <= dx) { err += dx; y += sy; }
            }
        }
    }
}

#define line_dev gdi_line

DLLAPI BOOL WINAPI MoveToEx(HDC hdc, int x, int y, LPPOINT old)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (old) *old = dc->pos;
    dc->pos.x = x;
    dc->pos.y = y;
    if (gdi_path_recording(dc)) gdi_path_moveto(dc);
    RET(TRUE);
}

DLLAPI BOOL WINAPI GetCurrentPositionEx(HDC hdc, LPPOINT p)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || !p) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    *p = dc->pos;
    RET(TRUE);
}

DLLAPI BOOL WINAPI LineTo(HDC hdc, int x, int y)
{
    dc_t *dc;
    gctx_t g;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (gdi_path_recording(dc)) {
        const BOOL ok = gdi_path_lineto(dc, x, y);
        if (ok) { dc->pos.x = x; dc->pos.y = y; }
        RET(ok);
    }
    if (gctx_begin(&g, dc)) {
        line_dev(&g, dc_lx(dc, dc->pos.x), dc_ly(dc, dc->pos.y), dc_lx(dc, x), dc_ly(dc, y), 0);
        gctx_end(&g);
    }
    dc->pos.x = x;
    dc->pos.y = y;
    RET(TRUE);
}

DLLAPI BOOL WINAPI Polyline(HDC hdc, const POINT *pts, int n)
{
    dc_t *dc;
    gctx_t g;
    int i;
    if (!pts || n < 2) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (gdi_path_recording(dc)) RET(gdi_path_poly(dc, pts, n, 0));
    if (gctx_begin(&g, dc)) {
        for (i = 0; i + 1 < n; ++i)
            line_dev(&g, dc_lx(dc, pts[i].x), dc_ly(dc, pts[i].y), dc_lx(dc, pts[i + 1].x), dc_ly(dc, pts[i + 1].y), i + 2 == n);
        gctx_end(&g);
    }
    RET(TRUE);
}

/* ---------------------------------------------------------------- rectangles, ellipses, polygons */
DLLAPI BOOL WINAPI Rectangle(HDC hdc, int l, int t, int r, int b)
{
    dc_t *dc;
    gctx_t g;
    int pw;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    l = dc_lx(dc, l); r = dc_lx(dc, r); t = dc_ly(dc, t); b = dc_ly(dc, b);
    if (l > r) { int s = l; l = r; r = s; }
    if (t > b) { int s = t; t = b; b = s; }
    if (gdi_path_recording(dc)) RET(gdi_path_rect_dev(dc, l, t, r, b, 0));
    if (!gctx_begin(&g, dc)) RET(TRUE);
    pw = g.pnull ? 0 : g.pwidth;
    { const int half = ((r - l) < (b - t) ? (r - l) : (b - t)) / 2; if (pw > half) pw = half; }
    fill_rect_brush(&g, l + pw, t + pw, r - pw, b - pw);
    if (pw) {                                                      /* the pen draws inside the rectangle */
        if (g.pstyle >= PS_DASH && g.pstyle <= PS_DASHDOTDOT && g.pwidth == 1) {
            line_dev(&g, l, t, r - 1, t, 1);
            line_dev(&g, r - 1, t, r - 1, b - 1, 1);
            line_dev(&g, r - 1, b - 1, l, b - 1, 1);
            line_dev(&g, l, b - 1, l, t, 1);
        } else {
            fill_rect_solid(&g, l, t, r, t + pw, g.ppix, dc->rop2);
            fill_rect_solid(&g, l, b - pw, r, b, g.ppix, dc->rop2);
            fill_rect_solid(&g, l, t + pw, l + pw, b - pw, g.ppix, dc->rop2);
            fill_rect_solid(&g, r - pw, t + pw, r, b - pw, g.ppix, dc->rop2);
        }
    }
    gctx_end(&g);
    RET(TRUE);
}

/* x extents of the ellipse inscribed in [l,r)x[t,b) on row y; returns 0 if the row misses it. A pixel belongs to the row when
 * its CENTRE lies inside the ellipse, computed in doubled coordinates so that the result is exactly mirror symmetric. */
static int ellipse_row(int l, int t, int r, int b, int y, int *xl, int *xr)
{
    const int64_t A2 = r - l, B2 = b - t, cx2 = (int64_t)l + r;      /* doubled semi-axes and centre */
    const int64_t dy2 = 2 * (int64_t)(y - t) + 1 - B2;
    int64_t q, dmax;
    if (A2 <= 0 || B2 <= 0 || dy2 * dy2 >= B2 * B2) return 0;
    q = isqrt64((uint64_t)(A2 * A2 * (B2 * B2 - dy2 * dy2) / (B2 * B2)));
    dmax = ((q ^ (cx2 + 1)) & 1) ? q - 1 : q;                          /* |2x+1-cx2| has the parity of cx2+1 */
    if (dmax < 0) return 0;
    *xl = (int)((cx2 - dmax - 1) / 2);
    *xr = (int)((cx2 + dmax - 1) / 2) + 1;
    return *xr > *xl;
}

DLLAPI BOOL WINAPI Ellipse(HDC hdc, int l, int t, int r, int b)
{
    dc_t *dc;
    gctx_t g;
    int y, pw;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    l = dc_lx(dc, l); r = dc_lx(dc, r); t = dc_ly(dc, t); b = dc_ly(dc, b);
    if (l > r) { int s = l; l = r; r = s; }
    if (t > b) { int s = t; t = b; b = s; }
    if (gdi_path_recording(dc)) RET(gdi_path_ellipse_dev(dc, l, t, r, b));
    if (!gctx_begin(&g, dc)) RET(TRUE);
    pw = g.pnull ? 0 : g.pwidth;
    for (y = t; y < b; ++y) {
        int ol, or_, il, ir;
        if (!ellipse_row(l, t, r, b, y, &ol, &or_)) continue;
        if (pw && ellipse_row(l + pw, t + pw, r - pw, b - pw, y, &il, &ir) && il > ol && ir < or_) {
            gctx_span_rop2(&g, ol, il, y, g.ppix, dc->rop2);
            gctx_span_rop2(&g, ir, or_, y, g.ppix, dc->rop2);
            gctx_span_brush(&g, il, ir, y);
        } else if (pw) {
            gctx_span_rop2(&g, ol, or_, y, g.ppix, dc->rop2);
        } else {
            gctx_span_brush(&g, ol, or_, y);
        }
    }
    gctx_end(&g);
    RET(TRUE);
}

DLLAPI BOOL WINAPI Polygon(HDC hdc, const POINT *pts, int n)
{
    dc_t *dc;
    gctx_t g;
    POINT *dv;
    int i;
    if (!pts || n < 2) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (gdi_path_recording(dc)) RET(gdi_path_poly(dc, pts, n, 1));
    if (!gctx_begin(&g, dc)) RET(TRUE);
    dv = gdi_alloc((size_t)n * sizeof *dv);
    if (!dv) RET(FALSE);
    for (i = 0; i < n; ++i) { dv[i].x = dc_lx(dc, pts[i].x); dv[i].y = dc_ly(dc, pts[i].y); }
    if (g.bkind) poly_fill(&g, dv, n, dc->polyfill == WINDING, span_br, 0);
    if (!g.pnull)
        for (i = 0; i < n; ++i) line_dev(&g, dv[i].x, dv[i].y, dv[(i + 1) % n].x, dv[(i + 1) % n].y, 0);
    gdi_free(dv);
    gctx_end(&g);
    RET(TRUE);
}

DLLAPI BOOL WINAPI FillRgn(HDC hdc, HRGN hrgn, HBRUSH hbr)
{
    dc_t *dc;
    rgn_t *rg;
    HBRUSH old;
    gctx_t g;
    int i;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    rg = gdi_obj_get((HGDIOBJ)hrgn, OBJ_REGION, 0);
    if (!dc || !rg || !gdi_obj_get((HGDIOBJ)hbr, OBJ_BRUSH, 0)) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    old = dc->brush;
    dc->brush = hbr;
    if (gctx_begin(&g, dc)) {
        const int dx = dc_ox(dc), dy = dc_oy(dc);
        for (i = 0; i < rg->rl.n; ++i)
            fill_rect_brush(&g, rg->rl.r[i].left + dx, rg->rl.r[i].top + dy, rg->rl.r[i].right + dx, rg->rl.r[i].bottom + dy);
        gctx_end(&g);
    }
    dc->brush = old;
    RET(TRUE);
}

/* ---------------------------------------------------------------- PatBlt / BitBlt / StretchBlt */
static uint32_t brush_pixel(gctx_t *g, int x, int y, int *draw)
{
    *draw = 1;
    if (g->bkind == 2) {
        const int hh = g->bhatch >= 0 && g->bhatch < 6 ? g->bhatch : 0;
        const int px = (x - g->dc->brush_org.x) & 7, py = (y - g->dc->brush_org.y) & 7;
        if ((hatch_bits[hh][py] >> px) & 1) return g->bpix;
        if (g->bopaque) return g->bbg;
        *draw = 0;
        return 0;
    }
    if (g->bkind == 0) { *draw = 0; return 0; }
    return g->bpix;
}

static int rop_uses_src(uint32_t rop3)
{
    unsigned p, d;
    for (p = 0; p < 2; ++p)
        for (d = 0; d < 2; ++d)
            if (((rop3 >> ((p << 2) | 2 | d)) & 1) != ((rop3 >> ((p << 2) | d)) & 1)) return 1;
    return 0;
}
static int rop_uses_pat(uint32_t rop3)
{
    unsigned s, d;
    for (s = 0; s < 2; ++s)
        for (d = 0; d < 2; ++d)
            if (((rop3 >> (4 | (s << 1) | d)) & 1) != ((rop3 >> ((s << 1) | d)) & 1)) return 1;
    return 0;
}

typedef struct {
    bitmap_t *src;                                                  /* NULL: the ROP does not read a source */
    int sx, sy, sw, sh, flipx, flipy;                               /* source rectangle (device) and mirroring */
    int dx, dy, dw, dh;                                             /* destination rectangle (device) */
    uint32_t rop3;
} blit_t;

/* 1:1 without mirroring: rows are copied (SRCCOPY copies the whole 32-bit pixel, alpha byte included, as GDI does
 * for 32 bpp DIBs) or combined without any per-pixel division. Rows go bottom-up when the source lies above the
 * destination inside the same bitmap, so no snapshot is needed for overlapping copies. */
static void rop_rect_1to1(gctx_t *g, const blit_t *b, const RECT *o0, int upat)
{
    RECT o = *o0;
    const int ox = b->sx - b->dx, oy = b->sy - b->dy;                /* source = destination + (ox, oy) */
    int y, y0, y1, step;
    if (o.left + ox < 0) o.left = -ox;                              /* keep the source inside its bitmap */
    if (o.top + oy < 0) o.top = -oy;
    if (o.right + ox > b->src->w) o.right = b->src->w - ox;
    if (o.bottom + oy > b->src->h) o.bottom = b->src->h - oy;
    if (o.left >= o.right || o.top >= o.bottom) return;
    if (b->src == g->bm && oy < 0) { y0 = o.bottom - 1; y1 = o.top - 1; step = -1; } else { y0 = o.top; y1 = o.bottom; step = 1; }
    for (y = y0; y != y1; y += step) {
        uint32_t *d = bm_px(g->bm, o.left, y);
        const uint32_t *sr = bm_px(b->src, o.left + ox, y + oy);
        const int n = o.right - o.left;
        int x;
        if (b->rop3 == 0xcc) { memmove(d, sr, (size_t)n * 4); continue; }
        for (x = 0; x < n; ++x) {
            uint32_t p = 0;
            if (upat) {
                int drew;
                p = brush_pixel(g, o.left + x, y, &drew);
                if (!drew) { if (b->rop3 == 0xf0) continue; p = 0; }
            }
            d[x] = gdi_rop3(b->rop3, p, sr[x], d[x]);
        }
    }
    mark(g, o.left, o.top, o.right, o.bottom);
}

static void rop_rect(gctx_t *g, const blit_t *b)
{
    int i, y;
    const int upat = rop_uses_pat(b->rop3);
    int *xmap = 0;
    int xmap_stack[1024];
    if (upat && g->bkind == 0) return;                              /* NULL_BRUSH: nothing to paint with */
    if (b->src && b->sw == b->dw && b->sh == b->dh && !b->flipx && !b->flipy) {
        for (i = 0; i < g->clip->n; ++i) {
            RECT want, o;
            want.left = b->dx; want.top = b->dy; want.right = b->dx + b->dw; want.bottom = b->dy + b->dh;
            if (rc_intersect(&o, &want, &g->clip->r[i])) rop_rect_1to1(g, b, &o, upat);
        }
        return;
    }
    if (b->src) {                                                   /* stretching: the source column of every destination column, once */
        int k;
        xmap = b->dw <= 1024 ? xmap_stack : gdi_alloc((size_t)b->dw * sizeof *xmap);
        if (!xmap) return;
        for (k = 0; k < b->dw; ++k) {
            int ux = (int)(((int64_t)k * b->sw) / b->dw);
            if (b->flipx) ux = b->sw - 1 - ux;
            ux += b->sx;
            xmap[k] = ux >= 0 && ux < b->src->w ? ux : -1;
        }
    }
    for (i = 0; i < g->clip->n; ++i) {
        RECT want, o;
        want.left = b->dx; want.top = b->dy; want.right = b->dx + b->dw; want.bottom = b->dy + b->dh;
        if (!rc_intersect(&o, &want, &g->clip->r[i])) continue;
        for (y = o.top; y < o.bottom; ++y) {
            const uint32_t *srow = 0;
            if (b->src) {
                int uy = (int)(((int64_t)(y - b->dy) * b->sh) / b->dh);
                if (b->flipy) uy = b->sh - 1 - uy;
                uy += b->sy;
                if (uy < 0 || uy >= b->src->h) continue;
                srow = bm_px(b->src, 0, uy);
            }
            {
                int x;
                uint32_t *row = bm_px(g->bm, o.left, y);
                for (x = o.left; x < o.right; ++x, ++row) {
                    uint32_t p = 0, s = 0;
                    if (srow) {
                        const int ux = xmap[x - b->dx];
                        if (ux < 0) continue;
                        s = srow[ux];
                        if (b->rop3 == 0xcc) { *row = s; continue; }
                    }
                    if (upat) {
                        int drew;
                        p = brush_pixel(g, x, y, &drew);
                        if (!drew) { if (b->rop3 == 0xf0) continue; p = 0; }
                    }
                    *row = gdi_rop3(b->rop3, p, s, *row);
                }
            }
        }
        mark(g, o.left, o.top, o.right, o.bottom);
    }
    if (xmap && xmap != xmap_stack) gdi_free(xmap);
}

static BOOL do_blit(dc_t *dst, int dx, int dy, int dw, int dh, dc_t *src, int sx, int sy, int sw, int sh, DWORD rop)
{
    gctx_t g;
    blit_t b;
    bitmap_t *tmp = 0;
    memset(&b, 0, sizeof b);
    b.rop3 = (rop >> 16) & 0xff;
    if (!gctx_begin(&g, dst)) return TRUE;
    dx = dc_lx(dst, dx); dy = dc_ly(dst, dy);
    if (rop_uses_src(b.rop3)) {
        bitmap_t *raw;
        if (!src) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        raw = gdi_dc_target(src);
        if (!raw || !raw->bits) return FALSE;
        sx = dc_lx(src, sx); sy = dc_ly(src, sy);
        if (raw == g.bm && !(sw == dw && sh == dh && sw > 0 && sh > 0 && dw > 0 && dh > 0)) {   /* stretched copy inside one bitmap: a snapshot */
            tmp = gdi_alloc(sizeof *tmp);
            if (!tmp) return FALSE;
            *tmp = *raw;
            tmp->bits = gdi_alloc_pixels((uint64_t)raw->w * (uint64_t)raw->h, &tmp->big);
            if (!tmp->bits) { gdi_free(tmp); return FALSE; }
            memcpy(tmp->bits, raw->bits, (size_t)raw->w * (size_t)raw->h * 4);
            b.src = tmp;
        } else {
            b.src = raw;
        }
        if (sw < 0) { sx += sw; sw = -sw; b.flipx ^= 1; }
        if (sh < 0) { sy += sh; sh = -sh; b.flipy ^= 1; }
        b.sx = sx; b.sy = sy; b.sw = sw; b.sh = sh;
    }
    if (dw < 0) { dx += dw; dw = -dw; b.flipx ^= 1; }
    if (dh < 0) { dy += dh; dh = -dh; b.flipy ^= 1; }
    b.dx = dx; b.dy = dy; b.dw = dw; b.dh = dh;
    if (dw > 0 && dh > 0 && (!b.src || (b.sw > 0 && b.sh > 0))) rop_rect(&g, &b);
    gctx_end(&g);
    if (tmp) { gdi_free_pixels(tmp->bits, (uint64_t)tmp->w * (uint64_t)tmp->h, tmp->big); gdi_free(tmp); }
    return TRUE;
}

DLLAPI BOOL WINAPI PatBlt(HDC hdc, int x, int y, int w, int h, DWORD rop)
{
    dc_t *dc;
    BOOL ok;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    ok = do_blit(dc, x, y, w, h, 0, 0, 0, 0, 0, rop);
    RET(ok);
}

DLLAPI BOOL WINAPI BitBlt(HDC hdcd, int xd, int yd, int w, int h, HDC hdcs, int xs, int ys, DWORD rop)
{
    dc_t *d, *s = 0;
    BOOL ok;
    GDI_ENTER();
    d = gdi_dc_get(hdcd);
    if (hdcs) s = gdi_dc_get(hdcs);
    if (!d || (hdcs && !s)) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    ok = do_blit(d, xd, yd, w, h, s, xs, ys, w, h, rop);
    RET(ok);
}

DLLAPI BOOL WINAPI StretchBlt(HDC hdcd, int xd, int yd, int wd, int hd, HDC hdcs, int xs, int ys, int ws, int hs, DWORD rop)
{
    dc_t *d, *s = 0;
    BOOL ok;
    GDI_ENTER();
    d = gdi_dc_get(hdcd);
    if (hdcs) s = gdi_dc_get(hdcs);
    if (!d || (hdcs && !s)) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    ok = do_blit(d, xd, yd, wd, hd, s, xs, ys, ws, hs, rop);
    RET(ok);
}

DLLAPI BOOL WINAPI GdiAlphaBlend(HDC hdcd, int xd, int yd, int wd, int hd, HDC hdcs, int xs, int ys, int ws, int hs, BLENDFUNCTION bf)
{
    dc_t *d, *s;
    gctx_t g;
    bitmap_t *sb;
    int i, y;
    GDI_ENTER();
    d = gdi_dc_get(hdcd);
    s = gdi_dc_get(hdcs);
    if (!d || !s || bf.BlendOp != AC_SRC_OVER || wd <= 0 || hd <= 0 || ws <= 0 || hs <= 0 || (bf.AlphaFormat & ~AC_SRC_ALPHA)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        RET(FALSE);
    }
    if (!gctx_begin(&g, d)) RET(TRUE);
    sb = gdi_dc_target(s);
    if (!sb || !sb->bits) RET(FALSE);
    xd = dc_lx(d, xd); yd = dc_ly(d, yd); xs = dc_lx(s, xs); ys = dc_ly(s, ys);
    for (i = 0; i < g.clip->n; ++i) {
        RECT want, o;
        want.left = xd; want.top = yd; want.right = xd + wd; want.bottom = yd + hd;
        if (!rc_intersect(&o, &want, &g.clip->r[i])) continue;
        for (y = o.top; y < o.bottom; ++y) {
            int x;
            for (x = o.left; x < o.right; ++x) {
                const int ux = xs + (int)((int64_t)(x - xd) * ws / wd), uy = ys + (int)((int64_t)(y - yd) * hs / hd);
                uint32_t sp, dp, a, ia, sa;
                uint32_t *px;
                if (ux < 0 || uy < 0 || ux >= sb->w || uy >= sb->h) continue;
                sp = *bm_px(sb, ux, uy);
                px = bm_px(g.bm, x, y);
                dp = *px;
                sa = (bf.AlphaFormat & AC_SRC_ALPHA) ? (sp >> 24) * bf.SourceConstantAlpha / 255 : bf.SourceConstantAlpha;
                if (bf.AlphaFormat & AC_SRC_ALPHA) {                /* premultiplied source: dst = src*constant + dst*(1 - srcalpha*constant) */
                    const uint32_t k = bf.SourceConstantAlpha;
                    const uint32_t r = ((sp >> 16 & 255) * k / 255) + (dp >> 16 & 255) * (255 - sa) / 255;
                    const uint32_t gg = ((sp >> 8 & 255) * k / 255) + (dp >> 8 & 255) * (255 - sa) / 255;
                    const uint32_t b2 = ((sp & 255) * k / 255) + (dp & 255) * (255 - sa) / 255;
                    *px = (r > 255 ? 255 : r) << 16 | (gg > 255 ? 255 : gg) << 8 | (b2 > 255 ? 255 : b2);
                } else {
                    a = sa; ia = 255 - a;
                    *px = (((sp >> 16 & 255) * a + (dp >> 16 & 255) * ia) / 255) << 16 | (((sp >> 8 & 255) * a + (dp >> 8 & 255) * ia) / 255) << 8 |
                          (((sp & 255) * a + (dp & 255) * ia) / 255);
                }
            }
        }
        mark(&g, o.left, o.top, o.right, o.bottom);
    }
    gctx_end(&g);
    RET(TRUE);
}

/* Private export for user32's icons and cursors (not a Windows API): draws a top-down sw x sh image of straight
 * (non-premultiplied) 0xAARRGGBB pixels scaled nearest-neighbour to w x h at logical (x,y), clipped like any primitive.
 * mode 3 (DI_NORMAL) blends with the per-pixel alpha, mode 2 (DI_IMAGE) copies the colour ignoring alpha, mode 1 (DI_MASK)
 * blackens the pixels whose alpha is at least 128 (the AND mask) and leaves the others alone. */
DLLAPI BOOL WINAPI ShzGdiDrawArgb(HDC hdc, int x, int y, int w, int h, const uint32_t *argb, int sw, int sh, int mode)
{
    dc_t *d;
    gctx_t g;
    int i, py;
    GDI_ENTER();
    d = gdi_dc_get(hdc);
    if (!d || !argb || w <= 0 || h <= 0 || sw <= 0 || sh <= 0 || mode < 1 || mode > 3) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    if (!gctx_begin(&g, d)) RET(TRUE);
    x = dc_lx(d, x); y = dc_ly(d, y);
    for (i = 0; i < g.clip->n; ++i) {
        RECT want, o;
        want.left = x; want.top = y; want.right = x + w; want.bottom = y + h;
        if (!rc_intersect(&o, &want, &g.clip->r[i])) continue;
        for (py = o.top; py < o.bottom; ++py) {
            const uint32_t *srow = argb + (size_t)((int64_t)(py - y) * sh / h) * (size_t)sw;
            uint32_t *px = bm_px(g.bm, o.left, py);
            int px_x;
            for (px_x = o.left; px_x < o.right; ++px_x, ++px) {
                const uint32_t s = srow[(int64_t)(px_x - x) * sw / w], a = s >> 24, d0 = *px;
                if (mode == 1) { if (a >= 128) *px = d0 & 0xff000000u; continue; }
                if (mode == 2 || a == 255) { *px = (s & 0x00ffffffu) | (d0 & 0xff000000u); continue; }
                if (a == 0) continue;
                *px = (((s >> 16 & 255) * a + (d0 >> 16 & 255) * (255 - a)) / 255) << 16 | (((s >> 8 & 255) * a + (d0 >> 8 & 255) * (255 - a)) / 255) << 8 |
                      (((s & 255) * a + (d0 & 255) * (255 - a)) / 255) | (d0 & 0xff000000u);
            }
        }
        mark(&g, o.left, o.top, o.right, o.bottom);
    }
    gctx_end(&g);
    RET(TRUE);
}

/* ---------------------------------------------------------------- DIB transfer */
typedef struct {
    const BITMAPINFOHEADER *h;
    const uint8_t *bits;
    int w, ha, bpp, topdown;
    size_t stride;
    const RGBQUAD *pal; int npal;
    uint32_t rmask, gmask, bmask;
} dib_t;

static int dib_open(dib_t *d, const BITMAPINFO *bmi, const void *bits)
{
    const BITMAPINFOHEADER *h;
    if (!bmi || !bits || bmi->bmiHeader.biSize < sizeof(BITMAPINFOHEADER) || bmi->bmiHeader.biPlanes != 1) return 0;
    h = &bmi->bmiHeader;
    d->h = h;
    d->bits = bits;
    d->w = h->biWidth;
    d->topdown = h->biHeight < 0;
    d->ha = h->biHeight < 0 ? -h->biHeight : h->biHeight;
    d->bpp = h->biBitCount;
    if (d->w <= 0 || d->ha <= 0) return 0;
    if (h->biCompression != BI_RGB && h->biCompression != BI_BITFIELDS) return 0;
    if (d->bpp != 1 && d->bpp != 4 && d->bpp != 8 && d->bpp != 16 && d->bpp != 24 && d->bpp != 32) return 0;
    d->stride = (((size_t)d->w * (size_t)d->bpp + 31) / 32) * 4;
    d->pal = 0; d->npal = 0;
    d->rmask = d->bpp == 16 ? 0x7c00 : 0x00ff0000; d->gmask = d->bpp == 16 ? 0x03e0 : 0x0000ff00; d->bmask = d->bpp == 16 ? 0x001f : 0x000000ff;
    if (h->biCompression == BI_BITFIELDS && (d->bpp == 16 || d->bpp == 32)) {
        const DWORD *m = (const DWORD *)((const uint8_t *)bmi + h->biSize);
        d->rmask = m[0]; d->gmask = m[1]; d->bmask = m[2];
    }
    if (d->bpp <= 8) {
        d->npal = h->biClrUsed ? (int)h->biClrUsed : 1 << d->bpp;
        d->pal = (const RGBQUAD *)((const uint8_t *)bmi + h->biSize);
    }
    return 1;
}

static uint32_t scale_mask(uint32_t v, uint32_t mask)
{
    unsigned sh = 0, bitsn = 0;
    uint32_t m = mask;
    if (!m) return 0;
    while (!(m & 1)) { m >>= 1; ++sh; }
    while (m & 1) { m >>= 1; ++bitsn; }
    v = (v & mask) >> sh;
    return bitsn >= 8 ? v >> (bitsn - 8) : (v * 255) / ((1u << bitsn) - 1);
}

/* pixel at (x, row counted from the TOP of the picture) as 0x00RRGGBB */
static uint32_t dib_px(const dib_t *d, int x, int ytop)
{
    const int row = d->topdown ? ytop : d->ha - 1 - ytop;
    const uint8_t *p = d->bits + (size_t)row * d->stride;
    switch (d->bpp) {
    case 32: { uint32_t v = *(const uint32_t *)(p + (size_t)x * 4); return d->rmask == 0x00ff0000 && d->gmask == 0xff00 && d->bmask == 0xff ? v : (scale_mask(v, d->rmask) << 16 | scale_mask(v, d->gmask) << 8 | scale_mask(v, d->bmask)); }
    case 24: return (uint32_t)p[(size_t)x * 3 + 2] << 16 | (uint32_t)p[(size_t)x * 3 + 1] << 8 | p[(size_t)x * 3];
    case 16: { uint32_t v = *(const uint16_t *)(p + (size_t)x * 2); return scale_mask(v, d->rmask) << 16 | scale_mask(v, d->gmask) << 8 | scale_mask(v, d->bmask); }
    case 8: { int i = p[x]; if (i >= d->npal) return 0; return (uint32_t)d->pal[i].rgbRed << 16 | (uint32_t)d->pal[i].rgbGreen << 8 | d->pal[i].rgbBlue; }
    case 4: { int i = (p[x >> 1] >> ((x & 1) ? 0 : 4)) & 15; if (i >= d->npal) return 0; return (uint32_t)d->pal[i].rgbRed << 16 | (uint32_t)d->pal[i].rgbGreen << 8 | d->pal[i].rgbBlue; }
    default: { int i = (p[x >> 3] >> (7 - (x & 7))) & 1; if (i >= d->npal) return i ? 0xffffff : 0; return (uint32_t)d->pal[i].rgbRed << 16 | (uint32_t)d->pal[i].rgbGreen << 8 | d->pal[i].rgbBlue; }
    }
}

/* one DIB row -> 0x00RRGGBB (0xAARRGGBB for 32 bpp) pixels, columns [x0, x0+n) */
static void dib_row(const dib_t *d, int ytop, int x0, int n, uint32_t *out)
{
    const int row = d->topdown ? ytop : d->ha - 1 - ytop;
    const uint8_t *p = d->bits + (size_t)row * d->stride;
    int x;
    if (d->bpp == 32 && d->rmask == 0x00ff0000 && d->gmask == 0xff00 && d->bmask == 0xff) { memcpy(out, p + (size_t)x0 * 4, (size_t)n * 4); return; }
    if (d->bpp == 24) {
        const uint8_t *q = p + (size_t)x0 * 3;
        for (x = 0; x < n; ++x, q += 3) out[x] = (uint32_t)q[2] << 16 | (uint32_t)q[1] << 8 | q[0];
        return;
    }
    for (x = 0; x < n; ++x) out[x] = dib_px(d, x0 + x, ytop);
}

/* Source rectangle in DIB coordinates (origin bottom-left for bottom-up DIBs, as GDI defines them). At 1:1 without
 * mirroring whole rows are converted at once (32 bpp BI_RGB rows are plain copies, the alpha byte included); stretching
 * maps every destination column to its source column once per call. */
static int stretch_dib(dc_t *dc, int xd, int yd, int wd, int hd, int xs, int ys, int ws, int hs, const dib_t *d, DWORD rop)
{
    gctx_t g;
    const uint32_t rop3 = (rop >> 16) & 0xff;
    int i, y, flipx = 0, flipy = 0, ytop;
    int *xmap = 0, xmap_stack[1024];
    uint32_t *line = 0, line_stack[1024];
    if (!gctx_begin(&g, dc)) return 1;
    xd = dc_lx(dc, xd); yd = dc_ly(dc, yd);
    if (wd < 0) { xd += wd; wd = -wd; flipx ^= 1; }
    if (hd < 0) { yd += hd; hd = -hd; flipy ^= 1; }
    if (ws < 0) { xs += ws; ws = -ws; flipx ^= 1; }
    if (hs < 0) { ys += hs; hs = -hs; flipy ^= 1; }
    if (wd == 0 || hd == 0 || ws == 0 || hs == 0) return 1;
    ytop = d->topdown ? ys : d->ha - ys - hs;
    if (wd == ws && hd == hs && !flipx && !flipy) {                 /* 1:1 */
        for (i = 0; i < g.clip->n; ++i) {
            RECT want, o;
            want.left = xd; want.top = yd; want.right = xd + wd; want.bottom = yd + hd;
            if (!rc_intersect(&o, &want, &g.clip->r[i])) continue;
            if (o.left - xd + xs < 0) o.left = xd - xs;             /* the source columns/rows that exist */
            if (o.right - xd + xs > d->w) o.right = xd - xs + d->w;
            if (o.top - yd + ytop < 0) o.top = yd - ytop;
            if (o.bottom - yd + ytop > d->ha) o.bottom = yd - ytop + d->ha;
            if (o.left >= o.right || o.top >= o.bottom) continue;
            for (y = o.top; y < o.bottom; ++y) {
                uint32_t *row = bm_px(g.bm, o.left, y);
                const int n = o.right - o.left;
                if (rop3 == 0xcc) { dib_row(d, y - yd + ytop, o.left - xd + xs, n, row); continue; }
                {
                    int x;
                    if (!line) line = d->w <= 1024 ? line_stack : gdi_alloc((size_t)d->w * 4);
                    if (!line) break;
                    dib_row(d, y - yd + ytop, o.left - xd + xs, n, line);
                    for (x = 0; x < n; ++x) row[x] = gdi_rop3(rop3, g.bkind ? g.bpix : 0, line[x], row[x]);
                }
            }
            mark(&g, o.left, o.top, o.right, o.bottom);
        }
        if (line && line != line_stack) gdi_free(line);
        gctx_end(&g);
        return 1;
    }
    xmap = wd <= 1024 ? xmap_stack : gdi_alloc((size_t)wd * sizeof *xmap);
    if (!xmap) return 0;
    for (i = 0; i < wd; ++i) {
        int ux = (int)((int64_t)i * ws / wd);
        if (flipx) ux = ws - 1 - ux;
        ux += xs;
        xmap[i] = ux >= 0 && ux < d->w ? ux : -1;
    }
    for (i = 0; i < g.clip->n; ++i) {
        RECT want, o;
        want.left = xd; want.top = yd; want.right = xd + wd; want.bottom = yd + hd;
        if (!rc_intersect(&o, &want, &g.clip->r[i])) continue;
        for (y = o.top; y < o.bottom; ++y) {
            int x, uy = (int)((int64_t)(y - yd) * hs / hd);
            uint32_t *row = bm_px(g.bm, o.left, y);
            if (flipy) uy = hs - 1 - uy;
            uy += ytop;
            if (uy < 0 || uy >= d->ha) continue;
            for (x = o.left; x < o.right; ++x, ++row) {
                const int ux = xmap[x - xd];
                uint32_t s;
                if (ux < 0) continue;
                s = dib_px(d, ux, uy);
                *row = rop3 == 0xcc ? s : gdi_rop3(rop3, g.bkind ? g.bpix : 0, s, *row);
            }
        }
        mark(&g, o.left, o.top, o.right, o.bottom);
    }
    if (xmap != xmap_stack) gdi_free(xmap);
    gctx_end(&g);
    return 1;
}

DLLAPI int WINAPI StretchDIBits(HDC hdc, int xd, int yd, int wd, int hd, int xs, int ys, int ws, int hs, const VOID *bits,
                                const BITMAPINFO *bmi, UINT usage, DWORD rop)
{
    dc_t *dc;
    dib_t d;
    int ok;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(GDI_ERROR); }
    if (usage != DIB_RGB_COLORS || !dib_open(&d, bmi, bits)) { SetLastError(ERROR_INVALID_PARAMETER); RET(GDI_ERROR); }
    ok = stretch_dib(dc, xd, yd, wd, hd, xs, ys, ws, hs, &d, rop);
    RET(ok ? (hs < 0 ? -hs : hs) : GDI_ERROR);
}

DLLAPI int WINAPI SetDIBitsToDevice(HDC hdc, int xd, int yd, DWORD w, DWORD h, int xs, int ys, UINT start, UINT lines,
                                    const VOID *bits, const BITMAPINFO *bmi, UINT usage)
{
    dc_t *dc;
    dib_t d;
    int y0, y1, dest_y, n;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    if (usage != DIB_RGB_COLORS || !dib_open(&d, bmi, bits)) { SetLastError(ERROR_INVALID_PARAMETER); RET(0); }
    if (start >= (UINT)d.ha) RET(0);
    if (lines > (UINT)d.ha - start) lines = (UINT)d.ha - start;
    d.bits = (const uint8_t *)bits - (size_t)start * d.stride;      /* `bits` holds scan lines [start, start+lines) only */
    y0 = ys; y1 = ys + (int)h;                                      /* rows of the source rectangle, in the DIB's own row order */
    if (y0 < (int)start) y0 = (int)start;
    if (y1 > (int)(start + lines)) y1 = (int)(start + lines);
    if (y1 <= y0) RET(0);
    /* bottom-up DIBs count rows from the bottom, so the highest row lands on the destination's top edge */
    dest_y = d.topdown ? yd + (y0 - ys) : yd + (ys + (int)h - y1);
    stretch_dib(dc, xd, dest_y, (int)w, y1 - y0, xs, y0, (int)w, y1 - y0, &d, SRCCOPY);
    n = y1 - y0;
    RET(n);
}

DLLAPI int WINAPI SetDIBits(HDC hdc, HBITMAP hbm, UINT start, UINT lines, const VOID *bits, const BITMAPINFO *bmi, UINT usage)
{
    bitmap_t *b;
    dib_t d;
    int x, y, n = 0;
    (void)hdc;
    GDI_ENTER();
    b = gdi_obj_get((HGDIOBJ)hbm, OBJ_BITMAP, 0);
    if (!b || usage != DIB_RGB_COLORS || !dib_open(&d, bmi, bits)) { SetLastError(ERROR_INVALID_PARAMETER); RET(0); }
    for (y = 0; y < (int)lines && (int)(start + (UINT)y) < d.ha; ++y) {
        const int ytop = d.topdown ? (int)start + y : d.ha - 1 - ((int)start + y);
        if (ytop >= b->h) continue;
        for (x = 0; x < d.w && x < b->w; ++x) *bm_px(b, x, ytop) = dib_px(&d, x, d.topdown ? (int)start + y : d.ha - 1 - ((int)start + y));
        ++n;
    }
    RET(n);
}

DLLAPI int WINAPI GetDIBits(HDC hdc, HBITMAP hbm, UINT start, UINT lines, LPVOID bits, LPBITMAPINFO bmi, UINT usage)
{
    bitmap_t *b;
    int y, n = 0;
    size_t stride;
    (void)hdc;
    GDI_ENTER();
    b = gdi_obj_get((HGDIOBJ)hbm, OBJ_BITMAP, 0);
    if (!b || !bmi || usage != DIB_RGB_COLORS || bmi->bmiHeader.biSize < sizeof(BITMAPINFOHEADER)) { SetLastError(ERROR_INVALID_PARAMETER); RET(0); }
    if (!bits) {                                                    /* query: describe the bitmap as a DIB */
        BITMAPINFOHEADER *h = &bmi->bmiHeader;
        if (h->biBitCount == 0) h->biBitCount = 32;
        h->biWidth = b->w;
        h->biHeight = h->biHeight < 0 ? -b->h : b->h;
        h->biPlanes = 1;
        h->biCompression = BI_RGB;
        h->biSizeImage = (DWORD)(((size_t)b->w * h->biBitCount + 31) / 32 * 4 * (size_t)b->h);
        RET(b->h);
    }
    if (bmi->bmiHeader.biBitCount != 32 && bmi->bmiHeader.biBitCount != 24) { SetLastError(ERROR_NOT_SUPPORTED); RET(0); }
    if (bmi->bmiHeader.biCompression != BI_RGB) { SetLastError(ERROR_NOT_SUPPORTED); RET(0); }
    stride = ((size_t)b->w * bmi->bmiHeader.biBitCount + 31) / 32 * 4;
    for (y = 0; y < (int)lines && (int)(start + (UINT)y) < b->h; ++y) {
        const int srow = bmi->bmiHeader.biHeight < 0 ? (int)start + y : b->h - 1 - ((int)start + y);
        const int top = b->topdown ? srow : b->h - 1 - srow;
        uint8_t *dst = (uint8_t *)bits + (size_t)y * stride;
        int x;
        for (x = 0; x < b->w; ++x) {
            const uint32_t p = b->bits[(size_t)top * (size_t)b->w + (size_t)x];
            if (bmi->bmiHeader.biBitCount == 32) ((uint32_t *)dst)[x] = p;
            else { dst[x * 3] = (uint8_t)p; dst[x * 3 + 1] = (uint8_t)(p >> 8); dst[x * 3 + 2] = (uint8_t)(p >> 16); }
        }
        ++n;
    }
    RET(n);
}
