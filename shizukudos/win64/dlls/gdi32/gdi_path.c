/* SPDX-License-Identifier: GPL-2.0-only
 * gdi32: paths, Bezier curves, the world transform, pixel formats and the printing entry points.
 *
 * Paths. BeginPath opens a bracket; until EndPath, MoveToEx/LineTo/Polyline/Polygon/Rectangle/Ellipse/PolyBezier(To)/
 * CloseFigure and ExtTextOut add figures instead of drawing. Points are kept in DEVICE coordinates, as on Windows, with the
 * PT_MOVETO/PT_LINETO/PT_BEZIERTO/PT_CLOSEFIGURE types GetPath reports. Curves are flattened (FlattenPath, and before any
 * use) by uniform subdivision fine enough that no chord is longer than about two pixels. FillPath fills with the brush
 * under the DC's polygon fill mode (every figure closed), StrokePath strokes each figure with the pen (closed figures get
 * their closing segment), SelectClipPath/PathToRegion turn the filled area into a region pixel-exactly (pixel centres
 * inside), WidenPath replaces the path by the outline of the area the pen would paint: both sides of every figure, with
 * the pen's end caps (round/square/flat) and joins (round/bevel/mitre within the miter limit). The widened outline of a
 * figure whose inner side turns sharply crosses itself, as on Windows, so it is meant to be filled with WINDING.
 * Text in a path adds the exact pixel outline of the bitmap glyphs (one rectangle per run of set pixels).
 *
 * World transform. Only translations exist: SetWorldTransform/ModifyWorldTransform accept a matrix whose linear part is the
 * identity (offsets are rounded to whole pixels) and refuse anything that scales, rotates or shears with
 * ERROR_NOT_SUPPORTED, leaving the transform unchanged. Both need GM_ADVANCED, as on Windows.
 *
 * Pixel formats. There is no OpenGL: the one pixel format is the GDI-only generic format (32-bit RGBA drawn to a window or
 * a bitmap, single buffered, no depth or stencil). SwapBuffers presents what GDI drew into the window.
 *
 * Printing. No printer DC can be created, so StartDoc/StartPage/EndPage/EndDoc/SetAbortProc fail with SP_ERROR on every
 * DC this gdi32 has; ExtEscape implements no escape (0, as Windows answers for an unsupported one); CancelDC has nothing
 * pending to cancel (every call completes synchronously) and succeeds. GetICMProfile: no colour profile is installed.
 */
#include "gdi_internal.h"

DLLAPI BOOL WINAPI ShzGdiRegionSetRects(HRGN h, const RECT *in, int n);

/* ---------------------------------------------------------------- the little floating-point maths this file needs (no libm) */
#define PI_D 3.14159265358979323846
static double m_sqrt(double x) { double r; __asm__("sqrtsd %1, %0" : "=x"(r) : "x"(x)); return r; }
static double m_fabs(double x) { return x < 0 ? -x : x; }
static double m_floor(double x)                                    /* |x| < 2^62 */
{
    const double d = (double)(long long)x;
    return d > x ? d - 1.0 : d;
}
static double m_sin(double x)                                       /* Taylor series after reduction to [-pi, pi] */
{
    double term, sum, x2;
    int k;
    x -= 2 * PI_D * m_floor((x + PI_D) / (2 * PI_D));
    x2 = x * x;
    term = sum = x;
    for (k = 1; k <= 11; ++k) { term *= -x2 / ((2.0 * k) * (2.0 * k + 1)); sum += term; }
    return sum;
}
static double m_cos(double x) { return m_sin(x + PI_D / 2); }
static double m_atan(double x)                                      /* two argument halvings, then the series */
{
    double x2, term, sum;
    int k, neg = x < 0, inv;
    if (neg) x = -x;
    inv = x > 1.0;
    if (inv) x = 1.0 / x;
    x = x / (1.0 + m_sqrt(1.0 + x * x));
    x = x / (1.0 + m_sqrt(1.0 + x * x));                            /* now x <= tan(pi/16) */
    x2 = x * x;
    term = sum = x;
    for (k = 1; k <= 10; ++k) { term *= -x2; sum += term / (2 * k + 1); }
    sum *= 4.0;
    if (inv) sum = PI_D / 2 - sum;
    return neg ? -sum : sum;
}
static double m_atan2(double y, double x)
{
    if (x > 0) return m_atan(y / x);
    if (x < 0) return y >= 0 ? m_atan(y / x) + PI_D : m_atan(y / x) - PI_D;
    return y > 0 ? PI_D / 2 : y < 0 ? -PI_D / 2 : 0.0;
}

typedef struct gpath {
    int n, cap;
    POINT *pt;                                                      /* device coordinates */
    BYTE *ty;
    int newfig;                                                     /* the next segment starts a figure at the current position */
} gpath_t;

/* ---------------------------------------------------------------- path storage */
static gpath_t *path_new(void) { gpath_t *p = gdi_alloc(sizeof *p); if (p) p->newfig = 1; return p; }

void gdi_path_free(gpath_t *p)
{
    if (!p) return;
    gdi_free(p->pt);
    gdi_free(p->ty);
    gdi_free(p);
}

gpath_t *gdi_path_copy(const gpath_t *s)
{
    gpath_t *p;
    if (!s) return 0;
    p = gdi_alloc(sizeof *p);
    if (!p) return 0;
    *p = *s;
    p->pt = gdi_alloc((size_t)(s->cap ? s->cap : 1) * sizeof(POINT));
    p->ty = gdi_alloc((size_t)(s->cap ? s->cap : 1));
    if (!p->pt || !p->ty) { gdi_free(p->pt); gdi_free(p->ty); gdi_free(p); return 0; }
    if (s->n) { memcpy(p->pt, s->pt, (size_t)s->n * sizeof(POINT)); memcpy(p->ty, s->ty, (size_t)s->n); }
    return p;
}

static int path_add(gpath_t *p, int x, int y, BYTE t)
{
    if (p->n == p->cap) {
        const int nc = p->cap ? p->cap * 2 : 32;
        POINT *np = gdi_alloc((size_t)nc * sizeof *np);
        BYTE *nt = gdi_alloc((size_t)nc);
        if (!np || !nt) { gdi_free(np); gdi_free(nt); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
        if (p->n) { memcpy(np, p->pt, (size_t)p->n * sizeof *np); memcpy(nt, p->ty, (size_t)p->n); }
        gdi_free(p->pt);
        gdi_free(p->ty);
        p->pt = np;
        p->ty = nt;
        p->cap = nc;
    }
    p->pt[p->n].x = x;
    p->pt[p->n].y = y;
    p->ty[p->n++] = t;
    return 1;
}

static void path_discard(dc_t *dc)
{
    gdi_path_free(dc->path);
    dc->path = 0;
    dc->path_open = 0;
}

/* the figure the next segment belongs to: starts one at the current position if needed */
static int path_start(dc_t *dc)
{
    gpath_t *p = dc->path;
    if (!p->newfig) return 1;
    p->newfig = 0;
    return path_add(p, dc_lx(dc, dc->pos.x), dc_ly(dc, dc->pos.y), PT_MOVETO);
}

void gdi_path_moveto(dc_t *dc) { dc->path->newfig = 1; }

BOOL gdi_path_lineto(dc_t *dc, int x, int y)
{
    return path_start(dc) && path_add(dc->path, dc_lx(dc, x), dc_ly(dc, y), PT_LINETO);
}

BOOL gdi_path_poly(dc_t *dc, const POINT *pts, int n, int closed)
{
    gpath_t *p = dc->path;
    int i;
    for (i = 0; i < n; ++i)
        if (!path_add(p, dc_lx(dc, pts[i].x), dc_ly(dc, pts[i].y), i ? PT_LINETO : PT_MOVETO)) return FALSE;
    if (closed) p->ty[p->n - 1] |= PT_CLOSEFIGURE;
    p->newfig = 1;
    return TRUE;
}

/* Rectangle/Ellipse corners: in GM_COMPATIBLE the right and bottom edges are exclusive, as the drawing functions treat them */
static void path_corners(dc_t *dc, int *r, int *b)
{
    if (dc->gfxmode == GM_COMPATIBLE) { --*r; --*b; }
}

BOOL gdi_path_rect_dev(dc_t *dc, int l, int t, int r, int b, int exact)
{
    gpath_t *p = dc->path;
    POINT q[4];
    int i;
    if (!exact) path_corners(dc, &r, &b);
    q[0].x = r; q[0].y = t; q[1].x = l; q[1].y = t; q[2].x = l; q[2].y = b; q[3].x = r; q[3].y = b;   /* counter-clockwise */
    for (i = 0; i < 4; ++i) {
        const POINT v = dc->arcdir == AD_CLOCKWISE ? q[3 - i] : q[i];
        if (!path_add(p, v.x, v.y, i ? PT_LINETO : PT_MOVETO)) return FALSE;
    }
    p->ty[p->n - 1] |= PT_CLOSEFIGURE;
    p->newfig = 1;
    return TRUE;
}

/* four cubic Beziers (control distance 0.5523 of the half axes), starting at the right end, counter-clockwise unless
 * AD_CLOCKWISE */
BOOL gdi_path_ellipse_dev(dc_t *dc, int l, int t, int r, int b)
{
    static const double k = 0.5522847498;
    gpath_t *p = dc->path;
    double cx, cy, rx, ry, pts[13][2];
    int i, cw = dc->arcdir == AD_CLOCKWISE;
    path_corners(dc, &r, &b);
    cx = (l + r) / 2.0; cy = (t + b) / 2.0; rx = (r - l) / 2.0; ry = (b - t) / 2.0;
    {
        const double base[13][2] = {
            { 1, 0 }, { 1, -k }, { k, -1 }, { 0, -1 }, { -k, -1 }, { -1, -k }, { -1, 0 },
            { -1, k }, { -k, 1 }, { 0, 1 }, { k, 1 }, { 1, k }, { 1, 0 } };
        for (i = 0; i < 13; ++i) { pts[i][0] = cx + base[i][0] * rx; pts[i][1] = cy + (cw ? -base[i][1] : base[i][1]) * ry; }
    }
    for (i = 0; i < 13; ++i)
        if (!path_add(p, (int)(pts[i][0] + (pts[i][0] < 0 ? -0.5 : 0.5)), (int)(pts[i][1] + (pts[i][1] < 0 ? -0.5 : 0.5)),
                      i ? PT_BEZIERTO : PT_MOVETO)) return FALSE;
    p->ty[p->n - 1] |= PT_CLOSEFIGURE;
    p->newfig = 1;
    return TRUE;
}

/* ---------------------------------------------------------------- flattening and figures */
static int bez_steps(POINT a, POINT b, POINT c, POINT d)
{
    const double len = m_sqrt((double)(b.x - a.x) * (b.x - a.x) + (double)(b.y - a.y) * (b.y - a.y)) +
                       m_sqrt((double)(c.x - b.x) * (c.x - b.x) + (double)(c.y - b.y) * (c.y - b.y)) +
                       m_sqrt((double)(d.x - c.x) * (d.x - c.x) + (double)(d.y - c.y) * (d.y - c.y));
    const int n = (int)(len / 2.0) + 1;
    return n > 512 ? 512 : n;
}

static int add_bezier(gpath_t *o, POINT a, POINT b, POINT c, POINT d, BYTE last_type)
{
    const int n = bez_steps(a, b, c, d);
    int i;
    for (i = 1; i <= n; ++i) {
        const double t = (double)i / n, u = 1 - t;
        const double x = u * u * u * a.x + 3 * u * u * t * b.x + 3 * u * t * t * c.x + t * t * t * d.x;
        const double y = u * u * u * a.y + 3 * u * u * t * b.y + 3 * u * t * t * c.y + t * t * t * d.y;
        int xi = (int)m_floor(x + 0.5), yi = (int)m_floor(y + 0.5);
        if (i == n) { xi = d.x; yi = d.y; }
        if (!path_add(o, xi, yi, i == n ? last_type : PT_LINETO)) return 0;
    }
    return 1;
}

/* a copy of `p` with every Bezier replaced by line segments */
static gpath_t *path_flat(const gpath_t *p)
{
    gpath_t *o = path_new();
    int i;
    if (!o) return 0;
    for (i = 0; i < p->n; ++i) {
        const BYTE t = p->ty[i] & ~PT_CLOSEFIGURE;
        if (t == PT_BEZIERTO && i > 0 && i + 2 < p->n) {
            if (!add_bezier(o, p->pt[i - 1], p->pt[i], p->pt[i + 1], p->pt[i + 2], (BYTE)(PT_LINETO | (p->ty[i + 2] & PT_CLOSEFIGURE)))) {
                gdi_path_free(o);
                return 0;
            }
            i += 2;
        } else if (!path_add(o, p->pt[i].x, p->pt[i].y, p->ty[i])) {
            gdi_path_free(o);
            return 0;
        }
    }
    o->newfig = p->newfig;
    return o;
}

typedef struct { const POINT *pt; int n; int closed; } fig_t;

/* splits a flat path into figures; returns how many (the array is gdi_alloc'ed) */
static int path_figures(const gpath_t *f, fig_t **out)
{
    fig_t *figs;
    int i, nf = 0;
    *out = 0;
    figs = gdi_alloc((size_t)(f->n ? f->n : 1) * sizeof *figs);
    if (!figs) return -1;
    for (i = 0; i < f->n; ++i) {
        if ((f->ty[i] & ~PT_CLOSEFIGURE) == PT_MOVETO || nf == 0) {
            figs[nf].pt = &f->pt[i];
            figs[nf].n = 0;
            figs[nf].closed = 0;
            ++nf;
        }
        ++figs[nf - 1].n;
        if (f->ty[i] & PT_CLOSEFIGURE) figs[nf - 1].closed = 1;
    }
    *out = figs;
    return nf;
}

/* fill the area of a flat path (all figures closed) through `fn` */
static int fill_flat(gctx_t *g, const gpath_t *f, int winding, gdi_span_fn fn, void *ctx)
{
    fig_t *figs;
    int nf = path_figures(f, &figs), i, *counts, total = 0;
    POINT *pts;
    if (nf < 0) return 0;
    counts = gdi_alloc((size_t)(nf ? nf : 1) * sizeof *counts);
    pts = gdi_alloc((size_t)(f->n ? f->n : 1) * sizeof *pts);
    if (!counts || !pts) { gdi_free(figs); gdi_free(counts); gdi_free(pts); return 0; }
    for (i = 0; i < nf; ++i) {
        memcpy(pts + total, figs[i].pt, (size_t)figs[i].n * sizeof *pts);
        counts[i] = figs[i].n;
        total += figs[i].n;
    }
    if (total >= 3) gdi_poly_fill(g, pts, counts, nf, winding, fn, ctx);
    gdi_free(figs);
    gdi_free(counts);
    gdi_free(pts);
    return 1;
}

static void stroke_flat(gctx_t *g, const gpath_t *f)
{
    fig_t *figs;
    int nf = path_figures(f, &figs), i, k;
    if (nf < 0) return;
    for (i = 0; i < nf; ++i) {
        const fig_t *fg = &figs[i];
        if (fg->n == 1) continue;
        for (k = 0; k + 1 < fg->n; ++k)
            gdi_line(g, fg->pt[k].x, fg->pt[k].y, fg->pt[k + 1].x, fg->pt[k + 1].y, !fg->closed && k + 2 == fg->n);
        if (fg->closed) gdi_line(g, fg->pt[fg->n - 1].x, fg->pt[fg->n - 1].y, fg->pt[0].x, fg->pt[0].y, 0);
    }
    gdi_free(figs);
}

/* the closed path of a DC for FillPath & co: NULL (with the error set) unless a path exists and EndPath closed it */
static gpath_t *closed_path(dc_t *dc)
{
    if (!dc->path || dc->path_open) { SetLastError(ERROR_CAN_NOT_COMPLETE); return 0; }
    return dc->path;
}

/* ---------------------------------------------------------------- path API */
DLLAPI BOOL WINAPI BeginPath(HDC hdc)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    path_discard(dc);
    dc->path = path_new();
    if (!dc->path) RET(FALSE);
    dc->path_open = 1;
    RET(TRUE);
}

DLLAPI BOOL WINAPI EndPath(HDC hdc)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (!gdi_path_recording(dc)) { SetLastError(ERROR_CAN_NOT_COMPLETE); RET(FALSE); }
    dc->path_open = 0;
    RET(TRUE);
}

DLLAPI BOOL WINAPI AbortPath(HDC hdc)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    path_discard(dc);
    RET(TRUE);
}

DLLAPI BOOL WINAPI CloseFigure(HDC hdc)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (!gdi_path_recording(dc)) { SetLastError(ERROR_CAN_NOT_COMPLETE); RET(FALSE); }
    if (dc->path->n && !dc->path->newfig) {
        dc->path->ty[dc->path->n - 1] |= PT_CLOSEFIGURE;
        dc->path->newfig = 1;
    }
    RET(TRUE);
}

static BOOL poly_bezier(HDC hdc, const POINT *pts, DWORD n, int to)
{
    dc_t *dc;
    gpath_t *p, tmp;
    DWORD i;
    if (!pts || (to ? n % 3 != 0 : (n < 4 || (n - 1) % 3 != 0))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (gdi_path_recording(dc)) {
        p = dc->path;
        if (to) { if (!path_start(dc)) RET(FALSE); }
        else p->newfig = 0;
        for (i = 0; i < n; ++i)
            if (!path_add(p, dc_lx(dc, pts[i].x), dc_ly(dc, pts[i].y), !to && i == 0 ? PT_MOVETO : PT_BEZIERTO)) RET(FALSE);
    } else {
        gctx_t g;
        gpath_t *flat;
        memset(&tmp, 0, sizeof tmp);
        if (to && !path_add(&tmp, dc_lx(dc, dc->pos.x), dc_ly(dc, dc->pos.y), PT_MOVETO)) RET(FALSE);
        for (i = 0; i < n; ++i)
            if (!path_add(&tmp, dc_lx(dc, pts[i].x), dc_ly(dc, pts[i].y), !to && i == 0 ? PT_MOVETO : PT_BEZIERTO)) {
                gdi_free(tmp.pt); gdi_free(tmp.ty); RET(FALSE);
            }
        flat = path_flat(&tmp);
        gdi_free(tmp.pt);
        gdi_free(tmp.ty);
        if (!flat) RET(FALSE);
        if (gctx_begin(&g, dc)) { stroke_flat(&g, flat); gctx_end(&g); }
        gdi_path_free(flat);
    }
    if (to) dc->pos = pts[n - 1];
    RET(TRUE);
}

DLLAPI BOOL WINAPI PolyBezier(HDC hdc, const POINT *pts, DWORD n) { return poly_bezier(hdc, pts, n, 0); }
DLLAPI BOOL WINAPI PolyBezierTo(HDC hdc, const POINT *pts, DWORD n) { return poly_bezier(hdc, pts, n, 1); }

DLLAPI BOOL WINAPI PolylineTo(HDC hdc, const POINT *pts, DWORD n)
{
    DWORD i;
    if (!pts) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < n; ++i)
        if (!LineTo(hdc, pts[i].x, pts[i].y)) return FALSE;
    return TRUE;
}

DLLAPI BOOL WINAPI FlattenPath(HDC hdc)
{
    dc_t *dc;
    gpath_t *p, *f;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (!(p = closed_path(dc))) RET(FALSE);
    if (!(f = path_flat(p))) RET(FALSE);
    gdi_path_free(p);
    dc->path = f;
    RET(TRUE);
}

/* GetPath: logical coordinates (device minus the DC offsets) */
DLLAPI int WINAPI GetPath(HDC hdc, LPPOINT pts, LPBYTE types, int n)
{
    dc_t *dc;
    gpath_t *p;
    int i;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(-1); }
    if (!(p = closed_path(dc))) RET(-1);
    if (n == 0) RET(p->n);
    if (n < p->n || !pts || !types) { SetLastError(ERROR_INVALID_PARAMETER); RET(-1); }
    for (i = 0; i < p->n; ++i) {
        pts[i].x = p->pt[i].x - dc_ox(dc);
        pts[i].y = p->pt[i].y - dc_oy(dc);
        types[i] = p->ty[i];
    }
    RET(p->n);
}

static BOOL fill_stroke(HDC hdc, int fill, int stroke)
{
    dc_t *dc;
    gpath_t *p, *f;
    gctx_t g;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (!(p = closed_path(dc))) RET(FALSE);
    if (!(f = path_flat(p))) RET(FALSE);
    if (gctx_begin(&g, dc)) {
        if (fill && g.bkind) fill_flat(&g, f, dc->polyfill == WINDING, gdi_span_brush, 0);
        if (stroke && !g.pnull) stroke_flat(&g, f);
        gctx_end(&g);
    }
    gdi_path_free(f);
    path_discard(dc);
    RET(TRUE);
}

DLLAPI BOOL WINAPI FillPath(HDC hdc) { return fill_stroke(hdc, 1, 0); }
DLLAPI BOOL WINAPI StrokePath(HDC hdc) { return fill_stroke(hdc, 0, 1); }
DLLAPI BOOL WINAPI StrokeAndFillPath(HDC hdc) { return fill_stroke(hdc, 1, 1); }

/* area of a closed flat path as disjoint rectangles (device coordinates): one per span of each row, then coalesced */
static void span_rgn(gctx_t *g, int x0, int x1, int y, void *ctx)
{
    RECT r;
    (void)g;
    if (x0 >= x1) return;
    r.left = x0; r.right = x1; r.top = y; r.bottom = y + 1;
    rl_add_rect(ctx, &r);
}

static int path_to_rects(dc_t *dc, rlist_t *out)
{
    gpath_t *p = closed_path(dc), *f;
    if (!p || !(f = path_flat(p))) return 0;
    if (!fill_flat(0, f, dc->polyfill == WINDING, span_rgn, out)) { gdi_path_free(f); return 0; }
    gdi_path_free(f);
    rl_coalesce(out);
    return 1;
}

DLLAPI HRGN WINAPI PathToRegion(HDC hdc)
{
    dc_t *dc;
    rlist_t rl;
    HRGN h;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    rl_init(&rl);
    if (!path_to_rects(dc, &rl)) { rl_free(&rl); RET(0); }
    path_discard(dc);
    h = CreateRectRgn(0, 0, 0, 0);                                  /* region coordinates are device units */
    if (h) ShzGdiRegionSetRects(h, rl.r, rl.n);
    rl_free(&rl);
    RET(h);
}

DLLAPI BOOL WINAPI SelectClipPath(HDC hdc, int mode)
{
    dc_t *dc;
    rlist_t rl;
    HRGN h, cur;
    int ok;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (mode < RGN_AND || mode > RGN_COPY) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    rl_init(&rl);
    if (!path_to_rects(dc, &rl)) { rl_free(&rl); RET(FALSE); }
    path_discard(dc);
    h = CreateRectRgn(0, 0, 0, 0);
    cur = CreateRectRgn(0, 0, 0, 0);
    ok = h && cur && ShzGdiRegionSetRects(h, rl.r, rl.n);
    rl_free(&rl);
    if (ok) OffsetRgn(h, -dc->dev_org.x, -dc->dev_org.y);             /* clip regions are in device units from the DC origin */
    if (ok && mode != RGN_COPY) {
        const int big = 1 << 28;
        if (GetClipRgn(hdc, cur) != 1) SetRectRgn(cur, -big, -big, big, big);   /* no clip region: the whole surface */
        ok = CombineRgn(cur, cur, h, mode) != ERROR;
        { HRGN t = h; h = cur; cur = t; }
    }
    if (ok) ok = SelectClipRgn(hdc, h) != ERROR;
    if (h) DeleteObject(h);
    if (cur) DeleteObject(cur);
    RET(ok);
}

/* ---------------------------------------------------------------- WidenPath */
typedef struct { double x, y; } dpt_t;

static int out_pt(gpath_t *o, dpt_t p, BYTE t) { return path_add(o, (int)m_floor(p.x + 0.5), (int)m_floor(p.y + 0.5), t); }

/* arc of radius h around c from angle a0 to a1 (radians, the sweep direction given by the sign of a1 - a0) */
static int out_arc(gpath_t *o, dpt_t c, double h, double a0, double a1)
{
    const double sweep = a1 - a0;
    int n = (int)(m_fabs(sweep) * h / 2.0) + 1, i;
    if (n > 64) n = 64;
    for (i = 1; i < n; ++i) {
        const double a = a0 + sweep * i / n;
        dpt_t p;
        p.x = c.x + h * m_cos(a);
        p.y = c.y + h * m_sin(a);
        if (!out_pt(o, p, PT_LINETO)) return 0;
    }
    return 1;
}

typedef struct { int cap, join; double h, miter; } pen_geo_t;

/* one side of a polyline, offset by +h along the left normal (y down: (dy, -dx) turned so that walking forward it is on
 * the left), with the joins at the interior vertices; `closed` also joins the last segment to the first */
static int out_side(gpath_t *o, const dpt_t *v, int n, int closed, const pen_geo_t *pg, int first_type)
{
    int i, nseg = closed ? n : n - 1;
    BYTE t = (BYTE)first_type;
    for (i = 0; i < nseg; ++i) {
        const dpt_t a = v[i], b = v[(i + 1) % n];
        const double dx = b.x - a.x, dy = b.y - a.y, len = m_sqrt(dx * dx + dy * dy);
        const double nx = dy / len * pg->h, ny = -dx / len * pg->h;
        dpt_t p0, p1;
        p0.x = a.x + nx; p0.y = a.y + ny;
        p1.x = b.x + nx; p1.y = b.y + ny;
        if (!out_pt(o, p0, t)) return 0;
        t = PT_LINETO;
        if (!out_pt(o, p1, PT_LINETO)) return 0;
        if (i + 1 < nseg || closed) {                               /* join at b with the next segment */
            const dpt_t c = v[(i + 2) % n];
            const double ex = c.x - b.x, ey = c.y - b.y, elen = m_sqrt(ex * ex + ey * ey);
            const double mx = ey / elen * pg->h, my = -ex / elen * pg->h;
            const double cross = dx * ey - dy * ex;                     /* > 0: a right turn (y down), this side is outside */
            const double a0 = m_atan2(ny, nx), a1 = m_atan2(my, mx);
            double sweep = a1 - a0;
            while (sweep > PI_D) sweep -= 2 * PI_D;
            while (sweep < -PI_D) sweep += 2 * PI_D;
            if (cross > 0) {
                if (pg->join == PS_JOIN_ROUND) { if (!out_arc(o, b, pg->h, a0, a0 + sweep)) return 0; }
                else if (pg->join == PS_JOIN_MITER) {
                    const double half = m_fabs(sweep) / 2, ml = 1.0 / m_cos(half);
                    if (ml <= pg->miter) {
                        const double am = a0 + sweep / 2;
                        dpt_t m;
                        m.x = b.x + pg->h * ml * m_cos(am);
                        m.y = b.y + pg->h * ml * m_sin(am);
                        if (!out_pt(o, m, PT_LINETO)) return 0;
                    }
                }
            } else {
                dpt_t mid = b;                                          /* inner side: through the vertex (the outline crosses itself) */
                if (!out_pt(o, mid, PT_LINETO)) return 0;
            }
        }
    }
    return 1;
}

static int out_cap(gpath_t *o, dpt_t end, dpt_t dir, const pen_geo_t *pg)
{
    /* from end + h*left to end - h*left, around the end in the direction `dir` (unit) */
    const double lx = dir.y * pg->h, ly = -dir.x * pg->h;
    if (pg->cap == PS_ENDCAP_ROUND) return out_arc(o, end, pg->h, m_atan2(ly, lx), m_atan2(ly, lx) + PI_D);   /* through `dir` */
    if (pg->cap == PS_ENDCAP_SQUARE) {
        dpt_t a, b;
        a.x = end.x + lx + dir.x * pg->h; a.y = end.y + ly + dir.y * pg->h;
        b.x = end.x - lx + dir.x * pg->h; b.y = end.y - ly + dir.y * pg->h;
        return out_pt(o, a, PT_LINETO) && out_pt(o, b, PT_LINETO);
    }
    return 1;
}

static int widen_figure(gpath_t *o, const POINT *pt, int n, int closed, const pen_geo_t *pg)
{
    dpt_t *v = gdi_alloc((size_t)n * sizeof *v), *r = gdi_alloc((size_t)n * sizeof *r);
    int m = 0, i, ok = 1;
    if (!v || !r) { gdi_free(v); gdi_free(r); return 0; }
    for (i = 0; i < n; ++i)                                           /* drop repeated points */
        if (!m || pt[i].x != (int)v[m - 1].x || pt[i].y != (int)v[m - 1].y) { v[m].x = pt[i].x; v[m].y = pt[i].y; ++m; }
    if (closed && m > 1 && v[0].x == v[m - 1].x && v[0].y == v[m - 1].y) --m;
    for (i = 0; i < m; ++i) r[i] = v[m - 1 - i];
    if (m == 1) {                                                     /* a dot: round caps make a disc, square ones a square */
        if (pg->cap == PS_ENDCAP_ROUND) {
            dpt_t s;
            s.x = v[0].x + pg->h; s.y = v[0].y;
            ok = out_pt(o, s, PT_MOVETO) && out_arc(o, v[0], pg->h, 0, 2 * PI_D);
            if (ok) o->ty[o->n - 1] |= PT_CLOSEFIGURE;
        } else if (pg->cap == PS_ENDCAP_SQUARE) {
            const int h = (int)pg->h;
            ok = path_add(o, (int)v[0].x - h, (int)v[0].y - h, PT_MOVETO) && path_add(o, (int)v[0].x + h, (int)v[0].y - h, PT_LINETO) &&
                 path_add(o, (int)v[0].x + h, (int)v[0].y + h, PT_LINETO) && path_add(o, (int)v[0].x - h, (int)v[0].y + h, PT_LINETO | PT_CLOSEFIGURE);
        }
    } else if (m >= 2 && closed && m >= 3) {                          /* two loops: the left side forwards, the right side backwards */
        ok = out_side(o, v, m, 1, pg, PT_MOVETO);
        if (ok) o->ty[o->n - 1] |= PT_CLOSEFIGURE;
        ok = ok && out_side(o, r, m, 1, pg, PT_MOVETO);
        if (ok) o->ty[o->n - 1] |= PT_CLOSEFIGURE;
    } else if (m >= 2) {                                              /* one loop: left side, end cap, right side back, start cap */
        dpt_t d_end, d_start;
        double l;
        d_end.x = v[m - 1].x - v[m - 2].x; d_end.y = v[m - 1].y - v[m - 2].y;
        l = m_sqrt(d_end.x * d_end.x + d_end.y * d_end.y); d_end.x /= l; d_end.y /= l;
        d_start.x = v[0].x - v[1].x; d_start.y = v[0].y - v[1].y;
        l = m_sqrt(d_start.x * d_start.x + d_start.y * d_start.y); d_start.x /= l; d_start.y /= l;
        ok = out_side(o, v, m, 0, pg, PT_MOVETO) && out_cap(o, v[m - 1], d_end, pg) &&
             out_side(o, r, m, 0, pg, PT_LINETO) && out_cap(o, v[0], d_start, pg);
        if (ok) o->ty[o->n - 1] |= PT_CLOSEFIGURE;
    }
    gdi_free(v);
    gdi_free(r);
    return ok;
}

DLLAPI BOOL WINAPI WidenPath(HDC hdc)
{
    dc_t *dc;
    gpath_t *p, *f, *o;
    fig_t *figs;
    pen_t *pen;
    pen_geo_t pg;
    int nf, i, ok = 1, width;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (!(p = closed_path(dc))) RET(FALSE);
    pen = gdi_obj_get((HGDIOBJ)dc->pen, OBJ_PEN, 0);
    if (!pen) { SetLastError(ERROR_CAN_NOT_COMPLETE); RET(FALSE); }
    if (pen->ext && (pen->ext_style & PS_TYPE_MASK) == PS_COSMETIC) { SetLastError(ERROR_CAN_NOT_COMPLETE); RET(FALSE); }
    width = pen->lp.lopnWidth.x > 0 ? pen->lp.lopnWidth.x : 1;
    pg.h = width / 2.0;
    pg.cap = pen->ext ? (int)(pen->ext_style & PS_ENDCAP_MASK) : PS_ENDCAP_ROUND;
    pg.join = pen->ext ? (int)(pen->ext_style & PS_JOIN_MASK) : PS_JOIN_ROUND;
    pg.miter = dc->miter;
    if (!(f = path_flat(p))) RET(FALSE);
    o = path_new();
    nf = path_figures(f, &figs);
    if (!o || nf < 0) { gdi_path_free(f); gdi_path_free(o); RET(FALSE); }
    for (i = 0; i < nf && ok; ++i) ok = widen_figure(o, figs[i].pt, figs[i].n, figs[i].closed, &pg);
    gdi_free(figs);
    gdi_path_free(f);
    if (!ok) { gdi_path_free(o); RET(FALSE); }
    gdi_path_free(dc->path);
    dc->path = o;
    RET(TRUE);
}

/* ---------------------------------------------------------------- state: miter limit, arc direction */
DLLAPI BOOL WINAPI SetMiterLimit(HDC hdc, FLOAT limit, PFLOAT old)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (!(limit >= 1.0f)) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    if (old) *old = dc->miter;
    dc->miter = limit;
    RET(TRUE);
}

DLLAPI BOOL WINAPI GetMiterLimit(HDC hdc, PFLOAT out)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (out) *out = dc->miter;
    RET(TRUE);
}

DLLAPI int WINAPI SetArcDirection(HDC hdc, int dir)
{
    dc_t *dc;
    int old;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    if (dir != AD_COUNTERCLOCKWISE && dir != AD_CLOCKWISE) { SetLastError(ERROR_INVALID_PARAMETER); RET(0); }
    old = dc->arcdir;
    dc->arcdir = dir;
    RET(old);
}

DLLAPI int WINAPI GetArcDirection(HDC hdc)
{
    dc_t *dc;
    int v;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    v = dc ? dc->arcdir : 0;
    RET(v);
}

/* ---------------------------------------------------------------- world transform */
static int xf_is_translation(const XFORM *x) { return x->eM11 == 1.0f && x->eM22 == 1.0f && x->eM12 == 0.0f && x->eM21 == 0.0f; }

static int xf_apply(dc_t *dc, const XFORM *x)
{
    if (!xf_is_translation(x)) { SetLastError(ERROR_NOT_SUPPORTED); return 0; }
    dc->xf = *x;
    dc->xf_dx = (int)m_floor((double)x->eDx + 0.5);
    dc->xf_dy = (int)m_floor((double)x->eDy + 0.5);
    dc->eff_valid = 0;
    return 1;
}

DLLAPI BOOL WINAPI CombineTransform(LPXFORM out, const XFORM *a, const XFORM *b)
{
    XFORM r;
    if (!out || !a || !b) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    r.eM11 = a->eM11 * b->eM11 + a->eM12 * b->eM21;                    /* a then b */
    r.eM12 = a->eM11 * b->eM12 + a->eM12 * b->eM22;
    r.eM21 = a->eM21 * b->eM11 + a->eM22 * b->eM21;
    r.eM22 = a->eM21 * b->eM12 + a->eM22 * b->eM22;
    r.eDx = a->eDx * b->eM11 + a->eDy * b->eM21 + b->eDx;
    r.eDy = a->eDx * b->eM12 + a->eDy * b->eM22 + b->eDy;
    *out = r;
    return TRUE;
}

DLLAPI BOOL WINAPI SetWorldTransform(HDC hdc, const XFORM *x)
{
    dc_t *dc;
    BOOL ok;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (!x || dc->gfxmode != GM_ADVANCED) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    ok = xf_apply(dc, x);
    RET(ok);
}

DLLAPI BOOL WINAPI GetWorldTransform(HDC hdc, LPXFORM x)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (!x) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    *x = dc->xf;
    RET(TRUE);
}

DLLAPI BOOL WINAPI ModifyWorldTransform(HDC hdc, const XFORM *x, DWORD mode)
{
    static const XFORM ident = { 1.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f };
    dc_t *dc;
    XFORM r;
    BOOL ok;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (dc->gfxmode != GM_ADVANCED) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    switch (mode) {
    case MWT_IDENTITY: r = ident; break;
    case MWT_LEFTMULTIPLY: if (!x) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); } CombineTransform(&r, x, &dc->xf); break;
    case MWT_RIGHTMULTIPLY: if (!x) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); } CombineTransform(&r, &dc->xf, x); break;
    default: SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE);
    }
    ok = xf_apply(dc, &r);
    RET(ok);
}

DLLAPI int WINAPI GetGraphicsMode(HDC hdc)
{
    dc_t *dc;
    int v;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    v = dc ? dc->gfxmode : 0;
    RET(v);
}

/* ---------------------------------------------------------------- pixel formats */
#define PF_WINDOWS 64
static struct { HWND hwnd; int fmt; } g_pf[PF_WINDOWS];

static void describe(PIXELFORMATDESCRIPTOR *p)
{
    memset(p, 0, sizeof *p);
    p->nSize = sizeof *p;
    p->nVersion = 1;
    p->dwFlags = PFD_DRAW_TO_WINDOW | PFD_DRAW_TO_BITMAP | PFD_SUPPORT_GDI | PFD_GENERIC_FORMAT;
    p->iPixelType = PFD_TYPE_RGBA;
    p->cColorBits = 32;
    p->cRedBits = 8; p->cRedShift = 16;
    p->cGreenBits = 8; p->cGreenShift = 8;
    p->cBlueBits = 8; p->cBlueShift = 0;
    p->iLayerType = PFD_MAIN_PLANE;
}

static int pf_slot(HWND hwnd, int create)
{
    int i, free_i = -1;
    for (i = 0; i < PF_WINDOWS; ++i) {
        if (g_pf[i].hwnd == hwnd) return i;
        if (!g_pf[i].hwnd && free_i < 0) free_i = i;
    }
    if (!create || free_i < 0) return -1;
    g_pf[free_i].hwnd = hwnd;
    g_pf[free_i].fmt = 0;
    return free_i;
}

BOOL gdi_window_pixel_format_forget(HWND hwnd)
{
    const int i = pf_slot(hwnd, 0);
    if (i < 0) return FALSE;
    g_pf[i].hwnd = 0;
    return TRUE;
}

DLLAPI int WINAPI DescribePixelFormat(HDC hdc, int fmt, UINT n, LPPIXELFORMATDESCRIPTOR pfd)
{
    GDI_ENTER();
    if (!gdi_dc_get(hdc)) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    if (pfd) {
        if (fmt != 1 || n < sizeof *pfd) { SetLastError(ERROR_INVALID_PARAMETER); RET(0); }
        describe(pfd);
    }
    RET(1);                                                         /* the number of formats */
}

DLLAPI int WINAPI ChoosePixelFormat(HDC hdc, const PIXELFORMATDESCRIPTOR *pfd)
{
    GDI_ENTER();
    if (!gdi_dc_get(hdc)) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    if (!pfd || pfd->nSize != sizeof *pfd) { SetLastError(ERROR_INVALID_PARAMETER); RET(0); }
    RET(1);                                                         /* the closest (the only) format */
}

DLLAPI int WINAPI GetPixelFormat(HDC hdc)
{
    dc_t *dc;
    int v = 0, i;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    if (dc->hwnd) { i = pf_slot(dc->hwnd, 0); v = i >= 0 ? g_pf[i].fmt : 0; }
    else v = dc->pixfmt;
    if (!v) SetLastError(ERROR_INVALID_PIXEL_FORMAT);
    RET(v);
}

DLLAPI BOOL WINAPI SetPixelFormat(HDC hdc, int fmt, const PIXELFORMATDESCRIPTOR *pfd)
{
    dc_t *dc;
    int i;
    (void)pfd;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (fmt != 1) { SetLastError(ERROR_INVALID_PIXEL_FORMAT); RET(FALSE); }
    if (!dc->hwnd) { dc->pixfmt = fmt; RET(TRUE); }
    i = pf_slot(dc->hwnd, 1);
    if (i < 0) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); RET(FALSE); }
    if (g_pf[i].fmt && g_pf[i].fmt != fmt) { SetLastError(ERROR_INVALID_PIXEL_FORMAT); RET(FALSE); }   /* set once per window */
    g_pf[i].fmt = fmt;
    RET(TRUE);
}

DLLAPI BOOL WINAPI SwapBuffers(HDC hdc)
{
    dc_t *dc;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (dc->hwnd ? pf_slot(dc->hwnd, 0) < 0 || !g_pf[pf_slot(dc->hwnd, 0)].fmt : !dc->pixfmt) {
        SetLastError(ERROR_INVALID_PIXEL_FORMAT);
        RET(FALSE);
    }
    if (dc->hwnd) gdi_window_dc_flush(dc);                           /* single buffered: present what was drawn */
    RET(TRUE);
}

/* ---------------------------------------------------------------- printing entry points, escapes, colour profiles */
DLLAPI int WINAPI StartDocW(HDC hdc, const DOCINFOW *di)
{
    (void)di;
    SetLastError(gdi_dc_get(hdc) ? ERROR_NOT_SUPPORTED : ERROR_INVALID_HANDLE);   /* no DC here is a printer DC */
    return SP_ERROR;
}
DLLAPI int WINAPI StartDocA(HDC hdc, const DOCINFOA *di) { (void)di; return StartDocW(hdc, 0); }
DLLAPI int WINAPI EndDoc(HDC hdc) { return StartDocW(hdc, 0); }
DLLAPI int WINAPI StartPage(HDC hdc) { return StartDocW(hdc, 0); }
DLLAPI int WINAPI EndPage(HDC hdc) { return StartDocW(hdc, 0); }
DLLAPI int WINAPI AbortDoc(HDC hdc) { return StartDocW(hdc, 0); }
DLLAPI int WINAPI SetAbortProc(HDC hdc, ABORTPROC proc) { (void)proc; return StartDocW(hdc, 0); }

DLLAPI BOOL WINAPI CancelDC(HDC hdc)
{
    BOOL ok;
    GDI_ENTER();
    ok = gdi_dc_get(hdc) != 0;                                        /* nothing is ever pending */
    if (!ok) SetLastError(ERROR_INVALID_HANDLE);
    RET(ok);
}

DLLAPI int WINAPI ExtEscape(HDC hdc, int esc, int cbin, LPCSTR in, int cbout, LPSTR out)
{
    (void)esc; (void)cbin; (void)in; (void)cbout; (void)out;
    GDI_ENTER();
    if (!gdi_dc_get(hdc)) { SetLastError(ERROR_INVALID_HANDLE); RET(-1); }
    RET(0);                                                           /* QUERYESCSUPPORT included: no escape is implemented */
}

DLLAPI BOOL WINAPI GetICMProfileW(HDC hdc, LPDWORD size, LPWSTR name)
{
    (void)size; (void)name;
    GDI_ENTER();
    if (!gdi_dc_get(hdc)) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    SetLastError(ERROR_FILE_NOT_FOUND);                               /* no colour profile is installed */
    RET(FALSE);
}
