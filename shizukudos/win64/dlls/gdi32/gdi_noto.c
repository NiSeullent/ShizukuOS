/* SPDX-License-Identifier: GPL-2.0-only
 * gdi32 <-> Noto provider adapter core; see gdi_noto.h. Portable C: compiled into gdi32.dll and the host controls. */
#include <string.h>
#include "gdi_noto.h"

static int64_t ceil26(int64_t v) { return (v + 63) >> 6; }

void gdi_noto_init(GdiNoto *g, GdiNotoOpenFn open, void *ctx, uint64_t (*now_ms)(void))
{
    unsigned char *z = (unsigned char *)g; size_t i;
    for (i = 0; i < sizeof *g; ++i) z[i] = 0;
    g->open = open; g->open_ctx = ctx; g->now_ms = now_ms; g->st = NOTO_E_UNAVAILABLE;
}

NotoProvider *gdi_noto_get(GdiNoto *g, NotoStatus *st)
{
    NotoProvider *p = NULL; NotoStatus s;
    if (!g || !g->open) { if (st) *st = NOTO_E_UNAVAILABLE; return NULL; }
    if (g->p) { if (st) *st = NOTO_OK; return g->p; }
    if (g->tried) {                                  /* a failure is reported again; UNAVAILABLE may be retried later */
        if (g->st != NOTO_E_UNAVAILABLE || !g->now_ms || g->now_ms() < g->retry_at) { if (st) *st = g->st; return NULL; }
    }
    g->tried = 1;
    s = g->open(g->open_ctx, &p);
    if (s == NOTO_OK && !p) s = NOTO_E_UNAVAILABLE;  /* an opener that reports OK without a provider is a failure */
    if (s != NOTO_OK) {
        if (p) noto_destroy(p);
        g->p = NULL; g->st = s; ++g->open_failures;
        if (g->now_ms) g->retry_at = g->now_ms() + GDI_NOTO_RETRY_MS;
        if (st) *st = s;
        return NULL;
    }
    g->p = p; g->st = NOTO_OK; ++g->opens;
    if (st) *st = NOTO_OK;
    return p;
}

NotoStatus gdi_noto_release(GdiNoto *g)
{
    NotoStatus s;
    if (!g) return NOTO_E_PARAM;
    if (!g->p) { g->tried = 0; g->st = NOTO_E_UNAVAILABLE; return NOTO_OK; }
    s = noto_destroy(g->p);
    if (s != NOTO_OK) return s;
    g->p = NULL; g->tried = 0; g->st = NOTO_E_UNAVAILABLE; g->retry_at = 0;
    return NOTO_OK;
}

static NotoStatus cell_height(NotoProvider *p, int px, int *h)
{
    NotoMetrics m; NotoStatus st = noto_metrics_px(p, px, &m);
    if (st != NOTO_OK) return st;
    *h = (int)ceil26(m.height);
    return NOTO_OK;
}

NotoStatus gdi_noto_resolve_px(NotoProvider *p, int lf_height, int *px)
{
    int h, est, ch;
    NotoStatus st;
    if (!p || !px) return NOTO_E_PARAM;
    if (lf_height < 0) {
        if (lf_height == INT32_MIN || -lf_height > NOTO_MAX_PIXELS) return NOTO_E_RANGE;
        *px = -lf_height;
        return NOTO_OK;
    }
    h = lf_height ? lf_height : 16;
    if (h > 4096) return NOTO_E_RANGE;
    est = (int)(((int64_t)h * 1000 + 681) / 1362);
    if (est < 1) est = 1;
    if (est > NOTO_MAX_PIXELS) est = NOTO_MAX_PIXELS;
    for (;;) {                                       /* largest px whose cell height <= h (smallest px if none) */
        if ((st = cell_height(p, est, &ch)) != NOTO_OK) return st;
        if (ch > h && est > 1) --est; else break;
    }
    while (est < NOTO_MAX_PIXELS) {
        if ((st = cell_height(p, est + 1, &ch)) != NOTO_OK) return st;
        if (ch > h) break;
        ++est;
    }
    if ((st = cell_height(p, est, &ch)) != NOTO_OK) return st;
    if (ch < h && est == NOTO_MAX_PIXELS && h > ch + 1) return NOTO_E_RANGE;
    *px = est;
    return NOTO_OK;
}

NotoStatus gdi_noto_text_metrics(NotoProvider *p, int px, GdiNotoTM *tm)
{
    NotoMetrics m; NotoStatus st; uint32_t c; int64_t sum = 0; int64_t mx = 0;
    if (!p || !tm) return NOTO_E_PARAM;
    if ((st = noto_metrics_px(p, px, &m)) != NOTO_OK) return st;
    tm->ascent = (int)ceil26(m.ascent);
    tm->height = (int)ceil26(m.height);
    tm->descent = tm->height - tm->ascent;
    if (tm->descent < 0) tm->descent = 0;
    tm->internal_leading = tm->height > px ? tm->height - px : 0;
    for (c = 'a'; c <= 'z'; ++c) {
        NotoGlyph g;
        if ((st = noto_glyph_px(p, c, px, &g)) != NOTO_OK) return st;
        sum += g.advance;
    }
    tm->avg_width = (int)((sum / 26 + 32) >> 6);
    if (tm->avg_width < 1) tm->avg_width = 1;
    for (c = 0x20; c <= 0x7e; ++c) {                 /* printable ASCII plus the widest common Hangul syllable */
        NotoGlyph g;
        if ((st = noto_glyph_px(p, c, px, &g)) != NOTO_OK) return st;
        if (g.advance > mx) mx = g.advance;
    }
    {
        NotoGlyph g;
        if ((st = noto_glyph_px(p, 0xAC00, px, &g)) != NOTO_OK) return st;
        if (g.advance > mx) mx = g.advance;
    }
    tm->max_width = (int)ceil26(mx);
    return NOTO_OK;
}

NotoStatus gdi_noto_extent(NotoProvider *p, const uint16_t *text, size_t len, int px, int *cx, int *cy, int *ascent)
{
    NotoExtent e; NotoStatus st;
    if (!p || !cx || !cy) return NOTO_E_PARAM;
    if ((st = noto_measure_px(p, text, len, px, &e)) != NOTO_OK) return st;
    *cx = e.cx; *cy = e.cy;
    if (ascent) *ascent = e.ascent;
    return NOTO_OK;
}

NotoStatus gdi_noto_extent_ex(NotoProvider *p, const uint16_t *text, size_t len, int px, int maxw, int *fit, int *dx,
                              int *cx, int *cy)
{
    size_t cur = 0, nfit = 0; int64_t cum = 0; int stopped = 0; NotoStatus st; NotoMetrics m;
    if (!p || (len && !text) || len > NOTO_MAX_TEXT) return NOTO_E_PARAM;
    while (cur < len) {
        size_t before = cur, i; uint32_t sc; int rep; NotoGlyph g; int64_t cpx;
        if ((st = noto_decode(text, len, &cur, &sc, &rep)) != NOTO_OK) return st;
        if ((st = noto_glyph_px(p, sc, px, &g)) != NOTO_OK) return st;
        cum += g.advance;
        cpx = ceil26(cum);
        if (cpx > INT32_MAX) return NOTO_E_RANGE;
        if (dx) for (i = before; i < cur; ++i) dx[i] = (int)cpx;
        if (!stopped) {
            if (maxw < 0 || cpx <= maxw) nfit = cur; else stopped = 1;
        }
    }
    if ((st = noto_metrics_px(p, px, &m)) != NOTO_OK) return st;
    if (fit) *fit = (int)nfit;
    if (cx) *cx = (int)ceil26(cum);
    if (cy) *cy = (int)ceil26(m.height);
    return NOTO_OK;
}

NotoStatus gdi_noto_char_width(NotoProvider *p, uint32_t scalar, int px, int *w)
{
    NotoGlyph g; NotoStatus st;
    if (!p || !w) return NOTO_E_PARAM;
    if ((st = noto_glyph_px(p, scalar, px, &g)) != NOTO_OK) return st;
    *w = (int)ceil26(g.advance);
    return NOTO_OK;
}

NotoStatus gdi_noto_abc(NotoProvider *p, uint32_t scalar, int px, GdiNotoABC *abc)
{
    NotoGlyph g; NotoStatus st; int64_t a, right, adv;
    if (!p || !abc) return NOTO_E_PARAM;
    if ((st = noto_glyph_px(p, scalar, px, &g)) != NOTO_OK) return st;
    a = g.abc_a >> 6;                                /* floor */
    right = ceil26((int64_t)g.abc_a + g.abc_b);
    adv = ceil26(g.advance);
    abc->a = (int)a;
    abc->b = (int)(right - a);
    abc->c = (int)(adv - right);                     /* may be negative (overhang); A + B + C == the pen advance */
    return NOTO_OK;
}

typedef struct { const GdiNotoSurface *s; uint32_t fg; GdiNotoDirty *d; } BlendCtx;

static int blend_cb(void *vctx, int x, int y, const uint8_t *cov, int n)
{
    BlendCtx *c = vctx; const GdiNotoSurface *s = c->s; uint32_t *row; int i;
    if (n <= 0 || y < 0 || y >= s->h || x < 0 || x > s->w - n) return 1;   /* defensive: never write outside the target */
    row = s->bits + (size_t)(s->topdown ? y : s->h - 1 - y) * (size_t)s->w + (size_t)x;
    for (i = 0; i < n; ++i) row[i] = gdi_noto_blend(row[i], c->fg, cov[i]);
    if (!c->d->valid) { c->d->r.left = x; c->d->r.top = y; c->d->r.right = x + n; c->d->r.bottom = y + 1; c->d->valid = 1; }
    else {
        if (x < c->d->r.left) c->d->r.left = x;
        if (y < c->d->r.top) c->d->r.top = y;
        if (x + n > c->d->r.right) c->d->r.right = x + n;
        if (y + 1 > c->d->r.bottom) c->d->r.bottom = y + 1;
    }
    ++c->d->spans;
    return 0;
}

typedef struct { GdiNotoRunFn fn; void *ctx; } RunCtx;
static int run_cb(void *vctx, int x, int y, const uint8_t *cov, int n)
{
    RunCtx *c = vctx; int i = 0;
    while (i < n) {
        int j;
        while (i < n && cov[i] < 128) ++i;
        j = i;
        while (j < n && cov[j] >= 128) ++j;
        if (j > i && c->fn(c->ctx, x + i, y, j - i)) return 1;
        i = j;
    }
    return 0;
}

/* Walk the text scalar by scalar when explicit advances exist, else hand it to the provider in one call. */
static NotoStatus walk(NotoProvider *p, const uint16_t *text, size_t len, int px, int x, const NotoRect *clip, int y,
                       const int *dx, NotoCoverageFn fn, void *ctx)
{
    NotoPen pen; NotoStatus st; size_t cur = 0; int64_t pos = x;
    if (!dx) { memset(&pen, 0, sizeof pen); return noto_draw_px(p, text, len, px, x, y, clip, fn, ctx, &pen); }
    while (cur < len) {
        size_t before = cur, i; uint32_t sc; int rep; int64_t adv = 0;
        if ((st = noto_decode(text, len, &cur, &sc, &rep)) != NOTO_OK) return st;
        for (i = before; i < cur; ++i) { if (dx[i] < 0) return NOTO_E_PARAM; adv += dx[i]; }
        if (pos < -NOTO_COORD_LIMIT || pos > NOTO_COORD_LIMIT) return NOTO_E_RANGE;
        memset(&pen, 0, sizeof pen);
        if ((st = noto_draw_px(p, text + before, cur - before, px, (int)pos, y, clip, fn, ctx, &pen)) != NOTO_OK) return st;
        pos += adv;
    }
    return NOTO_OK;
}

static int64_t dx_total(const int *dx, size_t len)
{
    int64_t t = 0; size_t i;
    for (i = 0; i < len; ++i) { if (dx[i] < 0) return -1; t += dx[i]; }
    return t;
}

NotoStatus gdi_noto_draw(NotoProvider *p, const GdiNotoSurface *s, const NotoRect *clips, int nclips, const uint16_t *text,
                         size_t len, int px, int x, int top, const int *dx, uint32_t fg, GdiNotoDirty *dirty)
{
    BlendCtx c; int i; NotoStatus st; int64_t width, lo, hi, vlo, vhi; NotoExtent e;
    if (!p || !s || !s->bits || s->w <= 0 || s->h <= 0 || !dirty || nclips < 0 || nclips > GDI_NOTO_MAX_RECTS ||
        (nclips && !clips) || (len && !text) || len > NOTO_MAX_TEXT) return NOTO_E_PARAM;
    if (px < NOTO_MIN_PIXELS || px > NOTO_MAX_PIXELS) return NOTO_E_RANGE;
    if (x < -NOTO_COORD_LIMIT || x > NOTO_COORD_LIMIT || top < -NOTO_COORD_LIMIT || top > NOTO_COORD_LIMIT) return NOTO_E_RANGE;
    if (!len) return NOTO_OK;
    if (dx) { if ((width = dx_total(dx, len)) < 0) return NOTO_E_PARAM; }
    else { if ((st = noto_measure_px(p, text, len, px, &e)) != NOTO_OK) return st; width = e.cx; }
    c.s = s; c.fg = fg; c.d = dirty;
    lo = (int64_t)x - px * 2 - 8; hi = (int64_t)x + width + px * 2 + 8;       /* ink may overhang the advance box */
    vlo = (int64_t)top - px * 2 - 8; vhi = (int64_t)top + px * 4 + 16;
    for (i = 0; i < nclips; ++i) {
        NotoRect r = clips[i];
        if (r.left < 0) r.left = 0;
        if (r.top < 0) r.top = 0;
        if (r.right > s->w) r.right = s->w;
        if (r.bottom > s->h) r.bottom = s->h;
        if (r.right <= r.left || r.bottom <= r.top) continue;
        if (r.right <= lo || r.left >= hi || r.bottom <= vlo || r.top >= vhi) continue;
        if ((st = walk(p, text, len, px, x, &r, top, dx, blend_cb, &c)) != NOTO_OK) return st;
    }
    return NOTO_OK;
}

NotoStatus gdi_noto_runs(NotoProvider *p, const uint16_t *text, size_t len, int px, int x, int top, const int *dx,
                         GdiNotoRunFn fn, void *ctx)
{
    RunCtx c;
    if (!p || !fn || (len && !text) || len > NOTO_MAX_TEXT) return NOTO_E_PARAM;
    c.fn = fn; c.ctx = ctx;
    return walk(p, text, len, px, x, NULL, top, dx, run_cb, &c);
}
