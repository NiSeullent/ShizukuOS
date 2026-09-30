/* SPDX-License-Identifier: GPL-2.0-only
 * gdi32: rectangle-list algebra, regions (HRGN) and device-context clipping. A region is a set of DISJOINT rectangles;
 * union/intersection/difference/xor are computed pairwise (fine for the few-rectangle regions GDI clients use). */
#include "gdi_internal.h"

void rl_init(rlist_t *l) { memset(l, 0, sizeof *l); }
void rl_free(rlist_t *l) { gdi_free(l->r); memset(l, 0, sizeof *l); }

static int rl_reserve(rlist_t *l, int n)
{
    RECT *nr;
    int cap;
    if (l->cap >= n) return 1;
    cap = l->cap ? l->cap * 2 : 8;
    while (cap < n) cap *= 2;
    nr = gdi_alloc((size_t)cap * sizeof(RECT));
    if (!nr) return 0;
    if (l->n) memcpy(nr, l->r, (size_t)l->n * sizeof(RECT));
    gdi_free(l->r);
    l->r = nr;
    l->cap = cap;
    return 1;
}

int rl_add_rect(rlist_t *l, const RECT *r)
{
    if (rc_is_empty(r)) return 1;
    if (!rl_reserve(l, l->n + 1)) return 0;
    l->r[l->n++] = *r;
    return 1;
}

int rl_copy(rlist_t *d, const rlist_t *s)
{
    d->n = 0;
    if (!s->n) return 1;
    if (!rl_reserve(d, s->n)) return 0;
    memcpy(d->r, s->r, (size_t)s->n * sizeof(RECT));
    d->n = s->n;
    return 1;
}

void rl_bbox(const rlist_t *l, RECT *b)
{
    int i;
    b->left = b->top = b->right = b->bottom = 0;
    for (i = 0; i < l->n; ++i) {
        if (i == 0) { *b = l->r[0]; continue; }
        if (l->r[i].left < b->left) b->left = l->r[i].left;
        if (l->r[i].top < b->top) b->top = l->r[i].top;
        if (l->r[i].right > b->right) b->right = l->r[i].right;
        if (l->r[i].bottom > b->bottom) b->bottom = l->r[i].bottom;
    }
}

void rl_offset(rlist_t *l, int dx, int dy)
{
    int i;
    for (i = 0; i < l->n; ++i) {
        l->r[i].left += dx; l->r[i].right += dx; l->r[i].top += dy; l->r[i].bottom += dy;
    }
}

int rl_intersect(rlist_t *out, const rlist_t *a, const rlist_t *b)
{
    int i, j;
    out->n = 0;
    for (i = 0; i < a->n; ++i)
        for (j = 0; j < b->n; ++j) {
            RECT r;
            if (rc_intersect(&r, &a->r[i], &b->r[j]) && !rl_add_rect(out, &r)) return 0;
        }
    return 1;
}

/* pieces of a minus b (at most four disjoint rectangles) appended to out */
static int rect_minus(rlist_t *out, const RECT *a, const RECT *b)
{
    RECT i, p;
    if (!rc_intersect(&i, a, b)) return rl_add_rect(out, a);
    if (i.top > a->top) { p = *a; p.bottom = i.top; if (!rl_add_rect(out, &p)) return 0; }
    if (i.bottom < a->bottom) { p = *a; p.top = i.bottom; if (!rl_add_rect(out, &p)) return 0; }
    if (i.left > a->left) { p.left = a->left; p.right = i.left; p.top = i.top; p.bottom = i.bottom; if (!rl_add_rect(out, &p)) return 0; }
    if (i.right < a->right) { p.left = i.right; p.right = a->right; p.top = i.top; p.bottom = i.bottom; if (!rl_add_rect(out, &p)) return 0; }
    return 1;
}

int rl_subtract(rlist_t *out, const rlist_t *a, const rlist_t *b)
{
    rlist_t cur, nxt;
    int i, j, k, ok = 1;
    out->n = 0;
    rl_init(&cur);
    rl_init(&nxt);
    for (i = 0; i < a->n && ok; ++i) {
        cur.n = 0;
        ok = rl_add_rect(&cur, &a->r[i]);
        for (j = 0; j < b->n && ok && cur.n; ++j) {
            nxt.n = 0;
            for (k = 0; k < cur.n && ok; ++k) ok = rect_minus(&nxt, &cur.r[k], &b->r[j]);
            { rlist_t t = cur; cur = nxt; nxt = t; }
        }
        for (k = 0; k < cur.n && ok; ++k) ok = rl_add_rect(out, &cur.r[k]);
    }
    rl_free(&cur);
    rl_free(&nxt);
    return ok;
}

int rl_union(rlist_t *out, const rlist_t *a, const rlist_t *b)
{
    rlist_t diff;
    int i, ok;
    rl_init(&diff);
    ok = rl_subtract(&diff, b, a);
    out->n = 0;
    for (i = 0; ok && i < a->n; ++i) ok = rl_add_rect(out, &a->r[i]);
    for (i = 0; ok && i < diff.n; ++i) ok = rl_add_rect(out, &diff.r[i]);
    rl_free(&diff);
    return ok;
}

void rl_coalesce(rlist_t *l)
{
    int changed = 1;
    while (changed && l->n > 1) {
        int i, j;
        changed = 0;
        for (i = 0; i < l->n && !changed; ++i)
            for (j = i + 1; j < l->n && !changed; ++j) {
                RECT *a = &l->r[i], *b = &l->r[j];
                if (a->left == b->left && a->right == b->right && (a->bottom == b->top || b->bottom == a->top)) {
                    if (b->top < a->top) a->top = b->top;
                    if (b->bottom > a->bottom) a->bottom = b->bottom;
                    changed = 1;
                } else if (a->top == b->top && a->bottom == b->bottom && (a->right == b->left || b->right == a->left)) {
                    if (b->left < a->left) a->left = b->left;
                    if (b->right > a->right) a->right = b->right;
                    changed = 1;
                }
                if (changed) l->r[j] = l->r[--l->n];
            }
    }
}

static int rl_type(const rlist_t *l) { return l->n == 0 ? NULLREGION : l->n == 1 ? SIMPLEREGION : COMPLEXREGION; }

/* ---------------------------------------------------------------- HRGN */
static HRGN rgn_create(const RECT *r)
{
    rgn_t *g = gdi_alloc(sizeof *g);
    HGDIOBJ h;
    RECT n;
    if (!g) return 0;
    n.left = r->left < r->right ? r->left : r->right;
    n.right = r->left < r->right ? r->right : r->left;
    n.top = r->top < r->bottom ? r->top : r->bottom;
    n.bottom = r->top < r->bottom ? r->bottom : r->top;
    rl_add_rect(&g->rl, &n);
    h = gdi_obj_new(OBJ_REGION, g, 0);
    if (!h) { rl_free(&g->rl); gdi_free(g); }
    return (HRGN)h;
}

DLLAPI HRGN WINAPI CreateRectRgn(int l, int t, int r, int b)
{
    RECT rc;
    HRGN h;
    rc.left = l; rc.top = t; rc.right = r; rc.bottom = b;
    GDI_ENTER();
    h = rgn_create(&rc);
    RET(h);
}

DLLAPI HRGN WINAPI CreateRectRgnIndirect(const RECT *rc)
{
    HRGN h;
    if (!rc) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    GDI_ENTER();
    h = rgn_create(rc);
    RET(h);
}

DLLAPI BOOL WINAPI SetRectRgn(HRGN h, int l, int t, int r, int b)
{
    rgn_t *g;
    RECT n;
    GDI_ENTER();
    g = gdi_obj_get((HGDIOBJ)h, OBJ_REGION, 0);
    if (!g) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    n.left = l < r ? l : r; n.right = l < r ? r : l; n.top = t < b ? t : b; n.bottom = t < b ? b : t;
    g->rl.n = 0;
    rl_add_rect(&g->rl, &n);
    RET(TRUE);
}

DLLAPI int WINAPI CombineRgn(HRGN dst, HRGN s1, HRGN s2, int mode)
{
    rgn_t *d, *a, *b;
    rlist_t tmp, t2;
    int ok = 1, ty;
    GDI_ENTER();
    d = gdi_obj_get((HGDIOBJ)dst, OBJ_REGION, 0);
    a = gdi_obj_get((HGDIOBJ)s1, OBJ_REGION, 0);
    b = mode == RGN_COPY ? a : gdi_obj_get((HGDIOBJ)s2, OBJ_REGION, 0);
    if (!d || !a || !b) { SetLastError(ERROR_INVALID_HANDLE); RET(ERROR); }
    rl_init(&tmp);
    rl_init(&t2);
    switch (mode) {
    case RGN_AND: ok = rl_intersect(&tmp, &a->rl, &b->rl); break;
    case RGN_OR: ok = rl_union(&tmp, &a->rl, &b->rl); break;
    case RGN_DIFF: ok = rl_subtract(&tmp, &a->rl, &b->rl); break;
    case RGN_XOR: {
        rlist_t x, y;
        rl_init(&x); rl_init(&y);
        ok = rl_subtract(&x, &a->rl, &b->rl) && rl_subtract(&y, &b->rl, &a->rl) && rl_union(&tmp, &x, &y);
        rl_free(&x); rl_free(&y);
        break;
    }
    case RGN_COPY: ok = rl_copy(&tmp, &a->rl); break;
    default: SetLastError(ERROR_INVALID_PARAMETER); rl_free(&tmp); RET(ERROR);
    }
    if (!ok) { rl_free(&tmp); RET(ERROR); }
    rl_coalesce(&tmp);
    rl_free(&d->rl);
    d->rl = tmp;
    ty = rl_type(&d->rl);
    RET(ty);
}

DLLAPI int WINAPI GetRgnBox(HRGN h, LPRECT rc)
{
    rgn_t *g;
    int ty;
    GDI_ENTER();
    g = gdi_obj_get((HGDIOBJ)h, OBJ_REGION, 0);
    if (!g || !rc) { SetLastError(ERROR_INVALID_HANDLE); RET(ERROR); }
    rl_bbox(&g->rl, rc);
    ty = rl_type(&g->rl);
    RET(ty);
}

DLLAPI BOOL WINAPI EqualRgn(HRGN h1, HRGN h2)
{
    rgn_t *a, *b;
    rlist_t x, y;
    BOOL eq;
    GDI_ENTER();
    a = gdi_obj_get((HGDIOBJ)h1, OBJ_REGION, 0);
    b = gdi_obj_get((HGDIOBJ)h2, OBJ_REGION, 0);
    if (!a || !b) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    rl_init(&x); rl_init(&y);
    eq = rl_subtract(&x, &a->rl, &b->rl) && rl_subtract(&y, &b->rl, &a->rl) && x.n == 0 && y.n == 0;
    rl_free(&x); rl_free(&y);
    RET(eq);
}

DLLAPI int WINAPI OffsetRgn(HRGN h, int dx, int dy)
{
    rgn_t *g;
    int ty;
    GDI_ENTER();
    g = gdi_obj_get((HGDIOBJ)h, OBJ_REGION, 0);
    if (!g) { SetLastError(ERROR_INVALID_HANDLE); RET(ERROR); }
    rl_offset(&g->rl, dx, dy);
    ty = rl_type(&g->rl);
    RET(ty);
}

DLLAPI BOOL WINAPI PtInRegion(HRGN h, int x, int y)
{
    rgn_t *g;
    int i;
    GDI_ENTER();
    g = gdi_obj_get((HGDIOBJ)h, OBJ_REGION, 0);
    if (!g) RET(FALSE);
    for (i = 0; i < g->rl.n; ++i)
        if (x >= g->rl.r[i].left && x < g->rl.r[i].right && y >= g->rl.r[i].top && y < g->rl.r[i].bottom) RET(TRUE);
    RET(FALSE);
}

DLLAPI BOOL WINAPI RectInRegion(HRGN h, const RECT *rc)
{
    rgn_t *g;
    int i;
    GDI_ENTER();
    g = gdi_obj_get((HGDIOBJ)h, OBJ_REGION, 0);
    if (!g || !rc) RET(FALSE);
    for (i = 0; i < g->rl.n; ++i) {
        RECT o;
        if (rc_intersect(&o, &g->rl.r[i], rc)) RET(TRUE);
    }
    RET(FALSE);
}

DLLAPI DWORD WINAPI GetRegionData(HRGN h, DWORD count, LPRGNDATA data)
{
    rgn_t *g;
    DWORD need;
    GDI_ENTER();
    g = gdi_obj_get((HGDIOBJ)h, OBJ_REGION, 0);
    if (!g) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    need = (DWORD)(sizeof(RGNDATAHEADER) + (size_t)g->rl.n * sizeof(RECT));
    if (!data) RET(need);
    if (count < need) RET(0);
    data->rdh.dwSize = sizeof(RGNDATAHEADER);
    data->rdh.iType = RDH_RECTANGLES;
    data->rdh.nCount = (DWORD)g->rl.n;
    data->rdh.nRgnSize = (DWORD)g->rl.n * sizeof(RECT);
    rl_bbox(&g->rl, &data->rdh.rcBound);
    if (g->rl.n) memcpy(data->Buffer, g->rl.r, (size_t)g->rl.n * sizeof(RECT));
    RET(need);
}

/* Private export for user32 (InvalidateRgn/RedrawWindow/GetUpdateRgn): the region's rectangles, up to `max`. Returns the
 * number written, or -1 if the handle is not a region. */
DLLAPI int WINAPI ShzGdiRegionRects(HRGN h, RECT *out, int max)
{
    rgn_t *g;
    int n;
    GDI_ENTER();
    g = gdi_obj_get((HGDIOBJ)h, OBJ_REGION, 0);
    if (!g) RET(-1);
    n = g->rl.n < max ? g->rl.n : max;
    if (n) memcpy(out, g->rl.r, (size_t)n * sizeof(RECT));
    RET(n);
}

/* Private export for user32: replace a region's contents with the given rectangles (GetUpdateRgn). */
DLLAPI BOOL WINAPI ShzGdiRegionSetRects(HRGN h, const RECT *in, int n)
{
    rgn_t *g;
    int i;
    GDI_ENTER();
    g = gdi_obj_get((HGDIOBJ)h, OBJ_REGION, 0);
    if (!g) RET(FALSE);
    g->rl.n = 0;
    for (i = 0; i < n; ++i) rl_add_rect(&g->rl, &in[i]);
    RET(TRUE);
}

/* ---------------------------------------------------------------- DC clipping */
static void target_bounds(dc_t *dc, RECT *b)
{
    b->left = b->top = 0;
    if (dc->memdc) {
        bitmap_t *bm = gdi_obj_get((HGDIOBJ)dc->hbmp, OBJ_BITMAP, 0);
        b->right = bm ? bm->w : 0;
        b->bottom = bm ? bm->h : 0;
    } else {
        b->right = dc->wcx;
        b->bottom = dc->wcy;
    }
}

const rlist_t *gdi_dc_clip(dc_t *dc)
{
    if (!dc->eff_valid) {
        RECT b;
        rlist_t base, t1;
        target_bounds(dc, &b);
        rl_init(&base);
        rl_init(&t1);
        rl_add_rect(&base, &b);
        rl_free(&dc->eff);
        if (dc->has_sysclip) { rl_intersect(&t1, &base, &dc->sysclip); { rlist_t t = base; base = t1; t1 = t; } }
        if (dc->has_userclip) { rl_intersect(&t1, &base, &dc->userclip); { rlist_t t = base; base = t1; t1 = t; } }
        dc->eff = base;
        rl_free(&t1);
        dc->eff_valid = 1;
    }
    return &dc->eff;
}

int gdi_dc_select_region(dc_t *dc, rgn_t *r)
{
    rl_free(&dc->userclip);
    rl_copy(&dc->userclip, &r->rl);
    rl_offset(&dc->userclip, dc->dev_org.x, dc->dev_org.y);        /* region coordinates are device units, as on Windows */
    dc->has_userclip = 1;
    dc->eff_valid = 0;
    return rl_type(&dc->userclip);
}

DLLAPI int WINAPI SelectClipRgn(HDC hdc, HRGN h)
{
    dc_t *dc;
    int ty;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(ERROR); }
    if (!h) {
        rl_free(&dc->userclip);
        dc->has_userclip = 0;
        dc->eff_valid = 0;
        RET(SIMPLEREGION);
    }
    {
        rgn_t *r = gdi_obj_get((HGDIOBJ)h, OBJ_REGION, 0);
        if (!r) { SetLastError(ERROR_INVALID_HANDLE); RET(ERROR); }
        ty = gdi_dc_select_region(dc, r);
    }
    RET(ty);
}

static int user_clip_base(dc_t *dc, rlist_t *base)
{
    if (dc->has_userclip) return rl_copy(base, &dc->userclip);
    {
        RECT b;
        target_bounds(dc, &b);
        base->n = 0;
        return rl_add_rect(base, &b);
    }
}

static int clip_apply(dc_t *dc, const RECT *dev, int exclude)
{
    rlist_t base, rr, out;
    int ok;
    rl_init(&base); rl_init(&rr); rl_init(&out);
    ok = user_clip_base(dc, &base) && rl_add_rect(&rr, dev) &&
         (exclude ? rl_subtract(&out, &base, &rr) : rl_intersect(&out, &base, &rr));
    if (ok) {
        rl_coalesce(&out);
        rl_free(&dc->userclip);
        dc->userclip = out;
        dc->has_userclip = 1;
        dc->eff_valid = 0;
    } else {
        rl_free(&out);
    }
    rl_free(&base); rl_free(&rr);
    return ok ? rl_type(&dc->userclip) : ERROR;
}

DLLAPI int WINAPI IntersectClipRect(HDC hdc, int l, int t, int r, int b)
{
    dc_t *dc;
    RECT rc;
    int ty;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(ERROR); }
    rc.left = dc_lx(dc, l); rc.right = dc_lx(dc, r); rc.top = dc_ly(dc, t); rc.bottom = dc_ly(dc, b);
    ty = clip_apply(dc, &rc, 0);
    RET(ty);
}

DLLAPI int WINAPI ExcludeClipRect(HDC hdc, int l, int t, int r, int b)
{
    dc_t *dc;
    RECT rc;
    int ty;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(ERROR); }
    rc.left = dc_lx(dc, l); rc.right = dc_lx(dc, r); rc.top = dc_ly(dc, t); rc.bottom = dc_ly(dc, b);
    ty = clip_apply(dc, &rc, 1);
    RET(ty);
}

DLLAPI int WINAPI GetClipBox(HDC hdc, LPRECT out)
{
    dc_t *dc;
    const rlist_t *c;
    int ty;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || !out) { SetLastError(ERROR_INVALID_HANDLE); RET(ERROR); }
    c = gdi_dc_clip(dc);
    rl_bbox(c, out);
    out->left -= dc_ox(dc); out->right -= dc_ox(dc);
    out->top -= dc_oy(dc); out->bottom -= dc_oy(dc);
    ty = rl_type(c);
    RET(ty);
}

DLLAPI int WINAPI GetClipRgn(HDC hdc, HRGN h)
{
    dc_t *dc;
    rgn_t *r;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    r = gdi_obj_get((HGDIOBJ)h, OBJ_REGION, 0);
    if (!dc || !r) { SetLastError(ERROR_INVALID_HANDLE); RET(-1); }
    if (!dc->has_userclip) RET(0);
    rl_copy(&r->rl, &dc->userclip);
    rl_offset(&r->rl, -dc->dev_org.x, -dc->dev_org.y);
    RET(1);
}

DLLAPI BOOL WINAPI PtVisible(HDC hdc, int x, int y)
{
    dc_t *dc;
    const rlist_t *c;
    int i;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) RET(FALSE);
    c = gdi_dc_clip(dc);
    x = dc_lx(dc, x); y = dc_ly(dc, y);
    for (i = 0; i < c->n; ++i)
        if (x >= c->r[i].left && x < c->r[i].right && y >= c->r[i].top && y < c->r[i].bottom) RET(TRUE);
    RET(FALSE);
}

DLLAPI BOOL WINAPI RectVisible(HDC hdc, const RECT *rc)
{
    dc_t *dc;
    const rlist_t *c;
    int i;
    RECT d, o;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || !rc) RET(FALSE);
    c = gdi_dc_clip(dc);
    d.left = dc_lx(dc, rc->left); d.right = dc_lx(dc, rc->right); d.top = dc_ly(dc, rc->top); d.bottom = dc_ly(dc, rc->bottom);
    for (i = 0; i < c->n; ++i)
        if (rc_intersect(&o, &c->r[i], &d)) RET(TRUE);
    RET(FALSE);
}
