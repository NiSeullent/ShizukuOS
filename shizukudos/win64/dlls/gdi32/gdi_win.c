/* SPDX-License-Identifier: GPL-2.0-only
 * gdi32: window and screen device contexts. A window DC draws into a per-window "backing" bitmap in this process and
 * pushes the changed rectangle to the kernel window manager with NtGdiPresent (see gdi_internal.h). The ShzGdi* exports
 * are the private interface user32 uses to create/release window DCs; they are not Windows APIs. */
#include "gdi_internal.h"
#include "gdi_render_trace.h"

static backing_t *g_backings;

static backing_t *backing_find(HWND hwnd)
{
    backing_t *b;
    for (b = g_backings; b; b = b->next)
        if (b->hwnd == hwnd) return b;
    return 0;
}

#define FACE_PIXEL 0x00c0c0c0u

/* Attaches (creating or resizing) the backing bitmap of a window DC. New areas start as the kernel's initial surface
 * colour so partial repaints and raster operations see what is really on screen. */
static backing_t *backing_attach(HWND hwnd, int cx, int cy)
{
    backing_t *b = backing_find(hwnd);
    uint64_t n;
    uint32_t *nb;
    int big, y, cw, ch;
    uint32_t fill = FACE_PIXEL;
    if (cx <= 0 || cy <= 0) return 0;
    if (b && b->bmp.w == cx && b->bmp.h == cy) return b;
    if ((uint64_t)cx * (uint64_t)cy * 4 > (64u << 20)) return 0;
    if (!b) {
        b = gdi_alloc(sizeof *b);
        if (!b) return 0;
        b->hwnd = hwnd;
        b->bmp.topdown = 1;
        b->next = g_backings;
        g_backings = b;
    }
    {
        uint64_t desk = 0;
        int32_t st;
        shz_wnd_t q;
        memset(&q, 0, sizeof q);
        q.what = SHZ_WQ_DESKTOP;
        st = NtUserWindowQuery(&q);
        desk = st >= 0 ? q.v0 : 0;
        if ((uint64_t)(uintptr_t)hwnd == desk) fill = SHZ_DESKTOP_RGB;
    }
    n = (uint64_t)cx * (uint64_t)cy;
    nb = gdi_alloc_pixels(n, &big);
    if (!nb) return 0;
    {
        uint64_t i;
        for (i = 0; i < n; ++i) nb[i] = fill;
    }
    cw = b->bmp.w < cx ? b->bmp.w : cx;
    ch = b->bmp.h < cy ? b->bmp.h : cy;
    if (b->bmp.bits)
        for (y = 0; y < ch; ++y) memcpy(nb + (size_t)y * (size_t)cx, b->bmp.bits + (size_t)y * (size_t)b->bmp.w, (size_t)cw * 4);
    gdi_free_pixels(b->bmp.bits, (uint64_t)b->bmp.w * (uint64_t)b->bmp.h, b->bmp.big);
    b->bmp.bits = nb;
    b->bmp.big = big;
    b->bmp.w = cx;
    b->bmp.h = cy;
    return b;
}

bitmap_t *gdi_dc_target(dc_t *dc)
{
    if (dc->memdc) return gdi_obj_get((HGDIOBJ)dc->hbmp, OBJ_BITMAP, 0);
    if (!dc->bk) dc->bk = backing_attach(dc->hwnd, dc->wcx, dc->wcy);
    return dc->bk ? &dc->bk->bmp : 0;
}

static int64_t rc_area(const RECT *r) { return (int64_t)(r->right - r->left) * (r->bottom - r->top); }
static void rc_merge(RECT *a, const RECT *b)
{
    if (b->left < a->left) a->left = b->left;
    if (b->top < a->top) a->top = b->top;
    if (b->right > a->right) a->right = b->right;
    if (b->bottom > a->bottom) a->bottom = b->bottom;
}

/* The changed area of a window backing, kept as up to GDI_DIRTY_RECTS rectangles so scattered small updates are
 * presented as what they are, not as their bounding box: a rectangle that touches or overlaps a kept one is merged into
 * it; when the list is full the pair whose merge adds the least area is merged. */
void gdi_dc_touch(dc_t *dc, const RECT *dev)
{
    backing_t *b = dc->bk;
    RECT r = *dev;
    int i, again = 1;
    if (dc->emf) { gdi_emf_touch(dc, dev); return; }
    if (dc->memdc || !b || rc_is_empty(dev)) return;
    while (again) {                                                   /* absorb every kept rectangle the new one meets */
        again = 0;
        for (i = 0; i < b->ndirty; ++i) {
            const RECT *k = &b->dirty[i];
            if (k->left <= r.right && r.left <= k->right && k->top <= r.bottom && r.top <= k->bottom) {
                rc_merge(&r, k);
                b->dirty[i] = b->dirty[--b->ndirty];
                again = 1;
                break;
            }
        }
    }
    if (b->ndirty == GDI_DIRTY_RECTS) {
        int best = 0;
        int64_t cost = -1;
        for (i = 0; i < b->ndirty; ++i) {
            RECT m = b->dirty[i];
            int64_t c;
            rc_merge(&m, &r);
            c = rc_area(&m) - rc_area(&b->dirty[i]) - rc_area(&r);
            if (cost < 0 || c < cost) { cost = c; best = i; }
        }
        rc_merge(&b->dirty[best], &r);
        return;
    }
    b->dirty[b->ndirty++] = r;
}

void gdi_window_flush(backing_t *b)
{
    shz_present_t p;
    RECT full, r;
    int i;
    const int n = b->ndirty;
    full.left = full.top = 0;
    full.right = b->bmp.w;
    full.bottom = b->bmp.h;
    b->ndirty = 0;
    for (i = 0; i < n; ++i) {
        if (!rc_intersect(&r, &b->dirty[i], &full)) continue;
        memset(&p, 0, sizeof p);
        p.hwnd = (uint64_t)(uintptr_t)b->hwnd;
        p.x = r.left; p.y = r.top; p.w = r.right - r.left; p.h = r.bottom - r.top;
        p.bits = (uint64_t)(uintptr_t)b->bmp.bits;
        p.stride = (uint32_t)b->bmp.w * 4;
        p.surf_w = b->bmp.w;
        p.surf_h = b->bmp.h;
        {
            int32_t status = NtGdiPresent(&p);
            gdi_render_trace_present(b,&r,status);
            if (status < 0) break;   /* the window vanished or was resized meanwhile: nothing left to update */
        }
    }
}

void gdi_window_dc_flush(dc_t *dc)
{
    if (dc->bk) gdi_window_flush(dc->bk);
}

void gdi_flush_all_locked(void)
{
    backing_t *b;
    for (b = g_backings; b; b = b->next) gdi_window_flush(b);
}

/* ---------------------------------------------------------------- private exports for user32 */
DLLAPI HDC WINAPI ShzGdiWindowDC(HWND hwnd, int cx, int cy, const RECT *sysclip, int nclip)
{
    dc_t *dc;
    HGDIOBJ h;
    int i;
    GDI_ENTER();
    dc = gdi_alloc(sizeof *dc);
    if (!dc) RET(0);
    gdi_dc_defaults(dc);
    dc->hwnd = hwnd;
    dc->wcx = cx;
    dc->wcy = cy;
    if (sysclip) {
        dc->has_sysclip = 1;
        for (i = 0; i < nclip; ++i) rl_add_rect(&dc->sysclip, &sysclip[i]);
    }
    h = gdi_obj_new(OBJ_DC, dc, 0);
    if (!h) { rl_free(&dc->sysclip); gdi_free(dc); RET(0); }
    RET((HDC)h);
}

DLLAPI BOOL WINAPI ShzGdiWindowDCRelease(HDC hdc)
{
    dc_t *dc;
    BOOL ok;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    ok = dc != 0 && dc->hwnd != 0;
    GDI_LEAVE();
    return ok ? DeleteDC(hdc) : FALSE;
}

DLLAPI VOID WINAPI ShzGdiFlushAll(void)
{
    GDI_ENTER();
    gdi_flush_all_locked();
    GDI_LEAVE();
}

/* The window is gone (or is being destroyed): drop its backing bitmap. */
DLLAPI VOID WINAPI ShzGdiWindowGone(HWND hwnd)
{
    backing_t **pp, *b;
    GDI_ENTER();
    gdi_window_pixel_format_forget(hwnd);
    for (pp = &g_backings; (b = *pp); pp = &b->next)
        if (b->hwnd == hwnd) {
            *pp = b->next;
            gdi_forget_backing(b);
            gdi_free_pixels(b->bmp.bits, (uint64_t)b->bmp.w * (uint64_t)b->bmp.h, b->bmp.big);
            gdi_free(b);
            break;
        }
    GDI_LEAVE();
}

DLLAPI HDC WINAPI CreateDCW(LPCWSTR driver, LPCWSTR device, LPCWSTR port, const DEVMODEW *dm)
{
    static const WCHAR display[] = { 'D', 'I', 'S', 'P', 'L', 'A', 'Y', 0 };
    shz_wnd_t q;
    shz_display_info_t info;
    unsigned i;
    (void)device; (void)port; (void)dm;
    if (!driver) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    for (i = 0; display[i]; ++i)
        if ((driver[i] | 0x20) != (display[i] | 0x20)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (driver[i]) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (NtUserQueryDisplay(&info, SHZ_DISP_QUERY) < 0) { SetLastError(ERROR_NOT_SUPPORTED); return 0; }     /* no display device */
    memset(&q, 0, sizeof q);
    q.what = SHZ_WQ_DESKTOP;
    if (NtUserWindowQuery(&q) < 0) { SetLastError(ERROR_NOT_SUPPORTED); return 0; }
    return ShzGdiWindowDC((HWND)(uintptr_t)q.v0, (int)info.width, (int)info.height, 0, 0);
}
