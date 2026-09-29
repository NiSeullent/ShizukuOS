/* SPDX-License-Identifier: GPL-2.0-only
 * gdi32.dll internals (shared by gdi_*.c). GDI is implemented entirely in USER mode:
 *
 *  - Every drawing target is a bitmap in the application's own address space: memory-DC bitmaps, DIB sections (the
 *    application must be able to write their pixels through the pointer CreateDIBSection returns, which only user-space
 *    memory can offer without a shared-section facility), and one "backing" bitmap per window that a window DC draws into.
 *  - A window DC pushes the rectangle it changed to the kernel window manager (NtGdiPresent), which copies it into the
 *    window's kernel surface and recomposes. Flush points: ReleaseDC/EndPaint (user32 calls ShzGdiWindowDCRelease),
 *    GdiFlush and the message-loop idle points in user32 (ShzGdiFlushAll).
 *  - All pixels are 32 bit, 0x00RRGGBB (blue in the low byte, the alpha byte is carried but never interpreted by the
 *    classic drawing calls). Palette and colour-depth handling other than 32 bit does not exist.
 *  - Coordinates: MM_TEXT only, with SetViewportOrgEx/SetWindowOrgEx offsets. No world transform.
 *  - The only font is the built-in 8x16 bitmap font (see gdi_text.c). One coarse lock protects all GDI state.
 */
#ifndef SHZ_GDI_INTERNAL_H
#define SHZ_GDI_INTERNAL_H
#define _GDI32_
#define _USER32_
#include "nt.h"
#include <wingdi.h>
#include "shzgfx.h"

#define GDI_MAX_OBJECTS 8192
#define GDI_MAX_CLIP_RECTS 4096

typedef struct { int n, cap; RECT *r; } rlist_t;            /* disjoint rectangles */

typedef struct bitmap {
    int w, h;
    uint32_t *bits;
    int topdown;                                            /* row 0 of `bits` is the top scanline */
    int is_dib;                                             /* CreateDIBSection: application holds a pointer to bits */
    int big;                                                /* bits came from VirtualAlloc */
    int sel;                                                /* number of DCs it is selected into */
    BITMAPINFOHEADER bih;                                   /* what CreateDIBSection was given (for GetObject) */
} bitmap_t;

typedef struct { LOGPEN lp; int ext; DWORD ext_style; } pen_t;
typedef struct { LOGBRUSH lb; HBITMAP pattern; } brush_t;
typedef struct { LOGFONTW lf; int scale; } font_t;
typedef struct { rlist_t rl; } rgn_t;

typedef struct dc {
    int memdc;                                              /* memory DC (else a window/screen DC) */
    HBITMAP hbmp;                                           /* selected bitmap (memory DC) */
    HWND hwnd;                                              /* window DC: the window; 0 for memory DCs */
    int wcx, wcy;                                           /* window DC: client size when it was created */
    struct backing *bk;                                     /* window DC: the window's backing bitmap (lazily attached) */
    rlist_t sysclip; int has_sysclip;                       /* BeginPaint region, device coordinates */
    rlist_t userclip; int has_userclip;                     /* SelectClipRgn, logical coordinates converted to device */
    rlist_t eff; int eff_valid;                             /* cached effective clip */
    HPEN pen; HBRUSH brush; HFONT font;
    COLORREF text, bk_color;
    int bkmode, rop2, polyfill, stretchmode, mapmode, textalign, gfxmode;
    POINT pos;
    POINT win_org, vp_org, brush_org;
    COLORREF dcpen, dcbrush;
    struct dc *saved;                                       /* SaveDC stack */
    int dirty_valid; RECT dirty;                            /* window DC: not yet presented */
} dc_t;

typedef struct backing {
    struct backing *next;
    HWND hwnd;
    bitmap_t bmp;
    RECT dirty; int dirty_valid;
} backing_t;

/* handle table */
HGDIOBJ gdi_obj_new(int type, void *p, int stock);
void *gdi_obj_get(HGDIOBJ h, int type, int *type_out);     /* type 0: any; NULL if stale */
void gdi_obj_free(HGDIOBJ h);
int gdi_obj_type(HGDIOBJ h);
extern CRITICAL_SECTION g_gdi_lock;
#define GDI_ENTER() EnterCriticalSection(&g_gdi_lock)
#define GDI_LEAVE() LeaveCriticalSection(&g_gdi_lock)
#define RET(x) do { GDI_LEAVE(); return (x); } while (0)

/* memory */
void *gdi_alloc(size_t n);                                  /* zeroed */
void gdi_free(void *p);
uint32_t *gdi_alloc_pixels(uint64_t n_dwords, int *big);
void gdi_free_pixels(uint32_t *p, uint64_t n_dwords, int big);

/* rectangle lists */
void rl_init(rlist_t *l);
void rl_free(rlist_t *l);
int rl_copy(rlist_t *d, const rlist_t *s);
int rl_add_rect(rlist_t *l, const RECT *r);                 /* appends without overlap test */
int rl_intersect(rlist_t *out, const rlist_t *a, const rlist_t *b);
int rl_subtract(rlist_t *out, const rlist_t *a, const rlist_t *b);
int rl_union(rlist_t *out, const rlist_t *a, const rlist_t *b);
void rl_bbox(const rlist_t *l, RECT *r);
void rl_offset(rlist_t *l, int dx, int dy);
void rl_coalesce(rlist_t *l);
static inline int rc_is_empty(const RECT *r) { return r->right <= r->left || r->bottom <= r->top; }
static inline int rc_intersect(RECT *o, const RECT *a, const RECT *b)
{
    o->left = a->left > b->left ? a->left : b->left;
    o->top = a->top > b->top ? a->top : b->top;
    o->right = a->right < b->right ? a->right : b->right;
    o->bottom = a->bottom < b->bottom ? a->bottom : b->bottom;
    return !rc_is_empty(o);
}

/* device contexts */
dc_t *gdi_dc_get(HDC h);
bitmap_t *gdi_dc_target(dc_t *dc);                          /* the bitmap drawing goes to (allocates a window backing lazily) */
const rlist_t *gdi_dc_clip(dc_t *dc);                       /* effective clip in device coordinates, bounded by the target */
void gdi_dc_touch(dc_t *dc, const RECT *dev);               /* record a changed device rectangle (window DCs) */
static inline int dc_lx(const dc_t *dc, int x) { return x - dc->win_org.x + dc->vp_org.x; }
static inline int dc_ly(const dc_t *dc, int y) { return y - dc->win_org.y + dc->vp_org.y; }
void gdi_window_flush(backing_t *b);
void gdi_forget_backing(backing_t *b);                      /* detach every DC from a backing that is about to be freed */

/* pixels */
static inline uint32_t *bm_px(const bitmap_t *b, int x, int y)
{
    return b->bits + (size_t)(b->topdown ? y : b->h - 1 - y) * (size_t)b->w + (size_t)x;
}
static inline uint32_t colorref_to_pixel(COLORREF c)
{
    return ((c & 0xff) << 16) | (c & 0xff00) | ((c >> 16) & 0xff);
}
static inline COLORREF pixel_to_colorref(uint32_t p)
{
    return ((p & 0xff) << 16) | (p & 0xff00) | ((p >> 16) & 0xff);
}
uint32_t gdi_rop3(uint32_t rop3, uint32_t p, uint32_t s, uint32_t d);
uint32_t gdi_rop2(int rop2, uint32_t pen, uint32_t dst);

/* drawing context: one per API call. All rectangles are DEVICE coordinates of the target bitmap. */
typedef struct {
    dc_t *dc;
    bitmap_t *bm;
    const rlist_t *clip;
    RECT dirty; int has_dirty;
    /* current brush, resolved */
    int bkind;                                              /* 0 none, 1 solid, 2 hatch */
    uint32_t bpix, bbg; int bhatch, bopaque;
    /* current pen, resolved */
    int pnull, pwidth, pstyle; uint32_t ppix;
} gctx_t;
int gctx_begin(gctx_t *g, dc_t *dc);                        /* resolves target, clip, pen and brush; 0 if there is no target */
void gctx_end(gctx_t *g);                                   /* records the changed area for window DCs */
void gctx_span_rop2(gctx_t *g, int x0, int x1, int y, uint32_t v, int rop2);   /* [x0,x1), clipped */
void gctx_span_brush(gctx_t *g, int x0, int x1, int y);
void gctx_pixel(gctx_t *g, int x, int y, uint32_t v, int rop2);
int gdi_font_scale(dc_t *dc);
void gdi_dc_defaults(dc_t *dc);
extern HGDIOBJ g_stock[32];

/* private exports used by user32 */
#define SHZ_EXPORT_GDI
#endif
