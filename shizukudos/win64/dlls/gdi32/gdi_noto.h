/* SPDX-License-Identifier: GPL-2.0-only
 * gdi32 <-> Noto provider adapter core (portable: no Windows header, no HDC, no user32). The SAME file is compiled into
 * gdi32.dll and into the host controls (gdi32/host_tests). Every measurement, ABC value and drawn glyph comes from one
 * NotoProvider (integration/shizuku-font), so GetTextExtent*, GetTextMetrics and ExtTextOut cannot disagree.
 *
 * Lifetime: a GdiNoto owns at most one provider, opened lazily by a caller supplied open function (never from DllMain)
 * and released only by gdi_noto_release (never from DllMain / the loader lock). Callers serialise every use with the GDI
 * coarse lock; the provider itself is single threaded and returns NOTO_E_BUSY on re-entry. No callback outlives its call.
 * A failed open is remembered (with its NotoStatus) and an UNAVAILABLE failure is retried at most every GDI_NOTO_RETRY_MS;
 * nothing ever falls back to another font. */
#ifndef SHZ_GDI_NOTO_H
#define SHZ_GDI_NOTO_H
#include <stddef.h>
#include <stdint.h>
#include "noto_provider.h"

#define GDI_NOTO_RETRY_MS 2000u
#define GDI_NOTO_MAX_RECTS 4096

typedef NotoStatus (*GdiNotoOpenFn)(void *ctx, NotoProvider **out);
typedef struct GdiNoto {
    NotoProvider *p;
    NotoStatus st;                  /* last open status (NOTO_OK when p != NULL) */
    int tried;
    uint64_t retry_at;
    unsigned opens, open_failures;
    GdiNotoOpenFn open; void *open_ctx;
    uint64_t (*now_ms)(void);       /* NULL: never retry after a failure */
} GdiNoto;

void gdi_noto_init(GdiNoto *g, GdiNotoOpenFn open, void *ctx, uint64_t (*now_ms)(void));
/* The provider, opening it on first use. NULL with *st != NOTO_OK when the assets are unavailable/invalid. */
NotoProvider *gdi_noto_get(GdiNoto *g, NotoStatus *st);
NotoStatus gdi_noto_release(GdiNoto *g);        /* NOTO_E_BUSY keeps the provider; the state is reset only on success */

/* LOGFONT lfHeight -> real pixel size 1..128 (<0 em height, >0 cell height, 0 = cell height 16). NOTO_E_RANGE otherwise. */
NotoStatus gdi_noto_resolve_px(NotoProvider *p, int lf_height, int *px);

typedef struct GdiNotoTM { int height, ascent, descent, internal_leading, avg_width, max_width; } GdiNotoTM;
NotoStatus gdi_noto_text_metrics(NotoProvider *p, int px, GdiNotoTM *tm);

/* Total width/height in whole pixels (ceil of the 26.6 sum, identical to noto_measure_px). */
NotoStatus gdi_noto_extent(NotoProvider *p, const uint16_t *text, size_t len, int px, int *cx, int *cy, int *ascent);
/* GetTextExtentExPoint: dx[i] (may be NULL) is the cumulative pixel extent after code unit i (both units of a pair carry
 * the pair's value); *fit is the number of code units whose cumulative extent is <= maxw (maxw < 0: all), never splitting a
 * surrogate pair. */
NotoStatus gdi_noto_extent_ex(NotoProvider *p, const uint16_t *text, size_t len, int px, int maxw, int *fit, int *dx,
                              int *cx, int *cy);
NotoStatus gdi_noto_char_width(NotoProvider *p, uint32_t scalar, int px, int *w);
typedef struct GdiNotoABC { int a, b, c; } GdiNotoABC;
NotoStatus gdi_noto_abc(NotoProvider *p, uint32_t scalar, int px, GdiNotoABC *abc);

/* 32 bit 0x00RRGGBB target; same row mapping as gdi_internal.h bm_px. */
typedef struct GdiNotoSurface { uint32_t *bits; int w, h, topdown; } GdiNotoSurface;
typedef struct GdiNotoDirty { NotoRect r; int valid; unsigned long spans; } GdiNotoDirty;

/* Alpha blend `fg` (0x00RRGGBB) through the provider's 8 bit coverage into the destination RGB, preserving the destination
 * alpha byte, inside the union of `clips` (device rects, further intersected with the surface). `top` is the line's top;
 * the baseline is top + ceil(ascent). dx != NULL: per code unit advances (integer pixels, >= 0), the pen advances by the sum
 * over a scalar's units. The changed area is merged into *dirty. */
NotoStatus gdi_noto_draw(NotoProvider *p, const GdiNotoSurface *s, const NotoRect *clips, int nclips, const uint16_t *text,
                         size_t len, int px, int x, int top, const int *dx, uint32_t fg, GdiNotoDirty *dirty);

/* Path recording: coverage >= 128 runs (x,y,count) are reported; the callback returns non-zero to abort. This is a
 * bitmap-threshold approximation of the text, NOT an outline (the provider has no outline API). */
typedef int (*GdiNotoRunFn)(void *ctx, int x, int y, int count);
NotoStatus gdi_noto_runs(NotoProvider *p, const uint16_t *text, size_t len, int px, int x, int top, const int *dx,
                         GdiNotoRunFn fn, void *ctx);

static inline uint32_t gdi_noto_blend(uint32_t d, uint32_t f, unsigned c)
{
    if (c >= 255) return (d & 0xff000000u) | (f & 0x00ffffffu);
    if (!c) return d;
    {
        const uint32_t r = (((d >> 16) & 255) * (255 - c) + ((f >> 16) & 255) * c + 127) / 255;
        const uint32_t g = (((d >> 8) & 255) * (255 - c) + ((f >> 8) & 255) * c + 127) / 255;
        const uint32_t b = ((d & 255) * (255 - c) + (f & 255) * c + 127) / 255;
        return (d & 0xff000000u) | (r << 16) | (g << 8) | b;
    }
}
#endif
