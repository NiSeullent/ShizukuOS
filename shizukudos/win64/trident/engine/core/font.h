/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - the font-metrics interface between layout (portable) and a text backend. Owner: L1.
 *
 * Backends:
 *   - fixed (core/font_fixed.c): the model of Shizuku gdi32's only font, used by the host tests: every UTF-16 code
 *     unit advances 8 * scale px, ascent 13 * scale, descent 3 * scale, height 16 * scale, where
 *     scale = clamp((round(size_px) + 8) / 16, 1, 4) with integer division (gdi32 gdi_obj.c: lfHeight -> scale).
 *   - GDI (win/, L1): CreateFontIndirectW + GetTextMetricsW / GetTextExtentExPointW, drawn with ExtTextOutW. On
 *     Shizuku it reproduces the fixed model exactly, so host and guest layouts agree.
 *   - DirectWrite (optional, win/, L1): selected at run time; never required by the tests.
 * The process-wide backend is set once at DLL load (shz_font_set_backend) or by a host test.
 */
#ifndef SHZ_FONT_H
#define SHZ_FONT_H

#include "base.h"

typedef struct shz_font shz_font;               /* backend-owned, cached, never freed by callers */

#define SHZ_FONT_ITALIC     0x01
#define SHZ_FONT_UNDERLINE  0x02                /* drawing hints only: decorations do not change metrics */
#define SHZ_FONT_STRIKE     0x04

typedef struct shz_font_desc {
    const shz_char *family;                     /* CSS font-family value as computed ("Arial, sans-serif"), may be NULL */
    float size;                                 /* px */
    int weight;                                 /* 100..900 (400 normal, 700 bold) */
    unsigned flags;                             /* SHZ_FONT_* */
} shz_font_desc;

typedef struct shz_font_metrics {
    float ascent;                               /* baseline to the top of the em box / cell */
    float descent;                              /* baseline to the bottom */
    float line_height;                          /* "normal" line height: ascent + descent + external leading */
    float x_height;
    float avg_width;                            /* average character width */
} shz_font_metrics;

typedef struct shz_font_backend shz_font_backend;
struct shz_font_backend {
    const char *name;                           /* "fixed", "gdi", "dwrite" */
    /* Font for a description (cached by the backend; the same desc gives the same pointer). */
    shz_font *(*get_font)(shz_font_backend *self, const shz_font_desc *desc);
    void      (*metrics)(shz_font_backend *self, shz_font *font, shz_font_metrics *out);
    /* Width of text[0..n) in px. */
    float     (*text_width)(shz_font_backend *self, shz_font *font, const shz_char *text, size_t n);
    /* Cumulative advances: pos[i] = width of text[0..i] (i.e. the x offset after unit i); used for line breaking,
     * caret placement and hit testing inside text. */
    void      (*advances)(shz_font_backend *self, shz_font *font, const shz_char *text, size_t n, float *pos);
};

shz_font_backend *shz_font_fixed_backend(void);          /* core/font_fixed.c */
void              shz_font_set_backend(shz_font_backend *backend);
shz_font_backend *shz_font_get_backend(void);             /* the fixed backend until one is set */

/* the scale gdi32 picks for a pixel size (see above) */
int               shz_font_fixed_scale(float size_px);

#endif /* SHZ_FONT_H */
