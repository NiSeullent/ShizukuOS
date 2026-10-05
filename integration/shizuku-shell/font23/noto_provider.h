/* SPDX-License-Identifier: GPL-2.0-only
 * Noto Sans / Noto Sans KR provider over the existing FreeType 2.13.3 static library (FTL/GPLv2).
 * No HDC, no user32/GDI dependency: callers (ShzText, a future GDI adapter) supply font bytes and a coverage
 * callback. One NotoProvider is one owned context (FT_Library, two FT_Faces, budgeted allocator); no global
 * mutable state. A context is single-threaded: concurrent/re-entrant entry returns NOTO_E_BUSY. Font bytes are
 * owned by the face lifetime and released via NotoFontSource.release AFTER FT_Done_Face; call noto_destroy
 * outside any loader lock. Text is UTF-16 (uint16_t); bad surrogates decode to U+FFFD. Metrics are 26.6.
 * Measure and draw use the same advances (unhinted outlines, pen accumulated in 26.6, rounded per glyph). */
#ifndef NOTO_PROVIDER_H
#define NOTO_PROVIDER_H
#include <stddef.h>
#include <stdint.h>

#define NOTO_MAX_TEXT        32767
#define NOTO_MAX_SCALE       8
#define NOTO_BASE_PIXELS     16
#define NOTO_MAX_FONT_BYTES  (48u * 1024u * 1024u)   /* per face source */
#define NOTO_MAX_FT_BYTES    (48u * 1024u * 1024u)   /* FreeType heap budget per context */
#define NOTO_COORD_LIMIT     (1 << 24)

typedef enum {
    NOTO_OK = 0, NOTO_E_PARAM = 1, NOTO_E_BUSY = 2, NOTO_E_NOMEM = 3, NOTO_E_FONT = 4,
    NOTO_E_FAMILY = 5, NOTO_E_FREETYPE = 6, NOTO_E_RANGE = 7, NOTO_E_ABORT = 8, NOTO_E_BITMAP = 9
} NotoStatus;

typedef struct NotoProvider NotoProvider;

/* Ownership of `data` transfers to noto_create on every call (also on failure): release(ctx,data) is called
 * exactly once after the face is gone (or immediately on failure). release may be NULL for static bytes. */
typedef struct NotoFontSource {
    const void *data; size_t size; long face_index;
    void (*release)(void *ctx, const void *data); void *ctx;
} NotoFontSource;

/* Both faces' family must start with "Noto Sans" (latin must not be CJK). Variable faces are set to wght=400
 * (a variable face without a wght axis fails). */
NotoStatus noto_create(NotoFontSource *latin, NotoFontSource *kr, NotoProvider **out);
void noto_destroy(NotoProvider *p);
const char *noto_family(const NotoProvider *p, int kr_face);
size_t noto_ft_bytes_in_use(const NotoProvider *p);

/* Bounded UTF-16 decode. *cursor is the ORIGINAL UTF-16 unit index; advances by 1 or 2. */
NotoStatus noto_decode(const uint16_t *text, size_t len, size_t *cursor, uint32_t *scalar, int *replaced);

typedef struct NotoGlyph {
    uint32_t scalar; unsigned glyph_index; int kr_face;
    int missing;                                  /* in neither face: that face's glyph 0 (.notdef) is used */
    int32_t advance;                              /* 26.6 */
    int32_t abc_a, abc_b, abc_c;                  /* 26.6: left bearing, ink width, right bearing */
    int32_t bearing_x, bearing_y, width, height;  /* 26.6 outline metrics */
} NotoGlyph;
NotoStatus noto_glyph(NotoProvider *p, uint32_t scalar, int scale, NotoGlyph *g);
int noto_has_glyph(NotoProvider *p, uint32_t scalar);

typedef struct NotoMetrics { int32_t ascent, descent, height; } NotoMetrics;   /* 26.6, max of both faces */
NotoStatus noto_metrics(NotoProvider *p, int scale, NotoMetrics *m);

typedef struct NotoExtent {
    int64_t width26; int cx, cy, ascent;          /* cx=ceil(width26/64); baseline = top + ascent */
    unsigned glyphs, missing, replaced;
} NotoExtent;
NotoStatus noto_measure(NotoProvider *p, const uint16_t *text, size_t len, int scale, NotoExtent *e);

typedef struct NotoRect { int left, top, right, bottom; } NotoRect;   /* half-open */

/* Called per bitmap row span: pixels x..x+count-1 on row y with 8-bit coverage. Non-zero return aborts with
 * NOTO_E_ABORT; the pen stays at the failing glyph so noto_draw can resume (retry). */
typedef int (*NotoCoverageFn)(void *ctx, int x, int y, const uint8_t *coverage, int count);

typedef struct NotoPen { size_t cursor; int64_t x26; } NotoPen;   /* zero-init to start */
NotoStatus noto_draw(NotoProvider *p, const uint16_t *text, size_t len, int scale, int x, int y,
                     const NotoRect *clip, NotoCoverageFn fn, void *ctx, NotoPen *pen);
#endif
