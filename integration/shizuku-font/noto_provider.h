/* SPDX-License-Identifier: GPL-2.0-only
 * Noto Sans / Noto Sans KR provider over the existing FreeType 2.13.3 static library (FTL/GPLv2).
 * Shared common font core (repair of integration/shizuku-shell/font23, which is kept as the historical first
 * epoch). No HDC, no user32/GDI dependency: callers (ShzText, GDI adapter) supply font bytes and a coverage
 * callback. One NotoProvider is one owned context (FT_Library, two FT_Faces, bounded allocator); no global
 * mutable state.
 *
 * Threading: a context is single-threaded. Every query and draw takes a per-context busy flag; concurrent or
 * re-entrant (callback) entry returns NOTO_E_BUSY. noto_destroy() requires a quiescent context: it returns
 * NOTO_E_BUSY (and keeps the context alive) if a call is in flight, but it cannot detect a thread that has
 * fetched the pointer and not yet entered, so the owner must serialize destroy against all users (the process
 * wrapper does this with a lock). Using a context after a successful destroy is a caller use-after-free.
 *
 * Identity: font bytes are accepted only if their SHA-256 equals a caller-supplied expected pin, the
 * family is exactly "Noto Sans" (latin) / "Noto Sans KR" or "Noto Sans CJK KR" (kr), and coverage is
 * verified (all 11172 Hangul syllables + modern conjoining Jamo in kr, A-Z a-z 0-9 in latin).
 * Pixel sizes are integers 1..128. Metrics are 26.6 unhinted. Measure and draw use identical advances. */
#ifndef NOTO_PROVIDER_H
#define NOTO_PROVIDER_H
#include <stddef.h>
#include <stdint.h>

#define NOTO_MAX_TEXT        32767
#define NOTO_MIN_PIXELS      1
#define NOTO_MAX_PIXELS      128
#define NOTO_MAX_SCALE       8                       /* legacy scale 1..8 == 16*scale pixels */
#define NOTO_BASE_PIXELS     16
#define NOTO_MAX_FONT_BYTES  (48u * 1024u * 1024u)   /* per face source */
#define NOTO_MAX_FT_BYTES    (48u * 1024u * 1024u)   /* default FreeType heap budget per context */
#define NOTO_COORD_LIMIT     (1 << 24)
#define NOTO_SHA256_LEN      32

typedef enum {
    NOTO_OK = 0, NOTO_E_PARAM = 1, NOTO_E_BUSY = 2, NOTO_E_NOMEM = 3, NOTO_E_FONT = 4,
    NOTO_E_FAMILY = 5, NOTO_E_FREETYPE = 6, NOTO_E_RANGE = 7, NOTO_E_ABORT = 8, NOTO_E_BITMAP = 9,
    NOTO_E_UNAVAILABLE = 10,   /* no provider / font assets absent: caller must fail visibly, no fake fallback */
    NOTO_E_HASH = 11,          /* bytes do not match the expected SHA-256 pin */
    NOTO_E_COVERAGE = 12       /* family ok but required glyph coverage missing */
} NotoStatus;
const char *noto_status_str(NotoStatus st);

typedef struct NotoProvider NotoProvider;

/* Ownership of `data` transfers to noto_create on every call (also on failure): release(ctx,data) is called
 * exactly once after the face is gone (or immediately on failure). release may be NULL for static bytes.
 * expected_sha256 (32 bytes, REQUIRED, copied) is the pin of the whole `data` image; face_index selects the
 * face inside a collection and is part of the contract (pin the file, publish the index). Latin and kr must be
 * distinct, non-overlapping images (aliasing rejects with NOTO_E_PARAM, release once per distinct pointer). */
typedef struct NotoFontSource {
    const void *data; size_t size; long face_index;
    void (*release)(void *ctx, const void *data); void *ctx;
    const uint8_t *expected_sha256;
} NotoFontSource;

/* Optional per-instance allocator (NULL cfg or NULL fields = malloc/free). alloc/free must be consistent with each
 * other and thread-compatible with the provider's single thread. max_ft_bytes 0 = NOTO_MAX_FT_BYTES (must be
 * <= it otherwise). The provider struct and FreeType heap both use it, with bounded accounting; with an arena
 * allocator, destroy still calls free() per block (a no-op free is acceptable). */
typedef struct NotoConfig {
    void *(*alloc)(void *ctx, size_t n); void (*free)(void *ctx, void *p); void *ctx; size_t max_ft_bytes;
} NotoConfig;

NotoStatus noto_create(NotoFontSource *latin, NotoFontSource *kr, NotoProvider **out);
NotoStatus noto_create_ex(const NotoConfig *cfg, NotoFontSource *latin, NotoFontSource *kr, NotoProvider **out);
NotoStatus noto_destroy(NotoProvider *p);      /* NOTO_E_BUSY: still alive, nothing freed. NULL: OK */
const char *noto_family(const NotoProvider *p, int kr_face);    /* immutable copy, valid until destroy */
size_t noto_ft_bytes_in_use(const NotoProvider *p);

/* Hex pin helper: 64 hex digits (any case) -> 32 bytes. NOTO_E_PARAM otherwise. */
NotoStatus noto_pin_from_hex(const char *hex64, uint8_t out[NOTO_SHA256_LEN]);
/* SHA-256 of a buffer through the portable bcrypt hashes.c implementation. */
void noto_sha256(const void *data, size_t n, uint8_t out[NOTO_SHA256_LEN]);

/* Bounded UTF-16 decode. *cursor is the ORIGINAL UTF-16 unit index; advances by 1 or 2. */
NotoStatus noto_decode(const uint16_t *text, size_t len, size_t *cursor, uint32_t *scalar, int *replaced);

typedef struct NotoGlyph {
    uint32_t scalar; unsigned glyph_index; int kr_face;
    int missing;                                  /* in neither face: that face's glyph 0 (.notdef) is used */
    int32_t advance;                              /* 26.6 */
    int32_t abc_a, abc_b, abc_c;                  /* 26.6: left bearing, ink width, right bearing */
    int32_t bearing_x, bearing_y, width, height;  /* 26.6 outline metrics */
} NotoGlyph;
/* scalar must be a Unicode scalar value (<=0x10FFFF, not a surrogate) else NOTO_E_PARAM. */
NotoStatus noto_glyph_px(NotoProvider *p, uint32_t scalar, int pixel_size, NotoGlyph *g);
NotoStatus noto_glyph(NotoProvider *p, uint32_t scalar, int scale, NotoGlyph *g);
NotoStatus noto_query_glyph(NotoProvider *p, uint32_t scalar, int *present);   /* BUSY-guarded */
int noto_has_glyph(NotoProvider *p, uint32_t scalar);   /* 1 present; 0 absent OR busy/invalid (use noto_query_glyph) */

typedef struct NotoMetrics { int32_t ascent, descent, height; } NotoMetrics;   /* 26.6, max of both faces */
NotoStatus noto_metrics_px(NotoProvider *p, int pixel_size, NotoMetrics *m);
NotoStatus noto_metrics(NotoProvider *p, int scale, NotoMetrics *m);

typedef struct NotoExtent {
    int64_t width26; int cx, cy, ascent;          /* cx=ceil(width26/64); baseline = top + ascent */
    unsigned glyphs, missing, replaced;           /* missing = glyphs in neither face (.notdef) */
} NotoExtent;
NotoStatus noto_measure_px(NotoProvider *p, const uint16_t *text, size_t len, int pixel_size, NotoExtent *e);
NotoStatus noto_measure(NotoProvider *p, const uint16_t *text, size_t len, int scale, NotoExtent *e);

typedef struct NotoRect { int left, top, right, bottom; } NotoRect;   /* half-open; extreme values are clamped */

/* Called per bitmap row span: pixels x..x+count-1 on row y with 8-bit coverage. The callback must be ATOMIC per
 * call: return 0 only after the whole span was committed, non-zero (nothing committed) to abort. A non-zero
 * return aborts with NOTO_E_ABORT and the pen records the failing glyph AND the failing row, so a resumed
 * noto_draw delivers every span exactly once (no row twice, none skipped): blending callbacks are safe. */
typedef int (*NotoCoverageFn)(void *ctx, int x, int y, const uint8_t *coverage, int count);

/* Zero-init to start. Resume with the SAME text/len/pixel size/x/y/clip. pixel/row are managed by noto_draw. */
typedef struct NotoPen {
    size_t cursor; int64_t x26;
    int row;                       /* next row of the current glyph to deliver */
    int pixel_size;                /* bound on first use; a resume with another size is NOTO_E_PARAM */
    unsigned missing, replaced;    /* completed glyphs so far (.notdef / U+FFFD) */
} NotoPen;
NotoStatus noto_draw_px(NotoProvider *p, const uint16_t *text, size_t len, int pixel_size, int x, int y,
                        const NotoRect *clip, NotoCoverageFn fn, void *ctx, NotoPen *pen);
NotoStatus noto_draw(NotoProvider *p, const uint16_t *text, size_t len, int scale, int x, int y,
                     const NotoRect *clip, NotoCoverageFn fn, void *ctx, NotoPen *pen);
#endif
