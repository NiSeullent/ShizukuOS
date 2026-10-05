/* SPDX-License-Identifier: GPL-2.0-only
 * user32 text layout: the portable, measure-callback driven core of DrawTextW.
 *
 * This unit has no Windows header dependency. Every width comes from an injected callback (in user32 these are
 * GetTextExtentPoint32W / GetTextExtentExPointW of the DC's current font, so layout uses exactly the metrics the glyph
 * renderer uses; in the host controls they are variable-width fakes). The same file is compiled into user32.dll and into
 * the host controls (user32/host_tests/user32_text_layout_host.c).
 *
 * Handled DT_* flags (values are the Windows ones, mirrored below and cross-checked by _Static_assert in user32_paint.c):
 *   LEFT/CENTER/RIGHT, TOP/VCENTER/BOTTOM (vertical alignment only with SINGLELINE, as documented by Windows),
 *   SINGLELINE, WORDBREAK (space, hard CR/LF and, unless NOFULLWIDTHCHARBREAK, East Asian wide character breaks),
 *   EXPANDTABS / TABSTOP (pixel tab stops of tab_chars * average char width; TABSTOP bits 15..8 are the tab length and are
 *   NOT interpreted as other flags, exactly as Windows documents), NOCLIP, NOPREFIX / HIDEPREFIX / PREFIXONLY (first valid
 *   "&x" is underlined, "&&" is a literal '&', a trailing '&' is dropped), CALCRECT (ellipsis is not applied),
 *   END_ELLIPSIS / PATH_ELLIPSIS / WORD_ELLIPSIS, MODIFYSTRING (caller side), EDITCONTROL (edit-control average char
 *   width, no partially visible last line), EXTERNALLEADING, NOFULLWIDTHCHARBREAK, INTERNAL (caller side).
 * Explicitly UNSUPPORTED (shz_tl_layout returns SHZ_TL_E_UNSUPPORTED, never silently ignored): DT_RTLREADING (no bidi
 * reordering exists) and any undefined bit above DT_PREFIXONLY.
 * Documented simplifications: a tab without EXPANDTABS/TABSTOP is one blank; CR/LF inside SINGLELINE text is one blank;
 * only the first prefix is underlined; text is UTF-16 and never split inside a surrogate pair.
 *
 * Memory: the processed text can never be longer than the input (prefix characters and CR/LF disappear, tabs stay a single
 * code unit and are expanded in pixels, not by inserting blanks), so the one text allocation is (n + 1) code units and the
 * line table grows geometrically. Every size computation is overflow checked, input length is capped at SHZ_TL_MAX_CHARS
 * and the line count at SHZ_TL_MAX_LINES; larger inputs fail with SHZ_TL_E_TOOBIG instead of allocating.
 */
#ifndef SHZ_USER32_TEXT_LAYOUT_H
#define SHZ_USER32_TEXT_LAYOUT_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Windows DT_* values (no winuser.h here) */
#define SHZ_TL_DT_CENTER 0x00000001u
#define SHZ_TL_DT_RIGHT 0x00000002u
#define SHZ_TL_DT_VCENTER 0x00000004u
#define SHZ_TL_DT_BOTTOM 0x00000008u
#define SHZ_TL_DT_WORDBREAK 0x00000010u
#define SHZ_TL_DT_SINGLELINE 0x00000020u
#define SHZ_TL_DT_EXPANDTABS 0x00000040u
#define SHZ_TL_DT_TABSTOP 0x00000080u
#define SHZ_TL_DT_NOCLIP 0x00000100u
#define SHZ_TL_DT_EXTERNALLEADING 0x00000200u
#define SHZ_TL_DT_CALCRECT 0x00000400u
#define SHZ_TL_DT_NOPREFIX 0x00000800u
#define SHZ_TL_DT_INTERNAL 0x00001000u
#define SHZ_TL_DT_EDITCONTROL 0x00002000u
#define SHZ_TL_DT_PATH_ELLIPSIS 0x00004000u
#define SHZ_TL_DT_END_ELLIPSIS 0x00008000u
#define SHZ_TL_DT_MODIFYSTRING 0x00010000u
#define SHZ_TL_DT_RTLREADING 0x00020000u
#define SHZ_TL_DT_WORD_ELLIPSIS 0x00040000u
#define SHZ_TL_DT_NOFULLWIDTHCHARBREAK 0x00080000u
#define SHZ_TL_DT_HIDEPREFIX 0x00100000u
#define SHZ_TL_DT_PREFIXONLY 0x00200000u

#define SHZ_TL_MAX_CHARS (1u << 18)             /* 262144 UTF-16 units */
#define SHZ_TL_MAX_LINES (1u << 18)

#define SHZ_TL_OK 0
#define SHZ_TL_E_PARAM (-1)
#define SHZ_TL_E_NOMEM (-2)
#define SHZ_TL_E_MEASURE (-3)                   /* the measure callback failed; the caller owns the error code */
#define SHZ_TL_E_TOOBIG (-4)
#define SHZ_TL_E_UNSUPPORTED (-5)

/* all callbacks return 1 on success, 0 on failure */
typedef int (*shz_tl_measure_fn)(void *ctx, const uint16_t *s, int n, int *width);
/* optional: how many of the first n units fit into maxw (>= 0) and their width. May be NULL (binary search on measure). */
typedef int (*shz_tl_fit_fn)(void *ctx, const uint16_t *s, int n, int maxw, int *fit, int *width);
typedef void *(*shz_tl_alloc_fn)(void *ctx, size_t bytes);
typedef void (*shz_tl_free_fn)(void *ctx, void *p);

typedef struct {
    shz_tl_measure_fn measure;                  /* required */
    shz_tl_fit_fn fit;                          /* optional */
    shz_tl_alloc_fn alloc;                      /* required */
    shz_tl_free_fn release;                     /* required */
    void *ctx;
    int line_height;                            /* tmHeight, must be > 0 */
    int external_leading;                       /* tmExternalLeading, used with DT_EXTERNALLEADING */
    int ascent;                                 /* tmAscent, underline placement */
    int avg_char_width;                         /* tmAveCharWidth, tab stop unit */
} shz_tl_params_t;

typedef struct {
    int start, head_len;                        /* displayed head: buf[start, start + head_len) */
    int dots;                                   /* 1: "..." follows the head */
    int tail_off, tail_len;                     /* displayed tail (path ellipsis) */
    int width;                                  /* displayed width in pixels */
    int x, y;                                   /* offsets relative to the rectangle's left/top after alignment */
    int visible;                                /* 0: lies outside the clip and is not drawn */
    int para_end;                               /* internal: end of the hard-line paragraph that holds this line */
} shz_tl_line_t;

typedef struct {
    shz_tl_params_t p;
    uint32_t fmt;                               /* effective flags (TABSTOP length bits removed) */
    uint16_t *buf;                              /* processed text, buf_len units */
    int buf_len;
    shz_tl_line_t *lines;
    int nlines;
    size_t lines_cap;
    int line_h;                                 /* line pitch including external leading when requested */
    int tab_px;                                 /* tab stop distance in pixels (0: tabs are blanks) */
    int ul_index;                               /* buf index of the underlined character, -1 none */
    int max_width;                              /* widest displayed line */
    int height;                                 /* nlines * line_h */
    int modified;                               /* an ellipsis changed the displayed text */
} shz_tl_layout_t;

typedef struct { const uint16_t *p; int n; int x; int w; int is_dots; int buf_off; } shz_tl_run_t;

typedef struct {
    const shz_tl_layout_t *L;
    const shz_tl_line_t *ln;
    int part, pos, x;
} shz_tl_iter_t;

/* Overflow checked size helpers (exported so the host controls prove them). 1 = ok, 0 = overflow. */
int shz_tl_mul_size(size_t a, size_t b, size_t *out);
int shz_tl_add_size(size_t a, size_t b, size_t *out);
/* Bytes needed for the processed text of an n unit input (checks cap and overflow). 0 on failure. */
int shz_tl_text_bytes(int n, size_t *bytes);

int shz_tl_is_wide(uint16_t c);

/* Lay out text[0..len) (len < 0: NUL terminated, scanned with the SHZ_TL_MAX_CHARS cap) for a rectangle of rect_w x rect_h.
 * On success *L owns memory: release with shz_tl_free. On failure *L owns nothing. */
int shz_tl_layout(const shz_tl_params_t *p, const uint16_t *text, int len, int rect_w, int rect_h, uint32_t fmt,
                  shz_tl_layout_t *L);
void shz_tl_free(shz_tl_layout_t *L);

/* Draw order iteration of one line: 1 = run produced, 0 = end, negative = error (SHZ_TL_E_MEASURE). x is relative to the
 * rectangle left (line alignment included). */
void shz_tl_iter_begin(const shz_tl_layout_t *L, int line, shz_tl_iter_t *it);
int shz_tl_iter_next(shz_tl_iter_t *it, shz_tl_run_t *run);
/* Underline of the line: 1 and *x,*w (relative to rect left) when the underlined char is displayed on this line. */
int shz_tl_underline(const shz_tl_layout_t *L, int line, int *x, int *w);

/* Displayed text of the whole layout (lines joined by nothing; only meaningful for a single line) for DT_MODIFYSTRING.
 * Returns the number of units the displayed text needs, or negative on error. Writes at most cap units (no NUL). */
int shz_tl_displayed_text(const shz_tl_layout_t *L, uint16_t *out, int cap);

#ifdef __cplusplus
}
#endif
#endif
