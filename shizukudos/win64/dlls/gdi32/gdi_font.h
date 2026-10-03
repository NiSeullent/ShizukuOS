/* SPDX-License-Identifier: GPL-2.0-only
 * The built-in gdi32 bitmap font, independent of any Windows header so the host test can link it.
 *
 * A glyph is a 16-row cell, 8 (half-width) or 16 (full-width) pixels wide, ascent 13. Sources:
 *   - 0x00..0x7f: the public-domain 8x8 IBM VGA font (supervisor/src/font8x8_basic.h), every row doubled, unchanged
 *     from the original ASCII-only gdi32 (control codes draw as blank space).
 *   - gdi_font_data.c: GNU Unifont 18.0.01 glyphs for the bounded ranges listed in fonts/gen_font_data.py (Latin-1,
 *     Hangul Jamo / compatibility Jamo, all 11172 modern Hangul syllables, CJK punctuation, fullwidth forms, ...).
 *   - everything else: a hollow ".notdef" box (glyph index 0), 16 wide for East Asian wide code points, else 8.
 *     A UTF-16 high surrogate draws one wide box (standing for the supplementary-plane character); every low
 *     surrogate is zero width and draws nothing, so a pair measures and draws as one wide box.
 *
 * Glyph indices: ASCII glyph = its code (0x20..0x7f); Unifont glyph = 0x100 + its ordinal in gdi_font_data.c;
 * 0 = notdef box (narrow), 1 = notdef box (wide), 2 = zero-width (low surrogate). */
#ifndef SHZ_GDI_FONT_H
#define SHZ_GDI_FONT_H
#include <stdint.h>

#define GDI_FONT_CELL_H 16
#define GDI_FONT_ASCENT 13
#define GDI_FONT_NARROW 8
#define GDI_FONT_WIDE 16

typedef struct { uint16_t first, last; uint8_t width; uint32_t offset; } gdi_font_range_t;
extern const gdi_font_range_t gdi_font_ranges[];
extern const unsigned gdi_font_range_count;
extern const uint8_t gdi_font_bits[];

enum { GDI_GLYPH_ASCII, GDI_GLYPH_DATA, GDI_GLYPH_BOX, GDI_GLYPH_EMPTY };
typedef struct {
    int kind;
    int width;                     /* advance in unscaled pixels: 0, 8 or 16 */
    unsigned index;                /* glyph index (see above) */
    const uint8_t *bits;           /* DATA: 16 rows of width/8 bytes, LSB = leftmost pixel; ASCII: font8x8 row table */
} gdi_glyph_t;

/* the glyph of one UTF-16 unit; returns its glyph index */
unsigned gdi_font_glyph(unsigned ch, gdi_glyph_t *g);
/* inverse for ETO_GLYPH_INDEX; returns 0 for an index the font does not have */
int gdi_font_glyph_by_index(unsigned index, gdi_glyph_t *g);
/* pixel mask of cell row 0..15: bit c set = column c is ink */
uint32_t gdi_font_row(const gdi_glyph_t *g, int row);
/* Grayscale antialiasing (no ClearType / subpixel claim). The 1-bit glyph is treated as samples at pixel centres; the
 * outline is the 0.5 level set of their bilinear interpolation (marching-squares-like: straight horizontal/vertical
 * edges stay on pixel boundaries, diagonal stair steps become sloped edges), rendered at scale num/den (output cell is
 * ceil(width*num/den) x ceil(16*num/den)) and box-filtered from GDI_FONT_AA_SS x GDI_FONT_AA_SS samples per output
 * pixel. Returns coverage 0..255 of output pixel (ox, oy). `bold` widens the source by one pixel to the right. */
#define GDI_FONT_AA_SS 4
unsigned gdi_font_coverage(const gdi_glyph_t *g, int num, int den, int bold, int ox, int oy);
/* output-cell width of a glyph at scale num/den (the advance used for measuring is this value too) */
int gdi_font_scaled(int units, int num, int den);
/* composite 0x00RRGGBB foreground over destination with coverage a (0..255), rounded per channel */
uint32_t gdi_font_blend(uint32_t dst, uint32_t fg, unsigned a);
/* 1 if the font has a real glyph (not the notdef box) for this UTF-16 unit */
int gdi_font_has_glyph(unsigned ch);
/* advance width in unscaled pixels of one UTF-16 unit */
int gdi_font_advance(unsigned ch);
#endif
