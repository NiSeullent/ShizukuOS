/* SPDX-License-Identifier: GPL-2.0-only
 * Host test of the gdi32 built-in font lookup (gdi_font.c + generated gdi_font_data.c):
 *   cc -O2 -Wall -Wextra -Werror -I.. ../gdi_font.c ../gdi_font_data.c test_font_glyphs.c && ./a.out */
#include "../gdi_font.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned ink(const gdi_glyph_t *g, uint32_t rows[GDI_FONT_CELL_H])
{
    unsigned n = 0, r;
    for (r = 0; r < GDI_FONT_CELL_H; ++r) {
        rows[r] = gdi_font_row(g, (int)r);
        assert(!(rows[r] >> g->width));                            /* no ink outside the advance */
        n += (unsigned)__builtin_popcount(rows[r]);
    }
    return n;
}

int main(void)
{
    gdi_glyph_t g, h;
    uint32_t a[GDI_FONT_CELL_H], b[GDI_FONT_CELL_H];
    unsigned checks = 0, ga, gh, cp, n;
#define VERIFY(c) do { assert(c); ++checks; } while (0)
    /* ASCII unchanged: 8 wide, index = code, doubled font8x8 rows ('A' row 0 of font8x8 is 0x0C) */
    VERIFY(gdi_font_glyph('A', &g) == 'A' && g.kind == GDI_GLYPH_ASCII && g.width == 8);
    VERIFY(gdi_font_row(&g, 0) == 0x0C && gdi_font_row(&g, 1) == 0x0C && ink(&g, a) > 0);
    VERIFY(gdi_font_glyph(0x01, &g) == 0x20 && gdi_font_advance(0x01) == 8);
    VERIFY(gdi_font_has_glyph('~') && !gdi_font_has_glyph(0x01));
    /* 가 (U+AC00) and 힣 (U+D7A3): real 16-wide Unifont glyphs, non-empty and distinct */
    ga = gdi_font_glyph(0xAC00, &g);
    gh = gdi_font_glyph(0xD7A3, &h);
    VERIFY(g.kind == GDI_GLYPH_DATA && h.kind == GDI_GLYPH_DATA && g.width == 16 && h.width == 16);
    VERIFY(ink(&g, a) > 20 && ink(&h, b) > 20 && memcmp(a, b, sizeof a));
    /* Unifont AC00 row 3 is 0x3F84 (MSB-left) -> LSB-left mask 0x21FC */
    VERIFY(a[2] == 0x2000 && a[3] == 0x21FC);
    VERIFY(ga >= 0x100 && gh == ga + (0xD7A3 - 0xAC00));
    /* every modern syllable is present, 16 wide and has ink; index round-trips */
    for (cp = 0xAC00, n = 0; cp <= 0xD7A3; ++cp) {
        gdi_font_glyph(cp, &g);
        assert(g.kind == GDI_GLYPH_DATA && g.width == 16 && ink(&g, a) > 0);
        assert(gdi_font_glyph_by_index(g.index, &h) && h.bits == g.bits);
        ++n;
    }
    VERIFY(n == 11172 && gdi_font_has_glyph(0xAC00));
    /* compatibility Jamo ㄱ (U+3131) and ㅎ (U+314E) */
    VERIFY(gdi_font_glyph(0x3131, &g) && g.kind == GDI_GLYPH_DATA && g.width == 16 && ink(&g, a) > 0);
    /* Latin-1 é is half width */
    VERIFY(gdi_font_glyph(0xE9, &g) && g.kind == GDI_GLYPH_DATA && g.width == 8 && ink(&g, a) > 0);
    /* unmapped: CJK ideograph -> wide notdef box, Cyrillic -> narrow box, both non-empty, reported missing */
    VERIFY(gdi_font_glyph(0x4E00, &g) == 1 && g.kind == GDI_GLYPH_BOX && g.width == 16 && ink(&g, a) > 0);
    VERIFY(gdi_font_glyph(0x0416, &g) == 0 && g.kind == GDI_GLYPH_BOX && g.width == 8 && ink(&g, a) > 0);
    VERIFY(!gdi_font_has_glyph(0x4E00) && !gdi_font_has_glyph(0x0416));
    /* surrogate pair: one wide box + zero-width low half */
    VERIFY(gdi_font_advance(0xD83D) == 16 && gdi_font_advance(0xDE00) == 0);
    /* measurement: "A가" = 8 + 16 */
    VERIFY(gdi_font_advance('A') + gdi_font_advance(0xAC00) == 24);
    VERIFY(!gdi_font_glyph_by_index(0xFFFF, &g));
    /* grayscale coverage: 가 at scale 1 has full (255), partial (1..254) and empty pixels; strokes stay solid */
    {
        unsigned hist[3] = { 0, 0, 0 }, x, y, cov, sum1 = 0, sum15 = 0, partial15 = 0;
        gdi_font_glyph(0xAC00, &g);
        for (y = 0; y < 16; ++y)
            for (x = 0; x < 16; ++x) {
                cov = gdi_font_coverage(&g, 1, 1, 0, (int)x, (int)y);
                assert(cov <= 255);
                hist[cov == 0 ? 0 : cov == 255 ? 2 : 1]++;
                sum1 += cov;
                /* a pixel whose 4-neighbourhood is solid ink is fully covered */
                if (y && x && x < 15 && y < 15 && ((gdi_font_row(&g, (int)y) >> x) & 7u << (x - 1)) == 7u << (x - 1) &&
                    ((gdi_font_row(&g, (int)y - 1) >> x) & 1) && ((gdi_font_row(&g, (int)y + 1) >> x) & 1)) assert(cov == 255);
            }
        VERIFY(hist[0] > 0 && hist[1] > 0 && hist[2] > 0);
        /* row 3 (0x21FC): the horizontal stroke interior is solid ink */
        VERIFY(gdi_font_coverage(&g, 1, 1, 0, 4, 3) == 255 && gdi_font_coverage(&g, 1, 1, 0, 4, 0) == 0);
        /* non-integer scale 3/2 (24 px cell) through the same box filter: partial values present, total ink ~ 2.25x */
        VERIFY(gdi_font_scaled(16, 3, 2) == 24 && gdi_font_scaled(8, 3, 2) == 12);
        for (y = 0; y < 24; ++y)
            for (x = 0; x < 24; ++x) {
                cov = gdi_font_coverage(&g, 3, 2, 0, (int)x, (int)y);
                sum15 += cov;
                partial15 += cov > 0 && cov < 255;
            }
        VERIFY(partial15 > 0 && sum15 * 100 > sum1 * 180 && sum15 * 100 < sum1 * 270);
        /* ASCII 'A' also has a coverage rendering (used for ANTIALIASED_QUALITY), the notdef box too */
        gdi_font_glyph('A', &h);
        for (y = 0, n = 0; y < 16; ++y) for (x = 0; x < 8; ++x) { cov = gdi_font_coverage(&h, 1, 1, 0, (int)x, (int)y); n += cov > 0 && cov < 255; }
        VERIFY(n > 0);
        /* empty glyph has no coverage */
        gdi_font_glyph(0xDE00, &h);
        VERIFY(gdi_font_coverage(&h, 1, 1, 0, 0, 0) == 0);
    }
    /* compositing against actual destination pixels */
    VERIFY(gdi_font_blend(0x00FFFFFF, 0x00000000, 255) == 0x00000000);
    VERIFY(gdi_font_blend(0x00FFFFFF, 0x00000000, 0) == 0x00FFFFFF);
    VERIFY(gdi_font_blend(0x00FFFFFF, 0x00000000, 128) == 0x007F7F7F);
    /* Zero, partial and full glyph coverage preserve the exact destination alpha, not just opaque alpha. */
    VERIFY(gdi_font_blend(0xA5FFFFFF, 0x00000000, 0) == 0xA5FFFFFF);
    VERIFY(gdi_font_blend(0xA5FFFFFF, 0x00000000, 128) == 0xA57F7F7F);
    VERIFY(gdi_font_blend(0xA5FFFFFF, 0x00000000, 255) == 0xA5000000);
    VERIFY(gdi_font_blend(0x00204060, 0x00E0C0A0, 64) == (((0xE0u * 64 + 0x20u * 191 + 127) / 255) << 16 |
                                                         ((0xC0u * 64 + 0x40u * 191 + 127) / 255) << 8 |
                                                         ((0xA0u * 64 + 0x60u * 191 + 127) / 255)));
    VERIFY(gdi_font_blend(0xFF000000, 0x00FFFFFF, 100) >> 24 == 0xFF);     /* the destination's alpha byte is kept */
    printf("test_font_glyphs: %u checks passed (11172 syllables, ranges %u)\n", checks, gdi_font_range_count);
    return 0;
}
