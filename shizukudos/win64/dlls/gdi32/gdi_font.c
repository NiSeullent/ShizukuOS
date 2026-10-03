/* SPDX-License-Identifier: GPL-2.0-only
 * Glyph lookup of the built-in gdi32 bitmap font (see gdi_font.h). No Windows headers: also linked by the host test
 * tests/test_font_glyphs.c. */
#include "gdi_font.h"
#include "../../../supervisor/src/font8x8_basic.h"

/* East Asian Wide / Fullwidth blocks (UAX #11, coarse): a missing glyph in these gets the wide notdef box */
static int east_asian_wide(unsigned ch)
{
    return (ch >= 0x1100 && ch <= 0x115F) || (ch >= 0x2E80 && ch <= 0x303E) || (ch >= 0x3041 && ch <= 0x33FF) ||
           (ch >= 0x3400 && ch <= 0x4DBF) || (ch >= 0x4E00 && ch <= 0x9FFF) || (ch >= 0xA000 && ch <= 0xA4CF) ||
           (ch >= 0xA960 && ch <= 0xA97F) || (ch >= 0xAC00 && ch <= 0xD7A3) || (ch >= 0xF900 && ch <= 0xFAFF) ||
           (ch >= 0xFE30 && ch <= 0xFE4F) || (ch >= 0xFF00 && ch <= 0xFF60) || (ch >= 0xFFE0 && ch <= 0xFFE6);
}

static const gdi_font_range_t *find_range(unsigned ch)
{
    unsigned lo = 0, hi = gdi_font_range_count;
    while (lo < hi) {
        const unsigned mid = (lo + hi) / 2;
        const gdi_font_range_t *r = &gdi_font_ranges[mid];
        if (ch < r->first) hi = mid;
        else if (ch > r->last) lo = mid + 1;
        else return r;
    }
    return 0;
}

static void set_box(gdi_glyph_t *g, int wide)
{
    g->kind = GDI_GLYPH_BOX;
    g->width = wide ? GDI_FONT_WIDE : GDI_FONT_NARROW;
    g->index = wide ? 1 : 0;
    g->bits = 0;
}

unsigned gdi_font_glyph(unsigned ch, gdi_glyph_t *g)
{
    const gdi_font_range_t *r;
    ch &= 0xffff;
    if (ch < 0x80) {
        g->kind = GDI_GLYPH_ASCII;
        g->width = GDI_FONT_NARROW;
        g->index = ch < 0x20 ? 0x20 : ch;                          /* control codes draw as a blank cell, as before */
        g->bits = font8x8_basic[g->index];
        return g->index;
    }
    if (ch >= 0xDC00 && ch <= 0xDFFF) {                            /* low surrogate: its pair's box is already drawn */
        g->kind = GDI_GLYPH_EMPTY; g->width = 0; g->index = 2; g->bits = 0;
        return 2;
    }
    if (ch >= 0xD800 && ch <= 0xDBFF) { set_box(g, 1); return g->index; }
    r = find_range(ch);
    if (!r) { set_box(g, east_asian_wide(ch)); return g->index; }
    {
        /* ordinal of this glyph among all data glyphs: ranges are in code point order and their offsets accumulate */
        const unsigned row_bytes = r->width / 8u, k = ch - r->first;
        unsigned ordinal = 0, i;
        for (i = 0; &gdi_font_ranges[i] != r; ++i) ordinal += gdi_font_ranges[i].last - gdi_font_ranges[i].first + 1u;
        g->kind = GDI_GLYPH_DATA;
        g->width = r->width;
        g->index = 0x100 + ordinal + k;
        g->bits = gdi_font_bits + r->offset + k * row_bytes * GDI_FONT_CELL_H;
        return g->index;
    }
}

int gdi_font_glyph_by_index(unsigned index, gdi_glyph_t *g)
{
    unsigned i, base = 0x100;
    if (index == 0 || index == 1) { set_box(g, (int)index); return 1; }
    if (index == 2) { g->kind = GDI_GLYPH_EMPTY; g->width = 0; g->index = 2; g->bits = 0; return 1; }
    if (index >= 0x20 && index < 0x80) { gdi_font_glyph(index, g); return 1; }
    for (i = 0; i < gdi_font_range_count && index >= base; ++i) {
        const gdi_font_range_t *r = &gdi_font_ranges[i];
        const unsigned n = r->last - r->first + 1u;
        if (index < base + n) { gdi_font_glyph(r->first + (index - base), g); return 1; }
        base += n;
    }
    return 0;
}

uint32_t gdi_font_row(const gdi_glyph_t *g, int row)
{
    if (row < 0 || row >= GDI_FONT_CELL_H) return 0;
    switch (g->kind) {
    case GDI_GLYPH_ASCII:
        return g->bits[row >> 1];
    case GDI_GLYPH_DATA:
        return g->width == GDI_FONT_WIDE ? (uint32_t)g->bits[row * 2] | (uint32_t)g->bits[row * 2 + 1] << 8 : g->bits[row];
    case GDI_GLYPH_BOX: {                                          /* hollow rectangle, rows 2..13, one pixel inset */
        const uint32_t full = ((1u << (g->width - 2)) - 1u) << 1, sides = 1u << 1 | 1u << (g->width - 2);
        if (row < 2 || row > 13) return 0;
        return row == 2 || row == 13 ? full : sides;
    }
    default:
        return 0;
    }
}

int gdi_font_has_glyph(unsigned ch)
{
    gdi_glyph_t g;
    gdi_font_glyph(ch, &g);
    return g.kind == GDI_GLYPH_ASCII ? ch >= 0x20 && ch < 0x7f : g.kind == GDI_GLYPH_DATA;
}

int gdi_font_advance(unsigned ch)
{
    gdi_glyph_t g;
    gdi_font_glyph(ch, &g);
    return g.width;
}

/* source pixel (col, row) of the glyph, 0 outside the cell; bold smears one source pixel to the right */
static int src_on(const gdi_glyph_t *g, int col, int row, int bold)
{
    uint32_t bits;
    if (row < 0 || row >= GDI_FONT_CELL_H || col < 0 || col >= g->width + (bold ? 1 : 0)) return 0;
    bits = gdi_font_row(g, row);
    return (int)((bits >> col) & 1) | (bold && col > 0 ? (int)((bits >> (col - 1)) & 1) : 0);
}

int gdi_font_scaled(int units, int num, int den)
{
    return den > 0 && num > 0 ? (units * num + den - 1) / den : 0;
}

/* Integer arithmetic. A sample at output position o + (i + 0.5)/SS maps to source u = that * den / num; with
 * D = 2*SS*num, u*D = (2*SS*o + 2*i + 1) * den. Pixel centres are at k + 0.5, so t = u*D - D/2 locates the sample
 * between centre k0 = floor(t / D) and k0 + 1 with fraction f = t - k0*D (0 <= f < D). The bilinear value times D*D is
 * compared against D*D/2. */
unsigned gdi_font_coverage(const gdi_glyph_t *g, int num, int den, int bold, int ox, int oy)
{
    const long long D = 2LL * GDI_FONT_AA_SS * num;
    unsigned inside = 0;
    int i, j;
    if (num <= 0 || den <= 0 || g->kind == GDI_GLYPH_EMPTY) return 0;
    for (j = 0; j < GDI_FONT_AA_SS; ++j) {
        const long long ty = (2LL * GDI_FONT_AA_SS * oy + 2 * j + 1) * den - D / 2;
        const long long ky = ty >= 0 ? ty / D : -((-ty + D - 1) / D), fy = ty - ky * D;
        for (i = 0; i < GDI_FONT_AA_SS; ++i) {
            const long long tx = (2LL * GDI_FONT_AA_SS * ox + 2 * i + 1) * den - D / 2;
            const long long kx = tx >= 0 ? tx / D : -((-tx + D - 1) / D), fx = tx - kx * D;
            const int a = src_on(g, (int)kx, (int)ky, bold), b = src_on(g, (int)kx + 1, (int)ky, bold);
            const int c = src_on(g, (int)kx, (int)ky + 1, bold), d = src_on(g, (int)kx + 1, (int)ky + 1, bold);
            const long long v = (a * (D - fx) + b * fx) * (D - fy) + (c * (D - fx) + d * fx) * fy;
            if (2 * v >= D * D) ++inside;
        }
    }
    return (inside * 255u + (GDI_FONT_AA_SS * GDI_FONT_AA_SS) / 2) / (GDI_FONT_AA_SS * GDI_FONT_AA_SS);
}

uint32_t gdi_font_blend(uint32_t dst, uint32_t fg, unsigned a)
{
    uint32_t out = dst & 0xff000000u;
    int sh;
    if (a >= 255) return (fg & 0x00ffffffu) | out;
    if (!a) return dst;
    for (sh = 0; sh < 24; sh += 8) {
        const unsigned f = (fg >> sh) & 0xff, d = (dst >> sh) & 0xff;
        out |= ((f * a + d * (255u - a) + 127u) / 255u) << sh;
    }
    return out;
}
