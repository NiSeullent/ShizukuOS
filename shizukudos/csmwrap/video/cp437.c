/* SPDX-License-Identifier: GPL-2.0-only
 * 8x16 CP437 glyphs.
 * ASCII 00h-7Eh is the public-domain 8x8 VGA font, each row doubled.
 * Box drawing (B3h-DAh) and blocks/shades (B0h-B2h, DBh-DFh) are drawn
 * from the CP437 line and block repertoire. Latin letters 80h-A5h use the
 * matching ASCII base plus a diacritic. Remaining symbols are compact
 * approximations, not an IBM VGA ROM dump. 0xFF is the blank CP437 nbsp.
 */
#include "video/cp437.h"
#include "video/font8x8_basic.h"

#define U  0x01u
#define D  0x02u
#define L  0x04u
#define R  0x08u
#define UU 0x10u
#define DD 0x20u
#define LL 0x40u
#define RR 0x80u

/* Flags for B3h..DAh inclusive, in code-point order. */
static const uint8_t k_box[0x28] = {
    /* B3 │ */ U|D,   U|D|L,     U|D|LL,     UU|DD|L,
    /* B7 ╖ */ DD|L,  D|LL,      UU|DD|LL,   UU|DD,
    /* BB ╗ */ DD|LL, UU|LL,     UU|L,       U|LL,
    /* BF ┐ */ D|L,   U|R,       U|L|R,      D|L|R,
    /* C3 ├ */ U|D|R, L|R,       U|D|L|R,    U|D|RR,
    /* C7 ╟ */ UU|DD|R, UU|RR,   DD|RR,      UU|LL|RR,
    /* CB ╦ */ DD|LL|RR, UU|DD|RR, LL|RR,    UU|DD|LL|RR,
    /* CF ╧ */ U|LL|RR, UU|L|R,  D|LL|RR,    DD|L|R,
    /* D3 ╙ */ UU|R,  U|RR,      D|RR,       DD|R,
    /* D7 ╫ */ UU|DD|L|R, U|D|LL|RR, U|L,    D|R
};

enum {
    AC_NONE = 0,
    AC_DIAER,
    AC_ACUTE,
    AC_GRAVE,
    AC_CIRC,
    AC_RING,
    AC_TILDE,
    AC_CEDILLA
};

/* CP437 80h..A5h. */
static const uint8_t k_latin_base[0x26] = {
    'C','u','e','a','a','a','a','c','e','e','e','i','i','i','A','A',
    'E','a','A','o','o','o','u','u','y','O','U','c','P','Y','P','f',
    'a','i','o','u','n','N'
};
static const uint8_t k_latin_acc[0x26] = {
    AC_CEDILLA, AC_DIAER, AC_ACUTE, AC_CIRC, AC_DIAER, AC_GRAVE, AC_RING, AC_CEDILLA,
    AC_CIRC, AC_DIAER, AC_GRAVE, AC_DIAER, AC_CIRC, AC_GRAVE, AC_DIAER, AC_RING,
    AC_ACUTE, AC_NONE, AC_NONE, AC_CIRC, AC_DIAER, AC_GRAVE, AC_CIRC, AC_GRAVE,
    AC_DIAER, AC_DIAER, AC_DIAER, AC_NONE, AC_NONE, AC_NONE, AC_NONE, AC_NONE,
    AC_ACUTE, AC_ACUTE, AC_ACUTE, AC_ACUTE, AC_TILDE, AC_TILDE
};

_Static_assert(sizeof k_box == 0xDA - 0xB3 + 1, "box flag table");
_Static_assert(sizeof k_latin_base == 0xA5 - 0x80 + 1, "latin base table");
_Static_assert(sizeof k_latin_acc == sizeof k_latin_base, "latin accent table");

static uint8_t shade_or_block(uint8_t ch, unsigned row)
{
    if (ch == 0xDB)
        return 0xFF;
    if (ch == 0xDC)
        return row >= 8 ? 0xFF : 0;
    if (ch == 0xDD)
        return 0x0F; /* left half; bit 0 is leftmost */
    if (ch == 0xDE)
        return 0xF0;
    if (ch == 0xDF)
        return row < 8 ? 0xFF : 0;
    if (ch == 0xB0)
        return (row & 3) == 0 ? 0x55 : 0;
    if (ch == 0xB1)
        return (row & 1) ? 0xAA : 0x55;
    if (ch == 0xB2)
        return (row & 1) ? 0xFF : 0xAA;
    return 0;
}

static uint8_t box_row(uint8_t flags, unsigned row)
{
    uint8_t bits = 0;
    int single_v = ((flags & U) && row <= 8) || ((flags & D) && row >= 7);
    int double_v = ((flags & UU) && row <= 10) || ((flags & DD) && row >= 5);
    if (row == 7 || row == 8) {
        if (flags & L)
            bits |= 0x1F;
        if (flags & R)
            bits |= 0xF8;
    }
    if (row == 5 || row == 6 || row == 9 || row == 10) {
        if (flags & LL)
            bits |= 0x3F;
        if (flags & RR)
            bits |= 0xFC;
    }
    if (single_v)
        bits |= 0x18;
    if (double_v)
        bits |= 0x66;
    return bits;
}

static uint8_t accent_bits(uint8_t accent, unsigned font_row)
{
    if (font_row == 0) {
        if (accent == AC_DIAER) return 0x22;
        if (accent == AC_ACUTE) return 0x10;
        if (accent == AC_GRAVE) return 0x04;
        if (accent == AC_CIRC) return 0x1C;
        if (accent == AC_RING) return 0x18;
        if (accent == AC_TILDE) return 0x3C;
    }
    if (font_row == 7 && accent == AC_CEDILLA)
        return 0x18;
    return 0;
}

static uint8_t symbol_row(uint8_t ch, unsigned row)
{
    if (ch == 0xFF)
        return 0;
    if (ch == 0xFE)
        return (row >= 2 && row <= 13) ? 0x7E : 0;
    if (ch == 0xF8 && row < 4)
        return 0x18;
    if ((ch == 0xF9 || ch == 0xFA) && row >= 12)
        return 0x18;
    if (ch == 0xF1) {
        if (row == 6 || row == 10)
            return 0x3C;
        if (row >= 7 && row <= 9)
            return 0x18;
        return 0;
    }
    if (row < 3 || row > 13)
        return 0;
    return (uint8_t)(0x42 | ((ch >> (row & 3)) & 0x18));
}

uint8_t csm_cp437_row(uint8_t ch, unsigned row)
{
    static const uint8_t house[8] = {
        0x18, 0x3C, 0x7E, 0xFF, 0x18, 0x18, 0x3C, 0x7E
    };
    if (row >= 16)
        return 0;
    if (ch < 0x80) {
        unsigned font_row = row >> 1;
        if (ch == 0x7F)
            return house[font_row];
        return font8x8_basic[ch][font_row];
    }
    if (ch >= 0xB0 && ch <= 0xDF) {
        if (ch >= 0xB3 && ch <= 0xDA)
            return box_row(k_box[ch - 0xB3], row);
        return shade_or_block(ch, row);
    }
    if (ch <= 0xA5) {
        unsigned font_row = row >> 1;
        uint8_t base = k_latin_base[ch - 0x80];
        return (uint8_t)(font8x8_basic[base][font_row] |
                         accent_bits(k_latin_acc[ch - 0x80], font_row));
    }
    return symbol_row(ch, row);
}
