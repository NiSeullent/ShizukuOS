/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CSMWRAP_CP437_H
#define CSMWRAP_CP437_H
#include <stdint.h>

/* One scanline of the 8x16 CP437 glyph. Bit 0 is the leftmost pixel,
 * matching font8x8_basic. row is 0..15. */
uint8_t csm_cp437_row(uint8_t ch, unsigned row);
#endif
