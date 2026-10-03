/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel caption metrics for the shared GDI32 glyphs. No allocation or Windows imports.
 */
#ifndef K64_GFX_FB_H
#define K64_GFX_FB_H
#include <stdint.h>

/* Width of n UTF-16 units at the caption's native 16-pixel height: ASCII 8, Hangul 16.
 * Matches gfx_text(), including the shared font's missing-glyph and surrogate rules.
 * A null string measures zero; widths above INT32_MAX saturate there. */
int gfx_text_width(const uint16_t *s, unsigned n);
#endif
