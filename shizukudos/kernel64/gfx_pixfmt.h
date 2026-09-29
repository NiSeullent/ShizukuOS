/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 display: conversion of back-buffer rows to the pixel layouts a boot framebuffer can have. Kept free of kernel
 * dependencies (the includer provides uint32_t) so that tests/run_k64_gop.py compiles and checks it on the host.
 *
 * The back buffer holds 0x00RRGGBB dwords, i.e. bytes B,G,R,X in memory: exactly UEFI GOP PixelBlueGreenRedReserved8BitPerColor
 * (SHZ_FB_BGRX8888), which is copied unchanged. PixelRedGreenBlueReserved8BitPerColor (SHZ_FB_RGBX8888) wants bytes R,G,B,X,
 * i.e. the dword 0x00BBGGRR: red and blue swap places. The X byte is written as 0.
 */
#ifndef K64_GFX_PIXFMT_H
#define K64_GFX_PIXFMT_H

static inline uint32_t gfx_px_to_rgbx(uint32_t v) { return (v & 0x0000ff00u) | ((v >> 16) & 0xffu) | ((v & 0xffu) << 16); }
static inline uint32_t gfx_px_to_bgrx(uint32_t v) { return v & 0x00ffffffu; }

/* one row of `n` pixels; `rgbx` selects the layout */
static inline void gfx_row_convert(volatile uint32_t *dst, const uint32_t *src, int n, int rgbx)
{
    int i;
    if (rgbx) for (i = 0; i < n; ++i) dst[i] = gfx_px_to_rgbx(src[i]);
    else for (i = 0; i < n; ++i) dst[i] = gfx_px_to_bgrx(src[i]);
}
#endif
