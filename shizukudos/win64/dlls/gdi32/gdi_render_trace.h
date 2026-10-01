/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_GDI_RENDER_TRACE_H
#define SHZ_GDI_RENDER_TRACE_H
/* Caller holds the ordinary GDI lock; diagnostics preserve thread LastError. */
void gdi_render_trace_dib(bitmap_t *b, HBITMAP handle);
void gdi_render_trace_blit(dc_t *dst, const bitmap_t *source, const gctx_t *ctx,
    int x, int y, int w, int h, int sx, int sy, int sw, int sh, DWORD rop);
void gdi_render_trace_present(backing_t *b, const RECT *rect, int32_t status);
#endif
