/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - painting the display list with GDI, and the GDI (and optional DirectWrite) font backends.
 * Owner: L1 (win/paint_gdi.c, win/font_gdi.c, win/font_dwrite.c). Declared by core.
 *
 * Everything here works without a display: painting targets a memory DC with a 32-bpp DIB section selected
 * (snapshot) or whatever DC the caller gives (view_paint, WM_PAINT of the view).
 */
#ifndef SHZ_PAINT_H
#define SHZ_PAINT_H

#include "winglue.h"
#include "../core/font.h"

/* engine.h view_paint: lay out at the width of dest (if the viewport is unset) and paint the document viewport
 * scrolled to (scroll_x, scroll_y) into dest of dc. Also used by the view window (L2) for WM_PAINT. */
HRESULT   shz_paint_to_dc(shz_doc *doc, HDC dc, const RECT *dest, LONG scroll_x, LONG scroll_y);
/* engine.h snapshot: lay out at width (viewport width x height, height 0 = the document height) and render into a new
 * top-down 32-bpp DIB section (0x00RRGGBB). */
HRESULT   shz_paint_snapshot(shz_doc *doc, LONG width, LONG height, HBITMAP *bitmap);
/* The GDI font backend (created on first use); DllMain installs it with shz_font_set_backend. */
shz_font_backend *shz_gdi_font_backend(void);
/* DLL attach / detach (font caches, DirectWrite probing) */
void      shz_paint_process_attach(void);
void      shz_paint_process_detach(void);

#endif /* SHZ_PAINT_H */
