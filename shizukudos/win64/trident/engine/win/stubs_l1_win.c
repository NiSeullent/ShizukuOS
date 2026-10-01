/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - TEMPORARY weak stubs for the Windows L1 API (paint.h). Agent L1 deletes each stub as the
 * real function lands (win/paint_gdi.c, win/font_gdi.c) and removes this file when empty.
 */
#include "paint.h"

/* ELF (host tests): weak definitions, overridden by the real ones. PE (the DLL): GNU ld cannot resolve a weak
 * definition from another object, so the stubs are plain definitions and build_engine.py localizes (objcopy
 * --localize-symbol) every stub that a real object also defines. */
#ifdef _WIN32
#define SHZ_WEAK
#else
#define SHZ_WEAK __attribute__((weak))
#endif

SHZ_WEAK HRESULT shz_paint_to_dc(shz_doc *doc, HDC dc, const RECT *dest, LONG scroll_x, LONG scroll_y)
{
    SHZ_UNUSED(doc); SHZ_UNUSED(dc); SHZ_UNUSED(dest); SHZ_UNUSED(scroll_x); SHZ_UNUSED(scroll_y);
    return E_NOTIMPL;
}

SHZ_WEAK HRESULT shz_paint_snapshot(shz_doc *doc, LONG width, LONG height, HBITMAP *bitmap)
{
    SHZ_UNUSED(doc); SHZ_UNUSED(width); SHZ_UNUSED(height);
    if (bitmap) *bitmap = NULL;
    return E_NOTIMPL;
}

SHZ_WEAK shz_font_backend *shz_gdi_font_backend(void)
{
    return NULL;                        /* the fixed 8x16 model stays in use */
}

SHZ_WEAK void shz_paint_process_attach(void) {}
SHZ_WEAK void shz_paint_process_detach(void) {}
