/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - TEMPORARY weak stubs for the Windows L2 API (view.h). Agent L2 deletes each stub as the real
 * function lands (win/view.c) and removes this file when empty.
 */
#include "view.h"

/* ELF (host tests): weak definitions, overridden by the real ones. PE (the DLL): GNU ld cannot resolve a weak
 * definition from another object, so the stubs are plain definitions and build_engine.py localizes (objcopy
 * --localize-symbol) every stub that a real object also defines. */
#ifdef _WIN32
#define SHZ_WEAK
#else
#define SHZ_WEAK __attribute__((weak))
#endif

SHZ_WEAK HRESULT shz_view_create(shz_doc *doc, HWND parent, const RECT *rect, shzeng_view **view)
{
    SHZ_UNUSED(doc); SHZ_UNUSED(parent); SHZ_UNUSED(rect);
    if (view) *view = NULL;
    return E_NOTIMPL;
}

SHZ_WEAK void shz_view_destroy(shzeng_view *view) { SHZ_UNUSED(view); }
SHZ_WEAK HWND shz_view_hwnd(shzeng_view *view) { SHZ_UNUSED(view); return NULL; }
SHZ_WEAK HRESULT shz_view_set_rect(shzeng_view *view, const RECT *rect) { SHZ_UNUSED(view); SHZ_UNUSED(rect); return E_NOTIMPL; }
SHZ_WEAK HRESULT shz_view_show(shzeng_view *view, BOOL show) { SHZ_UNUSED(view); SHZ_UNUSED(show); return E_NOTIMPL; }
SHZ_WEAK HRESULT shz_view_set_parent(shzeng_view *view, HWND parent) { SHZ_UNUSED(view); SHZ_UNUSED(parent); return E_NOTIMPL; }
SHZ_WEAK HRESULT shz_view_focus(shzeng_view *view) { SHZ_UNUSED(view); return E_NOTIMPL; }
SHZ_WEAK HRESULT shz_view_scroll(shzeng_view *view, LONG x, LONG y, BOOL relative)
{ SHZ_UNUSED(view); SHZ_UNUSED(x); SHZ_UNUSED(y); SHZ_UNUSED(relative); return E_NOTIMPL; }
SHZ_WEAK HRESULT shz_view_scroll_pos(shzeng_view *view, LONG *x, LONG *y)
{ SHZ_UNUSED(view); if (x) *x = 0; if (y) *y = 0; return E_NOTIMPL; }
SHZ_WEAK HRESULT shz_view_set_zoom(shzeng_view *view, float zoom) { SHZ_UNUSED(view); SHZ_UNUSED(zoom); return E_NOTIMPL; }
SHZ_WEAK void shz_view_process_attach(void) {}
SHZ_WEAK void shz_view_process_detach(void) {}
