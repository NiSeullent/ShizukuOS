/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - the view window ("ShizukuTridentView"): a WS_CHILD window presenting a document, double
 * buffered through a DIB section, with its own scroll bars, input turned into DOM events, focus and caret.
 * Owner: L2 (win/view.c). Declared by core.
 *
 * struct shzeng_view is defined by L2. A view holds a document reference (shz_doc_addref) while it exists.
 */
#ifndef SHZ_VIEW_H
#define SHZ_VIEW_H

#include "winglue.h"

HRESULT   shz_view_create(shz_doc *doc, HWND parent, const RECT *rect, shzeng_view **view);
void      shz_view_destroy(shzeng_view *view);
HWND      shz_view_hwnd(shzeng_view *view);
HRESULT   shz_view_set_rect(shzeng_view *view, const RECT *rect);
HRESULT   shz_view_show(shzeng_view *view, BOOL show);
HRESULT   shz_view_set_parent(shzeng_view *view, HWND parent);
HRESULT   shz_view_focus(shzeng_view *view);
HRESULT   shz_view_scroll(shzeng_view *view, LONG x, LONG y, BOOL relative);
HRESULT   shz_view_scroll_pos(shzeng_view *view, LONG *x, LONG *y);
HRESULT   shz_view_set_zoom(shzeng_view *view, float zoom);
/* DLL attach / detach: register / unregister the window class */
void      shz_view_process_attach(void);
void      shz_view_process_detach(void);

#endif /* SHZ_VIEW_H */
