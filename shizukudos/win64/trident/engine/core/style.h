/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - cascade and computed style. Owner: L1 (style*.c). Declared by core.
 *
 * L1 keeps the computed style of each element in shz_element.style (struct shz_style_elem, private to L1) and the
 * per-document cascade state in shz_doc.css (struct shz_css_doc). It restyles lazily: shz_render_dom_changed
 * (observe.h) marks what is dirty; shz_layout_update (layout.h) recomputes styles and layout before any query.
 *
 * Quirks (shz_doc_quirks): FULL quirks applies at least the "percentage height of body/html resolves against the
 * viewport" and "table cells do not inherit font size/weight/style/color from outside the table" quirks; LIMITED
 * applies the table-cell line-height quirk only; NONE is standards mode. DESIGN.md section 7 lists what each does.
 */
#ifndef SHZ_STYLE_H
#define SHZ_STYLE_H

#include "dom.h"
#include "observe.h"

typedef enum {
    SHZ_DISPLAY_NONE = 0, SHZ_DISPLAY_INLINE, SHZ_DISPLAY_BLOCK, SHZ_DISPLAY_INLINE_BLOCK, SHZ_DISPLAY_LIST_ITEM,
    SHZ_DISPLAY_TABLE, SHZ_DISPLAY_INLINE_TABLE, SHZ_DISPLAY_TABLE_ROW_GROUP, SHZ_DISPLAY_TABLE_HEADER_GROUP,
    SHZ_DISPLAY_TABLE_FOOTER_GROUP, SHZ_DISPLAY_TABLE_ROW, SHZ_DISPLAY_TABLE_CELL, SHZ_DISPLAY_TABLE_COLUMN_GROUP,
    SHZ_DISPLAY_TABLE_COLUMN, SHZ_DISPLAY_TABLE_CAPTION
} shz_display;

typedef enum { SHZ_WS_NORMAL = 0, SHZ_WS_PRE, SHZ_WS_NOWRAP, SHZ_WS_PRE_WRAP, SHZ_WS_PRE_LINE } shz_white_space;

typedef enum {
    SHZ_CURSOR_AUTO = 0, SHZ_CURSOR_DEFAULT, SHZ_CURSOR_POINTER, SHZ_CURSOR_TEXT, SHZ_CURSOR_WAIT, SHZ_CURSOR_CROSSHAIR,
    SHZ_CURSOR_HELP, SHZ_CURSOR_MOVE, SHZ_CURSOR_NOT_ALLOWED, SHZ_CURSOR_E_RESIZE, SHZ_CURSOR_N_RESIZE,
    SHZ_CURSOR_NE_RESIZE, SHZ_CURSOR_NW_RESIZE
} shz_cursor;

/* Computed values other modules need (up to date: they bring the style of elem current first). For a node that is
 * not an element, or is not connected, the UA default of its tag is returned. */
int       shz_style_display(shz_node *elem);                   /* shz_display */
int       shz_style_white_space(shz_node *elem);               /* shz_white_space */
int       shz_style_cursor(shz_node *elem);                    /* shz_cursor, "auto" resolved (links -> POINTER) */
int       shz_style_visible(shz_node *elem);                   /* visibility: visible (1) / hidden, collapse (0) */

/* observe.h: void shz_render_dom_changed(const shz_chg_info *info); implemented by L1 in style.c */

#endif /* SHZ_STYLE_H */
