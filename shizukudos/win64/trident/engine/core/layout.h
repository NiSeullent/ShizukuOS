/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - layout (box tree, block/inline/table/float/positioned layout) and the geometry entries of
 * engine.h. Owner: L1 (layout*.c). Declared by core.
 *
 * Layout is lazy: every query below first calls shz_layout_update(), which restyles and relayouts what
 * shz_render_dom_changed() marked dirty, for the viewport doc->viewport_w x doc->viewport_h (0 x 0 means 800 x 600,
 * the size used by snapshot when the caller gives none). Box data lives in node->box (struct shz_box, private to
 * L1) and the document state in doc->layout.
 *
 * Coordinates: document space (origin at the initial containing block) unless stated otherwise; SHZ_BOX_BORDER and
 * hit testing use viewport space (document minus doc->scroll_x / scroll_y), as getBoundingClientRect and
 * elementFromPoint require.
 */
#ifndef SHZ_LAYOUT_H
#define SHZ_LAYOUT_H

#include "dom.h"
#include "display_list.h"

/* engine.h shzeng_box values */
enum { SHZ_BOX_OFFSET = 0, SHZ_BOX_CLIENT, SHZ_BOX_SCROLL, SHZ_BOX_BORDER };

shz_res   shz_layout_update(shz_doc *doc);
/* Set the viewport (initial containing block) size; marks layout dirty when it changes. */
void      shz_layout_set_viewport(shz_doc *doc, int32_t width, int32_t height);
/* engine.h elem_box: left/top/right/bottom per shzeng_box (OFFSET: offsetLeft/Top and offsetLeft+Width ...;
 * CLIENT: clientLeft/Top and +clientWidth/Height; SCROLL: scrollLeft/Top and +scrollWidth/Height). An element
 * without a box (display: none, not connected) gives an all-zero rectangle and SHZ_OK. */
shz_res   shz_layout_elem_box(shz_node *elem, int which, shz_irect *out);
shz_res   shz_layout_offset_parent(shz_node *elem, shz_node **out);            /* no reference; SHZ_FALSE + NULL */
uint32_t  shz_layout_client_rects(shz_node *elem, shz_irect *rects, uint32_t max);   /* viewport space; count */
shz_res   shz_layout_set_scroll(shz_node *elem, int32_t x, int32_t y);         /* element (or root: viewport) scroll */
shz_res   shz_layout_scroll_into_view(shz_node *elem, int align_top);
/* elementFromPoint: innermost element whose border box contains the viewport point (no reference; SHZ_FALSE). */
shz_res   shz_layout_hit_test(shz_doc *doc, int32_t x, int32_t y, shz_node **out);
shz_res   shz_layout_content_size(shz_doc *doc, int32_t *width, int32_t *height);

/* Detailed hit test for the view (L2): document coordinates. */
typedef struct shz_hit {
    shz_node *element;                  /* innermost element (NULL outside the document) */
    shz_node *link;                     /* nearest <a href>/<area href> ancestor, or NULL */
    shz_node *text;                     /* text node under the point, or NULL */
    uint32_t text_offset;               /* character offset inside text / inside a text control's value */
    int32_t local_x, local_y;           /* point relative to element's border box */
} shz_hit;
shz_res   shz_layout_hit(shz_doc *doc, int32_t doc_x, int32_t doc_y, shz_hit *out);

/* The display list for the document area (document space; NULL = everything). The caller frees it with
 * shz_dl_free. Includes focus ring and caret for doc->focus (L2 state). */
shz_res   shz_layout_display_list(shz_doc *doc, const shz_irect *area, shz_display_list *out);
/* Caret rectangle (document space) of a focused text control at character offset. */
shz_res   shz_layout_caret_rect(shz_node *ctl, uint32_t offset, shz_irect *out);
/* Character offset in a text control for a point relative to its border box (click-to-place-caret). */
uint32_t  shz_layout_ctl_offset_at(shz_node *ctl, int32_t local_x, int32_t local_y);

#endif /* SHZ_LAYOUT_H */
