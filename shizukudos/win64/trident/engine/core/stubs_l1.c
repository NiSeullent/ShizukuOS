/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - TEMPORARY weak stubs for the portable L1 API (css.h, style.h, layout.h, display_list.h and
 * shz_render_dom_changed). Agent L1 deletes each stub as the real function lands and removes this file when empty.
 * A real definition elsewhere replaces the stub here (see SHZ_WEAK), so implementing a function never breaks the build.
 */
#include "css.h"
#include "style.h"
#include "layout.h"
#include "display_list.h"

/* ELF (host tests): weak definitions, overridden by the real ones. PE (the DLL): GNU ld cannot resolve a weak
 * definition from another object, so the stubs are plain definitions and build_engine.py localizes (objcopy
 * --localize-symbol) every stub that a real object also defines. */
#ifdef _WIN32
#define SHZ_WEAK
#else
#define SHZ_WEAK __attribute__((weak))
#endif

/* ---- observe.h */
SHZ_WEAK void shz_render_dom_changed(const shz_chg_info *info) { SHZ_UNUSED(info); }

/* ---- style.h: UA defaults by tag until the cascade exists */
SHZ_WEAK int shz_style_display(shz_node *elem)
{
    int tag = shz_tag_of(elem);
    unsigned flags = shz_tag_flags(tag);
    if (!elem || elem->type != SHZ_ELEMENT_NODE) return SHZ_DISPLAY_INLINE;
    switch (tag) {
    case SHZ_TAG_LI: return SHZ_DISPLAY_LIST_ITEM;
    case SHZ_TAG_TABLE: return SHZ_DISPLAY_TABLE;
    case SHZ_TAG_CAPTION: return SHZ_DISPLAY_TABLE_CAPTION;
    case SHZ_TAG_THEAD: return SHZ_DISPLAY_TABLE_HEADER_GROUP;
    case SHZ_TAG_TBODY: return SHZ_DISPLAY_TABLE_ROW_GROUP;
    case SHZ_TAG_TFOOT: return SHZ_DISPLAY_TABLE_FOOTER_GROUP;
    case SHZ_TAG_TR: return SHZ_DISPLAY_TABLE_ROW;
    case SHZ_TAG_TD: case SHZ_TAG_TH: return SHZ_DISPLAY_TABLE_CELL;
    case SHZ_TAG_COL: return SHZ_DISPLAY_TABLE_COLUMN;
    case SHZ_TAG_COLGROUP: return SHZ_DISPLAY_TABLE_COLUMN_GROUP;
    default: break;
    }
    if (flags & SHZ_TF_HIDDEN) return SHZ_DISPLAY_NONE;
    if (flags & SHZ_TF_BLOCK) return SHZ_DISPLAY_BLOCK;
    return SHZ_DISPLAY_INLINE;
}

SHZ_WEAK int shz_style_white_space(shz_node *elem)
{
    switch (shz_tag_of(elem)) {
    case SHZ_TAG_PRE: case SHZ_TAG_LISTING: case SHZ_TAG_PLAINTEXT: case SHZ_TAG_XMP: case SHZ_TAG_TEXTAREA:
        return SHZ_WS_PRE;
    case SHZ_TAG_NOBR:
        return SHZ_WS_NOWRAP;
    default:
        return SHZ_WS_NORMAL;
    }
}

SHZ_WEAK int shz_style_cursor(shz_node *elem) { SHZ_UNUSED(elem); return SHZ_CURSOR_AUTO; }
SHZ_WEAK int shz_style_visible(shz_node *elem) { SHZ_UNUSED(elem); return 1; }

/* ---- css.h */
SHZ_WEAK shz_res shz_css_inline_style(shz_node *elem, shz_style **out) { SHZ_UNUSED(elem); *out = NULL; return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_css_computed_style(shz_node *elem, const shz_char *pseudo, shz_style **out)
{ SHZ_UNUSED(elem); SHZ_UNUSED(pseudo); *out = NULL; return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_css_style_get(shz_style *s, const shz_char *p, shz_char **v) { SHZ_UNUSED(s); SHZ_UNUSED(p); *v = NULL; return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_css_style_get_priority(shz_style *s, const shz_char *p, shz_char **v) { SHZ_UNUSED(s); SHZ_UNUSED(p); *v = NULL; return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_css_style_set(shz_style *s, const shz_char *p, const shz_char *v, const shz_char *prio)
{ SHZ_UNUSED(s); SHZ_UNUSED(p); SHZ_UNUSED(v); SHZ_UNUSED(prio); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_css_style_remove(shz_style *s, const shz_char *p) { SHZ_UNUSED(s); SHZ_UNUSED(p); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_css_style_text(shz_style *s, shz_char **t) { SHZ_UNUSED(s); *t = NULL; return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_css_style_set_text(shz_style *s, const shz_char *t) { SHZ_UNUSED(s); SHZ_UNUSED(t); return SHZ_E_NOTIMPL; }
SHZ_WEAK uint32_t shz_css_style_length(shz_style *s) { SHZ_UNUSED(s); return 0; }
SHZ_WEAK shz_res shz_css_style_item(shz_style *s, uint32_t i, shz_char **p) { SHZ_UNUSED(s); SHZ_UNUSED(i); *p = NULL; return SHZ_E_NOTIMPL; }
SHZ_WEAK void shz_css_style_addref(shz_style *s) { SHZ_UNUSED(s); }
SHZ_WEAK void shz_css_style_release(shz_style *s) { SHZ_UNUSED(s); }
SHZ_WEAK uint32_t shz_css_sheet_count(shz_doc *doc) { SHZ_UNUSED(doc); return 0; }
SHZ_WEAK shz_res shz_css_sheet_at(shz_doc *doc, uint32_t i, shz_sheet **out) { SHZ_UNUSED(doc); SHZ_UNUSED(i); *out = NULL; return SHZ_E_NOTIMPL; }
SHZ_WEAK uint32_t shz_css_sheet_rule_count(shz_sheet *s) { SHZ_UNUSED(s); return 0; }
SHZ_WEAK shz_res shz_css_sheet_rule_text(shz_sheet *s, uint32_t i, shz_char **t) { SHZ_UNUSED(s); SHZ_UNUSED(i); *t = NULL; return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_css_sheet_rule_style(shz_sheet *s, uint32_t i, shz_char **sel, shz_style **st)
{ SHZ_UNUSED(s); SHZ_UNUSED(i); *sel = NULL; *st = NULL; return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_css_sheet_insert_rule(shz_sheet *s, const shz_char *r, uint32_t i) { SHZ_UNUSED(s); SHZ_UNUSED(r); SHZ_UNUSED(i); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_css_sheet_delete_rule(shz_sheet *s, uint32_t i) { SHZ_UNUSED(s); SHZ_UNUSED(i); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_css_sheet_href(shz_sheet *s, shz_char **h) { SHZ_UNUSED(s); *h = NULL; return SHZ_E_NOTIMPL; }
SHZ_WEAK void shz_css_sheet_addref(shz_sheet *s) { SHZ_UNUSED(s); }
SHZ_WEAK void shz_css_sheet_release(shz_sheet *s) { SHZ_UNUSED(s); }
SHZ_WEAK shz_res shz_css_media_matches(shz_doc *doc, const shz_char *q, int *r) { SHZ_UNUSED(doc); SHZ_UNUSED(q); *r = 0; return SHZ_E_NOTIMPL; }

/* ---- layout.h */
SHZ_WEAK shz_res shz_layout_update(shz_doc *doc) { SHZ_UNUSED(doc); return SHZ_E_NOTIMPL; }
SHZ_WEAK void shz_layout_set_viewport(shz_doc *doc, int32_t w, int32_t h) { doc->viewport_w = w; doc->viewport_h = h; }
SHZ_WEAK shz_res shz_layout_elem_box(shz_node *e, int which, shz_irect *out)
{ SHZ_UNUSED(e); SHZ_UNUSED(which); memset(out, 0, sizeof(*out)); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_layout_offset_parent(shz_node *e, shz_node **out) { SHZ_UNUSED(e); *out = NULL; return SHZ_E_NOTIMPL; }
SHZ_WEAK uint32_t shz_layout_client_rects(shz_node *e, shz_irect *r, uint32_t max) { SHZ_UNUSED(e); SHZ_UNUSED(r); SHZ_UNUSED(max); return 0; }
SHZ_WEAK shz_res shz_layout_set_scroll(shz_node *e, int32_t x, int32_t y) { SHZ_UNUSED(e); SHZ_UNUSED(x); SHZ_UNUSED(y); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_layout_scroll_into_view(shz_node *e, int top) { SHZ_UNUSED(e); SHZ_UNUSED(top); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_layout_hit_test(shz_doc *doc, int32_t x, int32_t y, shz_node **out)
{ SHZ_UNUSED(doc); SHZ_UNUSED(x); SHZ_UNUSED(y); *out = NULL; return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_layout_content_size(shz_doc *doc, int32_t *w, int32_t *h) { SHZ_UNUSED(doc); *w = *h = 0; return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_layout_hit(shz_doc *doc, int32_t x, int32_t y, shz_hit *out)
{ SHZ_UNUSED(doc); SHZ_UNUSED(x); SHZ_UNUSED(y); memset(out, 0, sizeof(*out)); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_layout_display_list(shz_doc *doc, const shz_irect *area, shz_display_list *out)
{ SHZ_UNUSED(doc); SHZ_UNUSED(area); SHZ_UNUSED(out); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_layout_caret_rect(shz_node *ctl, uint32_t off, shz_irect *out)
{ SHZ_UNUSED(ctl); SHZ_UNUSED(off); memset(out, 0, sizeof(*out)); return SHZ_E_NOTIMPL; }
SHZ_WEAK uint32_t shz_layout_ctl_offset_at(shz_node *ctl, int32_t x, int32_t y) { SHZ_UNUSED(ctl); SHZ_UNUSED(x); SHZ_UNUSED(y); return 0; }

/* ---- display_list.h */
SHZ_WEAK void shz_dl_init(shz_display_list *dl) { memset(dl, 0, sizeof(*dl)); }
SHZ_WEAK void shz_dl_free(shz_display_list *dl) { SHZ_UNUSED(dl); }
SHZ_WEAK shz_dl_item *shz_dl_push(shz_display_list *dl, int kind) { SHZ_UNUSED(dl); SHZ_UNUSED(kind); return NULL; }
SHZ_WEAK uint32_t shz_dl_add_text(shz_display_list *dl, const shz_char *s, size_t n) { SHZ_UNUSED(dl); SHZ_UNUSED(s); SHZ_UNUSED(n); return 0; }
