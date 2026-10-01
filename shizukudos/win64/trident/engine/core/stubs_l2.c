/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - TEMPORARY weak stubs for the portable L2 API (events.h, forms.h, image.h, loader.h and
 * shz_interact_dom_changed). Agent L2 deletes each stub as the real function lands and removes this file when empty.
 * A real definition elsewhere replaces the stub here (see SHZ_WEAK), so implementing a function never breaks the build.
 */
#include "events.h"
#include "forms.h"
#include "image.h"
#include "loader.h"
#include "observe.h"

/* ELF (host tests): weak definitions, overridden by the real ones. PE (the DLL): GNU ld cannot resolve a weak
 * definition from another object, so the stubs are plain definitions and build_engine.py localizes (objcopy
 * --localize-symbol) every stub that a real object also defines. */
#ifdef _WIN32
#define SHZ_WEAK
#else
#define SHZ_WEAK __attribute__((weak))
#endif

/* ---- observe.h */
SHZ_WEAK void shz_interact_dom_changed(const shz_chg_info *info) { SHZ_UNUSED(info); }

/* ---- events.h */
SHZ_WEAK shz_res shz_events_add_listener(shz_doc *d, shz_node *t, const shz_char *ty, int c, void *k)
{ SHZ_UNUSED(d); SHZ_UNUSED(t); SHZ_UNUSED(ty); SHZ_UNUSED(c); SHZ_UNUSED(k); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_events_remove_listener(shz_doc *d, shz_node *t, const shz_char *ty, int c, void *k)
{ SHZ_UNUSED(d); SHZ_UNUSED(t); SHZ_UNUSED(ty); SHZ_UNUSED(c); SHZ_UNUSED(k); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_events_dispatch_synthetic(shz_doc *d, shz_node *t, const shz_char *ty, int b, int c, int *p)
{ SHZ_UNUSED(d); SHZ_UNUSED(t); SHZ_UNUSED(ty); SHZ_UNUSED(b); SHZ_UNUSED(c); if (p) *p = 0; return SHZ_E_NOTIMPL; }
SHZ_WEAK void shz_event_addref(shz_event *ev) { SHZ_UNUSED(ev); }
SHZ_WEAK void shz_event_release(shz_event *ev) { SHZ_UNUSED(ev); }
SHZ_WEAK shz_res shz_events_click(shz_node *e) { SHZ_UNUSED(e); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_events_focus(shz_node *e) { SHZ_UNUSED(e); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_events_blur(shz_node *e) { SHZ_UNUSED(e); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_events_active_element(shz_doc *d, shz_node **out) { SHZ_UNUSED(d); *out = NULL; return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_event *shz_event_new(shz_doc *d, const char *ty, int k, shz_node *t, int b, int c, int tr)
{ SHZ_UNUSED(d); SHZ_UNUSED(ty); SHZ_UNUSED(k); SHZ_UNUSED(t); SHZ_UNUSED(b); SHZ_UNUSED(c); SHZ_UNUSED(tr); return NULL; }
SHZ_WEAK shz_res shz_events_dispatch(shz_event *ev, int *p) { SHZ_UNUSED(ev); if (p) *p = 0; return SHZ_E_NOTIMPL; }
SHZ_WEAK void shz_events_fire(shz_doc *d, shz_node *t, const char *ty, int b, int c)
{ SHZ_UNUSED(d); SHZ_UNUSED(t); SHZ_UNUSED(ty); SHZ_UNUSED(b); SHZ_UNUSED(c); }
SHZ_WEAK int shz_events_has_listener(shz_doc *d, const char *ty) { SHZ_UNUSED(d); SHZ_UNUSED(ty); return 0; }

/* ---- forms.h */
SHZ_WEAK shz_res shz_forms_get_value(shz_node *c, shz_char **v) { SHZ_UNUSED(c); *v = NULL; return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_forms_set_value(shz_node *c, const shz_char *v) { SHZ_UNUSED(c); SHZ_UNUSED(v); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_forms_get_checked(shz_node *c, int *v) { SHZ_UNUSED(c); *v = 0; return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_forms_set_checked(shz_node *c, int v) { SHZ_UNUSED(c); SHZ_UNUSED(v); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_forms_select_get_index(shz_node *s, long *i) { SHZ_UNUSED(s); *i = -1; return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_forms_select_set_index(shz_node *s, long i) { SHZ_UNUSED(s); SHZ_UNUSED(i); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_forms_submission(shz_node *f, shz_node *s, shz_form_submission *out)
{ SHZ_UNUSED(f); SHZ_UNUSED(s); memset(out, 0, sizeof(*out)); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_forms_reset(shz_node *f) { SHZ_UNUSED(f); return SHZ_E_NOTIMPL; }
SHZ_WEAK int shz_forms_is_checked(shz_node *e)
{
    if (shz_is_tag(e, SHZ_TAG_INPUT)) return shz_elem_has_attr(e, SHZ_ATTR_CHECKED);
    if (shz_is_tag(e, SHZ_TAG_OPTION)) return shz_elem_has_attr(e, SHZ_ATTR_SELECTED);
    return 0;
}
SHZ_WEAK int shz_forms_ctl_kind(shz_node *e) { SHZ_UNUSED(e); return SHZ_CTL_NONE; }
SHZ_WEAK shz_res shz_forms_render_info(shz_node *c, shz_ctl_render *out) { SHZ_UNUSED(c); memset(out, 0, sizeof(*out)); return SHZ_E_NOTIMPL; }
SHZ_WEAK void shz_forms_render_info_free(shz_ctl_render *info) { SHZ_UNUSED(info); }
SHZ_WEAK shz_res shz_forms_edit_insert(shz_node *c, const shz_char *t, size_t n) { SHZ_UNUSED(c); SHZ_UNUSED(t); SHZ_UNUSED(n); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_forms_edit_delete(shz_node *c, int d) { SHZ_UNUSED(c); SHZ_UNUSED(d); return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_res shz_forms_set_caret(shz_node *c, uint32_t o) { SHZ_UNUSED(c); SHZ_UNUSED(o); return SHZ_E_NOTIMPL; }

/* ---- image.h */
SHZ_WEAK shz_res shz_image_decode(const uint8_t *d, size_t n, shz_image **out) { SHZ_UNUSED(d); SHZ_UNUSED(n); *out = NULL; return SHZ_E_NOTIMPL; }
SHZ_WEAK void shz_image_addref(shz_image *img) { SHZ_UNUSED(img); }
SHZ_WEAK void shz_image_release(shz_image *img) { SHZ_UNUSED(img); }
SHZ_WEAK shz_res shz_image_state(shz_node *e, int *c, int32_t *w, int32_t *h)
{ SHZ_UNUSED(e); *c = 0; *w = *h = 0; return SHZ_E_NOTIMPL; }
SHZ_WEAK shz_image *shz_image_of(shz_node *e) { SHZ_UNUSED(e); return NULL; }

/* ---- loader.h: the minimal sequence so parse_done / load_done reach the host before L2 lands */
SHZ_WEAK void shz_load_parser_started(shz_doc *doc)
{
    doc->ready_state = SHZ_READY_LOADING;
}

SHZ_WEAK void shz_load_check_complete(shz_doc *doc)
{
    if (doc->ready_state != SHZ_READY_INTERACTIVE || doc->fetch_pending || doc->parser) return;
    doc->ready_state = SHZ_READY_COMPLETE;
    if (doc->hooks && doc->hooks->load_done) doc->hooks->load_done(doc->hooks_ctx, doc);
}

SHZ_WEAK void shz_load_parser_finished(shz_doc *doc)
{
    doc->ready_state = SHZ_READY_INTERACTIVE;
    if (doc->hooks && doc->hooks->parse_done) doc->hooks->parse_done(doc->hooks_ctx, doc);
    shz_load_check_complete(doc);
}

SHZ_WEAK void shz_doc_invalidate(shz_doc *doc, const shz_irect *rect)
{
    if (doc->hooks && doc->hooks->invalidate) doc->hooks->invalidate(doc->hooks_ctx, doc, rect);
}
