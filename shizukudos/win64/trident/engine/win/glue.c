/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - the engine.h vtable: every entry adapts engine.h types (WCHAR, HRESULT, BOOL, RECT, handles)
 * to the portable core or to the L1/L2 modules. Owner: core. The handle types are the core structures themselves
 * (see core/dom.h), so nodes, lists, events and ranges pass through unchanged.
 *
 * Reference conventions (engine.h): every node / list / style / event / range handed out carries one new reference;
 * strings are shz_alloc'ed and released by str_free (= shz_free); "no value" is NULL + S_FALSE.
 */
#include "winglue.h"
#include "../core/html_parser.h"
#include "../core/serialize.h"
#include "../core/selectors.h"
#include "../core/range.h"
#include "../core/fetch.h"
#include "../core/css.h"
#include "../core/style.h"
#include "../core/layout.h"
#include "../core/events.h"
#include "../core/forms.h"
#include "../core/image.h"
#include "../core/observe.h"
#include "paint.h"
#include "view.h"

/* ---------------------------------------------------------------------------------------------------- helpers */

static HRESULT ret_str(shz_char *s, WCHAR **out)
{
    *out = shz_to_w(s);
    return s ? S_OK : E_OUTOFMEMORY;
}

/* NULL string = "no value" */
static HRESULT ret_str_opt(shz_char *s, WCHAR **out)
{
    *out = shz_to_w(s);
    return s ? S_OK : S_FALSE;
}

static HRESULT ret_node(shz_node *n, shzeng_node **out)
{
    if (!out) return E_POINTER;
    *out = n;
    if (!n) return S_FALSE;
    shz_node_addref(n);
    return S_OK;
}

static HRESULT ret_list(shz_list *l, shzeng_list **out)
{
    *out = l;
    return l ? S_OK : E_OUTOFMEMORY;
}

/* ---------------------------------------------------------------------------------------------------- host hooks */

static void h_node_inserted(void *ctx, shz_doc *doc, shz_node *node)
{
    shz_win_doc *w = ctx;
    if (w->host && w->host->node_inserted) w->host->node_inserted(w->ctx, doc, node);
}

static void h_node_removed(void *ctx, shz_doc *doc, shz_node *node)
{
    shz_win_doc *w = ctx;
    if (w->host && w->host->node_removed) w->host->node_removed(w->ctx, doc, node);
}

static void h_parse_done(void *ctx, shz_doc *doc)
{
    shz_win_doc *w = ctx;
    if (w->host && w->host->parse_done) w->host->parse_done(w->ctx, doc);
}

static void h_run_script(void *ctx, shz_doc *doc, shz_node *script, int parser_inserted)
{
    shz_win_doc *w = ctx;
    if (w->host && w->host->run_script) w->host->run_script(w->ctx, doc, script, parser_inserted ? TRUE : FALSE);
}

static shz_res h_event(void *ctx, shz_node *current_target, shz_event *ev, void *cookie)
{
    shz_win_doc *w = ctx;
    if (w->host && w->host->event) return w->host->event(w->ctx, current_target, ev, cookie);
    return SHZ_OK;
}

/* engine.h sink wrapper around a core fetch sink */
typedef struct win_sink {
    shzeng_sink base;
    shz_fetch_sink *core;
} win_sink;

static void ws_start(shzeng_sink *sink, const WCHAR *final_url, const WCHAR *mime, const WCHAR *charset)
{
    win_sink *s = (win_sink *)sink;
    s->core->start(s->core, shz_from_w(final_url), shz_from_w(mime), shz_from_w(charset));
}

static void ws_data(shzeng_sink *sink, const void *bytes, SIZE_T len)
{
    win_sink *s = (win_sink *)sink;
    s->core->data(s->core, bytes, len);
}

static void ws_done(shzeng_sink *sink, HRESULT status)
{
    win_sink *s = (win_sink *)sink;
    shz_fetch_sink *core = s->core;
    shz_free(s);
    core->done(core, status);
}

static const shzeng_sink_vtbl win_sink_vtbl = { ws_start, ws_data, ws_done };

static shz_res h_fetch(void *ctx, shz_doc *doc, const shz_char *url, int kind, shz_fetch_sink *sink)
{
    shz_win_doc *w = ctx;
    win_sink *s;
    HRESULT hr;
    if (!w->host || !w->host->fetch) return E_NOTIMPL;
    s = shz_alloc(sizeof(*s));
    if (!s) return E_OUTOFMEMORY;
    s->base.vtbl = &win_sink_vtbl;
    s->core = sink;
    hr = w->host->fetch(w->ctx, doc, shz_to_wc(url), (shzeng_fetch_kind)kind, &s->base);
    if (FAILED(hr)) shz_free(s);           /* the sink is not called after a failure */
    return hr;
}

static void h_load_done(void *ctx, shz_doc *doc)
{
    shz_win_doc *w = ctx;
    if (w->host && w->host->load_done) w->host->load_done(w->ctx, doc);
}

static void h_title_changed(void *ctx, shz_doc *doc)
{
    shz_win_doc *w = ctx;
    if (w->host && w->host->title_changed) w->host->title_changed(w->ctx, doc);
}

static void h_status_text(void *ctx, const shz_char *text)
{
    shz_win_doc *w = ctx;
    if (w->host && w->host->status_text) w->host->status_text(w->ctx, shz_to_wc(text));
}

static shz_res h_navigate(void *ctx, shz_doc *doc, const shz_char *url, const shz_char *target, const void *post,
                          size_t post_len, const shz_char *headers)
{
    shz_win_doc *w = ctx;
    if (!w->host || !w->host->navigate) return E_NOTIMPL;
    return w->host->navigate(w->ctx, doc, shz_to_wc(url), shz_to_wc(target), post, post_len, shz_to_wc(headers));
}

static void h_context_menu(void *ctx, shz_doc *doc, int32_t sx, int32_t sy, shz_node *node)
{
    shz_win_doc *w = ctx;
    if (w->host && w->host->context_menu) w->host->context_menu(w->ctx, doc, sx, sy, node);
}

static void h_invalidate(void *ctx, shz_doc *doc, const shz_irect *rect)
{
    shz_win_doc *w = ctx;
    RECT r;
    if (!w->host || !w->host->invalidate) return;
    if (rect) shz_rect_to_win(rect, &r);
    w->host->invalidate(w->ctx, doc, rect ? &r : NULL);
}

static void win_doc_free(void *platform)
{
    shz_free(platform);
}

/* ---------------------------------------------------------------------------------------------------- documents */

static void WINAPI_str_free(WCHAR *str)
{
    shz_free(str);
}

static HRESULT doc_create(const shzeng_host *host, void *ctx, const WCHAR *url, const WCHAR *mime, shzeng_doc **out)
{
    shz_win_doc *w;
    shz_doc *doc;
    shz_res hr;
    if (!out) return E_POINTER;
    *out = NULL;
    w = shz_alloc(sizeof(*w));
    if (!w) return E_OUTOFMEMORY;
    w->host = host;
    w->ctx = ctx;
    w->hooks.node_inserted = h_node_inserted;
    w->hooks.node_removed = h_node_removed;
    w->hooks.parse_done = h_parse_done;
    w->hooks.run_script = h_run_script;
    w->hooks.event = h_event;
    w->hooks.fetch = host && host->fetch ? h_fetch : NULL;   /* no host fetch: file: URLs are read directly */
    w->hooks.load_done = h_load_done;
    w->hooks.title_changed = h_title_changed;
    w->hooks.status_text = h_status_text;
    w->hooks.navigate = h_navigate;
    w->hooks.context_menu = h_context_menu;
    w->hooks.invalidate = h_invalidate;
    hr = shz_doc_create(&w->hooks, w, shz_from_w(url), shz_from_w(mime), &doc);
    if (SHZ_FAILED(hr)) {
        shz_free(w);
        return hr;
    }
    doc->platform = w;
    doc->platform_free = win_doc_free;
    *out = doc;
    return S_OK;
}

static void doc_release(shzeng_doc *doc)
{
    shz_doc_release(doc);
}

static HRESULT doc_set_url(shzeng_doc *doc, const WCHAR *url)
{
    return shz_doc_set_url(doc, shz_from_w(url));
}

static HRESULT parser_begin(shzeng_doc *doc, const WCHAR *charset)
{
    return shz_parser_begin(doc, shz_from_w(charset));
}

static HRESULT parser_feed(shzeng_doc *doc, const void *bytes, SIZE_T len)
{
    return shz_parser_feed(doc, bytes, len);
}

static HRESULT parser_end(shzeng_doc *doc)
{
    return shz_parser_end(doc);
}

static HRESULT load_string(shzeng_doc *doc, const WCHAR *html, SIZE_T len)
{
    return shz_doc_load_string(doc, shz_from_w(html), len);
}

static HRESULT doc_open(shzeng_doc *doc)
{
    return shz_doc_open(doc);
}

static HRESULT doc_write(shzeng_doc *doc, const WCHAR *text, BOOL newline)
{
    const shz_char *t = shz_from_w(text);
    return shz_doc_write(doc, t, shz_strlen(t), newline);
}

static HRESULT doc_close(shzeng_doc *doc)
{
    return shz_doc_close(doc);
}

static HRESULT doc_set_mode(shzeng_doc *doc, shzeng_mode mode)
{
    return shz_doc_set_mode(doc, (int)mode);
}

static HRESULT doc_get_ready_state(shzeng_doc *doc, WCHAR **state)
{
    static const char *const names[] = { "uninitialized", "loading", "interactive", "complete" };
    int s = doc->ready_state;
    if (s < 0 || s > 3) s = 0;
    return ret_str(shz_strdup_ascii(names[s]), state);
}

static HRESULT parse_document(const WCHAR *src, const WCHAR *mime, shzeng_doc **doc)
{
    const shz_char *s = shz_from_w(src);
    return shz_parse_document(s, shz_strlen(s), shz_from_w(mime), doc);
}

/* ---------------------------------------------------------------------------------------------------- tree */

static HRESULT doc_node(shzeng_doc *doc, shzeng_node **node)
{
    return ret_node(doc->node, node);
}

static HRESULT doc_element(shzeng_doc *doc, shzeng_node **node)
{
    return ret_node(shz_doc_element(doc), node);
}

static HRESULT doc_body(shzeng_doc *doc, shzeng_node **node)
{
    return ret_node(shz_doc_body(doc), node);
}

static HRESULT doc_head(shzeng_doc *doc, shzeng_node **node)
{
    return ret_node(shz_doc_head(doc), node);
}

static HRESULT doc_doctype(shzeng_doc *doc, shzeng_node **node, WCHAR **name, WCHAR **public_id, WCHAR **system_id)
{
    shz_node *dt = shz_doc_doctype(doc);
    shz_doctype *d = (shz_doctype *)dt;
    if (node) *node = NULL;
    if (name) *name = NULL;
    if (public_id) *public_id = NULL;
    if (system_id) *system_id = NULL;
    if (!dt) return S_FALSE;
    if (node) ret_node(dt, node);
    if (name) *name = shz_to_w(shz_strdup(d->name));
    if (public_id && d->public_id) *public_id = shz_to_w(shz_strdup(d->public_id));
    if (system_id && d->system_id) *system_id = shz_to_w(shz_strdup(d->system_id));
    return S_OK;
}

static HRESULT node_doc(shzeng_node *node, shzeng_doc **doc)
{
    *doc = node->doc;
    return S_OK;
}

static void node_addref(shzeng_node *node)
{
    shz_node_addref(node);
}

static void node_release(shzeng_node *node)
{
    shz_node_release(node);
}

static int node_type(shzeng_node *node)
{
    return node->type;
}

static HRESULT node_name(shzeng_node *node, WCHAR **name)
{
    return ret_str(shz_node_name(node), name);
}

static HRESULT node_value(shzeng_node *node, WCHAR **value)
{
    if (!shz_is_chardata(node) && node->type != SHZ_ATTRIBUTE_NODE) {
        *value = NULL;
        return S_FALSE;
    }
    return ret_str(shz_node_value(node), value);
}

static HRESULT node_set_value(shzeng_node *node, const WCHAR *value)
{
    return shz_node_set_value(node, shz_from_w(value));
}

static HRESULT node_parent(shzeng_node *node, shzeng_node **out)
{
    return ret_node(node->parent, out);
}

static HRESULT node_first_child(shzeng_node *node, shzeng_node **out)
{
    return ret_node(node->first_child, out);
}

static HRESULT node_last_child(shzeng_node *node, shzeng_node **out)
{
    return ret_node(node->last_child, out);
}

static HRESULT node_next_sibling(shzeng_node *node, shzeng_node **out)
{
    return ret_node(node->next_sibling, out);
}

static HRESULT node_prev_sibling(shzeng_node *node, shzeng_node **out)
{
    return ret_node(node->prev_sibling, out);
}

static HRESULT node_child_nodes(shzeng_node *node, shzeng_list **list)
{
    return ret_list(shz_list_children(node), list);
}

static HRESULT node_insert_before(shzeng_node *parent, shzeng_node *child, shzeng_node *ref)
{
    return shz_node_insert_before(parent, child, ref);
}

static HRESULT node_remove_child(shzeng_node *parent, shzeng_node *child)
{
    return shz_node_remove_child(parent, child);
}

static HRESULT node_replace_child(shzeng_node *parent, shzeng_node *child, shzeng_node *old)
{
    return shz_node_replace_child(parent, child, old);
}

static HRESULT node_clone(shzeng_node *node, BOOL deep, shzeng_node **out)
{
    return shz_node_clone(node, deep, out);
}

static BOOL node_contains(shzeng_node *node, shzeng_node *other)
{
    return node && other && shz_node_contains(node, other);
}

static UINT node_compare_position(shzeng_node *node, shzeng_node *other)
{
    return shz_node_compare_position(node, other);
}

static HRESULT node_text(shzeng_node *node, BOOL inner_text, WCHAR **text)
{
    if (node->type == SHZ_DOCUMENT_NODE || node->type == SHZ_DOCTYPE_NODE) {
        *text = NULL;
        return S_FALSE;
    }
    return ret_str(inner_text ? shz_node_inner_text(node) : shz_node_text_content(node), text);
}

static HRESULT node_set_text(shzeng_node *node, const WCHAR *text)
{
    return shz_node_set_text_content(node, shz_from_w(text));
}

static void node_set_host_data(shzeng_node *node, void *data)
{
    node->host_data = data;
}

static void *node_get_host_data(shzeng_node *node)
{
    return node->host_data;
}

static HRESULT create_element(shzeng_doc *doc, const WCHAR *ns, const WCHAR *tag, shzeng_node **out)
{
    const shz_char *t = shz_from_w(tag);
    size_t n = shz_strlen(t);
    *out = NULL;
    if (!shz_is_valid_name(t, n)) return SHZ_E_INVALID_CHAR;
    *out = ns && *ns ? shz_create_element_ns(doc, shz_from_w(ns), t, n) : shz_create_element(doc, t, n);
    return *out ? S_OK : E_OUTOFMEMORY;
}

static HRESULT create_text(shzeng_doc *doc, const WCHAR *data, shzeng_node **out)
{
    const shz_char *d = shz_from_w(data);
    *out = shz_create_text(doc, d, shz_strlen(d));
    return *out ? S_OK : E_OUTOFMEMORY;
}

static HRESULT create_comment(shzeng_doc *doc, const WCHAR *data, shzeng_node **out)
{
    const shz_char *d = shz_from_w(data);
    *out = shz_create_comment(doc, d, shz_strlen(d));
    return *out ? S_OK : E_OUTOFMEMORY;
}

static HRESULT create_fragment(shzeng_doc *doc, shzeng_node **out)
{
    *out = shz_create_fragment(doc);
    return *out ? S_OK : E_OUTOFMEMORY;
}

static HRESULT parse_fragment(shzeng_node *context, const WCHAR *html, shzeng_node **fragment)
{
    const shz_char *h = shz_from_w(html);
    return shz_parse_fragment(context, h, shz_strlen(h), fragment);
}

static HRESULT serialize(shzeng_node *node, BOOL outer, WCHAR **html)
{
    return ret_str(shz_serialize(node, outer), html);
}

static HRESULT text_split(shzeng_node *text, UINT offset, shzeng_node **tail)
{
    return shz_text_split(text, offset, tail);
}

/* ---------------------------------------------------------------------------------------------------- elements */

static HRESULT elem_tag(shzeng_node *elem, WCHAR **local_name)
{
    shz_element *e = shz_elem(elem);
    if (!e) { *local_name = NULL; return E_INVALIDARG; }
    return ret_str(shz_strdup(e->local), local_name);
}

static HRESULT elem_namespace(shzeng_node *elem, WCHAR **ns)
{
    if (!shz_elem(elem)) { *ns = NULL; return E_INVALIDARG; }
    return ret_str_opt(shz_elem_namespace(elem), ns);
}

static HRESULT elem_get_attr(shzeng_node *elem, const WCHAR *name, WCHAR **value)
{
    const shz_char *v;
    *value = NULL;
    if (!shz_elem(elem)) return E_INVALIDARG;
    v = shz_elem_attr_str(elem, shz_from_w(name));
    if (!v) return S_FALSE;
    return ret_str(shz_strdup(v), value);
}

static HRESULT elem_set_attr(shzeng_node *elem, const WCHAR *name, const WCHAR *value)
{
    const shz_char *n = shz_from_w(name), *v = shz_from_w(value);
    return shz_elem_set_attr(elem, n, shz_strlen(n), v, shz_strlen(v));
}

static HRESULT elem_remove_attr(shzeng_node *elem, const WCHAR *name)
{
    const shz_char *n = shz_from_w(name);
    return shz_elem_remove_attr(elem, n, shz_strlen(n));
}

static UINT elem_attr_count(shzeng_node *elem)
{
    shz_element *e = shz_elem(elem);
    return e ? e->attr_count : 0;
}

static HRESULT elem_attr_at(shzeng_node *elem, UINT index, WCHAR **name, WCHAR **value)
{
    shz_element *e = shz_elem(elem);
    if (name) *name = NULL;
    if (value) *value = NULL;
    if (!e || index >= e->attr_count) return E_INVALIDARG;
    if (name && !(*name = shz_to_w(shz_strdup(e->attrs[index].name)))) return E_OUTOFMEMORY;
    if (value && !(*value = shz_to_w(shz_strdup(e->attrs[index].value)))) {
        if (name) { shz_free(*name); *name = NULL; }
        return E_OUTOFMEMORY;
    }
    return S_OK;
}

static HRESULT elem_attr_node(shzeng_node *elem, const WCHAR *name, shzeng_node **attr)
{
    const shz_char *n = shz_from_w(name);
    return shz_elem_attr_node(elem, n, shz_strlen(n), attr);
}

static HRESULT doc_get_element_by_id(shzeng_doc *doc, const WCHAR *id, shzeng_node **out)
{
    return ret_node(shz_doc_get_element_by_id(doc, shz_from_w(id)), out);
}

static HRESULT get_elements_by(shzeng_node *root, shzeng_by by, const WCHAR *ns, const WCHAR *value, shzeng_list **out)
{
    if ((int)by < 0 || by > SHZENG_BY_TAG_NS) { *out = NULL; return E_INVALIDARG; }
    return ret_list(shz_list_by(root, (int)by, shz_from_w(ns), shz_from_w(value)), out);
}

static HRESULT doc_collection(shzeng_doc *doc, shzeng_collection which, shzeng_list **out)
{
    if ((int)which < 0 || which > SHZENG_COLL_EMBEDS) { *out = NULL; return E_INVALIDARG; }
    return ret_list(shz_list_collection(doc, (int)which), out);
}

static HRESULT query_selector(shzeng_node *root, const WCHAR *selector, BOOL all, shzeng_node **one, shzeng_list **list)
{
    if (one) *one = NULL;
    if (list) *list = NULL;
    if (all) {
        if (!list) return E_POINTER;
        return shz_query_selector_all(root, shz_from_w(selector), list);
    } else {
        shz_node *n;
        shz_res hr;
        if (!one) return E_POINTER;
        hr = shz_query_selector(root, shz_from_w(selector), &n);
        if (hr != SHZ_OK) return hr;
        return ret_node(n, one);
    }
}

static HRESULT matches(shzeng_node *elem, const WCHAR *selector, BOOL *result)
{
    int r = 0;
    shz_res hr = shz_element_matches(elem, shz_from_w(selector), &r);
    *result = r ? TRUE : FALSE;
    return hr;
}

static UINT list_length(shzeng_list *list)
{
    return shz_list_length(list);
}

static HRESULT list_item(shzeng_list *list, UINT index, shzeng_node **out)
{
    return ret_node(shz_list_item(list, index), out);
}

static HRESULT list_named_item(shzeng_list *list, const WCHAR *name, shzeng_node **out)
{
    return ret_node(shz_list_named_item(list, shz_from_w(name)), out);
}

static void list_release(shzeng_list *list)
{
    shz_list_release(list);
}

/* ---------------------------------------------------------------------------------------------------- forms (L2) */

static HRESULT ctl_get_value(shzeng_node *ctl, WCHAR **value)
{
    shz_char *v = NULL;
    shz_res hr = shz_forms_get_value(ctl, &v);
    *value = shz_to_w(v);
    return hr;
}

static HRESULT ctl_set_value(shzeng_node *ctl, const WCHAR *value)
{
    return shz_forms_set_value(ctl, shz_from_w(value));
}

static HRESULT ctl_get_checked(shzeng_node *ctl, BOOL *checked)
{
    int c = 0;
    shz_res hr = shz_forms_get_checked(ctl, &c);
    *checked = c ? TRUE : FALSE;
    return hr;
}

static HRESULT ctl_set_checked(shzeng_node *ctl, BOOL checked)
{
    return shz_forms_set_checked(ctl, checked != FALSE);
}

static HRESULT select_get_index(shzeng_node *select, LONG *index)
{
    long i = -1;
    shz_res hr = shz_forms_select_get_index(select, &i);
    *index = (LONG)i;
    return hr;
}

static HRESULT select_set_index(shzeng_node *select, LONG index)
{
    return shz_forms_select_set_index(select, index);
}

static HRESULT form_submission(shzeng_node *form, shzeng_node *submitter, WCHAR **action, WCHAR **method,
                               WCHAR **content_type, BYTE **body, SIZE_T *body_len)
{
    shz_form_submission s;
    shz_res hr;
    memset(&s, 0, sizeof(s));
    hr = shz_forms_submission(form, submitter, &s);
    if (action) *action = shz_to_w(s.action); else shz_free(s.action);
    if (method) *method = shz_to_w(s.method); else shz_free(s.method);
    if (content_type) *content_type = shz_to_w(s.content_type); else shz_free(s.content_type);
    if (body) *body = s.body; else shz_free(s.body);
    if (body_len) *body_len = s.body_len;
    return hr;
}

static HRESULT form_reset(shzeng_node *form)
{
    return shz_forms_reset(form);
}

static void bytes_free(BYTE *bytes)
{
    shz_free(bytes);
}

static HRESULT img_state(shzeng_node *img, BOOL *complete, LONG *natural_width, LONG *natural_height)
{
    int c = 0;
    int32_t w = 0, h = 0;
    shz_res hr = shz_image_state(img, &c, &w, &h);
    if (complete) *complete = c ? TRUE : FALSE;
    if (natural_width) *natural_width = w;
    if (natural_height) *natural_height = h;
    return hr;
}

static HRESULT frame_doc(shzeng_node *frame, shzeng_doc **doc)
{
    SHZ_UNUSED(frame);
    *doc = NULL;
    return S_FALSE;                     /* frames are not loaded by this engine version */
}

/* ---------------------------------------------------------------------------------------------------- style (L1) */

static HRESULT style_inline(shzeng_node *elem, shzeng_style **style)
{
    return shz_css_inline_style(elem, style);
}

static HRESULT style_computed(shzeng_node *elem, const WCHAR *pseudo, shzeng_style **style)
{
    return shz_css_computed_style(elem, shz_from_w(pseudo), style);
}

static HRESULT style_get(shzeng_style *style, const WCHAR *property, WCHAR **value)
{
    shz_char *v = NULL;
    shz_res hr = shz_css_style_get(style, shz_from_w(property), &v);
    *value = shz_to_w(v);
    return hr;
}

static HRESULT style_get_priority(shzeng_style *style, const WCHAR *property, WCHAR **priority)
{
    shz_char *v = NULL;
    shz_res hr = shz_css_style_get_priority(style, shz_from_w(property), &v);
    *priority = shz_to_w(v);
    return hr;
}

static HRESULT style_set(shzeng_style *style, const WCHAR *property, const WCHAR *value, const WCHAR *priority)
{
    return shz_css_style_set(style, shz_from_w(property), shz_from_w(value), shz_from_w(priority));
}

static HRESULT style_remove(shzeng_style *style, const WCHAR *property)
{
    return shz_css_style_remove(style, shz_from_w(property));
}

static HRESULT style_css_text(shzeng_style *style, WCHAR **text)
{
    shz_char *t = NULL;
    shz_res hr = shz_css_style_text(style, &t);
    *text = shz_to_w(t);
    return hr;
}

static HRESULT style_set_css_text(shzeng_style *style, const WCHAR *text)
{
    return shz_css_style_set_text(style, shz_from_w(text));
}

static UINT style_length(shzeng_style *style)
{
    return shz_css_style_length(style);
}

static HRESULT style_item(shzeng_style *style, UINT index, WCHAR **property)
{
    shz_char *p = NULL;
    shz_res hr = shz_css_style_item(style, index, &p);
    *property = shz_to_w(p);
    return hr;
}

static void style_release(shzeng_style *style)
{
    shz_css_style_release(style);
}

static UINT doc_sheet_count(shzeng_doc *doc)
{
    return shz_css_sheet_count(doc);
}

static HRESULT doc_sheet_at(shzeng_doc *doc, UINT index, shzeng_sheet **sheet)
{
    return shz_css_sheet_at(doc, index, sheet);
}

static UINT sheet_rule_count(shzeng_sheet *sheet)
{
    return shz_css_sheet_rule_count(sheet);
}

static HRESULT sheet_rule_text(shzeng_sheet *sheet, UINT index, WCHAR **text)
{
    shz_char *t = NULL;
    shz_res hr = shz_css_sheet_rule_text(sheet, index, &t);
    *text = shz_to_w(t);
    return hr;
}

static HRESULT sheet_rule_style(shzeng_sheet *sheet, UINT index, WCHAR **selector, shzeng_style **style)
{
    shz_char *s = NULL;
    shz_style *st = NULL;
    shz_res hr = shz_css_sheet_rule_style(sheet, index, &s, &st);
    if (selector) *selector = shz_to_w(s); else shz_free(s);
    if (style) *style = st; else if (st) shz_css_style_release(st);
    return hr;
}

static HRESULT sheet_insert_rule(shzeng_sheet *sheet, const WCHAR *rule, UINT index)
{
    return shz_css_sheet_insert_rule(sheet, shz_from_w(rule), index);
}

static HRESULT sheet_delete_rule(shzeng_sheet *sheet, UINT index)
{
    return shz_css_sheet_delete_rule(sheet, index);
}

static HRESULT sheet_href(shzeng_sheet *sheet, WCHAR **href)
{
    shz_char *h = NULL;
    shz_res hr = shz_css_sheet_href(sheet, &h);
    *href = shz_to_w(h);
    return hr;
}

static void sheet_release(shzeng_sheet *sheet)
{
    shz_css_sheet_release(sheet);
}

static HRESULT media_matches(shzeng_doc *doc, const WCHAR *query, BOOL *result)
{
    int r = 0;
    shz_res hr = shz_css_media_matches(doc, shz_from_w(query), &r);
    *result = r ? TRUE : FALSE;
    return hr;
}

/* ---------------------------------------------------------------------------------------------------- geometry (L1) */

static HRESULT elem_box(shzeng_node *elem, shzeng_box which, RECT *box)
{
    shz_irect r;
    shz_res hr;
    memset(&r, 0, sizeof(r));
    hr = shz_layout_elem_box(elem, (int)which, &r);
    shz_rect_to_win(&r, box);
    return hr;
}

static HRESULT elem_offset_parent(shzeng_node *elem, shzeng_node **parent)
{
    shz_node *p = NULL;
    shz_res hr = shz_layout_offset_parent(elem, &p);
    if (SHZ_FAILED(hr)) { *parent = NULL; return hr; }
    return ret_node(p, parent);
}

static UINT elem_client_rects(shzeng_node *elem, RECT *rects, UINT max)
{
    shz_irect buf[16], *tmp = buf;
    UINT n, i;
    if (max > SHZ_ARRAY_SIZE(buf)) {
        tmp = shz_alloc_array(max, sizeof(*tmp));
        if (!tmp) return 0;
    }
    n = shz_layout_client_rects(elem, tmp, max);
    for (i = 0; i < n && i < max && rects; ++i) shz_rect_to_win(&tmp[i], &rects[i]);
    if (tmp != buf) shz_free(tmp);
    return n;
}

static HRESULT elem_set_scroll(shzeng_node *elem, LONG x, LONG y)
{
    return shz_layout_set_scroll(elem, x, y);
}

static HRESULT elem_scroll_into_view(shzeng_node *elem, BOOL align_top)
{
    return shz_layout_scroll_into_view(elem, align_top != FALSE);
}

static HRESULT hit_test(shzeng_doc *doc, LONG x, LONG y, shzeng_node **node)
{
    shz_node *n = NULL;
    shz_res hr = shz_layout_hit_test(doc, x, y, &n);
    if (SHZ_FAILED(hr)) { *node = NULL; return hr; }
    return ret_node(n, node);
}

/* ---------------------------------------------------------------------------------------------------- events (L2) */

static HRESULT add_listener(shzeng_doc *doc, shzeng_node *target, const WCHAR *type, BOOL capture, void *cookie)
{
    return shz_events_add_listener(doc, target, shz_from_w(type), capture != FALSE, cookie);
}

static HRESULT remove_listener(shzeng_doc *doc, shzeng_node *target, const WCHAR *type, BOOL capture, void *cookie)
{
    return shz_events_remove_listener(doc, target, shz_from_w(type), capture != FALSE, cookie);
}

static HRESULT dispatch_event(shzeng_doc *doc, shzeng_node *target, const WCHAR *type, BOOL bubbles, BOOL cancelable,
                              BOOL *default_prevented)
{
    int prevented = 0;
    shz_res hr = shz_events_dispatch_synthetic(doc, target, shz_from_w(type), bubbles != FALSE, cancelable != FALSE,
                                               &prevented);
    if (default_prevented) *default_prevented = prevented ? TRUE : FALSE;
    return hr;
}

static HRESULT event_type(shzeng_event *event, WCHAR **type)
{
    static const shz_char empty[1] = {0};
    return ret_str(shz_strdup(event->type ? event->type : empty), type);
}

static shzeng_event_kind event_kind(shzeng_event *event)
{
    return (shzeng_event_kind)event->kind;
}

static HRESULT event_target(shzeng_event *event, shzeng_node **target)
{
    return ret_node(event->target, target);
}

static HRESULT event_flags(shzeng_event *event, BOOL *bubbles, BOOL *cancelable, BOOL *trusted, UINT *phase,
                           ULONGLONG *time_stamp)
{
    if (bubbles) *bubbles = event->bubbles ? TRUE : FALSE;
    if (cancelable) *cancelable = event->cancelable ? TRUE : FALSE;
    if (trusted) *trusted = event->trusted ? TRUE : FALSE;
    if (phase) *phase = event->phase;
    if (time_stamp) *time_stamp = event->time_stamp;
    return S_OK;
}

static HRESULT event_mouse(shzeng_event *event, shzeng_mouse *mouse)
{
    const shz_mouse_data *m = &event->mouse;
    if (event->kind != SHZ_EVENT_MOUSE) return E_INVALIDARG;
    mouse->client_x = m->client_x;
    mouse->client_y = m->client_y;
    mouse->screen_x = m->screen_x;
    mouse->screen_y = m->screen_y;
    mouse->page_x = m->page_x;
    mouse->page_y = m->page_y;
    mouse->offset_x = m->offset_x;
    mouse->offset_y = m->offset_y;
    mouse->button = m->button;
    mouse->buttons = m->buttons;
    mouse->ctrl = m->ctrl;
    mouse->shift = m->shift;
    mouse->alt = m->alt;
    mouse->meta = m->meta;
    mouse->related = m->related;
    if (m->related) shz_node_addref(m->related);
    mouse->detail = m->detail;
    return S_OK;
}

static HRESULT event_key(shzeng_event *event, shzeng_key *key)
{
    const shz_key_data *k = &event->key;
    if (event->kind != SHZ_EVENT_KEYBOARD) return E_INVALIDARG;
    key->key_code = k->key_code;
    key->char_code = k->char_code;
    memcpy(key->key, k->key, sizeof(key->key));
    key->key[SHZ_ARRAY_SIZE(key->key) - 1] = 0;
    key->location = k->location;
    key->repeat = k->repeat;
    key->ctrl = k->ctrl;
    key->shift = k->shift;
    key->alt = k->alt;
    key->meta = k->meta;
    return S_OK;
}

static HRESULT event_progress(shzeng_event *event, ULONGLONG *loaded, ULONGLONG *total, BOOL *computable)
{
    if (event->kind != SHZ_EVENT_PROGRESS) return E_INVALIDARG;
    if (loaded) *loaded = event->loaded;
    if (total) *total = event->total;
    if (computable) *computable = event->computable ? TRUE : FALSE;
    return S_OK;
}

static HRESULT event_prevent_default(shzeng_event *event)
{
    if (event->cancelable) event->default_prevented = 1;
    return S_OK;
}

static HRESULT event_stop(shzeng_event *event, BOOL immediate)
{
    event->stop = 1;
    if (immediate) event->stop_immediate = 1;
    return S_OK;
}

static BOOL event_default_prevented(shzeng_event *event)
{
    return event->default_prevented ? TRUE : FALSE;
}

static void event_addref(shzeng_event *event)
{
    shz_event_addref(event);
}

static void event_release(shzeng_event *event)
{
    shz_event_release(event);
}

static HRESULT elem_click(shzeng_node *elem)
{
    return shz_events_click(elem);
}

static HRESULT elem_focus(shzeng_node *elem)
{
    return shz_events_focus(elem);
}

static HRESULT elem_blur(shzeng_node *elem)
{
    return shz_events_blur(elem);
}

static HRESULT doc_active_element(shzeng_doc *doc, shzeng_node **elem)
{
    shz_node *n = NULL;
    shz_res hr = shz_events_active_element(doc, &n);
    if (SHZ_FAILED(hr)) { *elem = NULL; return hr; }
    return ret_node(n, elem);
}

/* ---------------------------------------------------------------------------------------------------- script */

static HRESULT script_eval(shzeng_doc *doc, const WCHAR *lang, const WCHAR *code, const WCHAR *source_url, UINT line,
                           VARIANT *result)
{
    SHZ_UNUSED(doc); SHZ_UNUSED(lang); SHZ_UNUSED(code); SHZ_UNUSED(source_url); SHZ_UNUSED(line);
    if (result) memset(result, 0, sizeof(*result));
    return E_NOTIMPL;                   /* no JavaScript engine: the Trident layer runs scripts with jscript */
}

/* ---------------------------------------------------------------------------------------------------- views */

static HRESULT view_create(shzeng_doc *doc, HWND parent, const RECT *rect, shzeng_view **view)
{
    return shz_view_create(doc, parent, rect, view);
}

static void view_destroy(shzeng_view *view)
{
    shz_view_destroy(view);
}

static HWND view_hwnd(shzeng_view *view)
{
    return shz_view_hwnd(view);
}

static HRESULT view_set_rect(shzeng_view *view, const RECT *rect)
{
    return shz_view_set_rect(view, rect);
}

static HRESULT view_show(shzeng_view *view, BOOL show)
{
    return shz_view_show(view, show);
}

static HRESULT view_set_parent(shzeng_view *view, HWND parent)
{
    return shz_view_set_parent(view, parent);
}

static HRESULT view_focus(shzeng_view *view)
{
    return shz_view_focus(view);
}

static HRESULT view_scroll(shzeng_view *view, LONG x, LONG y, BOOL relative)
{
    return shz_view_scroll(view, x, y, relative);
}

static HRESULT view_scroll_pos(shzeng_view *view, LONG *x, LONG *y)
{
    return shz_view_scroll_pos(view, x, y);
}

static HRESULT view_set_zoom(shzeng_view *view, float zoom)
{
    return shz_view_set_zoom(view, zoom);
}

static HRESULT view_paint(shzeng_doc *doc, HDC dc, const RECT *dest, LONG scroll_x, LONG scroll_y)
{
    return shz_paint_to_dc(doc, dc, dest, scroll_x, scroll_y);
}

static HRESULT snapshot(shzeng_doc *doc, LONG width, LONG height, HBITMAP *bitmap)
{
    return shz_paint_snapshot(doc, width, height, bitmap);
}

static HRESULT doc_content_size(shzeng_doc *doc, LONG *width, LONG *height)
{
    int32_t w = 0, h = 0;
    shz_res hr = shz_layout_content_size(doc, &w, &h);
    if (width) *width = w;
    if (height) *height = h;
    return hr;
}

/* ---------------------------------------------------------------------------------------------------- ranges */

static HRESULT range_create(shzeng_doc *doc, shzeng_range **range)
{
    return shz_range_create(doc, range);
}

static HRESULT range_set(shzeng_range *range, BOOL end, shzeng_node *node, LONG offset)
{
    if (offset < 0) return SHZ_E_INDEX_SIZE;
    return shz_range_set(range, end != FALSE, node, (uint32_t)offset);
}

static HRESULT range_get(shzeng_range *range, BOOL end, shzeng_node **node, LONG *offset)
{
    if (offset) *offset = (LONG)(end ? range->end_off : range->start_off);
    if (node) return ret_node(end ? range->end : range->start, node);
    return S_OK;
}

static HRESULT range_text(shzeng_range *range, WCHAR **text)
{
    return ret_str(shz_range_text(range), text);
}

static void range_release(shzeng_range *range)
{
    shz_range_release(range);
}

static HRESULT sel_get(shzeng_doc *doc, shzeng_range **range)
{
    return shz_sel_get(doc, range);
}

static HRESULT sel_set(shzeng_doc *doc, shzeng_range *range)
{
    return shz_sel_set(doc, range);
}

/* ---------------------------------------------------------------------------------------------------- the table */

static const shzeng_vtbl vtbl = {
    .api_version = SHZENG_API_VERSION,
    .caps = SHZENG_CAP_LAYOUT | SHZENG_CAP_CSSOM | SHZENG_CAP_RANGES | SHZENG_CAP_IMAGES | SHZENG_CAP_FORMS,
    .name = L"ShizukuTrident Lite 1.0",
    .ua_token = L"ShizukuTridentLite/1.0",
    .str_free = WINAPI_str_free,
    .doc_create = doc_create,
    .doc_release = doc_release,
    .doc_set_url = doc_set_url,
    .parser_begin = parser_begin,
    .parser_feed = parser_feed,
    .parser_end = parser_end,
    .load_string = load_string,
    .doc_open = doc_open,
    .doc_write = doc_write,
    .doc_close = doc_close,
    .doc_set_mode = doc_set_mode,
    .doc_get_ready_state = doc_get_ready_state,
    .parse_document = parse_document,
    .doc_node = doc_node,
    .doc_element = doc_element,
    .doc_body = doc_body,
    .doc_head = doc_head,
    .doc_doctype = doc_doctype,
    .node_doc = node_doc,
    .node_addref = node_addref,
    .node_release = node_release,
    .node_type = node_type,
    .node_name = node_name,
    .node_value = node_value,
    .node_set_value = node_set_value,
    .node_parent = node_parent,
    .node_first_child = node_first_child,
    .node_last_child = node_last_child,
    .node_next_sibling = node_next_sibling,
    .node_prev_sibling = node_prev_sibling,
    .node_child_nodes = node_child_nodes,
    .node_insert_before = node_insert_before,
    .node_remove_child = node_remove_child,
    .node_replace_child = node_replace_child,
    .node_clone = node_clone,
    .node_contains = node_contains,
    .node_compare_position = node_compare_position,
    .node_text = node_text,
    .node_set_text = node_set_text,
    .node_set_host_data = node_set_host_data,
    .node_get_host_data = node_get_host_data,
    .create_element = create_element,
    .create_text = create_text,
    .create_comment = create_comment,
    .create_fragment = create_fragment,
    .parse_fragment = parse_fragment,
    .serialize = serialize,
    .text_split = text_split,
    .elem_tag = elem_tag,
    .elem_namespace = elem_namespace,
    .elem_get_attr = elem_get_attr,
    .elem_set_attr = elem_set_attr,
    .elem_remove_attr = elem_remove_attr,
    .elem_attr_count = elem_attr_count,
    .elem_attr_at = elem_attr_at,
    .elem_attr_node = elem_attr_node,
    .doc_get_element_by_id = doc_get_element_by_id,
    .get_elements_by = get_elements_by,
    .doc_collection = doc_collection,
    .query_selector = query_selector,
    .matches = matches,
    .list_length = list_length,
    .list_item = list_item,
    .list_named_item = list_named_item,
    .list_release = list_release,
    .ctl_get_value = ctl_get_value,
    .ctl_set_value = ctl_set_value,
    .ctl_get_checked = ctl_get_checked,
    .ctl_set_checked = ctl_set_checked,
    .select_get_index = select_get_index,
    .select_set_index = select_set_index,
    .form_submission = form_submission,
    .form_reset = form_reset,
    .bytes_free = bytes_free,
    .img_state = img_state,
    .frame_doc = frame_doc,
    .style_inline = style_inline,
    .style_computed = style_computed,
    .style_get = style_get,
    .style_get_priority = style_get_priority,
    .style_set = style_set,
    .style_remove = style_remove,
    .style_css_text = style_css_text,
    .style_set_css_text = style_set_css_text,
    .style_length = style_length,
    .style_item = style_item,
    .style_release = style_release,
    .doc_sheet_count = doc_sheet_count,
    .doc_sheet_at = doc_sheet_at,
    .sheet_rule_count = sheet_rule_count,
    .sheet_rule_text = sheet_rule_text,
    .sheet_rule_style = sheet_rule_style,
    .sheet_insert_rule = sheet_insert_rule,
    .sheet_delete_rule = sheet_delete_rule,
    .sheet_href = sheet_href,
    .sheet_release = sheet_release,
    .media_matches = media_matches,
    .elem_box = elem_box,
    .elem_offset_parent = elem_offset_parent,
    .elem_client_rects = elem_client_rects,
    .elem_set_scroll = elem_set_scroll,
    .elem_scroll_into_view = elem_scroll_into_view,
    .hit_test = hit_test,
    .add_listener = add_listener,
    .remove_listener = remove_listener,
    .dispatch_event = dispatch_event,
    .event_type = event_type,
    .event_kind = event_kind,
    .event_target = event_target,
    .event_flags = event_flags,
    .event_mouse = event_mouse,
    .event_key = event_key,
    .event_progress = event_progress,
    .event_prevent_default = event_prevent_default,
    .event_stop = event_stop,
    .event_default_prevented = event_default_prevented,
    .event_addref = event_addref,
    .event_release = event_release,
    .elem_click = elem_click,
    .elem_focus = elem_focus,
    .elem_blur = elem_blur,
    .doc_active_element = doc_active_element,
    .script_eval = script_eval,
    .view_create = view_create,
    .view_destroy = view_destroy,
    .view_hwnd = view_hwnd,
    .view_set_rect = view_set_rect,
    .view_show = view_show,
    .view_set_parent = view_set_parent,
    .view_focus = view_focus,
    .view_scroll = view_scroll,
    .view_scroll_pos = view_scroll_pos,
    .view_set_zoom = view_set_zoom,
    .view_paint = view_paint,
    .snapshot = snapshot,
    .doc_content_size = doc_content_size,
    .range_create = range_create,
    .range_set = range_set,
    .range_get = range_get,
    .range_text = range_text,
    .range_release = range_release,
    .sel_get = sel_get,
    .sel_set = sel_set,
    .doc_set_design_mode = NULL,             /* not offered (no editing / printing caps) */
    .exec_command = NULL,             /* not offered (no editing / printing caps) */
    .paginate = NULL,             /* not offered (no editing / printing caps) */
    .print_page = NULL,             /* not offered (no editing / printing caps) */
};

const shzeng_vtbl *shz_win_vtbl(void)
{
    return &vtbl;
}
