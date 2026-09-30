/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuTrident Lite (shzlite.dll) through its engine.h contract, as the Trident layer uses it: the DLL is loaded with
 * LoadLibraryW and ShzEngineGetInterface; documents are parsed from strings and from C:\SHZ\TESTS\TRIDENT_E*.HTM, then
 * queried and mutated. Runs without a display (the standalone run has none): nothing here needs a window.
 *
 * Sections: core (DOM, HTML parser, charset, document.write, fragments, serializer, selectors, live lists, ranges,
 * lifetime); L1 and L2 add theirs (style, geometry, snapshot pixels / events, forms, images) below the core ones.
 * Expected values come from the specifications (WHATWG HTML parsing and serialization, DOM, Selectors, the
 * Encoding Standard's windows-1252 table) and from the test pages themselves, never from the engine's output. */
#include <windows.h>
#include <oleauto.h>
#include "../trident/engine.h"
#include "u_check.h"

static const shzeng_vtbl *E;

/* ---------------------------------------------------------------------------------------------------- host */

typedef struct test_host {
    int inserted, removed, parse_done, load_done, title_changed, scripts, comments;
    int write_in_script;                /* run_script: document.write a paragraph */
} test_host;

static void th_node_inserted(void *ctx, shzeng_doc *doc, shzeng_node *node)
{
    test_host *h = ctx;
    (void)doc;
    ++h->inserted;
    if (E->node_type(node) == SHZENG_COMMENT_NODE) ++h->comments;
}

static void th_node_removed(void *ctx, shzeng_doc *doc, shzeng_node *node)
{
    (void)doc; (void)node;
    ++((test_host *)ctx)->removed;
}

static void th_parse_done(void *ctx, shzeng_doc *doc)
{
    (void)doc;
    ++((test_host *)ctx)->parse_done;
}

static void th_load_done(void *ctx, shzeng_doc *doc)
{
    (void)doc;
    ++((test_host *)ctx)->load_done;
}

static void th_title_changed(void *ctx, shzeng_doc *doc)
{
    (void)doc;
    ++((test_host *)ctx)->title_changed;
}

static void th_run_script(void *ctx, shzeng_doc *doc, shzeng_node *script, BOOL parser_inserted)
{
    test_host *h = ctx;
    (void)script;
    ++h->scripts;
    if (h->write_in_script && parser_inserted) E->doc_write(doc, L"<p id=\"written\">w</p>", FALSE);
}

static shzeng_host host_callbacks;

static shzeng_doc *new_doc(test_host *h, const WCHAR *url)
{
    shzeng_doc *doc = NULL;
    memset(h, 0, sizeof(*h));
    host_callbacks.node_inserted = th_node_inserted;
    host_callbacks.node_removed = th_node_removed;
    host_callbacks.parse_done = th_parse_done;
    host_callbacks.load_done = th_load_done;
    host_callbacks.title_changed = th_title_changed;
    host_callbacks.run_script = th_run_script;
    if (FAILED(E->doc_create(&host_callbacks, h, url, NULL, &doc))) return NULL;
    return doc;
}

static int w_eq(const WCHAR *w, const char *s)
{
    return w && u_ascii_eq_w((const unsigned short *)w, s);
}

/* read a whole file into a new heap buffer */
static BYTE *read_file(const WCHAR *path, DWORD *len)
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    BYTE *buf;
    DWORD size, got = 0;
    *len = 0;
    if (f == INVALID_HANDLE_VALUE) return NULL;
    size = GetFileSize(f, NULL);
    buf = HeapAlloc(GetProcessHeap(), 0, size + 1);
    if (buf && !ReadFile(f, buf, size, &got, NULL)) got = 0;
    CloseHandle(f);
    *len = got;
    return buf;
}

static shzeng_node *by_id(shzeng_doc *doc, const WCHAR *id)
{
    shzeng_node *n = NULL;
    E->doc_get_element_by_id(doc, id, &n);
    return n;
}

static int text_is(shzeng_node *n, const char *expected)
{
    WCHAR *t = NULL;
    int ok;
    if (!n || FAILED(E->node_text(n, FALSE, &t))) return 0;
    ok = w_eq(t, expected);
    E->str_free(t);
    return ok;
}

/* ---------------------------------------------------------------------------------------------------- core */

static void test_interface(HMODULE dll)
{
    shzeng_get_interface_fn get = (shzeng_get_interface_fn)(void *)GetProcAddress(dll, SHZENG_ENTRY_NAME);
    U_CHECK("GetProcAddress(ShzEngineGetInterface)", get != NULL);
    if (!get) return;
    E = get(SHZENG_API_VERSION);
    U_CHECK("ShzEngineGetInterface(1) returns the vtable", E != NULL);
    U_CHECK("ShzEngineGetInterface(2) returns NULL", get(SHZENG_API_VERSION + 1) == NULL);
    if (!E) return;
    U_CHECK("api_version 1", E->api_version == SHZENG_API_VERSION);
    U_CHECK("caps: layout, CSSOM, images, forms, no script", (E->caps & SHZENG_CAP_LAYOUT) && (E->caps & SHZENG_CAP_CSSOM)
            && (E->caps & SHZENG_CAP_IMAGES) && (E->caps & SHZENG_CAP_FORMS) && !(E->caps & SHZENG_CAP_SCRIPT));
    U_CHECK("name and ua_token", E->name && E->ua_token && w_eq(E->name, "ShizukuTrident Lite 1.0"));
    U_CHECK("required slots present", E->str_free && E->doc_create && E->doc_release && E->parser_begin && E->parser_feed
            && E->parser_end && E->load_string && E->doc_set_mode && E->doc_node && E->doc_element && E->doc_body
            && E->node_doc && E->node_addref && E->node_release && E->node_type && E->node_parent
            && E->node_first_child && E->node_next_sibling && E->node_set_host_data && E->node_get_host_data
            && E->create_element && E->create_text && E->parse_fragment && E->serialize && E->elem_tag
            && E->elem_get_attr && E->elem_set_attr && E->elem_remove_attr && E->doc_get_element_by_id
            && E->event_type && E->event_kind && E->view_create && E->view_destroy && E->view_hwnd
            && E->view_set_rect && E->snapshot);
}

static void test_parse_string(void)
{
    static const WCHAR html[] = L"<!DOCTYPE html><title>T</title><p id=a class='x y'>Hello <b>world</b></p>"
                                L"<!--[if IE]><p>ie</p><![endif]-->";
    test_host h;
    shzeng_doc *doc = new_doc(&h, L"http://example.com/dir/page.html");
    shzeng_node *body = NULL, *p, *b = NULL, *first = NULL, *again = NULL, *dt = NULL;
    WCHAR *s = NULL, *name = NULL, *pub = NULL, *sys = NULL;
    VARIANT v;

    U_CHECK("doc_create", doc != NULL);
    if (!doc) return;
    U_CHECK("load_string", E->load_string(doc, html, lstrlenW(html)) == S_OK);
    U_CHECK("parse_done called once", h.parse_done == 1);
    U_CHECK("load_done called once (no pending resources)", h.load_done == 1);
    U_CHECK("title_changed reported", h.title_changed >= 1);
    U_CHECK("node_inserted: doctype html head title #text body p #text b #text comment = 11", h.inserted == 11);
    U_CHECK("the conditional comment is one comment node", h.comments == 1);
    U_CHECK("doc_get_ready_state: complete", E->doc_get_ready_state(doc, &s) == S_OK && w_eq(s, "complete"));
    E->str_free(s);
    U_CHECK("doc_doctype: html, no ids", E->doc_doctype(doc, &dt, &name, &pub, &sys) == S_OK && dt && w_eq(name, "html")
            && !pub && !sys);
    E->str_free(name);
    if (dt) E->node_release(dt);
    U_CHECK("doc_body", E->doc_body(doc, &body) == S_OK && body);
    U_CHECK("elem_tag(body) = body", body && E->elem_tag(body, &s) == S_OK && w_eq(s, "body"));
    E->str_free(s);
    p = by_id(doc, L"a");
    U_CHECK("getElementById(a)", p != NULL);
    U_CHECK("nodeName is upper-case: P", p && E->node_name(p, &s) == S_OK && w_eq(s, "P"));
    E->str_free(s);
    U_CHECK("querySelector(p.x > b)", E->query_selector(body, L"p.x > b", FALSE, &b, NULL) == S_OK && b);
    U_CHECK("textContent(b) = world", text_is(b, "world"));
    U_CHECK("outerHTML (HTML serialization)", p && E->serialize(p, TRUE, &s) == S_OK
            && w_eq(s, "<p id=\"a\" class=\"x y\">Hello <b>world</b></p>"));
    E->str_free(s);
    U_CHECK("node identity: first child twice gives the same pointer", E->node_first_child(body, &first) == S_OK
            && E->node_first_child(body, &again) == S_OK && first == again && first == p);
    if (first) E->node_release(first);
    if (again) E->node_release(again);
    VariantInit(&v);
    U_CHECK("script_eval: E_NOTIMPL (no JavaScript engine)", E->script_eval(doc, L"javascript", L"1", NULL, 0, &v) == E_NOTIMPL);
    if (b) E->node_release(b);
    if (p) E->node_release(p);
    if (body) E->node_release(body);
    E->doc_release(doc);
}

static void test_mutation(void)
{
    static const WCHAR html[] = L"<body><div id=d><p id=p>x</p></div>";
    test_host h;
    shzeng_doc *doc = new_doc(&h, NULL);
    shzeng_node *d, *p, *frag = NULL, *i2 = NULL, *attr = NULL, *clone = NULL;
    shzeng_list *list = NULL, *kids = NULL;
    WCHAR *s = NULL;
    int before;

    E->load_string(doc, html, lstrlenW(html));
    d = by_id(doc, L"d");
    p = by_id(doc, L"p");
    U_CHECK("mutation page parsed", d && p);
    if (!d || !p) { E->doc_release(doc); return; }
    U_CHECK("getElementsByTagName(i) is live (0)", E->get_elements_by(d, SHZENG_BY_TAG, NULL, L"i", &list) == S_OK
            && E->list_length(list) == 0);
    before = h.inserted;
    U_CHECK("parse_fragment in <div>", E->parse_fragment(d, L"<i>1</i><!--c-->", &frag) == S_OK && frag);
    U_CHECK("fragment nodes are not reported before insertion", h.inserted == before);
    U_CHECK("insert the fragment before <p>", E->node_insert_before(d, frag, p) == S_OK);
    U_CHECK("node_inserted per inserted node: i, #text, comment", h.inserted == before + 3);
    U_CHECK("live list sees the new <i>", E->list_length(list) == 1);
    U_CHECK("innerHTML after insertion", E->serialize(d, FALSE, &s) == S_OK && w_eq(s, "<i>1</i><!--c--><p id=\"p\">x</p>"));
    E->str_free(s);
    U_CHECK("create_element(I) is <i>", E->create_element(doc, NULL, L"I", &i2) == S_OK && i2);
    U_CHECK("append it", i2 && E->node_insert_before(d, i2, NULL) == S_OK);
    U_CHECK("live list length 2", E->list_length(list) == 2);
    U_CHECK("childNodes live: 4 children", E->node_child_nodes(d, &kids) == S_OK && E->list_length(kids) == 4);
    U_CHECK("hierarchy error: div into its own child", E->node_insert_before(p, d, NULL) == (HRESULT)0x80530003);
    U_CHECK("remove <p>", E->node_remove_child(d, p) == S_OK && h.removed >= 1);
    U_CHECK("childNodes follows (3)", E->list_length(kids) == 3);
    U_CHECK("removed node stays alive and usable", text_is(p, "x"));
    U_CHECK("setAttribute / getAttribute", E->elem_set_attr(p, L"Title", L"t1") == S_OK && E->elem_get_attr(p, L"title", &s) == S_OK
            && w_eq(s, "t1"));
    E->str_free(s);
    U_CHECK("Attr node reflects the attribute", E->elem_attr_node(p, L"title", &attr) == S_OK && attr
            && E->node_value(attr, &s) == S_OK && w_eq(s, "t1"));
    E->str_free(s);
    U_CHECK("removeAttribute", E->elem_remove_attr(p, L"title") == S_OK && E->elem_get_attr(p, L"title", &s) == S_FALSE && !s);
    U_CHECK("detached Attr node keeps the value", attr && E->node_value(attr, &s) == S_OK && w_eq(s, "t1"));
    E->str_free(s);
    U_CHECK("deep clone serializes the same", E->node_clone(d, TRUE, &clone) == S_OK && clone
            && E->serialize(clone, TRUE, &s) == S_OK && w_eq(s, "<div id=\"d\"><i>1</i><!--c--><i></i></div>"));
    E->str_free(s);
    U_CHECK("textContent setter", E->node_set_text(d, L"plain") == S_OK && E->serialize(d, FALSE, &s) == S_OK && w_eq(s, "plain"));
    E->str_free(s);
    U_CHECK("the old list no longer has <i>", E->list_length(list) == 0);
    if (clone) E->node_release(clone);
    if (attr) E->node_release(attr);
    if (i2) E->node_release(i2);
    if (frag) E->node_release(frag);
    E->list_release(kids);
    E->list_release(list);
    E->node_release(p);
    E->node_release(d);
    E->doc_release(doc);
}

static void test_document_write(void)
{
    static const WCHAR html[] = L"<body><script>w()</script><p id=\"after\">a</p>";
    test_host h;
    shzeng_doc *doc = new_doc(&h, NULL);
    shzeng_node *w, *a;
    WCHAR *s = NULL;
    h.write_in_script = 1;
    E->load_string(doc, html, lstrlenW(html));
    w = by_id(doc, L"written");
    a = by_id(doc, L"after");
    U_CHECK("run_script called for the parser-inserted script", h.scripts == 1);
    U_CHECK("document.write output is in the tree", w != NULL && text_is(w, "w"));
    U_CHECK("written paragraph precedes the rest of the page", w && a && (E->node_compare_position(w, a) & 4));
    if (w) E->node_release(w);
    if (a) E->node_release(a);
    /* document.open/write/close outside the parser replaces the document */
    U_CHECK("doc_open", E->doc_open(doc) == S_OK);
    U_CHECK("doc_write x2", E->doc_write(doc, L"<p id=\"n\">new", FALSE) == S_OK && E->doc_write(doc, L" doc</p>", FALSE) == S_OK);
    U_CHECK("doc_close", E->doc_close(doc) == S_OK);
    a = by_id(doc, L"after");
    w = by_id(doc, L"n");
    U_CHECK("old content is gone, new content parsed", !a && w && text_is(w, "new doc"));
    if (a) E->node_release(a);
    if (w) E->node_release(w);
    U_CHECK("body innerHTML of the written document", E->doc_body(doc, &w) == S_OK && E->serialize(w, FALSE, &s) == S_OK
            && w_eq(s, "<p id=\"n\">new doc</p>"));
    E->str_free(s);
    if (w) E->node_release(w);
    E->doc_release(doc);
}

static void test_reference_page(void)
{
    test_host h;
    shzeng_doc *doc = new_doc(&h, L"file:///C:/SHZ/TESTS/TRIDENT_E1.HTM");
    DWORD len = 0, i;
    BYTE *bytes = read_file(L"C:\\SHZ\\TESTS\\TRIDENT_E1.HTM", &len);
    shzeng_node *euro, *li = NULL, *t = NULL, *root = NULL;
    shzeng_list *l = NULL;
    shzeng_range *r = NULL;
    WCHAR *s = NULL;
    U_CHECK("TRIDENT_E1.HTM read", bytes && len > 600);
    if (!bytes || !doc) return;
    U_CHECK("parser_begin (charset sniffed)", E->parser_begin(doc, NULL) == S_OK);
    for (i = 0; i < len; i += 7) E->parser_feed(doc, bytes + i, len - i < 7 ? len - i : 7);
    U_CHECK("parser_end", E->parser_end(doc) == S_OK);
    HeapFree(GetProcessHeap(), 0, bytes);
    euro = by_id(doc, L"euro");
    E->doc_node(doc, &root);
    /* windows-1252 (from <meta http-equiv>): 0x80 = U+20AC, 0xE9 = U+00E9 */
    U_CHECK("windows-1252 via <meta http-equiv> in 7-byte chunks", euro && E->node_text(euro, FALSE, &s) == S_OK && s
            && lstrlenW(s) == 17 && s[9] == 0x20AC && s[16] == 0xE9);
    E->str_free(s);
    U_CHECK("document.forms: 2", E->doc_collection(doc, SHZENG_COLL_FORMS, &l) == S_OK && E->list_length(l) == 2);
    E->list_release(l);
    U_CHECK("document.images: 1", E->doc_collection(doc, SHZENG_COLL_IMAGES, &l) == S_OK && E->list_length(l) == 1);
    E->list_release(l);
    U_CHECK("document.links: 1", E->doc_collection(doc, SHZENG_COLL_LINKS, &l) == S_OK && E->list_length(l) == 1);
    E->list_release(l);
    U_CHECK("document.anchors: 2", E->doc_collection(doc, SHZENG_COLL_ANCHORS, &l) == S_OK && E->list_length(l) == 2);
    E->list_release(l);
    U_CHECK("forms.namedItem(f2)", E->doc_collection(doc, SHZENG_COLL_FORMS, &l) == S_OK && E->list_named_item(l, L"f2", &t) == S_OK
            && t);
    if (t) E->node_release(t);
    t = NULL;
    E->list_release(l);
    U_CHECK("querySelectorAll(li:nth-child(odd)): 2", E->query_selector(root, L"li:nth-child(odd)", TRUE, NULL, &l) == S_OK
            && E->list_length(l) == 2);
    E->list_release(l);
    U_CHECK("implied tbody: table > tbody > tr > td x2", E->query_selector(root, L"#t > tbody > tr > td + td", FALSE, &t, NULL) == S_OK
            && text_is(t, "2"));
    if (t) E->node_release(t);
    U_CHECK("range over the first <li> text", E->query_selector(root, L"li", FALSE, &li, NULL) == S_OK && li
            && E->range_create(doc, &r) == S_OK);
    if (li && r) {
        shzeng_node *text = NULL;
        E->node_first_child(li, &text);
        U_CHECK("range_set start/end", text && E->range_set(r, FALSE, text, 1) == S_OK && E->range_set(r, TRUE, text, 3) == S_OK);
        U_CHECK("range_text = ne", E->range_text(r, &s) == S_OK && w_eq(s, "ne"));
        E->str_free(s);
        if (text) E->node_release(text);
    }
    if (r) E->range_release(r);
    if (li) E->node_release(li);
    if (euro) E->node_release(euro);
    if (root) E->node_release(root);
    E->doc_release(doc);
}

static void test_lifetime(void)
{
    static const WCHAR html[] = L"<p id=k>keep</p>";
    test_host h;
    shzeng_doc *doc = new_doc(&h, NULL), *owner = NULL;
    shzeng_node *k;
    E->load_string(doc, html, lstrlenW(html));
    k = by_id(doc, L"k");
    E->doc_release(doc);            /* the node keeps its document alive */
    U_CHECK("node usable after doc_release", k && text_is(k, "keep"));
    U_CHECK("node_doc still answers", k && E->node_doc(k, &owner) == S_OK && owner == doc);
    if (k) E->node_release(k);      /* frees the document */
}

/* ---------------------------------------------------------------------------------------------------- L1 */
/* ---- L1 begin: owned by agent L1 (style / computed values, geometry of TRIDENT_L1*.HTM with the 8x16 GDI font,
 * snapshot() pixel checks, doc_set_mode effects on layout). Edit only between these markers. */
static void l1_tests(void)
{
}
/* ---- L1 end */

/* ---------------------------------------------------------------------------------------------------- L2 */
/* ---- L2 begin: owned by agent L2 (event dispatch order with host callbacks, trusted events, form_submission bytes,
 * form_reset, PNG + GIF decode through <img> (natural size, complete, pixels), load / readystate sequence).
 * Edit only between these markers. */
static void l2_tests(void)
{
}
/* ---- L2 end */

int main(void)
{
    HMODULE dll = LoadLibraryW(L"shzlite.dll");
    U_CHECK("LoadLibraryW(shzlite.dll)", dll != NULL);
    if (!dll) return u_finish("t_trident_engine");
    test_interface(dll);
    if (E) {
        test_parse_string();
        test_mutation();
        test_document_write();
        test_reference_page();
        test_lifetime();
        l1_tests();
        l2_tests();
    }
    return u_finish("t_trident_engine");
}
