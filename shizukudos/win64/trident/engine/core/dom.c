/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - DOM core: documents, node lifetime, tree mutation and notifications (see dom.h).
 */
#include "dom.h"
#include "observe.h"
#include "html_parser.h"
#include "range.h"
#include "url.h"

static const char *const ns_uris[] = {
    NULL,
    "http://www.w3.org/1999/xhtml",
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1998/Math/MathML",
    "http://www.w3.org/XML/1998/namespace",
    "http://www.w3.org/2000/xmlns/",
    "http://www.w3.org/1999/xlink",
    NULL
};

const char *shz_ns_uri_ascii(int ns)
{
    return ns >= 0 && ns < (int)SHZ_ARRAY_SIZE(ns_uris) ? ns_uris[ns] : NULL;
}

int shz_ns_from_uri(const shz_char *uri)
{
    int i;
    if (!uri || !*uri) return SHZ_NS_NONE;
    for (i = 1; i < (int)SHZ_ARRAY_SIZE(ns_uris); ++i)
        if (ns_uris[i] && shz_streq_ascii(uri, ns_uris[i])) return i;
    return SHZ_NS_OTHER;
}

shz_char *shz_elem_namespace(shz_node *node)
{
    shz_element *e = shz_elem(node);
    if (!e) return NULL;
    if (e->ns == SHZ_NS_OTHER) return shz_strdup(e->ns_uri);
    return ns_uris[e->ns] ? shz_strdup_ascii(ns_uris[e->ns]) : NULL;
}

int shz_is_valid_name(const shz_char *name, size_t n)
{
    size_t i;
    if (!n) return 0;
    if (shz_is_ascii_digit(name[0]) || name[0] == '-' || name[0] == '.') return 0;
    for (i = 0; i < n; ++i) {
        shz_char c = name[i];
        if (shz_is_space(c) || c == '<' || c == '>' || c == '/' || c == '=' || c == '"' || c == '\'' || c == '&'
            || c == 0 || c == '!' || c == '?' || c == '(' || c == ')' || c == ';' || c == ',')
            return 0;
    }
    return 1;
}

/* ---------------------------------------------------------------------------------------------------- documents */

static void doc_maybe_free(shz_doc *doc);
static void destroy_tree(shz_node *root);

shz_res shz_doc_create(const shz_doc_hooks *hooks, void *hooks_ctx, const shz_char *url, const shz_char *mime,
                       shz_doc **out)
{
    shz_doc *doc = shz_alloc(sizeof(*doc));
    shz_node *node;
    *out = NULL;
    if (!doc) return SHZ_E_OUTOFMEMORY;
    node = shz_alloc(sizeof(*node));
    if (!node) { shz_free(doc); return SHZ_E_OUTOFMEMORY; }
    doc->refs = 1;
    doc->scripting = 1;
    doc->hooks = hooks;
    doc->hooks_ctx = hooks_ctx;
    doc->zoom = 1.0f;
    doc->mode = SHZ_MODE_QUIRKS;
    doc->doctype_quirks = SHZ_QUIRKS_FULL;      /* no doctype seen yet: quirks, as HTML specifies */
    doc->ready_state = SHZ_READY_UNINITIALIZED;
    node->type = SHZ_DOCUMENT_NODE;
    node->flags = SHZ_NF_IN_DOC;
    node->doc = doc;
    doc->node = node;
    doc->content_type = mime && *mime ? shz_strdup(mime) : shz_strdup_ascii("text/html");
    doc->is_html = !mime || !*mime || shz_strieq_ascii(mime, "text/html");
    doc->url = url && *url ? shz_strdup(url) : shz_strdup_ascii("about:blank");
    doc->charset = shz_strdup_ascii("UTF-8");
    if (!doc->content_type || !doc->url || !doc->charset) {
        shz_free(doc->content_type);
        shz_free(doc->url);
        shz_free(doc->charset);
        shz_free(node);
        shz_free(doc);
        return SHZ_E_OUTOFMEMORY;
    }
    *out = doc;
    return SHZ_OK;
}

void shz_doc_addref(shz_doc *doc)
{
    if (doc) ++doc->refs;
}

void shz_doc_release(shz_doc *doc)
{
    shz_chg_info info;
    if (!doc || !doc->refs) return;
    if (--doc->refs) return;
    if (doc->closed) { doc_maybe_free(doc); return; }
    doc->closed = 1;                                    /* closing: frees are deferred */
    if (doc->parser) shz_parser_destroy(doc);
    if (doc->selection) {
        shz_range *r = doc->selection;
        doc->selection = NULL;
        shz_range_release(r);
    }
    memset(&info, 0, sizeof(info));
    info.what = SHZ_CHG_DOC_CLOSED;
    info.doc = doc;
    shz_notify_modules(&info);
    doc->closed = 2;
    doc_maybe_free(doc);
}

static void doc_maybe_free(shz_doc *doc)
{
    shz_chg_info info;
    if (!doc || doc->refs || doc->pinned || doc->closed != 2 || doc->freeing) return;
    doc->freeing = 1;
    destroy_tree(doc->node);
    memset(&info, 0, sizeof(info));
    info.what = SHZ_CHG_DOC_DESTROYED;
    info.doc = doc;
    shz_notify_modules(&info);
    if (doc->platform_free) doc->platform_free(doc->platform);
    shz_free(doc->url);
    shz_free(doc->content_type);
    shz_free(doc->charset);
    shz_free(doc);
}

shz_res shz_doc_set_url(shz_doc *doc, const shz_char *url)
{
    shz_char *copy = shz_strdup(url && *url ? url : NULL);
    if (url && *url && !copy) return SHZ_E_OUTOFMEMORY;
    if (!copy) copy = shz_strdup_ascii("about:blank");
    if (!copy) return SHZ_E_OUTOFMEMORY;
    shz_free(doc->url);
    doc->url = copy;
    return SHZ_OK;
}

shz_res shz_doc_set_mode(shz_doc *doc, int mode)
{
    shz_chg_info info;
    if (mode < SHZ_MODE_QUIRKS || mode > SHZ_MODE_IE11) return SHZ_E_INVALIDARG;
    if (doc->mode_set && doc->mode == mode) return SHZ_OK;
    doc->mode = mode;
    doc->mode_set = 1;
    ++doc->version;                     /* quirks affect class/id matching: live lists re-evaluate */
    memset(&info, 0, sizeof(info));
    info.what = SHZ_CHG_MODE;
    info.doc = doc;
    shz_notify_modules(&info);
    return SHZ_OK;
}

int shz_doc_quirks(const shz_doc *doc)
{
    if (!doc->is_html) return SHZ_QUIRKS_NONE;
    if (doc->mode_set) {
        if (doc->mode <= SHZ_MODE_IE5) return SHZ_QUIRKS_FULL;
        if (doc->mode == SHZ_MODE_IE7) return SHZ_QUIRKS_LIMITED;
        return SHZ_QUIRKS_NONE;
    }
    return doc->doctype_quirks;
}

void shz_doc_clear(shz_doc *doc)
{
    shz_chg_info info;
    while (doc->node->first_child) shz_node_remove(doc->node->first_child);
    doc->doctype_quirks = SHZ_QUIRKS_FULL;
    memset(&info, 0, sizeof(info));
    info.what = SHZ_CHG_DOC_RESET;
    info.doc = doc;
    shz_notify_modules(&info);
}

shz_node *shz_doc_element(shz_doc *doc)
{
    return shz_first_element_child(doc->node);
}

shz_node *shz_doc_head(shz_doc *doc)
{
    shz_node *html = shz_doc_element(doc), *c;
    if (!shz_is_tag(html, SHZ_TAG_HTML)) return NULL;
    for (c = html->first_child; c; c = c->next_sibling)
        if (shz_is_tag(c, SHZ_TAG_HEAD)) return c;
    return NULL;
}

shz_node *shz_doc_body(shz_doc *doc)
{
    shz_node *html = shz_doc_element(doc), *c;
    if (!shz_is_tag(html, SHZ_TAG_HTML)) return NULL;
    for (c = html->first_child; c; c = c->next_sibling)
        if (shz_is_tag(c, SHZ_TAG_BODY) || shz_is_tag(c, SHZ_TAG_FRAMESET)) return c;
    return NULL;
}

shz_node *shz_doc_doctype(shz_doc *doc)
{
    shz_node *c;
    for (c = doc->node->first_child; c; c = c->next_sibling)
        if (c->type == SHZ_DOCTYPE_NODE) return c;
    return NULL;
}

shz_node *shz_doc_get_element_by_id(shz_doc *doc, const shz_char *id)
{
    shz_node *n;
    if (!id || !*id) return NULL;
    for (n = doc->node->first_child; n; n = shz_node_next(n, doc->node)) {
        const shz_char *v;
        if (n->type != SHZ_ELEMENT_NODE) continue;
        v = shz_elem_attr(n, SHZ_ATTR_ID);
        if (v && shz_streq(v, id)) return n;
    }
    return NULL;
}

shz_char *shz_doc_resolve_url(shz_doc *doc, const shz_char *rel)
{
    shz_node *head = shz_doc_head(doc), *c;
    const shz_char *href = NULL;
    if (head) {
        for (c = head->first_child; c; c = c->next_sibling) {
            if (shz_is_tag(c, SHZ_TAG_BASE)) {
                href = shz_elem_attr(c, SHZ_ATTR_HREF);
                if (href && *href) break;
                href = NULL;
            }
        }
    }
    if (href) {
        shz_char *base = shz_url_resolve(doc->url, href), *r;
        if (!base) return NULL;
        r = shz_url_resolve(base, rel);
        shz_free(base);
        return r;
    }
    return shz_url_resolve(doc->url, rel);
}

shz_char *shz_doc_title(shz_doc *doc)
{
    shz_node *n, *title = NULL;
    shz_buf b;
    shz_char *text, *p;
    size_t len;
    const shz_char *s;
    for (n = doc->node->first_child; n; n = shz_node_next(n, doc->node))
        if (shz_is_tag(n, SHZ_TAG_TITLE)) { title = n; break; }
    shz_buf_init(&b);
    if (!title) return shz_buf_detach(&b);
    text = shz_node_text_content(title);
    if (!text) return NULL;
    len = shz_strlen(text);
    s = shz_trim(text, &len);
    for (p = (shz_char *)s; p < s + len; ++p) {
        if (shz_is_space(*p)) {
            if (b.len && b.s[b.len - 1] != ' ') shz_buf_putc(&b, ' ');
        } else {
            shz_buf_putc(&b, *p);
        }
    }
    shz_free(text);
    return shz_buf_detach(&b);
}

/* ---------------------------------------------------------------------------------------------------- creation */

static void *node_new(shz_doc *doc, size_t size, int type)
{
    shz_node *n = shz_alloc(size);
    if (!n) return NULL;
    n->type = (uint16_t)type;
    n->doc = doc;
    n->refs = 1;
    ++doc->pinned;
    return n;
}

static shz_node *element_new(shz_doc *doc, int ns, const shz_char *ns_uri, const shz_char *name, size_t n, int lower)
{
    shz_element *e;
    size_t i, colon = (size_t)-1;
    if (!n) return NULL;
    e = node_new(doc, sizeof(*e), SHZ_ELEMENT_NODE);
    if (!e) return NULL;
    e->qname = lower ? shz_strdup_lower(name, n) : shz_strndup(name, n);
    if (ns == SHZ_NS_OTHER) e->ns_uri = shz_strdup(ns_uri);
    if (!e->qname || (ns == SHZ_NS_OTHER && !e->ns_uri)) {
        shz_free(e->qname);
        shz_free(e->ns_uri);
        --doc->pinned;
        shz_free(e);
        return NULL;
    }
    e->qname_len = (uint32_t)n;
    for (i = 0; i < n; ++i)
        if (e->qname[i] == ':') { colon = i; break; }
    e->local = colon != (size_t)-1 && ns != SHZ_NS_HTML ? e->qname + colon + 1 : e->qname;
    e->ns = (uint8_t)ns;
    if (ns == SHZ_NS_HTML) {
        e->tag = (uint16_t)shz_tag_lookup(e->qname, n);
    } else if (ns == SHZ_NS_SVG && shz_streq_ascii(e->local, "svg")) {
        e->tag = SHZ_TAG_SVG;
    } else if (ns == SHZ_NS_MATHML && shz_streq_ascii(e->local, "math")) {
        e->tag = SHZ_TAG_MATH;
    }
    return &e->node;
}

shz_node *shz_create_element(shz_doc *doc, const shz_char *name, size_t n)
{
    if (!doc->is_html) return element_new(doc, SHZ_NS_NONE, NULL, name, n, 0);
    return element_new(doc, SHZ_NS_HTML, NULL, name, n, 1);
}

shz_node *shz_create_element_tag(shz_doc *doc, int tag)
{
    const char *name = shz_tag_name(tag);
    shz_char buf[16];
    size_t n = 0;
    while (name[n] && n < SHZ_ARRAY_SIZE(buf)) { buf[n] = (unsigned char)name[n]; ++n; }
    return element_new(doc, SHZ_NS_HTML, NULL, buf, n, 0);
}

shz_node *shz_create_element_ns(shz_doc *doc, const shz_char *ns_uri, const shz_char *qname, size_t n)
{
    int ns = shz_ns_from_uri(ns_uri);
    return element_new(doc, ns, ns_uri, qname, n, 0);
}

shz_node *shz_create_element_in(shz_doc *doc, int ns, const shz_char *name, size_t n)
{
    return element_new(doc, ns, NULL, name, n, ns == SHZ_NS_HTML && doc->is_html);
}

static shz_node *chardata_new(shz_doc *doc, int type, const shz_char *s, size_t n)
{
    shz_chardata *c = node_new(doc, sizeof(*c), type);
    if (!c) return NULL;
    c->data = shz_strndup(s, n);
    if (!c->data) {
        --doc->pinned;
        shz_free(c);
        return NULL;
    }
    c->len = (uint32_t)n;
    c->cap = (uint32_t)n + 1;
    return &c->node;
}

shz_node *shz_create_text(shz_doc *doc, const shz_char *s, size_t n)
{
    return chardata_new(doc, SHZ_TEXT_NODE, s, n);
}

shz_node *shz_create_comment(shz_doc *doc, const shz_char *s, size_t n)
{
    return chardata_new(doc, SHZ_COMMENT_NODE, s, n);
}

shz_node *shz_create_cdata(shz_doc *doc, const shz_char *s, size_t n)
{
    return chardata_new(doc, SHZ_CDATA_SECTION_NODE, s, n);
}

shz_node *shz_create_pi(shz_doc *doc, const shz_char *target, const shz_char *data, size_t n)
{
    shz_node *node = chardata_new(doc, SHZ_PI_NODE, data, n);
    if (!node) return NULL;
    ((shz_chardata *)node)->target = shz_strdup(target);
    if (!((shz_chardata *)node)->target) {
        shz_node_release(node);
        return NULL;
    }
    return node;
}

shz_node *shz_create_fragment(shz_doc *doc)
{
    return node_new(doc, sizeof(shz_node), SHZ_FRAGMENT_NODE);
}

shz_node *shz_create_doctype(shz_doc *doc, const shz_char *name, const shz_char *public_id, const shz_char *system_id)
{
    shz_doctype *d = node_new(doc, sizeof(*d), SHZ_DOCTYPE_NODE);
    if (!d) return NULL;
    d->name = name ? shz_strdup(name) : shz_alloc(sizeof(shz_char));
    d->public_id = public_id ? shz_strdup(public_id) : NULL;
    d->system_id = system_id ? shz_strdup(system_id) : NULL;
    if (!d->name || (public_id && !d->public_id) || (system_id && !d->system_id)) {
        shz_node_release(&d->node);
        return NULL;
    }
    return &d->node;
}

/* ---------------------------------------------------------------------------------------------------- lifetime */

void shz_node_addref(shz_node *node)
{
    if (!node) return;
    if (node->refs++ == 0) ++node->doc->pinned;
}

void shz_node_release(shz_node *node)
{
    shz_doc *doc;
    if (!node || !node->refs) return;
    if (--node->refs) return;
    doc = node->doc;
    /* the node stays counted in doc->pinned while its tree is destroyed: releases nested in the destruction (an Attr
     * node dropping its owner, module data) must not free the document under us */
    if (!node->parent && node != doc->node && !(node->flags & SHZ_NF_FREEING)) destroy_tree(node);
    --doc->pinned;
    doc_maybe_free(doc);
}

static void free_node(shz_node *node)
{
    shz_chg_info info;
    memset(&info, 0, sizeof(info));
    info.what = SHZ_CHG_DESTROYED;
    info.doc = node->doc;
    info.node = node;
    shz_notify_modules(&info);
    switch (node->type) {
    case SHZ_ELEMENT_NODE: {
        shz_element *e = (shz_element *)node;
        uint32_t i;
        for (i = 0; i < e->attr_count; ++i) {
            shz_attr *a = &e->attrs[i];
            /* An Attr node holds a reference on its owner, so none can exist here. */
            shz_free(a->name);
            shz_free(a->value);
        }
        shz_free(e->attrs);
        shz_free(e->qname);
        shz_free(e->ns_uri);
        break;
    }
    case SHZ_TEXT_NODE: case SHZ_COMMENT_NODE: case SHZ_CDATA_SECTION_NODE: case SHZ_PI_NODE: {
        shz_chardata *c = (shz_chardata *)node;
        shz_free(c->data);
        shz_free(c->target);
        break;
    }
    case SHZ_DOCTYPE_NODE: {
        shz_doctype *d = (shz_doctype *)node;
        shz_free(d->name);
        shz_free(d->public_id);
        shz_free(d->system_id);
        break;
    }
    case SHZ_ATTRIBUTE_NODE: {
        shz_attrnode *a = (shz_attrnode *)node;
        shz_node *owner = a->owner;
        if (owner) {
            shz_element *e = (shz_element *)owner;
            uint32_t i;
            for (i = 0; i < e->attr_count; ++i)
                if (e->attrs[i].node == node) e->attrs[i].node = NULL;
            a->owner = NULL;
        }
        shz_free(a->name);
        shz_free(a->value);
        shz_free(node);
        if (owner) shz_node_release(owner);
        return;
    }
    default:
        break;
    }
    shz_free(node);
}

/* Free root and every descendant without references (iteratively: documents can be deeply nested). Referenced
 * descendants are detached and survive as roots of their own trees. */
static void destroy_tree(shz_node *root)
{
    shz_vec work;
    shz_vec_init(&work);
    root->flags |= SHZ_NF_FREEING;
    if (!shz_vec_push(&work, root)) {
        /* OOM: leak rather than crash */
        return;
    }
    while (work.len) {
        shz_node *n = work.items[work.len - 1];
        shz_node *c = n->first_child;
        if (!c) {
            --work.len;
            free_node(n);
            continue;
        }
        /* unlink the first child */
        n->first_child = c->next_sibling;
        if (c->next_sibling) c->next_sibling->prev_sibling = NULL;
        else n->last_child = NULL;
        c->parent = NULL;
        c->next_sibling = c->prev_sibling = NULL;
        c->flags &= (uint16_t)~SHZ_NF_IN_DOC;
        if (c->refs) {
            /* survives detached: its subtree is no longer connected */
            shz_node *d;
            for (d = c->first_child; d; d = shz_node_next(d, c)) d->flags &= (uint16_t)~SHZ_NF_IN_DOC;
            continue;
        }
        c->flags |= SHZ_NF_FREEING;
        if (!shz_vec_push(&work, c)) break;
    }
    shz_vec_free(&work);
}

/* ---------------------------------------------------------------------------------------------------- traversal */

shz_node *shz_node_next(shz_node *node, const shz_node *root)
{
    if (node->first_child) return node->first_child;
    return shz_node_next_skip(node, root);
}

shz_node *shz_node_next_skip(shz_node *node, const shz_node *root)
{
    while (node && node != root) {
        if (node->next_sibling) return node->next_sibling;
        node = node->parent;
    }
    return NULL;
}

shz_node *shz_node_next_element(shz_node *node, const shz_node *root)
{
    do node = shz_node_next(node, root);
    while (node && node->type != SHZ_ELEMENT_NODE);
    return node;
}

shz_node *shz_first_element_child(shz_node *node)
{
    shz_node *c;
    for (c = node ? node->first_child : NULL; c; c = c->next_sibling)
        if (c->type == SHZ_ELEMENT_NODE) return c;
    return NULL;
}

shz_node *shz_next_element_sibling(shz_node *node)
{
    for (node = node->next_sibling; node; node = node->next_sibling)
        if (node->type == SHZ_ELEMENT_NODE) return node;
    return NULL;
}

shz_node *shz_prev_element_sibling(shz_node *node)
{
    for (node = node->prev_sibling; node; node = node->prev_sibling)
        if (node->type == SHZ_ELEMENT_NODE) return node;
    return NULL;
}

shz_node *shz_node_ancestor_tag(shz_node *node, int tag)
{
    for (; node; node = node->parent)
        if (shz_is_tag(node, tag)) return node;
    return NULL;
}

shz_node *shz_node_root(shz_node *node)
{
    if (node->type == SHZ_ATTRIBUTE_NODE) return node;
    while (node->parent) node = node->parent;
    return node;
}

size_t shz_node_index(const shz_node *node)
{
    size_t i = 0;
    for (node = node->prev_sibling; node; node = node->prev_sibling) ++i;
    return i;
}

size_t shz_node_child_count(const shz_node *node)
{
    size_t i = 0;
    const shz_node *c;
    for (c = node->first_child; c; c = c->next_sibling) ++i;
    return i;
}

shz_node *shz_node_child_at(shz_node *node, size_t index)
{
    shz_node *c;
    for (c = node->first_child; c && index; c = c->next_sibling) --index;
    return c;
}

int shz_node_contains(const shz_node *node, const shz_node *other)
{
    for (; other; other = other->parent)
        if (other == node) return 1;
    return 0;
}

/* tree-order comparison of two nodes of the same tree: -1 when a precedes b */
static int tree_order(shz_node *a, shz_node *b)
{
    shz_node *pa[256], *pb[256], **va = pa, **vb = pb, *n;
    size_t da = 0, db = 0, i;
    int res = 0;
    for (n = a; n; n = n->parent) ++da;
    for (n = b; n; n = n->parent) ++db;
    if (da > SHZ_ARRAY_SIZE(pa)) va = shz_alloc_array(da, sizeof(*va));
    if (db > SHZ_ARRAY_SIZE(pb)) vb = shz_alloc_array(db, sizeof(*vb));
    if (!va || !vb) goto done;
    i = da; for (n = a; n; n = n->parent) va[--i] = n;
    i = db; for (n = b; n; n = n->parent) vb[--i] = n;
    for (i = 0; i < da && i < db && va[i] == vb[i]; ++i) {}
    if (i == da) res = -1;              /* a is an ancestor of b */
    else if (i == db) res = 1;
    else {
        for (n = va[i]; n; n = n->next_sibling)
            if (n == vb[i]) { res = -1; break; }
        if (!res) res = 1;
    }
done:
    if (va != pa) shz_free(va);
    if (vb != pb) shz_free(vb);
    return res;
}

unsigned shz_node_compare_position(shz_node *node, shz_node *other)
{
    shz_node *node1 = other, *node2 = node;
    shz_node *attr1 = NULL, *attr2 = NULL;
    if (node == other) return 0;
    if (node1->type == SHZ_ATTRIBUTE_NODE) { attr1 = node1; node1 = ((shz_attrnode *)attr1)->owner; }
    if (node2->type == SHZ_ATTRIBUTE_NODE) {
        attr2 = node2;
        node2 = ((shz_attrnode *)attr2)->owner;
        if (attr1 && node1 && node2 == node1) {
            shz_element *e = (shz_element *)node2;
            uint32_t i;
            for (i = 0; i < e->attr_count; ++i) {
                if (e->attrs[i].node == attr1) return SHZ_POS_IMPL_SPECIFIC | SHZ_POS_PRECEDING;
                if (e->attrs[i].node == attr2) return SHZ_POS_IMPL_SPECIFIC | SHZ_POS_FOLLOWING;
            }
        }
    }
    if (!node1 || !node2 || shz_node_root(node1) != shz_node_root(node2))
        return SHZ_POS_DISCONNECTED | SHZ_POS_IMPL_SPECIFIC
               | ((uintptr_t)node1 < (uintptr_t)node2 ? SHZ_POS_PRECEDING : SHZ_POS_FOLLOWING);
    if ((!attr1 && node1 != node2 && shz_node_contains(node1, node2)) || (node1 == node2 && attr2))
        return SHZ_POS_CONTAINS | SHZ_POS_PRECEDING;
    if ((!attr2 && node1 != node2 && shz_node_contains(node2, node1)) || (node1 == node2 && attr1))
        return SHZ_POS_CONTAINED_BY | SHZ_POS_FOLLOWING;
    return tree_order(node1, node2) < 0 ? SHZ_POS_PRECEDING : SHZ_POS_FOLLOWING;
}

/* ---------------------------------------------------------------------------------------------------- mutation */

static void set_in_doc(shz_node *root, int on)
{
    shz_node *n;
    for (n = root; n; n = shz_node_next(n, root)) {
        if (on) n->flags |= SHZ_NF_IN_DOC;
        else n->flags &= (uint16_t)~SHZ_NF_IN_DOC;
    }
}

static void link_before(shz_node *parent, shz_node *child, shz_node *ref)
{
    child->parent = parent;
    child->next_sibling = ref;
    child->prev_sibling = ref ? ref->prev_sibling : parent->last_child;
    if (child->prev_sibling) child->prev_sibling->next_sibling = child;
    else parent->first_child = child;
    if (ref) ref->prev_sibling = child;
    else parent->last_child = child;
}

static void unlink_node(shz_node *child)
{
    shz_node *parent = child->parent;
    if (child->prev_sibling) child->prev_sibling->next_sibling = child->next_sibling;
    else parent->first_child = child->next_sibling;
    if (child->next_sibling) child->next_sibling->prev_sibling = child->prev_sibling;
    else parent->last_child = child->prev_sibling;
    child->parent = child->prev_sibling = child->next_sibling = NULL;
}

static void notify_children(shz_doc *doc, shz_node *parent)
{
    shz_chg_info info;
    memset(&info, 0, sizeof(info));
    info.what = SHZ_CHG_CHILDREN;
    info.doc = doc;
    info.node = parent;
    shz_notify_modules(&info);
}

static int in_title(shz_node *n)
{
    for (; n; n = n->parent)
        if (shz_is_tag(n, SHZ_TAG_TITLE)) return 1;
    return 0;
}

void shz_dom_title_maybe_changed(shz_doc *doc, shz_node *changed)
{
    if (!doc->hooks || !doc->hooks->title_changed || !shz_in_doc(changed) || !in_title(changed)) return;
    if (doc->parser && shz_parser_in_title(doc)) return;       /* the parser reports it at </title> */
    doc->hooks->title_changed(doc->hooks_ctx, doc);
}

/* Detach child from its parent with notifications. The caller must hold a reference on child. */
static void remove_with_notify(shz_node *child)
{
    shz_node *parent = child->parent, *n;
    shz_doc *doc = child->doc;
    int was_connected = shz_in_doc(child);
    int title = was_connected && (in_title(parent) || shz_is_tag(child, SHZ_TAG_TITLE));
    shz_vec removed;
    shz_chg_info info;

    shz_vec_init(&removed);
    if (was_connected && doc->hooks && doc->hooks->node_removed) {
        for (n = child; n; n = shz_node_next(n, child))
            if (shz_vec_push(&removed, n)) shz_node_addref(n);
    }
    shz_range_node_removing(child);
    unlink_node(child);
    if (was_connected) set_in_doc(child, 0);
    ++doc->version;
    notify_children(doc, parent);
    if (was_connected) {
        memset(&info, 0, sizeof(info));
        info.what = SHZ_CHG_REMOVED;
        info.doc = doc;
        info.node = child;
        info.other = parent;
        shz_notify_modules(&info);
    }
    if (removed.len) {
        size_t i;
        for (i = 0; i < removed.len; ++i) {
            if (doc->hooks && doc->hooks->node_removed)
                doc->hooks->node_removed(doc->hooks_ctx, doc, removed.items[i]);
        }
        for (i = 0; i < removed.len; ++i) shz_node_release(removed.items[i]);
    }
    shz_vec_free(&removed);
    if (title && doc->hooks && doc->hooks->title_changed && !(doc->parser && shz_parser_in_title(doc)))
        doc->hooks->title_changed(doc->hooks_ctx, doc);
}

void shz_node_remove(shz_node *node)
{
    if (!node || !node->parent) return;
    shz_node_addref(node);
    remove_with_notify(node);
    shz_node_release(node);
}

/* Move a detached subtree into another document. */
static void adopt(shz_node *root, shz_doc *to)
{
    shz_doc *from = root->doc;
    shz_node *n;
    shz_chg_info info;
    if (from == to) return;
    for (n = root; n; n = shz_node_next(n, root)) {
        if (n->refs) { --from->pinned; ++to->pinned; }
        n->doc = to;
        if (n->type == SHZ_ELEMENT_NODE) {
            shz_element *e = (shz_element *)n;
            uint32_t i;
            for (i = 0; i < e->attr_count; ++i) {
                shz_node *an = e->attrs[i].node;
                if (an) {
                    if (an->refs) { --from->pinned; ++to->pinned; }
                    an->doc = to;
                }
            }
        }
    }
    ++from->version;
    memset(&info, 0, sizeof(info));
    info.what = SHZ_CHG_ADOPTED;
    info.doc = to;
    info.node = root;
    info.old_doc = from;
    shz_notify_modules(&info);
}

static int script_needs_run(shz_node *n)
{
    if (!shz_is_tag(n, SHZ_TAG_SCRIPT) || (n->flags & SHZ_NF_STARTED)) return 0;
    if (shz_elem_attr(n, SHZ_ATTR_SRC)) return 1;
    return n->first_child != NULL;
}

/* Link child (parentless, already in parent's document) before ref and send the insertion notifications.
 * run_scripts: DOM insertion (not the parser) prepares newly connected scripts. */
static void insert_and_notify(shz_node *parent, shz_node *child, shz_node *ref, int run_scripts)
{
    shz_doc *doc = parent->doc;
    shz_vec added;
    shz_node *n;
    size_t i;
    shz_chg_info info;
    int connected = shz_in_doc(parent);

    link_before(parent, child, ref);
    if (connected) set_in_doc(child, 1);
    ++doc->version;
    shz_range_node_inserted(child);
    notify_children(doc, parent);
    if (!connected) return;

    shz_vec_init(&added);
    for (n = child; n; n = shz_node_next(n, child))
        if (shz_vec_push(&added, n)) shz_node_addref(n);
    for (i = 0; i < added.len; ++i) {
        n = added.items[i];
        if (!shz_in_doc(n) || n->doc != doc) continue;
        memset(&info, 0, sizeof(info));
        info.what = SHZ_CHG_INSERTED;
        info.doc = doc;
        info.node = n;
        shz_notify_modules(&info);
        if (doc->hooks && doc->hooks->node_inserted && shz_in_doc(n))
            doc->hooks->node_inserted(doc->hooks_ctx, doc, n);
    }
    if (run_scripts) {
        for (i = 0; i < added.len; ++i) {
            n = added.items[i];
            if (!shz_in_doc(n) || n->doc != doc || !script_needs_run(n)) continue;
            n->flags |= SHZ_NF_STARTED;
            if (doc->hooks && doc->hooks->run_script) doc->hooks->run_script(doc->hooks_ctx, doc, n, 0);
        }
    }
    if (in_title(parent) || shz_is_tag(child, SHZ_TAG_TITLE)) shz_dom_title_maybe_changed(doc, child);
    for (i = 0; i < added.len; ++i) shz_node_release(added.items[i]);
    shz_vec_free(&added);
}

void shz_dom_insert_raw(shz_node *parent, shz_node *child, shz_node *ref)
{
    shz_doc *old_doc = child->doc, *new_doc = parent->doc;
    if (old_doc != new_doc) shz_doc_addref(old_doc);   /* adoption may leave it freeable: release it last */
    shz_node_addref(child);                 /* a moved node may have no reference but its old parent's */
    if (child->parent) remove_with_notify(child);
    if (ref && ref->parent != parent) ref = NULL;
    if (child->doc != parent->doc) adopt(child, parent->doc);
    insert_and_notify(parent, child, ref, 0);
    shz_node_release(child);
    if (old_doc != new_doc) shz_doc_release(old_doc);
}

static int can_have_children(const shz_node *n)
{
    return n->type == SHZ_ELEMENT_NODE || n->type == SHZ_DOCUMENT_NODE || n->type == SHZ_FRAGMENT_NODE;
}

static int has_child_type(const shz_node *parent, int type, const shz_node *except)
{
    const shz_node *c;
    for (c = parent->first_child; c; c = c->next_sibling)
        if (c->type == type && c != except) return 1;
    return 0;
}

static int type_follows(const shz_node *child, int type)
{
    for (child = child->next_sibling; child; child = child->next_sibling)
        if (child->type == type) return 1;
    return 0;
}

static int type_precedes(const shz_node *child, int type)
{
    for (child = child->prev_sibling; child; child = child->prev_sibling)
        if (child->type == type) return 1;
    return 0;
}

/* DOM "ensure pre-insertion validity" / "replace" checks. old: the child being replaced (NULL for insertion). */
static shz_res check_insert(shz_node *parent, shz_node *node, shz_node *child, shz_node *old)
{
    if (!can_have_children(parent)) return SHZ_E_HIERARCHY;
    if (shz_node_contains(node, parent)) return SHZ_E_HIERARCHY;
    if (child && child->parent != parent) return SHZ_E_NOT_FOUND;
    switch (node->type) {
    case SHZ_FRAGMENT_NODE: case SHZ_DOCTYPE_NODE: case SHZ_ELEMENT_NODE: case SHZ_TEXT_NODE:
    case SHZ_CDATA_SECTION_NODE: case SHZ_COMMENT_NODE: case SHZ_PI_NODE:
        break;
    default:
        return SHZ_E_HIERARCHY;
    }
    if ((shz_is_text(node) && parent->type == SHZ_DOCUMENT_NODE)
        || (node->type == SHZ_DOCTYPE_NODE && parent->type != SHZ_DOCUMENT_NODE))
        return SHZ_E_HIERARCHY;
    if (parent->type == SHZ_DOCUMENT_NODE) {
        if (node->type == SHZ_FRAGMENT_NODE) {
            size_t elems = 0;
            shz_node *c;
            for (c = node->first_child; c; c = c->next_sibling) {
                if (c->type == SHZ_ELEMENT_NODE) ++elems;
                else if (shz_is_text(c)) return SHZ_E_HIERARCHY;
            }
            if (elems > 1) return SHZ_E_HIERARCHY;
            if (elems == 1 && (has_child_type(parent, SHZ_ELEMENT_NODE, old)
                               || (child && child->type == SHZ_DOCTYPE_NODE && child != old)
                               || (child && type_follows(child, SHZ_DOCTYPE_NODE))))
                return SHZ_E_HIERARCHY;
        } else if (node->type == SHZ_ELEMENT_NODE) {
            if (has_child_type(parent, SHZ_ELEMENT_NODE, old)
                || (child && child->type == SHZ_DOCTYPE_NODE && child != old)
                || (child && type_follows(child, SHZ_DOCTYPE_NODE)))
                return SHZ_E_HIERARCHY;
        } else if (node->type == SHZ_DOCTYPE_NODE) {
            if (has_child_type(parent, SHZ_DOCTYPE_NODE, old)
                || (child && type_precedes(child, SHZ_ELEMENT_NODE))
                || (!child && has_child_type(parent, SHZ_ELEMENT_NODE, old)))
                return SHZ_E_HIERARCHY;
        }
    }
    return SHZ_OK;
}

/* insert node (validated) before ref; handles fragments, removal from the old parent and adoption */
static void do_insert(shz_node *parent, shz_node *node, shz_node *ref)
{
    shz_doc *old_doc = node->doc, *new_doc = parent->doc;
    if (old_doc != new_doc) shz_doc_addref(old_doc);   /* adoption may leave it freeable: release it last */
    if (node->type == SHZ_FRAGMENT_NODE) {
        shz_vec kids;
        shz_node *c;
        size_t i;
        shz_vec_init(&kids);
        for (c = node->first_child; c; c = c->next_sibling)
            if (shz_vec_push(&kids, c)) shz_node_addref(c);
        while (node->first_child) unlink_node(node->first_child);
        ++node->doc->version;
        notify_children(node->doc, node);
        for (i = 0; i < kids.len; ++i) {
            c = kids.items[i];
            if (c->parent) { shz_node_release(c); continue; }       /* moved by a callback meanwhile */
            if (ref && ref->parent != parent) ref = NULL;
            if (c->doc != parent->doc) adopt(c, parent->doc);
            insert_and_notify(parent, c, ref, 1);
            shz_node_release(c);
        }
        shz_vec_free(&kids);
    } else {
        if (node->parent) remove_with_notify(node);
        if (ref && ref->parent != parent) ref = NULL;
        if (node->doc != parent->doc) adopt(node, parent->doc);
        insert_and_notify(parent, node, ref, 1);
    }
    if (old_doc != new_doc) shz_doc_release(old_doc);
}

shz_res shz_node_insert_before(shz_node *parent, shz_node *child, shz_node *ref)
{
    shz_res hr;
    if (!parent || !child) return SHZ_E_INVALIDARG;
    hr = check_insert(parent, child, ref, NULL);
    if (SHZ_FAILED(hr)) return hr;
    if (ref == child) ref = child->next_sibling;
    if (ref == child) return SHZ_OK;
    shz_node_addref(child);
    if (ref) shz_node_addref(ref);
    do_insert(parent, child, ref);
    if (ref) shz_node_release(ref);
    shz_node_release(child);
    return SHZ_OK;
}

shz_res shz_node_append(shz_node *parent, shz_node *child)
{
    return shz_node_insert_before(parent, child, NULL);
}

shz_res shz_node_remove_child(shz_node *parent, shz_node *child)
{
    if (!parent || !child) return SHZ_E_INVALIDARG;
    if (child->parent != parent) return SHZ_E_NOT_FOUND;
    shz_node_remove(child);
    return SHZ_OK;
}

shz_res shz_node_replace_child(shz_node *parent, shz_node *node, shz_node *old)
{
    shz_node *ref;
    shz_res hr;
    if (!parent || !node || !old) return SHZ_E_INVALIDARG;
    if (!can_have_children(parent)) return SHZ_E_HIERARCHY;
    if (old->parent != parent) return SHZ_E_NOT_FOUND;
    hr = check_insert(parent, node, old, old);
    if (SHZ_FAILED(hr)) return hr;
    if (node == old) return SHZ_OK;
    ref = old->next_sibling;
    if (ref == node) ref = node->next_sibling;
    shz_node_addref(node);
    shz_node_addref(old);
    if (ref) shz_node_addref(ref);
    shz_node_remove(old);
    if (!ref || ref->parent == parent) do_insert(parent, node, ref);
    else do_insert(parent, node, NULL);
    if (ref) shz_node_release(ref);
    shz_node_release(old);
    shz_node_release(node);
    return SHZ_OK;
}

/* ---------------------------------------------------------------------------------------------------- clone */

static shz_node *clone_one(shz_node *node, shz_doc *doc)
{
    shz_node *c = NULL;
    switch (node->type) {
    case SHZ_ELEMENT_NODE: {
        shz_element *e = (shz_element *)node;
        uint32_t i;
        c = element_new(doc, e->ns, e->ns_uri, e->qname, e->qname_len, 0);
        if (!c) return NULL;
        c->flags |= node->flags & SHZ_NF_STARTED;          /* a clone of a started script stays started */
        for (i = 0; i < e->attr_count; ++i) {
            shz_attr *a = &e->attrs[i];
            if (SHZ_FAILED(shz_elem_add_attr_raw(c, a->name, shz_strlen(a->name), a->value, a->value_len))) {
                shz_node_release(c);
                return NULL;
            }
            ((shz_element *)c)->attrs[i].ns = a->ns;
        }
        break;
    }
    case SHZ_TEXT_NODE: case SHZ_COMMENT_NODE: case SHZ_CDATA_SECTION_NODE:
        c = chardata_new(doc, node->type, ((shz_chardata *)node)->data, ((shz_chardata *)node)->len);
        break;
    case SHZ_PI_NODE:
        c = shz_create_pi(doc, ((shz_chardata *)node)->target, ((shz_chardata *)node)->data, ((shz_chardata *)node)->len);
        break;
    case SHZ_DOCTYPE_NODE: {
        shz_doctype *d = (shz_doctype *)node;
        c = shz_create_doctype(doc, d->name, d->public_id, d->system_id);
        break;
    }
    case SHZ_FRAGMENT_NODE:
        c = shz_create_fragment(doc);
        break;
    case SHZ_ATTRIBUTE_NODE: {
        shz_attrnode *a = (shz_attrnode *)node, *na = node_new(doc, sizeof(*na), SHZ_ATTRIBUTE_NODE);
        if (!na) return NULL;
        na->name = shz_strdup(a->name);
        na->value = shz_strdup(shz_attrnode_value(node));
        if (!na->name || !na->value) { shz_node_release(&na->node); return NULL; }
        c = &na->node;
        break;
    }
    default:
        return NULL;
    }
    if (c) {
        shz_chg_info info;
        memset(&info, 0, sizeof(info));
        info.what = SHZ_CHG_CLONED;
        info.doc = doc;
        info.node = node;
        info.other = c;
        shz_notify_modules(&info);
    }
    return c;
}

shz_res shz_node_clone(shz_node *node, int deep, shz_node **out)
{
    shz_node *root, *src, *dst;
    *out = NULL;
    if (node->type == SHZ_DOCUMENT_NODE) return SHZ_E_NOT_SUPPORTED;
    root = clone_one(node, node->doc);
    if (!root) return SHZ_E_OUTOFMEMORY;
    if (deep) {
        /* walk the source subtree, mirroring it under root */
        src = node->first_child;
        dst = root;
        while (src) {
            shz_node *c = clone_one(src, node->doc);
            if (!c) { shz_node_release(root); return SHZ_E_OUTOFMEMORY; }
            link_before(dst, c, NULL);
            shz_node_release(c);            /* owned by the tree now */
            if (src->first_child) {
                src = src->first_child;
                dst = c;
                continue;
            }
            while (src != node && !src->next_sibling) {
                src = src->parent;
                dst = dst->parent;
            }
            if (src == node) break;
            src = src->next_sibling;
        }
    }
    *out = root;
    return SHZ_OK;
}

/* ---------------------------------------------------------------------------------------------------- names */

shz_char *shz_node_name(shz_node *node)
{
    const char *fixed = NULL;
    switch (node->type) {
    case SHZ_ELEMENT_NODE: {
        shz_element *e = (shz_element *)node;
        if (e->ns == SHZ_NS_HTML && node->doc->is_html) {
            shz_char *r = shz_strndup(e->qname, e->qname_len);
            uint32_t i;
            if (r) for (i = 0; i < e->qname_len; ++i) r[i] = shz_upper(r[i]);
            return r;
        }
        return shz_strndup(e->qname, e->qname_len);
    }
    case SHZ_ATTRIBUTE_NODE: return shz_strdup(((shz_attrnode *)node)->name);
    case SHZ_TEXT_NODE: fixed = "#text"; break;
    case SHZ_CDATA_SECTION_NODE: fixed = "#cdata-section"; break;
    case SHZ_COMMENT_NODE: fixed = "#comment"; break;
    case SHZ_DOCUMENT_NODE: fixed = "#document"; break;
    case SHZ_FRAGMENT_NODE: fixed = "#document-fragment"; break;
    case SHZ_PI_NODE: return shz_strdup(((shz_chardata *)node)->target);
    case SHZ_DOCTYPE_NODE: return shz_strdup(((shz_doctype *)node)->name);
    default: fixed = ""; break;
    }
    return shz_strdup_ascii(fixed);
}

shz_char *shz_node_value(shz_node *node)
{
    if (shz_is_chardata(node)) return shz_strndup(((shz_chardata *)node)->data, ((shz_chardata *)node)->len);
    if (node->type == SHZ_ATTRIBUTE_NODE) return shz_strdup(shz_attrnode_value(node));
    return NULL;
}

shz_res shz_node_set_value(shz_node *node, const shz_char *value)
{
    if (shz_is_chardata(node)) return shz_chardata_set(node, value, shz_strlen(value));
    if (node->type == SHZ_ATTRIBUTE_NODE) {
        shz_attrnode *a = (shz_attrnode *)node;
        if (a->owner) return shz_elem_set_attr(a->owner, a->name, shz_strlen(a->name), value, shz_strlen(value));
        {
            shz_char *v = value ? shz_strdup(value) : shz_alloc(sizeof(shz_char));
            if (!v) return SHZ_E_OUTOFMEMORY;
            shz_free(a->value);
            a->value = v;
        }
        return SHZ_OK;
    }
    return SHZ_OK;              /* nodeValue of other nodes is null: setting it does nothing */
}
