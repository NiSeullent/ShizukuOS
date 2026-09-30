/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - element attributes and Attr nodes (see dom.h).
 */
#include "dom.h"
#include "observe.h"

static int html_names(const shz_element *e)
{
    return e->ns == SHZ_NS_HTML && e->node.doc->is_html;
}

static int attr_name_eq(const shz_element *e, const shz_attr *a, const shz_char *name, size_t n)
{
    size_t an = shz_strlen(a->name);
    return html_names(e) ? shz_strnieq(a->name, an, name, n) : shz_strneq(a->name, an, name, n);
}

shz_attr *shz_elem_find_attr(shz_node *node, const shz_char *name, size_t n)
{
    shz_element *e = shz_elem(node);
    uint32_t i;
    if (!e || !name) return NULL;
    for (i = 0; i < e->attr_count; ++i)
        if (attr_name_eq(e, &e->attrs[i], name, n)) return &e->attrs[i];
    return NULL;
}

shz_attr *shz_elem_find_attr_id(shz_node *node, int attr_id)
{
    shz_element *e = shz_elem(node);
    uint32_t i;
    if (!e || !attr_id) return NULL;
    for (i = 0; i < e->attr_count; ++i)
        if (e->attrs[i].id == attr_id && e->attrs[i].ns == SHZ_NS_NONE) return &e->attrs[i];
    return NULL;
}

const shz_char *shz_elem_attr(shz_node *elem, int attr_id)
{
    shz_attr *a = shz_elem_find_attr_id(elem, attr_id);
    return a ? a->value : NULL;
}

const shz_char *shz_elem_attr_str(shz_node *elem, const shz_char *name)
{
    shz_attr *a = shz_elem_find_attr(elem, name, shz_strlen(name));
    return a ? a->value : NULL;
}

int shz_elem_has_attr(shz_node *elem, int attr_id)
{
    return shz_elem_find_attr_id(elem, attr_id) != NULL;
}

/* Known-name id: only for plain attributes whose stored name is lower-case (HTML attributes). */
static int name_id(const shz_char *name, size_t n)
{
    return shz_attr_lookup(name, n);
}

shz_res shz_elem_add_attr_raw(shz_node *node, const shz_char *name, size_t n, const shz_char *value, size_t vn)
{
    shz_element *e = shz_elem(node);
    shz_attr *a;
    void *p;
    size_t cap;
    if (!e) return SHZ_E_INVALIDARG;
    p = e->attrs;
    cap = e->attr_cap;
    if (!shz_grow(&p, &cap, (size_t)e->attr_count + 1, sizeof(shz_attr))) return SHZ_E_OUTOFMEMORY;
    e->attrs = p;
    e->attr_cap = (uint32_t)cap;
    a = &e->attrs[e->attr_count];
    memset(a, 0, sizeof(*a));
    a->name = html_names(e) ? shz_strdup_lower(name, n) : shz_strndup(name, n);
    a->value = shz_strndup(value ? value : name, value ? vn : 0);
    if (!a->name || !a->value) {
        shz_free(a->name);
        shz_free(a->value);
        return SHZ_E_OUTOFMEMORY;
    }
    a->value_len = (uint32_t)(value ? vn : 0);
    a->id = (uint16_t)name_id(a->name, n);
    /* xlink:href / xml:lang and friends on foreign elements */
    if (e->ns != SHZ_NS_HTML && n > 6 && shz_strneq_ascii(a->name, 6, "xlink:")) a->ns = SHZ_NS_XLINK, a->id = 0;
    else if (n > 4 && shz_strneq_ascii(a->name, 4, "xml:")) a->ns = SHZ_NS_XML, a->id = 0;
    ++e->attr_count;
    return SHZ_OK;
}

static void notify_attr(shz_node *elem, const shz_char *name, int id)
{
    shz_chg_info info;
    ++elem->doc->version;
    memset(&info, 0, sizeof(info));
    info.what = SHZ_CHG_ATTR;
    info.doc = elem->doc;
    info.node = elem;
    info.attr_name = name;
    info.attr_id = id;
    shz_notify_modules(&info);
}

shz_res shz_elem_set_attr(shz_node *elem, const shz_char *name, size_t n, const shz_char *value, size_t vn)
{
    shz_element *e = shz_elem(elem);
    shz_attr *a;
    shz_res hr;
    shz_char *nameref;
    static const shz_char empty[1] = {0};
    if (!e) return SHZ_E_INVALIDARG;
    if (!shz_is_valid_name(name, n)) return SHZ_E_INVALID_CHAR;
    if (!value) { value = empty; vn = 0; }
    a = shz_elem_find_attr(elem, name, n);
    if (a) {
        shz_char *v;
        if (shz_strneq(a->value, a->value_len, value, vn)) return SHZ_OK;
        v = shz_strndup(value, vn);
        if (!v) return SHZ_E_OUTOFMEMORY;
        shz_free(a->value);
        a->value = v;
        a->value_len = (uint32_t)vn;
    } else {
        hr = shz_elem_add_attr_raw(elem, name, n, value, vn);
        if (SHZ_FAILED(hr)) return hr;
        a = &e->attrs[e->attr_count - 1];
    }
    /* the attribute array may move during notifications: pass a private copy of the name */
    nameref = shz_strdup(a->name);
    notify_attr(elem, nameref ? nameref : a->name, a->id);
    shz_free(nameref);
    return SHZ_OK;
}

shz_res shz_elem_set_attr_id(shz_node *elem, int attr_id, const shz_char *value)
{
    const char *name = shz_attr_name(attr_id);
    shz_char buf[32];
    size_t n = 0;
    if (!attr_id) return SHZ_E_INVALIDARG;
    while (name[n] && n < SHZ_ARRAY_SIZE(buf)) { buf[n] = (unsigned char)name[n]; ++n; }
    return shz_elem_set_attr(elem, buf, n, value, shz_strlen(value));
}

shz_res shz_elem_remove_attr(shz_node *elem, const shz_char *name, size_t n)
{
    shz_element *e = shz_elem(elem);
    shz_attr *a = shz_elem_find_attr(elem, name, n);
    shz_attr removed;
    uint32_t index;
    if (!e) return SHZ_E_INVALIDARG;
    if (!a) return SHZ_FALSE;
    removed = *a;
    index = (uint32_t)(a - e->attrs);
    memmove(e->attrs + index, e->attrs + index + 1, (e->attr_count - index - 1) * sizeof(shz_attr));
    --e->attr_count;
    if (removed.node) {
        /* the Attr node keeps the last value and lets go of its owner */
        shz_attrnode *an = (shz_attrnode *)removed.node;
        an->value = removed.value;
        removed.value = NULL;
        an->owner = NULL;
        shz_node_addref(elem);           /* keep elem alive across the notification below */
        shz_node_release(elem);          /* the Attr node's reference */
    } else {
        shz_node_addref(elem);
    }
    notify_attr(elem, removed.name, removed.id);
    shz_free(removed.name);
    shz_free(removed.value);
    shz_node_release(elem);
    return SHZ_OK;
}

shz_res shz_elem_attr_node(shz_node *elem, const shz_char *name, size_t n, shz_node **out)
{
    shz_attr *a = shz_elem_find_attr(elem, name, n);
    shz_attrnode *an;
    *out = NULL;
    if (!a) return SHZ_FALSE;
    if (a->node) {
        shz_node_addref(a->node);
        *out = a->node;
        return SHZ_OK;
    }
    an = shz_alloc(sizeof(*an));
    if (!an) return SHZ_E_OUTOFMEMORY;
    an->name = shz_strdup(a->name);
    if (!an->name) { shz_free(an); return SHZ_E_OUTOFMEMORY; }
    an->node.type = SHZ_ATTRIBUTE_NODE;
    an->node.doc = elem->doc;
    an->node.refs = 1;
    ++elem->doc->pinned;
    an->owner = elem;
    shz_node_addref(elem);
    a->node = &an->node;
    *out = &an->node;
    return SHZ_OK;
}

const shz_char *shz_attrnode_value(shz_node *node)
{
    static const shz_char empty[1] = {0};
    shz_attrnode *an = (shz_attrnode *)node;
    if (node->type != SHZ_ATTRIBUTE_NODE) return empty;
    if (an->owner) {
        shz_element *e = (shz_element *)an->owner;
        uint32_t i;
        for (i = 0; i < e->attr_count; ++i)
            if (e->attrs[i].node == node) return e->attrs[i].value;
    }
    return an->value ? an->value : empty;
}

const shz_char *shz_attrnode_name(shz_node *node)
{
    return node->type == SHZ_ATTRIBUTE_NODE ? ((shz_attrnode *)node)->name : NULL;
}

int shz_elem_has_class(shz_node *elem, const shz_char *cls, size_t n)
{
    shz_attr *a = shz_elem_find_attr_id(elem, SHZ_ATTR_CLASS);
    if (!a) return 0;
    return shz_token_list_has(a->value, a->value_len, cls, n, shz_doc_quirks(elem->doc) == SHZ_QUIRKS_FULL);
}
