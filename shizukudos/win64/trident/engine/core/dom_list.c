/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - NodeList / HTMLCollection (see dom.h). Live lists cache their items and rebuild the cache
 * when the document's mutation counter (doc->version) moved or the root changed documents.
 */
#include "dom.h"

static shz_list *list_new(int kind, shz_node *root)
{
    shz_list *l = shz_alloc(sizeof(*l));
    if (!l) return NULL;
    l->refs = 1;
    l->kind = (uint8_t)kind;
    l->root = root;
    if (root) shz_node_addref(root);
    shz_vec_init(&l->items);
    return l;
}

shz_list *shz_list_new_static(void)
{
    return list_new(SHZ_LIST_STATIC, NULL);
}

shz_res shz_list_static_push(shz_list *list, shz_node *node)
{
    if (!shz_vec_push(&list->items, node)) return SHZ_E_OUTOFMEMORY;
    shz_node_addref(node);
    return SHZ_OK;
}

shz_list *shz_list_children(shz_node *node)
{
    return list_new(SHZ_LIST_CHILDREN, node);
}

shz_list *shz_list_by(shz_node *root, int by, const shz_char *ns, const shz_char *value)
{
    static const int kinds[] = { SHZ_LIST_BY_TAG, SHZ_LIST_BY_CLASS, SHZ_LIST_BY_NAME, SHZ_LIST_BY_TAG_NS };
    shz_list *l;
    if (by < 0 || by > 3) return NULL;
    l = list_new(kinds[by], root);
    if (!l) return NULL;
    l->arg = value ? shz_strdup(value) : NULL;
    if (by == 3 && ns) l->arg2 = shz_strdup(ns);
    if ((value && !l->arg) || (by == 3 && ns && !l->arg2)) {
        shz_list_release(l);
        return NULL;
    }
    if (by == 0 && l->arg && root->doc->is_html) {
        /* getElementsByTagName in an HTML document: HTML elements match the lower-cased name */
        l->arg2 = shz_strdup_lower(l->arg, shz_strlen(l->arg));
        if (!l->arg2) { shz_list_release(l); return NULL; }
    }
    return l;
}

shz_list *shz_list_collection(shz_doc *doc, int which)
{
    shz_list *l = list_new(SHZ_LIST_COLLECTION, doc->node);
    if (l) l->coll = (uint8_t)which;
    return l;
}

void shz_list_addref(shz_list *list)
{
    if (list) ++list->refs;
}

void shz_list_release(shz_list *list)
{
    size_t i;
    if (!list || !list->refs || --list->refs) return;
    if (list->kind == SHZ_LIST_STATIC)
        for (i = 0; i < list->items.len; ++i) shz_node_release(list->items.items[i]);
    shz_vec_free(&list->items);
    shz_free(list->arg);
    shz_free(list->arg2);
    if (list->root) shz_node_release(list->root);
    shz_free(list);
}

static int class_set_matches(shz_node *elem, const shz_char *set)
{
    size_t n = shz_strlen(set), i = 0, any = 0;
    shz_attr *a = shz_elem_find_attr_id(elem, SHZ_ATTR_CLASS);
    int ci = shz_doc_quirks(elem->doc) == SHZ_QUIRKS_FULL;
    if (!a) return 0;
    while (i < n) {
        size_t start;
        while (i < n && shz_is_space(set[i])) ++i;
        start = i;
        while (i < n && !shz_is_space(set[i])) ++i;
        if (i > start) {
            ++any;
            if (!shz_token_list_has(a->value, a->value_len, set + start, i - start, ci)) return 0;
        }
    }
    return any != 0;
}

static int has_nonempty_attr(shz_node *n, int id)
{
    const shz_char *v = shz_elem_attr(n, id);
    return v != NULL;
}

static int list_matches(shz_list *l, shz_node *n)
{
    shz_element *e = shz_elem(n);
    if (!e) return 0;
    switch (l->kind) {
    case SHZ_LIST_BY_TAG:
        if (!l->arg) return 0;
        if (l->arg[0] == '*' && !l->arg[1]) return 1;
        if (e->ns == SHZ_NS_HTML && n->doc->is_html) return shz_streq(e->qname, l->arg2);
        return shz_streq(e->qname, l->arg);
    case SHZ_LIST_BY_TAG_NS: {
        int any_ns = l->arg2 && l->arg2[0] == '*' && !l->arg2[1];
        int any_local = l->arg && l->arg[0] == '*' && !l->arg[1];
        if (!any_ns) {
            int ns = shz_ns_from_uri(l->arg2);
            if (ns != e->ns) return 0;
            if (ns == SHZ_NS_OTHER && !shz_streq(e->ns_uri, l->arg2)) return 0;
        }
        return any_local || shz_streq(e->local, l->arg);
    }
    case SHZ_LIST_BY_CLASS:
        return l->arg && class_set_matches(n, l->arg);
    case SHZ_LIST_BY_NAME: {
        const shz_char *v = shz_elem_attr(n, SHZ_ATTR_NAME);
        return v && l->arg && shz_streq(v, l->arg);
    }
    case SHZ_LIST_COLLECTION:
        switch (l->coll) {
        case SHZ_COLL_ALL: return 1;
        case SHZ_COLL_FORMS: return shz_is_tag(n, SHZ_TAG_FORM);
        case SHZ_COLL_IMAGES: return shz_is_tag(n, SHZ_TAG_IMG);
        case SHZ_COLL_LINKS:
            return (shz_is_tag(n, SHZ_TAG_A) || shz_is_tag(n, SHZ_TAG_AREA)) && has_nonempty_attr(n, SHZ_ATTR_HREF);
        case SHZ_COLL_ANCHORS: return shz_is_tag(n, SHZ_TAG_A) && has_nonempty_attr(n, SHZ_ATTR_NAME);
        case SHZ_COLL_SCRIPTS: return shz_is_tag(n, SHZ_TAG_SCRIPT);
        case SHZ_COLL_APPLETS: return shz_is_tag(n, SHZ_TAG_APPLET) || shz_is_tag(n, SHZ_TAG_OBJECT);
        case SHZ_COLL_EMBEDS: return shz_is_tag(n, SHZ_TAG_EMBED);
        default: return 0;
        }
    default:
        return 0;
    }
}

static void refresh(shz_list *l)
{
    shz_node *n;
    if (l->kind == SHZ_LIST_STATIC) return;
    if (l->cache_valid && l->cache_doc == l->root->doc && l->cache_version == l->root->doc->version) return;
    l->items.len = 0;
    l->items.oom = 0;
    if (l->kind == SHZ_LIST_CHILDREN) {
        for (n = l->root->first_child; n; n = n->next_sibling) shz_vec_push(&l->items, n);
    } else {
        for (n = l->root->first_child; n; n = shz_node_next(n, l->root))
            if (list_matches(l, n)) shz_vec_push(&l->items, n);
    }
    l->cache_valid = !l->items.oom;
    l->cache_doc = l->root->doc;
    l->cache_version = l->root->doc->version;
}

uint32_t shz_list_length(shz_list *list)
{
    refresh(list);
    return (uint32_t)list->items.len;
}

shz_node *shz_list_item(shz_list *list, uint32_t index)
{
    refresh(list);
    return index < list->items.len ? list->items.items[index] : NULL;
}

shz_node *shz_list_named_item(shz_list *list, const shz_char *name)
{
    size_t i;
    if (!name || !*name) return NULL;
    refresh(list);
    for (i = 0; i < list->items.len; ++i) {
        shz_node *n = list->items.items[i];
        const shz_char *v;
        if (n->type != SHZ_ELEMENT_NODE) continue;
        v = shz_elem_attr(n, SHZ_ATTR_ID);
        if (v && shz_streq(v, name)) return n;
        v = shz_elem_attr(n, SHZ_ATTR_NAME);
        if (v && ((shz_element *)n)->ns == SHZ_NS_HTML && shz_streq(v, name)) return n;
    }
    return NULL;
}
