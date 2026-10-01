/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - character data, textContent and innerText (see dom.h).
 */
#include "dom.h"
#include "observe.h"
#include "range.h"
#include "style.h"

/* ---------------------------------------------------------------------------------------------------- chardata */

static void notify_text(shz_node *node)
{
    shz_chg_info info;
    memset(&info, 0, sizeof(info));
    info.what = SHZ_CHG_TEXT;
    info.doc = node->doc;
    info.node = node;
    shz_notify_modules(&info);
    shz_dom_title_maybe_changed(node->doc, node);
}

shz_res shz_chardata_replace(shz_node *node, uint32_t offset, uint32_t count, const shz_char *s, size_t n)
{
    shz_chardata *c = shz_cdata(node);
    size_t newlen;
    if (!c) return SHZ_E_INVALIDARG;
    if (offset > c->len) return SHZ_E_INDEX_SIZE;
    if (count > c->len - offset) count = c->len - offset;
    if (n > 0x7fffffff - (size_t)c->len) return SHZ_E_OUTOFMEMORY;
    newlen = c->len - count + n;
    if (newlen + 1 > c->cap) {
        size_t cap = c->cap;
        void *p = c->data;
        if (!shz_grow(&p, &cap, newlen + 1, sizeof(shz_char))) return SHZ_E_OUTOFMEMORY;
        c->data = p;
        c->cap = (uint32_t)cap;
    }
    memmove(c->data + offset + n, c->data + offset + count, (c->len - offset - count) * sizeof(shz_char));
    if (n) memcpy(c->data + offset, s, n * sizeof(shz_char));
    c->len = (uint32_t)newlen;
    c->data[newlen] = 0;
    shz_range_text_replaced(node, offset, count, (uint32_t)n);
    notify_text(node);
    return SHZ_OK;
}

shz_res shz_chardata_set(shz_node *node, const shz_char *s, size_t n)
{
    shz_chardata *c = shz_cdata(node);
    if (!c) return SHZ_E_INVALIDARG;
    return shz_chardata_replace(node, 0, c->len, s, n);
}

shz_res shz_chardata_append(shz_node *node, const shz_char *s, size_t n)
{
    shz_chardata *c = shz_cdata(node);
    if (!c) return SHZ_E_INVALIDARG;
    return shz_chardata_replace(node, c->len, 0, s, n);
}

shz_res shz_text_split(shz_node *node, uint32_t offset, shz_node **tail)
{
    shz_chardata *c = shz_cdata(node);
    shz_node *t;
    *tail = NULL;
    if (!c || !shz_is_text(node)) return SHZ_E_INVALIDARG;
    if (offset > c->len) return SHZ_E_INDEX_SIZE;
    t = node->type == SHZ_CDATA_SECTION_NODE ? shz_create_cdata(node->doc, c->data + offset, c->len - offset)
                                             : shz_create_text(node->doc, c->data + offset, c->len - offset);
    if (!t) return SHZ_E_OUTOFMEMORY;
    if (node->parent) {
        shz_node_addref(node);
        shz_dom_insert_raw(node->parent, t, node->next_sibling);
        shz_range_text_split(node, t, offset);
        shz_node_release(node);
    }
    shz_chardata_replace(node, offset, c->len - offset, NULL, 0);
    *tail = t;
    return SHZ_OK;
}

/* ---------------------------------------------------------------------------------------------------- textContent */

shz_char *shz_node_text_content(shz_node *node)
{
    shz_buf b;
    shz_node *n;
    switch (node->type) {
    case SHZ_DOCUMENT_NODE: case SHZ_DOCTYPE_NODE:
        return NULL;
    case SHZ_ATTRIBUTE_NODE:
        return shz_strdup(shz_attrnode_value(node));
    case SHZ_TEXT_NODE: case SHZ_COMMENT_NODE: case SHZ_CDATA_SECTION_NODE: case SHZ_PI_NODE:
        return shz_strndup(((shz_chardata *)node)->data, ((shz_chardata *)node)->len);
    default:
        break;
    }
    shz_buf_init(&b);
    for (n = node->first_child; n; n = shz_node_next(n, node))
        if (shz_is_text(n)) shz_buf_put(&b, ((shz_chardata *)n)->data, ((shz_chardata *)n)->len);
    return shz_buf_detach(&b);
}

shz_res shz_node_set_text_content(shz_node *node, const shz_char *text)
{
    size_t n = shz_strlen(text);
    shz_node *t;
    shz_res hr = SHZ_OK;
    switch (node->type) {
    case SHZ_DOCUMENT_NODE: case SHZ_DOCTYPE_NODE:
        return SHZ_OK;
    case SHZ_ATTRIBUTE_NODE:
        return shz_node_set_value(node, text);
    case SHZ_TEXT_NODE: case SHZ_COMMENT_NODE: case SHZ_CDATA_SECTION_NODE: case SHZ_PI_NODE:
        return shz_chardata_set(node, text, n);
    default:
        break;
    }
    t = n ? shz_create_text(node->doc, text, n) : NULL;
    if (n && !t) return SHZ_E_OUTOFMEMORY;
    shz_node_addref(node);
    while (node->first_child) shz_node_remove(node->first_child);
    if (t) {
        hr = shz_node_append(node, t);
        shz_node_release(t);
    }
    shz_node_release(node);
    return hr;
}

/* ---------------------------------------------------------------------------------------------------- innerText */

typedef struct {
    shz_buf out;
    int required;           /* pending required line breaks */
    int pending_space;      /* a collapsible space waits for the next visible character */
} itext;

static void it_flush_breaks(itext *t)
{
    if (t->required && t->out.len) {
        int i;
        for (i = 0; i < t->required; ++i) shz_buf_putc(&t->out, '\n');
        t->pending_space = 0;
    }
    t->required = 0;
}

static void it_put_char(itext *t, shz_char c)
{
    it_flush_breaks(t);
    if (t->pending_space) {
        if (t->out.len && t->out.s[t->out.len - 1] != '\n') shz_buf_putc(&t->out, ' ');
        t->pending_space = 0;
    }
    shz_buf_putc(&t->out, c);
}

static void it_text(itext *t, const shz_char *s, size_t n, int ws)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        shz_char c = s[i];
        if (ws == SHZ_WS_PRE || ws == SHZ_WS_PRE_WRAP) {
            it_put_char(t, c);
        } else if (c == '\n' && ws == SHZ_WS_PRE_LINE) {
            t->pending_space = 0;
            it_put_char(t, '\n');
        } else if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f') {
            if (t->out.len || t->required) t->pending_space = 1;
        } else {
            it_put_char(t, c);
        }
    }
}

static void it_break(itext *t, int count)
{
    t->pending_space = 0;
    if (count > t->required) t->required = count;
}

static int is_block_display(int d)
{
    switch (d) {
    case SHZ_DISPLAY_BLOCK: case SHZ_DISPLAY_LIST_ITEM: case SHZ_DISPLAY_TABLE: case SHZ_DISPLAY_TABLE_CAPTION:
    case SHZ_DISPLAY_TABLE_ROW_GROUP: case SHZ_DISPLAY_TABLE_HEADER_GROUP: case SHZ_DISPLAY_TABLE_FOOTER_GROUP:
        return 1;
    default:
        return 0;
    }
}

static int has_next_sibling_display(shz_node *n, int display)
{
    for (n = n->next_sibling; n; n = n->next_sibling)
        if (n->type == SHZ_ELEMENT_NODE && shz_style_display(n) == display) return 1;
    return 0;
}

static void it_open(itext *t, shz_node *n, int d)
{
    if (shz_is_tag(n, SHZ_TAG_BR)) {
        t->pending_space = 0;
        it_put_char(t, '\n');
    } else if (shz_is_tag(n, SHZ_TAG_P)) {
        it_break(t, 2);
    } else if (is_block_display(d)) {
        it_break(t, 1);
    }
}

static void it_close(itext *t, shz_node *n)
{
    int d = shz_style_display(n);
    if (d == SHZ_DISPLAY_TABLE_CELL && has_next_sibling_display(n, SHZ_DISPLAY_TABLE_CELL)) {
        t->pending_space = 0;
        it_put_char(t, '\t');
    } else if (d == SHZ_DISPLAY_TABLE_ROW) {
        it_break(t, 1);
    } else if (shz_is_tag(n, SHZ_TAG_P)) {
        it_break(t, 2);
    } else if (is_block_display(d)) {
        it_break(t, 1);
    }
}

shz_char *shz_node_inner_text(shz_node *node)
{
    itext t;
    shz_node *n;
    if (node->type != SHZ_ELEMENT_NODE) return shz_node_text_content(node);
    if (shz_style_display(node) == SHZ_DISPLAY_NONE) return shz_node_text_content(node);
    memset(&t, 0, sizeof(t));
    shz_buf_init(&t.out);
    n = node->first_child;
    while (n) {
        int enter = 0;
        if (shz_is_text(n)) {
            shz_node *p = n->parent;
            it_text(&t, ((shz_chardata *)n)->data, ((shz_chardata *)n)->len,
                    p && p->type == SHZ_ELEMENT_NODE ? shz_style_white_space(p) : SHZ_WS_NORMAL);
        } else if (n->type == SHZ_ELEMENT_NODE) {
            int d = shz_style_display(n);
            if (d != SHZ_DISPLAY_NONE) {
                it_open(&t, n, d);
                if (n->first_child) enter = 1;
                else it_close(&t, n);
            }
        }
        if (enter) { n = n->first_child; continue; }
        while (n != node && !n->next_sibling) {
            n = n->parent;
            if (n == node) break;
            it_close(&t, n);
        }
        if (n == node) break;
        n = n->next_sibling;
    }
    return shz_buf_detach(&t.out);
}
