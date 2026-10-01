/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - markup serialization (see serialize.h).
 */
#include "serialize.h"

static void escape(shz_buf *b, const shz_char *s, size_t n, int attr, int xml)
{
    size_t i, run = 0;
    for (i = 0; i < n; ++i) {
        const char *rep = NULL;
        switch (s[i]) {
        case '&': rep = "&amp;"; break;
        case 0xA0: rep = xml ? NULL : "&nbsp;"; break;
        case '"': rep = attr ? "&quot;" : NULL; break;
        case '<': rep = "&lt;"; break;
        case '>': rep = "&gt;"; break;
        default: break;
        }
        if (!rep) continue;
        shz_buf_put(b, s + run, i - run);
        shz_buf_put_ascii(b, rep);
        run = i + 1;
    }
    shz_buf_put(b, s + run, n - run);
}

static int raw_text_parent(shz_node *parent)
{
    int tag = shz_tag_of(parent);
    if (!tag) return 0;
    if (tag == SHZ_TAG_NOSCRIPT) return parent->doc->scripting;
    return (shz_tag_flags(tag) & SHZ_TF_RAWTEXT) != 0;
}

static int is_void(shz_node *n)
{
    return (shz_tag_flags(shz_tag_of(n)) & SHZ_TF_VOID) != 0;
}

static void open_tag(shz_buf *b, shz_node *n, int xml, int empty)
{
    shz_element *e = (shz_element *)n;
    uint32_t i;
    shz_buf_putc(b, '<');
    shz_buf_put(b, e->qname, e->qname_len);
    for (i = 0; i < e->attr_count; ++i) {
        shz_buf_putc(b, ' ');
        shz_buf_puts(b, e->attrs[i].name);
        shz_buf_put_ascii(b, "=\"");
        escape(b, e->attrs[i].value, e->attrs[i].value_len, 1, xml);
        shz_buf_putc(b, '"');
    }
    if (xml && empty) shz_buf_put_ascii(b, "/>");
    else shz_buf_putc(b, '>');
}

static void close_tag(shz_buf *b, shz_node *n)
{
    shz_element *e = (shz_element *)n;
    shz_buf_put_ascii(b, "</");
    shz_buf_put(b, e->qname, e->qname_len);
    shz_buf_putc(b, '>');
}

/* serialize one node that is not an element (or the start of an element); returns 1 when its children follow */
static int enter(shz_buf *b, shz_node *n, int xml)
{
    switch (n->type) {
    case SHZ_ELEMENT_NODE:
        if (xml) {
            open_tag(b, n, 1, !n->first_child);
            return n->first_child != NULL;
        }
        open_tag(b, n, 0, 0);
        return !is_void(n);
    case SHZ_TEXT_NODE: {
        shz_chardata *c = (shz_chardata *)n;
        if (!xml && n->parent && raw_text_parent(n->parent)) shz_buf_put(b, c->data, c->len);
        else escape(b, c->data, c->len, 0, xml);
        return 0;
    }
    case SHZ_CDATA_SECTION_NODE: {
        shz_chardata *c = (shz_chardata *)n;
        if (xml) {
            shz_buf_put_ascii(b, "<![CDATA[");
            shz_buf_put(b, c->data, c->len);
            shz_buf_put_ascii(b, "]]>");
        } else {
            escape(b, c->data, c->len, 0, 0);
        }
        return 0;
    }
    case SHZ_COMMENT_NODE: {
        shz_chardata *c = (shz_chardata *)n;
        shz_buf_put_ascii(b, "<!--");
        shz_buf_put(b, c->data, c->len);
        shz_buf_put_ascii(b, "-->");
        return 0;
    }
    case SHZ_PI_NODE: {
        shz_chardata *c = (shz_chardata *)n;
        shz_buf_put_ascii(b, "<?");
        shz_buf_puts(b, c->target);
        shz_buf_putc(b, ' ');
        shz_buf_put(b, c->data, c->len);
        shz_buf_put_ascii(b, xml ? "?>" : ">");
        return 0;
    }
    case SHZ_DOCTYPE_NODE: {
        shz_doctype *d = (shz_doctype *)n;
        shz_buf_put_ascii(b, "<!DOCTYPE ");
        shz_buf_puts(b, d->name);
        if (xml && d->public_id) {
            shz_buf_put_ascii(b, " PUBLIC \"");
            shz_buf_puts(b, d->public_id);
            shz_buf_putc(b, '"');
            if (d->system_id) { shz_buf_put_ascii(b, " \""); shz_buf_puts(b, d->system_id); shz_buf_putc(b, '"'); }
        } else if (xml && d->system_id) {
            shz_buf_put_ascii(b, " SYSTEM \"");
            shz_buf_puts(b, d->system_id);
            shz_buf_putc(b, '"');
        }
        shz_buf_putc(b, '>');
        return 0;
    }
    case SHZ_DOCUMENT_NODE: case SHZ_FRAGMENT_NODE:
        return n->first_child != NULL;
    case SHZ_ATTRIBUTE_NODE:
        escape(b, shz_attrnode_value(n), shz_strlen(shz_attrnode_value(n)), 0, xml);
        return 0;
    default:
        return 0;
    }
}

static void leave(shz_buf *b, shz_node *n, int xml)
{
    if (n->type == SHZ_ELEMENT_NODE && (xml ? n->first_child != NULL : !is_void(n))) close_tag(b, n);
}

shz_char *shz_serialize(shz_node *node, int outer)
{
    shz_buf b;
    shz_node *n;
    int xml = !node->doc->is_html;
    shz_buf_init(&b);
    if (outer) {
        if (!enter(&b, node, xml)) {
            if (node->type == SHZ_ELEMENT_NODE && !xml && !is_void(node)) close_tag(&b, node);
            return shz_buf_detach(&b);
        }
    } else if (node->type == SHZ_ELEMENT_NODE && !xml && is_void(node)) {
        return shz_buf_detach(&b);
    }
    /* children, iteratively */
    n = node->first_child;
    while (n) {
        if (enter(&b, n, xml) && n->first_child) {
            n = n->first_child;
            continue;
        }
        if (n->type == SHZ_ELEMENT_NODE && (xml ? 0 : !is_void(n)) && !n->first_child) close_tag(&b, n);
        while (n != node && !n->next_sibling) {
            n = n->parent;
            if (n == node) break;
            leave(&b, n, xml);
        }
        if (n == node) break;
        n = n->next_sibling;
    }
    if (outer) leave(&b, node, xml);
    return shz_buf_detach(&b);
}
