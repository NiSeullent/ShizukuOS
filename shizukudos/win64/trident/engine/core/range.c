/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - DOM ranges and the selection (see range.h).
 */
#include "range.h"

uint32_t shz_node_length(shz_node *node)
{
    if (node->type == SHZ_DOCTYPE_NODE || node->type == SHZ_ATTRIBUTE_NODE) return 0;
    if (shz_is_chardata(node)) return ((shz_chardata *)node)->len;
    return (uint32_t)shz_node_child_count(node);
}

shz_res shz_range_create(shz_doc *doc, shz_range **out)
{
    shz_range *r = shz_alloc(sizeof(*r));
    *out = NULL;
    if (!r) return SHZ_E_OUTOFMEMORY;
    r->refs = 1;
    r->doc = doc;
    r->start = r->end = doc->node;
    shz_node_addref(doc->node);
    shz_node_addref(doc->node);
    r->next_live = doc->live_ranges;
    if (doc->live_ranges) doc->live_ranges->prev_live = r;
    doc->live_ranges = r;
    *out = r;
    return SHZ_OK;
}

void shz_range_addref(shz_range *r)
{
    if (r) ++r->refs;
}

void shz_range_release(shz_range *r)
{
    shz_doc *doc;
    if (!r || !r->refs || --r->refs) return;
    doc = r->doc;
    if (r->prev_live) r->prev_live->next_live = r->next_live;
    else doc->live_ranges = r->next_live;
    if (r->next_live) r->next_live->prev_live = r->prev_live;
    shz_node_release(r->start);
    shz_node_release(r->end);
    shz_free(r);
}

int shz_boundary_compare(shz_node *a, uint32_t ao, shz_node *b, uint32_t bo)
{
    unsigned pos;
    shz_node *child;
    if (a == b) return ao == bo ? 0 : (ao < bo ? -1 : 1);
    pos = shz_node_compare_position(a, b);
    if (pos & SHZ_POS_FOLLOWING) {
        /* b follows a */
        if (pos & SHZ_POS_CONTAINED_BY) {
            /* b is inside a: find a's child containing b */
            for (child = b; child->parent != a; child = child->parent) {}
            return shz_node_index(child) < ao ? 1 : -1;
        }
        return -1;
    }
    if (pos & SHZ_POS_CONTAINS) {
        /* a is inside b */
        for (child = a; child->parent != b; child = child->parent) {}
        return shz_node_index(child) < bo ? -1 : 1;
    }
    return 1;
}

static void set_point(shz_range *r, int end, shz_node *node, uint32_t off)
{
    shz_node **pn = end ? &r->end : &r->start;
    uint32_t *po = end ? &r->end_off : &r->start_off;
    if (*pn != node) {
        shz_node_addref(node);
        shz_node_release(*pn);
        *pn = node;
    }
    *po = off;
}

shz_res shz_range_set(shz_range *r, int end, shz_node *node, uint32_t offset)
{
    if (!node) return SHZ_E_INVALIDARG;
    if (node->type == SHZ_DOCTYPE_NODE) return SHZ_E_INVALID_STATE;
    if (offset > shz_node_length(node)) return SHZ_E_INDEX_SIZE;
    if (node->doc != r->doc) return SHZ_E_WRONG_DOCUMENT;
    if (!end) {
        if (shz_node_root(node) != shz_node_root(r->end) || shz_boundary_compare(node, offset, r->end, r->end_off) > 0)
            set_point(r, 1, node, offset);
        set_point(r, 0, node, offset);
    } else {
        if (shz_node_root(node) != shz_node_root(r->start) || shz_boundary_compare(node, offset, r->start, r->start_off) < 0)
            set_point(r, 0, node, offset);
        set_point(r, 1, node, offset);
    }
    return SHZ_OK;
}

shz_char *shz_range_text(shz_range *r)
{
    shz_buf b;
    shz_node *n, *stop;
    shz_buf_init(&b);
    if (r->start == r->end && shz_is_text(r->start)) {
        shz_chardata *c = (shz_chardata *)r->start;
        if (r->end_off > r->start_off) shz_buf_put(&b, c->data + r->start_off, r->end_off - r->start_off);
        return shz_buf_detach(&b);
    }
    if (shz_is_text(r->start)) {
        shz_chardata *c = (shz_chardata *)r->start;
        shz_buf_put(&b, c->data + r->start_off, c->len - r->start_off);
    }
    /* first node after the start boundary */
    if (shz_is_chardata(r->start) || !r->start->first_child) n = shz_node_next_skip(r->start, NULL);
    else n = r->start_off < shz_node_child_count(r->start) ? shz_node_child_at(r->start, r->start_off)
                                                          : shz_node_next_skip(r->start, NULL);
    /* the node the end boundary points before */
    if (shz_is_chardata(r->end)) stop = r->end;
    else stop = r->end_off < shz_node_child_count(r->end) ? shz_node_child_at(r->end, r->end_off)
                                                         : shz_node_next_skip(r->end, NULL);
    for (; n && n != stop; n = shz_node_next(n, NULL)) {
        if (n == r->end && shz_is_text(n)) break;
        if (shz_is_text(n)) shz_buf_put(&b, ((shz_chardata *)n)->data, ((shz_chardata *)n)->len);
    }
    if (shz_is_text(r->end) && r->end != r->start)
        shz_buf_put(&b, ((shz_chardata *)r->end)->data, r->end_off);
    return shz_buf_detach(&b);
}

shz_res shz_sel_get(shz_doc *doc, shz_range **out)
{
    *out = doc->selection;
    if (!*out) return SHZ_FALSE;
    shz_range_addref(*out);
    return SHZ_OK;
}

shz_res shz_sel_set(shz_doc *doc, shz_range *r)
{
    shz_range *old = doc->selection;
    if (r && r->doc != doc) return SHZ_E_WRONG_DOCUMENT;
    if (r) shz_range_addref(r);
    doc->selection = r;
    if (old) shz_range_release(old);
    return SHZ_OK;
}

/* ---------------------------------------------------------------------------------------------------- live */

void shz_range_node_removing(shz_node *node)
{
    shz_node *parent = node->parent;
    shz_range *r;
    uint32_t index;
    if (!parent || !node->doc->live_ranges) return;
    index = (uint32_t)shz_node_index(node);
    for (r = node->doc->live_ranges; r; r = r->next_live) {
        if (shz_node_contains(node, r->start)) set_point(r, 0, parent, index);
        else if (r->start == parent && r->start_off > index) --r->start_off;
        if (shz_node_contains(node, r->end)) set_point(r, 1, parent, index);
        else if (r->end == parent && r->end_off > index) --r->end_off;
    }
}

void shz_range_node_inserted(shz_node *node)
{
    shz_node *parent = node->parent;
    shz_range *r;
    uint32_t index;
    if (!parent || !node->doc->live_ranges) return;
    index = (uint32_t)shz_node_index(node);
    for (r = node->doc->live_ranges; r; r = r->next_live) {
        if (r->start == parent && r->start_off > index) ++r->start_off;
        if (r->end == parent && r->end_off > index) ++r->end_off;
    }
}

void shz_range_text_replaced(shz_node *node, uint32_t offset, uint32_t removed, uint32_t added)
{
    shz_range *r;
    for (r = node->doc->live_ranges; r; r = r->next_live) {
        if (r->start == node && r->start_off > offset) {
            if (r->start_off <= offset + removed) r->start_off = offset;
            else r->start_off = r->start_off - removed + added;
        }
        if (r->end == node && r->end_off > offset) {
            if (r->end_off <= offset + removed) r->end_off = offset;
            else r->end_off = r->end_off - removed + added;
        }
    }
}

void shz_range_text_split(shz_node *node, shz_node *tail, uint32_t offset)
{
    shz_range *r;
    for (r = node->doc->live_ranges; r; r = r->next_live) {
        if (r->start == node && r->start_off > offset) set_point(r, 0, tail, r->start_off - offset);
        if (r->end == node && r->end_off > offset) set_point(r, 1, tail, r->end_off - offset);
    }
}
