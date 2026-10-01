/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - DOM ranges and the document selection (core, engine.h range_* / sel_*).
 *
 * A range holds references on its boundary nodes and stays valid across mutations: dom.c reports removals,
 * insertions and character-data changes, and boundary points move as the DOM Standard's "live range" rules say.
 */
#ifndef SHZ_RANGE_H
#define SHZ_RANGE_H

#include "dom.h"

struct shzeng_range {
    uint32_t refs;
    shz_doc *doc;                       /* kept alive by the boundary node references (no document reference) */
    shz_node *start, *end;              /* references held */
    uint32_t start_off, end_off;
    shz_range *prev_live, *next_live;   /* doc->live_ranges */
};

shz_res   shz_range_create(shz_doc *doc, shz_range **out);          /* collapsed at (document, 0) */
void      shz_range_addref(shz_range *r);
void      shz_range_release(shz_range *r);
/* DOM setStart/setEnd: SHZ_E_INDEX_SIZE for an offset past the node's length, SHZ_E_INVALID_STATE for a doctype.
 * If the new start is after the end (or the end before the start) the range collapses to the new point. */
shz_res   shz_range_set(shz_range *r, int end, shz_node *node, uint32_t offset);
/* length of a node for boundary purposes: character count or child count */
uint32_t  shz_node_length(shz_node *node);
/* Text of the range (text nodes only, tree order), allocated. */
shz_char *shz_range_text(shz_range *r);
/* -1 / 0 / 1: boundary point (a, ao) before / equal / after (b, bo) (same tree assumed) */
int       shz_boundary_compare(shz_node *a, uint32_t ao, shz_node *b, uint32_t bo);

/* the document selection: at most one range (NULL clears) */
shz_res   shz_sel_get(shz_doc *doc, shz_range **out);               /* SHZ_FALSE + NULL when there is none */
shz_res   shz_sel_set(shz_doc *doc, shz_range *r);

/* mutation hooks called by dom.c */
void      shz_range_node_removing(shz_node *node);                   /* before node is unlinked from its parent */
void      shz_range_node_inserted(shz_node *node);                   /* after node was linked */
void      shz_range_text_replaced(shz_node *node, uint32_t offset, uint32_t removed, uint32_t added);
void      shz_range_text_split(shz_node *node, shz_node *tail, uint32_t offset);

#endif /* SHZ_RANGE_H */
