/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - how the DOM tells the other modules about changes.
 *
 * The DOM (core) calls exactly two dispatchers, one per follow-up workstream, so that each agent owns its fan-out:
 *   shz_render_dom_changed()    L1: css / style / layout (style.c implements it)
 *   shz_interact_dom_changed()  L2: events / forms / images / loader (events.c implements it)
 * Both have weak no-op stubs in core/stubs_l1.c and core/stubs_l2.c until then.
 *
 * Order for one mutation: the tree is updated, doc->version is bumped, then for every affected node:
 * shz_render_dom_changed, shz_interact_dom_changed, and finally the host callback (node_inserted / node_removed).
 * The host may mutate the tree from its callback; the DOM re-checks connectedness before each notification.
 */
#ifndef SHZ_OBSERVE_H
#define SHZ_OBSERVE_H

#include "dom.h"

typedef enum {
    SHZ_CHG_INSERTED = 1,   /* node became connected (once per node, tree order; also for parser insertions) */
    SHZ_CHG_REMOVED,        /* node (root of a subtree) was disconnected; other = the old parent. Called after the
                             * removal; the subtree's SHZ_NF_IN_DOC flags are already clear. */
    SHZ_CHG_CHILDREN,       /* node's child list changed (any tree, connected or not); sent once per mutation */
    SHZ_CHG_ATTR,           /* attribute attr_name (attr_id) of element node was set/changed/removed (any tree) */
    SHZ_CHG_TEXT,           /* character data of node changed (any tree) */
    SHZ_CHG_ADOPTED,        /* node (subtree root, detached) moved from old_doc to node->doc */
    SHZ_CHG_CLONED,         /* other = the fresh clone of node (copy module state such as form control values) */
    SHZ_CHG_DESTROYED,      /* node is being freed: release node->box / listeners / elem->style / ctl / img */
    SHZ_CHG_DOC_CLOSED,     /* doc->refs reached 0: release module references on nodes (focus, hover, events...) */
    SHZ_CHG_DOC_DESTROYED,  /* the document is being freed: release doc->css / layout / events / forms / ... */
    SHZ_CHG_DOC_RESET,      /* the document was emptied for a new load (load_string, parser_begin, document.open) */
    SHZ_CHG_MODE            /* doc_set_mode changed doc->mode (restyle / relayout) */
} shz_chg;

typedef struct shz_chg_info {
    shz_chg what;
    shz_doc *doc;               /* the document concerned (node->doc, or the document for DOC_*) */
    shz_node *node;             /* the node concerned (NULL for DOC_*) */
    shz_node *other;            /* REMOVED: old parent; CLONED: the clone */
    shz_doc *old_doc;           /* ADOPTED */
    const shz_char *attr_name;  /* ATTR: the attribute's (qualified) name */
    int attr_id;                /* ATTR: SHZ_ATTR_* or 0 */
} shz_chg_info;

void shz_render_dom_changed(const shz_chg_info *info);     /* L1 */
void shz_interact_dom_changed(const shz_chg_info *info);   /* L2 */

/* convenience used by dom.c and the parser */
static inline void shz_notify_modules(const shz_chg_info *info)
{
    shz_render_dom_changed(info);
    shz_interact_dom_changed(info);
}

#endif /* SHZ_OBSERVE_H */
