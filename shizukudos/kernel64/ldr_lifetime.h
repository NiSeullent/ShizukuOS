/* SPDX-License-Identifier: GPL-2.0-only
 * Loader lifetime primitives. Callers serialize graph changes with the loader
 * mutex and image lifetime changes with irq_save (the kernel is single-CPU).
 * This header is also compiled directly by the host lifetime contract.
 */
#ifndef SHZ_LDR_LIFETIME_H
#define SHZ_LDR_LIFETIME_H
#include <stdint.h>

typedef struct shz_ldr_life shz_ldr_life_t;
typedef struct shz_ldr_edge {
    struct shz_ldr_edge *next;
    shz_ldr_life_t *to;
} shz_ldr_edge_t;
struct shz_ldr_life {
    shz_ldr_life_t *next;
    shz_ldr_edge_t *edges;
    uint32_t refs;
    unsigned root, pinned, retiring, reachable;
};

static inline int shz_ldr_life_addref(shz_ldr_life_t *n, unsigned pin)
{
    if (n->retiring || (!pin && n->refs == UINT32_MAX)) return -1;
    if (pin) n->pinned = 1;
    else ++n->refs;
    return 0;
}

/* Roots include explicit LoadLibrary references, startup images and pins.
 * Edges hold dependencies even when they have no explicit reference. Fixed
 * point reachability releases an unreachable import cycle as one transaction.
 */
static inline void shz_ldr_life_mark(shz_ldr_life_t *head)
{
    shz_ldr_life_t *n;
    unsigned changed;
    for (n = head; n; n = n->next)
        n->reachable = !n->retiring && (n->root || n->pinned || n->refs);
    do {
        changed = 0;
        for (n = head; n; n = n->next) {
            shz_ldr_edge_t *e;
            if (!n->reachable) continue;
            for (e = n->edges; e; e = e->next)
                if (!e->to->retiring && !e->to->reachable) {
                    e->to->reachable = 1;
                    changed = 1;
                }
        }
    } while (changed);
}

static inline int shz_ldr_life_has_edge(const shz_ldr_life_t *from, const shz_ldr_life_t *to)
{
    const shz_ldr_edge_t *e;
    for (e = from->edges; e; e = e->next) if (e->to == to) return 1;
    return 0;
}

/* The module owns one image reference. Each blocked page-in owns another.
 * Retiring the owner forbids new page-ins and publication of old I/O results;
 * the final reference, which may be a page-in, releases the image metadata.
 */
typedef struct { uint32_t refs; unsigned retired; } shz_ldr_image_life_t;
static inline int shz_ldr_image_acquire(shz_ldr_image_life_t *n)
{
    if (n->retired || !n->refs || n->refs == UINT32_MAX) return -1;
    ++n->refs;
    return 0;
}
static inline int shz_ldr_image_release(shz_ldr_image_life_t *n)
{
    return n->refs && --n->refs == 0;
}
static inline int shz_ldr_image_retire(shz_ldr_image_life_t *n)
{
    if (n->retired) return 0;
    n->retired = 1;
    return shz_ldr_image_release(n);
}
#endif
