/* SPDX-License-Identifier: GPL-2.0-only
 * Split virtqueue ring model, see virtq.h. Compiled into Kernel64 and into the host unit test unchanged. */
#include "virtq.h"

int virtq_init(virtq_t *q, uint16_t index, uint16_t size, void *desc, uint64_t desc_pa, void *avail, uint64_t avail_pa,
               void *used, uint64_t used_pa, void **cookies, uint16_t *chain_len)
{
    unsigned i;
    if (!q || !size || size > VIRTQ_MAX_SIZE || !desc || !avail || !used || !cookies || !chain_len) return -1;
    q->size = size;
    q->index = index;
    q->desc = (virtq_desc_t *)desc;
    q->avail = (virtq_avail_t *)avail;
    q->used = (virtq_used_t *)used;
    q->desc_pa = desc_pa;
    q->avail_pa = avail_pa;
    q->used_pa = used_pa;
    q->cookie = cookies;
    q->chain_len = chain_len;
    for (i = 0; i < size; ++i) {                    /* free list threaded through desc[].next, 0 -> 1 -> ... -> size-1 */
        q->desc[i].addr = 0;
        q->desc[i].len = 0;
        q->desc[i].flags = 0;
        q->desc[i].next = (uint16_t)(i + 1);
        q->cookie[i] = 0;
        q->chain_len[i] = 0;
    }
    q->free_head = 0;
    q->num_free = size;
    q->last_used_idx = 0;
    q->avail_pending = 0;
    q->avail->flags = 0;
    q->avail->idx = 0;
    q->n_added = q->n_completed = q->n_kicks = q->n_kicks_suppressed = 0;
    return 0;
}

int virtq_add(virtq_t *q, const virtq_sg_t *out, unsigned n_out, const virtq_sg_t *in, unsigned n_in, void *cookie)
{
    const unsigned total = n_out + n_in;
    uint16_t head, cur, prev = 0;
    unsigned i;
    if (!total || total > q->size || q->num_free < total) return -1;
    head = cur = q->free_head;
    for (i = 0; i < total; ++i) {
        const virtq_sg_t *sg = i < n_out ? &out[i] : &in[i - n_out];
        virtq_desc_t *d = &q->desc[cur];
        d->addr = sg->pa;
        d->len = sg->len;
        d->flags = (uint16_t)((i < n_out ? 0 : VIRTQ_DESC_F_WRITE) | (i + 1 < total ? VIRTQ_DESC_F_NEXT : 0));
        prev = cur;
        cur = d->next;                              /* next free descriptor (kept as the chain link when F_NEXT is set) */
    }
    q->desc[prev].next = 0;                         /* last descriptor of the chain: no link (flags say so too) */
    q->free_head = cur;
    q->num_free = (uint16_t)(q->num_free - total);
    q->cookie[head] = cookie;
    q->chain_len[head] = (uint16_t)total;
    q->avail->ring[(uint16_t)(q->avail->idx + q->avail_pending) % q->size] = head;
    ++q->avail_pending;
    ++q->n_added;
    return head;
}

int virtq_kick_prepare(virtq_t *q)
{
    uint16_t flags;
    if (!q->avail_pending) return 0;
    VIRTQ_WMB();                                    /* descriptors and ring entries before the index */
    q->avail->idx = (uint16_t)(q->avail->idx + q->avail_pending);
    q->avail_pending = 0;
    VIRTQ_MB();                                     /* index visible before the device's flags are examined */
    flags = q->used->flags;
    if (flags & VIRTQ_USED_F_NO_NOTIFY) { ++q->n_kicks_suppressed; return 0; }
    ++q->n_kicks;
    return 1;
}

int virtq_has_used(const virtq_t *q)
{
    const int r = q->last_used_idx != q->used->idx;
    VIRTQ_RMB();
    return r;
}

void *virtq_get_used(virtq_t *q, uint32_t *written)
{
    virtq_used_elem_t e;
    uint16_t head, cur, n, i;
    void *cookie;
    if (q->last_used_idx == q->used->idx) return 0;
    VIRTQ_RMB();                                    /* idx before the element it covers */
    e = q->used->ring[q->last_used_idx % q->size];
    ++q->last_used_idx;
    head = (uint16_t)e.id;
    if (head >= q->size || !q->chain_len[head]) {   /* the device returned an id it never got: ignore it */
        if (written) *written = 0;
        return 0;
    }
    n = q->chain_len[head];
    cookie = q->cookie[head];
    q->cookie[head] = 0;
    q->chain_len[head] = 0;
    for (cur = head, i = 0; i + 1 < n; ++i) cur = q->desc[cur].next;    /* walk to the chain's tail, then splice */
    q->desc[cur].next = q->free_head;
    q->free_head = head;
    q->num_free = (uint16_t)(q->num_free + n);
    ++q->n_completed;
    if (written) *written = e.len;
    return cookie;
}

void virtq_suppress_interrupts(virtq_t *q, int suppress)
{
    q->avail->flags = suppress ? VIRTQ_AVAIL_F_NO_INTERRUPT : 0;
    VIRTQ_MB();
}
