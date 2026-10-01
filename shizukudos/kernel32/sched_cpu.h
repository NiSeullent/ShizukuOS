/* SPDX-License-Identifier: GPL-2.0-only
 * Internal bounded Kernel32 runqueue operations. All *_locked calls require the
 * same ticket; native callers disable local IRQs before taking it. No allocator,
 * wait, stack switch or callback runs while held. This is not an AP bootstrap.
 */
#ifndef K32_SCHED_CPU_H
#define K32_SCHED_CPU_H
#include "../kcommon/pma_sync.h"
#define K32_CPU_MAX 32u
#define K32_CPU_NONE UINT32_MAX
#define K32_THREAD_MAX 48u

typedef struct {
    thread_t *head, *tail, *current, *idle, *outgoing;
    uint32_t queued;
} k32_cpu_sched_t;
typedef struct {
    pma_ticketlock_t lock;
    thread_t *table;
    uint32_t count, online_mask;
    k32_cpu_sched_t cpu[K32_CPU_MAX];
} k32_runqueues_t;

static inline void k32_rq_init(k32_runqueues_t *r, thread_t *table,
                               uint32_t count, uint32_t online_mask)
{
    memset(r, 0, sizeof *r);
    pma_ticket_init(&r->lock);
    r->table = table;
    r->count = table && count && count <= K32_THREAD_MAX ? count : 0;
    r->online_mask = r->count ? online_mask : 0;
}
static inline uint32_t k32_rq_lock(k32_runqueues_t *r) { return pma_ticket_lock(&r->lock); }
static inline void k32_rq_unlock(k32_runqueues_t *r, uint32_t token)
{
    KASSERT(pma_ticket_unlock(&r->lock, token));
}
static inline int k32_rq_valid(const k32_runqueues_t *r, const thread_t *t)
{
    const uintptr_t base = (uintptr_t)r->table, addr = (uintptr_t)t;
    return t && addr >= base && addr - base < r->count * sizeof *t &&
           (addr - base) % sizeof *t == 0;
}
static inline int k32_rq_cpu_online(const k32_runqueues_t *r, uint32_t cpu)
{
    return cpu < K32_CPU_MAX && (r->online_mask & (1u << cpu)) != 0;
}
static inline uint32_t k32_rq_choose_locked(const k32_runqueues_t *r, uint32_t affinity)
{
    uint32_t best = K32_CPU_NONE;
    if (!affinity || (affinity & ~r->online_mask)) return best;
    for (uint32_t c = 0; c < K32_CPU_MAX; ++c)
        if ((affinity & (1u << c)) &&
            (best == K32_CPU_NONE || r->cpu[c].queued < r->cpu[best].queued)) best = c;
    return best;
}
static inline int k32_rq_enqueue_locked(k32_runqueues_t *r, thread_t *t, uint32_t cpu)
{
    if (!k32_rq_valid(r, t) || !k32_rq_cpu_online(r, cpu) || t->state != 1 ||
        t->on_cpu != K32_CPU_NONE || t->ready_queued || !t->affinity_mask ||
        (t->affinity_mask & ~r->online_mask) || !(t->affinity_mask & (1u << cpu)) ||
        r->cpu[cpu].queued >= r->count || t == r->cpu[cpu].idle) return -1;
    t->ready_next = 0;
    t->ready_cpu = cpu;
    t->ready_queued = 1;
    if (r->cpu[cpu].tail) r->cpu[cpu].tail->ready_next = t;
    else r->cpu[cpu].head = t;
    r->cpu[cpu].tail = t;
    ++r->cpu[cpu].queued;
    return 0;
}
static inline int k32_rq_remove_locked(k32_runqueues_t *r, thread_t *t)
{
    if (!k32_rq_valid(r, t) || !t->ready_queued ||
        !k32_rq_cpu_online(r, t->ready_cpu)) return -1;
    k32_cpu_sched_t *c = &r->cpu[t->ready_cpu];
    thread_t *prev = 0, *it = c->head;
    for (uint32_t n = 0; it && n < r->count; ++n) {
        if (it == t) {
            if (prev) prev->ready_next = t->ready_next;
            else c->head = t->ready_next;
            if (c->tail == t) c->tail = prev;
            --c->queued;
            t->ready_next = 0; t->ready_cpu = K32_CPU_NONE; t->ready_queued = 0;
            return 0;
        }
        prev = it; it = it->ready_next;
    }
    return -1;
}
static inline thread_t *k32_rq_pop_locked(k32_runqueues_t *r, uint32_t cpu)
{
    if (!k32_rq_cpu_online(r, cpu)) return 0;
    thread_t *t = r->cpu[cpu].head;
    if (t && k32_rq_remove_locked(r, t)) return 0;
    return t;
}
/* Affinity transaction is indivisible with queued ownership. No silent mask
 * trimming or migration of an executing context. Equal policy preserves FIFO. */
static inline int k32_rq_affinity_locked(k32_runqueues_t *r, thread_t *t, uint32_t mask)
{
    if (!k32_rq_valid(r, t) || t->state == 0 || t->state >= 4 || !mask ||
        (mask & ~r->online_mask) ||
        (t->on_cpu != K32_CPU_NONE && (!k32_rq_cpu_online(r, t->on_cpu) ||
                                       !(mask & (1u << t->on_cpu))))) return -1;
    if (t->affinity_mask == mask) return 0;
    const int queued = t->ready_queued;
    if (queued && k32_rq_remove_locked(r, t)) return -1;
    t->affinity_mask = mask;
    if (queued) return k32_rq_enqueue_locked(r, t, k32_rq_choose_locked(r, mask));
    return 0;
}
static inline int k32_rq_reapable_locked(const k32_runqueues_t *r, const thread_t *t)
{
    return k32_rq_valid(r, t) && t->state == 4 && t->on_cpu == K32_CPU_NONE && !t->ready_queued;
}
/* Bounded diagnostic, including duplicate/cycle/foreign identity checks. */
static inline int k32_rq_validate_locked(const k32_runqueues_t *r)
{
    uint32_t seen[K32_THREAD_MAX] = {0};
    for (uint32_t c = 0; c < K32_CPU_MAX; ++c) {
        thread_t *t = r->cpu[c].head, *last = 0;
        uint32_t n = 0;
        for (; t && n < r->count; ++n) {
            if (!k32_rq_valid(r, t)) return -1;
            const uint32_t i = (uint32_t)(t - r->table);
            if (seen[i]++ || !t->ready_queued || t->ready_cpu != c || t->state != 1 ||
                t->on_cpu != K32_CPU_NONE || !k32_rq_cpu_online(r, c) ||
                !(t->affinity_mask & (1u << c)) || (t->affinity_mask & ~r->online_mask)) return -1;
            last = t; t = t->ready_next;
        }
        if (t || n != r->cpu[c].queued || last != r->cpu[c].tail) return -1;
    }
    for (uint32_t i = 0; i < r->count; ++i)
        if (!!seen[i] != !!r->table[i].ready_queued) return -1;
    return 0;
}
#endif
