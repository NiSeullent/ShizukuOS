/* SPDX-License-Identifier: GPL-2.0-only
 * Bounded internal Kernel64 priority/FIFO CPU queues. Every *_locked operation
 * requires one common ticket. Native callers mask local IRQs before admission;
 * never allocate, call external callbacks, wait or switch stacks while held.
 * The online mask is an owner-provided fact, not an AP bootstrap operation.
 */
#ifndef K64_SCHED_CPU_H
#define K64_SCHED_CPU_H
#include "../kcommon/pma_sync.h"
#define K64_CPU_MAX 32u
#define K64_CPU_NONE UINT32_MAX
#define K64_THREAD_MAX 1024u

typedef struct {
    struct { thread_t *head, *tail; } ready[SCHED_PRIORITY_LEVELS];
    uint32_t ready_mask, ready_count;
    thread_t *current, *idle, *outgoing;
    uint64_t idle_ticks, kernel_ticks, user_ticks;
    int tick_from_user;
} k64_cpu_sched_t;
typedef struct {
    pma_ticketlock_t lock;
    thread_t *table;
    uint32_t count;
    uint64_t online_mask;
    k64_cpu_sched_t cpu[K64_CPU_MAX];
} k64_runqueues_t;
static inline void k64_rq_init(k64_runqueues_t *r, thread_t *table, uint32_t count, uint64_t online_mask)
{
    memset(r, 0, sizeof *r);
    pma_ticket_init(&r->lock);
    r->table = table;
    r->count = table && count && count <= K64_THREAD_MAX ? count : 0;
    r->online_mask = r->count && !(online_mask >> K64_CPU_MAX) ? online_mask : 0;
}
static inline uint32_t k64_rq_lock(k64_runqueues_t *r) { return pma_ticket_lock(&r->lock); }
static inline void k64_rq_unlock(k64_runqueues_t *r, uint32_t ticket) { KASSERT(pma_ticket_unlock(&r->lock, ticket)); }
static inline int k64_rq_valid(const k64_runqueues_t *r, const thread_t *t)
{
    uintptr_t base = (uintptr_t)r->table, addr = (uintptr_t)t;
    return t && addr >= base && addr - base < r->count * sizeof *t && (addr - base) % sizeof *t == 0;
}
static inline int k64_rq_online(const k64_runqueues_t *r, uint32_t cpu)
{
    return cpu < K64_CPU_MAX && (r->online_mask & (1ull << cpu)) != 0;
}
static inline uint32_t k64_rq_choose_locked(const k64_runqueues_t *r, uint64_t mask)
{
    uint32_t best = K64_CPU_NONE;
    if (!mask || (mask & ~r->online_mask)) return best;
    for (uint32_t c = 0; c < K64_CPU_MAX; ++c)
        if ((mask & (1ull << c)) && (best == K64_CPU_NONE || r->cpu[c].ready_count < r->cpu[best].ready_count)) best = c;
    return best;
}
static inline int k64_rq_enqueue_locked(k64_runqueues_t *r, thread_t *t, uint32_t cpu, uint64_t since, uint64_t order)
{
    if (!k64_rq_valid(r, t) || !k64_rq_online(r, cpu) || t->state != TS_READY || t->ready_queued ||
        t->on_cpu != K64_CPU_NONE || t->sched_priority >= SCHED_PRIORITY_LEVELS || !t->cpu_mask ||
        (t->cpu_mask & ~r->online_mask) || !(t->cpu_mask & (1ull << cpu)) || t == r->cpu[cpu].idle ||
        r->cpu[cpu].ready_count >= r->count) return -1;
    k64_cpu_sched_t *c = &r->cpu[cpu];
    const uint32_t p = t->sched_priority;
    t->ready_prev = c->ready[p].tail;
    t->ready_next = 0;
    if (t->ready_prev) t->ready_prev->ready_next = t;
    else c->ready[p].head = t;
    c->ready[p].tail = t;
    t->ready_since = since;
    t->ready_order = order;
    t->ready_queued = 1;
    t->ready_cpu = cpu;
    t->aging_service_left = 0;
    c->ready_mask |= 1u << p;
    ++c->ready_count;
    return 0;
}
static inline int k64_rq_remove_locked(k64_runqueues_t *r, thread_t *t)
{
    if (!k64_rq_valid(r, t) || !t->ready_queued || !k64_rq_online(r, t->ready_cpu) ||
        t->sched_priority >= SCHED_PRIORITY_LEVELS) return -1;
    k64_cpu_sched_t *c = &r->cpu[t->ready_cpu];
    const uint32_t p = t->sched_priority;
    if ((t->ready_prev && (!k64_rq_valid(r, t->ready_prev) || t->ready_prev->ready_next != t)) ||
        (t->ready_next && (!k64_rq_valid(r, t->ready_next) || t->ready_next->ready_prev != t))) return -1;
    if (!c->ready_count || (!t->ready_prev && c->ready[p].head != t) ||
        (!t->ready_next && c->ready[p].tail != t)) return -1;
    if (t->ready_prev) t->ready_prev->ready_next = t->ready_next;
    else c->ready[p].head = t->ready_next;
    if (t->ready_next) t->ready_next->ready_prev = t->ready_prev;
    else c->ready[p].tail = t->ready_prev;
    if (!c->ready[p].head) c->ready_mask &= ~(1u << p);
    t->ready_prev = t->ready_next = 0;
    t->ready_queued = 0;
    t->ready_cpu = K64_CPU_NONE;
    --c->ready_count;
    return 0;
}
static inline thread_t *k64_rq_aged_locked(k64_runqueues_t *r, uint32_t cpu, uint64_t now)
{
    if (!k64_rq_online(r, cpu)) return 0;
    thread_t *oldest = 0;
    for (int p = SCHED_PRIORITY_LEVELS - 1; p >= 0; --p) {
        thread_t *t = r->cpu[cpu].ready[p].head;
        if (t && now - t->ready_since >= SCHED_STARVATION_TICKS &&
            (!oldest || t->ready_order < oldest->ready_order)) oldest = t;
    }
    return oldest;
}
static inline thread_t *k64_rq_pick_locked(k64_runqueues_t *r, uint32_t cpu, uint64_t now, int *aged)
{
    *aged = 0;
    if (!k64_rq_online(r, cpu)) return 0;
    thread_t *t = k64_rq_aged_locked(r, cpu, now);
    if (t) { *aged = 1; return t; }
    for (int p = SCHED_PRIORITY_LEVELS - 1; p >= 0; --p)
        if (r->cpu[cpu].ready_mask & (1u << p)) return r->cpu[cpu].ready[p].head;
    return 0;
}
static inline int k64_rq_policy_locked(k64_runqueues_t *r, thread_t *t, uint32_t priority,
                                      uint32_t quantum, uint64_t mask, uint64_t now, uint64_t order)
{
    if (!k64_rq_valid(r, t) || t->state == TS_FREE || t->state == TS_ZOMBIE ||
        priority >= SCHED_PRIORITY_LEVELS || !quantum || quantum > SCHED_MAX_QUANTUM_TICKS ||
        !mask || (mask & ~r->online_mask) || (t->on_cpu != K64_CPU_NONE &&
        (!k64_rq_online(r, t->on_cpu) || !(mask & (1ull << t->on_cpu))))) return -1;
    if (t->ready_queued && (t->on_cpu != K64_CPU_NONE || !k64_rq_online(r, t->ready_cpu))) return -1;
    for (uint32_t c = 0; c < K64_CPU_MAX; ++c) if (t == r->cpu[c].idle) return -1;
    int move = t->ready_queued && (priority != t->sched_priority || !(mask & (1ull << t->ready_cpu)));
    if (move && k64_rq_remove_locked(r, t)) return -1;
    t->sched_priority = priority;
    t->quantum_ticks = quantum;
    if (t->state != TS_RUNNING || t->quantum_left > quantum) t->quantum_left = quantum;
    t->cpu_mask = mask;
    if (move) return k64_rq_enqueue_locked(r, t, k64_rq_choose_locked(r, mask), now, order);
    return 0;
}
static inline int k64_rq_reapable_locked(const k64_runqueues_t *r, const thread_t *t)
{
    return k64_rq_valid(r, t) && t->state == TS_ZOMBIE && t->on_cpu == K64_CPU_NONE && !t->ready_queued;
}
static inline int k64_rq_validate_locked(const k64_runqueues_t *r)
{
    uint8_t seen[K64_THREAD_MAX] = {0};
    for (uint32_t c = 0; c < K64_CPU_MAX; ++c) {
        uint32_t n = 0, mask = 0;
        for (uint32_t p = 0; p < SCHED_PRIORITY_LEVELS; ++p) {
            thread_t *prev = 0, *t = r->cpu[c].ready[p].head;
            if (t) mask |= 1u << p;
            while (t) {
                if (++n > r->count || !k64_rq_valid(r, t)) return -1;
                uint32_t i = (uint32_t)(t - r->table);
                if (seen[i]++ || t->state != TS_READY || !t->ready_queued || t->ready_cpu != c ||
                    t->on_cpu != K64_CPU_NONE || t->sched_priority != p || t->ready_prev != prev ||
                    !k64_rq_online(r, c) || !(t->cpu_mask & (1ull << c)) || (t->cpu_mask & ~r->online_mask)) return -1;
                prev = t; t = t->ready_next;
            }
            if (prev != r->cpu[c].ready[p].tail) return -1;
        }
        if (n != r->cpu[c].ready_count || mask != r->cpu[c].ready_mask) return -1;
    }
    for (uint32_t i = 0; i < r->count; ++i)
        if (!!r->table[i].ready_queued != !!seen[i] || (!seen[i] && (r->table[i].ready_prev || r->table[i].ready_next))) return -1;
    return 0;
}
#endif
