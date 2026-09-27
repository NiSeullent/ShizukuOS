/* SPDX-License-Identifier: GPL-2.0-only
 * Independent algorithm: bit 0 exclusive; remaining bits reader count.
 * Lock state is an implementation detail, not an NT internal structure. */
#include "sync.h"
void ntw_srw_init(ntw_srw *s) { __atomic_store_n(&s->state, 0, __ATOMIC_RELAXED); }
int ntw_srw_try_exclusive(ntw_srw *s) {
    uint32_t expected = 0;
    return __atomic_compare_exchange_n(&s->state, &expected, 1, 0,
                                       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}
int ntw_srw_try_shared(ntw_srw *s) {
    uint32_t value = __atomic_load_n(&s->state, __ATOMIC_RELAXED);
    for (;;) {
        if ((value & 1u) || value == 0xfffffffeu) return 0;
        if (__atomic_compare_exchange_n(&s->state, &value, value + 2u, 0,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return 1;
    }
}
void ntw_srw_acquire_exclusive(ntw_srw *s, ntw_yield_fn yield) {
    while (!ntw_srw_try_exclusive(s)) yield();
}
void ntw_srw_acquire_shared(ntw_srw *s, ntw_yield_fn yield) {
    while (!ntw_srw_try_shared(s)) yield();
}
void ntw_srw_release_exclusive(ntw_srw *s) { __atomic_store_n(&s->state, 0, __ATOMIC_RELEASE); }
void ntw_srw_release_shared(ntw_srw *s) { (void)__atomic_fetch_sub(&s->state, 2u, __ATOMIC_RELEASE); }
uint64_t ntw_tick_sample(struct ntw_tick_clock *c, uint32_t now) {
    if (now < c->previous) ++c->high;
    c->previous = now;
    return ((uint64_t)c->high << 32) | now;
}
