/* SPDX-License-Identifier: GPL-2.0-only */
#include "initonce.h"
static ntw_init_pause pause_fn;
void ntw_init_set_pause(ntw_init_pause pause) { pause_fn = pause; }
int ntw_init_execute(uint32_t *once, ntw_init_fn fn, uint32_t param, uint32_t *context, uint32_t *error) {
    uint32_t state, stored = 0;
    if (!error) return 0;
    if (!once || !fn) { *error = 87; return 0; }
    for (;;) {
        state = *once;
        if (state & 1u) {
            if (context) *context = state & ~1u;
            *error = 0;
            return 1;
        }
        if (state == 0 && __sync_bool_compare_and_swap(once, 0, 2u)) {
            if (!fn((uint32_t)(unsigned long)once, param, &stored) || (stored & 1u)) {
                *once = 0;
                *error = (stored & 1u) ? 87u : 0u;
                return 0;
            }
            *once = stored | 1u;
            if (context) *context = stored;
            *error = 0;
            return 1;
        }
        if (pause_fn) pause_fn();
    }
}
