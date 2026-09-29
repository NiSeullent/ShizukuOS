/* SPDX-License-Identifier: GPL-2.0-only
 * Original sticky clock monitor, reusing the project's division primitive.
 */
#include "budget.h"
uint64_t sdahci_divide(uint64_t value, uint32_t divisor);
int sdfat_clock_sample(struct sdfat_clock *clock, uint64_t ticks, uint64_t *out_us)
{
    uint64_t now;
    if (!clock || !out_us) return -1;
    if (clock->fault) return -1;
    if (clock->ticks_per_us < 10 || clock->ticks_per_us > 100000 ||
        clock->last_tsc < clock->start_tsc) {
        clock->fault = SDFAT_CLOCK_INVALID;
        return -1;
    }
    if (ticks < clock->last_tsc) {
        clock->fault = SDFAT_CLOCK_BACKWARDS;
        return -1;
    }
    if (ticks == clock->last_tsc) {
        if (++clock->stagnant >= SDFAT_STAGNANT_LIMIT) {
            clock->fault = SDFAT_CLOCK_STALLED;
            return -1;
        }
    } else clock->stagnant = 0;
    now = sdahci_divide(ticks - clock->start_tsc, clock->ticks_per_us);
    clock->last_tsc = ticks;
    clock->last_us = now;
    *out_us = now;
    return 0;
}
