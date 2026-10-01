/* SPDX-License-Identifier: GPL-2.0-only
 * Finite deadlines for a monotonic uint64 tick clock. The caller must hold
 * its clock/scheduler lock and supply a positive uint32 tick interval in us.
 * Zero is reserved for an infinite wait and is never a finite result.
 */
#ifndef SHZ_SCHED_DEADLINE_H
#define SHZ_SCHED_DEADLINE_H
#include <stdint.h>

static inline uint64_t shz_sched_finite_deadline_ms(uint64_t now, uint32_t ms,
                                                   uint32_t tick_us)
{
    /* Splitting the quotient and remainder keeps every product bounded by
     * UINT32_MAX * 1000, well inside uint64. Ceil via quotient/remainder
     * avoids adding tick_us - 1 to the dividend. tick_us must be positive. */
    const uint64_t remainder_us = (uint64_t)(ms % tick_us) * 1000u;
    uint64_t ticks = (uint64_t)(ms / tick_us) * 1000u;
    ticks += remainder_us / tick_us + (remainder_us % tick_us != 0);
    if (!ticks) ticks = 1;
    /* UINT64_MAX has no representable later absolute tick. Clamping finite
     * addition is not full clock-rollover or terminal-endpoint expiry support. */
    return ticks > UINT64_MAX - now ? UINT64_MAX : now + ticks;
}
#endif
