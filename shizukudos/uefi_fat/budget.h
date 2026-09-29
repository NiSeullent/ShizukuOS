/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SDFAT_BUDGET_H
#define SDFAT_BUDGET_H
#include <stdint.h>
#define SDFAT_CLOCK_BACKWARDS 1u
#define SDFAT_CLOCK_STALLED 2u
#define SDFAT_CLOCK_INVALID 3u
#define SDFAT_STAGNANT_LIMIT 64u
struct sdfat_clock {
    uint64_t start_tsc, last_tsc, last_us;
    uint32_t ticks_per_us, stagnant, fault;
};
/* Initialize all fields to zero except start_tsc=last_tsc=calibrated origin,
 * ticks_per_us=10..100000. Failure is sticky and does not modify *out_us.
 * Repeated RAW ticks are counted, not rounded microseconds. A faulty clock
 * supplies no elapsed-time guarantee; callers still require an external timer.
 */
int sdfat_clock_sample(struct sdfat_clock *, uint64_t ticks, uint64_t *out_us);
#endif
