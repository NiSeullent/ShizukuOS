/* SPDX-License-Identifier: GPL-2.0-only
 * Exact conversion for the block layer's measured TSC ticks per millisecond.
 * Division before multiplication avoids overflowing an absolute TSC value.
 */
#ifndef NTW_AHCI_CLOCK_H
#define NTW_AHCI_CLOCK_H
#include <stdint.h>
static inline uint64_t ahci_ticks_to_us(uint64_t ticks, uint64_t ticks_per_ms)
{
    /* blk_tsc_per_ms() returns 100,000..20,000,000 (or nominal 1,000,000).
     * Reject an unusable denominator without a divide-by-zero fault. */
    if (ticks_per_ms < UINT64_C(100000) || ticks_per_ms > UINT64_C(20000000)) return UINT64_MAX;
    return (ticks / ticks_per_ms) * UINT64_C(1000) +
           ((ticks % ticks_per_ms) * UINT64_C(1000)) / ticks_per_ms;
}
#endif
