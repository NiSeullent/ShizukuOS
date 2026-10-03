/* SPDX-License-Identifier: GPL-2.0-only -- original Core clock contract. */
#ifndef SHZ_CLOCK_H
#define SHZ_CLOCK_H
#include "shz_abi.h"

#define SHZ_CLOCK_VERSION 1u
#define SHZ_CLOCK_MAGIC 0x4b435a53u /* SZCK */
#define SHZ_CLOCK_FREQUENCY UINT64_C(1000000000)

/* Fixed-width DIOC reply. No user pointer crosses the Core boundary. */
typedef struct shz_clock_reply {
    uint32_t magic, size, version, reserved;
    uint64_t counter, frequency;
} shz_clock_reply_t;
_Static_assert(sizeof(shz_clock_reply_t) == 32, "Core clock reply ABI");

/* The Core uses its existing boot TSC origin and measured frequency. Reject
 * uninitialized clocks and arithmetic outside the signed API count range.
 * Frequency is a normalization unit, not a claim of nanosecond resolution. */
static inline int32_t shz_clock_ticks_ns(uint64_t ticks, uint64_t hz, uint64_t *value)
{
    uint64_t sec, fraction, ns;
    if (!value || !hz) return SHZ_E_INVALID;
    if (hz > UINT64_MAX / SHZ_CLOCK_FREQUENCY) return SHZ_E_RANGE;
    sec = ticks / hz;
    if (sec > (uint64_t)INT64_MAX / SHZ_CLOCK_FREQUENCY) return SHZ_E_RANGE;
    fraction = (ticks % hz) * SHZ_CLOCK_FREQUENCY / hz;
    ns = sec * SHZ_CLOCK_FREQUENCY;
    if (fraction > (uint64_t)INT64_MAX - ns) return SHZ_E_RANGE;
    *value = ns + fraction;
    return SHZ_OK;
}

typedef int32_t (*shz_clock_sample_fn)(void *opaque, uint64_t *value);
/* Same body used by the real hypercall and bounded source tests. Validate
 * before sampling; publish neither half on error; take exactly one sample. */
static inline int32_t shz_clock_split(uint64_t version, uint64_t reserved,
                                    shz_clock_sample_fn sample, void *opaque,
                                    uint64_t *low, uint64_t *high)
{
    uint64_t value;
    int32_t status;
    if (version != SHZ_CLOCK_VERSION) return SHZ_E_UNSUPPORTED;
    if (reserved || !sample || !low || !high || low == high) return SHZ_E_INVALID;
    status = sample(opaque, &value);
    if (status != SHZ_OK) return status;
    if (value > (uint64_t)INT64_MAX) return SHZ_E_RANGE;
    *low = (uint32_t)value;
    *high = (uint32_t)(value >> 32);
    return SHZ_OK;
}
#endif
