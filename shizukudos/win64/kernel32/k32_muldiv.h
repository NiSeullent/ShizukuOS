/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_K32_MULDIV_H
#define SHZ_K32_MULDIV_H
#include <stdint.h>
#include <limits.h>
/* Exact signed 32-bit product in 64 bits; nearest rounding, ties away from zero.
 * Taking absolute values after widening also supports INT_MIN operands. */
static inline int shz_muldiv(int number, int numerator, int denominator)
{
    int64_t product = (int64_t)number * numerator;
    int64_t divisor = denominator;
    int negative;
    uint64_t magnitude, scale, quotient;
    if (!divisor) return -1;
    negative = (product < 0) != (divisor < 0);
    magnitude = (uint64_t)(product < 0 ? -product : product);
    scale = (uint64_t)(divisor < 0 ? -divisor : divisor);
    quotient = (magnitude + scale / 2) / scale;
    if (quotient > (uint64_t)INT_MAX + (unsigned)negative) return -1;
    return negative ? (int)(-(int64_t)quotient) : (int)quotient;
}
#endif
