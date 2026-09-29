/* SPDX-License-Identifier: GPL-2.0-only
 * Original unsigned long division; no i386 compiler runtime dependency.
 * Used for bounded TSC-clock conversion in the isolated AHCI boot test.
 */
#include "layout.h"
uint64_t sdahci_divide(uint64_t value, uint32_t divisor)
{
    uint64_t quotient = 0;
    uint32_t remainder = 0, carry;
    unsigned i;
    if (!divisor) return UINT64_MAX;
    for (i = 0; i < 64; ++i) {
        carry = remainder >> 31;
        remainder = (remainder << 1) | (uint32_t)(value >> 63);
        value <<= 1;
        quotient <<= 1;
        if (carry || remainder >= divisor) {
            remainder -= divisor;
            quotient |= 1;
        }
    }
    return quotient;
}
