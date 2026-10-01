/* SPDX-License-Identifier: GPL-2.0-only
 * Documented C absolute value, using the existing CRT IEEE-754 bit helpers.
 * No external CRT source is copied. */
#include "crtint.h"

DLLAPI double CRTAPI fabs(double value)
{
    return crt_u2d(crt_d2u(value) & UINT64_C(0x7fffffffffffffff));
}
