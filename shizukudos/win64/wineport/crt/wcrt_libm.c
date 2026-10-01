/* SPDX-License-Identifier: GPL-2.0-only
 * C runtime for the Wine port: the parts of the math library that Wine keeps outside libs/musl.
 *  math_error  the error hook Wine's musl calls (libs/musl/src/internal/libm.h): Wine's msvcrt implements it in
 *              dlls/msvcrt/math.c; here, without _matherr handlers, it sets errno the way that one does
 *              (_DOMAIN -> EDOM, _SING/_OVERFLOW -> ERANGE, _UNDERFLOW and 0 -> unchanged) and returns retval.
 *  lround      C99 round-half-away-from-zero to long; like the UCRT (and Wine), EDOM and 0 when the result does not
 *              fit a 32-bit long (or x is a NaN).
 * Written from the C standard / MSDN; self-contained (no libm), so every module can link it.
 */
#include "shzwcrt.h"
#include <errno.h>
#include <math.h>

double math_error(int type, const char *name, double arg1, double arg2, double retval);

double math_error(int type, const char *name, double arg1, double arg2, double retval)
{
    (void)name; (void)arg1; (void)arg2;
    switch (type) {
    case _DOMAIN:
        shzw_set_errno(EDOM);
        break;
    case _SING:
    case _OVERFLOW:
        shzw_set_errno(ERANGE);
        break;
    default:                        /* 0, _UNDERFLOW: errno is not changed */
        break;
    }
    return retval;
}

/* round half away from zero; exact for every double (x - trunc(x) is exact below 2^52, above it x is integral) */
static double round_away(double x)
{
    double a = x < 0 ? -x : x, i;
    if (!(a < 4503599627370496.0)) return x;             /* NaN, infinities, |x| >= 2^52 */
    i = (double)(long long)a;
    if (a - i >= 0.5) i += 1.0;
    return x < 0 ? -i : i;
}

long __cdecl lround(double x)
{
    double d = round_away(x);
    if (!(d >= -2147483648.0 && d <= 2147483647.0)) {
        shzw_set_errno(EDOM);
        return 0;
    }
    return (long)d;
}
