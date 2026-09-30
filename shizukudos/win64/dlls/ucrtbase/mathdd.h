/* SPDX-License-Identifier: GPL-2.0-only
 * Double-double arithmetic for math.c (values hi + lo with |lo| <= ulp(hi)/2, about 106 significant bits), built from
 * the error-free transformations TwoSum, FastTwoSum and Dekker's TwoProduct (Veltkamp splitting; no FMA is assumed).
 * Exact only in the default round-to-nearest mode, which is the mode the results of math.c are specified for.
 */
#ifndef SHZ_MATHDD_H
#define SHZ_MATHDD_H
typedef struct { double hi, lo; } dd;
static inline dd mk(double h, double l) { dd r; r.hi = h; r.lo = l; return r; }
static inline dd two_sum(double a, double b)
{
    const double s = a + b, bb = s - a;
    return mk(s, (a - (s - bb)) + (b - bb));
}
static inline dd fast_two_sum(double a, double b)       /* |a| >= |b| or a == 0 */
{
    const double s = a + b;
    return mk(s, b - (s - a));
}
static inline dd two_prod(double a, double b)            /* |a|, |b| < 2^995 */
{
    const double p = a * b;
    const double ca = 134217729.0 * a, ah = ca - (ca - a), al = a - ah;
    const double cb = 134217729.0 * b, bh = cb - (cb - b), bl = b - bh;
    return mk(p, ((ah * bh - p) + ah * bl + al * bh) + al * bl);
}
static inline dd dd_add(dd a, dd b)
{
    dd s = two_sum(a.hi, b.hi), t = two_sum(a.lo, b.lo);
    s.lo += t.hi;
    s = fast_two_sum(s.hi, s.lo);
    s.lo += t.lo;
    return fast_two_sum(s.hi, s.lo);
}
static inline dd dd_add_d(dd a, double b)
{
    dd s = two_sum(a.hi, b);
    s.lo += a.lo;
    return fast_two_sum(s.hi, s.lo);
}
static inline dd dd_neg(dd a) { return mk(-a.hi, -a.lo); }
static inline dd dd_sub(dd a, dd b) { return dd_add(a, dd_neg(b)); }
static inline dd dd_mul(dd a, dd b)
{
    dd p = two_prod(a.hi, b.hi);
    p.lo += a.hi * b.lo + a.lo * b.hi;
    return fast_two_sum(p.hi, p.lo);
}
static inline dd dd_mul_d(dd a, double b)
{
    dd p = two_prod(a.hi, b);
    p.lo += a.lo * b;
    return fast_two_sum(p.hi, p.lo);
}
static inline dd dd_scale(dd a, double pow2) { return mk(a.hi * pow2, a.lo * pow2); }   /* exact for a power of two in range */
static inline dd dd_div(dd a, dd b)
{
    const double q1 = a.hi / b.hi;
    dd r = dd_sub(a, dd_mul_d(b, q1));
    const double q2 = r.hi / b.hi;
    r = dd_sub(r, dd_mul_d(b, q2));
    {
        const double q3 = r.hi / b.hi;
        return dd_add_d(fast_two_sum(q1, q2), q3);
    }
}
static inline double hw_sqrt(double x)                   /* SSE2 sqrtsd: correctly rounded */
{
    double r;
    __asm__("sqrtsd %1, %0" : "=x"(r) : "x"(x));
    return r;
}
static inline dd dd_sqrt(dd a)                             /* a > 0 */
{
    const double s = hw_sqrt(a.hi);
    const dd s2 = two_prod(s, s);
    const double e = ((a.hi - s2.hi) - s2.lo + a.lo) / (2.0 * s);
    return fast_two_sum(s, e);
}
#endif
