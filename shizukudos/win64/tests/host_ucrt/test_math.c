/* SPDX-License-Identifier: GPL-2.0-only
 * Host accuracy test of the Shizuku UCRT math library (u_* = the ucrtbase core, prefixed).
 *
 * Reference: glibc's long double (x87 80-bit, 64-bit mantissa) functions, accurate to about one long-double ulp, i.e.
 * about 2^-11 of a double ulp; for float functions the glibc double functions. For every function the test reports
 * the maximum error in ulps and the number of results that differ from the correctly rounded reference (a result is
 * only counted as "not correctly rounded" when the reference is farther than 2^-8 ulp from a rounding boundary, so the
 * reference's own error cannot cause the count). Exact functions (fmod, remainder, fma, rounding, ...) must match
 * glibc bit for bit. Exit status: 0 when every function stays within its documented bound.
 *   usage: test_math [samples-per-function] [seed]
 */
#define _GNU_SOURCE
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fenv.h>

#define U(name) u_##name
double U(exp)(double); double U(exp2)(double); double U(expm1)(double); double U(log)(double); double U(log2)(double);
double U(log10)(double); double U(log1p)(double); double U(pow)(double, double); double U(sin)(double); double U(cos)(double);
double U(tan)(double); double U(asin)(double); double U(acos)(double); double U(atan)(double); double U(atan2)(double, double);
double U(sinh)(double); double U(cosh)(double); double U(tanh)(double); double U(asinh)(double); double U(acosh)(double);
double U(atanh)(double); double U(cbrt)(double); double U(hypot)(double, double); double U(erf)(double); double U(erfc)(double);
double U(lgamma)(double); double U(tgamma)(double); double U(sqrt)(double); double U(fma)(double, double, double);
double U(fmod)(double, double); double U(remainder)(double, double); double U(remquo)(double, double, int *);
double U(floor)(double); double U(ceil)(double); double U(trunc)(double); double U(round)(double); double U(rint)(double);
double U(nearbyint)(double); double U(frexp)(double, int *); double U(ldexp)(double, int); double U(modf)(double, double *);
double U(logb)(double); int U(ilogb)(double); double U(nextafter)(double, double); double U(fdim)(double, double);
double U(fmax)(double, double); double U(fmin)(double, double); int32_t U(lrint)(double); long long U(llround)(double);
int32_t U(lround)(double); double U(scalbn)(double, int);
float U(expf)(float); float U(exp2f)(float); float U(expm1f)(float); float U(logf)(float); float U(log2f)(float);
float U(log10f)(float); float U(log1pf)(float); float U(powf)(float, float); float U(sinf)(float); float U(cosf)(float);
float U(tanf)(float); float U(asinf)(float); float U(acosf)(float); float U(atanf)(float); float U(atan2f)(float, float);
float U(sinhf)(float); float U(coshf)(float); float U(tanhf)(float); float U(asinhf)(float); float U(acoshf)(float);
float U(atanhf)(float); float U(cbrtf)(float); float U(erff)(float); float U(erfcf)(float); float U(lgammaf)(float);
float U(tgammaf)(float); float U(fmaf)(float, float, float); float U(fmodf)(float, float); float U(sqrtf)(float);
float U(ceilf)(float); float U(floorf)(float); float U(roundf)(float); int32_t U(lrintf)(float); int32_t U(lroundf)(float);
float U(_hypotf)(float, float);
int host_errno(void);
void host_set_errno(int);

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t next(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }
static double uni(double lo, double hi) { return lo + (hi - lo) * ((next() >> 11) * 0x1p-53); }
static double logu(double lo, double hi) { return exp(uni(log(lo), log(hi))); }       /* log-uniform in [lo, hi] */
static double any_double(void) { uint64_t u; do u = next(); while (((u >> 52) & 0x7ff) == 0x7ff); double d; memcpy(&d, &u, 8); return d; }
static uint64_t dbits(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }
static uint32_t fbits(float f) { uint32_t u; memcpy(&u, &f, 4); return u; }

static int failures;
typedef struct { const char *name; double max_ulp, bound; long n, not_cr, uncertain, special_bad; } stat_t;

static double ulp_of(long double v)                       /* ulp of the double nearest v */
{
    double d = (double)v;
    int e;
    if (d == 0 || !isfinite(d)) return 0x1p-1074;
    frexp(d, &e);
    e -= 53;
    return e < -1074 ? 0x1p-1074 : ldexp(1.0, e);
}
static void account(stat_t *s, double mine, long double ref)
{
    const double r = (double)ref;
    double u, err;
    ++s->n;
    if (isnan(r) || isinf(r) || isnan(mine) || isinf(mine)) {
        if ((isnan(r) != isnan(mine)) || (!isnan(r) && r != mine)) {
            if (s->special_bad < 3) printf("  %s special mismatch: mine=%a ref=%La\n", s->name, mine, ref);
            ++s->special_bad;
        }
        return;
    }
    u = ulp_of(ref);
    err = (double)(fabsl((long double)mine - ref) / u);
    if (err > s->max_ulp) s->max_ulp = err;
    if (mine != r) {
        /* distance of the reference from the rounding boundary between r and its neighbour */
        const double frac = (double)(fabsl(ref - (long double)r) / u);
        if (fabs(frac - 0.5) < 0x1p-8) ++s->uncertain; else ++s->not_cr;
    }
}
static void accountf(stat_t *s, float mine, double ref)
{
    const float r = (float)ref;
    ++s->n;
    if (isnan(r) || isinf(r) || isnan(mine) || isinf(mine)) {
        if ((isnan(r) != isnan(mine)) || (!isnan(r) && r != mine)) ++s->special_bad;
        return;
    }
    {
        int e;
        double u, err;
        if (r == 0) u = 0x1p-149;
        else { frexpf(r, &e); u = e - 24 < -149 ? 0x1p-149 : ldexp(1.0, e - 24); }
        err = fabs((double)mine - ref) / u;
        if (err > s->max_ulp) s->max_ulp = err;
        if (mine != r) {
            const double frac = fabs(ref - (double)r) / u;
            if (fabs(frac - 0.5) < 0x1p-20) ++s->uncertain; else ++s->not_cr;
        }
    }
}
static void report(stat_t *s)
{
    const int ok = s->max_ulp <= s->bound && !s->special_bad;
    printf("%-10s n=%-8ld max_err=%.4f ulp  not_correctly_rounded=%ld (%.2e)  near_tie=%ld  special_mismatch=%ld  [%s, bound %.2f]\n",
           s->name, s->n, s->max_ulp, s->not_cr, s->n ? (double)s->not_cr / s->n : 0.0, s->uncertain, s->special_bad,
           ok ? "PASS" : "FAIL", s->bound);
    if (!ok) ++failures;
}

typedef double (*f1)(double);
typedef long double (*r1)(long double);
static void test1(const char *name, f1 f, r1 ref, double lo, double hi, int logscale, int symmetric, long n, double bound)
{
    stat_t s = { name, 0, bound, 0, 0, 0, 0 };
    long i;
    for (i = 0; i < n; ++i) {
        double x = logscale ? logu(lo, hi) : uni(lo, hi);
        if (symmetric && (next() & 1)) x = -x;
        account(&s, f(x), ref((long double)x));
    }
    report(&s);
}
typedef float (*g1)(float);
typedef double (*q1)(double);
static void testf1(const char *name, g1 f, q1 ref, double lo, double hi, int logscale, int symmetric, long n, double bound)
{
    stat_t s = { name, 0, bound, 0, 0, 0, 0 };
    long i;
    for (i = 0; i < n; ++i) {
        float x = (float)(logscale ? logu(lo, hi) : uni(lo, hi));
        if (symmetric && (next() & 1)) x = -x;
        accountf(&s, f(x), ref((double)x));
    }
    report(&s);
}

/* exact functions: bitwise identity with glibc */
static long exact_bad;
static void same(const char *name, double a, double b, double x, double y, double z)
{
    if (dbits(a) != dbits(b) && !(isnan(a) && isnan(b))) {
        if (exact_bad < 8) printf("  %s mismatch: x=%a y=%a z=%a mine=%a glibc=%a\n", name, x, y, z, a, b);
        ++exact_bad;
    }
}
static void exact_check(const char *name, long n, int which)
{
    long i;
    exact_bad = 0;
    for (i = 0; i < n; ++i) {
        double x = any_double(), y = any_double(), z = any_double();
        int qa = 0, qb = 0, ea = 0, eb = 0, k;
        if (next() % 4 == 0) y = x * uni(0.5, 2.0);                   /* similar magnitudes */
        if (next() % 8 == 0) { x = uni(-1e6, 1e6); y = uni(-100, 100); }
        switch (which) {
        case 0: same(name, U(fmod)(x, y), fmod(x, y), x, y, 0); break;
        case 1: same(name, U(remainder)(x, y), remainder(x, y), x, y, 0); break;
        case 2:
            same(name, U(remquo)(x, y, &qa), remquo(x, y, &qb), x, y, 0);
            /* C requires the sign and at least the 3 low bits of the quotient (glibc returns exactly those) */
            if ((abs(qa) & 7) != (abs(qb) & 7) || ((abs(qb) & 7) && (qa < 0) != (qb < 0))) {
                if (exact_bad < 8) printf("  remquo quotient bits: x=%a y=%a mine=%d glibc=%d\n", x, y, qa, qb);
                ++exact_bad;
            }
            break;
        case 3:
            if (next() & 1) z = -x * y * uni(0.999, 1.001);
            if (next() % 4 == 0) { x = uni(-4, 4); y = uni(-4, 4); z = -x * y + ldexp(uni(-1, 1), -60); }
            same(name, U(fma)(x, y, z), fma(x, y, z), x, y, z);
            break;
        case 4: same(name, U(sqrt)(fabs(x)), sqrt(fabs(x)), x, 0, 0); break;
        case 5:
            x = ldexp(x, -(int)(next() % 1100));
            same("floor", U(floor)(x), floor(x), x, 0, 0);
            same("ceil", U(ceil)(x), ceil(x), x, 0, 0);
            same("trunc", U(trunc)(x), trunc(x), x, 0, 0);
            same("round", U(round)(x), round(x), x, 0, 0);
            same("rint", U(rint)(x), rint(x), x, 0, 0);
            same("nearbyint", U(nearbyint)(x), nearbyint(x), x, 0, 0);
            if (fabs(x) < 2e9) { if (U(lrint)(x) != (int32_t)lrint(x)) { ++exact_bad; } if (U(lround)(x) != (int32_t)lround(x)) ++exact_bad; }
            if (fabs(x) < 9e18 && U(llround)(x) != llround(x)) ++exact_bad;
            break;
        case 6:
            same("frexp", U(frexp)(x, &ea), frexp(x, &eb), x, 0, 0);
            if (ea != eb) ++exact_bad;
            k = (int)(next() % 4300) - 2150;
            same("ldexp", U(ldexp)(x, k), ldexp(x, k), x, k, 0);
            same("scalbn", U(scalbn)(x, k), scalbn(x, k), x, k, 0);
            { double ia, ib; same("modf", U(modf)(x, &ia), modf(x, &ib), x, 0, 0); same("modf.i", ia, ib, x, 0, 0); }
            same("logb", U(logb)(x), logb(x), x, 0, 0);
            if (U(ilogb)(x) != ilogb(x)) ++exact_bad;
            same("nextafter", U(nextafter)(x, y), nextafter(x, y), x, y, 0);
            same("fdim", U(fdim)(x, y), fdim(x, y), x, y, 0);
            same("fmax", U(fmax)(x, y), fmax(x, y), x, y, 0);
            same("fmin", U(fmin)(x, y), fmin(x, y), x, y, 0);
            break;
        case 7: {
            const float a = (float)x, b = (float)y, c = (float)z;
            float r1 = U(fmaf)(a, b, c), r2 = fmaf(a, b, c);
            if (fbits(r1) != fbits(r2) && !(isnan(r1) && isnan(r2))) { if (exact_bad < 8) printf("  fmaf mismatch %a %a %a: %a %a\n", a, b, c, r1, r2); ++exact_bad; }
            r1 = U(fmodf)(a, b); r2 = fmodf(a, b);
            if (fbits(r1) != fbits(r2) && !(isnan(r1) && isnan(r2))) { if (exact_bad < 8) printf("  fmodf mismatch %a %a: %a %a\n", a, b, r1, r2); ++exact_bad; }
            r1 = U(sqrtf)(fabsf(a)); r2 = sqrtf(fabsf(a));
            if (fbits(r1) != fbits(r2)) ++exact_bad;
            break;
        }
        default: break;
        }
    }
    printf("%-10s n=%-8ld bitwise mismatches vs glibc: %ld  [%s]\n", name, n, exact_bad, exact_bad ? "FAIL" : "PASS");
    if (exact_bad) ++failures;
}

/* special values (C99 Annex F / Microsoft documentation) */
static int spec_fail;
static void sp(const char *what, double got, double want)
{
    if (dbits(got) != dbits(want) && !(isnan(got) && isnan(want))) { printf("  special %s: got %a want %a\n", what, got, want); ++spec_fail; }
}
static void sp_errno(const char *what, int want)
{
    if (host_errno() != want) { printf("  errno after %s: got %d want %d\n", what, host_errno(), want); ++spec_fail; }
}
static void specials(void)
{
    const double inf = INFINITY, nan_ = NAN;
    host_set_errno(0); sp("log(0)", U(log)(0.0), -inf); sp_errno("log(0)", 34);
    host_set_errno(0); sp("log(-1)", U(log)(-1.0), nan_); sp_errno("log(-1)", 33);
    host_set_errno(0); sp("exp(1000)", U(exp)(1000.0), inf); sp_errno("exp(1000)", 34);
    host_set_errno(0); sp("exp(-1000)", U(exp)(-1000.0), 0.0); sp_errno("exp(-1000)", 34);
    sp("exp(-inf)", U(exp)(-inf), 0.0); sp("exp(inf)", U(exp)(inf), inf); sp("exp(0)", U(exp)(0.0), 1.0);
    sp("pow(0,-1)", U(pow)(0.0, -1.0), inf); sp("pow(-0,-1)", U(pow)(-0.0, -1.0), -inf); sp("pow(-0,-2)", U(pow)(-0.0, -2.0), inf);
    sp("pow(-0,3)", U(pow)(-0.0, 3.0), -0.0); sp("pow(-0,2)", U(pow)(-0.0, 2.0), 0.0); sp("pow(nan,0)", U(pow)(nan_, 0.0), 1.0);
    sp("pow(1,nan)", U(pow)(1.0, nan_), 1.0); sp("pow(-1,inf)", U(pow)(-1.0, inf), 1.0); sp("pow(0.5,inf)", U(pow)(0.5, inf), 0.0);
    sp("pow(0.5,-inf)", U(pow)(0.5, -inf), inf); sp("pow(2,inf)", U(pow)(2.0, inf), inf); sp("pow(-inf,3)", U(pow)(-inf, 3.0), -inf);
    sp("pow(-inf,-3)", U(pow)(-inf, -3.0), -0.0); sp("pow(-inf,2)", U(pow)(-inf, 2.0), inf); sp("pow(inf,-1)", U(pow)(inf, -1.0), 0.0);
    host_set_errno(0); sp("pow(-8,1/3)", U(pow)(-8.0, 1.0 / 3), nan_); sp_errno("pow(-8,1/3)", 33);
    sp("pow(-2,3)", U(pow)(-2.0, 3.0), -8.0); sp("pow(2,-1074)", U(pow)(2.0, -1074.0), 0x1p-1074); sp("pow(2,1023)", U(pow)(2.0, 1023.0), 0x1p1023);
    sp("pow(10,22)", U(pow)(10.0, 22.0), 1e22); sp("pow((2^27-1),2)", U(pow)(134217727.0, 2.0), 134217727.0 * 134217727.0);
    sp("sin(-0)", U(sin)(-0.0), -0.0); sp("tan(-0)", U(tan)(-0.0), -0.0); sp("cos(0)", U(cos)(0.0), 1.0);
    host_set_errno(0); sp("sin(inf)", U(sin)(inf), nan_); sp_errno("sin(inf)", 33);
    sp("atan2(0,-0)", U(atan2)(0.0, -0.0), M_PI); sp("atan2(-0,-0)", U(atan2)(-0.0, -0.0), -M_PI); sp("atan2(-0,0)", U(atan2)(-0.0, 0.0), -0.0);
    sp("atan2(1,-inf)", U(atan2)(1.0, -inf), M_PI); sp("atan2(inf,inf)", U(atan2)(inf, inf), M_PI_4); sp("atan2(-inf,-inf)", U(atan2)(-inf, -inf), -3 * M_PI_4);
    sp("atan(inf)", U(atan)(inf), M_PI_2); sp("asin(1)", U(asin)(1.0), M_PI_2); sp("acos(-1)", U(acos)(-1.0), M_PI); sp("acos(1)", U(acos)(1.0), 0.0);
    sp("log2(8)", U(log2)(8.0), 3.0); sp("log10(1000)", U(log10)(1000.0), 3.0); sp("log10(1e22)", U(log10)(1e22), 22.0); sp("log(1)", U(log)(1.0), 0.0);
    sp("exp2(-1074)", U(exp2)(-1074.0), 0x1p-1074); sp("exp2(10)", U(exp2)(10.0), 1024.0); sp("expm1(-inf)", U(expm1)(-inf), -1.0);
    sp("cbrt(27)", U(cbrt)(27.0), 3.0); sp("cbrt(-0x1p-1074)", U(cbrt)(-0x1p-1074), -cbrt(0x1p-1074)); sp("hypot(3,4)", U(hypot)(3.0, 4.0), 5.0);
    sp("hypot(inf,nan)", U(hypot)(inf, nan_), inf); sp("tgamma(5)", U(tgamma)(5.0), 24.0); sp("tgamma(0.5)", U(tgamma)(0.5), 0x1.c5bf891b4ef6bp+0);   /* sqrt(pi) correctly rounded */
    host_set_errno(0); sp("tgamma(-1)", U(tgamma)(-1.0), nan_); sp_errno("tgamma(-1)", 33);
    sp("lgamma(1)", U(lgamma)(1.0), 0.0); sp("lgamma(2)", U(lgamma)(2.0), 0.0); sp("erf(inf)", U(erf)(inf), 1.0); sp("erfc(-inf)", U(erfc)(-inf), 2.0);
    sp("atanh(1)", U(atanh)(1.0), inf); sp("acosh(1)", U(acosh)(1.0), 0.0); sp("tanh(-inf)", U(tanh)(-inf), -1.0);
    sp("fmod(5.5,2)", U(fmod)(5.5, 2.0), 1.5); sp("remainder(5.5,2)", U(remainder)(5.5, 2.0), -0.5); sp("fma(2,3,4)", U(fma)(2, 3, 4), 10);
    sp("exp(709.78)", U(exp)(709.782712893383973096), 0x1.fffffffffff2ap+1023);
    printf("special    %d value/errno mismatches  [%s]\n", spec_fail, spec_fail ? "FAIL" : "PASS");
    if (spec_fail) ++failures;
}

static long double lgammal_(long double x) { return lgammal(x); }
static double lgamma_d(double x) { return lgamma(x); }
static long double tgammal_(long double x) { return tgammal(x); }
static long double sinpil_small(long double x) { return sinl(x); }

int main(int argc, char **argv)
{
    const long N = argc > 1 ? atol(argv[1]) : 200000;
    const long NF = N;
    if (argc > 2) rng = strtoull(argv[2], 0, 0) | 1;
    (void)sinpil_small;
    specials();
    /* double functions: bound 0.52 ulp where the result is expected to be correctly rounded up to rare near-ties */
    test1("exp", U(exp), expl, -745, 709.7, 0, 0, N, 0.51);
    test1("exp/small", U(exp), expl, 1e-18, 1, 1, 1, N, 0.51);
    test1("exp2", U(exp2), exp2l, -1074, 1023.9, 0, 0, N, 0.51);
    test1("expm1", U(expm1), expm1l, 1e-300, 700, 1, 1, N, 0.51);
    test1("log", U(log), logl, 1e-300, 1e300, 1, 0, N, 0.51);
    test1("log/near1", U(log), logl, 0.9, 1.1, 0, 0, N, 0.51);
    test1("log/subn", U(log), logl, 0x1p-1074, 0x1p-1022, 1, 0, N / 4, 0.51);
    test1("log2", U(log2), log2l, 1e-300, 1e300, 1, 0, N, 0.51);
    test1("log10", U(log10), log10l, 1e-300, 1e300, 1, 0, N, 0.51);
    test1("log1p", U(log1p), log1pl, 1e-300, 1e300, 1, 0, N, 0.51);
    test1("log1p/neg", U(log1p), log1pl, -0.999999, -1e-300, 0, 0, N, 0.51);
    test1("sin", U(sin), sinl, 1e-8, 1e6, 1, 1, N, 0.51);
    test1("sin/huge", U(sin), sinl, 1e6, 1e300, 1, 1, N, 0.51);
    test1("cos", U(cos), cosl, 1e-8, 1e6, 1, 1, N, 0.51);
    test1("cos/huge", U(cos), cosl, 1e6, 1e300, 1, 1, N, 0.51);
    test1("tan", U(tan), tanl, 1e-8, 1e6, 1, 1, N, 0.51);
    test1("tan/huge", U(tan), tanl, 1e6, 1e300, 1, 1, N, 0.51);
    test1("asin", U(asin), asinl, 1e-10, 1, 1, 1, N, 0.51);
    test1("acos", U(acos), acosl, -1, 1, 0, 0, N, 0.51);
    test1("atan", U(atan), atanl, 1e-10, 1e20, 1, 1, N, 0.51);
    test1("sinh", U(sinh), sinhl, 1e-10, 710, 1, 1, N, 0.51);
    test1("cosh", U(cosh), coshl, 1e-10, 710, 1, 1, N, 0.51);
    test1("tanh", U(tanh), tanhl, 1e-10, 25, 1, 1, N, 0.51);
    test1("asinh", U(asinh), asinhl, 1e-10, 1e300, 1, 1, N, 0.51);
    test1("acosh", U(acosh), acoshl, 1, 1e300, 1, 0, N, 0.51);
    test1("atanh", U(atanh), atanhl, 1e-10, 0.9999999, 1, 1, N, 0.51);
    test1("cbrt", U(cbrt), cbrtl, 1e-300, 1e300, 1, 1, N, 0.51);
    test1("erf", U(erf), erfl, 1e-10, 6, 1, 1, N, 0.51);
    test1("erfc", U(erfc), erfcl, -6, 27.2, 0, 0, N / 2, 0.51);
    test1("lgamma", U(lgamma), lgammal_, 1e-10, 1e10, 1, 0, N / 2, 0.51);
    test1("lgamma/neg", U(lgamma), lgammal_, -170, -1e-10, 0, 0, N / 4, 4096);        /* near the negative zeros: see CRT.md */
    test1("tgamma", U(tgamma), tgammal_, 1e-10, 171, 1, 0, N / 2, 0.51);
    test1("tgamma/neg", U(tgamma), tgammal_, -180, -1e-5, 0, 0, N / 4, 0.51);
    {   /* two-argument functions */
        stat_t s = { "pow", 0, 0.51, 0, 0, 0, 0 }, t = { "atan2", 0, 0.51, 0, 0, 0, 0 }, h = { "hypot", 0, 0.51, 0, 0, 0, 0 };
        long i;
        for (i = 0; i < N; ++i) {
            double x = logu(1e-5, 1e5), y = uni(-60, 60);
            if (next() % 4 == 0) { x = uni(0.5, 2); y = uni(-2000, 2000); }
            if (next() % 8 == 0) { x = -x; y = (double)(int64_t)y; }
            account(&s, U(pow)(x, y), powl(x, y));
            x = any_double(); y = any_double();
            account(&t, U(atan2)(x, y), atan2l(x, y));
            account(&h, U(hypot)(x, y), hypotl(x, y));
        }
        report(&s); report(&t); report(&h);
    }
    /* float functions against the glibc double functions */
    testf1("expf", U(expf), exp, -104, 88.7, 0, 0, NF, 0.5);
    testf1("exp2f", U(exp2f), exp2, -150, 127.9, 0, 0, NF, 0.5);
    testf1("expm1f", U(expm1f), expm1, 1e-30, 88, 1, 1, NF, 0.5);
    testf1("logf", U(logf), log, 1e-38, 1e38, 1, 0, NF, 0.5);
    testf1("log2f", U(log2f), log2, 1e-38, 1e38, 1, 0, NF, 0.5);
    testf1("log10f", U(log10f), log10, 1e-38, 1e38, 1, 0, NF, 0.5);
    testf1("log1pf", U(log1pf), log1p, 1e-30, 1e30, 1, 0, NF, 0.5);
    testf1("sinf", U(sinf), sin, 1e-8, 1e30, 1, 1, NF, 0.5);
    testf1("cosf", U(cosf), cos, 1e-8, 1e30, 1, 1, NF, 0.5);
    testf1("tanf", U(tanf), tan, 1e-8, 1e30, 1, 1, NF, 0.5);
    testf1("asinf", U(asinf), asin, 1e-8, 1, 1, 1, NF, 0.5);
    testf1("acosf", U(acosf), acos, -1, 1, 0, 0, NF, 0.5);
    testf1("atanf", U(atanf), atan, 1e-8, 1e30, 1, 1, NF, 0.5);
    testf1("sinhf", U(sinhf), sinh, 1e-8, 89, 1, 1, NF, 0.5);
    testf1("coshf", U(coshf), cosh, 1e-8, 89, 1, 1, NF, 0.5);
    testf1("tanhf", U(tanhf), tanh, 1e-8, 20, 1, 1, NF, 0.5);
    testf1("asinhf", U(asinhf), asinh, 1e-8, 1e30, 1, 1, NF, 0.5);
    testf1("acoshf", U(acoshf), acosh, 1, 1e30, 1, 0, NF, 0.5);
    testf1("atanhf", U(atanhf), atanh, 1e-8, 0.99999, 1, 1, NF, 0.5);
    testf1("cbrtf", U(cbrtf), cbrt, 1e-38, 1e38, 1, 1, NF, 0.5);
    testf1("erff", U(erff), erf, 1e-8, 4, 1, 1, NF, 0.5);
    testf1("erfcf", U(erfcf), erfc, -4, 10, 0, 0, NF, 0.5);
    testf1("lgammaf", U(lgammaf), lgamma_d, 1e-8, 1e30, 1, 0, NF / 2, 0.5);
    testf1("tgammaf", U(tgammaf), tgamma, 1e-8, 35, 1, 0, NF / 2, 0.5);
    {
        stat_t s = { "powf", 0, 0.5, 0, 0, 0, 0 }, t = { "atan2f", 0, 0.5, 0, 0, 0, 0 }, h = { "_hypotf", 0, 0.5, 0, 0, 0, 0 };
        long i;
        for (i = 0; i < NF; ++i) {
            float x = (float)logu(1e-3, 1e3), y = (float)uni(-12, 12), a = (float)any_double(), b = (float)any_double();
            accountf(&s, U(powf)(x, y), pow(x, y));
            if (isfinite(a) && isfinite(b)) { accountf(&t, U(atan2f)(a, b), atan2(a, b)); accountf(&h, U(_hypotf)(a, b), hypot(a, b)); }
        }
        report(&s); report(&t); report(&h);
    }
    exact_check("fmod", N, 0);
    exact_check("remainder", N, 1);
    exact_check("remquo", N, 2);
    exact_check("fma", N, 3);
    exact_check("sqrt", N, 4);
    exact_check("rounding", N, 5);
    exact_check("scaling", N, 6);
    exact_check("float-ex", N, 7);
    printf("math: %d failing group(s)\n", failures);
    return failures ? 1 : 0;
}
