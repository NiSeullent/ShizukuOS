/* SPDX-License-Identifier: GPL-2.0-only
 * <math.h> of the Shizuku UCRT, own implementation.
 *
 * Exact operations (sqrt, fma, fmod, remainder, remquo, floor/ceil/trunc/round/rint/nearbyint and the l[l]rint /
 * l[l]round conversions, frexp/ldexp/scalbn/modf/logb/ilogb/nextafter, copysign, fdim, fmin/fmax, the classification
 * helpers) are correctly rounded, as in the Microsoft CRT. The transcendental functions evaluate in double-double
 * arithmetic (about 100 significant bits) with table-driven argument reduction (2^(j/128), log(1/c), atan(k/64);
 * mathtab.h, generated exactly by gen_mathtab.py) and Taylor series, and exact Cody-Waite / Payne-Hanek reduction modulo
 * pi/2 for the trigonometric functions, so the double result is the correctly rounded value except in rare
 * near-midpoint cases; float versions round the same double-double result directly to float. The accuracy actually
 * reached is measured against glibc's 80-bit long double functions by shizukudos/win64/tests/host_ucrt (see CRT.md).
 * Results are specified for the default round-to-nearest mode.
 *
 * Errors follow the UCRT: domain errors set EDOM and return a NaN (the "indefinite" -nan(ind)), poles and range
 * errors set ERANGE; a handler registered with __setusermatherr can intercept them (struct _exception).
 */
#include "crtint.h"
#include "mathdd.h"
#include "mathtab.h"

#define DOMAIN_ 1
#define SING_ 2
#define OVERFLOW_ 3
#define UNDERFLOW_ 4
#define SIGN64 0x8000000000000000ull
#define INF64 0x7ff0000000000000ull

struct crt_exception { int type; char *name; double arg1, arg2, retval; };
typedef int (CRTAPI *crt_matherr_fn)(struct crt_exception *);
static crt_matherr_fn g_user_matherr;
DLLAPI void CRTAPI __setusermatherr(crt_matherr_fn f) { g_user_matherr = f; }

static double math_error(int type, const char *name, double a1, double a2, double retval)
{
    if (g_user_matherr) {
        struct crt_exception e;
        e.type = type;
        e.name = (char *)name;
        e.arg1 = a1;
        e.arg2 = a2;
        e.retval = retval;
        if (g_user_matherr(&e)) return e.retval;
    }
    crt_set_errno(type == DOMAIN_ ? CRT_EDOM : CRT_ERANGE);
    return retval;
}
/* results that also raise the matching floating-point exception flags */
static double f_invalid(void) { volatile double z = 0.0; return z / z; }                     /* -nan(ind), FE_INVALID */
static double f_divzero(double s) { volatile double z = 0.0; return s / z; }                 /* +-inf, FE_DIVBYZERO */
static double f_overflow(double s) { volatile double h = 0x1p1023; return s * h * h; }      /* +-inf, FE_OVERFLOW */
static double f_underflow(double s) { volatile double t = 0x1p-1022; return s * t * t; }    /* +-0, FE_UNDERFLOW */
static double domain_err(const char *name, double a1, double a2) { return math_error(DOMAIN_, name, a1, a2, f_invalid()); }

static inline uint64_t bits(double x) { return crt_d2u(x); }
static inline double from_bits(uint64_t u) { return crt_u2d(u); }
static inline double fabs_(double x) { return from_bits(bits(x) & ~SIGN64); }
static inline float fabsf_(float x) { return crt_u2f(crt_f2u(x) & 0x7fffffffu); }
static inline double copysign_(double x, double s) { return from_bits((bits(x) & ~SIGN64) | (bits(s) & SIGN64)); }
static inline int is_nan(double x) { return (bits(x) & ~SIGN64) > INF64; }
static inline int is_inf(double x) { return (bits(x) & ~SIGN64) == INF64; }
static inline int is_finite(double x) { return (bits(x) & ~SIGN64) < INF64; }
static inline double pow2(int e) { return from_bits((uint64_t)(e + 1023) << 52); }    /* only for -1022 <= e <= 1023 */
static inline dd DDT(const double t[2]) { return mk(t[0], t[1]); }
static inline int round_int(double v) { return v >= 0 ? (int)(v + 0.5) : -(int)(-v + 0.5); }   /* |v| < 2^30 */
static inline int is_integer(double y) { const double a = fabs_(y); return a >= 0x1p52 || (double)(int64_t)a == a; }
static inline int is_odd_integer(double y)
{
    const double a = fabs_(y);
    return a < 0x1p53 && (double)(int64_t)a == a && ((int64_t)a & 1);
}

/* ---------------------------------------------------------------- scaling with a single rounding */
/* round(y * 2^m) to double; y a nonzero double-double. Sets *tiny when the result is subnormal/zero and inexact. */
static double dd_ldexp(dd y, int m, int *tiny)
{
    const double sgn = y.hi < 0 ? -1.0 : 1.0;
    *tiny = 0;
    if (y.hi < 0) y = dd_neg(y);
    while (y.hi >= 2.0) { y = dd_scale(y, 0.5); ++m; }
    while (y.hi < 1.0) { y = dd_scale(y, 2.0); --m; }
    if (m > 1023) return sgn * (y.hi * pow2(m - 1023 > 1023 ? 1023 : m - 1023)) * 0x1p1023;   /* overflows to inf */
    if (m >= -1022) return sgn * y.hi * pow2(m);                                       /* exact scaling */
    {
        const int sh = m + 1074;                                  /* result = round(y * 2^sh) * 2^-1074 */
        double wh, wl, n;
        if (sh < -1) { *tiny = 1; return sgn * 0.0; }
        wh = y.hi * (sh >= 0 ? pow2(sh) : 0.5);
        wl = y.lo * (sh >= 0 ? pow2(sh) : 0.5);
        n = (wh + 0x1p52) - 0x1p52;                               /* nearest integer, ties to even */
        if (wh - n == 0.5 && wl > 0) n += 1.0;
        else if (wh - n == -0.5 && wl < 0) n -= 1.0;
        if (wh != n || wl != 0.0) *tiny = 1;
        return sgn * (n * 0x1p-1074);
    }
}

/* round a double-double to float (correct also when y.hi lies exactly on a float midpoint) */
static float dd_to_float(dd y)
{
    float f = (float)y.hi;
    const double back = (double)f;
    if (back != y.hi && y.lo != 0.0 && is_finite(back)) {
        /* neighbour of f on the side of y.hi */
        uint32_t u = crt_f2u(f);
        float g;
        double mid;
        if ((y.hi > back) == (f >= 0.0f)) u += 1; else u -= 1;
        if (f == 0.0f) u = (y.hi > 0 ? 0x00000001u : 0x80000001u);
        g = crt_u2f(u);
        mid = (back + (double)g) * 0.5;
        if (y.hi == mid && (y.lo > 0) == ((double)g > back)) f = g;
    }
    return f;
}
static float dd_ldexp_float(dd y, int m)                      /* round(y * 2^m) to float */
{
    if (m > 200) return (float)(y.hi * 0x1p200) * 0x1p100f * 0x1p100f;
    if (m < -300) return (float)f_underflow(y.hi < 0 ? -1.0 : 1.0);
    return dd_to_float(dd_scale(y, m >= -1022 ? pow2(m) : 0x1p-1022 * pow2(m + 1022)));
}

/* ================================================================ exact functions */
DLLAPI double CRTAPI sqrt(double x)
{
    if (x < 0) return domain_err("sqrt", x, 0);
    return hw_sqrt(x);
}
DLLAPI float CRTAPI sqrtf(float x)
{
    float r;
    if (x < 0) return (float)domain_err("sqrtf", x, 0);
    __asm__("sqrtss %1, %0" : "=x"(r) : "x"(x));
    return r;
}
DLLAPI double CRTAPI copysign(double x, double y) { return copysign_(x, y); }
DLLAPI float CRTAPI copysignf(float x, float y) { return crt_u2f((crt_f2u(x) & 0x7fffffffu) | (crt_f2u(y) & 0x80000000u)); }
DLLAPI double CRTAPI _copysign(double x, double y) { return copysign_(x, y); }
DLLAPI float CRTAPI _copysignf(float x, float y) { return copysignf(x, y); }
DLLAPI double CRTAPI _chgsign(double x) { return from_bits(bits(x) ^ SIGN64); }
DLLAPI float CRTAPI _chgsignf(float x) { return crt_u2f(crt_f2u(x) ^ 0x80000000u); }

DLLAPI double CRTAPI trunc(double x)
{
    const uint64_t u = bits(x);
    const int e = (int)((u >> 52) & 0x7ff) - 1023;
    if (e >= 52) return is_nan(x) ? x + x : x;
    if (e < 0) return copysign_(0.0, x);
    return from_bits(u & ~((1ull << (52 - e)) - 1));
}
DLLAPI double CRTAPI floor(double x)
{
    const double t = trunc(x);
    if (!is_finite(x)) return x + x;
    return (x < t) ? t - 1.0 : t;
}
DLLAPI double CRTAPI ceil(double x)
{
    const double t = trunc(x);
    if (!is_finite(x)) return x + x;
    return (x > t) ? t + 1.0 : (t == 0.0 ? copysign_(0.0, x) : t);
}
DLLAPI double CRTAPI round(double x)
{
    const double t = trunc(x);
    if (!is_finite(x)) return x + x;
    if (fabs_(x - t) >= 0.5) return t + copysign_(1.0, x);
    return t;
}
DLLAPI float CRTAPI truncf(float x) { return (float)trunc(x); }
DLLAPI float CRTAPI floorf(float x) { return (float)floor(x); }
DLLAPI float CRTAPI ceilf(float x) { return (float)ceil(x); }
DLLAPI float CRTAPI roundf(float x) { return (float)round(x); }

static inline unsigned read_mxcsr(void) { unsigned v; __asm__ volatile("stmxcsr %0" : "=m"(v)); return v; }
static inline void write_mxcsr(unsigned v) { __asm__ volatile("ldmxcsr %0" : : "m"(v)); }
DLLAPI double CRTAPI rint(double x)                               /* current rounding mode */
{
    volatile double big = copysign_(0x1p52, x), r;
    if (!is_finite(x)) return x + x;
    if (fabs_(x) >= 0x1p52) return x;
    r = x + big;
    r = r - big;
    return copysign_(r, x);
}
DLLAPI double CRTAPI nearbyint(double x)                          /* rint without the inexact flag */
{
    const unsigned csr = read_mxcsr();
    const double r = rint(x);
    write_mxcsr(csr);
    return r;
}
DLLAPI float CRTAPI rintf(float x) { return (float)rint(x); }
DLLAPI float CRTAPI nearbyintf(float x) { return (float)nearbyint(x); }
/* conversions use the SSE instructions, which raise FE_INVALID and give the "integer indefinite" when out of range */
DLLAPI crt_long CRTAPI lrint(double x) { int r; __asm__ volatile("cvtsd2si %1, %0" : "=r"(r) : "x"(x)); return r; }
DLLAPI long long CRTAPI llrint(double x) { long long r; __asm__ volatile("cvtsd2si %1, %0" : "=r"(r) : "x"(x)); return r; }
DLLAPI crt_long CRTAPI lrintf(float x) { int r; __asm__ volatile("cvtss2si %1, %0" : "=r"(r) : "x"(x)); return r; }
DLLAPI long long CRTAPI llrintf(float x) { long long r; __asm__ volatile("cvtss2si %1, %0" : "=r"(r) : "x"(x)); return r; }
DLLAPI crt_long CRTAPI lround(double x) { const double r = round(x); int v; __asm__ volatile("cvttsd2si %1, %0" : "=r"(v) : "x"(r)); return v; }
DLLAPI long long CRTAPI llround(double x) { const double r = round(x); long long v; __asm__ volatile("cvttsd2si %1, %0" : "=r"(v) : "x"(r)); return v; }
DLLAPI crt_long CRTAPI lroundf(float x) { return lround(x); }
DLLAPI long long CRTAPI llroundf(float x) { return llround(x); }

DLLAPI double CRTAPI modf(double x, double *ip)
{
    const double t = trunc(x);
    if (ip) *ip = t;
    if (is_inf(x)) return copysign_(0.0, x);
    if (is_nan(x)) return x + x;
    return copysign_(x - t, x);
}
DLLAPI float CRTAPI modff(float x, float *ip)
{
    double t;
    const double r = modf(x, &t);
    if (ip) *ip = (float)t;
    return (float)r;
}

DLLAPI double CRTAPI frexp(double x, int *e)
{
    uint64_t u = bits(x);
    int ex = (int)((u >> 52) & 0x7ff);
    if (e) *e = 0;
    if (!is_finite(x) || x == 0.0) return x + x;
    if (!ex) { x *= 0x1p64; u = bits(x); ex = (int)((u >> 52) & 0x7ff) - 64; }
    if (e) *e = ex - 1022;
    return from_bits((u & ~(0x7ffull << 52)) | (1022ull << 52));
}

/* x * 2^n with one rounding (the intermediate scalings are exact) */
static double scalbn_core(double x, long n)
{
    if (n > 1023) {
        x *= 0x1p1023; n -= 1023;
        if (n > 1023) { x *= 0x1p1023; n -= 1023; if (n > 1023) n = 1023; }
    } else if (n < -1022) {
        x *= 0x1p-1022 * 0x1p53; n += 1022 - 53;
        if (n < -1022) { x *= 0x1p-1022 * 0x1p53; n += 1022 - 53; if (n < -1022) n = -1022; }
    }
    return x * pow2((int)n);
}
static double scalb_checked(double x, long n, const char *name)
{
    double r;
    if (!is_finite(x) || x == 0.0) return x + x;
    r = scalbn_core(x, n);
    if (is_inf(r)) return math_error(OVERFLOW_, name, x, (double)n, r);
    if (r == 0.0) return math_error(UNDERFLOW_, name, x, (double)n, r);
    return r;
}
DLLAPI double CRTAPI ldexp(double x, int n) { return scalb_checked(x, n, "ldexp"); }
DLLAPI double CRTAPI scalbn(double x, int n) { return scalb_checked(x, n, "scalbn"); }
DLLAPI double CRTAPI scalbln(double x, crt_long n) { return scalb_checked(x, n, "scalbln"); }
DLLAPI double CRTAPI _scalb(double x, crt_long n) { return scalb_checked(x, n, "_scalb"); }
DLLAPI float CRTAPI scalbnf(float x, int n) { return (float)scalbn_core(x, n < -400 ? -400 : n > 400 ? 400 : n); }
DLLAPI float CRTAPI scalblnf(float x, crt_long n) { return scalbnf(x, (int)(n < -400 ? -400 : n > 400 ? 400 : n)); }
DLLAPI float CRTAPI _scalbf(float x, crt_long n) { return scalblnf(x, n); }

DLLAPI int CRTAPI ilogb(double x)
{
    uint64_t u = bits(x);
    int e = (int)((u >> 52) & 0x7ff);
    if (x == 0.0) { f_invalid(); return (int)0x80000000; }                    /* FP_ILOGB0 = INT_MIN */
    if (e == 0x7ff) { f_invalid(); return is_nan(x) ? (int)0x80000000 : 0x7fffffff; }   /* FP_ILOGBNAN = INT_MIN */
    if (!e) { u = bits(x * 0x1p64); e = (int)((u >> 52) & 0x7ff) - 64; }
    return e - 1023;
}
DLLAPI int CRTAPI ilogbf(float x) { return ilogb(x); }
DLLAPI double CRTAPI logb(double x)
{
    if (x == 0.0) return math_error(SING_, "logb", x, 0, f_divzero(-1.0));
    if (!is_finite(x)) return x * x;
    return (double)ilogb(x);
}
DLLAPI float CRTAPI logbf(float x) { return (float)logb(x); }
DLLAPI double CRTAPI _logb(double x) { return logb(x); }
DLLAPI float CRTAPI _logbf(float x) { return logbf(x); }

DLLAPI double CRTAPI nextafter(double x, double y)
{
    uint64_t u;
    if (is_nan(x) || is_nan(y)) return x + y;
    if (x == y) return y;
    if (x == 0.0) u = 1 | (bits(y) & SIGN64);
    else {
        u = bits(x);
        if ((x < y) == (x > 0)) ++u; else --u;
    }
    {
        const double r = from_bits(u);
        if (is_inf(r)) return math_error(OVERFLOW_, "nextafter", x, y, f_overflow(copysign_(1.0, r)));
        if ((bits(r) & 0x7ff0000000000000ull) == 0) { volatile double t = r * r; (void)t; crt_set_errno(CRT_ERANGE); }
        return r;
    }
}
DLLAPI double CRTAPI nexttoward(double x, double y) { return nextafter(x, y); }
DLLAPI double CRTAPI _nextafter(double x, double y) { return nextafter(x, y); }
DLLAPI float CRTAPI nextafterf(float x, float y)
{
    uint32_t u;
    if (x != x || y != y) return x + y;
    if (x == y) return y;
    if (x == 0.0f) u = 1 | (crt_f2u(y) & 0x80000000u);
    else {
        u = crt_f2u(x);
        if ((x < y) == (x > 0)) ++u; else --u;
    }
    {
        const float r = crt_u2f(u);
        if ((crt_f2u(r) & 0x7fffffffu) == 0x7f800000u || (crt_f2u(r) & 0x7f800000u) == 0) crt_set_errno(CRT_ERANGE);
        return r;
    }
}
DLLAPI float CRTAPI nexttowardf(float x, double y)
{
    if (x != x || y != y) return (float)(x + y);
    if ((double)x == y) return (float)y;
    return nextafterf(x, (double)x < y ? 0x1p127f * 4.0f : -0x1p127f * 4.0f);
}
DLLAPI float CRTAPI _nextafterf(float x, float y) { return nextafterf(x, y); }

DLLAPI double CRTAPI fdim(double x, double y)
{
    if (is_nan(x) || is_nan(y)) return x + y;
    if (x <= y) return 0.0;
    {
        const double r = x - y;
        if (is_inf(r)) return math_error(OVERFLOW_, "fdim", x, y, r);
        return r;
    }
}
DLLAPI float CRTAPI fdimf(float x, float y) { return (x != x || y != y) ? x + y : x > y ? x - y : 0.0f; }
DLLAPI double CRTAPI fmax(double x, double y)
{
    if (is_nan(x)) return y;
    if (is_nan(y)) return x;
    if (x == y) return (bits(x) & SIGN64) ? y : x;              /* fmax(-0, +0) = +0 */
    return x > y ? x : y;
}
DLLAPI double CRTAPI fmin(double x, double y)
{
    if (is_nan(x)) return y;
    if (is_nan(y)) return x;
    if (x == y) return (bits(x) & SIGN64) ? x : y;
    return x < y ? x : y;
}
DLLAPI float CRTAPI fmaxf(float x, float y) { return (float)fmax(x, y); }
DLLAPI float CRTAPI fminf(float x, float y) { return (float)fmin(x, y); }

/* nan("n-char-sequence"): quiet NaN, payload from the (decimal, octal or hex) sequence */
static uint64_t nan_payload(const char *tag)
{
    uint64_t v = 0;
    int base = 10, i = 0;
    if (!tag) return 0;
    if (tag[0] == '0' && (tag[1] == 'x' || tag[1] == 'X')) { base = 16; i = 2; }
    else if (tag[0] == '0') base = 8;
    for (; tag[i]; ++i) {
        int d;
        const char c = tag[i];
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return 0;
        if (d >= base) return 0;
        v = v * (uint64_t)base + (uint64_t)d;
    }
    return v;
}
DLLAPI double CRTAPI nan(const char *tag) { return from_bits(0x7ff8000000000000ull | (nan_payload(tag) & 0x7ffffffffffffull)); }
DLLAPI float CRTAPI nanf(const char *tag) { return crt_u2f(0x7fc00000u | (uint32_t)(nan_payload(tag) & 0x3fffffu)); }

/* ---------------------------------------------------------------- fmod / remainder / remquo (exact) */
/* |x| rem |y| by binary long division; *q receives the low 31 bits of the integer quotient */
static double rem_core(double x, double y, unsigned *q)
{
    uint64_t ux = bits(x) & ~SIGN64, uy = bits(y) & ~SIGN64, mx, my;
    int ex = (int)(ux >> 52), ey = (int)(uy >> 52);
    unsigned quo = 0;
    if (ux < uy) { *q = 0; return from_bits(ux); }
    if (!ex) { int s = __builtin_clzll(ux) - 11; mx = ux << s; ex = 1 - s; } else mx = (ux & 0xfffffffffffffull) | (1ull << 52);
    if (!ey) { int s = __builtin_clzll(uy) - 11; my = uy << s; ey = 1 - s; } else my = (uy & 0xfffffffffffffull) | (1ull << 52);
    for (; ex > ey; --ex) {
        if (mx >= my) { mx -= my; quo = quo << 1 | 1; } else quo <<= 1;
        mx <<= 1;
    }
    if (mx >= my) { mx -= my; quo = quo << 1 | 1; } else quo <<= 1;
    *q = quo & 0x7fffffffu;
    if (!mx) return 0.0;
    while (mx < (1ull << 52)) { mx <<= 1; --ey; }
    if (ey > 0) return from_bits(((uint64_t)ey << 52) | (mx & 0xfffffffffffffull));
    return from_bits(mx >> (1 - ey));                               /* subnormal: exact (low bits are zero) */
}
DLLAPI double CRTAPI fmod(double x, double y)
{
    unsigned q;
    if (is_nan(x) || is_nan(y)) return x + y;
    if (is_inf(x) || y == 0.0) return domain_err("fmod", x, y);
    if (is_inf(y)) return x;
    if (x == 0.0) return x;
    return copysign_(rem_core(x, y, &q), x);
}
DLLAPI float CRTAPI fmodf(float x, float y)
{
    unsigned q;
    if (x != x || y != y) return x + y;
    if ((crt_f2u(x) & 0x7fffffffu) == 0x7f800000u || y == 0.0f) return (float)domain_err("fmodf", x, y);
    if ((crt_f2u(y) & 0x7fffffffu) == 0x7f800000u || x == 0.0f) return x;
    return (float)copysign_(rem_core(x, y, &q), x);
}
static double remquo_core(double x, double y, int *quo, const char *name)
{
    unsigned q;
    double r, ay;
    int neg_q = (bits(x) ^ bits(y)) >> 63 != 0;
    if (quo) *quo = 0;
    if (is_nan(x) || is_nan(y)) return x + y;
    if (is_inf(x) || y == 0.0) return domain_err(name, x, y);
    if (is_inf(y) || x == 0.0) return x;
    ay = fabs_(y);
    r = rem_core(x, y, &q);                                        /* 0 <= r < |y| */
    /* round the quotient to nearest even: compare 2r with |y| (exactly, avoiding overflow) */
    if (ay >= 0x1p-1021 ? (r > 0.5 * ay || (r == 0.5 * ay && (q & 1))) : (2 * r > ay || (2 * r == ay && (q & 1)))) {
        r -= ay;
        ++q;
    }
    if (quo) *quo = neg_q ? -(int)(q & 0x7fffffff) : (int)(q & 0x7fffffff);
    if (r == 0.0) return copysign_(0.0, x);
    return bits(x) >> 63 ? -r : r;
}
DLLAPI double CRTAPI remainder(double x, double y) { return remquo_core(x, y, 0, "remainder"); }
DLLAPI double CRTAPI remquo(double x, double y, int *q) { return remquo_core(x, y, q, "remquo"); }
DLLAPI float CRTAPI remainderf(float x, float y) { return (float)remquo_core(x, y, 0, "remainderf"); }
DLLAPI float CRTAPI remquof(float x, float y, int *q) { return (float)remquo_core(x, y, q, "remquof"); }

/* ---------------------------------------------------------------- fma (exact integer arithmetic) */
typedef struct { uint64_t w[3]; } u192;                  /* w[2] most significant */
static void u192_shr_sticky(u192 *a, int s, int *sticky)
{
    while (s >= 64) { if (a->w[0]) *sticky = 1; a->w[0] = a->w[1]; a->w[1] = a->w[2]; a->w[2] = 0; s -= 64; }
    if (s > 0) {
        if (a->w[0] << (64 - s)) *sticky = 1;
        a->w[0] = (a->w[0] >> s) | (a->w[1] << (64 - s));
        a->w[1] = (a->w[1] >> s) | (a->w[2] << (64 - s));
        a->w[2] >>= s;
    }
}
static int u192_cmp(const u192 *a, const u192 *b)
{
    int i;
    for (i = 2; i >= 0; --i) if (a->w[i] != b->w[i]) return a->w[i] < b->w[i] ? -1 : 1;
    return 0;
}
static void u192_add(u192 *a, const u192 *b)
{
    unsigned __int128 c = 0;
    int i;
    for (i = 0; i < 3; ++i) { c += (unsigned __int128)a->w[i] + b->w[i]; a->w[i] = (uint64_t)c; c >>= 64; }
}
static void u192_sub(u192 *a, const u192 *b)                  /* a -= b, a >= b */
{
    unsigned __int128 borrow = 0;
    int i;
    for (i = 0; i < 3; ++i) {
        const unsigned __int128 t = (unsigned __int128)a->w[i] - b->w[i] - borrow;
        a->w[i] = (uint64_t)t;
        borrow = (t >> 64) ? 1 : 0;
    }
}
static int decompose(double x, uint64_t *m)                   /* |x| = m * 2^e, m < 2^53; returns e */
{
    const uint64_t u = bits(x) & ~SIGN64;
    const int ex = (int)(u >> 52);
    if (!ex) { *m = u; return -1074; }
    *m = (u & 0xfffffffffffffull) | (1ull << 52);
    return ex - 1075;
}
DLLAPI double CRTAPI fma(double a, double b, double c)
{
    uint64_t ma, mb, mc;
    int ea, eb, ec, ep, base, sticky = 0, sa, sc, top, k, e, i;
    u192 P, C, R;
    unsigned __int128 prod;
    if (!is_finite(a) || !is_finite(b) || a == 0.0 || b == 0.0) return a * b + c;
    if (!is_finite(c)) return c + c;                               /* the exact product is finite */
    if (c == 0.0) {
        /* exact product rounded once: a*b + (+-0) keeps the sign of the product unless it is exactly zero */
        const double p = a * b;
        return p;
    }
    ea = decompose(a, &ma);
    eb = decompose(b, &mb);
    ec = decompose(c, &mc);
    prod = (unsigned __int128)ma * mb;
    ep = ea + eb;
    sa = (int)((bits(a) ^ bits(b)) >> 63);
    sc = (int)(bits(c) >> 63);
    /* place both terms in a 192-bit window whose least significant bit has weight 2^base */
    top = ep + 106 > ec + 53 ? ep + 106 : ec + 53;
    base = top - 190;
    P.w[0] = (uint64_t)prod; P.w[1] = (uint64_t)(prod >> 64); P.w[2] = 0;
    C.w[0] = mc; C.w[1] = 0; C.w[2] = 0;
    {
        int sp = 0, sc2 = 0;
        if (ep >= base) { k = ep - base; for (i = 0; i < k / 64; ++i) { P.w[2] = P.w[1]; P.w[1] = P.w[0]; P.w[0] = 0; }
            k %= 64; if (k) { P.w[2] = (P.w[2] << k) | (P.w[1] >> (64 - k)); P.w[1] = (P.w[1] << k) | (P.w[0] >> (64 - k)); P.w[0] <<= k; } }
        else u192_shr_sticky(&P, base - ep, &sp);
        if (ec >= base) { k = ec - base; for (i = 0; i < k / 64; ++i) { C.w[2] = C.w[1]; C.w[1] = C.w[0]; C.w[0] = 0; }
            k %= 64; if (k) { C.w[2] = (C.w[2] << k) | (C.w[1] >> (64 - k)); C.w[1] = (C.w[1] << k) | (C.w[0] >> (64 - k)); C.w[0] <<= k; } }
        else u192_shr_sticky(&C, base - ec, &sc2);
        /* one of the terms was shifted out with sticky bits: it is tiny relative to the other; keep it as a
         * sticky "epsilon" by making sure the larger term's window keeps two guard bits (top - base = 190) */
        if (sa == sc) { u192_add(&P, &C); R = P; sticky = sp | sc2; }
        else {
            const int cmp = u192_cmp(&P, &C);
            if (cmp == 0 && !sp && !sc2) return 0.0;                                 /* exact zero: +0 when rounding to nearest */
            if (cmp > 0 || (cmp == 0 && sp)) {
                R = P; u192_sub(&R, &C);
                if (sc2) { u192 one = { { 1, 0, 0 } }; u192_sub(&R, &one); }        /* borrow the discarded part */
                sticky = sp | sc2;
            } else {
                R = C; u192_sub(&R, &P);
                if (sp) { u192 one = { { 1, 0, 0 } }; u192_sub(&R, &one); }
                sticky = sp | sc2;
                sa = sc;
            }
        }
    }
    /* normalise: find the top bit of R */
    {
        int lead;
        uint64_t mant, rest_nonzero;
        int shift, roundbit;
        if (R.w[2]) lead = 128 + 63 - __builtin_clzll(R.w[2]);
        else if (R.w[1]) lead = 64 + 63 - __builtin_clzll(R.w[1]);
        else if (R.w[0]) lead = 63 - __builtin_clzll(R.w[0]);
        else return sa ? -0.0 : 0.0;
        e = base + lead;                                         /* value in [2^e, 2^(e+1)) */
        /* unit of the result: 2^(e-52), or 2^-1074 for subnormals */
        k = e - 52 < -1074 ? -1074 : e - 52;
        shift = k - base;                                        /* bits of R below the unit */
        if (shift <= 0) {
            /* every bit is above the unit: exact (sticky cannot be set here since the window keeps 190 bits) */
            mant = R.w[0] << -shift;
            roundbit = 0; rest_nonzero = 0;
        } else {
            u192 t = R;
            int st = 0;
            u192_shr_sticky(&t, shift - 1, &st);
            roundbit = (int)(t.w[0] & 1);
            u192_shr_sticky(&t, 1, &st);
            mant = t.w[0];
            rest_nonzero = (uint64_t)(st | sticky);
        }
        if (roundbit && (rest_nonzero || (mant & 1))) {
            ++mant;
            if (mant == (1ull << 53)) { mant >>= 1; ++k; }
        }
        if (k > 971) return f_overflow(sa ? -1.0 : 1.0);
        {
            double r;
            if (mant < (1ull << 52)) r = from_bits(mant);                     /* subnormal (k == -1074) */
            else r = from_bits(((uint64_t)(k + 1075) << 52) | (mant & 0xfffffffffffffull));
            if ((roundbit || rest_nonzero) && mant < (1ull << 52)) (void)f_underflow(1.0);
            return sa ? -r : r;
        }
    }
}
DLLAPI float CRTAPI fmaf(float a, float b, float c)
{
    const double p = (double)a * (double)b;                       /* exact: 48-bit product */
    if (!is_finite(p) || !is_finite(c) || c == 0.0f || p == 0.0) return (float)(p + c);
    return dd_to_float(two_sum(p, c));
}

/* ================================================================ exponential and logarithm cores */
static void dd_normalize(dd *y, int *m)                     /* y.hi into [1, 2), exponent moved into *m */
{
    const int e = (int)((bits(y->hi) >> 52) & 0x7ff) - 1023;
    if (e) { *y = dd_scale(*y, pow2(-e)); *m += e; }
}
/* e^r - 1 for |r| <= ~0.006, Taylor series to r^11 in double-double */
static dd expm1_poly(dd r)
{
    dd p = DDT(INV_FACT[11]);
    int n;
    for (n = 10; n >= 1; --n) p = dd_add(dd_mul(p, r), DDT(INV_FACT[n]));
    return dd_mul(p, r);
}
/* e^x for a double-double x with |x.hi| <= 746: e^x = y * 2^m with y in about [0.99, 2.01] */
static dd exp_core(dd x, int *m)
{
    const int k = round_int(x.hi * INV_LN2_128);
    const double kd = (double)k;
    dd r = two_sum(x.hi - kd * LN2_128_HI, -kd * LN2_128_MID);   /* both products exact, the difference exact */
    r.lo += x.lo - kd * LN2_128_LO;
    r = fast_two_sum(r.hi, r.lo);
    {
        const dd T = DDT(EXP2_TAB[k & 127]);
        *m = (k - (k & 127)) / 128;
        return dd_add(T, dd_mul(T, expm1_poly(r)));
    }
}
/* log(1 + r) for |r| <= ~0.006: alternating series to r^13 */
static dd log1p_poly(dd r)
{
    dd p = DDT(INV_N[13]);
    int n;
    for (n = 12; n >= 1; --n) p = dd_add(dd_mul(p, r), (n & 1) ? DDT(INV_N[n]) : dd_neg(DDT(INV_N[n])));
    return dd_mul(p, r);
}
/* log(x) = e * ln2 + (returned value), x > 0 finite */
static dd log_parts(double x, int *eout)
{
    uint64_t u = bits(x);
    int e = (int)(u >> 52), j;
    double m, t;
    if (!e) { u = bits(x * 0x1p54); e = (int)(u >> 52) - 54; }
    e -= 1023;
    m = from_bits((u & 0xfffffffffffffull) | 0x3ff0000000000000ull);
    if (m > 1.41) { m *= 0.5; ++e; }
    t = (m - 1.0) * 128.0 + 0.5;
    j = (int)t;
    if ((double)j > t) --j;
    *eout = e;
    {
        const double *row = LOG_TAB[j - LOG_JMIN];
        const dd p = two_prod(m, row[0]);
        const dd r = two_sum(p.hi - 1.0, p.lo);             /* m * inv - 1, exact */
        return dd_add(mk(row[1], row[2]), log1p_poly(r));
    }
}
static dd log_core(double x)
{
    int e;
    const dd lm = log_parts(x, &e);
    return dd_add(fast_two_sum(e * LN2_HI, e * LN2_LO), lm);
}
static dd log_dd(dd v) { return dd_add_d(log_core(v.hi), v.lo / v.hi); }     /* v > 0 */
static dd log1p_dd(dd v)                                                    /* v > -1 */
{
    dd u;
    if (fabs_(v.hi) < 1.0 / 256) return log1p_poly(v);
    u = dd_add_d(v, 1.0);
    return log_dd(u);
}
/* e^x - 1 in double-double for |x| <= 60 */
static dd expm1_dd(double x)
{
    int m;
    dd y;
    if (fabs_(x) <= 0.0027) return expm1_poly(mk(x, 0.0));
    y = exp_core(mk(x, 0.0), &m);
    return dd_add_d(dd_scale(y, pow2(m)), -1.0);
}

static double finish_double(dd y, int m, const char *name, double a1, double a2)
{
    int tiny;
    const double r = dd_ldexp(y, m, &tiny);
    if (is_inf(r)) return math_error(OVERFLOW_, name, a1, a2, f_overflow(copysign_(1.0, r)));
    if (tiny) { (void)f_underflow(1.0); return math_error(UNDERFLOW_, name, a1, a2, r); }
    return r;
}
static float finish_float(dd y, int m, const char *name, double a1, double a2)
{
    const float r = dd_ldexp_float(y, m);
    if ((crt_f2u(r) & 0x7fffffffu) == 0x7f800000u) return (float)math_error(OVERFLOW_, name, a1, a2, r);
    if ((crt_f2u(r) & 0x7f800000u) == 0 && y.hi != 0.0) return (float)math_error(UNDERFLOW_, name, a1, a2, r);
    return r;
}

/* ---------------------------------------------------------------- exp, exp2, expm1 */
/* 0: y * 2^m holds the result; otherwise *special holds it */
static int exp_prep(double x, double hi_lim, double lo_lim, double *special, int fl)
{
    if (is_nan(x)) { *special = x + x; return 1; }
    if (is_inf(x)) { *special = x > 0 ? x : 0.0; return 1; }
    if (x > hi_lim) { *special = math_error(OVERFLOW_, fl ? "expf" : "exp", x, 0, f_overflow(1.0)); return 1; }
    if (x < lo_lim) { *special = math_error(UNDERFLOW_, fl ? "expf" : "exp", x, 0, f_underflow(1.0)); return 1; }
    return 0;
}
DLLAPI double CRTAPI exp(double x)
{
    double s;
    int m;
    dd y;
    if (exp_prep(x, 709.782712893384, -745.2, &s, 0)) return s;
    if (fabs_(x) < 0x1p-54) return 1.0 + x;
    y = exp_core(mk(x, 0.0), &m);
    return finish_double(y, m, "exp", x, 0);
}
DLLAPI float CRTAPI expf(float x)
{
    double s;
    int m;
    dd y;
    if (exp_prep(x, 88.8, -104.0, &s, 1)) return (float)s;
    y = exp_core(mk(x, 0.0), &m);
    return finish_float(y, m, "expf", x, 0);
}
static dd exp2_core(double x, int *m)                      /* |x| <= 1100 */
{
    const int k = round_int(x * 128.0);
    const double r = x - (double)k / 128.0;                 /* exact */
    const dd T = DDT(EXP2_TAB[k & 127]);
    *m = (k - (k & 127)) / 128;
    if (r == 0.0) return T;
    return dd_add(T, dd_mul(T, expm1_poly(dd_mul_d(mk(C_LN2_HI, C_LN2_LO), r))));
}
DLLAPI double CRTAPI exp2(double x)
{
    int m;
    dd y;
    if (is_nan(x)) return x + x;
    if (is_inf(x)) return x > 0 ? x : 0.0;
    if (x >= 1024.0) return math_error(OVERFLOW_, "exp2", x, 0, f_overflow(1.0));
    if (x < -1076.0) return math_error(UNDERFLOW_, "exp2", x, 0, f_underflow(1.0));
    y = exp2_core(x, &m);
    return finish_double(y, m, "exp2", x, 0);
}
DLLAPI float CRTAPI exp2f(float x)
{
    int m;
    dd y;
    if (x != x) return x + x;
    if ((crt_f2u(x) & 0x7fffffffu) == 0x7f800000u) return x > 0 ? x : 0.0f;
    if (x >= 128.0f) return (float)math_error(OVERFLOW_, "exp2f", x, 0, f_overflow(1.0));
    if (x < -151.0f) return (float)math_error(UNDERFLOW_, "exp2f", x, 0, f_underflow(1.0));
    y = exp2_core(x, &m);
    return finish_float(y, m, "exp2f", x, 0);
}
static int expm1_special(double x, double lim, double *s, const char *name)
{
    if (is_nan(x)) { *s = x + x; return 1; }
    if (is_inf(x)) { *s = x > 0 ? x : -1.0; return 1; }
    if (x > lim) { *s = math_error(OVERFLOW_, name, x, 0, f_overflow(1.0)); return 1; }
    if (x < -40.0) { volatile double t = 0x1p-100; *s = t - 1.0; return 1; }     /* -1, inexact */
    if (fabs_(x) < 0x1p-54) { *s = x; return 1; }
    return 0;
}
DLLAPI double CRTAPI expm1(double x)
{
    double s;
    if (expm1_special(x, 709.782712893384, &s, "expm1")) return s;
    if (x > 700.0) {
        int m;
        const dd y = exp_core(mk(x, 0.0), &m);
        return finish_double(y, m, "expm1", x, 0);
    }
    return expm1_dd(x).hi;
}
DLLAPI float CRTAPI expm1f(float x)
{
    double s;
    if (expm1_special(x, 88.8, &s, "expm1f")) return (float)s;
    {
        const dd r = expm1_dd(x);
        const float f = dd_to_float(r);
        if ((crt_f2u(f) & 0x7fffffffu) == 0x7f800000u) return (float)math_error(OVERFLOW_, "expm1f", x, 0, f);
        return f;
    }
}

/* ---------------------------------------------------------------- log family */
/* 0 when x is in the normal domain; otherwise *s is the result (errors reported) */
static int log_special(double x, double *s, const char *name)
{
    if (is_nan(x)) { *s = x + x; return 1; }
    if (x < 0) { *s = domain_err(name, x, 0); return 1; }
    if (x == 0) { *s = math_error(SING_, name, x, 0, f_divzero(-1.0)); return 1; }
    if (is_inf(x)) { *s = x; return 1; }
    return 0;
}
DLLAPI double CRTAPI log(double x) { double s; return log_special(x, &s, "log") ? s : log_core(x).hi; }
DLLAPI float CRTAPI logf(float x) { double s; return log_special(x, &s, "logf") ? (float)s : dd_to_float(log_core(x)); }
static dd log2_dd(double x)
{
    int e;
    const dd lm = log_parts(x, &e);
    return dd_add_d(dd_mul(lm, mk(C_INV_LN2_HI, C_INV_LN2_LO)), (double)e);
}
static dd log10_dd(double x)
{
    int e;
    const dd lm = log_parts(x, &e);
    return dd_add(dd_mul_d(mk(C_LOG10_2_HI, C_LOG10_2_LO), (double)e), dd_mul(lm, mk(C_INV_LN10_HI, C_INV_LN10_LO)));
}
DLLAPI double CRTAPI log2(double x) { double s; return log_special(x, &s, "log2") ? s : log2_dd(x).hi; }
DLLAPI float CRTAPI log2f(float x) { double s; return log_special(x, &s, "log2f") ? (float)s : dd_to_float(log2_dd(x)); }
DLLAPI double CRTAPI log10(double x) { double s; return log_special(x, &s, "log10") ? s : log10_dd(x).hi; }
DLLAPI float CRTAPI log10f(float x) { double s; return log_special(x, &s, "log10f") ? (float)s : dd_to_float(log10_dd(x)); }
static int log1p_special(double x, double *s, const char *name)
{
    if (is_nan(x)) { *s = x + x; return 1; }
    if (x < -1.0) { *s = domain_err(name, x, 0); return 1; }
    if (x == -1.0) { *s = math_error(SING_, name, x, 0, f_divzero(-1.0)); return 1; }
    if (is_inf(x)) { *s = x; return 1; }
    if (fabs_(x) < 0x1p-54) { *s = x; return 1; }
    return 0;
}
DLLAPI double CRTAPI log1p(double x) { double s; return log1p_special(x, &s, "log1p") ? s : log1p_dd(mk(x, 0.0)).hi; }
DLLAPI float CRTAPI log1pf(float x) { double s; return log1p_special(x, &s, "log1pf") ? (float)s : dd_to_float(log1p_dd(mk(x, 0.0))); }

/* ---------------------------------------------------------------- pow */
static dd dd_powi(double x, unsigned n)
{
    dd r = mk(1.0, 0.0), b = mk(x, 0.0);
    for (;;) {
        if (n & 1) r = dd_mul(r, b);
        n >>= 1;
        if (!n) return r;
        b = dd_mul(b, b);
    }
}
/* returns 1 with *s set for the special cases of C99 F.9.4.4; 0 with x, y finite and nonzero otherwise */
static int pow_special(double x, double y, double *s, const char *name)
{
    if (y == 0.0 || x == 1.0) { *s = 1.0; return 1; }
    if (is_nan(x) || is_nan(y)) { *s = x + y; return 1; }
    if (x == 0.0) {
        const int odd = is_odd_integer(y);
        if (y < 0) { *s = math_error(SING_, name, x, y, f_divzero(odd ? copysign_(1.0, x) : 1.0)); return 1; }
        *s = odd ? x : 0.0;
        return 1;
    }
    if (is_inf(y)) {
        const double ax = fabs_(x);
        if (ax == 1.0) *s = 1.0;
        else if ((ax < 1.0) == (y < 0)) *s = from_bits(INF64);
        else *s = 0.0;
        return 1;
    }
    if (is_inf(x)) {
        const int odd = is_odd_integer(y), neg = x < 0;
        if (y < 0) *s = (neg && odd) ? -0.0 : 0.0;
        else *s = (neg && odd) ? x : fabs_(x);
        return 1;
    }
    if (x < 0 && !is_integer(y)) { *s = domain_err(name, x, y); return 1; }
    return 0;
}
/* |x|^y for finite nonzero x, y: result = y * 2^m (double-double); returns -1 (underflow) / +1 (overflow) when out of range */
static int pow_core(double ax, double y, dd *r, int *m)
{
    if (is_integer(y) && fabs_(y) <= 512.0) {
        int e = 0;
        double mx = frexp(ax, &e) * 2.0;                   /* ax = mx * 2^(e-1), mx in [1, 2) */
        const unsigned n = (unsigned)fabs_(y);
        dd p = dd_powi(mx, n);                             /* < 2^512: no overflow */
        long ee = (long)(e - 1) * (long)n;
        int pm = 0;
        dd_normalize(&p, &pm);
        if (y < 0) { p = dd_div(mk(1.0, 0.0), p); ee = -ee; pm = -pm; dd_normalize(&p, &pm); }
        ee += pm;
        if (ee > 2000) return 1;
        if (ee < -2000) return -1;
        *r = p;
        *m = (int)ee;
        return 0;
    }
    if (fabs_(y) > 0x1p64) return (ax > 1.0) == (y > 0) ? 1 : -1;
    {
        const dd z = dd_mul_d(log_core(ax), y);
        if (z.hi > 710.0) return 1;
        if (z.hi < -746.0) return -1;
        *r = exp_core(z, m);
        return 0;
    }
}
DLLAPI double CRTAPI pow(double x, double y)
{
    double s;
    dd r;
    int m, k;
    const double sign = (x < 0 && is_odd_integer(y)) ? -1.0 : 1.0;
    if (pow_special(x, y, &s, "pow")) return s;
    k = pow_core(fabs_(x), y, &r, &m);
    if (k > 0) return math_error(OVERFLOW_, "pow", x, y, f_overflow(sign));
    if (k < 0) return math_error(UNDERFLOW_, "pow", x, y, f_underflow(sign));
    return finish_double(sign < 0 ? dd_neg(r) : r, m, "pow", x, y);
}
DLLAPI float CRTAPI powf(float x, float y)
{
    double s;
    dd r;
    int m, k;
    const double sign = (x < 0 && is_odd_integer(y)) ? -1.0 : 1.0;
    if (pow_special(x, y, &s, "powf")) return (float)s;
    k = pow_core(fabs_(x), y, &r, &m);
    if (k > 0) return (float)math_error(OVERFLOW_, "powf", x, y, f_overflow(sign));
    if (k < 0) return (float)math_error(UNDERFLOW_, "powf", x, y, f_underflow(sign));
    return finish_float(sign < 0 ? dd_neg(r) : r, m, "powf", x, y);
}

/* ================================================================ trigonometric functions */
/* |x| mod pi/2: returns the quadrant (0..3) and r = |x| - n * pi/2 as a double-double, |r| <= ~pi/4 */
static int rem_pio2(double ax, dd *r)
{
    if (ax <= 0x1.921fb54442d18p-1) { *r = mk(ax, 0.0); return 0; }
    if (ax < 0x1p20) {
        /* Cody-Waite with pi/2 split into 33 + 33 + 33 + 53 bits: every product with n < 2^20 is exact */
        const int n = round_int(ax * TWO_OVER_PI_D);
        const double nd = (double)n;
        dd t = two_sum(ax - nd * PIO2_1, -nd * PIO2_2);
        t = dd_add_d(t, -nd * PIO2_3);
        t = dd_add_d(t, -nd * PIO2_4);
        *r = t;
        return n & 3;
    }
    {
        /* Payne-Hanek: ax = M * 2^e (M a 53-bit integer); multiply M by a 256-bit window of the bits of 2/pi starting
         * where the product's weights drop below 4, so the integer part of the result is the quadrant and 190+ bits
         * of fraction remain (the closest double to a multiple of pi/2 leaves at least ~2^-61 of fraction). */
        const uint64_t u = bits(ax);
        const int e = (int)(u >> 52) - 1075;
        const uint64_t M = (u & 0xfffffffffffffull) | (1ull << 52);
        const int i0 = e - 1 > 1 ? e - 1 : 1;                /* first bit (1-based) of 2/pi that matters */
        uint32_t W[9], P[11];
        int i, pt, n;
        uint64_t f[4];
        /* W = bits i0 .. i0+255 of 2/pi, little-endian 32-bit words */
        for (i = 0; i < 8; ++i) {
            const int bitpos = i0 - 1 + (7 - i) * 32;          /* 0-based position of the word's most significant bit */
            const int w = bitpos / 32, s = bitpos % 32;
            const uint32_t hi = w < 44 ? TWO_OVER_PI[w] : 0, lo = w + 1 < 44 ? TWO_OVER_PI[w + 1] : 0;
            W[i] = s ? (hi << s) | (lo >> (32 - s)) : hi;
        }
        W[8] = 0;
        /* P = M * W (up to 309 bits) */
        {
            uint64_t carry = 0;
            const uint64_t m0 = M & 0xffffffffu, m1 = M >> 32;
            for (i = 0; i < 11; ++i) P[i] = 0;
            for (i = 0; i < 8; ++i) {
                uint64_t t = (uint64_t)W[i] * m0 + P[i] + carry;
                P[i] = (uint32_t)t;
                carry = t >> 32;
            }
            P[8] = (uint32_t)carry;
            carry = 0;
            for (i = 0; i < 8; ++i) {
                uint64_t t = (uint64_t)W[i] * m1 + P[i + 1] + carry;
                P[i + 1] = (uint32_t)t;
                carry = t >> 32;
            }
            P[9] = (uint32_t)carry;
        }
        /* the value is P / 2^pt (mod 4) with pt = 255 + i0 - e */
        pt = 255 + i0 - e;
        {
            /* extract bits pt+1, pt (integer part) and 192 fraction bits below pt */
            int b;
            n = 0;
            for (b = pt + 1; b >= pt; --b) n = n << 1 | (int)((P[b / 32] >> (b % 32)) & 1);
            for (i = 0; i < 3; ++i) {
                uint64_t v = 0;
                for (b = 0; b < 64; ++b) {
                    const int pos = pt - 1 - i * 64 - b;
                    v = v << 1 | (pos >= 0 ? (uint64_t)((P[pos / 32] >> (pos % 32)) & 1) : 0);
                }
                f[i] = v;
            }
            f[3] = 0;
        }
        {
            int neg = 0, lz;
            if (f[0] >> 63) {                                   /* fraction >= 1/2: next quadrant, negative remainder */
                neg = 1;
                n = (n + 1) & 3;
                f[2] = ~f[2] + 1;
                f[1] = ~f[1] + (f[2] == 0);
                f[0] = ~f[0] + (f[1] == 0 && f[2] == 0);
            }
            /* normalise the 192-bit fraction and turn its top 106 bits into a double-double */
            lz = 0;
            while (!f[0] && lz < 128) { f[0] = f[1]; f[1] = f[2]; f[2] = 0; lz += 64; }
            {
                const int s = f[0] ? __builtin_clzll(f[0]) : 0;
                double hi, lo;
                if (s) { f[0] = (f[0] << s) | (f[1] >> (64 - s)); f[1] = (f[1] << s) | (f[2] >> (64 - s)); }
                lz += s;
                hi = (double)(f[0] >> 11) * 0x1p-53;                               /* 53 bits, exact */
                lo = (double)(((f[0] & 0x7ff) << 42) | (f[1] >> 22)) * 0x1p-106;   /* next 53 bits, exact */
                {
                    dd fr = fast_two_sum(hi, lo);
                    fr = dd_scale(fr, pow2(-lz));
                    fr = dd_mul(fr, mk(C_PIO2_HI, C_PIO2_LO));
                    *r = neg ? dd_neg(fr) : fr;
                }
            }
        }
        return n;
    }
}
static dd sin_kernel(dd r)                                  /* |r| <= ~0.79: series to r^25 */
{
    const dd r2 = dd_mul(r, r);
    dd p = DDT(INV_FACT[25]);
    int k;
    for (k = 11; k >= 0; --k) p = dd_add(dd_mul(p, r2), (k & 1) ? dd_neg(DDT(INV_FACT[2 * k + 1])) : DDT(INV_FACT[2 * k + 1]));
    return dd_mul(p, r);
}
static dd cos_kernel(dd r)                                  /* series to r^24 */
{
    const dd r2 = dd_mul(r, r);
    dd p = DDT(INV_FACT[24]);
    int k;
    for (k = 11; k >= 0; --k) p = dd_add(dd_mul(p, r2), (k & 1) ? dd_neg(DDT(INV_FACT[2 * k])) : DDT(INV_FACT[2 * k]));
    return p;
}
/* which: 0 sin, 1 cos, 2 tan; x finite */
static dd trig_dd(double x, int which)
{
    dd r, s, c;
    const int n = rem_pio2(fabs_(x), &r);
    const int neg = x < 0;
    if (which == 0) {
        s = (n & 1) ? cos_kernel(r) : sin_kernel(r);
        if (n & 2) s = dd_neg(s);
        return neg ? dd_neg(s) : s;
    }
    if (which == 1) {
        c = (n & 1) ? sin_kernel(r) : cos_kernel(r);
        if (((n + 1) & 2)) c = dd_neg(c);
        return c;
    }
    s = sin_kernel(r);
    c = cos_kernel(r);
    s = (n & 1) ? dd_neg(dd_div(c, s)) : dd_div(s, c);
    return neg ? dd_neg(s) : s;
}
static int trig_special(double x, double *s, const char *name, int which)
{
    if (is_nan(x)) { *s = x + x; return 1; }
    if (is_inf(x)) { *s = domain_err(name, x, 0); return 1; }
    if (fabs_(x) < 0x1p-27) {
        if (which == 1) { *s = 1.0 - x * x; return 1; }             /* rounds to 1, inexact */
        if (x != 0 && fabs_(x) < 0x1p-1022) (void)f_underflow(1.0);
        *s = x == 0 ? x : which == 2 ? x + x * x * x : x - x * x * x;   /* x, inexact, rounded the right way */
        return 1;
    }
    return 0;
}
DLLAPI double CRTAPI sin(double x) { double s; return trig_special(x, &s, "sin", 0) ? s : trig_dd(x, 0).hi; }
DLLAPI double CRTAPI cos(double x) { double s; return trig_special(x, &s, "cos", 1) ? s : trig_dd(x, 1).hi; }
DLLAPI double CRTAPI tan(double x) { double s; return trig_special(x, &s, "tan", 2) ? s : trig_dd(x, 2).hi; }
DLLAPI float CRTAPI sinf(float x) { double s; return trig_special(x, &s, "sinf", 0) ? (float)s : dd_to_float(trig_dd(x, 0)); }
DLLAPI float CRTAPI cosf(float x) { double s; return trig_special(x, &s, "cosf", 1) ? (float)s : dd_to_float(trig_dd(x, 1)); }
DLLAPI float CRTAPI tanf(float x) { double s; return trig_special(x, &s, "tanf", 2) ? (float)s : dd_to_float(trig_dd(x, 2)); }

/* atan of a double-double x >= 0 */
static dd atan_core(dd x)
{
    int inv = 0, k, n;
    dd y = x, t, t2, p;
    double c;
    if (x.hi > 1.0) { y = dd_div(mk(1.0, 0.0), x); inv = 1; }
    k = (int)(y.hi * 64.0 + 0.5);
    if (k < 0 || k > 64) k = k < 0 ? 0 : 64;                    /* only reachable with a NaN argument */
    c = (double)k / 64.0;
    t = dd_div(dd_add_d(y, -c), dd_add_d(dd_mul_d(y, c), 1.0));   /* |t| <= 1/128 */
    t2 = dd_mul(t, t);
    p = DDT(INV_N[17]);
    for (n = 7; n >= 0; --n) p = dd_add(dd_mul(p, t2), (n & 1) ? dd_neg(DDT(INV_N[2 * n + 1])) : DDT(INV_N[2 * n + 1]));
    p = dd_add(DDT(ATAN_TAB[k]), dd_mul(p, t));
    return inv ? dd_sub(mk(C_PIO2_HI, C_PIO2_LO), p) : p;
}
static dd atan_dd(double x)
{
    const dd r = atan_core(mk(fabs_(x), 0.0));
    return x < 0 ? dd_neg(r) : r;
}
DLLAPI double CRTAPI atan(double x)
{
    if (is_nan(x)) return x + x;
    if (is_inf(x)) return copysign_(C_PIO2_HI, x);
    if (fabs_(x) < 0x1p-27) { if (x != 0 && fabs_(x) < 0x1p-1022) (void)f_underflow(1.0); return x == 0 ? x : x - x * x * x; }
    return atan_dd(x).hi;
}
DLLAPI float CRTAPI atanf(float x)
{
    if (x != x) return x + x;
    if ((crt_f2u(x) & 0x7fffffffu) == 0x7f800000u) return (float)copysign_(C_PIO2_HI, x);
    if (fabsf_(x) < 0x1p-27f) return x;
    return dd_to_float(atan_dd(x));
}
/* atan2 for finite nonzero y and x, as a double-double */
static dd atan2_dd(double y, double x)
{
    double ay = fabs_(y), ax = fabs_(x);
    dd a;
    if (ay < ax * 0x1p-60) {
        /* |y/x| < 2^-60: atan(t) = t (1 - t^2/3 ...) rounds like t; for x < 0 the result is pi - t */
        if (x > 0) { const double q = y / x; return mk(q, 0.0); }
        a = dd_sub(mk(C_PI_HI, C_PI_LO), mk(ay / ax, 0.0));
        return y < 0 ? dd_neg(a) : a;
    }
    if (ax < ay * 0x1p-60) {
        a = mk(C_PIO2_HI, C_PIO2_LO);                           /* pi/2 -+ something below 2^-60 */
        a = dd_add_d(a, x > 0 ? -ax / ay : ax / ay);
        return y < 0 ? dd_neg(a) : a;
    }
    {
        /* scale so that |x| is in [1, 2): both stay normal and no double-double product underflows or overflows */
        int e = (int)((bits(ax) >> 52) & 0x7ff) - 1023;
        if (e < -1022) { ax *= 0x1p600; ay *= 0x1p600; e = (int)((bits(ax) >> 52) & 0x7ff) - 1023; }  /* subnormal x */
        ax = scalbn_core(ax, -e);                               /* exact: both results are normal */
        ay = scalbn_core(ay, -e);
    }
    if (ay <= ax) a = atan_core(dd_div(mk(ay, 0.0), mk(ax, 0.0)));
    else a = dd_sub(mk(C_PIO2_HI, C_PIO2_LO), atan_core(dd_div(mk(ax, 0.0), mk(ay, 0.0))));
    if (x < 0) a = dd_sub(mk(C_PI_HI, C_PI_LO), a);
    return y < 0 ? dd_neg(a) : a;
}
static int atan2_special(double y, double x, double *s)
{
    if (is_nan(x) || is_nan(y)) { *s = x + y; return 1; }
    if (y == 0.0) {
        if (x > 0 || (x == 0 && !(bits(x) >> 63))) *s = y;                    /* +-0 */
        else *s = copysign_(C_PI_HI, y) + copysign_(C_PI_LO, y);           /* +-pi */
        return 1;
    }
    if (x == 0.0) { *s = copysign_(C_PIO2_HI, y); return 1; }
    if (is_inf(x)) {
        if (is_inf(y)) *s = copysign_(x > 0 ? C_PIO4_HI : 3.0 * C_PIO4_HI, y);
        else *s = x > 0 ? copysign_(0.0, y) : copysign_(C_PI_HI, y);
        return 1;
    }
    if (is_inf(y)) { *s = copysign_(C_PIO2_HI, y); return 1; }
    return 0;
}
DLLAPI double CRTAPI atan2(double y, double x)
{
    double s;
    if (atan2_special(y, x, &s)) return s;
    {
        const dd r = atan2_dd(y, x);
        if (fabs_(r.hi) < 0x1p-1022 && (r.hi != 0.0 || y != 0.0)) {           /* subnormal or zero result */
            (void)f_underflow(1.0);
            return math_error(UNDERFLOW_, "atan2", y, x, r.hi);
        }
        return r.hi;
    }
}
DLLAPI float CRTAPI atan2f(float y, float x)
{
    double s;
    if (atan2_special(y, x, &s)) return (float)s;
    return dd_to_float(atan2_dd(y, x));
}
/* sqrt(1 - x*x) as a double-double, |x| <= 1 */
static dd sqrt_one_minus_sq(double ax)
{
    const dd a = two_sum(1.0, -ax), b = two_sum(1.0, ax);
    const dd p = dd_mul(a, b);
    return p.hi > 0 ? dd_sqrt(p) : mk(0.0, 0.0);
}
static dd asin_dd(double x)
{
    const double ax = fabs_(x);
    const dd s = sqrt_one_minus_sq(ax);
    dd a;
    if (s.hi == 0.0) a = mk(C_PIO2_HI, C_PIO2_LO);
    else if (ax <= s.hi) a = atan_core(dd_div(mk(ax, 0.0), s));
    else a = dd_sub(mk(C_PIO2_HI, C_PIO2_LO), atan_core(dd_div(s, mk(ax, 0.0))));
    return x < 0 ? dd_neg(a) : a;
}
static dd acos_dd(double x)
{
    const double ax = fabs_(x);
    const dd s = sqrt_one_minus_sq(ax);
    dd a;                                                    /* acos(|x|) = atan(s / |x|) */
    if (ax == 0.0) a = mk(C_PIO2_HI, C_PIO2_LO);
    else if (s.hi <= ax) a = atan_core(dd_div(s, mk(ax, 0.0)));
    else a = dd_sub(mk(C_PIO2_HI, C_PIO2_LO), atan_core(dd_div(mk(ax, 0.0), s)));
    return x < 0 ? dd_sub(mk(C_PI_HI, C_PI_LO), a) : a;
}
DLLAPI double CRTAPI asin(double x)
{
    if (is_nan(x)) return x + x;
    if (fabs_(x) > 1.0) return domain_err("asin", x, 0);
    if (fabs_(x) < 0x1p-27) { if (x != 0 && fabs_(x) < 0x1p-1022) (void)f_underflow(1.0); return x == 0 ? x : x + x * x * x; }
    return asin_dd(x).hi;
}
DLLAPI double CRTAPI acos(double x)
{
    if (is_nan(x)) return x + x;
    if (fabs_(x) > 1.0) return domain_err("acos", x, 0);
    if (x == 1.0) return 0.0;
    return acos_dd(x).hi;
}
DLLAPI float CRTAPI asinf(float x)
{
    if (x != x) return x + x;
    if (fabsf_(x) > 1.0f) return (float)domain_err("asinf", x, 0);
    if (fabsf_(x) < 0x1p-27f) return x;
    return dd_to_float(asin_dd(x));
}
DLLAPI float CRTAPI acosf(float x)
{
    if (x != x) return x + x;
    if (fabsf_(x) > 1.0f) return (float)domain_err("acosf", x, 0);
    if (x == 1.0f) return 0.0f;
    return dd_to_float(acos_dd(x));
}

/* ================================================================ hyperbolic functions */
/* sinh / cosh of ax >= 2^-27 (finite, <= 711): result = y * 2^m */
static dd sinh_core(double ax, int *m, int cosh_)
{
    *m = 0;
    if (ax < 1.0) {
        const dd E = expm1_dd(ax), E1 = dd_add_d(E, 1.0);
        if (cosh_) return dd_add_d(dd_div(dd_mul(E, E), dd_scale(E1, 2.0)), 1.0);       /* 1 + E^2 / (2 (E + 1)) */
        return dd_div(dd_mul(E, dd_add_d(E, 2.0)), dd_scale(E1, 2.0));                  /* E (E + 2) / (2 (E + 1)) */
    }
    if (ax > 40.0) {                                           /* e^-x is below 2^-115 relative: e^x / 2 */
        const dd y = exp_core(mk(ax, 0.0), m);
        --*m;
        return y;
    }
    {
        int mm;
        const dd ex = exp_core(mk(ax, 0.0), &mm);
        const dd e = dd_scale(ex, pow2(mm)), inv = dd_div(mk(1.0, 0.0), e);
        return dd_scale(cosh_ ? dd_add(e, inv) : dd_sub(e, inv), 0.5);
    }
}
DLLAPI double CRTAPI sinh(double x)
{
    int m;
    dd y;
    if (!is_finite(x)) return x + x;
    if (fabs_(x) < 0x1p-27) { if (x != 0 && fabs_(x) < 0x1p-1022) (void)f_underflow(1.0); return x == 0 ? x : x + x * x * x; }
    if (fabs_(x) > 711.0) return math_error(OVERFLOW_, "sinh", x, 0, f_overflow(copysign_(1.0, x)));
    y = sinh_core(fabs_(x), &m, 0);
    return finish_double(x < 0 ? dd_neg(y) : y, m, "sinh", x, 0);
}
DLLAPI double CRTAPI cosh(double x)
{
    int m;
    if (is_nan(x)) return x + x;
    if (is_inf(x)) return fabs_(x);
    if (fabs_(x) < 0x1p-27) return 1.0 + x * x;                /* 1, inexact */
    if (fabs_(x) > 711.0) return math_error(OVERFLOW_, "cosh", x, 0, f_overflow(1.0));
    {
        const dd y = sinh_core(fabs_(x), &m, 1);
        return finish_double(y, m, "cosh", x, 0);
    }
}
DLLAPI double CRTAPI tanh(double x)
{
    const double ax = fabs_(x);
    dd E, t;
    if (is_nan(x)) return x + x;
    if (ax > 22.0) return copysign_(1.0 - 0x1p-60, x);       /* +-1, inexact */
    if (ax < 0x1p-27) { if (x != 0 && ax < 0x1p-1022) (void)f_underflow(1.0); return x == 0 ? x : x - x * x * x; }
    E = expm1_dd(2.0 * ax);
    t = dd_div(E, dd_add_d(E, 2.0));
    return x < 0 ? -t.hi : t.hi;
}
DLLAPI float CRTAPI sinhf(float x)
{
    int m;
    dd y;
    if ((crt_f2u(x) & 0x7fffffffu) >= 0x7f800000u) return x + x;
    if (fabsf_(x) < 0x1p-27f) return x;
    if (fabsf_(x) > 100.0f) return (float)math_error(OVERFLOW_, "sinhf", x, 0, f_overflow(copysign_(1.0, x)));
    y = sinh_core(fabs_(x), &m, 0);
    return finish_float(x < 0 ? dd_neg(y) : y, m, "sinhf", x, 0);
}
DLLAPI float CRTAPI coshf(float x)
{
    int m;
    if (x != x) return x + x;
    if ((crt_f2u(x) & 0x7fffffffu) == 0x7f800000u) return fabsf_(x);
    if (fabsf_(x) < 0x1p-27f) return 1.0f;
    if (fabsf_(x) > 100.0f) return (float)math_error(OVERFLOW_, "coshf", x, 0, f_overflow(1.0));
    {
        const dd y = sinh_core(fabs_(x), &m, 1);
        return finish_float(y, m, "coshf", x, 0);
    }
}
DLLAPI float CRTAPI tanhf(float x)
{
    const double ax = fabs_(x);
    dd E, t;
    if (x != x) return x + x;
    if (ax > 22.0) return (float)copysign_(1.0, x);
    if (ax < 0x1p-27) return x;
    E = expm1_dd(2.0 * ax);
    t = dd_div(E, dd_add_d(E, 2.0));
    return dd_to_float(x < 0 ? dd_neg(t) : t);
}

static dd asinh_dd(double ax)                                 /* 2^-27 <= ax < inf */
{
    dd s;
    if (ax > 0x1p28) return dd_add(log_core(ax), mk(C_LN2_HI, C_LN2_LO));
    s = dd_sqrt(dd_add_d(two_prod(ax, ax), 1.0));                                    /* sqrt(x^2 + 1) */
    if (ax < 0.5) return log1p_dd(dd_add_d(dd_div(two_prod(ax, ax), dd_add_d(s, 1.0)), ax));
    return log_dd(dd_add_d(s, ax));
}
static dd acosh_dd(double x)                                  /* 1 < x < inf */
{
    if (x > 0x1p28) return dd_add(log_core(x), mk(C_LN2_HI, C_LN2_LO));
    if (x < 2.0) {
        const double t = x - 1.0;                                                     /* exact */
        const dd w = dd_sqrt(dd_add_d(two_prod(t, t), 2.0 * t));                    /* sqrt(2t + t^2) */
        return log1p_dd(dd_add_d(w, t));
    }
    return log_dd(dd_add_d(dd_sqrt(dd_mul(two_sum(x, -1.0), two_sum(x, 1.0))), x));
}
static dd atanh_dd(double ax)                                 /* 2^-27 <= ax < 1 */
{
    const dd q = dd_div(mk(2.0 * ax, 0.0), two_sum(1.0, -ax));
    return dd_scale(log1p_dd(q), 0.5);
}
DLLAPI double CRTAPI asinh(double x)
{
    const double ax = fabs_(x);
    dd r;
    if (!is_finite(x)) return x + x;
    if (ax < 0x1p-27) { if (x != 0 && ax < 0x1p-1022) (void)f_underflow(1.0); return x == 0 ? x : x - x * x * x; }
    r = asinh_dd(ax);
    return x < 0 ? -r.hi : r.hi;
}
DLLAPI double CRTAPI acosh(double x)
{
    if (is_nan(x)) return x + x;
    if (x < 1.0) return domain_err("acosh", x, 0);
    if (x == 1.0) return 0.0;
    if (is_inf(x)) return x;
    return acosh_dd(x).hi;
}
DLLAPI double CRTAPI atanh(double x)
{
    const double ax = fabs_(x);
    dd r;
    if (is_nan(x)) return x + x;
    if (ax > 1.0) return domain_err("atanh", x, 0);
    if (ax == 1.0) return math_error(SING_, "atanh", x, 0, f_divzero(x));
    if (ax < 0x1p-27) { if (x != 0 && ax < 0x1p-1022) (void)f_underflow(1.0); return x == 0 ? x : x + x * x * x; }
    r = atanh_dd(ax);
    return x < 0 ? -r.hi : r.hi;
}
DLLAPI float CRTAPI asinhf(float x)
{
    const double ax = fabs_(x);
    dd r;
    if ((crt_f2u(x) & 0x7fffffffu) >= 0x7f800000u) return x + x;
    if (ax < 0x1p-27) return x;
    r = asinh_dd(ax);
    return dd_to_float(x < 0 ? dd_neg(r) : r);
}
DLLAPI float CRTAPI acoshf(float x)
{
    if (x != x) return x + x;
    if (x < 1.0f) return (float)domain_err("acoshf", x, 0);
    if (x == 1.0f) return 0.0f;
    if ((crt_f2u(x) & 0x7fffffffu) == 0x7f800000u) return x;
    return dd_to_float(acosh_dd(x));
}
DLLAPI float CRTAPI atanhf(float x)
{
    const double ax = fabs_(x);
    dd r;
    if (x != x) return x + x;
    if (ax > 1.0) return (float)domain_err("atanhf", x, 0);
    if (ax == 1.0) return (float)math_error(SING_, "atanhf", x, 0, f_divzero(x));
    if (ax < 0x1p-27) return x;
    r = atanh_dd(ax);
    return dd_to_float(x < 0 ? dd_neg(r) : r);
}

/* ================================================================ cbrt, hypot */
static dd cbrt_dd(double ax, int *q)                          /* ax > 0 finite: cbrt(ax) = r * 2^q */
{
    uint64_t u = bits(ax);
    int e = (int)(u >> 52), rr, i;
    double v, y;
    if (!e) { u = bits(ax * 0x1p54); e = (int)(u >> 52) - 54; }
    e -= 1023;
    v = from_bits((u & 0xfffffffffffffull) | 0x3ff0000000000000ull);          /* [1, 2) */
    *q = e >= 0 ? e / 3 : -((-e + 2) / 3);
    rr = e - 3 * *q;                                                          /* 0, 1, 2 */
    v *= (double)(1 << rr);                                                   /* [1, 8) */
    y = 1.0 + (v - 1.0) / 7.0;
    for (i = 0; i < 5; ++i) {                                                  /* Halley: cubic convergence */
        const double y3 = y * y * y;
        y = y * (y3 + 2.0 * v) / (2.0 * y3 + v);
    }
    {
        /* one correction from the exact residual v - y^3 */
        const dd y3 = dd_mul_d(two_prod(y, y), y);
        const dd res = dd_sub(mk(v, 0.0), y3);
        return fast_two_sum(y, res.hi / (3.0 * y * y));
    }
}
DLLAPI double CRTAPI cbrt(double x)
{
    int q;
    dd r;
    if (!is_finite(x) || x == 0.0) return x + x;
    r = cbrt_dd(fabs_(x), &q);
    return copysign_(r.hi * pow2(q), x);
}
DLLAPI float CRTAPI cbrtf(float x)
{
    int q;
    dd r;
    if ((crt_f2u(x) & 0x7fffffffu) >= 0x7f800000u || x == 0.0f) return x + x;
    r = cbrt_dd(fabs_(x), &q);
    r = dd_scale(r, pow2(q));
    return dd_to_float(x < 0 ? dd_neg(r) : r);
}
/* hypot = r * 2^m */
static int hypot_core(double x, double y, dd *r, int *m)
{
    double ax = fabs_(x), ay = fabs_(y), t;
    int e;
    if (ax < ay) { t = ax; ax = ay; ay = t; }
    *m = 0;
    if (ay == 0.0 || ax > ay * 0x1p60) { *r = mk(ax, ay == 0.0 ? 0.0 : ay * (ay / ax) * 0.5); return ax == 0.0; }
    e = (int)((bits(ax) >> 52) & 0x7ff) - 1023;
    if (e < -1022) {                                                           /* subnormal ax: scale up first */
        ax *= 0x1p600; ay *= 0x1p600; *m = -600;
        e = (int)((bits(ax) >> 52) & 0x7ff) - 1023;
    }
    ax = scalbn_core(ax, -e);                                                  /* exact: [1, 2) */
    ay = scalbn_core(ay, -e);                                                  /* exact: >= 2^-60 */
    *m += e;
    *r = dd_sqrt(dd_add(two_prod(ax, ax), two_prod(ay, ay)));
    return 0;
}
DLLAPI double CRTAPI hypot(double x, double y)
{
    dd r;
    int m, tiny;
    double v;
    if (is_inf(x) || is_inf(y)) return from_bits(INF64);
    if (is_nan(x) || is_nan(y)) return x + y;
    if (hypot_core(x, y, &r, &m)) return 0.0;
    v = dd_ldexp(r, m, &tiny);
    if (is_inf(v)) return math_error(OVERFLOW_, "hypot", x, y, f_overflow(1.0));
    return v;
}
DLLAPI double CRTAPI _hypot(double x, double y) { return hypot(x, y); }
DLLAPI float CRTAPI _hypotf(float x, float y)
{
    dd r;
    int m;
    float v;
    if ((crt_f2u(x) & 0x7fffffffu) == 0x7f800000u || (crt_f2u(y) & 0x7fffffffu) == 0x7f800000u) return crt_u2f(0x7f800000u);
    if (x != x || y != y) return x + y;
    if (hypot_core(x, y, &r, &m)) return 0.0f;
    v = dd_ldexp_float(r, m);
    if ((crt_f2u(v) & 0x7fffffffu) == 0x7f800000u) return (float)math_error(OVERFLOW_, "_hypotf", x, y, v);
    return v;
}
typedef struct { double x, y; } crt_complex;
DLLAPI double CRTAPI _cabs(crt_complex z) { return hypot(z.x, z.y); }

/* ================================================================ error function */
/* erf(x) for 0 < x <= 3: 2/sqrt(pi) exp(-x^2) sum 2^n x^(2n+1) / (1*3*...*(2n+1)), all terms positive */
static dd erf_series(double x)
{
    const dd x2 = two_prod(x, x), twox2 = dd_scale(x2, 2.0);
    dd term = mk(x, 0.0), sum = term, e;
    int n, m;
    for (n = 1; n < 400; ++n) {
        term = dd_div(dd_mul(term, twox2), mk(2.0 * n + 1.0, 0.0));
        sum = dd_add(sum, term);
        if (term.hi < sum.hi * 0x1p-112) break;
    }
    e = exp_core(dd_neg(x2), &m);
    e = dd_scale(e, pow2(m));
    return dd_mul(dd_mul(sum, e), mk(C_TWO_OVER_SQRT_PI_HI, C_TWO_OVER_SQRT_PI_LO));
}
/* erfc(x) for x > 3 = y * 2^m: exp(-x^2)/sqrt(pi) / (x + (1/2)/(x + 1/(x + (3/2)/(x + ...)))) by Lentz's method */
static dd erfc_cf(double x, int *m)
{
    const dd X = mk(x, 0.0);
    dd f = X, C = X, D = mk(0.0, 0.0), e;
    int k;
    for (k = 1; k < 5000; ++k) {
        const double a = 0.5 * k;
        dd delta;
        D = dd_add(X, dd_mul_d(D, a));
        D = dd_div(mk(1.0, 0.0), D);
        C = dd_add(X, dd_div(mk(a, 0.0), C));
        delta = dd_mul(C, D);
        f = dd_mul(f, delta);
        if (fabs_(delta.hi - 1.0) < 0x1p-104 && fabs_(delta.hi - 1.0 + delta.lo) < 0x1p-104) break;
    }
    e = exp_core(dd_neg(two_prod(x, x)), m);
    return dd_div(dd_mul(e, dd_scale(mk(C_TWO_OVER_SQRT_PI_HI, C_TWO_OVER_SQRT_PI_LO), 0.5)), f);
}
DLLAPI double CRTAPI erf(double x)
{
    const double ax = fabs_(x);
    dd r;
    if (is_nan(x)) return x + x;
    if (is_inf(x)) return copysign_(1.0, x);
    if (ax < 0x1p-28) {                                          /* 2/sqrt(pi) (x - x^3/3) */
        r = dd_mul(mk(C_TWO_OVER_SQRT_PI_HI, C_TWO_OVER_SQRT_PI_LO), fast_two_sum(ax, -ax * ax * ax / 3.0));
        if (ax != 0 && ax < 0x1p-1022) (void)f_underflow(1.0);
        return x < 0 ? -r.hi : r.hi;
    }
    if (ax >= 6.0) return copysign_(1.0 - 0x1p-60, x);
    if (ax <= 3.0) r = erf_series(ax);
    else {
        int m;
        r = erfc_cf(ax, &m);
        r = dd_add_d(dd_neg(dd_scale(r, pow2(m))), 1.0);
    }
    return x < 0 ? -r.hi : r.hi;
}
static int erfc_dd(double x, dd *r, int *m)                   /* erfc(x) = r * 2^m for finite x; 1 on total underflow */
{
    const double ax = fabs_(x);
    *m = 0;
    if (x > 27.3) return 1;
    if (ax <= 3.0) {
        const dd e = ax < 0x1p-60 ? mk(0.0, 0.0) : erf_series(ax);
        *r = x < 0 ? dd_add_d(e, 1.0) : dd_add_d(dd_neg(e), 1.0);
        return 0;
    }
    if (x < 0) {
        if (ax >= 10.0) { *r = mk(2.0, -0x1p-100); return 0; }
        {
            int mm;
            const dd c = erfc_cf(ax, &mm);
            *r = dd_add_d(dd_neg(dd_scale(c, pow2(mm))), 2.0);
            return 0;
        }
    }
    *r = erfc_cf(ax, m);
    return 0;
}
DLLAPI double CRTAPI erfc(double x)
{
    dd r;
    int m;
    if (is_nan(x)) return x + x;
    if (is_inf(x)) return x > 0 ? 0.0 : 2.0;
    if (erfc_dd(x, &r, &m)) return math_error(UNDERFLOW_, "erfc", x, 0, f_underflow(1.0));
    return finish_double(r, m, "erfc", x, 0);
}
DLLAPI float CRTAPI erff(float x)
{
    const double ax = fabs_(x);
    dd r;
    if (x != x) return x + x;
    if ((crt_f2u(x) & 0x7fffffffu) == 0x7f800000u) return (float)copysign_(1.0, x);
    if (ax < 0x1p-28) { r = dd_mul_d(mk(C_TWO_OVER_SQRT_PI_HI, C_TWO_OVER_SQRT_PI_LO), x); return dd_to_float(r); }
    if (ax >= 4.0) return (float)copysign_(1.0, x);
    if (ax <= 3.0) r = erf_series(ax);
    else {
        int m;
        r = erfc_cf(ax, &m);
        r = dd_add_d(dd_neg(dd_scale(r, pow2(m))), 1.0);
    }
    return dd_to_float(x < 0 ? dd_neg(r) : r);
}
DLLAPI float CRTAPI erfcf(float x)
{
    dd r;
    int m;
    if (x != x) return x + x;
    if ((crt_f2u(x) & 0x7fffffffu) == 0x7f800000u) return x > 0 ? 0.0f : 2.0f;
    if (x > 10.1f) return (float)math_error(UNDERFLOW_, "erfcf", x, 0, f_underflow(1.0));
    if (erfc_dd(x, &r, &m)) return 0.0f;
    return finish_float(r, m, "erfcf", x, 0);
}

/* ================================================================ gamma functions */
/* lgamma(1 + z) = -gamma z + sum_{k>=2} (-1)^k zeta(k) z^k / k, |z| <= 1/4 */
static dd lgamma_near1(dd z)
{
    dd p = mk(0.0, 0.0);
    int k;
    for (k = 60; k >= 2; --k) {
        dd c = k < 41 ? dd_mul(DDT(ZETA[k]), DDT(INV_N[k])) : dd_div(DDT(ZETA[k]), mk((double)k, 0.0));
        if (k & 1) c = dd_neg(c);
        p = dd_add(dd_mul(p, z), c);
    }
    p = dd_mul(p, z);                                               /* sum_{k>=2} ... z^(k-1) */
    p = dd_sub(p, mk(C_EULER_HI, C_EULER_LO));
    return dd_mul(p, z);
}
/* lgamma(2 + z) = (1 - gamma) z + sum_{k>=2} (-1)^k (zeta(k) - 1) z^k / k, |z| <= 1/4 */
static dd lgamma_near2(dd z)
{
    dd p = mk(0.0, 0.0);
    int k;
    for (k = 60; k >= 2; --k) {
        dd c = k < 41 ? dd_mul(DDT(ZETA_M1[k]), DDT(INV_N[k])) : dd_div(DDT(ZETA_M1[k]), mk((double)k, 0.0));
        if (k & 1) c = dd_neg(c);
        p = dd_add(dd_mul(p, z), c);
    }
    p = dd_mul(p, z);
    p = dd_add(p, mk(C_ONE_MINUS_EULER_HI, C_ONE_MINUS_EULER_LO));
    return dd_mul(p, z);
}
/* Stirling: (z - 1/2) log z - z + log sqrt(2 pi) + sum B_2k / (2k (2k-1) z^(2k-1)), z >= 20 */
static dd lgamma_stirling(dd z)
{
    const dd iz = dd_div(mk(1.0, 0.0), z), w = dd_mul(iz, iz);
    dd s = DDT(STIRLING[15]), r;
    int k;
    for (k = 14; k >= 1; --k) s = dd_add(dd_mul(s, w), DDT(STIRLING[k]));
    s = dd_mul(s, iz);
    r = dd_mul(dd_add_d(z, -0.5), log_dd(z));
    r = dd_sub(r, z);
    r = dd_add(r, mk(C_LN_SQRT_2PI_HI, C_LN_SQRT_2PI_LO));
    return dd_add(r, s);
}
static dd lgamma_pos(dd a)                                     /* a > 0 */
{
    if (a.hi < 0x1p-60) return dd_neg(log_dd(a));
    if (fabs_(a.hi - 1.0) <= 0.25) return lgamma_near1(dd_add_d(a, -1.0));
    if (fabs_(a.hi - 2.0) <= 0.25) return lgamma_near2(dd_add_d(a, -2.0));
    if (a.hi >= 20.0) return lgamma_stirling(a);
    {
        const int n = (int)(20.0 - a.hi) + 1;
        dd prod = a, z = a;
        int i;
        for (i = 1; i < n; ++i) prod = dd_mul(prod, dd_add_d(a, (double)i));
        z = dd_add_d(a, (double)n);
        return dd_sub(lgamma_stirling(z), log_dd(prod));
    }
}
/* sin(pi x) for |x| < 2^52 non-integer, as a double-double (exact reduction) */
static dd sinpi_dd(double x)
{
    const double h = x * 0.5;
    const double k = (double)(int64_t)(h + (h >= 0 ? 0.5 : -0.5));
    double f = x - 2.0 * k, g;                                  /* exact, f in [-1, 1] */
    const int neg = f < 0;
    dd r;
    if (neg) f = -f;
    g = f > 0.5 ? 1.0 - f : f;                                  /* sin(pi f) = sin(pi (1 - f)); exact */
    if (g <= 0.25) r = sin_kernel(dd_mul_d(mk(C_PI_HI, C_PI_LO), g));
    else r = cos_kernel(dd_mul_d(mk(C_PI_HI, C_PI_LO), 0.5 - g));
    return neg ? dd_neg(r) : r;
}
static int lgamma_special(double x, double *s, const char *name)
{
    if (is_nan(x)) { *s = x + x; return 1; }
    if (is_inf(x)) { *s = fabs_(x); return 1; }
    if (x <= 0 && is_integer(x)) { *s = math_error(SING_, name, x, 0, f_divzero(1.0)); return 1; }
    return 0;
}
static dd lgamma_dd(double x)
{
    if (x >= 0x1p900) {                                          /* x (log x - 1); the other terms are below 2^-850 relative */
        const dd l1 = dd_add_d(log_core(x), -1.0);
        return dd_scale(dd_mul_d(l1, x * 0x1p-100), 0x1p100);
    }
    if (x > 0) return lgamma_pos(mk(x, 0.0));
    if (x > -0x1p-60) return dd_neg(log_core(-x));
    {
        /* reflection: lgamma(x) = log(pi) - log|sin(pi x)| - lgamma(1 - x) */
        dd s = sinpi_dd(x);
        if (s.hi < 0) s = dd_neg(s);
        return dd_sub(dd_sub(mk(C_LN_PI_HI, C_LN_PI_LO), log_dd(s)), lgamma_pos(two_sum(1.0, -x)));
    }
}
DLLAPI double CRTAPI lgamma(double x)
{
    double s;
    dd r;
    if (lgamma_special(x, &s, "lgamma")) return s;
    r = lgamma_dd(x);
    if (is_inf(r.hi)) return math_error(OVERFLOW_, "lgamma", x, 0, r.hi);
    return r.hi;
}
DLLAPI float CRTAPI lgammaf(float x)
{
    double s;
    float f;
    if (lgamma_special(x, &s, "lgammaf")) return (float)s;
    f = dd_to_float(lgamma_dd(x));
    if ((crt_f2u(f) & 0x7fffffffu) == 0x7f800000u) return (float)math_error(OVERFLOW_, "lgammaf", x, 0, f);
    return f;
}
/* gamma = sign * r * 2^m; 1 overflow, -1 underflow */
static int tgamma_core(double x, dd *r, int *m, double *sign)
{
    *sign = 1.0;
    if (x > 171.7) return 1;
    if (x > 0) {
        const dd L = lgamma_pos(mk(x, 0.0));
        if (L.hi > 710.0) return 1;
        *r = exp_core(L, m);
        return 0;
    }
    {
        dd s = sinpi_dd(x), L;
        if (s.hi < 0) { *sign = -1.0; s = dd_neg(s); }
        if (x < -190.0) return -1;
        /* gamma(x) = pi / (sin(pi x) gamma(1 - x)) */
        L = dd_sub(dd_sub(mk(C_LN_PI_HI, C_LN_PI_LO), log_dd(s)), lgamma_pos(two_sum(1.0, -x)));
        if (L.hi > 710.0) return 1;
        if (L.hi < -760.0) return -1;
        *r = exp_core(L, m);
        return 0;
    }
}
static int tgamma_special(double x, double *s, const char *name)
{
    if (is_nan(x)) { *s = x + x; return 1; }
    if (x == 0.0) { *s = math_error(SING_, name, x, 0, f_divzero(x)); return 1; }
    if (is_inf(x)) { *s = x > 0 ? x : domain_err(name, x, 0); return 1; }
    if (x < 0 && is_integer(x)) { *s = domain_err(name, x, 0); return 1; }
    return 0;
}
DLLAPI double CRTAPI tgamma(double x)
{
    double s, sign;
    dd r;
    int m, k;
    if (tgamma_special(x, &s, "tgamma")) return s;
    if (x > 0 && x == (double)(int)x && x <= 23.0) {                            /* exact factorials */
        double f = 1.0;
        int i;
        for (i = 2; i < (int)x; ++i) f *= i;
        return f;
    }
    k = tgamma_core(x, &r, &m, &sign);
    if (k > 0) return math_error(OVERFLOW_, "tgamma", x, 0, f_overflow(sign));
    if (k < 0) return math_error(UNDERFLOW_, "tgamma", x, 0, f_underflow(sign));
    return finish_double(sign < 0 ? dd_neg(r) : r, m, "tgamma", x, 0);
}
DLLAPI float CRTAPI tgammaf(float x)
{
    double s, sign;
    dd r;
    int m, k;
    if (tgamma_special(x, &s, "tgammaf")) return (float)s;
    k = tgamma_core(x, &r, &m, &sign);
    if (k > 0) return (float)math_error(OVERFLOW_, "tgammaf", x, 0, f_overflow(sign));
    if (k < 0) return (float)math_error(UNDERFLOW_, "tgammaf", x, 0, f_underflow(sign));
    return finish_float(sign < 0 ? dd_neg(r) : r, m, "tgammaf", x, 0);
}

/* ================================================================ classification (<float.h>, corecrt_math.h helpers) */
#define FP_INFINITE_ 1
#define FP_NAN_ 2
#define FP_NORMAL_ (-1)
#define FP_SUBNORMAL_ (-2)
#define FP_ZERO_ 0
static short dclass(double x)
{
    const uint64_t a = bits(x) & ~SIGN64;
    if (a > INF64) return FP_NAN_;
    if (a == INF64) return FP_INFINITE_;
    if (!a) return FP_ZERO_;
    return (a >> 52) ? FP_NORMAL_ : FP_SUBNORMAL_;
}
static short fdclass(float x)
{
    const uint32_t a = crt_f2u(x) & 0x7fffffffu;
    if (a > 0x7f800000u) return FP_NAN_;
    if (a == 0x7f800000u) return FP_INFINITE_;
    if (!a) return FP_ZERO_;
    return (a >> 23) ? FP_NORMAL_ : FP_SUBNORMAL_;
}
DLLAPI short CRTAPI _dclass(double x) { return dclass(x); }
DLLAPI short CRTAPI _ldclass(double x) { return dclass(x); }
DLLAPI short CRTAPI _fdclass(float x) { return fdclass(x); }
DLLAPI int CRTAPI _dsign(double x) { return (bits(x) >> 63) ? 0x8000 : 0; }
DLLAPI int CRTAPI _ldsign(double x) { return _dsign(x); }
DLLAPI int CRTAPI _fdsign(float x) { return (crt_f2u(x) >> 31) ? 0x8000 : 0; }
DLLAPI short CRTAPI _dtest(double *x) { return dclass(*x); }
DLLAPI short CRTAPI _ldtest(double *x) { return dclass(*x); }
DLLAPI short CRTAPI _fdtest(float *x) { return fdclass(*x); }
/* _FP_LT 1, _FP_EQ 2, _FP_GT 4; 0 when unordered */
DLLAPI int CRTAPI _dpcomp(double x, double y) { return x < y ? 1 : x == y ? 2 : x > y ? 4 : 0; }
DLLAPI int CRTAPI _ldpcomp(double x, double y) { return _dpcomp(x, y); }
DLLAPI int CRTAPI _fdpcomp(float x, float y) { return x < y ? 1 : x == y ? 2 : x > y ? 4 : 0; }
DLLAPI int CRTAPI _isnan(double x) { return is_nan(x); }
DLLAPI int CRTAPI _isnanf(float x) { return x != x; }
DLLAPI int CRTAPI _finite(double x) { return is_finite(x); }
DLLAPI int CRTAPI _finitef(float x) { return (crt_f2u(x) & 0x7f800000u) != 0x7f800000u; }
/* _FPCLASS_SNAN 1, QNAN 2, NINF 4, NN 8, ND 0x10, NZ 0x20, PZ 0x40, PD 0x80, PN 0x100, PINF 0x200 */
DLLAPI int CRTAPI _fpclass(double x)
{
    const int neg = (int)(bits(x) >> 63);
    switch (dclass(x)) {
    case FP_NAN_: return (bits(x) & 0x0008000000000000ull) ? 2 : 1;
    case FP_INFINITE_: return neg ? 4 : 0x200;
    case FP_ZERO_: return neg ? 0x20 : 0x40;
    case FP_SUBNORMAL_: return neg ? 0x10 : 0x80;
    default: return neg ? 8 : 0x100;
    }
}
DLLAPI int CRTAPI _fpclassf(float x)
{
    const int neg = (int)(crt_f2u(x) >> 31);
    switch (fdclass(x)) {
    case FP_NAN_: return (crt_f2u(x) & 0x00400000u) ? 2 : 1;
    case FP_INFINITE_: return neg ? 4 : 0x200;
    case FP_ZERO_: return neg ? 0x20 : 0x40;
    case FP_SUBNORMAL_: return neg ? 0x10 : 0x80;
    default: return neg ? 8 : 0x100;
    }
}
