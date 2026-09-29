/* SPDX-License-Identifier: GPL-2.0-only
 * Correctly rounded decimal / hexadecimal string -> double and float (strtod, strtof, wcstod, atof, scanf %f).
 *
 * Method (exact, no floating-point estimate): the significant digits D (the first 800 are kept exactly, the rest only
 * as a "nonzero" flag, which is enough because a midpoint between adjacent doubles has at most 767 significant digits)
 * and the decimal exponent E give V = D * 10^E. With big integers, Q = floor(V * 2^s) and a sticky bit (V * 2^s not an
 * integer) are computed for an s that leaves at least two bits below the last place of the result, including the
 * subnormal range; the result is then rounded to nearest, ties to even (the Universal CRT's mode). Short inputs take
 * Clinger's exact fast path (at most 15 digits and |E| <= 22: one correctly rounded IEEE multiplication or division).
 * Hexadecimal input (0x1.8p3) is rounded from its bits the same way. Also accepted, case-insensitively: inf, infinity,
 * nan, nan(...), nan(snan) and nan(ind) (Microsoft's spellings of a signalling and the default "indefinite" NaN).
 * *range_err reports overflow (result infinite) and underflow (result subnormal or zero and inexact).
 * Thread-safe: all working storage is on the caller's stack.
 */
#include "crtint.h"

#define MAXDIG 800
#define BL 136                                             /* 4352-bit integers: 10^1125 * 2^s stays below this */
typedef struct { uint32_t d[BL]; int n; } big;

static void big_small(big *b, uint32_t v) { b->d[0] = v; b->n = v ? 1 : 0; }
static void big_mul_add(big *b, uint32_t m, uint32_t add)
{
    uint64_t carry = add;
    int i;
    for (i = 0; i < b->n; ++i) {
        const uint64_t t = (uint64_t)b->d[i] * m + carry;
        b->d[i] = (uint32_t)t;
        carry = t >> 32;
    }
    if (carry && b->n < BL) b->d[b->n++] = (uint32_t)carry;
}
static void big_pow10_mul(big *b, int e)
{
    while (e >= 9) { big_mul_add(b, 1000000000u, 0); e -= 9; }
    while (e-- > 0) big_mul_add(b, 10, 0);
}
static int big_bits(const big *b) { return b->n ? 32 * (b->n - 1) + (32 - __builtin_clz(b->d[b->n - 1])) : 0; }
static void big_shl(big *b, int bits)
{
    const int w = bits / 32, s = bits % 32;
    int i;
    if (!b->n || bits <= 0) return;
    if (b->n + w + 1 > BL) { b->n = 0; return; }             /* cannot happen for the sizes used here */
    b->d[b->n + w] = 0;
    for (i = b->n - 1; i >= 0; --i) {
        const uint32_t v = b->d[i];
        b->d[i + w + 1] |= s ? v >> (32 - s) : 0;
        b->d[i + w] = s ? v << s : v;
    }
    for (i = 0; i < w; ++i) b->d[i] = 0;
    b->n += w + 1;
    while (b->n > 0 && !b->d[b->n - 1]) --b->n;
}
static void big_shr1(big *b)
{
    int i;
    for (i = 0; i < b->n; ++i) b->d[i] = (b->d[i] >> 1) | (i + 1 < b->n ? b->d[i + 1] << 31 : 0);
    while (b->n > 0 && !b->d[b->n - 1]) --b->n;
}
static int big_cmp(const big *a, const big *b)
{
    int i;
    if (a->n != b->n) return a->n < b->n ? -1 : 1;
    for (i = a->n - 1; i >= 0; --i)
        if (a->d[i] != b->d[i]) return a->d[i] < b->d[i] ? -1 : 1;
    return 0;
}
static void big_sub(big *a, const big *b)                  /* a -= b, a >= b */
{
    int64_t borrow = 0;
    int i;
    for (i = 0; i < a->n; ++i) {
        int64_t t = (int64_t)a->d[i] - (i < b->n ? b->d[i] : 0) - borrow;
        borrow = t < 0;
        a->d[i] = (uint32_t)(t + (borrow << 32));
    }
    while (a->n > 0 && !a->d[a->n - 1]) --a->n;
}
static int big_bit(const big *b, int i) { return i >= 0 && i / 32 < b->n ? (int)((b->d[i / 32] >> (i % 32)) & 1) : 0; }
static int big_any_below(const big *b, int i)              /* any set bit at positions < i */
{
    int w;
    if (i <= 0) return 0;
    for (w = 0; w < i / 32 && w < b->n; ++w) if (b->d[w]) return 1;
    if (w < b->n && (i % 32) && (b->d[w] & ((1u << (i % 32)) - 1))) return 1;
    return 0;
}
static uint64_t big_extract(const big *b, int lo, int count)   /* bits lo .. lo+count-1 (count <= 64) */
{
    uint64_t v = 0;
    int i;
    for (i = count - 1; i >= 0; --i) v = (v << 1) | (uint64_t)big_bit(b, lo + i);
    return v;
}

typedef struct { int p, kmin, kmax; } fmt_t;               /* mantissa bits, min / max exponent of the unit bit */
static const fmt_t F64 = { 53, -1074, 971 }, F32 = { 24, -149, 104 };

static double assemble(int neg, uint64_t m, int k, const fmt_t *f, int want_float)
{
    if (want_float) {
        uint32_t u;
        if (k > f->kmax) u = 0x7f800000u;
        else if (m < (1ull << (f->p - 1))) u = (uint32_t)m;              /* subnormal or zero (k == kmin) */
        else u = ((uint32_t)(k - f->kmin + 1) << 23) | ((uint32_t)m & 0x7fffffu);
        if (neg) u |= 0x80000000u;
        return (double)crt_u2f(u);
    } else {
        uint64_t u;
        if (k > f->kmax) u = 0x7ff0000000000000ull;
        else if (m < (1ull << (f->p - 1))) u = m;
        else u = ((uint64_t)(k - f->kmin + 1) << 52) | (m & 0xfffffffffffffull);
        if (neg) u |= 0x8000000000000000ull;
        return crt_u2d(u);
    }
}

/* Rounds Q * 2^-s (+ sticky) to the format. Q must carry at least two bits below the unit of the result. */
static double round_big(int neg, const big *q, int s, int sticky, const fmt_t *f, int want_float, int *range_err)
{
    const int L = big_bits(q);
    int k, drop, r;
    uint64_t m;
    if (!L) { if (sticky) *range_err = 1; return assemble(neg, 0, f->kmin, f, want_float); }
    k = L - 1 - s - (f->p - 1);                            /* unit exponent for a normal result */
    if (k < f->kmin) k = f->kmin;
    if (k > f->kmax) { *range_err = 1; return assemble(neg, 0, f->kmax + 1, f, want_float); }
    drop = k + s;                                          /* bits of Q below the unit */
    if (drop <= 0) {                                       /* every bit of Q is above the unit: exact */
        m = big_extract(q, 0, L) << -drop;
        r = sticky;
    } else {
        m = big_extract(q, drop, L - drop > 0 ? L - drop : 0);
        const int half = big_bit(q, drop - 1), rest = sticky || big_any_below(q, drop - 1);
        r = half || rest;                                  /* inexact */
        if (half && (rest || (m & 1))) {
            ++m;
            if (m == (1ull << f->p)) { m >>= 1; ++k; }
            if (k > f->kmax) { *range_err = 1; return assemble(neg, 0, f->kmax + 1, f, want_float); }
        }
    }
    if (r && m < (1ull << (f->p - 1))) *range_err = 1;     /* tiny and inexact: underflow */
    return assemble(neg, m, k, f, want_float);
}

static double decimal_to_binary(int neg, const char *dig, int nd, int E, int sticky, const fmt_t *f, int want_float, int *range_err)
{
    big num, den;
    int i;
    /* fast path (exact operands, one IEEE operation) when rounding to nearest */
    if (!sticky && nd <= 15 && crt_current_rounding() == CRT_RND_NEAREST) {
        uint64_t v = 0;
        for (i = 0; i < nd; ++i) v = v * 10 + (uint64_t)(dig[i] - '0');
        if (!want_float && E >= -22 && E <= 22) {
            static const double p10[] = { 1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15,
                                          1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22 };
            volatile double d = (double)v;                   /* v < 10^15 < 2^53: exact */
            d = E >= 0 ? d * p10[E] : d / p10[-E];
            return neg ? -d : d;
        }
        if (want_float && v < (1u << 24) && E >= -10 && E <= 10) {
            static const float p10f[] = { 1e0f, 1e1f, 1e2f, 1e3f, 1e4f, 1e5f, 1e6f, 1e7f, 1e8f, 1e9f, 1e10f };
            volatile float x = (float)v;
            x = E >= 0 ? x * p10f[E] : x / p10f[-E];
            return neg ? -(double)x : (double)x;
        }
    }
    big_small(&num, 0);
    for (i = 0; i < nd; ++i) {
        if (!num.n) big_small(&num, (uint32_t)(dig[i] - '0'));
        else big_mul_add(&num, 10, (uint32_t)(dig[i] - '0'));
    }
    if (E >= 0) {
        big_pow10_mul(&num, E);
        return round_big(neg, &num, 0, sticky, f, want_float, range_err);
    }
    big_small(&den, 1);
    big_pow10_mul(&den, -E);
    {
        /* choose s so that Q = floor(num * 2^s / den) has p + 3 bits, or reaches 2 bits below 2^kmin */
        const int ln = big_bits(&num), ld = big_bits(&den);
        int s = (f->p + 3) - (ln - ld);
        int qbits, b;
        big q, dsh;
        if ((ln - ld) - 2 - (f->p - 1) < f->kmin && s < 2 - f->kmin) s = 2 - f->kmin;   /* subnormal range */
        if (s < 0) s = 0;
        big_shl(&num, s);
        /* binary long division, quotient bits from the top */
        qbits = big_bits(&num) - ld + 1;
        if (qbits < 1) qbits = 1;
        dsh = den;
        big_shl(&dsh, qbits - 1);
        big_small(&q, 0);
        for (b = qbits - 1; b >= 0; --b) {
            if (big_cmp(&num, &dsh) >= 0) {
                big_sub(&num, &dsh);
                while (q.n <= b / 32) q.d[q.n++] = 0;
                q.d[b / 32] |= 1u << (b % 32);
            }
            big_shr1(&dsh);
        }
        while (q.n > 0 && !q.d[q.n - 1]) --q.n;
        return round_big(neg, &q, s, sticky || num.n != 0, f, want_float, range_err);
    }
}

static int lower(unsigned c) { return (c >= 'A' && c <= 'Z') ? (int)(c + 32) : (int)c; }
static int match_word(const void *s, crt_getch_fn get, size_t i, const char *w)
{
    size_t j;
    for (j = 0; w[j]; ++j)
        if (lower(get(s, i + j)) != w[j]) return 0;
    return 1;
}
static int hexval(unsigned c)
{
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c >= 'a' && c <= 'f') return (int)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (int)(c - 'A' + 10);
    return -1;
}

double crt_strtod_core(const void *s, crt_getch_fn get, size_t *consumed, int *range_err, int want_float)
{
    const fmt_t *f = want_float ? &F32 : &F64;
    size_t i = 0;
    int neg = 0;
    unsigned c;
    *range_err = 0;
    *consumed = 0;
    while ((c = get(s, i)) == ' ' || (c >= 9 && c <= 13)) ++i;
    if (c == '+' || c == '-') { neg = c == '-'; ++i; }
    c = get(s, i);
    if (lower(c) == 'i') {
        if (match_word(s, get, i, "infinity")) i += 8;
        else if (match_word(s, get, i, "inf")) i += 3;
        else return 0.0;
        *consumed = i;
        return assemble(neg, 0, f->kmax + 1, f, want_float);
    }
    if (lower(c) == 'n') {
        uint64_t bits = 0x7ff8000000000000ull;
        if (!match_word(s, get, i, "nan")) return 0.0;
        i += 3;
        if (get(s, i) == '(') {
            size_t j = i + 1;
            unsigned d;
            while ((d = get(s, j)) != 0 && ((d >= '0' && d <= '9') || (lower(d) >= 'a' && lower(d) <= 'z') || d == '_')) ++j;
            if (get(s, j) == ')') {
                if (j - i - 1 == 4 && match_word(s, get, i + 1, "snan")) bits = 0x7ff4000000000000ull;
                else if (j - i - 1 == 3 && match_word(s, get, i + 1, "ind")) bits = 0xfff8000000000000ull, neg = 0;
                i = j + 1;
            }
        }
        *consumed = i;
        if (neg) bits |= 0x8000000000000000ull;
        if (want_float) {
            uint32_t u = (uint32_t)(bits >> 63) << 31 | 0x7f800000u | (uint32_t)((bits >> 29) & 0x7fffffu);
            return (double)crt_u2f(u);
        }
        return crt_u2d(bits);
    }
    if (c == '0' && lower(get(s, i + 1)) == 'x' &&
        (hexval(get(s, i + 2)) >= 0 || (get(s, i + 2) == '.' && hexval(get(s, i + 3)) >= 0))) {
        /* up to 64 significant bits are kept; further nonzero digits only set the sticky flag */
        uint64_t hm = 0;
        long be = 0;
        int sticky = 0, h, started = 0;
        big q;
        i += 2;
        while ((h = hexval(get(s, i))) >= 0) {
            if (!started && !h) { ++i; continue; }
            started = 1;
            if (hm >> 60) { be += 4; if (h) sticky = 1; }
            else hm = hm * 16 + (uint64_t)h;
            ++i;
        }
        if (get(s, i) == '.') {
            ++i;
            while ((h = hexval(get(s, i))) >= 0) {
                if (!started && !h) { be -= 4; ++i; continue; }
                started = 1;
                if (!(hm >> 60)) { hm = hm * 16 + (uint64_t)h; be -= 4; }
                else if (h) sticky = 1;
                ++i;
            }
        }
        if (lower(get(s, i)) == 'p') {
            size_t j = i + 1;
            int eneg = 0, digits = 0;
            long ev = 0;
            if (get(s, j) == '+' || get(s, j) == '-') { eneg = get(s, j) == '-'; ++j; }
            while ((c = get(s, j)) >= '0' && c <= '9') { if (ev < 100000000) ev = ev * 10 + (long)(c - '0'); ++j; ++digits; }
            if (digits) { be += eneg ? -ev : ev; i = j; }
        }
        *consumed = i;
        if (!hm) return assemble(neg, 0, f->kmin, f, want_float);
        /* value = hm * 2^be: overflow / underflow far outside the range are decided without big numbers */
        {
            const long top = be + (64 - __builtin_clzll(hm)) - 1;
            if (top > f->kmax + f->p) { *range_err = 1; return assemble(neg, 0, f->kmax + 1, f, want_float); }
            if (top < f->kmin - 2) { *range_err = 1; return assemble(neg, 0, f->kmin, f, want_float); }
        }
        q.d[0] = (uint32_t)hm;
        q.d[1] = (uint32_t)(hm >> 32);
        q.n = q.d[1] ? 2 : 1;
        if (be >= 0) { big_shl(&q, (int)be); return round_big(neg, &q, 0, sticky, f, want_float, range_err); }
        return round_big(neg, &q, (int)-be, sticky, f, want_float, range_err);   /* value = Q * 2^-(-be), exact */
    }
    {
        char dig[MAXDIG];
        int nd = 0, sticky = 0, any = 0;
        long dexp = 0, E;
        while ((c = get(s, i)) == '0') { any = 1; ++i; }
        while ((c = get(s, i)) >= '0' && c <= '9') {
            any = 1;
            if (nd < MAXDIG) dig[nd++] = (char)c;
            else { ++dexp; if (c != '0') sticky = 1; }
            ++i;
        }
        if (c == '.') {
            const unsigned d = get(s, i + 1);
            if (any || (d >= '0' && d <= '9')) {
                ++i;
                if (!nd) while ((c = get(s, i)) == '0') { any = 1; --dexp; ++i; }
                while ((c = get(s, i)) >= '0' && c <= '9') {
                    any = 1;
                    if (nd < MAXDIG) { dig[nd++] = (char)c; --dexp; }
                    else if (c != '0') sticky = 1;
                    ++i;
                }
            }
        }
        if (!any) return 0.0;                              /* no digits: nothing converted */
        E = dexp;
        if (lower(get(s, i)) == 'e') {
            size_t j = i + 1;
            int eneg = 0, digits = 0;
            long ev = 0;
            if (get(s, j) == '+' || get(s, j) == '-') { eneg = get(s, j) == '-'; ++j; }
            while ((c = get(s, j)) >= '0' && c <= '9') { if (ev < 100000000) ev = ev * 10 + (long)(c - '0'); ++j; ++digits; }
            if (digits) { E += eneg ? -ev : ev; i = j; }
        }
        *consumed = i;
        while (nd > 0 && dig[nd - 1] == '0') { --nd; ++E; }
        if (!nd) return assemble(neg, 0, f->kmin, f, want_float);
        {
            const long mag = nd + E;                        /* value in [10^(mag-1), 10^mag) */
            const long maxmag = want_float ? 40 : 310, minmag = want_float ? -46 : -325;
            if (mag > maxmag) { *range_err = 1; return assemble(neg, 0, f->kmax + 1, f, want_float); }
            if (mag < minmag) { *range_err = 1; return assemble(neg, 0, f->kmin, f, want_float); }
            return decimal_to_binary(neg, dig, nd, (int)E, sticky, f, want_float, range_err);
        }
    }
}
