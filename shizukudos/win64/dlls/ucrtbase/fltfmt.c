/* SPDX-License-Identifier: GPL-2.0-only
 * Exact binary -> decimal conversion for the printf family (%e %f %g). The value m * 2^e is split into an integer
 * part and a binary fraction held in small fixed-size big integers; decimal digits are then produced exactly (the
 * integer part by repeated division by 10^9, the fraction by repeated multiplication by 10^9), so every digit printed
 * is the true digit of the stored double, as the Universal CRT does since Visual Studio 2015. The final digit is
 * rounded with the caller's rule (IEEE nearest-even, directed modes, or the legacy half-away-from-zero rule).
 */
#include "crtint.h"

#define BN_LIMBS 40                                  /* 1280 bits: > 1024-bit integer parts and 1074-bit fractions */
typedef struct { uint32_t d[BN_LIMBS]; int n; } bignum;

int crt_current_rounding(void)
{
    uint32_t csr;
    __asm__ volatile("stmxcsr %0" : "=m"(csr));
    switch ((csr >> 13) & 3) {
    case 1: return CRT_RND_DOWN;
    case 2: return CRT_RND_UP;
    case 3: return CRT_RND_ZERO;
    default: return CRT_RND_NEAREST;
    }
}

/* integer part (as limbs) -> decimal characters, most significant first; returns the count (0 for zero) */
static int bn_to_decimal(bignum *b, char *out)
{
    char tmp[340];
    int len = 0, i;
    while (b->n > 0) {
        uint64_t rem = 0;
        for (i = b->n - 1; i >= 0; --i) {
            const uint64_t cur = (rem << 32) | b->d[i];
            b->d[i] = (uint32_t)(cur / 1000000000u);
            rem = cur % 1000000000u;
        }
        while (b->n > 0 && !b->d[b->n - 1]) --b->n;
        for (i = 0; i < 9; ++i) { tmp[len++] = (char)('0' + rem % 10); rem /= 10; }
    }
    while (len > 0 && tmp[len - 1] == '0') --len;         /* strip leading zeros of the top chunk */
    for (i = 0; i < len; ++i) out[i] = tmp[len - 1 - i];
    return len;
}

/* Fraction generator: value = F / 2^(32*L), digits come out 9 at a time. */
typedef struct { uint32_t d[BN_LIMBS]; int n, lo; } frac_t;

static uint32_t frac_next9(frac_t *f)
{
    uint64_t carry = 0;
    int i;
    for (i = f->lo; i < f->n; ++i) {
        const uint64_t t = (uint64_t)f->d[i] * 1000000000u + carry;
        f->d[i] = (uint32_t)t;
        carry = t >> 32;
    }
    while (f->lo < f->n && !f->d[f->lo]) ++f->lo;
    return (uint32_t)carry;
}
static int frac_zero(const frac_t *f) { return f->lo >= f->n; }

/* Digit stream over the fraction: returns digits one by one. */
typedef struct { frac_t f; char blk[9]; int bpos; } fstream;
static void fs_init(fstream *s) { s->bpos = 9; }
static int fs_digit(fstream *s)
{
    if (s->bpos == 9) {
        uint32_t v;
        int i;
        if (frac_zero(&s->f)) return 0;
        v = frac_next9(&s->f);
        for (i = 8; i >= 0; --i) { s->blk[i] = (char)(v % 10); v /= 10; }
        s->bpos = 0;
    }
    return s->blk[s->bpos++];
}
static int fs_rest_nonzero(const fstream *s)
{
    int i;
    for (i = s->bpos; i < 9; ++i)
        if (s->blk[i]) return 1;
    return !frac_zero(&s->f);
}

static int round_up_decision(int rnd, int neg, int last, int r, int sticky)
{
    switch (rnd) {
    case CRT_RND_ZERO: return 0;
    case CRT_RND_UP: return !neg && (r || sticky);
    case CRT_RND_DOWN: return neg && (r || sticky);
    case CRT_RND_HALF_AWAY: return r >= 5;
    default: return r > 5 || (r == 5 && (sticky || (last & 1)));
    }
}

int crt_dtoa_fixed(double v, int prec, char mode, int rnd, int neg, char *buf, int *exp10)
{
    const uint64_t bits = crt_d2u(v) & 0x7fffffffffffffffull;
    const int ef = (int)(bits >> 52);
    uint64_t m = bits & 0xfffffffffffffull;
    int e, n = 0, i, r, sticky, ilen;
    bignum ip;
    fstream fs;
    char idig[340];

    if (ef) m |= 1ull << 52;
    e = ef ? ef - 1075 : -1074;
    ip.n = 0;
    fs.f.n = fs.f.lo = 0;
    fs_init(&fs);
    if (m) {
        if (e >= 0) {                                             /* integer: m << e */
            const int w = e / 32, s = e % 32;
            for (i = 0; i < BN_LIMBS; ++i) ip.d[i] = 0;
            ip.d[w] = (uint32_t)(m << s);
            ip.d[w + 1] = (uint32_t)((m << s) >> 32);
            if (s) ip.d[w + 2] = (uint32_t)(m >> (64 - s));
            ip.n = w + 3;
            while (ip.n > 0 && !ip.d[ip.n - 1]) --ip.n;
        } else {
            const int k = -e;                                     /* fractional bits */
            uint64_t ipart = k < 64 ? m >> k : 0, fpart = k < 64 ? m & ((1ull << k) - 1) : m;
            int L = (k + 31) / 32, sh = 32 * L - k, w, s;
            ip.d[0] = (uint32_t)ipart;
            ip.d[1] = (uint32_t)(ipart >> 32);
            ip.n = ipart ? (ipart >> 32 ? 2 : 1) : 0;
            /* fraction bits fpart / 2^k -> limbs of F << sh over 32*L bits */
            for (i = 0; i < L; ++i) fs.f.d[i] = 0;
            w = sh / 32;
            s = sh % 32;
            if (w < L) fs.f.d[w] |= (uint32_t)(fpart << s);
            if (w + 1 < L) fs.f.d[w + 1] |= (uint32_t)((fpart << s) >> 32);
            if (s && w + 2 < L) fs.f.d[w + 2] |= (uint32_t)(fpart >> (64 - s));
            fs.f.n = L;
            fs.f.lo = 0;
            while (fs.f.lo < fs.f.n && !fs.f.d[fs.f.lo]) ++fs.f.lo;
        }
    }
    ilen = bn_to_decimal(&ip, idig);

    if (mode == 'f') {
        /* integer digits (at least one), then prec fraction digits */
        if (ilen == 0) { buf[n++] = '0'; *exp10 = 1; }
        else { for (i = 0; i < ilen; ++i) buf[n++] = idig[i]; *exp10 = ilen; }
        for (i = 0; i < prec; ++i) buf[n++] = (char)('0' + fs_digit(&fs));
        r = fs_digit(&fs);
        sticky = fs_rest_nonzero(&fs);
    } else {
        const int want = prec + 1;
        int x;
        if (ilen) {
            x = ilen - 1;
            for (i = 0; i < ilen && n < want; ++i) buf[n++] = idig[i];
            if (n < want) {
                while (n < want) buf[n++] = (char)('0' + fs_digit(&fs));
                r = fs_digit(&fs);
                sticky = fs_rest_nonzero(&fs);
            } else if (i < ilen) {
                r = idig[i++] - '0';
                sticky = 0;
                for (; i < ilen; ++i) if (idig[i] != '0') sticky = 1;
                if (!sticky) sticky = fs_rest_nonzero(&fs) || !frac_zero(&fs.f);
            } else {
                r = fs_digit(&fs);
                sticky = fs_rest_nonzero(&fs);
            }
        } else if (!m) {
            x = 0;
            while (n < want) buf[n++] = '0';
            r = 0;
            sticky = 0;
        } else {
            int d;
            x = -1;
            while ((d = fs_digit(&fs)) == 0) --x;
            buf[n++] = (char)('0' + d);
            while (n < want) buf[n++] = (char)('0' + fs_digit(&fs));
            r = fs_digit(&fs);
            sticky = fs_rest_nonzero(&fs);
        }
        *exp10 = x;
    }
    if (round_up_decision(rnd, neg, n ? buf[n - 1] - '0' : 0, r, sticky)) {
        for (i = n - 1; i >= 0; --i) {
            if (buf[i] == '9') buf[i] = '0';
            else { ++buf[i]; break; }
        }
        if (i < 0) {                                              /* carry out of the leading digit */
            if (mode == 'f') {
                for (i = n; i > 0; --i) buf[i] = buf[i - 1];
                buf[0] = '1';
                ++n;
                ++*exp10;
            } else {
                buf[0] = '1';
                for (i = 1; i < n; ++i) buf[i] = '0';
                ++*exp10;
            }
        }
    }
    return n;
}
