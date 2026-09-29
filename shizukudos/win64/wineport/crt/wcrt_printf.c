/* SPDX-License-Identifier: GPL-2.0-only
 * C runtime for the Wine port: the printf engine behind every UCRT __stdio_common_v*printf* entry point.
 *
 * Written from the C standard and the documented Microsoft format syntax:
 *   %[flags][width][.precision][size]type, flags - + space # 0, sizes hh h l ll L w I I32 I64 j z t, types
 *   d i u o x X c C s S Z p n e E f F g G a A and %%.
 * Microsoft rules that differ from ISO C are kept: 'l' is 32 bits, %p prints 16 upper-case hex digits, and with
 * _CRT_INTERNAL_PRINTF_LEGACY_WIDE_SPECIFIERS (what Wine's headers pass) %s/%c in a wide format mean wide text while
 * %S/%C mean the other width. %Z prints an ANSI_STRING / UNICODE_STRING (with l or w).
 *
 * Floating point is converted exactly: the binary value m * 2^e is expanded to all of its decimal digits with a small
 * base-1e9 big integer (at most ~770 digits for a double) and then rounded once, half away from zero, or half to even
 * when _CRT_INTERNAL_PRINTF_STANDARD_ROUNDING is set. inf/nan print as the UCRT does ("inf", "nan", "-nan(ind)").
 * long double is double (Microsoft ABI).
 */
#include "shzwcrt.h"
#include <corecrt_stdio_config.h>

#define OPT_LEGACY_WIDE   _CRT_INTERNAL_PRINTF_LEGACY_WIDE_SPECIFIERS
#define OPT_THREE_DIGIT   _CRT_INTERNAL_PRINTF_LEGACY_THREE_DIGIT_EXPONENTS
#define OPT_STD_ROUNDING  _CRT_INTERNAL_PRINTF_STANDARD_ROUNDING

/* ---------------------------------------------------------------- sink */
static void sink_unit(shzw_sink *s, unsigned int u)
{
    if (s->fp) {
        if (s->wide) {
            wchar_t w = (wchar_t)u;
            if (shzw_file_write(s->fp, &w, sizeof w) < 0) s->error = 1;
        } else {
            char c = (char)u;
            if (shzw_file_write(s->fp, &c, 1) < 0) s->error = 1;
        }
    } else if (s->pos < s->cap) {
        if (s->wide) { if (s->w) s->w[s->pos] = (wchar_t)u; }
        else if (s->a) s->a[s->pos] = (char)u;
        s->pos++;
    }
    s->total++;
}

/* narrow text into the sink (bytes 0..255 are code points U+0000..U+00FF in a wide sink) */
static void sink_narrow(shzw_sink *s, const char *p, size_t n)
{
    if (s->fp && !s->wide) {
        if (n && shzw_file_write(s->fp, p, n) < 0) s->error = 1;
        s->total += n;
        return;
    }
    while (n--) sink_unit(s, (unsigned char)*p++);
}

/* wide text into the sink (code points above U+00FF become '?' in a narrow sink: C locale) */
static void sink_wide(shzw_sink *s, const wchar_t *p, size_t n)
{
    while (n--) {
        unsigned int c = (unsigned short)*p++;
        sink_unit(s, s->wide || c < 256 ? c : '?');
    }
}

static void sink_pad(shzw_sink *s, unsigned int c, int n)
{
    while (n-- > 0) sink_unit(s, c);
}

/* ---------------------------------------------------------------- format reading (narrow or wide) */
typedef struct {
    const unsigned char *a;
    const unsigned short *w;
} fmt_ptr;

static unsigned int fch(const fmt_ptr *f, size_t i) { return f->a ? f->a[i] : f->w[i]; }

/* ---------------------------------------------------------------- exact decimal expansion of a double */
#define BIG_LIMBS 132                       /* base 1e9 limbs: 1188 digits >= 767 needed for 2^-1074 * (2^53-1) */
typedef struct { uint32_t d[BIG_LIMBS]; int n; } bigdec;

static void big_set_u64(bigdec *b, uint64_t v)
{
    b->n = 0;
    do { b->d[b->n++] = (uint32_t)(v % 1000000000u); v /= 1000000000u; } while (v);
}

static void big_mul_small(bigdec *b, uint32_t m)
{
    uint64_t carry = 0;
    int i;
    for (i = 0; i < b->n; ++i) {
        uint64_t t = (uint64_t)b->d[i] * m + carry;
        b->d[i] = (uint32_t)(t % 1000000000u);
        carry = t / 1000000000u;
    }
    while (carry && b->n < BIG_LIMBS) {
        b->d[b->n++] = (uint32_t)(carry % 1000000000u);
        carry /= 1000000000u;
    }
}

/* digits of b (most significant first, no leading zeros) into out; returns the count */
static int big_digits(const bigdec *b, char *out)
{
    int n = 0, i, k;
    char tmp[10];
    for (i = b->n - 1; i >= 0; --i) {
        uint32_t v = b->d[i];
        for (k = 8; k >= 0; --k) { tmp[k] = (char)('0' + v % 10); v /= 10; }
        if (i == b->n - 1) {
            for (k = 0; k < 8 && tmp[k] == '0'; ++k) { }
            memcpy(out + n, tmp + k, 9 - k);
            n += 9 - k;
        } else {
            memcpy(out + n, tmp, 9);
            n += 9;
        }
    }
    return n;
}

/* |v| = 0.D * 10^point where D = digits[0..n). v must be finite and nonzero. */
static int exact_digits(double v, char *digits, int *point)
{
    union { double d; uint64_t u; } x = { v };
    uint64_t mant = x.u & ((1ull << 52) - 1);
    int e = (int)((x.u >> 52) & 0x7ff), n, i;
    bigdec b;
    if (e) { mant |= 1ull << 52; e -= 1075; } else e = -1074;
    while (!(mant & 1)) { mant >>= 1; ++e; }             /* smaller numbers, same value */
    big_set_u64(&b, mant);
    if (e >= 0) {
        for (i = e; i >= 29; i -= 29) big_mul_small(&b, 1u << 29);
        if (i) big_mul_small(&b, 1u << i);
        n = big_digits(&b, digits);
        *point = n;
    } else {
        for (i = -e; i >= 13; i -= 13) big_mul_small(&b, 1220703125u);   /* 5^13 */
        {
            uint32_t p5 = 1;
            while (i--) p5 *= 5;
            if (p5 > 1) big_mul_small(&b, p5);
        }
        n = big_digits(&b, digits);
        *point = n + e;                                    /* divide by 10^-e */
    }
    while (n > 1 && digits[n - 1] == '0') --n;
    return n;
}

/* Round D (n digits, value 0.D * 10^*point) to keep `keep` digits; returns the new count (may grow the point). */
static int round_digits(char *d, int n, int keep, int *point, int half_even)
{
    int i, up;
    if (keep >= n) return n;
    if (keep < 0) { return 0; }
    if (d[keep] > '5') up = 1;
    else if (d[keep] < '5') up = 0;
    else {
        up = 0;
        for (i = keep + 1; i < n; ++i) if (d[i] != '0') { up = 1; break; }
        if (!up) up = half_even ? (keep > 0 && ((d[keep - 1] - '0') & 1)) : 1;
    }
    n = keep;
    if (up) {
        for (i = keep - 1; i >= 0; --i) {
            if (d[i] == '9') d[i] = '0';
            else { d[i]++; break; }
        }
        if (i < 0) {                                       /* 99..9 -> 100..0 */
            memmove(d + 1, d, keep);
            d[0] = '1';
            ++*point;
            if (keep == 0) n = 1;
        }
    }
    return n;
}

/* ---------------------------------------------------------------- one conversion */
typedef struct {
    int left, plus, space, alt, zero;
    int width, prec;                     /* prec < 0: not given */
    int size;                            /* 0 int, 1 char(hh), 2 short(h), 4 long(l, 32-bit), 8 64-bit */
    int wide_arg;                        /* -1 narrow forced (h), 1 wide forced (l/w), 0 default */
} spec;

static void emit_field(shzw_sink *s, const spec *sp, const char *prefix, const char *body, int body_len, int zeros)
{
    int plen = (int)strlen(prefix), total = plen + zeros + body_len;
    int pad = sp->width > total ? sp->width - total : 0;
    if (!sp->left && !sp->zero) sink_pad(s, ' ', pad);
    sink_narrow(s, prefix, plen);
    if (!sp->left && sp->zero) sink_pad(s, '0', pad);
    sink_pad(s, '0', zeros);
    sink_narrow(s, body, body_len);
    if (sp->left) sink_pad(s, ' ', pad);
}

static void fmt_integer(shzw_sink *s, spec sp, unsigned int type, uint64_t raw)
{
    char buf[80], prefix[4] = "";
    int neg = 0, len = 0, zeros = 0, base = 10;
    const char *digs = type == 'X' ? "0123456789ABCDEF" : "0123456789abcdef";
    uint64_t v = raw;
    if (type == 'd' || type == 'i') {
        int64_t sv;
        switch (sp.size) {
        case 1: sv = (signed char)raw; break;
        case 2: sv = (short)raw; break;
        case 8: sv = (int64_t)raw; break;
        default: sv = (int)raw; break;
        }
        if (sv < 0) { neg = 1; v = (uint64_t)0 - (uint64_t)sv; } else v = (uint64_t)sv;
    } else {
        switch (sp.size) {
        case 1: v = (unsigned char)raw; break;
        case 2: v = (unsigned short)raw; break;
        case 8: break;
        default: v = (unsigned int)raw; break;
        }
        base = type == 'o' ? 8 : type == 'u' ? 10 : 16;
    }
    if (sp.prec == 0 && v == 0) len = 0;
    else {
        char tmp[70];
        int k = 0;
        do { tmp[k++] = digs[v % (unsigned)base]; v /= (unsigned)base; } while (v);
        while (k) buf[len++] = tmp[--k];
    }
    if (neg) strcpy(prefix, "-");
    else if ((type == 'd' || type == 'i') && sp.plus) strcpy(prefix, "+");
    else if ((type == 'd' || type == 'i') && sp.space) strcpy(prefix, " ");
    if (sp.alt && raw) {
        if (type == 'x') strcpy(prefix, "0x");
        else if (type == 'X') strcpy(prefix, "0X");
    }
    if (sp.alt && type == 'o' && (len == 0 || buf[0] != '0')) {
        if (sp.prec <= len) zeros = 1;
    }
    if (sp.prec >= 0) {
        if (sp.prec > len) zeros = sp.prec - len;
        sp.zero = 0;
    }
    emit_field(s, &sp, prefix, buf, len, zeros);
}

static void fmt_pointer(shzw_sink *s, spec sp, uint64_t v)
{
    char buf[17];
    int i;
    for (i = 15; i >= 0; --i) { buf[i] = "0123456789ABCDEF"[v & 15]; v >>= 4; }
    sp.zero = 0;
    emit_field(s, &sp, sp.alt ? "0X" : "", buf, 16, 0);
}

static void fmt_string(shzw_sink *s, const spec *sp, const void *str, int wide, int is_char)
{
    size_t len = 0, max;
    int pad;
    if (!str) { str = wide ? (const void *)L"(null)" : (const void *)"(null)"; }
    max = (!is_char && sp->prec >= 0) ? (size_t)sp->prec : (size_t)-1;
    if (is_char) len = 1;
    else if (wide) { const wchar_t *w = str; while (len < max && w[len]) ++len; }
    else { const char *a = str; while (len < max && a[len]) ++len; }
    pad = sp->width > (int)len ? sp->width - (int)len : 0;
    if (!sp->left) sink_pad(s, sp->zero ? '0' : ' ', pad);
    if (wide) sink_wide(s, str, len);
    else sink_narrow(s, str, len);
    if (sp->left) sink_pad(s, ' ', pad);
}

static void fmt_float(shzw_sink *s, spec sp, unsigned int type, double v, unsigned long long options)
{
    char *d, out[1500], prefix[4] = "";
    union { double d; uint64_t u; } x = { v };
    int neg = (int)(x.u >> 63), upper = type == 'E' || type == 'F' || type == 'G' || type == 'A';
    int n, point, prec = sp.prec, len = 0, i, half_even = !!(options & OPT_STD_ROUNDING);
    unsigned int lt = type | 0x20;
    char local_digits[800];
    d = local_digits;
    if (neg) strcpy(prefix, "-");
    else if (sp.plus) strcpy(prefix, "+");
    else if (sp.space) strcpy(prefix, " ");
    if (((x.u >> 52) & 0x7ff) == 0x7ff) {                  /* inf / nan */
        uint64_t m = x.u & ((1ull << 52) - 1);
        const char *txt = !m ? "inf" : (neg && m == (1ull << 51)) ? "nan(ind)" : (m & (1ull << 51)) ? "nan" : "nan(snan)";
        for (i = 0; txt[i]; ++i) out[i] = upper ? (char)(txt[i] >= 'a' && txt[i] <= 'z' ? txt[i] - 32 : txt[i]) : txt[i];
        sp.zero = 0;
        emit_field(s, &sp, prefix, out, i, 0);
        return;
    }
    if (lt == 'a') {                                       /* hexadecimal: 0x1.hhhhp+e (13 digits unless precision) */
        uint64_t mant = x.u & ((1ull << 52) - 1);
        int e = (int)((x.u >> 52) & 0x7ff), lead = 1, nd;
        const char *hx = upper ? "0123456789ABCDEF" : "0123456789abcdef";
        char tmp[40];
        if (!e) { lead = 0; e = mant ? -1022 : 0; } else e -= 1023;
        if (prec < 0) prec = 13;
        if (prec < 13) {                                   /* round the 52-bit fraction to prec hex digits */
            int drop = (13 - prec) * 4;
            uint64_t half = 1ull << (drop - 1), rem = mant & ((1ull << drop) - 1);
            mant >>= drop;
            if (rem > half || (rem == half && (mant & 1))) mant++;
            if (prec == 0 ? mant >= 1 : (mant >> (prec * 4))) { lead++; mant &= prec ? (1ull << (prec * 4)) - 1 : 0; }
            nd = prec;
        } else nd = 13;
        strcat(prefix, upper ? "0X" : "0x");
        out[len++] = (char)('0' + lead);
        if (nd || sp.alt) out[len++] = '.';
        for (i = nd - 1; i >= 0; --i) tmp[i] = hx[(mant >> ((nd - 1 - i) * 4)) & 15];
        memcpy(out + len, tmp, nd);
        len += nd;
        for (i = 13; i < prec; ++i) out[len++] = '0';
        len += sprintf(out + len, "%c%+d", upper ? 'P' : 'p', e);
        emit_field(s, &sp, prefix, out, len, 0);
        return;
    }
    if (prec < 0) prec = 6;
    if (v == 0.0) { d[0] = '0'; n = 1; point = 1; }
    else n = exact_digits(v, d, &point);
    if (lt == 'g') {
        int P = prec ? prec : 1, X;
        int n2 = n, p2 = point;
        char save[800];
        memcpy(save, d, n);
        if (v != 0.0) n2 = round_digits(save, n, P, &p2, half_even);
        X = v == 0.0 ? 0 : p2 - 1;
        if (P > X && X >= -4) { lt = 'f'; prec = P - 1 - X; }
        else { lt = 'e'; prec = P - 1; }
        if (!sp.alt) {                                     /* %g drops trailing zeros: limit prec to significant digits */
            int sig;
            if (v == 0.0) sig = 0;
            else {
                int keep = lt == 'f' ? point + prec : prec + 1, nn, pp = point;
                char t2[800];
                memcpy(t2, d, n);
                nn = round_digits(t2, n, keep, &pp, half_even);
                while (nn > 0 && t2[nn - 1] == '0') --nn;
                sig = lt == 'f' ? nn - pp : nn - 1;
                if (sig < 0) sig = 0;
            }
            if (sig < prec) prec = sig;
        }
    }
    if (lt == 'e') {
        int exp10, ed;
        char eb[8];
        if (v != 0.0) n = round_digits(d, n, prec + 1, &point, half_even);
        exp10 = v == 0.0 ? 0 : point - 1;
        out[len++] = n > 0 ? d[0] : '0';
        if (prec || sp.alt) out[len++] = '.';
        for (i = 1; i <= prec; ++i) out[len++] = i < n ? d[i] : '0';
        out[len++] = upper ? 'E' : 'e';
        out[len++] = exp10 < 0 ? '-' : '+';
        if (exp10 < 0) exp10 = -exp10;
        ed = 0;
        do { eb[ed++] = (char)('0' + exp10 % 10); exp10 /= 10; } while (exp10);
        while (ed < ((options & OPT_THREE_DIGIT) ? 3 : 2)) eb[ed++] = '0';
        while (ed) out[len++] = eb[--ed];
    } else {                                               /* f */
        int keep = point + prec;
        if (v != 0.0) {
            if (keep < 0) n = 0;
            else n = round_digits(d, n, keep, &point, half_even);
        }
        if (n == 0) point = 1;                             /* rounded to zero */
        if (point <= 0) out[len++] = '0';
        else for (i = 0; i < point; ++i) {
            out[len++] = i < n ? d[i] : '0';
            if (len >= (int)sizeof out - 400) break;       /* cannot happen for doubles (<= 309 integer digits) */
        }
        if (prec || sp.alt) out[len++] = '.';
        for (i = 0; i < prec && len < (int)sizeof out - 2; ++i) {
            int idx = point + i;
            out[len++] = (idx >= 0 && idx < n) ? d[idx] : '0';
        }
        if (prec > i) {                                    /* very large precision: the rest are zeros */
            emit_field(s, &sp, prefix, out, len, 0);
            sink_pad(s, '0', prec - i);
            return;
        }
    }
    emit_field(s, &sp, prefix, out, len, 0);
}

/* ---------------------------------------------------------------- driver */
int shzw_format(shzw_sink *s, const void *fmt, int fmt_wide, unsigned long long options, va_list *ap)
{
    fmt_ptr f = { fmt_wide ? NULL : fmt, fmt_wide ? fmt : NULL };
    size_t i = 0;
    const int legacy = !!(options & OPT_LEGACY_WIDE);
    if (!fmt) return -1;
    for (;;) {
        unsigned int c = fch(&f, i), type;
        spec sp;
        if (!c) break;
        if (c != '%') {
            size_t j = i;
            while (fch(&f, j) && fch(&f, j) != '%') ++j;
            if (fmt_wide) sink_wide(s, (const wchar_t *)fmt + i, j - i);
            else sink_narrow(s, (const char *)fmt + i, j - i);
            i = j;
            continue;
        }
        ++i;
        memset(&sp, 0, sizeof sp);
        sp.prec = -1;
        for (;; ++i) {                                     /* flags */
            c = fch(&f, i);
            if (c == '-') sp.left = 1;
            else if (c == '+') sp.plus = 1;
            else if (c == ' ') sp.space = 1;
            else if (c == '#') sp.alt = 1;
            else if (c == '0') sp.zero = 1;
            else if (c == '\'') { }
            else break;
        }
        if (fch(&f, i) == '*') {
            sp.width = va_arg(*ap, int);
            if (sp.width < 0) { sp.left = 1; sp.width = -sp.width; }
            ++i;
        } else while ((c = fch(&f, i)) >= '0' && c <= '9') { sp.width = sp.width * 10 + (int)(c - '0'); ++i; }
        if (fch(&f, i) == '.') {
            ++i;
            sp.prec = 0;
            if (fch(&f, i) == '*') { sp.prec = va_arg(*ap, int); ++i; if (sp.prec < 0) sp.prec = -1; }
            else while ((c = fch(&f, i)) >= '0' && c <= '9') { sp.prec = sp.prec * 10 + (int)(c - '0'); ++i; }
        }
        for (;;) {                                         /* size */
            c = fch(&f, i);
            if (c == 'h') {
                if (fch(&f, i + 1) == 'h') { sp.size = 1; ++i; }
                else sp.size = 2;
                sp.wide_arg = -1;
                ++i;
            } else if (c == 'l') {
                if (fch(&f, i + 1) == 'l') { sp.size = 8; ++i; }
                else sp.size = 4;
                sp.wide_arg = 1;
                ++i;
            } else if (c == 'w') { sp.wide_arg = 1; ++i; }
            else if (c == 'L') { sp.size = 8; ++i; }
            else if (c == 'j' || c == 'z' || c == 't') { sp.size = 8; ++i; }
            else if (c == 'I') {
                if (fch(&f, i + 1) == '6' && fch(&f, i + 2) == '4') { sp.size = 8; i += 3; }
                else if (fch(&f, i + 1) == '3' && fch(&f, i + 2) == '2') { sp.size = 4; i += 3; }
                else { sp.size = 8; ++i; }
            } else if (c == 'T') { sp.wide_arg = fmt_wide ? 1 : -1; ++i; }
            else break;
        }
        type = fch(&f, i);
        if (!type) break;
        ++i;
        switch (type) {
        case '%':
            sink_unit(s, '%');
            break;
        case 'd': case 'i': case 'u': case 'o': case 'x': case 'X':
            fmt_integer(s, sp, type, sp.size == 8 ? va_arg(*ap, uint64_t) : (uint64_t)va_arg(*ap, unsigned int));
            break;
        case 'p':
            fmt_pointer(s, sp, (uint64_t)(uintptr_t)va_arg(*ap, void *));
            break;
        case 'c': case 'C': {
            int wide = sp.wide_arg ? sp.wide_arg > 0 : (type == 'C') != (fmt_wide && legacy);
            unsigned int ch = (unsigned int)va_arg(*ap, int);
            if (wide) { wchar_t w = (wchar_t)ch; fmt_string(s, &sp, &w, 1, 1); }
            else { char a = (char)ch; fmt_string(s, &sp, &a, 0, 1); }
            break;
        }
        case 's': case 'S': {
            int wide = sp.wide_arg ? sp.wide_arg > 0 : (type == 'S') != (fmt_wide && legacy);
            fmt_string(s, &sp, va_arg(*ap, const void *), wide, 0);
            break;
        }
        case 'Z': {                                        /* ANSI_STRING / UNICODE_STRING */
            const struct { USHORT Length, MaximumLength; void *Buffer; } *str = va_arg(*ap, const void *);
            if (!str || !str->Buffer) fmt_string(s, &sp, NULL, 0, 0);
            else {
                spec s2 = sp;
                int wide = sp.wide_arg > 0;
                int units = str->Length / (wide ? 2 : 1);
                if (s2.prec < 0 || s2.prec > units) s2.prec = units;
                fmt_string(s, &s2, str->Buffer, wide, 0);
            }
            break;
        }
        case 'n': {
            void *p = va_arg(*ap, void *);
            if (p) {
                if (sp.size == 8) *(int64_t *)p = (int64_t)s->total;
                else if (sp.size == 2) *(short *)p = (short)s->total;
                else if (sp.size == 1) *(signed char *)p = (signed char)s->total;
                else *(int *)p = (int)s->total;
            }
            break;
        }
        case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'a': case 'A':
            fmt_float(s, sp, type, va_arg(*ap, double), options);
            break;
        default:                                           /* unknown conversion: printed literally */
            sink_unit(s, '%');
            sink_unit(s, type);
            break;
        }
    }
    return s->error ? -1 : (int)s->total;
}

/* ---------------------------------------------------------------- UCRT entry points */
static int finish_buffer(shzw_sink *s, int ret, unsigned long long options, size_t len)
{
    /* the formatter stored min(ret, len) units; add the terminator the same way the UCRT does */
    if (s->pos < len) { if (s->wide) s->w[s->pos] = 0; else s->a[s->pos] = 0; }
    if (ret < 0) return ret;
    if (options & _CRT_INTERNAL_PRINTF_LEGACY_VSPRINTF_NULL_TERMINATION) return (size_t)ret > len ? -1 : ret;
    if ((size_t)ret >= len) {
        if (len) { if (s->wide) s->w[len - 1] = 0; else s->a[len - 1] = 0; }
        if (options & _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR) return ret;
        return len > 0 ? -2 : -1;
    }
    return ret;
}

int __cdecl __stdio_common_vsprintf(unsigned __int64 options, char *str, size_t len, const char *format,
                                    _locale_t locale, va_list args)
{
    shzw_sink s = { 0, str, NULL, str ? len : 0, 0, 0, NULL, 0 };
    va_list ap;
    int ret;
    (void)locale;
    va_copy(ap, args);
    ret = shzw_format(&s, format, 0, options, &ap);
    va_end(ap);
    if (!str) return ret;
    return finish_buffer(&s, ret, options, len);
}

int __cdecl __stdio_common_vswprintf(unsigned __int64 options, wchar_t *str, size_t len, const wchar_t *format,
                                     _locale_t locale, va_list args)
{
    shzw_sink s = { 1, NULL, str, str ? len : 0, 0, 0, NULL, 0 };
    va_list ap;
    int ret;
    (void)locale;
    va_copy(ap, args);
    ret = shzw_format(&s, format, 1, options, &ap);
    va_end(ap);
    if (!str) return ret;
    return finish_buffer(&s, ret, options, len);
}

int __cdecl __stdio_common_vsprintf_p(unsigned __int64 options, char *str, size_t len, const char *format,
                                      _locale_t locale, va_list args)
{
    /* positional parameters are not supported; formats without them behave like vsprintf_s */
    return __stdio_common_vsprintf_s(options, str, len, format, locale, args);
}

int __cdecl __stdio_common_vswprintf_p(unsigned __int64 options, wchar_t *str, size_t len, const wchar_t *format,
                                       _locale_t locale, va_list args)
{
    return __stdio_common_vswprintf_s(options, str, len, format, locale, args);
}

int __cdecl __stdio_common_vsprintf_s(unsigned __int64 options, char *str, size_t len, const char *format,
                                      _locale_t locale, va_list args)
{
    int ret;
    if (!str || !len || !format) { shzw_set_errno(22); return -1; }
    ret = __stdio_common_vsprintf(options | _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR, str, len, format, locale, args);
    if (ret < 0 || (size_t)ret >= len) { str[0] = 0; shzw_set_errno(34); return -1; }
    return ret;
}

int __cdecl __stdio_common_vswprintf_s(unsigned __int64 options, wchar_t *str, size_t len, const wchar_t *format,
                                       _locale_t locale, va_list args)
{
    int ret;
    if (!str || !len || !format) { shzw_set_errno(22); return -1; }
    ret = __stdio_common_vswprintf(options | _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR, str, len, format, locale, args);
    if (ret < 0 || (size_t)ret >= len) { str[0] = 0; shzw_set_errno(34); return -1; }
    return ret;
}

int __cdecl __stdio_common_vsnprintf_s(unsigned __int64 options, char *str, size_t size, size_t count,
                                       const char *format, _locale_t locale, va_list args)
{
    /* count == _TRUNCATE: fill the buffer and report truncation with -1; count < size: at most count units, -1 if
     * more were produced; otherwise the whole output must fit or the call fails with ERANGE and an empty buffer */
    unsigned __int64 o = options | _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR;
    int ret;
    if (!str || !size || !format) { shzw_set_errno(22); return -1; }
    if (count == (size_t)-1) {
        ret = __stdio_common_vsprintf(o, str, size, format, locale, args);
        return ret < 0 || (size_t)ret >= size ? -1 : ret;
    }
    if (count < size) {
        ret = __stdio_common_vsprintf(o, str, count + 1, format, locale, args);
        return ret < 0 || (size_t)ret > count ? -1 : ret;
    }
    ret = __stdio_common_vsprintf(o, str, size, format, locale, args);
    if (ret < 0 || (size_t)ret >= size) { str[0] = 0; shzw_set_errno(34); return -1; }
    return ret;
}

int __cdecl __stdio_common_vsnwprintf_s(unsigned __int64 options, wchar_t *str, size_t size, size_t count,
                                       const wchar_t *format, _locale_t locale, va_list args)
{
    /* count == _TRUNCATE: fill the buffer and report truncation with -1; count < size: at most count units, -1 if
     * more were produced; otherwise the whole output must fit or the call fails with ERANGE and an empty buffer */
    unsigned __int64 o = options | _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR;
    int ret;
    if (!str || !size || !format) { shzw_set_errno(22); return -1; }
    if (count == (size_t)-1) {
        ret = __stdio_common_vswprintf(o, str, size, format, locale, args);
        return ret < 0 || (size_t)ret >= size ? -1 : ret;
    }
    if (count < size) {
        ret = __stdio_common_vswprintf(o, str, count + 1, format, locale, args);
        return ret < 0 || (size_t)ret > count ? -1 : ret;
    }
    ret = __stdio_common_vswprintf(o, str, size, format, locale, args);
    if (ret < 0 || (size_t)ret >= size) { str[0] = 0; shzw_set_errno(34); return -1; }
    return ret;
}

int __cdecl __stdio_common_vfprintf(unsigned __int64 options, FILE *file, const char *format, _locale_t locale,
                                    va_list args)
{
    shzw_sink s = { 0, NULL, NULL, 0, 0, 0, file, 0 };
    va_list ap;
    int ret;
    (void)locale;
    if (!file || !format) { shzw_set_errno(22); return -1; }
    va_copy(ap, args);
    ret = shzw_format(&s, format, 0, options, &ap);
    va_end(ap);
    return ret;
}

int __cdecl __stdio_common_vfprintf_s(unsigned __int64 options, FILE *file, const char *format, _locale_t locale,
                                      va_list args)
{
    return __stdio_common_vfprintf(options, file, format, locale, args);
}

int __cdecl __stdio_common_vfprintf_p(unsigned __int64 options, FILE *file, const char *format, _locale_t locale,
                                      va_list args)
{
    return __stdio_common_vfprintf(options, file, format, locale, args);
}

int __cdecl __stdio_common_vfwprintf(unsigned __int64 options, FILE *file, const wchar_t *format, _locale_t locale,
                                     va_list args)
{
    /* wide output to a byte stream: characters are narrowed (C locale), like a text-mode stream without a code page */
    wchar_t buf[512], *big = NULL, *p = buf;
    va_list ap;
    int n, i;
    char out[512], *o = out;
    if (!file || !format) { shzw_set_errno(22); return -1; }
    va_copy(ap, args);
    n = __stdio_common_vswprintf(options | _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR, NULL, 0, format, locale, ap);
    va_end(ap);
    if (n < 0) return n;
    if ((size_t)n >= ARRAY_SIZE(buf)) {
        if (!(big = malloc((n + 1) * sizeof(wchar_t)))) return -1;
        p = big;
    }
    va_copy(ap, args);
    __stdio_common_vswprintf(options | _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR, p, n + 1, format, locale, ap);
    va_end(ap);
    if (n >= (int)sizeof out && !(o = malloc(n))) { free(big); return -1; }
    for (i = 0; i < n; ++i) o[i] = (unsigned short)p[i] < 256 ? (char)p[i] : '?';
    if (n && shzw_file_write(file, o, n) < 0) n = -1;
    if (o != out) free(o);
    free(big);
    return n;
}

int __cdecl __stdio_common_vfwprintf_s(unsigned __int64 options, FILE *file, const wchar_t *format, _locale_t locale,
                                       va_list args)
{
    return __stdio_common_vfwprintf(options, file, format, locale, args);
}
