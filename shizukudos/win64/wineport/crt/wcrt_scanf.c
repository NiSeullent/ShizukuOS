/* SPDX-License-Identifier: GPL-2.0-only
 * C runtime for the Wine port: sscanf/swscanf (UCRT __stdio_common_vs*scanf) and the string-to-floating conversions.
 *
 * Supported: %d %i %u %o %x %X %p %n %c %s %[set] %e %f %g %a (upper-case too), '*' suppression, widths, sizes
 * hh h l ll L w I I32 I64 j z t, and the secure (_s) form where %c/%s/%[ take a buffer size argument. With
 * _CRT_INTERNAL_SCANF_LEGACY_WIDE_SPECIFIERS a wide format's %s/%c/%[ store wide text (Microsoft rule).
 *
 * strtod: decimal and hexadecimal forms, inf/infinity/nan. Up to 19 significant decimal digits are accumulated exactly;
 * the power of ten is applied in x87 extended precision (64-bit mantissa), so results are within one unit in the last
 * place of the correctly rounded double and exact for the common cases (<= 15 digits, |exponent| <= 22).
 */
#include "shzwcrt.h"
#include <corecrt_stdio_config.h>
#include <math.h>

typedef struct {
    const unsigned char *a;
    const unsigned short *w;
    size_t len, pos;
} src;

static int peekc(src *s)
{
    if (s->pos >= s->len) return -1;
    {
        unsigned int c = s->a ? s->a[s->pos] : s->w[s->pos];
        return c ? (int)c : -1;
    }
}
static int getc_(src *s) { int c = peekc(s); if (c >= 0) s->pos++; return c; }
static int is_space(int c) { return c == ' ' || (c >= 9 && c <= 13); }

static int digit_val(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'z') return c - 'a' + 10;
    if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
    return 99;
}

/* ---------------------------------------------------------------- floating point parsing */
static long double pow10l_(int e)
{
    long double r = 1.0L, b = 10.0L;
    int n = e < 0 ? -e : e;
    while (n) { if (n & 1) r *= b; b *= b; n >>= 1; }
    return e < 0 ? 1.0L / r : r;
}

/* parse a floating value from src, reading at most `width` units; returns 1 if a number was read */
static int parse_float(src *s, size_t width, double *out)
{
    size_t start = s->pos, lim = width ? s->pos + width : (size_t)-1;
    int neg = 0, c, any = 0, exp10 = 0, ndig = 0, dropped = 0;
    unsigned long long m = 0;
    long double v;
#define PEEK() (s->pos < lim ? peekc(s) : -1)
    c = PEEK();
    if (c == '+' || c == '-') { neg = c == '-'; s->pos++; c = PEEK(); }
    if ((c | 0x20) == 'i' || (c | 0x20) == 'n') {       /* inf, infinity, nan, nan(...) */
        static const char inf[] = "infinity", nan_[] = "nan";
        size_t k = 0, save = s->pos;
        const char *word = (c | 0x20) == 'i' ? inf : nan_;
        while (word[k] && PEEK() >= 0 && (PEEK() | 0x20) == word[k]) { s->pos++; k++; }
        if (word == inf && (k == 3 || k == 8)) { *out = neg ? -HUGE_VAL : HUGE_VAL; return 1; }
        if (word == nan_ && k == 3) {
            if (PEEK() == '(') {
                size_t p = s->pos + 1;
                while (p < s->len && p < lim) {
                    unsigned int ch = s->a ? s->a[p] : s->w[p];
                    if (ch == ')') { s->pos = p + 1; break; }
                    if (!(ch == '_' || (ch >= '0' && ch <= '9') || ((ch | 0x20) >= 'a' && (ch | 0x20) <= 'z'))) break;
                    ++p;
                }
            }
            *out = neg ? -NAN : NAN;
            return 1;
        }
        s->pos = save;
        s->pos = start;
        return 0;
    }
    if (c == '0' && s->pos + 1 < lim && s->pos + 1 < s->len &&
        ((s->a ? s->a[s->pos + 1] : s->w[s->pos + 1]) | 0x20) == 'x') {
        /* hexadecimal floating constant */
        int bexp = 0, seen = 0;
        s->pos += 2;
        while ((c = PEEK()) >= 0 && digit_val(c) < 16) {
            if (m >> 60) { dropped |= digit_val(c) != 0; bexp += 4; }
            else m = m * 16 + digit_val(c);
            s->pos++; seen = 1;
        }
        if (PEEK() == '.') {
            s->pos++;
            while ((c = PEEK()) >= 0 && digit_val(c) < 16) {
                if (!(m >> 60)) { m = m * 16 + digit_val(c); bexp -= 4; }
                else dropped |= digit_val(c) != 0;
                s->pos++; seen = 1;
            }
        }
        if (!seen) { s->pos = start + (neg || (s->a ? s->a[start] : s->w[start]) == '+') + 1; *out = 0; return 1; }
        if ((PEEK() | 0x20) == 'p') {
            size_t save = s->pos;
            int en = 0, eneg = 0, ed = 0;
            s->pos++;
            c = PEEK();
            if (c == '+' || c == '-') { eneg = c == '-'; s->pos++; }
            while ((c = PEEK()) >= '0' && c <= '9') { if (en < 100000) en = en * 10 + c - '0'; s->pos++; ed = 1; }
            if (!ed) s->pos = save;
            else bexp += eneg ? -en : en;
        }
        if (dropped) m |= 1;
        v = (long double)m;
        while (bexp > 0) { int k = bexp > 60 ? 60 : bexp; v *= (long double)(1ull << k); bexp -= k; }
        while (bexp < 0) { int k = -bexp > 60 ? 60 : -bexp; v /= (long double)(1ull << k); bexp += k; }
        *out = (double)(neg ? -v : v);
        return 1;
    }
    while ((c = PEEK()) >= '0' && c <= '9') {
        if (ndig < 19) { m = m * 10 + (c - '0'); if (m) ndig++; }
        else { exp10++; dropped |= c != '0'; }
        s->pos++; any = 1;
    }
    if (c == '.') {
        s->pos++;
        while ((c = PEEK()) >= '0' && c <= '9') {
            if (ndig < 19) { m = m * 10 + (c - '0'); exp10--; if (m) ndig++; }
            else dropped |= c != '0';
            s->pos++; any = 1;
        }
    }
    if (!any) { s->pos = start; return 0; }
    if ((PEEK() | 0x20) == 'e') {
        size_t save = s->pos;
        int en = 0, eneg = 0, ed = 0;
        s->pos++;
        c = PEEK();
        if (c == '+' || c == '-') { eneg = c == '-'; s->pos++; }
        while ((c = PEEK()) >= '0' && c <= '9') { if (en < 100000) en = en * 10 + c - '0'; s->pos++; ed = 1; }
        if (!ed) s->pos = save;
        else exp10 += eneg ? -en : en;
    }
#undef PEEK
    if (!m) { *out = neg ? -0.0 : 0.0; return 1; }
    if (m < (1ull << 53) && exp10 >= -22 && exp10 <= 22 && !dropped) {
        double d = (double)m, p = (double)pow10l_(exp10 < 0 ? -exp10 : exp10);
        d = exp10 < 0 ? d / p : d * p;                     /* both operands exact: one correctly rounded operation */
        *out = neg ? -d : d;
        return 1;
    }
    if (exp10 > 330) v = __builtin_huge_vall();
    else if (exp10 < -360) v = 0;
    else v = (long double)m * pow10l_(exp10);            /* x87 range covers 10^-360..10^350 without overflow */
    *out = (double)(neg ? -v : v);
    if (*out == HUGE_VAL || *out == -HUGE_VAL || *out == 0.0) shzw_set_errno(34);
    return 1;
}

double shzw_strtod(const void *str, int wide, const void **end)
{
    src s = { wide ? NULL : str, wide ? str : NULL, (size_t)-1, 0 };
    double v = 0;
    while (is_space(peekc(&s))) s.pos++;
    if (!parse_float(&s, 0, &v)) s.pos = 0;
    if (end) *end = wide ? (const void *)((const wchar_t *)str + s.pos) : (const void *)((const char *)str + s.pos);
    return v;
}

double __cdecl strtod(const char *s, char **end) { return shzw_strtod(s, 0, (const void **)end); }
double __cdecl wcstod(const wchar_t *s, wchar_t **end) { return shzw_strtod(s, 1, (const void **)end); }
float __cdecl strtof(const char *s, char **end) { return (float)strtod(s, end); }
float __cdecl wcstof(const wchar_t *s, wchar_t **end) { return (float)wcstod(s, end); }
double __cdecl atof(const char *s) { return strtod(s, NULL); }
double __cdecl _wtof(const wchar_t *s) { return wcstod(s, NULL); }
double __cdecl _strtod_l(const char *s, char **end, _locale_t l) { (void)l; return strtod(s, end); }
double __cdecl _wcstod_l(const wchar_t *s, wchar_t **end, _locale_t l) { (void)l; return wcstod(s, end); }
double __cdecl _atof_l(const char *s, _locale_t l) { (void)l; return atof(s); }

/* ---------------------------------------------------------------- scanf engine */
static void store_int(void *p, int size, unsigned long long v)
{
    switch (size) {
    case 1: *(unsigned char *)p = (unsigned char)v; break;
    case 2: *(unsigned short *)p = (unsigned short)v; break;
    case 8: *(unsigned long long *)p = v; break;
    default: *(unsigned int *)p = (unsigned int)v; break;
    }
}

int shzw_scan(const void *input, size_t len, int wide, const void *fmt, unsigned long long options, va_list *ap)
{
    src in = { wide ? NULL : input, wide ? input : NULL, len, 0 };
    const unsigned char *fa = wide ? NULL : fmt;
    const unsigned short *fw = wide ? fmt : NULL;
    size_t i = 0;
    int assigned = 0, secure = !!(options & _CRT_INTERNAL_SCANF_SECURECRT);
    int legacy = !!(options & _CRT_INTERNAL_SCANF_LEGACY_WIDE_SPECIFIERS);
#define F(k) ((unsigned int)(fa ? fa[k] : fw[k]))
    if (!input || !fmt) return -1;
    if (peekc(&in) < 0) {
        /* input empty: EOF unless the format is empty or only whitespace */
        size_t k = 0;
        while (F(k) && is_space((int)F(k))) ++k;
        if (F(k)) return -1;
        return 0;
    }
    while (F(i)) {
        unsigned int c = F(i);
        int suppress = 0, size = 0, wide_arg = 0, type;
        size_t width = 0;
        if (is_space((int)c)) {
            while (is_space((int)F(i))) ++i;
            while (is_space(peekc(&in))) in.pos++;
            continue;
        }
        if (c != '%' || F(i + 1) == '%') {
            if (c == '%') ++i;
            if (peekc(&in) != (int)c) break;
            in.pos++; ++i;
            continue;
        }
        ++i;
        if (F(i) == '*') { suppress = 1; ++i; }
        while (F(i) >= '0' && F(i) <= '9') { width = width * 10 + (F(i) - '0'); ++i; }
        for (;;) {
            c = F(i);
            if (c == 'h') { if (F(i + 1) == 'h') { size = 1; ++i; } else size = 2; wide_arg = -1; ++i; }
            else if (c == 'l') { if (F(i + 1) == 'l') { size = 8; ++i; } else size = 4; wide_arg = 1; ++i; }
            else if (c == 'w') { wide_arg = 1; ++i; }
            else if (c == 'L' || c == 'j' || c == 'z' || c == 't') { size = 8; ++i; }
            else if (c == 'I') {
                if (F(i + 1) == '6' && F(i + 2) == '4') { size = 8; i += 3; }
                else if (F(i + 1) == '3' && F(i + 2) == '2') { size = 4; i += 3; }
                else { size = 8; ++i; }
            } else break;
        }
        type = (int)F(i);
        if (!type) break;
        ++i;
        if (type != 'c' && type != 'C' && type != '[' && type != 'n')
            while (is_space(peekc(&in))) in.pos++;
        if (type == 'n') {
            if (!suppress) store_int(va_arg(*ap, void *), size, in.pos);
            continue;
        }
        if (peekc(&in) < 0) return assigned ? assigned : -1;
        switch (type) {
        case 'd': case 'i': case 'u': case 'o': case 'x': case 'X': case 'p': {
            int base = type == 'o' ? 8 : (type == 'x' || type == 'X' || type == 'p') ? 16 : type == 'i' ? 0 : 10;
            size_t lim = width ? in.pos + width : (size_t)-1, start = in.pos;
            int neg = 0, any = 0, ch;
            unsigned long long v = 0;
            if (type == 'p') size = 8;
            ch = peekc(&in);
            if ((ch == '+' || ch == '-') && in.pos < lim) { neg = ch == '-'; in.pos++; }
            if (in.pos < lim && peekc(&in) == '0') {
                if (in.pos + 1 < lim && (base == 0 || base == 16) && in.pos + 1 < in.len &&
                    ((wide ? in.w[in.pos + 1] : in.a[in.pos + 1]) | 0x20) == 'x') {
                    in.pos += 2; base = 16;
                } else if (base == 0) base = 8;
                any = 1;                                   /* the '0' itself (not consumed if base 8) */
            }
            if (base == 0) base = 10;
            while (in.pos < lim && (ch = peekc(&in)) >= 0 && digit_val(ch) < base) {
                v = v * (unsigned)base + (unsigned)digit_val(ch);
                in.pos++; any = 1;
            }
            if (!any) { in.pos = start; return assigned; }
            if (neg) v = (unsigned long long)0 - v;
            if (!suppress) { store_int(va_arg(*ap, void *), size, v); assigned++; }
            break;
        }
        case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'a': case 'A': {
            double d;
            if (!parse_float(&in, width, &d)) return assigned;
            if (!suppress) {
                void *p = va_arg(*ap, void *);
                if (size == 4 || size == 8) *(double *)p = d;
                else *(float *)p = (float)d;
                assigned++;
            }
            break;
        }
        case 'c': case 'C': case 's': case 'S': case '[': {
            int to_wide = wide_arg ? wide_arg > 0 : ((type == 'C' || type == 'S') != (wide && legacy));
            unsigned char set[8192 / 8];
            int invert = 0, ch;
            size_t n = 0, cap = (size_t)-1;
            void *dst = NULL;
            if (type == 'c' || type == 'C') { if (!width) width = 1; }
            if (type == '[') {
                unsigned int prev = 0x10000;
                memset(set, 0, sizeof set);
                if (F(i) == '^') { invert = 1; ++i; }
                if (F(i) == ']') { set[']' >> 3] |= 1 << (']' & 7); prev = ']'; ++i; }
                while (F(i) && F(i) != ']') {
                    unsigned int a = F(i);
                    if (a == '-' && prev != 0x10000 && F(i + 1) && F(i + 1) != ']') {
                        unsigned int b = F(i + 1), k;
                        for (k = prev < b ? prev : b; k <= (prev < b ? b : prev) && k < 8192; ++k) set[k >> 3] |= 1 << (k & 7);
                        i += 2; prev = 0x10000;
                        continue;
                    }
                    if (a < 8192) set[a >> 3] |= 1 << (a & 7);
                    prev = a; ++i;
                }
                if (F(i) == ']') ++i;
            }
            if (!suppress) {
                dst = va_arg(*ap, void *);
                if (secure) cap = va_arg(*ap, unsigned int);
            }
            while ((!width || n < width) && (ch = peekc(&in)) >= 0) {
                if (type == 's' || type == 'S') { if (is_space(ch)) break; }
                else if (type == '[') {
                    int in_set = ch < 8192 ? !!(set[ch >> 3] & (1 << (ch & 7))) : 0;
                    if (in_set == invert) break;
                }
                if (dst) {
                    if (n + ((type == 'c' || type == 'C') ? 0 : 1) >= cap && cap != (size_t)-1) {
                        if (cap) { if (to_wide) ((wchar_t *)dst)[0] = 0; else ((char *)dst)[0] = 0; }
                        return assigned;
                    }
                    if (to_wide) ((wchar_t *)dst)[n] = (wchar_t)ch;
                    else ((char *)dst)[n] = ch < 256 ? (char)ch : '?';
                }
                n++; in.pos++;
            }
            if (!n) return assigned;
            if ((type == 'c' || type == 'C') && n < width) return assigned;
            if (dst) {
                if (type != 'c' && type != 'C') { if (to_wide) ((wchar_t *)dst)[n] = 0; else ((char *)dst)[n] = 0; }
                assigned++;
            }
            break;
        }
        default:
            return assigned;
        }
    }
#undef F
    return assigned;
}

int __cdecl __stdio_common_vsscanf(unsigned __int64 options, const char *input, size_t length, const char *format,
                                   _locale_t locale, va_list args)
{
    va_list ap;
    int r;
    (void)locale;
    va_copy(ap, args);
    r = shzw_scan(input, length, 0, format, options, &ap);
    va_end(ap);
    return r;
}

int __cdecl __stdio_common_vswscanf(unsigned __int64 options, const wchar_t *input, size_t length, const wchar_t *format,
                                    _locale_t locale, va_list args)
{
    va_list ap;
    int r;
    (void)locale;
    va_copy(ap, args);
    r = shzw_scan(input, length, 1, format, options, &ap);
    va_end(ap);
    return r;
}
