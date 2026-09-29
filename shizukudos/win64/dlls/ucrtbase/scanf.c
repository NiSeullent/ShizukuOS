/* SPDX-License-Identifier: GPL-2.0-only
 * scanf engine of the Shizuku UCRT and the string entry points __stdio_common_vsscanf / __stdio_common_vswscanf.
 * Conversions d i o u x X n p c s [ e E f F g G a A C S and %%, the size prefixes hh h l ll L j z t I I32 I64 w,
 * assignment suppression (*), field widths, scan sets with ranges and ^, the secure (_s) forms that take a buffer size
 * after every c / s / [ pointer, and the legacy wide-specifier rule of the wide functions (%s is wchar_t* unless the
 * ISO bit is used). Integers wrap modulo the field size; floating-point fields are converted with the correctly
 * rounded strtod core. Only the "C" locale exists.
 */
#include "crtint.h"

typedef struct {
    crt_in *in;
    size_t consumed;
    int eof;
} scanner;

static int sc_get(scanner *s)
{
    int c = s->in->get(s->in);
    if (c < 0) { s->eof = 1; return -1; }
    ++s->consumed;
    return c;
}
static void sc_unget(scanner *s, int c)
{
    if (c < 0) return;
    s->in->unget(s->in, c);
    --s->consumed;
}
static int is_ws(int c) { return c == ' ' || (c >= 9 && c <= 13); }
static unsigned fch(const void *f, int wide, size_t i) { return wide ? ((const wchar16 *)f)[i] : ((const unsigned char *)f)[i]; }

enum { SZ_DEF, SZ_HH, SZ_H, SZ_L, SZ_LL, SZ_PTR, SZ_LD };

static void store_int(void *p, int size, uint64_t v)
{
    switch (size) {
    case SZ_HH: *(unsigned char *)p = (unsigned char)v; break;
    case SZ_H: *(unsigned short *)p = (unsigned short)v; break;
    case SZ_LL: case SZ_PTR: *(uint64_t *)p = v; break;
    default: *(uint32_t *)p = (uint32_t)v; break;                   /* int and long are 32 bits */
    }
}

static int digit_of(int c, int base)
{
    int d;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'z') d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'Z') d = c - 'A' + 10;
    else return -1;
    return d < base ? d : -1;
}

/* reads an integer field of at most `width` units; returns 1 on success, 0 on matching failure */
static int scan_int(scanner *s, int width, int base, uint64_t *out)
{
    int c, neg = 0, any = 0;
    uint64_t v = 0;
    c = sc_get(s);
    if ((c == '+' || c == '-') && width) { neg = c == '-'; --width; c = width ? sc_get(s) : -2; }
    if (c == '0' && width) {
        any = 1;
        --width;
        c = width ? sc_get(s) : -2;
        if ((c == 'x' || c == 'X') && width && (base == 16 || base == 0)) {
            --width;
            base = 16;
            any = 0;
            c = width ? sc_get(s) : -2;
            if (digit_of(c, 16) < 0) {                          /* "0x" not followed by a digit: the 0 counts */
                any = 1;
            }
        } else if (base == 0) base = 8;
    } else if (base == 0) base = 10;
    while (width && c >= 0) {
        const int d = digit_of(c, base);
        if (d < 0) break;
        any = 1;
        v = v * (uint64_t)base + (uint64_t)d;
        --width;
        c = width ? sc_get(s) : -2;
    }
    if (c >= 0) sc_unget(s, c);
    if (!any) return 0;
    *out = neg ? (uint64_t)0 - v : v;
    return 1;
}

/* collects the longest prefix of a floating-point number (C grammar incl. inf, nan(...), hex) into buf */
static int scan_float_text(scanner *s, int width, char *buf, size_t cap)
{
    size_t n = 0;
    int c = sc_get(s);
#define TAKE() do { if (n + 1 < cap) buf[n++] = (char)c; --width; c = width ? sc_get(s) : -2; } while (0)
    if ((c == '+' || c == '-') && width) TAKE();
    if (c == 'i' || c == 'I' || c == 'n' || c == 'N') {
        const char *word = (c == 'i' || c == 'I') ? "infinity" : "nan";
        size_t k = 0;
        while (word[k] && width && (c | 0x20) == word[k]) { TAKE(); ++k; }
        if (word[0] == 'i') {
            if (k != 3 && k != 8) { if (c >= 0) sc_unget(s, c); return 0; }  /* partial word: matching failure */
        } else {
            if (k != 3) { if (c >= 0) sc_unget(s, c); return 0; }
            if (c == '(' && width) {
                TAKE();
                while (width && c >= 0 && ((c >= '0' && c <= '9') || ((c | 0x20) >= 'a' && (c | 0x20) <= 'z') || c == '_')) TAKE();
                if (c == ')' && width) TAKE();
                else { if (c >= 0) sc_unget(s, c); return 0; }
            }
        }
        if (c >= 0) sc_unget(s, c);
        buf[n] = 0;
        return 1;
    }
    {
        int hex = 0, digits = 0;
        if (c == '0' && width) {
            TAKE();
            digits = 1;
            if ((c == 'x' || c == 'X') && width) { TAKE(); hex = 1; digits = 0; }
        }
        while (width && c >= 0 && (hex ? digit_of(c, 16) >= 0 : (c >= '0' && c <= '9'))) { TAKE(); digits = 1; }
        if (c == '.' && width) {
            TAKE();
            while (width && c >= 0 && (hex ? digit_of(c, 16) >= 0 : (c >= '0' && c <= '9'))) { TAKE(); digits = 1; }
        }
        if (!digits) { if (c >= 0) sc_unget(s, c); return 0; }
        if (width && c >= 0 && ((!hex && (c == 'e' || c == 'E')) || (hex && (c == 'p' || c == 'P')))) {
            TAKE();
            if ((c == '+' || c == '-') && width) TAKE();
            while (width && c >= '0' && c <= '9') TAKE();
        }
    }
#undef TAKE
    if (c >= 0) sc_unget(s, c);
    buf[n] = 0;
    return 1;
}

typedef struct { unsigned char bits[8192]; int neg; } scanset;
static size_t parse_set(const void *f, int wide, size_t k, scanset *set)
{
    unsigned c, prev = 0x10000;
    size_t start;
    crt_memset(set->bits, 0, sizeof set->bits);
    set->neg = 0;
    if (fch(f, wide, k) == '^') { set->neg = 1; ++k; }
    start = k;
    for (;; ++k) {
        c = fch(f, wide, k);
        if (!c) return 0;
        if (c == ']' && k != start) break;
        if (c == '-' && prev != 0x10000 && fch(f, wide, k + 1) != ']' && fch(f, wide, k + 1)) {
            unsigned hi = fch(f, wide, k + 1), lo = prev, x;
            if (hi < lo) { x = lo; lo = hi; hi = x; }
            for (x = lo; x <= hi; ++x) set->bits[x >> 3] |= (unsigned char)(1u << (x & 7));
            ++k;
            prev = 0x10000;
            continue;
        }
        set->bits[c >> 3] |= (unsigned char)(1u << (c & 7));
        prev = c;
    }
    return k + 1;
}
static int in_set(const scanset *set, int c)
{
    const int hit = c >= 0 && c < 0x10000 && (set->bits[c >> 3] >> (c & 7)) & 1;
    return set->neg ? !hit : hit;
}

int crt_scan(crt_in *in, uint64_t options, const void *fmt, int wide, va_list *ap)
{
    scanner s;
    size_t k = 0;
    int assigned = 0, conversions = 0;
    const int secure = (options & SCANF_SECURECRT) != 0;
    s.in = in;
    s.consumed = 0;
    s.eof = 0;
    CRT_VALIDATE(fmt != 0, CRT_EINVAL, CRT_EOF);
    for (;;) {
        unsigned c = fch(fmt, wide, k);
        int suppress = 0, width = -1, size = SZ_DEF, hflag = 0, lflag = 0, ch;
        unsigned conv;
        void *dest = 0;
        if (!c) break;
        if (is_ws((int)c)) {
            while (is_ws((int)fch(fmt, wide, k))) ++k;
            do ch = sc_get(&s); while (ch >= 0 && is_ws(ch));
            sc_unget(&s, ch);
            continue;
        }
        if (c != '%') {
            ch = sc_get(&s);
            if (ch != (int)c) { sc_unget(&s, ch); break; }
            ++k;
            continue;
        }
        ++k;
        if (fch(fmt, wide, k) == '%') {
            ++k;
            do ch = sc_get(&s); while (ch >= 0 && is_ws(ch));
            if (ch != '%') { sc_unget(&s, ch); break; }
            continue;
        }
        if (fch(fmt, wide, k) == '*') { suppress = 1; ++k; }
        if (fch(fmt, wide, k) >= '0' && fch(fmt, wide, k) <= '9') {
            width = 0;
            while (fch(fmt, wide, k) >= '0' && fch(fmt, wide, k) <= '9') width = width * 10 + (int)(fch(fmt, wide, k++) - '0');
            if (width == 0) width = -1;
        }
        switch (fch(fmt, wide, k)) {
        case 'h': ++k; if (fch(fmt, wide, k) == 'h') { ++k; size = SZ_HH; } else size = SZ_H; hflag = 1; break;
        case 'l': ++k; if (fch(fmt, wide, k) == 'l') { ++k; size = SZ_LL; } else size = SZ_L; lflag = 1; break;
        case 'L': ++k; size = SZ_LD; break;
        case 'j': case 'z': case 't': ++k; size = SZ_PTR; break;
        case 'w': ++k; lflag = 1; size = SZ_L; break;
        case 'I':
            ++k;
            if (fch(fmt, wide, k) == '6' && fch(fmt, wide, k + 1) == '4') { k += 2; size = SZ_LL; }
            else if (fch(fmt, wide, k) == '3' && fch(fmt, wide, k + 1) == '2') { k += 2; size = SZ_L; }
            else size = SZ_PTR;
            break;
        default: break;
        }
        conv = fch(fmt, wide, k++);
        if (!conv) { crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return CRT_EOF; }
        if (conv != 'c' && conv != 'C' && conv != '[' && conv != 'n') {
            do ch = sc_get(&s); while (ch >= 0 && is_ws(ch));
            sc_unget(&s, ch);
        }
        if (conv == 'n') {
            if (!suppress) store_int(va_arg(*ap, void *), size, (uint64_t)s.consumed);
            continue;
        }
        switch (conv) {
        case 'd': case 'i': case 'o': case 'u': case 'x': case 'X': case 'p': {
            uint64_t v = 0;
            const int base = conv == 'd' || conv == 'u' ? 10 : conv == 'i' ? 0 : conv == 'o' ? 8 : 16;
            if (s.eof) goto input_failure;
            if (!scan_int(&s, width < 0 ? 0x7fffffff : width, base, &v)) goto matching_failure;
            ++conversions;
            if (!suppress) {
                store_int(va_arg(*ap, void *), conv == 'p' ? SZ_PTR : size, v);
                ++assigned;
            }
            break;
        }
        case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'a': case 'A': {
            char text[512];
            size_t used;
            int range;
            double v;
            if (s.eof) goto input_failure;
            if (!scan_float_text(&s, width < 0 ? 0x7fffffff : width, text, sizeof text)) goto matching_failure;
            v = crt_strtod_core(text, crt_get_narrow, &used, &range, size != SZ_L && size != SZ_LL && size != SZ_LD);
            if (!used) goto matching_failure;
            ++conversions;
            if (!suppress) {
                if (size == SZ_L || size == SZ_LL || size == SZ_LD) *va_arg(*ap, double *) = v;
                else *va_arg(*ap, float *) = (float)v;
                ++assigned;
            }
            break;
        }
        case 'c': case 'C': case 's': case 'S': case '[': {
            scanset set;
            int to_wide, n = 0;
            const int upper = conv == 'C' || conv == 'S';
            unsigned cap = 0xffffffffu;
            if (conv == '[') {
                const size_t nk = parse_set(fmt, wide, k, &set);
                if (!nk) { crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return CRT_EOF; }
                k = nk;
            }
            if (hflag) to_wide = 0;
            else if (lflag) to_wide = 1;
            else if (!wide) to_wide = upper;
            else if (options & SCANF_LEGACY_WIDE_SPECIFIERS) to_wide = !upper;
            else to_wide = upper;
            if (!suppress) {
                dest = va_arg(*ap, void *);
                if (secure) cap = va_arg(*ap, unsigned);
            }
            if (width < 0) width = (conv == 'c' || conv == 'C') ? 1 : 0x7fffffff;
            ch = sc_get(&s);
            if (ch < 0) goto input_failure;
            for (;;) {
                if (conv == 's' || conv == 'S') { if (is_ws(ch)) break; }
                else if (conv == '[') { if (!in_set(&set, ch)) break; }
                if (!suppress) {
                    if ((unsigned)n >= cap) {
                        if (to_wide) ((wchar16 *)dest)[0] = 0; else ((char *)dest)[0] = 0;
                        crt_set_errno(CRT_ENOMEM);
                        return assigned;
                    }
                    if (to_wide) ((wchar16 *)dest)[n] = (wchar16)ch;
                    else {
                        char b;
                        if (crt_wctomb_c(&b, (unsigned)ch) < 0) { crt_set_errno(CRT_EILSEQ); return assigned; }
                        ((char *)dest)[n] = b;
                    }
                }
                ++n;
                if (n >= width) { ch = -2; break; }
                ch = sc_get(&s);
                if (ch < 0) break;
            }
            if (ch >= 0) sc_unget(&s, ch);
            if (!n) goto matching_failure;
            if (conv != 'c' && conv != 'C' && !suppress) {
                if ((unsigned)n >= cap) {
                    if (to_wide) ((wchar16 *)dest)[0] = 0; else ((char *)dest)[0] = 0;
                    crt_set_errno(CRT_ENOMEM);
                    return assigned;
                }
                if (to_wide) ((wchar16 *)dest)[n] = 0; else ((char *)dest)[n] = 0;
            }
            ++conversions;
            if (!suppress) ++assigned;
            break;
        }
        default:
            crt_set_errno(CRT_EINVAL);
            crt_invalid_parameter();
            return CRT_EOF;
        }
        continue;
    input_failure:
        return conversions || assigned ? assigned : CRT_EOF;
    matching_failure:
        break;
    }
    return assigned;
}

/* ---------------------------------------------------------------- string sources */
typedef struct { crt_in in; const void *str; size_t pos, lim; int wide; } str_in;
static int str_get(crt_in *in)
{
    str_in *s = (str_in *)in;
    unsigned c;
    if (s->pos >= s->lim) return -1;
    c = s->wide ? ((const wchar16 *)s->str)[s->pos] : ((const unsigned char *)s->str)[s->pos];
    if (!c) return -1;
    ++s->pos;
    return (int)c;
}
static void str_unget(crt_in *in, int c)
{
    str_in *s = (str_in *)in;
    (void)c;
    if (s->pos) --s->pos;
}
static int sscanf_common(uint64_t opt, const void *buf, size_t count, const void *fmt, int wide, va_list ap)
{
    str_in s;
    va_list aq;
    int r;
    CRT_VALIDATE(buf != 0 && fmt != 0, CRT_EINVAL, CRT_EOF);
    crt_memset(&s, 0, sizeof s);
    s.in.get = str_get;
    s.in.unget = str_unget;
    s.str = buf;
    s.lim = count;
    s.wide = wide;
    va_copy(aq, ap);
    r = crt_scan(&s.in, opt, fmt, wide, &aq);
    va_end(aq);
    return r;
}
DLLAPI int CRTAPI __stdio_common_vsscanf(uint64_t opt, const char *buf, size_t count, const char *fmt, void *loc, va_list ap)
{
    (void)loc;
    return sscanf_common(opt, buf, count, fmt, 0, ap);
}
DLLAPI int CRTAPI __stdio_common_vswscanf(uint64_t opt, const wchar16 *buf, size_t count, const wchar16 *fmt, void *loc, va_list ap)
{
    (void)loc;
    return sscanf_common(opt, buf, count, fmt, 1, ap);
}
