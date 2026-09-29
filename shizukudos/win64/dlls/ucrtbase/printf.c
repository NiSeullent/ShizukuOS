/* SPDX-License-Identifier: GPL-2.0-only
 * printf engine of the Shizuku UCRT and the string-output entry points (__stdio_common_vs[n]printf[_s|_p], narrow and
 * wide). Semantics follow Microsoft's documentation of the Universal CRT format specification:
 *   size prefixes h hh l ll L j z t I I32 I64 w;  %Z (ANSI_STRING / UNICODE_STRING);  %C %S (opposite width);
 *   %p = 16 upper-case hex digits;  %a without precision prints all 13 hex digits;  NaN spelled nan / -nan(ind) /
 *   nan(snan);  %n only after _set_printf_count_output(1);  an unknown conversion is an invalid parameter (-1);
 *   the legacy option bits (vsprintf NUL termination, wide specifiers, three-digit exponents) and the
 *   _CRT_INTERNAL_PRINTF_STANDARD_ROUNDING bit (IEEE rounding of exact ties; without it ties round away from zero,
 *   the pre-Windows 10 2004 behaviour).
 * Floating-point digits are exact (fltfmt.c). Only the "C" locale exists: decimal point '.', no grouping.
 */
#include "crtint.h"

static int g_printf_count_output;

DLLAPI int CRTAPI _set_printf_count_output(int enable)
{
    int old = g_printf_count_output;
    g_printf_count_output = enable != 0;
    return old;
}
DLLAPI int CRTAPI _get_printf_count_output(void) { return g_printf_count_output; }

unsigned crt_get_narrow(const void *s, size_t i) { return ((const unsigned char *)s)[i]; }
unsigned crt_get_wide(const void *s, size_t i) { return ((const wchar16 *)s)[i]; }


/* ---------------------------------------------------------------- output helpers */
static void emit_units(crt_out *o, const void *u, size_t n)
{
    if (!n) return;
    if (!o->stopped && o->put(o, u, n) < 0) o->stopped = 1;
    o->count += n;
}
static void emit_ascii(crt_out *o, const char *s, size_t n)
{
    if (!o->wide) { emit_units(o, s, n); return; }
    while (n) {
        wchar16 tmp[64];
        size_t k = n < 64 ? n : 64, i;
        for (i = 0; i < k; ++i) tmp[i] = (unsigned char)s[i];
        emit_units(o, tmp, k);
        s += k;
        n -= k;
    }
}
static void emit_pad(crt_out *o, char c, int n)
{
    char tmp[64];
    int i;
    for (i = 0; i < 64; ++i) tmp[i] = c;
    while (n > 0) {
        int k = n < 64 ? n : 64;
        emit_ascii(o, tmp, (size_t)k);
        n -= k;
    }
}

/* ---------------------------------------------------------------- arguments */
enum { SZ_DEFAULT, SZ_CHAR, SZ_SHORT, SZ_LONG, SZ_LL, SZ_PTR, SZ_LDBL };
enum { AT_NONE, AT_INT, AT_I64, AT_DBL, AT_PTR };
typedef union { int64_t i; double d; void *p; } argval;
#define MAX_POS_ARGS 100

typedef struct {
    va_list *ap;
    argval *pos;             /* non-null in positional mode */
    int next;
} argsrc;

static int size_is_64(int size) { return size == SZ_LL || size == SZ_PTR; }

static int64_t arg_int(argsrc *a, int idx, int size)
{
    if (a->pos) return a->pos[idx].i;
    return size_is_64(size) ? (int64_t)va_arg(*a->ap, long long) : (int64_t)va_arg(*a->ap, int);
}
static double arg_dbl(argsrc *a, int idx)
{
    if (a->pos) return a->pos[idx].d;
    return va_arg(*a->ap, double);
}
static void *arg_ptr(argsrc *a, int idx)
{
    if (a->pos) return a->pos[idx].p;
    return va_arg(*a->ap, void *);
}

/* ---------------------------------------------------------------- conversion spec parser */
typedef struct {
    int left, plus, space, alt, zero;
    int width, prec;              /* prec < 0: not given */
    int size;
    int hflag, lflag;             /* explicit narrow / wide markers for c s Z */
    unsigned conv;
    int argidx, widx, pidx;       /* positional indices (0-based), -1 when sequential */
} spec_t;

static unsigned fch(const void *f, int wide, size_t i) { return wide ? ((const wchar16 *)f)[i] : ((const unsigned char *)f)[i]; }

/* Parses the spec starting after '%'. Returns the index after the conversion character or 0 on a malformed spec. */
static size_t parse_spec(const void *f, int wide, size_t i, spec_t *s, int positional)
{
    unsigned c;
    s->left = s->plus = s->space = s->alt = s->zero = 0;
    s->width = 0;
    s->prec = -1;
    s->size = SZ_DEFAULT;
    s->hflag = s->lflag = 0;
    s->argidx = s->widx = s->pidx = -1;
    if (positional) {
        int n = 0;
        size_t j = i;
        while ((c = fch(f, wide, j)) >= '0' && c <= '9') { n = n * 10 + (int)(c - '0'); ++j; if (n > MAX_POS_ARGS) return 0; }
        if (j == i || fch(f, wide, j) != '$' || n < 1) return 0;
        s->argidx = n - 1;
        i = j + 1;
    }
    for (;; ++i) {
        c = fch(f, wide, i);
        if (c == '-') s->left = 1;
        else if (c == '+') s->plus = 1;
        else if (c == ' ') s->space = 1;
        else if (c == '#') s->alt = 1;
        else if (c == '0') s->zero = 1;
        else break;
    }
    if (c == '*') {
        ++i;
        s->width = -2;                                  /* from argument */
        if (positional) {
            int n = 0;
            size_t j = i;
            while ((c = fch(f, wide, j)) >= '0' && c <= '9') { n = n * 10 + (int)(c - '0'); ++j; if (n > MAX_POS_ARGS) return 0; }
            if (j == i || fch(f, wide, j) != '$' || n < 1) return 0;
            s->widx = n - 1;
            i = j + 1;
        }
    } else {
        while ((c = fch(f, wide, i)) >= '0' && c <= '9') {
            if (s->width > 100000000) return 0;
            s->width = s->width * 10 + (int)(c - '0');
            ++i;
        }
    }
    if (fch(f, wide, i) == '.') {
        ++i;
        if (fch(f, wide, i) == '*') {
            ++i;
            s->prec = -2;
            if (positional) {
                int n = 0;
                size_t j = i;
                while ((c = fch(f, wide, j)) >= '0' && c <= '9') { n = n * 10 + (int)(c - '0'); ++j; if (n > MAX_POS_ARGS) return 0; }
                if (j == i || fch(f, wide, j) != '$' || n < 1) return 0;
                s->pidx = n - 1;
                i = j + 1;
            }
        } else {
            s->prec = 0;
            while ((c = fch(f, wide, i)) >= '0' && c <= '9') {
                if (s->prec > 100000000) return 0;
                s->prec = s->prec * 10 + (int)(c - '0');
                ++i;
            }
        }
    }
    c = fch(f, wide, i);
    switch (c) {
    case 'h':
        ++i;
        if (fch(f, wide, i) == 'h') { ++i; s->size = SZ_CHAR; } else s->size = SZ_SHORT;
        s->hflag = 1;
        break;
    case 'l':
        ++i;
        if (fch(f, wide, i) == 'l') { ++i; s->size = SZ_LL; } else s->size = SZ_LONG;
        s->lflag = 1;
        break;
    case 'L': ++i; s->size = SZ_LDBL; break;
    case 'j': case 'z': case 't': ++i; s->size = SZ_PTR; break;
    case 'w': ++i; s->lflag = 1; s->size = SZ_LONG; break;
    case 'I':
        ++i;
        if (fch(f, wide, i) == '6' && fch(f, wide, i + 1) == '4') { i += 2; s->size = SZ_LL; }
        else if (fch(f, wide, i) == '3' && fch(f, wide, i + 1) == '2') { i += 2; s->size = SZ_LONG; }
        else s->size = SZ_PTR;
        break;
    default: break;
    }
    s->conv = fch(f, wide, i);
    if (!s->conv) return 0;
    return i + 1;
}

/* does this c/s/Z conversion take a wide argument? */
static int wide_arg(const spec_t *s, int wide_fn, uint64_t options)
{
    const int upper = s->conv == 'C' || s->conv == 'S';
    if (s->conv == 'Z') return s->lflag;
    if (s->hflag) return 0;
    if (s->lflag) return 1;
    if (!wide_fn) return upper;
    if (options & PRINTF_LEGACY_WIDE_SPECIFIERS) return !upper;
    return upper;
}

/* ---------------------------------------------------------------- integer and string conversions */
static void emit_padded(crt_out *o, const spec_t *s, const char *prefix, int plen, int zeros, const char *body, int blen)
{
    const int total = plen + zeros + blen;
    if (!s->left && s->width > total) emit_pad(o, ' ', s->width - total);
    emit_ascii(o, prefix, (size_t)plen);
    emit_pad(o, '0', zeros);
    emit_ascii(o, body, (size_t)blen);
    if (s->left && s->width > total) emit_pad(o, ' ', s->width - total);
}

static void fmt_integer(crt_out *o, const spec_t *s, uint64_t mag, int neg, unsigned base, int upper, int is_signed)
{
    char body[72], prefix[4];
    int blen = 0, plen = 0, zeros = 0, i;
    const char *dig = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char tmp[72];
    int n = 0;
    while (mag) { tmp[n++] = dig[mag % base]; mag /= base; }
    for (i = 0; i < n; ++i) body[i] = tmp[n - 1 - i];
    blen = n;
    if (is_signed) {
        if (neg) prefix[plen++] = '-';
        else if (s->plus) prefix[plen++] = '+';
        else if (s->space) prefix[plen++] = ' ';
    }
    if (s->alt && base == 16 && blen) { prefix[plen++] = '0'; prefix[plen++] = upper ? 'X' : 'x'; }
    {
        const int prec = s->prec < 0 ? 1 : s->prec;
        if (blen < prec) zeros = prec - blen;
        if (s->alt && base == 8 && zeros == 0 && (blen == 0 || body[0] != '0')) zeros = 1;
        if (s->prec < 0 && s->zero && !s->left && s->width > plen + zeros + blen) zeros = s->width - plen - blen;
    }
    emit_padded(o, s, prefix, plen, zeros, body, blen);
}

/* A string argument of either width into the sink. `n` is -1 for NUL-terminated. Returns -1 on a conversion error. */
static int fmt_string(crt_out *o, const spec_t *s, const void *str, int str_wide, int64_t n)
{
    size_t len = 0, i;
    int pad;
    if (n < 0) {
        if (str_wide) while (((const wchar16 *)str)[len] && (s->prec < 0 || len < (size_t)s->prec)) ++len;
        else while (((const char *)str)[len] && (s->prec < 0 || len < (size_t)s->prec)) ++len;
    } else {
        len = (size_t)n;
        if (s->prec >= 0 && len > (size_t)s->prec) len = (size_t)s->prec;
    }
    if (!o->wide && str_wide)                            /* validate the wide -> narrow conversion first */
        for (i = 0; i < len; ++i)
            if (((const wchar16 *)str)[i] > 0xff) { crt_set_errno(CRT_EILSEQ); return -1; }
    pad = s->width > (int)len ? s->width - (int)len : 0;
    if (!s->left) emit_pad(o, s->zero ? '0' : ' ', pad);
    if (o->wide == str_wide) emit_units(o, str, len);
    else if (o->wide) {
        for (i = 0; i < len;) {
            wchar16 tmp[64];
            size_t k = 0;
            while (k < 64 && i < len) tmp[k++] = ((const unsigned char *)str)[i++];
            emit_units(o, tmp, k);
        }
    } else {
        for (i = 0; i < len;) {
            char tmp[64];
            size_t k = 0;
            while (k < 64 && i < len) tmp[k++] = (char)((const wchar16 *)str)[i++];
            emit_units(o, tmp, k);
        }
    }
    if (s->left) emit_pad(o, ' ', pad);
    return 0;
}

/* ---------------------------------------------------------------- floating point */
static void fmt_special(crt_out *o, const spec_t *s, uint64_t bits, int upper)
{
    char buf[16];
    int n = 0;
    const int neg = (int)(bits >> 63);
    const uint64_t frac = bits & 0xfffffffffffffull;
    const char *word;
    if (neg) buf[n++] = '-';
    else if (s->plus) buf[n++] = '+';
    else if (s->space) buf[n++] = ' ';
    if (!frac) word = upper ? "INF" : "inf";
    else if (!(frac >> 51)) word = upper ? "NAN(SNAN)" : "nan(snan)";
    else if (neg && frac == (1ull << 51)) word = upper ? "NAN(IND)" : "nan(ind)";
    else word = upper ? "NAN" : "nan";
    while (*word) buf[n++] = *word++;
    {
        spec_t t = *s;
        t.zero = 0;
        emit_padded(o, &t, "", 0, 0, buf, n);
    }
}

static int put_exp(char *p, int x, int min_digits)
{
    char tmp[8];
    int n = 0, k = 0, i;
    p[k++] = x < 0 ? '-' : '+';
    if (x < 0) x = -x;
    do { tmp[n++] = (char)('0' + x % 10); x /= 10; } while (x);
    while (n < min_digits) tmp[n++] = '0';
    for (i = n - 1; i >= 0; --i) p[k++] = tmp[i];
    return k;
}

/* Emits sign/prefix + body with width and '0' padding (numbers only). */
static void emit_number(crt_out *o, const spec_t *s, const char *sign, int slen, const char *body, int blen)
{
    int zeros = 0;
    if (s->zero && !s->left && s->width > slen + blen) zeros = s->width - slen - blen;
    emit_padded(o, s, sign, slen, zeros, body, blen);
}

static int fmt_float(crt_out *o, const spec_t *s, double v, uint64_t options)
{
    const uint64_t bits = crt_d2u(v);
    const unsigned conv = s->conv;
    const int upper = conv == 'E' || conv == 'F' || conv == 'G' || conv == 'A';
    const int neg = (int)(bits >> 63);
    char sign[2];
    int slen = 0;
    char local[512];
    char *buf = local, *body;
    size_t cap;
    int prec = s->prec, n, x, blen = 0, i;
    int rnd = (options & PRINTF_STANDARD_ROUNDING) ? crt_current_rounding() : CRT_RND_HALF_AWAY;
    const int expdig = (options & PRINTF_LEGACY_THREE_DIGIT_EXPONENTS) ? 3 : 2;

    if (((bits >> 52) & 0x7ff) == 0x7ff) { fmt_special(o, s, bits, upper); return 0; }
    if (neg) sign[slen++] = '-';
    else if (s->plus) sign[slen++] = '+';
    else if (s->space) sign[slen++] = ' ';

    if (conv == 'a' || conv == 'A') {
        const char *hex = upper ? "0123456789ABCDEF" : "0123456789abcdef";
        const int ef = (int)((bits >> 52) & 0x7ff);
        uint64_t mant = bits & 0xfffffffffffffull;
        int lead = ef ? 1 : 0, e2 = ef ? ef - 1023 : (mant ? -1022 : 0), p = prec < 0 ? 13 : prec, digits = p < 13 ? p : 13;
        char out[64 + 16];
        if (p < 13) {                                   /* round the 52-bit mantissa to 4*p bits */
            const int drop = 4 * (13 - p);
            const uint64_t rest = mant & ((1ull << drop) - 1), half = 1ull << (drop - 1);
            uint64_t kept = mant >> drop;
            int up;
            switch (rnd) {
            case CRT_RND_ZERO: up = 0; break;
            case CRT_RND_UP: up = !neg && rest; break;
            case CRT_RND_DOWN: up = neg && rest; break;
            case CRT_RND_HALF_AWAY: up = rest >= half; break;
            default: up = rest > half || (rest == half && ((p ? kept : (uint64_t)lead) & 1)); break;
            }
            if (up) {
                ++kept;
                if (kept >> (4 * p)) { kept &= (1ull << (4 * p)) - 1; ++lead; }
            }
            mant = kept << drop;
        }
        n = 0;
        out[n++] = '0';
        out[n++] = upper ? 'X' : 'x';
        out[n++] = (char)('0' + lead);
        if (p > 0 || s->alt) out[n++] = '.';
        for (i = 0; i < digits; ++i) out[n++] = hex[(mant >> (48 - 4 * i)) & 15];
        body = out;
        blen = n;
        {
            /* precision beyond 13 digits: trailing zeros, emitted separately to avoid a large buffer */
            char tail[8];
            int tl = 0, extra = p > 13 ? p - 13 : 0;
            tail[tl++] = upper ? 'P' : 'p';
            tl += put_exp(tail + tl, e2, 1);
            if (!s->left && !s->zero && s->width > slen + blen + extra + tl) emit_pad(o, ' ', s->width - slen - blen - extra - tl);
            emit_ascii(o, sign, (size_t)slen);
            emit_ascii(o, body, 2);
            if (!s->left && s->zero && s->width > slen + blen + extra + tl) emit_pad(o, '0', s->width - slen - blen - extra - tl);
            emit_ascii(o, body + 2, (size_t)blen - 2);
            emit_pad(o, '0', extra);
            emit_ascii(o, tail, (size_t)tl);
            if (s->left && s->width > slen + blen + extra + tl) emit_pad(o, ' ', s->width - slen - blen - extra - tl);
        }
        return 0;
    }

    if (prec < 0) prec = 6;
    if ((conv == 'g' || conv == 'G') && prec == 0) prec = 1;
    cap = (size_t)prec + 400;
    if (cap > sizeof local) {
        buf = crt_malloc(cap * 2 + 16);
        if (!buf) { crt_set_errno(CRT_ENOMEM); return -1; }
    }
    body = buf + cap;
    if (conv == 'f' || conv == 'F') {
        n = crt_dtoa_fixed(v, prec, 'f', rnd, neg, buf, &x);
        for (i = 0; i < x; ++i) body[blen++] = buf[i];
        if (prec > 0 || s->alt) body[blen++] = '.';
        for (i = x; i < n; ++i) body[blen++] = buf[i];
    } else if (conv == 'e' || conv == 'E') {
        n = crt_dtoa_fixed(v, prec, 'e', rnd, neg, buf, &x);
        body[blen++] = buf[0];
        if (prec > 0 || s->alt) body[blen++] = '.';
        for (i = 1; i < n; ++i) body[blen++] = buf[i];
        body[blen++] = upper ? 'E' : 'e';
        blen += put_exp(body + blen, x, expdig);
    } else {                                            /* g G */
        const int P = prec;
        n = crt_dtoa_fixed(v, P - 1, 'e', rnd, neg, buf, &x);
        if (!s->alt)                                     /* strip trailing zeros of the significant digits */
            while (n > 1 && buf[n - 1] == '0') --n;
        if (x < P && x >= -4) {                         /* f style with P-1-x fraction digits */
            if (x >= 0) {
                for (i = 0; i <= x; ++i) body[blen++] = i < n ? buf[i] : '0';
                if (n > x + 1 || s->alt) body[blen++] = '.';
                for (i = x + 1; i < n; ++i) body[blen++] = buf[i];
                if (s->alt) for (i = n > x + 1 ? n : x + 1; i < P; ++i) body[blen++] = '0';
            } else {
                body[blen++] = '0';
                body[blen++] = '.';
                for (i = 0; i < -x - 1; ++i) body[blen++] = '0';
                for (i = 0; i < n; ++i) body[blen++] = buf[i];
                if (s->alt) for (i = n; i < P; ++i) body[blen++] = '0';
            }
        } else {
            body[blen++] = buf[0];
            if (n > 1 || s->alt) body[blen++] = '.';
            for (i = 1; i < n; ++i) body[blen++] = buf[i];
            if (s->alt) for (i = n; i < P; ++i) body[blen++] = '0';
            body[blen++] = conv == 'G' ? 'E' : 'e';
            blen += put_exp(body + blen, x, expdig);
        }
    }
    emit_number(o, s, sign, slen, body, blen);
    if (buf != local) crt_free(buf);
    return 0;
}

/* ---------------------------------------------------------------- positional pre-pass */
static int arg_type_of(const spec_t *s)
{
    switch (s->conv) {
    case 'd': case 'i': case 'o': case 'u': case 'x': case 'X': return size_is_64(s->size) ? AT_I64 : AT_INT;
    case 'c': case 'C': return AT_INT;
    case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'a': case 'A': return AT_DBL;
    case 's': case 'S': case 'Z': case 'p': case 'n': return AT_PTR;
    default: return AT_NONE;
    }
}

static int collect_positional(const void *f, int wide, va_list *ap, argval *vals)
{
    unsigned char types[MAX_POS_ARGS];
    int count = 0, i;
    size_t k = 0;
    unsigned c;
    for (i = 0; i < MAX_POS_ARGS; ++i) types[i] = AT_NONE;
    while ((c = fch(f, wide, k)) != 0) {
        spec_t s;
        size_t nk;
        int t;
        ++k;
        if (c != '%') continue;
        if (fch(f, wide, k) == '%') { ++k; continue; }
        nk = parse_spec(f, wide, k, &s, 1);
        if (!nk) return -1;
        k = nk;
        t = arg_type_of(&s);
        if (t == AT_NONE) return -1;
        if (types[s.argidx] != AT_NONE && types[s.argidx] != t) return -1;
        types[s.argidx] = (unsigned char)t;
        if (s.argidx + 1 > count) count = s.argidx + 1;
        if (s.widx >= 0) { if (types[s.widx] != AT_NONE && types[s.widx] != AT_INT) return -1; types[s.widx] = AT_INT; if (s.widx + 1 > count) count = s.widx + 1; }
        if (s.pidx >= 0) { if (types[s.pidx] != AT_NONE && types[s.pidx] != AT_INT) return -1; types[s.pidx] = AT_INT; if (s.pidx + 1 > count) count = s.pidx + 1; }
    }
    for (i = 0; i < count; ++i) {
        switch (types[i]) {
        case AT_INT: vals[i].i = va_arg(*ap, int); break;
        case AT_I64: vals[i].i = va_arg(*ap, long long); break;
        case AT_DBL: vals[i].d = va_arg(*ap, double); break;
        case AT_PTR: vals[i].p = va_arg(*ap, void *); break;
        default: return -1;                              /* a gap in the positional arguments */
        }
    }
    return count;
}

static int has_positional(const void *f, int wide)
{
    size_t k = 0;
    unsigned c;
    while ((c = fch(f, wide, k)) != 0) {
        ++k;
        if (c == '%') {
            size_t j = k;
            if (fch(f, wide, j) == '%') { ++k; continue; }
            while ((c = fch(f, wide, j)) >= '0' && c <= '9') ++j;
            return j > k && fch(f, wide, j) == '$';
        }
    }
    return 0;
}

/* ---------------------------------------------------------------- engine */
static int format_error(void)
{
    crt_set_errno(CRT_EINVAL);
    crt_invalid_parameter();
    return -1;
}

static int crt_format_impl(crt_out *o, uint64_t options, const void *f, int wide, va_list *ap, int allow_positional)
{
    argval vals[MAX_POS_ARGS];
    argsrc a;
    size_t k = 0, lit;
    unsigned c;
    int positional = 0;
    a.ap = ap;
    a.pos = 0;
    a.next = 0;
    if (!f) return format_error();
    if (allow_positional && has_positional(f, wide)) {
        if (collect_positional(f, wide, ap, vals) < 0) return format_error();
        a.pos = vals;
        positional = 1;
    }
    for (;;) {
        spec_t s;
        size_t nk;
        lit = k;
        while ((c = fch(f, wide, k)) != 0 && c != '%') ++k;
        if (k > lit) emit_units(o, wide ? (const void *)((const wchar16 *)f + lit) : (const void *)((const char *)f + lit), k - lit);
        if (!c) break;
        ++k;
        if (fch(f, wide, k) == '%') { emit_ascii(o, "%", 1); ++k; continue; }
        nk = parse_spec(f, wide, k, &s, positional);
        if (!nk) return format_error();
        k = nk;
        if (s.width == -2) {
            int w = (int)arg_int(&a, s.widx, SZ_DEFAULT);
            if (w < 0) { s.left = 1; w = -w; }
            s.width = w;
        }
        if (s.prec == -2) {
            int p = (int)arg_int(&a, s.pidx, SZ_DEFAULT);
            s.prec = p < 0 ? -1 : p;
        }
        switch (s.conv) {
        case 'd': case 'i': {
            int64_t v = arg_int(&a, s.argidx, s.size);
            if (s.size == SZ_CHAR) v = (signed char)v;
            else if (s.size == SZ_SHORT) v = (short)v;
            else if (!size_is_64(s.size)) v = (int32_t)v;
            fmt_integer(o, &s, v < 0 ? (uint64_t)0 - (uint64_t)v : (uint64_t)v, v < 0, 10, 0, 1);
            break;
        }
        case 'u': case 'o': case 'x': case 'X': {
            uint64_t v = (uint64_t)arg_int(&a, s.argidx, s.size);
            if (s.size == SZ_CHAR) v = (unsigned char)v;
            else if (s.size == SZ_SHORT) v = (unsigned short)v;
            else if (!size_is_64(s.size)) v = (uint32_t)v;
            fmt_integer(o, &s, v, 0, s.conv == 'u' ? 10 : s.conv == 'o' ? 8 : 16, s.conv == 'X', 0);
            break;
        }
        case 'p': {
            spec_t t = s;
            t.prec = 16;
            t.size = SZ_PTR;
            fmt_integer(o, &t, (uint64_t)(uintptr_t)arg_ptr(&a, s.argidx), 0, 16, 1, 0);
            break;
        }
        case 'c': case 'C': {
            const int v = (int)arg_int(&a, s.argidx, SZ_DEFAULT);
            if (wide_arg(&s, wide, options)) {
                wchar16 ch = (wchar16)v;
                spec_t t = s;
                t.prec = -1;
                if (fmt_string(o, &t, &ch, 1, 1) < 0) return -1;
            } else {
                char ch = (char)v;
                spec_t t = s;
                t.prec = -1;
                if (fmt_string(o, &t, &ch, 0, 1) < 0) return -1;
            }
            break;
        }
        case 's': case 'S': {
            const void *p = arg_ptr(&a, s.argidx);
            const int w = wide_arg(&s, wide, options);
            static const wchar16 wnull[] = { '(', 'n', 'u', 'l', 'l', ')', 0 };
            if (!p) p = w ? (const void *)wnull : (const void *)"(null)";
            if (fmt_string(o, &s, p, w, -1) < 0) return -1;
            break;
        }
        case 'Z': {
            const struct { unsigned short len, max; uint32_t pad; const void *buf; } *us = arg_ptr(&a, s.argidx);
            const int w = wide_arg(&s, wide, options);
            if (!us || !us->buf) {
                if (fmt_string(o, &s, "(null)", 0, -1) < 0) return -1;
            } else if (fmt_string(o, &s, us->buf, w, w ? us->len / 2 : us->len) < 0) return -1;
            break;
        }
        case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'a': case 'A':
            if (fmt_float(o, &s, arg_dbl(&a, s.argidx), options) < 0) return -1;
            break;
        case 'n': {
            void *p = arg_ptr(&a, s.argidx);
            if (!g_printf_count_output) return format_error();
            switch (s.size) {
            case SZ_CHAR: *(signed char *)p = (signed char)o->count; break;
            case SZ_SHORT: *(short *)p = (short)o->count; break;
            case SZ_LL: case SZ_PTR: *(int64_t *)p = (int64_t)o->count; break;
            default: *(int *)p = (int)o->count; break;
            }
            break;
        }
        default:
            return format_error();
        }
    }
    if (o->stopped) return -1;
    return o->count > 0x7fffffff ? -1 : (int)o->count;
}

int crt_format(crt_out *o, uint64_t options, const void *format, int wide_format, va_list *ap)
{
    return crt_format_impl(o, options, format, wide_format, ap, 0);
}
int crt_format_p(crt_out *o, uint64_t options, const void *format, int wide_format, va_list *ap)
{
    return crt_format_impl(o, options, format, wide_format, ap, 1);
}

/* ---------------------------------------------------------------- string sinks */
typedef struct { void *buf; size_t cap, used; } strsink;

static int str_put(crt_out *o, const void *u, size_t n)
{
    strsink *s = o->ctx;
    const size_t unit = o->wide ? 2 : 1;
    size_t room = s->cap > s->used ? s->cap - s->used : 0, k = n < room ? n : room;
    if (k && s->buf) crt_memcpy((char *)s->buf + s->used * unit, u, k * unit);
    s->used += k;
    return 0;
}

static void term_at(void *buf, int wide, size_t i)
{
    if (wide) ((wchar16 *)buf)[i] = 0;
    else ((char *)buf)[i] = 0;
}

/* common_vsprintf semantics: see the header comment; returns the length, -1 (error / legacy overflow) or -2 (buffer
 * too small for the non-legacy, non-C99 callers). */
static int common_vsprintf(uint64_t options, void *buf, size_t cap, const void *fmt, int wide, va_list ap, int positional)
{
    strsink s;
    crt_out o;
    int r;
    va_list aq;
    CRT_VALIDATE(fmt != 0, CRT_EINVAL, -1);
    CRT_VALIDATE(cap == 0 || buf != 0, CRT_EINVAL, -1);
    s.buf = buf;
    s.cap = cap;
    s.used = 0;
    o.wide = wide;
    o.put = str_put;
    o.count = 0;
    o.stopped = 0;
    o.ctx = &s;
    va_copy(aq, ap);
    r = crt_format_impl(&o, options, fmt, wide, &aq, positional);
    va_end(aq);
    if (r < 0) {
        if (buf && cap) term_at(buf, wide, s.used < cap ? s.used : cap - 1);
        return -1;
    }
    if (options & PRINTF_STANDARD_SNPRINTF_BEHAVIOR) {
        if (buf && cap) term_at(buf, wide, (size_t)r < cap ? (size_t)r : cap - 1);
        return r;
    }
    if (!buf) return r;
    if ((size_t)r < cap) { term_at(buf, wide, (size_t)r); return r; }
    if (options & PRINTF_LEGACY_VSPRINTF_NULL_TERMINATION) return (size_t)r == cap ? r : -1;
    term_at(buf, wide, cap - 1);
    return -2;
}

static int common_vsprintf_s(uint64_t options, void *buf, size_t cap, const void *fmt, int wide, va_list ap, int positional)
{
    int r;
    CRT_VALIDATE(fmt != 0, CRT_EINVAL, -1);
    CRT_VALIDATE(buf != 0 && cap > 0, CRT_EINVAL, -1);
    r = common_vsprintf(options & ~(PRINTF_LEGACY_VSPRINTF_NULL_TERMINATION | PRINTF_STANDARD_SNPRINTF_BEHAVIOR), buf, cap, fmt, wide, ap,
                        positional);
    if (r < 0) term_at(buf, wide, 0);
    if (r == -2) { crt_set_errno(CRT_ERANGE); crt_invalid_parameter(); return -1; }
    return r < 0 ? -1 : r;
}

static int common_vsnprintf_s(uint64_t options, void *buf, size_t cap, size_t maxcount, const void *fmt, int wide, va_list ap)
{
    int r, saved;
    const uint64_t opt = options & ~(PRINTF_LEGACY_VSPRINTF_NULL_TERMINATION | PRINTF_STANDARD_SNPRINTF_BEHAVIOR);
    CRT_VALIDATE(fmt != 0, CRT_EINVAL, -1);
    if (maxcount == 0 && !buf && cap == 0) return 0;
    CRT_VALIDATE(buf != 0 && cap > 0, CRT_EINVAL, -1);
    saved = crt_get_errno();
    if (cap > maxcount) {
        r = common_vsprintf(opt, buf, maxcount + 1, fmt, wide, ap, 0);
        if (r == -2) { crt_set_errno(saved); return -1; }
    } else {
        r = common_vsprintf(opt, buf, cap, fmt, wide, ap, 0);
        term_at(buf, wide, cap - 1);
        if (r == -2 && maxcount == (size_t)-1) { crt_set_errno(saved); return -1; }
    }
    if (r < 0) {
        term_at(buf, wide, 0);
        if (r == -2) { crt_set_errno(CRT_ERANGE); crt_invalid_parameter(); }
        return -1;
    }
    return r;
}

DLLAPI int CRTAPI __stdio_common_vsprintf(uint64_t options, char *buf, size_t cap, const char *fmt, void *locale, va_list ap)
{
    (void)locale;
    return common_vsprintf(options, buf, cap, fmt, 0, ap, 0);
}
DLLAPI int CRTAPI __stdio_common_vsprintf_s(uint64_t options, char *buf, size_t cap, const char *fmt, void *locale, va_list ap)
{
    (void)locale;
    return common_vsprintf_s(options, buf, cap, fmt, 0, ap, 0);
}
DLLAPI int CRTAPI __stdio_common_vsnprintf_s(uint64_t options, char *buf, size_t cap, size_t maxcount, const char *fmt, void *locale,
                                             va_list ap)
{
    (void)locale;
    return common_vsnprintf_s(options, buf, cap, maxcount, fmt, 0, ap);
}
DLLAPI int CRTAPI __stdio_common_vsprintf_p(uint64_t options, char *buf, size_t cap, const char *fmt, void *locale, va_list ap)
{
    (void)locale;
    return common_vsprintf_s(options, buf, cap, fmt, 0, ap, 1);
}
DLLAPI int CRTAPI __stdio_common_vswprintf(uint64_t options, wchar16 *buf, size_t cap, const wchar16 *fmt, void *locale, va_list ap)
{
    (void)locale;
    return common_vsprintf(options, buf, cap, fmt, 1, ap, 0);
}
DLLAPI int CRTAPI __stdio_common_vswprintf_s(uint64_t options, wchar16 *buf, size_t cap, const wchar16 *fmt, void *locale, va_list ap)
{
    (void)locale;
    return common_vsprintf_s(options, buf, cap, fmt, 1, ap, 0);
}
DLLAPI int CRTAPI __stdio_common_vsnwprintf_s(uint64_t options, wchar16 *buf, size_t cap, size_t maxcount, const wchar16 *fmt,
                                              void *locale, va_list ap)
{
    (void)locale;
    return common_vsnprintf_s(options, buf, cap, maxcount, fmt, 1, ap);
}
DLLAPI int CRTAPI __stdio_common_vswprintf_p(uint64_t options, wchar16 *buf, size_t cap, const wchar16 *fmt, void *locale, va_list ap)
{
    (void)locale;
    return common_vsprintf_s(options, buf, cap, fmt, 1, ap, 1);
}

/* internal helper for _gcvt and friends: snprintf into a narrow buffer with the standard (C99) behaviour */
int crt_format_to_buffer(char *buf, size_t cap, const char *fmt, ...)
{
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = common_vsprintf(PRINTF_STANDARD_SNPRINTF_BEHAVIOR | PRINTF_STANDARD_ROUNDING, buf, cap, fmt, 0, ap, 0);
    va_end(ap);
    return r;
}
