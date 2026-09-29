/* SPDX-License-Identifier: GPL-2.0-only
 * Number <-> string conversions: strtol & co. (narrow and wide, 32/64-bit), strtod / strtof / wcstod (correctly
 * rounded, fltparse.c), ato*, _itoa & co. with their _s forms, _ecvt / _fcvt / _gcvt, _atodbl / _atoflt.
 * Semantics per the C standard and Microsoft's documentation: leading white space, optional sign, 0x / 0 prefixes for
 * base 16 / 0, overflow saturates and sets ERANGE, an invalid base is an invalid parameter. Only ASCII digits are
 * recognised (the UCRT's wide versions also accept some other Unicode decimal digits; see CRT.md).
 */
#include "crtint.h"

static int digit_val(unsigned c)
{
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c >= 'a' && c <= 'z') return (int)(c - 'a' + 10);
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A' + 10);
    return 99;
}
static int is_space_unit(unsigned c) { return c == ' ' || (c >= 9 && c <= 13); }

uint64_t crt_strtoint_core(const void *s, crt_getch_fn get, size_t *consumed, int base, int is_unsigned, int bits, int *range_err)
{
    size_t i = 0;
    unsigned c;
    int neg = 0, any = 0, over = 0;
    uint64_t v = 0, limit;
    const uint64_t umax = bits == 64 ? ~0ull : 0xffffffffull;
    *range_err = 0;
    *consumed = 0;
    while (is_space_unit(get(s, i))) ++i;
    c = get(s, i);
    if (c == '+' || c == '-') { neg = c == '-'; ++i; }
    if ((base == 0 || base == 16) && get(s, i) == '0' && (get(s, i + 1) == 'x' || get(s, i + 1) == 'X')) {
        if (digit_val(get(s, i + 2)) < 16) { i += 2; base = 16; }
        else { base = base ? base : 8; }                  /* "0x" without hex digits: the "0" is the number */
    } else if (base == 0) base = get(s, i) == '0' ? 8 : 10;
    if (is_unsigned) limit = umax;
    else limit = neg ? (umax >> 1) + 1 : umax >> 1;
    for (;; ++i) {
        const int d = digit_val(get(s, i));
        if (d >= base) break;
        any = 1;
        if (!over) {
            if (v > (limit - (uint64_t)d) / (uint64_t)base) over = 1;
            else v = v * (uint64_t)base + (uint64_t)d;
        }
    }
    if (!any) return 0;
    *consumed = i;
    if (over) {
        *range_err = 1;
        if (is_unsigned) return umax;
        return neg ? ((umax >> 1) + 1) : (umax >> 1);        /* caller sign-extends for 32-bit */
    }
    return neg ? (uint64_t)0 - v : v;
}

static uint64_t int_common(const void *s, crt_getch_fn get, void *endp, int base, int is_unsigned, int bits, size_t unit)
{
    size_t used;
    int range;
    uint64_t v;
    if (endp) *(const void **)endp = s;
    CRT_VALIDATE(s != 0, CRT_EINVAL, 0);
    CRT_VALIDATE(base == 0 || (base >= 2 && base <= 36), CRT_EINVAL, 0);
    v = crt_strtoint_core(s, get, &used, base, is_unsigned, bits, &range);
    if (endp) *(const void **)endp = (const char *)s + used * unit;
    if (range) crt_set_errno(CRT_ERANGE);
    if (!is_unsigned && bits == 32) v = (uint64_t)(int64_t)(int32_t)(uint32_t)v;
    return v;
}

DLLAPI crt_long CRTAPI strtol(const char *s, char **end, int base) { return (crt_long)int_common(s, crt_get_narrow, end, base, 0, 32, 1); }
DLLAPI crt_ulong CRTAPI strtoul(const char *s, char **end, int base) { return (crt_ulong)int_common(s, crt_get_narrow, end, base, 1, 32, 1); }
DLLAPI long long CRTAPI strtoll(const char *s, char **end, int base) { return (long long)int_common(s, crt_get_narrow, end, base, 0, 64, 1); }
DLLAPI unsigned long long CRTAPI strtoull(const char *s, char **end, int base) { return int_common(s, crt_get_narrow, end, base, 1, 64, 1); }
DLLAPI long long CRTAPI _strtoi64(const char *s, char **end, int base) { return strtoll(s, end, base); }
DLLAPI unsigned long long CRTAPI _strtoui64(const char *s, char **end, int base) { return strtoull(s, end, base); }
DLLAPI long long CRTAPI strtoimax(const char *s, char **end, int base) { return strtoll(s, end, base); }
DLLAPI unsigned long long CRTAPI strtoumax(const char *s, char **end, int base) { return strtoull(s, end, base); }
DLLAPI crt_long CRTAPI wcstol(const wchar16 *s, wchar16 **end, int base) { return (crt_long)int_common(s, crt_get_wide, end, base, 0, 32, 2); }
DLLAPI crt_ulong CRTAPI wcstoul(const wchar16 *s, wchar16 **end, int base) { return (crt_ulong)int_common(s, crt_get_wide, end, base, 1, 32, 2); }
DLLAPI long long CRTAPI wcstoll(const wchar16 *s, wchar16 **end, int base) { return (long long)int_common(s, crt_get_wide, end, base, 0, 64, 2); }
DLLAPI unsigned long long CRTAPI wcstoull(const wchar16 *s, wchar16 **end, int base) { return int_common(s, crt_get_wide, end, base, 1, 64, 2); }
DLLAPI long long CRTAPI _wcstoi64(const wchar16 *s, wchar16 **end, int base) { return wcstoll(s, end, base); }
DLLAPI unsigned long long CRTAPI _wcstoui64(const wchar16 *s, wchar16 **end, int base) { return wcstoull(s, end, base); }
DLLAPI long long CRTAPI wcstoimax(const wchar16 *s, wchar16 **end, int base) { return wcstoll(s, end, base); }
DLLAPI unsigned long long CRTAPI wcstoumax(const wchar16 *s, wchar16 **end, int base) { return wcstoull(s, end, base); }
DLLAPI crt_long CRTAPI _strtol_l(const char *s, char **e, int b, void *l) { (void)l; return strtol(s, e, b); }
DLLAPI crt_ulong CRTAPI _strtoul_l(const char *s, char **e, int b, void *l) { (void)l; return strtoul(s, e, b); }
DLLAPI long long CRTAPI _strtoi64_l(const char *s, char **e, int b, void *l) { (void)l; return strtoll(s, e, b); }
DLLAPI unsigned long long CRTAPI _strtoui64_l(const char *s, char **e, int b, void *l) { (void)l; return strtoull(s, e, b); }
DLLAPI crt_long CRTAPI _wcstol_l(const wchar16 *s, wchar16 **e, int b, void *l) { (void)l; return wcstol(s, e, b); }
DLLAPI crt_ulong CRTAPI _wcstoul_l(const wchar16 *s, wchar16 **e, int b, void *l) { (void)l; return wcstoul(s, e, b); }

DLLAPI int CRTAPI atoi(const char *s) { CRT_VALIDATE(s != 0, CRT_EINVAL, 0); return (int)strtol(s, 0, 10); }
DLLAPI crt_long CRTAPI atol(const char *s) { CRT_VALIDATE(s != 0, CRT_EINVAL, 0); return strtol(s, 0, 10); }
DLLAPI long long CRTAPI atoll(const char *s) { CRT_VALIDATE(s != 0, CRT_EINVAL, 0); return strtoll(s, 0, 10); }
DLLAPI long long CRTAPI _atoi64(const char *s) { CRT_VALIDATE(s != 0, CRT_EINVAL, 0); return strtoll(s, 0, 10); }
DLLAPI int CRTAPI _wtoi(const wchar16 *s) { CRT_VALIDATE(s != 0, CRT_EINVAL, 0); return (int)wcstol(s, 0, 10); }
DLLAPI crt_long CRTAPI _wtol(const wchar16 *s) { CRT_VALIDATE(s != 0, CRT_EINVAL, 0); return wcstol(s, 0, 10); }
DLLAPI long long CRTAPI _wtoll(const wchar16 *s) { CRT_VALIDATE(s != 0, CRT_EINVAL, 0); return wcstoll(s, 0, 10); }
DLLAPI long long CRTAPI _wtoi64(const wchar16 *s) { CRT_VALIDATE(s != 0, CRT_EINVAL, 0); return wcstoll(s, 0, 10); }
DLLAPI int CRTAPI _atoi_l(const char *s, void *l) { (void)l; return atoi(s); }
DLLAPI crt_long CRTAPI _atol_l(const char *s, void *l) { (void)l; return atol(s); }

/* ---------------------------------------------------------------- floating point */
static double flt_common(const void *s, crt_getch_fn get, void *endp, int want_float, size_t unit)
{
    size_t used;
    int range;
    double v;
    if (endp) *(const void **)endp = s;
    CRT_VALIDATE(s != 0, CRT_EINVAL, 0.0);
    v = crt_strtod_core(s, get, &used, &range, want_float);
    if (endp) *(const void **)endp = (const char *)s + used * unit;
    if (range) crt_set_errno(CRT_ERANGE);
    return v;
}
DLLAPI double CRTAPI strtod(const char *s, char **end) { return flt_common(s, crt_get_narrow, end, 0, 1); }
DLLAPI double CRTAPI strtold(const char *s, char **end) { return flt_common(s, crt_get_narrow, end, 0, 1); }
DLLAPI float CRTAPI strtof(const char *s, char **end) { return (float)flt_common(s, crt_get_narrow, end, 1, 1); }
DLLAPI double CRTAPI wcstod(const wchar16 *s, wchar16 **end) { return flt_common(s, crt_get_wide, end, 0, 2); }
DLLAPI double CRTAPI wcstold(const wchar16 *s, wchar16 **end) { return flt_common(s, crt_get_wide, end, 0, 2); }
DLLAPI float CRTAPI wcstof(const wchar16 *s, wchar16 **end) { return (float)flt_common(s, crt_get_wide, end, 1, 2); }
DLLAPI double CRTAPI _strtod_l(const char *s, char **e, void *l) { (void)l; return strtod(s, e); }
DLLAPI float CRTAPI _strtof_l(const char *s, char **e, void *l) { (void)l; return strtof(s, e); }
DLLAPI double CRTAPI _wcstod_l(const wchar16 *s, wchar16 **e, void *l) { (void)l; return wcstod(s, e); }
DLLAPI double CRTAPI atof(const char *s) { CRT_VALIDATE(s != 0, CRT_EINVAL, 0.0); return strtod(s, 0); }
DLLAPI double CRTAPI _wtof(const wchar16 *s) { CRT_VALIDATE(s != 0, CRT_EINVAL, 0.0); return wcstod(s, 0); }
DLLAPI double CRTAPI _atof_l(const char *s, void *l) { (void)l; return atof(s); }

/* _atodbl / _atoflt: 0, _OVERFLOW (3) or _UNDERFLOW (4) */
DLLAPI int CRTAPI _atodbl(double *out, char *s)
{
    size_t used;
    int range;
    double v = crt_strtod_core(s, crt_get_narrow, &used, &range, 0);
    *out = v;
    if (!range) return 0;
    return (crt_d2u(v) & 0x7fffffffffffffffull) == 0x7ff0000000000000ull ? 3 : 4;
}
DLLAPI int CRTAPI _atoflt(float *out, const char *s)
{
    size_t used;
    int range;
    float v = (float)crt_strtod_core(s, crt_get_narrow, &used, &range, 1);
    *out = v;
    if (!range) return 0;
    return (crt_f2u(v) & 0x7fffffffu) == 0x7f800000u ? 3 : 4;
}

/* ---------------------------------------------------------------- integer -> string */
static int utoa_core(uint64_t v, int neg, char *tmp, unsigned radix)
{
    int n = 0;
    do { const unsigned d = (unsigned)(v % radix); tmp[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10); v /= radix; } while (v);
    if (neg) tmp[n++] = '-';
    return n;
}
static crt_errno_t xtoa_s(uint64_t v, int neg, void *buf, size_t size, int radix, int wide)
{
    char tmp[72];
    int n, i;
    CRT_VALIDATE(buf != 0 && size > 0, CRT_EINVAL, CRT_EINVAL);
    if (wide) ((wchar16 *)buf)[0] = 0; else ((char *)buf)[0] = 0;
    CRT_VALIDATE(radix >= 2 && radix <= 36, CRT_EINVAL, CRT_EINVAL);
    n = utoa_core(v, neg, tmp, (unsigned)radix);
    CRT_VALIDATE((size_t)n < size, CRT_ERANGE, CRT_ERANGE);
    for (i = 0; i < n; ++i) {
        if (wide) ((wchar16 *)buf)[i] = (unsigned char)tmp[n - 1 - i];
        else ((char *)buf)[i] = tmp[n - 1 - i];
    }
    if (wide) ((wchar16 *)buf)[n] = 0; else ((char *)buf)[n] = 0;
    return 0;
}
/* signed variants print a minus sign only for radix 10; other radixes show the two's-complement bits */
#define SIGNED_ARGS(val, bits) ((radix == 10 && (val) < 0) ? (uint64_t)0 - (uint64_t)(int64_t)(val) : (uint64_t)(val) & (bits == 32 ? 0xffffffffull : ~0ull)), (radix == 10 && (val) < 0)
DLLAPI crt_errno_t CRTAPI _itoa_s(int v, char *b, size_t n, int radix) { return xtoa_s(SIGNED_ARGS(v, 32), b, n, radix, 0); }
DLLAPI crt_errno_t CRTAPI _ltoa_s(crt_long v, char *b, size_t n, int radix) { return xtoa_s(SIGNED_ARGS(v, 32), b, n, radix, 0); }
DLLAPI crt_errno_t CRTAPI _ultoa_s(crt_ulong v, char *b, size_t n, int radix) { return xtoa_s(v, 0, b, n, radix, 0); }
DLLAPI crt_errno_t CRTAPI _i64toa_s(long long v, char *b, size_t n, int radix) { return xtoa_s(SIGNED_ARGS(v, 64), b, n, radix, 0); }
DLLAPI crt_errno_t CRTAPI _ui64toa_s(unsigned long long v, char *b, size_t n, int radix) { return xtoa_s(v, 0, b, n, radix, 0); }
DLLAPI crt_errno_t CRTAPI _itow_s(int v, wchar16 *b, size_t n, int radix) { return xtoa_s(SIGNED_ARGS(v, 32), b, n, radix, 1); }
DLLAPI crt_errno_t CRTAPI _ltow_s(crt_long v, wchar16 *b, size_t n, int radix) { return xtoa_s(SIGNED_ARGS(v, 32), b, n, radix, 1); }
DLLAPI crt_errno_t CRTAPI _ultow_s(crt_ulong v, wchar16 *b, size_t n, int radix) { return xtoa_s(v, 0, b, n, radix, 1); }
DLLAPI crt_errno_t CRTAPI _i64tow_s(long long v, wchar16 *b, size_t n, int radix) { return xtoa_s(SIGNED_ARGS(v, 64), b, n, radix, 1); }
DLLAPI crt_errno_t CRTAPI _ui64tow_s(unsigned long long v, wchar16 *b, size_t n, int radix) { return xtoa_s(v, 0, b, n, radix, 1); }
/* the unbounded forms: the buffer is assumed large enough (65 characters always suffice) */
DLLAPI char *CRTAPI _itoa(int v, char *b, int radix) { _itoa_s(v, b, 66, radix); return b; }
DLLAPI char *CRTAPI _ltoa(crt_long v, char *b, int radix) { _ltoa_s(v, b, 66, radix); return b; }
DLLAPI char *CRTAPI _ultoa(crt_ulong v, char *b, int radix) { _ultoa_s(v, b, 66, radix); return b; }
DLLAPI char *CRTAPI _i64toa(long long v, char *b, int radix) { _i64toa_s(v, b, 66, radix); return b; }
DLLAPI char *CRTAPI _ui64toa(unsigned long long v, char *b, int radix) { _ui64toa_s(v, b, 66, radix); return b; }
DLLAPI wchar16 *CRTAPI _itow(int v, wchar16 *b, int radix) { _itow_s(v, b, 66, radix); return b; }
DLLAPI wchar16 *CRTAPI _ltow(crt_long v, wchar16 *b, int radix) { _ltow_s(v, b, 66, radix); return b; }
DLLAPI wchar16 *CRTAPI _ultow(crt_ulong v, wchar16 *b, int radix) { _ultow_s(v, b, 66, radix); return b; }
DLLAPI wchar16 *CRTAPI _i64tow(long long v, wchar16 *b, int radix) { _i64tow_s(v, b, 66, radix); return b; }
DLLAPI wchar16 *CRTAPI _ui64tow(unsigned long long v, wchar16 *b, int radix) { _ui64tow_s(v, b, 66, radix); return b; }

/* ---------------------------------------------------------------- _ecvt / _fcvt / _gcvt */
/* digits of |v| without point; *decpt = position of the decimal point, *sign = negative */
static crt_errno_t cvt_common(char *buf, size_t size, double v, int ndig, int *decpt, int *sign, int fmode)
{
    char tmp[400];
    int n, x, i;
    const uint64_t b = crt_d2u(v);
    CRT_VALIDATE(buf != 0 && size > 0 && decpt != 0 && sign != 0, CRT_EINVAL, CRT_EINVAL);
    buf[0] = 0;
    *sign = (int)(b >> 63);
    if (((b >> 52) & 0x7ff) == 0x7ff) {
        const char *w = (b & 0xfffffffffffffull) ? "1#QNAN" : "1#INF";
        for (i = 0; w[i] && (size_t)i + 1 < size; ++i) buf[i] = w[i];
        buf[i] = 0;
        *decpt = 1;
        return 0;
    }
    if (fmode) {
        if (ndig < 0) ndig = 0;
        if (ndig > 340) ndig = 340;
        n = crt_dtoa_fixed(v, ndig, 'f', CRT_RND_HALF_AWAY, *sign, tmp, &x);
        if (x == 1 && tmp[0] == '0') {                        /* strip the integer zero: "0.0012" -> "12", decpt -2 */
            int z = 1;
            while (z < n && tmp[z] == '0') ++z;
            if (z == n) { n = 0; x = 0; }
            else { crt_memcpy(tmp, tmp + z, (size_t)(n - z)); n -= z; x = 1 - z; }
            x = x == 0 && n == 0 ? 0 : x;
        }
    } else {
        if (ndig < 1) ndig = 1;
        if (ndig > 340) ndig = 340;
        n = crt_dtoa_fixed(v, ndig - 1, 'e', CRT_RND_HALF_AWAY, *sign, tmp, &x);
        x += 1;
        if ((b & 0x7fffffffffffffffull) == 0) x = 0;
    }
    CRT_VALIDATE((size_t)n < size, CRT_ERANGE, CRT_ERANGE);
    crt_memcpy(buf, tmp, (size_t)n);
    buf[n] = 0;
    *decpt = x;
    return 0;
}
DLLAPI crt_errno_t CRTAPI _ecvt_s(char *buf, size_t size, double v, int ndig, int *decpt, int *sign)
{
    return cvt_common(buf, size, v, ndig, decpt, sign, 0);
}
DLLAPI crt_errno_t CRTAPI _fcvt_s(char *buf, size_t size, double v, int ndig, int *decpt, int *sign)
{
    return cvt_common(buf, size, v, ndig, decpt, sign, 1);
}
DLLAPI char *CRTAPI _ecvt(double v, int ndig, int *decpt, int *sign)
{
    static char buf[400];
    return cvt_common(buf, sizeof buf, v, ndig, decpt, sign, 0) ? 0 : buf;
}
DLLAPI char *CRTAPI _fcvt(double v, int ndig, int *decpt, int *sign)
{
    static char buf[800];
    return cvt_common(buf, sizeof buf, v, ndig, decpt, sign, 1) ? 0 : buf;
}
int crt_format_to_buffer(char *buf, size_t cap, const char *fmt, ...);
/* _gcvt: like %.*g with the requested significant digits */
DLLAPI crt_errno_t CRTAPI _gcvt_s(char *buf, size_t size, double v, int ndig)
{
    int r;
    CRT_VALIDATE(buf != 0 && size > 0, CRT_EINVAL, CRT_EINVAL);
    buf[0] = 0;
    CRT_VALIDATE(ndig >= 0, CRT_ERANGE, CRT_ERANGE);
    r = crt_format_to_buffer(buf, size, "%.*g", ndig ? ndig : 1, v);
    if (r < 0 || (size_t)r >= size) { buf[0] = 0; CRT_VALIDATE(0, CRT_ERANGE, CRT_ERANGE); }
    return 0;
}
DLLAPI char *CRTAPI _gcvt(double v, int ndig, char *buf)
{
    return _gcvt_s(buf, 400, v, ndig) ? 0 : buf;
}
