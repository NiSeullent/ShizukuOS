/* SPDX-License-Identifier: GPL-2.0-only
 * VARIANT management: VariantInit / VariantClear / VariantCopy / VariantCopyInd / VariantChangeType(Ex).
 *
 * VariantClear and VariantCopy follow the documented ownership rules for every VARTYPE (BSTR, IUnknown/IDispatch,
 * SAFEARRAY, VT_BYREF, VT_RECORD through IRecordInfo).
 *
 * VariantChangeType(Ex) supports these conversions, and returns E_NOTIMPL (never a wrong value) for everything else that
 * is legal but needs locale or currency/date tables:
 *   integers  I1 UI1 I2 UI2 I4 UI4 INT UINT I8 UI8, floats R4 R8, BOOL, EMPTY  <->  each other (range checked: DISP_E_OVERFLOW;
 *             float -> integer rounds to nearest, ties to even, as the Var*From* family documents);
 *   BSTR <-> integers and BOOL; BSTR -> R4/R8 when the decimal value is exactly representable by the classic fast path
 *   (at most 15 significant digits and a power-of-ten scale of at most 22). BOOL -> BSTR is "-1"/"0", or "True"/"False"
 *   with VARIANT_ALPHABOOL; BSTR -> BOOL accepts True/False/#TRUE#/#FALSE# or any number. Number text may have
 *   surrounding blanks, a sign, a decimal point and an exponent; &H/&O, thousands separators, currency, parentheses and
 *   trailing signs are E_NOTIMPL. The lcid argument is ignored (invariant, English behaviour).
 *   Not supported: R4/R8 -> BSTR, CY, DATE, DECIMAL, ERROR, DISPATCH/UNKNOWN conversions.
 */
#include "oleaut_int.h"

/* ---------------------------------------------------------------- type validity */
static int base_is_scalar(VARTYPE b)
{
    switch (b) {
    case VT_I2: case VT_I4: case VT_R4: case VT_R8: case VT_CY: case VT_DATE: case VT_BSTR: case VT_DISPATCH: case VT_ERROR:
    case VT_BOOL: case VT_UNKNOWN: case VT_DECIMAL: case VT_I1: case VT_UI1: case VT_UI2: case VT_UI4: case VT_I8: case VT_UI8:
    case VT_INT: case VT_UINT: case VT_RECORD:
        return 1;
    }
    return 0;
}

int shz_vt_valid(VARTYPE vt)
{
    const VARTYPE base = vt & VT_TYPEMASK;
    if (vt & (VT_VECTOR | VT_RESERVED)) return 0;
    if (vt & (VT_ARRAY | VT_BYREF)) return base_is_scalar(base) || base == VT_VARIANT;
    return base == VT_EMPTY || base == VT_NULL || base_is_scalar(base);
}

/* payload size of a by-reference scalar (what a VT_BYREF pointer points to) */
static SIZE_T scalar_size(VARTYPE b)
{
    switch (b) {
    case VT_I1: case VT_UI1: return 1;
    case VT_I2: case VT_UI2: case VT_BOOL: return 2;
    case VT_I4: case VT_UI4: case VT_R4: case VT_INT: case VT_UINT: case VT_ERROR: return 4;
    case VT_I8: case VT_UI8: case VT_R8: case VT_CY: case VT_DATE: return 8;
    case VT_BSTR: case VT_DISPATCH: case VT_UNKNOWN: return sizeof(void *);
    case VT_DECIMAL: return sizeof(DECIMAL);
    }
    return 0;
}

DLLAPI void WINAPI VariantInit(VARIANTARG *pv) { if (pv) V_VT(pv) = VT_EMPTY; }

/* ---------------------------------------------------------------- clear / copy */
DLLAPI HRESULT WINAPI VariantClear(VARIANTARG *pv)
{
    VARTYPE vt;
    if (!pv) return E_INVALIDARG;
    vt = V_VT(pv);
    if (!shz_vt_valid(vt)) return DISP_E_BADVARTYPE;
    if (!(vt & VT_BYREF)) {
        if (vt & VT_ARRAY) {
            HRESULT hr = SafeArrayDestroy(V_ARRAY(pv));
            if (FAILED(hr)) return hr;
        } else {
            switch (vt) {
            case VT_BSTR: SysFreeString(V_BSTR(pv)); break;
            case VT_UNKNOWN: if (V_UNKNOWN(pv)) IUnknown_Release(V_UNKNOWN(pv)); break;
            case VT_DISPATCH: if (V_DISPATCH(pv)) IDispatch_Release(V_DISPATCH(pv)); break;
            case VT_RECORD: {
                IRecordInfo *ri = V_RECORDINFO(pv);
                if (ri) {
                    IRecordInfo_RecordClear(ri, V_RECORD(pv));
                    IRecordInfo_Release(ri);
                }
                break;
            }
            }
        }
    }
    V_VT(pv) = VT_EMPTY;
    return S_OK;
}

DLLAPI HRESULT WINAPI VariantCopy(VARIANTARG *dst, VARIANTARG *src)
{
    VARTYPE vt;
    HRESULT hr;
    if (!dst || !src) return E_INVALIDARG;
    vt = V_VT(src);
    if (!shz_vt_valid(vt)) return DISP_E_BADVARTYPE;
    if (dst == src) return S_OK;
    hr = VariantClear(dst);
    if (FAILED(hr)) return hr;
    if (vt & VT_BYREF) {
        *dst = *src;                                                      /* only the pointer is copied */
        return S_OK;
    }
    if (vt & VT_ARRAY) {
        SAFEARRAY *copy = 0;
        hr = SafeArrayCopy(V_ARRAY(src), &copy);
        if (FAILED(hr)) return hr;
        V_ARRAY(dst) = copy;
        V_VT(dst) = vt;
        return S_OK;
    }
    switch (vt) {
    case VT_BSTR: {
        BSTR s = V_BSTR(src), n = 0;
        if (s) {
            n = SysAllocStringByteLen((const char *)s, SysStringByteLen(s));
            if (!n) return E_OUTOFMEMORY;
        }
        *dst = *src;
        V_BSTR(dst) = n;
        return S_OK;
    }
    case VT_UNKNOWN:
        *dst = *src;
        if (V_UNKNOWN(src)) IUnknown_AddRef(V_UNKNOWN(src));
        return S_OK;
    case VT_DISPATCH:
        *dst = *src;
        if (V_DISPATCH(src)) IDispatch_AddRef(V_DISPATCH(src));
        return S_OK;
    case VT_RECORD: {
        IRecordInfo *ri = V_RECORDINFO(src);
        PVOID copy = 0;
        *dst = *src;
        if (ri) {
            hr = IRecordInfo_RecordCreateCopy(ri, V_RECORD(src), &copy);
            if (FAILED(hr)) { V_VT(dst) = VT_EMPTY; return hr; }
            V_RECORD(dst) = copy;
            IRecordInfo_AddRef(ri);
        }
        return S_OK;
    }
    default:
        *dst = *src;
        return S_OK;
    }
}

DLLAPI HRESULT WINAPI VariantCopyInd(VARIANT *dst, VARIANTARG *src)
{
    VARTYPE vt;
    VARIANT tmp;
    HRESULT hr;
    if (!dst || !src) return E_INVALIDARG;
    vt = V_VT(src);
    if (!shz_vt_valid(vt)) return DISP_E_BADVARTYPE;
    if (!(vt & VT_BYREF)) return VariantCopy(dst, src);
    if (dst == src) {
        /* in place: copy through a temporary so the by-reference pointer is not lost before it is read */
        VariantInit(&tmp);
        hr = VariantCopyInd(&tmp, src);
        if (FAILED(hr)) return hr;
        V_VT(src) = VT_EMPTY;
        *dst = tmp;
        return S_OK;
    }
    if (vt == (VT_VARIANT | VT_BYREF)) {
        VARIANT *inner = V_VARIANTREF(src);
        if (!inner) return E_INVALIDARG;
        if (V_VT(inner) == (VT_VARIANT | VT_BYREF)) return DISP_E_BADVARTYPE;           /* no chains of variant references */
        return VariantCopyInd(dst, inner);
    }
    if (!V_BYREF(src)) return E_INVALIDARG;
    if (vt & VT_ARRAY) {
        VariantInit(&tmp);
        V_VT(&tmp) = (VARTYPE)(vt & ~VT_BYREF);
        V_ARRAY(&tmp) = *V_ARRAYREF(src);
        return VariantCopy(dst, &tmp);
    }
    {
        const VARTYPE base = vt & VT_TYPEMASK;
        const SIZE_T n = scalar_size(base);
        if (!n && base != VT_RECORD) return DISP_E_BADVARTYPE;
        memset(&tmp, 0, sizeof tmp);
        if (base == VT_RECORD) {
            tmp = *src;                                                       /* pvRecord / pRecInfo travel with the variant */
            V_VT(&tmp) = VT_RECORD;
        } else if (base == VT_DECIMAL) {
            memcpy(&tmp, V_BYREF(src), sizeof(DECIMAL));
            V_VT(&tmp) = VT_DECIMAL;
        } else {
            memcpy(&V_I8(&tmp), V_BYREF(src), n);                            /* sits at the start of the value union */
            V_VT(&tmp) = base;
        }
        return VariantCopy(dst, &tmp);
    }
}

/* ---------------------------------------------------------------- change type */
typedef struct { int is_float; int is_bool; __int128 i; double d; } num_t;

static HRESULT get_num(const VARIANT *v, num_t *n)
{
    memset(n, 0, sizeof *n);
    switch (V_VT(v)) {
    case VT_EMPTY: return S_OK;
    case VT_I1: n->i = V_I1(v); return S_OK;
    case VT_UI1: n->i = V_UI1(v); return S_OK;
    case VT_I2: n->i = V_I2(v); return S_OK;
    case VT_UI2: n->i = V_UI2(v); return S_OK;
    case VT_I4: n->i = V_I4(v); return S_OK;
    case VT_INT: n->i = V_INT(v); return S_OK;
    case VT_UI4: n->i = V_UI4(v); return S_OK;
    case VT_UINT: n->i = V_UINT(v); return S_OK;
    case VT_I8: n->i = V_I8(v); return S_OK;
    case VT_UI8: n->i = (__int128)V_UI8(v); return S_OK;
    case VT_R4: n->is_float = 1; n->d = V_R4(v); return S_OK;
    case VT_R8: n->is_float = 1; n->d = V_R8(v); return S_OK;
    case VT_BOOL: n->is_bool = 1; n->i = V_BOOL(v); return S_OK;
    }
    return E_NOTIMPL;
}

/* Round to nearest, ties to even; returns 0 if the magnitude does not fit an int64/uint64 range we can express. */
static int round_even(double d, __int128 *out)
{
    long long t;
    double frac;
    if (d != d) return 0;                                       /* NaN */
    if (d >= 18446744073709551616.0 || d < -9223372036854775808.0) return 0;
    if (d >= 9223372036854775808.0) { *out = (__int128)(unsigned long long)d; return 1; }      /* already integral at this size */
    t = (long long)d;                                           /* truncates toward zero */
    frac = d - (double)t;
    if (frac > 0.5 || (frac == 0.5 && (t & 1))) ++t;
    else if (frac < -0.5 || (frac == -0.5 && (t & 1))) --t;
    *out = t;
    return 1;
}

static HRESULT int_range(__int128 v, VARTYPE vt, int is_bool)
{
    __int128 lo, hi;
    switch (vt) {
    case VT_I1: lo = -128; hi = 127; break;
    case VT_UI1: lo = 0; hi = 255; break;
    case VT_I2: lo = -32768; hi = 32767; break;
    case VT_UI2: lo = 0; hi = 65535; break;
    case VT_I4: case VT_INT: lo = -2147483648ll; hi = 2147483647ll; break;
    case VT_UI4: case VT_UINT: lo = 0; hi = 4294967295ll; break;
    case VT_I8: lo = -(__int128)9223372036854775807ll - 1; hi = 9223372036854775807ll; break;
    default: lo = 0; hi = (__int128)18446744073709551615ull; break;            /* VT_UI8 */
    }
    if (is_bool) return S_OK;                                                  /* a BOOL is cast, never range checked */
    return v < lo || v > hi ? DISP_E_OVERFLOW : S_OK;
}

static void store_int(VARIANT *d, VARTYPE vt, __int128 v)
{
    switch (vt) {
    case VT_I1: V_I1(d) = (CHAR)v; break;
    case VT_UI1: V_UI1(d) = (BYTE)v; break;
    case VT_I2: V_I2(d) = (SHORT)v; break;
    case VT_UI2: V_UI2(d) = (USHORT)v; break;
    case VT_I4: V_I4(d) = (LONG)v; break;
    case VT_INT: V_INT(d) = (INT)v; break;
    case VT_UI4: V_UI4(d) = (ULONG)v; break;
    case VT_UINT: V_UINT(d) = (UINT)v; break;
    case VT_I8: V_I8(d) = (LONGLONG)v; break;
    default: V_UI8(d) = (ULONGLONG)v; break;
    }
    V_VT(d) = vt;
}

static int is_int_vt(VARTYPE vt)
{
    return vt == VT_I1 || vt == VT_UI1 || vt == VT_I2 || vt == VT_UI2 || vt == VT_I4 || vt == VT_UI4 || vt == VT_INT || vt == VT_UINT ||
           vt == VT_I8 || vt == VT_UI8;
}

static HRESULT num_to_variant(const num_t *n, VARIANT *d, VARTYPE vt, USHORT flags)
{
    if (is_int_vt(vt)) {
        __int128 v;
        HRESULT hr;
        if (n->is_float) {
            if (!round_even(n->d, &v)) return DISP_E_OVERFLOW;
            hr = int_range(v, vt, 0);
        } else {
            v = n->i;
            hr = int_range(v, vt, n->is_bool);
        }
        if (FAILED(hr)) return hr;
        store_int(d, vt, v);
        return S_OK;
    }
    if (vt == VT_BOOL) {
        int nonzero = n->is_float ? n->d != 0.0 : n->i != 0;
        V_BOOL(d) = nonzero ? VARIANT_TRUE : VARIANT_FALSE;
        V_VT(d) = VT_BOOL;
        return S_OK;
    }
    if (vt == VT_R8 || vt == VT_R4) {
        double x = n->is_float ? n->d : (n->i < 0 ? -(double)(unsigned long long)(-n->i) : (double)(unsigned long long)n->i);
        if (vt == VT_R4) {
            float f = (float)x;
            if (x == x && (f - f) != 0.0f) return DISP_E_OVERFLOW;                       /* finite double beyond float range */
            V_R4(d) = f;
        } else {
            V_R8(d) = x;
        }
        V_VT(d) = vt;
        return S_OK;
    }
    (void)flags;
    return E_NOTIMPL;
}

/* ---- BSTR <-> numbers ---- */
static BSTR int_to_bstr(__int128 v)
{
    OLECHAR tmp[48];
    int n = 0, neg = v < 0, i;
    unsigned long long m = neg ? (unsigned long long)(-v) : (unsigned long long)v;
    OLECHAR out[48];
    if (!m) tmp[n++] = '0';
    while (m) { tmp[n++] = (OLECHAR)('0' + m % 10); m /= 10; }
    i = 0;
    if (neg) out[i++] = '-';
    while (n) out[i++] = tmp[--n];
    out[i] = 0;
    return SysAllocStringLen(out, (UINT)i);
}

static int is_blank(OLECHAR c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

/* Parses [blanks][sign] digits [. digits] [e|E [sign] digits] [blanks] into a decimal string + exponent.
 * Returns S_OK, DISP_E_TYPEMISMATCH (not a number), or E_NOTIMPL (a form we deliberately do not handle). */
typedef struct { int neg; char digits[64]; int nd; int exp10; int truncated; } dec_t;    /* value = 0.d1d2..dn * 10^exp10 is not used: see below */

static HRESULT parse_decimal(const OLECHAR *s, UINT len, dec_t *out)
{
    UINT i = 0;
    int have_digit = 0, seen_dot = 0, frac_digits = 0, exp = 0, exp_neg = 0;
    memset(out, 0, sizeof *out);
    while (i < len && is_blank(s[i])) ++i;
    if (i < len && (s[i] == '-' || s[i] == '+')) { out->neg = s[i] == '-'; ++i; }
    if (i < len && s[i] == '&') return E_NOTIMPL;                                    /* &H hex / &O octal */
    for (; i < len; ++i) {
        OLECHAR c = s[i];
        if (c >= '0' && c <= '9') {
            have_digit = 1;
            if (out->nd < 63) {
                out->digits[out->nd++] = (char)c;
                if (seen_dot) ++frac_digits;
            } else {
                if (c != '0') out->truncated = 1;                                    /* buffer full: keep only a "nonzero tail" flag */
                if (!seen_dot) out->exp10++;                                         /* dropped integer digit: scale by 10 */
            }
        } else if (c == '.' && !seen_dot) {
            seen_dot = 1;
        } else {
            break;
        }
    }
    if (!have_digit) {
        if (i < len && (s[i] == '(' || s[i] == '$' || s[i] == ',')) return E_NOTIMPL;
        return DISP_E_TYPEMISMATCH;
    }
    if (i < len && (s[i] == 'e' || s[i] == 'E')) {
        UINT j = i + 1;
        int ed = 0;
        if (j < len && (s[j] == '-' || s[j] == '+')) { exp_neg = s[j] == '-'; ++j; }
        while (j < len && s[j] >= '0' && s[j] <= '9') { if (exp < 100000) exp = exp * 10 + (s[j] - '0'); ++j; ++ed; }
        if (!ed) return DISP_E_TYPEMISMATCH;
        i = j;
    }
    while (i < len && is_blank(s[i])) ++i;
    if (i < len) {
        if (s[i] == '-' || s[i] == '+' || s[i] == ')' || s[i] == ',' || s[i] == '(' || s[i] == '$') return E_NOTIMPL;      /* trailing sign, parens, ... */
        return DISP_E_TYPEMISMATCH;
    }
    out->exp10 += (exp_neg ? -exp : exp) - frac_digits;                              /* value = digits * 10^exp10 */
    return S_OK;
}

/* digits * 10^exp10 -> integer, rounding half to even; DISP_E_OVERFLOW if it does not fit 65 bits of magnitude */
static HRESULT dec_to_int(const dec_t *d, __int128 *out)
{
    __int128 mag = 0;
    int i, drop = 0, nd = d->nd, e = d->exp10;
    int round_up = 0, half = 0;
    /* number of low digits that fall after the decimal point */
    if (e < 0) drop = -e;
    for (i = 0; i < nd; ++i) if (d->digits[i] != '0') break;
    if (i == nd) { *out = 0; return S_OK; }                                          /* zero */
    if (drop > nd) { *out = 0; return S_OK; }                                        /* |x| < 0.1 (the leading digit is dropped entirely): rounds to 0 */
    {
        int keep = nd - drop;                                                        /* digits kept as integer digits */
        for (i = 0; i < keep; ++i) {
            mag = mag * 10 + (d->digits[i] - '0');
            if (mag > ((__int128)1 << 66)) return DISP_E_OVERFLOW;
        }
        if (drop) {
            char first = d->digits[keep];
            int rest_nonzero = d->truncated;
            for (i = keep + 1; i < nd; ++i) if (d->digits[i] != '0') rest_nonzero = 1;
            if (first > '5' || (first == '5' && rest_nonzero)) round_up = 1;
            else if (first == '5' && !rest_nonzero) half = 1;
            if (half && (mag & 1)) round_up = 1;
        }
        if (round_up) ++mag;
    }
    if (e > 0) {
        while (e-- > 0) {
            mag *= 10;
            if (mag > ((__int128)1 << 66)) return DISP_E_OVERFLOW;
        }
    }
    *out = d->neg ? -mag : mag;
    return S_OK;
}

/* digits * 10^exp10 -> double when the classic fast path applies (exact); else E_NOTIMPL */
static HRESULT dec_to_double(const dec_t *d, double *out)
{
    static const double p10[23] = { 1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18,
                                    1e19, 1e20, 1e21, 1e22 };
    unsigned long long m = 0;
    int i, nd = d->nd, e = d->exp10;
    double x;
    while (nd > 0 && d->digits[nd - 1] == '0') { --nd; ++e; }                       /* trailing zeros only scale */
    for (i = 0; i < nd && d->digits[i] == '0'; ++i) { }
    if (i == nd) { *out = d->neg ? -0.0 : 0.0; return S_OK; }
    if (nd - i > 15 || d->truncated) return E_NOTIMPL;
    for (; i < nd; ++i) m = m * 10 + (unsigned)(d->digits[i] - '0');
    x = (double)m;
    if (e >= 0 && e <= 22) x *= p10[e];
    else if (e < 0 && e >= -22) x /= p10[-e];
    else return E_NOTIMPL;
    *out = d->neg ? -x : x;
    return S_OK;
}

static int bstr_eq_ci(BSTR s, const char *lit)
{
    UINT n = SysStringLen(s), i;
    for (i = 0; lit[i]; ++i) {
        OLECHAR c;
        if (i >= n) return 0;
        c = s[i];
        if (c >= 'A' && c <= 'Z') c = (OLECHAR)(c + 32);
        if (c != (OLECHAR)(unsigned char)lit[i]) return 0;
    }
    return i == n;
}

static HRESULT bstr_to_target(BSTR s, VARIANT *d, VARTYPE vt)
{
    dec_t dec;
    HRESULT hr;
    UINT len = SysStringLen(s);
    if (vt == VT_BOOL) {
        if (bstr_eq_ci(s, "true") || bstr_eq_ci(s, "#true#")) { V_BOOL(d) = VARIANT_TRUE; V_VT(d) = VT_BOOL; return S_OK; }
        if (bstr_eq_ci(s, "false") || bstr_eq_ci(s, "#false#")) { V_BOOL(d) = VARIANT_FALSE; V_VT(d) = VT_BOOL; return S_OK; }
    }
    hr = parse_decimal(s, len, &dec);
    if (FAILED(hr)) return hr;
    if (is_int_vt(vt)) {
        __int128 v;
        hr = dec_to_int(&dec, &v);
        if (FAILED(hr)) return hr;
        hr = int_range(v, vt, 0);
        if (FAILED(hr)) return hr;
        store_int(d, vt, v);
        return S_OK;
    }
    if (vt == VT_BOOL) {
        int i, nonzero = 0;
        for (i = 0; i < dec.nd; ++i) if (dec.digits[i] != '0') nonzero = 1;
        V_BOOL(d) = nonzero ? VARIANT_TRUE : VARIANT_FALSE;
        V_VT(d) = VT_BOOL;
        return S_OK;
    }
    if (vt == VT_R8 || vt == VT_R4) {
        double x;
        num_t n;
        hr = dec_to_double(&dec, &x);
        if (FAILED(hr)) return hr;
        memset(&n, 0, sizeof n);
        n.is_float = 1;
        n.d = x;
        return num_to_variant(&n, d, vt, 0);
    }
    return E_NOTIMPL;
}

static HRESULT change_one(VARIANT *dst, const VARIANT *src, USHORT flags, VARTYPE vt)
{
    const VARTYPE svt = V_VT(src);
    num_t n;
    HRESULT hr;
    /* invalid or impossible target/source classes */
    if (vt & (VT_BYREF | VT_ARRAY | VT_VECTOR)) return DISP_E_BADVARTYPE;
    if (svt & (VT_ARRAY | VT_VECTOR)) return DISP_E_TYPEMISMATCH;
    if (vt == VT_EMPTY || vt == VT_NULL) return DISP_E_TYPEMISMATCH;
    if (svt == VT_NULL) return DISP_E_TYPEMISMATCH;
    if (svt == VT_BSTR && vt != VT_BSTR) return bstr_to_target(V_BSTR(src), dst, vt);
    if (vt == VT_BSTR) {
        BSTR b;
        if (svt == VT_EMPTY) { b = SysAllocStringLen(0, 0); }
        else if (svt == VT_BOOL) {
            static const OLECHAR t[] = { 'T', 'r', 'u', 'e' }, f[] = { 'F', 'a', 'l', 's', 'e' };
            if (flags & VARIANT_ALPHABOOL) b = V_BOOL(src) ? SysAllocStringLen(t, 4) : SysAllocStringLen(f, 5);
            else b = int_to_bstr(V_BOOL(src) ? -1 : 0);
        } else {
            hr = get_num(src, &n);
            if (FAILED(hr) || n.is_float) return E_NOTIMPL;                       /* R4/R8 text formatting needs the shortest-round-trip printer */
            b = int_to_bstr(n.i);
        }
        if (!b) return E_OUTOFMEMORY;
        V_BSTR(dst) = b;
        V_VT(dst) = VT_BSTR;
        return S_OK;
    }
    hr = get_num(src, &n);
    if (hr == E_NOTIMPL) {
        /* legal source types that carry no number here: UNKNOWN/DISPATCH cannot become numbers at all */
        if (svt == VT_UNKNOWN || svt == VT_DISPATCH) return DISP_E_TYPEMISMATCH;
        return E_NOTIMPL;
    }
    return num_to_variant(&n, dst, vt, flags);
}

DLLAPI HRESULT WINAPI VariantChangeTypeEx(VARIANTARG *dst, VARIANTARG *src, LCID lcid, USHORT flags, VARTYPE vt)
{
    VARIANT tmp, out;
    VARIANT *from = src;
    HRESULT hr;
    (void)lcid;
    if (!dst || !src) return E_INVALIDARG;
    if (!shz_vt_valid(V_VT(src))) return DISP_E_BADVARTYPE;
    VariantInit(&tmp);
    VariantInit(&out);
    if (V_VT(src) & VT_BYREF) {                                                  /* convert the referenced value */
        hr = VariantCopyInd(&tmp, src);
        if (FAILED(hr)) return hr;
        from = &tmp;
    }
    if (V_VT(from) == vt) {                                                      /* identical type: a plain copy */
        if (from == src && dst == src) return S_OK;
        hr = VariantCopy(&out, from);
    } else if (!(vt == VT_EMPTY || vt == VT_NULL || (!(vt & (VT_BYREF | VT_ARRAY | VT_VECTOR | VT_RESERVED)) && shz_vt_valid(vt)))) {
        hr = DISP_E_BADVARTYPE;
    } else {
        hr = change_one(&out, from, flags, vt);
    }
    if (from == &tmp) VariantClear(&tmp);
    if (FAILED(hr)) {
        VariantClear(&out);
        if (dst != src) VariantClear(dst);                                       /* the destination is left empty on failure */
        return hr;
    }
    VariantClear(dst);                                                           /* releases the old value (in place: the source) */
    *dst = out;
    return S_OK;
}

DLLAPI HRESULT WINAPI VariantChangeType(VARIANTARG *dst, VARIANTARG *src, USHORT flags, VARTYPE vt)
{
    return VariantChangeTypeEx(dst, src, 0x0400 /* LOCALE_USER_DEFAULT */, flags, vt);
}
