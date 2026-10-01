/* SPDX-License-Identifier: GPL-2.0-only
 * tridentrt: kernel32 functions the Wine browser modules import and the Shizuku kernel32 does not export yet
 * (ieframe: MulDiv; urlmon and wininet: IdnToAscii/IdnToUnicode; wininet: DosDateTimeToFileTime,
 * FileTimeToDosDateTime, GetComputerNameExA). They belong in kernel32 (listed under "Needed from K4" in the
 * tridentrt report); the browser modules take them from here until then.
 *
 * IdnToAscii/IdnToUnicode follow RFC 3490 ToASCII/ToUnicode with the RFC 3492 Punycode algorithm. Labels are split at
 * '.' and at U+3002, U+FF0E, U+FF61. An all-ASCII label is kept as it is (as Windows does, no case change); a label
 * with other characters is lowercased (towlower) and Punycode-encoded behind "xn--". Nameprep here is only that case
 * mapping: no NFKC normalisation and no check for unassigned code points, so a label that is not already in normal
 * form may encode differently from Windows.
 */
#define WINBASEAPI                                          /* defined here, not imported */
#define WINNORMALIZEAPI
#include <wchar.h>
#include <wctype.h>
#include "comrt.h"
#include "winnls.h"

#ifndef IDN_EMAIL_ADDRESS                                   /* Windows 8 SDK values, not in Wine's winnls.h */
#define IDN_EMAIL_ADDRESS 0x04
#endif
#ifndef IDN_RAW_PUNYCODE
#define IDN_RAW_PUNYCODE 0x08
#endif

INT WINAPI MulDiv(INT a, INT b, INT c)
{
    LONGLONG r;
    if (!c) return -1;
    if (c < 0) { a = -a; c = -c; }
    /* round half away from zero, the documented result */
    if ((a < 0) == (b < 0)) r = ((LONGLONG)a * b + c / 2) / c;
    else r = ((LONGLONG)a * b - c / 2) / c;
    if (r > 2147483647 || r < -2147483647) return -1;
    return (INT)r;
}

/* ---------------------------------------------------------------- MS-DOS date/time */
BOOL WINAPI DosDateTimeToFileTime(WORD date, WORD time, FILETIME *ft)
{
    SYSTEMTIME st;
    if (!ft) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memset(&st, 0, sizeof(st));
    st.wYear = (date >> 9) + 1980;
    st.wMonth = (date >> 5) & 0x0f;
    st.wDay = date & 0x1f;
    st.wHour = time >> 11;
    st.wMinute = (time >> 5) & 0x3f;
    st.wSecond = (time & 0x1f) * 2;
    return SystemTimeToFileTime(&st, ft);
}

BOOL WINAPI FileTimeToDosDateTime(const FILETIME *ft, WORD *date, WORD *time)
{
    SYSTEMTIME st;
    if (!ft || !date || !time || !FileTimeToSystemTime(ft, &st) || st.wYear < 1980 || st.wYear > 2107)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *time = (st.wHour << 11) | (st.wMinute << 5) | (st.wSecond / 2);
    *date = ((st.wYear - 1980) << 9) | (st.wMonth << 5) | st.wDay;
    return TRUE;
}

/* ---------------------------------------------------------------- GetComputerNameExA */
BOOL WINAPI GetComputerNameExA(COMPUTER_NAME_FORMAT format, char *name, DWORD *size)
{
    WCHAR buf[MAX_COMPUTERNAME_LENGTH * 4 + 256];
    DWORD len = ARRAY_SIZE(buf);
    int need;

    if (!size) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!GetComputerNameExW(format, buf, &len)) return FALSE;
    need = WideCharToMultiByte(CP_ACP, 0, buf, len + 1, NULL, 0, NULL, NULL);
    if (!name || *size < (DWORD)need)
    {
        *size = need;
        SetLastError(ERROR_MORE_DATA);
        return FALSE;
    }
    WideCharToMultiByte(CP_ACP, 0, buf, len + 1, name, *size, NULL, NULL);
    *size = need - 1;
    return TRUE;
}

/* ---------------------------------------------------------------- IDN (RFC 3490 / RFC 3492) */
enum { BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128, MAX_LABEL = 63 };

static unsigned adapt(unsigned delta, unsigned points, BOOL first)
{
    unsigned k = 0;
    delta = first ? delta / DAMP : delta / 2;
    delta += delta / points;
    while (delta > ((BASE - TMIN) * TMAX) / 2)
    {
        delta /= BASE - TMIN;
        k += BASE;
    }
    return k + (BASE - TMIN + 1) * delta / (delta + SKEW);
}

static unsigned threshold(unsigned k, unsigned bias)
{
    return k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
}

static WCHAR encode_digit(unsigned d) { return d < 26 ? 'a' + d : '0' + d - 26; }

static int decode_digit(WCHAR c)
{
    if (c >= '0' && c <= '9') return c - '0' + 26;
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= 'A' && c <= 'Z') return c - 'A';
    return -1;
}

static BOOL is_dot(WCHAR c) { return c == '.' || c == 0x3002 || c == 0xff0e || c == 0xff61; }

/* Punycode of code points cp[0..n) into out (capacity cap); length, or -1 when it does not fit */
static int punycode_encode(const unsigned *cp, int n, WCHAR *out, int cap)
{
    unsigned code = INITIAL_N, delta = 0, bias = INITIAL_BIAS, h, b = 0, m, q, k, t;
    int len = 0, i;

    for (i = 0; i < n; i++)
        if (cp[i] < 0x80)
        {
            if (len >= cap) return -1;
            out[len++] = (WCHAR)cp[i];
            b++;
        }
    h = b;
    if (b)
    {
        if (len >= cap) return -1;
        out[len++] = '-';
    }
    while (h < (unsigned)n)
    {
        for (m = 0xffffffff, i = 0; i < n; i++)
            if (cp[i] >= code && cp[i] < m) m = cp[i];
        if ((m - code) > (0xffffffff - delta) / (h + 1)) return -1;
        delta += (m - code) * (h + 1);
        code = m;
        for (i = 0; i < n; i++)
        {
            if (cp[i] < code && ++delta == 0) return -1;
            if (cp[i] != code) continue;
            for (q = delta, k = BASE; ; k += BASE)
            {
                t = threshold(k, bias);
                if (q < t) break;
                if (len >= cap) return -1;
                out[len++] = encode_digit(t + (q - t) % (BASE - t));
                q = (q - t) / (BASE - t);
            }
            if (len >= cap) return -1;
            out[len++] = encode_digit(q);
            bias = adapt(delta, h + 1, h == b);
            delta = 0;
            h++;
        }
        delta++;
        code++;
    }
    return len;
}

/* code points of Punycode in[0..n) into cp (capacity cap); count, or -1 on invalid input */
static int punycode_decode(const WCHAR *in, int n, unsigned *cp, int cap)
{
    unsigned code = INITIAL_N, i = 0, bias = INITIAL_BIAS, oldi, w, k, t;
    int b = 0, j, pos, out = 0, digit;

    for (j = 0; j < n; j++)
        if (in[j] == '-') b = j;
    for (j = 0; j < b; j++)
    {
        if (in[j] >= 0x80 || out >= cap) return -1;
        cp[out++] = in[j];
    }
    for (pos = b > 0 ? b + 1 : 0; pos < n; )
    {
        for (oldi = i, w = 1, k = BASE; ; k += BASE)
        {
            if (pos >= n || (digit = decode_digit(in[pos++])) < 0) return -1;
            if ((unsigned)digit > (0xffffffff - i) / w) return -1;
            i += digit * w;
            t = threshold(k, bias);
            if ((unsigned)digit < t) break;
            if (w > 0xffffffff / (BASE - t)) return -1;
            w *= BASE - t;
        }
        bias = adapt(i - oldi, out + 1, oldi == 0);
        if (i / (out + 1) > 0x10ffff - code) return -1;
        code += i / (out + 1);
        i %= out + 1;
        if (out >= cap || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return -1;
        memmove(cp + i + 1, cp + i, (out - i) * sizeof(*cp));
        cp[i++] = code;
        out++;
    }
    return out;
}

/* appends to dst (capacity cap, -1 = counting only); FALSE when it does not fit */
static BOOL put(WCHAR *dst, int cap, int *len, const WCHAR *s, int n)
{
    if (cap >= 0)
    {
        if (*len + n > cap) return FALSE;
        memcpy(dst + *len, s, n * sizeof(WCHAR));
    }
    *len += n;
    return TRUE;
}

static int idn_result(int len, BOOL fits, int out_len)
{
    if (!fits || (out_len && len > out_len))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    return len;
}

INT WINAPI IdnToAscii(DWORD flags, const WCHAR *in, INT in_len, WCHAR *out, INT out_len)
{
    unsigned cp[MAX_LABEL * 4 + 8];
    WCHAR label[MAX_LABEL + 8];
    int len = 0, start, end, i, n, cap = out_len ? out_len : -1;
    BOOL fits = TRUE, ascii;

    if (!in || !in_len || in_len < -1 || out_len < 0 || (out_len && !out) ||
        (flags & ~(IDN_ALLOW_UNASSIGNED | IDN_USE_STD3_ASCII_RULES | IDN_EMAIL_ADDRESS | IDN_RAW_PUNYCODE)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (in_len == -1) in_len = lstrlenW(in) + 1;
    for (start = 0; start < in_len; start = end + 1)
    {
        for (end = start; end < in_len && in[end] && !is_dot(in[end]); end++) { }
        for (ascii = TRUE, i = start; i < end; i++) if (in[i] >= 0x80) ascii = FALSE;
        if (ascii)
        {
            if (end - start > MAX_LABEL) goto invalid;
            if (flags & IDN_USE_STD3_ASCII_RULES)
            {
                for (i = start; i < end; i++)
                    if (!iswalnum(in[i]) && in[i] != '-') goto invalid;
                if (end > start && (in[start] == '-' || in[end - 1] == '-')) goto invalid;
            }
            if (fits) fits = put(out, cap, &len, in + start, end - start);
        }
        else
        {
            for (n = 0, i = start; i < end && n < (int)ARRAY_SIZE(cp); i++, n++)
            {
                if (in[i] >= 0xd800 && in[i] <= 0xdbff && i + 1 < end && in[i + 1] >= 0xdc00 && in[i + 1] <= 0xdfff)
                {
                    cp[n] = 0x10000 + ((in[i] - 0xd800) << 10) + (in[i + 1] - 0xdc00);
                    i++;
                }
                else cp[n] = towlower(in[i]);
            }
            if (i < end) goto invalid;
            memcpy(label, L"xn--", 4 * sizeof(WCHAR));
            if ((i = punycode_encode(cp, n, label + 4, MAX_LABEL - 4)) < 0) goto invalid;
            if (fits) fits = put(out, cap, &len, label, i + 4);
        }
        if (end < in_len)
        {
            if (!in[end]) { if (fits) fits = put(out, cap, &len, L"", 1); break; }   /* the terminating NUL */
            if (end == start && end + 1 < in_len && in[end + 1]) goto invalid;         /* an empty label */
            if (fits) fits = put(out, cap, &len, L".", 1);
        }
    }
    if (len > 255 + 1) goto invalid;
    return idn_result(len, fits, out_len);
invalid:
    SetLastError(ERROR_INVALID_NAME);
    return 0;
}

INT WINAPI IdnToUnicode(DWORD flags, const WCHAR *in, INT in_len, WCHAR *out, INT out_len)
{
    unsigned cp[MAX_LABEL + 8];
    WCHAR u[2 * (MAX_LABEL + 8)];
    int len = 0, start, end, i, n, k, cap = out_len ? out_len : -1;
    BOOL fits = TRUE;

    if (!in || !in_len || in_len < -1 || out_len < 0 || (out_len && !out) ||
        (flags & ~(IDN_ALLOW_UNASSIGNED | IDN_USE_STD3_ASCII_RULES | IDN_EMAIL_ADDRESS | IDN_RAW_PUNYCODE)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (in_len == -1) in_len = lstrlenW(in) + 1;
    for (start = 0; start < in_len; start = end + 1)
    {
        for (end = start; end < in_len && in[end] && !is_dot(in[end]); end++)
            if (in[end] >= 0x80) goto invalid;
        if (end - start > MAX_LABEL) goto invalid;
        if (end - start > 4 && !_wcsnicmp(in + start, L"xn--", 4))
        {
            if ((n = punycode_decode(in + start + 4, end - start - 4, cp, ARRAY_SIZE(cp))) <= 0) goto invalid;
            for (k = 0, i = 0; i < n; i++)
            {
                if (cp[i] >= 0x10000)
                {
                    u[k++] = 0xd800 + ((cp[i] - 0x10000) >> 10);
                    u[k++] = 0xdc00 + ((cp[i] - 0x10000) & 0x3ff);
                }
                else u[k++] = (WCHAR)cp[i];
            }
            if (fits) fits = put(out, cap, &len, u, k);
        }
        else if (fits) fits = put(out, cap, &len, in + start, end - start);
        if (end < in_len)
        {
            if (!in[end]) { if (fits) fits = put(out, cap, &len, L"", 1); break; }
            if (fits) fits = put(out, cap, &len, L".", 1);
        }
    }
    return idn_result(len, fits, out_len);
invalid:
    SetLastError(ERROR_INVALID_NAME);
    return 0;
}
