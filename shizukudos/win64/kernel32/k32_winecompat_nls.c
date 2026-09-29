/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: national-language support used by the DLLs ported from Wine (wineport): string comparison and mapping,
 * character types, locale identifiers, GetLocaleInfo and date/time formatting.
 *
 * Scope (documented limits, not approximations presented as Windows data):
 *  - One locale exists: en-US (LCID 0x0409), which is also the user, system, thread and UI default. LOCALE_INVARIANT is
 *    accepted and differs from en-US where Windows' invariant locale does (date/time pictures, currency, names). Any
 *    other LCID or locale name fails with ERROR_INVALID_PARAMETER.
 *  - The ANSI and OEM code pages are 65001 (UTF-8), as GetACP/GetOEMCP report, so LOCALE_IDEFAULT[ANSI]CODEPAGE say 65001.
 *  - Case mapping is the simple Unicode 14.0 BMP mapping of shz_wupper.h (lower case = its inverse).
 *  - CompareString is not the Windows sort-key algorithm: strings compare by case-folded code unit (primary), then by
 *    case with lower case first (tertiary); without SORT_STRINGSORT hyphens and apostrophes are ignored at the primary
 *    level ("word sort"). NORM_IGNORECASE / NORM_IGNORESYMBOLS / NORM_IGNORENONSPACE (only the combining marks
 *    U+0300..U+036F) are honoured. LCMAP_SORTKEY produces keys that sort in that same order.
 *  - Calendar: Gregorian only (era "A.D.").
 */
#include "k32_winecompat.h"
#include "shz_wupper.h"

static WCHAR wupper(WCHAR c) { return shz_wupper(c); }
static WCHAR wlower(WCHAR c)
{
    unsigned i;
    if (c < 0x80) return c >= 'A' && c <= 'Z' ? (WCHAR)(c + 32) : c;
    for (i = 0; i < sizeof shz_upper_runs / sizeof shz_upper_runs[0]; ++i) {
        int32_t x = (int32_t)c - shz_upper_runs[i].delta;
        if (x >= shz_upper_runs[i].lo && x <= shz_upper_runs[i].hi && (x - shz_upper_runs[i].lo) % shz_upper_runs[i].step == 0 &&
            wupper((WCHAR)x) == c)
            return (WCHAR)x;
    }
    return c;
}

/* ---------------------------------------------------------------- locale identity */
#define SHZ_LCID 0x0409

static LCID resolve_lcid(LCID lcid)
{
    switch (lcid) {
    case LOCALE_NEUTRAL: case LOCALE_USER_DEFAULT: case LOCALE_SYSTEM_DEFAULT: case LOCALE_CUSTOM_DEFAULT:
    case LOCALE_CUSTOM_UNSPECIFIED: case LOCALE_CUSTOM_UI_DEFAULT: case 0x0009:  /* LANG_ENGLISH, SUBLANG_NEUTRAL */
    case SHZ_LCID:
        return SHZ_LCID;
    case LOCALE_INVARIANT:
        return LOCALE_INVARIANT;
    }
    if (LANGIDFROMLCID(lcid) == SHZ_LCID && SORTIDFROMLCID(lcid) == SORT_DEFAULT) return SHZ_LCID;
    return 0;
}

K32API LCID WINAPI GetUserDefaultLCID(void) { return SHZ_LCID; }
K32API LCID WINAPI GetSystemDefaultLCID(void) { return SHZ_LCID; }
K32API LANGID WINAPI GetUserDefaultLangID(void) { return SHZ_LCID; }
K32API LANGID WINAPI GetSystemDefaultLangID(void) { return SHZ_LCID; }
K32API LANGID WINAPI GetUserDefaultUILanguage(void) { return SHZ_LCID; }
K32API LANGID WINAPI GetSystemDefaultUILanguage(void) { return SHZ_LCID; }
K32API LCID WINAPI GetThreadLocale(void) { return SHZ_LCID; }
K32API BOOL WINAPI SetThreadLocale(LCID lcid)
{
    if (resolve_lcid(lcid) != SHZ_LCID) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return TRUE;
}
K32API LANGID WINAPI GetThreadUILanguage(void) { return SHZ_LCID; }
K32API LANGID WINAPI SetThreadUILanguage(LANGID id) { return (id == 0 || id == SHZ_LCID) ? SHZ_LCID : 0; }
K32API BOOL WINAPI IsValidLocale(LCID lcid, DWORD flags) { (void)flags; return resolve_lcid(lcid) != 0; }
K32API LCID WINAPI ConvertDefaultLocale(LCID lcid) { LCID r = resolve_lcid(lcid); return r ? r : lcid; }

static int copy_w(const WCHAR *s, WCHAR *out, int cap)
{
    int n = lstrlenW(s) + 1;
    if (!cap) return n;
    if (n > cap) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
    memcpy(out, s, n * sizeof(WCHAR));
    return n;
}

K32API int WINAPI GetUserDefaultLocaleName(LPWSTR name, int cap) { return copy_w(L"en-US", name, cap); }
K32API int WINAPI GetSystemDefaultLocaleName(LPWSTR name, int cap) { return copy_w(L"en-US", name, cap); }
K32API int WINAPI LCIDToLocaleName(LCID lcid, LPWSTR name, int cap, DWORD flags)
{
    LCID r = resolve_lcid(lcid);
    (void)flags;
    if (!r) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return copy_w(r == LOCALE_INVARIANT ? L"" : L"en-US", name, cap);
}
static LCID name_to_lcid(LPCWSTR name)
{
    if (!name || !lstrcmpiW(name, L"en-US") || !lstrcmpiW(name, L"en") || !lstrcmpiW(name, LOCALE_NAME_USER_DEFAULT) ||
        !lstrcmpiW(name, LOCALE_NAME_SYSTEM_DEFAULT))
        return SHZ_LCID;
    if (!name[0]) return LOCALE_INVARIANT;
    return 0;
}
K32API LCID WINAPI LocaleNameToLCID(LPCWSTR name, DWORD flags)
{
    LCID r = name_to_lcid(name);
    (void)flags;
    if (!r) SetLastError(ERROR_INVALID_PARAMETER);
    return r;
}
K32API BOOL WINAPI IsValidLocaleName(LPCWSTR name) { return name && name_to_lcid(name) != 0; }

/* ---------------------------------------------------------------- lstr* */
K32API int WINAPI lstrcmpW(LPCWSTR a, LPCWSTR b)
{
    int r;
    if (!a || !b) return a ? 1 : b ? -1 : 0;
    r = CompareStringW(LOCALE_USER_DEFAULT, 0, a, -1, b, -1);
    return r ? r - CSTR_EQUAL : 0;
}
K32API int WINAPI lstrcmpiW(LPCWSTR a, LPCWSTR b)
{
    int r;
    if (!a || !b) return a ? 1 : b ? -1 : 0;
    r = CompareStringW(LOCALE_USER_DEFAULT, NORM_IGNORECASE, a, -1, b, -1);
    return r ? r - CSTR_EQUAL : 0;
}
K32API LPWSTR WINAPI lstrcpynW(LPWSTR d, LPCWSTR s, int n)
{
    LPWSTR r = d;
    if (!d || !s || n <= 0) return n == 0 ? d : NULL;
    while (--n > 0 && *s) *d++ = *s++;
    *d = 0;
    return r;
}
K32API LPSTR WINAPI lstrcpynA(LPSTR d, LPCSTR s, int n)
{
    LPSTR r = d;
    if (!d || !s || n <= 0) return n == 0 ? d : NULL;
    while (--n > 0 && *s) *d++ = *s++;
    *d = 0;
    return r;
}
K32API LPWSTR WINAPI lstrcatW(LPWSTR d, LPCWSTR s) { if (!d || !s) return NULL; lstrcpyW(d + lstrlenW(d), s); return d; }
K32API LPSTR WINAPI lstrcatA(LPSTR d, LPCSTR s) { if (!d || !s) return NULL; lstrcpyA(d + lstrlenA(d), s); return d; }

/* ---------------------------------------------------------------- character types */
static BOOL is_combining(WCHAR c) { return c >= 0x300 && c <= 0x36f; }
static BOOL is_space(WCHAR c) { return (c >= 9 && c <= 13) || c == ' ' || c == 0x85 || c == 0xa0 || c == 0x1680 || (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 || c == 0x202f || c == 0x205f || c == 0x3000; }
static BOOL is_digit(WCHAR c) { return c >= '0' && c <= '9'; }
static BOOL is_alpha(WCHAR c)
{
    if (c < 0x80) return (c | 0x20) >= 'a' && (c | 0x20) <= 'z';
    if (wupper(c) != c || wlower(c) != c) return TRUE;                     /* cased letters */
    return (c == 0xaa || c == 0xba || (c >= 0x1c0 && c <= 0x1c3) || (c >= 0x5d0 && c <= 0x5ea) || (c >= 0x620 && c <= 0x64a) ||
            (c >= 0x904 && c <= 0x939) || (c >= 0xe01 && c <= 0xe30) || (c >= 0x3041 && c <= 0x3096) ||
            (c >= 0x30a1 && c <= 0x30fa) || (c >= 0x3400 && c <= 0x4dbf) || (c >= 0x4e00 && c <= 0x9fff) ||
            (c >= 0xac00 && c <= 0xd7a3) || (c >= 0xf900 && c <= 0xfaff));
}
static BOOL is_cntrl(WCHAR c) { return c < 0x20 || (c >= 0x7f && c < 0xa0); }
static BOOL is_punct(WCHAR c)
{
    if (c < 0x80) return c > 0x20 && c < 0x7f && !is_alpha(c) && !is_digit(c);
    return (c >= 0xa1 && c <= 0xbf && c != 0xaa && c != 0xba) || c == 0xd7 || c == 0xf7 || (c >= 0x2010 && c <= 0x2027) ||
           (c >= 0x2030 && c <= 0x205e) || (c >= 0x3001 && c <= 0x3003) || (c >= 0x3008 && c <= 0x3011) || (c >= 0xff01 && c <= 0xff0f);
}

static WORD ctype1(WCHAR c)
{
    WORD t = C1_DEFINED;
    if (is_space(c)) t |= C1_SPACE;
    if (c == ' ' || c == '\t' || c == 0xa0 || c == 0x3000) t |= C1_BLANK;
    if (is_cntrl(c)) t |= C1_CNTRL;
    if (is_digit(c)) t |= C1_DIGIT;
    if ((c >= '0' && c <= '9') || ((c | 0x20) >= 'a' && (c | 0x20) <= 'f')) t |= C1_XDIGIT;
    if (is_alpha(c)) {
        t |= C1_ALPHA;
        if (wlower(c) != c) t |= C1_UPPER;
        if (wupper(c) != c || c == 0xdf) t |= C1_LOWER;
    }
    if (is_punct(c)) t |= C1_PUNCT;
    return t;
}

static WORD ctype2(WCHAR c)
{
    if (is_digit(c)) return C2_EUROPENUMBER;
    if (c == '+' || c == '-') return C2_EUROPESEPARATOR;
    if (c == '#' || c == '$' || c == '%') return C2_EUROPETERMINATOR;
    if (c == '.' || c == ',' || c == ':' || c == '/') return C2_COMMONSEPARATOR;
    if (c == ' ' || c == 0xa0 || (c >= 0x2000 && c <= 0x200a) || c == 0x3000) return C2_WHITESPACE;
    if (c == '\n' || c == '\r' || c == 0x2029) return C2_BLOCKSEPARATOR;
    if (c == '\t' || c == 0x0b || c == 0x1f) return C2_SEGMENTSEPARATOR;
    if ((c >= 0x5d0 && c <= 0x5ff) || (c >= 0xfb1d && c <= 0xfb4f)) return C2_RIGHTTOLEFT;
    if ((c >= 0x600 && c <= 0x6ff) || (c >= 0xfb50 && c <= 0xfdff) || (c >= 0xfe70 && c <= 0xfeff)) return C2_RIGHTTOLEFT;
    if (is_alpha(c)) return C2_LEFTTORIGHT;
    if (is_cntrl(c) || is_combining(c)) return C2_OTHERNEUTRAL;
    return C2_OTHERNEUTRAL;
}

static WORD ctype3(WCHAR c)
{
    WORD t = 0;
    if (is_combining(c)) t |= C3_NONSPACING | C3_DIACRITIC;
    if (is_punct(c) || (c >= 0x2190 && c <= 0x2bff)) t |= C3_SYMBOL;
    if (c >= 0x3041 && c <= 0x309f) t |= C3_HIRAGANA;
    if (c >= 0x30a0 && c <= 0x30ff) t |= C3_KATAKANA;
    if ((c >= 0x3400 && c <= 0x4dbf) || (c >= 0x4e00 && c <= 0x9fff)) t |= C3_IDEOGRAPH;
    if (c >= 0xff01 && c <= 0xff5e) t |= C3_FULLWIDTH;
    if (c >= 0xff61 && c <= 0xffdc) t |= C3_HALFWIDTH;
    if (is_alpha(c)) t |= C3_ALPHA;
    return t;
}

K32API BOOL WINAPI GetStringTypeW(DWORD type, LPCWSTR s, int n, LPWORD out)
{
    int i;
    if (!s || !out) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (n < 0) n = lstrlenW(s) + 1;
    for (i = 0; i < n; ++i) {
        switch (type) {
        case CT_CTYPE1: out[i] = ctype1(s[i]); break;
        case CT_CTYPE2: out[i] = ctype2(s[i]); break;
        case CT_CTYPE3: out[i] = ctype3(s[i]); break;
        default: SetLastError(ERROR_INVALID_FLAGS); return FALSE;
        }
    }
    return TRUE;
}
K32API BOOL WINAPI GetStringTypeExW(LCID lcid, DWORD type, LPCWSTR s, int n, LPWORD out)
{
    (void)lcid;
    return GetStringTypeW(type, s, n, out);
}
K32API BOOL WINAPI GetStringTypeA(LCID lcid, DWORD type, LPCSTR s, int n, LPWORD out)
{
    WCHAR buf[256], *w = buf;
    int wn;
    BOOL r;
    (void)lcid;
    if (!s || !out) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (n < 0) n = lstrlenA(s) + 1;
    if (n > 256 && !(w = HeapAlloc(GetProcessHeap(), 0, n * sizeof(WCHAR)))) return FALSE;
    for (wn = 0; wn < n; ++wn) w[wn] = (unsigned char)s[wn];                /* one type per byte, as documented */
    r = GetStringTypeW(type, w, n, out);
    if (w != buf) HeapFree(GetProcessHeap(), 0, w);
    return r;
}
K32API BOOL WINAPI GetStringTypeExA(LCID lcid, DWORD type, LPCSTR s, int n, LPWORD out) { return GetStringTypeA(lcid, type, s, n, out); }

/* ---------------------------------------------------------------- comparison */
typedef struct { const WCHAR *s; int n, i; } cursor;

static BOOL ignorable(WCHAR c, DWORD flags, int level)
{
    if ((flags & NORM_IGNORENONSPACE) && is_combining(c)) return TRUE;
    if ((flags & NORM_IGNORESYMBOLS) && (is_punct(c) || is_space(c))) return TRUE;
    if (level == 0 && !(flags & SORT_STRINGSORT) && (c == '-' || c == '\'' || c == 0xad)) return TRUE;
    return FALSE;
}

static int next_unit(cursor *c, DWORD flags, int level)
{
    while (c->i < c->n) {
        WCHAR ch = c->s[c->i++];
        if (!ignorable(ch, flags, level)) return ch;
    }
    return -1;
}

static int compare_level(const WCHAR *a, int an, const WCHAR *b, int bn, DWORD flags, int level)
{
    cursor x = { a, an, 0 }, y = { b, bn, 0 };
    for (;;) {
        int p = next_unit(&x, flags, level), q = next_unit(&y, flags, level);
        if (p < 0 || q < 0) return p < 0 ? (q < 0 ? 0 : -1) : 1;
        if (level == 0 || (level == 2 && (flags & NORM_IGNORECASE))) { p = wupper((WCHAR)p); q = wupper((WCHAR)q); }
        else if (level == 1) {
            if (flags & NORM_IGNORECASE) { p = wupper((WCHAR)p); q = wupper((WCHAR)q); }
            else if (wupper((WCHAR)p) == wupper((WCHAR)q) && p != q) return wlower((WCHAR)p) == p ? -1 : 1;  /* lower first */
        }
        if (p != q) return p < q ? -1 : 1;
    }
}

K32API int WINAPI CompareStringW(LCID lcid, DWORD flags, LPCWSTR a, int an, LPCWSTR b, int bn)
{
    int r;
    (void)lcid;
    if (!a || !b) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (an < 0) an = lstrlenW(a);
    if (bn < 0) bn = lstrlenW(b);
    if (!(r = compare_level(a, an, b, bn, flags, 0)) && !(r = compare_level(a, an, b, bn, flags, 1)) &&
        !(flags & SORT_STRINGSORT))
        r = compare_level(a, an, b, bn, flags | SORT_STRINGSORT, 2);        /* word sort: the ignored hyphens decide last */
    return r < 0 ? CSTR_LESS_THAN : r > 0 ? CSTR_GREATER_THAN : CSTR_EQUAL;
}

K32API int WINAPI CompareStringEx(LPCWSTR locale, DWORD flags, LPCWSTR a, int an, LPCWSTR b, int bn, LPNLSVERSIONINFO v,
                                  LPVOID reserved, LPARAM param)
{
    (void)v; (void)reserved; (void)param;
    if (locale && !name_to_lcid(locale)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return CompareStringW(SHZ_LCID, flags & ~LINGUISTIC_IGNORECASE, a, an, b, bn) ;
}

static WCHAR *a_to_w(LPCSTR s, int n, int *outn)
{
    int wn;
    WCHAR *w;
    if (n < 0) n = lstrlenA(s) + 1;
    wn = MultiByteToWideChar(CP_ACP, 0, s, n, NULL, 0);
    if (!(w = HeapAlloc(GetProcessHeap(), 0, (wn + 1) * sizeof(WCHAR)))) return NULL;
    MultiByteToWideChar(CP_ACP, 0, s, n, w, wn);
    *outn = wn;
    return w;
}

K32API int WINAPI CompareStringA(LCID lcid, DWORD flags, LPCSTR a, int an, LPCSTR b, int bn)
{
    WCHAR *wa, *wb;
    int na, nb, r;
    if (!a || !b) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (an < 0) an = lstrlenA(a);
    if (bn < 0) bn = lstrlenA(b);
    wa = a_to_w(a, an, &na);
    wb = a_to_w(b, bn, &nb);
    r = (wa && wb) ? CompareStringW(lcid, flags, wa, na, wb, nb) : 0;
    if (wa) HeapFree(GetProcessHeap(), 0, wa);
    if (wb) HeapFree(GetProcessHeap(), 0, wb);
    return r;
}

/* ---------------------------------------------------------------- mapping */
K32API int WINAPI LCMapStringW(LCID lcid, DWORD flags, LPCWSTR src, int n, LPWSTR dst, int cap)
{
    int i, out;
    if (!src || cap < 0 || (cap && !dst)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (n < 0) n = lstrlenW(src) + 1;
    if (flags & LCMAP_SORTKEY) {
        /* primary: upper-cased units (big endian, ignorables skipped), 01, tertiary: case bits, 01 01, 00 */
        BYTE *key = (BYTE *)dst;
        int k = 0, len = n;
        if (len && !src[len - 1]) len--;
#define PUT(b) do { if (cap && k < cap) key[k] = (BYTE)(b); k++; } while (0)
        for (i = 0; i < len; ++i) {
            WCHAR c = src[i];
            if (ignorable(c, flags, 0)) continue;
            c = wupper(c);
            PUT(c >> 8); PUT(c & 0xff);
        }
        PUT(1);
        if (!(flags & NORM_IGNORECASE))
            for (i = 0; i < len; ++i) if (!ignorable(src[i], flags, 0)) PUT(wlower(src[i]) == src[i] ? 1 : 2);
        PUT(1); PUT(1); PUT(0);
#undef PUT
        if (cap && k > cap) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
        return k;
    }
    if (!cap) return n;
    if (cap < n) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
    for (i = 0, out = 0; i < n; ++i) {
        WCHAR c = src[i];
        if (flags & LCMAP_UPPERCASE) c = wupper(c);
        else if (flags & LCMAP_LOWERCASE) c = wlower(c);
        dst[out++] = c;
    }
    (void)lcid;
    return out;
}

K32API int WINAPI LCMapStringEx(LPCWSTR locale, DWORD flags, LPCWSTR src, int n, LPWSTR dst, int cap, LPNLSVERSIONINFO v,
                                LPVOID reserved, LPARAM param)
{
    (void)v; (void)reserved; (void)param;
    if (locale && !name_to_lcid(locale)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return LCMapStringW(SHZ_LCID, flags, src, n, dst, cap);
}

K32API int WINAPI LCMapStringA(LCID lcid, DWORD flags, LPCSTR src, int n, LPSTR dst, int cap)
{
    WCHAR *w, *o;
    int wn, r, on;
    if (!src) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!(w = a_to_w(src, n, &wn))) return 0;
    if (flags & LCMAP_SORTKEY) {
        r = LCMapStringW(lcid, flags, w, wn, (LPWSTR)dst, cap);
        HeapFree(GetProcessHeap(), 0, w);
        return r;
    }
    if (!(o = HeapAlloc(GetProcessHeap(), 0, (wn + 1) * sizeof(WCHAR)))) { HeapFree(GetProcessHeap(), 0, w); return 0; }
    on = LCMapStringW(lcid, flags, w, wn, o, wn);
    r = on ? WideCharToMultiByte(CP_ACP, 0, o, on, dst, cap, NULL, NULL) : 0;
    HeapFree(GetProcessHeap(), 0, o);
    HeapFree(GetProcessHeap(), 0, w);
    return r;
}

/* ---------------------------------------------------------------- GetLocaleInfo */
struct lcinfo { LCTYPE type; const WCHAR *en_us, *invariant; };
static const struct lcinfo locale_table[] = {
    { LOCALE_ILANGUAGE, L"0409", L"007f" },
    { LOCALE_SLANGUAGE, L"English (United States)", L"Invariant Language (Invariant Country)" },
    { LOCALE_SENGLANGUAGE, L"English", L"Invariant Language" },
    { LOCALE_SABBREVLANGNAME, L"ENU", L"IVL" },
    { LOCALE_SNATIVELANGNAME, L"English", L"Invariant Language" },
    { LOCALE_ICOUNTRY, L"1", L"1" },
    { LOCALE_SCOUNTRY, L"United States", L"Invariant Country" },
    { LOCALE_SENGCOUNTRY, L"United States", L"Invariant Country" },
    { LOCALE_SABBREVCTRYNAME, L"USA", L"IVC" },
    { LOCALE_SNATIVECTRYNAME, L"United States", L"Invariant Country" },
    { LOCALE_IDEFAULTLANGUAGE, L"0409", L"0409" },
    { LOCALE_IDEFAULTCOUNTRY, L"1", L"1" },
    { LOCALE_IDEFAULTCODEPAGE, L"65001", L"65001" },
    { LOCALE_IDEFAULTANSICODEPAGE, L"65001", L"65001" },
    { LOCALE_IDEFAULTMACCODEPAGE, L"10000", L"10000" },
    { LOCALE_IDEFAULTEBCDICCODEPAGE, L"037", L"037" },
    { LOCALE_SLIST, L",", L"," },
    { LOCALE_IMEASURE, L"1", L"0" },
    { LOCALE_SDECIMAL, L".", L"." },
    { LOCALE_STHOUSAND, L",", L"," },
    { LOCALE_SGROUPING, L"3;0", L"3;0" },
    { LOCALE_IDIGITS, L"2", L"2" },
    { LOCALE_ILZERO, L"1", L"1" },
    { LOCALE_INEGNUMBER, L"1", L"1" },
    { LOCALE_SNATIVEDIGITS, L"0123456789", L"0123456789" },
    { LOCALE_IDIGITSUBSTITUTION, L"1", L"1" },
    { LOCALE_SCURRENCY, L"$", L"\x00a4" },
    { LOCALE_SINTLSYMBOL, L"USD", L"XDR" },
    { LOCALE_SENGCURRNAME, L"US Dollar", L"International Monetary Fund" },
    { LOCALE_SNATIVECURRNAME, L"US Dollar", L"International Monetary Fund" },
    { LOCALE_SMONDECIMALSEP, L".", L"." },
    { LOCALE_SMONTHOUSANDSEP, L",", L"," },
    { LOCALE_SMONGROUPING, L"3;0", L"3;0" },
    { LOCALE_ICURRDIGITS, L"2", L"2" },
    { LOCALE_IINTLCURRDIGITS, L"2", L"2" },
    { LOCALE_ICURRENCY, L"0", L"0" },
    { LOCALE_INEGCURR, L"0", L"0" },
    { LOCALE_SPOSITIVESIGN, L"", L"+" },
    { LOCALE_SNEGATIVESIGN, L"-", L"-" },
    { LOCALE_IPOSSIGNPOSN, L"3", L"3" },
    { LOCALE_INEGSIGNPOSN, L"0", L"0" },
    { LOCALE_IPOSSYMPRECEDES, L"1", L"1" },
    { LOCALE_IPOSSEPBYSPACE, L"0", L"0" },
    { LOCALE_INEGSYMPRECEDES, L"1", L"1" },
    { LOCALE_INEGSEPBYSPACE, L"0", L"0" },
    { LOCALE_SDATE, L"/", L"/" },
    { LOCALE_STIME, L":", L":" },
    { LOCALE_SSHORTDATE, L"M/d/yyyy", L"MM/dd/yyyy" },
    { LOCALE_SLONGDATE, L"dddd, MMMM d, yyyy", L"dddd, dd MMMM yyyy" },
    { LOCALE_SYEARMONTH, L"MMMM yyyy", L"yyyy MMMM" },
    { LOCALE_STIMEFORMAT, L"h:mm:ss tt", L"HH:mm:ss" },
    { LOCALE_SSHORTTIME, L"h:mm tt", L"HH:mm" },
    { LOCALE_SDURATION, L"h:mm:ss", L"h:mm:ss" },
    { LOCALE_IDATE, L"0", L"0" },
    { LOCALE_ILDATE, L"0", L"1" },
    { LOCALE_ITIME, L"0", L"1" },
    { LOCALE_ITIMEMARKPOSN, L"0", L"0" },
    { LOCALE_ICENTURY, L"1", L"1" },
    { LOCALE_ITLZERO, L"0", L"1" },
    { LOCALE_IDAYLZERO, L"0", L"1" },
    { LOCALE_IMONLZERO, L"0", L"1" },
    { LOCALE_S1159, L"AM", L"AM" },
    { LOCALE_S2359, L"PM", L"PM" },
    { LOCALE_ICALENDARTYPE, L"1", L"1" },
    { LOCALE_IOPTIONALCALENDAR, L"0", L"0" },
    { LOCALE_IFIRSTDAYOFWEEK, L"6", L"0" },
    { LOCALE_IFIRSTWEEKOFYEAR, L"0", L"0" },
    { LOCALE_SDAYNAME1, L"Monday", L"Monday" }, { LOCALE_SDAYNAME2, L"Tuesday", L"Tuesday" },
    { LOCALE_SDAYNAME3, L"Wednesday", L"Wednesday" }, { LOCALE_SDAYNAME4, L"Thursday", L"Thursday" },
    { LOCALE_SDAYNAME5, L"Friday", L"Friday" }, { LOCALE_SDAYNAME6, L"Saturday", L"Saturday" },
    { LOCALE_SDAYNAME7, L"Sunday", L"Sunday" },
    { LOCALE_SABBREVDAYNAME1, L"Mon", L"Mon" }, { LOCALE_SABBREVDAYNAME2, L"Tue", L"Tue" },
    { LOCALE_SABBREVDAYNAME3, L"Wed", L"Wed" }, { LOCALE_SABBREVDAYNAME4, L"Thu", L"Thu" },
    { LOCALE_SABBREVDAYNAME5, L"Fri", L"Fri" }, { LOCALE_SABBREVDAYNAME6, L"Sat", L"Sat" },
    { LOCALE_SABBREVDAYNAME7, L"Sun", L"Sun" },
    { LOCALE_SSHORTESTDAYNAME1, L"Mo", L"Mo" }, { LOCALE_SSHORTESTDAYNAME2, L"Tu", L"Tu" },
    { LOCALE_SSHORTESTDAYNAME3, L"We", L"We" }, { LOCALE_SSHORTESTDAYNAME4, L"Th", L"Th" },
    { LOCALE_SSHORTESTDAYNAME5, L"Fr", L"Fr" }, { LOCALE_SSHORTESTDAYNAME6, L"Sa", L"Sa" },
    { LOCALE_SSHORTESTDAYNAME7, L"Su", L"Su" },
    { LOCALE_SMONTHNAME1, L"January", L"January" }, { LOCALE_SMONTHNAME2, L"February", L"February" },
    { LOCALE_SMONTHNAME3, L"March", L"March" }, { LOCALE_SMONTHNAME4, L"April", L"April" },
    { LOCALE_SMONTHNAME5, L"May", L"May" }, { LOCALE_SMONTHNAME6, L"June", L"June" },
    { LOCALE_SMONTHNAME7, L"July", L"July" }, { LOCALE_SMONTHNAME8, L"August", L"August" },
    { LOCALE_SMONTHNAME9, L"September", L"September" }, { LOCALE_SMONTHNAME10, L"October", L"October" },
    { LOCALE_SMONTHNAME11, L"November", L"November" }, { LOCALE_SMONTHNAME12, L"December", L"December" },
    { LOCALE_SMONTHNAME13, L"", L"" },
    { LOCALE_SABBREVMONTHNAME1, L"Jan", L"Jan" }, { LOCALE_SABBREVMONTHNAME2, L"Feb", L"Feb" },
    { LOCALE_SABBREVMONTHNAME3, L"Mar", L"Mar" }, { LOCALE_SABBREVMONTHNAME4, L"Apr", L"Apr" },
    { LOCALE_SABBREVMONTHNAME5, L"May", L"May" }, { LOCALE_SABBREVMONTHNAME6, L"Jun", L"Jun" },
    { LOCALE_SABBREVMONTHNAME7, L"Jul", L"Jul" }, { LOCALE_SABBREVMONTHNAME8, L"Aug", L"Aug" },
    { LOCALE_SABBREVMONTHNAME9, L"Sep", L"Sep" }, { LOCALE_SABBREVMONTHNAME10, L"Oct", L"Oct" },
    { LOCALE_SABBREVMONTHNAME11, L"Nov", L"Nov" }, { LOCALE_SABBREVMONTHNAME12, L"Dec", L"Dec" },
    { LOCALE_SABBREVMONTHNAME13, L"", L"" },
    { LOCALE_SISO639LANGNAME, L"en", L"iv" },
    { LOCALE_SISO3166CTRYNAME, L"US", L"IV" },
    { LOCALE_SISO639LANGNAME2, L"eng", L"ivl" },
    { LOCALE_SISO3166CTRYNAME2, L"USA", L"ivc" },
    { LOCALE_SNAME, L"en-US", L"" },
    { LOCALE_SPARENT, L"en", L"" },
    { LOCALE_SSCRIPTS, L"Latn;", L"Latn;" },
    { LOCALE_SENGLISHDISPLAYNAME, L"English (United States)", L"Invariant Language (Invariant Country)" },
    { LOCALE_SNATIVEDISPLAYNAME, L"English (United States)", L"Invariant Language (Invariant Country)" },
    { LOCALE_SPERCENT, L"%", L"%" },
    { LOCALE_SPERMILLE, L"\x2030", L"\x2030" },
    { LOCALE_SNAN, L"NaN", L"NaN" },
    { LOCALE_SPOSINFINITY, L"\x221e", L"Infinity" },
    { LOCALE_SNEGINFINITY, L"-\x221e", L"-Infinity" },
    { LOCALE_IREADINGLAYOUT, L"0", L"0" },
    { LOCALE_IPAPERSIZE, L"1", L"9" },
    { LOCALE_SKEYBOARDSTOINSTALL, L"0409:00000409", L"0409:00000409" },
    { LOCALE_SCONSOLEFALLBACKNAME, L"en-US", L"" },
    { LOCALE_SOPENTYPELANGUAGETAG, L"ENG", L"dflt" },
};

K32API int WINAPI GetLocaleInfoW(LCID lcid, LCTYPE type, LPWSTR buf, int cap)
{
    LCID l = resolve_lcid(lcid);
    LCTYPE t = type & ~(LOCALE_NOUSEROVERRIDE | LOCALE_USE_CP_ACP | LOCALE_RETURN_NUMBER | LOCALE_RETURN_GENITIVE_NAMES |
                        LOCALE_ALLOW_NEUTRAL_NAMES);
    unsigned i;
    if (!l || cap < 0 || (cap && !buf)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    for (i = 0; i < sizeof locale_table / sizeof locale_table[0]; ++i) {
        const WCHAR *v;
        if (locale_table[i].type != t) continue;
        v = l == LOCALE_INVARIANT ? locale_table[i].invariant : locale_table[i].en_us;
        if (type & LOCALE_RETURN_NUMBER) {
            DWORD num = 0;
            const WCHAR *p = v;
            if (!*p || *p < '0' || *p > '9') { SetLastError(ERROR_INVALID_FLAGS); return 0; }
            if (t == LOCALE_ILANGUAGE || t == LOCALE_IDEFAULTLANGUAGE)
                for (; *p; ++p) num = num * 16 + (*p <= '9' ? *p - '0' : (*p | 0x20) - 'a' + 10);
            else
                for (; *p >= '0' && *p <= '9'; ++p) num = num * 10 + (*p - '0');
            if (!cap) return sizeof(DWORD) / sizeof(WCHAR);
            if (cap < (int)(sizeof(DWORD) / sizeof(WCHAR))) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
            memcpy(buf, &num, sizeof num);
            return sizeof(DWORD) / sizeof(WCHAR);
        }
        return copy_w(v, buf, cap);
    }
    SetLastError(ERROR_INVALID_FLAGS);
    return 0;
}

K32API int WINAPI GetLocaleInfoEx(LPCWSTR locale, LCTYPE type, LPWSTR buf, int cap)
{
    LCID l = name_to_lcid(locale);
    if (!l) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return GetLocaleInfoW(l, type, buf, cap);
}

K32API int WINAPI GetLocaleInfoA(LCID lcid, LCTYPE type, LPSTR buf, int cap)
{
    WCHAR w[128];
    int n;
    if (type & LOCALE_RETURN_NUMBER) {
        n = GetLocaleInfoW(lcid, type, w, 2);
        if (!n) return 0;
        if (!cap) return sizeof(DWORD);
        if (cap < (int)sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
        memcpy(buf, w, sizeof(DWORD));
        return sizeof(DWORD);
    }
    if (!(n = GetLocaleInfoW(lcid, type, w, ARRAYSIZE(w)))) return 0;
    n = WideCharToMultiByte(CP_ACP, 0, w, -1, cap ? buf : NULL, cap, NULL, NULL);
    if (!n && cap) SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return n;
}

/* ---------------------------------------------------------------- date / time formatting */
static int day_of_week(int y, int m, int d)                      /* 0 = Sunday (Sakamoto) */
{
    static const int t[] = { 0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4 };
    if (m < 3) y -= 1;
    return (y + y / 4 - y / 100 + y / 400 + t[m - 1] + d) % 7;
}

typedef struct { WCHAR *out; int cap, n; BOOL overflow; } wbuf;
static void put_c(wbuf *b, WCHAR c) { if (b->cap) { if (b->n < b->cap) b->out[b->n] = c; else b->overflow = TRUE; } b->n++; }
static void put_s(wbuf *b, const WCHAR *s) { while (*s) put_c(b, *s++); }
static void put_num(wbuf *b, int v, int width)
{
    WCHAR t[12];
    int k = 0;
    do { t[k++] = (WCHAR)('0' + v % 10); v /= 10; } while (v);
    while (k < width) t[k++] = '0';
    while (k) put_c(b, t[--k]);
}
static const WCHAR *lc_str(LCID l, LCTYPE t)
{
    unsigned i;
    for (i = 0; i < sizeof locale_table / sizeof locale_table[0]; ++i)
        if (locale_table[i].type == t) return l == LOCALE_INVARIANT ? locale_table[i].invariant : locale_table[i].en_us;
    return L"";
}

static int format_picture(LCID l, const SYSTEMTIME *st, LPCWSTR fmt, BOOL is_date, DWORD tflags, LPWSTR out, int cap)
{
    wbuf b = { out, cap, 0, FALSE };
    const WCHAR *p = fmt;
    while (*p) {
        WCHAR c = *p;
        int n = 1;
        if (c == '\'') {                                          /* quoted literal; '' is a quote */
            ++p;
            while (*p) {
                if (*p == '\'') { if (p[1] == '\'') { put_c(&b, '\''); p += 2; continue; } ++p; break; }
                put_c(&b, *p++);
            }
            continue;
        }
        while (p[n] == c) n++;
        if (is_date && c == 'd') {
            if (n <= 2) put_num(&b, st->wDay, n);
            else put_s(&b, lc_str(l, (n == 3 ? LOCALE_SABBREVDAYNAME1 : LOCALE_SDAYNAME1) + (st->wDayOfWeek + 6) % 7));
        } else if (is_date && c == 'M') {
            if (n <= 2) put_num(&b, st->wMonth, n);
            else put_s(&b, lc_str(l, (n == 3 ? LOCALE_SABBREVMONTHNAME1 : LOCALE_SMONTHNAME1) + st->wMonth - 1));
        } else if (is_date && c == 'y') {
            if (n <= 2) put_num(&b, st->wYear % 100, n);
            else put_num(&b, st->wYear, 1);
        } else if (is_date && c == 'g') {
            put_s(&b, L"A.D.");
        } else if (!is_date && (c == 'h' || c == 'H')) {
            int h = st->wHour;
            if (c == 'h' && !(tflags & TIME_FORCE24HOURFORMAT)) { h %= 12; if (!h) h = 12; }
            put_num(&b, h, n >= 2 ? 2 : 1);
        } else if (!is_date && c == 'm') {
            if (!(tflags & TIME_NOMINUTESORSECONDS)) put_num(&b, st->wMinute, n >= 2 ? 2 : 1);
        } else if (!is_date && c == 's') {
            if (!(tflags & (TIME_NOSECONDS | TIME_NOMINUTESORSECONDS))) put_num(&b, st->wSecond, n >= 2 ? 2 : 1);
        } else if (!is_date && c == 't') {
            if (!(tflags & TIME_NOTIMEMARKER)) {
                const WCHAR *m = lc_str(l, st->wHour < 12 ? LOCALE_S1159 : LOCALE_S2359);
                if (n == 1) put_c(&b, m[0]); else put_s(&b, m);
            }
        } else {
            int k;
            for (k = 0; k < n; ++k) put_c(&b, c);
        }
        p += n;
    }
    put_c(&b, 0);
    if (b.overflow) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
    return b.n;
}

/* The minute/second separators that TIME_NOSECONDS / TIME_NOMINUTESORSECONDS remove with their field. */
static void strip_time_fields(const WCHAR *in, WCHAR *out, int cap, DWORD flags)
{
    int k = 0;
    const WCHAR *p = in;
    while (*p && k < cap - 1) {
        if (((flags & TIME_NOMINUTESORSECONDS) && (*p == 'm' || *p == 's')) || ((flags & TIME_NOSECONDS) && *p == 's')) {
            while (k > 0 && out[k - 1] != 'h' && out[k - 1] != 'H' && out[k - 1] != 'm' && out[k - 1] != ' ' && out[k - 1] != 't') k--;
            while (*p == 'm' || *p == 's') p++;
            continue;
        }
        out[k++] = *p++;
    }
    out[k] = 0;
}

K32API int WINAPI GetDateFormatW(LCID lcid, DWORD flags, const SYSTEMTIME *st, LPCWSTR fmt, LPWSTR out, int cap)
{
    LCID l = resolve_lcid(lcid);
    SYSTEMTIME t;
    FILETIME ft;
    if (!l || cap < 0 || (cap && !out) || (fmt && (flags & (DATE_SHORTDATE | DATE_LONGDATE | DATE_YEARMONTH)))) {
        SetLastError(fmt ? ERROR_INVALID_FLAGS : ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (st) {
        t = *st;
        if (!SystemTimeToFileTime(&t, &ft)) {
            t.wHour = t.wMinute = t.wSecond = t.wMilliseconds = 0;           /* the time part is not validated */
            if (!SystemTimeToFileTime(&t, &ft)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
        }
    } else GetLocalTime(&t);
    t.wDayOfWeek = (WORD)day_of_week(t.wYear, t.wMonth, t.wDay);
    if (!fmt) fmt = lc_str(l, (flags & DATE_LONGDATE) ? LOCALE_SLONGDATE : (flags & DATE_YEARMONTH) ? LOCALE_SYEARMONTH : LOCALE_SSHORTDATE);
    return format_picture(l, &t, fmt, TRUE, 0, out, cap);
}

K32API int WINAPI GetTimeFormatW(LCID lcid, DWORD flags, const SYSTEMTIME *st, LPCWSTR fmt, LPWSTR out, int cap)
{
    LCID l = resolve_lcid(lcid);
    SYSTEMTIME t;
    WCHAR pic[80];
    if (!l || cap < 0 || (cap && !out)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (st) {
        t = *st;
        if (t.wHour > 23 || t.wMinute > 59 || t.wSecond > 59 || t.wMilliseconds > 999) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    } else GetLocalTime(&t);
    if (!fmt) {
        strip_time_fields(lc_str(l, LOCALE_STIMEFORMAT), pic, ARRAYSIZE(pic), flags);
        fmt = pic;
    }
    return format_picture(l, &t, fmt, FALSE, flags, out, cap);
}

K32API int WINAPI GetDateFormatEx(LPCWSTR locale, DWORD flags, const SYSTEMTIME *st, LPCWSTR fmt, LPWSTR out, int cap, LPCWSTR cal)
{
    LCID l = name_to_lcid(locale);
    (void)cal;
    if (!l) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return GetDateFormatW(l, flags, st, fmt, out, cap);
}
K32API int WINAPI GetTimeFormatEx(LPCWSTR locale, DWORD flags, const SYSTEMTIME *st, LPCWSTR fmt, LPWSTR out, int cap)
{
    LCID l = name_to_lcid(locale);
    if (!l) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return GetTimeFormatW(l, flags, st, fmt, out, cap);
}

static int format_a(BOOL date, LCID lcid, DWORD flags, const SYSTEMTIME *st, LPCSTR fmt, LPSTR out, int cap)
{
    WCHAR wfmt[128], wout[256];
    int n;
    if (fmt && !MultiByteToWideChar(CP_ACP, 0, fmt, -1, wfmt, ARRAYSIZE(wfmt))) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    n = date ? GetDateFormatW(lcid, flags, st, fmt ? wfmt : NULL, wout, ARRAYSIZE(wout))
             : GetTimeFormatW(lcid, flags, st, fmt ? wfmt : NULL, wout, ARRAYSIZE(wout));
    if (!n) return 0;
    n = WideCharToMultiByte(CP_ACP, 0, wout, -1, cap ? out : NULL, cap, NULL, NULL);
    if (!n && cap) SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return n;
}
K32API int WINAPI GetDateFormatA(LCID lcid, DWORD flags, const SYSTEMTIME *st, LPCSTR fmt, LPSTR out, int cap)
{
    return format_a(TRUE, lcid, flags, st, fmt, out, cap);
}
K32API int WINAPI GetTimeFormatA(LCID lcid, DWORD flags, const SYSTEMTIME *st, LPCSTR fmt, LPSTR out, int cap)
{
    return format_a(FALSE, lcid, flags, st, fmt, out, cap);
}
