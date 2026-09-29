/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: National Language Support on top of the Unicode tables in nls_core.c / nls_fmt.c.
 *
 * Locales. Exactly two locales exist: en-US (LCID 0x0409, name "en-US") and the invariant locale (LOCALE_INVARIANT 0x007F,
 * name ""). LOCALE_USER_DEFAULT (0x0400) and LOCALE_SYSTEM_DEFAULT (0x0800) resolve to en-US. Every other LCID or locale
 * name is reported as it would be for a locale that does not exist: ERROR_INVALID_PARAMETER, IsValidLocale == FALSE.
 * LCTYPE values the tables do not carry fail with ERROR_INVALID_FLAGS. Unicode data comes from unidata.h (UNI_VERSION),
 * not from Windows' NLS files; collation is the documented model in nls_core.c. There are no user overrides
 * (LOCALE_NOUSEROVERRIDE and LOCALE_USE_CP_ACP are accepted and change nothing: the ANSI code page is UTF-8).
 */
#include "k32.h"
#include "nls_core.h"
#include "nls_fmt.h"

#define LCID_ENUS 0x0409
#define LCID_INV 0x007f
#define NA ((const WCHAR *)1)
#define SAME ((const WCHAR *)0)

/* ---------------------------------------------------------------- locale identification */
static int lcid_kind(LCID l, int allow_neutral)
{
    switch (l) {
    case 0x0400: case 0x0800: case LCID_ENUS: return 1;
    case LCID_INV: return 2;
    case 0: return allow_neutral ? 2 : 0;
    default: return 0;
    }
}

static int ieq_ascii(const WCHAR *a, const char *b)
{
    for (; *a && *b; ++a, ++b) {
        WCHAR x = *a, y = (WCHAR)(unsigned char)*b;
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y) return 0;
    }
    return !*a && !*b;
}

static int name_kind(LPCWSTR name)
{
    if (!name) return 1;                                      /* LOCALE_NAME_USER_DEFAULT */
    if (!name[0]) return 2;                                   /* LOCALE_NAME_INVARIANT */
    if (ieq_ascii(name, "en-US") || ieq_ascii(name, "!x-sys-default-locale")) return 1;
    return 0;
}

/* Copies a NUL-terminated wide string with the GetLocaleInfo return convention (count including the terminator). */
static int give_w(const WCHAR *s, LPWSTR buf, int cch)
{
    const int n = (int)k32_wlen(s) + 1;
    if (cch == 0) return n;
    if (cch < n) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
    memcpy(buf, s, (size_t)n * sizeof(WCHAR));
    return n;
}

/* ---------------------------------------------------------------- GetLocaleInfo tables */
typedef struct { DWORD type; const WCHAR *us, *inv; BYTE num; } li_row;
#define R(t, us, inv) { t, us, inv, 0 }
#define RN(t, us, inv) { t, us, inv, 1 }
static const li_row li_rows[] = {
    R(LOCALE_ILANGUAGE, L"0409", L"007F"),
    R(LOCALE_SLANGUAGE, L"English (United States)", L"Invariant Language (Invariant Country)"),
    R(LOCALE_SENGLANGUAGE, L"English", L"Invariant Language"),
    R(LOCALE_SABBREVLANGNAME, L"ENU", NA),
    R(LOCALE_SNATIVELANGNAME, L"English", L"Invariant Language"),
    RN(LOCALE_ICOUNTRY, L"1", NA),
    R(LOCALE_SCOUNTRY, L"United States", L"Invariant Country"),
    R(LOCALE_SENGCOUNTRY, L"United States", L"Invariant Country"),
    R(LOCALE_SABBREVCTRYNAME, L"USA", NA),
    R(LOCALE_SNATIVECTRYNAME, L"United States", L"Invariant Country"),
    R(LOCALE_IDEFAULTLANGUAGE, L"0409", NA),
    RN(LOCALE_IDEFAULTCOUNTRY, L"1", NA),
    RN(LOCALE_IDEFAULTCODEPAGE, L"437", NA),
    RN(LOCALE_IDEFAULTANSICODEPAGE, L"1252", NA),
    RN(LOCALE_IDEFAULTMACCODEPAGE, L"10000", NA),
    R(LOCALE_SLIST, L",", SAME),
    RN(LOCALE_IMEASURE, L"1", NA),
    R(LOCALE_SDECIMAL, L".", SAME),
    R(LOCALE_STHOUSAND, L",", SAME),
    R(LOCALE_SGROUPING, L"3;0", SAME),
    RN(LOCALE_IDIGITS, L"2", SAME),
    RN(LOCALE_ILZERO, L"1", SAME),
    RN(LOCALE_INEGNUMBER, L"1", SAME),
    R(LOCALE_SNATIVEDIGITS, L"0123456789", SAME),
    R(LOCALE_SCURRENCY, L"$", L"\x00a4"),
    R(LOCALE_SINTLSYMBOL, L"USD", NA),
    R(LOCALE_SMONDECIMALSEP, L".", SAME),
    R(LOCALE_SMONTHOUSANDSEP, L",", SAME),
    R(LOCALE_SMONGROUPING, L"3;0", SAME),
    RN(LOCALE_ICURRDIGITS, L"2", SAME),
    RN(LOCALE_IINTLCURRDIGITS, L"2", NA),
    RN(LOCALE_ICURRENCY, L"0", SAME),
    RN(LOCALE_INEGCURR, L"0", SAME),
    R(LOCALE_SDATE, L"/", SAME),
    R(LOCALE_STIME, L":", SAME),
    R(LOCALE_SSHORTDATE, L"M/d/yyyy", L"MM/dd/yyyy"),
    R(LOCALE_SLONGDATE, L"dddd, MMMM d, yyyy", L"dddd, dd MMMM yyyy"),
    R(LOCALE_STIMEFORMAT, L"h:mm:ss tt", L"HH:mm:ss"),
    R(LOCALE_SSHORTTIME, L"h:mm tt", L"HH:mm"),
    R(LOCALE_SYEARMONTH, L"MMMM yyyy", L"yyyy MMMM"),
    RN(LOCALE_IDATE, L"0", SAME),
    RN(LOCALE_ILDATE, L"0", L"1"),
    RN(LOCALE_ITIME, L"0", L"1"),
    RN(LOCALE_ITIMEMARKPOSN, L"0", SAME),
    RN(LOCALE_ICENTURY, L"1", SAME),
    RN(LOCALE_ITLZERO, L"0", L"1"),
    RN(LOCALE_IDAYLZERO, L"0", L"1"),
    RN(LOCALE_IMONLZERO, L"0", L"1"),
    R(LOCALE_S1159, L"AM", SAME),
    R(LOCALE_S2359, L"PM", SAME),
    RN(LOCALE_ICALENDARTYPE, L"1", SAME),
    RN(LOCALE_IOPTIONALCALENDAR, L"0", SAME),
    RN(LOCALE_IFIRSTDAYOFWEEK, L"6", SAME),
    RN(LOCALE_IFIRSTWEEKOFYEAR, L"0", SAME),
    R(LOCALE_SPOSITIVESIGN, L"", SAME),
    R(LOCALE_SNEGATIVESIGN, L"-", SAME),
    RN(LOCALE_IPOSSIGNPOSN, L"3", NA),
    RN(LOCALE_INEGSIGNPOSN, L"0", NA),
    RN(LOCALE_IPOSSYMPRECEDES, L"1", NA),
    RN(LOCALE_IPOSSEPBYSPACE, L"0", NA),
    RN(LOCALE_INEGSYMPRECEDES, L"1", NA),
    RN(LOCALE_INEGSEPBYSPACE, L"0", NA),
    R(LOCALE_SISO639LANGNAME, L"en", L"iv"),
    R(LOCALE_SISO3166CTRYNAME, L"US", NA),
    R(LOCALE_SISO639LANGNAME2, L"eng", NA),
    R(LOCALE_SISO3166CTRYNAME2, L"USA", NA),
    R(LOCALE_SNAME, L"en-US", L""),
    R(LOCALE_SPARENT, L"en", L""),
    R(LOCALE_SENGCURRNAME, L"US Dollar", NA),
    R(LOCALE_SNATIVECURRNAME, L"US Dollar", NA),
    RN(LOCALE_IPAPERSIZE, L"1", NA),
    R(LOCALE_SSORTNAME, L"Default", NA),
    R(LOCALE_SLOCALIZEDLANGUAGENAME, L"English", NA),
    R(LOCALE_SENGLISHDISPLAYNAME, L"English (United States)", NA),
    R(LOCALE_SNATIVEDISPLAYNAME, L"English (United States)", NA),
    R(LOCALE_SKEYBOARDSTOINSTALL, L"00000409", NA),
    RN(LOCALE_IREADINGLAYOUT, L"0", SAME),
    R(LOCALE_SMONTHNAME13, L"", SAME),
    R(LOCALE_SABBREVMONTHNAME13, L"", SAME),
};

static const li_row *li_find(DWORD type)
{
    unsigned i;
    for (i = 0; i < sizeof li_rows / sizeof li_rows[0]; ++i)
        if (li_rows[i].type == type) return &li_rows[i];
    return 0;
}

static int decimal_value(const WCHAR *s)
{
    int v = 0;
    for (; *s; ++s) v = v * 10 + (*s - '0');
    return v;
}

static int getlocaleinfo_w(int kind, DWORD lctype, LPWSTR buf, int cch)
{
    const DWORD flags = lctype & 0xF8000000u, type = lctype & ~0xF8000000u;
    const WCHAR *s = 0;
    if (cch < 0 || (cch > 0 && !buf)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (flags & ~(DWORD)(LOCALE_NOUSEROVERRIDE | LOCALE_USE_CP_ACP | LOCALE_RETURN_NUMBER | LOCALE_RETURN_GENITIVE_NAMES |
                         LOCALE_ALLOW_NEUTRAL_NAMES)) { shz_set_last_error(ERROR_INVALID_FLAGS); return 0; }
    if ((type >= LOCALE_SDAYNAME1 && type <= LOCALE_SDAYNAME7)) s = nls_day_names[(type - LOCALE_SDAYNAME1 + 1) % 7];
    else if (type >= LOCALE_SABBREVDAYNAME1 && type <= LOCALE_SABBREVDAYNAME7) s = nls_day_abbrev[(type - LOCALE_SABBREVDAYNAME1 + 1) % 7];
    else if (type >= LOCALE_SSHORTESTDAYNAME1 && type <= LOCALE_SSHORTESTDAYNAME7) s = nls_day_shortest[(type - LOCALE_SSHORTESTDAYNAME1 + 1) % 7];
    else if (type >= LOCALE_SMONTHNAME1 && type <= LOCALE_SMONTHNAME12) s = nls_month_names[type - LOCALE_SMONTHNAME1];
    else if (type >= LOCALE_SABBREVMONTHNAME1 && type <= LOCALE_SABBREVMONTHNAME12) s = nls_month_abbrev[type - LOCALE_SABBREVMONTHNAME1];
    if (s) {
        if (flags & LOCALE_RETURN_NUMBER) { shz_set_last_error(ERROR_INVALID_FLAGS); return 0; }
        return give_w(s, buf, cch);
    }
    {
        const li_row *r = li_find(type);
        if (!r) { shz_set_last_error(ERROR_INVALID_FLAGS); return 0; }
        s = kind == 2 ? (r->inv == SAME ? r->us : r->inv) : r->us;
        if (s == NA) { shz_set_last_error(ERROR_INVALID_FLAGS); return 0; }       /* not carried for the invariant locale */
        if (flags & LOCALE_RETURN_NUMBER) {
            DWORD v;
            if (!r->num) { shz_set_last_error(ERROR_INVALID_FLAGS); return 0; }
            if (cch == 0) return (int)(sizeof(DWORD) / sizeof(WCHAR));
            if (cch < (int)(sizeof(DWORD) / sizeof(WCHAR))) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
            v = (DWORD)decimal_value(s);
            memcpy(buf, &v, sizeof v);
            return (int)(sizeof(DWORD) / sizeof(WCHAR));
        }
        return give_w(s, buf, cch);
    }
}

K32API int WINAPI GetLocaleInfoW(LCID loc, LCTYPE type, LPWSTR buf, int cch)
{
    const int kind = lcid_kind(loc, 0);
    if (!kind) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return getlocaleinfo_w(kind, type, buf, cch);
}
K32API int WINAPI GetLocaleInfoEx(LPCWSTR name, LCTYPE type, LPWSTR buf, int cch)
{
    const int kind = name_kind(name);
    if (!kind) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return getlocaleinfo_w(kind, type, buf, cch);
}
K32API int WINAPI GetLocaleInfoA(LCID loc, LCTYPE type, LPSTR buf, int cch)
{
    WCHAR w[128];
    int n, r;
    const int kind = lcid_kind(loc, 0);
    if (!kind) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (cch < 0 || (cch > 0 && !buf)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (type & LOCALE_RETURN_NUMBER) {                                    /* a DWORD either way; cch counts bytes here */
        int got;
        if (cch == 0) { if (!getlocaleinfo_w(kind, type, w, 0)) return 0; return (int)sizeof(DWORD); }
        if (cch < (int)sizeof(DWORD)) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
        got = getlocaleinfo_w(kind, type, w, 128);
        if (!got) return 0;
        memcpy(buf, w, sizeof(DWORD));
        return (int)sizeof(DWORD);
    }
    n = getlocaleinfo_w(kind, type, w, 128);
    if (!n) return 0;
    if (cch == 0) {
        char tmp[512];
        r = k32_wide_to_utf8(w, n, tmp, sizeof tmp);
        return r;
    }
    r = k32_wide_to_utf8(w, n, buf, cch);
    if (!r) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
    return r;
}

/* ---------------------------------------------------------------- default locale and identifiers */
K32API LCID WINAPI GetUserDefaultLCID(void) { return LCID_ENUS; }
K32API LCID WINAPI GetSystemDefaultLCID(void) { return LCID_ENUS; }
K32API LANGID WINAPI GetUserDefaultLangID(void) { return LCID_ENUS; }
K32API LANGID WINAPI GetSystemDefaultLangID(void) { return LCID_ENUS; }
K32API LANGID WINAPI GetUserDefaultUILanguage(void) { return LCID_ENUS; }
K32API LANGID WINAPI GetSystemDefaultUILanguage(void) { return LCID_ENUS; }
K32API LANGID WINAPI GetThreadUILanguage(void) { return LCID_ENUS; }

#define TEB_CURRENT_LOCALE 0x108                                   /* x64 TEB.CurrentLocale */
K32API LCID WINAPI GetThreadLocale(void)
{
    const DWORD l = *(volatile DWORD *)(shz_teb() + TEB_CURRENT_LOCALE);
    return l ? l : LCID_ENUS;
}
K32API BOOL WINAPI SetThreadLocale(LCID loc)
{
    const int k = lcid_kind(loc, 0);
    if (!k) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    *(volatile DWORD *)(shz_teb() + TEB_CURRENT_LOCALE) = loc == 0x0400 || loc == 0x0800 ? LCID_ENUS : loc;
    return TRUE;
}

K32API BOOL WINAPI IsValidLocale(LCID loc, DWORD flags)
{
    if (flags & ~(DWORD)(LCID_INSTALLED | LCID_SUPPORTED)) { shz_set_last_error(ERROR_INVALID_FLAGS); return FALSE; }
    return loc == LCID_ENUS || loc == LCID_INV;
}

K32API int WINAPI GetUserDefaultLocaleName(LPWSTR buf, int cch)
{
    if (cch < 0 || (cch > 0 && !buf)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return give_w(L"en-US", buf, cch);
}
K32API int WINAPI GetSystemDefaultLocaleName(LPWSTR buf, int cch) { return GetUserDefaultLocaleName(buf, cch); }

K32API LCID WINAPI LocaleNameToLCID(LPCWSTR name, DWORD flags)
{
    const int k = name_kind(name);
    if (flags & ~(DWORD)LOCALE_ALLOW_NEUTRAL_NAMES) { shz_set_last_error(ERROR_INVALID_FLAGS); return 0; }
    if (!k) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return k == 1 ? LCID_ENUS : LCID_INV;
}
K32API int WINAPI LCIDToLocaleName(LCID loc, LPWSTR buf, int cch, DWORD flags)
{
    const int k = lcid_kind(loc, 0);
    if (flags & ~(DWORD)LOCALE_ALLOW_NEUTRAL_NAMES) { shz_set_last_error(ERROR_INVALID_FLAGS); return 0; }
    if (!k) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (cch < 0 || (cch > 0 && !buf)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return give_w(k == 1 ? L"en-US" : L"", buf, cch);
}
K32API int WINAPI ResolveLocaleName(LPCWSTR name, LPWSTR out, int cch)
{
    const WCHAR *r;
    if (!name || cch < 0 || (cch > 0 && !out)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (!name[0]) r = L"";
    else if (name_kind(name) == 1 || ieq_ascii(name, "en")) r = L"en-US";      /* a neutral name resolves to its default specific locale */
    else { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return give_w(r, out, cch);
}

/* ---------------------------------------------------------------- enumeration */
K32API BOOL WINAPI EnumSystemLocalesW(LOCALE_ENUMPROCW proc, DWORD flags)
{
    static const WCHAR id[] = { '0', '0', '0', '0', '0', '4', '0', '9', 0 };
    WCHAR buf[9];
    if (!proc) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!flags || (flags & ~(DWORD)(LCID_INSTALLED | LCID_SUPPORTED | LCID_ALTERNATE_SORTS))) { shz_set_last_error(ERROR_INVALID_FLAGS); return FALSE; }
    if (flags & (LCID_INSTALLED | LCID_SUPPORTED)) { memcpy(buf, id, sizeof id); proc(buf); }
    return TRUE;                                                  /* no alternate sort orders exist */
}
K32API BOOL WINAPI EnumSystemLocalesEx(LOCALE_ENUMPROCEX proc, DWORD flags, LPARAM lparam, LPVOID reserved)
{
    WCHAR name[6];
    if (!proc || reserved) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (flags & ~(DWORD)(LOCALE_WINDOWS | LOCALE_SUPPLEMENTAL | LOCALE_ALTERNATE_SORTS | LOCALE_NEUTRALDATA | LOCALE_SPECIFICDATA)) {
        shz_set_last_error(ERROR_INVALID_FLAGS);
        return FALSE;
    }
    /* en-US is a Windows specific locale; there are no supplemental locales, alternate sorts or neutral-only entries. */
    if (flags == 0 || (flags & (LOCALE_WINDOWS | LOCALE_SPECIFICDATA))) {
        memcpy(name, L"en-US", 12);
        proc(name, LOCALE_WINDOWS | LOCALE_SPECIFICDATA, lparam);
    }
    return TRUE;
}

/* ---------------------------------------------------------------- collation */
#define CMP_KNOWN (NORM_IGNORECASE | NORM_IGNORENONSPACE | NORM_IGNORESYMBOLS | LINGUISTIC_IGNORECASE | LINGUISTIC_IGNOREDIACRITIC | \
                   NORM_LINGUISTIC_CASING | NORM_IGNOREKANATYPE | NORM_IGNOREWIDTH | SORT_STRINGSORT | SORT_DIGITSASNUMBERS | \
                   LOCALE_USE_CP_ACP)

static uint32_t core_flags(DWORD f)
{
    uint32_t c = f & (NORM_IGNORECASE | NORM_IGNORENONSPACE | NORM_IGNORESYMBOLS | SORT_STRINGSORT | SORT_DIGITSASNUMBERS |
                      NORM_IGNOREKANATYPE | NORM_IGNOREWIDTH);
    if (f & LINGUISTIC_IGNORECASE) c |= NORM_IGNORECASE;
    if (f & LINGUISTIC_IGNOREDIACRITIC) c |= NORM_IGNORENONSPACE;
    return c;
}

static int compare_w(int kind, DWORD flags, const WCHAR *a, int an, const WCHAR *b, int bn)
{
    int r;
    if (!kind) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (flags & ~(DWORD)CMP_KNOWN) { shz_set_last_error(ERROR_INVALID_FLAGS); return 0; }
    if (!a || !b || an < -1 || bn < -1) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (an == -1) an = (int)k32_wlen(a);
    if (bn == -1) bn = (int)k32_wlen(b);
    r = nls_compare(a, an, b, bn, core_flags(flags));
    shz_set_last_error(0);
    return r < 0 ? CSTR_LESS_THAN : r > 0 ? CSTR_GREATER_THAN : CSTR_EQUAL;
}

K32API int WINAPI CompareStringW(LCID loc, DWORD flags, PCNZWCH a, int an, PCNZWCH b, int bn)
{
    return compare_w(lcid_kind(loc, 1), flags, a, an, b, bn);
}
K32API int WINAPI CompareStringEx(LPCWSTR name, DWORD flags, LPCWCH a, int an, LPCWCH b, int bn, LPNLSVERSIONINFO ver, LPVOID reserved,
                                  LPARAM lparam)
{
    (void)ver;
    if (reserved || lparam) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return compare_w(name_kind(name), flags, a, an, b, bn);
}
K32API int WINAPI CompareStringA(LCID loc, DWORD flags, PCNZCH a, int an, PCNZCH b, int bn)
{
    WCHAR *wa, *wb;
    int na, nb, r;
    if (!a || !b || an < -1 || bn < -1) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (an == -1) an = lstrlenA(a);
    if (bn == -1) bn = lstrlenA(b);
    wa = RtlAllocateHeap(ShzProcessHeap(), 0, ((size_t)an + (size_t)bn + 2) * sizeof(WCHAR));
    if (!wa) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    wb = wa + an + 1;
    na = an ? k32_utf8_to_wide(a, an, wa, an + 1) : 0;
    nb = bn ? k32_utf8_to_wide(b, bn, wb, bn + 1) : 0;
    if ((an && !na) || (bn && !nb)) { RtlFreeHeap(ShzProcessHeap(), 0, wa); shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    r = CompareStringW(loc, flags, wa, na, wb, nb);
    RtlFreeHeap(ShzProcessHeap(), 0, wa);
    return r;
}

K32API int WINAPI lstrcmpW(LPCWSTR a, LPCWSTR b)
{
    const int r = CompareStringW(LOCALE_USER_DEFAULT, LOCALE_USE_CP_ACP, a ? a : L"", -1, b ? b : L"", -1);
    return r ? r - 2 : 0;
}
K32API int WINAPI lstrcmpiW(LPCWSTR a, LPCWSTR b)
{
    const int r = CompareStringW(LOCALE_USER_DEFAULT, LOCALE_USE_CP_ACP | NORM_IGNORECASE, a ? a : L"", -1, b ? b : L"", -1);
    return r ? r - 2 : 0;
}

/* ---------------------------------------------------------------- LCMapString */
#define MAP_CASE (LCMAP_LOWERCASE | LCMAP_UPPERCASE)
#define MAP_XFORM (LCMAP_LOWERCASE | LCMAP_UPPERCASE | LCMAP_BYTEREV | LCMAP_HIRAGANA | LCMAP_KATAKANA | LCMAP_HALFWIDTH | LCMAP_FULLWIDTH)
#define MAP_KNOWN (MAP_XFORM | LCMAP_SORTKEY | LCMAP_LINGUISTIC_CASING | CMP_KNOWN)

static int lcmap_w(int kind, DWORD flags, const WCHAR *src, int n, void *dst, int cch)
{
    uint32_t mf = 0;
    int r;
    if (!kind) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (!flags || (flags & ~(DWORD)MAP_KNOWN) || (flags & MAP_CASE) == MAP_CASE ||
        (flags & (LCMAP_HALFWIDTH | LCMAP_FULLWIDTH)) == (LCMAP_HALFWIDTH | LCMAP_FULLWIDTH) ||
        (flags & (LCMAP_HIRAGANA | LCMAP_KATAKANA)) == (LCMAP_HIRAGANA | LCMAP_KATAKANA) ||
        ((flags & LCMAP_SORTKEY) && (flags & MAP_XFORM))) {
        shz_set_last_error(ERROR_INVALID_FLAGS);                     /* includes LCMAP_TITLECASE and the Chinese conversions */
        return 0;
    }
    if (!src || n == 0 || n < -1 || cch < 0 || (cch > 0 && !dst)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    {
        const int with_nul = n == -1;
        if (with_nul) n = (int)k32_wlen(src);
        if (dst && (const void *)src < (const void *)((BYTE *)dst + (size_t)cch * ((flags & LCMAP_SORTKEY) ? 1 : sizeof(WCHAR))) &&
            dst < (void *)((BYTE *)src + (size_t)(n + with_nul) * sizeof(WCHAR)) && cch &&
            (((flags & MAP_XFORM) & ~(DWORD)MAP_CASE) || (flags & LCMAP_SORTKEY) || (const void *)src != dst)) {
            shz_set_last_error(ERROR_INVALID_FLAGS);                 /* overlap is allowed only for in-place case mapping */
            return 0;
        }
        if (flags & LCMAP_SORTKEY) {
            r = nls_sortkey(src, n, core_flags(flags), (uint8_t *)dst, cch);
            if (cch && r > cch) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
            return r;
        }
        if (flags & LCMAP_UPPERCASE) mf |= NLS_MAP_UPPER;
        if (flags & LCMAP_LOWERCASE) mf |= NLS_MAP_LOWER;
        if (flags & LCMAP_HIRAGANA) mf |= NLS_MAP_HIRAGANA;
        if (flags & LCMAP_KATAKANA) mf |= NLS_MAP_KATAKANA;
        if (flags & LCMAP_HALFWIDTH) mf |= NLS_MAP_HALFWIDTH;
        if (flags & LCMAP_FULLWIDTH) mf |= NLS_MAP_FULLWIDTH;
        if (flags & (NORM_IGNORENONSPACE | LINGUISTIC_IGNOREDIACRITIC)) mf |= NLS_MAP_STRIPMARKS;
        if (flags & NORM_IGNORESYMBOLS) mf |= NLS_MAP_STRIPSYMBOLS;
        r = nls_map(src, n, (nls_w *)(cch ? dst : 0), cch, mf);
        if (r < 0) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
        if (with_nul) {                                              /* the terminator is part of the string */
            if (cch) {
                if (r + 1 > cch) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
                ((WCHAR *)dst)[r] = 0;
            }
            ++r;
        }
        if (cch && (flags & LCMAP_BYTEREV)) {
            int i;
            for (i = 0; i < r; ++i) { const WCHAR c = ((WCHAR *)dst)[i]; ((WCHAR *)dst)[i] = (WCHAR)((c << 8) | (c >> 8)); }
        }
        return r;
    }
}

K32API int WINAPI LCMapStringW(LCID loc, DWORD flags, LPCWSTR src, int n, LPWSTR dst, int cch)
{
    return lcmap_w(lcid_kind(loc, 1), flags, src, n, dst, cch);
}
K32API int WINAPI LCMapStringEx(LPCWSTR name, DWORD flags, LPCWSTR src, int n, LPWSTR dst, int cch, LPNLSVERSIONINFO ver,
                                LPVOID reserved, LPARAM sort_handle)
{
    (void)ver;
    if (reserved || sort_handle) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return lcmap_w(name_kind(name), flags, src, n, dst, cch);
}

/* ---------------------------------------------------------------- GetStringType */
static BOOL stringtype_w(DWORD type, const WCHAR *s, int n, LPWORD out)
{
    int i;
    if (!s || !out || n == 0 || n < -1) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (type != CT_CTYPE1 && type != CT_CTYPE2 && type != CT_CTYPE3) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (n == -1) n = (int)k32_wlen(s) + 1;                           /* including the terminator */
    for (i = 0; i < n; ++i) {                                        /* one entry per UTF-16 code unit */
        const uint32_t cp = s[i];
        out[i] = (WORD)(type == CT_CTYPE1 ? nls_ctype1(cp) : type == CT_CTYPE2 ? nls_ctype2(cp) : nls_ctype3(cp));
    }
    return TRUE;
}
K32API BOOL WINAPI GetStringTypeW(DWORD type, LPCWCH s, int n, LPWORD out) { return stringtype_w(type, s, n, out); }
K32API BOOL WINAPI GetStringTypeExW(LCID loc, DWORD type, LPCWCH s, int n, LPWORD out)
{
    if (!lcid_kind(loc, 1)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    return stringtype_w(type, s, n, out);
}

/* ---------------------------------------------------------------- FoldString */
/* Supported: MAP_FOLDDIGITS (Nd digits of any script -> ASCII), MAP_FOLDCZONE (fullwidth ASCII variants and the ideographic space
 * -> ASCII; halfwidth katakana and the other compatibility-zone forms are left alone), MAP_EXPAND_LIGATURES (the Latin ligatures
 * of lig_tab), MAP_COMPOSITE (canonical decomposition) and MAP_PRECOMPOSED (canonical composition of base + one combining mark). */
static const struct { uint16_t cp; const char *to; } lig_tab[] = {
    { 0x00C6, "AE" }, { 0x00E6, "ae" }, { 0x0132, "IJ" }, { 0x0133, "ij" }, { 0x0152, "OE" }, { 0x0153, "oe" },
    { 0xFB00, "ff" }, { 0xFB01, "fi" }, { 0xFB02, "fl" }, { 0xFB03, "ffi" }, { 0xFB04, "ffl" }, { 0xFB05, "st" }, { 0xFB06, "st" },
};

K32API int WINAPI FoldStringW(DWORD flags, LPCWCH src, int n, LPWSTR dst, int cch)
{
    const DWORD known = MAP_PRECOMPOSED | MAP_COMPOSITE | MAP_FOLDCZONE | MAP_FOLDDIGITS | MAP_EXPAND_LIGATURES;
    WCHAR *tmp;
    int i = 0, o = 0, with_nul, result;
    if (!flags || (flags & ~known) || ((flags & MAP_PRECOMPOSED) && (flags & (MAP_COMPOSITE | MAP_EXPAND_LIGATURES)))) {
        shz_set_last_error(ERROR_INVALID_FLAGS);
        return 0;
    }
    if (!src || n == 0 || n < -1 || cch < 0 || (cch > 0 && !dst) || (src == dst && cch)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    with_nul = n == -1;
    if (with_nul) n = (int)k32_wlen(src);
    tmp = RtlAllocateHeap(ShzProcessHeap(), 0, ((size_t)n * 6 + 8) * sizeof(WCHAR));   /* a code point grows to at most 3 code points */
    if (!tmp) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    while (i < n) {
        uint32_t cp = nls_next_cp(src, n, &i), seq[8];
        int ns = 0, k;
        const uint32_t a = nls_attr(cp);
        if ((flags & MAP_FOLDDIGITS) && NLS_GC(a) == GC_Nd && NLS_HASDIG(a)) cp = '0' + NLS_DIGIT(a);
        if (flags & MAP_FOLDCZONE) {
            if (cp >= 0xFF01 && cp <= 0xFF5E) cp -= 0xFEE0;
            else if (cp == 0x3000) cp = 0x20;
        }
        seq[ns++] = cp;
        if (flags & MAP_EXPAND_LIGATURES) {
            unsigned t;
            for (t = 0; t < sizeof lig_tab / sizeof lig_tab[0]; ++t)
                if (lig_tab[t].cp == cp) {
                    const char *l = lig_tab[t].to;
                    ns = 0;
                    while (*l && ns < 8) seq[ns++] = (uint32_t)(unsigned char)*l++;
                    break;
                }
        }
        if ((flags & MAP_COMPOSITE) && ns == 1) {
            uint32_t d[3];
            const int nd = nls_decompose(seq[0], d);
            if (nd) { ns = nd; for (k = 0; k < nd; ++k) seq[k] = d[k]; }
        }
        if ((flags & MAP_PRECOMPOSED) && o > 0 && ns == 1 && cp >= 0x300 && cp < 0x370) {
            const uint32_t comp = nls_compose(tmp[o - 1], cp);                  /* base + combining mark -> precomposed */
            if (comp) { tmp[o - 1] = (WCHAR)comp; continue; }
        }
        for (k = 0; k < ns; ++k) o += nls_put_cp(tmp, o + 8, o, seq[k]);
    }
    result = o + (with_nul ? 1 : 0);
    if (cch == 0) { RtlFreeHeap(ShzProcessHeap(), 0, tmp); return result; }
    if (cch < result) { RtlFreeHeap(ShzProcessHeap(), 0, tmp); shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
    memcpy(dst, tmp, (size_t)o * sizeof(WCHAR));
    if (with_nul) dst[o] = 0;
    RtlFreeHeap(ShzProcessHeap(), 0, tmp);
    return result;
}

/* ---------------------------------------------------------------- date, time, number formats */
static void systemtime_to_dt(const SYSTEMTIME *st, nls_dt *t)
{
    t->year = st->wYear; t->month = st->wMonth; t->day = st->wDay;
    t->hour = st->wHour; t->minute = st->wMinute; t->second = st->wSecond;
    t->wday = 0;
}

static int emit_picture(int kind_pic, const WCHAR *pic, const nls_dt *t, const WCHAR *am, const WCHAR *pm, LPWSTR out, int cch)
{
    WCHAR tmp[512];
    int n = nls_picture(kind_pic, pic, t, am, pm, tmp, 512);
    if (n < 0) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
    ++n;                                                             /* the terminator */
    if (cch == 0) return n;
    if (cch < n) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
    memcpy(out, tmp, (size_t)n * sizeof(WCHAR));
    return n;
}

static const WCHAR *locale_string(int kind, DWORD type)
{
    const li_row *r = li_find(type);
    return kind == 2 && r->inv != SAME ? r->inv : r->us;
}

static int gettimeformat_w(int kind, DWORD flags, const SYSTEMTIME *st, const WCHAR *fmt, LPWSTR out, int cch)
{
    SYSTEMTIME now;
    nls_dt t;
    WCHAR pic[256], edited[256];
    const WCHAR *use;
    if (!kind) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (cch < 0 || (cch > 0 && !out)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (flags & ~(DWORD)(TIME_NOMINUTESORSECONDS | TIME_NOSECONDS | TIME_NOTIMEMARKER | TIME_FORCE24HOURFORMAT | LOCALE_NOUSEROVERRIDE |
                         LOCALE_USE_CP_ACP)) { shz_set_last_error(ERROR_INVALID_FLAGS); return 0; }
    if (fmt && (flags & (TIME_NOMINUTESORSECONDS | TIME_NOSECONDS | TIME_NOTIMEMARKER | TIME_FORCE24HOURFORMAT))) {
        shz_set_last_error(ERROR_INVALID_FLAGS);                     /* time flags contradict an explicit picture */
        return 0;
    }
    if (!st) { GetLocalTime(&now); st = &now; }
    if (st->wHour > 23 || st->wMinute > 59 || st->wSecond > 59 || st->wMilliseconds > 999) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    systemtime_to_dt(st, &t);
    if (fmt) {
        use = fmt;
    } else {
        const WCHAR *base = locale_string(kind, LOCALE_STIMEFORMAT);
        use = base;
        if (flags & (TIME_NOMINUTESORSECONDS | TIME_NOSECONDS | TIME_NOTIMEMARKER | TIME_FORCE24HOURFORMAT)) {
            const int n = nls_time_picture_edit(base, flags, edited, 256);
            if (n < 0) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
            use = edited;
        }
    }
    (void)pic;
    return emit_picture(NLS_PIC_TIME, use, &t, locale_string(kind, LOCALE_S1159), locale_string(kind, LOCALE_S2359), out, cch);
}

static int getdateformat_w(int kind, DWORD flags, const SYSTEMTIME *st, const WCHAR *fmt, LPWSTR out, int cch)
{
    SYSTEMTIME now;
    nls_dt t;
    const WCHAR *use;
    const DWORD picflags = flags & (DATE_SHORTDATE | DATE_LONGDATE | DATE_YEARMONTH);
    if (!kind) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (cch < 0 || (cch > 0 && !out)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (flags & ~(DWORD)(DATE_SHORTDATE | DATE_LONGDATE | DATE_YEARMONTH | LOCALE_NOUSEROVERRIDE | LOCALE_USE_CP_ACP)) {
        shz_set_last_error(ERROR_INVALID_FLAGS);                     /* alternate calendars, reading order and month-day pictures are not carried */
        return 0;
    }
    if (picflags & (picflags - 1)) { shz_set_last_error(ERROR_INVALID_FLAGS); return 0; }
    if (fmt && picflags) { shz_set_last_error(ERROR_INVALID_FLAGS); return 0; }
    if (!st) { GetLocalTime(&now); st = &now; }
    if (st->wYear < 1601 || st->wYear > 30827 || st->wMonth < 1 || st->wMonth > 12 || st->wDay < 1 ||
        st->wDay > nls_days_in_month(st->wYear, st->wMonth)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    systemtime_to_dt(st, &t);
    t.wday = nls_day_of_week(t.year, t.month, t.day);                 /* wDayOfWeek of the input is ignored */
    if (fmt) use = fmt;
    else if (picflags == DATE_LONGDATE) use = locale_string(kind, LOCALE_SLONGDATE);
    else if (picflags == DATE_YEARMONTH) use = locale_string(kind, LOCALE_SYEARMONTH);
    else use = locale_string(kind, LOCALE_SSHORTDATE);
    return emit_picture(NLS_PIC_DATE, use, &t, L"", L"", out, cch);
}

K32API int WINAPI GetTimeFormatW(LCID loc, DWORD flags, const SYSTEMTIME *st, LPCWSTR fmt, LPWSTR out, int cch)
{
    return gettimeformat_w(lcid_kind(loc, 0), flags, st, fmt, out, cch);
}
K32API int WINAPI GetTimeFormatEx(LPCWSTR name, DWORD flags, const SYSTEMTIME *st, LPCWSTR fmt, LPWSTR out, int cch)
{
    return gettimeformat_w(name_kind(name), flags, st, fmt, out, cch);
}
K32API int WINAPI GetDateFormatW(LCID loc, DWORD flags, const SYSTEMTIME *st, LPCWSTR fmt, LPWSTR out, int cch)
{
    return getdateformat_w(lcid_kind(loc, 0), flags, st, fmt, out, cch);
}
K32API int WINAPI GetDateFormatEx(LPCWSTR name, DWORD flags, const SYSTEMTIME *st, LPCWSTR fmt, LPWSTR out, int cch, LPCWSTR calendar)
{
    if (calendar) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }         /* lpCalendar is reserved */
    return getdateformat_w(name_kind(name), flags, st, fmt, out, cch);
}

static int number_common(int kind, DWORD flags, const WCHAR *value, const NUMBERFMTW *nf, const CURRENCYFMTW *cf, LPWSTR out, int cch)
{
    nls_numfmt f;
    WCHAR tmp[700];
    int n;
    const int currency = cf != 0;
    if (!kind) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (!value || cch < 0 || (cch > 0 && !out)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (flags & ~(DWORD)(LOCALE_NOUSEROVERRIDE | LOCALE_USE_CP_ACP)) { shz_set_last_error(ERROR_INVALID_FLAGS); return 0; }
    if ((nf || cf) && (flags & ~(DWORD)LOCALE_USE_CP_ACP)) { shz_set_last_error(ERROR_INVALID_FLAGS); return 0; }
    if (nf) {
        f.digits = nf->NumDigits; f.lzero = nf->LeadingZero; f.grouping = nf->Grouping; f.negorder = nf->NegativeOrder;
        f.posorder = 0; f.dec = nf->lpDecimalSep; f.thou = nf->lpThousandSep; f.curr = L"";
        if (!f.dec || !f.thou) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    } else if (cf) {
        f.digits = cf->NumDigits; f.lzero = cf->LeadingZero; f.grouping = cf->Grouping; f.negorder = cf->NegativeOrder;
        f.posorder = cf->PositiveOrder; f.dec = cf->lpDecimalSep; f.thou = cf->lpThousandSep; f.curr = cf->lpCurrencySymbol;
        if (!f.dec || !f.thou || !f.curr) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    } else {
        f.digits = 2; f.lzero = 1; f.grouping = 3; f.dec = L"."; f.thou = L","; f.posorder = 0; f.curr = L"";
        f.negorder = currency ? 0 : 1;
    }
    (void)cf;
    n = nls_number(value, &f, currency, tmp, 700);
    if (n == -2) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (n < 0) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
    ++n;
    if (cch == 0) return n;
    if (cch < n) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
    memcpy(out, tmp, (size_t)n * sizeof(WCHAR));
    return n;
}

static int currency_common(int kind, DWORD flags, const WCHAR *value, const CURRENCYFMTW *cf, LPWSTR out, int cch)
{
    CURRENCYFMTW def;
    if (!cf) {
        def.NumDigits = 2; def.LeadingZero = 1; def.Grouping = 3; def.lpDecimalSep = (LPWSTR)L"."; def.lpThousandSep = (LPWSTR)L",";
        def.NegativeOrder = 0; def.PositiveOrder = 0; def.lpCurrencySymbol = (LPWSTR)locale_string(kind ? kind : 1, LOCALE_SCURRENCY);
        cf = &def;
    }
    return number_common(kind, cf == &def ? flags & LOCALE_USE_CP_ACP : flags, value, 0, cf, out, cch);
}

K32API int WINAPI GetNumberFormatW(LCID loc, DWORD flags, LPCWSTR v, const NUMBERFMTW *nf, LPWSTR out, int cch)
{
    return number_common(lcid_kind(loc, 0), flags, v, nf, 0, out, cch);
}
K32API int WINAPI GetNumberFormatEx(LPCWSTR name, DWORD flags, LPCWSTR v, const NUMBERFMTW *nf, LPWSTR out, int cch)
{
    return number_common(name_kind(name), flags, v, nf, 0, out, cch);
}
K32API int WINAPI GetCurrencyFormatW(LCID loc, DWORD flags, LPCWSTR v, const CURRENCYFMTW *cf, LPWSTR out, int cch)
{
    return currency_common(lcid_kind(loc, 0), flags, v, cf, out, cch);
}
K32API int WINAPI GetCurrencyFormatEx(LPCWSTR name, DWORD flags, LPCWSTR v, const CURRENCYFMTW *cf, LPWSTR out, int cch)
{
    return currency_common(name_kind(name), flags, v, cf, out, cch);
}

/* ---------------------------------------------------------------- UI languages and geography */
static BOOL ui_languages(DWORD flags, PULONG count, PZZWSTR buf, PULONG cch)
{
    /* One language, en-US. MUI_LANGUAGE_NAME (default) yields "en-US", MUI_LANGUAGE_ID yields "0409". */
    const WCHAR *s;
    ULONG need;
    const DWORD known = MUI_LANGUAGE_ID | MUI_LANGUAGE_NAME | MUI_MERGE_SYSTEM_FALLBACK | MUI_MERGE_USER_FALLBACK | MUI_THREAD_LANGUAGES |
                        MUI_CONSOLE_FILTER | MUI_COMPLEX_SCRIPT_FILTER;
    if ((flags & ~known) || !count || !cch || ((flags & MUI_LANGUAGE_ID) && (flags & MUI_LANGUAGE_NAME))) {
        shz_set_last_error(flags & ~known ? ERROR_INVALID_FLAGS : ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    s = (flags & MUI_LANGUAGE_ID) ? L"0409" : L"en-US";
    need = (ULONG)k32_wlen(s) + 2;                                    /* the string, its terminator and the multi-string terminator */
    *count = 1;
    if (!buf) { *cch = need; return TRUE; }
    if (*cch < need) { *cch = need; shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    memcpy(buf, s, (need - 1) * sizeof(WCHAR));
    buf[need - 1] = 0;
    *cch = need;
    return TRUE;
}
K32API BOOL WINAPI GetUserPreferredUILanguages(DWORD flags, PULONG n, PZZWSTR buf, PULONG cch) { return ui_languages(flags, n, buf, cch); }
K32API BOOL WINAPI GetThreadPreferredUILanguages(DWORD flags, PULONG n, PZZWSTR buf, PULONG cch) { return ui_languages(flags, n, buf, cch); }
K32API BOOL WINAPI GetSystemPreferredUILanguages(DWORD flags, PULONG n, PZZWSTR buf, PULONG cch) { return ui_languages(flags, n, buf, cch); }
K32API BOOL WINAPI GetProcessPreferredUILanguages(DWORD flags, PULONG n, PZZWSTR buf, PULONG cch) { return ui_languages(flags, n, buf, cch); }

K32API GEOID WINAPI GetUserGeoID(GEOCLASS geoclass)
{
    if (geoclass != GEOCLASS_NATION) { shz_set_last_error(ERROR_INVALID_PARAMETER); return GEOID_NOT_AVAILABLE; }
    return 244;                                                       /* United States */
}
K32API int WINAPI GetGeoInfoW(GEOID geo, GEOTYPE type, LPWSTR buf, int cch, LANGID lang)
{
    const WCHAR *s;
    (void)lang;
    if (geo != 244) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    switch (type) {
    case GEO_NATION: s = L"244"; break;
    case GEO_ISO2: s = L"US"; break;
    case GEO_ISO3: s = L"USA"; break;
    case GEO_FRIENDLYNAME: s = L"United States"; break;
    default: shz_set_last_error(ERROR_INVALID_FLAGS); return 0;      /* other GEOTYPEs are not carried */
    }
    if (cch < 0 || (cch > 0 && !buf)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return give_w(s, buf, cch);
}
