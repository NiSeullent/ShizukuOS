/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32 NLS: locale identification, GetLocaleInfo, enumeration, CompareString, LCMapString, GetStringType, FoldString,
 * date/time/number/currency formatting, UI languages, geo id. Only en-US and the invariant locale exist here (see k32_nls.c);
 * expectations are the documented Windows results for those locales. */
#include "k32test.h"

static int enum_count, enum_found;
static BOOL CALLBACK enum_w(LPWSTR id) { ++enum_count; if (k32t_weq(id, L"00000409")) ++enum_found; return TRUE; }
static BOOL CALLBACK enum_stop(LPWSTR id) { (void)id; ++enum_count; return FALSE; }
static BOOL CALLBACK enum_ex(LPWSTR name, DWORD flags, LPARAM lp)
{
    (void)flags;
    ++enum_count;
    if (k32t_weq(name, L"en-US")) enum_found += (int)lp;
    return TRUE;
}

static int sign(int v) { return v < 0 ? -1 : v > 0; }

static void test_ids(void)
{
    WCHAR buf[64];
    CHECK(GetUserDefaultLCID() == 0x0409, "GetUserDefaultLCID is en-US");
    CHECK(GetSystemDefaultLCID() == 0x0409, "GetSystemDefaultLCID is en-US");
    CHECK(GetUserDefaultLangID() == 0x0409 && GetSystemDefaultLangID() == 0x0409, "default LANGIDs are en-US");
    CHECK(GetUserDefaultUILanguage() == 0x0409 && GetSystemDefaultUILanguage() == 0x0409, "default UI languages are en-US");
    CHECK(PRIMARYLANGID(GetUserDefaultLangID()) == LANG_ENGLISH && SUBLANGID(GetUserDefaultLangID()) == SUBLANG_ENGLISH_US, "en-US decomposes to LANG_ENGLISH/SUBLANG_ENGLISH_US");
    CHECK(GetThreadLocale() == 0x0409, "thread locale defaults to en-US");
    CHECK(SetThreadLocale(0x0409) && GetThreadLocale() == 0x0409, "SetThreadLocale(en-US) succeeds");
    SetLastError(0);
    CHECK(!SetThreadLocale(0xDEAD), "SetThreadLocale rejects an invalid LCID");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "SetThreadLocale invalid LCID: ERROR_INVALID_PARAMETER");
    CHECK(GetThreadLocale() == 0x0409, "failed SetThreadLocale leaves the locale alone");
    CHECK(IsValidLocale(0x0409, LCID_INSTALLED) && IsValidLocale(0x0409, LCID_SUPPORTED), "en-US is valid, installed and supported");
    SetLastError(0);
    CHECK(!IsValidLocale(0xDEAD, LCID_SUPPORTED), "invalid LCID is not valid");
    CHECK(LocaleNameToLCID(L"en-US", 0) == 0x0409, "LocaleNameToLCID(en-US)");
    CHECK(LocaleNameToLCID(L"EN-us", 0) == 0x0409, "locale names are case-insensitive");
    CHECK(LocaleNameToLCID(LOCALE_NAME_INVARIANT, 0) == LOCALE_INVARIANT, "LocaleNameToLCID(\"\") is LOCALE_INVARIANT");
    CHECK(LocaleNameToLCID(LOCALE_NAME_USER_DEFAULT, 0) == 0x0409, "LOCALE_NAME_USER_DEFAULT is the user locale");
    SetLastError(0);
    CHECK(LocaleNameToLCID(L"xx-YY", 0) == 0, "unknown locale name gives 0");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "unknown locale name: ERROR_INVALID_PARAMETER");
    CHECKV(LCIDToLocaleName(0x0409, buf, 64, 0) == 6 && k32t_weq(buf, L"en-US"), "LCIDToLocaleName(0x409) = en-US (6)", "n=%d", LCIDToLocaleName(0x0409, buf, 64, 0));
    CHECK(LCIDToLocaleName(0x0409, 0, 0, 0) == 6, "LCIDToLocaleName size query");
    SetLastError(0);
    CHECK(LCIDToLocaleName(0x0409, buf, 3, 0) == 0, "LCIDToLocaleName with a short buffer fails");
    CHECK_ERR(ERROR_INSUFFICIENT_BUFFER, "short buffer: ERROR_INSUFFICIENT_BUFFER");
    CHECK(GetUserDefaultLocaleName(buf, 64) == 6 && k32t_weq(buf, L"en-US"), "GetUserDefaultLocaleName");
    CHECK(GetSystemDefaultLocaleName(buf, 64) == 6 && k32t_weq(buf, L"en-US"), "GetSystemDefaultLocaleName");
    CHECK(ResolveLocaleName(L"en-us", buf, 64) == 6 && k32t_weq(buf, L"en-US"), "ResolveLocaleName canonicalises the case");
}

static void test_localeinfo(void)
{
    WCHAR b[128];
    char a[64];
    DWORD num = 0;
    int n;
    n = GetLocaleInfoW(0x0409, LOCALE_SNAME, b, 128);
    CHECKV(n == 6 && k32t_weq(b, L"en-US"), "LOCALE_SNAME = en-US", "n=%d", n);
    CHECK(GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SNAME, 0, 0) == 6, "size query returns the size with the terminator");
    SetLastError(0);
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SNAME, b, 3) == 0, "buffer too small fails");
    CHECK_ERR(ERROR_INSUFFICIENT_BUFFER, "buffer too small: ERROR_INSUFFICIENT_BUFFER");
    SetLastError(0);
    CHECK(GetLocaleInfoW(0xDEAD, LOCALE_SNAME, b, 128) == 0, "invalid LCID fails");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "invalid LCID: ERROR_INVALID_PARAMETER");
    SetLastError(0);
    CHECK(GetLocaleInfoW(0x0409, 0x7777, b, 128) == 0, "unknown LCTYPE fails");
    CHECK_ERR(ERROR_INVALID_FLAGS, "unknown LCTYPE: ERROR_INVALID_FLAGS");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SISO639LANGNAME, b, 128) == 3 && k32t_weq(b, L"en"), "ISO 639 language name");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SISO3166CTRYNAME, b, 128) == 3 && k32t_weq(b, L"US"), "ISO 3166 country name");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SENGLISHLANGUAGENAME, b, 128) > 0 && k32t_weq(b, L"English"), "English language name");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SENGLISHCOUNTRYNAME, b, 128) > 0 && k32t_weq(b, L"United States"), "English country name");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SDECIMAL, b, 128) == 2 && b[0] == '.', "decimal separator");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_STHOUSAND, b, 128) == 2 && b[0] == ',', "thousands separator");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SGROUPING, b, 128) > 0 && k32t_weq(b, L"3;0"), "digit grouping 3;0");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SCURRENCY, b, 128) == 2 && b[0] == '$', "currency symbol");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SINTLSYMBOL, b, 128) > 0 && k32t_weq(b, L"USD"), "international currency symbol");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SSHORTDATE, b, 128) > 0 && k32t_weq(b, L"M/d/yyyy"), "short date picture");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SLONGDATE, b, 128) > 0 && k32t_weq(b, L"dddd, MMMM d, yyyy"), "long date picture");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_STIMEFORMAT, b, 128) > 0 && k32t_weq(b, L"h:mm:ss tt"), "time picture");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_S1159, b, 128) > 0 && k32t_weq(b, L"AM") && GetLocaleInfoW(0x0409, LOCALE_S2359, b, 128) > 0 && k32t_weq(b, L"PM"), "AM/PM designators");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SDAYNAME1, b, 128) > 0 && k32t_weq(b, L"Monday"), "LOCALE_SDAYNAME1 is Monday");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SDAYNAME7, b, 128) > 0 && k32t_weq(b, L"Sunday"), "LOCALE_SDAYNAME7 is Sunday");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SABBREVDAYNAME3, b, 128) > 0 && k32t_weq(b, L"Wed"), "abbreviated day name 3");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SMONTHNAME3, b, 128) > 0 && k32t_weq(b, L"March"), "month name 3");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SMONTHNAME12, b, 128) > 0 && k32t_weq(b, L"December"), "month name 12");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SABBREVMONTHNAME2, b, 128) > 0 && k32t_weq(b, L"Feb"), "abbreviated month name 2");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_ILANGUAGE, b, 128) > 0 && k32t_weq(b, L"0409"), "ILANGUAGE is the 4 digit hex LANGID");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_IDIGITS | LOCALE_RETURN_NUMBER, (LPWSTR)&num, 2) == 2 && num == 2, "IDIGITS as a number");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_ICOUNTRY | LOCALE_RETURN_NUMBER, (LPWSTR)&num, 2) == 2 && num == 1, "ICOUNTRY as a number");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_IFIRSTDAYOFWEEK | LOCALE_RETURN_NUMBER, (LPWSTR)&num, 2) == 2 && num == 6, "first day of the week is Sunday (6)");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_ITIME | LOCALE_RETURN_NUMBER, (LPWSTR)&num, 2) == 2 && num == 0, "12 hour clock");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_IMEASURE | LOCALE_RETURN_NUMBER, (LPWSTR)&num, 2) == 2 && num == 1, "US measurement system");
    CHECK(GetLocaleInfoW(0x0409, LOCALE_IDIGITS | LOCALE_RETURN_NUMBER, 0, 0) == 2, "LOCALE_RETURN_NUMBER size query is 2 WCHARs");
    SetLastError(0);
    CHECK(GetLocaleInfoW(0x0409, LOCALE_SNAME | LOCALE_RETURN_NUMBER, b, 128) == 0, "RETURN_NUMBER on a string LCTYPE fails");
    CHECK_ERR(ERROR_INVALID_FLAGS, "RETURN_NUMBER on a string LCTYPE: ERROR_INVALID_FLAGS");
    /* invariant locale */
    n = GetLocaleInfoW(LOCALE_INVARIANT, LOCALE_SNAME, b, 128);
    CHECK(n == 1 && b[0] == 0, "invariant locale name is the empty string");
    CHECK(GetLocaleInfoW(LOCALE_INVARIANT, LOCALE_SSHORTDATE, b, 128) > 0 && k32t_weq(b, L"MM/dd/yyyy"), "invariant short date");
    CHECK(GetLocaleInfoW(LOCALE_INVARIANT, LOCALE_SLONGDATE, b, 128) > 0 && k32t_weq(b, L"dddd, dd MMMM yyyy"), "invariant long date");
    CHECK(GetLocaleInfoW(LOCALE_INVARIANT, LOCALE_STIMEFORMAT, b, 128) > 0 && k32t_weq(b, L"HH:mm:ss"), "invariant time format");
    CHECK(GetLocaleInfoW(LOCALE_INVARIANT, LOCALE_SCURRENCY, b, 128) == 2 && b[0] == 0x00A4, "invariant currency symbol is the generic currency sign");
    CHECK(GetLocaleInfoW(LOCALE_INVARIANT, LOCALE_SMONTHNAME1, b, 128) > 0 && k32t_weq(b, L"January"), "invariant month names are English");
    /* Ex and A variants */
    CHECK(GetLocaleInfoEx(L"en-US", LOCALE_SNAME, b, 128) == 6 && k32t_weq(b, L"en-US"), "GetLocaleInfoEx(en-US)");
    CHECK(GetLocaleInfoEx(LOCALE_NAME_USER_DEFAULT, LOCALE_SISO639LANGNAME, b, 128) == 3, "GetLocaleInfoEx(user default)");
    CHECK(GetLocaleInfoEx(LOCALE_NAME_INVARIANT, LOCALE_SNAME, b, 128) == 1, "GetLocaleInfoEx(invariant)");
    SetLastError(0);
    CHECK(GetLocaleInfoEx(L"xx-YY", LOCALE_SNAME, b, 128) == 0, "GetLocaleInfoEx(unknown name) fails");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "GetLocaleInfoEx unknown name: ERROR_INVALID_PARAMETER");
    n = GetLocaleInfoA(0x0409, LOCALE_SNAME, a, 64);
    CHECK(n == 6 && !strcmp(a, "en-US"), "GetLocaleInfoA(LOCALE_SNAME)");
    CHECK(GetLocaleInfoA(0x0409, LOCALE_SNAME, 0, 0) == 6, "GetLocaleInfoA size query");
    CHECK(GetLocaleInfoA(0x0409, LOCALE_IDIGITS | LOCALE_RETURN_NUMBER, (LPSTR)&num, 4) == 4 && num == 2, "GetLocaleInfoA with RETURN_NUMBER counts bytes");
}

static void test_enum(void)
{
    enum_count = enum_found = 0;
    CHECK(EnumSystemLocalesW(enum_w, LCID_INSTALLED) && enum_found == 1 && enum_count >= 1, "EnumSystemLocalesW(LCID_INSTALLED) reports 00000409");
    enum_count = enum_found = 0;
    CHECK(EnumSystemLocalesW(enum_w, LCID_SUPPORTED) && enum_found == 1, "EnumSystemLocalesW(LCID_SUPPORTED) reports 00000409");
    enum_count = 0;
    CHECK(EnumSystemLocalesW(enum_stop, LCID_SUPPORTED) && enum_count == 1, "returning FALSE stops the enumeration");
    enum_count = enum_found = 0;
    CHECK(EnumSystemLocalesEx(enum_ex, LOCALE_WINDOWS, 1, 0) && enum_found == 1, "EnumSystemLocalesEx(LOCALE_WINDOWS) reports en-US");
    enum_count = enum_found = 0;
    CHECK(EnumSystemLocalesEx(enum_ex, LOCALE_ALL, 1, 0) && enum_found == 1, "EnumSystemLocalesEx(LOCALE_ALL) reports en-US");
    SetLastError(0);
    CHECK(!EnumSystemLocalesEx(enum_ex, LOCALE_ALL, 1, (LPVOID)1), "reserved must be NULL");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "reserved: ERROR_INVALID_PARAMETER");
}

static int cmpw(const WCHAR *a, const WCHAR *b, DWORD flags) { return CompareStringW(LOCALE_USER_DEFAULT, flags, a, -1, b, -1); }

static void test_compare(void)
{
    static const WCHAR e_acute_nfc[] = L"r" L"\xe9" L"sum" L"\xe9", e_acute_nfd[] = L"re" L"\x301" L"sume" L"\x301";   /* precomposed and decomposed */
    CHECK(cmpw(L"a", L"b", 0) == CSTR_LESS_THAN && cmpw(L"b", L"a", 0) == CSTR_GREATER_THAN, "a < b");
    CHECK(cmpw(L"abc", L"abc", 0) == CSTR_EQUAL, "equal strings");
    CHECK(cmpw(L"a", L"A", 0) == CSTR_LESS_THAN, "lowercase sorts before uppercase");
    CHECK(cmpw(L"a", L"A", NORM_IGNORECASE) == CSTR_EQUAL, "NORM_IGNORECASE ignores case");
    CHECK(cmpw(L"a", L"A", LINGUISTIC_IGNORECASE) == CSTR_EQUAL, "LINGUISTIC_IGNORECASE ignores case");
    CHECK(cmpw(L"apple", L"Banana", 0) == CSTR_LESS_THAN, "linguistic: apple < Banana");
    CHECK(cmpw(L"Zebra", L"apple", 0) == CSTR_GREATER_THAN, "linguistic: Zebra > apple");
    CHECK(cmpw(L"abc", L"abcd", 0) == CSTR_LESS_THAN, "prefix is smaller");
    CHECK(cmpw(L"", L"a", 0) == CSTR_LESS_THAN && cmpw(L"", L"", 0) == CSTR_EQUAL, "empty strings");
    CHECK(cmpw(L"1", L"a", 0) == CSTR_LESS_THAN, "digits sort before letters");
    CHECK(cmpw(L"10", L"9", 0) == CSTR_LESS_THAN, "string comparison of digits: 10 < 9");
    CHECK(cmpw(L"10", L"9", SORT_DIGITSASNUMBERS) == CSTR_GREATER_THAN, "SORT_DIGITSASNUMBERS: 10 > 9");
    CHECK(cmpw(e_acute_nfc, L"resume", 0) == CSTR_GREATER_THAN, "an accent sorts after the plain letter");
    CHECK(cmpw(e_acute_nfc, L"resume", NORM_IGNORENONSPACE) == CSTR_EQUAL, "NORM_IGNORENONSPACE ignores accents");
    CHECK(cmpw(e_acute_nfc, L"RESUME", NORM_IGNORENONSPACE | NORM_IGNORECASE) == CSTR_EQUAL, "both ignore flags");
    CHECK(cmpw(e_acute_nfc, e_acute_nfd, 0) == CSTR_EQUAL, "precomposed and decomposed forms are canonically equivalent");
    CHECK(cmpw(L"a b", L"ab", NORM_IGNORESYMBOLS) == CSTR_EQUAL, "NORM_IGNORESYMBOLS ignores white space");
    CHECK(cmpw(L"co-op", L"coa", 0) == CSTR_GREATER_THAN, "word sort: the hyphen is ignored, so co-op > coa");
    CHECK(cmpw(L"co-op", L"coa", SORT_STRINGSORT) == CSTR_LESS_THAN, "SORT_STRINGSORT treats the hyphen as punctuation");
    CHECK(cmpw(L"α", L"z", 0) == CSTR_GREATER_THAN, "Greek sorts after Latin");
    CHECK(cmpw(L"Ａ", L"A", NORM_IGNOREWIDTH) == CSTR_EQUAL && cmpw(L"Ａ", L"A", 0) != CSTR_EQUAL, "NORM_IGNOREWIDTH folds fullwidth letters");
    CHECK(CompareStringW(LOCALE_USER_DEFAULT, 0, L"abc", 2, L"abd", 2) == CSTR_EQUAL, "explicit lengths limit the comparison");
    CHECK(CompareStringW(LOCALE_USER_DEFAULT, 0, L"abc", 3, L"abd", 3) == CSTR_LESS_THAN, "explicit lengths, different strings");
    SetLastError(0);
    CHECK(CompareStringW(LOCALE_USER_DEFAULT, 0x40, L"a", -1, L"a", -1) == 0, "undefined flag bits fail");
    CHECK_ERR(ERROR_INVALID_FLAGS, "undefined flag bits: ERROR_INVALID_FLAGS");
    SetLastError(0);
    CHECK(CompareStringW(LOCALE_USER_DEFAULT, 0, 0, -1, L"a", -1) == 0, "NULL string fails");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "NULL string: ERROR_INVALID_PARAMETER");
    SetLastError(0);
    CHECK(CompareStringW(0xDEAD, 0, L"a", -1, L"a", -1) == 0, "invalid locale fails");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "invalid locale: ERROR_INVALID_PARAMETER");
    CHECK(CompareStringEx(L"en-US", NORM_IGNORECASE, L"Hello", -1, L"hello", -1, 0, 0, 0) == CSTR_EQUAL, "CompareStringEx");
    CHECK(CompareStringEx(LOCALE_NAME_INVARIANT, 0, L"a", -1, L"b", -1, 0, 0, 0) == CSTR_LESS_THAN, "CompareStringEx, invariant locale");
    SetLastError(0);
    CHECK(CompareStringEx(L"xx-YY", 0, L"a", -1, L"b", -1, 0, 0, 0) == 0, "CompareStringEx with an unknown locale name fails");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "CompareStringEx unknown name: ERROR_INVALID_PARAMETER");
    CHECK(CompareStringA(LOCALE_USER_DEFAULT, NORM_IGNORECASE, "abc", -1, "ABC", -1) == CSTR_EQUAL, "CompareStringA");
    CHECK(CompareStringA(LOCALE_USER_DEFAULT, 0, "abc", 3, "abd", 3) == CSTR_LESS_THAN, "CompareStringA with lengths");
    CHECK(lstrcmpW(L"a", L"b") == -1 && lstrcmpW(L"b", L"a") == 1 && lstrcmpW(L"abc", L"abc") == 0, "lstrcmpW returns -1, 0, 1");
    CHECK(lstrcmpiW(L"ABC", L"abc") == 0 && lstrcmpiW(L"abc", L"abd") == -1, "lstrcmpiW ignores case");
    CHECK(lstrcmpW(L"apple", L"Banana") == -1, "lstrcmpW is a linguistic comparison");
}

static void test_lcmap(void)
{
    WCHAR d[64];
    BYTE k1[256], k2[256];
    int n, n1, n2;
    n = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_UPPERCASE, L"Hello, wörld", -1, d, 64);
    CHECKV(n == 13 && k32t_weq(d, L"HELLO, WÖRLD"), "LCMAP_UPPERCASE with -1 counts the terminator", "n=%d", n);
    n = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_LOWERCASE, L"HELLO ÉΑЯ", -1, d, 64);
    CHECK(n == 10 && k32t_weq(d, L"hello éαя"), "LCMAP_LOWERCASE on Latin, Greek and Cyrillic");
    n = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_UPPERCASE, L"a\U00010428", -1, d, 64);
    CHECK(n == 4 && d[0] == 'A' && d[1] == 0xD801 && d[2] == 0xDC00, "uppercase of a supplementary letter");
    n = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_UPPERCASE, L"abc", 2, d, 64);
    CHECK(n == 2 && d[0] == 'A' && d[1] == 'B', "explicit length has no terminator");
    CHECK(LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_UPPERCASE, L"abc", -1, 0, 0) == 4, "size query counts the terminator");
    SetLastError(0);
    CHECK(LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_UPPERCASE, L"abcdef", -1, d, 3) == 0, "short buffer fails");
    CHECK_ERR(ERROR_INSUFFICIENT_BUFFER, "short buffer: ERROR_INSUFFICIENT_BUFFER");
    {
        WCHAR inplace[] = L"mixed Case";
        n = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_UPPERCASE, inplace, -1, inplace, 11);
        CHECK(n == 11 && k32t_weq(inplace, L"MIXED CASE"), "in-place case mapping is allowed");
    }
    SetLastError(0);
    CHECK(LCMapStringW(LOCALE_USER_DEFAULT, 0, L"abc", -1, d, 64) == 0, "no flags fails");
    CHECK_ERR(ERROR_INVALID_FLAGS, "no flags: ERROR_INVALID_FLAGS");
    SetLastError(0);
    CHECK(LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_UPPERCASE | LCMAP_LOWERCASE, L"abc", -1, d, 64) == 0, "upper|lower together fail");
    CHECK(GetLastError() == ERROR_INVALID_FLAGS, "upper|lower: ERROR_INVALID_FLAGS");
    SetLastError(0);
    CHECK(LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_UPPERCASE, 0, -1, d, 64) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "NULL source: ERROR_INVALID_PARAMETER");
    SetLastError(0);
    CHECK(LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_UPPERCASE, L"abc", 0, d, 64) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "zero length: ERROR_INVALID_PARAMETER");
    SetLastError(0);
    CHECK(LCMapStringW(0xDEAD, LCMAP_UPPERCASE, L"abc", -1, d, 64) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "invalid locale: ERROR_INVALID_PARAMETER");
    n = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_FULLWIDTH, L"Ab 1", -1, d, 64);
    CHECK(n == 5 && d[0] == 0xFF21 && d[1] == 0xFF42 && d[2] == 0x3000 && d[3] == 0xFF11, "LCMAP_FULLWIDTH");
    n = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_HALFWIDTH, L"Ａｂ　１", -1, d, 64);
    CHECK(n == 5 && k32t_weq(d, L"Ab 1"), "LCMAP_HALFWIDTH");
    n = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_KATAKANA, L"あい", -1, d, 64);
    CHECK(n == 3 && d[0] == 0x30A2 && d[1] == 0x30A4, "LCMAP_KATAKANA");
    n = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_HIRAGANA, L"アイ", -1, d, 64);
    CHECK(n == 3 && d[0] == 0x3042 && d[1] == 0x3044, "LCMAP_HIRAGANA");
    n = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_UPPERCASE | LCMAP_BYTEREV, L"ab", -1, d, 64);
    CHECK(n == 3 && d[0] == 0x4100 && d[1] == 0x4200, "LCMAP_UPPERCASE | LCMAP_BYTEREV maps first, then swaps the bytes");
    n = LCMapStringEx(L"en-US", LCMAP_UPPERCASE, L"abc", -1, d, 64, 0, 0, 0);
    CHECK(n == 4 && k32t_weq(d, L"ABC"), "LCMapStringEx");
    SetLastError(0);
    CHECK(LCMapStringEx(L"xx-YY", LCMAP_UPPERCASE, L"abc", -1, d, 64, 0, 0, 0) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "LCMapStringEx unknown locale name: ERROR_INVALID_PARAMETER");
    /* sort keys are opaque, but their byte order must be the linguistic order */
    n1 = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_SORTKEY, L"apple", -1, (LPWSTR)k1, 256);
    n2 = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_SORTKEY, L"Banana", -1, (LPWSTR)k2, 256);
    CHECK(n1 > 0 && n2 > 0 && n1 <= 256 && n2 <= 256, "LCMAP_SORTKEY produces bytes");
    CHECK(sign(memcmp(k1, k2, (size_t)(n1 < n2 ? n1 : n2))) < 0, "sort key of apple < sort key of Banana");
    CHECK(LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_SORTKEY, L"apple", -1, 0, 0) == n1, "sort key size query matches");
    n1 = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_SORTKEY | NORM_IGNORECASE, L"Apple", -1, (LPWSTR)k1, 256);
    n2 = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_SORTKEY | NORM_IGNORECASE, L"aPPLE", -1, (LPWSTR)k2, 256);
    CHECK(n1 == n2 && n1 > 0 && !memcmp(k1, k2, (size_t)n1), "sort keys with NORM_IGNORECASE are equal for case variants");
    {
        /* the contract of a sort key: byte order == CompareString order */
        static const WCHAR *const pairs[][2] = { { L"a", L"A" }, { L"apple", L"Banana" }, { L"10", L"9" }, { L"abc", L"abcd" }, { L"a", L"b" },
                                                 { L"Zed", L"apple" }, { L"abc", L"abc" }, { L"a1", L"a2" }, { L"x y", L"xy" } };
        unsigned i;
        int agree = 1;
        for (i = 0; i < sizeof pairs / sizeof pairs[0]; ++i) {
            const int c = CompareStringW(LOCALE_USER_DEFAULT, 0, pairs[i][0], -1, pairs[i][1], -1) - 2;
            n1 = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_SORTKEY, pairs[i][0], -1, (LPWSTR)k1, 256);
            n2 = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_SORTKEY, pairs[i][1], -1, (LPWSTR)k2, 256);
            {
                const int m = n1 < n2 ? n1 : n2, r = memcmp(k1, k2, (size_t)m);
                const int order = r ? sign(r) : n1 == n2 ? 0 : n1 < n2 ? -1 : 1;
                if (order != c) { agree = 0; printf("sort key order %d != CompareString order %d for pair %u\n", order, c, i); }
            }
        }
        CHECK(agree, "sort key byte order equals CompareStringW order");
    }
    SetLastError(0);
    CHECK(LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_SORTKEY, L"apple", -1, (LPWSTR)k1, 4) == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "short sort key buffer: ERROR_INSUFFICIENT_BUFFER");
}

static void test_stringtype(void)
{
    static const WCHAR s[] = L"gG0 !\t\nfg";
    /* Windows reports C1_DEFINED for every assigned character: 'g' 0x302, 'G' 0x301, '0' 0x284, ' ' 0x248, '!' 0x210 */
    {
        WORD c1[16];
        CHECK(GetStringTypeW(CT_CTYPE1, s, 9, c1), "GetStringTypeW(CT_CTYPE1)");
        CHECKV(c1[0] == 0x302, "lowercase letter: LOWER|ALPHA|DEFINED", "%x", c1[0]);
        CHECKV(c1[1] == 0x301, "uppercase letter: UPPER|ALPHA|DEFINED", "%x", c1[1]);
        CHECKV(c1[2] == 0x284, "digit: DIGIT|XDIGIT|DEFINED", "%x", c1[2]);
        CHECKV(c1[3] == 0x248, "space: SPACE|BLANK|DEFINED", "%x", c1[3]);
        CHECKV(c1[4] == 0x210, "punctuation: PUNCT|DEFINED", "%x", c1[4]);
        CHECKV(c1[5] == 0x268, "tab: SPACE|CNTRL|BLANK|DEFINED", "%x", c1[5]);
        CHECKV(c1[6] == 0x228, "newline: SPACE|CNTRL|DEFINED", "%x", c1[6]);
        CHECKV(c1[7] == 0x382, "hex letter f: LOWER|XDIGIT|ALPHA|DEFINED", "%x", c1[7]);
        CHECKV(c1[8] == 0x302, "non-hex letter g", "%x", c1[8]);
    }
    {
        WORD c2[4];
        CHECK(GetStringTypeW(CT_CTYPE2, L"A1 ", 3, c2) && c2[0] == C2_LEFTTORIGHT && c2[1] == C2_EUROPENUMBER && c2[2] == C2_WHITESPACE, "GetStringTypeW(CT_CTYPE2): L, EN, WS");
        CHECK(GetStringTypeW(CT_CTYPE2, L"אا٠", 3, c2) && c2[0] == C2_RIGHTTOLEFT && c2[1] == C2_RIGHTTOLEFT && c2[2] == C2_ARABICNUMBER, "CT_CTYPE2: Hebrew, Arabic, Arabic-Indic digit");
    }
    {
        WORD c3[8];
        static const WCHAR u[] = { 'a', 0x0301, 0xD83D, 0xDE00, 0x3042, 0x30A2, 0xFF21, 0x4E00 };
        CHECK(GetStringTypeW(CT_CTYPE3, u, 8, c3), "GetStringTypeW(CT_CTYPE3)");
        CHECK(c3[0] & C3_ALPHA, "C3_ALPHA for a letter");
        CHECK(c3[1] & C3_NONSPACING, "C3_NONSPACING for a combining acute");
        CHECK((c3[2] & C3_HIGHSURROGATE) && (c3[3] & C3_LOWSURROGATE), "surrogate halves are reported per code unit");
        CHECK(c3[4] & C3_HIRAGANA, "C3_HIRAGANA");
        CHECK(c3[5] & C3_KATAKANA, "C3_KATAKANA");
        CHECK(c3[6] & C3_FULLWIDTH, "C3_FULLWIDTH");
        CHECK(c3[7] & C3_IDEOGRAPH, "C3_IDEOGRAPH");
    }
    {
        WORD c1[4];
        CHECK(GetStringTypeW(CT_CTYPE1, L"ab", -1, c1) && (c1[2] & C1_CNTRL), "cchSrc = -1 includes the terminator");
        SetLastError(0);
        CHECK(!GetStringTypeW(8, L"ab", 2, c1), "invalid info type fails");
        CHECK_ERR(ERROR_INVALID_PARAMETER, "invalid info type: ERROR_INVALID_PARAMETER");
        SetLastError(0);
        CHECK(!GetStringTypeW(CT_CTYPE1, 0, 2, c1), "NULL source fails");
        CHECK_ERR(ERROR_INVALID_PARAMETER, "NULL source: ERROR_INVALID_PARAMETER");
        CHECK(GetStringTypeExW(LOCALE_USER_DEFAULT, CT_CTYPE1, L"g", 1, c1) && c1[0] == 0x302, "GetStringTypeExW");
        CHECKV(GetStringTypeW(CT_CTYPE1, L"aA", 2, c1) && c1[0] == 0x382 && c1[1] == 0x381, "a and A are also hex digits", "%x %x", c1[0], c1[1]);
    }
}

static void test_fold(void)
{
    WCHAR d[32];
    int n;
    n = FoldStringW(MAP_FOLDDIGITS, L"١٢٣x", -1, d, 32);
    CHECK(n == 5 && k32t_weq(d, L"123x"), "MAP_FOLDDIGITS folds Arabic-Indic digits");
    n = FoldStringW(MAP_PRECOMPOSED, L"e" L"\x301" L"a", -1, d, 32);
    CHECK(n == 3 && d[0] == 0x00E9 && d[1] == 'a', "MAP_PRECOMPOSED composes e + acute");
    n = FoldStringW(MAP_COMPOSITE, L"éa", -1, d, 32);
    CHECK(n == 4 && d[0] == 'e' && d[1] == 0x0301 && d[2] == 'a', "MAP_COMPOSITE decomposes e-acute");
    n = FoldStringW(MAP_EXPAND_LIGATURES, L"\xfb01" L"ne", -1, d, 32);
    CHECK(n == 5 && k32t_weq(d, L"fine"), "MAP_EXPAND_LIGATURES expands fi");
    n = FoldStringW(MAP_FOLDCZONE, L"ＡＢ", -1, d, 32);
    CHECK(n == 3 && k32t_weq(d, L"AB"), "MAP_FOLDCZONE folds fullwidth letters");
    CHECK(FoldStringW(MAP_FOLDDIGITS, L"12", -1, 0, 0) == 3, "FoldStringW size query");
    SetLastError(0);
    CHECK(FoldStringW(0, L"a", -1, d, 32) == 0 && GetLastError() == ERROR_INVALID_FLAGS, "no flags: ERROR_INVALID_FLAGS");
    SetLastError(0);
    CHECK(FoldStringW(MAP_PRECOMPOSED | MAP_COMPOSITE, L"a", -1, d, 32) == 0 && GetLastError() == ERROR_INVALID_FLAGS, "PRECOMPOSED|COMPOSITE: ERROR_INVALID_FLAGS");
    SetLastError(0);
    n = FoldStringW(MAP_FOLDDIGITS, L"12345", -1, d, 3);
    CHECKV(GetLastError() == ERROR_INSUFFICIENT_BUFFER, "short buffer: ERROR_INSUFFICIENT_BUFFER", "n=%d err=%u", n, (unsigned)GetLastError());   /* Windows returns 0; Wine returns the needed size */
}

static void test_dates(void)
{
    SYSTEMTIME st = { 2024, 3, 0, 9, 15, 4, 5, 678 };                /* Saturday 2024-03-09 15:04:05.678; wDayOfWeek deliberately 0 */
    WCHAR b[128];
    int n;
    n = GetDateFormatW(LOCALE_USER_DEFAULT, DATE_LONGDATE, &st, 0, b, 128);
    CHECKV(n == 24 && k32t_weq(b, L"Saturday, March 9, 2024"), "DATE_LONGDATE", "n=%d", n);
    n = GetDateFormatW(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &st, 0, b, 128);
    CHECK(n == 9 && k32t_weq(b, L"3/9/2024"), "DATE_SHORTDATE");
    n = GetDateFormatW(LOCALE_USER_DEFAULT, 0, &st, 0, b, 128);
    CHECK(n == 9 && k32t_weq(b, L"3/9/2024"), "no date flag: short date");
    n = GetDateFormatW(LOCALE_USER_DEFAULT, DATE_YEARMONTH, &st, 0, b, 128);
    CHECK(n == 11 && k32t_weq(b, L"March 2024"), "DATE_YEARMONTH");
    n = GetDateFormatW(LOCALE_USER_DEFAULT, 0, &st, L"yyyy-MM-dd ddd MMM", b, 128);
    CHECK(n == 19 && k32t_weq(b, L"2024-03-09 Sat Mar"), "custom picture with padded fields and abbreviations");
    n = GetDateFormatW(LOCALE_USER_DEFAULT, 0, &st, L"'Day' d 'of' MMMM yy", b, 128);
    CHECK(k32t_weq(b, L"Day 9 of March 24") && n == 18, "quoted literals and two digit year");
    n = GetDateFormatEx(L"en-US", DATE_LONGDATE, &st, 0, b, 128, 0);
    CHECK(n == 24 && k32t_weq(b, L"Saturday, March 9, 2024"), "GetDateFormatEx");
    n = GetDateFormatEx(LOCALE_NAME_INVARIANT, DATE_SHORTDATE, &st, 0, b, 128, 0);
    CHECK(n == 11 && k32t_weq(b, L"03/09/2024"), "invariant short date");
    CHECK(GetDateFormatW(LOCALE_USER_DEFAULT, DATE_LONGDATE, &st, 0, 0, 0) == 24, "date size query");
    SetLastError(0);
    CHECK(GetDateFormatW(LOCALE_USER_DEFAULT, DATE_LONGDATE, &st, 0, b, 5) == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "date short buffer");
    {
        SYSTEMTIME bad = st;
        bad.wMonth = 13;
        SetLastError(0);
        CHECK(GetDateFormatW(LOCALE_USER_DEFAULT, 0, &bad, 0, b, 128) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "month 13 is invalid");
        bad = st; bad.wMonth = 2; bad.wDay = 30;
        SetLastError(0);
        CHECK(GetDateFormatW(LOCALE_USER_DEFAULT, 0, &bad, 0, b, 128) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "30 February is invalid");
        bad = st; bad.wYear = 2023; bad.wMonth = 2; bad.wDay = 29;
        SetLastError(0);
        bad.wYear = 2024;
        CHECK(GetDateFormatW(LOCALE_USER_DEFAULT, 0, &bad, 0, b, 128) == 10 && k32t_weq(b, L"2/29/2024"), "29 February 2024 is valid");
        bad = st; bad.wYear = 1600;
        SetLastError(0);
        CHECK(GetDateFormatW(LOCALE_USER_DEFAULT, 0, &bad, 0, b, 128) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "year 1600 is invalid");
    }
    SetLastError(0);
    CHECK(GetDateFormatW(LOCALE_USER_DEFAULT, DATE_LONGDATE | DATE_SHORTDATE, &st, 0, b, 128) == 0 && GetLastError() == ERROR_INVALID_FLAGS, "two date pictures at once: ERROR_INVALID_FLAGS");
    SetLastError(0);
    CHECK(GetDateFormatW(LOCALE_USER_DEFAULT, DATE_LONGDATE, &st, L"yyyy", b, 128) == 0 && GetLastError() == ERROR_INVALID_FLAGS, "flags with an explicit picture: ERROR_INVALID_FLAGS");
    SetLastError(0);
    CHECK(GetDateFormatW(0xDEAD, 0, &st, 0, b, 128) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "invalid locale");
    /* time */
    n = GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &st, 0, b, 128);
    CHECK(n == 11 && k32t_weq(b, L"3:04:05 PM"), "default time format");
    n = GetTimeFormatW(LOCALE_USER_DEFAULT, TIME_NOSECONDS, &st, 0, b, 128);
    CHECK(n == 8 && k32t_weq(b, L"3:04 PM"), "TIME_NOSECONDS");
    n = GetTimeFormatW(LOCALE_USER_DEFAULT, TIME_NOTIMEMARKER, &st, 0, b, 128);
    CHECK(n == 8 && k32t_weq(b, L"3:04:05"), "TIME_NOTIMEMARKER");
    n = GetTimeFormatW(LOCALE_USER_DEFAULT, TIME_NOMINUTESORSECONDS, &st, 0, b, 128);
    CHECK(n == 5 && k32t_weq(b, L"3 PM"), "TIME_NOMINUTESORSECONDS");
    n = GetTimeFormatW(LOCALE_USER_DEFAULT, TIME_FORCE24HOURFORMAT | TIME_NOTIMEMARKER, &st, 0, b, 128);
    CHECK(n == 9 && k32t_weq(b, L"15:04:05"), "TIME_FORCE24HOURFORMAT | TIME_NOTIMEMARKER");
    n = GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &st, L"HH':'mm':'ss", b, 128);
    CHECK(n == 9 && k32t_weq(b, L"15:04:05"), "custom 24 hour picture");
    n = GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &st, L"hh.mm t", b, 128);
    CHECK(k32t_weq(b, L"03.04 P") && n == 8, "two digit hour and one letter marker");
    n = GetTimeFormatEx(L"en-US", 0, &st, 0, b, 128);
    CHECK(n == 11 && k32t_weq(b, L"3:04:05 PM"), "GetTimeFormatEx");
    n = GetTimeFormatEx(LOCALE_NAME_INVARIANT, 0, &st, 0, b, 128);
    CHECK(n == 9 && k32t_weq(b, L"15:04:05"), "invariant time format");
    {
        SYSTEMTIME mid = st;
        mid.wHour = 0;
        n = GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &mid, 0, b, 128);
        CHECK(k32t_weq(b, L"12:04:05 AM"), "midnight is 12 AM");
        mid.wHour = 12;
        n = GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &mid, 0, b, 128);
        CHECK(k32t_weq(b, L"12:04:05 PM"), "noon is 12 PM");
        mid.wHour = 24;
        SetLastError(0);
        CHECK(GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &mid, 0, b, 128) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "hour 24 is invalid");
        mid = st; mid.wMinute = 60;
        SetLastError(0);
        CHECK(GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &mid, 0, b, 128) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "minute 60 is invalid");
    }
    CHECK(GetTimeFormatW(LOCALE_USER_DEFAULT, 0, 0, 0, b, 128) > 0, "NULL time uses the current time");
    CHECK(GetDateFormatW(LOCALE_USER_DEFAULT, 0, 0, 0, b, 128) > 0, "NULL date uses the current date");
}

static void test_numbers(void)
{
    WCHAR b[128];
    int n;
    n = GetNumberFormatEx(L"en-US", 0, L"1234567.891", 0, b, 128);
    CHECKV(n == 13 && k32t_weq(b, L"1,234,567.89"), "GetNumberFormatEx default", "n=%d", n);
    n = GetNumberFormatW(LOCALE_USER_DEFAULT, 0, L"-1234.5", 0, b, 128);
    CHECK(n == 10 && k32t_weq(b, L"-1,234.50"), "negative number");
    n = GetNumberFormatW(LOCALE_USER_DEFAULT, 0, L"0.5", 0, b, 128);
    CHECK(k32t_weq(b, L"0.50") && n == 5, "leading zero");
    n = GetNumberFormatW(LOCALE_USER_DEFAULT, 0, L"1234567", 0, b, 128);
    CHECK(n == 13 && k32t_weq(b, L"1,234,567.00"), "integer input gets the default 2 digits");
    {
        WCHAR dec[] = L",", thou[] = L".";
        NUMBERFMTW f = { 3, 0, 3, dec, thou, 1 };
        n = GetNumberFormatEx(L"en-US", 0, L"-0.5", &f, b, 128);
        CHECK(n == 6 && k32t_weq(b, L"-,500"), "custom NUMBERFMT: three digits, no leading zero, ',' decimal");
        n = GetNumberFormatEx(L"en-US", 0, L"1234567.8", &f, b, 128);
        CHECK(k32t_weq(b, L"1.234.567,800"), "custom separators");
        f.Grouping = 32;
        f.NumDigits = 0;
        n = GetNumberFormatEx(L"en-US", 0, L"1234567", &f, b, 128);
        CHECK(k32t_weq(b, L"12.34.567"), "grouping 3;2");
        SetLastError(0);
        CHECK(GetNumberFormatEx(L"en-US", LOCALE_NOUSEROVERRIDE, L"1", &f, b, 128) == 0 && GetLastError() == ERROR_INVALID_FLAGS, "flags with a NUMBERFMT: ERROR_INVALID_FLAGS");
    }
    SetLastError(0);
    CHECK(GetNumberFormatW(LOCALE_USER_DEFAULT, 0, L"12a", 0, b, 128) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "invalid number string");
    SetLastError(0);
    CHECK(GetNumberFormatW(LOCALE_USER_DEFAULT, 0, L"1234567", 0, b, 5) == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "number short buffer");
    CHECK(GetNumberFormatW(LOCALE_USER_DEFAULT, 0, L"1234567", 0, 0, 0) == 13, "number size query");
    n = GetCurrencyFormatEx(L"en-US", 0, L"1234567.891", 0, b, 128);
    CHECKV(n == 14 && k32t_weq(b, L"$1,234,567.89"), "GetCurrencyFormatEx default", "n=%d", n);
    n = GetCurrencyFormatEx(L"en-US", 0, L"-1234.5", 0, b, 128);
    CHECK(k32t_weq(b, L"($1,234.50)") && n == 12, "negative currency uses parentheses in en-US");
    n = GetCurrencyFormatW(LOCALE_USER_DEFAULT, 0, L"0", 0, b, 128);
    CHECK(k32t_weq(b, L"$0.00"), "zero currency");
    {
        WCHAR dec[] = L".", thou[] = L",", sym[] = L"EUR";
        CURRENCYFMTW f = { 2, 1, 3, dec, thou, 8, 3, sym };
        n = GetCurrencyFormatEx(L"en-US", 0, L"-1234.5", &f, b, 128);
        CHECK(k32t_weq(b, L"-1,234.50 EUR"), "custom CURRENCYFMT negative order 8");
        n = GetCurrencyFormatEx(L"en-US", 0, L"99.999", &f, b, 128);
        CHECK(k32t_weq(b, L"100.00 EUR"), "rounding carries and positive order 3");
    }
    (void)n;
}

static void test_misc(void)
{
    ULONG count = 0, cch = 0;
    WCHAR buf[32];
    CHECK(GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &count, 0, &cch) && count == 1 && cch == 7, "UI language size query: one language, 7 WCHARs");
    CHECK(GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &count, buf, &cch) && k32t_weq(buf, L"en-US") && buf[5] == 0 && buf[6] == 0, "UI language list is en-US double-terminated");
    cch = 7;
    CHECK(GetThreadPreferredUILanguages(MUI_LANGUAGE_ID, &count, buf, &cch) && k32t_weq(buf, L"0409") && count == 1 && cch == 6, "MUI_LANGUAGE_ID gives 0409");
    cch = 2;
    SetLastError(0);
    CHECK(!GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &count, buf, &cch) && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "UI language short buffer");
    CHECK(GetUserGeoID(GEOCLASS_NATION) == 244, "user geo id is 244 (United States)");
    CHECK(GetGeoInfoW(244, GEO_ISO2, buf, 32, 0) == 3 && k32t_weq(buf, L"US"), "GEO_ISO2");
    CHECK(GetGeoInfoW(244, GEO_ISO3, buf, 32, 0) == 4 && k32t_weq(buf, L"USA"), "GEO_ISO3");
    CHECK(GetGeoInfoW(244, GEO_NATION, buf, 32, 0) == 4 && k32t_weq(buf, L"244"), "GEO_NATION");
    SetLastError(0);
    CHECK(GetGeoInfoW(999999, GEO_ISO2, buf, 32, 0) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "unknown geo id");
}

int main(void)
{
    test_ids();
    test_localeinfo();
    test_enum();
    test_compare();
    test_lcmap();
    test_stringtype();
    test_fold();
    test_dates();
    test_numbers();
    test_misc();
    return k32t_finish("t_k32_nls");
}
