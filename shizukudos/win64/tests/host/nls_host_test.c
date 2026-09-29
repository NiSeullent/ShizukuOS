/* SPDX-License-Identifier: GPL-2.0-only
 * Native (Linux) unit test of the pure NLS code: nls_core.c (properties, case, character types, collation, sort keys)
 * and nls_fmt.c (date/time/number pictures). The same sources are linked into kernel32.dll.
 * Build and run:  python3 shizukudos/win64/tests/host/run_host_tests.py
 * Expected values come from the C library's own <ctype.h> for ASCII, from the Unicode standard (fixed code point pairs) and
 * from documented Windows formatting rules, not from the implementation under test. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../kernel32/nls_core.c"
#include "../../kernel32/nls_fmt.c"

static int failures, checks;
#define CHECK(cond, ...) do { ++checks; if (!(cond)) { ++failures; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static int w_from_utf8(const char *s, nls_w *w, int cap)
{
    int n = 0;
    while (*s) {
        unsigned c = (unsigned char)*s++, cp;
        if (c < 0x80) cp = c;
        else if ((c & 0xE0) == 0xC0) { cp = ((c & 0x1F) << 6) | (*s++ & 0x3F); }
        else if ((c & 0xF0) == 0xE0) { cp = ((c & 0x0F) << 12) | ((s[0] & 0x3F) << 6) | (s[1] & 0x3F); s += 2; }
        else { cp = ((c & 7) << 18) | ((s[0] & 0x3F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F); s += 3; }
        n += nls_put_cp(w, cap, n, cp);
    }
    w[n] = 0;
    return n;
}

static int cmp(const char *a, const char *b, uint32_t fl)
{
    nls_w wa[128], wb[128];
    const int na = w_from_utf8(a, wa, 128), nb = w_from_utf8(b, wb, 128);
    return nls_compare(wa, na, wb, nb, fl);
}

static int keycmp(const char *a, const char *b, uint32_t fl)
{
    nls_w wa[128], wb[128];
    uint8_t ka[1024], kb[1024];
    int na = w_from_utf8(a, wa, 128), nb = w_from_utf8(b, wb, 128), la, lb, m, c;
    la = nls_sortkey(wa, na, fl, ka, sizeof ka);
    lb = nls_sortkey(wb, nb, fl, kb, sizeof kb);
    CHECK(la <= (int)sizeof ka && lb <= (int)sizeof kb, "sort key fits");
    m = la < lb ? la : lb;
    c = memcmp(ka, kb, (size_t)m);
    if (c) return c < 0 ? -1 : 1;
    return la == lb ? 0 : la < lb ? -1 : 1;
}

static void test_ascii_ctype(void)
{
    int c;
    for (c = 0; c < 128; ++c) {
        const unsigned t = nls_ctype1((uint32_t)c);
        CHECK(!!(t & 1) == !!isupper(c), "C1_UPPER %d", c);
        CHECK(!!(t & 2) == !!islower(c), "C1_LOWER %d", c);
        CHECK(!!(t & 4) == !!isdigit(c), "C1_DIGIT %d", c);
        CHECK(!!(t & 8) == !!isspace(c), "C1_SPACE %d", c);
        CHECK(!!(t & 0x10) == !!ispunct(c), "C1_PUNCT %d", c);
        CHECK(!!(t & 0x20) == !!iscntrl(c), "C1_CNTRL %d", c);
        CHECK(!!(t & 0x40) == !!isblank(c), "C1_BLANK %d", c);
        CHECK(!!(t & 0x80) == !!isxdigit(c), "C1_XDIGIT %d", c);
        CHECK(!!(t & 0x100) == !!isalpha(c), "C1_ALPHA %d", c);
        CHECK(t & 0x200, "C1_DEFINED %d", c);
        CHECK(nls_upper((uint32_t)c) == (uint32_t)toupper(c), "toupper %d", c);
        CHECK(nls_lower((uint32_t)c) == (uint32_t)tolower(c), "tolower %d", c);
    }
    CHECK(nls_ctype1(0x0378) == 0, "unassigned U+0378 has no C1 bits");
    CHECK(nls_ctype1(0x0661) & 4, "ARABIC-INDIC DIGIT ONE is C1_DIGIT");
    CHECK(nls_ctype1(0x00E9) == (0x2 | 0x100 | 0x200), "e-acute is lower alpha defined (%x)", nls_ctype1(0x00E9));
    CHECK(nls_ctype1(0xFF21) & 0x80, "fullwidth A is a hex digit");
    CHECK(nls_ctype1(0x00A0) & (8 | 0x40), "NBSP is space and blank");
}

static void test_ctype23(void)
{
    CHECK(nls_ctype2('A') == 1, "C2 L");
    CHECK(nls_ctype2('1') == 3, "C2 EN");
    CHECK(nls_ctype2('+') == 4, "C2 ES");
    CHECK(nls_ctype2('$') == 5, "C2 ET");
    CHECK(nls_ctype2(',') == 7, "C2 CS");
    CHECK(nls_ctype2('\n') == 8, "C2 B");
    CHECK(nls_ctype2('\t') == 9, "C2 S");
    CHECK(nls_ctype2(' ') == 10, "C2 WS");
    CHECK(nls_ctype2('!') == 11, "C2 ON");
    CHECK(nls_ctype2(0x05D0) == 2, "C2 hebrew alef RTL");
    CHECK(nls_ctype2(0x0627) == 2, "C2 arabic alef RTL");
    CHECK(nls_ctype2(0x0660) == 6, "C2 arabic-indic digit AN");
    CHECK(nls_ctype3('a') == 0x8000, "C3 latin a alpha (%x)", nls_ctype3('a'));
    CHECK(nls_ctype3(0x0301) == 0x1, "C3 combining acute nonspacing (%x)", nls_ctype3(0x0301));
    CHECK(nls_ctype3(0xD83D) == 0x800 && nls_ctype3(0xDE00) == 0x1000, "C3 surrogates");
    CHECK(nls_ctype3(0x3042) == (0x20 | 0x8000), "C3 hiragana A (%x)", nls_ctype3(0x3042));
    CHECK(nls_ctype3(0x30A2) == (0x10 | 0x8000), "C3 katakana A (%x)", nls_ctype3(0x30A2));
    CHECK(nls_ctype3(0x4E00) == (0x100 | 0x8000), "C3 ideograph (%x)", nls_ctype3(0x4E00));
    CHECK(nls_ctype3(0xFF21) == (0x80 | 0x8000), "C3 fullwidth A (%x)", nls_ctype3(0xFF21));
    CHECK(nls_ctype3(0xFF71) == (0x40 | 0x10 | 0x8000), "C3 halfwidth katakana A (%x)", nls_ctype3(0xFF71));
    CHECK(nls_ctype3('+') & 0x8, "C3 symbol +");
}

static void test_case(void)
{
    CHECK(nls_upper(0x00E9) == 0x00C9, "e-acute");
    CHECK(nls_upper(0x00FF) == 0x0178, "y-diaeresis -> Y-diaeresis");
    CHECK(nls_upper(0x03B1) == 0x0391, "alpha");
    CHECK(nls_upper(0x044F) == 0x042F, "cyrillic ya");
    CHECK(nls_upper(0x00DF) == 0x00DF, "sharp s has no simple uppercase");
    CHECK(nls_upper(0x01C6) == 0x01C4 && nls_lower(0x01C4) == 0x01C6, "dz digraph");
    CHECK(nls_upper(0x1F80) == 0x1F88, "greek alpha with psili and ypogegrammeni");
    CHECK(nls_upper(0x10428) == 0x10400 && nls_lower(0x10400) == 0x10428, "deseret long i");
    CHECK(nls_lower(0x0130) == 'i', "capital I with dot above lowercases to i (simple mapping)");
    CHECK(nls_upper(0x0131) == 'I', "dotless i uppercases to I");
    CHECK(nls_lower(0x03A3) == 0x03C3, "capital sigma");
    CHECK(nls_upper('1') == '1' && nls_lower(0x4E00) == 0x4E00, "uncased characters map to themselves");
    {
        nls_w s[16], d[16];
        int n = w_from_utf8("Hello \xc3\xa9\xf0\x90\x90\xa8!", s, 16);        /* "Hello é" + U+10428 + "!" */
        int r = nls_map(s, n, d, 16, NLS_MAP_UPPER);
        nls_w want[16];
        int wn = w_from_utf8("HELLO \xc3\x89\xf0\x90\x90\x80!", want, 16);
        CHECK(r == wn && !memcmp(d, want, (size_t)wn * 2), "string uppercase with a supplementary character (%d)", r);
        CHECK(nls_map(s, n, d, 3, NLS_MAP_UPPER) == -1, "too small output reports -1");
        CHECK(nls_map(s, n, 0, 0, NLS_MAP_UPPER) == wn, "length-only query");
        r = nls_map(s, n, d, 16, NLS_MAP_FULLWIDTH);
        CHECK(d[0] == 0xFF28 && d[5] == 0x3000, "fullwidth H and ideographic space (%x %x)", d[0], d[5]);
        w_from_utf8("\xe3\x81\x82\xe3\x82\xa2", s, 16);                         /* hiragana A, katakana A */
        nls_map(s, 2, d, 16, NLS_MAP_KATAKANA);
        CHECK(d[0] == 0x30A2 && d[1] == 0x30A2, "hiragana -> katakana");
        nls_map(s, 2, d, 16, NLS_MAP_HIRAGANA);
        CHECK(d[0] == 0x3042 && d[1] == 0x3042, "katakana -> hiragana");
    }
}

static void test_decomp(void)
{
    uint32_t d[3];
    CHECK(nls_decompose(0x00E9, d) == 2 && d[0] == 'e' && d[1] == 0x0301, "e-acute decomposes");
    CHECK(nls_decompose(0x1E09, d) == 3 && d[0] == 'c' && d[1] == 0x0327 && d[2] == 0x0301, "c-cedilla-acute fully decomposes");
    CHECK(nls_decompose('a', d) == 0, "ASCII has no decomposition");
    CHECK(nls_compose('e', 0x0301) == 0x00E9, "compose e + acute");
    CHECK(nls_compose('e', 'e') == 0, "no composition");
}

static void test_compare(void)
{
    CHECK(cmp("a", "A", 0) < 0, "lowercase sorts before uppercase");
    CHECK(cmp("a", "A", NLS_IGNORECASE) == 0, "NORM_IGNORECASE equal");
    CHECK(cmp("a", "b", 0) < 0 && cmp("b", "a", 0) > 0, "a < b");
    CHECK(cmp("apple", "Banana", 0) < 0, "linguistic: apple < Banana (ordinal says the opposite)");
    CHECK(cmp("Zebra", "apple", 0) > 0, "Z > a linguistically");
    CHECK(cmp("resume", "r\xc3\xa9sum\xc3\xa9", 0) < 0, "accent sorts after the plain letter");
    CHECK(cmp("resume", "r\xc3\xa9sum\xc3\xa9", NLS_IGNORENONSPACE) == 0, "NORM_IGNORENONSPACE equal");
    CHECK(cmp("resume", "r\xc3\xa9sum\xc3\xa9", NLS_IGNORENONSPACE | NLS_IGNORECASE) == 0, "both ignore flags");
    CHECK(cmp("e\xcc\x81", "\xc3\xa9", 0) == 0, "decomposed and precomposed are equal");
    CHECK(cmp("\xc3\xa9", "f", 0) < 0 && cmp("\xc3\xa9", "e", 0) > 0 && cmp("\xc3\xa9", "d", 0) > 0, "e-acute sorts with e");
    CHECK(cmp("10", "9", 0) < 0, "string compare: 10 < 9");
    CHECK(cmp("10", "9", NLS_DIGITSASNUMBERS) > 0, "digits as numbers: 10 > 9");
    CHECK(cmp("a10", "a9", NLS_DIGITSASNUMBERS) > 0, "digits as numbers inside a word");
    CHECK(cmp("a007", "a7", NLS_DIGITSASNUMBERS) == 0, "leading zeros ignored when digits are numbers");
    CHECK(cmp("abc", "abcd", 0) < 0, "prefix sorts first");
    CHECK(cmp("", "a", 0) < 0 && cmp("", "", 0) == 0, "empty string");
    CHECK(cmp("1", "a", 0) < 0, "digits before letters");
    CHECK(cmp("_", "1", 0) < 0 && cmp("$", "1", 0) < 0 && cmp("-", "1", NLS_STRINGSORT) < 0, "punctuation, currency before digits");
    CHECK(cmp("_", "-", NLS_STRINGSORT) < 0 && cmp("-", ",", NLS_STRINGSORT) < 0 && cmp("!", "?", NLS_STRINGSORT) < 0 &&
          cmp("(", ")", NLS_STRINGSORT) < 0 && cmp("+", "=", NLS_STRINGSORT) < 0 && cmp("~", "$", NLS_STRINGSORT) < 0,
          "DUCET order of ASCII punctuation");
    CHECK(cmp("co-op", "coa", 0) > 0, "word sort ignores the hyphen at the first levels");
    CHECK(cmp("co-op", "coa", NLS_STRINGSORT) < 0, "string sort orders the hyphen as punctuation");
    CHECK(cmp("co-op", "coop", 0) > 0 && cmp("coop", "co-op", 0) < 0, "word sort: hyphen only breaks ties");
    CHECK(cmp("a b", "ab", NLS_IGNORESYMBOLS) == 0, "NORM_IGNORESYMBOLS ignores white space");
    CHECK(cmp("a.b", "ab", NLS_IGNORESYMBOLS) == 0, "NORM_IGNORESYMBOLS ignores punctuation");
    CHECK(cmp("a b", "ab", 0) < 0, "space is not ignored by default");
    CHECK(cmp("stra\xc3\x9f" "e", "strasse", 0) > 0 && cmp("stra\xc3\x9f" "e", "strasse", NLS_IGNORECASE) > 0, "sharp s expands to ss with a tertiary difference");
    CHECK(cmp("stra\xc3\x9f" "e", "strass", 0) > 0, "sharp s expansion is longer than ss");
    CHECK(cmp("\xc3\xa6", "ae", 0) > 0 && cmp("\xc3\xa6", "af", 0) < 0, "ae ligature sorts as ae");
    CHECK(cmp("\xef\xbc\xa1", "A", 0) > 0 && cmp("\xef\xbc\xa1", "A", NLS_IGNOREWIDTH) == 0, "fullwidth A vs A");
    CHECK(cmp("\xe3\x81\x82", "\xe3\x82\xa2", 0) < 0 && cmp("\xe3\x81\x82", "\xe3\x82\xa2", NLS_IGNOREKANATYPE) == 0, "hiragana vs katakana");
    CHECK(cmp("\xce\xb1", "z", 0) > 0, "Greek after Latin");
    CHECK(cmp("\xce\xb1", "\xce\x91", 0) < 0 && cmp("\xce\xb1", "\xce\x91", NLS_IGNORECASE) == 0, "Greek case");
    CHECK(cmp("\xd0\xaf", "\xd0\xb0", 0) > 0, "cyrillic Ya after a");
    CHECK(cmp("\xf0\x90\x90\x80", "\xf0\x90\x90\xa8", NLS_IGNORECASE) == 0, "supplementary case folding");
    CHECK(cmp("\xc3\xb8", "o", 0) > 0 && cmp("\xc3\xb8", "p", 0) < 0, "o with stroke sorts with o");
}

static const char *const pool[] = {
    "", "a", "A", "b", "B", "ab", "aB", "Ab", "AB", "abc", "a b", "a-b", "a'b", "ab1", "a1", "a10", "a9", "a09", "10", "9", "09",
    "co-op", "coop", "coa", "cooper", "\xc3\xa9", "e\xcc\x81", "e", "E", "\xc3\x89", "f", "resume", "r\xc3\xa9sum\xc3\xa9",
    "r\xc3\xa9sume", "stra\xc3\x9f" "e", "strasse", "\xc3\xa6", "ae", "\xef\xbc\xa1", "\xce\xb1", "\xce\x91", "\xd0\xaf", "_x", "$", "1",
    "\xe3\x81\x82", "\xe3\x82\xa2", "z", "Z", "\xc3\xb8", "o", ".", "a.b", "a_b", "\t", " ", "x y", "xy", "\xef\xbc\x91",
    "\xd9\xa1", "\xf0\x90\x90\x80", "\xf0\x90\x90\xa8", "\xe4\xb8\x80", "\xe4\xba\x8c",
};
#define POOL_N ((int)(sizeof pool / sizeof pool[0]))

static void test_properties(void)
{
    static const uint32_t flagsets[] = { 0, NLS_IGNORECASE, NLS_IGNORENONSPACE, NLS_IGNORESYMBOLS, NLS_STRINGSORT, NLS_DIGITSASNUMBERS,
        NLS_IGNOREKANATYPE | NLS_IGNOREWIDTH, NLS_IGNORECASE | NLS_IGNORENONSPACE | NLS_IGNORESYMBOLS, NLS_STRINGSORT | NLS_DIGITSASNUMBERS };
    unsigned f;
    int i, j, k;
    for (f = 0; f < sizeof flagsets / sizeof flagsets[0]; ++f) {
        for (i = 0; i < POOL_N; ++i) {
            CHECK(cmp(pool[i], pool[i], flagsets[f]) == 0, "reflexive %d flags %x", i, flagsets[f]);
            for (j = 0; j < POOL_N; ++j) {
                const int ab = cmp(pool[i], pool[j], flagsets[f]), ba = cmp(pool[j], pool[i], flagsets[f]);
                const int ks = keycmp(pool[i], pool[j], flagsets[f]);
                CHECK(ab == -ba, "antisymmetric \"%s\" \"%s\" flags %x (%d %d)", pool[i], pool[j], flagsets[f], ab, ba);
                CHECK(ab == ks, "sort key order matches compare for \"%s\" \"%s\" flags %x (%d vs %d)", pool[i], pool[j], flagsets[f], ab, ks);
            }
        }
        /* transitivity on all triples */
        for (i = 0; i < POOL_N; ++i)
            for (j = 0; j < POOL_N; ++j) {
                const int ab = cmp(pool[i], pool[j], flagsets[f]);
                if (ab > 0) continue;
                for (k = 0; k < POOL_N; ++k) {
                    const int bc = cmp(pool[j], pool[k], flagsets[f]), ac = cmp(pool[i], pool[k], flagsets[f]);
                    if (bc <= 0) CHECK(ac <= 0, "transitive \"%s\" <= \"%s\" <= \"%s\" flags %x", pool[i], pool[j], pool[k], flagsets[f]);
                    if ((ab < 0 && bc <= 0) || (ab <= 0 && bc < 0))
                        CHECK(ac < 0, "strict transitive \"%s\" ... \"%s\" ... \"%s\" flags %x (%d)", pool[i], pool[j], pool[k], flagsets[f], ac);
                    if (ab == 0 && bc == 0) CHECK(ac == 0, "equivalence transitive \"%s\" \"%s\" \"%s\" flags %x", pool[i], pool[j], pool[k], flagsets[f]);
                }
            }
    }
}

static int fmt_str(const char *expect, const nls_w *got, int n)
{
    nls_w e[256];
    int en = w_from_utf8(expect, e, 256);
    return n == en && !memcmp(e, got, (size_t)n * 2);
}

static void test_format(void)
{
    nls_dt t = { 2024, 3, 9, 6, 15, 4, 5 };                       /* Saturday 9 March 2024, 15:04:05 */
    nls_w pic[128], out[256], am[4], pm[4];
    int n;
    w_from_utf8("AM", am, 4); w_from_utf8("PM", pm, 4);
    CHECK(nls_day_of_week(2024, 3, 9) == 6 && nls_day_of_week(2000, 1, 1) == 6 && nls_day_of_week(1970, 1, 1) == 4 &&
          nls_day_of_week(1601, 1, 1) == 1 && nls_day_of_week(2024, 2, 29) == 4, "day of week");
    CHECK(nls_days_in_month(2024, 2) == 29 && nls_days_in_month(1900, 2) == 28 && nls_days_in_month(2000, 2) == 29 &&
          nls_days_in_month(2023, 4) == 30 && nls_days_in_month(2023, 12) == 31 && nls_days_in_month(2023, 13) == 0, "days in month");
    w_from_utf8("dddd, MMMM d, yyyy", pic, 128);
    n = nls_picture(NLS_PIC_DATE, pic, &t, am, pm, out, 256);
    CHECK(fmt_str("Saturday, March 9, 2024", out, n), "long date (%d)", n);
    w_from_utf8("M/d/yyyy", pic, 128);
    n = nls_picture(NLS_PIC_DATE, pic, &t, am, pm, out, 256);
    CHECK(fmt_str("3/9/2024", out, n), "short date");
    w_from_utf8("MM/dd/yy ddd MMM", pic, 128);
    n = nls_picture(NLS_PIC_DATE, pic, &t, am, pm, out, 256);
    CHECK(fmt_str("03/09/24 Sat Mar", out, n), "padded date pieces");
    w_from_utf8("'Day' d 'of' MMMM", pic, 128);
    n = nls_picture(NLS_PIC_DATE, pic, &t, am, pm, out, 256);
    CHECK(fmt_str("Day 9 of March", out, n), "quoted literals");
    w_from_utf8("h:mm:ss tt", pic, 128);
    n = nls_picture(NLS_PIC_TIME, pic, &t, am, pm, out, 256);
    CHECK(fmt_str("3:04:05 PM", out, n), "12 hour time");
    t.hour = 0;
    n = nls_picture(NLS_PIC_TIME, pic, &t, am, pm, out, 256);
    CHECK(fmt_str("12:04:05 AM", out, n), "midnight is 12 AM");
    t.hour = 12;
    n = nls_picture(NLS_PIC_TIME, pic, &t, am, pm, out, 256);
    CHECK(fmt_str("12:04:05 PM", out, n), "noon is 12 PM");
    t.hour = 15;
    w_from_utf8("HH:mm:ss", pic, 128);
    n = nls_picture(NLS_PIC_TIME, pic, &t, am, pm, out, 256);
    CHECK(fmt_str("15:04:05", out, n), "24 hour time");
    w_from_utf8("h:m t", pic, 128);
    n = nls_picture(NLS_PIC_TIME, pic, &t, am, pm, out, 256);
    CHECK(fmt_str("3:4 P", out, n), "single letter pieces");
    n = nls_picture(NLS_PIC_TIME, pic, &t, am, pm, out, 3);
    CHECK(n == -1, "output too small");
    w_from_utf8("h:mm:ss tt", pic, 128);
    n = nls_time_picture_edit(pic, 2, out, 256);
    CHECK(fmt_str("h:mm tt", out, n), "TIME_NOSECONDS");
    n = nls_time_picture_edit(pic, 1, out, 256);
    CHECK(fmt_str("h tt", out, n), "TIME_NOMINUTESORSECONDS");
    n = nls_time_picture_edit(pic, 4, out, 256);
    CHECK(fmt_str("h:mm:ss", out, n), "TIME_NOTIMEMARKER");
    n = nls_time_picture_edit(pic, 8, out, 256);
    CHECK(fmt_str("H:mm:ss tt", out, n), "TIME_FORCE24HOURFORMAT alone keeps the marker");
    n = nls_time_picture_edit(pic, 8 | 4, out, 256);
    CHECK(fmt_str("H:mm:ss", out, n), "TIME_FORCE24HOURFORMAT | TIME_NOTIMEMARKER");
    w_from_utf8("tt h:mm", pic, 128);
    n = nls_time_picture_edit(pic, 4, out, 256);
    CHECK(fmt_str("h:mm", out, n), "leading marker removal");
}

static int num(const char *v, unsigned digits, unsigned lz, unsigned grp, unsigned neg, char *res, size_t cap)
{
    nls_w wv[400], out[800], dec[2], thou[2];
    nls_numfmt f;
    int n, i;
    w_from_utf8(v, wv, 400); w_from_utf8(".", dec, 2); w_from_utf8(",", thou, 2);
    f.digits = digits; f.lzero = lz; f.grouping = grp; f.negorder = neg; f.posorder = 0; f.dec = dec; f.thou = thou; f.curr = dec;
    n = nls_number(wv, &f, 0, out, 800);
    if (n < 0) return n;
    for (i = 0; i < n && (size_t)i + 1 < cap; ++i) res[i] = (char)out[i];
    res[i] = 0;
    return n;
}

static int cur(const char *v, unsigned neg, unsigned pos, char *res, size_t cap)
{
    nls_w wv[400], out[800], dec[2], thou[2], sym[2];
    nls_numfmt f;
    int n, i;
    w_from_utf8(v, wv, 400); w_from_utf8(".", dec, 2); w_from_utf8(",", thou, 2); w_from_utf8("$", sym, 2);
    f.digits = 2; f.lzero = 1; f.grouping = 3; f.negorder = neg; f.posorder = pos; f.dec = dec; f.thou = thou; f.curr = sym;
    n = nls_number(wv, &f, 1, out, 800);
    if (n < 0) return n;
    for (i = 0; i < n && (size_t)i + 1 < cap; ++i) res[i] = (char)out[i];
    res[i] = 0;
    return n;
}

static void test_number(void)
{
    char r[128];
    CHECK(num("1234567.891", 2, 1, 3, 1, r, sizeof r) > 0 && !strcmp(r, "1,234,567.89"), "grouping and rounding (%s)", r);
    CHECK(num("1234567.895", 2, 1, 3, 1, r, sizeof r) > 0 && !strcmp(r, "1,234,567.90"), "round half up (%s)", r);
    CHECK(num("999.999", 2, 1, 3, 1, r, sizeof r) > 0 && !strcmp(r, "1,000.00"), "carry into the integer part (%s)", r);
    CHECK(num("0.5", 2, 1, 3, 1, r, sizeof r) > 0 && !strcmp(r, "0.50"), "leading zero (%s)", r);
    CHECK(num("0.5", 2, 0, 3, 1, r, sizeof r) > 0 && !strcmp(r, ".50"), "no leading zero (%s)", r);
    CHECK(num("-1234.5", 1, 1, 3, 1, r, sizeof r) > 0 && !strcmp(r, "-1,234.5"), "negative order 1 (%s)", r);
    CHECK(num("-1234.5", 1, 1, 3, 0, r, sizeof r) > 0 && !strcmp(r, "(1,234.5)"), "negative order 0 (%s)", r);
    CHECK(num("-1234.5", 1, 1, 3, 2, r, sizeof r) > 0 && !strcmp(r, "- 1,234.5"), "negative order 2 (%s)", r);
    CHECK(num("-1234.5", 1, 1, 3, 3, r, sizeof r) > 0 && !strcmp(r, "1,234.5-"), "negative order 3 (%s)", r);
    CHECK(num("-1234.5", 1, 1, 3, 4, r, sizeof r) > 0 && !strcmp(r, "1,234.5 -"), "negative order 4 (%s)", r);
    CHECK(num("1234567", 0, 1, 32, 1, r, sizeof r) > 0 && !strcmp(r, "12,34,567"), "Indian grouping 3;2 (%s)", r);
    CHECK(num("1234567", 0, 1, 0, 1, r, sizeof r) > 0 && !strcmp(r, "1234567"), "no grouping, no decimals (%s)", r);
    CHECK(num("1234567", 0, 1, 2, 1, r, sizeof r) > 0 && !strcmp(r, "1,23,45,67"), "grouping by 2 (%s)", r);
    CHECK(num("12", 3, 1, 3, 1, r, sizeof r) > 0 && !strcmp(r, "12.000"), "padding (%s)", r);
    CHECK(num("000123", 0, 1, 3, 1, r, sizeof r) > 0 && !strcmp(r, "123"), "leading zeros of the input dropped (%s)", r);
    CHECK(num("abc", 2, 1, 3, 1, r, sizeof r) == -2 && num("1.2.3", 2, 1, 3, 1, r, sizeof r) == -2 && num("", 2, 1, 3, 1, r, sizeof r) == -2 &&
          num("1e5", 2, 1, 3, 1, r, sizeof r) == -2 && num("-", 2, 1, 3, 1, r, sizeof r) == -2 && num(" 1", 2, 1, 3, 1, r, sizeof r) == -2,
          "invalid value strings");
    CHECK(num("1", 100, 1, 3, 1, r, sizeof r) == -2 && num("1", 2, 2, 3, 1, r, sizeof r) == -2 && num("1", 2, 1, 33, 1, r, sizeof r) == -2 &&
          num("1", 2, 1, 3, 5, r, sizeof r) == -2, "invalid formats");
    CHECK(cur("1234.5", 0, 0, r, sizeof r) > 0 && !strcmp(r, "$1,234.50"), "currency positive order 0 (%s)", r);
    CHECK(cur("1234.5", 0, 1, r, sizeof r) > 0 && !strcmp(r, "1,234.50$"), "positive order 1 (%s)", r);
    CHECK(cur("1234.5", 0, 2, r, sizeof r) > 0 && !strcmp(r, "$ 1,234.50"), "positive order 2 (%s)", r);
    CHECK(cur("1234.5", 0, 3, r, sizeof r) > 0 && !strcmp(r, "1,234.50 $"), "positive order 3 (%s)", r);
    {
        static const char *const neg[16] = { "($1,234.50)", "-$1,234.50", "$-1,234.50", "$1,234.50-", "(1,234.50$)", "-1,234.50$", "1,234.50-$",
                                             "1,234.50$-", "-1,234.50 $", "-$ 1,234.50", "1,234.50 $-", "$ 1,234.50-", "$ -1,234.50",
                                             "1,234.50- $", "($ 1,234.50)", "(1,234.50 $)" };
        unsigned k;
        for (k = 0; k < 16; ++k) CHECK(cur("-1234.5", k, 0, r, sizeof r) > 0 && !strcmp(r, neg[k]), "currency negative order %u (%s)", k, r);
    }
    CHECK(cur("-1234.5", 16, 0, r, sizeof r) == -2 && cur("1", 0, 4, r, sizeof r) == -2, "invalid currency orders");
}

int main(void)
{
    test_ascii_ctype();
    test_ctype23();
    test_case();
    test_decomp();
    test_compare();
    test_properties();
    test_format();
    test_number();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
