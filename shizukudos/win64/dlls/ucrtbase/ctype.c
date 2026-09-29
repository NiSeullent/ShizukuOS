/* SPDX-License-Identifier: GPL-2.0-only
 * Character classification, case mapping, the locale interface and multibyte/wide conversion of the Shizuku UCRT.
 *
 * Only the "C" locale exists (documented in docs/shizukudos10/CRT.md): narrow classification is ASCII (bytes 0x80..0xff
 * have no class, as in the Microsoft "C" locale), toupper/tolower/towupper/towlower map ASCII letters only, and the
 * multibyte code page of the C locale maps bytes 0..255 one-to-one onto U+0000..U+00FF. Wide classification
 * (iswalpha & co.) uses Unicode general categories (wctype_tab.h) where Windows would consult its NLS tables.
 * mbrtoc16 / c16rtomb / mbrtoc32 / c32rtomb always use UTF-8, as Microsoft documents for the UCRT.
 */
#include "crtint.h"
#include "wctype_tab.h"

#define C_UPPER 0x1
#define C_LOWER 0x2
#define C_DIGIT 0x4
#define C_SPACE 0x8
#define C_PUNCT 0x10
#define C_CONTROL 0x20
#define C_BLANK 0x40
#define C_HEX 0x80
#define C_ALPHA (0x100 | C_UPPER | C_LOWER)

/* ---------------------------------------------------------------- narrow "C" table: index -1 (EOF) .. 255 */
static unsigned short g_ctype[257];
static unsigned short g_wctype[256];
static int g_tables_built;
static void build_tables(void)
{
    int c;
    if (g_tables_built) return;
    for (c = 0; c < 128; ++c) {
        unsigned short m = 0;
        if (c < 32 || c == 127) m |= C_CONTROL;
        if (c >= 9 && c <= 13) m |= C_SPACE;
        if (c == 9 || c == ' ') m |= C_BLANK;
        if (c == ' ') m |= C_SPACE;
        if (c >= '0' && c <= '9') m |= C_DIGIT | C_HEX;
        if (c >= 'A' && c <= 'Z') m |= 0x100 | C_UPPER;
        if (c >= 'a' && c <= 'z') m |= 0x100 | C_LOWER;
        if ((c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) m |= C_HEX;
        if (c > 32 && c < 127 && !(m & (C_DIGIT | 0x100))) m |= C_PUNCT;
        g_ctype[c + 1] = m;
    }
    {
        unsigned i;
        for (i = 0; i < sizeof wctype_runs / sizeof wctype_runs[0] && wctype_runs[i].lo < 256; ++i) {
            unsigned x;
            for (x = wctype_runs[i].lo; x <= wctype_runs[i].hi && x < 256; ++x) g_wctype[x] = wctype_runs[i].m;
        }
    }
    g_tables_built = 1;
}
static unsigned short narrow_class(int c)
{
    if (c < -1 || c > 255) return 0;
    build_tables();
    return g_ctype[c + 1];
}
static unsigned wide_class(unsigned c)
{
    unsigned lo = 0, hi = sizeof wctype_runs / sizeof wctype_runs[0];
    if (c == CRT_WEOF) return 0;
    if (c < 256) { build_tables(); return g_wctype[c]; }
    while (lo < hi) {
        unsigned mid = (lo + hi) / 2;
        if (c < wctype_runs[mid].lo) hi = mid;
        else if (c > wctype_runs[mid].hi) lo = mid + 1;
        else return wctype_runs[mid].m;
    }
    return 0;
}

DLLAPI const unsigned short *CRTAPI __pctype_func(void) { build_tables(); return g_ctype + 1; }
DLLAPI const unsigned short *CRTAPI __pwctype_func(void) { build_tables(); return g_wctype; }
DLLAPI int CRTAPI _isctype(int c, int mask) { return narrow_class(c) & mask; }
DLLAPI int CRTAPI _isctype_l(int c, int mask, void *l) { (void)l; return _isctype(c, mask); }

#define NARROW_IS(name, mask)                                                                                          \
    DLLAPI int CRTAPI name(int c) { return narrow_class(c) & (mask); }                                                 \
    DLLAPI int CRTAPI _##name##_l(int c, void *l) { (void)l; return narrow_class(c) & (mask); }
NARROW_IS(isalpha, C_ALPHA)
NARROW_IS(isupper, C_UPPER)
NARROW_IS(islower, C_LOWER)
NARROW_IS(isdigit, C_DIGIT)
NARROW_IS(isxdigit, C_HEX)
NARROW_IS(isspace, C_SPACE)
NARROW_IS(ispunct, C_PUNCT)
NARROW_IS(isalnum, C_ALPHA | C_DIGIT)
NARROW_IS(isprint, C_ALPHA | C_DIGIT | C_PUNCT | C_BLANK)
NARROW_IS(isgraph, C_ALPHA | C_DIGIT | C_PUNCT)
NARROW_IS(iscntrl, C_CONTROL)
DLLAPI int CRTAPI isblank(int c) { return c == '\t' ? C_BLANK : narrow_class(c) & C_BLANK; }
DLLAPI int CRTAPI _isblank_l(int c, void *l) { (void)l; return isblank(c); }
int crt_isspace_c(int c) { return narrow_class(c) & C_SPACE; }
DLLAPI int CRTAPI __isascii(int c) { return (unsigned)c < 0x80; }
DLLAPI int CRTAPI __toascii(int c) { return c & 0x7f; }
DLLAPI int CRTAPI __iscsymf(int c) { return isalpha(c) || c == '_'; }
DLLAPI int CRTAPI __iscsym(int c) { return isalnum(c) || c == '_'; }

int crt_toupper_c(int c) { return (c >= 'a' && c <= 'z') ? c - 32 : c; }
int crt_tolower_c(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }
DLLAPI int CRTAPI toupper(int c) { return crt_toupper_c(c); }
DLLAPI int CRTAPI tolower(int c) { return crt_tolower_c(c); }
DLLAPI int CRTAPI _toupper_l(int c, void *l) { (void)l; return crt_toupper_c(c); }
DLLAPI int CRTAPI _tolower_l(int c, void *l) { (void)l; return crt_tolower_c(c); }
DLLAPI int CRTAPI _toupper(int c) { return c - 'a' + 'A'; }             /* unconditional, as documented */
DLLAPI int CRTAPI _tolower(int c) { return c - 'A' + 'a'; }

/* ---------------------------------------------------------------- wide classification */
unsigned crt_towupper_c(unsigned c) { return (c >= 'a' && c <= 'z') ? c - 32 : c; }
unsigned crt_towlower_c(unsigned c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }
DLLAPI crt_wint CRTAPI towupper(crt_wint c) { return (crt_wint)crt_towupper_c(c); }
DLLAPI crt_wint CRTAPI towlower(crt_wint c) { return (crt_wint)crt_towlower_c(c); }
DLLAPI crt_wint CRTAPI _towupper_l(crt_wint c, void *l) { (void)l; return towupper(c); }
DLLAPI crt_wint CRTAPI _towlower_l(crt_wint c, void *l) { (void)l; return towlower(c); }
DLLAPI int CRTAPI iswctype(crt_wint c, unsigned short mask) { return (int)(wide_class(c) & mask); }
DLLAPI int CRTAPI _iswctype_l(crt_wint c, unsigned short mask, void *l) { (void)l; return iswctype(c, mask); }
DLLAPI int CRTAPI is_wctype(crt_wint c, unsigned short mask) { return iswctype(c, mask); }
#define WIDE_IS(name, mask)                                                                                            \
    DLLAPI int CRTAPI name(crt_wint c) { return (int)(wide_class(c) & (mask)); }                                       \
    DLLAPI int CRTAPI _##name##_l(crt_wint c, void *l) { (void)l; return (int)(wide_class(c) & (mask)); }
WIDE_IS(iswalpha, C_ALPHA)
WIDE_IS(iswupper, C_UPPER)
WIDE_IS(iswlower, C_LOWER)
WIDE_IS(iswdigit, C_DIGIT)
WIDE_IS(iswxdigit, C_HEX)
WIDE_IS(iswspace, C_SPACE)
WIDE_IS(iswpunct, C_PUNCT)
WIDE_IS(iswalnum, C_ALPHA | C_DIGIT)
WIDE_IS(iswprint, C_ALPHA | C_DIGIT | C_PUNCT | C_BLANK)
WIDE_IS(iswgraph, C_ALPHA | C_DIGIT | C_PUNCT)
WIDE_IS(iswcntrl, C_CONTROL)
WIDE_IS(iswblank, C_BLANK)
DLLAPI int CRTAPI iswascii(crt_wint c) { return c < 0x80; }
DLLAPI int CRTAPI __iswcsymf(crt_wint c) { return iswalpha(c) || c == '_'; }
DLLAPI int CRTAPI __iswcsym(crt_wint c) { return iswalnum(c) || c == '_'; }

static const struct { const char *name; unsigned short mask; } g_wctypes[] = {
    {"alnum", C_ALPHA | C_DIGIT}, {"alpha", C_ALPHA}, {"blank", C_BLANK}, {"cntrl", C_CONTROL}, {"digit", C_DIGIT},
    {"graph", C_ALPHA | C_DIGIT | C_PUNCT}, {"lower", C_LOWER}, {"print", C_ALPHA | C_DIGIT | C_PUNCT | C_BLANK},
    {"punct", C_PUNCT}, {"space", C_SPACE}, {"upper", C_UPPER}, {"xdigit", C_HEX},
};
DLLAPI unsigned short CRTAPI wctype(const char *name)
{
    unsigned i;
    for (i = 0; name && i < sizeof g_wctypes / sizeof g_wctypes[0]; ++i) {
        const char *a = g_wctypes[i].name, *b = name;
        while (*a && *a == *b) { ++a; ++b; }
        if (!*a && !*b) return g_wctypes[i].mask;
    }
    return 0;
}
DLLAPI crt_wint CRTAPI towctrans(crt_wint c, unsigned short t) { return t == 1 ? towupper(c) : t == 2 ? towlower(c) : c; }
DLLAPI unsigned short CRTAPI wctrans(const char *name)
{
    if (name && name[0] == 't' && name[1] == 'o' && name[2] == 'u' && name[3] == 'p' && name[4] == 'p' && name[5] == 'e' && name[6] == 'r' && !name[7]) return 1;
    if (name && name[0] == 't' && name[1] == 'o' && name[2] == 'l' && name[3] == 'o' && name[4] == 'w' && name[5] == 'e' && name[6] == 'r' && !name[7]) return 2;
    return 0;
}

/* ---------------------------------------------------------------- locale interface ("C" only) */
struct crt_lconv {
    char *decimal_point, *thousands_sep, *grouping, *int_curr_symbol, *currency_symbol, *mon_decimal_point,
        *mon_thousands_sep, *mon_grouping, *positive_sign, *negative_sign;
    char int_frac_digits, frac_digits, p_cs_precedes, p_sep_by_space, n_cs_precedes, n_sep_by_space, p_sign_posn, n_sign_posn;
    wchar16 *w_decimal_point, *w_thousands_sep, *w_int_curr_symbol, *w_currency_symbol, *w_mon_decimal_point,
        *w_mon_thousands_sep, *w_positive_sign, *w_negative_sign;
};
static char s_dot[] = ".", s_empty[] = "";
static wchar16 w_dot[] = { '.', 0 }, w_empty[] = { 0 };
static struct crt_lconv g_lconv = {
    s_dot, s_empty, s_empty, s_empty, s_empty, s_empty, s_empty, s_empty, s_empty, s_empty,
    127, 127, 127, 127, 127, 127, 127, 127,
    w_dot, w_empty, w_empty, w_empty, w_empty, w_empty, w_empty, w_empty,
};
DLLAPI struct crt_lconv *CRTAPI localeconv(void) { return &g_lconv; }

static char g_c_name[] = "C";
static wchar16 g_c_wname[] = { 'C', 0 };
static int is_c_name(const char *n)
{
    return n && ((n[0] == 'C' && !n[1]) || !n[0] || (n[0] == 'P' && n[1] == 'O' && n[2] == 'S' && n[3] == 'I' && n[4] == 'X' && !n[5]));
}
static int is_c_wname(const wchar16 *n)
{
    char tmp[8];
    size_t i;
    if (!n) return 0;
    for (i = 0; i < 7 && n[i]; ++i) tmp[i] = n[i] < 0x80 ? (char)n[i] : '?';
    if (i == 7 && n[i]) return 0;
    tmp[i] = 0;
    return is_c_name(tmp);
}
/* Querying returns "C"; selecting "C", "POSIX" or "" (the user default, which on this system is the C locale)
 * succeeds; every other locale name fails with a null result. */
DLLAPI char *CRTAPI setlocale(int cat, const char *name)
{
    if (cat < 0 || cat > 5) { crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return 0; }
    if (!name || is_c_name(name)) return g_c_name;
    return 0;
}
DLLAPI wchar16 *CRTAPI _wsetlocale(int cat, const wchar16 *name)
{
    if (cat < 0 || cat > 5) { crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return 0; }
    if (!name || is_c_wname(name)) return g_c_wname;
    return 0;
}
typedef struct { void *locinfo, *mbcinfo; } crt_locale_struct;
static crt_locale_struct g_c_locale;
DLLAPI void *CRTAPI _create_locale(int cat, const char *name)
{
    if (cat < 0 || cat > 5 || !name) { crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return 0; }
    return is_c_name(name) ? &g_c_locale : 0;
}
DLLAPI void *CRTAPI _wcreate_locale(int cat, const wchar16 *name)
{
    if (cat < 0 || cat > 5 || !name) { crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return 0; }
    return is_c_wname(name) ? &g_c_locale : 0;
}
DLLAPI void CRTAPI _free_locale(void *l) { (void)l; }
DLLAPI void *CRTAPI _get_current_locale(void) { return &g_c_locale; }
DLLAPI int CRTAPI _configthreadlocale(int mode)
{
    crt_ptd *p = crt_getptd();
    const int old = p->locale_mode ? p->locale_mode : 2;      /* _DISABLE_PER_THREAD_LOCALE is the default */
    if (mode == 1 || mode == 2) p->locale_mode = mode;
    else if (mode == -1) p->locale_mode = 0;
    else if (mode != 0) { crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return -1; }
    return old;
}
DLLAPI unsigned CRTAPI ___lc_codepage_func(void) { return 0; }          /* the C locale's code page (CP_ACP-free) */
DLLAPI unsigned CRTAPI ___lc_collate_cp_func(void) { return 0; }
static wchar16 *g_lc_names[6];
DLLAPI wchar16 **CRTAPI ___lc_locale_name_func(void) { return g_lc_names; }
DLLAPI int CRTAPI ___mb_cur_max_func(void) { return 1; }
DLLAPI int CRTAPI ___mb_cur_max_l_func(void *l) { (void)l; return 1; }

/* ---------------------------------------------------------------- C-locale multibyte <-> wide (bytes = U+0000..U+00FF) */
DLLAPI int CRTAPI mblen(const char *s, size_t n)
{
    if (!s || !n) return 0;
    return *s ? 1 : 0;
}
DLLAPI int CRTAPI mbtowc(wchar16 *pwc, const char *s, size_t n)
{
    if (!s) return 0;
    if (!n) return -1;
    if (pwc) *pwc = (unsigned char)*s;
    return *s ? 1 : 0;
}
int crt_wctomb_c(char *out, unsigned wc)
{
    if (wc > 0xff) return -1;
    *out = (char)wc;
    return 1;
}
DLLAPI int CRTAPI wctomb(char *s, wchar16 wc)
{
    if (!s) return 0;
    if (crt_wctomb_c(s, wc) < 0) { crt_set_errno(CRT_EILSEQ); return -1; }
    return 1;
}
DLLAPI crt_errno_t CRTAPI wctomb_s(int *ret, char *s, size_t n, wchar16 wc)
{
    if (!s) { if (ret) *ret = 0; return 0; }
    CRT_VALIDATE(n >= 1, CRT_ERANGE, CRT_ERANGE);
    if (crt_wctomb_c(s, wc) < 0) { if (ret) *ret = -1; crt_set_errno(CRT_EILSEQ); return CRT_EILSEQ; }
    if (ret) *ret = 1;
    return 0;
}
DLLAPI size_t CRTAPI mbstowcs(wchar16 *d, const char *s, size_t n)
{
    size_t i = 0;
    CRT_VALIDATE(s != 0, CRT_EINVAL, (size_t)-1);
    if (!d) return crt_strlen(s);
    for (; i < n; ++i) {
        d[i] = (unsigned char)s[i];
        if (!s[i]) break;
    }
    return i;
}
DLLAPI size_t CRTAPI wcstombs(char *d, const wchar16 *s, size_t n)
{
    size_t i;
    CRT_VALIDATE(s != 0, CRT_EINVAL, (size_t)-1);
    if (!d) {
        for (i = 0; s[i]; ++i)
            if (s[i] > 0xff) { crt_set_errno(CRT_EILSEQ); return (size_t)-1; }
        return i;
    }
    for (i = 0; i < n; ++i) {
        if (s[i] > 0xff) { crt_set_errno(CRT_EILSEQ); return (size_t)-1; }
        d[i] = (char)s[i];
        if (!s[i]) break;
    }
    return i;
}
DLLAPI crt_errno_t CRTAPI mbstowcs_s(size_t *conv, wchar16 *d, size_t dn, const char *s, size_t count)
{
    size_t len, i, lim;
    CRT_VALIDATE((d != 0 && dn > 0) || (d == 0 && dn == 0), CRT_EINVAL, CRT_EINVAL);
    if (d) d[0] = 0;
    if (conv) *conv = 0;
    CRT_VALIDATE(s != 0, CRT_EINVAL, CRT_EINVAL);
    len = crt_strlen(s);
    lim = count == (size_t)-1 ? len : (count < len ? count : len);
    if (!d) { if (conv) *conv = lim + 1; return 0; }
    if (lim >= dn) {
        if (count == (size_t)-1) {
            for (i = 0; i + 1 < dn; ++i) d[i] = (unsigned char)s[i];
            d[dn - 1] = 0;
            if (conv) *conv = dn;
            return CRT_STRUNCATE;
        }
        d[0] = 0;
        CRT_VALIDATE(0, CRT_ERANGE, CRT_ERANGE);
    }
    for (i = 0; i < lim; ++i) d[i] = (unsigned char)s[i];
    d[lim] = 0;
    if (conv) *conv = lim + 1;
    return 0;
}
DLLAPI crt_errno_t CRTAPI wcstombs_s(size_t *conv, char *d, size_t dn, const wchar16 *s, size_t count)
{
    size_t len, i, lim;
    CRT_VALIDATE((d != 0 && dn > 0) || (d == 0 && dn == 0), CRT_EINVAL, CRT_EINVAL);
    if (d) d[0] = 0;
    if (conv) *conv = 0;
    CRT_VALIDATE(s != 0, CRT_EINVAL, CRT_EINVAL);
    len = crt_wcslen(s);
    lim = count == (size_t)-1 ? len : (count < len ? count : len);
    for (i = 0; i < lim; ++i)
        if (s[i] > 0xff) { crt_set_errno(CRT_EILSEQ); return CRT_EILSEQ; }
    if (!d) { if (conv) *conv = lim + 1; return 0; }
    if (lim >= dn) {
        if (count == (size_t)-1) {
            for (i = 0; i + 1 < dn; ++i) d[i] = (char)s[i];
            d[dn - 1] = 0;
            if (conv) *conv = dn;
            return CRT_STRUNCATE;
        }
        d[0] = 0;
        CRT_VALIDATE(0, CRT_ERANGE, CRT_ERANGE);
    }
    for (i = 0; i < lim; ++i) d[i] = (char)s[i];
    d[lim] = 0;
    if (conv) *conv = lim + 1;
    return 0;
}
DLLAPI crt_wint CRTAPI btowc(int c) { return (c == CRT_EOF || c < 0 || c > 255) ? CRT_WEOF : (crt_wint)c; }
DLLAPI int CRTAPI wctob(crt_wint c) { return c > 0xff ? CRT_EOF : (int)c; }
DLLAPI size_t CRTAPI mbrlen(const char *s, size_t n, void *st) { (void)st; if (!s) return 0; if (!n) return (size_t)-2; return *s ? 1 : 0; }
DLLAPI size_t CRTAPI mbrtowc(wchar16 *pwc, const char *s, size_t n, void *st)
{
    (void)st;
    if (!s) return 0;
    if (!n) return (size_t)-2;
    if (pwc) *pwc = (unsigned char)*s;
    return *s ? 1 : 0;
}
DLLAPI size_t CRTAPI wcrtomb(char *s, wchar16 wc, void *st)
{
    (void)st;
    if (!s) return 1;
    if (crt_wctomb_c(s, wc) < 0) { crt_set_errno(CRT_EILSEQ); return (size_t)-1; }
    return 1;
}
DLLAPI crt_errno_t CRTAPI wcrtomb_s(size_t *ret, char *s, size_t n, wchar16 wc, void *st)
{
    (void)st;
    if (!s) { if (ret) *ret = 1; return 0; }
    CRT_VALIDATE(n >= 1, CRT_EINVAL, CRT_EINVAL);
    if (crt_wctomb_c(s, wc) < 0) { if (ret) *ret = (size_t)-1; crt_set_errno(CRT_EILSEQ); return CRT_EILSEQ; }
    if (ret) *ret = 1;
    return 0;
}
DLLAPI size_t CRTAPI mbsrtowcs(wchar16 *d, const char **src, size_t n, void *st)
{
    const char *s;
    size_t i = 0;
    (void)st;
    CRT_VALIDATE(src != 0 && *src != 0, CRT_EINVAL, (size_t)-1);
    s = *src;
    if (!d) return crt_strlen(s);
    for (; i < n; ++i) {
        d[i] = (unsigned char)s[i];
        if (!s[i]) { *src = 0; return i; }
    }
    *src = s + i;
    return i;
}
DLLAPI size_t CRTAPI wcsrtombs(char *d, const wchar16 **src, size_t n, void *st)
{
    const wchar16 *s;
    size_t i = 0;
    (void)st;
    CRT_VALIDATE(src != 0 && *src != 0, CRT_EINVAL, (size_t)-1);
    s = *src;
    if (!d) return wcstombs(0, s, 0);
    for (; i < n; ++i) {
        if (s[i] > 0xff) { *src = s + i; crt_set_errno(CRT_EILSEQ); return (size_t)-1; }
        d[i] = (char)s[i];
        if (!s[i]) { *src = 0; return i; }
    }
    *src = s + i;
    return i;
}

/* ---------------------------------------------------------------- char16_t / char32_t: always UTF-8 in the UCRT */
/* mbstate_t is 8 bytes; this file keeps {pending count or surrogate marker, partial code point} in it */
static size_t utf8_decode(uint32_t *out, const char *s, size_t n, unsigned *st_count, unsigned *st_cp)
{
    size_t i = 0;
    unsigned need = *st_count, cp = *st_cp;
    if (!need) {
        const unsigned char b = (unsigned char)s[0];
        if (b < 0x80) { *out = b; return b ? 1 : 0; }
        if (b >= 0xc2 && b <= 0xdf) { need = 1; cp = b & 0x1f; }
        else if (b >= 0xe0 && b <= 0xef) { need = 2; cp = b & 0x0f; }
        else if (b >= 0xf0 && b <= 0xf4) { need = 3; cp = b & 0x07; }
        else return (size_t)-1;
        i = 1;
    }
    for (; need && i < n; ++i, --need) {
        const unsigned char b = (unsigned char)s[i];
        if ((b & 0xc0) != 0x80) return (size_t)-1;
        cp = (cp << 6) | (b & 0x3f);
    }
    if (need) { *st_count = need; *st_cp = cp; return (size_t)-2; }
    *st_count = 0;
    *st_cp = 0;
    if ((cp >= 0xd800 && cp <= 0xdfff) || cp > 0x10ffff) return (size_t)-1;
    *out = cp;
    return i;
}
static int utf8_encode(char *s, uint32_t cp)
{
    if (cp < 0x80) { s[0] = (char)cp; return 1; }
    if (cp < 0x800) { s[0] = (char)(0xc0 | (cp >> 6)); s[1] = (char)(0x80 | (cp & 0x3f)); return 2; }
    if (cp < 0x10000) {
        if (cp >= 0xd800 && cp <= 0xdfff) return -1;
        s[0] = (char)(0xe0 | (cp >> 12)); s[1] = (char)(0x80 | ((cp >> 6) & 0x3f)); s[2] = (char)(0x80 | (cp & 0x3f));
        return 3;
    }
    if (cp > 0x10ffff) return -1;
    s[0] = (char)(0xf0 | (cp >> 18)); s[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
    s[2] = (char)(0x80 | ((cp >> 6) & 0x3f)); s[3] = (char)(0x80 | (cp & 0x3f));
    return 4;
}
static unsigned *st_words(void *st)
{
    static unsigned internal[2];
    return st ? (unsigned *)st : internal;
}
DLLAPI size_t CRTAPI mbrtoc32(uint32_t *pc, const char *s, size_t n, void *st)
{
    unsigned *w = st_words(st);
    uint32_t cp = 0;
    size_t r;
    if (!s) { w[0] = w[1] = 0; return 0; }
    if (!n) return (size_t)-2;
    r = utf8_decode(&cp, s, n, &w[0], &w[1]);
    if (r == (size_t)-1) { w[0] = w[1] = 0; crt_set_errno(CRT_EILSEQ); return r; }
    if (r != (size_t)-2 && pc) *pc = cp;
    return r;
}
DLLAPI size_t CRTAPI c32rtomb(char *s, uint32_t c, void *st)
{
    int k;
    char tmp[4];
    (void)st;
    if (!s) return 1;
    k = utf8_encode(tmp, c);
    if (k < 0) { crt_set_errno(CRT_EILSEQ); return (size_t)-1; }
    crt_memcpy(s, tmp, (size_t)k);
    return (size_t)k;
}
/* UTF-16: a supplementary character is delivered in two calls; the second returns (size_t)-3 */
DLLAPI size_t CRTAPI mbrtoc16(uint16_t *pc, const char *s, size_t n, void *st)
{
    unsigned *w = st_words(st);
    uint32_t cp = 0;
    size_t r;
    if (w[0] == 0xffffffffu) {                             /* pending low surrogate */
        if (pc) *pc = (uint16_t)w[1];
        w[0] = w[1] = 0;
        return (size_t)-3;
    }
    if (!s) { w[0] = w[1] = 0; return 0; }
    if (!n) return (size_t)-2;
    r = utf8_decode(&cp, s, n, &w[0], &w[1]);
    if (r == (size_t)-1) { w[0] = w[1] = 0; crt_set_errno(CRT_EILSEQ); return r; }
    if (r == (size_t)-2) return r;
    if (cp >= 0x10000) {
        cp -= 0x10000;
        if (pc) *pc = (uint16_t)(0xd800 | (cp >> 10));
        w[0] = 0xffffffffu;
        w[1] = 0xdc00 | (cp & 0x3ff);
    } else if (pc) *pc = (uint16_t)cp;
    return r;
}
DLLAPI size_t CRTAPI c16rtomb(char *s, uint16_t c, void *st)
{
    unsigned *w = st_words(st);
    int k;
    char tmp[4];
    if (!s) { w[0] = w[1] = 0; return 1; }
    if (c >= 0xd800 && c <= 0xdbff) {
        if (w[0] == 0xfffffffeu) { w[0] = w[1] = 0; crt_set_errno(CRT_EILSEQ); return (size_t)-1; }
        w[0] = 0xfffffffeu;
        w[1] = c;
        return 0;
    }
    if (c >= 0xdc00 && c <= 0xdfff) {
        uint32_t cp;
        if (w[0] != 0xfffffffeu) { crt_set_errno(CRT_EILSEQ); return (size_t)-1; }
        cp = 0x10000 + (((w[1] & 0x3ff) << 10) | (c & 0x3ffu));
        w[0] = w[1] = 0;
        k = utf8_encode(tmp, cp);
    } else {
        if (w[0] == 0xfffffffeu) { w[0] = w[1] = 0; crt_set_errno(CRT_EILSEQ); return (size_t)-1; }
        k = utf8_encode(tmp, c);
    }
    if (k < 0) { crt_set_errno(CRT_EILSEQ); return (size_t)-1; }
    crt_memcpy(s, tmp, (size_t)k);
    return (size_t)k;
}
