/* SPDX-License-Identifier: GPL-2.0-only
 * C runtime for the Wine port: memory, byte-string, wide-string and character-class functions.
 * Written from the C standard / MSDN descriptions; plain loops, no locale (the "C" locale only, plus Latin-1 and the
 * simple alphabetic case ranges of the BMP for the wide functions).
 */
#include "shzwcrt.h"
#include <ctype.h>
#include <wctype.h>

/* ---------------------------------------------------------------- memory */
void *__cdecl memcpy(void *d, const void *s, size_t n)
{
    unsigned char *a = d;
    const unsigned char *b = s;
    while (n--) *a++ = *b++;
    return d;
}
void *__cdecl memmove(void *d, const void *s, size_t n)
{
    unsigned char *a = d;
    const unsigned char *b = s;
    if (a == b || !n) return d;
    if (a < b || a >= b + n) { while (n--) *a++ = *b++; }
    else { a += n; b += n; while (n--) *--a = *--b; }
    return d;
}
void *__cdecl memset(void *d, int c, size_t n)
{
    unsigned char *a = d;
    while (n--) *a++ = (unsigned char)c;
    return d;
}
int __cdecl memcmp(const void *x, const void *y, size_t n)
{
    const unsigned char *a = x, *b = y;
    for (; n; --n, ++a, ++b)
        if (*a != *b) return *a < *b ? -1 : 1;
    return 0;
}
void *__cdecl memchr(const void *s, int c, size_t n)
{
    const unsigned char *p = s;
    for (; n; --n, ++p)
        if (*p == (unsigned char)c) return (void *)p;
    return 0;
}
errno_t __cdecl memcpy_s(void *d, size_t dn, const void *s, size_t n)
{
    if (!n) return 0;
    if (!d || !s || n > dn) { if (d) memset(d, 0, dn); return 22; }
    memmove(d, s, n);
    return 0;
}
errno_t __cdecl memmove_s(void *d, size_t dn, const void *s, size_t n) { return memcpy_s(d, dn, s, n); }

/* ---------------------------------------------------------------- byte strings */
size_t __cdecl strlen(const char *s) { size_t n = 0; while (s[n]) ++n; return n; }
size_t __cdecl strnlen(const char *s, size_t max) { size_t n = 0; while (n < max && s[n]) ++n; return n; }
char *__cdecl strcpy(char *d, const char *s) { char *r = d; while ((*d++ = *s++)) { } return r; }
char *__cdecl strncpy(char *d, const char *s, size_t n)
{
    char *r = d;
    while (n && (*d = *s)) { ++d; ++s; --n; }
    while (n--) *d++ = 0;
    return r;
}
char *__cdecl strcat(char *d, const char *s) { strcpy(d + strlen(d), s); return d; }
char *__cdecl strncat(char *d, const char *s, size_t n)
{
    char *p = d + strlen(d);
    while (n-- && *s) *p++ = *s++;
    *p = 0;
    return d;
}
int __cdecl strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return (unsigned char)*a < (unsigned char)*b ? -1 : (unsigned char)*a > (unsigned char)*b;
}
int __cdecl strncmp(const char *a, const char *b, size_t n)
{
    for (; n; --n, ++a, ++b) {
        if (*a != *b) return (unsigned char)*a < (unsigned char)*b ? -1 : 1;
        if (!*a) break;
    }
    return 0;
}
static int lower_a(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }
int __cdecl _stricmp(const char *a, const char *b)
{
    for (;; ++a, ++b) {
        int x = lower_a((unsigned char)*a), y = lower_a((unsigned char)*b);
        if (x != y) return x < y ? -1 : 1;
        if (!x) return 0;
    }
}
int __cdecl _strcmpi(const char *a, const char *b) { return _stricmp(a, b); }
int __cdecl _strnicmp(const char *a, const char *b, size_t n)
{
    for (; n; --n, ++a, ++b) {
        int x = lower_a((unsigned char)*a), y = lower_a((unsigned char)*b);
        if (x != y) return x < y ? -1 : 1;
        if (!x) break;
    }
    return 0;
}
char *__cdecl strchr(const char *s, int c)
{
    for (;; ++s) {
        if (*s == (char)c) return (char *)s;
        if (!*s) return 0;
    }
}
char *__cdecl strrchr(const char *s, int c)
{
    const char *r = 0;
    for (;; ++s) {
        if (*s == (char)c) r = s;
        if (!*s) return (char *)r;
    }
}
char *__cdecl strstr(const char *h, const char *n)
{
    size_t ln = strlen(n);
    if (!ln) return (char *)h;
    for (; *h; ++h)
        if (*h == *n && !strncmp(h, n, ln)) return (char *)h;
    return 0;
}
size_t __cdecl strspn(const char *s, const char *set)
{
    size_t n = 0;
    while (s[n] && strchr(set, s[n])) ++n;
    return n;
}
size_t __cdecl strcspn(const char *s, const char *set)
{
    size_t n = 0;
    while (s[n] && !strchr(set, s[n])) ++n;
    return n;
}
char *__cdecl strpbrk(const char *s, const char *set)
{
    for (; *s; ++s)
        if (strchr(set, *s)) return (char *)s;
    return 0;
}
char *__cdecl strtok_s(char *s, const char *delim, char **ctx)
{
    char *tok;
    if (!s) s = *ctx;
    if (!s) return 0;
    s += strspn(s, delim);
    if (!*s) { *ctx = 0; return 0; }
    tok = s;
    s += strcspn(s, delim);
    if (*s) *s++ = 0;
    *ctx = s;
    return tok;
}
char *__cdecl strtok(char *s, const char *delim)
{
    static char *ctx;
    return strtok_s(s, delim, &ctx);
}
char *__cdecl _strlwr(char *s) { char *r = s; for (; *s; ++s) *s = (char)lower_a((unsigned char)*s); return r; }
char *__cdecl _strupr(char *s) { char *r = s; for (; *s; ++s) if (*s >= 'a' && *s <= 'z') *s -= 32; return r; }
char *__cdecl _strrev(char *s)
{
    char *a = s, *b = s + strlen(s);
    while (b - a > 1) { char t = *a; *a++ = *--b; *b = t; }
    return s;
}
errno_t __cdecl strcpy_s(char *d, size_t n, const char *s)
{
    size_t l;
    if (!d || !n) return 22;
    if (!s) { d[0] = 0; return 22; }
    l = strlen(s);
    if (l >= n) { d[0] = 0; return 34; }
    memcpy(d, s, l + 1);
    return 0;
}
errno_t __cdecl strcat_s(char *d, size_t n, const char *s)
{
    size_t l;
    if (!d || !n) return 22;
    l = strnlen(d, n);
    if (l == n || !s) { if (l < n) d[0] = 0; return 22; }
    return strcpy_s(d + l, n - l, s);
}
errno_t __cdecl strncpy_s(char *d, size_t n, const char *s, size_t count)
{
    size_t l;
    if (!d || !n) return 22;
    if (!s) { d[0] = 0; return 22; }
    l = strnlen(s, count);
    if (l >= n) { d[0] = 0; return 34; }
    memcpy(d, s, l);
    d[l] = 0;
    return 0;
}
char *__cdecl strerror(int e)
{
    static char buf[32];
    sprintf(buf, "error %d", e);
    return buf;
}

/* ---------------------------------------------------------------- wide strings */
size_t __cdecl wcslen(const wchar_t *s) { size_t n = 0; while (s[n]) ++n; return n; }
size_t __cdecl wcsnlen(const wchar_t *s, size_t max) { size_t n = 0; while (n < max && s[n]) ++n; return n; }
size_t __cdecl _wcsnlen(const wchar_t *s, size_t max) { return wcsnlen(s, max); }
wchar_t *__cdecl wcscpy(wchar_t *d, const wchar_t *s) { wchar_t *r = d; while ((*d++ = *s++)) { } return r; }
wchar_t *__cdecl wcsncpy(wchar_t *d, const wchar_t *s, size_t n)
{
    wchar_t *r = d;
    while (n && (*d = *s)) { ++d; ++s; --n; }
    while (n--) *d++ = 0;
    return r;
}
wchar_t *__cdecl wcscat(wchar_t *d, const wchar_t *s) { wcscpy(d + wcslen(d), s); return d; }
wchar_t *__cdecl wcsncat(wchar_t *d, const wchar_t *s, size_t n)
{
    wchar_t *p = d + wcslen(d);
    while (n-- && *s) *p++ = *s++;
    *p = 0;
    return d;
}
int __cdecl wcscmp(const wchar_t *a, const wchar_t *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return *a < *b ? -1 : *a > *b;
}
int __cdecl wcsncmp(const wchar_t *a, const wchar_t *b, size_t n)
{
    for (; n; --n, ++a, ++b) {
        if (*a != *b) return *a < *b ? -1 : 1;
        if (!*a) break;
    }
    return 0;
}
int __cdecl _wcsicmp(const wchar_t *a, const wchar_t *b)
{
    for (;; ++a, ++b) {
        unsigned x = towlower(*a), y = towlower(*b);
        if (x != y) return x < y ? -1 : 1;
        if (!x) return 0;
    }
}
int __cdecl _wcsnicmp(const wchar_t *a, const wchar_t *b, size_t n)
{
    for (; n; --n, ++a, ++b) {
        unsigned x = towlower(*a), y = towlower(*b);
        if (x != y) return x < y ? -1 : 1;
        if (!x) break;
    }
    return 0;
}
wchar_t *__cdecl wcschr(const wchar_t *s, wchar_t c)
{
    for (;; ++s) {
        if (*s == c) return (wchar_t *)s;
        if (!*s) return 0;
    }
}
wchar_t *__cdecl wcsrchr(const wchar_t *s, wchar_t c)
{
    const wchar_t *r = 0;
    for (;; ++s) {
        if (*s == c) r = s;
        if (!*s) return (wchar_t *)r;
    }
}
wchar_t *__cdecl wcsstr(const wchar_t *h, const wchar_t *n)
{
    size_t ln = wcslen(n);
    if (!ln) return (wchar_t *)h;
    for (; *h; ++h)
        if (*h == *n && !wcsncmp(h, n, ln)) return (wchar_t *)h;
    return 0;
}
size_t __cdecl wcsspn(const wchar_t *s, const wchar_t *set)
{
    size_t n = 0;
    while (s[n] && wcschr(set, s[n])) ++n;
    return n;
}
size_t __cdecl wcscspn(const wchar_t *s, const wchar_t *set)
{
    size_t n = 0;
    while (s[n] && !wcschr(set, s[n])) ++n;
    return n;
}
wchar_t *__cdecl wcspbrk(const wchar_t *s, const wchar_t *set)
{
    for (; *s; ++s)
        if (wcschr(set, *s)) return (wchar_t *)s;
    return 0;
}
wchar_t *__cdecl wcstok_s(wchar_t *s, const wchar_t *delim, wchar_t **ctx)
{
    wchar_t *tok;
    if (!s) s = *ctx;
    if (!s) return 0;
    s += wcsspn(s, delim);
    if (!*s) { *ctx = 0; return 0; }
    tok = s;
    s += wcscspn(s, delim);
    if (*s) *s++ = 0;
    *ctx = s;
    return tok;
}
wchar_t *__cdecl wcstok(wchar_t *s, const wchar_t *delim, wchar_t **ctx)
{
    static wchar_t *global_ctx;
    return wcstok_s(s, delim, ctx ? ctx : &global_ctx);
}
wchar_t *__cdecl _wcslwr(wchar_t *s) { wchar_t *r = s; for (; *s; ++s) *s = (wchar_t)towlower(*s); return r; }
wchar_t *__cdecl _wcsupr(wchar_t *s) { wchar_t *r = s; for (; *s; ++s) *s = (wchar_t)towupper(*s); return r; }
errno_t __cdecl _wcslwr_s(wchar_t *s, size_t n) { if (!s || wcsnlen(s, n) == n) return 22; _wcslwr(s); return 0; }
errno_t __cdecl _wcsupr_s(wchar_t *s, size_t n) { if (!s || wcsnlen(s, n) == n) return 22; _wcsupr(s); return 0; }
wchar_t *__cdecl _wcsrev(wchar_t *s)
{
    wchar_t *a = s, *b = s + wcslen(s);
    while (b - a > 1) { wchar_t t = *a; *a++ = *--b; *b = t; }
    return s;
}
errno_t __cdecl wcscpy_s(wchar_t *d, size_t n, const wchar_t *s)
{
    size_t l;
    if (!d || !n) return 22;
    if (!s) { d[0] = 0; return 22; }
    l = wcslen(s);
    if (l >= n) { d[0] = 0; return 34; }
    memcpy(d, s, (l + 1) * sizeof(wchar_t));
    return 0;
}
errno_t __cdecl wcscat_s(wchar_t *d, size_t n, const wchar_t *s)
{
    size_t l;
    if (!d || !n) return 22;
    l = wcsnlen(d, n);
    if (l == n || !s) { if (l < n) d[0] = 0; return 22; }
    return wcscpy_s(d + l, n - l, s);
}
errno_t __cdecl wcsncpy_s(wchar_t *d, size_t n, const wchar_t *s, size_t count)
{
    size_t l;
    if (!d || !n) return 22;
    if (!s) { d[0] = 0; return 22; }
    l = wcsnlen(s, count);
    if (l >= n) { d[0] = 0; return 34; }
    memcpy(d, s, l * sizeof(wchar_t));
    d[l] = 0;
    return 0;
}

/* ---------------------------------------------------------------- character classes */
int __cdecl isdigit(int c) { return c >= '0' && c <= '9'; }
int __cdecl isxdigit(int c) { return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
int __cdecl isupper(int c) { return c >= 'A' && c <= 'Z'; }
int __cdecl islower(int c) { return c >= 'a' && c <= 'z'; }
int __cdecl isalpha(int c) { return isupper(c) || islower(c); }
int __cdecl isalnum(int c) { return isalpha(c) || isdigit(c); }
int __cdecl isspace(int c) { return c == ' ' || (c >= '\t' && c <= '\r'); }
int __cdecl isblank(int c) { return c == ' ' || c == '\t'; }
int __cdecl iscntrl(int c) { return (c >= 0 && c < 32) || c == 127; }
int __cdecl isprint(int c) { return c >= 32 && c < 127; }
int __cdecl isgraph(int c) { return c > 32 && c < 127; }
int __cdecl ispunct(int c) { return isgraph(c) && !isalnum(c); }
int __cdecl toupper(int c) { return islower(c) ? c - 32 : c; }
int __cdecl tolower(int c) { return isupper(c) ? c + 32 : c; }
int __cdecl _toupper(int c) { return c - 32; }
int __cdecl _tolower(int c) { return c + 32; }
int __cdecl __isascii(int c) { return (unsigned)c < 128; }
int __cdecl __toascii(int c) { return c & 0x7f; }
int __cdecl __iscsymf(int c) { return isalpha(c) || c == '_'; }
int __cdecl __iscsym(int c) { return isalnum(c) || c == '_'; }
int __cdecl _isctype(int c, int type)
{
    int r = 0;
    if (type & _UPPER) r |= isupper(c);
    if (type & _LOWER) r |= islower(c);
    if (type & _DIGIT) r |= isdigit(c);
    if (type & _SPACE) r |= isspace(c);
    if (type & _PUNCT) r |= ispunct(c);
    if (type & _CONTROL) r |= iscntrl(c);
    if (type & _BLANK) r |= isblank(c);
    if (type & _HEX) r |= isxdigit(c);
    if (type & 0x0100) r |= isalpha(c);
    return r;
}
int __cdecl isleadbyte(int c) { (void)c; return 0; }
int __cdecl ___mb_cur_max_func(void) { return 1; }

/* Wide classes: ASCII, Latin-1 supplement and the regular case pairs of Latin Extended-A, Greek and Cyrillic. */
static int latin_ext_a_upper_is_even(wint_t c)      /* U+0100..U+017F: which member of each pair is the capital */
{
    return (c <= 0x137) || (c >= 0x14a && c <= 0x177);
}
wint_t __cdecl towupper(wint_t c)
{
    if (c < 128) return (wint_t)toupper((int)c);
    if (c >= 0xe0 && c <= 0xfe && c != 0xf7) return c - 32;
    if (c == 0xff) return 0x178;
    if (c == 0x17f) return 'S';
    if (c >= 0x100 && c <= 0x17e && c != 0x138 && c != 0x149 && c != 0x178)
        return latin_ext_a_upper_is_even(c) ? ((c & 1) ? c - 1 : c) : ((c & 1) ? c : c - 1);
    if (c == 0x3c2) return 0x3a3;
    if (c >= 0x3b1 && c <= 0x3c9) return c - 32;
    if (c >= 0x430 && c <= 0x44f) return c - 32;
    if (c >= 0x450 && c <= 0x45f) return c - 80;
    return c;
}
wint_t __cdecl towlower(wint_t c)
{
    if (c < 128) return (wint_t)tolower((int)c);
    if (c >= 0xc0 && c <= 0xde && c != 0xd7) return c + 32;
    if (c == 0x178) return 0xff;
    if (c >= 0x100 && c <= 0x17e && c != 0x138 && c != 0x149 && c != 0x17f)
        return latin_ext_a_upper_is_even(c) ? ((c & 1) ? c : c + 1) : ((c & 1) ? c + 1 : c);
    if (c >= 0x391 && c <= 0x3a9 && c != 0x3a2) return c + 32;
    if (c >= 0x410 && c <= 0x42f) return c + 32;
    if (c >= 0x400 && c <= 0x40f) return c + 80;
    return c;
}
int __cdecl iswdigit(wint_t c) { return c >= '0' && c <= '9'; }
int __cdecl iswxdigit(wint_t c) { return c < 128 && isxdigit((int)c); }
int __cdecl iswspace(wint_t c) { return (c < 128 && isspace((int)c)) || c == 0xa0 || c == 0x2028 || c == 0x2029 || c == 0x3000 || (c >= 0x2000 && c <= 0x200a); }
int __cdecl iswupper(wint_t c) { return towlower(c) != c; }
int __cdecl iswlower(wint_t c) { return towupper(c) != c; }
int __cdecl iswalpha(wint_t c) { return (c < 128 && isalpha((int)c)) || (c >= 0xc0 && c <= 0x2af && c != 0xd7 && c != 0xf7) || (c >= 0x370 && c <= 0x52f) || (c >= 0x3040 && c <= 0x9fff) || (c >= 0xac00 && c <= 0xd7a3); }
int __cdecl iswalnum(wint_t c) { return iswalpha(c) || iswdigit(c); }
int __cdecl iswcntrl(wint_t c) { return c < 32 || (c >= 127 && c < 160); }
int __cdecl iswprint(wint_t c) { return !iswcntrl(c); }
int __cdecl iswgraph(wint_t c) { return iswprint(c) && !iswspace(c); }
int __cdecl iswpunct(wint_t c) { return iswgraph(c) && !iswalnum(c); }
int __cdecl iswblank(wint_t c) { return c == ' ' || c == '\t' || c == 0xa0 || c == 0x3000; }
int __cdecl iswascii(wint_t c) { return c < 128; }
int __cdecl iswctype(wint_t c, wctype_t t)
{
    int r = 0;
    if (t & _UPPER) r |= iswupper(c);
    if (t & _LOWER) r |= iswlower(c);
    if (t & _DIGIT) r |= iswdigit(c);
    if (t & _SPACE) r |= iswspace(c);
    if (t & _PUNCT) r |= iswpunct(c);
    if (t & _CONTROL) r |= iswcntrl(c);
    if (t & _BLANK) r |= iswblank(c);
    if (t & _HEX) r |= iswxdigit(c);
    if (t & 0x0100) r |= iswalpha(c);
    return r;
}
int __cdecl is_wctype(wint_t c, wctype_t t) { return iswctype(c, t); }
