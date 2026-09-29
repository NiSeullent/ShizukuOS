/* SPDX-License-Identifier: GPL-2.0-only
 * <string.h> / <wchar.h> string and memory functions of the Shizuku UCRT, including the bounds-checked *_s variants
 * with the documented Microsoft semantics (invalid-parameter handler, errno codes, destination cleared on failure,
 * _TRUNCATE). Comparisons, case mapping and collation use the "C" locale (the only locale this CRT provides).
 */
#include "crtint.h"

#define TRUNCATE_ ((size_t)-1)

/* ---------------------------------------------------------------- memory */
DLLAPI void *CRTAPI memcpy(void *d, const void *s, size_t n)
{
#ifdef SHZ_HOST_TEST
    unsigned char *a = d; const unsigned char *b = s; while (n--) *a++ = *b++;
#else
    void *dd = d;
    __asm__ volatile("rep movsb" : "+D"(dd), "+S"(s), "+c"(n) : : "memory");
#endif
    return d;
}
DLLAPI void *CRTAPI memmove(void *d, const void *s, size_t n)
{
    unsigned char *a = d;
    const unsigned char *b = s;
    if (a == b || !n) return d;
    if (a < b || a >= b + n) return memcpy(d, s, n);
    a += n;
    b += n;
    while (n--) *--a = *--b;
    return d;
}
DLLAPI void *CRTAPI memset(void *d, int c, size_t n)
{
#ifdef SHZ_HOST_TEST
    unsigned char *a = d; while (n--) *a++ = (unsigned char)c;
#else
    void *dd = d;
    __asm__ volatile("rep stosb" : "+D"(dd), "+c"(n) : "a"(c) : "memory");
#endif
    return d;
}
DLLAPI int CRTAPI memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = a, *y = b;
    for (; n; --n, ++x, ++y)
        if (*x != *y) return *x < *y ? -1 : 1;
    return 0;
}
DLLAPI void *CRTAPI memchr(const void *s, int c, size_t n)
{
    const unsigned char *p = s;
    for (; n; --n, ++p)
        if (*p == (unsigned char)c) return (void *)p;
    return 0;
}
void *crt_memcpy(void *d, const void *s, size_t n) { return memcpy(d, s, n); }
void *crt_memset(void *d, int c, size_t n) { return memset(d, c, n); }

DLLAPI crt_errno_t CRTAPI memcpy_s(void *d, size_t dsz, const void *s, size_t n)
{
    if (!n) return 0;
    CRT_VALIDATE(d != 0, CRT_EINVAL, CRT_EINVAL);
    if (!s || dsz < n) {
        memset(d, 0, dsz);
        CRT_VALIDATE(s != 0, CRT_EINVAL, CRT_EINVAL);
        CRT_VALIDATE(dsz >= n, CRT_ERANGE, CRT_ERANGE);
    }
    memcpy(d, s, n);
    return 0;
}
DLLAPI crt_errno_t CRTAPI memmove_s(void *d, size_t dsz, const void *s, size_t n)
{
    if (!n) return 0;
    CRT_VALIDATE(d != 0, CRT_EINVAL, CRT_EINVAL);
    CRT_VALIDATE(s != 0, CRT_EINVAL, CRT_EINVAL);
    CRT_VALIDATE(dsz >= n, CRT_ERANGE, CRT_ERANGE);
    memmove(d, s, n);
    return 0;
}
DLLAPI crt_errno_t CRTAPI wmemcpy_s(wchar16 *d, size_t dsz, const wchar16 *s, size_t n)
{
    if (!n) return 0;
    CRT_VALIDATE(d != 0, CRT_EINVAL, CRT_EINVAL);
    if (!s || dsz < n) {
        memset(d, 0, dsz * sizeof(wchar16));
        CRT_VALIDATE(s != 0, CRT_EINVAL, CRT_EINVAL);
        CRT_VALIDATE(dsz >= n, CRT_ERANGE, CRT_ERANGE);
    }
    memcpy(d, s, n * sizeof(wchar16));
    return 0;
}
DLLAPI crt_errno_t CRTAPI wmemmove_s(wchar16 *d, size_t dsz, const wchar16 *s, size_t n)
{
    if (!n) return 0;
    CRT_VALIDATE(d != 0 && s != 0, CRT_EINVAL, CRT_EINVAL);
    CRT_VALIDATE(dsz >= n, CRT_ERANGE, CRT_ERANGE);
    memmove(d, s, n * sizeof(wchar16));
    return 0;
}
DLLAPI void *CRTAPI _memccpy(void *d, const void *s, int c, size_t n)
{
    unsigned char *a = d;
    const unsigned char *b = s;
    for (; n; --n) {
        if ((*a++ = *b++) == (unsigned char)c) return a;
    }
    return 0;
}
DLLAPI int CRTAPI _memicmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = a, *y = b;
    CRT_VALIDATE(n == 0 || (a && b), CRT_EINVAL, CRT_INT_MAX);
    for (; n; --n, ++x, ++y) {
        const int p = crt_tolower_c(*x), q = crt_tolower_c(*y);
        if (p != q) return p - q;
    }
    return 0;
}
DLLAPI int CRTAPI _memicmp_l(const void *a, const void *b, size_t n, void *loc) { (void)loc; return _memicmp(a, b, n); }

/* ---------------------------------------------------------------- narrow strings */
DLLAPI size_t CRTAPI strlen(const char *s) { const char *p = s; while (*p) ++p; return (size_t)(p - s); }
size_t crt_strlen(const char *s) { return strlen(s); }
DLLAPI size_t CRTAPI strnlen(const char *s, size_t max) { size_t n = 0; while (n < max && s[n]) ++n; return n; }
DLLAPI char *CRTAPI strcpy(char *d, const char *s) { char *r = d; while ((*d++ = *s++) != 0) {} return r; }
DLLAPI char *CRTAPI strncpy(char *d, const char *s, size_t n)
{
    char *r = d;
    for (; n && *s; --n) *d++ = *s++;
    for (; n; --n) *d++ = 0;
    return r;
}
DLLAPI char *CRTAPI strcat(char *d, const char *s) { strcpy(d + strlen(d), s); return d; }
DLLAPI char *CRTAPI strncat(char *d, const char *s, size_t n)
{
    char *p = d + strlen(d);
    for (; n && *s; --n) *p++ = *s++;
    *p = 0;
    return d;
}
DLLAPI int CRTAPI strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return (unsigned char)*a < (unsigned char)*b ? -1 : (unsigned char)*a > (unsigned char)*b;
}
DLLAPI int CRTAPI strncmp(const char *a, const char *b, size_t n)
{
    for (; n; --n, ++a, ++b) {
        if (*a != *b) return (unsigned char)*a < (unsigned char)*b ? -1 : 1;
        if (!*a) break;
    }
    return 0;
}
DLLAPI char *CRTAPI strchr(const char *s, int c)
{
    for (;; ++s) {
        if (*s == (char)c) return (char *)s;
        if (!*s) return 0;
    }
}
DLLAPI char *CRTAPI strrchr(const char *s, int c)
{
    const char *r = 0;
    for (;; ++s) {
        if (*s == (char)c) r = s;
        if (!*s) return (char *)r;
    }
}
DLLAPI char *CRTAPI strstr(const char *h, const char *n)
{
    size_t k = strlen(n);
    if (!k) return (char *)h;
    for (; *h; ++h)
        if (*h == *n && !strncmp(h, n, k)) return (char *)h;
    return 0;
}
static int in_set(const char *set, char c) { for (; *set; ++set) if (*set == c) return 1; return 0; }
DLLAPI size_t CRTAPI strspn(const char *s, const char *set) { size_t n = 0; while (s[n] && in_set(set, s[n])) ++n; return n; }
DLLAPI size_t CRTAPI strcspn(const char *s, const char *set) { size_t n = 0; while (s[n] && !in_set(set, s[n])) ++n; return n; }
DLLAPI char *CRTAPI strpbrk(const char *s, const char *set)
{
    for (; *s; ++s) if (in_set(set, *s)) return (char *)s;
    return 0;
}
static char *tok_core(char *s, const char *delim, char **ctx)
{
    char *start;
    if (!s) s = *ctx;
    if (!s) return 0;
    s += strspn(s, delim);
    if (!*s) { *ctx = s; return 0; }
    start = s;
    s += strcspn(s, delim);
    if (*s) *s++ = 0;
    *ctx = s;
    return start;
}
DLLAPI char *CRTAPI strtok(char *s, const char *delim)
{
    crt_ptd *p = crt_getptd();
    return tok_core(s, delim, &p->strtok_ctx);
}
DLLAPI char *CRTAPI strtok_s(char *s, const char *delim, char **ctx)
{
    CRT_VALIDATE(ctx != 0 && delim != 0, CRT_EINVAL, 0);
    CRT_VALIDATE(s != 0 || *ctx != 0, CRT_EINVAL, 0);
    return tok_core(s, delim, ctx);
}
DLLAPI char *CRTAPI _strdup(const char *s)
{
    size_t n;
    char *d;
    if (!s) return 0;
    n = strlen(s) + 1;
    d = crt_malloc(n);
    if (d) memcpy(d, s, n);
    return d;
}
DLLAPI int CRTAPI _stricmp(const char *a, const char *b)
{
    int x, y;
    CRT_VALIDATE(a && b, CRT_EINVAL, CRT_INT_MAX);
    do {
        x = crt_tolower_c((unsigned char)*a++);
        y = crt_tolower_c((unsigned char)*b++);
    } while (x && x == y);
    return x - y;
}
DLLAPI int CRTAPI _strnicmp(const char *a, const char *b, size_t n)
{
    int x = 0, y = 0;
    CRT_VALIDATE(n == 0 || (a && b), CRT_EINVAL, CRT_INT_MAX);
    for (; n; --n) {
        x = crt_tolower_c((unsigned char)*a++);
        y = crt_tolower_c((unsigned char)*b++);
        if (!x || x != y) break;
    }
    return x - y;
}
DLLAPI int CRTAPI _stricmp_l(const char *a, const char *b, void *l) { (void)l; return _stricmp(a, b); }
DLLAPI int CRTAPI _strnicmp_l(const char *a, const char *b, size_t n, void *l) { (void)l; return _strnicmp(a, b, n); }
DLLAPI int CRTAPI strcoll(const char *a, const char *b) { return strcmp(a, b); }
DLLAPI int CRTAPI _stricoll(const char *a, const char *b) { return _stricmp(a, b); }
DLLAPI int CRTAPI _strncoll(const char *a, const char *b, size_t n) { return strncmp(a, b, n); }
DLLAPI int CRTAPI _strnicoll(const char *a, const char *b, size_t n) { return _strnicmp(a, b, n); }
DLLAPI size_t CRTAPI strxfrm(char *d, const char *s, size_t n)
{
    size_t len = strlen(s);
    if (len < n) memcpy(d, s, len + 1);
    return len;
}
DLLAPI char *CRTAPI _strlwr(char *s) { char *p; for (p = s; *p; ++p) *p = (char)crt_tolower_c((unsigned char)*p); return s; }
DLLAPI char *CRTAPI _strupr(char *s) { char *p; for (p = s; *p; ++p) *p = (char)crt_toupper_c((unsigned char)*p); return s; }
DLLAPI crt_errno_t CRTAPI _strlwr_s(char *s, size_t n)
{
    CRT_VALIDATE(s != 0, CRT_EINVAL, CRT_EINVAL);
    if (strnlen(s, n) >= n) { if (n) s[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    _strlwr(s);
    return 0;
}
DLLAPI crt_errno_t CRTAPI _strupr_s(char *s, size_t n)
{
    CRT_VALIDATE(s != 0, CRT_EINVAL, CRT_EINVAL);
    if (strnlen(s, n) >= n) { if (n) s[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    _strupr(s);
    return 0;
}
DLLAPI char *CRTAPI _strrev(char *s)
{
    size_t n = strlen(s), i;
    for (i = 0; i < n / 2; ++i) { char t = s[i]; s[i] = s[n - 1 - i]; s[n - 1 - i] = t; }
    return s;
}
DLLAPI char *CRTAPI _strset(char *s, int c) { char *p; for (p = s; *p; ++p) *p = (char)c; return s; }
DLLAPI char *CRTAPI _strnset(char *s, int c, size_t n) { char *p; for (p = s; n && *p; --n, ++p) *p = (char)c; return s; }

DLLAPI crt_errno_t CRTAPI strcpy_s(char *d, size_t n, const char *s)
{
    size_t i;
    CRT_VALIDATE(d != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    if (!s) { d[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    for (i = 0; i < n; ++i)
        if ((d[i] = s[i]) == 0) return 0;
    d[0] = 0;
    CRT_VALIDATE(0, CRT_ERANGE, CRT_ERANGE);
}
DLLAPI crt_errno_t CRTAPI strncpy_s(char *d, size_t n, const char *s, size_t count)
{
    size_t i, len;
    if (count == 0 && !d && n == 0) return 0;
    CRT_VALIDATE(d != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    if (count == 0) { d[0] = 0; return 0; }
    if (!s) { d[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    len = strnlen(s, count == TRUNCATE_ ? n : count);
    if (count == TRUNCATE_ && len >= n) {
        for (i = 0; i + 1 < n; ++i) d[i] = s[i];
        d[n - 1] = 0;
        return CRT_STRUNCATE;
    }
    if (len >= n) { d[0] = 0; CRT_VALIDATE(0, CRT_ERANGE, CRT_ERANGE); }
    for (i = 0; i < len; ++i) d[i] = s[i];
    d[len] = 0;
    return 0;
}
DLLAPI crt_errno_t CRTAPI strcat_s(char *d, size_t n, const char *s)
{
    size_t dl, i;
    CRT_VALIDATE(d != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    if (!s) { d[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    dl = strnlen(d, n);
    if (dl == n) { d[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    for (i = 0; dl + i < n; ++i)
        if ((d[dl + i] = s[i]) == 0) return 0;
    d[0] = 0;
    CRT_VALIDATE(0, CRT_ERANGE, CRT_ERANGE);
}
DLLAPI crt_errno_t CRTAPI strncat_s(char *d, size_t n, const char *s, size_t count)
{
    size_t dl, len, i;
    if (count == 0 && !d && n == 0) return 0;
    CRT_VALIDATE(d != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    if (count == 0) return 0;
    if (!s) { d[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    dl = strnlen(d, n);
    if (dl == n) { d[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    len = strnlen(s, count == TRUNCATE_ ? n : count);
    if (dl + len >= n) {
        if (count == TRUNCATE_) {
            for (i = 0; dl + i + 1 < n; ++i) d[dl + i] = s[i];
            d[n - 1] = 0;
            return CRT_STRUNCATE;
        }
        d[0] = 0;
        CRT_VALIDATE(0, CRT_ERANGE, CRT_ERANGE);
    }
    for (i = 0; i < len; ++i) d[dl + i] = s[i];
    d[dl + len] = 0;
    return 0;
}
DLLAPI crt_errno_t CRTAPI _strset_s(char *s, size_t n, int c)
{
    size_t i;
    CRT_VALIDATE(s != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    for (i = 0; i < n && s[i]; ++i) s[i] = (char)c;
    if (i == n) { s[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    return 0;
}
DLLAPI crt_errno_t CRTAPI _strnset_s(char *s, size_t n, int c, size_t count)
{
    size_t i;
    if (!s && n == 0 && count == 0) return 0;
    CRT_VALIDATE(s != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    for (i = 0; i < n && s[i] && i < count; ++i) s[i] = (char)c;
    if (i == n && s[n - 1]) { s[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    return 0;
}

/* ---------------------------------------------------------------- wide strings (16-bit code units) */
DLLAPI size_t CRTAPI wcslen(const wchar16 *s) { const wchar16 *p = s; while (*p) ++p; return (size_t)(p - s); }
size_t crt_wcslen(const wchar16 *s) { return wcslen(s); }
DLLAPI size_t CRTAPI wcsnlen(const wchar16 *s, size_t max) { size_t n = 0; while (n < max && s[n]) ++n; return n; }
DLLAPI wchar16 *CRTAPI wcscpy(wchar16 *d, const wchar16 *s) { wchar16 *r = d; while ((*d++ = *s++) != 0) {} return r; }
DLLAPI wchar16 *CRTAPI wcsncpy(wchar16 *d, const wchar16 *s, size_t n)
{
    wchar16 *r = d;
    for (; n && *s; --n) *d++ = *s++;
    for (; n; --n) *d++ = 0;
    return r;
}
DLLAPI wchar16 *CRTAPI wcscat(wchar16 *d, const wchar16 *s) { wcscpy(d + wcslen(d), s); return d; }
DLLAPI wchar16 *CRTAPI wcsncat(wchar16 *d, const wchar16 *s, size_t n)
{
    wchar16 *p = d + wcslen(d);
    for (; n && *s; --n) *p++ = *s++;
    *p = 0;
    return d;
}
DLLAPI int CRTAPI wcscmp(const wchar16 *a, const wchar16 *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return *a < *b ? -1 : *a > *b;
}
DLLAPI int CRTAPI wcsncmp(const wchar16 *a, const wchar16 *b, size_t n)
{
    for (; n; --n, ++a, ++b) {
        if (*a != *b) return *a < *b ? -1 : 1;
        if (!*a) break;
    }
    return 0;
}
DLLAPI wchar16 *CRTAPI wcschr(const wchar16 *s, wchar16 c)
{
    for (;; ++s) {
        if (*s == c) return (wchar16 *)s;
        if (!*s) return 0;
    }
}
DLLAPI wchar16 *CRTAPI wcsrchr(const wchar16 *s, wchar16 c)
{
    const wchar16 *r = 0;
    for (;; ++s) {
        if (*s == c) r = s;
        if (!*s) return (wchar16 *)r;
    }
}
DLLAPI wchar16 *CRTAPI wcsstr(const wchar16 *h, const wchar16 *n)
{
    size_t k = wcslen(n);
    if (!k) return (wchar16 *)h;
    for (; *h; ++h)
        if (*h == *n && !wcsncmp(h, n, k)) return (wchar16 *)h;
    return 0;
}
static int in_wset(const wchar16 *set, wchar16 c) { for (; *set; ++set) if (*set == c) return 1; return 0; }
DLLAPI size_t CRTAPI wcsspn(const wchar16 *s, const wchar16 *set) { size_t n = 0; while (s[n] && in_wset(set, s[n])) ++n; return n; }
DLLAPI size_t CRTAPI wcscspn(const wchar16 *s, const wchar16 *set) { size_t n = 0; while (s[n] && !in_wset(set, s[n])) ++n; return n; }
DLLAPI wchar16 *CRTAPI wcspbrk(const wchar16 *s, const wchar16 *set)
{
    for (; *s; ++s) if (in_wset(set, *s)) return (wchar16 *)s;
    return 0;
}
static wchar16 *wtok_core(wchar16 *s, const wchar16 *delim, wchar16 **ctx)
{
    wchar16 *start;
    if (!s) s = *ctx;
    if (!s) return 0;
    s += wcsspn(s, delim);
    if (!*s) { *ctx = s; return 0; }
    start = s;
    s += wcscspn(s, delim);
    if (*s) *s++ = 0;
    *ctx = s;
    return start;
}
/* ISO C form (three arguments; a null context uses the per-thread one, like the UCRT) and the legacy two-argument form */
DLLAPI wchar16 *CRTAPI wcstok(wchar16 *s, const wchar16 *delim, wchar16 **ctx)
{
    if (!ctx) ctx = &crt_getptd()->wcstok_ctx;
    return wtok_core(s, delim, ctx);
}
DLLAPI wchar16 *CRTAPI wcstok_s(wchar16 *s, const wchar16 *delim, wchar16 **ctx)
{
    CRT_VALIDATE(ctx != 0 && delim != 0, CRT_EINVAL, 0);
    CRT_VALIDATE(s != 0 || *ctx != 0, CRT_EINVAL, 0);
    return wtok_core(s, delim, ctx);
}
DLLAPI wchar16 *CRTAPI _wcsdup(const wchar16 *s)
{
    size_t n;
    wchar16 *d;
    if (!s) return 0;
    n = (wcslen(s) + 1) * sizeof(wchar16);
    d = crt_malloc(n);
    if (d) memcpy(d, s, n);
    return d;
}
DLLAPI int CRTAPI _wcsicmp(const wchar16 *a, const wchar16 *b)
{
    unsigned x, y;
    CRT_VALIDATE(a && b, CRT_EINVAL, CRT_INT_MAX);
    do {
        x = crt_towlower_c(*a++);
        y = crt_towlower_c(*b++);
    } while (x && x == y);
    return (int)x - (int)y;
}
DLLAPI int CRTAPI _wcsnicmp(const wchar16 *a, const wchar16 *b, size_t n)
{
    unsigned x = 0, y = 0;
    CRT_VALIDATE(n == 0 || (a && b), CRT_EINVAL, CRT_INT_MAX);
    for (; n; --n) {
        x = crt_towlower_c(*a++);
        y = crt_towlower_c(*b++);
        if (!x || x != y) break;
    }
    return (int)x - (int)y;
}
DLLAPI int CRTAPI _wcsicmp_l(const wchar16 *a, const wchar16 *b, void *l) { (void)l; return _wcsicmp(a, b); }
DLLAPI int CRTAPI _wcsnicmp_l(const wchar16 *a, const wchar16 *b, size_t n, void *l) { (void)l; return _wcsnicmp(a, b, n); }
DLLAPI int CRTAPI wcscoll(const wchar16 *a, const wchar16 *b) { return wcscmp(a, b); }
DLLAPI int CRTAPI _wcsicoll(const wchar16 *a, const wchar16 *b) { return _wcsicmp(a, b); }
DLLAPI int CRTAPI _wcsncoll(const wchar16 *a, const wchar16 *b, size_t n) { return wcsncmp(a, b, n); }
DLLAPI int CRTAPI _wcsnicoll(const wchar16 *a, const wchar16 *b, size_t n) { return _wcsnicmp(a, b, n); }
DLLAPI size_t CRTAPI wcsxfrm(wchar16 *d, const wchar16 *s, size_t n)
{
    size_t len = wcslen(s);
    if (len < n) memcpy(d, s, (len + 1) * sizeof(wchar16));
    return len;
}
DLLAPI wchar16 *CRTAPI _wcslwr(wchar16 *s) { wchar16 *p; for (p = s; *p; ++p) *p = (wchar16)crt_towlower_c(*p); return s; }
DLLAPI wchar16 *CRTAPI _wcsupr(wchar16 *s) { wchar16 *p; for (p = s; *p; ++p) *p = (wchar16)crt_towupper_c(*p); return s; }
DLLAPI crt_errno_t CRTAPI _wcslwr_s(wchar16 *s, size_t n)
{
    CRT_VALIDATE(s != 0, CRT_EINVAL, CRT_EINVAL);
    if (wcsnlen(s, n) >= n) { if (n) s[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    _wcslwr(s);
    return 0;
}
DLLAPI crt_errno_t CRTAPI _wcsupr_s(wchar16 *s, size_t n)
{
    CRT_VALIDATE(s != 0, CRT_EINVAL, CRT_EINVAL);
    if (wcsnlen(s, n) >= n) { if (n) s[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    _wcsupr(s);
    return 0;
}
DLLAPI wchar16 *CRTAPI _wcsrev(wchar16 *s)
{
    size_t n = wcslen(s), i;
    for (i = 0; i < n / 2; ++i) { wchar16 t = s[i]; s[i] = s[n - 1 - i]; s[n - 1 - i] = t; }
    return s;
}
DLLAPI wchar16 *CRTAPI _wcsset(wchar16 *s, wchar16 c) { wchar16 *p; for (p = s; *p; ++p) *p = c; return s; }
DLLAPI wchar16 *CRTAPI _wcsnset(wchar16 *s, wchar16 c, size_t n) { wchar16 *p; for (p = s; n && *p; --n, ++p) *p = c; return s; }

DLLAPI crt_errno_t CRTAPI wcscpy_s(wchar16 *d, size_t n, const wchar16 *s)
{
    size_t i;
    CRT_VALIDATE(d != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    if (!s) { d[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    for (i = 0; i < n; ++i)
        if ((d[i] = s[i]) == 0) return 0;
    d[0] = 0;
    CRT_VALIDATE(0, CRT_ERANGE, CRT_ERANGE);
}
DLLAPI crt_errno_t CRTAPI wcsncpy_s(wchar16 *d, size_t n, const wchar16 *s, size_t count)
{
    size_t i, len;
    if (count == 0 && !d && n == 0) return 0;
    CRT_VALIDATE(d != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    if (count == 0) { d[0] = 0; return 0; }
    if (!s) { d[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    len = wcsnlen(s, count == TRUNCATE_ ? n : count);
    if (count == TRUNCATE_ && len >= n) {
        for (i = 0; i + 1 < n; ++i) d[i] = s[i];
        d[n - 1] = 0;
        return CRT_STRUNCATE;
    }
    if (len >= n) { d[0] = 0; CRT_VALIDATE(0, CRT_ERANGE, CRT_ERANGE); }
    for (i = 0; i < len; ++i) d[i] = s[i];
    d[len] = 0;
    return 0;
}
DLLAPI crt_errno_t CRTAPI wcscat_s(wchar16 *d, size_t n, const wchar16 *s)
{
    size_t dl, i;
    CRT_VALIDATE(d != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    if (!s) { d[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    dl = wcsnlen(d, n);
    if (dl == n) { d[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    for (i = 0; dl + i < n; ++i)
        if ((d[dl + i] = s[i]) == 0) return 0;
    d[0] = 0;
    CRT_VALIDATE(0, CRT_ERANGE, CRT_ERANGE);
}
DLLAPI crt_errno_t CRTAPI wcsncat_s(wchar16 *d, size_t n, const wchar16 *s, size_t count)
{
    size_t dl, len, i;
    if (count == 0 && !d && n == 0) return 0;
    CRT_VALIDATE(d != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    if (count == 0) return 0;
    if (!s) { d[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    dl = wcsnlen(d, n);
    if (dl == n) { d[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    len = wcsnlen(s, count == TRUNCATE_ ? n : count);
    if (dl + len >= n) {
        if (count == TRUNCATE_) {
            for (i = 0; dl + i + 1 < n; ++i) d[dl + i] = s[i];
            d[n - 1] = 0;
            return CRT_STRUNCATE;
        }
        d[0] = 0;
        CRT_VALIDATE(0, CRT_ERANGE, CRT_ERANGE);
    }
    for (i = 0; i < len; ++i) d[dl + i] = s[i];
    d[dl + len] = 0;
    return 0;
}
DLLAPI crt_errno_t CRTAPI _wcsset_s(wchar16 *s, size_t n, wchar16 c)
{
    size_t i;
    CRT_VALIDATE(s != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    for (i = 0; i < n && s[i]; ++i) s[i] = c;
    if (i == n) { s[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    return 0;
}
DLLAPI crt_errno_t CRTAPI _wcsnset_s(wchar16 *s, size_t n, wchar16 c, size_t count)
{
    size_t i;
    if (!s && n == 0 && count == 0) return 0;
    CRT_VALIDATE(s != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    for (i = 0; i < n && s[i] && i < count; ++i) s[i] = c;
    if (i == n && s[n - 1]) { s[0] = 0; CRT_VALIDATE(0, CRT_EINVAL, CRT_EINVAL); }
    return 0;
}

/* ---------------------------------------------------------------- error messages (Microsoft's _sys_errlist texts) */
static const char *const g_errlist[] = {
    "No error", "Operation not permitted", "No such file or directory", "No such process", "Interrupted function call",
    "Input/output error", "No such device or address", "Arg list too long", "Exec format error", "Bad file descriptor",
    "No child processes", "Resource temporarily unavailable", "Not enough space", "Permission denied", "Bad address",
    "Unknown error", "Resource device", "File exists", "Improper link", "No such device", "Not a directory", "Is a directory",
    "Invalid argument", "Too many open files in system", "Too many open files", "Inappropriate I/O control operation",
    "Unknown error", "File too large", "No space left on device", "Invalid seek", "Read-only file system", "Too many links",
    "Broken pipe", "Domain error", "Result too large", "Unknown error", "Resource deadlock avoided", "Unknown error",
    "Filename too long", "No locks available", "Function not implemented", "Directory not empty", "Illegal byte sequence",
    "Unknown error",
};
#define SYS_NERR ((int)(sizeof g_errlist / sizeof g_errlist[0]))
static int g_sys_nerr = SYS_NERR;
DLLAPI char **CRTAPI __sys_errlist(void) { return (char **)g_errlist; }
DLLAPI int *CRTAPI __sys_nerr(void) { return &g_sys_nerr; }
static const char *errmsg(int e) { return (e >= 0 && e < SYS_NERR) ? g_errlist[e] : g_errlist[SYS_NERR - 1]; }

DLLAPI char *CRTAPI strerror(int e)
{
    crt_ptd *p = crt_getptd();
    const char *m = errmsg(e);
    size_t n = strlen(m);
    memcpy(p->errbuf, m, n + 1);
    return p->errbuf;
}
DLLAPI crt_errno_t CRTAPI strerror_s(char *buf, size_t n, int e)
{
    crt_errno_t r;
    CRT_VALIDATE(buf != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    r = strncpy_s(buf, n, errmsg(e), TRUNCATE_);
    return r == CRT_STRUNCATE ? 0 : r;
}
/* _strerror(prefix): "prefix: message\n" for errno, or "message\n" when prefix is null */
static void build_strerror(char *out, size_t cap, const char *prefix)
{
    size_t k = 0, i;
    const char *m = errmsg(crt_get_errno());
    if (prefix && *prefix) {
        for (i = 0; prefix[i] && k + 1 < cap; ++i) out[k++] = prefix[i];
        for (i = 0; ": "[i] && k + 1 < cap; ++i) out[k++] = ": "[i];
    }
    for (i = 0; m[i] && k + 1 < cap; ++i) out[k++] = m[i];
    if (k + 1 < cap) out[k++] = '\n';
    out[k] = 0;
}
DLLAPI char *CRTAPI _strerror(const char *prefix)
{
    crt_ptd *p = crt_getptd();
    build_strerror(p->errbuf, sizeof p->errbuf, prefix);
    return p->errbuf;
}
DLLAPI crt_errno_t CRTAPI _strerror_s(char *buf, size_t n, const char *prefix)
{
    CRT_VALIDATE(buf != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    build_strerror(buf, n, prefix);
    return 0;
}
static void widen(wchar16 *d, const char *s, size_t cap)
{
    size_t i;
    for (i = 0; s[i] && i + 1 < cap; ++i) d[i] = (unsigned char)s[i];
    d[i] = 0;
}
DLLAPI wchar16 *CRTAPI _wcserror(int e)
{
    crt_ptd *p = crt_getptd();
    widen(p->werrbuf, errmsg(e), sizeof p->werrbuf / sizeof p->werrbuf[0]);
    return p->werrbuf;
}
DLLAPI crt_errno_t CRTAPI _wcserror_s(wchar16 *buf, size_t n, int e)
{
    CRT_VALIDATE(buf != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    widen(buf, errmsg(e), n);
    return 0;
}
DLLAPI wchar16 *CRTAPI __wcserror(const wchar16 *prefix)
{
    crt_ptd *p = crt_getptd();
    char tmp[96], pre[64];
    size_t i;
    for (i = 0; prefix && prefix[i] && i + 1 < sizeof pre; ++i) pre[i] = (char)(prefix[i] < 0x80 ? prefix[i] : '?');
    pre[i] = 0;
    build_strerror(tmp, sizeof tmp, prefix ? pre : 0);
    widen(p->werrbuf, tmp, sizeof p->werrbuf / sizeof p->werrbuf[0]);
    return p->werrbuf;
}
