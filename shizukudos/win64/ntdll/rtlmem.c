/* SPDX-License-Identifier: GPL-2.0-only
 * Byte/wide-string primitives that ntdll.dll exports on Windows (memcpy family, strlen, wcslen, ...).
 * Written from the C standard's descriptions; simple loops on purpose (correctness over speed).
 */
#include "../include/nt.h"
#include <string.h>

SHZ_EXPORT void *__cdecl memcpy(void *d, const void *s, size_t n)
{
    unsigned char *a = d;
    const unsigned char *b = s;
    while (n--) *a++ = *b++;
    return d;
}

SHZ_EXPORT void *__cdecl memmove(void *d, const void *s, size_t n)
{
    unsigned char *a = d;
    const unsigned char *b = s;
    if (a == b) return d;
    if (a < b || a >= b + n) { while (n--) *a++ = *b++; }
    else { a += n; b += n; while (n--) *--a = *--b; }
    return d;
}

SHZ_EXPORT void *__cdecl memset(void *d, int c, size_t n)
{
    unsigned char *a = d;
    while (n--) *a++ = (unsigned char)c;
    return d;
}

SHZ_EXPORT int __cdecl memcmp(const void *x, const void *y, size_t n)
{
    const unsigned char *a = x, *b = y;
    for (; n; --n, ++a, ++b)
        if (*a != *b) return *a < *b ? -1 : 1;
    return 0;
}

SHZ_EXPORT size_t __cdecl strlen(const char *s)
{
    size_t n = 0;
    while (s[n]) ++n;
    return n;
}

SHZ_EXPORT size_t __cdecl wcslen(const wchar_t *s)
{
    size_t n = 0;
    while (s[n]) ++n;
    return n;
}

SHZ_EXPORT int __cdecl strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return (unsigned char)*a - (unsigned char)*b;
}

SHZ_EXPORT int __cdecl wcscmp(const wchar_t *a, const wchar_t *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return (int)*a - (int)*b;
}
