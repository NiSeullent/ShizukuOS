/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - the four libc functions the core uses (and GCC emits for structure copies). shzlite.dll links
 * no C runtime; this file is compiled with -ffreestanding -fno-builtin -fno-tree-loop-distribute-patterns so these
 * loops do not turn into calls to themselves. Owner: core.
 */
#include <stddef.h>
#include <stdint.h>

typedef uint64_t __attribute__((may_alias)) u64_alias;

void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    if (!(((uintptr_t)d | (uintptr_t)s) & 7)) {
        while (n >= 8) {
            *(u64_alias *)d = *(const u64_alias *)s;
            d += 8;
            s += 8;
            n -= 8;
        }
    }
    while (n--) *d++ = *s++;
    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    if (d == s || !n) return dst;
    if (d < s || d >= s + n) return memcpy(dst, src, n);
    d += n;
    s += n;
    while (n--) *--d = *--s;
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = dst;
    if (!((uintptr_t)d & 7) && n >= 8) {
        uint64_t v = (unsigned char)c;
        v |= v << 8;
        v |= v << 16;
        v |= v << 32;
        while (n >= 8) {
            *(u64_alias *)d = v;
            d += 8;
            n -= 8;
        }
    }
    while (n--) *d++ = (unsigned char)c;
    return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = a, *y = b;
    for (; n; --n, ++x, ++y)
        if (*x != *y) return *x < *y ? -1 : 1;
    return 0;
}
