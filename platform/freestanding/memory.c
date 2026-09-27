/* SPDX-License-Identifier: GPL-2.0-only
 * Original compiler-support primitives; no imported libc implementation.
 * Volatile byte accesses prevent loop-to-libcall lowering and recursion.
 */
#include "memory.h"
#include <stdint.h>

void *memset(void *destination, int value, size_t count)
{
    volatile unsigned char *out = destination;
    unsigned char byte = (unsigned char)value;
    size_t i;
    for (i = 0; i < count; ++i)
        out[i] = byte;
    return destination;
}

void *memcpy(void *destination, const void *source, size_t count)
{
    volatile unsigned char *out = destination;
    const volatile unsigned char *in = source;
    size_t i;
    for (i = 0; i < count; ++i)
        out[i] = in[i];
    return destination;
}

void *memmove(void *destination, const void *source, size_t count)
{
    volatile unsigned char *out = destination;
    const volatile unsigned char *in = source;
    size_t i;
    /* Flat i386/x86_64 address order, avoiding relational comparison between
     * pointers into unrelated C objects. No address+count overflow is needed. */
    if ((uintptr_t)destination < (uintptr_t)source) {
        for (i = 0; i < count; ++i)
            out[i] = in[i];
    } else if (destination != source) {
        while (count) {
            --count;
            out[count] = in[count];
        }
    }
    return destination;
}

int memcmp(const void *left, const void *right, size_t count)
{
    const volatile unsigned char *a = left, *b = right;
    size_t i;
    for (i = 0; i < count; ++i) {
        unsigned char x = a[i], y = b[i];
        if (x != y)
            return (int)x - (int)y;
    }
    return 0;
}
