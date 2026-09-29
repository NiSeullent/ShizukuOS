/* SPDX-License-Identifier: GPL-2.0-only
 * Hardware entropy for the user-mode system DLLs (rpcrt4 UuidCreate, bcrypt BCryptGenRandom, ...).
 *
 * The only entropy source this system has is the CPU's RDRAND instruction (CPUID.1:ECX bit 30). There is no
 * fallback PRNG on purpose: a pseudo-random generator seeded from the clock would silently produce predictable
 * "random" bytes. When RDRAND is absent, shz_random_bytes() fails and every caller reports an error.
 *
 * Retry policy follows Intel's Digital Random Number Generator guide: RDRAND may transiently report CF=0
 * ("no data available"); the guide recommends retrying up to 10 times before treating it as a failure.
 */
#ifndef SHZ_RAND_H
#define SHZ_RAND_H
#include <stdint.h>
#include <stddef.h>

static inline int shz_has_rdrand(void)
{
    static volatile int cached = -1;
    int v = cached;
    if (v < 0) {
        uint32_t a = 1, b = 0, c = 0, d = 0;
        __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
        v = (int)((c >> 30) & 1u);
        cached = v;
    }
    return v;
}

/* One 64-bit RDRAND value with the documented 10-attempt retry. Returns 1 on success, 0 on failure. */
static inline int shz_rdrand64(uint64_t *out)
{
    int i;
    for (i = 0; i < 10; ++i) {
        uint64_t v;
        unsigned char ok;
        __asm__ volatile("rdrand %0; setc %1" : "=r"(v), "=qm"(ok) : : "cc");
        if (ok) { *out = v; return 1; }
    }
    return 0;
}

/* Fill buf with n random bytes. Returns 1 on success; 0 if RDRAND is missing or keeps failing (buf is then
 * partially filled and must not be used). */
static inline int shz_random_bytes(void *buf, size_t n)
{
    unsigned char *p = (unsigned char *)buf;
    if (!shz_has_rdrand()) return 0;
    while (n) {
        uint64_t v;
        size_t k = n < 8 ? n : 8, j;
        if (!shz_rdrand64(&v)) return 0;
        for (j = 0; j < k; ++j) { p[j] = (unsigned char)v; v >>= 8; }
        p += k;
        n -= k;
    }
    return 1;
}
#endif
