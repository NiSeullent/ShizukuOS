/* SPDX-License-Identifier: GPL-2.0-only
 * System random bytes for the user-mode DLLs (bcryptprimitives ProcessPrng, bcrypt BCryptGenRandom, rpcrt4 UuidCreate,
 * and through ProcessPrng Wine's cryptbase RtlGenRandom / RtlEncryptMemory).
 *
 * The source is the kernel's generator (kernel64/krandom.c, system call NtShzRandom): an entropy pool fed by RDSEED /
 * RDRAND when the CPU has them, boot-time CPU execution jitter and the timing of every interrupt, output through a
 * ChaCha20 CSPRNG with fast key erasure. It works on CPUs without RDRAND (Intel before Ivy Bridge, many virtual
 * machines), where the previous RDRAND-only source failed and every caller reported an error.
 */
#ifndef SHZ_RAND_H
#define SHZ_RAND_H
#include <stdint.h>
#include <stddef.h>

long NtShzRandom(void *buffer, unsigned long long length);     /* ntdll, generated from kernel64/ntsys.h (0xa0) */

/* Fill buf with n random bytes. Returns 1 on success, 0 if the kernel refused (bad buffer). */
static inline int shz_random_bytes(void *buf, size_t n)
{
    unsigned char *p = (unsigned char *)buf;
    while (n) {
        const size_t k = n < (1u << 20) ? n : (1u << 20);   /* the kernel serves at most 1 MiB per call */
        if (NtShzRandom(p, k) != 0) return 0;
        p += k;
        n -= k;
    }
    return 1;
}
#endif
