/* SPDX-License-Identifier: GPL-2.0-only
 * Tiny self-check helpers for the t_u_*.c user-mode DLL tests. Every check prints one `PASS:` or `FAIL:` line;
 * main() returns the number of failures, so exit code 0 means every check passed. Expected values in these tests come
 * from documented behaviour or public test vectors (RFCs, FIPS), never from the implementation's own output. */
#ifndef U_CHECK_H
#define U_CHECK_H
#include "shzcrt.h"

static int u_failures, u_checks;

#define U_CHECK(name, cond) do { ++u_checks; if (cond) printf("PASS: %s\n", (name)); else { ++u_failures; printf("FAIL: %s\n", (name)); } } while (0)
/* Same, with a printf-style detail (integers/strings only: the CRT's printf has no floating point or wide strings). */
#define U_CHECKF(name, cond, ...) do { ++u_checks; if (cond) printf("PASS: %s\n", (name)); else { ++u_failures; printf("FAIL: %s: ", (name)); printf(__VA_ARGS__); printf("\n"); } } while (0)

static inline int u_wide_eq(const unsigned short *a, const unsigned short *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

/* Widen an ASCII literal into a caller-provided buffer (tests only use ASCII). */
static inline unsigned short *u_wide(const char *s, unsigned short *buf, unsigned cap)
{
    unsigned i = 0;
    while (s[i] && i + 1 < cap) { buf[i] = (unsigned char)s[i]; ++i; }
    buf[i] = 0;
    return buf;
}

static inline int u_ascii_eq_w(const unsigned short *w, const char *s)
{
    while (*s && *w == (unsigned char)*s) { ++w; ++s; }
    return !*s && !*w;
}

static inline int u_finish(const char *what)
{
    printf("%s: %d checks, %d failed\n", what, u_checks, u_failures);
    return u_failures ? 1 : 0;
}
#endif
