/* SPDX-License-Identifier: GPL-2.0-only
 * Independent literal edge cases plus the host C library's C99 oracle. */
#include "m98_tls_i486_format.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

static void oracle(const char *format, ...)
{
    static const size_t sizes[] = {0, 1, 2, 3, 4, 7, 8, 13, 31, 64, 127, 512};
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; ++i) {
        unsigned char actual[544], expected[544];
        va_list args, copy;
        memset(actual, 0xa5, sizeof actual); memset(expected, 0xa5, sizeof expected);
        va_start(args, format); va_copy(copy, args);
        int a = m98_tls_i486_vsnprintf((char *)actual, sizes[i], format, args);
        int b = vsnprintf((char *)expected, sizes[i], format, copy);
        va_end(copy); va_end(args);
        CHECK(a == b); CHECK(!memcmp(actual, expected, sizeof actual));
    }
}
static void invalid(const char *format, ...)
{
    char actual[64], expected[64];
    va_list args;
    memset(actual, 0x5a, sizeof actual); memcpy(expected, actual, sizeof expected);
    va_start(args, format);
    int result = m98_tls_i486_vsnprintf(actual, sizeof actual, format, args);
    va_end(args);
    CHECK(result == -1); CHECK(!memcmp(actual, expected, sizeof actual));
}
int main(void)
{
    char b[64];
    CHECK(m98_tls_i486_snprintf(b, sizeof b, "%s:%04d:%02X", "TLS", 7, 255u) == 11);
    CHECK(!strcmp(b, "TLS:0007:FF"));
    CHECK(m98_tls_i486_snprintf(b, 5, "%s", "abcdef") == 6); CHECK(!strcmp(b, "abcd"));
    CHECK(m98_tls_i486_snprintf(NULL, 0, "%lld", LLONG_MIN) == 20);
    CHECK(m98_tls_i486_snprintf(NULL, 1, "x") == -1);
    CHECK(m98_tls_i486_snprintf(b, sizeof b, "%I64d/%I32u/%Iu", (long long)-23, (uint32_t)42, (uintptr_t)17) == 9);
    CHECK(!strcmp(b, "-23/42/17"));
    CHECK(m98_tls_i486_snprintf(b, sizeof b, "%p", (void *)0) == 3); CHECK(!strcmp(b, "0x0"));
    for (int n = -129; n <= 129; ++n) {
        oracle("%d/%i/%+08d/% 8d/%-8d/%08.3d/%.0d", n, n, n, n, n, n, n);
        oracle("%u/%#o/%#08x/%#08X/%-12.6u/%#.0x/%#.0o", (unsigned)n, (unsigned)n, (unsigned)n,
               (unsigned)n, (unsigned)n, (unsigned)n, (unsigned)n);
        oracle("%hhd/%hhu/%hd/%hu", n, (unsigned)n, n, (unsigned)n);
    }
    oracle("%d/%u/%ld/%lu/%lld/%llu", INT_MIN, UINT_MAX, LONG_MIN, ULONG_MAX, LLONG_MIN, ULLONG_MAX);
    oracle("%jd/%ju/%zd/%zu/%td", INTMAX_MIN, UINTMAX_MAX, (ptrdiff_t)PTRDIFF_MIN, SIZE_MAX, (ptrdiff_t)PTRDIFF_MAX);
    oracle("%#o|%#x|%#X|%#.0o|%#.0x|%#.0X", 0u, 0u, 0u, 0u, 0u, 0u);
    oracle("%s|%.0s|%.3s|%10.3s|%-10.3s|%*.*s|%%|%c", "abcdef", "abcdef", "abcdef", "abcdef", "abcdef", -9, 4, "abcdef", 0);
    oracle("%*.*d|%*.*u|%*.*s", -8, -1, -23, 8, -1, 23u, 8, -1, "abcd");
    oracle("%.32llu/%064llu/%#.23llo", ULLONG_MAX, ULLONG_MAX, ULLONG_MAX);
    oracle("%4096d", 17);
    invalid("%4097d", 17); invalid("%.*d", 4097, 17); invalid("%*d", INT_MIN, 17);
    invalid("%d/floating:%f", 3, 1.5); invalid("%e", 1.5); invalid("%g", 1.5); invalid("%a", 1.5);
    invalid("%ls", L"wide"); invalid("%S", "wide"); invalid("%m"); invalid("%"); invalid("%I64");
    invalid("%s", (char *)0); invalid("%010s", "abc"); invalid("%q"); invalid(NULL);
    int untouched = 71; invalid("%d/%n", 5, &untouched); CHECK(untouched == 71);
    char long_format[4098]; memset(long_format, 'x', sizeof long_format - 1); long_format[sizeof long_format - 1] = 0;
    invalid(long_format);
    char exact_format[4097]; memset(exact_format, 'x', 4096); exact_format[4096] = 0;
    CHECK(m98_tls_i486_snprintf(NULL, 0, exact_format) == 4096);
    oracle("%*d", -4096, 17);
    char *large = malloc(1048578); CHECK(large != NULL);
    memset(large, 'x', 1048577); large[1048577] = 0;
    invalid("before/%s", large); /* String scan bound, with unchanged output. */
    invalid("%s", large);
    large[1048576] = 0;
    CHECK(m98_tls_i486_snprintf(NULL, 0, "%s", large) == 1048576);
    memset(b, 0x5a, sizeof b);
    CHECK(m98_tls_i486_snprintf(b, sizeof b, "%s", large) == 1048576);
    for (unsigned i = 0; i < sizeof b - 1; ++i) CHECK(b[i] == 'x');
    CHECK(b[sizeof b - 1] == 0);
    char *full = malloc(1048578); CHECK(full != NULL);
    memset(full, 0x5a, 1048578);
    CHECK(m98_tls_i486_snprintf(full, 1048577, "%s", large) == 1048576);
    CHECK(!memcmp(full, large, 1048577)); CHECK(full[1048577] == 0x5a);
    memset(full, 0x5a, 1048578);
    CHECK(m98_tls_i486_snprintf(full, 1, "%s", large) == 1048576);
    CHECK(full[0] == 0); CHECK(full[1] == 0x5a); CHECK(full[1048577] == 0x5a);
    free(full);
    invalid("%s%c", large, 'y'); /* Exact-limit source plus another byte. */
    invalid("before/%s", large); /* Prefix alone can exceed the total bound. */
    large[1048575] = 0;
    CHECK(m98_tls_i486_snprintf(NULL, 0, "%s%c", large, 'y') == 1048576);
    invalid("%s%cX", large, 'y'); /* Total output bound after valid conversions. */
    free(large);
    printf("PASS bounded TLS i486 formatter: %u assertions; independent C99 integer/string oracle; no TLS/native claim\n", checks);
    return 0;
}
