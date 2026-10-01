/* SPDX-License-Identifier: GPL-2.0-only
 * Current Steam's actual ANSI version and integer-scaling import contracts.
 * Independent expectations follow the documented API, not a desktop Steam test.
 */
#include "k32test.h"
#include <limits.h>

struct muldiv_case { int number, numerator, denominator, expected; };
static const struct muldiv_case cases[] = {
    { 1, 1, 2, 1 }, { -1, 1, 2, -1 }, { 1, -1, 2, -1 }, { 1, 1, -2, -1 },
    { -1, -1, 2, 1 }, { -1, 1, -2, 1 }, { 1, -1, -2, 1 }, { -1, -1, -2, -1 },
    { 1, 1, 3, 0 }, { -1, 1, 3, 0 }, { 5, 1, 2, 3 }, { -5, 1, 2, -3 },
    { 5, 1, -2, -3 }, { -5, 1, -2, 3 }, { 3, 1, 3, 1 }, { 0, INT_MIN, -1, 0 },
    { INT_MIN, 1, 1, INT_MIN }, { INT_MIN, 1, -1, -1 }, { INT_MAX, 1, 1, INT_MAX },
    { INT_MAX, 2, 2, INT_MAX }, { INT_MIN, 2, 2, INT_MIN }, { INT_MIN, INT_MIN, INT_MIN, INT_MIN },
    { INT_MIN, INT_MIN, INT_MAX, -1 }, { INT_MAX, INT_MAX, INT_MAX, INT_MAX },
    { INT_MIN, -1, INT_MIN, -1 }, { INT_MIN, 1, INT_MIN, 1 }, { INT_MAX, INT_MIN, INT_MIN, INT_MAX },
    { INT_MIN, INT_MAX, INT_MIN, INT_MAX }, { 1, INT_MIN, INT_MAX, -1 }, { 2, INT_MAX, 1, -1 },
    { 5, 3, 0, -1 }, { 0, 0, 0, -1 }, { INT_MAX, INT_MIN, -1, -1 }
};

static int untouched(const unsigned char *bytes, unsigned count)
{
    unsigned i;
    for (i = 0; i < count; ++i) if (bytes[i] != 0xa5) return 0;
    return 1;
}

int main(void)
{
    struct { OSVERSIONINFOA version; unsigned char guard[16]; } basic;
    struct { OSVERSIONINFOEXA version; unsigned char guard[16]; } extended;
    OSVERSIONINFOEXW wide;
    DWORD invalid_sizes[] = { 0, sizeof(OSVERSIONINFOA) - 1, sizeof(OSVERSIONINFOA) + 1,
                             sizeof(OSVERSIONINFOEXA) - 1, sizeof(OSVERSIONINFOEXA) + 1 };
    unsigned i;
    memset(&basic, 0xa5, sizeof basic);
    basic.version.dwOSVersionInfoSize = sizeof basic.version;
    memset(&wide, 0, sizeof wide);
    wide.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);
    CHECK(GetVersionExW((LPOSVERSIONINFOW)&wide) && GetVersionExA(&basic.version), "basic ANSI and wide version queries succeed");
    CHECK(basic.version.dwMajorVersion == wide.dwMajorVersion && basic.version.dwMinorVersion == wide.dwMinorVersion &&
          basic.version.dwBuildNumber == wide.dwBuildNumber && basic.version.dwPlatformId == wide.dwPlatformId,
          "ANSI version reports the same manifest-dependent fields as wide query");
    CHECK(basic.version.dwOSVersionInfoSize == sizeof basic.version && basic.version.szCSDVersion[0] == 0 &&
          untouched(basic.guard, sizeof basic.guard), "basic ANSI result preserves its size, terminates CSD and never overwrites suffix guard");
    memset(&extended, 0xa5, sizeof extended);
    extended.version.dwOSVersionInfoSize = sizeof extended.version;
    memset(&wide, 0, sizeof wide);
    wide.dwOSVersionInfoSize = sizeof wide;
    CHECK(GetVersionExW((LPOSVERSIONINFOW)&wide) && GetVersionExA((LPOSVERSIONINFOA)&extended.version), "extended ANSI and wide version queries succeed");
    CHECK(extended.version.dwMajorVersion == wide.dwMajorVersion && extended.version.dwMinorVersion == wide.dwMinorVersion &&
          extended.version.dwBuildNumber == wide.dwBuildNumber && extended.version.dwPlatformId == wide.dwPlatformId &&
          extended.version.wServicePackMajor == wide.wServicePackMajor && extended.version.wServicePackMinor == wide.wServicePackMinor &&
          extended.version.wSuiteMask == wide.wSuiteMask && extended.version.wProductType == wide.wProductType && extended.version.wReserved == wide.wReserved,
          "ANSI extended fields equal manifest-dependent wide query");
    CHECK(extended.version.dwOSVersionInfoSize == sizeof extended.version && extended.version.szCSDVersion[0] == 0 &&
          untouched(extended.guard, sizeof extended.guard), "extended ANSI query preserves size and suffix guard");
    /* This guest test has no supportedOS manifest. The API's documented report
     * is Windows 8 compatibility (6.2) while the actual platform remains 10.0. */
    CHECK(extended.version.dwMajorVersion == 6 && extended.version.dwMinorVersion == 2 && extended.version.dwBuildNumber == 9200 &&
          extended.version.dwPlatformId == VER_PLATFORM_WIN32_NT && extended.version.wProductType == VER_NT_WORKSTATION,
          "manifest-less ANSI query honors documented 6.2.9200 version compatibility");
    for (i = 0; i < sizeof invalid_sizes / sizeof invalid_sizes[0]; ++i) {
        memset(&extended, 0xa5, sizeof extended);
        extended.version.dwOSVersionInfoSize = invalid_sizes[i];
        CHECK(!GetVersionExA((LPOSVERSIONINFOA)&extended.version) &&
              untouched((unsigned char *)&extended.version + sizeof(DWORD), sizeof extended - sizeof(DWORD)),
              "invalid ANSI structure size fails without writing output or suffix guard");
    }
    CHECK(!GetVersionExA(NULL), "NULL ANSI output fails");
    for (i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        const struct muldiv_case *c = &cases[i];
        int result = MulDiv(c->number, c->numerator, c->denominator);
        CHECKV(result == c->expected, "MulDiv documented rounding, signed endpoints and overflow", "%d * %d / %d: actual=%d expected=%d",
               c->number, c->numerator, c->denominator, result, c->expected);
    }
    return k32t_finish("T_STEAM_COMPAT");
}
