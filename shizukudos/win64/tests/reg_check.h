/* SPDX-License-Identifier: GPL-2.0-only
 * Shared helpers of the t_reg_*.c self-checking programs: PASS/FAIL accounting and small registry utilities.
 * A program exits 0 only if every CHECK passed. Expected values in the checks come from documented Windows behaviour
 * (winreg.h/MSDN error codes and limits) or are computed independently in the test, never read back from the code
 * under test.
 */
#ifndef REG_CHECK_H
#define REG_CHECK_H
#include "ntreg.h"                      /* native registry calls first: nt.h sets up the SDK headers the NT way */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winreg.h>
#include "shzcrt.h"

static int g_pass, g_fail;

static void check_impl(int ok, const char *what, int line)
{
    if (ok) { ++g_pass; printf("PASS: %s\n", what); }
    else { ++g_fail; printf("FAIL: %s (line %d)\n", what, line); }
}
#define CHECK(cond, what) check_impl((cond) ? 1 : 0, what, __LINE__)
/* error-code check: prints the value seen when it differs */
static void check_err_impl(LONG got, LONG want, const char *what, int line)
{
    if (got == want) { ++g_pass; printf("PASS: %s\n", what); }
    else { ++g_fail; printf("FAIL: %s: got %d want %d (line %d)\n", what, (int)got, (int)want, line); }
}
#define CHECK_ERR(got, want, what) check_err_impl((LONG)(got), (LONG)(want), what, __LINE__)

static int finish_tests(const char *name)
{
    printf("%s: %d passed, %d failed\n", name, g_pass, g_fail);
    printf("%s: %s\n", name, g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}

static size_t wl(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }
static int weq(const WCHAR *a, const WCHAR *b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }
static int weq_ci(const WCHAR *a, const WCHAR *b)
{
    for (;; ++a, ++b) {
        WCHAR x = *a, y = *b;
        if (x >= L'a' && x <= L'z') x = (WCHAR)(x - 32);
        if (y >= L'a' && y <= L'z') y = (WCHAR)(y - 32);
        if (x != y) return 0;
        if (!x) return 1;
    }
}

static int weq_ci_n(const WCHAR *a, const WCHAR *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        WCHAR x = a[i], y = b[i];
        if (x >= L'a' && x <= L'z') x = (WCHAR)(x - 32);
        if (y >= L'a' && y <= L'z') y = (WCHAR)(y - 32);
        if (x != y) return 0;
    }
    return 1;
}

/* Recursively deletes `sub` below `root` (RegDeleteKey only removes keys without sub-keys). Returns the last error. */
static LONG delete_tree(HKEY root, const WCHAR *sub)
{
    HKEY k;
    LONG e = RegOpenKeyExW(root, sub, 0, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | DELETE, &k);
    if (e) return e;
    for (;;) {
        WCHAR name[300];
        DWORD n = 300;
        if (RegEnumKeyExW(k, 0, name, &n, 0, 0, 0, 0)) break;        /* always index 0: the list shrinks */
        if (delete_tree(k, name)) break;
    }
    RegCloseKey(k);
    return RegDeleteKeyW(root, sub);
}
#endif
