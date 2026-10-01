/* SPDX-License-Identifier: GPL-2.0-only
 * Tiny self-checking harness for the Win64 kernel32 test programs (t_k32_*.c). A program returns 0 only if every check
 * passed; it prints one `PASS: ...` or `FAIL: ...` line per check through the console. The expected values in the checks
 * come from documented Windows behaviour or from independent computation, never from what the implementation returns. */
#ifndef K32TEST_H
#define K32TEST_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winnls.h>
#include "shzcrt.h"

static int k32t_checks, k32t_failed;

/* Console output calls Win32 I/O too. Preserve the error produced by the
 * tested expression, including before formatted failure diagnostics, so a
 * following CHECK_ERR observes the API rather than printf's WriteFile. */
#define CHECK(cond, what) do { BOOL k32t_ok; DWORD k32t_error; ++k32t_checks; \
    k32t_ok = !!(cond); k32t_error = GetLastError(); \
    if (k32t_ok) printf("PASS: %s\n", what); \
    else { ++k32t_failed; printf("FAIL: %s (line %d)\n", what, __LINE__); } \
    SetLastError(k32t_error); } while (0)
#define CHECKV(cond, what, ...) do { BOOL k32t_ok; DWORD k32t_error; ++k32t_checks; \
    k32t_ok = !!(cond); k32t_error = GetLastError(); \
    if (k32t_ok) printf("PASS: %s\n", what); \
    else { ++k32t_failed; printf("FAIL: %s (line %d: ", what, __LINE__); \
        SetLastError(k32t_error); printf(__VA_ARGS__); printf(")\n"); } \
    SetLastError(k32t_error); } while (0)
/* CHECK_W / CHECKV_W: expectations that follow Windows documentation or Windows' own message texts but where Wine (the reference
 * implementation of tests/host/run_wine_tests.py, built with -DK32T_WINE) is known to behave differently: reported as skipped there. */
#ifdef K32T_WINE
#define CHECK_W(cond, what) do { (void)(cond); ++k32t_checks; printf("PASS: %s (skipped: Wine differs from Windows here)\n", what); } while (0)
#define CHECKV_W(cond, what, ...) CHECK_W(cond, what)
#else
#define CHECK_W(cond, what) CHECK(cond, what)
#define CHECKV_W(cond, what, ...) CHECKV(cond, what, __VA_ARGS__)
#endif
/* CHECK_N / CHECKV_N: expectations that hold on Windows and on Kernel64 but where Wine's NT layer (ntdll, also underneath the Shizuku
 * kernel32 sources in the developer harness; -DK32T_UNDER_WINE is given in both harness modes) is known to differ: skipped under Wine and
 * enforced in the Kernel64 run. */
#if defined(K32T_UNDER_WINE)
#define CHECK_N(cond, what) do { (void)(cond); ++k32t_checks; printf("PASS: %s (skipped: Wine's NT layer differs from Windows here)\n", what); } while (0)
#define CHECKV_N(cond, what, ...) CHECK_N(cond, what)
#else
#define CHECK_N(cond, what) CHECK(cond, what)
#define CHECKV_N(cond, what, ...) CHECKV(cond, what, __VA_ARGS__)
#endif
/* GetLastError() must equal `err` (checked right after a failing call) */
#define CHECK_ERR(err, what) CHECKV(GetLastError() == (DWORD)(err), what, "GetLastError=%u expected %u", (unsigned)GetLastError(), (unsigned)(err))

static int k32t_finish(const char *name)
{
    printf("%s: %d checks, %d failed\n", name, k32t_checks, k32t_failed);
    return k32t_failed ? 1 : 0;
}

/* wide string helpers (no CRT wchar functions) */
static int k32t_weq(const WCHAR *a, const WCHAR *b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }
static int k32t_wlen(const WCHAR *a) { int n = 0; while (a[n]) ++n; return n; }
#endif
