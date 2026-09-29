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

#define CHECK(cond, what) do { ++k32t_checks; if (cond) printf("PASS: %s\n", what); \
    else { ++k32t_failed; printf("FAIL: %s (line %d)\n", what, __LINE__); } } while (0)
#define CHECKV(cond, what, ...) do { ++k32t_checks; if (cond) printf("PASS: %s\n", what); \
    else { ++k32t_failed; printf("FAIL: %s (line %d: ", what, __LINE__); printf(__VA_ARGS__); printf(")\n"); } } while (0)
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
