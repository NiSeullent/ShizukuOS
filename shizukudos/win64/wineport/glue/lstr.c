/* SPDX-License-Identifier: GPL-2.0-only
 * Wine port glue: lstrcmpA / lstrcmpiA with the documented Win32 behaviour the Wine code relies on: a NULL string
 * sorts before any other (two NULLs are equal) and the comparison is CompareStringA's (linguistic, user locale).
 * The Shizuku kernel32 exports byte-wise versions without NULL handling; the Wine modules link these instead.
 */
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "winnls.h"

int WINAPI lstrcmpA(LPCSTR a, LPCSTR b)
{
    int r;
    if (!a || !b) return a ? 1 : b ? -1 : 0;
    r = CompareStringA(GetThreadLocale(), 0, a, -1, b, -1);
    return r ? r - CSTR_EQUAL : 0;
}

int WINAPI lstrcmpiA(LPCSTR a, LPCSTR b)
{
    int r;
    if (!a || !b) return a ? 1 : b ? -1 : 0;
    r = CompareStringA(GetThreadLocale(), NORM_IGNORECASE, a, -1, b, -1);
    return r ? r - CSTR_EQUAL : 0;
}

void *__imp_lstrcmpA = (void *)lstrcmpA;
void *__imp_lstrcmpiA = (void *)lstrcmpiA;
