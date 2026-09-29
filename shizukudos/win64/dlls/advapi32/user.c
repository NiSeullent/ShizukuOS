/* SPDX-License-Identifier: GPL-2.0-only
 * advapi32.dll: identity of the single system user (GetUserNameW/A).
 *
 * Kernel64 has one interactive user and no logon sessions or tokens, so the name is a documented constant
 * (SHZ_USER_NAME_W in ntreg.h) and the SID behind it is SHZ_USER_SID_A: \Registry\User\<that SID> is the tree HKEY_CURRENT_USER
 * maps to. Token, SID-lookup and impersonation APIs are deliberately absent (they need real logon sessions).
 */
#define _ADVAPI32_
#include "nt.h"
#include "ntreg.h"

/* Buffer size is in characters including the terminating NUL, in and out (ERROR_INSUFFICIENT_BUFFER reports the size needed). */
DLLAPI BOOL WINAPI GetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer)
{
    static const WCHAR name[] = SHZ_USER_NAME_W;
    const DWORD need = sizeof name / sizeof(WCHAR);
    DWORD i;
    if (!pcbBuffer || (!lpBuffer && *pcbBuffer)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (*pcbBuffer < need) {
        *pcbBuffer = need;
        shz_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    for (i = 0; i < need; ++i) lpBuffer[i] = name[i];
    *pcbBuffer = need;
    return TRUE;
}

DLLAPI BOOL WINAPI GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer)
{
    static const WCHAR name[] = SHZ_USER_NAME_W;              /* pure ASCII: the ANSI form is the same characters */
    const DWORD need = sizeof name / sizeof(WCHAR);
    DWORD i;
    if (!pcbBuffer || (!lpBuffer && *pcbBuffer)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (*pcbBuffer < need) {
        *pcbBuffer = need;
        shz_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    for (i = 0; i < need; ++i) lpBuffer[i] = (char)name[i];
    *pcbBuffer = need;
    return TRUE;
}
