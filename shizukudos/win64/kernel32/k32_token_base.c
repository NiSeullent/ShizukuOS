/* SPDX-License-Identifier: GPL-2.0-only
 * Base process/thread-token entry points used through the process API-set.
 * The same genuine Nt token object/access/error backend as advapi32, without
 * a Kernel32->Advapi32 import cycle or replacement identities/privileges.
 */
#define _ADVAPI32_
#include "k32.h"

K32API BOOL WINAPI OpenProcessToken(HANDLE process, DWORD access, PHANDLE token)
{
    NTSTATUS status = NtOpenProcessToken(process, access, token);
    if (NT_SUCCESS(status)) return TRUE;
    shz_set_last_error(k32_nt_error(status));
    return FALSE;
}

K32API BOOL WINAPI OpenThreadToken(HANDLE thread, DWORD access, BOOL self, PHANDLE token)
{
    NTSTATUS status = NtOpenThreadToken(thread, access, (BOOLEAN)self, token);
    if (NT_SUCCESS(status)) return TRUE;
    shz_set_last_error(k32_nt_error(status));
    return FALSE;
}
