/* SPDX-License-Identifier: GPL-2.0-only
 * Open an owned native handle to the current user's real registry profile.
 * The existing kernel token/profile model has one user identity, including
 * impersonation tokens; this inherits that boundary instead of inventing a
 * second profile or returning the predefined pseudo handle as an owned key.
 */
#define _ADVAPI32_
#include "nt.h"
#include "ntreg.h"
#include <winreg.h>

DLLAPI LONG WINAPI RegOpenCurrentUser(REGSAM desired, PHKEY result)
{
    SHZ_UNICODE_STRING path;
    SHZ_OBJECT_ATTRIBUTES attributes = {0};
    HANDLE handle = NULL;
    NTSTATUS status;
    if (!result) return ERROR_INVALID_PARAMETER;
    *result = NULL;
    status = RtlFormatCurrentUserKeyPath(&path);
    if (status) return (LONG)RtlNtStatusToDosError(status);
    attributes.Length = sizeof attributes;
    attributes.ObjectName = &path;
    attributes.Attributes = 0x40; /* OBJ_CASE_INSENSITIVE */
    status = NtOpenKeyEx(&handle, desired, &attributes, 0);
    RtlFreeUnicodeString(&path);
    if (status) return (LONG)RtlNtStatusToDosError(status);
    *result = (HKEY)handle;
    return ERROR_SUCCESS;
}
