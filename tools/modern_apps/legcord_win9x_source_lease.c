/* Real Win9x filesystem read leases for source imports.
 * SPDX-License-Identifier: GPL-2.0-only
 * Node/Electron binding and native acceptance remain required.
 */
#include "legcord_win9x_source_lease.h"

struct legcord_source_lease {
    DWORD count;
    HANDLE files[1];
};

static BOOL absolute_ascii_path(LPCSTR path)
{
    DWORD index;
    if (!path || !((path[0] >= 'A' && path[0] <= 'Z') ||
                  (path[0] >= 'a' && path[0] <= 'z')) ||
        path[1] != ':' || path[2] != '\\')
        return FALSE;
    for (index = 3; index < MAX_PATH; ++index) {
        BYTE value = (BYTE)path[index];
        if (!value)
            return index > 3;
        if (value < 32 || value > 126 || value == ':' ||
            value == '*' || value == '?' || value == '/')
            return FALSE;
    }
    return FALSE;
}

VOID WINAPI legcord_win9x_ReleaseSourceReadLeases(legcord_source_lease *lease)
{
    if (!lease)
        return;
    while (lease->count)
        CloseHandle(lease->files[--lease->count]);
    HeapFree(GetProcessHeap(), 0, lease);
}

BOOL WINAPI legcord_win9x_AcquireSourceReadLeases(LPCSTR const *paths,
                                                DWORD count,
                                                legcord_source_lease **result)
{
    legcord_source_lease *lease;
    OSVERSIONINFOA version = { 0 };
    DWORD index, error;
    if (!result) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *result = NULL;
    if (!paths || !count || count > 256 || sizeof(PVOID) != 4) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    version.dwOSVersionInfoSize = sizeof(version);
    if (!GetVersionExA(&version) || version.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS ||
        version.dwMajorVersion != 4 || version.dwMinorVersion != 10 ||
        LOWORD(version.dwBuildNumber) != 2222) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    lease = (legcord_source_lease *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        sizeof(*lease) + (count - 1) * sizeof(HANDLE));
    if (!lease) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    for (index = 0; index < count; ++index) {
        HANDLE file;
        if (!absolute_ascii_path(paths[index])) {
            SetLastError(ERROR_INVALID_NAME);
            goto failed;
        }
        /* Read sharing permits Node's import read while denying another open
         * for writing/deletion. An existing writer also prevents acquisition.
         * Hold every lease before JS hashes the files or imports any module. */
        file = CreateFileA(paths[index], GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE)
            goto failed;
        lease->files[lease->count++] = file;
    }
    *result = lease;
    return TRUE;
failed:
    error = GetLastError();
    legcord_win9x_ReleaseSourceReadLeases(lease);
    SetLastError(error);
    return FALSE;
}
