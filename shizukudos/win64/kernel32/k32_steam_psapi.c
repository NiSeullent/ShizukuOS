/* SPDX-License-Identifier: GPL-2.0-only
 * PSAPI process IDs from an actual Kernel64 process snapshot. EnumProcesses
 * reports bytes returned, unlike module enumeration's total bytes required.
 * A short array is successful and contains only whole DWORD identifiers.
 */
#include "k32.h"
#include <tlhelp32.h>

K32API BOOL WINAPI K32EnumProcesses(DWORD *ids, DWORD bytes, DWORD *returned)
{
    HANDLE snapshot;
    PROCESSENTRY32W entry;
    DWORD count = 0, capacity = bytes / sizeof(DWORD), error;
    BOOL next;
    if (!returned || (capacity && !ids)) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *returned = 0;
    if (!capacity) return TRUE;
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return FALSE;
    memset(&entry, 0, sizeof entry);
    entry.dwSize = sizeof entry;
    next = Process32FirstW(snapshot, &entry);
    while (next && count < capacity) {
        ids[count++] = entry.th32ProcessID;
        if (count == capacity) break;
        next = Process32NextW(snapshot, &entry);
    }
    error = next ? ERROR_SUCCESS : GetLastError();
    CloseHandle(snapshot);
    if (error != ERROR_SUCCESS && error != ERROR_NO_MORE_FILES) {
        shz_set_last_error(error);
        return FALSE;
    }
    *returned = count * sizeof(DWORD);
    return TRUE;
}
