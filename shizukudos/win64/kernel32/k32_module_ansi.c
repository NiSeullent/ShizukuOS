/* SPDX-License-Identifier: GPL-2.0-only
 * Bare ANSI Module32First/Next exports over the actual shared W snapshot.
 * Original implementation from the Microsoft Toolhelp contract and existing
 * snapshot/UTF-8 providers; no upstream implementation copied.
 */
#include "k32.h"
/* tlhelp32.h maps these exact bare names/types to W under UNICODE. This
 * translation unit implements the ANSI ABI regardless of the build flag. */
#ifdef UNICODE
#undef UNICODE
#endif
#include <tlhelp32.h>

_Static_assert(sizeof(MODULEENTRY32) == 568 && sizeof(MODULEENTRY32W) == 1080, "AMD64 Toolhelp module ABI");
_Static_assert(offsetof(MODULEENTRY32, szModule) == 48 && offsetof(MODULEENTRY32, szExePath) == 304,
               "ANSI module string offsets");

static BOOL module_ansi_string(const WCHAR *wide, size_t wide_capacity, char *ansi, int ansi_capacity)
{
    size_t length;
    for (length = 0; length < wide_capacity && wide[length]; ++length) { }
    if (length == wide_capacity) { shz_set_last_error(ERROR_INVALID_DATA); return FALSE; }
    if (k32_wide_to_utf8(wide, (int)length + 1, ansi, ansi_capacity) <= 0) {
        shz_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return TRUE;
}

static BOOL module_ansi_entry(HANDLE snapshot, LPMODULEENTRY32 entry, BOOL first)
{
    MODULEENTRY32W wide;
    MODULEENTRY32 result;
    DWORD prior_error, caller_size;
    if (!entry || entry->dwSize < sizeof *entry) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
    caller_size = entry->dwSize;
    prior_error = shz_last_error();
    memset(&wide, 0, sizeof wide);
    wide.dwSize = sizeof wide;
    /* Exactly one call on the original snapshot: W/A share its real cursor,
     * immutable data, lock, handle validation and end-of-list behavior. */
    if (!(first ? Module32FirstW(snapshot, &wide) : Module32NextW(snapshot, &wide))) return FALSE;

    memset(&result, 0, sizeof result);
    result.dwSize = caller_size;
    result.th32ModuleID = wide.th32ModuleID;
    result.th32ProcessID = wide.th32ProcessID;
    result.GlblcntUsage = wide.GlblcntUsage;
    result.ProccntUsage = wide.ProccntUsage;
    result.modBaseAddr = wide.modBaseAddr;
    result.modBaseSize = wide.modBaseSize;
    result.hModule = wide.hModule;
    if (!module_ansi_string(wide.szModule, MAX_MODULE_NAME32 + 1, result.szModule, sizeof result.szModule) ||
        !module_ansi_string(wide.szExePath, MAX_PATH, result.szExePath, sizeof result.szExePath))
        return FALSE;
    /* Conversion failure consumes the W entry but never commits partial caller
     * output. Current 48/128-byte kernel UTF-8 records fit both ANSI arrays. */
    memcpy(entry, &result, sizeof result);
    shz_set_last_error(prior_error);
    return TRUE;
}

K32API BOOL WINAPI Module32First(HANDLE snapshot, LPMODULEENTRY32 entry)
{
    return module_ansi_entry(snapshot, entry, TRUE);
}

K32API BOOL WINAPI Module32Next(HANDLE snapshot, LPMODULEENTRY32 entry)
{
    return module_ansi_entry(snapshot, entry, FALSE);
}
