/* SPDX-License-Identifier: GPL-2.0-only
 * WER executable exclusions backed by the actual registry provider.
 * Independently implemented from Microsoft contracts after reviewing Wine
 * db11d0fe6a169c457e23d007e20404643d067aa8 dlls/wer/main.c and One-Core
 * 9eb3c31de9460c1ccce3f6a10c9c4a704f032514 oca/new-dlls/wer/main.c.
 * Those implementations ignore a failed RegSetValueExW; this one preserves
 * every registry error. No report collection/upload backend is provided.
 */
#include "nt.h"
#include <winreg.h>
#include <winerror.h>

/* ---- WER registry exclusions contract ---- */
static const WCHAR exclusion_key[] = L"Software\\Microsoft\\Windows Error Reporting\\ExcludedApplications";

static PCWSTR exclusion_name(PCWSTR path)
{
    PCWSTR name = path;
    unsigned i;
    if (!path) return NULL;
    for (i = 0; i < MAX_PATH && path[i]; ++i)
        if (path[i] == '\\') name = path + i + 1;
    /* MAX_PATH includes the terminating NUL; retain a borrowed basename only
     * during this call. An extension is not restricted to .exe (e.g. .bin). */
    if (!i || i == MAX_PATH || !*name) return NULL;
    return name;
}

DLLAPI HRESULT WINAPI WerAddExcludedApplication(PCWSTR path, BOOL all_users)
{
    PCWSTR name = exclusion_name(path);
    HKEY key;
    const DWORD value = 1;
    LONG error, closed;
    if (!name) return E_INVALIDARG;
    error = RegCreateKeyExW(all_users ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER,
                           exclusion_key, 0, NULL, REG_OPTION_NON_VOLATILE,
                           KEY_SET_VALUE, NULL, &key, NULL);
    if (error) return HRESULT_FROM_WIN32(error);
    error = RegSetValueExW(key, name, 0, REG_DWORD, (const BYTE *)&value, sizeof value);
    closed = RegCloseKey(key);
    if (!error) error = closed;
    return HRESULT_FROM_WIN32(error);
}

DLLAPI HRESULT WINAPI WerRemoveExcludedApplication(PCWSTR path, BOOL all_users)
{
    PCWSTR name = exclusion_name(path);
    HKEY key;
    LONG error, closed;
    if (!name) return E_INVALIDARG;
    /* An absent list is an actual absence; do not create a list on removal. */
    error = RegOpenKeyExW(all_users ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER,
                         exclusion_key, 0, KEY_SET_VALUE, &key);
    if (error) return HRESULT_FROM_WIN32(error);
    error = RegDeleteValueW(key, name);
    closed = RegCloseKey(key);
    if (!error) error = closed;
    return HRESULT_FROM_WIN32(error);
}
/* ---- end WER registry exclusions contract ---- */
