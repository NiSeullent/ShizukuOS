/* SPDX-License-Identifier: GPL-2.0-only
 * shlwapi.dll - registry helpers (SHDeleteKey, SHDeleteEmptyKey, SHGetValue, SHSetValue, SHDeleteValue), added once the
 * Win32 registry API existed (advapi32 over the Kernel64 registry). Written from the shlwapi documentation:
 *   SHDeleteKey       deletes a key with all its sub-keys and values (RegDeleteTree with a sub-key name)
 *   SHDeleteEmptyKey  deletes a key only if it has no sub-keys (values do not matter), else ERROR_KEY_HAS_CHILDREN
 *   SHGetValue        RegOpenKeyEx + RegQueryValueEx; REG_EXPAND_SZ data is returned expanded, typed as REG_SZ
 *   SHSetValue        RegCreateKeyEx + RegSetValueEx
 *   SHDeleteValue     RegOpenKeyEx + RegDeleteValue
 */
#include "nt.h"
#include <string.h>
#include <winnls.h>
#include <winreg.h>

#ifndef ERROR_KEY_HAS_CHILDREN
#define ERROR_KEY_HAS_CHILDREN 1020
#endif

DLLAPI DWORD WINAPI SHDeleteKeyW(HKEY hkey, LPCWSTR sub) { return (DWORD)RegDeleteTreeW(hkey, sub && *sub ? sub : NULL); }
DLLAPI DWORD WINAPI SHDeleteKeyA(HKEY hkey, LPCSTR sub) { return (DWORD)RegDeleteTreeA(hkey, sub && *sub ? sub : NULL); }

DLLAPI DWORD WINAPI SHDeleteEmptyKeyW(HKEY hkey, LPCWSTR sub)
{
    HKEY k;
    DWORD subkeys = 0;
    LONG r = RegOpenKeyExW(hkey, sub, 0, KEY_READ, &k);
    if (r) return (DWORD)r;
    r = RegQueryInfoKeyW(k, NULL, NULL, NULL, &subkeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    RegCloseKey(k);
    if (r) return (DWORD)r;
    if (subkeys) return ERROR_KEY_HAS_CHILDREN;
    return (DWORD)RegDeleteKeyW(hkey, sub);
}
DLLAPI DWORD WINAPI SHDeleteEmptyKeyA(HKEY hkey, LPCSTR sub)
{
    WCHAR w[MAX_PATH];
    if (!MultiByteToWideChar(CP_ACP, 0, sub, -1, w, MAX_PATH)) return ERROR_INVALID_PARAMETER;
    return SHDeleteEmptyKeyW(hkey, w);
}

DLLAPI DWORD WINAPI SHGetValueW(HKEY hkey, LPCWSTR sub, LPCWSTR value, DWORD *type, void *data, DWORD *size)
{
    HKEY k = hkey;
    DWORD t = 0, cap = size ? *size : 0;
    LONG r;
    if (sub && *sub && (r = RegOpenKeyExW(hkey, sub, 0, KEY_QUERY_VALUE, &k))) return (DWORD)r;
    r = RegQueryValueExW(k, value, NULL, &t, data, size);
    if (k != hkey) RegCloseKey(k);
    if (!r && t == REG_EXPAND_SZ && data && size) {
        WCHAR *tmp = HeapAlloc(GetProcessHeap(), 0, *size ? *size : sizeof(WCHAR));
        if (tmp) {
            DWORD need;
            memcpy(tmp, data, *size);
            need = ExpandEnvironmentStringsW(tmp, data, cap / sizeof(WCHAR));
            HeapFree(GetProcessHeap(), 0, tmp);
            if (need * sizeof(WCHAR) > cap) r = ERROR_MORE_DATA;
            *size = need * sizeof(WCHAR);
            t = REG_SZ;
        }
    }
    if (type) *type = t;
    return (DWORD)r;
}
DLLAPI DWORD WINAPI SHGetValueA(HKEY hkey, LPCSTR sub, LPCSTR value, DWORD *type, void *data, DWORD *size)
{
    HKEY k = hkey;
    DWORD t = 0;
    LONG r;
    if (sub && *sub && (r = RegOpenKeyExA(hkey, sub, 0, KEY_QUERY_VALUE, &k))) return (DWORD)r;
    r = RegQueryValueExA(k, value, NULL, &t, data, size);
    if (k != hkey) RegCloseKey(k);
    if (type) *type = t == REG_EXPAND_SZ ? REG_SZ : t;     /* ANSI expansion is not performed (UTF-8 system code page) */
    return (DWORD)r;
}

DLLAPI DWORD WINAPI SHSetValueW(HKEY hkey, LPCWSTR sub, LPCWSTR value, DWORD type, const void *data, DWORD size)
{
    HKEY k = hkey;
    LONG r;
    if (sub && *sub && (r = RegCreateKeyExW(hkey, sub, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL))) return (DWORD)r;
    r = RegSetValueExW(k, value, 0, type, data, size);
    if (k != hkey) RegCloseKey(k);
    return (DWORD)r;
}
DLLAPI DWORD WINAPI SHSetValueA(HKEY hkey, LPCSTR sub, LPCSTR value, DWORD type, const void *data, DWORD size)
{
    HKEY k = hkey;
    LONG r;
    if (sub && *sub && (r = RegCreateKeyExA(hkey, sub, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL))) return (DWORD)r;
    r = RegSetValueExA(k, value, 0, type, data, size);
    if (k != hkey) RegCloseKey(k);
    return (DWORD)r;
}

DLLAPI DWORD WINAPI SHDeleteValueW(HKEY hkey, LPCWSTR sub, LPCWSTR value)
{
    HKEY k = hkey;
    LONG r;
    if (sub && *sub && (r = RegOpenKeyExW(hkey, sub, 0, KEY_SET_VALUE, &k))) return (DWORD)r;
    r = RegDeleteValueW(k, value);
    if (k != hkey) RegCloseKey(k);
    return (DWORD)r;
}
DLLAPI DWORD WINAPI SHDeleteValueA(HKEY hkey, LPCSTR sub, LPCSTR value)
{
    HKEY k = hkey;
    LONG r;
    if (sub && *sub && (r = RegOpenKeyExA(hkey, sub, 0, KEY_SET_VALUE, &k))) return (DWORD)r;
    r = RegDeleteValueA(k, value);
    if (k != hkey) RegCloseKey(k);
    return (DWORD)r;
}
