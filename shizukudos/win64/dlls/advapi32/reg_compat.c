/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku advapi32.dll, registry part 2: the older / convenience Reg* entry points that are thin layers over the Ex
 * functions of reg.c, as documented for Win32:
 *   RegOpenKey[A|W]      = RegOpenKeyEx(..., 0, MAXIMUM_ALLOWED); an empty or NULL sub-key returns the key itself
 *   RegCreateKey[A|W]    = RegCreateKeyEx(..., REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED)
 *   RegEnumKey[A|W]      = RegEnumKeyEx without class/time
 *   RegQueryValue[A|W] / RegSetValue[A|W]  the REG_SZ default value of a sub-key
 *   RegSetKeyValue / RegDeleteKeyValue / RegGetValueA / RegQueryInfoKeyA
 *   RegDeleteTree[A|W]   deletes all sub-keys (depth first) and the values of the key; with a sub-key name, that key too
 * They were added for the DLLs ported from Wine (wineport), which call them; written from the Win32 documentation.
 */
#define _ADVAPI32_
#include "nt.h"
#include <string.h>
#include <winnls.h>
#include <winreg.h>

static WCHAR *to_wide(const char *s)
{
    int n;
    WCHAR *w;
    if (!s) return NULL;
    n = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
    if (!(w = HeapAlloc(GetProcessHeap(), 0, n * sizeof(WCHAR)))) return NULL;
    MultiByteToWideChar(CP_ACP, 0, s, -1, w, n);
    return w;
}
static void free_w(WCHAR *w) { if (w) HeapFree(GetProcessHeap(), 0, w); }

DLLAPI LONG WINAPI RegOpenKeyW(HKEY hkey, LPCWSTR sub, PHKEY result)
{
    if (!result) return ERROR_INVALID_PARAMETER;
    if (!sub || !*sub) { *result = hkey; return ERROR_SUCCESS; }
    return RegOpenKeyExW(hkey, sub, 0, MAXIMUM_ALLOWED, result);
}
DLLAPI LONG WINAPI RegOpenKeyA(HKEY hkey, LPCSTR sub, PHKEY result)
{
    if (!result) return ERROR_INVALID_PARAMETER;
    if (!sub || !*sub) { *result = hkey; return ERROR_SUCCESS; }
    return RegOpenKeyExA(hkey, sub, 0, MAXIMUM_ALLOWED, result);
}
DLLAPI LONG WINAPI RegCreateKeyW(HKEY hkey, LPCWSTR sub, PHKEY result)
{
    if (!result) return ERROR_INVALID_PARAMETER;
    return RegCreateKeyExW(hkey, sub ? sub : L"", 0, NULL, REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED, NULL, result, NULL);
}
DLLAPI LONG WINAPI RegCreateKeyA(HKEY hkey, LPCSTR sub, PHKEY result)
{
    if (!result) return ERROR_INVALID_PARAMETER;
    return RegCreateKeyExA(hkey, sub ? sub : "", 0, NULL, REG_OPTION_NON_VOLATILE, MAXIMUM_ALLOWED, NULL, result, NULL);
}
DLLAPI LONG WINAPI RegEnumKeyW(HKEY hkey, DWORD index, LPWSTR name, DWORD cch)
{
    DWORD len = cch;
    return RegEnumKeyExW(hkey, index, name, &len, NULL, NULL, NULL, NULL);
}
DLLAPI LONG WINAPI RegEnumKeyA(HKEY hkey, DWORD index, LPSTR name, DWORD cch)
{
    DWORD len = cch;
    return RegEnumKeyExA(hkey, index, name, &len, NULL, NULL, NULL, NULL);
}

DLLAPI LONG WINAPI RegQueryValueW(HKEY hkey, LPCWSTR sub, LPWSTR data, LONG *count)
{
    HKEY k = hkey;
    DWORD type, size = count ? (DWORD)*count : 0;
    LONG r;
    if (sub && *sub && (r = RegOpenKeyExW(hkey, sub, 0, KEY_QUERY_VALUE, &k))) return r;
    r = RegQueryValueExW(k, NULL, NULL, &type, (BYTE *)data, count ? &size : NULL);
    if (r == ERROR_FILE_NOT_FOUND) {                           /* no default value: an empty string */
        if (count) {
            if (data && *count >= (LONG)sizeof(WCHAR)) data[0] = 0;
            *count = sizeof(WCHAR);
        }
        r = ERROR_SUCCESS;
    } else if (count) *count = (LONG)size;
    if (k != hkey) RegCloseKey(k);
    return r;
}
DLLAPI LONG WINAPI RegQueryValueA(HKEY hkey, LPCSTR sub, LPSTR data, LONG *count)
{
    HKEY k = hkey;
    DWORD type, size = count ? (DWORD)*count : 0;
    LONG r;
    if (sub && *sub && (r = RegOpenKeyExA(hkey, sub, 0, KEY_QUERY_VALUE, &k))) return r;
    r = RegQueryValueExA(k, NULL, NULL, &type, (BYTE *)data, count ? &size : NULL);
    if (r == ERROR_FILE_NOT_FOUND) {
        if (count) {
            if (data && *count >= 1) data[0] = 0;
            *count = 1;
        }
        r = ERROR_SUCCESS;
    } else if (count) *count = (LONG)size;
    if (k != hkey) RegCloseKey(k);
    return r;
}
DLLAPI LONG WINAPI RegSetValueW(HKEY hkey, LPCWSTR sub, DWORD type, LPCWSTR data, DWORD count)
{
    HKEY k = hkey;
    LONG r;
    (void)count;
    if (type != REG_SZ || !data) return ERROR_INVALID_PARAMETER;
    if (sub && *sub && (r = RegCreateKeyW(hkey, sub, &k))) return r;
    r = RegSetValueExW(k, NULL, 0, REG_SZ, (const BYTE *)data, (DWORD)(lstrlenW(data) + 1) * sizeof(WCHAR));
    if (k != hkey) RegCloseKey(k);
    return r;
}
DLLAPI LONG WINAPI RegSetValueA(HKEY hkey, LPCSTR sub, DWORD type, LPCSTR data, DWORD count)
{
    HKEY k = hkey;
    LONG r;
    (void)count;
    if (type != REG_SZ || !data) return ERROR_INVALID_PARAMETER;
    if (sub && *sub && (r = RegCreateKeyA(hkey, sub, &k))) return r;
    r = RegSetValueExA(k, NULL, 0, REG_SZ, (const BYTE *)data, (DWORD)lstrlenA(data) + 1);
    if (k != hkey) RegCloseKey(k);
    return r;
}

DLLAPI LONG WINAPI RegSetKeyValueW(HKEY hkey, LPCWSTR sub, LPCWSTR name, DWORD type, const void *data, DWORD len)
{
    HKEY k = hkey;
    LONG r;
    if (sub && *sub && (r = RegCreateKeyExW(hkey, sub, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL))) return r;
    r = RegSetValueExW(k, name, 0, type, data, len);
    if (k != hkey) RegCloseKey(k);
    return r;
}
DLLAPI LONG WINAPI RegSetKeyValueA(HKEY hkey, LPCSTR sub, LPCSTR name, DWORD type, const void *data, DWORD len)
{
    HKEY k = hkey;
    LONG r;
    if (sub && *sub && (r = RegCreateKeyExA(hkey, sub, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL))) return r;
    r = RegSetValueExA(k, name, 0, type, data, len);
    if (k != hkey) RegCloseKey(k);
    return r;
}
DLLAPI LONG WINAPI RegDeleteKeyValueW(HKEY hkey, LPCWSTR sub, LPCWSTR name)
{
    HKEY k = hkey;
    LONG r;
    if (sub && *sub && (r = RegOpenKeyExW(hkey, sub, 0, KEY_SET_VALUE, &k))) return r;
    r = RegDeleteValueW(k, name);
    if (k != hkey) RegCloseKey(k);
    return r;
}
DLLAPI LONG WINAPI RegDeleteKeyValueA(HKEY hkey, LPCSTR sub, LPCSTR name)
{
    HKEY k = hkey;
    LONG r;
    if (sub && *sub && (r = RegOpenKeyExA(hkey, sub, 0, KEY_SET_VALUE, &k))) return r;
    r = RegDeleteValueA(k, name);
    if (k != hkey) RegCloseKey(k);
    return r;
}

/* RegDeleteTree: sub-keys depth first, then the values of the key; with a sub-key name, that key is deleted as well. */
DLLAPI LONG WINAPI RegDeleteTreeW(HKEY hkey, LPCWSTR sub)
{
    HKEY k = hkey;
    WCHAR name[256];
    LONG r;
    if (sub && *sub && (r = RegOpenKeyExW(hkey, sub, 0, KEY_ALL_ACCESS, &k))) return r;
    for (;;) {                                                   /* index 0 each time: the list shrinks */
        DWORD len = ARRAYSIZE(name);
        r = RegEnumKeyExW(k, 0, name, &len, NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r || (r = RegDeleteTreeW(k, name))) goto done;
    }
    for (;;) {
        DWORD len = ARRAYSIZE(name);
        r = RegEnumValueW(k, 0, name, &len, NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) { r = ERROR_SUCCESS; break; }
        if (r || (r = RegDeleteValueW(k, name))) goto done;
    }
    if (k != hkey) {
        RegCloseKey(k);
        k = hkey;
        r = RegDeleteKeyW(hkey, sub);
    }
done:
    if (k != hkey) RegCloseKey(k);
    return r;
}
DLLAPI LONG WINAPI RegDeleteTreeA(HKEY hkey, LPCSTR sub)
{
    WCHAR *w = to_wide(sub);
    LONG r;
    if (sub && !w) return ERROR_NOT_ENOUGH_MEMORY;
    r = RegDeleteTreeW(hkey, w);
    free_w(w);
    return r;
}

DLLAPI LONG WINAPI RegGetValueA(HKEY hkey, LPCSTR sub, LPCSTR value, DWORD flags, LPDWORD type, PVOID data, LPDWORD count)
{
    HKEY k = hkey;
    DWORD t = 0, size = count ? *count : 0;
    LONG r;
    if (sub && *sub && (r = RegOpenKeyExA(hkey, sub, 0, KEY_QUERY_VALUE, &k))) return r;
    r = RegQueryValueExA(k, value, NULL, &t, data, count ? &size : NULL);
    if (k != hkey) RegCloseKey(k);
    if (r && r != ERROR_MORE_DATA) return r;
    if (((flags & RRF_RT_REG_SZ) && t == REG_SZ) || ((flags & RRF_RT_REG_EXPAND_SZ) && t == REG_EXPAND_SZ) ||
        ((flags & RRF_RT_REG_BINARY) && t == REG_BINARY) || ((flags & RRF_RT_REG_DWORD) && t == REG_DWORD) ||
        ((flags & RRF_RT_REG_MULTI_SZ) && t == REG_MULTI_SZ) || ((flags & RRF_RT_REG_QWORD) && t == REG_QWORD) ||
        ((flags & RRF_RT_REG_NONE) && t == REG_NONE)) {
        if (type) *type = t;
        if (count) *count = size;
        return r;
    }
    return ERROR_UNSUPPORTED_TYPE;
}

DLLAPI LONG WINAPI RegQueryInfoKeyA(HKEY hkey, LPSTR cls, LPDWORD cls_len, LPDWORD reserved, LPDWORD subkeys, LPDWORD max_subkey,
                                    LPDWORD max_class, LPDWORD values, LPDWORD max_value, LPDWORD max_data, LPDWORD sec,
                                    PFILETIME modif)
{
    DWORD wlen = 0;
    LONG r = RegQueryInfoKeyW(hkey, NULL, cls ? &wlen : NULL, reserved, subkeys, max_subkey, max_class, values, max_value,
                              max_data, sec, modif);
    if (!r && cls && cls_len) {
        if (*cls_len) cls[0] = 0;                               /* key classes are not stored: always empty */
        *cls_len = 0;
    }
    return r;
}
