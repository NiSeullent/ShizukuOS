/* SPDX-License-Identifier: GPL-2.0-only
 * tridentrt: shlwapi functions (besides the URL family, which is Wine's kernelbase/path.c) that the Wine browser
 * modules import and the Shizuku shlwapi does not export: the user-specific registry keys SHReg*USKey/Value
 * (ieframe), IStream_Read/IStream_Write (#184/#212), SHSetParentHwnd (#167, ieframe), StrStrIA (wininet),
 * GetMIMETypeSubKeyW (#329, mshtml) and SHStrDupW. Exported by name from tridentrt.dll.
 *
 * An HUSKEY is a pair of keys: the path under HKEY_CURRENT_USER and the same path under HKEY_LOCAL_MACHINE (or under
 * the two keys of a relative HUSKEY). Queries try HKCU first unless told to ignore it, then HKLM, then the caller's
 * default, as documented. SHRegEnumUSValueW enumerates HKCU (SHREGENUM_HKCU), HKLM (SHREGENUM_HKLM) or, for
 * SHREGENUM_DEFAULT, whichever of the two is open (HKCU first); the merged SHREGENUM_BOTH view is not provided and
 * fails with ERROR_INVALID_FUNCTION, as in Wine.
 */
#include "comrt.h"
#include "winuser.h"
#include "shlwapi.h"

struct uskey
{
    HKEY hkcu, hklm;            /* opened keys, 0 when absent */
};

LONG WINAPI SHRegOpenUSKeyW(const WCHAR *path, REGSAM access, HUSKEY relative, HUSKEY *out, BOOL ignore_hkcu)
{
    const struct uskey *rel = (const struct uskey *)relative;
    HKEY cu_base = HKEY_CURRENT_USER, lm_base = HKEY_LOCAL_MACHINE;
    struct uskey *key;
    LONG cu = ERROR_FILE_NOT_FOUND, lm;

    if (out) *out = NULL;
    if (!out) return ERROR_INVALID_PARAMETER;
    if (rel)
    {
        cu_base = rel->hkcu;
        lm_base = rel->hklm;
    }
    if (!(key = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*key)))) return ERROR_NOT_ENOUGH_MEMORY;
    if (!ignore_hkcu && cu_base) cu = RegOpenKeyExW(cu_base, path, 0, access, &key->hkcu);
    lm = lm_base ? RegOpenKeyExW(lm_base, path, 0, access, &key->hklm) : ERROR_FILE_NOT_FOUND;
    if (cu) key->hkcu = 0;
    if (lm) key->hklm = 0;
    if (!key->hkcu && !key->hklm)
    {
        HeapFree(GetProcessHeap(), 0, key);
        return lm;
    }
    *out = (HUSKEY)key;
    return ERROR_SUCCESS;
}

LONG WINAPI SHRegCloseUSKey(HUSKEY handle)
{
    struct uskey *key = (struct uskey *)handle;
    LONG ret = ERROR_SUCCESS;
    if (!key) return ERROR_INVALID_PARAMETER;
    if (key->hkcu) ret = RegCloseKey(key->hkcu);
    if (key->hklm && !ret) ret = RegCloseKey(key->hklm);
    else if (key->hklm) RegCloseKey(key->hklm);
    HeapFree(GetProcessHeap(), 0, key);
    return ret;
}

LONG WINAPI SHRegQueryUSValueW(HUSKEY handle, const WCHAR *value, DWORD *type, void *data, DWORD *size,
                               BOOL ignore_hkcu, void *default_data, DWORD default_size)
{
    struct uskey *key = (struct uskey *)handle;
    LONG ret = ERROR_FILE_NOT_FOUND;
    DWORD n;

    if (!key) return ERROR_INVALID_PARAMETER;
    if (!ignore_hkcu && key->hkcu && !(ret = RegQueryValueExW(key->hkcu, value, NULL, type, data, size))) return ret;
    if (key->hklm && !(ret = RegQueryValueExW(key->hklm, value, NULL, type, data, size))) return ret;
    if (default_data && default_size && size)
    {
        n = default_size < *size ? default_size : *size;
        if (data) memcpy(data, default_data, n);
        *size = n;
        ret = ERROR_SUCCESS;
    }
    return ret;
}

LONG WINAPI SHRegGetUSValueW(const WCHAR *subkey, const WCHAR *value, DWORD *type, void *data, DWORD *size,
                             BOOL ignore_hkcu, void *default_data, DWORD default_size)
{
    HUSKEY key;
    LONG ret;

    if (!data || !size) return ERROR_INVALID_FUNCTION;
    if (!(ret = SHRegOpenUSKeyW(subkey, KEY_QUERY_VALUE, 0, &key, ignore_hkcu)))
    {
        ret = SHRegQueryUSValueW(key, value, type, data, size, ignore_hkcu, default_data, default_size);
        SHRegCloseUSKey(key);
    }
    else if (default_data && default_size)
    {
        DWORD n = default_size < *size ? default_size : *size;
        memcpy(data, default_data, n);
        *size = n;
        ret = ERROR_SUCCESS;
    }
    return ret;
}

LONG WINAPI SHRegEnumUSValueW(HUSKEY handle, DWORD index, WCHAR *name, DWORD *name_len, DWORD *type, void *data,
                              DWORD *data_len, SHREGENUM_FLAGS flags)
{
    struct uskey *key = (struct uskey *)handle;
    if (!key) return ERROR_INVALID_PARAMETER;
    if ((flags == SHREGENUM_HKCU || flags == SHREGENUM_DEFAULT) && key->hkcu)
        return RegEnumValueW(key->hkcu, index, name, name_len, NULL, type, data, data_len);
    if ((flags == SHREGENUM_HKLM || flags == SHREGENUM_DEFAULT) && key->hklm)
        return RegEnumValueW(key->hklm, index, name, name_len, NULL, type, data, data_len);
    return ERROR_INVALID_FUNCTION;
}

/* ---------------------------------------------------------------- IStream helpers (#184, #212) */
HRESULT WINAPI IStream_Read(IStream *stream, void *data, ULONG size)
{
    ULONG done = 0;
    HRESULT hr = stream->lpVtbl->Read(stream, data, size, &done);
    return SUCCEEDED(hr) && done != size ? E_FAIL : hr;
}

HRESULT WINAPI IStream_Write(IStream *stream, const void *data, ULONG size)
{
    ULONG done = 0;
    HRESULT hr = stream->lpVtbl->Write(stream, data, size, &done);
    return SUCCEEDED(hr) && done != size ? E_FAIL : hr;
}

/* ---------------------------------------------------------------- windows and strings */
/* #167: make hwnd a child of parent (WS_CHILD instead of WS_POPUP), or a popup again when parent is NULL; returns
 * SetParent's result (the previous parent), NULL when nothing changed or when un-parenting */
HWND WINAPI SHSetParentHwnd(HWND hwnd, HWND parent)
{
    LONG style;
    if (GetParent(hwnd) == parent) return NULL;
    style = GetWindowLongW(hwnd, GWL_STYLE);
    style = (style & ~(WS_CHILD | WS_POPUP)) | (parent ? WS_CHILD : WS_POPUP);
    if (style != GetWindowLongW(hwnd, GWL_STYLE)) SetWindowLongW(hwnd, GWL_STYLE, style);
    return parent ? SetParent(hwnd, parent) : NULL;
}

static char fold(char c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

/* case-insensitive search; ASCII letters are folded, other bytes compare exactly */
char * WINAPI StrStrIA(const char *str, const char *search)
{
    size_t n, i;
    if (!str || !search || !*search) return NULL;
    n = strlen(search);
    for (; *str; str++)
    {
        for (i = 0; i < n && str[i] && fold(str[i]) == fold(search[i]); i++) { }
        if (i == n) return (char *)str;
    }
    return NULL;
}

/* Module-local ANSI string helpers Wine's kernelbase/path.c calls (the Shizuku shlwapi exports the W forms only);
 * not exported. Single-byte code pages only, like the rest of the Shizuku ANSI support. */
char * WINAPI StrChrA(const char *str, WORD ch)
{
    if (!str) return NULL;
    for (; *str; str++) if ((BYTE)*str == ch) return (char *)str;
    return NULL;
}

char * WINAPI StrRChrA(const char *str, const char *end, WORD ch)
{
    const char *found = NULL;
    if (!str) return NULL;
    if (!end) end = str + strlen(str);
    for (; *str && str < end; str++) if ((BYTE)*str == ch) found = str;
    return (char *)found;
}

int WINAPI StrToIntA(const char *str)
{
    int value = 0, neg = 0;
    if (!str) return 0;
    if (*str == '-') { neg = 1; str++; }
    else if (*str == '+') str++;
    for (; *str >= '0' && *str <= '9'; str++) value = value * 10 + (*str - '0');
    return neg ? -value : value;
}

/* FALSE when the characters are equal ignoring case (a comparison result, as documented) */
BOOL WINAPI ChrCmpIW(WCHAR ch1, WCHAR ch2)
{
    return CompareStringW(GetThreadLocale(), NORM_IGNORECASE, &ch1, 1, &ch2, 1) - CSTR_EQUAL;
}

/* #329: "MIME\Database\Content Type\<type>" */
BOOL WINAPI GetMIMETypeSubKeyW(const WCHAR *type, WCHAR *buffer, DWORD len)
{
    static const WCHAR prefix[] = L"MIME\\Database\\Content Type\\";
    DWORD plen = ARRAY_SIZE(prefix) - 1, tlen;
    if (!type || !buffer || len <= plen) return FALSE;
    tlen = lstrlenW(type);
    if (tlen >= len - plen) return FALSE;
    memcpy(buffer, prefix, plen * sizeof(WCHAR));
    memcpy(buffer + plen, type, (tlen + 1) * sizeof(WCHAR));
    return TRUE;
}

HRESULT WINAPI SHStrDupW(const WCHAR *src, WCHAR **dest)
{
    size_t n;
    if (!dest) return E_INVALIDARG;
    *dest = NULL;
    if (!src) return E_INVALIDARG;
    n = (lstrlenW(src) + 1) * sizeof(WCHAR);
    if (!(*dest = CoTaskMemAlloc(n))) return E_OUTOFMEMORY;
    memcpy(*dest, src, n);
    return S_OK;
}
