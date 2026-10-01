/* SPDX-License-Identifier: GPL-2.0-only
 * Original registry-backed IMM32 metadata implementation.
 *
 * The actual Chromium157 rev1708403 chrome.dll delay-imports just
 * ImmGetIMEFileNameW. Microsoft documents layout metadata under HKLM's
 * System\\CurrentControlSet\\Control\\Keyboard Layouts\\HKL. Reviewed Wine11
 * db11d0fe6a169c457e23d007e20404643d067aa8 dlls/imm32/imm.c uses the
 * low32-bit HKL key and the "Ime File" / "Layout Text" REG_SZ values.
 * No upstream code is copied.
 *
 * These queries read real catalog metadata; they do not load an IME, select
 * a keyboard layout, or create/associate/destroy a window's input context.
 * The existing user32 keyboard backend supports the actual US layout only.
 * Composition, IME mode/capability and context APIs are absent rather than
 * reporting fabricated active input engines or successful transformations.
 *
 * Registry strings up to32768 UTF16 units are supported. Callers own their
 * declared output extents; cap includes room for the terminating NUL. Query
 * mode (NULL output or cap0) reports length excluding NUL. Truncation returns
 * the actual number copied, matching the reviewed Wine metadata API.
 */
#ifndef SHZ_IMM32_HOST_TEST
#include "nt.h"
#include <winreg.h>
#include <winnls.h>
#endif

enum { IMM_METADATA_MAX_BYTES = 65536, IMM_METADATA_RETRIES = 4 };

static void layout_path(HKL layout, WCHAR path[80])
{
    static const WCHAR prefix[] = L"System\\CurrentControlSet\\Control\\Keyboard Layouts\\";
    static const WCHAR hex[] = L"0123456789abcdef";
    DWORD id = (DWORD)(ULONG_PTR)layout;
    unsigned n = 0, i;
    while (prefix[n]) { path[n] = prefix[n]; ++n; }
    for (i = 0; i < 8; ++i) path[n + i] = hex[(id >> (28 - i * 4)) & 15];
    path[n + 8] = 0;
}

static WCHAR *layout_string(HKL layout, const WCHAR *value, UINT *length)
{
    WCHAR path[80], *text = NULL;
    HKEY key = NULL;
    DWORD type, bytes, capacity;
    LONG status;
    unsigned retry;
    layout_path(layout, path);
    *length = 0;
    status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE, &key);
    if (status != ERROR_SUCCESS) return NULL;
    for (retry = 0; retry < IMM_METADATA_RETRIES; ++retry) {
        bytes = 0; type = 0;
        status = RegQueryValueExW(key, value, NULL, &type, NULL, &bytes);
        if (status == ERROR_FILE_NOT_FOUND) {
            text = HeapAlloc(GetProcessHeap(), 0, sizeof(WCHAR));
            if (text) text[0] = 0;
            else status = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }
        if (status != ERROR_SUCCESS) break;
        if (type != REG_SZ || (bytes & 1)) { status = ERROR_INVALID_DATA; break; }
        if (bytes > IMM_METADATA_MAX_BYTES) { status = ERROR_NOT_SUPPORTED; break; }
        capacity = bytes;
        text = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)capacity + sizeof(WCHAR));
        if (!text) { status = ERROR_NOT_ENOUGH_MEMORY; break; }
        status = RegQueryValueExW(key, value, NULL, &type, (BYTE *)text, &bytes);
        if (status == ERROR_MORE_DATA) {
            HeapFree(GetProcessHeap(), 0, text); text = NULL;
            continue;
        }
        if (status != ERROR_SUCCESS || type != REG_SZ || (bytes & 1) || bytes > capacity) {
            if (status == ERROR_SUCCESS) status = ERROR_INVALID_DATA;
            HeapFree(GetProcessHeap(), 0, text); text = NULL;
            break;
        }
        /* RegQueryValueEx does not promise that a REG_SZ has a terminator. */
        text[bytes / sizeof(WCHAR)] = 0;
        while (text[*length]) ++*length;
        break;
    }
    RegCloseKey(key);
    if (!text && status != ERROR_FILE_NOT_FOUND) SetLastError((DWORD)status);
    return text;
}

static UINT metadata_w(HKL layout, const WCHAR *value, WCHAR *output, UINT cap)
{
    UINT length, copied;
    WCHAR *text = layout_string(layout, value, &length);
    if (!text) return 0;
    copied = length;
    if (output && cap) {
        UINT i;
        if (copied >= cap) copied = cap - 1;
        for (i = 0; i < copied; ++i) output[i] = text[i];
        output[copied] = 0;
    }
    HeapFree(GetProcessHeap(), 0, text);
    return copied;
}

static UINT metadata_a(HKL layout, const WCHAR *value, char *output, UINT cap)
{
    UINT length, copied;
    WCHAR *text = layout_string(layout, value, &length);
    char *bytes;
    int count;
    DWORD error;
    if (!text) return 0;
    (void)length;
    count = WideCharToMultiByte(CP_ACP, 0, text, -1, NULL, 0, NULL, NULL);
    if (count <= 0) {
        error = GetLastError(); HeapFree(GetProcessHeap(), 0, text); SetLastError(error);
        return 0;
    }
    copied = (UINT)count - 1;
    if (!output || !cap) { HeapFree(GetProcessHeap(), 0, text); return copied; }
    bytes = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)count);
    if (!bytes) { HeapFree(GetProcessHeap(), 0, text); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    if (!WideCharToMultiByte(CP_ACP, 0, text, -1, bytes, count, NULL, NULL)) {
        error = GetLastError(); HeapFree(GetProcessHeap(), 0, bytes); HeapFree(GetProcessHeap(), 0, text); SetLastError(error);
        return 0;
    }
    if (copied >= cap) copied = cap - 1;
    { UINT i; for (i = 0; i < copied; ++i) output[i] = bytes[i]; }
    output[copied] = 0;
    HeapFree(GetProcessHeap(), 0, bytes); HeapFree(GetProcessHeap(), 0, text);
    return copied;
}

DLLAPI UINT WINAPI ImmGetIMEFileNameW(HKL layout, LPWSTR output, UINT cap)
{
    return metadata_w(layout, L"Ime File", output, cap);
}
DLLAPI UINT WINAPI ImmGetIMEFileNameA(HKL layout, LPSTR output, UINT cap)
{
    return metadata_a(layout, L"Ime File", output, cap);
}
DLLAPI UINT WINAPI ImmGetDescriptionW(HKL layout, LPWSTR output, UINT cap)
{
    return metadata_w(layout, L"Layout Text", output, cap);
}
DLLAPI UINT WINAPI ImmGetDescriptionA(HKL layout, LPSTR output, UINT cap)
{
    return metadata_a(layout, L"Layout Text", output, cap);
}
