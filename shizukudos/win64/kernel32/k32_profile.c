/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: initialization files (GetPrivateProfileStringW). The file is read whole on every call (as Windows re-reads a
 * changed file) and parsed by ini_core.c (host-tested: tests/host/ini_host_test.c). Encoding: UTF-16LE with a byte-order mark,
 * otherwise the ANSI code page (UTF-8 here), an UTF-8 byte-order mark is skipped. A file name without a path lives in the Windows
 * directory, as documented.
 */
#include "k32.h"
#include "ini_core.h"

#define INI_MAX_BYTES (1u << 20)

/* Reads `path` into a freshly allocated UTF-16 buffer; returns it (caller frees) or 0 with GetLastError set. */
static WCHAR *read_text(LPCWSTR path, unsigned *chars)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, 0, 0);
    LARGE_INTEGER size;
    BYTE *raw;
    WCHAR *w;
    DWORD got = 0;
    int n;
    if (h == INVALID_HANDLE_VALUE) return 0;
    if (!GetFileSizeEx(h, &size) || size.QuadPart > INI_MAX_BYTES) { CloseHandle(h); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    raw = RtlAllocateHeap(ShzProcessHeap(), 0, (SIZE_T)size.QuadPart + 2);
    w = RtlAllocateHeap(ShzProcessHeap(), 0, ((SIZE_T)size.QuadPart + 2) * sizeof(WCHAR));
    if (!raw || !w || !ReadFile(h, raw, (DWORD)size.QuadPart, &got, 0)) {
        CloseHandle(h);
        if (raw) RtlFreeHeap(ShzProcessHeap(), 0, raw);
        if (w) RtlFreeHeap(ShzProcessHeap(), 0, w);
        shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    CloseHandle(h);
    if (got >= 2 && raw[0] == 0xff && raw[1] == 0xfe) {  /* UTF-16LE */
        n = (int)(got - 2) / 2;
        memcpy(w, raw + 2, (size_t)n * sizeof(WCHAR));
    } else {
        const BYTE *p = raw;
        DWORD len = got;
        if (len >= 3 && p[0] == 0xef && p[1] == 0xbb && p[2] == 0xbf) { p += 3; len -= 3; }
        n = len ? MultiByteToWideChar(CP_UTF8, 0, (LPCCH)p, (int)len, w, (int)len + 1) : 0;
    }
    RtlFreeHeap(ShzProcessHeap(), 0, raw);
    *chars = (unsigned)n;
    return w;
}

K32API DWORD WINAPI GetPrivateProfileStringW(LPCWSTR app, LPCWSTR key, LPCWSTR def, LPWSTR out, DWORD size, LPCWSTR file)
{
    static const WCHAR winini[] = { 'w', 'i', 'n', '.', 'i', 'n', 'i', 0 };
    WCHAR path[MAX_PATH];
    const WCHAR *f = file ? file : winini, *p;
    WCHAR *text;
    unsigned chars = 0;
    int found = 0;
    DWORD r;
    if (!out || !size) return 0;
    for (p = f; *p && *p != '\\' && *p != '/' && *p != ':'; ++p) { }
    if (!*p) {                                            /* no path: the Windows directory */
        UINT n = GetWindowsDirectoryW(path, MAX_PATH);
        size_t fl = k32_wlen(f);
        if (!n || n + 1 + fl >= MAX_PATH) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); out[0] = 0; return 0; }
        path[n] = '\\';
        memcpy(path + n + 1, f, (fl + 1) * sizeof(WCHAR));
        f = path;
    }
    text = read_text(f, &chars);
    r = ini_get_string((const ini_w *)(text ? text : (WCHAR *)L""), text ? chars : 0, (const ini_w *)app, (const ini_w *)key,
                       (const ini_w *)def, (ini_w *)out, size, &found);
    if (text) RtlFreeHeap(ShzProcessHeap(), 0, text);
    shz_set_last_error(found ? 0 : ERROR_FILE_NOT_FOUND);  /* documented: a missing file, section or key reports ERROR_FILE_NOT_FOUND */
    return r;
}
