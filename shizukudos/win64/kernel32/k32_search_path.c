/* SPDX-License-Identifier: GPL-2.0-only
 * Generic Win32 SearchPath and process search policy. This does not change
 * LoadLibrary policy, write the registry, or select an application by name.
 * Microsoft SetSearchPathMode/SearchPath contracts; permanent-mode edge
 * cases are also independently exercised by Wine's kernel32 path tests.
 */
#ifdef SHZ_SEARCH_PATH_HOST_TEST
#include "../tests/search_path_host.h"
#else
#include "k32.h"
#include "../include/ntreg.h"
#endif

/* Zero means read the actual registry. Other states are process-local,
 * protected by one atomic transition, including irreversible permanence. */
static LONG process_search_mode;
#define SEARCH_SAFE 1
#define SEARCH_UNSAFE 2
#define SEARCH_PERMANENT 3

K32API BOOL WINAPI SetSearchPathMode(DWORD flags)
{
    LONG before, after;
    if (flags != 1 && flags != 0x10000 && flags != 0x8001) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    after = flags == 0x8001 ? SEARCH_PERMANENT : flags == 1 ? SEARCH_SAFE : SEARCH_UNSAFE;
    for (;;) {
        before = __atomic_load_n(&process_search_mode, __ATOMIC_ACQUIRE);
        if (before == SEARCH_PERMANENT) {
            if (after == SEARCH_PERMANENT) return TRUE;
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        if (__atomic_compare_exchange_n(&process_search_mode, &before, after, FALSE,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return TRUE;
    }
}

static BOOL registry_safe_search(void)
{
    static const WCHAR key[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager";
    static const WCHAR value[] = L"SafeProcessSearchMode";
    SHZ_UNICODE_STRING name;
    SHZ_OBJECT_ATTRIBUTES attrs;
    struct { ULONG TitleIndex, Type, DataLength; DWORD Data; } result;
    HANDLE handle;
    ULONG length = 0;
    NTSTATUS status;
    BOOL safe = FALSE; /* Documented system default when the value is absent. */
    name.Buffer = (WCHAR *)key;
    name.Length = sizeof key - sizeof(WCHAR);
    name.MaximumLength = sizeof key;
    memset(&attrs, 0, sizeof attrs);
    attrs.Length = sizeof attrs;
    attrs.ObjectName = &name;
    attrs.Attributes = 0x40; /* OBJ_CASE_INSENSITIVE */
    status = NtOpenKey(&handle, 1 /* KEY_QUERY_VALUE */, &attrs);
    if (!NT_SUCCESS(status)) return FALSE;
    name.Buffer = (WCHAR *)value;
    name.Length = sizeof value - sizeof(WCHAR);
    name.MaximumLength = sizeof value;
    memset(&result, 0, sizeof result);
    status = NtQueryValueKey(handle, &name, SHZ_KeyValuePartialInformation, &result, sizeof result, &length);
    if (NT_SUCCESS(status) && length == sizeof result && result.Type == 4 /* REG_DWORD */ &&
        result.DataLength == sizeof(DWORD)) safe = result.Data != 0;
    NtClose(handle);
    return safe;
}

static BOOL safe_search(void)
{
    LONG mode = __atomic_load_n(&process_search_mode, __ATOMIC_ACQUIRE);
    BOOL safe;
    if (mode) return mode != SEARCH_UNSAFE;
    safe = registry_safe_search();
    /* A successful concurrent SetSearchPathMode overrides the registry. */
    mode = __atomic_load_n(&process_search_mode, __ATOMIC_ACQUIRE);
    return mode ? mode != SEARCH_UNSAFE : safe;
}

#define SEARCH_CAP (MAX_PATH * 2)
static BOOL candidate(const WCHAR *dir, size_t dlen, const WCHAR *name, const WCHAR *ext,
                       WCHAR *out, DWORD cap, DWORD *need, WCHAR **filepart)
{
    WCHAR buf[SEARCH_CAP];
    size_t n = dlen, names = k32_wlen(name), extras = ext ? k32_wlen(ext) : 0;
    BOOL slash = dlen && dir[dlen - 1] != '\\' && dir[dlen - 1] != '/';
    DWORD attr;
    if (dlen >= SEARCH_CAP || names >= SEARCH_CAP || extras >= SEARCH_CAP ||
        dlen + names + extras + slash >= SEARCH_CAP) {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }
    memcpy(buf, dir, dlen * sizeof(WCHAR));
    if (slash) buf[n++] = '\\';
    memcpy(buf + n, name, names * sizeof(WCHAR)); n += names;
    if (extras) { memcpy(buf + n, ext, extras * sizeof(WCHAR)); n += extras; }
    buf[n] = 0;
    attr = GetFileAttributesW(buf);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) return FALSE;
    *need = GetFullPathNameW(buf, cap, out, filepart);
    return *need != 0;
}

K32API DWORD WINAPI SearchPathW(LPCWSTR path, LPCWSTR name, LPCWSTR ext, DWORD cap, LPWSTR out, LPWSTR *filepart)
{
    WCHAR dirs[4][MAX_PATH] = {{0}}, env[2048];
    const WCHAR *use_ext = NULL, *p;
    DWORD need = 0, n, i, order[4] = {0, 1, 2, 3};
    if (!name || !*name || (cap && !out)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    for (p = name; *p; ++p) { }
    while (p > name && p[-1] != '.' && p[-1] != '\\' && p[-1] != '/') --p;
    if (!(p > name && p[-1] == '.')) use_ext = ext;
    for (p = name; *p; ++p) if (*p == '\\' || *p == '/' || *p == ':') break;
    if (*p) {
        if (candidate(L"", 0, name, use_ext, out, cap, &need, filepart)) return need;
        SetLastError(ERROR_FILE_NOT_FOUND); return 0;
    }
    if (path) {
        const WCHAR *s = path;
        while (*s) {
            const WCHAR *e = s;
            while (*e && *e != ';') ++e;
            if (e > s && candidate(s, e - s, name, use_ext, out, cap, &need, filepart)) return need;
            s = *e ? e + 1 : e;
        }
        SetLastError(ERROR_FILE_NOT_FOUND); return 0;
    }
    n = GetModuleFileNameW(NULL, dirs[0], MAX_PATH);
    if (n >= MAX_PATH) dirs[0][0] = 0;
    else {
        while (n && dirs[0][n - 1] != '\\' && dirs[0][n - 1] != '/') --n;
        dirs[0][n] = 0;
    }
    if (GetSystemDirectoryW(dirs[1], MAX_PATH) >= MAX_PATH) dirs[1][0] = 0;
    if (GetWindowsDirectoryW(dirs[2], MAX_PATH) >= MAX_PATH) dirs[2][0] = 0;
    if (GetCurrentDirectoryW(MAX_PATH, dirs[3]) >= MAX_PATH) dirs[3][0] = 0;
    if (!safe_search()) { order[1] = 3; order[2] = 1; order[3] = 2; }
    for (i = 0; i < 4; ++i) {
        const WCHAR *dir = dirs[order[i]];
        if (*dir && candidate(dir, k32_wlen(dir), name, use_ext, out, cap, &need, filepart)) return need;
    }
    n = GetEnvironmentVariableW(L"PATH", env, ARRAYSIZE(env));
    if (n >= ARRAYSIZE(env)) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return 0; }
    if (n) return SearchPathW(env, name, ext, cap, out, filepart);
    SetLastError(ERROR_FILE_NOT_FOUND); return 0;
}

K32API DWORD WINAPI SearchPathA(LPCSTR path, LPCSTR name, LPCSTR ext, DWORD cap, LPSTR out, LPSTR *filepart)
{
    WCHAR wpath[2048], wname[SEARCH_CAP], wext[SEARCH_CAP], wout[SEARCH_CAP];
    DWORD r;
    int bytes;
    if (!name || (cap && !out)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if ((path && !MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, ARRAYSIZE(wpath))) ||
        !MultiByteToWideChar(CP_ACP, 0, name, -1, wname, ARRAYSIZE(wname)) ||
        (ext && !MultiByteToWideChar(CP_ACP, 0, ext, -1, wext, ARRAYSIZE(wext)))) return 0;
    r = SearchPathW(path ? wpath : NULL, wname, ext ? wext : NULL, ARRAYSIZE(wout), wout, NULL);
    if (!r) return 0;
    if (r >= ARRAYSIZE(wout)) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return 0; }
    bytes = WideCharToMultiByte(CP_ACP, 0, wout, -1, NULL, 0, NULL, NULL);
    if (!bytes) return 0;
    if (!out || (DWORD)bytes > cap) return (DWORD)bytes;
    if (!WideCharToMultiByte(CP_ACP, 0, wout, -1, out, cap, NULL, NULL)) return 0;
    if (filepart) {
        char *s = out, *last = NULL;
        for (; *s; ++s) if (*s == '\\' || *s == '/') last = s;
        *filepart = last ? last + 1 : out;
    }
    return (DWORD)bytes - 1;
}
