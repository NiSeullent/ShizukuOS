/* SPDX-License-Identifier: GPL-2.0-only
 * shell32.dll - the parts of the shell API that do not need a shell, a desktop or a user profile:
 *   CommandLineToArgvW   the documented command-line splitting rules (see below)
 *   SHGetMalloc          the shell's allocator is the COM task allocator (ole32 CoGetMalloc(MEMCTX_TASK))
 *   Set/GetCurrentProcessExplicitAppUserModelID   a per-process string that is stored and read back (there is no taskbar
 *                        that would use it)
 *   SHGetFolderPathW, SHGetSpecialFolderPathW, SHGetKnownFolderPath   only the two folders that really exist here: Windows
 *                        (kernel32 GetWindowsDirectoryW) and System (GetSystemDirectoryW). This system has no per-user
 *                        profile directories, so every other folder (AppData, Documents, Program Files, ...) is reported as
 *                        not found (HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) instead of inventing a path. No ShellExecute*,
 *                        file-info, icon, notification-area or drag-and-drop functions exist either.
 *
 * CommandLineToArgvW rules (MSDN, "Parsing C++ command-line arguments" as applied by shell32): the first argument is the
 * program name, ended by the next quote if it starts with a quote (no escape processing), else by the next blank. Later
 * arguments are separated by blanks/tabs outside quotes; 2n backslashes before a quote give n backslashes and toggle
 * quoting; 2n+1 backslashes before a quote give n backslashes and a literal quote; backslashes not followed by a quote are
 * literal. The one rule MSDN does not spell out for shell32 -- a doubled quote inside a quoted section -- follows the C
 * runtime's (a literal quote, quoting continues). An empty command line yields the path of the
 * current executable as the only argument. The result is one LocalAlloc block (release with LocalFree).
 */
#include "nt.h"
#include <string.h>

extern LPVOID WINAPI CoTaskMemAlloc(SIZE_T);
extern HRESULT WINAPI CoGetMalloc(DWORD, LPVOID *);

static int is_blank(WCHAR c) { return c == ' ' || c == '\t'; }

/* Two-pass parser: with d == NULL it only measures. Returns argc; *chars = characters written incl. NULs. */
static int parse(const WCHAR *s, WCHAR *d, LPWSTR *argv, size_t *chars)
{
    int argc = 1;
    size_t n = 0;
#define EMIT(c) do { if (d) d[n] = (WCHAR)(c); ++n; } while (0)
    while (is_blank(*s)) ++s;
    if (argv) argv[0] = d + n;
    if (*s == '"') {                                          /* the program name ends at the next quote, whatever precedes it */
        ++s;
        while (*s) {
            if (*s == '"') { ++s; break; }
            EMIT(*s);
            ++s;
        }
    } else {
        while (*s && !is_blank(*s)) { EMIT(*s); ++s; }
    }
    EMIT(0);
    for (;;) {
        int in_quotes = 0;
        while (is_blank(*s)) ++s;
        if (!*s) break;
        if (argv) argv[argc] = d + n;
        ++argc;
        for (;;) {                                            /* one argument */
            int copy = 1;
            unsigned bs = 0;
            while (*s == '\\') { ++s; ++bs; }
            if (*s == '"') {
                if ((bs & 1) == 0) {                          /* 2n backslashes: n backslashes, and the quote toggles quoting */
                    if (in_quotes && s[1] == '"') ++s;        /* "" inside a quoted section: one literal quote, still quoted */
                    else { copy = 0; in_quotes = !in_quotes; }
                }                                             /* 2n+1 backslashes: n backslashes and a literal quote */
                bs /= 2;
            }
            while (bs--) EMIT('\\');
            if (!*s || (!in_quotes && is_blank(*s))) break;
            if (copy) EMIT(*s);
            ++s;
        }
        EMIT(0);
    }
#undef EMIT
    *chars = n;
    return argc;
}

DLLAPI LPWSTR *WINAPI CommandLineToArgvW(LPCWSTR cmd, int *numargs)
{
    LPWSTR *argv;
    size_t chars;
    int argc;
    if (!numargs || !cmd) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (!*cmd) {                                              /* documented: an empty string gives the executable's path */
        DWORD cap = MAX_PATH, len;
        for (;;) {
            argv = LocalAlloc(LMEM_FIXED, 2 * sizeof(LPWSTR) + cap * sizeof(WCHAR));
            if (!argv) return 0;
            len = GetModuleFileNameW(0, (LPWSTR)(argv + 2), cap);
            if (!len) { LocalFree(argv); return 0; }
            if (len < cap) break;
            LocalFree(argv);
            cap *= 2;
        }
        argv[0] = (LPWSTR)(argv + 2);
        argv[1] = 0;
        *numargs = 1;
        return argv;
    }
    argc = parse(cmd, 0, 0, &chars);
    argv = LocalAlloc(LMEM_FIXED, ((size_t)argc + 1) * sizeof(LPWSTR) + chars * sizeof(WCHAR));
    if (!argv) return 0;
    parse(cmd, (WCHAR *)(argv + argc + 1), argv, &chars);
    argv[argc] = 0;
    *numargs = argc;
    return argv;
}

/* ---- special folders: only Windows and System exist ---- */
#define CSIDL_WINDOWS_ 0x24
#define CSIDL_SYSTEM_ 0x25
#define CSIDL_FLAG_DONT_VERIFY_ 0x4000
#define HR_NOT_FOUND ((HRESULT)0x80070002)                      /* HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) */

static const GUID FOLDERID_Windows_ = { 0xf38bf404, 0x1d43, 0x42f2, { 0x93, 0x05, 0x67, 0xde, 0x0b, 0x28, 0xfc, 0x23 } };
static const GUID FOLDERID_System_ = { 0x1ac14e77, 0x02e7, 0x4e5d, { 0xb7, 0x44, 0x2e, 0xb1, 0xae, 0x51, 0x98, 0xb7 } };

/* which: 1 = Windows, 2 = System, 0 = anything else */
static HRESULT folder_path(int which, DWORD flags, WCHAR out[MAX_PATH])
{
    UINT n;
    out[0] = 0;
    if (which == 1) n = GetWindowsDirectoryW(out, MAX_PATH);
    else if (which == 2) n = GetSystemDirectoryW(out, MAX_PATH);
    else return HR_NOT_FOUND;
    if (!n || n >= MAX_PATH) { out[0] = 0; return HR_NOT_FOUND; }
    if (!(flags & CSIDL_FLAG_DONT_VERIFY_)) {
        DWORD a = GetFileAttributesW(out);
        if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY)) { out[0] = 0; return HR_NOT_FOUND; }
    }
    return S_OK;
}

DLLAPI HRESULT WINAPI SHGetFolderPathW(HWND hwnd, int csidl, HANDLE token, DWORD flags, LPWSTR path)
{
    int id = csidl & 0xff;
    (void)hwnd; (void)token; (void)flags;
    if (!path) return E_INVALIDARG;
    return folder_path(id == CSIDL_WINDOWS_ ? 1 : id == CSIDL_SYSTEM_ ? 2 : 0, (DWORD)csidl & CSIDL_FLAG_DONT_VERIFY_, path);
}

DLLAPI BOOL WINAPI SHGetSpecialFolderPathW(HWND hwnd, LPWSTR path, int csidl, BOOL create)
{
    (void)create;                                              /* the two supported folders always exist or are reported missing */
    return SUCCEEDED(SHGetFolderPathW(hwnd, csidl, 0, 0, path));
}

DLLAPI HRESULT WINAPI SHGetKnownFolderPath(const GUID *id, DWORD flags, HANDLE token, PWSTR *out)
{
    WCHAR tmp[MAX_PATH], *p;
    HRESULT hr;
    size_t n = 0;
    (void)token;
    if (!out) return E_INVALIDARG;
    *out = 0;
    if (!id) return E_INVALIDARG;
    hr = folder_path(!memcmp(id, &FOLDERID_Windows_, sizeof(GUID)) ? 1 : !memcmp(id, &FOLDERID_System_, sizeof(GUID)) ? 2 : 0, flags, tmp);
    if (FAILED(hr)) return hr;
    while (tmp[n]) ++n;
    p = CoTaskMemAlloc((n + 1) * sizeof(WCHAR));
    if (!p) return E_OUTOFMEMORY;
    memcpy(p, tmp, (n + 1) * sizeof(WCHAR));
    *out = p;                                                  /* released with CoTaskMemFree */
    return S_OK;
}

DLLAPI HRESULT WINAPI SHGetMalloc(LPVOID *out) { return CoGetMalloc(1 /* MEMCTX_TASK */, out); }

/* ---- explicit AppUserModelID ---- */
static WCHAR g_appid[129];
static int g_appid_set;

DLLAPI HRESULT WINAPI SetCurrentProcessExplicitAppUserModelID(PCWSTR id)
{
    size_t n = 0;
    if (!id) return E_INVALIDARG;
    while (id[n] && n < 129) ++n;
    if (!n || n > 128) return E_INVALIDARG;                    /* documented limit: 128 characters */
    memcpy(g_appid, id, (n + 1) * sizeof(WCHAR));
    g_appid_set = 1;
    return S_OK;
}

DLLAPI HRESULT WINAPI GetCurrentProcessExplicitAppUserModelID(PWSTR *out)
{
    size_t n = 0;
    WCHAR *p;
    if (!out) return E_INVALIDARG;
    *out = 0;
    if (!g_appid_set) return E_FAIL;                           /* nothing was set explicitly */
    while (g_appid[n]) ++n;
    p = CoTaskMemAlloc((n + 1) * sizeof(WCHAR));
    if (!p) return E_OUTOFMEMORY;
    memcpy(p, g_appid, (n + 1) * sizeof(WCHAR));
    *out = p;                                                  /* the caller frees it with CoTaskMemFree */
    return S_OK;
}
