/* SPDX-License-Identifier: GPL-2.0-only
 * shell32.dll - the parts of the shell API that do not need a shell, a desktop or a user profile:
 *   CommandLineToArgvW   the documented command-line splitting rules (see below)
 *   SHGetMalloc          the shell's allocator is the COM task allocator (ole32 CoGetMalloc(MEMCTX_TASK))
 *   Set/GetCurrentProcessExplicitAppUserModelID   a per-process string that is stored and read back (there is no taskbar
 *                        that would use it)
 * There are no known-folder functions (SHGetFolderPath*, SHGetKnownFolderPath): this system has no per-user profile
 * directories, and inventing paths would only make programs fail later. No ShellExecute*, file-info, icon, notification
 * area or drag-and-drop functions exist either.
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
