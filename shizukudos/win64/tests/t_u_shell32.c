/* SPDX-License-Identifier: GPL-2.0-only
 * shell32.dll: CommandLineToArgvW, SHGetMalloc, the explicit AppUserModelID pair. Expected values: the backslash/quote rules
 * MSDN documents for CommandLineToArgvW (2n backslashes + quote, 2n+1 backslashes + quote, n backslashes), the program-name
 * rule, the empty-command-line rule ("the path of the current executable") and the rows of the "Parsing C++ command-line
 * arguments" table. The one rule shell32 does not document (a doubled quote inside quotes) follows the C runtime and is
 * asserted only as that convention. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <objbase.h>
#include "u_check.h"

/* declared by shlobj.h / shobjidl.h in the SDK; declared here to keep the freestanding build free of those headers */
HRESULT WINAPI SHGetMalloc(IMalloc **);
HRESULT WINAPI SetCurrentProcessExplicitAppUserModelID(PCWSTR);
HRESULT WINAPI GetCurrentProcessExplicitAppUserModelID(PWSTR *);
HRESULT WINAPI SHGetFolderPathW(HWND, int, HANDLE, DWORD, LPWSTR);
BOOL WINAPI SHGetSpecialFolderPathW(HWND, LPWSTR, int, BOOL);
HRESULT WINAPI SHGetKnownFolderPath(const GUID *, DWORD, HANDLE, PWSTR *);
static const GUID FID_Windows = { 0xf38bf404, 0x1d43, 0x42f2, { 0x93, 0x05, 0x67, 0xde, 0x0b, 0x28, 0xfc, 0x23 } };
static const GUID FID_System = { 0x1ac14e77, 0x02e7, 0x4e5d, { 0xb7, 0x44, 0x2e, 0xb1, 0xae, 0x51, 0x98, 0xb7 } };
static const GUID FID_RoamingAppData = { 0x3eb685db, 0x65f9, 0x4cf6, { 0xa0, 0x3a, 0xe3, 0xef, 0x65, 0x72, 0x9f, 0x3d } };

static int argv_is(LPWSTR *argv, int argc, int n, const WCHAR *const *expect)
{
    int i;
    if (!argv || argc != n) return 0;
    for (i = 0; i < n; ++i)
        if (!u_wide_eq((const unsigned short *)argv[i], (const unsigned short *)expect[i])) return 0;
    return argv[n] == 0;
}

#define CASE(name, cmd, ...) do { \
    static const WCHAR *const e_[] = { __VA_ARGS__ }; \
    int argc_ = -1; LPWSTR *av_ = CommandLineToArgvW(cmd, &argc_); \
    U_CHECKF(name, argv_is(av_, argc_, (int)(sizeof e_ / sizeof e_[0]), e_), "argc=%d", argc_); \
    if (av_) LocalFree(av_); } while (0)

int main(void)
{
    CASE("plain arguments", L"prog.exe a b c", L"prog.exe", L"a", L"b", L"c");
    CASE("MSDN row 1:  p \"abc\" d e", L"p \"abc\" d e", L"p", L"abc", L"d", L"e");
    CASE("MSDN row 2:  p a\\\\\\b d\"e f\"g h", L"p a\\\\\\b d\"e f\"g h", L"p", L"a\\\\\\b", L"de fg", L"h");
    CASE("MSDN row 3:  p a\\\\\\\"b c d", L"p a\\\\\\\"b c d", L"p", L"a\\\"b", L"c", L"d");
    CASE("MSDN row 4:  p a\\\\\\\\\"b c\" d e", L"p a\\\\\\\\\"b c\" d e", L"p", L"a\\\\b c", L"d", L"e");
    CASE("consecutive-quote rule (C runtime convention): p a\"b\"\" c d", L"p a\"b\"\" c d", L"p", L"ab\" c d");
    CASE("a doubled quote inside quotes is one literal quote: p \"a \"\"b\"\" c\"", L"p \"a \"\"b\"\" c\"", L"p", L"a \"b\" c");
    CASE("quoted program name with spaces loses its quotes", L"\"C:\\Program Files\\app.exe\" arg1 \"arg two\" arg3", L"C:\\Program Files\\app.exe", L"arg1", L"arg two", L"arg3");
    CASE("the program name ends at the next quote, backslashes are not special there", L"\"C:\\dir\\\\\" x", L"C:\\dir\\\\", L"x");
    CASE("unquoted program name up to the first blank", L"C:\\dir\\prog.exe x", L"C:\\dir\\prog.exe", L"x");
    CASE("program name only", L"prog.exe", L"prog.exe");
    CASE("tabs separate arguments", L"p\ta\tb", L"p", L"a", L"b");
    CASE("runs of blanks separate arguments", L"p    a  \t  b", L"p", L"a", L"b");
    CASE("trailing blanks do not add an argument", L"p a   ", L"p", L"a");
    CASE("an empty quoted argument is an argument", L"p \"\" b", L"p", L"", L"b");
    CASE("a quoted argument keeps its blanks", L"p \"a b\" c", L"p", L"a b", L"c");
    CASE("backslashes not followed by a quote are literal", L"p C:\\dir\\file.txt", L"p", L"C:\\dir\\file.txt");
    CASE("2 backslashes before the closing quote give 1 and close", L"p \"C:\\dir\\\\\" y", L"p", L"C:\\dir\\", L"y");
    CASE("1 backslash before a quote gives a literal quote", L"p \\\"x\\\"", L"p", L"\"x\"");
    CASE("3 backslashes before a quote: 1 backslash and a literal quote", L"p \\\\\\\"", L"p", L"\\\"");
    CASE("an unterminated quote runs to the end", L"p \"abc def", L"p", L"abc def");
    CASE("blank inside quotes then more text", L"p x\"y z\"w", L"p", L"xy zw");

    {
        int n = -1;
        LPWSTR *av = CommandLineToArgvW(L"", &n);
        WCHAR path[MAX_PATH];
        DWORD len = GetModuleFileNameW(0, path, MAX_PATH);
        U_CHECK("empty command line: one argument, the executable's path", av && n == 1 && len && u_wide_eq((const unsigned short *)av[0], (const unsigned short *)path) && av[1] == 0);
        if (av) LocalFree(av);
        SetLastError(0);
        av = CommandLineToArgvW(L"a b", 0);
        U_CHECK("NULL numargs fails with ERROR_INVALID_PARAMETER", av == 0 && GetLastError() == ERROR_INVALID_PARAMETER);
    }
    {
        WCHAR big[4096];
        int i, n = -1, ok = 1, pos = 0;
        LPWSTR *av;
        big[pos++] = 'p';
        for (i = 0; i < 300; ++i) {
            big[pos++] = ' ';
            big[pos++] = (WCHAR)('a' + i % 26);
            big[pos++] = (WCHAR)('0' + i % 10);
        }
        big[pos] = 0;
        av = CommandLineToArgvW(big, &n);
        for (i = 0; av && i < 300; ++i)
            if (av[i + 1][0] != (WCHAR)('a' + i % 26) || av[i + 1][1] != (WCHAR)('0' + i % 10) || av[i + 1][2]) ok = 0;
        U_CHECKF("301 arguments (program + 300)", av && n == 301 && ok && av[301] == 0, "n=%d", n);
        if (av) LocalFree(av);
    }
    {
        IMalloc *a = 0, *b = 0;
        void *p;
        U_CHECK("SHGetMalloc returns an IMalloc", SHGetMalloc(&a) == S_OK && a);
        U_CHECK("it is the COM task allocator (same object as CoGetMalloc)", CoGetMalloc(MEMCTX_TASK, &b) == S_OK && a == b);
        p = a->lpVtbl->Alloc(a, 64);
        U_CHECK("its allocations are CoTaskMem blocks", p && (CoTaskMemFree(p), 1));
    }
    {
        PWSTR id = (PWSTR)1;
        WCHAR long128[129], long129[130];
        int i;
        U_CHECK("GetCurrentProcessExplicitAppUserModelID before any Set fails and clears the output", GetCurrentProcessExplicitAppUserModelID(&id) == E_FAIL && id == 0);
        U_CHECK("Set(NULL) is E_INVALIDARG", SetCurrentProcessExplicitAppUserModelID(0) == E_INVALIDARG);
        U_CHECK("Set(\"Shizuku.Test.App\") succeeds", SetCurrentProcessExplicitAppUserModelID(L"Shizuku.Test.App") == S_OK);
        U_CHECK("Get returns the stored string (CoTaskMem block)", GetCurrentProcessExplicitAppUserModelID(&id) == S_OK && id && u_wide_eq((const unsigned short *)id, (const unsigned short *)L"Shizuku.Test.App"));
        CoTaskMemFree(id);
        for (i = 0; i < 128; ++i) long128[i] = 'x';
        long128[128] = 0;
        for (i = 0; i < 129; ++i) long129[i] = 'y';
        long129[129] = 0;
        U_CHECK("an ID of 129 characters is rejected and the old one is kept", SetCurrentProcessExplicitAppUserModelID(long129) == E_INVALIDARG &&
                GetCurrentProcessExplicitAppUserModelID(&id) == S_OK && u_wide_eq((const unsigned short *)id, (const unsigned short *)L"Shizuku.Test.App"));
        CoTaskMemFree(id);
        U_CHECK("an ID of 128 characters is accepted", SetCurrentProcessExplicitAppUserModelID(long128) == S_OK && GetCurrentProcessExplicitAppUserModelID(&id) == S_OK &&
                u_wide_eq((const unsigned short *)id, (const unsigned short *)long128));
        CoTaskMemFree(id);
        U_CHECK("Get(NULL) is E_INVALIDARG", GetCurrentProcessExplicitAppUserModelID(0) == E_INVALIDARG);
    }
    /* ---- special folders: only the ones that exist ---- */
    {
        WCHAR a[MAX_PATH], b[MAX_PATH];
        PWSTR k = 0;
        HRESULT hr;
        GetWindowsDirectoryW(a, MAX_PATH);
        memset(b, 0xcc, sizeof b);
        hr = SHGetFolderPathW(0, 0x24 /* CSIDL_WINDOWS */, 0, 0, b);
        U_CHECKF("SHGetFolderPathW(CSIDL_WINDOWS) is the kernel32 Windows directory", hr == S_OK && u_wide_eq((const unsigned short *)a, (const unsigned short *)b), "hr=%x", (unsigned)hr);
        U_CHECK("...and that directory really exists", GetFileAttributesW(b) != INVALID_FILE_ATTRIBUTES && (GetFileAttributesW(b) & FILE_ATTRIBUTE_DIRECTORY));
        GetSystemDirectoryW(a, MAX_PATH);
        hr = SHGetFolderPathW(0, 0x25 /* CSIDL_SYSTEM */ | 0x8000 /* CSIDL_FLAG_CREATE */, 0, 0, b);
        U_CHECK("SHGetFolderPathW(CSIDL_SYSTEM | CSIDL_FLAG_CREATE) is the System directory", hr == S_OK && u_wide_eq((const unsigned short *)a, (const unsigned short *)b));
        memset(b, 0xcc, sizeof b);
        hr = SHGetFolderPathW(0, 0x1a /* CSIDL_APPDATA */, 0, 0, b);
        U_CHECK("CSIDL_APPDATA does not exist here: HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) and an empty path", hr == (HRESULT)0x80070002 && b[0] == 0);
        U_CHECK("SHGetFolderPathW(NULL buffer) is E_INVALIDARG", SHGetFolderPathW(0, 0x24, 0, 0, 0) == E_INVALIDARG);
        U_CHECK("SHGetSpecialFolderPathW(CSIDL_WINDOWS) is TRUE", SHGetSpecialFolderPathW(0, b, 0x24, FALSE) && GetWindowsDirectoryW(a, MAX_PATH) && u_wide_eq((const unsigned short *)a, (const unsigned short *)b));
        U_CHECK("SHGetSpecialFolderPathW(CSIDL_PROFILE) is FALSE", !SHGetSpecialFolderPathW(0, b, 0x28, FALSE));
        hr = SHGetKnownFolderPath(&FID_Windows, 0, 0, &k);
        GetWindowsDirectoryW(a, MAX_PATH);
        U_CHECK("SHGetKnownFolderPath(FOLDERID_Windows) is the Windows directory (CoTaskMem string)", hr == S_OK && k && u_wide_eq((const unsigned short *)a, (const unsigned short *)k));
        CoTaskMemFree(k);
        k = 0;
        hr = SHGetKnownFolderPath(&FID_System, 0, 0, &k);
        GetSystemDirectoryW(a, MAX_PATH);
        U_CHECK("SHGetKnownFolderPath(FOLDERID_System) is the System directory", hr == S_OK && k && u_wide_eq((const unsigned short *)a, (const unsigned short *)k));
        CoTaskMemFree(k);
        k = (PWSTR)1;
        hr = SHGetKnownFolderPath(&FID_RoamingAppData, 0, 0, &k);
        U_CHECK("FOLDERID_RoamingAppData does not exist here: failure HRESULT and a NULL output", FAILED(hr) && k == 0);
        U_CHECK("SHGetKnownFolderPath(NULL id) / (NULL output) is E_INVALIDARG", SHGetKnownFolderPath(0, 0, 0, &k) == E_INVALIDARG && SHGetKnownFolderPath(&FID_Windows, 0, 0, 0) == E_INVALIDARG);
    }
    return u_finish("t_u_shell32");
}
