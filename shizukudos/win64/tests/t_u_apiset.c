/* SPDX-License-Identifier: GPL-2.0-only
 * API-set contracts that map onto the user-mode system DLLs of this directory (kernel64/ldr.c apiset_schema): loading a
 * contract name must yield the hosting DLL, and a function the DLL really exports must be callable through it. A contract
 * that is not in the schema must still fail (no blind forwarding). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "u_check.h"

typedef HRESULT (WINAPI *create_string_t)(LPCWSTR, UINT32, void **);
typedef HRESULT (WINAPI *delete_string_t)(void *);
typedef DWORD (WINAPI *time_t_)(void);
typedef LPWSTR (WINAPI *find_name_t)(LPCWSTR);
typedef void *(WINAPI *alloc_t)(SIZE_T);
typedef void (WINAPI *free_t)(void *);
typedef DWORD (WINAPI *size_t_)(LPCWSTR, LPDWORD);

static void host_check(const WCHAR *contract, const WCHAR *host, const char *proc, const char *name)
{
    HMODULE c = LoadLibraryW(contract), h = LoadLibraryW(host);
    FARPROC pc = c ? GetProcAddress(c, proc) : 0, ph = h ? GetProcAddress(h, proc) : 0;
    char nm[160];
    snprintf(nm, sizeof nm, "%s resolves to the same %s export as the host DLL", name, proc);
    U_CHECKF(nm, c && h && pc && pc == ph, "c=%p h=%p pc=%p ph=%p", (void *)c, (void *)h, (void *)pc, (void *)ph);
}

int main(void)
{
    HMODULE m;
    DWORD err;

    host_check(L"api-ms-win-core-winrt-string-l1-1-0.dll", L"combase.dll", "WindowsCreateString", "api-ms-win-core-winrt-string-l1-1-0");
    host_check(L"api-ms-win-core-winrt-l1-1-0.dll", L"combase.dll", "RoInitialize", "api-ms-win-core-winrt-l1-1-0");
    host_check(L"api-ms-win-core-com-l1-1-0.dll", L"ole32.dll", "CoInitializeEx", "api-ms-win-core-com-l1-1-0");
    host_check(L"api-ms-win-core-com-l1-1-1.dll", L"ole32.dll", "CoTaskMemAlloc", "api-ms-win-core-com-l1-1-1 (another minor version)");
    host_check(L"api-ms-win-core-shlwapi-legacy-l1-1-0.dll", L"shlwapi.dll", "PathFindFileNameW", "api-ms-win-core-shlwapi-legacy-l1-1-0");
    host_check(L"api-ms-win-core-shlwapi-obsolete-l1-1-0.dll", L"shlwapi.dll", "StrStrIW", "api-ms-win-core-shlwapi-obsolete-l1-1-0");
    host_check(L"api-ms-win-core-version-l1-1-0.dll", L"version.dll", "GetFileVersionInfoSizeW", "api-ms-win-core-version-l1-1-0");
    host_check(L"api-ms-win-mm-time-l1-1-0.dll", L"winmm.dll", "timeGetTime", "api-ms-win-mm-time-l1-1-0");

    /* the functions really work when reached through the contract */
    {
        HMODULE s = LoadLibraryW(L"api-ms-win-core-winrt-string-l1-1-0.dll");
        create_string_t cs = s ? (create_string_t)GetProcAddress(s, "WindowsCreateString") : 0;
        delete_string_t ds = s ? (delete_string_t)GetProcAddress(s, "WindowsDeleteString") : 0;
        void *hs = 0;
        U_CHECK("WindowsCreateString through the winrt-string contract", cs && ds && cs(L"via apiset", 10, &hs) == S_OK && hs && ds(hs) == S_OK);
    }
    {
        HMODULE t = LoadLibraryW(L"api-ms-win-mm-time-l1-1-0.dll");
        time_t_ tg = t ? (time_t_)GetProcAddress(t, "timeGetTime") : 0;
        DWORD a = tg ? tg() : 0, b;
        Sleep(20);
        b = tg ? tg() : 0;
        U_CHECK("timeGetTime through the mm-time contract advances", tg && (DWORD)(b - a) >= 20 && (DWORD)(b - a) < 1000);
    }
    {
        HMODULE l = LoadLibraryW(L"api-ms-win-core-shlwapi-legacy-l1-1-0.dll");
        find_name_t f = l ? (find_name_t)GetProcAddress(l, "PathFindFileNameW") : 0;
        static const WCHAR p[] = L"C:\\a\\b.txt";
        U_CHECK("PathFindFileNameW through the shlwapi-legacy contract", f && f(p) == p + 5);
    }
    {
        HMODULE c = LoadLibraryW(L"api-ms-win-core-com-l1-1-0.dll");
        alloc_t a = c ? (alloc_t)GetProcAddress(c, "CoTaskMemAlloc") : 0;
        free_t fr = c ? (free_t)GetProcAddress(c, "CoTaskMemFree") : 0;
        void *p = a ? a(32) : 0;
        U_CHECK("CoTaskMemAlloc/Free through the com contract", p && fr && (fr(p), 1));
        U_CHECK("a com-contract function ole32 does not implement is not found (no fake export)", c && GetProcAddress(c, "CoCreateInstance") == 0);
    }
    {
        HMODULE v = LoadLibraryW(L"api-ms-win-core-version-l1-1-0.dll");
        size_t_ f = v ? (size_t_)GetProcAddress(v, "GetFileVersionInfoSizeW") : 0;
        U_CHECK("GetFileVersionInfoSizeW through the version contract (every built image carries a version resource)", f && f(L"C:\\SHZ\\TESTS\\T_U_APISET.EXE", 0) > 0 &&
                f(L"C:\\SHZ\\TESTS\\NO_SUCH.EXE", 0) == 0 && GetLastError() == ERROR_FILE_NOT_FOUND);
    }

    SetLastError(0);
    m = LoadLibraryW(L"api-ms-win-core-nonexistent-l1-1-0.dll");
    err = GetLastError();
    U_CHECKF("an unknown contract still fails to load", m == 0 && err != 0, "m=%p err=%u", (void *)m, (unsigned)err);
    return u_finish("t_u_apiset");
}
