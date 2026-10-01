/* SPDX-License-Identifier: GPL-2.0-only
 * Controlled loader failures exercise the real API-set wrapper code.
 */
#define SHZ_PATHCCH_WRAPPER_HOST_TEST
#include "../../../kernel32/k32_pathcch.c"
#include <stdio.h>
#include <string.h>
static unsigned checks, frees, calls;
static int mode;
static DWORD last_error;
#define CHECK(condition) do { ++checks; if (!(condition)) { fprintf(stderr, "wrapper failure at %d: %s\n", __LINE__, #condition); return 1; } } while (0)
static HRESULT operation(WCHAR *out, SIZE_T size, const WCHAR *in, DWORD flags)
{ (void)out; (void)size; (void)in; (void)flags; ++calls; return S_FALSE; }
static HMODULE LoadLibraryExW(const WCHAR *name, void *file, DWORD flags)
{ (void)name; (void)file; if (flags != LOAD_LIBRARY_SEARCH_SYSTEM32) return NULL; return mode == 1 ? NULL : (HMODULE)1; }
static FARPROC GetProcAddress(HMODULE module, const char *name)
{ (void)module; if (mode == 2 || strcmp(name, "PathCchCanonicalizeEx")) return NULL; return (FARPROC)(ULONG_PTR)operation; }
static BOOL FreeLibrary(HMODULE module) { (void)module; ++frees; return 1; }
static DWORD GetLastError(void) { return last_error; }
static void SetLastError(DWORD error) { last_error = error; }
int main(void)
{
    WCHAR output[5];
    mode = 1; last_error = 0;
    CHECK(PathCchCanonicalizeEx(output, 5, L"C:\\", 0) == HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND));
    CHECK(last_error == ERROR_MOD_NOT_FOUND && frees == 0 && calls == 0);
    last_error = 5;
    CHECK(PathCchCanonicalizeEx(output, 5, L"C:\\", 0) == HRESULT_FROM_WIN32(5));
    CHECK(last_error == 5 && frees == 0);
    mode = 2; last_error = 0;
    CHECK(PathCchCanonicalizeEx(output, 5, L"C:\\", 0) == HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND));
    CHECK(last_error == ERROR_PROC_NOT_FOUND && frees == 1 && calls == 0);
    last_error = 0;
    CHECK(!PathCchIsRoot(L"C:\\"));
    CHECK(last_error == ERROR_PROC_NOT_FOUND && frees == 2);
    mode = 0; last_error = 0;
    CHECK(PathCchCanonicalizeEx(output, 5, L"C:\\", 0) == S_FALSE);
    CHECK(frees == 3 && calls == 1);
    printf("PathCch wrapper failure checks: %u PASS\n", checks);
    return 0;
}
