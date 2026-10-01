/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise the actual PathCch DLL and API-set host delegation in Kernel64.
 */
#include "nt.h"
#include "shzcrt.h"
#include "../dlls/pathcch/pathcch_compat.h"

typedef HRESULT (WINAPI *canonical_fn)(WCHAR *, SIZE_T, const WCHAR *, DWORD);
typedef HRESULT (WINAPI *alloc_fn)(const WCHAR *, DWORD, WCHAR **);
typedef HRESULT (WINAPI *combine_fn)(WCHAR *, SIZE_T, const WCHAR *, const WCHAR *, DWORD);
typedef HRESULT (WINAPI *remove_fn)(WCHAR *, SIZE_T, WCHAR **, SIZE_T *);
static unsigned checks, failures;
#define CHECK(condition, name) do { ++checks; if (!(condition)) { ++failures; printf("[FAIL] %s\n", name); } } while (0)
static BOOL equal(const WCHAR *a, const WCHAR *b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }

int main(void)
{
    HMODULE direct = LoadLibraryExW(L"pathcch.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    HMODULE host = LoadLibraryW(L"api-ms-win-core-path-l1-1-0.dll");
    canonical_fn canonical;
    alloc_fn allocate;
    combine_fn combine;
    remove_fn remove;
    WCHAR output[512], *allocation, *end;
    WCHAR bounded[3] = { 'x', 'y', '\\' };
    SIZE_T remaining;
    const char *exports[] = {
        "PathAllocCanonicalize", "PathAllocCombine", "PathCchAddBackslash", "PathCchAddBackslashEx",
        "PathCchAddExtension", "PathCchAppend", "PathCchAppendEx", "PathCchCanonicalize", "PathCchCanonicalizeEx",
        "PathCchCombine", "PathCchCombineEx", "PathCchFindExtension", "PathCchIsRoot", "PathCchRemoveBackslash",
        "PathCchRemoveBackslashEx", "PathCchRemoveExtension", "PathCchRemoveFileSpec", "PathCchRenameExtension",
        "PathCchSkipRoot", "PathCchStripPrefix", "PathCchStripToRoot", "PathIsUNCEx",
    };
    unsigned i;
    CHECK(direct != NULL, "real pathcch module loaded");
    CHECK(host != NULL, "path API-set host loaded");
    if (!direct || !host) return 1;
    for (i = 0; i < sizeof(exports) / sizeof(exports[0]); ++i) {
        CHECK(GetProcAddress(direct, exports[i]) != NULL, exports[i]);
        CHECK(GetProcAddress(host, exports[i]) != NULL, exports[i]);
    }
    canonical = (canonical_fn)(ULONG_PTR)GetProcAddress(direct, "PathCchCanonicalizeEx");
    CHECK(canonical(output, 512, L"C:\\one\\.\\two\\..\\file", 0) == S_OK, "direct canonicalize");
    CHECK(equal(output, L"C:\\one\\file"), "direct canonicalize result");
    canonical = (canonical_fn)(ULONG_PTR)GetProcAddress(host, "PathCchCanonicalizeEx");
    allocate = (alloc_fn)(ULONG_PTR)GetProcAddress(host, "PathAllocCanonicalize");
    combine = (combine_fn)(ULONG_PTR)GetProcAddress(host, "PathCchCombineEx");
    remove = (remove_fn)(ULONG_PTR)GetProcAddress(host, "PathCchRemoveBackslashEx");
    if (!canonical || !allocate || !combine || !remove) return 1;
    CHECK(canonical(output, 512, L"C:\\..\\file", 0) == S_OK && equal(output, L"C:\\file"), "API-set canonicalize");
    CHECK(canonical(output, 2, L"C:\\file", 0) == STRSAFE_E_INSUFFICIENT_BUFFER, "capacity error");
    CHECK(canonical(NULL, 512, L"C:\\file", 0) == E_INVALIDARG, "null output refused");
    CHECK(canonical(output, 512, NULL, 0) == E_INVALIDARG, "null input refused");
    CHECK(canonical(output, 512, L"C:\\file", PATHCCH_ENSURE_TRAILING_SLASH) == S_OK && equal(output, L"C:\\file\\"), "trailing slash");
    allocation = (WCHAR *)1;
    CHECK(allocate(L"C:\\file", PATHCCH_FORCE_ENABLE_LONG_NAME_PROCESS, &allocation) == E_INVALIDARG && !allocation, "invalid flags and output ownership");
    CHECK(allocate(L"C:\\one\\..\\file", 0, &allocation) == S_OK && equal(allocation, L"C:\\file"), "allocated canonical result");
    CHECK(LocalFree(allocation) == NULL, "allocated result freed by caller");
    CHECK(combine(output, 512, L"C:\\dir", L"\\leaf", 0) == S_OK && equal(output, L"C:\\leaf"), "combine rooted component");
    CHECK(remove(bounded, 3, &end, &remaining) == E_INVALIDARG, "bounded unterminated input");
    CHECK(FreeLibrary(direct), "direct module reference released");
    CHECK(FreeLibrary(host), "API-set host reference released");
    printf("SHZ-PATHCCH-CHECKS %u checked %u failed\n", checks, failures);
    if (!failures) printf("SHZ-PATHCCH-PASS\n");
    return failures ? 1 : 0;
}
