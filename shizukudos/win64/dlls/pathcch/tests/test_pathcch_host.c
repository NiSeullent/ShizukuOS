/* SPDX-License-Identifier: GPL-2.0-only */
#define SHZ_PATHCCH_HOST_TEST
#include "../pathcch.c"
#include <stdio.h>

static unsigned checks;
#define CHECK(condition) do { ++checks; if (!(condition)) { fprintf(stderr, "PathCch check %u failed at %d: %s\n", checks, __LINE__, #condition); return 1; } } while (0)
static int equal(const WCHAR *a, const WCHAR *b)
{ while (*a && *a == *b) { ++a; ++b; } return *a == *b; }

int main(void)
{
    WCHAR out[512], *allocated, *end;
    const WCHAR *position;
    SIZE_T remaining;
    WCHAR no_nul[3] = { 'a', 'b', '\\' };
    WCHAR long_path[300];
    unsigned i;
    CHECK(sizeof(WCHAR) == 2);
    CHECK(PathCchCanonicalizeEx(out, 512, L"C:\\one\\.\\two\\..\\file", 0) == S_OK);
    CHECK(equal(out, L"C:\\one\\file"));
    CHECK(PathCchCanonicalizeEx(out, 512, L"C:\\..\\..\\file", 0) == S_OK);
    CHECK(equal(out, L"C:\\file"));
    CHECK(PathCchCanonicalizeEx(out, 512, L"\\\\server\\share\\one\\..\\file", 0) == S_OK);
    CHECK(equal(out, L"\\\\server\\share\\file"));
    CHECK(PathCchCanonicalizeEx(out, 512, L"C:\\file...", 0) == S_OK);
    CHECK(equal(out, L"C:\\file"));
    CHECK(PathCchCanonicalizeEx(out, 512, L"C:\\file...", PATHCCH_DO_NOT_NORMALIZE_SEGMENTS) == S_OK);
    CHECK(equal(out, L"C:\\file..."));
    CHECK(PathCchCanonicalizeEx(out, 512, L"C:\\dir", PATHCCH_ENSURE_TRAILING_SLASH) == S_OK);
    CHECK(equal(out, L"C:\\dir\\"));
    CHECK(PathCchCanonicalizeEx(out, 512, L"C:\\dir", PATHCCH_ENSURE_IS_EXTENDED_LENGTH_PATH) == S_OK);
    CHECK(equal(out, L"\\\\?\\C:\\dir"));
    CHECK(PathCchCanonicalizeEx(out, 2, L"C:\\file", 0) == STRSAFE_E_INSUFFICIENT_BUFFER);
    CHECK(PathCchCanonicalizeEx(NULL, 5, L"C:\\", 0) == E_INVALIDARG);
    CHECK(PathCchCanonicalizeEx(out, 5, NULL, 0) == E_INVALIDARG);
    CHECK(PathCchCanonicalizeEx(out, 0, L"C:\\", 0) == E_INVALIDARG);
    CHECK(PathCchCanonicalizeEx(out, PATHCCH_MAX_CCH + 1, L"C:\\", 0) == E_INVALIDARG);
    allocated = (WCHAR *)1;
    CHECK(PathAllocCanonicalize(L"C:\\file", PATHCCH_FORCE_ENABLE_LONG_NAME_PROCESS, &allocated) == E_INVALIDARG);
    CHECK(allocated == NULL);
    CHECK(PathAllocCanonicalize(L"C:\\file", PATHCCH_ALLOW_LONG_PATHS | PATHCCH_FORCE_ENABLE_LONG_NAME_PROCESS | PATHCCH_FORCE_DISABLE_LONG_NAME_PROCESS, &allocated) == E_INVALIDARG);
    CHECK(allocated == NULL);
    path_host_fail_allocation = 1;
    CHECK(PathAllocCanonicalize(L"C:\\file", 0, &allocated) == E_OUTOFMEMORY);
    CHECK(allocated == NULL && path_host_allocations == 0);
    CHECK(PathAllocCombine(L"C:\\dir", L"..\\file", 0, &allocated) == S_OK);
    CHECK(equal(allocated, L"C:\\file"));
    LocalFree(allocated);
    CHECK(PathCchCombineEx(out, 512, L"C:\\dir", L"\\leaf", 0) == S_OK);
    CHECK(equal(out, L"C:\\leaf"));
    CHECK(PathCchCombineEx(out, 512, L"C:\\dir", L"D:\\other", 0) == S_OK);
    CHECK(equal(out, L"D:\\other"));
    lstrcpyW(out, L"C:\\dir");
    CHECK(PathCchAppendEx(out, 512, L"leaf", 0) == S_OK);
    CHECK(equal(out, L"C:\\dir\\leaf"));
    CHECK(PathCchRemoveFileSpec(out, 512) == S_OK && equal(out, L"C:\\dir"));
    CHECK(PathCchAddBackslashEx(out, 512, &end, &remaining) == S_OK);
    CHECK(equal(out, L"C:\\dir\\") && *end == 0 && remaining == 512 - (SIZE_T)lstrlenW(out));
    CHECK(PathCchRemoveBackslashEx(out, 512, &end, &remaining) == S_OK);
    CHECK(equal(out, L"C:\\dir") && *end == 0);
    CHECK(PathCchRemoveBackslashEx(no_nul, 3, &end, &remaining) == E_INVALIDARG);
    CHECK(PathCchRemoveBackslashEx(NULL, 3, &end, &remaining) == E_INVALIDARG);
    lstrcpyW(out, L"C:\\");
    CHECK(PathCchRemoveBackslash(out, 512) == S_FALSE && equal(out, L"C:\\"));
    CHECK(PathCchIsRoot(out));
    CHECK(PathCchSkipRoot(L"\\\\server\\share\\leaf", &position) == S_OK && equal(position, L"leaf"));
    lstrcpyW(out, L"\\\\server\\share\\leaf");
    CHECK(PathCchStripToRoot(out, 512) == S_OK && equal(out, L"\\\\server\\share"));
    lstrcpyW(out, L"\\\\?\\UNC\\server\\share");
    CHECK(PathCchStripPrefix(out, 512) == S_OK && equal(out, L"\\\\server\\share"));
    CHECK(PathIsUNCEx(out, &position) && equal(position, L"server\\share"));
    lstrcpyW(out, L"C:\\file.txt");
    CHECK(PathCchFindExtension(out, 512, &position) == S_OK && equal(position, L".txt"));
    CHECK(PathCchRenameExtension(out, 512, L"odt") == S_OK && equal(out, L"C:\\file.odt"));
    CHECK(PathCchRemoveExtension(out, 512) == S_OK && equal(out, L"C:\\file"));
    CHECK(PathCchAddExtension(out, 512, L".txt") == S_OK && equal(out, L"C:\\file.txt"));
    CHECK(PathCchAddExtension(out, 512, L"bad.extension") == E_INVALIDARG);
    long_path[0] = 'C'; long_path[1] = ':'; long_path[2] = '\\';
    for (i = 3; i < 280; ++i) long_path[i] = 'a';
    long_path[280] = 0;
    CHECK(PathCchCanonicalizeEx(out, 512, long_path, 0) == HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE));
    CHECK(PathCchCanonicalizeEx(out, 512, long_path, PATHCCH_ALLOW_LONG_PATHS) == S_OK);
    CHECK(path_wcsncmp(out, L"\\\\?\\C:\\", 7) == 0);
    CHECK(path_host_allocations == 0);
    printf("PathCch host contract checks: %u PASS\n", checks);
    return 0;
}
