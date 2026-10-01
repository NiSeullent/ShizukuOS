/* SPDX-License-Identifier: GPL-2.0-only
 * Run the full production module with catalog/heap/codec host adapters.
 * Native registry/loader behavior is covered separately in the guest test. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
typedef uint16_t WCHAR;
typedef uint32_t DWORD, UINT;
typedef int32_t LONG;
typedef unsigned char BYTE;
typedef uintptr_t ULONG_PTR;
typedef size_t SIZE_T;
typedef void *HKL, *HKEY;
typedef WCHAR *LPWSTR;
typedef char *LPSTR;
#define DLLAPI
#define WINAPI
#define SHZ_IMM32_HOST_TEST
#define CP_ACP 0
#define ERROR_SUCCESS 0
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_NOT_ENOUGH_MEMORY 8
#define ERROR_INVALID_DATA 13
#define ERROR_NOT_SUPPORTED 50
#define ERROR_MORE_DATA 234
#define REG_SZ 1
#define KEY_QUERY_VALUE 1
#define HKEY_LOCAL_MACHINE ((HKEY)(uintptr_t)0x80000002)
static WCHAR catalog[32770];
static DWORD catalog_bytes, catalog_type = REG_SZ, last_error;
static int missing_key, missing_value, copy_race, codec_error;
static unsigned opened, closed, allocations, frees, checks, failed, fail_allocation;
static int weq(const WCHAR *a, const WCHAR *b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }
static DWORD GetLastError(void) { return last_error; }
static void SetLastError(DWORD error) { last_error = error; }
static void *GetProcessHeap(void) { return NULL; }
static void *HeapAlloc(void *heap, DWORD flags, SIZE_T size) {
    void *p; (void)heap; (void)flags;
    if (fail_allocation && allocations + 1 == fail_allocation) return NULL;
    p = malloc(size); assert(p); memset(p, 0xcc, size); ++allocations; return p;
}
static int HeapFree(void *heap, DWORD flags, void *p) {
    (void)heap; (void)flags; assert(p); free(p); ++frees; return 1;
}
static LONG RegOpenKeyExW(HKEY parent, const WCHAR *path, DWORD flags, DWORD access, HKEY *key) {
    assert(parent == HKEY_LOCAL_MACHINE && !flags && access == KEY_QUERY_VALUE);
    if (missing_key || !weq(path, L"System\\CurrentControlSet\\Control\\Keyboard Layouts\\e0fe0409")) return ERROR_FILE_NOT_FOUND;
    *key = (HKEY)(uintptr_t)1; ++opened; return ERROR_SUCCESS;
}
static LONG RegQueryValueExW(HKEY key, const WCHAR *name, DWORD *reserved, DWORD *type, BYTE *output, DWORD *bytes) {
    assert(key == (HKEY)(uintptr_t)1 && !reserved && type && bytes);
    assert(weq(name, L"Ime File") || weq(name, L"Layout Text"));
    if (missing_value) return ERROR_FILE_NOT_FOUND;
    *type = catalog_type;
    if (!output) { *bytes = catalog_bytes; return ERROR_SUCCESS; }
    if (copy_race) { if (copy_race > 0) --copy_race; *bytes = catalog_bytes + 2; return ERROR_MORE_DATA; }
    if (*bytes < catalog_bytes) { *bytes = catalog_bytes; return ERROR_MORE_DATA; }
    memcpy(output, catalog, catalog_bytes); *bytes = catalog_bytes; return ERROR_SUCCESS;
}
static LONG RegCloseKey(HKEY key) { assert(key == (HKEY)(uintptr_t)1); ++closed; return ERROR_SUCCESS; }
static int WideCharToMultiByte(UINT cp, DWORD flags, const WCHAR *input, int units, char *output,
                               int cap, const char *fallback, int *used_fallback) {
    int n = 0;
    assert(cp == CP_ACP && !flags && units == -1 && !fallback && !used_fallback);
    if (codec_error) { last_error = 1113; return 0; }
    do {
        unsigned c = *input++;
        unsigned char b[3]; int count, i;
        if (c < 128) { b[0] = (unsigned char)c; count = 1; }
        else if (c < 2048) { b[0] = (unsigned char)(0xc0 | c >> 6); b[1] = (unsigned char)(0x80 | (c & 63)); count = 2; }
        else { b[0] = (unsigned char)(0xe0 | c >> 12); b[1] = (unsigned char)(0x80 | ((c >> 6) & 63)); b[2] = (unsigned char)(0x80 | (c & 63)); count = 3; }
        if (output && n + count > cap) { last_error = 122; return 0; }
        if (output) for (i = 0; i < count; ++i) output[n + i] = (char)b[i];
        n += count;
        if (!c) break;
    } while (1);
    return n;
}
#include "../dlls/imm32/imm32_metadata.c"
#define CHECK(condition) do { ++checks; if (!(condition)) { ++failed; fprintf(stderr, "FAIL line %d\n", __LINE__); } } while (0)
static void set_catalog(const WCHAR *text, int terminator) {
    unsigned n = 0;
    while (text[n]) { catalog[n] = text[n]; ++n; }
    if (terminator) catalog[n++] = 0;
    catalog_bytes = n * 2;
}
int main(void) {
    HKL layout = (HKL)(uintptr_t)0xe0fe0409;
    WCHAR output[64]; char ansi[64]; unsigned cap, i;
    set_catalog(L"fixture-only.ime", 1);
    CHECK(ImmGetIMEFileNameW(layout, NULL, 0) == 16);
    CHECK(ImmGetDescriptionW(layout, output, 64) == 16 && weq(output, L"fixture-only.ime"));
    CHECK(ImmGetIMEFileNameW((HKL)(uintptr_t)0xffffffffe0fe0409ull, output, 64) == 16 && weq(output, L"fixture-only.ime"));
    CHECK(ImmGetIMEFileNameA(layout, NULL, 0) == 16);
    CHECK(ImmGetDescriptionA(layout, ansi, 64) == 16 && !strcmp(ansi, "fixture-only.ime"));
    for (cap = 0; cap < 32; ++cap) {
        struct { WCHAR left, value[32], right; } wide;
        struct { char left, value[32], right; } narrow;
        UINT n, want = cap && cap <= 16 ? cap - 1 : 16;
        memset(&wide, 0x33, sizeof wide); memset(&narrow, 'Q', sizeof narrow);
        n = ImmGetIMEFileNameW(layout, wide.value, cap);
        CHECK(n == want && wide.left == 0x3333 && wide.right == 0x3333);
        if (cap) CHECK(wide.value[want] == 0 && wide.value[cap] == 0x3333);
        else CHECK(wide.value[0] == 0x3333);
        n = ImmGetIMEFileNameA(layout, narrow.value, cap);
        CHECK(n == want && narrow.left == 'Q' && narrow.right == 'Q');
        if (cap) CHECK(narrow.value[want] == 0 && narrow.value[cap] == 'Q');
        else CHECK(narrow.value[0] == 'Q');
    }
    missing_key = 1; output[0] = 0x1234;
    CHECK(!ImmGetIMEFileNameW(layout, output, 64) && output[0] == 0x1234);
    missing_key = 0; missing_value = 1;
    CHECK(!ImmGetIMEFileNameW(layout, output, 64) && output[0] == 0);
    missing_value = 0; set_catalog(L"changed.ime", 1);
    CHECK(ImmGetIMEFileNameW(layout, output, 64) == 11 && weq(output, L"changed.ime"));
    set_catalog(L"unterminated", 0);
    CHECK(ImmGetIMEFileNameW(layout, output, 64) == 12 && weq(output, L"unterminated"));
    catalog[0] = 'X'; catalog[1] = 0; catalog[2] = 'Y'; catalog[3] = 0; catalog_bytes = 8;
    CHECK(ImmGetIMEFileNameW(layout, output, 64) == 1 && weq(output, L"X"));
    catalog[0] = 0xe9; catalog[1] = 0; catalog_bytes = 4;
    CHECK(ImmGetIMEFileNameW(layout, output, 64) == 1 && output[0] == 0xe9 && output[1] == 0);
    CHECK(ImmGetIMEFileNameA(layout, ansi, 64) == 2 && (unsigned char)ansi[0] == 0xc3 && (unsigned char)ansi[1] == 0xa9 && ansi[2] == 0);
    set_catalog(L"bounded", 1);
    catalog_bytes = 3; last_error = 0;
    CHECK(!ImmGetIMEFileNameW(layout, output, 64) && last_error == ERROR_INVALID_DATA);
    catalog_bytes = 16; catalog_type = 3; last_error = 0;
    CHECK(!ImmGetIMEFileNameW(layout, output, 64) && last_error == ERROR_INVALID_DATA);
    catalog_type = REG_SZ; catalog_bytes = 65538; last_error = 0;
    CHECK(!ImmGetIMEFileNameW(layout, output, 64) && last_error == ERROR_NOT_SUPPORTED);
    for (i = 0; i < 32768; ++i) catalog[i] = 'x'; catalog_bytes = 65536;
    CHECK(ImmGetIMEFileNameW(layout, NULL, 0) == 32768);
    set_catalog(L"bounded", 1); copy_race = 1;
    CHECK(ImmGetIMEFileNameW(layout, output, 64) == 7 && weq(output, L"bounded"));
    copy_race = -1; last_error = 0;
    CHECK(!ImmGetIMEFileNameW(layout, output, 64) && last_error == ERROR_MORE_DATA);
    copy_race = 0; fail_allocation = allocations + 1; last_error = 0;
    CHECK(!ImmGetIMEFileNameW(layout, output, 64) && last_error == ERROR_NOT_ENOUGH_MEMORY);
    fail_allocation = 0; codec_error = 1; last_error = 0;
    CHECK(!ImmGetIMEFileNameA(layout, ansi, 64) && last_error == 1113);
    codec_error = 0; fail_allocation = allocations + 2; last_error = 0;
    CHECK(!ImmGetIMEFileNameA(layout, ansi, 64) && last_error == ERROR_NOT_ENOUGH_MEMORY);
    fail_allocation = 0;
    CHECK(allocations == frees && opened == closed);
    printf("IMM_METADATA_HOST: %u checks, %u failed\n", checks, failed);
    return failed != 0;
}
