/* SPDX-License-Identifier: GPL-2.0-only */
#include "k32test.h"
typedef size_t (__cdecl *count_fn)(const char *, size_t);
int main(void)
{
    HMODULE module = LoadLibraryW(L"api-ms-win-crt-string-l1-1-0.dll");
    count_fn count = module ? (count_fn)GetProcAddress(module, "__strncnt") : 0;
    char *pages;
    DWORD old;
    unsigned n;
    CHECK(count != 0, "publisher CRT character counter resolves through the string API-set");
    if (!count) return 1;
    CHECK(count("", 20) == 0, "empty string");
    CHECK(count("abc", 0) == 0, "zero count for a valid string");
    CHECK(count("abc", (size_t)-1) == 3, "wide size_t count retains terminator bound");
    for (n = 0; n < 8; ++n)
        CHECKV(count("abc", n) == (n < 3 ? n : 3), "truncate at caller bound or terminator", "n=%u", n);
    pages = VirtualAlloc(0, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CHECK(pages != 0, "allocate guarded input");
    if (pages && VirtualProtect(pages + 4096, 4096, PAGE_NOACCESS, &old)) {
        memcpy(pages + 4093, "abc", 3);
        CHECK(count(pages + 4093, 3) == 3, "implementation stays within bounded unterminated input");
        CHECK(VirtualFree(pages, 0, MEM_RELEASE), "release guarded input");
    } else {
        CHECK(FALSE, "protect boundary guard page");
        if (pages) VirtualFree(pages, 0, MEM_RELEASE);
    }
    CHECK(FreeLibrary(module), "release CRT API-set reference");
    return k32t_finish("T_U_OFFICE_STRING");
}
