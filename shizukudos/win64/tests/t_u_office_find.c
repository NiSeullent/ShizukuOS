/* SPDX-License-Identifier: GPL-2.0-only: actual CRT and filesystem enumeration. */
#include "k32test.h"
#include "../dlls/ucrtbase/ucrt_office_find.h"
typedef intptr_t (__cdecl *first_fn)(const char *, struct crt_finddata64i32 *);
typedef int (__cdecl *next_fn)(intptr_t, struct crt_finddata64i32 *);
typedef int (__cdecl *close_fn)(intptr_t);
typedef int *(__cdecl *errno_fn)(void);
typedef void (__cdecl *invalid_fn)(const unsigned short *, const unsigned short *, const unsigned short *, unsigned, uintptr_t);
typedef invalid_fn (__cdecl *set_invalid_fn)(invalid_fn);
static int invalid_calls;
static void __cdecl invalid_handler(const unsigned short *a, const unsigned short *b, const unsigned short *c, unsigned d, uintptr_t e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; ++invalid_calls; }
static int create_bytes(const WCHAR *name, const char *text, DWORD count)
{
    HANDLE h = CreateFileW(name, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD put = 0; BOOL ok;
    if (h == INVALID_HANDLE_VALUE) return 0;
    ok = WriteFile(h, text, count, &put, NULL); CloseHandle(h); return ok && put == count;
}
struct guarded { uint64_t before; struct crt_finddata64i32 data; uint64_t after; };
int main(void)
{
    HMODULE module = LoadLibraryW(L"api-ms-win-crt-filesystem-l1-1-0.dll");
    first_fn first = module ? (first_fn)GetProcAddress(module, "_findfirst64i32") : NULL;
    next_fn next = module ? (next_fn)GetProcAddress(module, "_findnext64i32") : NULL;
    close_fn close = module ? (close_fn)GetProcAddress(module, "_findclose") : NULL;
    errno_fn error = module ? (errno_fn)GetProcAddress(module, "_errno") : NULL;
    set_invalid_fn handler = module ? (set_invalid_fn)GetProcAddress(module, "_set_invalid_parameter_handler") : NULL;
    struct guarded g, saved; intptr_t h; unsigned count = 0, seen = 0; int result, err; invalid_fn previous;
    CHECK(first && next && close && error && handler, "real CRT filesystem API-set exposes owned enumeration contracts");
    if (!first || !next || !close || !error || !handler) return 1;
    CreateDirectoryW(L"C:\\TEMP", NULL);
    CHECK(CreateDirectoryW(L"C:\\TEMP\\UFIND", NULL), "fresh disposable enumeration directory creates");
    CHECK(create_bytes(L"C:\\TEMP\\UFIND\\A.BIN", "first", 5), "actual first file creates with five bytes");
    CHECK(create_bytes(L"C:\\TEMP\\UFIND\\B.BIN", "secondone", 9), "actual second file creates with nine bytes");
    memset(&g, 0xa5, sizeof g); g.before = 0x12345678abcdef01ull; g.after = 0xfedcba9876543210ull;
    *error() = 123; h = first("C:\\TEMP\\UFIND\\*.BIN", &g.data); err = *error();
    CHECK(h != -1 && err == 123, "real wildcard enumeration returns owned native handle preserving errno");
    if (h != -1) {
        do {
            CHECK(g.before == 0x12345678abcdef01ull && g.after == 0xfedcba9876543210ull, "actual 296-byte result preserves neighboring memory");
            if (!strcmp(g.data.name, "A.BIN")) { seen |= 1; CHECK(g.data.size == 5, "name and 32-bit size describe actual first file"); }
            else if (!strcmp(g.data.name, "B.BIN")) { seen |= 2; CHECK(g.data.size == 9, "name and 32-bit size describe actual second file"); }
            else CHECK(FALSE, "wildcard enumeration contains only created files");
            saved = g; ++count; result = next(h, &g.data); err = *error();
        } while (!result && count < 8);
        CHECK(count == 2 && seen == 3 && result == -1 && err == 2, "actual next exhausts distinct entries and reports ENOENT");
        CHECK(!memcmp(&g, &saved, sizeof g), "end of actual enumeration leaves output untouched");
        CHECK(!close(h), "original findclose releases actual adapter-owned native handle");
        result = next(h, &g.data); err = *error();
        CHECK(result == -1 && err == 9 && !memcmp(&g, &saved, sizeof g), "closed native enumeration fails EBADF without output changes");
    }
    saved = g; h = first("C:\\TEMP\\UFIND\\ABSENT.*", &g.data); err = *error();
    CHECK(h == -1 && err == 2 && !memcmp(&g, &saved, sizeof g), "actual missing wildcard fails ENOENT without output changes");
    previous = handler(invalid_handler);
    h = first(NULL, &g.data); err = *error();
    CHECK(h == -1 && err == 22 && invalid_calls == 1, "null pattern invokes actual invalid-parameter handler");
    h = first("C:\\TEMP\\UFIND\\*.BIN", NULL); err = *error();
    CHECK(h == -1 && err == 22 && invalid_calls == 2, "null first output does not acquire a native enumeration handle");
    result = next(-1, NULL); err = *error();
    CHECK(result == -1 && err == 22 && invalid_calls == 3, "null next output invokes actual invalid-parameter handler");
    handler(previous);
    CHECK(DeleteFileW(L"C:\\TEMP\\UFIND\\A.BIN") && DeleteFileW(L"C:\\TEMP\\UFIND\\B.BIN") && RemoveDirectoryW(L"C:\\TEMP\\UFIND"), "actual fixture files and directory are released");
    CHECK(FreeLibrary(module), "release actual CRT API-set reference");
    return k32t_finish("T_U_OFFICE_FIND");
}
