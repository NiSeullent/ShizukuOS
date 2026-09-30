/* SPDX-License-Identifier: GPL-2.0-only */
#include "../../ntwin32/resolve.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
struct mock_loader { unsigned owned_calls, native_calls; uintptr_t module; const char *name; };
static void owned_proc(void) {}
static void native_proc(void) {}
static ntw_proc owned(void *context, const char *name) {
    struct mock_loader *mock = context;
    ++mock->owned_calls;
    return ntw_export_name_equal(name, "GetTickCount64") ? owned_proc : NULL;
}
static ntw_proc native(void *context, uintptr_t module, const char *name) {
    struct mock_loader *mock = context;
    ++mock->native_calls; mock->module = module; mock->name = name;
    return native_proc;
}
int main(void) {
    struct mock_loader mock = {0};
    /* No table, policy, owner callback or log: the legacy contract (mode Own). */
    struct ntw_resolver r = {0x8000, owned, native, &mock, 0, 0, 0, 0, 0};
    uintptr_t ordinal;
    const char *names[] = {"", "gettickcount64", "GetTickCount", "GetTickCount64Extra", "#13"};
    size_t i;
    assert(ntw_resolve(&r, 0x8000, "GetTickCount64") == owned_proc);
    assert(mock.native_calls == 0 && mock.owned_calls == 1);
    assert(ntw_resolve(&r, 0x8001, "GetTickCount64") == native_proc);
    assert(mock.module == 0x8001 && mock.owned_calls == 1);
    for (i = 0; i < sizeof(names)/sizeof(*names); ++i) {
        unsigned calls = mock.native_calls;
        assert(ntw_resolve(&r, 0x8000, names[i]) == native_proc);
        assert(mock.name == names[i] && mock.native_calls == calls + 1);
    }
    for (ordinal = 0; ordinal <= UINT16_MAX; ++ordinal) {
        unsigned calls = mock.owned_calls;
        assert(ntw_resolve(&r, 0x8000, (const char *)ordinal) == native_proc);
        assert(mock.owned_calls == calls && (uintptr_t)mock.name == ordinal);
    }
    assert(ntw_resolve(&r, 0, "GetTickCount64") == native_proc);
    r.kernel32_module = 0;
    assert(ntw_resolve(&r, 0, "GetTickCount64") == native_proc);
    assert(ntw_resolve(NULL, 0x8000, "GetTickCount64") == NULL);
    assert(ntw_export_name_equal("Same", "Same"));
    assert(!ntw_export_name_equal("Same", "same"));
    assert(!ntw_export_name_equal("Same", "SameMore"));
    puts("PASS: dynamic resolver exact module/name, all ordinal values, native fallback");
    return 0;
}
