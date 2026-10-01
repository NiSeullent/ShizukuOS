/* SPDX-License-Identifier: GPL-2.0-only
 * Verify negative-provider behavior and the caller's real failure branch.
 * A passing test does not establish graphics, factory or adapter support.
 */
#include <dxgi1_3.h>
#include <assert.h>
#include <stdio.h>

int main(void)
{
    const GUID iid = {0x770aae78u, 0xf26f, 0x4dba, {0xa8,0x29,0x25,0x3c,0x83,0xd1,0xb3,0x87}};
    HRESULT (WINAPI *entries[])(REFIID, void **) = {CreateDXGIFactory, CreateDXGIFactory1};
    struct { uintptr_t before; void *object; uintptr_t after; } guard;
    unsigned i, checks = 0;
    _Static_assert(sizeof(HRESULT) == 4 && sizeof(GUID) == 16, "Windows HRESULT/GUID ABI");
    for (i = 0; i < sizeof(entries) / sizeof(entries[0]); ++i) {
        guard.before = 0x12345678; guard.after = 0x98765432; guard.object = &guard;
        assert(entries[i](&iid, &guard.object) == DXGI_ERROR_UNSUPPORTED && !guard.object); ++checks;
        assert(guard.before == 0x12345678 && guard.after == 0x98765432); ++checks;
        assert(FAILED(entries[i](&iid, &guard.object))); ++checks;
        guard.object = &guard;
        assert(entries[i](NULL, &guard.object) == DXGI_ERROR_INVALID_CALL && !guard.object); ++checks;
        assert(entries[i](&iid, NULL) == DXGI_ERROR_INVALID_CALL); ++checks;
    }
    for (i = 0; i < 2; ++i) {
        guard.object = &guard;
        assert(CreateDXGIFactory2(i, &iid, &guard.object) == DXGI_ERROR_UNSUPPORTED && !guard.object); ++checks;
    }
    guard.object = &guard;
    assert(CreateDXGIFactory2(2, &iid, &guard.object) == DXGI_ERROR_INVALID_CALL && !guard.object); ++checks;
    assert(CreateDXGIFactory2(0, NULL, &guard.object) == DXGI_ERROR_INVALID_CALL && !guard.object); ++checks;
    assert(CreateDXGIFactory2(0, &iid, NULL) == DXGI_ERROR_INVALID_CALL); ++checks;
    /* Chromium's information collector branches on FAILED rather than
     * dereferencing a fake factory. Exercise that exact ownership boundary. */
    guard.object = &guard;
    if (FAILED(CreateDXGIFactory1(&iid, &guard.object))) {
        assert(!guard.object); ++checks;
    } else assert(!"unavailable backend advertised success");
    printf("DXGI unavailable-provider host: %u checks passed; graphics unsupported\n", checks);
    return 0;
}
