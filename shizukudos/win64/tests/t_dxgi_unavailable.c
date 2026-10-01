/* SPDX-License-Identifier: GPL-2.0-only
 * Real DXGI DLL/static-import failure boundary. Not a graphics-support test.
 */
#include <dxgi1_3.h>
#include "k32test.h"

typedef HRESULT (WINAPI *factory_fn)(REFIID, void **);
typedef HRESULT (WINAPI *factory2_fn)(UINT, REFIID, void **);
static const GUID factory_iid = {0x770aae78u, 0xf26f, 0x4dba, {0xa8,0x29,0x25,0x3c,0x83,0xd1,0xb3,0x87}};

int main(void)
{
    HMODULE module = LoadLibraryExW(L"dxgi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    factory_fn factories[2];
    factory2_fn extended;
    const char *names[2] = {"CreateDXGIFactory", "CreateDXGIFactory1"};
    struct { ULONG_PTR before; void *object; ULONG_PTR after; } guard;
    unsigned i;
    CHECK(module != NULL, "actual unavailable-provider DXGI module loads");
    if (!module) return 1;
    factories[0] = (factory_fn)GetProcAddress(module, names[0]);
    factories[1] = (factory_fn)GetProcAddress(module, names[1]);
    extended = (factory2_fn)GetProcAddress(module, "CreateDXGIFactory2");
    CHECK(factories[0] && factories[1] && extended, "three real creation failure entry points resolve");
    if (!factories[0] || !factories[1] || !extended) { FreeLibrary(module); return 1; }
    guard.before = 0x12345678; guard.after = 0x98765432;
    for (i = 0; i < 2; ++i) {
        guard.object = &guard;
        CHECK(factories[i](&factory_iid, &guard.object) == DXGI_ERROR_UNSUPPORTED && !guard.object,
              "no backend returns failing HRESULT and NULL factory");
        CHECK(guard.before == 0x12345678 && guard.after == 0x98765432, "failure does not write past pointer output");
        guard.object = &guard;
        CHECK(factories[i](NULL, &guard.object) == DXGI_ERROR_INVALID_CALL && !guard.object, "null IID fails with cleared output");
        CHECK(factories[i](&factory_iid, NULL) == DXGI_ERROR_INVALID_CALL, "null output fails safely");
    }
    for (i = 0; i < 2; ++i) {
        guard.object = &guard;
        CHECK(extended(i, &factory_iid, &guard.object) == DXGI_ERROR_UNSUPPORTED && !guard.object,
              "factory2 valid default/debug request reports absent graphics provider");
    }
    guard.object = &guard;
    CHECK(extended(2, &factory_iid, &guard.object) == DXGI_ERROR_INVALID_CALL && !guard.object,
          "factory2 unknown flags fail with cleared output");
    CHECK(extended(0, NULL, &guard.object) == DXGI_ERROR_INVALID_CALL && !guard.object, "factory2 null IID fails");
    CHECK(extended(0, &factory_iid, NULL) == DXGI_ERROR_INVALID_CALL, "factory2 null output fails");
    guard.object = &guard;
    CHECK(FAILED(CreateDXGIFactory1(&factory_iid, &guard.object)) && !guard.object,
          "actual static import reaches caller's failure path without an object");
    CHECK(FreeLibrary(module), "module reference releases");
    return k32t_finish("T_DXGI_UNAVAILABLE");
}
