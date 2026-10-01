/* SPDX-License-Identifier: GPL-2.0-only
 * Original unavailable-provider boundary, not a Direct3D implementation.
 * Wine 11.0 db11d0fe6a169c457e23d007e20404643d067aa8:
 * dlls/dxgi/factory.c: dxgi_factory_init returns DXGI_ERROR_UNSUPPORTED when
 * wined3d_create cannot provide a backend. No Wine implementation is copied.
 * Microsoft CreateDXGIFactory/1/2 and DXGI_ERROR contracts are linked in README.
 * Kernel64 currently has no DXGI/wined3d provider. Never fabricate a factory,
 * adapter, driver identity, device or successful graphics operation.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dxgi1_3.h>

#ifndef DLLAPI
#define DLLAPI __declspec(dllexport)
#endif

static HRESULT unavailable_factory(REFIID iid, void **factory)
{
    if (!factory) return DXGI_ERROR_INVALID_CALL;
    *factory = NULL;
    if (!iid) return DXGI_ERROR_INVALID_CALL;
    return DXGI_ERROR_UNSUPPORTED;
}

DLLAPI HRESULT WINAPI CreateDXGIFactory(REFIID iid, void **factory)
{
    return unavailable_factory(iid, factory);
}

DLLAPI HRESULT WINAPI CreateDXGIFactory1(REFIID iid, void **factory)
{
    return unavailable_factory(iid, factory);
}

DLLAPI HRESULT WINAPI CreateDXGIFactory2(UINT flags, REFIID iid, void **factory)
{
    if (factory) *factory = NULL;
    if (flags & ~DXGI_CREATE_FACTORY_DEBUG) return DXGI_ERROR_INVALID_CALL;
    return unavailable_factory(iid, factory);
}
