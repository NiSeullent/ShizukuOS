/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_DXGI_HOST_DXGI_H
#define SHZ_DXGI_HOST_DXGI_H
#include <windows.h>
#define DXGI_CREATE_FACTORY_DEBUG 1u
HRESULT WINAPI CreateDXGIFactory(REFIID, void **);
HRESULT WINAPI CreateDXGIFactory1(REFIID, void **);
HRESULT WINAPI CreateDXGIFactory2(UINT, REFIID, void **);
#endif
