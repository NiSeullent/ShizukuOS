/* Native Windows 98 COM Save As provider. SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_FILE_DIALOG_H
#define M98_FILE_DIALOG_H
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0600 /* Interface declarations; imports are gated to Win98. */
#define CINTERFACE
#define COBJMACROS
#define CONST_VTABLE
#include <windows.h>
#include <objbase.h>
#include <shobjidl.h>
#include <oleidl.h>

HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void **out);
HRESULT WINAPI DllCanUnloadNow(void);
HRESULT WINAPI DllRegisterServer(void);
HRESULT WINAPI DllUnregisterServer(void);
#endif
