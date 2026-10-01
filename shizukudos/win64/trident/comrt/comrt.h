/* SPDX-License-Identifier: GPL-2.0-only
 * tridentrt.dll internal header (docs/shizukudos10/TRIDENT.md sec. 1).
 *
 * tridentrt.dll carries the COM/OLE/shlwapi pieces the Wine browser modules import but the Shizuku ole32, oleaut32,
 * shlwapi and kernel32 do not provide yet. The browser modules link it before ole32/oleaut32/shlwapi, so a name
 * exported here wins over the Shizuku DLL of the same name. What is Wine code (compiled unmodified from the pinned
 * tree, except typelib.c's patch 0200) and what is Shizuku-original is listed in tridentrt.spec.
 *
 * Memory ownership: BSTRs and SAFEARRAYs are always allocated and freed by the Shizuku oleaut32 (SysAllocString,
 * SafeArrayCreate, ... are imported, never compiled here), task memory by the Shizuku ole32 (CoTaskMemAlloc).
 */
#ifndef SHZ_TRIDENTRT_COMRT_H
#define SHZ_TRIDENTRT_COMRT_H

#include <stdarg.h>
#include <string.h>
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "objbase.h"
#include "oleauto.h"

/* register.c: writes the browser's registry keys that are missing, once per process (first activation, ProgID or
 * type library lookup); ShzTridentRegister is the exported form (returns S_OK or the first registry error) */
void trt_register_once(void);
HRESULT WINAPI ShzTridentRegister(void);

/* activation.c: CO_E_NOTINITIALIZED unless the calling thread is in an apartment (explicit, or the implicit MTA) */
HRESULT trt_check_apartment(void);

HRESULT trt_open_clsid_key(REFCLSID clsid, const WCHAR *sub, HKEY *key);    /* HKCR\\CLSID\\{clsid}[\\sub] */

/* rot.c: the process's running object table */
HRESULT WINAPI GetRunningObjectTable(DWORD reserved, IRunningObjectTable **rot);

#define TRT_GUID_CHARS 39                                  /* "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" + NUL */

#endif
