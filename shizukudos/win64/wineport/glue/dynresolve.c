/* SPDX-License-Identifier: GPL-2.0-only
 * Wine port glue: resolver behind the generated "dynamic import" thunks (wineport/build.py dynamic_thunks).
 * The first call of such a function loads the DLL and looks the name up; the thunk's slot then points at the real
 * function, or at a stub that returns the failure value configured for that DLL (the function is absent here).
 */
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"

void shzw_dyn_resolve(const char *name, const char *dll, void **slot, void *fail)
{
    HMODULE h = GetModuleHandleA(dll);
    void *p = NULL;
    DWORD err = GetLastError();
    if (!h) h = LoadLibraryA(dll);
    if (h) p = (void *)GetProcAddress(h, name);
    InterlockedExchangePointer(slot, p ? p : fail);
    SetLastError(err);
}

/* the "absent" stub of a dynamic import: last error ERROR_PROC_NOT_FOUND, return value as configured */
ULONG_PTR shzw_dyn_fail(ULONG value)
{
    SetLastError(ERROR_PROC_NOT_FOUND);
    return value;
}
