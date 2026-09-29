/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: the resource functions the DLLs ported from Wine (wineport) call that kernel32's resource code
 * (k32_module.c) does not export: EnumResourceTypesA (ANSI type names through EnumResourceTypesW, CP_ACP) and
 * FreeResource (resources live in the mapped image and are never freed; it returns FALSE as on Win32).
 */
#include "k32_winecompat.h"

K32API BOOL WINAPI FreeResource(HGLOBAL h) { (void)h; return FALSE; }

struct enum_types_a { ENUMRESTYPEPROCA fn; LONG_PTR param; };

static BOOL CALLBACK types_a_thunk(HMODULE mod, LPWSTR type, LONG_PTR p)
{
    const struct enum_types_a *e = (const struct enum_types_a *)p;
    char *a;
    int n;
    BOOL r;
    if (IS_INTRESOURCE(type)) return e->fn(mod, (LPSTR)type, e->param);
    n = WideCharToMultiByte(CP_ACP, 0, type, -1, NULL, 0, NULL, NULL);
    if (!n || !(a = HeapAlloc(GetProcessHeap(), 0, n))) return FALSE;      /* stops the enumeration, error set */
    WideCharToMultiByte(CP_ACP, 0, type, -1, a, n, NULL, NULL);
    r = e->fn(mod, a, e->param);
    HeapFree(GetProcessHeap(), 0, a);
    return r;
}

K32API BOOL WINAPI EnumResourceTypesA(HMODULE mod, ENUMRESTYPEPROCA fn, LONG_PTR param)
{
    struct enum_types_a e = { fn, param };
    return EnumResourceTypesW(mod, types_a_thunk, (LONG_PTR)&e);
}
