/* SPDX-License-Identifier: GPL-2.0-only
 * tridentrt: the exported type library loaders. tridentrt.spec maps LoadTypeLib, LoadTypeLibEx, LoadRegTypeLib and
 * QueryPathOfRegTypeLib to these wrappers, which seed the registry (register.c) before the first type library lookup
 * of the process and then call Wine's implementation (dlls/oleaut32/typelib.c, compiled into tridentrt). Calls inside
 * typelib.c keep using Wine's functions directly.
 */
#include "comrt.h"

HRESULT WINAPI trt_LoadTypeLib(const OLECHAR *file, ITypeLib **lib)
{
    trt_register_once();
    return LoadTypeLib(file, lib);
}

HRESULT WINAPI trt_LoadTypeLibEx(const OLECHAR *file, REGKIND kind, ITypeLib **lib)
{
    trt_register_once();
    return LoadTypeLibEx(file, kind, lib);
}

HRESULT WINAPI trt_LoadRegTypeLib(REFGUID guid, WORD major, WORD minor, LCID lcid, ITypeLib **lib)
{
    trt_register_once();
    return LoadRegTypeLib(guid, major, minor, lcid, lib);
}

HRESULT WINAPI trt_QueryPathOfRegTypeLib(REFGUID guid, WORD major, WORD minor, LCID lcid, BSTR *path)
{
    trt_register_once();
    return QueryPathOfRegTypeLib(guid, major, minor, lcid, path);
}
