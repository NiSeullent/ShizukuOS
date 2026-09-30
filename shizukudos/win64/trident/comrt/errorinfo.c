/* SPDX-License-Identifier: GPL-2.0-only
 * tridentrt: per-thread COM error information (GetErrorInfo, SetErrorInfo, CreateErrorInfo).
 *
 * Each thread holds at most one IErrorInfo: SetErrorInfo replaces it (NULL clears it), GetErrorInfo hands it to the
 * caller and clears the slot, or returns S_FALSE with NULL when there is none, as documented. CreateErrorInfo makes
 * the standard object: IErrorInfo + ICreateErrorInfo + ISupportErrorInfo, whose strings are copied in and returned as
 * new BSTRs (allocated by the Shizuku oleaut32). Wine's typelib.c (ITypeInfo::Invoke) reads it after a failed call.
 */
#define COBJMACROS
#include "comrt.h"

struct error_info
{
    IErrorInfo IErrorInfo_iface;
    ICreateErrorInfo ICreateErrorInfo_iface;
    ISupportErrorInfo ISupportErrorInfo_iface;
    LONG refs;
    GUID guid;
    WCHAR *source, *description, *help_file;
    DWORD help_context;
};

static struct error_info *from_IErrorInfo(IErrorInfo *iface)
{
    return CONTAINING_RECORD(iface, struct error_info, IErrorInfo_iface);
}
static struct error_info *from_ICreateErrorInfo(ICreateErrorInfo *iface)
{
    return CONTAINING_RECORD(iface, struct error_info, ICreateErrorInfo_iface);
}
static struct error_info *from_ISupportErrorInfo(ISupportErrorInfo *iface)
{
    return CONTAINING_RECORD(iface, struct error_info, ISupportErrorInfo_iface);
}

static WCHAR *dup_str(const WCHAR *s)
{
    WCHAR *d;
    if (!s) return NULL;
    if ((d = HeapAlloc(GetProcessHeap(), 0, (lstrlenW(s) + 1) * sizeof(WCHAR)))) lstrcpyW(d, s);
    return d;
}

static HRESULT set_str(WCHAR **field, const WCHAR *s)
{
    WCHAR *d = dup_str(s);
    if (s && !d) return E_OUTOFMEMORY;
    HeapFree(GetProcessHeap(), 0, *field);
    *field = d;
    return S_OK;
}

static HRESULT get_str(const WCHAR *s, BSTR *out)
{
    if (!out) return E_INVALIDARG;
    *out = s ? SysAllocString(s) : NULL;
    return s && !*out ? E_OUTOFMEMORY : S_OK;
}

/* IErrorInfo */
static HRESULT WINAPI errorinfo_QueryInterface(IErrorInfo *iface, REFIID riid, void **obj)
{
    struct error_info *This = from_IErrorInfo(iface);
    if (!obj) return E_INVALIDARG;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IErrorInfo)) *obj = &This->IErrorInfo_iface;
    else if (IsEqualIID(riid, &IID_ICreateErrorInfo)) *obj = &This->ICreateErrorInfo_iface;
    else if (IsEqualIID(riid, &IID_ISupportErrorInfo)) *obj = &This->ISupportErrorInfo_iface;
    else
    {
        *obj = NULL;
        return E_NOINTERFACE;
    }
    IUnknown_AddRef((IUnknown *)*obj);
    return S_OK;
}

static ULONG WINAPI errorinfo_AddRef(IErrorInfo *iface)
{
    return InterlockedIncrement(&from_IErrorInfo(iface)->refs);
}

static ULONG WINAPI errorinfo_Release(IErrorInfo *iface)
{
    struct error_info *This = from_IErrorInfo(iface);
    ULONG refs = InterlockedDecrement(&This->refs);
    if (!refs)
    {
        HeapFree(GetProcessHeap(), 0, This->source);
        HeapFree(GetProcessHeap(), 0, This->description);
        HeapFree(GetProcessHeap(), 0, This->help_file);
        HeapFree(GetProcessHeap(), 0, This);
    }
    return refs;
}

static HRESULT WINAPI errorinfo_GetGUID(IErrorInfo *iface, GUID *guid)
{
    if (!guid) return E_INVALIDARG;
    *guid = from_IErrorInfo(iface)->guid;
    return S_OK;
}
static HRESULT WINAPI errorinfo_GetSource(IErrorInfo *iface, BSTR *s)
{
    return get_str(from_IErrorInfo(iface)->source, s);
}
static HRESULT WINAPI errorinfo_GetDescription(IErrorInfo *iface, BSTR *s)
{
    return get_str(from_IErrorInfo(iface)->description, s);
}
static HRESULT WINAPI errorinfo_GetHelpFile(IErrorInfo *iface, BSTR *s)
{
    return get_str(from_IErrorInfo(iface)->help_file, s);
}
static HRESULT WINAPI errorinfo_GetHelpContext(IErrorInfo *iface, DWORD *ctx)
{
    if (!ctx) return E_INVALIDARG;
    *ctx = from_IErrorInfo(iface)->help_context;
    return S_OK;
}

static const IErrorInfoVtbl errorinfo_vtbl =
{
    errorinfo_QueryInterface, errorinfo_AddRef, errorinfo_Release, errorinfo_GetGUID, errorinfo_GetSource,
    errorinfo_GetDescription, errorinfo_GetHelpFile, errorinfo_GetHelpContext
};

/* ICreateErrorInfo */
static HRESULT WINAPI create_QueryInterface(ICreateErrorInfo *iface, REFIID riid, void **obj)
{
    return errorinfo_QueryInterface(&from_ICreateErrorInfo(iface)->IErrorInfo_iface, riid, obj);
}
static ULONG WINAPI create_AddRef(ICreateErrorInfo *iface)
{
    return errorinfo_AddRef(&from_ICreateErrorInfo(iface)->IErrorInfo_iface);
}
static ULONG WINAPI create_Release(ICreateErrorInfo *iface)
{
    return errorinfo_Release(&from_ICreateErrorInfo(iface)->IErrorInfo_iface);
}
static HRESULT WINAPI create_SetGUID(ICreateErrorInfo *iface, REFGUID guid)
{
    from_ICreateErrorInfo(iface)->guid = *guid;
    return S_OK;
}
static HRESULT WINAPI create_SetSource(ICreateErrorInfo *iface, LPOLESTR s)
{
    return set_str(&from_ICreateErrorInfo(iface)->source, s);
}
static HRESULT WINAPI create_SetDescription(ICreateErrorInfo *iface, LPOLESTR s)
{
    return set_str(&from_ICreateErrorInfo(iface)->description, s);
}
static HRESULT WINAPI create_SetHelpFile(ICreateErrorInfo *iface, LPOLESTR s)
{
    return set_str(&from_ICreateErrorInfo(iface)->help_file, s);
}
static HRESULT WINAPI create_SetHelpContext(ICreateErrorInfo *iface, DWORD ctx)
{
    from_ICreateErrorInfo(iface)->help_context = ctx;
    return S_OK;
}

static const ICreateErrorInfoVtbl create_vtbl =
{
    create_QueryInterface, create_AddRef, create_Release, create_SetGUID, create_SetSource, create_SetDescription,
    create_SetHelpFile, create_SetHelpContext
};

/* ISupportErrorInfo */
static HRESULT WINAPI support_QueryInterface(ISupportErrorInfo *iface, REFIID riid, void **obj)
{
    return errorinfo_QueryInterface(&from_ISupportErrorInfo(iface)->IErrorInfo_iface, riid, obj);
}
static ULONG WINAPI support_AddRef(ISupportErrorInfo *iface)
{
    return errorinfo_AddRef(&from_ISupportErrorInfo(iface)->IErrorInfo_iface);
}
static ULONG WINAPI support_Release(ISupportErrorInfo *iface)
{
    return errorinfo_Release(&from_ISupportErrorInfo(iface)->IErrorInfo_iface);
}
static HRESULT WINAPI support_InterfaceSupportsErrorInfo(ISupportErrorInfo *iface, REFIID riid)
{
    return IsEqualIID(riid, &from_ISupportErrorInfo(iface)->guid) ? S_OK : S_FALSE;
}

static const ISupportErrorInfoVtbl support_vtbl =
{
    support_QueryInterface, support_AddRef, support_Release, support_InterfaceSupportsErrorInfo
};

HRESULT WINAPI CreateErrorInfo(ICreateErrorInfo **out)
{
    struct error_info *This;
    if (!out) return E_INVALIDARG;
    *out = NULL;
    if (!(This = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*This)))) return E_OUTOFMEMORY;
    This->IErrorInfo_iface.lpVtbl = &errorinfo_vtbl;
    This->ICreateErrorInfo_iface.lpVtbl = &create_vtbl;
    This->ISupportErrorInfo_iface.lpVtbl = &support_vtbl;
    This->refs = 1;
    *out = &This->ICreateErrorInfo_iface;
    return S_OK;
}

/* ---------------------------------------------------------------- the thread's current error */
static DWORD slot = TLS_OUT_OF_INDEXES;

static BOOL ensure_slot(void)
{
    if (slot == TLS_OUT_OF_INDEXES)
    {
        DWORD idx = TlsAlloc();
        if (idx == TLS_OUT_OF_INDEXES) return FALSE;
        if (InterlockedCompareExchange((LONG *)&slot, idx, TLS_OUT_OF_INDEXES) != TLS_OUT_OF_INDEXES) TlsFree(idx);
    }
    return TRUE;
}

HRESULT WINAPI SetErrorInfo(ULONG reserved, IErrorInfo *info)
{
    IErrorInfo *old;
    if (reserved) return E_INVALIDARG;
    if (!ensure_slot()) return E_OUTOFMEMORY;
    old = TlsGetValue(slot);
    if (info) IErrorInfo_AddRef(info);
    TlsSetValue(slot, info);
    if (old) IErrorInfo_Release(old);
    return S_OK;
}

HRESULT WINAPI GetErrorInfo(ULONG reserved, IErrorInfo **info)
{
    if (!info) return E_INVALIDARG;
    *info = NULL;
    if (reserved) return E_INVALIDARG;
    if (slot == TLS_OUT_OF_INDEXES || !(*info = TlsGetValue(slot))) return S_FALSE;
    TlsSetValue(slot, NULL);                                /* the caller takes over the thread's reference */
    return S_OK;
}
