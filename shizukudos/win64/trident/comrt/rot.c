/* SPDX-License-Identifier: GPL-2.0-only
 * tridentrt: the running object table (GetRunningObjectTable), what IBindCtx::GetRunningObjectTable returns.
 *
 * Windows keeps one table per machine in the RPCSS service; here it is one table per process (there is no service
 * and no marshaling), which is what in-process binding needs: urlmon's URL moniker asks it whether an object is
 * running before binding, Wine's bind context hands it out. Monikers are compared with IMoniker::IsEqual. Every
 * registration holds a reference on the object until Revoke (ROTFLAGS_REGISTRATIONKEEPSALIVE behaviour for all).
 */
#define COBJMACROS
#include "comrt.h"

struct rot_entry
{
    struct rot_entry *next;
    DWORD cookie;
    IUnknown *object;
    IMoniker *moniker;
    FILETIME last_change;
};

static CRITICAL_SECTION rot_lock = { NULL, -1, 0, 0, 0, 0 };
static struct rot_entry *entries;
static DWORD rot_next_cookie;

/* the entry for a moniker, with rot_lock held; NULL when none */
static struct rot_entry *find_moniker(IMoniker *mk)
{
    struct rot_entry *e;
    for (e = entries; e; e = e->next)
        if (IMoniker_IsEqual(e->moniker, mk) == S_OK) return e;
    return NULL;
}

static HRESULT WINAPI rot_QueryInterface(IRunningObjectTable *iface, REFIID riid, void **obj)
{
    if (!obj) return E_INVALIDARG;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IRunningObjectTable))
    {
        *obj = iface;
        return S_OK;
    }
    *obj = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI rot_AddRef(IRunningObjectTable *iface) { return 2; }      /* process lifetime object */
static ULONG WINAPI rot_Release(IRunningObjectTable *iface) { return 1; }

static HRESULT WINAPI rot_Register(IRunningObjectTable *iface, DWORD flags, IUnknown *object, IMoniker *mk,
                                   DWORD *cookie)
{
    struct rot_entry *e;
    HRESULT hr = S_OK;

    if (!cookie) return E_INVALIDARG;
    *cookie = 0;
    if (!object || !mk) return E_INVALIDARG;
    if (flags & ~(ROTFLAGS_REGISTRATIONKEEPSALIVE | ROTFLAGS_ALLOWANYCLIENT)) return E_INVALIDARG;
    if (!(e = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*e)))) return E_OUTOFMEMORY;
    IUnknown_AddRef(object);
    IMoniker_AddRef(mk);
    e->object = object;
    e->moniker = mk;
    GetSystemTimeAsFileTime(&e->last_change);
    EnterCriticalSection(&rot_lock);
    if (find_moniker(mk)) hr = MK_S_MONIKERALREADYREGISTERED;
    e->cookie = ++rot_next_cookie;
    e->next = entries;
    entries = e;
    *cookie = e->cookie;
    LeaveCriticalSection(&rot_lock);
    return hr;
}

static HRESULT WINAPI rot_Revoke(IRunningObjectTable *iface, DWORD cookie)
{
    struct rot_entry **p, *e = NULL;
    EnterCriticalSection(&rot_lock);
    for (p = &entries; *p; p = &(*p)->next)
        if ((*p)->cookie == cookie) { e = *p; *p = e->next; break; }
    LeaveCriticalSection(&rot_lock);
    if (!e) return E_INVALIDARG;
    IUnknown_Release(e->object);
    IMoniker_Release(e->moniker);
    HeapFree(GetProcessHeap(), 0, e);
    return S_OK;
}

static HRESULT WINAPI rot_IsRunning(IRunningObjectTable *iface, IMoniker *mk)
{
    HRESULT hr;
    if (!mk) return E_INVALIDARG;
    EnterCriticalSection(&rot_lock);
    hr = find_moniker(mk) ? S_OK : S_FALSE;
    LeaveCriticalSection(&rot_lock);
    return hr;
}

static HRESULT WINAPI rot_GetObject(IRunningObjectTable *iface, IMoniker *mk, IUnknown **object)
{
    struct rot_entry *e;
    if (!object) return E_INVALIDARG;
    *object = NULL;
    if (!mk) return E_INVALIDARG;
    EnterCriticalSection(&rot_lock);
    if ((e = find_moniker(mk)))
    {
        *object = e->object;
        IUnknown_AddRef(*object);
    }
    LeaveCriticalSection(&rot_lock);
    return *object ? S_OK : MK_E_UNAVAILABLE;
}

static HRESULT WINAPI rot_NoteChangeTime(IRunningObjectTable *iface, DWORD cookie, FILETIME *time)
{
    struct rot_entry *e;
    HRESULT hr = E_INVALIDARG;
    if (!time) return E_INVALIDARG;
    EnterCriticalSection(&rot_lock);
    for (e = entries; e; e = e->next)
        if (e->cookie == cookie) { e->last_change = *time; hr = S_OK; break; }
    LeaveCriticalSection(&rot_lock);
    return hr;
}

static HRESULT WINAPI rot_GetTimeOfLastChange(IRunningObjectTable *iface, IMoniker *mk, FILETIME *time)
{
    struct rot_entry *e;
    HRESULT hr = MK_E_UNAVAILABLE;
    if (!mk || !time) return E_INVALIDARG;
    EnterCriticalSection(&rot_lock);
    if ((e = find_moniker(mk)))
    {
        *time = e->last_change;
        hr = S_OK;
    }
    LeaveCriticalSection(&rot_lock);
    return hr;
}

/* IEnumMoniker over a snapshot of the registered monikers */
struct moniker_enum
{
    IEnumMoniker IEnumMoniker_iface;
    LONG refs;
    ULONG pos, count;
    IMoniker **monikers;
};

static struct moniker_enum *from_IEnumMoniker(IEnumMoniker *iface)
{
    return CONTAINING_RECORD(iface, struct moniker_enum, IEnumMoniker_iface);
}

static HRESULT create_enum(IMoniker **monikers, ULONG count, ULONG pos, IEnumMoniker **out);

static HRESULT WINAPI enum_QueryInterface(IEnumMoniker *iface, REFIID riid, void **obj)
{
    if (!obj) return E_INVALIDARG;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IEnumMoniker))
    {
        *obj = iface;
        IEnumMoniker_AddRef(iface);
        return S_OK;
    }
    *obj = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI enum_AddRef(IEnumMoniker *iface)
{
    return InterlockedIncrement(&from_IEnumMoniker(iface)->refs);
}

static ULONG WINAPI enum_Release(IEnumMoniker *iface)
{
    struct moniker_enum *This = from_IEnumMoniker(iface);
    ULONG refs = InterlockedDecrement(&This->refs), i;
    if (!refs)
    {
        for (i = 0; i < This->count; i++) IMoniker_Release(This->monikers[i]);
        HeapFree(GetProcessHeap(), 0, This->monikers);
        HeapFree(GetProcessHeap(), 0, This);
    }
    return refs;
}

static HRESULT WINAPI enum_Next(IEnumMoniker *iface, ULONG n, IMoniker **out, ULONG *fetched)
{
    struct moniker_enum *This = from_IEnumMoniker(iface);
    ULONG got = 0;
    if (!out || (n > 1 && !fetched)) return E_INVALIDARG;
    while (got < n && This->pos < This->count)
    {
        out[got] = This->monikers[This->pos++];
        IMoniker_AddRef(out[got]);
        got++;
    }
    if (fetched) *fetched = got;
    return got == n ? S_OK : S_FALSE;
}

static HRESULT WINAPI enum_Skip(IEnumMoniker *iface, ULONG n)
{
    struct moniker_enum *This = from_IEnumMoniker(iface);
    if (This->count - This->pos < n)
    {
        This->pos = This->count;
        return S_FALSE;
    }
    This->pos += n;
    return S_OK;
}

static HRESULT WINAPI enum_Reset(IEnumMoniker *iface)
{
    from_IEnumMoniker(iface)->pos = 0;
    return S_OK;
}

static HRESULT WINAPI enum_Clone(IEnumMoniker *iface, IEnumMoniker **out)
{
    struct moniker_enum *This = from_IEnumMoniker(iface);
    ULONG i;
    if (!out) return E_INVALIDARG;
    for (i = 0; i < This->count; i++) IMoniker_AddRef(This->monikers[i]);
    return create_enum(This->monikers, This->count, This->pos, out);
}

static const IEnumMonikerVtbl enum_vtbl =
{
    enum_QueryInterface, enum_AddRef, enum_Release, enum_Next, enum_Skip, enum_Reset, enum_Clone
};

/* takes over one reference on each of the count monikers */
static HRESULT create_enum(IMoniker **monikers, ULONG count, ULONG pos, IEnumMoniker **out)
{
    struct moniker_enum *This = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*This));
    IMoniker **copy = HeapAlloc(GetProcessHeap(), 0, (count ? count : 1) * sizeof(*copy));
    ULONG i;
    *out = NULL;
    if (!This || !copy)
    {
        for (i = 0; i < count; i++) IMoniker_Release(monikers[i]);
        HeapFree(GetProcessHeap(), 0, This);
        HeapFree(GetProcessHeap(), 0, copy);
        return E_OUTOFMEMORY;
    }
    memcpy(copy, monikers, count * sizeof(*copy));
    This->IEnumMoniker_iface.lpVtbl = &enum_vtbl;
    This->refs = 1;
    This->monikers = copy;
    This->count = count;
    This->pos = pos;
    *out = &This->IEnumMoniker_iface;
    return S_OK;
}

static HRESULT WINAPI rot_EnumRunning(IRunningObjectTable *iface, IEnumMoniker **out)
{
    struct rot_entry *e;
    IMoniker **list;
    ULONG n = 0, i = 0;
    HRESULT hr;

    if (!out) return E_INVALIDARG;
    *out = NULL;
    EnterCriticalSection(&rot_lock);
    for (e = entries; e; e = e->next) n++;
    if (!(list = HeapAlloc(GetProcessHeap(), 0, (n ? n : 1) * sizeof(*list))))
    {
        LeaveCriticalSection(&rot_lock);
        return E_OUTOFMEMORY;
    }
    for (e = entries; e; e = e->next)
    {
        list[i] = e->moniker;
        IMoniker_AddRef(list[i++]);
    }
    LeaveCriticalSection(&rot_lock);
    hr = create_enum(list, n, 0, out);
    HeapFree(GetProcessHeap(), 0, list);
    return hr;
}

static const IRunningObjectTableVtbl rot_vtbl =
{
    rot_QueryInterface, rot_AddRef, rot_Release, rot_Register, rot_Revoke, rot_IsRunning, rot_GetObject,
    rot_NoteChangeTime, rot_GetTimeOfLastChange, rot_EnumRunning
};

static IRunningObjectTable rot = { &rot_vtbl };

HRESULT WINAPI GetRunningObjectTable(DWORD reserved, IRunningObjectTable **out)
{
    HRESULT hr;
    if (!out) return E_INVALIDARG;
    *out = NULL;
    if (reserved) return E_UNEXPECTED;
    if ((hr = trt_check_apartment()) != S_OK) return hr;
    *out = &rot;
    return S_OK;
}
