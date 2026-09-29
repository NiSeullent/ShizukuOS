/* SPDX-License-Identifier: GPL-2.0-only
 * COM task allocator: CoTaskMemAlloc/Realloc/Free on the process heap, and the IMalloc object CoGetMalloc(MEMCTX_TASK) hands
 * out. One process, one allocator: memory allocated with any of these may be released with any other.
 */
#include "ole32_int.h"

const GUID shz_iid_unknown = { 0x00000000, 0x0000, 0x0000, { 0xc0, 0, 0, 0, 0, 0, 0, 0x46 } };
const GUID shz_iid_malloc = { 0x00000002, 0x0000, 0x0000, { 0xc0, 0, 0, 0, 0, 0, 0, 0x46 } };
const GUID shz_iid_initializespy = { 0x00000034, 0x0000, 0x0000, { 0xc0, 0, 0, 0, 0, 0, 0, 0x46 } };

DLLAPI LPVOID WINAPI CoTaskMemAlloc(SIZE_T size) { return HeapAlloc(GetProcessHeap(), 0, size ? size : 1); }

DLLAPI void WINAPI CoTaskMemFree(LPVOID p)
{
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

DLLAPI LPVOID WINAPI CoTaskMemRealloc(LPVOID p, SIZE_T size)
{
    if (!p) return CoTaskMemAlloc(size);
    if (!size) { CoTaskMemFree(p); return 0; }                     /* documented: size 0 frees the block and returns NULL */
    return HeapReAlloc(GetProcessHeap(), 0, p, size);
}

/* ---- IMalloc ---- */
static HRESULT STDMETHODCALLTYPE m_qi(IMalloc *This, REFIID riid, void **out)
{
    if (!out) return E_POINTER;
    if (!memcmp(riid, &shz_iid_unknown, sizeof(GUID)) || !memcmp(riid, &shz_iid_malloc, sizeof(GUID))) {
        *out = This;
        return S_OK;                                               /* one static object: no reference counting needed */
    }
    *out = 0;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE m_addref(IMalloc *This) { (void)This; return 1; }
static ULONG STDMETHODCALLTYPE m_release(IMalloc *This) { (void)This; return 1; }
static void *STDMETHODCALLTYPE m_alloc(IMalloc *This, SIZE_T cb) { (void)This; return CoTaskMemAlloc(cb); }
static void *STDMETHODCALLTYPE m_realloc(IMalloc *This, void *pv, SIZE_T cb) { (void)This; return CoTaskMemRealloc(pv, cb); }
static void STDMETHODCALLTYPE m_free(IMalloc *This, void *pv) { (void)This; CoTaskMemFree(pv); }
static SIZE_T STDMETHODCALLTYPE m_getsize(IMalloc *This, void *pv)
{
    (void)This;
    return pv ? HeapSize(GetProcessHeap(), 0, pv) : (SIZE_T)-1;    /* documented: -1 for a NULL pointer */
}
static int STDMETHODCALLTYPE m_didalloc(IMalloc *This, void *pv)
{
    (void)This;
    if (!pv) return 0;
    return HeapValidate(GetProcessHeap(), 0, pv) ? 1 : 0;
}
static void STDMETHODCALLTYPE m_heapminimize(IMalloc *This) { (void)This; }

static const IMallocVtbl g_malloc_vtbl = { m_qi, m_addref, m_release, m_alloc, m_realloc, m_free, m_getsize, m_didalloc, m_heapminimize };
static IMalloc g_malloc = { (IMallocVtbl *)&g_malloc_vtbl };

DLLAPI HRESULT WINAPI CoGetMalloc(DWORD ctx, LPMALLOC *out)
{
    if (!out) return E_POINTER;
    *out = 0;
    if (ctx != MEMCTX_TASK) return E_INVALIDARG;                   /* only the task allocator exists */
    *out = &g_malloc;
    return S_OK;
}
