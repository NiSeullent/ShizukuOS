/* SPDX-License-Identifier: GPL-2.0-only
 * COM apartment bookkeeping. This system has no RPC/marshaling layer, so an "apartment" is exactly what it is to a program
 * that only uses CoInitialize/CoUninitialize: a per-thread model (STA or MTA) with a reference count.
 *
 * CoInitializeEx: first call on a thread -> S_OK; a further call with the same model -> S_FALSE (count + 1); a different
 * model -> RPC_E_CHANGED_MODE (count unchanged). CoUninitialize decrements; at zero the thread leaves its apartment.
 * A CoUninitialize on a thread that never initialised does nothing.
 * The first STA thread of the process is the main STA (APTTYPE_MAINSTA) until it uninitialises. A thread that has not
 * initialised COM while some other thread is in the MTA is in the implicit MTA (APTTYPEQUALIFIER_IMPLICIT_MTA).
 *
 * Initialize spies (CoRegisterInitializeSpy) are per thread, as documented: PreInitialize/PostInitialize bracket
 * CoInitializeEx and PreUninitialize/PostUninitialize bracket CoUninitialize with the thread's apartment reference count;
 * the return values of the spy methods are ignored.
 */
#include "ole32_int.h"

enum { MODEL_NONE = 0, MODEL_STA = 1, MODEL_MTA = 2 };

typedef struct spy_entry { struct spy_entry *next; IInitializeSpy *spy; ULONG serial; } spy_entry;
typedef struct { int model; ULONG inits, ole_inits; int is_main_sta; spy_entry *spies; ULONG next_serial; } com_tls;

static DWORD g_tls = TLS_OUT_OF_INDEXES;
static CRITICAL_SECTION g_lock;
static ULONG g_mta_threads;
static DWORD g_main_sta_tid;
static volatile LONG g_server_refs;

static com_tls *tls_get(int create)
{
    com_tls *t;
    if (g_tls == TLS_OUT_OF_INDEXES) return 0;
    t = TlsGetValue(g_tls);
    if (!t && create) {
        t = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *t);
        if (t) TlsSetValue(g_tls, t);
    }
    return t;
}

static void leave_apartment(com_tls *t)
{
    EnterCriticalSection(&g_lock);
    if (t->model == MODEL_MTA && g_mta_threads) --g_mta_threads;
    if (t->is_main_sta) { g_main_sta_tid = 0; t->is_main_sta = 0; }
    LeaveCriticalSection(&g_lock);
    t->model = MODEL_NONE;
}

static void thread_cleanup(void)
{
    com_tls *t = tls_get(0);
    if (!t) return;
    while (t->spies) {
        spy_entry *e = t->spies;
        t->spies = e->next;
        IInitializeSpy_Release(e->spy);
        HeapFree(GetProcessHeap(), 0, e);
    }
    if (t->model != MODEL_NONE) leave_apartment(t);
    TlsSetValue(g_tls, 0);
    HeapFree(GetProcessHeap(), 0, t);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID res)
{
    (void)h; (void)res;
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        InitializeCriticalSection(&g_lock);
        g_tls = TlsAlloc();
        return g_tls != TLS_OUT_OF_INDEXES;
    case DLL_THREAD_DETACH:
        thread_cleanup();
        break;
    case DLL_PROCESS_DETACH:
        thread_cleanup();
        break;
    }
    return TRUE;
}

DLLAPI HRESULT WINAPI CoInitializeEx(LPVOID reserved, DWORD coinit)
{
    com_tls *t;
    spy_entry *e;
    int model;
    HRESULT hr;
    if (reserved) return E_INVALIDARG;
    if (coinit & ~(DWORD)(COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE | COINIT_SPEED_OVER_MEMORY)) return E_INVALIDARG;
    t = tls_get(1);
    if (!t) return E_OUTOFMEMORY;
    model = (coinit & COINIT_APARTMENTTHREADED) ? MODEL_STA : MODEL_MTA;
    for (e = t->spies; e; e = e->next) IInitializeSpy_PreInitialize(e->spy, coinit, t->inits);
    if (t->model == MODEL_NONE) {
        EnterCriticalSection(&g_lock);
        if (model == MODEL_STA) {
            if (!g_main_sta_tid) { g_main_sta_tid = GetCurrentThreadId(); t->is_main_sta = 1; }
        } else {
            ++g_mta_threads;
        }
        LeaveCriticalSection(&g_lock);
        t->model = model;
        t->inits = 1;
        hr = S_OK;
    } else if (t->model == model) {
        ++t->inits;
        hr = S_FALSE;
    } else {
        hr = RPC_E_CHANGED_MODE;
    }
    for (e = t->spies; e; e = e->next) IInitializeSpy_PostInitialize(e->spy, hr, coinit, t->inits);
    return hr;
}

DLLAPI HRESULT WINAPI CoInitialize(LPVOID reserved) { return CoInitializeEx(reserved, COINIT_APARTMENTTHREADED); }

DLLAPI void WINAPI CoUninitialize(void)
{
    com_tls *t = tls_get(0);
    spy_entry *e;
    if (!t || !t->inits) return;                                  /* unbalanced call: nothing to undo */
    for (e = t->spies; e; e = e->next) IInitializeSpy_PreUninitialize(e->spy, t->inits);
    if (--t->inits == 0) leave_apartment(t);
    for (e = t->spies; e; e = e->next) IInitializeSpy_PostUninitialize(e->spy, t->inits);
}

DLLAPI HRESULT WINAPI CoGetApartmentType(APTTYPE *type, APTTYPEQUALIFIER *qual)
{
    com_tls *t = tls_get(0);
    if (!type || !qual) return E_INVALIDARG;
    if (t && t->model == MODEL_STA) {
        *type = t->is_main_sta ? APTTYPE_MAINSTA : APTTYPE_STA;
        *qual = APTTYPEQUALIFIER_NONE;
        return S_OK;
    }
    if (t && t->model == MODEL_MTA) {
        *type = APTTYPE_MTA;
        *qual = APTTYPEQUALIFIER_NONE;
        return S_OK;
    }
    EnterCriticalSection(&g_lock);
    {
        const ULONG mta = g_mta_threads;
        LeaveCriticalSection(&g_lock);
        if (mta) {                                                /* another thread's MTA is visible to every thread */
            *type = APTTYPE_MTA;
            *qual = APTTYPEQUALIFIER_IMPLICIT_MTA;
            return S_OK;
        }
    }
    return CO_E_NOTINITIALIZED;
}

DLLAPI ULONG WINAPI CoAddRefServerProcess(void) { return (ULONG)InterlockedIncrement((LONG *)&g_server_refs); }

DLLAPI ULONG WINAPI CoReleaseServerProcess(void)
{
    LONG v;
    do {
        v = g_server_refs;
        if (v <= 0) return 0;                                      /* unbalanced: stays 0 */
    } while (InterlockedCompareExchange((LONG *)&g_server_refs, v - 1, v) != v);
    return (ULONG)(v - 1);                                         /* at 0 the (nonexistent) class objects would be suspended */
}

DLLAPI HRESULT WINAPI CoRegisterInitializeSpy(IInitializeSpy *spy, ULARGE_INTEGER *cookie)
{
    com_tls *t;
    spy_entry *e;
    IInitializeSpy *own = 0;
    HRESULT hr;
    if (!spy || !cookie) return E_INVALIDARG;
    hr = IInitializeSpy_QueryInterface(spy, &shz_iid_initializespy, (void **)&own);
    if (FAILED(hr)) return hr;
    t = tls_get(1);
    e = t ? HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *e) : 0;
    if (!e) { IInitializeSpy_Release(own); return E_OUTOFMEMORY; }
    e->spy = own;
    e->serial = ++t->next_serial;
    e->next = t->spies;
    t->spies = e;
    cookie->HighPart = GetCurrentThreadId();                       /* documented: the cookie names the registering thread */
    cookie->LowPart = e->serial;
    return S_OK;
}

DLLAPI HRESULT WINAPI CoRevokeInitializeSpy(ULARGE_INTEGER cookie)
{
    com_tls *t = tls_get(0);
    spy_entry **pp, *e;
    if (!t || cookie.HighPart != GetCurrentThreadId()) return E_INVALIDARG;
    for (pp = &t->spies; (e = *pp) != 0; pp = &e->next) {
        if (e->serial == cookie.LowPart) {
            *pp = e->next;
            IInitializeSpy_Release(e->spy);
            HeapFree(GetProcessHeap(), 0, e);
            return S_OK;
        }
    }
    return E_INVALIDARG;
}

/* OleInitialize/OleUninitialize: the STA apartment plus OLE's own reference count. No OLE services (clipboard, drag and
 * drop, in-place activation) exist here; nothing that would need them is exported. */
DLLAPI HRESULT WINAPI OleInitialize(LPVOID reserved)
{
    com_tls *t;
    HRESULT hr = CoInitializeEx(reserved, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return hr;
    t = tls_get(0);
    if (t) ++t->ole_inits;
    return hr;
}

DLLAPI void WINAPI OleUninitialize(void)
{
    com_tls *t = tls_get(0);
    if (!t || !t->ole_inits) return;
    --t->ole_inits;
    CoUninitialize();
}
