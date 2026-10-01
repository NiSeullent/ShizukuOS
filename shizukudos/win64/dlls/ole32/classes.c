/* SPDX-License-Identifier: GPL-2.0-only
 * ole32.dll: the in-process class table and object activation, proxy/security/message-filter entry points.
 *
 * There is no COM class store (no registry of CLSIDs, no out-of-process servers, no RPC). What exists is exactly what a
 * process registers itself: CoRegisterClassObject puts a class factory into a process-wide table (CLSCTX_INPROC_SERVER
 * and CLSCTX_LOCAL_SERVER contexts, REGCLS_MULTIPLEUSE/SINGLEUSE/SUSPENDED honoured: a suspended registration is found
 * only after CoResumeClassObjects, a single-use one is revoked after its first CoGetClassObject), CoRevokeClassObject
 * removes it, and CoGetClassObject / CoCreateInstance / CoCreateInstanceEx find classes there. Every other CLSID is
 * REGDB_E_CLASSNOTREG - the documented answer for a class that is not registered, and what Chromium's callers
 * (net::NetworkChangeNotifierWin asking for CLSID_NetworkListManager, ...) treat as "feature unavailable".
 * All activation requires an initialised apartment on the calling thread (CO_E_NOTINITIALIZED otherwise).
 *
 * CLSIDFromProgID: a "{clsid}" string is accepted (as on Windows); a real ProgID needs the registry that does not exist:
 * CO_E_CLASSSTRING. ProgIDFromCLSID: REGDB_E_CLASSNOTREG.
 * CoGetObjectContext: no context objects exist: E_NOINTERFACE (CO_E_NOTINITIALIZED without an apartment).
 * CoSetProxyBlanket: there are no proxies; an object that does not implement IClientSecurity gives E_NOINTERFACE,
 * which is what Windows answers for a direct (non-proxy) pointer. CoAllowSetForegroundWindow: IForegroundTransfer
 * through QueryInterface, E_NOINTERFACE when the object lacks it (as documented). OleLockRunning: S_OK for an object
 * without IRunnableObject (as documented), else IRunnableObject::LockRunning.
 * CoRegisterMessageFilter: per STA thread, the previous filter is returned (CO_E_NOT_SUPPORTED in the MTA); no call ever
 * goes through a filter here because no call is ever marshalled.
 */
#include "ole32_int.h"

#define REGDB_E_CLASSNOTREG_ ((HRESULT)0x80040154)
#define CO_E_NOTINITIALIZED_ ((HRESULT)0x800401F0)
#define CO_E_CLASSSTRING_ ((HRESULT)0x800401F3)
#define CO_E_NOT_SUPPORTED_ ((HRESULT)0x80004021)
#define E_NOINTERFACE_ ((HRESULT)0x80004002)
#define E_INVALIDARG_ ((HRESULT)0x80070057)
#define E_OUTOFMEMORY_ ((HRESULT)0x8007000E)
#define E_POINTER_ ((HRESULT)0x80004003)
#define CLASS_E_NOAGGREGATION_ ((HRESULT)0x80040110)

static const GUID iid_classfactory = { 0x00000001, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID iid_clientsecurity = { 0x0000013D, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID iid_foregroundtransfer = { 0x00000145, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID iid_runnableobject = { 0x00000126, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID iid_messagefilter = { 0x00000016, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

int shz_apt_active(void)
{
    APTTYPE t;
    APTTYPEQUALIFIER q;
    return CoGetApartmentType(&t, &q) == S_OK;
}

static int shz_apt_is_sta(void)
{
    APTTYPE t;
    APTTYPEQUALIFIER q;
    return CoGetApartmentType(&t, &q) == S_OK && (t == APTTYPE_STA || t == APTTYPE_MAINSTA);
}

/* ---------------------------------------------------------------- class table */
typedef struct class_entry {
    struct class_entry *next;
    CLSID clsid;
    IUnknown *factory;
    DWORD ctx, flags, cookie;
    int suspended;
} class_entry;

static SRWLOCK g_class_lock = SRWLOCK_INIT;
static class_entry *g_classes;
static DWORD g_next_cookie = 1;

DLLAPI HRESULT WINAPI CoRegisterClassObject(REFCLSID clsid, IUnknown *unk, DWORD ctx, DWORD flags, DWORD *cookie)
{
    class_entry *e;
    if (!clsid || !unk || !cookie) return E_INVALIDARG_;
    *cookie = 0;
    if (!shz_apt_active()) return CO_E_NOTINITIALIZED_;
    if (!(ctx & (CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER))) return E_INVALIDARG_;
    e = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *e);
    if (!e) return E_OUTOFMEMORY_;
    e->clsid = *clsid;
    e->factory = unk;
    IUnknown_AddRef(unk);
    e->ctx = ctx;
    e->flags = flags;
    e->suspended = (flags & REGCLS_SUSPENDED) != 0;
    AcquireSRWLockExclusive(&g_class_lock);
    e->cookie = g_next_cookie++;
    e->next = g_classes;
    g_classes = e;
    ReleaseSRWLockExclusive(&g_class_lock);
    *cookie = e->cookie;
    return S_OK;
}

DLLAPI HRESULT WINAPI CoRevokeClassObject(DWORD cookie)
{
    class_entry *e, **pp;
    if (!shz_apt_active()) return CO_E_NOTINITIALIZED_;
    AcquireSRWLockExclusive(&g_class_lock);
    for (pp = &g_classes; (e = *pp) != 0; pp = &e->next)
        if (e->cookie == cookie) { *pp = e->next; break; }
    ReleaseSRWLockExclusive(&g_class_lock);
    if (!e) return E_INVALIDARG_;
    IUnknown_Release(e->factory);
    HeapFree(GetProcessHeap(), 0, e);
    return S_OK;
}

DLLAPI HRESULT WINAPI CoResumeClassObjects(void)
{
    class_entry *e;
    if (!shz_apt_active()) return CO_E_NOTINITIALIZED_;
    AcquireSRWLockExclusive(&g_class_lock);
    for (e = g_classes; e; e = e->next) e->suspended = 0;
    ReleaseSRWLockExclusive(&g_class_lock);
    return S_OK;
}

DLLAPI HRESULT WINAPI CoSuspendClassObjects(void)
{
    class_entry *e;
    if (!shz_apt_active()) return CO_E_NOTINITIALIZED_;
    AcquireSRWLockExclusive(&g_class_lock);
    for (e = g_classes; e; e = e->next) e->suspended = 1;
    ReleaseSRWLockExclusive(&g_class_lock);
    return S_OK;
}

DLLAPI HRESULT WINAPI CoGetClassObject(REFCLSID clsid, DWORD ctx, LPVOID reserved, REFIID iid, LPVOID *out)
{
    class_entry *e, **pp;
    IUnknown *factory = 0;
    int single = 0;
    HRESULT hr;
    (void)reserved;
    if (!out) return E_POINTER_;
    *out = 0;
    if (!clsid || !iid) return E_INVALIDARG_;
    if (!shz_apt_active()) return CO_E_NOTINITIALIZED_;
    AcquireSRWLockExclusive(&g_class_lock);
    for (pp = &g_classes; (e = *pp) != 0; pp = &e->next) {
        if (memcmp(&e->clsid, clsid, sizeof(CLSID)) || e->suspended || !(e->ctx & ctx)) continue;
        factory = e->factory;
        IUnknown_AddRef(factory);
        if (!(e->flags & (REGCLS_MULTIPLEUSE | REGCLS_MULTI_SEPARATE))) {           /* REGCLS_SINGLEUSE = 0 */ *pp = e->next; single = 1; }
        break;
    }
    ReleaseSRWLockExclusive(&g_class_lock);
    if (!factory) return REGDB_E_CLASSNOTREG_;
    hr = IUnknown_QueryInterface(factory, iid, out);
    IUnknown_Release(factory);
    if (single) { IUnknown_Release(e->factory); HeapFree(GetProcessHeap(), 0, e); }
    return hr;
}

DLLAPI HRESULT WINAPI CoCreateInstance(REFCLSID clsid, IUnknown *outer, DWORD ctx, REFIID iid, LPVOID *out)
{
    IClassFactory *cf = 0;
    HRESULT hr;
    if (!out) return E_POINTER_;
    *out = 0;
    if (!clsid || !iid) return E_INVALIDARG_;
    if (outer && memcmp(iid, &shz_iid_unknown, sizeof(IID))) return CLASS_E_NOAGGREGATION_;   /* aggregation asks for IUnknown */
    hr = CoGetClassObject(clsid, ctx, 0, &iid_classfactory, (void **)&cf);
    if (FAILED(hr)) return hr;
    hr = IClassFactory_CreateInstance(cf, outer, iid, out);
    IClassFactory_Release(cf);
    return hr;
}

DLLAPI HRESULT WINAPI CoCreateInstanceEx(REFCLSID clsid, IUnknown *outer, DWORD ctx, COSERVERINFO *server, DWORD count, MULTI_QI *results)
{
    IUnknown *unk = 0;
    HRESULT hr;
    DWORD i, ok = 0;
    if (!clsid || !results || !count) return E_INVALIDARG_;
    for (i = 0; i < count; ++i) { results[i].pItf = 0; results[i].hr = E_NOINTERFACE_; }
    if (server && server->pwszName && server->pwszName[0]) return REGDB_E_CLASSNOTREG_;      /* no remote activation */
    hr = CoCreateInstance(clsid, outer, ctx, &shz_iid_unknown, (void **)&unk);
    if (FAILED(hr)) return hr;
    for (i = 0; i < count; ++i) {
        results[i].hr = IUnknown_QueryInterface(unk, results[i].pIID, (void **)&results[i].pItf);
        if (SUCCEEDED(results[i].hr)) ++ok;
    }
    IUnknown_Release(unk);
    return ok == count ? S_OK : ok ? CO_S_NOTALLINTERFACES : E_NOINTERFACE_;
}

/* ---------------------------------------------------------------- ProgIDs */
DLLAPI HRESULT WINAPI CLSIDFromProgID(LPCOLESTR progid, LPCLSID out)
{
    if (!progid || !out) return E_INVALIDARG_;
    if (progid[0] == '{') return CLSIDFromString(progid, out);
    memset(out, 0, sizeof *out);
    return CO_E_CLASSSTRING_;
}

DLLAPI HRESULT WINAPI CLSIDFromProgIDEx(LPCOLESTR progid, LPCLSID out) { return CLSIDFromProgID(progid, out); }

DLLAPI HRESULT WINAPI ProgIDFromCLSID(REFCLSID clsid, LPOLESTR *out)
{
    if (!clsid || !out) return E_INVALIDARG_;
    *out = 0;
    return REGDB_E_CLASSNOTREG_;
}

/* ---------------------------------------------------------------- contexts, proxies, running objects */
DLLAPI HRESULT WINAPI CoGetObjectContext(REFIID iid, LPVOID *out)
{
    if (!out) return E_POINTER_;
    *out = 0;
    if (!iid) return E_INVALIDARG_;
    if (!shz_apt_active()) return CO_E_NOTINITIALIZED_;
    return E_NOINTERFACE_;
}

DLLAPI HRESULT WINAPI CoSetProxyBlanket(IUnknown *proxy, DWORD authn, DWORD authz, OLECHAR *server, DWORD level, DWORD imp, RPC_AUTH_IDENTITY_HANDLE identity, DWORD caps)
{
    IClientSecurity *cs = 0;
    HRESULT hr;
    if (!proxy) return E_INVALIDARG_;
    hr = IUnknown_QueryInterface(proxy, &iid_clientsecurity, (void **)&cs);
    if (FAILED(hr)) return E_NOINTERFACE_;
    hr = IClientSecurity_SetBlanket(cs, proxy, authn, authz, server, level, imp, identity, caps);
    IClientSecurity_Release(cs);
    return hr;
}

DLLAPI HRESULT WINAPI CoQueryProxyBlanket(IUnknown *proxy, DWORD *authn, DWORD *authz, OLECHAR **server, DWORD *level, DWORD *imp, RPC_AUTH_IDENTITY_HANDLE *identity, DWORD *caps)
{
    IClientSecurity *cs = 0;
    HRESULT hr;
    if (!proxy) return E_INVALIDARG_;
    hr = IUnknown_QueryInterface(proxy, &iid_clientsecurity, (void **)&cs);
    if (FAILED(hr)) return E_NOINTERFACE_;
    hr = IClientSecurity_QueryBlanket(cs, proxy, authn, authz, server, level, imp, identity, caps);
    IClientSecurity_Release(cs);
    return hr;
}

DLLAPI HRESULT WINAPI CoAllowSetForegroundWindow(IUnknown *unk, LPVOID reserved)
{
    IForegroundTransfer *ft = 0;
    HRESULT hr;
    (void)reserved;
    if (!unk) return E_INVALIDARG_;
    hr = IUnknown_QueryInterface(unk, &iid_foregroundtransfer, (void **)&ft);
    if (FAILED(hr)) return E_NOINTERFACE_;
    hr = IForegroundTransfer_AllowForegroundTransfer(ft, 0);
    IForegroundTransfer_Release(ft);
    return hr;
}

DLLAPI HRESULT WINAPI OleLockRunning(LPUNKNOWN unk, BOOL lock, BOOL last_unlock_closes)
{
    IRunnableObject *ro = 0;
    HRESULT hr;
    if (!unk) return E_INVALIDARG_;
    if (FAILED(IUnknown_QueryInterface(unk, &iid_runnableobject, (void **)&ro))) return S_OK;      /* documented */
    hr = IRunnableObject_LockRunning(ro, lock, last_unlock_closes);
    IRunnableObject_Release(ro);
    return hr;
}

DLLAPI BOOL WINAPI OleIsRunning(LPOLEOBJECT obj)
{
    IRunnableObject *ro = 0;
    BOOL running;
    if (!obj) return FALSE;
    if (FAILED(IUnknown_QueryInterface((IUnknown *)obj, &iid_runnableobject, (void **)&ro))) return TRUE;   /* documented: not runnable = running */
    running = IRunnableObject_IsRunning(ro);
    IRunnableObject_Release(ro);
    return running;
}

/* ---------------------------------------------------------------- message filter (per STA thread) */
static DWORD g_filter_tls = TLS_OUT_OF_INDEXES;
static LONG g_filter_tls_init;

static DWORD filter_slot(void)
{
    if (g_filter_tls == TLS_OUT_OF_INDEXES && InterlockedCompareExchange(&g_filter_tls_init, 1, 0) == 0) g_filter_tls = TlsAlloc();
    while (g_filter_tls == TLS_OUT_OF_INDEXES && g_filter_tls_init) SwitchToThread();
    return g_filter_tls;
}

DLLAPI HRESULT WINAPI CoRegisterMessageFilter(LPMESSAGEFILTER filter, LPMESSAGEFILTER *old)
{
    DWORD slot;
    IMessageFilter *prev;
    if (old) *old = 0;
    if (!shz_apt_active()) return CO_E_NOTINITIALIZED_;
    if (!shz_apt_is_sta()) return CO_E_NOT_SUPPORTED_;
    slot = filter_slot();
    if (slot == TLS_OUT_OF_INDEXES) return E_OUTOFMEMORY_;
    prev = TlsGetValue(slot);
    if (filter) IUnknown_AddRef((IUnknown *)filter);
    TlsSetValue(slot, filter);
    if (old) *old = prev; else if (prev) IUnknown_Release((IUnknown *)prev);
    (void)iid_messagefilter;
    return S_OK;
}

/* No allocation or filter registration side effect. The registered per-thread
 * reference remains valid while AddRef runs; the caller's extra reference
 * then protects MessagePending against reentrant replacement/unregistration. */
IMessageFilter *shz_message_filter_snapshot(void)
{
    IMessageFilter *filter;
    if (g_filter_tls == TLS_OUT_OF_INDEXES) return NULL;
    filter = TlsGetValue(g_filter_tls);
    if (filter) IMessageFilter_AddRef(filter);
    return filter;
}
