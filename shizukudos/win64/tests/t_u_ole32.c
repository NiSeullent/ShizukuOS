/* SPDX-License-Identifier: GPL-2.0-only
 * ole32.dll core without a class registry: apartments, initialize spies, task allocator, IMalloc, GUID text conversion,
 * CoCreateGuid, PROPVARIANT clear/copy, OleInitialize counting. Expected values are the documented COM contracts
 * (CoInitializeEx S_OK / S_FALSE / RPC_E_CHANGED_MODE, StringFromGUID2 returning 39, CO_E_CLASSSTRING, MSDN
 * IInitializeSpy argument meaning, IMalloc semantics, PropVariant ownership) checked behaviourally, including from
 * several threads. CoCreateInstance and friends are deliberately absent from ole32.dll and therefore from this test. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ole2.h>
#include <oleauto.h>
#include <propidl.h>
#include "u_check.h"

#define ST_NOTINIT ((HRESULT)0x800401F0)
#define ST_CLASSSTRING ((HRESULT)0x800401F3)
#define ST_IIDSTRING ((HRESULT)0x800401F4)
#define ST_CHANGED_MODE ((HRESULT)0x80010106)
#define ST_INVALIDPARAM ((HRESULT)0x80030057)

static const GUID G_UNKNOWN = { 0x00000000, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID G_DNS = { 0x6ba7b810, 0x9dad, 0x11d1, { 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8 } };
static const GUID IID_MALLOC = { 0x00000002, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID IID_SPY = { 0x00000034, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

static int has_rdrand(void)
{
    unsigned a = 1, b = 0, c = 0, d = 0;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
    return (c >> 30) & 1;
}

/* ---- reference-counting COM object ---- */
typedef struct { const IDispatchVtbl *lpVtbl; LONG refs; } fake_t;
static HRESULT STDMETHODCALLTYPE f_qi(IDispatch *t, REFIID r, void **o) { (void)t; (void)r; *o = 0; return E_NOINTERFACE; }
static ULONG STDMETHODCALLTYPE f_addref(IDispatch *t) { return (ULONG)++((fake_t *)t)->refs; }
static ULONG STDMETHODCALLTYPE f_release(IDispatch *t) { return (ULONG)--((fake_t *)t)->refs; }
static HRESULT STDMETHODCALLTYPE f_count(IDispatch *t, UINT *n) { (void)t; *n = 0; return S_OK; }
static HRESULT STDMETHODCALLTYPE f_typeinfo(IDispatch *t, UINT i, LCID l, ITypeInfo **o) { (void)t; (void)i; (void)l; *o = 0; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE f_ids(IDispatch *t, REFIID r, LPOLESTR *n, UINT c, LCID l, DISPID *d) { (void)t; (void)r; (void)n; (void)c; (void)l; (void)d; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE f_invoke(IDispatch *t, DISPID d, REFIID r, LCID l, WORD f, DISPPARAMS *p, VARIANT *v, EXCEPINFO *e, UINT *u)
{ (void)t; (void)d; (void)r; (void)l; (void)f; (void)p; (void)v; (void)e; (void)u; return E_NOTIMPL; }
static const IDispatchVtbl fake_vtbl = { f_qi, f_addref, f_release, f_count, f_typeinfo, f_ids, f_invoke };

/* ---- initialize spy that records what it is told ---- */
typedef struct { const IInitializeSpyVtbl *lpVtbl; LONG refs; int n; struct { char kind; DWORD a, b, c; } ev[16]; } spy_t;
static HRESULT STDMETHODCALLTYPE s_qi(IInitializeSpy *t, REFIID r, void **o)
{
    if (!memcmp(r, &IID_SPY, sizeof(GUID)) || !memcmp(r, &G_UNKNOWN, sizeof(GUID))) { *o = t; ((spy_t *)t)->refs++; return S_OK; }
    *o = 0;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE s_addref(IInitializeSpy *t) { return (ULONG)++((spy_t *)t)->refs; }
static ULONG STDMETHODCALLTYPE s_release(IInitializeSpy *t) { return (ULONG)--((spy_t *)t)->refs; }
static void rec(IInitializeSpy *t, char k, DWORD a, DWORD b, DWORD c) { spy_t *s = (spy_t *)t; if (s->n < 16) { s->ev[s->n].kind = k; s->ev[s->n].a = a; s->ev[s->n].b = b; s->ev[s->n].c = c; } ++s->n; }
static HRESULT STDMETHODCALLTYPE s_pre(IInitializeSpy *t, DWORD coinit, DWORD refs) { rec(t, 'P', coinit, refs, 0); return S_OK; }
static HRESULT STDMETHODCALLTYPE s_post(IInitializeSpy *t, HRESULT hr, DWORD coinit, DWORD refs) { rec(t, 'Q', (DWORD)hr, coinit, refs); return hr; }
static HRESULT STDMETHODCALLTYPE s_preun(IInitializeSpy *t, DWORD refs) { rec(t, 'U', refs, 0, 0); return S_OK; }
static HRESULT STDMETHODCALLTYPE s_postun(IInitializeSpy *t, DWORD refs) { rec(t, 'V', refs, 0, 0); return S_OK; }
static const IInitializeSpyVtbl spy_vtbl = { s_qi, s_addref, s_release, s_pre, s_post, s_preun, s_postun };

static int spy_is(const spy_t *s, int idx, char k, DWORD a, DWORD b, DWORD c) { return idx < s->n && s->ev[idx].kind == k && s->ev[idx].a == a && s->ev[idx].b == b && s->ev[idx].c == c; }

/* ---- worker thread machinery ---- */
typedef struct { HANDLE ready, release; volatile LONG stage; HRESULT hr[8]; APTTYPE at[4]; APTTYPEQUALIFIER aq[4]; int mode; } worker_t;

static DWORD WINAPI worker(LPVOID p)
{
    worker_t *w = p;
    APTTYPE t = (APTTYPE)-9;
    APTTYPEQUALIFIER q = (APTTYPEQUALIFIER)-9;
    w->hr[0] = CoGetApartmentType(&t, &q);                                  /* before this thread initialised anything */
    w->at[0] = t; w->aq[0] = q;
    if (w->mode == 0) {                                                       /* STA, then park until released, then uninitialise */
        w->hr[1] = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
        t = (APTTYPE)-9; q = (APTTYPEQUALIFIER)-9;
        w->hr[2] = CoGetApartmentType(&t, &q);
        w->at[1] = t; w->aq[1] = q;
        SetEvent(w->ready);
        if (w->release) WaitForSingleObject(w->release, 10000);
        CoUninitialize();
    } else if (w->mode == 1) {                                                /* MTA and exit WITHOUT CoUninitialize */
        w->hr[1] = CoInitializeEx(0, COINIT_MULTITHREADED);
        SetEvent(w->ready);
    } else if (w->mode == 3) {                                                /* only observe the apartment state before any initialisation */
        SetEvent(w->ready);
    } else if (w->mode == 2) {                                                /* try to revoke a spy registered on another thread */
        ULARGE_INTEGER *c = (ULARGE_INTEGER *)w->release;
        w->hr[1] = CoRevokeInitializeSpy(*c);
        SetEvent(w->ready);
    }
    return 0;
}

static HANDLE start_worker(worker_t *w, int mode, int with_release)
{
    memset(w, 0, sizeof *w);
    w->mode = mode;
    w->ready = CreateEventW(0, TRUE, FALSE, 0);
    w->release = with_release ? CreateEventW(0, TRUE, FALSE, 0) : 0;
    return CreateThread(0, 0, worker, w, 0, 0);
}

int main(void)
{
    WCHAR buf[64];
    /* ================================================================ GUID text */
    U_CHECK("StringFromGUID2 returns 39 and upper-case braced text (IID_IUnknown)",
            StringFromGUID2(&G_UNKNOWN, buf, 64) == 39 && u_ascii_eq_w(buf, "{00000000-0000-0000-C000-000000000046}"));
    U_CHECK("StringFromGUID2 (RFC 4122 DNS namespace UUID)", StringFromGUID2(&G_DNS, buf, 39) == 39 && u_ascii_eq_w(buf, "{6BA7B810-9DAD-11D1-80B4-00C04FD430C8}"));
    U_CHECK("StringFromGUID2 with cchMax 38 returns 0", StringFromGUID2(&G_DNS, buf, 38) == 0);
    {
        LPOLESTR s = 0;
        U_CHECK("StringFromCLSID allocates the text", StringFromCLSID(&G_DNS, &s) == S_OK && s && u_ascii_eq_w(s, "{6BA7B810-9DAD-11D1-80B4-00C04FD430C8}"));
        CoTaskMemFree(s);
        s = 0;
        U_CHECK("StringFromIID allocates the text", StringFromIID(&G_UNKNOWN, &s) == S_OK && s && u_ascii_eq_w(s, "{00000000-0000-0000-C000-000000000046}"));
        CoTaskMemFree(s);
        U_CHECK("StringFromCLSID(NULL output) is E_POINTER", StringFromCLSID(&G_DNS, 0) == E_POINTER);
    }
    {
        GUID g;
        HRESULT hr;
        memset(&g, 0xcc, sizeof g);
        hr = CLSIDFromString(L"{6ba7b810-9dad-11d1-80b4-00c04fd430c8}", &g);
        U_CHECK("CLSIDFromString accepts lower-case hex", hr == S_OK && !memcmp(&g, &G_DNS, sizeof g));
        hr = CLSIDFromString(L"{6BA7B810-9DAD-11D1-80B4-00C04FD430C8}", &g);
        U_CHECK("CLSIDFromString accepts upper-case hex", hr == S_OK && !memcmp(&g, &G_DNS, sizeof g));
        U_CHECK("CLSIDFromString(NULL) is CLSID_NULL with S_OK", CLSIDFromString(0, &g) == S_OK && g.Data1 == 0 && g.Data2 == 0 && g.Data3 == 0 && g.Data4[7] == 0);
        {
            static const WCHAR *const bad[] = {
                L"6ba7b810-9dad-11d1-80b4-00c04fd430c8",              /* no braces: looks like a ProgID */
                L"{6ba7b810-9dad-11d1-80b4-00c04fd430c8",              /* missing closing brace */
                L"6ba7b810-9dad-11d1-80b4-00c04fd430c8}",              /* missing opening brace */
                L"{6ba7b810-9dad-11d1-80b4-00c04fd430c}",              /* one digit short */
                L"{6ba7b810-9dad-11d1-80b4-00c04fd430c88}",            /* one digit long */
                L"{6ba7b810-9dad-11d1-80b4-00c04fd430cg}",             /* not hex */
                L"{6ba7b8109-dad-11d1-80b4-00c04fd430c8}",             /* dash in the wrong place */
                L"Word.Application",                                    /* a ProgID: needs the registry, which does not exist here */
                L"",
                L"{}",
            };
            unsigned i;
            for (i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
                char nm[64];
                snprintf(nm, sizeof nm, "CLSIDFromString rejects malformed string #%u with CO_E_CLASSSTRING", i);
                hr = CLSIDFromString(bad[i], &g);
                U_CHECKF(nm, hr == ST_CLASSSTRING, "hr=%x", (unsigned)hr);
            }
        }
        hr = IIDFromString(L"{00000000-0000-0000-C000-000000000046}", &g);
        U_CHECK("IIDFromString parses a braced IID", hr == S_OK && !memcmp(&g, &G_UNKNOWN, sizeof g));
        hr = IIDFromString(L"00000000-0000-0000-C000-000000000046", &g);
        U_CHECK("IIDFromString without braces is CO_E_IIDSTRING", hr == ST_IIDSTRING);
        U_CHECK("IIDFromString(NULL) is IID_NULL with S_OK", IIDFromString(0, &g) == S_OK && g.Data1 == 0 && g.Data4[7] == 0);
        U_CHECK("CLSIDFromString(text, NULL) is E_INVALIDARG", CLSIDFromString(L"{6ba7b810-9dad-11d1-80b4-00c04fd430c8}", 0) == E_INVALIDARG);
    }
    if (has_rdrand()) {
        GUID a, b;
        HRESULT ha = CoCreateGuid(&a), hb = CoCreateGuid(&b);
        U_CHECK("CoCreateGuid succeeds twice", ha == S_OK && hb == S_OK);
        U_CHECK("two CoCreateGuid results differ", memcmp(&a, &b, sizeof a) != 0);
        U_CHECK("CoCreateGuid gives a version-4, RFC 4122 variant GUID", (a.Data3 >> 12) == 4 && (a.Data4[0] >> 6) == 2 && (b.Data3 >> 12) == 4 && (b.Data4[0] >> 6) == 2);
        {
            WCHAR t[40];
            GUID r;
            StringFromGUID2(&a, t, 40);
            U_CHECK("CoCreateGuid -> StringFromGUID2 -> CLSIDFromString round trip", CLSIDFromString(t, &r) == S_OK && !memcmp(&r, &a, sizeof a) && t[15] == '4');
        }
    } else {
        GUID a;
        U_CHECK("no RDRAND: CoCreateGuid fails instead of faking randomness", CoCreateGuid(&a) != S_OK);
    }
    U_CHECK("CoCreateGuid(NULL) is E_INVALIDARG", CoCreateGuid(0) == E_INVALIDARG);

    /* ================================================================ task allocator */
    {
        unsigned char *p, *q;
        unsigned i;
        int ok = 1;
        p = CoTaskMemAlloc(100);
        U_CHECK("CoTaskMemAlloc(100)", p != 0);
        for (i = 0; p && i < 100; ++i) p[i] = (unsigned char)(i * 7);
        q = CoTaskMemRealloc(p, 5000);
        U_CHECK("CoTaskMemRealloc grows the block", q != 0);
        for (i = 0; q && i < 100; ++i) if (q[i] != (unsigned char)(i * 7)) ok = 0;
        U_CHECK("...and preserves the contents", ok);
        for (i = 0; q && i < 5000; ++i) q[i] = 1;                        /* the whole new size is writable */
        U_CHECK("CoTaskMemRealloc(p, 0) frees and returns NULL", CoTaskMemRealloc(q, 0) == 0);
        p = CoTaskMemRealloc(0, 64);
        U_CHECK("CoTaskMemRealloc(NULL, n) allocates", p != 0);
        CoTaskMemFree(p);
        CoTaskMemFree(0);
        p = CoTaskMemAlloc(0);
        U_CHECK("CoTaskMemAlloc(0) returns a valid block", p != 0);
        CoTaskMemFree(p);
        U_CHECK("CoTaskMemAlloc of an impossible size fails (NULL)", CoTaskMemAlloc((SIZE_T)1 << 62) == 0);
    }
    {
        IMalloc *m = 0, *m2 = 0;
        void *p, *q, *out = 0;
        U_CHECK("CoGetMalloc(MEMCTX_TASK)", CoGetMalloc(MEMCTX_TASK, &m) == S_OK && m);
        U_CHECK("CoGetMalloc with another context is E_INVALIDARG", CoGetMalloc(MEMCTX_SHARED, &m2) == E_INVALIDARG && m2 == 0);
        U_CHECK("CoGetMalloc(NULL out) is E_POINTER", CoGetMalloc(MEMCTX_TASK, 0) == E_POINTER);
        U_CHECK("IMalloc::QueryInterface(IID_IMalloc) and (IID_IUnknown)", m->lpVtbl->QueryInterface(m, &IID_MALLOC, &out) == S_OK && out == m &&
                m->lpVtbl->QueryInterface(m, &G_UNKNOWN, &out) == S_OK && out == m);
        U_CHECK("IMalloc::QueryInterface(unknown IID) is E_NOINTERFACE", m->lpVtbl->QueryInterface(m, &G_DNS, &out) == E_NOINTERFACE && out == 0);
        U_CHECK("IMalloc AddRef / Release", m->lpVtbl->AddRef(m) >= 1 && m->lpVtbl->Release(m) >= 1);
        p = m->lpVtbl->Alloc(m, 200);
        U_CHECK("IMalloc::Alloc", p != 0);
        U_CHECK("IMalloc::GetSize >= requested size", p && m->lpVtbl->GetSize(m, p) >= 200);
        U_CHECK("IMalloc::DidAlloc says 1 for its own block", p && m->lpVtbl->DidAlloc(m, p) == 1);
        U_CHECK("IMalloc::GetSize(NULL) = -1", m->lpVtbl->GetSize(m, 0) == (SIZE_T)-1);
        q = m->lpVtbl->Realloc(m, p, 400);
        U_CHECK("IMalloc::Realloc", q != 0 && m->lpVtbl->GetSize(m, q) >= 400);
        U_CHECK("memory from IMalloc can be released with CoTaskMemFree (one allocator)", (CoTaskMemFree(q), 1));
        p = CoTaskMemAlloc(16);
        m->lpVtbl->Free(m, p);
        m->lpVtbl->HeapMinimize(m);
        U_CHECK("memory from CoTaskMemAlloc can be released with IMalloc::Free", 1);
    }

    /* ================================================================ apartments (this is the first COM use in the process) */
    {
        APTTYPE t = (APTTYPE)-9;
        APTTYPEQUALIFIER q = (APTTYPEQUALIFIER)-9;
        HRESULT hr;
        U_CHECK("CoGetApartmentType before any CoInitialize is CO_E_NOTINITIALIZED", CoGetApartmentType(&t, &q) == ST_NOTINIT);
        CoUninitialize();
        U_CHECK("CoUninitialize without CoInitialize does nothing", CoGetApartmentType(&t, &q) == ST_NOTINIT);
        U_CHECK("CoInitializeEx with a non-NULL reserved pointer is E_INVALIDARG", CoInitializeEx((LPVOID)1, COINIT_MULTITHREADED) == E_INVALIDARG);
        U_CHECK("CoInitializeEx with an undefined flag bit is E_INVALIDARG", CoInitializeEx(0, 0x10) == E_INVALIDARG);
        U_CHECK("CoGetApartmentType(NULL) is E_INVALIDARG", CoGetApartmentType(0, &q) == E_INVALIDARG);

        hr = CoInitializeEx(0, COINIT_MULTITHREADED);
        U_CHECKF("first CoInitializeEx(MTA) is S_OK", hr == S_OK, "hr=%x", (unsigned)hr);
        hr = CoInitializeEx(0, COINIT_MULTITHREADED);
        U_CHECKF("second CoInitializeEx(MTA) is S_FALSE", hr == S_FALSE, "hr=%x", (unsigned)hr);
        hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
        U_CHECKF("CoInitializeEx(STA) on an MTA thread is RPC_E_CHANGED_MODE", hr == ST_CHANGED_MODE, "hr=%x", (unsigned)hr);
        U_CHECK("apartment type is MTA with no qualifier", CoGetApartmentType(&t, &q) == S_OK && t == APTTYPE_MTA && q == APTTYPEQUALIFIER_NONE);
        CoUninitialize();
        U_CHECK("after one of two CoUninitialize the thread is still in the MTA", CoGetApartmentType(&t, &q) == S_OK && t == APTTYPE_MTA);
        hr = CoInitializeEx(0, COINIT_MULTITHREADED);
        U_CHECK("...and re-initialising with the same model gives S_FALSE (count back to 2)", hr == S_FALSE);
        CoUninitialize();
        CoUninitialize();
        U_CHECK("the RPC_E_CHANGED_MODE call did not change the count: two more CoUninitialize leave COM", CoGetApartmentType(&t, &q) == ST_NOTINIT);

        hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
        U_CHECKF("CoInitializeEx(STA) is S_OK", hr == S_OK, "hr=%x", (unsigned)hr);
        U_CHECK("the first STA of the process is the main STA", CoGetApartmentType(&t, &q) == S_OK && t == APTTYPE_MAINSTA && q == APTTYPEQUALIFIER_NONE);
        U_CHECK("CoInitialize(NULL) (an STA call) is S_FALSE now", CoInitialize(0) == S_FALSE);
        U_CHECK("CoInitialize(non-NULL) is E_INVALIDARG", CoInitialize((LPVOID)1) == E_INVALIDARG);
        U_CHECK("CoInitializeEx(MTA) on an STA thread is RPC_E_CHANGED_MODE", CoInitializeEx(0, COINIT_MULTITHREADED) == ST_CHANGED_MODE);
        CoUninitialize();
        CoUninitialize();
        U_CHECK("STA left after balanced uninitialisation", CoGetApartmentType(&t, &q) == ST_NOTINIT);
    }
    {
        ULONG r1 = CoAddRefServerProcess(), r2 = CoAddRefServerProcess(), r3 = CoReleaseServerProcess(), r4 = CoReleaseServerProcess(), r5 = CoReleaseServerProcess();
        U_CHECKF("CoAddRefServerProcess / CoReleaseServerProcess count 1, 2, 1, 0 (unbalanced stays 0)", r1 == 1 && r2 == 2 && r3 == 1 && r4 == 0 && r5 == 0,
                 "%u %u %u %u %u", (unsigned)r1, (unsigned)r2, (unsigned)r3, (unsigned)r4, (unsigned)r5);
    }
    {
        HRESULT hr;
        U_CHECK("OleInitialize(NULL) initialises an STA", (hr = OleInitialize(0)) == S_OK);
        U_CHECK("OleInitialize again is S_FALSE", OleInitialize(0) == S_FALSE);
        OleUninitialize();
        {
            APTTYPE t = (APTTYPE)-9;
            APTTYPEQUALIFIER q = (APTTYPEQUALIFIER)-9;
            U_CHECK("after one of two OleUninitialize the STA is still there", CoGetApartmentType(&t, &q) == S_OK && t == APTTYPE_MAINSTA);
            OleUninitialize();
            U_CHECK("after both, COM is uninitialised", CoGetApartmentType(&t, &q) == ST_NOTINIT);
            OleUninitialize();
            U_CHECK("an unbalanced OleUninitialize does nothing", CoGetApartmentType(&t, &q) == ST_NOTINIT);
        }
        CoInitializeEx(0, COINIT_MULTITHREADED);
        U_CHECK("OleInitialize on an MTA thread is RPC_E_CHANGED_MODE", OleInitialize(0) == ST_CHANGED_MODE);
        CoUninitialize();
        (void)hr;
    }

    /* ---- initialize spies ---- */
    {
        spy_t spy, spy2;
        ULARGE_INTEGER cookie, cookie2;
        HRESULT hr;
        memset(&spy, 0, sizeof spy); spy.lpVtbl = &spy_vtbl; spy.refs = 1;
        memset(&spy2, 0, sizeof spy2); spy2.lpVtbl = &spy_vtbl; spy2.refs = 1;
        U_CHECK("CoRegisterInitializeSpy(NULL spy) is E_INVALIDARG", CoRegisterInitializeSpy(0, &cookie) == E_INVALIDARG);
        U_CHECK("CoRegisterInitializeSpy(NULL cookie) is E_INVALIDARG", CoRegisterInitializeSpy((IInitializeSpy *)&spy, 0) == E_INVALIDARG);
        hr = CoRegisterInitializeSpy((IInitializeSpy *)&spy, &cookie);
        U_CHECK("CoRegisterInitializeSpy succeeds and holds a reference", hr == S_OK && spy.refs == 2);
        CoInitializeEx(0, COINIT_MULTITHREADED);            /* count 0 -> 1 */
        CoInitializeEx(0, COINIT_MULTITHREADED);            /* 1 -> 2 (S_FALSE) */
        CoInitializeEx(0, COINIT_APARTMENTTHREADED);        /* refused: RPC_E_CHANGED_MODE, count stays 2 */
        CoUninitialize();                                   /* 2 -> 1 */
        CoUninitialize();                                   /* 1 -> 0 */
        U_CHECKF("spy saw 10 calls: 3 CoInitializeEx (pre+post) and 2 CoUninitialize (pre+post)", spy.n == 10, "n=%d", spy.n);
        U_CHECK("PreInitialize(coinit 0, current refs 0)", spy_is(&spy, 0, 'P', 0, 0, 0));
        U_CHECK("PostInitialize(S_OK, coinit 0, new refs 1)", spy_is(&spy, 1, 'Q', (DWORD)S_OK, 0, 1));
        U_CHECK("PreInitialize(0, 1), PostInitialize(S_FALSE, 0, 2)", spy_is(&spy, 2, 'P', 0, 1, 0) && spy_is(&spy, 3, 'Q', (DWORD)S_FALSE, 0, 2));
        U_CHECK("refused STA call: PreInitialize(2, 2), PostInitialize(RPC_E_CHANGED_MODE, 2, 2)",
                spy_is(&spy, 4, 'P', COINIT_APARTMENTTHREADED, 2, 0) && spy_is(&spy, 5, 'Q', (DWORD)ST_CHANGED_MODE, COINIT_APARTMENTTHREADED, 2));
        U_CHECK("CoUninitialize: PreUninitialize(2), PostUninitialize(1)", spy_is(&spy, 6, 'U', 2, 0, 0) && spy_is(&spy, 7, 'V', 1, 0, 0));
        U_CHECK("CoUninitialize: PreUninitialize(1), PostUninitialize(0)", spy_is(&spy, 8, 'U', 1, 0, 0) && spy_is(&spy, 9, 'V', 0, 0, 0));
        hr = CoRegisterInitializeSpy((IInitializeSpy *)&spy2, &cookie2);
        spy.n = 0; spy2.n = 0;
        CoInitializeEx(0, COINIT_MULTITHREADED);
        CoUninitialize();
        U_CHECK("with two spies registered both are called", hr == S_OK && spy.n == 4 && spy2.n == 4);
        {
            worker_t w;
            HANDLE th;
            ULARGE_INTEGER c = cookie;
            memset(&w, 0, sizeof w);
            w.mode = 2;
            w.ready = CreateEventW(0, TRUE, FALSE, 0);
            w.release = (HANDLE)&c;                    /* smuggles the cookie pointer */
            th = CreateThread(0, 0, worker, &w, 0, 0);
            WaitForSingleObject(w.ready, 10000);
            WaitForSingleObject(th, 10000);
            U_CHECK("a spy cannot be revoked from another thread (E_INVALIDARG)", w.hr[1] == E_INVALIDARG);
            CloseHandle(th);
            CloseHandle(w.ready);
        }
        U_CHECK("CoRevokeInitializeSpy succeeds and drops the reference", CoRevokeInitializeSpy(cookie) == S_OK && spy.refs == 1);
        U_CHECK("revoking the same cookie again is E_INVALIDARG", CoRevokeInitializeSpy(cookie) == E_INVALIDARG);
        spy.n = 0; spy2.n = 0;
        CoInitializeEx(0, COINIT_MULTITHREADED);
        CoUninitialize();
        U_CHECK("the revoked spy is no longer called, the other one still is", spy.n == 0 && spy2.n == 4);
        U_CHECK("second CoRevokeInitializeSpy", CoRevokeInitializeSpy(cookie2) == S_OK && spy2.refs == 1);
    }

    /* ---- apartments across threads ---- */
    {
        worker_t w1, w2, w3, w4;
        HANDLE t1, t2, t3, t4;
        APTTYPE t = (APTTYPE)-9;
        APTTYPEQUALIFIER q = (APTTYPEQUALIFIER)-9;
        U_CHECK("main thread: no COM", CoGetApartmentType(&t, &q) == ST_NOTINIT);
        /* worker 1 becomes the process's main STA and parks */
        t1 = start_worker(&w1, 0, 1);
        WaitForSingleObject(w1.ready, 10000);
        U_CHECKF("worker before initialising: CO_E_NOTINITIALIZED", w1.hr[0] == ST_NOTINIT, "hr=%x", (unsigned)w1.hr[0]);
        U_CHECK("worker CoInitializeEx(STA) is S_OK and it becomes the main STA", w1.hr[1] == S_OK && w1.hr[2] == S_OK && w1.at[1] == APTTYPE_MAINSTA);
        U_CHECK("the main thread is unaffected by another thread's STA", CoGetApartmentType(&t, &q) == ST_NOTINIT);
        /* worker 2: a second STA is a plain STA */
        t2 = start_worker(&w2, 0, 0);
        WaitForSingleObject(w2.ready, 10000);
        WaitForSingleObject(t2, 10000);
        U_CHECK("a second STA thread is APTTYPE_STA (not the main one)", w2.hr[1] == S_OK && w2.at[1] == APTTYPE_STA && w2.aq[1] == APTTYPEQUALIFIER_NONE);
        SetEvent(w1.release);
        WaitForSingleObject(t1, 10000);
        /* worker 3: the main STA is free again */
        t3 = start_worker(&w3, 0, 0);
        WaitForSingleObject(w3.ready, 10000);
        WaitForSingleObject(t3, 10000);
        U_CHECK("after the main STA left, the next STA thread becomes the main STA", w3.hr[1] == S_OK && w3.at[1] == APTTYPE_MAINSTA);
        /* worker 4 joins the MTA and exits without CoUninitialize: the loader's thread-detach notification cleans up */
        t4 = start_worker(&w4, 1, 0);
        WaitForSingleObject(w4.ready, 10000);
        WaitForSingleObject(t4, 10000);
        U_CHECKF("worker CoInitializeEx(MTA) is S_OK", w4.hr[1] == S_OK, "hr=%x", (unsigned)w4.hr[1]);
        U_CHECK("a thread that exits without CoUninitialize leaves no phantom MTA (thread-detach cleanup)", CoGetApartmentType(&t, &q) == ST_NOTINIT);
        /* implicit MTA: while one thread is in the MTA, a thread that never initialised is in the implicit MTA */
        CoInitializeEx(0, COINIT_MULTITHREADED);
        {
            worker_t w5;
            HANDLE t5 = start_worker(&w5, 3, 0);
            (void)t5;
            WaitForSingleObject(w5.ready, 10000);
            WaitForSingleObject(t5, 10000);
            U_CHECK("worker that has not initialised COM sees the implicit MTA while another thread is in the MTA",
                    w5.hr[0] == S_OK && w5.at[0] == APTTYPE_MTA && w5.aq[0] == APTTYPEQUALIFIER_IMPLICIT_MTA);
        }
        CoUninitialize();
        CloseHandle(t1); CloseHandle(t2); CloseHandle(t3); CloseHandle(t4);
    }

    /* ================================================================ PROPVARIANT */
    {
        PROPVARIANT a, b;
        fake_t obj = { &fake_vtbl, 1 };
        memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
        U_CHECK("PropVariantClear(NULL) is S_OK", PropVariantClear(0) == S_OK);
        a.vt = VT_I4 | VT_BYREF;
        U_CHECK("PropVariantClear rejects VT_BYREF types (STG_E_INVALIDPARAMETER)", PropVariantClear(&a) == ST_INVALIDPARAM);
        a.vt = 200;
        U_CHECK("PropVariantClear rejects undefined types", PropVariantClear(&a) == ST_INVALIDPARAM);
        a.vt = VT_VARIANT;
        U_CHECK("a bare VT_VARIANT is not a PROPVARIANT scalar", PropVariantClear(&a) == ST_INVALIDPARAM);
        U_CHECK("PropVariantCopy of an invalid type fails", PropVariantCopy(&b, &a) == ST_INVALIDPARAM);
        U_CHECK("PropVariantCopy(NULL, ...) fails", PropVariantCopy(0, &a) == ST_INVALIDPARAM);

        a.vt = VT_I4; a.lVal = 1234567;
        U_CHECK("PropVariantCopy of a VT_I4", PropVariantCopy(&b, &a) == S_OK && b.vt == VT_I4 && b.lVal == 1234567 && PropVariantClear(&b) == S_OK && b.vt == VT_EMPTY);
        a.vt = VT_BSTR; a.bstrVal = SysAllocString(L"a bstr");
        U_CHECK("PropVariantCopy of a BSTR duplicates it", PropVariantCopy(&b, &a) == S_OK && b.vt == VT_BSTR && b.bstrVal != a.bstrVal && u_ascii_eq_w(b.bstrVal, "a bstr"));
        PropVariantClear(&b);
        U_CHECK("PropVariantClear(BSTR) leaves VT_EMPTY", PropVariantClear(&a) == S_OK && a.vt == VT_EMPTY);
        a.vt = VT_LPWSTR; a.pwszVal = CoTaskMemAlloc(9 * sizeof(WCHAR));
        u_wide("wide str", (unsigned short *)a.pwszVal, 9);
        U_CHECK("PropVariantCopy of an LPWSTR is a distinct CoTaskMem copy", PropVariantCopy(&b, &a) == S_OK && b.vt == VT_LPWSTR && b.pwszVal != a.pwszVal && u_ascii_eq_w(b.pwszVal, "wide str"));
        PropVariantClear(&b); PropVariantClear(&a);
        a.vt = VT_LPSTR; a.pszVal = CoTaskMemAlloc(6);
        memcpy(a.pszVal, "ansi", 5);
        U_CHECK("PropVariantCopy of an LPSTR", PropVariantCopy(&b, &a) == S_OK && b.pszVal != a.pszVal && !strcmp(b.pszVal, "ansi"));
        PropVariantClear(&b); PropVariantClear(&a);
        a.vt = VT_BLOB; a.blob.cbSize = 5; a.blob.pBlobData = CoTaskMemAlloc(5);
        memcpy(a.blob.pBlobData, "\x01\x02\x03\x04\x05", 5);
        U_CHECK("PropVariantCopy of a BLOB", PropVariantCopy(&b, &a) == S_OK && b.blob.cbSize == 5 && b.blob.pBlobData != a.blob.pBlobData && !memcmp(b.blob.pBlobData, a.blob.pBlobData, 5));
        PropVariantClear(&b); PropVariantClear(&a);
        a.vt = VT_CLSID; a.puuid = CoTaskMemAlloc(sizeof(CLSID));
        *a.puuid = G_DNS;
        U_CHECK("PropVariantCopy of a CLSID", PropVariantCopy(&b, &a) == S_OK && b.puuid != a.puuid && !memcmp(b.puuid, &G_DNS, sizeof(CLSID)));
        PropVariantClear(&b); PropVariantClear(&a);
        a.vt = VT_CF; a.pclipdata = CoTaskMemAlloc(sizeof(CLIPDATA));
        a.pclipdata->cbSize = sizeof(LONG) + 3; a.pclipdata->ulClipFmt = 49; a.pclipdata->pClipData = CoTaskMemAlloc(3);
        memcpy(a.pclipdata->pClipData, "xyz", 3);
        U_CHECK("PropVariantCopy of a clipboard datum", PropVariantCopy(&b, &a) == S_OK && b.pclipdata != a.pclipdata && b.pclipdata->ulClipFmt == 49 && b.pclipdata->cbSize == a.pclipdata->cbSize &&
                b.pclipdata->pClipData != a.pclipdata->pClipData && !memcmp(b.pclipdata->pClipData, "xyz", 3));
        PropVariantClear(&b); PropVariantClear(&a);
        a.vt = VT_UNKNOWN; a.punkVal = (IUnknown *)&obj;
        U_CHECK("PropVariantCopy(VT_UNKNOWN) AddRefs", PropVariantCopy(&b, &a) == S_OK && obj.refs == 2);
        U_CHECK("PropVariantClear(VT_UNKNOWN) Releases", PropVariantClear(&b) == S_OK && obj.refs == 1);
        a.vt = VT_STREAM; a.pStream = (IStream *)&obj;
        U_CHECK("VT_STREAM is reference counted", PropVariantCopy(&b, &a) == S_OK && obj.refs == 2 && PropVariantClear(&b) == S_OK && obj.refs == 1);
        a.vt = VT_STORAGE; a.pStorage = (IStorage *)&obj;
        U_CHECK("VT_STORAGE is reference counted", PropVariantCopy(&b, &a) == S_OK && obj.refs == 2 && PropVariantClear(&b) == S_OK && obj.refs == 1);
        a.vt = VT_VERSIONED_STREAM; a.pVersionedStream = CoTaskMemAlloc(sizeof(VERSIONEDSTREAM));
        a.pVersionedStream->guidVersion = G_DNS; a.pVersionedStream->pStream = (IStream *)&obj; ++obj.refs;   /* the variant owns one reference */
        U_CHECK("VT_VERSIONED_STREAM copy duplicates the block and AddRefs the stream", PropVariantCopy(&b, &a) == S_OK && b.pVersionedStream != a.pVersionedStream && obj.refs == 3);
        U_CHECK("...and clearing both releases both", PropVariantClear(&b) == S_OK && obj.refs == 2 && PropVariantClear(&a) == S_OK && obj.refs == 1);
        a.vt = VT_DISPATCH; a.pdispVal = (IDispatch *)&obj;
        U_CHECK("VT_DISPATCH is reference counted", PropVariantCopy(&b, &a) == S_OK && obj.refs == 2 && PropVariantClear(&b) == S_OK && obj.refs == 1);
        a.vt = VT_UNKNOWN; a.punkVal = 0;
        U_CHECK("NULL interface pointers are copied and cleared safely", PropVariantCopy(&b, &a) == S_OK && PropVariantClear(&b) == S_OK && PropVariantClear(&a) == S_OK);
    }
    {
        PROPVARIANT a, b;
        int ok;
        memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
        a.vt = VT_VECTOR | VT_I4; a.cal.cElems = 3; a.cal.pElems = CoTaskMemAlloc(3 * sizeof(LONG));
        a.cal.pElems[0] = 10; a.cal.pElems[1] = 20; a.cal.pElems[2] = 30;
        U_CHECK("PropVariantCopy of a vector of I4", PropVariantCopy(&b, &a) == S_OK && b.vt == (VT_VECTOR | VT_I4) && b.cal.cElems == 3 && b.cal.pElems != a.cal.pElems &&
                b.cal.pElems[0] == 10 && b.cal.pElems[2] == 30);
        PropVariantClear(&b); PropVariantClear(&a);
        a.vt = VT_VECTOR | VT_BSTR; a.cabstr.cElems = 2; a.cabstr.pElems = CoTaskMemAlloc(2 * sizeof(BSTR));
        a.cabstr.pElems[0] = SysAllocString(L"one"); a.cabstr.pElems[1] = 0;
        ok = PropVariantCopy(&b, &a) == S_OK && b.cabstr.pElems != a.cabstr.pElems && b.cabstr.pElems[0] != a.cabstr.pElems[0] && u_ascii_eq_w(b.cabstr.pElems[0], "one") && b.cabstr.pElems[1] == 0;
        U_CHECK("vector of BSTR is copied deeply (NULL element stays NULL)", ok);
        PropVariantClear(&b);
        U_CHECK("PropVariantClear of a vector of BSTR", PropVariantClear(&a) == S_OK && a.vt == VT_EMPTY);
        a.vt = VT_VECTOR | VT_LPWSTR; a.calpwstr.cElems = 2; a.calpwstr.pElems = CoTaskMemAlloc(2 * sizeof(LPWSTR));
        a.calpwstr.pElems[0] = CoTaskMemAlloc(4 * sizeof(WCHAR)); u_wide("abc", (unsigned short *)a.calpwstr.pElems[0], 4);
        a.calpwstr.pElems[1] = CoTaskMemAlloc(3 * sizeof(WCHAR)); u_wide("de", (unsigned short *)a.calpwstr.pElems[1], 3);
        ok = PropVariantCopy(&b, &a) == S_OK && b.calpwstr.pElems[0] != a.calpwstr.pElems[0] && u_ascii_eq_w(b.calpwstr.pElems[0], "abc") && u_ascii_eq_w(b.calpwstr.pElems[1], "de");
        U_CHECK("vector of LPWSTR is copied deeply", ok);
        PropVariantClear(&b); PropVariantClear(&a);
        a.vt = VT_VECTOR | VT_VARIANT; a.capropvar.cElems = 2; a.capropvar.pElems = CoTaskMemAlloc(2 * sizeof(PROPVARIANT));
        memset(a.capropvar.pElems, 0, 2 * sizeof(PROPVARIANT));
        a.capropvar.pElems[0].vt = VT_BSTR; a.capropvar.pElems[0].bstrVal = SysAllocString(L"inner");
        a.capropvar.pElems[1].vt = VT_I4; a.capropvar.pElems[1].lVal = 5;
        ok = PropVariantCopy(&b, &a) == S_OK && b.capropvar.pElems[0].vt == VT_BSTR && b.capropvar.pElems[0].bstrVal != a.capropvar.pElems[0].bstrVal &&
             u_ascii_eq_w(b.capropvar.pElems[0].bstrVal, "inner") && b.capropvar.pElems[1].lVal == 5;
        U_CHECK("vector of PROPVARIANT is copied recursively", ok);
        PropVariantClear(&b);
        U_CHECK("PropVariantClear of a vector of PROPVARIANT", PropVariantClear(&a) == S_OK);
        U_CHECK("vectors of the wrong element type are refused (VT_VECTOR|VT_DISPATCH)", (a.vt = VT_VECTOR | VT_DISPATCH, PropVariantClear(&a) == ST_INVALIDPARAM));
        a.vt = VT_VECTOR | VT_ARRAY | VT_I4;
        U_CHECK("VT_VECTOR|VT_ARRAY together are invalid", PropVariantClear(&a) == ST_INVALIDPARAM);
        {
            SAFEARRAYBOUND sb = { 3, 0 };
            SAFEARRAY *sa = SafeArrayCreate(VT_I4, 1, &sb);
            LONG idx = 1, v = 77;
            SafeArrayPutElement(sa, &idx, &v);
            a.vt = VT_ARRAY | VT_I4; a.parray = sa;
            U_CHECK("PropVariantCopy of VT_ARRAY copies the SAFEARRAY", PropVariantCopy(&b, &a) == S_OK && b.parray && b.parray != sa && ((LONG *)b.parray->pvData)[1] == 77);
            PropVariantClear(&b);
            U_CHECK("PropVariantClear of VT_ARRAY destroys the SAFEARRAY", PropVariantClear(&a) == S_OK && a.vt == VT_EMPTY);
        }
        {
            PROPVARIANT arr[3];
            memset(arr, 0, sizeof arr);
            arr[0].vt = VT_BSTR; arr[0].bstrVal = SysAllocString(L"x");
            arr[1].vt = VT_I4; arr[1].lVal = 1;
            arr[2].vt = VT_LPWSTR; arr[2].pwszVal = CoTaskMemAlloc(2 * sizeof(WCHAR)); arr[2].pwszVal[0] = 'y'; arr[2].pwszVal[1] = 0;
            U_CHECK("FreePropVariantArray clears every element", FreePropVariantArray(3, arr) == S_OK && arr[0].vt == VT_EMPTY && arr[1].vt == VT_EMPTY && arr[2].vt == VT_EMPTY);
        }
    }
    return u_finish("t_u_ole32");
}
