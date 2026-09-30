/* SPDX-License-Identifier: GPL-2.0-only
 * tridentrt: COM activation (CoGetClassObject, CoCreateInstance(Ex), CoRegisterClassObject & co.), ProgID lookups
 * and OleRegGetUserType.
 *
 * Where CoGetClassObject looks, in this order (the Windows order, minus activation contexts and DCOM):
 *   1. the process class table (CoRegisterClassObject below). A registration is found by any lookup whose CLSCTX
 *      shares a bit with the registered context; REGCLS_MULTIPLEUSE with CLSCTX_LOCAL_SERVER also serves
 *      CLSCTX_INPROC_SERVER, as documented. Registrations made with REGCLS_SUSPENDED, and all of them after
 *      CoSuspendClassObjects, are invisible until CoResumeClassObjects. A registration dies with the apartment that
 *      made it (an STA with its thread's last CoUninitialize, the MTA with its last thread), observed through an
 *      initialize spy (CoRegisterInitializeSpy) on the registering thread. The object is handed out directly to every
 *      apartment of the process: there is no cross-apartment marshaling here.
 *   2. the class table of the Shizuku ole32, when that ole32 exports CoGetClassObject (looked up at run time).
 *   3. for CLSCTX_INPROC_SERVER: HKCR\CLSID\{clsid}\InprocServer32 (default value, REG_SZ or REG_EXPAND_SZ) names the
 *      DLL; it is loaded with LoadLibraryW once per process and never unloaded (CoFreeUnusedLibraries does not exist
 *      here), then its DllGetClassObject is asked. ThreadingModel is not interpreted (no apartment hosting).
 * Out-of-process servers (LocalServer32), handlers (InprocHandler32), TreatAs and remote activation do not exist:
 * those lookups end in REGDB_E_CLASSNOTREG like an unregistered class.
 *
 * Every entry point needs an initialised apartment on the calling thread, or the implicit MTA (CoGetApartmentType
 * of the Shizuku ole32 decides), and fails with CO_E_NOTINITIALIZED otherwise, as on Windows. The registry keys the
 * browser needs are seeded (register.c) before the first lookup.
 */
#define COBJMACROS
#include "comrt.h"

struct class_reg
{
    struct class_reg *next;
    CLSID clsid;
    IUnknown *obj;
    DWORD ctx;                  /* CLSCTX_* bits the registration serves */
    DWORD flags;                /* REGCLS_* */
    DWORD cookie;
    DWORD tid;                  /* registering thread (STA registrations belong to its apartment) */
    BOOL mta;                   /* made from the MTA */
    BOOL suspended;             /* REGCLS_SUSPENDED, not yet resumed */
};

static CRITICAL_SECTION lock = { NULL, -1, 0, 0, 0, 0 };
static struct class_reg *classes;
static DWORD next_cookie;
static BOOL all_suspended;      /* CoSuspendClassObjects until CoResumeClassObjects */

HRESULT trt_check_apartment(void)
{
    APTTYPE type;
    APTTYPEQUALIFIER qual;
    return CoGetApartmentType(&type, &qual) == S_OK ? S_OK : CO_E_NOTINITIALIZED;
}

static BOOL current_is_mta(void)
{
    APTTYPE type;
    APTTYPEQUALIFIER qual;
    return CoGetApartmentType(&type, &qual) == S_OK && type == APTTYPE_MTA;
}

/* ---------------------------------------------------------------- apartment lifetime (initialize spy) */
static void revoke_where(BOOL (*match)(const struct class_reg *, DWORD), DWORD arg)
{
    struct class_reg **p, *dead = NULL, *r;
    EnterCriticalSection(&lock);
    for (p = &classes; *p; )
    {
        if (match(*p, arg)) { r = *p; *p = r->next; r->next = dead; dead = r; }
        else p = &(*p)->next;
    }
    LeaveCriticalSection(&lock);
    while ((r = dead))                                      /* Release outside the lock: it may call back into COM */
    {
        dead = r->next;
        IUnknown_Release(r->obj);
        HeapFree(GetProcessHeap(), 0, r);
    }
}

static BOOL match_sta_of(const struct class_reg *r, DWORD tid) { return !r->mta && r->tid == tid; }
static BOOL match_mta(const struct class_reg *r, DWORD unused) { return r->mta; }

static HRESULT WINAPI spy_QueryInterface(IInitializeSpy *iface, REFIID riid, void **obj)
{
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IInitializeSpy))
    {
        *obj = iface;
        return S_OK;
    }
    *obj = NULL;
    return E_NOINTERFACE;
}
static ULONG WINAPI spy_AddRef(IInitializeSpy *iface) { return 2; }
static ULONG WINAPI spy_Release(IInitializeSpy *iface) { return 1; }
static HRESULT WINAPI spy_PreInitialize(IInitializeSpy *iface, DWORD coinit, DWORD refs) { return S_OK; }
static HRESULT WINAPI spy_PostInitialize(IInitializeSpy *iface, HRESULT hr, DWORD coinit, DWORD refs) { return hr; }
static HRESULT WINAPI spy_PreUninitialize(IInitializeSpy *iface, DWORD refs) { return S_OK; }

static HRESULT WINAPI spy_PostUninitialize(IInitializeSpy *iface, DWORD refs)
{
    if (refs) return S_OK;                                  /* the thread is still in its apartment */
    revoke_where(match_sta_of, GetCurrentThreadId());       /* an STA ends with its thread's last CoUninitialize */
    if (trt_check_apartment() != S_OK) revoke_where(match_mta, 0);   /* no MTA thread left: the MTA is gone */
    return S_OK;
}

static const IInitializeSpyVtbl spy_vtbl =
{
    spy_QueryInterface, spy_AddRef, spy_Release, spy_PreInitialize, spy_PostInitialize, spy_PreUninitialize,
    spy_PostUninitialize
};
static IInitializeSpy spy = { &spy_vtbl };
static DWORD spy_tls = TLS_OUT_OF_INDEXES;

static void watch_apartment(void)
{
    ULARGE_INTEGER cookie;
    if (spy_tls == TLS_OUT_OF_INDEXES)
    {
        DWORD idx = TlsAlloc();
        if (idx == TLS_OUT_OF_INDEXES) return;
        if (InterlockedCompareExchange((LONG *)&spy_tls, idx, TLS_OUT_OF_INDEXES) != TLS_OUT_OF_INDEXES) TlsFree(idx);
    }
    if (TlsGetValue(spy_tls)) return;                       /* this thread's spy is registered already */
    if (CoRegisterInitializeSpy(&spy, &cookie) == S_OK) TlsSetValue(spy_tls, (void *)1);
}

/* ---------------------------------------------------------------- the class table */
static IUnknown *find_registered(REFCLSID clsid, DWORD ctx)
{
    struct class_reg *r;
    IUnknown *obj = NULL;
    EnterCriticalSection(&lock);
    for (r = classes; r; r = r->next)
    {
        if (!(r->ctx & ctx) || !IsEqualCLSID(&r->clsid, clsid)) continue;
        if (r->suspended || all_suspended) continue;
        obj = r->obj;
        IUnknown_AddRef(obj);
        break;
    }
    LeaveCriticalSection(&lock);
    return obj;
}

HRESULT WINAPI CoRegisterClassObject(REFCLSID clsid, IUnknown *obj, DWORD ctx, DWORD flags, DWORD *cookie)
{
    struct class_reg *r;
    IUnknown *existing;
    HRESULT hr;

    if (!cookie || !obj || !clsid) return E_INVALIDARG;
    *cookie = 0;
    if ((hr = trt_check_apartment()) != S_OK) return hr;
    trt_register_once();
    if ((flags & REGCLS_MULTIPLEUSE) && (ctx & CLSCTX_LOCAL_SERVER)) ctx |= CLSCTX_INPROC_SERVER;
    if ((existing = find_registered(clsid, ctx)))
    {
        IUnknown_Release(existing);
        return CO_E_OBJISREG;
    }
    if (!(r = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*r)))) return E_OUTOFMEMORY;
    r->clsid = *clsid;
    r->obj = obj;
    r->ctx = ctx;
    r->flags = flags;
    r->tid = GetCurrentThreadId();
    r->mta = current_is_mta();
    r->suspended = (flags & REGCLS_SUSPENDED) != 0;
    IUnknown_AddRef(obj);
    watch_apartment();
    EnterCriticalSection(&lock);
    r->cookie = ++next_cookie;
    r->next = classes;
    classes = r;
    *cookie = r->cookie;
    LeaveCriticalSection(&lock);
    return S_OK;
}

HRESULT WINAPI CoRevokeClassObject(DWORD cookie)
{
    struct class_reg **p, *r = NULL;
    HRESULT hr;

    if ((hr = trt_check_apartment()) != S_OK) return hr;
    EnterCriticalSection(&lock);
    for (p = &classes; *p; p = &(*p)->next)
    {
        if ((*p)->cookie != cookie) continue;
        r = *p;
        if (!r->mta && r->tid != GetCurrentThreadId()) { LeaveCriticalSection(&lock); return RPC_E_WRONG_THREAD; }
        *p = r->next;
        break;
    }
    LeaveCriticalSection(&lock);
    if (!r) return E_INVALIDARG;
    IUnknown_Release(r->obj);
    HeapFree(GetProcessHeap(), 0, r);
    return S_OK;
}

HRESULT WINAPI CoSuspendClassObjects(void)
{
    EnterCriticalSection(&lock);
    all_suspended = TRUE;
    LeaveCriticalSection(&lock);
    return S_OK;
}

HRESULT WINAPI CoResumeClassObjects(void)
{
    struct class_reg *r;
    EnterCriticalSection(&lock);
    all_suspended = FALSE;
    for (r = classes; r; r = r->next) r->suspended = FALSE;
    LeaveCriticalSection(&lock);
    return S_OK;
}

/* ---------------------------------------------------------------- in-process servers from the registry */
typedef HRESULT (WINAPI *get_class_object_fn)(REFCLSID, REFIID, void **);

static struct server { WCHAR path[MAX_PATH]; HMODULE module; get_class_object_fn get; } servers[64];
static unsigned server_count;

HRESULT trt_open_clsid_key(REFCLSID clsid, const WCHAR *sub, HKEY *key)
{
    WCHAR path[6 + TRT_GUID_CHARS + 64];
    HKEY k;
    LONG res;

    lstrcpyW(path, L"CLSID\\");
    StringFromGUID2(clsid, path + 6, TRT_GUID_CHARS);
    res = RegOpenKeyExW(HKEY_CLASSES_ROOT, path, 0, KEY_READ, &k);
    if (res == ERROR_FILE_NOT_FOUND) return REGDB_E_CLASSNOTREG;
    if (res) return REGDB_E_READREGDB;
    if (!sub)
    {
        *key = k;
        return S_OK;
    }
    res = RegOpenKeyExW(k, sub, 0, KEY_READ, key);
    RegCloseKey(k);
    if (res == ERROR_FILE_NOT_FOUND) return REGDB_E_KEYMISSING;
    return res ? REGDB_E_READREGDB : S_OK;
}

/* default value of an open key as a path: REG_EXPAND_SZ expanded, surrounding quotes removed */
static BOOL read_path_value(HKEY key, const WCHAR *name, WCHAR *out, DWORD cch)
{
    WCHAR raw[MAX_PATH], *p = raw;
    DWORD type, size = sizeof(raw) - sizeof(WCHAR), n;

    if (RegQueryValueExW(key, name, NULL, &type, (BYTE *)raw, &size) || (type != REG_SZ && type != REG_EXPAND_SZ))
        return FALSE;
    raw[size / sizeof(WCHAR)] = 0;
    if (*p == '"')
    {
        p++;
        if ((n = lstrlenW(p)) && p[n - 1] == '"') p[n - 1] = 0;
    }
    if (type == REG_EXPAND_SZ)
    {
        n = ExpandEnvironmentStringsW(p, out, cch);
        return n && n <= cch;
    }
    if ((DWORD)lstrlenW(p) >= cch) return FALSE;
    lstrcpyW(out, p);
    return *out != 0;
}

static HRESULT inproc_server_object(REFCLSID clsid, REFIID riid, void **obj)
{
    WCHAR path[MAX_PATH];
    get_class_object_fn get = NULL;
    HMODULE module;
    unsigned i;
    HKEY key;
    HRESULT hr;
    DWORD err;

    hr = trt_open_clsid_key(clsid, L"InprocServer32", &key);
    if (hr == REGDB_E_KEYMISSING) return REGDB_E_CLASSNOTREG;
    if (FAILED(hr)) return hr;
    if (!read_path_value(key, NULL, path, MAX_PATH))
    {
        RegCloseKey(key);
        return REGDB_E_CLASSNOTREG;
    }
    RegCloseKey(key);

    EnterCriticalSection(&lock);
    for (i = 0; i < server_count; i++)
        if (!lstrcmpiW(servers[i].path, path)) { get = servers[i].get; break; }
    LeaveCriticalSection(&lock);
    if (!get)
    {
        /* outside the lock: DllMain of the server may activate classes itself */
        if (!(module = LoadLibraryW(path)))
        {
            /* the loader's error as an HRESULT, what Windows returns (e.g. 0x8007007E for a missing DLL) */
            err = GetLastError();
            return err ? HRESULT_FROM_WIN32(err) : CO_E_DLLNOTFOUND;
        }
        if (!(get = (get_class_object_fn)GetProcAddress(module, "DllGetClassObject")))
            return CO_E_DLLNOTFOUND;                        /* as Wine: the DLL does not export DllGetClassObject */
        EnterCriticalSection(&lock);
        for (i = 0; i < server_count; i++)
            if (!lstrcmpiW(servers[i].path, path)) break;
        if (i == server_count && server_count < ARRAY_SIZE(servers))
        {
            lstrcpyW(servers[server_count].path, path);
            servers[server_count].module = module;      /* the reference LoadLibraryW took is never released */
            servers[server_count].get = get;
            server_count++;
        }
        LeaveCriticalSection(&lock);
    }
    return get(clsid, riid, obj);
}

/* ---------------------------------------------------------------- CoGetClassObject / CoCreateInstance(Ex) */
typedef HRESULT (WINAPI *co_get_class_object_fn)(REFCLSID, DWORD, COSERVERINFO *, REFIID, void **);

static co_get_class_object_fn ole32_get_class_object(void)
{
    static co_get_class_object_fn fn;
    static LONG looked;
    if (!InterlockedCompareExchange(&looked, 1, 0))
    {
        HMODULE ole32 = GetModuleHandleW(L"ole32.dll");
        co_get_class_object_fn f = ole32 ? (co_get_class_object_fn)GetProcAddress(ole32, "CoGetClassObject") : NULL;
        if (f != CoGetClassObject) fn = f;                  /* never ourselves (an ole32 forwarding here) */
    }
    return fn;
}

HRESULT WINAPI CoGetClassObject(REFCLSID clsid, DWORD ctx, COSERVERINFO *server, REFIID riid, void **obj)
{
    co_get_class_object_fn ole32_fn;
    IUnknown *registered;
    HRESULT hr;

    if (!obj) return E_INVALIDARG;
    *obj = NULL;
    if ((hr = trt_check_apartment()) != S_OK) return hr;
    if (!clsid || !riid) return E_INVALIDARG;
    trt_register_once();

    if ((registered = find_registered(clsid, ctx)))
    {
        hr = IUnknown_QueryInterface(registered, riid, obj);
        IUnknown_Release(registered);
        return hr;
    }
    if ((ole32_fn = ole32_get_class_object()))
    {
        hr = ole32_fn(clsid, ctx, server, riid, obj);
        if (hr != REGDB_E_CLASSNOTREG && hr != CLASS_E_CLASSNOTAVAILABLE) return hr;
        *obj = NULL;
    }
    if (ctx & CLSCTX_INPROC_SERVER) return inproc_server_object(clsid, riid, obj);
    return REGDB_E_CLASSNOTREG;
}

HRESULT WINAPI CoCreateInstanceEx(REFCLSID clsid, IUnknown *outer, DWORD ctx, COSERVERINFO *server, ULONG count,
                                  MULTI_QI *results)
{
    IClassFactory *factory;
    IUnknown *unk = NULL;
    ULONG i, got = 0;
    HRESULT hr;

    if (!count || !results) return E_INVALIDARG;
    for (i = 0; i < count; i++)
    {
        results[i].pItf = NULL;
        results[i].hr = E_NOINTERFACE;
    }
    if ((hr = trt_check_apartment()) != S_OK) return hr;
    if (!clsid) return E_INVALIDARG;
    hr = CoGetClassObject(clsid, ctx, server, &IID_IClassFactory, (void **)&factory);
    if (FAILED(hr)) return hr;
    hr = IClassFactory_CreateInstance(factory, outer, results[0].pIID, (void **)&unk);
    IClassFactory_Release(factory);
    if (FAILED(hr)) return hr;
    for (i = 0; i < count; i++)
    {
        results[i].hr = IUnknown_QueryInterface(unk, results[i].pIID, (void **)&results[i].pItf);
        if (results[i].hr == S_OK) got++;
    }
    IUnknown_Release(unk);
    if (!got) return E_NOINTERFACE;
    return got == count ? S_OK : CO_S_NOTALLINTERFACES;
}

HRESULT WINAPI CoCreateInstance(REFCLSID clsid, IUnknown *outer, DWORD ctx, REFIID riid, void **obj)
{
    MULTI_QI mqi;
    HRESULT hr;

    if (!obj) return E_POINTER;
    *obj = NULL;
    if ((hr = trt_check_apartment()) != S_OK) return hr;
    mqi.pIID = riid;
    mqi.pItf = NULL;
    mqi.hr = S_OK;
    hr = CoCreateInstanceEx(clsid, outer, ctx, NULL, 1, &mqi);
    *obj = mqi.pItf;
    return hr == S_OK ? mqi.hr : hr;
}

/* ---------------------------------------------------------------- ProgIDs */
static HRESULT clsid_of_progid(const WCHAR *progid, CLSID *clsid, int depth)
{
    WCHAR path[256 + 8], value[256];
    DWORD type, size;
    HKEY key;
    LONG res;

    if (lstrlenW(progid) > 255) return CO_E_CLASSSTRING;
    lstrcpyW(path, progid);
    lstrcatW(path, L"\\CLSID");
    if (!RegOpenKeyExW(HKEY_CLASSES_ROOT, path, 0, KEY_READ, &key))
    {
        size = sizeof(value) - sizeof(WCHAR);
        res = RegQueryValueExW(key, NULL, NULL, &type, (BYTE *)value, &size);
        RegCloseKey(key);
        if (res || type != REG_SZ) return CO_E_CLASSSTRING;
        value[size / sizeof(WCHAR)] = 0;
        return CLSIDFromString(value, clsid) == S_OK && value[0] == '{' ? S_OK : CO_E_CLASSSTRING;
    }
    /* a version-independent ProgID without its own CLSID key: follow CurVer to the current versioned ProgID */
    lstrcpyW(path, progid);
    lstrcatW(path, L"\\CurVer");
    if (depth > 4 || RegOpenKeyExW(HKEY_CLASSES_ROOT, path, 0, KEY_READ, &key)) return CO_E_CLASSSTRING;
    size = sizeof(value) - sizeof(WCHAR);
    res = RegQueryValueExW(key, NULL, NULL, &type, (BYTE *)value, &size);
    RegCloseKey(key);
    if (res || type != REG_SZ) return CO_E_CLASSSTRING;
    value[size / sizeof(WCHAR)] = 0;
    if (!value[0] || !lstrcmpiW(value, progid)) return CO_E_CLASSSTRING;
    return clsid_of_progid(value, clsid, depth + 1);
}

HRESULT WINAPI CLSIDFromProgID(LPCOLESTR progid, CLSID *clsid)
{
    HRESULT hr;
    if (!progid || !clsid) return E_INVALIDARG;
    trt_register_once();
    if ((hr = clsid_of_progid(progid, clsid, 0)) != S_OK) memset(clsid, 0, sizeof(*clsid));
    return hr;
}

HRESULT WINAPI CLSIDFromProgIDEx(LPCOLESTR progid, CLSID *clsid)
{
    return CLSIDFromProgID(progid, clsid);                  /* no class store to download from */
}

HRESULT WINAPI ProgIDFromCLSID(REFCLSID clsid, LPOLESTR *progid)
{
    WCHAR value[256];
    DWORD type, size = sizeof(value) - sizeof(WCHAR);
    HKEY key;
    HRESULT hr;
    LONG res;

    if (!progid) return E_INVALIDARG;
    *progid = NULL;
    if (!clsid) return E_INVALIDARG;
    trt_register_once();
    if (FAILED(hr = trt_open_clsid_key(clsid, L"ProgID", &key))) return hr;
    res = RegQueryValueExW(key, NULL, NULL, &type, (BYTE *)value, &size);
    RegCloseKey(key);
    if (res || type != REG_SZ) return REGDB_E_CLASSNOTREG;
    value[size / sizeof(WCHAR)] = 0;
    if (!(*progid = CoTaskMemAlloc((lstrlenW(value) + 1) * sizeof(WCHAR)))) return E_OUTOFMEMORY;
    lstrcpyW(*progid, value);
    return S_OK;
}

/* ---------------------------------------------------------------- OleRegGetUserType */
/* HKCR\CLSID\{clsid}\AuxUserType\<form> (USERCLASSTYPE_SHORT / _APP), else the CLSID key's default value */
HRESULT WINAPI OleRegGetUserType(REFCLSID clsid, DWORD form, LPOLESTR *user_type)
{
    WCHAR value[260], sub[16];
    DWORD type, size;
    HKEY key, aux;
    HRESULT hr;
    LONG res = ERROR_FILE_NOT_FOUND;

    if (!user_type) return E_INVALIDARG;
    *user_type = NULL;
    if (!clsid) return E_INVALIDARG;
    trt_register_once();
    if (FAILED(hr = trt_open_clsid_key(clsid, NULL, &key))) return hr;
    if (form != USERCLASSTYPE_FULL)
    {
        wsprintfW(sub, L"AuxUserType\\%lu", form);
        if (!RegOpenKeyExW(key, sub, 0, KEY_READ, &aux))
        {
            size = sizeof(value) - sizeof(WCHAR);
            res = RegQueryValueExW(aux, NULL, NULL, &type, (BYTE *)value, &size);
            if (!res && type != REG_SZ) res = ERROR_INVALID_DATA;
            RegCloseKey(aux);
        }
    }
    if (res)
    {
        size = sizeof(value) - sizeof(WCHAR);
        res = RegQueryValueExW(key, NULL, NULL, &type, (BYTE *)value, &size);
        if (!res && type != REG_SZ) res = ERROR_INVALID_DATA;
    }
    RegCloseKey(key);
    if (res || size < sizeof(WCHAR)) return REGDB_E_READREGDB;
    value[size / sizeof(WCHAR)] = 0;
    if (!(*user_type = CoTaskMemAlloc((lstrlenW(value) + 1) * sizeof(WCHAR)))) return E_OUTOFMEMORY;
    lstrcpyW(*user_type, value);
    return S_OK;
}
