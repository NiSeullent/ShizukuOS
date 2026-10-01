/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku checks of tridentrt.dll: COM activation as the Wine browser modules use it.
 *  - CO_E_NOTINITIALIZED without an apartment (Windows behaviour, see Wine's ole32 tests test_CoCreateInstance /
 *    test_CoGetClassObject);
 *  - REGDB_E_CLASSNOTREG for an unregistered class in every context;
 *  - activation from the registry: HKCR\CLSID\{9A02E012-...}\InprocServer32 = C:\SHZ\SYS64\propsys.dll (the Wine
 *    propsys InMemoryPropertyStore), CoCreateInstance/CoGetClassObject/CoCreateInstanceEx through tridentrt, and the
 *    IPropertyStore works; a registered but missing DLL fails with the loader's error, as on Windows (0x8007007E);
 *  - the process class table: CoRegisterClassObject/CoRevokeClassObject, CO_E_OBJISREG, REGCLS_MULTIPLEUSE +
 *    CLSCTX_LOCAL_SERVER also serving in-process, REGCLS_SUSPENDED until CoResumeClassObjects (Windows behaviour per
 *    Wine's marshal.c test), registrations ending with their apartment (Wine's compobj.c test_CoRegisterClassObject);
 *  - ProgIDs: CLSIDFromProgID (CLSID key and CurVer), ProgIDFromCLSID, OleRegGetUserType.
 */
#define COBJMACROS
#include <stdarg.h>
#include <stdio.h>
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "objbase.h"
#include "propsys.h"
#include "wine/test.h"

HRESULT WINAPI CLSIDFromProgIDEx(LPCOLESTR progid, CLSID *clsid);      /* not in Wine's objbase.h */

static const CLSID CLSID_InMemoryPropertyStore_ = {0x9a02e012, 0x6303, 0x4e1e, {0xb9, 0xa1, 0x63, 0x0f, 0x80, 0x25, 0x92, 0xc5}};
static const IID IID_IPropertyStore_ = {0x886d8eeb, 0x8cf2, 0x4446, {0x8d, 0x02, 0xcd, 0xba, 0x1d, 0xbd, 0xcf, 0x99}};
static const IID IID_IPropertyStoreCache_ = {0x3017056d, 0x9a91, 0x4e90, {0x93, 0x7d, 0x74, 0x6c, 0x72, 0xab, 0xbf, 0x4f}};
static const CLSID CLSID_WebBrowser_ = {0x8856f961, 0x340a, 0x11d0, {0xa9, 0x6b, 0x00, 0xc0, 0x4f, 0xd7, 0x05, 0xa2}};
static const CLSID CLSID_JScript_ = {0xf414c260, 0x6ac0, 0x11cf, {0xb6, 0xd1, 0x00, 0xaa, 0x00, 0xbb, 0xbb, 0x58}};
/* private classes of this test */
static const CLSID CLSID_Test = {0x5a9f1a10, 0x2b3c, 0x4d5e, {0x8f, 0x01, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}};
static const CLSID CLSID_Missing = {0x5a9f1a11, 0x2b3c, 0x4d5e, {0x8f, 0x01, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}};
static const CLSID CLSID_NonExistent = {0x5a9f1a12, 0x2b3c, 0x4d5e, {0x8f, 0x01, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}};

/* ---------------------------------------------------------------- a class factory implemented in C */
static LONG factory_refs = 1, objects_created;

static HRESULT WINAPI unk_QueryInterface(IUnknown *iface, REFIID riid, void **obj)
{
    if (IsEqualIID(riid, &IID_IUnknown)) { *obj = iface; IUnknown_AddRef(iface); return S_OK; }
    *obj = NULL;
    return E_NOINTERFACE;
}
static ULONG WINAPI unk_AddRef(IUnknown *iface) { return 2; }
static ULONG WINAPI unk_Release(IUnknown *iface) { return 1; }
static const IUnknownVtbl unk_vtbl = { unk_QueryInterface, unk_AddRef, unk_Release };
static IUnknown test_object = { &unk_vtbl };

static HRESULT WINAPI cf_QueryInterface(IClassFactory *iface, REFIID riid, void **obj)
{
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IClassFactory))
    {
        *obj = iface;
        IClassFactory_AddRef(iface);
        return S_OK;
    }
    *obj = NULL;
    return E_NOINTERFACE;
}
static ULONG WINAPI cf_AddRef(IClassFactory *iface) { return InterlockedIncrement(&factory_refs); }
static ULONG WINAPI cf_Release(IClassFactory *iface) { return InterlockedDecrement(&factory_refs); }
static HRESULT WINAPI cf_CreateInstance(IClassFactory *iface, IUnknown *outer, REFIID riid, void **obj)
{
    if (outer) return CLASS_E_NOAGGREGATION;
    InterlockedIncrement(&objects_created);
    return IUnknown_QueryInterface(&test_object, riid, obj);
}
static HRESULT WINAPI cf_LockServer(IClassFactory *iface, BOOL lock) { return S_OK; }
static const IClassFactoryVtbl cf_vtbl = { cf_QueryInterface, cf_AddRef, cf_Release, cf_CreateInstance, cf_LockServer };
static IClassFactory test_factory = { &cf_vtbl };

/* ---------------------------------------------------------------- helpers */
static void set_default_value(HKEY root, const WCHAR *path, const WCHAR *value)
{
    HKEY key;
    LONG res = RegCreateKeyExW(root, path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL);
    ok(!res, "RegCreateKeyExW(%s): %ld\n", wine_dbgstr_w(path), res);
    if (res) return;
    res = RegSetValueExW(key, NULL, 0, REG_SZ, (const BYTE *)value, (lstrlenW(value) + 1) * sizeof(WCHAR));
    ok(!res, "RegSetValueExW(%s): %ld\n", wine_dbgstr_w(path), res);
    RegCloseKey(key);
}

static void test_not_initialized(void)
{
    IUnknown *unk = (IUnknown *)0xdeadbeef;
    DWORD cookie = 0xdeadbeef;
    HRESULT hr;

    hr = CoCreateInstance(&CLSID_InMemoryPropertyStore_, NULL, CLSCTX_INPROC_SERVER, &IID_IUnknown, (void **)&unk);
    ok(hr == CO_E_NOTINITIALIZED, "CoCreateInstance without CoInitialize: %#lx\n", hr);
    ok(unk == NULL, "CoCreateInstance left %p\n", unk);
    unk = (IUnknown *)0xdeadbeef;
    hr = CoGetClassObject(&CLSID_InMemoryPropertyStore_, CLSCTX_INPROC_SERVER, NULL, &IID_IUnknown, (void **)&unk);
    ok(hr == CO_E_NOTINITIALIZED, "CoGetClassObject without CoInitialize: %#lx\n", hr);
    ok(unk == NULL, "CoGetClassObject left %p\n", unk);
    hr = CoGetClassObject(&CLSID_InMemoryPropertyStore_, CLSCTX_INPROC_SERVER, NULL, &IID_IUnknown, NULL);
    ok(hr == E_INVALIDARG, "CoGetClassObject with a NULL out pointer: %#lx\n", hr);
    hr = CoRegisterClassObject(&CLSID_Test, (IUnknown *)&test_factory, CLSCTX_INPROC_SERVER, REGCLS_MULTIPLEUSE, &cookie);
    ok(hr == CO_E_NOTINITIALIZED, "CoRegisterClassObject without CoInitialize: %#lx\n", hr);
    ok(factory_refs == 1, "the factory was referenced: %ld\n", factory_refs);
}

static void test_unregistered(void)
{
    static const DWORD contexts[] = { CLSCTX_INPROC_SERVER, CLSCTX_INPROC_HANDLER, CLSCTX_LOCAL_SERVER, CLSCTX_REMOTE_SERVER };
    IUnknown *unk;
    unsigned int i;
    HRESULT hr;

    for (i = 0; i < ARRAY_SIZE(contexts); i++)
    {
        unk = (IUnknown *)0xdeadbeef;
        hr = CoCreateInstance(&CLSID_NonExistent, NULL, contexts[i], &IID_IUnknown, (void **)&unk);
        ok(hr == REGDB_E_CLASSNOTREG, "context %#lx: %#lx\n", contexts[i], hr);
        ok(unk == NULL, "context %#lx: %p\n", contexts[i], unk);
    }
}

static void test_registry_activation(void)
{
    static const PROPERTYKEY key = { {0x5a9f1a20, 0x2b3c, 0x4d5e, {0x8f, 0x01, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}}, 2 };
    IPropertyStore *store = NULL;
    IClassFactory *cf = NULL;
    IUnknown *unk = NULL;
    PROPVARIANT pv, out;
    MULTI_QI mqi[3];
    PROPERTYKEY got;
    DWORD count = 0;
    HRESULT hr;

    set_default_value(HKEY_CLASSES_ROOT, L"CLSID\\{9A02E012-6303-4E1E-B9A1-630F802592C5}\\InprocServer32",
                      L"C:\\SHZ\\SYS64\\propsys.dll");

    hr = CoCreateInstance(&CLSID_InMemoryPropertyStore_, NULL, CLSCTX_INPROC_SERVER, &IID_IPropertyStore_, (void **)&store);
    ok(hr == S_OK, "CoCreateInstance(InMemoryPropertyStore): %#lx\n", hr);
    ok(GetModuleHandleW(L"propsys.dll") != NULL, "propsys.dll was not loaded\n");
    if (store)
    {
        PropVariantInit(&pv);
        pv.vt = VT_I4;
        pv.lVal = 12345;
        hr = IPropertyStore_SetValue(store, &key, &pv);
        ok(hr == S_OK, "SetValue: %#lx\n", hr);
        hr = IPropertyStore_GetCount(store, &count);
        ok(hr == S_OK && count == 1, "GetCount: %#lx, %lu\n", hr, count);
        hr = IPropertyStore_GetAt(store, 0, &got);
        ok(hr == S_OK && IsEqualGUID(&got.fmtid, &key.fmtid) && got.pid == key.pid, "GetAt: %#lx\n", hr);
        PropVariantInit(&out);
        hr = IPropertyStore_GetValue(store, &key, &out);
        ok(hr == S_OK && out.vt == VT_I4 && out.lVal == 12345, "GetValue: %#lx vt %d value %ld\n", hr, out.vt, out.lVal);
        PropVariantClear(&out);
        hr = IPropertyStore_Commit(store);
        ok(hr == S_OK, "Commit: %#lx\n", hr);
        IPropertyStore_Release(store);
    }

    hr = CoGetClassObject(&CLSID_InMemoryPropertyStore_, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&cf);
    ok(hr == S_OK, "CoGetClassObject: %#lx\n", hr);
    if (cf)
    {
        hr = IClassFactory_CreateInstance(cf, NULL, &IID_IUnknown, (void **)&unk);
        ok(hr == S_OK, "IClassFactory::CreateInstance: %#lx\n", hr);
        if (unk)
        {
            hr = IUnknown_QueryInterface(unk, &IID_IPropertyStore_, (void **)&store);
            ok(hr == S_OK, "QueryInterface(IPropertyStore): %#lx\n", hr);
            if (store) IPropertyStore_Release(store);
            IUnknown_Release(unk);
        }
        IClassFactory_Release(cf);
    }

    /* two interfaces the store has and one it has not: CO_S_NOTALLINTERFACES */
    mqi[0].pIID = &IID_IPropertyStore_;
    mqi[1].pIID = &IID_IPropertyStoreCache_;
    mqi[2].pIID = &IID_IDispatch;
    hr = CoCreateInstanceEx(&CLSID_InMemoryPropertyStore_, NULL, CLSCTX_INPROC_SERVER, NULL, 3, mqi);
    ok(hr == CO_S_NOTALLINTERFACES, "CoCreateInstanceEx: %#lx\n", hr);
    ok(mqi[0].hr == S_OK && mqi[0].pItf, "IPropertyStore: %#lx %p\n", mqi[0].hr, mqi[0].pItf);
    ok(mqi[1].hr == S_OK && mqi[1].pItf, "IPropertyStoreCache: %#lx %p\n", mqi[1].hr, mqi[1].pItf);
    ok(mqi[2].hr == E_NOINTERFACE && !mqi[2].pItf, "IDispatch: %#lx %p\n", mqi[2].hr, mqi[2].pItf);
    if (mqi[0].pItf) IUnknown_Release(mqi[0].pItf);
    if (mqi[1].pItf) IUnknown_Release(mqi[1].pItf);

    /* only an in-process server is registered */
    unk = (IUnknown *)0xdeadbeef;
    hr = CoCreateInstance(&CLSID_InMemoryPropertyStore_, NULL, CLSCTX_LOCAL_SERVER, &IID_IUnknown, (void **)&unk);
    ok(hr == REGDB_E_CLASSNOTREG && !unk, "CLSCTX_LOCAL_SERVER: %#lx %p\n", hr, unk);

    /* a registered server whose DLL does not exist: the loader's error (Windows reports it the same way) */
    set_default_value(HKEY_CLASSES_ROOT, L"CLSID\\{5A9F1A11-2B3C-4D5E-8F01-123456789ABC}\\InprocServer32",
                      L"C:\\SHZ\\SYS64\\trtmissing.dll");
    unk = (IUnknown *)0xdeadbeef;
    hr = CoCreateInstance(&CLSID_Missing, NULL, CLSCTX_INPROC_SERVER, &IID_IUnknown, (void **)&unk);
    ok(hr == HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND) && !unk, "missing server DLL: %#lx %p\n", hr, unk);
    RegDeleteTreeW(HKEY_CLASSES_ROOT, L"CLSID\\{5A9F1A11-2B3C-4D5E-8F01-123456789ABC}");
}

static void test_class_table(void)
{
    IClassFactory *cf;
    IUnknown *unk;
    DWORD cookie, cookie2;
    HRESULT hr;

    hr = CoRegisterClassObject(&CLSID_Test, (IUnknown *)&test_factory, CLSCTX_INPROC_SERVER, REGCLS_MULTIPLEUSE, &cookie);
    ok(hr == S_OK, "CoRegisterClassObject: %#lx\n", hr);
    ok(factory_refs == 2, "the registration holds one reference: %ld\n", factory_refs);
    objects_created = 0;
    unk = NULL;
    hr = CoCreateInstance(&CLSID_Test, NULL, CLSCTX_INPROC_SERVER, &IID_IUnknown, (void **)&unk);
    ok(hr == S_OK && unk == &test_object && objects_created == 1, "CoCreateInstance: %#lx %p %ld\n", hr, unk, objects_created);
    hr = CoCreateInstance(&CLSID_Test, NULL, CLSCTX_LOCAL_SERVER, &IID_IUnknown, (void **)&unk);
    ok(hr == REGDB_E_CLASSNOTREG, "an in-process registration does not serve CLSCTX_LOCAL_SERVER: %#lx\n", hr);
    hr = CoRegisterClassObject(&CLSID_Test, (IUnknown *)&test_factory, CLSCTX_INPROC_SERVER, REGCLS_MULTIPLEUSE, &cookie2);
    ok(hr == CO_E_OBJISREG, "second registration: %#lx\n", hr);
    hr = CoRevokeClassObject(cookie);
    ok(hr == S_OK, "CoRevokeClassObject: %#lx\n", hr);
    ok(factory_refs == 1, "revoking released the factory: %ld\n", factory_refs);
    hr = CoCreateInstance(&CLSID_Test, NULL, CLSCTX_INPROC_SERVER, &IID_IUnknown, (void **)&unk);
    ok(hr == REGDB_E_CLASSNOTREG, "after revocation: %#lx\n", hr);
    hr = CoRevokeClassObject(cookie);
    ok(hr != S_OK, "revoking twice: %#lx\n", hr);

    /* REGCLS_MULTIPLEUSE with CLSCTX_LOCAL_SERVER also registers CLSCTX_INPROC_SERVER (documented) */
    hr = CoRegisterClassObject(&CLSID_Test, (IUnknown *)&test_factory, CLSCTX_LOCAL_SERVER, REGCLS_MULTIPLEUSE, &cookie);
    ok(hr == S_OK, "CoRegisterClassObject(LOCAL_SERVER): %#lx\n", hr);
    cf = NULL;
    hr = CoGetClassObject(&CLSID_Test, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&cf);
    ok(hr == S_OK && cf == &test_factory, "in-process lookup: %#lx %p\n", hr, cf);
    if (cf) IClassFactory_Release(cf);
    hr = CoGetClassObject(&CLSID_Test, CLSCTX_LOCAL_SERVER, NULL, &IID_IClassFactory, (void **)&cf);
    ok(hr == S_OK && cf == &test_factory, "local-server lookup: %#lx %p\n", hr, cf);
    if (cf) IClassFactory_Release(cf);
    CoRevokeClassObject(cookie);

    /* REGCLS_SUSPENDED: not found until CoResumeClassObjects */
    hr = CoRegisterClassObject(&CLSID_Test, (IUnknown *)&test_factory, CLSCTX_LOCAL_SERVER,
                               REGCLS_MULTIPLEUSE | REGCLS_SUSPENDED, &cookie);
    ok(hr == S_OK, "CoRegisterClassObject(SUSPENDED): %#lx\n", hr);
    hr = CoGetClassObject(&CLSID_Test, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&cf);
    ok(hr == REGDB_E_CLASSNOTREG, "suspended registration found: %#lx\n", hr);
    hr = CoResumeClassObjects();
    ok(hr == S_OK, "CoResumeClassObjects: %#lx\n", hr);
    cf = NULL;
    hr = CoGetClassObject(&CLSID_Test, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&cf);
    ok(hr == S_OK && cf == &test_factory, "resumed registration: %#lx %p\n", hr, cf);
    if (cf) IClassFactory_Release(cf);
    CoRevokeClassObject(cookie);

    /* a registration ends with the apartment that made it */
    hr = CoRegisterClassObject(&CLSID_Test, (IUnknown *)&test_factory, CLSCTX_INPROC_SERVER, REGCLS_SINGLEUSE, &cookie);
    ok(hr == S_OK, "CoRegisterClassObject: %#lx\n", hr);
    CoUninitialize();
    ok(factory_refs == 1, "the apartment's end released the factory: %ld\n", factory_refs);
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    hr = CoGetClassObject(&CLSID_Test, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&cf);
    ok(hr == REGDB_E_CLASSNOTREG, "registration of a destroyed apartment: %#lx\n", hr);
}

static void test_progids(void)
{
    WCHAR *progid, *user_type;
    CLSID clsid;
    HRESULT hr;

    hr = CLSIDFromProgID(L"Shell.Explorer.2", &clsid);
    ok(hr == S_OK && IsEqualCLSID(&clsid, &CLSID_WebBrowser_), "Shell.Explorer.2: %#lx %s\n", hr, wine_dbgstr_guid(&clsid));
    hr = CLSIDFromProgID(L"shell.explorer", &clsid);
    ok(hr == S_OK && IsEqualCLSID(&clsid, &CLSID_WebBrowser_), "shell.explorer: %#lx %s\n", hr, wine_dbgstr_guid(&clsid));
    hr = CLSIDFromProgIDEx(L"JScript", &clsid);
    ok(hr == S_OK && IsEqualCLSID(&clsid, &CLSID_JScript_), "JScript: %#lx %s\n", hr, wine_dbgstr_guid(&clsid));
    memset(&clsid, 0xcc, sizeof(clsid));
    hr = CLSIDFromProgID(L"Shizuku.NoSuchProgID", &clsid);
    ok(hr == CO_E_CLASSSTRING && IsEqualCLSID(&clsid, &CLSID_NULL), "unknown ProgID: %#lx %s\n", hr, wine_dbgstr_guid(&clsid));
    hr = CLSIDFromProgID(NULL, &clsid);
    ok(hr == E_INVALIDARG, "NULL ProgID: %#lx\n", hr);

    /* a version-independent ProgID that only has CurVer */
    set_default_value(HKEY_CLASSES_ROOT, L"Shizuku.TridentTest.1\\CLSID", L"{5A9F1A10-2B3C-4D5E-8F01-123456789ABC}");
    set_default_value(HKEY_CLASSES_ROOT, L"Shizuku.TridentTest\\CurVer", L"Shizuku.TridentTest.1");
    hr = CLSIDFromProgID(L"Shizuku.TridentTest", &clsid);
    ok(hr == S_OK && IsEqualCLSID(&clsid, &CLSID_Test), "CurVer: %#lx %s\n", hr, wine_dbgstr_guid(&clsid));
    RegDeleteTreeW(HKEY_CLASSES_ROOT, L"Shizuku.TridentTest.1");
    RegDeleteTreeW(HKEY_CLASSES_ROOT, L"Shizuku.TridentTest");

    progid = NULL;
    hr = ProgIDFromCLSID(&CLSID_WebBrowser_, &progid);
    ok(hr == S_OK && progid && !lstrcmpW(progid, L"Shell.Explorer.2"), "ProgIDFromCLSID: %#lx %s\n", hr, wine_dbgstr_w(progid));
    CoTaskMemFree(progid);
    hr = ProgIDFromCLSID(&CLSID_NonExistent, &progid);
    ok(hr == REGDB_E_CLASSNOTREG && !progid, "ProgIDFromCLSID(unregistered): %#lx\n", hr);

    user_type = NULL;
    hr = OleRegGetUserType(&CLSID_WebBrowser_, USERCLASSTYPE_FULL, &user_type);
    ok(hr == S_OK && user_type && !lstrcmpW(user_type, L"Microsoft Web Browser"), "OleRegGetUserType: %#lx %s\n",
       hr, wine_dbgstr_w(user_type));
    CoTaskMemFree(user_type);
}

START_TEST(activation)
{
    test_not_initialized();
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    test_unregistered();
    test_registry_activation();
    test_class_table();
    test_progids();
    CoUninitialize();
}
