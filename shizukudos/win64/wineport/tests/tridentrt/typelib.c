/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku checks of tridentrt.dll: type libraries and IDispatch (Wine's oleaut32 typelib.c/dispatch.c + the x86_64
 * DispCallFunc thunk, compiled into tridentrt).
 *  - LoadTypeLib of a raw MSFT stdole2 type library (widl -t of Wine's dlls/stdole2.tlb/stdole2.idl, packed by
 *    wineport as \SHZ\TESTS\TRT_STD2.TLB): library attributes, GetTypeInfoOfGuid(IID_IUnknown / IID_IDispatch),
 *    GetTypeAttr (cbSizeVft 3 / 7 pointers, as Wine's own typelib tests expect), GetFuncDesc, GetNames, IsName
 *    (exact case: Wine's IsName is case-sensitive);
 *  - the registry path: QueryPathOfRegTypeLib of the seeded stdole registration, LoadRegTypeLib of a test library
 *    registered by this test, TYPE_E_LIBNOTREGISTERED for an unregistered one or version;
 *  - CreateDispTypeInfo + CreateStdDispatch over a C object: GetIDsOfNames, and Invoke calling the object's methods
 *    through DispCallFunc (integer, double and BSTR arguments and results, a property get, argument coercion);
 *    DispCallFunc directly on a vtable slot and on a plain function; DispGetParam.
 */
#define COBJMACROS
#include <stdarg.h>
#include <stdio.h>
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "objbase.h"
#include "oleauto.h"
#include "wine/test.h"

static const WCHAR test_tlb[] = L"C:\\SHZ\\TESTS\\TRT_STD2.TLB";
static const GUID LIBID_StdOle_ = {0x00020430, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID LIBID_Test = {0x5a9f1a30, 0x2b3c, 0x4d5e, {0x8f, 0x01, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}};
static const GUID LIBID_Unregistered = {0x5a9f1a31, 0x2b3c, 0x4d5e, {0x8f, 0x01, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}};

static void test_stdole(void)
{
    ITypeLib *tl = NULL, *tl2 = NULL;
    ITypeInfo *ti = NULL, *base = NULL;
    TYPEATTR *attr;
    TLIBATTR *libattr;
    FUNCDESC *fd;
    HREFTYPE href;
    BSTR name = NULL, doc = NULL, names[2];
    WCHAR find[16];
    UINT count;
    BOOL found;
    HRESULT hr;

    hr = LoadTypeLib(test_tlb, &tl);
    ok(hr == S_OK, "LoadTypeLib(%s): %#lx\n", wine_dbgstr_w(test_tlb), hr);
    if (!tl) return;

    hr = ITypeLib_GetLibAttr(tl, &libattr);
    ok(hr == S_OK, "GetLibAttr: %#lx\n", hr);
    ok(IsEqualGUID(&libattr->guid, &LIBID_StdOle_), "library %s\n", wine_dbgstr_guid(&libattr->guid));
    ok(libattr->wMajorVerNum == 2 && libattr->wMinorVerNum == 0, "version %u.%u\n", libattr->wMajorVerNum, libattr->wMinorVerNum);
    ok(libattr->syskind == SYS_WIN64, "syskind %d\n", libattr->syskind);
    ITypeLib_ReleaseTLibAttr(tl, libattr);
    ok(ITypeLib_GetTypeInfoCount(tl) > 0, "no type infos\n");
    hr = ITypeLib_GetDocumentation(tl, -1, &name, &doc, NULL, NULL);
    ok(hr == S_OK && !lstrcmpW(name, L"stdole") && !lstrcmpW(doc, L"OLE Automation"), "library documentation: %#lx %s %s\n",
       hr, wine_dbgstr_w(name), wine_dbgstr_w(doc));
    SysFreeString(name);
    SysFreeString(doc);

    hr = ITypeLib_GetTypeInfoOfGuid(tl, &IID_IUnknown, &ti);
    ok(hr == S_OK, "GetTypeInfoOfGuid(IID_IUnknown): %#lx\n", hr);
    if (ti)
    {
        hr = ITypeInfo_GetTypeAttr(ti, &attr);
        ok(hr == S_OK && attr->typekind == TKIND_INTERFACE && attr->cFuncs == 3 && attr->cbSizeVft == 3 * sizeof(void *),
           "IUnknown: kind %d funcs %u vft %u\n", attr->typekind, attr->cFuncs, attr->cbSizeVft);
        ITypeInfo_ReleaseTypeAttr(ti, attr);
        ITypeInfo_Release(ti);
    }

    ti = NULL;
    hr = ITypeLib_GetTypeInfoOfGuid(tl, &IID_IDispatch, &ti);
    ok(hr == S_OK, "GetTypeInfoOfGuid(IID_IDispatch): %#lx\n", hr);
    if (ti)
    {
        hr = ITypeInfo_GetTypeAttr(ti, &attr);
        ok(hr == S_OK, "GetTypeAttr: %#lx\n", hr);
        ok(IsEqualGUID(&attr->guid, &IID_IDispatch), "guid %s\n", wine_dbgstr_guid(&attr->guid));
        ok(attr->typekind == TKIND_INTERFACE, "typekind %d\n", attr->typekind);
        ok(attr->cFuncs == 4, "cFuncs %u\n", attr->cFuncs);
        ok(attr->cbSizeVft == 7 * sizeof(void *), "cbSizeVft %u\n", attr->cbSizeVft);
        ok(attr->cImplTypes == 1, "cImplTypes %u\n", attr->cImplTypes);
        ITypeInfo_ReleaseTypeAttr(ti, attr);

        hr = ITypeInfo_GetRefTypeOfImplType(ti, 0, &href);
        ok(hr == S_OK, "GetRefTypeOfImplType: %#lx\n", hr);
        hr = ITypeInfo_GetRefTypeInfo(ti, href, &base);
        ok(hr == S_OK, "GetRefTypeInfo: %#lx\n", hr);
        if (base)
        {
            hr = ITypeInfo_GetTypeAttr(base, &attr);
            ok(hr == S_OK && IsEqualGUID(&attr->guid, &IID_IUnknown), "base interface %s\n", wine_dbgstr_guid(&attr->guid));
            ITypeInfo_ReleaseTypeAttr(base, attr);
            ITypeInfo_Release(base);
        }

        hr = ITypeInfo_GetFuncDesc(ti, 0, &fd);
        ok(hr == S_OK, "GetFuncDesc(0): %#lx\n", hr);
        if (hr == S_OK)
        {
            ok(fd->funckind == FUNC_PUREVIRTUAL, "funckind %d\n", fd->funckind);
            ok(fd->invkind == INVOKE_FUNC, "invkind %d\n", fd->invkind);
            ok(fd->callconv == CC_STDCALL, "callconv %d\n", fd->callconv);
            ok(fd->cParams == 1, "cParams %d\n", fd->cParams);
            ok(fd->oVft == 3 * sizeof(void *), "oVft %d\n", fd->oVft);
            ok(fd->elemdescFunc.tdesc.vt == VT_HRESULT, "return vt %d\n", fd->elemdescFunc.tdesc.vt);
            ok(fd->wFuncFlags == FUNCFLAG_FRESTRICTED, "wFuncFlags %#x\n", fd->wFuncFlags);
            hr = ITypeInfo_GetNames(ti, fd->memid, names, 2, &count);
            ok(hr == S_OK && count == 2 && !lstrcmpW(names[0], L"GetTypeInfoCount") && !lstrcmpW(names[1], L"pctinfo"),
               "GetNames: %#lx %u %s\n", hr, count, count ? wine_dbgstr_w(names[0]) : "");
            if (hr == S_OK) while (count--) SysFreeString(names[count]);
            ITypeInfo_ReleaseFuncDesc(ti, fd);
        }
        hr = ITypeInfo_GetFuncDesc(ti, 3, &fd);
        ok(hr == S_OK && fd->cParams == 8 && fd->oVft == 6 * sizeof(void *), "Invoke: %#lx\n", hr);
        if (hr == S_OK) ITypeInfo_ReleaseFuncDesc(ti, fd);
        hr = ITypeInfo_GetFuncDesc(ti, 4, &fd);
        ok(hr == TYPE_E_ELEMENTNOTFOUND, "GetFuncDesc(4): %#lx\n", hr);
        ITypeInfo_Release(ti);
    }

    /* Wine's IsName compares case-sensitively (Windows documents a case-insensitive match): exact names here */
    lstrcpyW(find, L"IDispatch");
    found = FALSE;
    hr = ITypeLib_IsName(tl, find, 0, &found);
    ok(hr == S_OK && found, "IsName(IDispatch): %#lx %d\n", hr, found);
    lstrcpyW(find, L"Invoke");
    found = FALSE;
    hr = ITypeLib_IsName(tl, find, 0, &found);
    ok(hr == S_OK && found, "IsName(Invoke): %#lx %d\n", hr, found);
    lstrcpyW(find, L"NoSuchName");
    found = TRUE;
    hr = ITypeLib_IsName(tl, find, 0, &found);
    ok(hr == S_OK && !found, "IsName(NoSuchName): %#lx %d\n", hr, found);

    hr = LoadTypeLib(test_tlb, &tl2);
    ok(hr == S_OK && tl2 == tl, "second LoadTypeLib: %#lx %p %p\n", hr, tl2, tl);
    if (tl2) ITypeLib_Release(tl2);
    ITypeLib_Release(tl);

    tl = (ITypeLib *)0xdeadbeef;
    hr = LoadTypeLib(L"C:\\SHZ\\TESTS\\TRT_NONE.TLB", &tl);
    ok(hr == TYPE_E_CANTLOADLIBRARY, "missing file: %#lx\n", hr);
}

static void test_registered(void)
{
    ITypeLib *tl = NULL;
    TLIBATTR *libattr;
    BSTR path = NULL;
    HKEY key;
    LONG res;
    HRESULT hr;

    /* seeded by tridentrt (register.c): stdole 2.0 -> C:\SHZ\SYS64\stdole2.tlb */
    hr = QueryPathOfRegTypeLib(&LIBID_StdOle_, 2, 0, LOCALE_NEUTRAL, &path);
    ok(hr == S_OK && path && !lstrcmpiW(path, L"C:\\SHZ\\SYS64\\stdole2.tlb"), "stdole path: %#lx %s\n", hr, wine_dbgstr_w(path));
    SysFreeString(path);

    res = RegCreateKeyExW(HKEY_CLASSES_ROOT, L"TypeLib\\{5A9F1A30-2B3C-4D5E-8F01-123456789ABC}\\2.0\\0\\win64", 0, NULL, 0,
                          KEY_ALL_ACCESS, NULL, &key, NULL);
    ok(!res, "RegCreateKeyExW: %ld\n", res);
    if (!res)
    {
        RegSetValueExW(key, NULL, 0, REG_SZ, (const BYTE *)test_tlb, sizeof(test_tlb));
        RegCloseKey(key);
    }
    path = NULL;
    hr = QueryPathOfRegTypeLib(&LIBID_Test, 2, 0, LOCALE_NEUTRAL, &path);
    ok(hr == S_OK && path && !lstrcmpiW(path, test_tlb), "test library path: %#lx %s\n", hr, wine_dbgstr_w(path));
    SysFreeString(path);
    hr = LoadRegTypeLib(&LIBID_Test, 2, 0, LOCALE_NEUTRAL, &tl);
    ok(hr == S_OK, "LoadRegTypeLib: %#lx\n", hr);
    if (tl)
    {
        hr = ITypeLib_GetLibAttr(tl, &libattr);
        ok(hr == S_OK && IsEqualGUID(&libattr->guid, &LIBID_StdOle_), "loaded library %s\n", wine_dbgstr_guid(&libattr->guid));
        ITypeLib_ReleaseTLibAttr(tl, libattr);
        ITypeLib_Release(tl);
    }
    tl = NULL;
    hr = LoadRegTypeLib(&LIBID_Test, 3, 0, LOCALE_NEUTRAL, &tl);
    ok(hr == TYPE_E_LIBNOTREGISTERED && !tl, "unregistered version: %#lx\n", hr);
    hr = LoadRegTypeLib(&LIBID_Unregistered, 1, 0, LOCALE_NEUTRAL, &tl);
    ok(hr == TYPE_E_LIBNOTREGISTERED && !tl, "unregistered library: %#lx\n", hr);
    RegDeleteTreeW(HKEY_CLASSES_ROOT, L"TypeLib\\{5A9F1A30-2B3C-4D5E-8F01-123456789ABC}");
}

/* ---------------------------------------------------------------- an object called through IDispatch */
struct calc
{
    const void **vtbl;
    LONG total;
};

static HRESULT WINAPI calc_QueryInterface(struct calc *This, REFIID riid, void **obj) { *obj = NULL; return E_NOINTERFACE; }
static ULONG WINAPI calc_AddRef(struct calc *This) { return 2; }
static ULONG WINAPI calc_Release(struct calc *This) { return 1; }
static LONG WINAPI calc_Add(struct calc *This, LONG a, LONG b) { This->total += a + b; return a + b; }
static double WINAPI calc_Scale(struct calc *This, double x, LONG k) { return x * k; }
static BSTR WINAPI calc_Concat(struct calc *This, BSTR a, BSTR b)
{
    BSTR r = SysAllocStringLen(NULL, SysStringLen(a) + SysStringLen(b));
    if (r)
    {
        memcpy(r, a, SysStringLen(a) * sizeof(WCHAR));
        memcpy(r + SysStringLen(a), b, SysStringLen(b) * sizeof(WCHAR));
    }
    return r;
}
static LONG WINAPI calc_get_Total(struct calc *This) { return This->total; }
static LONG WINAPI plain_sub(LONG a, LONG b) { return a - b; }

static const void *calc_vtbl[] =
{
    (void *)calc_QueryInterface, (void *)calc_AddRef, (void *)calc_Release, (void *)calc_Add, (void *)calc_Scale,
    (void *)calc_Concat, (void *)calc_get_Total
};

static HRESULT invoke(IDispatch *disp, DISPID id, WORD flags, VARIANT *args, UINT nargs, VARIANT *res)
{
    DISPPARAMS dp = { args, NULL, nargs, 0 };
    EXCEPINFO ei;
    UINT argerr = 0;
    VariantInit(res);
    return IDispatch_Invoke(disp, id, &IID_NULL, LOCALE_NEUTRAL, flags, &dp, res, &ei, &argerr);
}

static void test_dispatch(void)
{
    static PARAMDATA add_params[] = { { (OLECHAR *)L"a", VT_I4 }, { (OLECHAR *)L"b", VT_I4 } };
    static PARAMDATA scale_params[] = { { (OLECHAR *)L"x", VT_R8 }, { (OLECHAR *)L"k", VT_I4 } };
    static PARAMDATA concat_params[] = { { (OLECHAR *)L"a", VT_BSTR }, { (OLECHAR *)L"b", VT_BSTR } };
    METHODDATA methods[4] =
    {
        { (OLECHAR *)L"Add", add_params, 1, 3, CC_STDCALL, 2, DISPATCH_METHOD, VT_I4 },
        { (OLECHAR *)L"Scale", scale_params, 2, 4, CC_STDCALL, 2, DISPATCH_METHOD, VT_R8 },
        { (OLECHAR *)L"Concat", concat_params, 3, 5, CC_STDCALL, 2, DISPATCH_METHOD, VT_BSTR },
        { (OLECHAR *)L"Total", NULL, 4, 6, CC_STDCALL, 0, DISPATCH_PROPERTYGET, VT_I4 },
    };
    INTERFACEDATA idata = { methods, ARRAY_SIZE(methods) };
    struct calc calc = { calc_vtbl, 0 };
    ITypeInfo *coclass = NULL, *iface = NULL;
    IUnknown *unk = NULL;
    IDispatch *disp = NULL;
    OLECHAR *name;
    VARIANT args[2], res, *argptrs[2];
    VARTYPE types[2];
    DISPPARAMS dp;
    HREFTYPE href;
    DISPID id;
    UINT argerr;
    HRESULT hr;

    hr = CreateDispTypeInfo(&idata, LOCALE_NEUTRAL, &coclass);
    ok(hr == S_OK, "CreateDispTypeInfo: %#lx\n", hr);
    if (!coclass) return;
    hr = ITypeInfo_GetRefTypeOfImplType(coclass, 0, &href);
    ok(hr == S_OK, "GetRefTypeOfImplType: %#lx\n", hr);
    hr = ITypeInfo_GetRefTypeInfo(coclass, href, &iface);
    ok(hr == S_OK, "GetRefTypeInfo: %#lx\n", hr);
    if (!iface) { ITypeInfo_Release(coclass); return; }

    name = (OLECHAR *)L"Concat";
    hr = DispGetIDsOfNames(iface, &name, 1, &id);
    ok(hr == S_OK && id == 3, "DispGetIDsOfNames(Concat): %#lx %ld\n", hr, id);

    hr = CreateStdDispatch(NULL, &calc, iface, &unk);
    ok(hr == S_OK, "CreateStdDispatch: %#lx\n", hr);
    if (unk)
    {
        hr = IUnknown_QueryInterface(unk, &IID_IDispatch, (void **)&disp);
        ok(hr == S_OK, "QueryInterface(IDispatch): %#lx\n", hr);
        IUnknown_Release(unk);
    }
    if (disp)
    {
        name = (OLECHAR *)L"scale";
        hr = IDispatch_GetIDsOfNames(disp, &IID_NULL, &name, 1, LOCALE_NEUTRAL, &id);
        ok(hr == S_OK && id == 2, "GetIDsOfNames(scale): %#lx %ld\n", hr, id);
        name = (OLECHAR *)L"Divide";
        hr = IDispatch_GetIDsOfNames(disp, &IID_NULL, &name, 1, LOCALE_NEUTRAL, &id);
        ok(hr == DISP_E_UNKNOWNNAME, "GetIDsOfNames(Divide): %#lx\n", hr);

        /* arguments are passed right to left */
        V_VT(&args[0]) = VT_I4; V_I4(&args[0]) = 5;
        V_VT(&args[1]) = VT_I4; V_I4(&args[1]) = 37;
        hr = invoke(disp, 1, DISPATCH_METHOD, args, 2, &res);
        ok(hr == S_OK && V_VT(&res) == VT_I4 && V_I4(&res) == 42, "Add(37, 5): %#lx vt %d %ld\n", hr, V_VT(&res), V_I4(&res));

        V_VT(&args[0]) = VT_I4; V_I4(&args[0]) = 4;
        V_VT(&args[1]) = VT_R8; V_R8(&args[1]) = 1.25;
        hr = invoke(disp, 2, DISPATCH_METHOD, args, 2, &res);
        ok(hr == S_OK && V_VT(&res) == VT_R8 && V_R8(&res) == 5.0, "Scale(1.25, 4): %#lx vt %d\n", hr, V_VT(&res));

        V_VT(&args[0]) = VT_BSTR; V_BSTR(&args[0]) = SysAllocString(L"Trident");
        V_VT(&args[1]) = VT_BSTR; V_BSTR(&args[1]) = SysAllocString(L"Shizuku ");
        hr = invoke(disp, 3, DISPATCH_METHOD, args, 2, &res);
        ok(hr == S_OK && V_VT(&res) == VT_BSTR && !lstrcmpW(V_BSTR(&res), L"Shizuku Trident"), "Concat: %#lx vt %d %s\n",
           hr, V_VT(&res), V_VT(&res) == VT_BSTR ? wine_dbgstr_w(V_BSTR(&res)) : "");
        VariantClear(&res);
        VariantClear(&args[0]);
        VariantClear(&args[1]);

        /* a BSTR argument coerced to the declared VT_I4 */
        V_VT(&args[0]) = VT_BSTR; V_BSTR(&args[0]) = SysAllocString(L"20");
        V_VT(&args[1]) = VT_I2; V_I2(&args[1]) = 3;
        hr = invoke(disp, 1, DISPATCH_METHOD, args, 2, &res);
        ok(hr == S_OK && V_VT(&res) == VT_I4 && V_I4(&res) == 23, "Add(3, \"20\"): %#lx vt %d %ld\n", hr, V_VT(&res), V_I4(&res));
        VariantClear(&args[0]);

        hr = invoke(disp, 4, DISPATCH_PROPERTYGET, NULL, 0, &res);
        ok(hr == S_OK && V_VT(&res) == VT_I4 && V_I4(&res) == 65, "Total: %#lx vt %d %ld\n", hr, V_VT(&res), V_I4(&res));
        hr = invoke(disp, 1, DISPATCH_METHOD, args, 1, &res);
        ok(hr == DISP_E_BADPARAMCOUNT, "Add with one argument: %#lx\n", hr);
        IDispatch_Release(disp);
    }

    /* DispCallFunc on a vtable slot, and on a plain function (NULL instance: oVft is the address) */
    V_VT(&args[0]) = VT_I4; V_I4(&args[0]) = 40;
    V_VT(&args[1]) = VT_I4; V_I4(&args[1]) = 2;
    types[0] = types[1] = VT_I4;
    argptrs[0] = &args[0];
    argptrs[1] = &args[1];
    VariantInit(&res);
    hr = DispCallFunc(&calc, 3 * sizeof(void *), CC_STDCALL, VT_I4, 2, types, argptrs, &res);
    ok(hr == S_OK && V_VT(&res) == VT_I4 && V_I4(&res) == 42, "DispCallFunc(Add): %#lx %ld\n", hr, V_I4(&res));
    VariantInit(&res);
    hr = DispCallFunc(NULL, (ULONG_PTR)plain_sub, CC_STDCALL, VT_I4, 2, types, argptrs, &res);
    ok(hr == S_OK && V_VT(&res) == VT_I4 && V_I4(&res) == 38, "DispCallFunc(plain_sub): %#lx %ld\n", hr, V_I4(&res));

    /* DispGetParam: positional argument 0 is the last in rgvarg, coerced to the asked type */
    V_VT(&args[0]) = VT_BSTR; V_BSTR(&args[0]) = SysAllocString(L"7");
    V_VT(&args[1]) = VT_R8; V_R8(&args[1]) = 2.5;
    dp.rgvarg = args;
    dp.rgdispidNamedArgs = NULL;
    dp.cArgs = 2;
    dp.cNamedArgs = 0;
    VariantInit(&res);
    hr = DispGetParam(&dp, 0, VT_I4, &res, &argerr);
    ok(hr == S_OK && V_VT(&res) == VT_I4 && V_I4(&res) == 2, "DispGetParam(0): %#lx %ld\n", hr, V_I4(&res));
    hr = DispGetParam(&dp, 1, VT_I4, &res, &argerr);
    ok(hr == S_OK && V_VT(&res) == VT_I4 && V_I4(&res) == 7, "DispGetParam(1): %#lx\n", hr);
    hr = DispGetParam(&dp, 2, VT_I4, &res, &argerr);
    ok(hr == DISP_E_PARAMNOTFOUND, "DispGetParam(2): %#lx\n", hr);
    VariantClear(&args[0]);

    ITypeInfo_Release(iface);
    ITypeInfo_Release(coclass);
}

START_TEST(typelib)
{
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    test_stdole();
    test_registered();
    test_dispatch();
    CoUninitialize();
}
