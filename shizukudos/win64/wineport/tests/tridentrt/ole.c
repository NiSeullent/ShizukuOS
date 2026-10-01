/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku checks of tridentrt.dll: the OLE services the browser modules use besides activation.
 *  - CreateStreamOnHGlobal (Wine combase hglobalstream.c): write, seek, read, stat, set size, clone, and
 *    GetHGlobalFromStream; a stream over an existing HGLOBAL;
 *  - CreateBindCtx (Wine ole32 bindctx.c): object parameters, bind options, bound objects, its running object table;
 *  - GetRunningObjectTable (per-process table): register, is-running, get-object, revoke;
 *  - GetErrorInfo/SetErrorInfo/CreateErrorInfo;
 *  - CreateOleAdviseHolder / CreateDataAdviseHolder (Wine ole32 oleobj.c): advise, notify, unadvise;
 *  - ReleaseStgMedium (documented pUnkForRelease semantics).
 */
#define COBJMACROS
#include <stdarg.h>
#include <stdio.h>
#include "windef.h"
#include "winbase.h"
#include "objbase.h"
#include "oleauto.h"
#include "ole2.h"
#include "wine/test.h"

/* ---------------------------------------------------------------- a counting IUnknown */
static LONG obj_refs;
static HRESULT WINAPI obj_QueryInterface(IUnknown *iface, REFIID riid, void **obj)
{
    if (IsEqualIID(riid, &IID_IUnknown)) { *obj = iface; IUnknown_AddRef(iface); return S_OK; }
    *obj = NULL;
    return E_NOINTERFACE;
}
static ULONG WINAPI obj_AddRef(IUnknown *iface) { return InterlockedIncrement(&obj_refs); }
static ULONG WINAPI obj_Release(IUnknown *iface) { return InterlockedDecrement(&obj_refs); }
static const IUnknownVtbl obj_vtbl = { obj_QueryInterface, obj_AddRef, obj_Release };
static IUnknown test_obj = { &obj_vtbl };

static void test_hglobal_stream(void)
{
    static const char text[] = "Shizuku Trident";
    IStream *stream = NULL, *clone = NULL;
    LARGE_INTEGER move;
    ULARGE_INTEGER pos, size;
    HGLOBAL mem = NULL, own;
    STATSTG stat;
    char buf[32];
    ULONG n;
    HRESULT hr;

    hr = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    ok(hr == S_OK && stream, "CreateStreamOnHGlobal: %#lx\n", hr);
    if (!stream) return;
    hr = IStream_Write(stream, text, sizeof(text) - 1, &n);
    ok(hr == S_OK && n == sizeof(text) - 1, "Write: %#lx %lu\n", hr, n);
    move.QuadPart = 0;
    hr = IStream_Seek(stream, move, STREAM_SEEK_CUR, &pos);
    ok(hr == S_OK && pos.QuadPart == sizeof(text) - 1, "Seek(CUR): %#lx %lu\n", hr, (ULONG)pos.QuadPart);
    move.QuadPart = 8;
    hr = IStream_Seek(stream, move, STREAM_SEEK_SET, &pos);
    ok(hr == S_OK && pos.QuadPart == 8, "Seek(SET 8): %#lx\n", hr);
    memset(buf, 0, sizeof(buf));
    hr = IStream_Read(stream, buf, sizeof(buf), &n);
    ok(hr == S_OK && n == 7 && !memcmp(buf, "Trident", 7), "Read: %#lx %lu %s\n", hr, n, buf);
    hr = IStream_Stat(stream, &stat, STATFLAG_NONAME);
    ok(hr == S_OK && stat.type == STGTY_STREAM && stat.cbSize.QuadPart == sizeof(text) - 1, "Stat: %#lx size %lu\n", hr,
       (ULONG)stat.cbSize.QuadPart);
    size.QuadPart = 64;
    hr = IStream_SetSize(stream, size);
    ok(hr == S_OK, "SetSize: %#lx\n", hr);
    hr = IStream_Stat(stream, &stat, STATFLAG_NONAME);
    ok(hr == S_OK && stat.cbSize.QuadPart == 64, "Stat after SetSize: %lu\n", (ULONG)stat.cbSize.QuadPart);
    hr = IStream_Clone(stream, &clone);
    ok(hr == S_OK && clone, "Clone: %#lx\n", hr);
    if (clone)
    {
        move.QuadPart = 0;
        IStream_Seek(clone, move, STREAM_SEEK_SET, NULL);
        memset(buf, 0, sizeof(buf));
        hr = IStream_Read(clone, buf, 7, &n);
        ok(hr == S_OK && n == 7 && !memcmp(buf, "Shizuku", 7), "Read through the clone: %#lx %s\n", hr, buf);
        IStream_Release(clone);
    }
    hr = GetHGlobalFromStream(stream, &mem);
    ok(hr == S_OK && mem && GlobalSize(mem) >= 64, "GetHGlobalFromStream: %#lx %p\n", hr, mem);
    if (mem)
    {
        const char *p = GlobalLock(mem);
        ok(p && !memcmp(p, text, sizeof(text) - 1), "HGLOBAL contents\n");
        GlobalUnlock(mem);
    }
    IStream_Release(stream);

    /* a stream over existing memory the caller keeps */
    own = GlobalAlloc(GMEM_MOVEABLE, 5);
    memcpy(GlobalLock(own), "hello", 5);
    GlobalUnlock(own);
    stream = NULL;
    hr = CreateStreamOnHGlobal(own, FALSE, &stream);
    ok(hr == S_OK, "CreateStreamOnHGlobal(existing): %#lx\n", hr);
    if (stream)
    {
        memset(buf, 0, sizeof(buf));
        hr = IStream_Read(stream, buf, sizeof(buf), &n);
        ok(hr == S_OK && n == 5 && !memcmp(buf, "hello", 5), "Read existing memory: %#lx %lu\n", hr, n);
        IStream_Release(stream);
    }
    ok(GlobalSize(own) >= 5, "the caller's HGLOBAL was freed\n");
    GlobalFree(own);
}

/* ---------------------------------------------------------------- a moniker for the running object table */
static LONG mk_refs;
static HRESULT WINAPI mk_QueryInterface(IMoniker *iface, REFIID riid, void **obj)
{
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IMoniker)) { *obj = iface; IMoniker_AddRef(iface); return S_OK; }
    *obj = NULL;
    return E_NOINTERFACE;
}
static ULONG WINAPI mk_AddRef(IMoniker *iface) { return InterlockedIncrement(&mk_refs); }
static ULONG WINAPI mk_Release(IMoniker *iface) { return InterlockedDecrement(&mk_refs); }
static HRESULT WINAPI mk_GetClassID(IMoniker *iface, CLSID *clsid) { return E_FAIL; }
static HRESULT WINAPI mk_IsDirty(IMoniker *iface) { return S_FALSE; }
static HRESULT WINAPI mk_Load(IMoniker *iface, IStream *stm) { return E_FAIL; }
static HRESULT WINAPI mk_Save(IMoniker *iface, IStream *stm, BOOL clear) { return E_FAIL; }
static HRESULT WINAPI mk_GetSizeMax(IMoniker *iface, ULARGE_INTEGER *size) { return E_FAIL; }
static HRESULT WINAPI mk_BindToObject(IMoniker *iface, IBindCtx *bc, IMoniker *left, REFIID riid, void **obj) { return E_FAIL; }
static HRESULT WINAPI mk_BindToStorage(IMoniker *iface, IBindCtx *bc, IMoniker *left, REFIID riid, void **obj) { return E_FAIL; }
static HRESULT WINAPI mk_Reduce(IMoniker *iface, IBindCtx *bc, DWORD how, IMoniker **left, IMoniker **reduced) { return E_FAIL; }
static HRESULT WINAPI mk_ComposeWith(IMoniker *iface, IMoniker *right, BOOL only_generic, IMoniker **composite) { return E_FAIL; }
static HRESULT WINAPI mk_Enum(IMoniker *iface, BOOL forward, IEnumMoniker **e) { return E_FAIL; }
static HRESULT WINAPI mk_IsEqual(IMoniker *iface, IMoniker *other) { return iface == other ? S_OK : S_FALSE; }
static HRESULT WINAPI mk_Hash(IMoniker *iface, DWORD *hash) { *hash = 1; return S_OK; }
static HRESULT WINAPI mk_IsRunning(IMoniker *iface, IBindCtx *bc, IMoniker *left, IMoniker *newly) { return E_FAIL; }
static HRESULT WINAPI mk_GetTimeOfLastChange(IMoniker *iface, IBindCtx *bc, IMoniker *left, FILETIME *t) { return E_FAIL; }
static HRESULT WINAPI mk_Inverse(IMoniker *iface, IMoniker **mk) { return E_FAIL; }
static HRESULT WINAPI mk_CommonPrefixWith(IMoniker *iface, IMoniker *other, IMoniker **prefix) { return E_FAIL; }
static HRESULT WINAPI mk_RelativePathTo(IMoniker *iface, IMoniker *other, IMoniker **rel) { return E_FAIL; }
static HRESULT WINAPI mk_GetDisplayName(IMoniker *iface, IBindCtx *bc, IMoniker *left, LPOLESTR *name) { return E_FAIL; }
static HRESULT WINAPI mk_ParseDisplayName(IMoniker *iface, IBindCtx *bc, IMoniker *left, LPOLESTR name, ULONG *eaten,
                                          IMoniker **out) { return E_FAIL; }
static HRESULT WINAPI mk_IsSystemMoniker(IMoniker *iface, DWORD *sys) { *sys = MKSYS_NONE; return S_FALSE; }
static const IMonikerVtbl mk_vtbl =
{
    mk_QueryInterface, mk_AddRef, mk_Release, mk_GetClassID, mk_IsDirty, mk_Load, mk_Save, mk_GetSizeMax,
    mk_BindToObject, mk_BindToStorage, mk_Reduce, mk_ComposeWith, mk_Enum, mk_IsEqual, mk_Hash, mk_IsRunning,
    mk_GetTimeOfLastChange, mk_Inverse, mk_CommonPrefixWith, mk_RelativePathTo, mk_GetDisplayName,
    mk_ParseDisplayName, mk_IsSystemMoniker
};
static IMoniker test_moniker = { &mk_vtbl };
static IMoniker other_moniker = { &mk_vtbl };

static void test_bind_ctx_and_rot(void)
{
    IRunningObjectTable *rot = NULL, *rot2 = NULL;
    IEnumMoniker *e = NULL;
    IMoniker *got_mk;
    IBindCtx *bc = NULL;
    IUnknown *unk;
    BIND_OPTS opts;
    DWORD cookie = 0;
    ULONG fetched;
    HRESULT hr;

    hr = CreateBindCtx(0, &bc);
    ok(hr == S_OK && bc, "CreateBindCtx: %#lx\n", hr);
    if (!bc) return;
    obj_refs = 1;
    hr = IBindCtx_RegisterObjectParam(bc, (OLECHAR *)L"Shizuku.Param", &test_obj);
    ok(hr == S_OK && obj_refs == 2, "RegisterObjectParam: %#lx refs %ld\n", hr, obj_refs);
    unk = NULL;
    hr = IBindCtx_GetObjectParam(bc, (OLECHAR *)L"Shizuku.Param", &unk);
    ok(hr == S_OK && unk == &test_obj, "GetObjectParam: %#lx %p\n", hr, unk);
    if (unk) IUnknown_Release(unk);
    hr = IBindCtx_RevokeObjectParam(bc, (OLECHAR *)L"Shizuku.Param");
    ok(hr == S_OK && obj_refs == 1, "RevokeObjectParam: %#lx refs %ld\n", hr, obj_refs);
    hr = IBindCtx_GetObjectParam(bc, (OLECHAR *)L"Shizuku.Param", &unk);
    ok(hr == E_FAIL && !unk, "GetObjectParam after revoke: %#lx\n", hr);

    memset(&opts, 0xcc, sizeof(opts));
    opts.cbStruct = sizeof(opts);
    hr = IBindCtx_GetBindOptions(bc, &opts);
    ok(hr == S_OK && opts.grfFlags == 0 && opts.grfMode == STGM_READWRITE && opts.dwTickCountDeadline == 0,
       "GetBindOptions: %#lx flags %#lx mode %#lx\n", hr, opts.grfFlags, opts.grfMode);
    opts.grfFlags = BIND_MAYBOTHERUSER;
    hr = IBindCtx_SetBindOptions(bc, &opts);
    ok(hr == S_OK, "SetBindOptions: %#lx\n", hr);
    opts.grfFlags = 0;
    IBindCtx_GetBindOptions(bc, &opts);
    ok(opts.grfFlags == BIND_MAYBOTHERUSER, "bind flags %#lx\n", opts.grfFlags);

    hr = IBindCtx_RegisterObjectBound(bc, &test_obj);
    ok(hr == S_OK && obj_refs == 2, "RegisterObjectBound: %#lx refs %ld\n", hr, obj_refs);
    hr = IBindCtx_ReleaseBoundObjects(bc);
    ok(hr == S_OK && obj_refs == 1, "ReleaseBoundObjects: %#lx refs %ld\n", hr, obj_refs);

    hr = IBindCtx_GetRunningObjectTable(bc, &rot);
    ok(hr == S_OK && rot, "IBindCtx::GetRunningObjectTable: %#lx\n", hr);
    hr = GetRunningObjectTable(0, &rot2);
    ok(hr == S_OK && rot2 == rot, "GetRunningObjectTable: %#lx %p %p\n", hr, rot2, rot);
    if (rot2) IRunningObjectTable_Release(rot2);
    IBindCtx_Release(bc);
    if (!rot) return;

    mk_refs = 1;
    hr = IRunningObjectTable_Register(rot, 0, &test_obj, &test_moniker, &cookie);
    ok(hr == S_OK && cookie, "Register: %#lx %lu\n", hr, cookie);
    ok(IRunningObjectTable_IsRunning(rot, &test_moniker) == S_OK, "IsRunning(registered)\n");
    ok(IRunningObjectTable_IsRunning(rot, &other_moniker) == S_FALSE, "IsRunning(other)\n");
    unk = NULL;
    hr = IRunningObjectTable_GetObject(rot, &test_moniker, &unk);
    ok(hr == S_OK && unk == &test_obj, "GetObject: %#lx\n", hr);
    if (unk) IUnknown_Release(unk);
    hr = IRunningObjectTable_GetObject(rot, &other_moniker, &unk);
    ok(hr == MK_E_UNAVAILABLE && !unk, "GetObject(other): %#lx\n", hr);
    hr = IRunningObjectTable_EnumRunning(rot, &e);
    ok(hr == S_OK && e, "EnumRunning: %#lx\n", hr);
    if (e)
    {
        got_mk = NULL;
        hr = IEnumMoniker_Next(e, 1, &got_mk, &fetched);
        ok(hr == S_OK && fetched == 1 && got_mk == &test_moniker, "IEnumMoniker::Next: %#lx %lu\n", hr, fetched);
        if (got_mk) IMoniker_Release(got_mk);
        IEnumMoniker_Release(e);
    }
    hr = IRunningObjectTable_Revoke(rot, cookie);
    ok(hr == S_OK, "Revoke: %#lx\n", hr);
    ok(IRunningObjectTable_IsRunning(rot, &test_moniker) == S_FALSE, "IsRunning after revoke\n");
    ok(obj_refs == 1 && mk_refs == 1, "references left: object %ld moniker %ld\n", obj_refs, mk_refs);
    hr = IRunningObjectTable_Revoke(rot, cookie);
    ok(hr == E_INVALIDARG, "second Revoke: %#lx\n", hr);
    IRunningObjectTable_Release(rot);
}

static void test_error_info(void)
{
    static const GUID guid = {0x5a9f1a40, 0x2b3c, 0x4d5e, {0x8f, 0x01, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}};
    ICreateErrorInfo *create = NULL;
    IErrorInfo *info = NULL, *got = NULL;
    BSTR desc = NULL, source = NULL;
    GUID g;
    HRESULT hr;

    hr = GetErrorInfo(0, &got);
    ok(hr == S_FALSE && !got, "GetErrorInfo with nothing set: %#lx\n", hr);
    hr = CreateErrorInfo(&create);
    ok(hr == S_OK && create, "CreateErrorInfo: %#lx\n", hr);
    if (!create) return;
    ICreateErrorInfo_SetGUID(create, &guid);
    ICreateErrorInfo_SetSource(create, (OLECHAR *)L"tridentrt");
    ICreateErrorInfo_SetDescription(create, (OLECHAR *)L"it failed");
    hr = ICreateErrorInfo_QueryInterface(create, &IID_IErrorInfo, (void **)&info);
    ok(hr == S_OK, "QueryInterface(IErrorInfo): %#lx\n", hr);
    ICreateErrorInfo_Release(create);
    if (!info) return;
    hr = SetErrorInfo(0, info);
    ok(hr == S_OK, "SetErrorInfo: %#lx\n", hr);
    IErrorInfo_Release(info);
    hr = GetErrorInfo(0, &got);
    ok(hr == S_OK && got == info, "GetErrorInfo: %#lx\n", hr);
    if (got)
    {
        IErrorInfo_GetGUID(got, &g);
        IErrorInfo_GetSource(got, &source);
        IErrorInfo_GetDescription(got, &desc);
        ok(IsEqualGUID(&g, &guid) && !lstrcmpW(source, L"tridentrt") && !lstrcmpW(desc, L"it failed"),
           "error info contents: %s %s\n", wine_dbgstr_w(source), wine_dbgstr_w(desc));
        SysFreeString(source);
        SysFreeString(desc);
        IErrorInfo_Release(got);
    }
    got = NULL;
    hr = GetErrorInfo(0, &got);
    ok(hr == S_FALSE && !got, "GetErrorInfo takes the error away: %#lx\n", hr);
}

/* ---------------------------------------------------------------- an advise sink */
static LONG closes, sink_refs;
static HRESULT WINAPI sink_QueryInterface(IAdviseSink *iface, REFIID riid, void **obj)
{
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IAdviseSink)) { *obj = iface; IAdviseSink_AddRef(iface); return S_OK; }
    *obj = NULL;
    return E_NOINTERFACE;
}
static ULONG WINAPI sink_AddRef(IAdviseSink *iface) { return InterlockedIncrement(&sink_refs); }
static ULONG WINAPI sink_Release(IAdviseSink *iface) { return InterlockedDecrement(&sink_refs); }
static void WINAPI sink_OnDataChange(IAdviseSink *iface, FORMATETC *fmt, STGMEDIUM *med) { }
static void WINAPI sink_OnViewChange(IAdviseSink *iface, DWORD aspect, LONG index) { }
static void WINAPI sink_OnRename(IAdviseSink *iface, IMoniker *mk) { }
static void WINAPI sink_OnSave(IAdviseSink *iface) { }
static void WINAPI sink_OnClose(IAdviseSink *iface) { InterlockedIncrement(&closes); }
static const IAdviseSinkVtbl sink_vtbl =
{
    sink_QueryInterface, sink_AddRef, sink_Release, sink_OnDataChange, sink_OnViewChange, sink_OnRename, sink_OnSave,
    sink_OnClose
};
static IAdviseSink test_sink = { &sink_vtbl };

static void test_advise_holders(void)
{
    IOleAdviseHolder *holder = NULL;
    IDataAdviseHolder *data = NULL;
    DWORD cookie = 0;
    HRESULT hr;

    hr = CreateOleAdviseHolder(&holder);
    ok(hr == S_OK && holder, "CreateOleAdviseHolder: %#lx\n", hr);
    if (holder)
    {
        sink_refs = 1;
        hr = IOleAdviseHolder_Advise(holder, &test_sink, &cookie);
        ok(hr == S_OK && cookie && sink_refs == 2, "Advise: %#lx %lu refs %ld\n", hr, cookie, sink_refs);
        closes = 0;
        hr = IOleAdviseHolder_SendOnClose(holder);
        ok(hr == S_OK && closes == 1, "SendOnClose: %#lx %ld\n", hr, closes);
        hr = IOleAdviseHolder_Unadvise(holder, cookie);
        ok(hr == S_OK && sink_refs == 1, "Unadvise: %#lx refs %ld\n", hr, sink_refs);
        hr = IOleAdviseHolder_Unadvise(holder, cookie);
        ok(hr == OLE_E_NOCONNECTION, "second Unadvise: %#lx\n", hr);
        IOleAdviseHolder_Release(holder);
    }
    hr = CreateDataAdviseHolder(&data);
    ok(hr == S_OK && data, "CreateDataAdviseHolder: %#lx\n", hr);
    if (data) IDataAdviseHolder_Release(data);
}

static void test_release_stg_medium(void)
{
    STGMEDIUM med;

    med.tymed = TYMED_HGLOBAL;
    med.hGlobal = GlobalAlloc(GMEM_MOVEABLE, 16);
    med.pUnkForRelease = NULL;
    ReleaseStgMedium(&med);
    ok(med.tymed == TYMED_NULL, "tymed after release: %lu\n", med.tymed);

    /* with pUnkForRelease only that object is released; the memory belongs to it */
    obj_refs = 2;
    med.tymed = TYMED_HGLOBAL;
    med.hGlobal = GlobalAlloc(GMEM_MOVEABLE, 16);
    med.pUnkForRelease = &test_obj;
    ReleaseStgMedium(&med);
    ok(obj_refs == 1 && !med.pUnkForRelease && med.tymed == TYMED_NULL, "pUnkForRelease: refs %ld\n", obj_refs);
}

START_TEST(ole)
{
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    test_hglobal_stream();
    test_bind_ctx_and_rot();
    test_error_info();
    test_advise_holders();
    test_release_stg_medium();
    CoUninitialize();
}
