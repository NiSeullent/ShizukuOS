/* SPDX-License-Identifier: GPL-2.0-only
 * ole32.dll: the in-process class table (CoRegisterClassObject / CoGetClassObject / CoCreateInstance / CoCreateInstanceEx
 * with REGCLS semantics, REGDB_E_CLASSNOTREG for everything else), IStream / ILockBytes over global memory
 * (documented IStream contract: short reads, growth on write, Seek/SetSize/Clone/Stat), STGMEDIUM release,
 * OleDuplicateData, in-process interface transfer (CoMarshalInterThreadInterfaceInStream / CoGetInterfaceAndReleaseStream
 * across a real second thread), the free-threaded marshaler, agile references, drop-target registration and the
 * proxy/security/message-filter entry points. Expected HRESULTs are the documented ones. */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <ole2.h>
#include "u_check.h"

HRESULT WINAPI RoGetAgileReference(int options, REFIID iid, IUnknown *unk, IAgileReference **out);   /* ole32 (combaseapi.h of newer SDKs) */

#define ST_NOTINIT ((HRESULT)0x800401F0)
#define ST_CLASSNOTREG ((HRESULT)0x80040154)
#define ST_CLASSSTRING ((HRESULT)0x800401F3)
#define ST_UNIMPL ((HRESULT)0x800300FE)
#define ST_INVALIDFUNCTION ((HRESULT)0x80030001)
#define ST_NOTREGISTERED ((HRESULT)0x80040100)
#define ST_ALREADYREG ((HRESULT)0x80040101)
#define ST_INVALIDHWND ((HRESULT)0x80040102)

static const GUID IID_UNK = { 0x00000000, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID IID_CF = { 0x00000001, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID IID_STREAM = { 0x0000000c, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID IID_MARSHAL_ = { 0x00000003, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID IID_AGILE = { 0xC03F6A43, 0x65A4, 0x9818, { 0x98, 0x7E, 0xE0, 0xB8, 0x10, 0xD2, 0xA6, 0xF2 } };
static const GUID IID_DROPTARGET_ = { 0x00000122, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID CLSID_TEST = { 0x5a2f1c60, 0x1111, 0x4c6f, { 0x8f, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };
static const GUID CLSID_NLM = { 0xDCB00C01, 0x570F, 0x4A9B, { 0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B } };   /* CLSID_NetworkListManager */
static const GUID IID_FTM_CLASS = { 0x0000033A, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

/* ---- a class factory producing counted objects ---- */
typedef struct { const IUnknownVtbl *vt; LONG refs; int tag; } obj_t;
static LONG g_objects_alive;
static HRESULT STDMETHODCALLTYPE o_qi(IUnknown *self, REFIID iid, void **out)
{
    if (!memcmp(iid, &IID_UNK, sizeof(IID))) { *out = self; IUnknown_AddRef(self); return S_OK; }
    *out = 0;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE o_addref(IUnknown *self) { return (ULONG)InterlockedIncrement(&((obj_t *)self)->refs); }
static ULONG STDMETHODCALLTYPE o_release(IUnknown *self)
{
    ULONG r = (ULONG)InterlockedDecrement(&((obj_t *)self)->refs);
    if (!r) { HeapFree(GetProcessHeap(), 0, self); InterlockedDecrement(&g_objects_alive); }
    return r;
}
static const IUnknownVtbl obj_vtbl = { o_qi, o_addref, o_release };

typedef struct { const IClassFactoryVtbl *vt; LONG refs; LONG created; } cf_t;
static HRESULT STDMETHODCALLTYPE cf_qi(IClassFactory *self, REFIID iid, void **out)
{
    if (!memcmp(iid, &IID_UNK, sizeof(IID)) || !memcmp(iid, &IID_CF, sizeof(IID))) { *out = self; IClassFactory_AddRef(self); return S_OK; }
    *out = 0;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE cf_addref(IClassFactory *self) { return (ULONG)InterlockedIncrement(&((cf_t *)self)->refs); }
static ULONG STDMETHODCALLTYPE cf_release(IClassFactory *self) { return (ULONG)InterlockedDecrement(&((cf_t *)self)->refs); }
static HRESULT STDMETHODCALLTYPE cf_create(IClassFactory *self, IUnknown *outer, REFIID iid, void **out)
{
    obj_t *o;
    if (outer) return CLASS_E_NOAGGREGATION;
    o = HeapAlloc(GetProcessHeap(), 0, sizeof *o);
    o->vt = &obj_vtbl; o->refs = 1; o->tag = 42;
    InterlockedIncrement(&g_objects_alive);
    InterlockedIncrement(&((cf_t *)self)->created);
    {
        HRESULT hr = IUnknown_QueryInterface((IUnknown *)o, iid, out);
        IUnknown_Release((IUnknown *)o);
        return hr;
    }
}
static HRESULT STDMETHODCALLTYPE cf_lock(IClassFactory *self, BOOL lock) { (void)self; (void)lock; return S_OK; }
static const IClassFactoryVtbl cf_vtbl = { cf_qi, cf_addref, cf_release, cf_create, cf_lock };

/* ---- a drop target ---- */
typedef struct { const IDropTargetVtbl *vt; LONG refs; } dt_t;
static HRESULT STDMETHODCALLTYPE dt_qi(IDropTarget *self, REFIID iid, void **out)
{
    if (!memcmp(iid, &IID_UNK, sizeof(IID)) || !memcmp(iid, &IID_DROPTARGET_, sizeof(IID))) { *out = self; IDropTarget_AddRef(self); return S_OK; }
    *out = 0; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE dt_addref(IDropTarget *self) { return (ULONG)InterlockedIncrement(&((dt_t *)self)->refs); }
static ULONG STDMETHODCALLTYPE dt_release(IDropTarget *self) { return (ULONG)InterlockedDecrement(&((dt_t *)self)->refs); }
static HRESULT STDMETHODCALLTYPE dt_enter(IDropTarget *s, IDataObject *d, DWORD k, POINTL p, DWORD *e) { (void)s; (void)d; (void)k; (void)p; (void)e; return S_OK; }
static HRESULT STDMETHODCALLTYPE dt_over(IDropTarget *s, DWORD k, POINTL p, DWORD *e) { (void)s; (void)k; (void)p; (void)e; return S_OK; }
static HRESULT STDMETHODCALLTYPE dt_leave(IDropTarget *s) { (void)s; return S_OK; }
static HRESULT STDMETHODCALLTYPE dt_drop(IDropTarget *s, IDataObject *d, DWORD k, POINTL p, DWORD *e) { (void)s; (void)d; (void)k; (void)p; (void)e; return S_OK; }
static const IDropTargetVtbl dt_vtbl = { dt_qi, dt_addref, dt_release, dt_enter, dt_over, dt_leave, dt_drop };

/* ---- the other thread of the marshalling test ---- */
static IStream *g_xfer;
static volatile LONG g_thread_result;
static DWORD WINAPI unmarshal_thread(LPVOID arg)
{
    IUnknown *u = 0;
    HRESULT hr;
    (void)arg;
    CoInitializeEx(0, COINIT_MULTITHREADED);
    hr = CoGetInterfaceAndReleaseStream(g_xfer, &IID_UNK, (void **)&u);
    if (hr == S_OK && u && ((obj_t *)u)->tag == 42) { g_thread_result = (LONG)((obj_t *)u)->refs; IUnknown_Release(u); }
    else g_thread_result = -1;
    CoUninitialize();
    return 0;
}

int main(void)
{
    HRESULT hr;
    IUnknown *u = 0;
    IClassFactory *cf = 0;
    cf_t factory = { &cf_vtbl, 1, 0 };
    DWORD cookie = 0;

    /* ---- without an apartment ---- */
    U_CHECK("CoCreateInstance before CoInitialize is CO_E_NOTINITIALIZED", CoCreateInstance(&CLSID_TEST, 0, CLSCTX_INPROC_SERVER, &IID_UNK, (void **)&u) == ST_NOTINIT && u == 0);
    U_CHECK("CoRegisterClassObject before CoInitialize is CO_E_NOTINITIALIZED", CoRegisterClassObject(&CLSID_TEST, (IUnknown *)&factory, CLSCTX_INPROC_SERVER, REGCLS_MULTIPLEUSE, &cookie) == ST_NOTINIT);
    hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    U_CHECK("CoInitializeEx(STA)", hr == S_OK);

    /* ---- class table ---- */
    U_CHECK("CoCreateInstance(CLSID_NetworkListManager) is REGDB_E_CLASSNOTREG (no class store), out = NULL", CoCreateInstance(&CLSID_NLM, 0, CLSCTX_ALL, &IID_UNK, (void **)&u) == ST_CLASSNOTREG && u == 0);
    U_CHECK("CoGetClassObject of an unregistered class is REGDB_E_CLASSNOTREG", CoGetClassObject(&CLSID_TEST, CLSCTX_INPROC_SERVER, 0, &IID_CF, (void **)&cf) == ST_CLASSNOTREG && cf == 0);
    hr = CoRegisterClassObject(&CLSID_TEST, (IUnknown *)&factory, CLSCTX_INPROC_SERVER, REGCLS_MULTIPLEUSE, &cookie);
    U_CHECKF("CoRegisterClassObject(REGCLS_MULTIPLEUSE) succeeds with a cookie and holds a reference", hr == S_OK && cookie && factory.refs == 2, "hr=%x refs=%d", (unsigned)hr, (int)factory.refs);
    U_CHECK("CoRegisterClassObject with a context that is neither in-proc nor local is E_INVALIDARG", CoRegisterClassObject(&CLSID_TEST, (IUnknown *)&factory, CLSCTX_REMOTE_SERVER, REGCLS_MULTIPLEUSE, &(DWORD){0}) == E_INVALIDARG);
    U_CHECK("CoGetClassObject finds the registered factory and QueryInterfaces it", CoGetClassObject(&CLSID_TEST, CLSCTX_INPROC_SERVER, 0, &IID_CF, (void **)&cf) == S_OK && cf == (IClassFactory *)&factory && factory.refs == 3);
    IClassFactory_Release(cf);
    U_CHECK("CoGetClassObject with a context the registration does not cover is REGDB_E_CLASSNOTREG", CoGetClassObject(&CLSID_TEST, CLSCTX_LOCAL_SERVER, 0, &IID_CF, (void **)&cf) == ST_CLASSNOTREG);
    hr = CoCreateInstance(&CLSID_TEST, 0, CLSCTX_INPROC_SERVER, &IID_UNK, (void **)&u);
    U_CHECKF("CoCreateInstance creates through the factory: one object, factory reference count restored", hr == S_OK && u && ((obj_t *)u)->tag == 42 && factory.created == 1 && factory.refs == 2 && g_objects_alive == 1, "hr=%x", (unsigned)hr);
    U_CHECK("CoCreateInstance with an outer unknown and a non-IUnknown IID is CLASS_E_NOAGGREGATION", CoCreateInstance(&CLSID_TEST, u, CLSCTX_INPROC_SERVER, &IID_CF, (void **)&cf) == CLASS_E_NOAGGREGATION);
    {
        MULTI_QI mq[2];
        mq[0].pIID = &IID_UNK; mq[0].pItf = 0; mq[0].hr = 0;
        mq[1].pIID = &IID_CF; mq[1].pItf = 0; mq[1].hr = 0;
        hr = CoCreateInstanceEx(&CLSID_TEST, 0, CLSCTX_INPROC_SERVER, 0, 2, mq);
        U_CHECK("CoCreateInstanceEx: IUnknown found, IClassFactory not: CO_S_NOTALLINTERFACES", hr == CO_S_NOTALLINTERFACES && mq[0].hr == S_OK && mq[0].pItf && mq[1].hr == E_NOINTERFACE && !mq[1].pItf);
        if (mq[0].pItf) IUnknown_Release(mq[0].pItf);
    }
    IUnknown_Release(u);
    U_CHECK("CoRevokeClassObject releases the factory; a second revoke is E_INVALIDARG", CoRevokeClassObject(cookie) == S_OK && factory.refs == 1 && CoRevokeClassObject(cookie) == E_INVALIDARG);
    U_CHECK("after the revoke the class is unregistered again", CoCreateInstance(&CLSID_TEST, 0, CLSCTX_INPROC_SERVER, &IID_UNK, (void **)&u) == ST_CLASSNOTREG);
    hr = CoRegisterClassObject(&CLSID_TEST, (IUnknown *)&factory, CLSCTX_INPROC_SERVER, REGCLS_MULTIPLEUSE | REGCLS_SUSPENDED, &cookie);
    U_CHECK("a REGCLS_SUSPENDED registration is not found until CoResumeClassObjects", hr == S_OK && CoCreateInstance(&CLSID_TEST, 0, CLSCTX_INPROC_SERVER, &IID_UNK, (void **)&u) == ST_CLASSNOTREG && CoResumeClassObjects() == S_OK && CoCreateInstance(&CLSID_TEST, 0, CLSCTX_INPROC_SERVER, &IID_UNK, (void **)&u) == S_OK);
    if (u) IUnknown_Release(u);
    CoRevokeClassObject(cookie);
    hr = CoRegisterClassObject(&CLSID_TEST, (IUnknown *)&factory, CLSCTX_INPROC_SERVER, REGCLS_SINGLEUSE, &cookie);
    U_CHECK("a REGCLS_SINGLEUSE registration serves exactly one CoGetClassObject", hr == S_OK && CoGetClassObject(&CLSID_TEST, CLSCTX_INPROC_SERVER, 0, &IID_CF, (void **)&cf) == S_OK && CoGetClassObject(&CLSID_TEST, CLSCTX_INPROC_SERVER, 0, &IID_CF, (void **)&u) == ST_CLASSNOTREG);
    if (cf) IClassFactory_Release(cf);
    {
        CLSID c;
        U_CHECK("CLSIDFromProgID(\"{guid}\") parses the guid; a ProgID needs the absent registry: CO_E_CLASSSTRING", CLSIDFromProgID(L"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}", &c) == S_OK && !memcmp(&c, &CLSID_NLM, sizeof c) && CLSIDFromProgID(L"Excel.Application", &c) == ST_CLASSSTRING);
        U_CHECK("CoGetObjectContext is E_NOINTERFACE (no context objects)", CoGetObjectContext(&IID_UNK, (void **)&u) == E_NOINTERFACE && u == 0);
    }

    /* ---- IStream over global memory ---- */
    {
        IStream *s = 0, *c = 0;
        HGLOBAL h = 0;
        char buf[32];
        ULONG n = 99;
        LARGE_INTEGER mv;
        ULARGE_INTEGER pos, sz;
        STATSTG st;
        U_CHECK("CreateStreamOnHGlobal(NULL, TRUE) makes an empty stream", CreateStreamOnHGlobal(0, TRUE, &s) == S_OK && s);
        U_CHECK("Read on the empty stream returns S_OK with 0 bytes", IStream_Read(s, buf, 10, &n) == S_OK && n == 0);
        U_CHECK("Write appends 11 bytes", IStream_Write(s, "hello world", 11, &n) == S_OK && n == 11);
        U_CHECK("GetHGlobalFromStream gives a block of at least 11 bytes holding the data", GetHGlobalFromStream(s, &h) == S_OK && h && GlobalSize(h) >= 11 && !memcmp(GlobalLock(h), "hello world", 11) && (GlobalUnlock(h), 1));
        mv.QuadPart = -5;
        U_CHECK("Seek(-5, END) positions at 6 and Read gives \"world\"", IStream_Seek(s, mv, STREAM_SEEK_END, &pos) == S_OK && pos.QuadPart == 6 && IStream_Read(s, buf, 32, &n) == S_OK && n == 5 && !memcmp(buf, "world", 5));
        mv.QuadPart = -100;
        U_CHECK("Seek before the start is STG_E_INVALIDFUNCTION", IStream_Seek(s, mv, STREAM_SEEK_CUR, 0) == ST_INVALIDFUNCTION);
        mv.QuadPart = 20;
        U_CHECK("Seek past the end is allowed and a Write there zero-fills the gap", IStream_Seek(s, mv, STREAM_SEEK_SET, 0) == S_OK && IStream_Write(s, "X", 1, &n) == S_OK && IStream_Stat(s, &st, STATFLAG_NONAME) == S_OK && st.cbSize.QuadPart == 21 && st.type == STGTY_STREAM);
        mv.QuadPart = 11;
        IStream_Seek(s, mv, STREAM_SEEK_SET, 0);
        IStream_Read(s, buf, 9, &n);
        U_CHECK("...the gap reads back as zeros", n == 9 && buf[0] == 0 && buf[8] == 0);
        sz.QuadPart = 5;
        U_CHECK("SetSize(5) truncates; Clone shares the data with its own position", IStream_SetSize(s, sz) == S_OK && IStream_Clone(s, &c) == S_OK && c && (mv.QuadPart = 0, IStream_Seek(c, mv, STREAM_SEEK_SET, 0) == S_OK) && IStream_Read(c, buf, 32, &n) == S_OK && n == 5 && !memcmp(buf, "hello", 5));
        U_CHECK("LockRegion is STG_E_INVALIDFUNCTION; Commit and Revert succeed", IStream_LockRegion(s, sz, sz, 0) == ST_INVALIDFUNCTION && IStream_Commit(s, 0) == S_OK && IStream_Revert(s) == S_OK);
        U_CHECK("QueryInterface(IStream) works, IMarshal is not there", IStream_QueryInterface(s, &IID_STREAM, (void **)&u) == S_OK && (IUnknown_Release(u), 1) && IStream_QueryInterface(s, &IID_MARSHAL_, (void **)&u) == E_NOINTERFACE);
        IStream_Release(c);
        U_CHECK("GetHGlobalFromStream on a stream that is not one of ours is E_INVALIDARG", GetHGlobalFromStream((IStream *)&factory, &h) == E_INVALIDARG);
        IStream_Release(s);
        h = GlobalAlloc(GMEM_MOVEABLE, 4);
        memcpy(GlobalLock(h), "abcd", 4); GlobalUnlock(h);
        U_CHECK("a stream over an existing block sees its size and content", CreateStreamOnHGlobal(h, FALSE, &s) == S_OK && IStream_Stat(s, &st, STATFLAG_NONAME) == S_OK && st.cbSize.QuadPart == 4 && IStream_Read(s, buf, 4, &n) == S_OK && n == 4 && !memcmp(buf, "abcd", 4));
        IStream_Release(s);
        U_CHECK("...and fDeleteOnRelease = FALSE leaves the block to the caller", GlobalSize(h) == 4 && GlobalFree(h) == 0);
    }
    /* ---- ILockBytes ---- */
    {
        ILockBytes *lb = 0;
        IStorage *stg = (IStorage *)1;
        ULARGE_INTEGER at;
        char buf[8];
        ULONG n = 0;
        STATSTG st;
        at.QuadPart = 3;
        U_CHECK("CreateILockBytesOnHGlobal, WriteAt(3) grows to 7, ReadAt(0) sees zeros then the data", CreateILockBytesOnHGlobal(0, TRUE, &lb) == S_OK && ILockBytes_WriteAt(lb, at, "abcd", 4, &n) == S_OK && n == 4 && ILockBytes_Stat(lb, &st, STATFLAG_NONAME) == S_OK && st.cbSize.QuadPart == 7 && st.type == STGTY_LOCKBYTES && (at.QuadPart = 0, ILockBytes_ReadAt(lb, at, buf, 8, &n) == S_OK) && n == 7 && buf[0] == 0 && buf[2] == 0 && buf[3] == 'a');
        U_CHECK("StgIsStorageILockBytes is S_FALSE for it; StgCreateDocfileOnILockBytes is STG_E_UNIMPLEMENTEDFUNCTION", StgIsStorageILockBytes(lb) == S_FALSE && StgCreateDocfileOnILockBytes(lb, STGM_READWRITE, 0, &stg) == ST_UNIMPL && stg == 0);
        ILockBytes_Release(lb);
    }
    /* ---- STGMEDIUM, OleDuplicateData ---- */
    {
        STGMEDIUM m;
        HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, 6), d;
        memcpy(GlobalLock(h), "sixbyt", 6); GlobalUnlock(h);
        d = OleDuplicateData(h, CF_TEXT, GMEM_MOVEABLE);
        U_CHECK("OleDuplicateData copies a 6-byte global block", d && d != h && GlobalSize(d) == 6 && !memcmp(GlobalLock(d), "sixbyt", 6) && (GlobalUnlock(d), 1));
        U_CHECK("OleDuplicateData of a GDI format is NULL (not duplicated here)", OleDuplicateData(h, CF_BITMAP, 0) == 0);
        m.tymed = TYMED_HGLOBAL; m.hGlobal = d; m.pUnkForRelease = 0;
        ReleaseStgMedium(&m);
        U_CHECK("ReleaseStgMedium(TYMED_HGLOBAL) frees the block and resets the medium", m.tymed == TYMED_NULL && m.hGlobal == 0);
        m.tymed = TYMED_HGLOBAL; m.hGlobal = h; m.pUnkForRelease = (IUnknown *)&factory;
        factory.refs = 5;
        ReleaseStgMedium(&m);
        U_CHECK("with pUnkForRelease only that object is released", factory.refs == 4 && GlobalSize(h) == 6 && m.tymed == TYMED_NULL);
        factory.refs = 1;
        GlobalFree(h);
    }
    /* ---- interface transfer to another thread ---- */
    {
        obj_t *o = HeapAlloc(GetProcessHeap(), 0, sizeof *o);
        HANDLE th;
        o->vt = &obj_vtbl; o->refs = 1; o->tag = 42;
        InterlockedIncrement(&g_objects_alive);
        U_CHECK("CoMarshalInterThreadInterfaceInStream takes one reference into the stream", CoMarshalInterThreadInterfaceInStream(&IID_UNK, (IUnknown *)o, &g_xfer) == S_OK && g_xfer && o->refs == 2);
        g_thread_result = 0;
        th = CreateThread(0, 0, unmarshal_thread, 0, 0, 0);
        WaitForSingleObject(th, 30000);
        CloseHandle(th);
        U_CHECKF("the MTA thread got the same object (packet reference consumed, stream released) and released it", g_thread_result == 2 && o->refs == 1, "result=%d refs=%d", (int)g_thread_result, (int)o->refs);
        U_CHECK("CoGetInterfaceAndReleaseStream on a stream without a packet is E_INVALIDARG", CreateStreamOnHGlobal(0, TRUE, &g_xfer) == S_OK && CoGetInterfaceAndReleaseStream(g_xfer, &IID_UNK, (void **)&u) == E_INVALIDARG && u == 0);
        {
            IStream *s = 0;
            LARGE_INTEGER zero = { { 0, 0 } };
            U_CHECK("CoMarshalInterface(MSHLFLAGS_TABLESTRONG) keeps the reference across CoUnmarshalInterface until CoReleaseMarshalData",
                    CreateStreamOnHGlobal(0, TRUE, &s) == S_OK && CoMarshalInterface(s, &IID_UNK, (IUnknown *)o, MSHCTX_INPROC, 0, MSHLFLAGS_TABLESTRONG) == S_OK && o->refs == 2 &&
                    IStream_Seek(s, zero, STREAM_SEEK_SET, 0) == S_OK && CoUnmarshalInterface(s, &IID_UNK, (void **)&u) == S_OK && u == (IUnknown *)o && o->refs == 3 && (IUnknown_Release(u), 1) &&
                    IStream_Seek(s, zero, STREAM_SEEK_SET, 0) == S_OK && CoReleaseMarshalData(s) == S_OK && o->refs == 1);
            IStream_Release(s);
        }
        /* free-threaded marshaler */
        {
            IUnknown *ftm = 0;
            IMarshal *m = 0;
            CLSID c;
            DWORD size = 0;
            IStream *s = 0;
            LARGE_INTEGER zero = { { 0, 0 } };
            U_CHECK("CoCreateFreeThreadedMarshaler gives an IUnknown exposing IMarshal", CoCreateFreeThreadedMarshaler(0, &ftm) == S_OK && ftm && IUnknown_QueryInterface(ftm, &IID_MARSHAL_, (void **)&m) == S_OK && m);
            U_CHECK("IMarshal::GetUnmarshalClass = CLSID_InProcFreeMarshaler, GetMarshalSizeMax = sizeof(void *)", IMarshal_GetUnmarshalClass(m, &IID_UNK, o, MSHCTX_INPROC, 0, MSHLFLAGS_NORMAL, &c) == S_OK && !memcmp(&c, &IID_FTM_CLASS, sizeof c) && IMarshal_GetMarshalSizeMax(m, &IID_UNK, o, MSHCTX_INPROC, 0, MSHLFLAGS_NORMAL, &size) == S_OK && size == sizeof(void *));
            U_CHECK("IMarshal::MarshalInterface / UnmarshalInterface round-trip the pointer", CreateStreamOnHGlobal(0, TRUE, &s) == S_OK && IMarshal_MarshalInterface(m, s, &IID_UNK, o, MSHCTX_INPROC, 0, MSHLFLAGS_NORMAL) == S_OK && o->refs == 2 && IStream_Seek(s, zero, STREAM_SEEK_SET, 0) == S_OK && IMarshal_UnmarshalInterface(m, s, &IID_UNK, (void **)&u) == S_OK && u == (IUnknown *)o && o->refs == 2 && (IUnknown_Release(u), 1) && o->refs == 1);
            U_CHECK("GetUnmarshalClass for another machine is E_INVALIDARG", IMarshal_GetUnmarshalClass(m, &IID_UNK, o, MSHCTX_DIFFERENTMACHINE, 0, MSHLFLAGS_NORMAL, &c) == E_INVALIDARG);
            IStream_Release(s);
            IMarshal_Release(m);
            IUnknown_Release(ftm);
        }
        /* agile reference */
        {
            IAgileReference *ar = 0;
            U_CHECK("RoGetAgileReference + Resolve give the object back; a bad option is E_INVALIDARG", RoGetAgileReference(0, &IID_UNK, (IUnknown *)o, &ar) == S_OK && ar && o->refs == 2 && IAgileReference_Resolve(ar, &IID_UNK, (void **)&u) == S_OK && u == (IUnknown *)o && (IUnknown_Release(u), 1) && RoGetAgileReference(7, &IID_UNK, (IUnknown *)o, &(IAgileReference *){0}) == E_INVALIDARG);
            U_CHECK("QueryInterface(IAgileReference) on it works; releasing it drops the reference", IAgileReference_QueryInterface(ar, &IID_AGILE, (void **)&u) == S_OK && (IUnknown_Release(u), 1) && IAgileReference_Release(ar) == 0 && o->refs == 1);
        }
        U_CHECK("CoSetProxyBlanket on a plain object is E_NOINTERFACE; CoAllowSetForegroundWindow too; OleLockRunning is S_OK", CoSetProxyBlanket((IUnknown *)o, 0, 0, 0, 0, 0, 0, 0) == E_NOINTERFACE && CoAllowSetForegroundWindow((IUnknown *)o, 0) == E_NOINTERFACE && OleLockRunning((IUnknown *)o, TRUE, FALSE) == S_OK);
        IUnknown_Release((IUnknown *)o);
        U_CHECK("every test object was destroyed", g_objects_alive == 0);
    }
    /* ---- message filter, drop targets ---- */
    {
        IMessageFilter *old = (IMessageFilter *)1;
        U_CHECK("CoRegisterMessageFilter(NULL) on the STA returns no previous filter", CoRegisterMessageFilter(0, &old) == S_OK && old == 0);
        U_CHECK("CoRegisterMessageFilter(object) then (NULL) returns the object with its reference", CoRegisterMessageFilter((IMessageFilter *)&factory, &old) == S_OK && old == 0 && factory.refs == 2 && CoRegisterMessageFilter(0, &old) == S_OK && old == (IMessageFilter *)&factory && (IUnknown_Release((IUnknown *)old), factory.refs == 1));
    }
    {
        dt_t target = { &dt_vtbl, 1 };
        HWND w;
        U_CHECK("RegisterDragDrop without OleInitialize is CO_E_NOTINITIALIZED", RegisterDragDrop((HWND)0x1234, (IDropTarget *)&target) == ST_NOTINIT);
        OleInitialize(0);
        U_CHECK("RegisterDragDrop with a bad window is DRAGDROP_E_INVALIDHWND", RegisterDragDrop((HWND)0x1234, (IDropTarget *)&target) == ST_INVALIDHWND);
        w = CreateWindowExW(0, L"STATIC", L"dd", 0, 0, 0, 10, 10, 0, 0, 0, 0);
        if (w) {
            U_CHECK("RegisterDragDrop on a window succeeds, holds a reference, refuses a second registration", RegisterDragDrop(w, (IDropTarget *)&target) == S_OK && target.refs == 2 && RegisterDragDrop(w, (IDropTarget *)&target) == ST_ALREADYREG);
            U_CHECK("RevokeDragDrop releases it; a second revoke is DRAGDROP_E_NOTREGISTERED", RevokeDragDrop(w) == S_OK && target.refs == 1 && RevokeDragDrop(w) == ST_NOTREGISTERED);
            DestroyWindow(w);
        } else {
            printf("INFO: no window (no display device): the registered-target checks need run_k64_gui.py\n");
        }
        OleUninitialize();
    }
    CoUninitialize();
    return u_finish("t_u_ole32cls");
}
