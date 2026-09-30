/* SPDX-License-Identifier: GPL-2.0-only
 * ole32.dll: in-process interface transfer between threads, the free-threaded marshaler, agile references, and the
 * drop-target table.
 *
 * There is no RPC and no proxy/stub layer: every interface pointer is called directly from every thread, exactly as an
 * agile (free-threaded-marshaled) object is on Windows. CoMarshalInterThreadInterfaceInStream therefore writes the
 * documented "marshal packet" of that case - an in-process reference - into a stream (an IStream over global memory
 * carrying a signature, the IID and the pointer, with one reference held for the packet), and
 * CoGetInterfaceAndReleaseStream reads it back, QueryInterfaces to the requested IID, releases the packet's reference
 * and the stream. A stream that does not hold such a packet gives E_INVALIDARG; STG_E_* codes propagate from the
 * stream. CoMarshalInterface/CoUnmarshalInterface/CoReleaseMarshalData use the same packet (MSHCTX/MSHLFLAGS are
 * validated, MSHLFLAGS_TABLE* keep the reference until CoReleaseMarshalData).
 * CoCreateFreeThreadedMarshaler: the aggregatable IMarshal whose class is CLSID_InProcFreeMarshaler and whose packet is
 * the pointer itself (GetMarshalSizeMax = sizeof(void *)); UnmarshalInterface in another process is impossible and
 * answers E_UNEXPECTED (packets never leave the process).
 * RoGetAgileReference: an IAgileReference whose Resolve QueryInterfaces the wrapped object (AGILEREFERENCE_DEFAULT and
 * AGILEREFERENCE_DELAYEDMARSHAL behave alike; other options E_INVALIDARG).
 * RegisterDragDrop / RevokeDragDrop: the per-window table of IDropTarget (OleInitialize required: CO_E_NOTINITIALIZED;
 * DRAGDROP_E_INVALIDHWND for a handle that is not a window, DRAGDROP_E_ALREADYREGISTERED, DRAGDROP_E_NOTREGISTERED, the
 * target is AddRef'd while registered). No drag loop exists (DoDragDrop is not exported: nothing can start a drag), so
 * a registered target is only ever revoked.
 */
#include "ole32_int.h"

#define E_INVALIDARG_ ((HRESULT)0x80070057)
#define E_OUTOFMEMORY_ ((HRESULT)0x8007000E)
#define E_NOINTERFACE_ ((HRESULT)0x80004002)
#define E_POINTER_ ((HRESULT)0x80004003)
#define E_UNEXPECTED_ ((HRESULT)0x8000FFFF)
#define CO_E_NOTINITIALIZED_ ((HRESULT)0x800401F0)
#define DRAGDROP_E_NOTREGISTERED_ ((HRESULT)0x80040100)
#define DRAGDROP_E_ALREADYREGISTERED_ ((HRESULT)0x80040101)
#define DRAGDROP_E_INVALIDHWND_ ((HRESULT)0x80040102)
#define STG_E_INVALIDPOINTER_ ((HRESULT)0x80030009)

static const GUID iid_marshal = { 0x00000003, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID iid_agilereference = { 0xC03F6A43, 0x65A4, 0x9818, { 0x98, 0x7E, 0xE0, 0xB8, 0x10, 0xD2, 0xA6, 0xF2 } };
static const GUID clsid_inprocfreemarshaler = { 0x0000033A, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

int shz_apt_active(void);                                /* classes.c */

/* ---------------------------------------------------------------- the packet */
typedef struct { DWORD sig; DWORD pid; IID iid; IUnknown *ptr; DWORD flags; DWORD pad; } packet;
#define PACKET_SIG 0x4d485a53u                           /* 'SZHM' */

static HRESULT packet_write(IStream *stm, REFIID iid, IUnknown *unk, DWORD flags)
{
    packet p;
    IUnknown *itf = 0;
    HRESULT hr = IUnknown_QueryInterface(unk, iid, (void **)&itf);
    ULONG put = 0;
    if (FAILED(hr)) return hr;
    p.sig = PACKET_SIG;
    p.pid = GetCurrentProcessId();
    p.iid = *iid;
    p.ptr = itf;                                          /* the reference QueryInterface took travels with the packet */
    p.flags = flags;
    p.pad = 0;
    hr = IStream_Write(stm, &p, sizeof p, &put);
    if (FAILED(hr) || put != sizeof p) { IUnknown_Release(itf); return FAILED(hr) ? hr : STG_E_INVALIDPOINTER_; }
    return S_OK;
}

static HRESULT packet_read(IStream *stm, packet *p)
{
    ULONG got = 0;
    HRESULT hr = IStream_Read(stm, p, sizeof *p, &got);
    if (FAILED(hr)) return hr;
    if (got != sizeof *p || p->sig != PACKET_SIG || !p->ptr) return E_INVALIDARG_;
    if (p->pid != GetCurrentProcessId()) return E_UNEXPECTED_;    /* a packet never leaves its process */
    return S_OK;
}

DLLAPI HRESULT WINAPI CoMarshalInterface(IStream *stm, REFIID iid, IUnknown *unk, DWORD ctx, void *pv, DWORD flags)
{
    (void)pv;
    if (!stm || !iid || !unk) return E_INVALIDARG_;
    if (ctx != MSHCTX_LOCAL && ctx != MSHCTX_NOSHAREDMEM && ctx != MSHCTX_DIFFERENTMACHINE && ctx != MSHCTX_INPROC && ctx != MSHCTX_CROSSCTX) return E_INVALIDARG_;
    if (flags & ~(DWORD)(MSHLFLAGS_TABLESTRONG | MSHLFLAGS_TABLEWEAK | MSHLFLAGS_NOPING)) return E_INVALIDARG_;
    if (!shz_apt_active()) return CO_E_NOTINITIALIZED_;
    return packet_write(stm, iid, unk, flags);
}

DLLAPI HRESULT WINAPI CoUnmarshalInterface(IStream *stm, REFIID iid, void **out)
{
    packet p;
    HRESULT hr;
    if (!out) return E_POINTER_;
    *out = 0;
    if (!stm || !iid) return E_INVALIDARG_;
    if (!shz_apt_active()) return CO_E_NOTINITIALIZED_;
    hr = packet_read(stm, &p);
    if (FAILED(hr)) return hr;
    hr = IUnknown_QueryInterface(p.ptr, iid, out);
    if (!(p.flags & (MSHLFLAGS_TABLESTRONG | MSHLFLAGS_TABLEWEAK))) IUnknown_Release(p.ptr);   /* a normal packet is consumed */
    return hr;
}

DLLAPI HRESULT WINAPI CoReleaseMarshalData(IStream *stm)
{
    packet p;
    HRESULT hr;
    if (!stm) return E_INVALIDARG_;
    if (!shz_apt_active()) return CO_E_NOTINITIALIZED_;
    hr = packet_read(stm, &p);
    if (FAILED(hr)) return hr;
    IUnknown_Release(p.ptr);
    return S_OK;
}

DLLAPI HRESULT WINAPI CoMarshalInterThreadInterfaceInStream(REFIID iid, LPUNKNOWN unk, LPSTREAM *out)
{
    IStream *stm = 0;
    HRESULT hr;
    LARGE_INTEGER zero;
    if (!out) return E_POINTER_;
    *out = 0;
    if (!iid || !unk) return E_INVALIDARG_;
    if (!shz_apt_active()) return CO_E_NOTINITIALIZED_;
    hr = CreateStreamOnHGlobal(0, TRUE, &stm);
    if (FAILED(hr)) return hr;
    hr = packet_write(stm, iid, unk, 0);
    if (FAILED(hr)) { IStream_Release(stm); return hr; }
    zero.QuadPart = 0;
    IStream_Seek(stm, zero, STREAM_SEEK_SET, 0);
    *out = stm;
    return S_OK;
}

DLLAPI HRESULT WINAPI CoGetInterfaceAndReleaseStream(LPSTREAM stm, REFIID iid, LPVOID *out)
{
    HRESULT hr;
    if (!out) return E_POINTER_;
    *out = 0;
    if (!stm) return E_INVALIDARG_;
    hr = CoUnmarshalInterface(stm, iid, out);
    IStream_Release(stm);                                 /* released whether or not the unmarshal succeeded, as documented */
    return hr;
}

/* ---------------------------------------------------------------- the free-threaded marshaler */
typedef struct ftm {
    const IMarshalVtbl *vt;
    const IUnknownVtbl *inner_vt;                        /* the non-delegating IUnknown handed to the aggregator */
    LONG refs;
    IUnknown *outer;
} ftm;

#define FTM_FROM_INNER(p) ((ftm *)((BYTE *)(p) - offsetof(ftm, inner_vt)))

static HRESULT STDMETHODCALLTYPE ftm_inner_qi(IUnknown *self, REFIID iid, void **out)
{
    ftm *f = FTM_FROM_INNER(self);
    if (!out) return E_POINTER_;
    if (!memcmp(iid, &shz_iid_unknown, sizeof(IID))) { *out = self; IUnknown_AddRef(self); return S_OK; }
    if (!memcmp(iid, &iid_marshal, sizeof(IID))) { *out = &f->vt; IUnknown_AddRef(self); return S_OK; }
    *out = 0;
    return E_NOINTERFACE_;
}
static ULONG STDMETHODCALLTYPE ftm_inner_addref(IUnknown *self) { return (ULONG)InterlockedIncrement(&FTM_FROM_INNER(self)->refs); }
static ULONG STDMETHODCALLTYPE ftm_inner_release(IUnknown *self)
{
    ftm *f = FTM_FROM_INNER(self);
    ULONG r = (ULONG)InterlockedDecrement(&f->refs);
    if (!r) HeapFree(GetProcessHeap(), 0, f);
    return r;
}
static const IUnknownVtbl ftm_inner_vtbl = { ftm_inner_qi, ftm_inner_addref, ftm_inner_release };

/* the IMarshal methods delegate IUnknown to the aggregator */
static HRESULT STDMETHODCALLTYPE ftm_qi(IMarshal *self, REFIID iid, void **out) { return IUnknown_QueryInterface(((ftm *)self)->outer, iid, out); }
static ULONG STDMETHODCALLTYPE ftm_addref(IMarshal *self) { return IUnknown_AddRef(((ftm *)self)->outer); }
static ULONG STDMETHODCALLTYPE ftm_release(IMarshal *self) { return IUnknown_Release(((ftm *)self)->outer); }
static HRESULT STDMETHODCALLTYPE ftm_unmarshal_class(IMarshal *self, REFIID iid, void *pv, DWORD ctx, void *pvctx, DWORD flags, CLSID *out)
{
    (void)self; (void)iid; (void)pv; (void)pvctx; (void)flags;
    if (!out) return E_POINTER_;
    if (ctx == MSHCTX_DIFFERENTMACHINE) return E_INVALIDARG_;
    *out = clsid_inprocfreemarshaler;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE ftm_size_max(IMarshal *self, REFIID iid, void *pv, DWORD ctx, void *pvctx, DWORD flags, DWORD *size)
{
    (void)self; (void)iid; (void)pv; (void)pvctx; (void)flags;
    if (!size) return E_POINTER_;
    if (ctx == MSHCTX_DIFFERENTMACHINE) return E_INVALIDARG_;
    *size = sizeof(void *);
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE ftm_marshal(IMarshal *self, IStream *stm, REFIID iid, void *pv, DWORD ctx, void *pvctx, DWORD flags)
{
    IUnknown *itf = 0;
    HRESULT hr;
    ULONG put = 0;
    (void)self; (void)pvctx;
    if (!stm || !pv) return E_INVALIDARG_;
    if (ctx == MSHCTX_DIFFERENTMACHINE) return E_INVALIDARG_;
    hr = IUnknown_QueryInterface((IUnknown *)pv, iid, (void **)&itf);
    if (FAILED(hr)) return hr;
    hr = IStream_Write(stm, &itf, sizeof itf, &put);
    if (FAILED(hr) || put != sizeof itf) { IUnknown_Release(itf); return FAILED(hr) ? hr : STG_E_INVALIDPOINTER_; }
    if (!(flags & (MSHLFLAGS_TABLESTRONG | MSHLFLAGS_TABLEWEAK))) return S_OK;            /* the reference is the packet's */
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE ftm_unmarshal(IMarshal *self, IStream *stm, REFIID iid, void **out)
{
    IUnknown *itf = 0;
    ULONG got = 0;
    HRESULT hr;
    (void)self;
    if (!out) return E_POINTER_;
    *out = 0;
    if (!stm) return E_INVALIDARG_;
    hr = IStream_Read(stm, &itf, sizeof itf, &got);
    if (FAILED(hr)) return hr;
    if (got != sizeof itf || !itf) return E_UNEXPECTED_;
    hr = IUnknown_QueryInterface(itf, iid, out);
    IUnknown_Release(itf);
    return hr;
}
static HRESULT STDMETHODCALLTYPE ftm_release_data(IMarshal *self, IStream *stm)
{
    IUnknown *itf = 0;
    ULONG got = 0;
    HRESULT hr;
    (void)self;
    if (!stm) return E_INVALIDARG_;
    hr = IStream_Read(stm, &itf, sizeof itf, &got);
    if (FAILED(hr)) return hr;
    if (got != sizeof itf || !itf) return E_UNEXPECTED_;
    IUnknown_Release(itf);
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE ftm_disconnect(IMarshal *self, DWORD reserved) { (void)self; (void)reserved; return S_OK; }
static const IMarshalVtbl ftm_vtbl = { ftm_qi, ftm_addref, ftm_release, ftm_unmarshal_class, ftm_size_max, ftm_marshal, ftm_unmarshal, ftm_release_data, ftm_disconnect };

DLLAPI HRESULT WINAPI CoCreateFreeThreadedMarshaler(LPUNKNOWN outer, LPUNKNOWN *out)
{
    ftm *f;
    if (!out) return E_POINTER_;
    *out = 0;
    f = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *f);
    if (!f) return E_OUTOFMEMORY_;
    f->vt = &ftm_vtbl;
    f->inner_vt = &ftm_inner_vtbl;
    f->refs = 1;
    f->outer = outer ? outer : (IUnknown *)&f->inner_vt;
    *out = (IUnknown *)&f->inner_vt;
    return S_OK;
}

/* ---------------------------------------------------------------- agile references */
typedef struct { const IAgileReferenceVtbl *vt; LONG refs; IUnknown *obj; } agileref;

static HRESULT STDMETHODCALLTYPE ar_qi(IAgileReference *self, REFIID iid, void **out)
{
    if (!out) return E_POINTER_;
    if (!memcmp(iid, &shz_iid_unknown, sizeof(IID)) || !memcmp(iid, &iid_agilereference, sizeof(IID))) { *out = self; IAgileReference_AddRef(self); return S_OK; }
    *out = 0;
    return E_NOINTERFACE_;
}
static ULONG STDMETHODCALLTYPE ar_addref(IAgileReference *self) { return (ULONG)InterlockedIncrement(&((agileref *)self)->refs); }
static ULONG STDMETHODCALLTYPE ar_release(IAgileReference *self)
{
    agileref *a = (agileref *)self;
    ULONG r = (ULONG)InterlockedDecrement(&a->refs);
    if (!r) { IUnknown_Release(a->obj); HeapFree(GetProcessHeap(), 0, a); }
    return r;
}
static HRESULT STDMETHODCALLTYPE ar_resolve(IAgileReference *self, REFIID iid, void **out)
{
    if (!out) return E_POINTER_;
    return IUnknown_QueryInterface(((agileref *)self)->obj, iid, out);
}
static const IAgileReferenceVtbl agileref_vtbl = { ar_qi, ar_addref, ar_release, ar_resolve };

/* AgileReferenceOptions (combaseapi.h of newer SDKs): AGILEREFERENCE_DEFAULT = 0, AGILEREFERENCE_DELAYEDMARSHAL = 1 */
#define AGILEREFERENCE_DEFAULT 0
#define AGILEREFERENCE_DELAYEDMARSHAL 1
DLLAPI HRESULT WINAPI RoGetAgileReference(int options, REFIID iid, IUnknown *unk, IAgileReference **out)
{
    agileref *a;
    IUnknown *itf = 0;
    HRESULT hr;
    if (!out) return E_POINTER_;
    *out = 0;
    if (!iid || !unk) return E_INVALIDARG_;
    if (options != AGILEREFERENCE_DEFAULT && options != AGILEREFERENCE_DELAYEDMARSHAL) return E_INVALIDARG_;
    if (!shz_apt_active()) return CO_E_NOTINITIALIZED_;
    hr = IUnknown_QueryInterface(unk, iid, (void **)&itf);
    if (FAILED(hr)) return hr;
    a = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *a);
    if (!a) { IUnknown_Release(itf); return E_OUTOFMEMORY_; }
    a->vt = &agileref_vtbl;
    a->refs = 1;
    a->obj = itf;
    *out = (IAgileReference *)a;
    return S_OK;
}

/* ---------------------------------------------------------------- drop targets */
typedef struct drop_entry { struct drop_entry *next; HWND hwnd; IDropTarget *target; } drop_entry;
static SRWLOCK g_drop_lock = SRWLOCK_INIT;
static drop_entry *g_drops;

int shz_ole_initialized(void);                            /* apartment.c */

DLLAPI HRESULT WINAPI RegisterDragDrop(HWND hwnd, LPDROPTARGET target)
{
    drop_entry *e;
    if (!target) return E_INVALIDARG_;
    if (!shz_ole_initialized()) return CO_E_NOTINITIALIZED_;
    if (!IsWindow(hwnd)) return DRAGDROP_E_INVALIDHWND_;
    AcquireSRWLockExclusive(&g_drop_lock);
    for (e = g_drops; e; e = e->next) if (e->hwnd == hwnd) { ReleaseSRWLockExclusive(&g_drop_lock); return DRAGDROP_E_ALREADYREGISTERED_; }
    e = HeapAlloc(GetProcessHeap(), 0, sizeof *e);
    if (!e) { ReleaseSRWLockExclusive(&g_drop_lock); return E_OUTOFMEMORY_; }
    e->hwnd = hwnd;
    e->target = target;
    IDropTarget_AddRef(target);
    e->next = g_drops;
    g_drops = e;
    ReleaseSRWLockExclusive(&g_drop_lock);
    return S_OK;
}

DLLAPI HRESULT WINAPI RevokeDragDrop(HWND hwnd)
{
    drop_entry *e, **pp;
    if (!IsWindow(hwnd)) return DRAGDROP_E_INVALIDHWND_;
    AcquireSRWLockExclusive(&g_drop_lock);
    for (pp = &g_drops; (e = *pp) != 0; pp = &e->next) if (e->hwnd == hwnd) { *pp = e->next; break; }
    ReleaseSRWLockExclusive(&g_drop_lock);
    if (!e) return DRAGDROP_E_NOTREGISTERED_;
    IDropTarget_Release(e->target);
    HeapFree(GetProcessHeap(), 0, e);
    return S_OK;
}
