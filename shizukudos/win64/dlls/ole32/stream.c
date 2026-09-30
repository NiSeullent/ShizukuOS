/* SPDX-License-Identifier: GPL-2.0-only
 * ole32.dll: IStream and ILockBytes over global memory, STGMEDIUM release, OleDuplicateData.
 *
 * CreateStreamOnHGlobal / GetHGlobalFromStream follow the documented contract: with a NULL handle the stream allocates
 * its own GMEM_MOVEABLE block (size 0); the block grows on Write/SetSize past its end (GlobalReAlloc); Seek beyond the
 * end is allowed (STG_E_INVALIDFUNCTION only for a negative position); Read past the end returns S_OK with the short
 * count (S_FALSE is never returned, as on Windows); Clone shares the memory with an independent position; Stat reports
 * STGTY_STREAM and the size; LockRegion/UnlockRegion are STG_E_INVALIDFUNCTION; Commit/Revert succeed. With
 * fDeleteOnRelease the block is freed when the last stream on it goes away; GetHGlobalFromStream on a stream that is not
 * one of these is E_INVALIDARG. ILockBytes (CreateILockBytesOnHGlobal / GetHGlobalFromILockBytes) is the same store
 * with the ReadAt/WriteAt interface.
 * StgCreateDocfileOnILockBytes: the compound-file format is not implemented: STG_E_UNIMPLEMENTEDFUNCTION (documented HRESULT).
 * ReleaseStgMedium: as documented per TYMED (pUnkForRelease first; HGLOBAL freed, file deleted and its name freed,
 * stream/storage released, GDI object deleted, metafile pict / enhanced metafile freed).
 * OleDuplicateData: global-memory formats are copied byte for byte; the GDI formats (CF_BITMAP, CF_PALETTE,
 * CF_ENHMETAFILE, CF_METAFILEPICT) would need GDI object duplication, which gdi32 does not provide here: NULL.
 */
#include "ole32_int.h"

#define STG_E_INVALIDFUNCTION_ ((HRESULT)0x80030001)
#define STG_E_INVALIDPOINTER_ ((HRESULT)0x80030009)
#define STG_E_MEDIUMFULL_ ((HRESULT)0x80030070)
#define STG_E_UNIMPLEMENTEDFUNCTION_ ((HRESULT)0x800300FE)
#define STG_E_INVALIDPARAMETER_ ((HRESULT)0x80030057)
#define E_INVALIDARG_ ((HRESULT)0x80070057)
#define E_OUTOFMEMORY_ ((HRESULT)0x8007000E)
#define E_NOINTERFACE_ ((HRESULT)0x80004002)
#define E_POINTER_ ((HRESULT)0x80004003)

static const GUID iid_stream = { 0x0000000c, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID iid_sequentialstream = { 0x0c733a30, 0x2a1c, 0x11ce, { 0xad, 0xe5, 0x00, 0xaa, 0x00, 0x44, 0x77, 0x3d } };
static const GUID iid_lockbytes = { 0x0000000a, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

/* the shared store of every stream/lockbytes cloned from one CreateStreamOnHGlobal */
typedef struct gstore {
    LONG refs;
    HGLOBAL h;
    ULONGLONG size;
    BOOL delete_on_release;
    SRWLOCK lock;
} gstore;

static gstore *store_new(HGLOBAL h, BOOL del)
{
    gstore *s = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *s);
    if (!s) return 0;
    if (!h) {
        h = GlobalAlloc(GMEM_MOVEABLE | GMEM_NODISCARD | GMEM_SHARE, 0);
        if (!h) { HeapFree(GetProcessHeap(), 0, s); return 0; }
        s->size = 0;
    } else {
        s->size = GlobalSize(h);
    }
    s->h = h;
    s->refs = 1;
    s->delete_on_release = del;
    InitializeSRWLock(&s->lock);
    return s;
}

static void store_release(gstore *s)
{
    if (InterlockedDecrement(&s->refs)) return;
    if (s->delete_on_release && s->h) GlobalFree(s->h);
    HeapFree(GetProcessHeap(), 0, s);
}

/* grows the block to hold `need` bytes (lock held). */
static HRESULT store_reserve(gstore *s, ULONGLONG need)
{
    SIZE_T have = s->h ? GlobalSize(s->h) : 0;
    if (need > have) {
        HGLOBAL nh;
        SIZE_T want = (SIZE_T)need;
        if (need > (ULONGLONG)(SIZE_T)-1 / 2) return STG_E_MEDIUMFULL_;
        if (want < have * 2) want = have * 2;
        nh = GlobalReAlloc(s->h, want, GMEM_MOVEABLE);
        if (!nh) return STG_E_MEDIUMFULL_;
        s->h = nh;
    }
    return S_OK;
}

static HRESULT store_read(gstore *s, ULONGLONG at, void *buf, ULONG n, ULONG *got)
{
    ULONG can = 0;
    BYTE *p;
    AcquireSRWLockShared(&s->lock);
    if (at < s->size) can = (ULONG)((s->size - at) < n ? s->size - at : n);
    if (can) {
        p = GlobalLock(s->h);
        if (!p) { ReleaseSRWLockShared(&s->lock); return STG_E_INVALIDPOINTER_; }
        memcpy(buf, p + at, can);
        GlobalUnlock(s->h);
    }
    ReleaseSRWLockShared(&s->lock);
    if (got) *got = can;
    return S_OK;
}

static HRESULT store_write(gstore *s, ULONGLONG at, const void *buf, ULONG n, ULONG *put)
{
    HRESULT hr;
    BYTE *p;
    if (put) *put = 0;
    if (!n) return S_OK;
    AcquireSRWLockExclusive(&s->lock);
    hr = store_reserve(s, at + n);
    if (FAILED(hr)) { ReleaseSRWLockExclusive(&s->lock); return hr; }
    p = GlobalLock(s->h);
    if (!p) { ReleaseSRWLockExclusive(&s->lock); return STG_E_INVALIDPOINTER_; }
    if (at > s->size) memset(p + s->size, 0, (SIZE_T)(at - s->size));
    memcpy(p + at, buf, n);
    GlobalUnlock(s->h);
    if (at + n > s->size) s->size = at + n;
    ReleaseSRWLockExclusive(&s->lock);
    if (put) *put = n;
    return S_OK;
}

static HRESULT store_setsize(gstore *s, ULONGLONG size)
{
    HRESULT hr = S_OK;
    AcquireSRWLockExclusive(&s->lock);
    if (size > s->size) {
        hr = store_reserve(s, size);
        if (SUCCEEDED(hr)) {
            BYTE *p = GlobalLock(s->h);
            if (p) { memset(p + s->size, 0, (SIZE_T)(size - s->size)); GlobalUnlock(s->h); }
        }
    }
    if (SUCCEEDED(hr)) s->size = size;
    ReleaseSRWLockExclusive(&s->lock);
    return hr;
}

/* ---------------------------------------------------------------- IStream */
typedef struct { const IStreamVtbl *vt; LONG refs; gstore *st; ULONGLONG pos; } hstream;

static HRESULT STDMETHODCALLTYPE hs_qi(IStream *self, REFIID iid, void **out)
{
    if (!out) return E_POINTER_;
    if (!memcmp(iid, &shz_iid_unknown, sizeof(IID)) || !memcmp(iid, &iid_stream, sizeof(IID)) || !memcmp(iid, &iid_sequentialstream, sizeof(IID))) {
        *out = self;
        IStream_AddRef(self);
        return S_OK;
    }
    *out = 0;
    return E_NOINTERFACE_;
}
static ULONG STDMETHODCALLTYPE hs_addref(IStream *self) { return (ULONG)InterlockedIncrement(&((hstream *)self)->refs); }
static ULONG STDMETHODCALLTYPE hs_release(IStream *self)
{
    hstream *s = (hstream *)self;
    ULONG r = (ULONG)InterlockedDecrement(&s->refs);
    if (!r) { store_release(s->st); HeapFree(GetProcessHeap(), 0, s); }
    return r;
}
static HRESULT STDMETHODCALLTYPE hs_read(IStream *self, void *buf, ULONG n, ULONG *got)
{
    hstream *s = (hstream *)self;
    ULONG g = 0;
    HRESULT hr;
    if (!buf && n) return STG_E_INVALIDPOINTER_;
    hr = store_read(s->st, s->pos, buf, n, &g);
    if (SUCCEEDED(hr)) s->pos += g;
    if (got) *got = g;
    return hr;
}
static HRESULT STDMETHODCALLTYPE hs_write(IStream *self, const void *buf, ULONG n, ULONG *put)
{
    hstream *s = (hstream *)self;
    ULONG p = 0;
    HRESULT hr;
    if (!buf && n) return STG_E_INVALIDPOINTER_;
    hr = store_write(s->st, s->pos, buf, n, &p);
    if (SUCCEEDED(hr)) s->pos += p;
    if (put) *put = p;
    return hr;
}
static HRESULT STDMETHODCALLTYPE hs_seek(IStream *self, LARGE_INTEGER move, DWORD origin, ULARGE_INTEGER *newpos)
{
    hstream *s = (hstream *)self;
    LONGLONG base, target;
    switch (origin) {
    case STREAM_SEEK_SET: base = 0; break;
    case STREAM_SEEK_CUR: base = (LONGLONG)s->pos; break;
    case STREAM_SEEK_END: base = (LONGLONG)s->st->size; break;
    default: return STG_E_INVALIDFUNCTION_;
    }
    target = base + move.QuadPart;
    if (target < 0) return STG_E_INVALIDFUNCTION_;
    s->pos = (ULONGLONG)target;
    if (newpos) newpos->QuadPart = s->pos;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE hs_setsize(IStream *self, ULARGE_INTEGER size) { return store_setsize(((hstream *)self)->st, size.QuadPart); }
static HRESULT STDMETHODCALLTYPE hs_copyto(IStream *self, IStream *dst, ULARGE_INTEGER cb, ULARGE_INTEGER *read, ULARGE_INTEGER *written)
{
    BYTE buf[4096];
    ULONGLONG total_r = 0, total_w = 0, left = cb.QuadPart;
    HRESULT hr = S_OK;
    if (!dst) return STG_E_INVALIDPOINTER_;
    while (left) {
        ULONG want = left > sizeof buf ? (ULONG)sizeof buf : (ULONG)left, got = 0, put = 0;
        hr = IStream_Read(self, buf, want, &got);
        if (FAILED(hr) || !got) break;
        total_r += got;
        hr = IStream_Write(dst, buf, got, &put);
        total_w += put;
        if (FAILED(hr)) break;
        left -= got;
    }
    if (read) read->QuadPart = total_r;
    if (written) written->QuadPart = total_w;
    return hr;
}
static HRESULT STDMETHODCALLTYPE hs_commit(IStream *self, DWORD flags) { (void)self; (void)flags; return S_OK; }
static HRESULT STDMETHODCALLTYPE hs_revert(IStream *self) { (void)self; return S_OK; }
static HRESULT STDMETHODCALLTYPE hs_lock(IStream *self, ULARGE_INTEGER o, ULARGE_INTEGER n, DWORD t) { (void)self; (void)o; (void)n; (void)t; return STG_E_INVALIDFUNCTION_; }
static HRESULT STDMETHODCALLTYPE hs_stat(IStream *self, STATSTG *st, DWORD flags)
{
    hstream *s = (hstream *)self;
    (void)flags;
    if (!st) return STG_E_INVALIDPOINTER_;
    memset(st, 0, sizeof *st);
    st->type = STGTY_STREAM;
    st->cbSize.QuadPart = s->st->size;
    st->grfMode = STGM_READWRITE;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE hs_clone(IStream *self, IStream **out);

static const IStreamVtbl hstream_vtbl = { hs_qi, hs_addref, hs_release, hs_read, hs_write, hs_seek, hs_setsize, hs_copyto, hs_commit, hs_revert, hs_lock, hs_lock, hs_stat, hs_clone };

static IStream *hstream_new(gstore *st, ULONGLONG pos)
{
    hstream *s = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *s);
    if (!s) return 0;
    s->vt = &hstream_vtbl;
    s->refs = 1;
    s->st = st;
    s->pos = pos;
    InterlockedIncrement(&st->refs);
    return (IStream *)s;
}

static HRESULT STDMETHODCALLTYPE hs_clone(IStream *self, IStream **out)
{
    hstream *s = (hstream *)self;
    if (!out) return STG_E_INVALIDPOINTER_;
    *out = hstream_new(s->st, s->pos);
    return *out ? S_OK : E_OUTOFMEMORY_;
}

DLLAPI HRESULT WINAPI CreateStreamOnHGlobal(HGLOBAL h, BOOL delete_on_release, LPSTREAM *out)
{
    gstore *st;
    if (!out) return E_INVALIDARG_;
    *out = 0;
    st = store_new(h, delete_on_release);
    if (!st) return E_OUTOFMEMORY_;
    *out = hstream_new(st, 0);
    store_release(st);                                     /* the stream holds its own reference */
    return *out ? S_OK : E_OUTOFMEMORY_;
}

DLLAPI HRESULT WINAPI GetHGlobalFromStream(LPSTREAM stream, HGLOBAL *out)
{
    hstream *s = (hstream *)stream;
    if (!stream || !out) return E_INVALIDARG_;
    if (s->vt != &hstream_vtbl) { *out = 0; return E_INVALIDARG_; }
    AcquireSRWLockShared(&s->st->lock);
    *out = s->st->h;
    ReleaseSRWLockShared(&s->st->lock);
    return S_OK;
}

/* ---------------------------------------------------------------- ILockBytes */
typedef struct { const ILockBytesVtbl *vt; LONG refs; gstore *st; } hlockbytes;

static HRESULT STDMETHODCALLTYPE lb_qi(ILockBytes *self, REFIID iid, void **out)
{
    if (!out) return E_POINTER_;
    if (!memcmp(iid, &shz_iid_unknown, sizeof(IID)) || !memcmp(iid, &iid_lockbytes, sizeof(IID))) { *out = self; ILockBytes_AddRef(self); return S_OK; }
    *out = 0;
    return E_NOINTERFACE_;
}
static ULONG STDMETHODCALLTYPE lb_addref(ILockBytes *self) { return (ULONG)InterlockedIncrement(&((hlockbytes *)self)->refs); }
static ULONG STDMETHODCALLTYPE lb_release(ILockBytes *self)
{
    hlockbytes *s = (hlockbytes *)self;
    ULONG r = (ULONG)InterlockedDecrement(&s->refs);
    if (!r) { store_release(s->st); HeapFree(GetProcessHeap(), 0, s); }
    return r;
}
static HRESULT STDMETHODCALLTYPE lb_readat(ILockBytes *self, ULARGE_INTEGER off, void *buf, ULONG n, ULONG *got)
{ if (!buf && n) return STG_E_INVALIDPOINTER_; return store_read(((hlockbytes *)self)->st, off.QuadPart, buf, n, got); }
static HRESULT STDMETHODCALLTYPE lb_writeat(ILockBytes *self, ULARGE_INTEGER off, const void *buf, ULONG n, ULONG *put)
{ if (!buf && n) return STG_E_INVALIDPOINTER_; return store_write(((hlockbytes *)self)->st, off.QuadPart, buf, n, put); }
static HRESULT STDMETHODCALLTYPE lb_flush(ILockBytes *self) { (void)self; return S_OK; }
static HRESULT STDMETHODCALLTYPE lb_setsize(ILockBytes *self, ULARGE_INTEGER size) { return store_setsize(((hlockbytes *)self)->st, size.QuadPart); }
static HRESULT STDMETHODCALLTYPE lb_lock(ILockBytes *self, ULARGE_INTEGER o, ULARGE_INTEGER n, DWORD t) { (void)self; (void)o; (void)n; (void)t; return STG_E_INVALIDFUNCTION_; }
static HRESULT STDMETHODCALLTYPE lb_stat(ILockBytes *self, STATSTG *st, DWORD flags)
{
    (void)flags;
    if (!st) return STG_E_INVALIDPOINTER_;
    memset(st, 0, sizeof *st);
    st->type = STGTY_LOCKBYTES;
    st->cbSize.QuadPart = ((hlockbytes *)self)->st->size;
    st->grfMode = STGM_READWRITE;
    return S_OK;
}
static const ILockBytesVtbl hlockbytes_vtbl = { lb_qi, lb_addref, lb_release, lb_readat, lb_writeat, lb_flush, lb_setsize, lb_lock, lb_lock, lb_stat };

DLLAPI HRESULT WINAPI CreateILockBytesOnHGlobal(HGLOBAL h, BOOL delete_on_release, ILockBytes **out)
{
    hlockbytes *s;
    if (!out) return E_INVALIDARG_;
    *out = 0;
    s = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *s);
    if (!s) return E_OUTOFMEMORY_;
    s->st = store_new(h, delete_on_release);
    if (!s->st) { HeapFree(GetProcessHeap(), 0, s); return E_OUTOFMEMORY_; }
    s->vt = &hlockbytes_vtbl;
    s->refs = 1;
    *out = (ILockBytes *)s;
    return S_OK;
}

DLLAPI HRESULT WINAPI GetHGlobalFromILockBytes(ILockBytes *lb, HGLOBAL *out)
{
    hlockbytes *s = (hlockbytes *)lb;
    if (!lb || !out) return E_INVALIDARG_;
    if (s->vt != &hlockbytes_vtbl) { *out = 0; return E_INVALIDARG_; }
    *out = s->st->h;
    return S_OK;
}

DLLAPI HRESULT WINAPI StgCreateDocfileOnILockBytes(ILockBytes *lb, DWORD mode, DWORD reserved, IStorage **out)
{
    (void)lb; (void)mode; (void)reserved;
    if (!out) return STG_E_INVALIDPOINTER_;
    *out = 0;
    return STG_E_UNIMPLEMENTEDFUNCTION_;                  /* the compound-file format is not implemented here */
}

DLLAPI HRESULT WINAPI StgOpenStorageOnILockBytes(ILockBytes *lb, IStorage *prio, DWORD mode, SNB exclude, DWORD reserved, IStorage **out)
{
    (void)lb; (void)prio; (void)mode; (void)exclude; (void)reserved;
    if (!out) return STG_E_INVALIDPOINTER_;
    *out = 0;
    return STG_E_UNIMPLEMENTEDFUNCTION_;
}

DLLAPI HRESULT WINAPI StgIsStorageILockBytes(ILockBytes *lb)
{
    BYTE sig[8];
    ULARGE_INTEGER zero;
    ULONG got = 0;
    static const BYTE cf[8] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    if (!lb) return STG_E_INVALIDPOINTER_;
    zero.QuadPart = 0;
    if (FAILED(ILockBytes_ReadAt(lb, zero, sig, 8, &got)) || got != 8) return S_FALSE;
    return memcmp(sig, cf, 8) ? S_FALSE : S_OK;
}

/* ---------------------------------------------------------------- STGMEDIUM, data duplication */
DLLAPI void WINAPI ReleaseStgMedium(STGMEDIUM *m)
{
    if (!m) return;
    if (m->pUnkForRelease) {
        IUnknown_Release(m->pUnkForRelease);
    } else {
        switch (m->tymed) {
        case TYMED_HGLOBAL: if (m->hGlobal) GlobalFree(m->hGlobal); break;
        case TYMED_FILE: if (m->lpszFileName) { DeleteFileW(m->lpszFileName); CoTaskMemFree(m->lpszFileName); } break;
        case TYMED_ISTREAM: if (m->pstm) IStream_Release(m->pstm); break;
        case TYMED_ISTORAGE: if (m->pstg) IStorage_Release(m->pstg); break;
        case TYMED_GDI: if (m->hBitmap) DeleteObject(m->hBitmap); break;
        case TYMED_MFPICT: if (m->hMetaFilePict) GlobalFree(m->hMetaFilePict); break;   /* no Windows metafiles exist here (gdi32 has no DeleteMetaFile) */
        case TYMED_ENHMF: if (m->hEnhMetaFile) DeleteEnhMetaFile(m->hEnhMetaFile); break;
        default: break;
        }
    }
    m->tymed = TYMED_NULL;
    m->hGlobal = 0;
    m->pUnkForRelease = 0;
}

DLLAPI HANDLE WINAPI OleDuplicateData(HANDLE src, CLIPFORMAT fmt, UINT flags)
{
    SIZE_T n;
    HGLOBAL dst;
    void *s, *d;
    if (!src) return 0;
    if (fmt == CF_BITMAP || fmt == CF_PALETTE || fmt == CF_ENHMETAFILE || fmt == CF_METAFILEPICT) return 0;   /* GDI objects: not duplicated here */
    n = GlobalSize(src);
    if (!n) return 0;
    dst = GlobalAlloc(flags ? flags : GMEM_MOVEABLE, n);
    if (!dst) return 0;
    s = GlobalLock(src);
    d = GlobalLock(dst);
    if (s && d) memcpy(d, s, n);
    if (s) GlobalUnlock(src);
    if (d) GlobalUnlock(dst);
    if (!s || !d) { GlobalFree(dst); return 0; }
    return dst;
}
