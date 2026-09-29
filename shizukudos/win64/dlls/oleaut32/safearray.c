/* SPDX-License-Identifier: GPL-2.0-only
 * SAFEARRAY: descriptor {cDims, fFeatures, cbElements, cLocks, pvData, rgsabound[cDims]} with the element vartype kept
 * in the hidden DWORD in front of the descriptor (FADF_HAVEVARTYPE), as the documented x64 layout prescribes.
 *
 * Dimension order: dimension 1 (the nDim of SafeArrayGetLBound/GetUBound) is the leftmost one and is rgsabound[cDims - 1];
 * rgIndices[0] indexes dimension 1 (the convention every C++ consumer of Excel/ADO arrays uses: idx[0] = row, idx[1] = column);
 * the leftmost dimension varies fastest in memory (column-major, as VB arrays are) and rgsabound[0], the only dimension
 * SafeArrayRedim may change, varies slowest so that growing it just extends the data. MSDN's prose for SafeArrayGetElement
 * words the direction of rgIndices ambiguously; this file follows the convention above, which has not been compared with a
 * real Windows here.
 *
 * Element vartypes handled: I1 UI1 I2 UI2 BOOL I4 UI4 INT UINT ERROR R4 I8 UI8 R8 CY DATE BSTR DISPATCH UNKNOWN VARIANT
 * DECIMAL. Arrays of records (IRecordInfo) or with an IID are not supported.
 */
#include "oleaut_int.h"

#define PREFIX 16                              /* hidden bytes in front of the descriptor: [-4] = vartype */
#define ELEM_LIMIT 0x7fffffffull

static ULONG vt_size(VARTYPE vt)
{
    switch (vt) {
    case VT_I1: case VT_UI1: return 1;
    case VT_I2: case VT_UI2: case VT_BOOL: return 2;
    case VT_I4: case VT_UI4: case VT_R4: case VT_INT: case VT_UINT: case VT_ERROR: return 4;
    case VT_I8: case VT_UI8: case VT_R8: case VT_CY: case VT_DATE: return 8;
    case VT_BSTR: case VT_DISPATCH: case VT_UNKNOWN: return sizeof(void *);
    case VT_VARIANT: return sizeof(VARIANT);
    case VT_DECIMAL: return sizeof(DECIMAL);
    }
    return 0;
}

static USHORT vt_features(VARTYPE vt)
{
    USHORT f = FADF_HAVEVARTYPE;
    if (vt == VT_BSTR) f |= FADF_BSTR;
    else if (vt == VT_UNKNOWN) f |= FADF_UNKNOWN;
    else if (vt == VT_DISPATCH) f |= FADF_DISPATCH;
    else if (vt == VT_VARIANT) f |= FADF_VARIANT;
    return f;
}

static VARTYPE psa_vt(const SAFEARRAY *psa)
{
    if (psa->fFeatures & FADF_HAVEVARTYPE) return (VARTYPE)*(ULONG *)((unsigned char *)psa - 4);
    if (psa->fFeatures & FADF_BSTR) return VT_BSTR;
    if (psa->fFeatures & FADF_UNKNOWN) return VT_UNKNOWN;
    if (psa->fFeatures & FADF_DISPATCH) return VT_DISPATCH;
    if (psa->fFeatures & FADF_VARIANT) return VT_VARIANT;
    return VT_EMPTY;
}

static int count_cells(const SAFEARRAY *psa, ULONGLONG *out)
{
    ULONGLONG n = 1;
    unsigned i;
    for (i = 0; i < psa->cDims; ++i) {
        n *= psa->rgsabound[i].cElements;
        if (n > ELEM_LIMIT) return 0;
    }
    *out = n;
    return 1;
}

DLLAPI HRESULT WINAPI SafeArrayAllocDescriptorEx(VARTYPE vt, UINT cdims, SAFEARRAY **out)
{
    unsigned char *p;
    SAFEARRAY *psa;
    if (!out || !cdims || cdims > 65535) return E_INVALIDARG;
    p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PREFIX + sizeof(SAFEARRAY) + (cdims - 1) * sizeof(SAFEARRAYBOUND));
    if (!p) return E_OUTOFMEMORY;
    psa = (SAFEARRAY *)(p + PREFIX);
    *(ULONG *)((unsigned char *)psa - 4) = vt;
    psa->cDims = (USHORT)cdims;
    psa->fFeatures = vt_features(vt);
    psa->cbElements = vt_size(vt);
    *out = psa;
    return S_OK;
}

DLLAPI HRESULT WINAPI SafeArrayAllocDescriptor(UINT cdims, SAFEARRAY **out)
{
    HRESULT hr = SafeArrayAllocDescriptorEx(VT_EMPTY, cdims, out);
    if (SUCCEEDED(hr)) {
        (*out)->fFeatures = 0;                                     /* no vartype: the caller sets cbElements and features */
        (*out)->cbElements = 0;
    }
    return hr;
}

DLLAPI HRESULT WINAPI SafeArrayAllocData(SAFEARRAY *psa)
{
    ULONGLONG cells;
    if (!psa) return E_INVALIDARG;
    if (!count_cells(psa, &cells) || cells * psa->cbElements > ELEM_LIMIT) return E_OUTOFMEMORY;
    psa->pvData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)(cells * psa->cbElements) + 1);
    return psa->pvData ? S_OK : E_OUTOFMEMORY;
}

DLLAPI SAFEARRAY *WINAPI SafeArrayCreate(VARTYPE vt, UINT cdims, SAFEARRAYBOUND *bounds)
{
    SAFEARRAY *psa = 0;
    UINT i;
    if (!vt_size(vt) || !cdims || !bounds) return 0;
    if (FAILED(SafeArrayAllocDescriptorEx(vt, cdims, &psa))) return 0;
    for (i = 0; i < cdims; ++i) psa->rgsabound[i] = bounds[i];
    if (FAILED(SafeArrayAllocData(psa))) {
        HeapFree(GetProcessHeap(), 0, (unsigned char *)psa - PREFIX);
        return 0;
    }
    return psa;
}

DLLAPI SAFEARRAY *WINAPI SafeArrayCreateVector(VARTYPE vt, LONG lbound, ULONG cElements)
{
    SAFEARRAYBOUND b;
    b.lLbound = lbound;
    b.cElements = cElements;
    return SafeArrayCreate(vt, 1, &b);
}

DLLAPI HRESULT WINAPI SafeArrayGetVartype(SAFEARRAY *psa, VARTYPE *pvt)
{
    VARTYPE vt;
    if (!psa || !pvt) return E_INVALIDARG;
    vt = psa_vt(psa);
    if (!vt) return E_INVALIDARG;
    *pvt = vt;
    return S_OK;
}

DLLAPI UINT WINAPI SafeArrayGetDim(SAFEARRAY *psa) { return psa ? psa->cDims : 0; }
DLLAPI UINT WINAPI SafeArrayGetElemsize(SAFEARRAY *psa) { return psa ? psa->cbElements : 0; }

DLLAPI HRESULT WINAPI SafeArrayGetLBound(SAFEARRAY *psa, UINT dim, LONG *out)
{
    if (!psa || !out) return E_INVALIDARG;
    if (!dim || dim > psa->cDims) return DISP_E_BADINDEX;
    *out = psa->rgsabound[psa->cDims - dim].lLbound;
    return S_OK;
}

DLLAPI HRESULT WINAPI SafeArrayGetUBound(SAFEARRAY *psa, UINT dim, LONG *out)
{
    if (!psa || !out) return E_INVALIDARG;
    if (!dim || dim > psa->cDims) return DISP_E_BADINDEX;
    *out = psa->rgsabound[psa->cDims - dim].lLbound + (LONG)psa->rgsabound[psa->cDims - dim].cElements - 1;
    return S_OK;
}

DLLAPI HRESULT WINAPI SafeArrayLock(SAFEARRAY *psa)
{
    if (!psa) return E_INVALIDARG;
    if (psa->cLocks == 0xffffu) return E_UNEXPECTED;
    InterlockedIncrement((LONG *)&psa->cLocks);
    return S_OK;
}

DLLAPI HRESULT WINAPI SafeArrayUnlock(SAFEARRAY *psa)
{
    if (!psa) return E_INVALIDARG;
    if (!psa->cLocks) return E_UNEXPECTED;
    InterlockedDecrement((LONG *)&psa->cLocks);
    return S_OK;
}

DLLAPI HRESULT WINAPI SafeArrayAccessData(SAFEARRAY *psa, void **ppv)
{
    if (!psa || !ppv) return E_INVALIDARG;
    SafeArrayLock(psa);
    *ppv = psa->pvData;
    return S_OK;
}

DLLAPI HRESULT WINAPI SafeArrayUnaccessData(SAFEARRAY *psa) { return SafeArrayUnlock(psa); }

/* Address of one element; DISP_E_BADINDEX if an index is outside its bounds. */
DLLAPI HRESULT WINAPI SafeArrayPtrOfIndex(SAFEARRAY *psa, LONG *idx, void **ppv)
{
    ULONGLONG cell = 0, stride = 1;
    unsigned k;
    if (!psa || !idx || !ppv) return E_INVALIDARG;
    for (k = 0; k < psa->cDims; ++k) {
        const SAFEARRAYBOUND *b = &psa->rgsabound[psa->cDims - 1 - k];    /* idx[0] belongs to dimension 1 = rgsabound[cDims-1] */
        LONGLONG rel = (LONGLONG)idx[k] - b->lLbound;
        if (rel < 0 || rel >= (LONGLONG)b->cElements) return DISP_E_BADINDEX;
        cell += (ULONGLONG)rel * stride;
        stride *= b->cElements;
    }
    *ppv = (unsigned char *)psa->pvData + cell * psa->cbElements;
    return S_OK;
}

/* Release what one element owns (BSTR / interface pointer / VARIANT payload) and zero it. */
static void element_clear(const SAFEARRAY *psa, void *elem)
{
    if (psa->fFeatures & FADF_BSTR) { SysFreeString(*(BSTR *)elem); *(BSTR *)elem = 0; }
    else if (psa->fFeatures & (FADF_UNKNOWN | FADF_DISPATCH)) {
        IUnknown *u = *(IUnknown **)elem;
        if (u) u->lpVtbl->Release(u);
        *(IUnknown **)elem = 0;
    } else if (psa->fFeatures & FADF_VARIANT) VariantClear((VARIANT *)elem);
}

static int owns_resources(const SAFEARRAY *psa) { return (psa->fFeatures & (FADF_BSTR | FADF_UNKNOWN | FADF_DISPATCH | FADF_VARIANT)) != 0; }

DLLAPI HRESULT WINAPI SafeArrayDestroyData(SAFEARRAY *psa)
{
    if (!psa) return S_OK;
    if (psa->cLocks) return DISP_E_ARRAYISLOCKED;
    if (psa->pvData) {
        if (owns_resources(psa)) {
            ULONGLONG cells = 0, i;
            count_cells(psa, &cells);
            for (i = 0; i < cells; ++i) element_clear(psa, (unsigned char *)psa->pvData + i * psa->cbElements);
        }
        if (!(psa->fFeatures & (FADF_STATIC | FADF_FIXEDSIZE))) {
            HeapFree(GetProcessHeap(), 0, psa->pvData);
            psa->pvData = 0;
        }
    }
    return S_OK;
}

DLLAPI HRESULT WINAPI SafeArrayDestroyDescriptor(SAFEARRAY *psa)
{
    if (!psa) return S_OK;
    if (psa->cLocks) return DISP_E_ARRAYISLOCKED;
    if (!(psa->fFeatures & (FADF_AUTO | FADF_STATIC | FADF_EMBEDDED))) HeapFree(GetProcessHeap(), 0, (unsigned char *)psa - PREFIX);
    return S_OK;
}

DLLAPI HRESULT WINAPI SafeArrayDestroy(SAFEARRAY *psa)
{
    HRESULT hr;
    if (!psa) return S_OK;
    if (psa->cLocks) return DISP_E_ARRAYISLOCKED;
    hr = SafeArrayDestroyData(psa);
    if (FAILED(hr)) return hr;
    return SafeArrayDestroyDescriptor(psa);
}

/* Copy one element with the ownership rules of its type: dst must hold a valid (possibly zero) element. */
static HRESULT element_copy(const SAFEARRAY *psa, void *dst, const void *src)
{
    if (dst == src) return S_OK;
    if (psa->fFeatures & FADF_BSTR) {
        BSTR s = *(BSTR const *)src, n = 0;
        if (s) {
            n = SysAllocStringByteLen((const char *)s, SysStringByteLen(s));
            if (!n) return E_OUTOFMEMORY;
        }
        SysFreeString(*(BSTR *)dst);
        *(BSTR *)dst = n;
    } else if (psa->fFeatures & (FADF_UNKNOWN | FADF_DISPATCH)) {
        IUnknown *s = *(IUnknown *const *)src, *old = *(IUnknown **)dst;
        if (s) s->lpVtbl->AddRef(s);
        *(IUnknown **)dst = s;
        if (old) old->lpVtbl->Release(old);
    } else if (psa->fFeatures & FADF_VARIANT) {
        HRESULT hr = VariantCopy((VARIANT *)dst, (VARIANT *)src);
        if (FAILED(hr)) return hr;
    } else {
        memcpy(dst, src, psa->cbElements);
    }
    return S_OK;
}

DLLAPI HRESULT WINAPI SafeArrayGetElement(SAFEARRAY *psa, LONG *idx, void *pv)
{
    void *elem;
    HRESULT hr;
    if (!psa || !idx || !pv) return E_INVALIDARG;
    if (psa->fFeatures & FADF_RECORD) return E_NOTIMPL;
    hr = SafeArrayPtrOfIndex(psa, idx, &elem);
    if (FAILED(hr)) return hr;
    SafeArrayLock(psa);
    if (psa->fFeatures & FADF_BSTR) {
        BSTR s = *(BSTR *)elem, n = 0;
        if (s) {
            n = SysAllocStringByteLen((const char *)s, SysStringByteLen(s));
            if (!n) { SafeArrayUnlock(psa); return E_OUTOFMEMORY; }
        }
        *(BSTR *)pv = n;                                                /* the caller owns the copy */
        hr = S_OK;
    } else if (psa->fFeatures & (FADF_UNKNOWN | FADF_DISPATCH)) {
        IUnknown *u = *(IUnknown **)elem;
        if (u) u->lpVtbl->AddRef(u);
        *(IUnknown **)pv = u;
        hr = S_OK;
    } else if (psa->fFeatures & FADF_VARIANT) {
        hr = VariantCopy((VARIANT *)pv, (VARIANT *)elem);              /* pv must be an initialised VARIANT */
    } else {
        memcpy(pv, elem, psa->cbElements);
        hr = S_OK;
    }
    SafeArrayUnlock(psa);
    return hr;
}

DLLAPI HRESULT WINAPI SafeArrayPutElement(SAFEARRAY *psa, LONG *idx, void *pv)
{
    void *elem;
    HRESULT hr;
    if (!psa || !idx) return E_INVALIDARG;
    if (psa->fFeatures & FADF_RECORD) return E_NOTIMPL;
    if (!pv && (psa->fFeatures & (FADF_VARIANT)) ) return E_INVALIDARG;
    hr = SafeArrayPtrOfIndex(psa, idx, &elem);
    if (FAILED(hr)) return hr;
    SafeArrayLock(psa);
    if (psa->fFeatures & FADF_BSTR) {
        /* for a BSTR array pv is the BSTR itself (not a pointer to it) */
        BSTR n = 0;
        if (pv) {
            n = SysAllocStringByteLen((const char *)pv, SysStringByteLen((BSTR)pv));
            if (!n) { SafeArrayUnlock(psa); return E_OUTOFMEMORY; }
        }
        SysFreeString(*(BSTR *)elem);
        *(BSTR *)elem = n;
        hr = S_OK;
    } else if (psa->fFeatures & (FADF_UNKNOWN | FADF_DISPATCH)) {
        /* for interface arrays pv is the interface pointer itself */
        IUnknown *n = (IUnknown *)pv, *old = *(IUnknown **)elem;
        if (n) n->lpVtbl->AddRef(n);
        *(IUnknown **)elem = n;
        if (old) old->lpVtbl->Release(old);
        hr = S_OK;
    } else if (psa->fFeatures & FADF_VARIANT) {
        hr = VariantCopy((VARIANT *)elem, (VARIANT *)pv);
    } else {
        if (!pv) hr = E_INVALIDARG;
        else { memcpy(elem, pv, psa->cbElements); hr = S_OK; }
    }
    SafeArrayUnlock(psa);
    return hr;
}

DLLAPI HRESULT WINAPI SafeArrayCopyData(SAFEARRAY *src, SAFEARRAY *dst)
{
    ULONGLONG cells = 0, i;
    unsigned d;
    if (!src || !dst) return E_INVALIDARG;
    if (src->cDims != dst->cDims || src->cbElements != dst->cbElements) return E_INVALIDARG;
    for (d = 0; d < src->cDims; ++d)
        if (src->rgsabound[d].cElements != dst->rgsabound[d].cElements) return E_INVALIDARG;
    if (src == dst) return S_OK;
    if (!count_cells(src, &cells)) return E_INVALIDARG;
    if (!cells) return S_OK;
    if (!src->pvData || !dst->pvData) return E_INVALIDARG;
    for (i = 0; i < cells; ++i) {
        HRESULT hr = element_copy(dst, (unsigned char *)dst->pvData + i * dst->cbElements, (unsigned char *)src->pvData + i * src->cbElements);
        if (FAILED(hr)) return hr;
    }
    return S_OK;
}

DLLAPI HRESULT WINAPI SafeArrayCopy(SAFEARRAY *psa, SAFEARRAY **out)
{
    SAFEARRAY *n = 0;
    VARTYPE vt;
    HRESULT hr;
    unsigned d;
    if (!out) return E_INVALIDARG;
    *out = 0;
    if (!psa) return S_OK;
    if (psa->fFeatures & FADF_RECORD) return E_NOTIMPL;
    vt = psa_vt(psa);
    hr = SafeArrayAllocDescriptorEx(vt, psa->cDims, &n);
    if (FAILED(hr)) return hr;
    for (d = 0; d < psa->cDims; ++d) n->rgsabound[d] = psa->rgsabound[d];
    n->cbElements = psa->cbElements;
    n->fFeatures = (USHORT)((psa->fFeatures & ~(FADF_AUTO | FADF_STATIC | FADF_EMBEDDED | FADF_FIXEDSIZE)) & ~0xf000);
    hr = SafeArrayAllocData(n);
    if (SUCCEEDED(hr)) hr = SafeArrayCopyData(psa, n);
    if (FAILED(hr)) {
        SafeArrayDestroy(n);
        return hr;
    }
    *out = n;
    return S_OK;
}

DLLAPI HRESULT WINAPI SafeArrayRedim(SAFEARRAY *psa, SAFEARRAYBOUND *nb)
{
    ULONGLONG others = 1, oldcells, newcells, i;
    unsigned d;
    void *nd;
    if (!psa || !nb) return E_INVALIDARG;
    if (psa->cLocks) return DISP_E_ARRAYISLOCKED;
    if (psa->fFeatures & (FADF_FIXEDSIZE | FADF_STATIC | FADF_EMBEDDED | FADF_AUTO)) return E_INVALIDARG;
    for (d = 1; d < psa->cDims; ++d) others *= psa->rgsabound[d].cElements;      /* rgsabound[0] varies slowest: resize at the end */
    oldcells = others * psa->rgsabound[0].cElements;
    newcells = others * nb->cElements;
    if (newcells > ELEM_LIMIT || newcells * psa->cbElements > ELEM_LIMIT) return E_OUTOFMEMORY;
    if (newcells < oldcells && owns_resources(psa))
        for (i = newcells; i < oldcells; ++i) element_clear(psa, (unsigned char *)psa->pvData + i * psa->cbElements);
    nd = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, psa->pvData, (SIZE_T)(newcells * psa->cbElements) + 1);
    if (!nd) return E_OUTOFMEMORY;
    if (newcells > oldcells) memset((unsigned char *)nd + oldcells * psa->cbElements, 0, (SIZE_T)((newcells - oldcells) * psa->cbElements) + 1);
    psa->pvData = nd;
    psa->rgsabound[0] = *nb;
    return S_OK;
}
