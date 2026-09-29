/* SPDX-License-Identifier: GPL-2.0-only
 * PROPVARIANT: PropVariantClear / PropVariantCopy / FreePropVariantArray with the documented ownership of every type:
 * scalars own nothing; BSTR is released with SysFreeString; LPSTR, LPWSTR, BLOB, CLSID, CF data and vector arrays are
 * CoTaskMem blocks; VT_UNKNOWN/DISPATCH/STREAM/STORAGE/STORED_OBJECT/STREAMED_OBJECT/VERSIONED_STREAM hold a COM
 * reference; VT_ARRAY holds a SAFEARRAY; VT_VECTOR|x owns its element array (and each element's payload for BSTR, LPSTR,
 * LPWSTR, CF and VARIANT/PROPVARIANT). Invalid or by-reference types fail with STG_E_INVALIDPARAMETER.
 * PropVariantCopy assumes its destination is uninitialised (documented: the caller clears it first if needed).
 */
#include "ole32_int.h"

static int scalar_ok(VARTYPE b)
{
    switch (b) {
    case VT_EMPTY: case VT_NULL: case VT_I2: case VT_I4: case VT_R4: case VT_R8: case VT_CY: case VT_DATE: case VT_BSTR:
    case VT_DISPATCH: case VT_ERROR: case VT_BOOL: case VT_UNKNOWN: case VT_DECIMAL: case VT_I1: case VT_UI1: case VT_UI2:
    case VT_UI4: case VT_I8: case VT_UI8: case VT_INT: case VT_UINT: case VT_LPSTR: case VT_LPWSTR: case VT_FILETIME:
    case VT_BLOB: case VT_STREAM: case VT_STORAGE: case VT_STREAMED_OBJECT: case VT_STORED_OBJECT: case VT_BLOB_OBJECT:
    case VT_CF: case VT_CLSID: case VT_VERSIONED_STREAM:
        return 1;
    }
    return 0;
}

static SIZE_T vec_elem_size(VARTYPE b)
{
    switch (b) {
    case VT_I1: case VT_UI1: return 1;
    case VT_I2: case VT_UI2: case VT_BOOL: return 2;
    case VT_I4: case VT_UI4: case VT_R4: case VT_ERROR: return 4;
    case VT_I8: case VT_UI8: case VT_R8: case VT_CY: case VT_DATE: case VT_FILETIME: return 8;
    case VT_CLSID: return sizeof(CLSID);
    case VT_CF: return sizeof(CLIPDATA);
    case VT_BSTR: case VT_LPSTR: case VT_LPWSTR: return sizeof(void *);
    case VT_VARIANT: return sizeof(PROPVARIANT);
    }
    return 0;
}

static int array_ok(VARTYPE b)
{
    switch (b) {
    case VT_I2: case VT_I4: case VT_R4: case VT_R8: case VT_CY: case VT_DATE: case VT_BSTR: case VT_DISPATCH: case VT_ERROR:
    case VT_BOOL: case VT_VARIANT: case VT_UNKNOWN: case VT_DECIMAL: case VT_I1: case VT_UI1: case VT_UI2: case VT_UI4:
    case VT_INT: case VT_UINT:
        return 1;
    }
    return 0;
}

static int pv_valid(VARTYPE vt)
{
    const VARTYPE base = vt & VT_TYPEMASK, flags = vt & 0xf000;
    if (flags & (VT_BYREF | VT_RESERVED)) return 0;
    if ((flags & VT_VECTOR) && (flags & VT_ARRAY)) return 0;
    if (flags & VT_VECTOR) return vec_elem_size(base) != 0;
    if (flags & VT_ARRAY) return array_ok(base);
    return scalar_ok(base);
}

DLLAPI HRESULT WINAPI PropVariantClear(PROPVARIANT *pv)
{
    VARTYPE vt;
    if (!pv) return S_OK;
    vt = pv->vt;
    if (!pv_valid(vt)) return STG_E_INVALIDPARAMETER;
    if (vt & VT_VECTOR) {
        const VARTYPE base = vt & VT_TYPEMASK;
        BYTE *p = pv->caub.pElems;
        ULONG i, n = pv->caub.cElems;
        if (p) {
            for (i = 0; i < n; ++i) {
                switch (base) {
                case VT_BSTR: SysFreeString(((BSTR *)p)[i]); break;
                case VT_LPSTR: case VT_LPWSTR: CoTaskMemFree(((void **)p)[i]); break;
                case VT_VARIANT: PropVariantClear(&((PROPVARIANT *)p)[i]); break;
                case VT_CF: CoTaskMemFree(((CLIPDATA *)p)[i].pClipData); break;
                }
            }
            CoTaskMemFree(p);
        }
    } else if (vt & VT_ARRAY) {
        if (pv->parray) SafeArrayDestroy(pv->parray);
    } else {
        switch (vt) {
        case VT_BSTR: SysFreeString(pv->bstrVal); break;
        case VT_LPSTR: CoTaskMemFree(pv->pszVal); break;
        case VT_LPWSTR: CoTaskMemFree(pv->pwszVal); break;
        case VT_BLOB: case VT_BLOB_OBJECT: CoTaskMemFree(pv->blob.pBlobData); break;
        case VT_CLSID: CoTaskMemFree(pv->puuid); break;
        case VT_CF:
            if (pv->pclipdata) { CoTaskMemFree(pv->pclipdata->pClipData); CoTaskMemFree(pv->pclipdata); }
            break;
        case VT_UNKNOWN: if (pv->punkVal) IUnknown_Release(pv->punkVal); break;
        case VT_DISPATCH: if (pv->pdispVal) IDispatch_Release(pv->pdispVal); break;
        case VT_STREAM: case VT_STREAMED_OBJECT: if (pv->pStream) IUnknown_Release((IUnknown *)pv->pStream); break;
        case VT_STORAGE: case VT_STORED_OBJECT: if (pv->pStorage) IUnknown_Release((IUnknown *)pv->pStorage); break;
        case VT_VERSIONED_STREAM:
            if (pv->pVersionedStream) {
                if (pv->pVersionedStream->pStream) IUnknown_Release((IUnknown *)pv->pVersionedStream->pStream);
                CoTaskMemFree(pv->pVersionedStream);
            }
            break;
        }
    }
    pv->vt = VT_EMPTY;
    return S_OK;
}

static void *dup_block(const void *src, SIZE_T n)
{
    void *p = CoTaskMemAlloc(n);
    if (p && n) memcpy(p, src, n);
    return p;
}

static SIZE_T str_bytes(const void *s, int wide)
{
    SIZE_T n = 0;
    if (wide) { const WCHAR *w = s; while (w[n]) ++n; return (n + 1) * sizeof(WCHAR); }
    { const char *c = s; while (c[n]) ++n; return n + 1; }
}

DLLAPI HRESULT WINAPI PropVariantCopy(PROPVARIANT *dst, const PROPVARIANT *src)
{
    VARTYPE vt;
    if (!dst || !src) return STG_E_INVALIDPARAMETER;
    vt = src->vt;
    if (!pv_valid(vt)) return STG_E_INVALIDPARAMETER;
    memcpy(dst, src, sizeof *dst);                                 /* scalars are done; owned payloads are replaced below */
    if (vt & VT_VECTOR) {
        const VARTYPE base = vt & VT_TYPEMASK;
        const SIZE_T es = vec_elem_size(base);
        const ULONG n = src->caub.cElems;
        BYTE *p;
        ULONG i;
        if (n > 0x7fffffffu / es) { dst->vt = VT_EMPTY; return E_OUTOFMEMORY; }
        p = CoTaskMemAlloc(n * es);
        if (!p && n) { dst->vt = VT_EMPTY; return E_OUTOFMEMORY; }
        if (p) memset(p, 0, n * es);                                 /* consistent (all-NULL) until each element is copied */
        dst->caub.pElems = p;
        for (i = 0; i < n; ++i) {
            const BYTE *s = src->caub.pElems + i * es;
            switch (base) {
            case VT_BSTR: {
                BSTR b = *(BSTR const *)s;
                if (b && !(((BSTR *)p)[i] = SysAllocStringByteLen((const char *)b, SysStringByteLen(b)))) goto fail;
                break;
            }
            case VT_LPSTR: case VT_LPWSTR: {
                void *str = *(void *const *)s;
                if (str && !(((void **)p)[i] = dup_block(str, str_bytes(str, base == VT_LPWSTR)))) goto fail;
                break;
            }
            case VT_VARIANT:
                if (FAILED(PropVariantCopy(&((PROPVARIANT *)p)[i], (const PROPVARIANT *)s))) goto fail;
                break;
            case VT_CF: {
                const CLIPDATA *c = (const CLIPDATA *)s;
                CLIPDATA *d = &((CLIPDATA *)p)[i];
                d->cbSize = c->cbSize;
                d->ulClipFmt = c->ulClipFmt;
                if (c->pClipData && c->cbSize >= sizeof(LONG) && !(d->pClipData = dup_block(c->pClipData, c->cbSize - sizeof(LONG)))) goto fail;
                break;
            }
            default:
                memcpy(p + i * es, s, es);
                break;
            }
        }
        return S_OK;
    fail:
        PropVariantClear(dst);
        return E_OUTOFMEMORY;
    }
    if (vt & VT_ARRAY) {
        SAFEARRAY *copy = 0;
        HRESULT hr = SafeArrayCopy(src->parray, &copy);
        if (FAILED(hr)) { dst->vt = VT_EMPTY; return hr; }
        dst->parray = copy;
        return S_OK;
    }
    switch (vt) {
    case VT_BSTR:
        if (src->bstrVal && !(dst->bstrVal = SysAllocStringByteLen((const char *)src->bstrVal, SysStringByteLen(src->bstrVal)))) { dst->vt = VT_EMPTY; return E_OUTOFMEMORY; }
        break;
    case VT_LPSTR:
        if (src->pszVal && !(dst->pszVal = dup_block(src->pszVal, str_bytes(src->pszVal, 0)))) { dst->vt = VT_EMPTY; return E_OUTOFMEMORY; }
        break;
    case VT_LPWSTR:
        if (src->pwszVal && !(dst->pwszVal = dup_block(src->pwszVal, str_bytes(src->pwszVal, 1)))) { dst->vt = VT_EMPTY; return E_OUTOFMEMORY; }
        break;
    case VT_BLOB: case VT_BLOB_OBJECT:
        dst->blob.pBlobData = 0;
        if (src->blob.cbSize) {
            if (!(dst->blob.pBlobData = dup_block(src->blob.pBlobData, src->blob.cbSize))) { dst->vt = VT_EMPTY; return E_OUTOFMEMORY; }
        }
        break;
    case VT_CLSID:
        if (src->puuid && !(dst->puuid = dup_block(src->puuid, sizeof(CLSID)))) { dst->vt = VT_EMPTY; return E_OUTOFMEMORY; }
        break;
    case VT_CF:
        if (src->pclipdata) {
            CLIPDATA *d = dup_block(src->pclipdata, sizeof(CLIPDATA));
            if (!d) { dst->vt = VT_EMPTY; return E_OUTOFMEMORY; }
            d->pClipData = 0;
            if (src->pclipdata->pClipData && src->pclipdata->cbSize >= sizeof(LONG) &&
                !(d->pClipData = dup_block(src->pclipdata->pClipData, src->pclipdata->cbSize - sizeof(LONG)))) {
                CoTaskMemFree(d);
                dst->vt = VT_EMPTY;
                return E_OUTOFMEMORY;
            }
            dst->pclipdata = d;
        }
        break;
    case VT_UNKNOWN: if (src->punkVal) IUnknown_AddRef(src->punkVal); break;
    case VT_DISPATCH: if (src->pdispVal) IDispatch_AddRef(src->pdispVal); break;
    case VT_STREAM: case VT_STREAMED_OBJECT: if (src->pStream) IUnknown_AddRef((IUnknown *)src->pStream); break;
    case VT_STORAGE: case VT_STORED_OBJECT: if (src->pStorage) IUnknown_AddRef((IUnknown *)src->pStorage); break;
    case VT_VERSIONED_STREAM:
        if (src->pVersionedStream) {
            VERSIONEDSTREAM *d = dup_block(src->pVersionedStream, sizeof(VERSIONEDSTREAM));
            if (!d) { dst->vt = VT_EMPTY; return E_OUTOFMEMORY; }
            if (d->pStream) IUnknown_AddRef((IUnknown *)d->pStream);
            dst->pVersionedStream = d;
        }
        break;
    }
    return S_OK;
}

DLLAPI HRESULT WINAPI FreePropVariantArray(ULONG n, PROPVARIANT *v)
{
    ULONG i;
    HRESULT hr = S_OK;
    if (!v) return E_INVALIDARG;
    for (i = 0; i < n; ++i)
        if (FAILED(PropVariantClear(&v[i]))) hr = STG_E_INVALIDPARAMETER;
    return hr;
}
