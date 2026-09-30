/* SPDX-License-Identifier: GPL-2.0-only
 * tridentrt: small OLE functions the Shizuku ole32/oleaut32 do not have yet and that Wine's typelib/variant code or
 * the browser modules call: ReleaseStgMedium (ole32), BstrFromVector/VectorFromBstr (oleaut32, BSTR <-> VT_ARRAY|VT_UI1
 * conversion of VariantChangeType), GetActiveObject (the lookup of Wine's ITypeInfo::CreateInstance for appobject
 * classes) and the module handle Wine's vartype.c loads its "True"/"False"/... strings from (tridentrt.rc).
 */
#define COBJMACROS
#include "comrt.h"
#include "wingdi.h"

extern IMAGE_DOS_HEADER __ImageBase;
HMODULE hProxyDll = (HMODULE)&__ImageBase;                  /* vartype.c: VARIANT_GetLocalisedText */

/* Documented behaviour: the medium's storage is freed unless pUnkForRelease is set, in which case only that object
 * is released; the medium is left TYMED_NULL. */
void WINAPI ReleaseStgMedium(STGMEDIUM *medium)
{
    if (!medium) return;
    switch (medium->tymed)
    {
    case TYMED_HGLOBAL:
        if (!medium->pUnkForRelease && medium->hGlobal) GlobalFree(medium->hGlobal);
        break;
    case TYMED_FILE:
        if (medium->lpszFileName)
        {
            if (!medium->pUnkForRelease) DeleteFileW(medium->lpszFileName);
            CoTaskMemFree(medium->lpszFileName);
        }
        break;
    case TYMED_ISTREAM:
        if (medium->pstm) IStream_Release(medium->pstm);
        break;
    case TYMED_ISTORAGE:
        if (medium->pstg) IStorage_Release(medium->pstg);
        break;
    case TYMED_GDI:
        if (!medium->pUnkForRelease && medium->hBitmap) DeleteObject(medium->hBitmap);
        break;
    case TYMED_MFPICT:
        if (!medium->pUnkForRelease && medium->hMetaFilePict)
        {
            METAFILEPICT *mf = GlobalLock(medium->hMetaFilePict);
            if (mf) DeleteMetaFile(mf->hMF);
            GlobalUnlock(medium->hMetaFilePict);
            GlobalFree(medium->hMetaFilePict);
        }
        break;
    case TYMED_ENHMF:
        if (!medium->pUnkForRelease && medium->hEnhMetaFile) DeleteEnhMetaFile(medium->hEnhMetaFile);
        break;
    default:
        break;
    }
    medium->tymed = TYMED_NULL;
    if (medium->pUnkForRelease)
    {
        IUnknown_Release(medium->pUnkForRelease);
        medium->pUnkForRelease = NULL;
    }
}

/* the bytes of a one-dimensional array of 1-byte elements as a BSTR (SysAllocStringByteLen of the Shizuku oleaut32) */
HRESULT WINAPI BstrFromVector(SAFEARRAY *psa, BSTR *out)
{
    if (out) *out = NULL;
    if (!psa || !out) return E_INVALIDARG;
    if (psa->cbElements != 1 || psa->cDims != 1) return DISP_E_TYPEMISMATCH;
    if (!(*out = SysAllocStringByteLen(psa->pvData, psa->rgsabound[0].cElements))) return E_OUTOFMEMORY;
    return S_OK;
}

/* the bytes of a BSTR as a VT_UI1 vector (SafeArrayCreate of the Shizuku oleaut32) */
HRESULT WINAPI VectorFromBstr(BSTR bstr, SAFEARRAY **out)
{
    SAFEARRAYBOUND bound;
    if (!out) return E_INVALIDARG;
    *out = NULL;
    if (!bstr) return E_INVALIDARG;
    bound.lLbound = 0;
    bound.cElements = SysStringByteLen(bstr);
    if (!(*out = SafeArrayCreate(VT_UI1, 1, &bound))) return E_OUTOFMEMORY;
    memcpy((*out)->pvData, bstr, bound.cElements);
    return S_OK;
}

/* An active object is one registered with RegisterActiveObject, which this runtime does not provide, so none can
 * exist: MK_E_UNAVAILABLE is the documented answer. Only used inside tridentrt (Wine's typelib.c), not exported. */
HRESULT WINAPI GetActiveObject(REFCLSID clsid, void *reserved, IUnknown **unk)
{
    if (!unk) return E_INVALIDARG;
    *unk = NULL;
    return MK_E_UNAVAILABLE;
}
