/* SPDX-License-Identifier: GPL-2.0-only
 * BSTR: a pointer to UTF-16 data preceded by a 4-byte length in *bytes*, followed by a terminating NUL that is not
 * counted. Embedded NULs are allowed. Memory comes from the process heap; a BSTR is owned by whoever received it and
 * released with SysFreeString. NULL is a valid "empty" BSTR everywhere.
 */
#include "oleaut_int.h"

BSTR shz_bstr_alloc_bytes(const void *src, UINT bytes)
{
    unsigned char *p;
    if (bytes > 0x7ffffff0u) return 0;
    p = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)bytes + 4 + 2);
    if (!p) return 0;
    *(ULONG *)p = bytes;
    if (src) memcpy(p + 4, src, bytes);
    else memset(p + 4, 0, bytes);                                 /* documented as uninitialised; zero is a valid choice */
    p[4 + bytes] = 0;                                             /* terminating wide NUL (two bytes, alignment-agnostic) */
    p[4 + bytes + 1] = 0;
    return (BSTR)(p + 4);
}

static size_t wlen(const OLECHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }

DLLAPI BSTR WINAPI SysAllocString(const OLECHAR *psz)
{
    if (!psz) return 0;
    return shz_bstr_alloc_bytes(psz, (UINT)(wlen(psz) * sizeof(OLECHAR)));
}

DLLAPI BSTR WINAPI SysAllocStringLen(const OLECHAR *psz, UINT len)
{
    if (len > 0x3ffffff0u) return 0;
    return shz_bstr_alloc_bytes(psz, len * (UINT)sizeof(OLECHAR));
}

DLLAPI BSTR WINAPI SysAllocStringByteLen(LPCSTR psz, UINT len)
{
    return shz_bstr_alloc_bytes(psz, len);                        /* len bytes, not converted, plus the wide NUL */
}

DLLAPI void WINAPI SysFreeString(BSTR bstr)
{
    if (bstr) HeapFree(GetProcessHeap(), 0, (unsigned char *)bstr - 4);
}

DLLAPI UINT WINAPI SysStringLen(BSTR bstr) { return bstr ? *(ULONG *)((unsigned char *)bstr - 4) / sizeof(OLECHAR) : 0; }
DLLAPI UINT WINAPI SysStringByteLen(BSTR bstr) { return bstr ? *(ULONG *)((unsigned char *)bstr - 4) : 0; }

DLLAPI INT WINAPI SysReAllocStringLen(BSTR *pbstr, const OLECHAR *psz, UINT len)
{
    BSTR n;
    if (!pbstr) return FALSE;
    if (len > 0x3ffffff0u) return FALSE;
    n = shz_bstr_alloc_bytes(psz, len * (UINT)sizeof(OLECHAR));   /* psz may point into the old string: allocate first */
    if (!n) return FALSE;
    if (!psz && *pbstr) {                                         /* documented as keeping the old text when psz is NULL */
        UINT keep = SysStringByteLen(*pbstr), want = len * (UINT)sizeof(OLECHAR);
        memcpy(n, *pbstr, keep < want ? keep : want);
    }
    SysFreeString(*pbstr);
    *pbstr = n;
    return TRUE;
}

DLLAPI INT WINAPI SysReAllocString(BSTR *pbstr, const OLECHAR *psz)
{
    if (!pbstr || !psz) return FALSE;
    return SysReAllocStringLen(pbstr, psz, (UINT)wlen(psz));
}

DLLAPI HRESULT WINAPI VarBstrCat(BSTR left, BSTR right, BSTR *out)
{
    UINT ll = SysStringByteLen(left), rl = SysStringByteLen(right);
    BSTR r;
    if (!out) return E_POINTER;
    if ((ULONGLONG)ll + rl > 0x7ffffff0u) return E_OUTOFMEMORY;
    r = shz_bstr_alloc_bytes(0, ll + rl);
    if (!r) return E_OUTOFMEMORY;
    if (ll) memcpy(r, left, ll);
    if (rl) memcpy((unsigned char *)r + ll, right, rl);
    *out = r;
    return S_OK;
}
