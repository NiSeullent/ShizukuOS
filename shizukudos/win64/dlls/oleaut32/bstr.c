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

/* VarBstrCmp (ordinal 314): compares with CompareStringW under `lcid` and the NORM_* flags; a NULL BSTR is the empty
 * string. Result: VARCMP_LT / VARCMP_EQ / VARCMP_GT. */
DLLAPI HRESULT WINAPI VarBstrCmp(BSTR left, BSTR right, LCID lcid, ULONG flags)
{
    static const OLECHAR empty[1] = { 0 };
    const UINT ln = SysStringLen(left), rn = SysStringLen(right);
    int r;
    if (!ln && !rn) return VARCMP_EQ;
    r = CompareStringW(lcid, flags, left ? left : empty, (int)ln, right ? right : empty, (int)rn);
    if (!r) return E_INVALIDARG;                                  /* CompareStringW rejected lcid or flags */
    return r == CSTR_LESS_THAN ? VARCMP_LT : r == CSTR_EQUAL ? VARCMP_EQ : VARCMP_GT;
}

/* LoadRegTypeLib (ordinal 162): a type library is found through its registration, HKEY_CLASSES_ROOT\TypeLib\{GUID}\
 * <major>.<minor> (hexadecimal). This oleaut32 cannot load type libraries (it has no ITypeLib implementation), so a
 * registered library is reported as TYPE_E_CANTLOADLIBRARY, and one that is not registered - every library on this
 * system, whose registry holds no TypeLib registrations - as TYPE_E_LIBNOTREGISTERED, as Windows reports it. */
DLLAPI HRESULT WINAPI LoadRegTypeLib(REFGUID guid, WORD major, WORD minor, LCID lcid, ITypeLib **out)
{
    static const char hex[] = "0123456789abcdef";
    static const unsigned order[16] = { 3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15 };
    static const char prefix[] = "TypeLib\\{";
    WCHAR path[80];
    unsigned n = 0, i, v, d;
    HKEY k;
    const BYTE *g = (const BYTE *)guid;
    (void)lcid;
    if (!out) return E_INVALIDARG;
    *out = 0;
    if (!guid) return E_INVALIDARG;
    for (i = 0; prefix[i]; ++i) path[n++] = (WCHAR)prefix[i];
    for (i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) path[n++] = '-';
        path[n++] = (WCHAR)(hex[g[order[i]] >> 4] - (hex[g[order[i]] >> 4] >= 'a' ? 32 : 0));
        path[n++] = (WCHAR)(hex[g[order[i]] & 15] - (hex[g[order[i]] & 15] >= 'a' ? 32 : 0));
    }
    path[n++] = '}';
    path[n++] = '\\';
    for (v = major, d = 1; v / d >= 16; d *= 16) { }
    for (; d; d /= 16) path[n++] = (WCHAR)hex[v / d % 16];
    path[n++] = '.';
    for (v = minor, d = 1; v / d >= 16; d *= 16) { }
    for (; d; d /= 16) path[n++] = (WCHAR)hex[v / d % 16];
    path[n] = 0;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, path, 0, KEY_READ, &k) != ERROR_SUCCESS) return TYPE_E_LIBNOTREGISTERED;
    RegCloseKey(k);
    return TYPE_E_CANTLOADLIBRARY;
}
