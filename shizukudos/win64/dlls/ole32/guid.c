/* SPDX-License-Identifier: GPL-2.0-only
 * GUID text conversion and creation.
 *
 * Text form: "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}", 38 characters, upper-case hex on output, either case on input.
 * CLSIDFromString: a NULL string yields CLSID_NULL; a string that starts with '{' must be exactly that form
 * (CO_E_CLASSSTRING otherwise); a string that does not start with '{' is a ProgID, which needs the registry: there is no
 * registry here, so it fails with CO_E_CLASSSTRING (what a ProgID that is not registered gets). IIDFromString accepts
 * only the braced form (CO_E_IIDSTRING otherwise) and maps NULL to IID_NULL.
 * CoCreateGuid is UuidCreate (RFC 4122 version 4, bits from the kernel RNG).
 */
#include "ole32_int.h"

static void guid_to_text(const GUID *g, WCHAR out[39])
{
    static const char hex[] = "0123456789ABCDEF";
    unsigned char b[16];
    int i, o = 0;
    b[0] = (unsigned char)(g->Data1 >> 24); b[1] = (unsigned char)(g->Data1 >> 16); b[2] = (unsigned char)(g->Data1 >> 8); b[3] = (unsigned char)g->Data1;
    b[4] = (unsigned char)(g->Data2 >> 8); b[5] = (unsigned char)g->Data2;
    b[6] = (unsigned char)(g->Data3 >> 8); b[7] = (unsigned char)g->Data3;
    memcpy(b + 8, g->Data4, 8);
    out[o++] = '{';
    for (i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out[o++] = '-';
        out[o++] = (WCHAR)hex[b[i] >> 4];
        out[o++] = (WCHAR)hex[b[i] & 15];
    }
    out[o++] = '}';
    out[o] = 0;
}

static int hexv(WCHAR c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* exactly {8-4-4-4-12} */
static int text_to_guid(const WCHAR *s, GUID *g)
{
    static const unsigned char pos[16] = { 1, 3, 5, 7, 10, 12, 15, 17, 20, 22, 25, 27, 29, 31, 33, 35 };
    unsigned char b[16];
    int i;
    for (i = 0; i < 38; ++i)
        if (!s[i]) return 0;
    if (s[38] || s[0] != '{' || s[9] != '-' || s[14] != '-' || s[19] != '-' || s[24] != '-' || s[37] != '}') return 0;
    for (i = 0; i < 16; ++i) {
        int hi = hexv(s[pos[i]]), lo = hexv(s[pos[i] + 1]);
        if (hi < 0 || lo < 0) return 0;
        b[i] = (unsigned char)(hi << 4 | lo);
    }
    g->Data1 = (unsigned long)b[0] << 24 | (unsigned long)b[1] << 16 | (unsigned long)b[2] << 8 | b[3];
    g->Data2 = (unsigned short)(b[4] << 8 | b[5]);
    g->Data3 = (unsigned short)(b[6] << 8 | b[7]);
    memcpy(g->Data4, b + 8, 8);
    return 1;
}

DLLAPI int WINAPI StringFromGUID2(REFGUID g, LPOLESTR out, int cch)
{
    if (!g || !out || cch < 39) return 0;
    guid_to_text(g, out);
    return 39;
}

static HRESULT alloc_text(REFGUID g, LPOLESTR *out)
{
    WCHAR *p;
    if (!out) return E_POINTER;
    *out = 0;
    if (!g) return E_INVALIDARG;
    p = CoTaskMemAlloc(39 * sizeof(WCHAR));
    if (!p) return E_OUTOFMEMORY;
    guid_to_text(g, p);
    *out = p;
    return S_OK;
}

DLLAPI HRESULT WINAPI StringFromCLSID(REFCLSID rclsid, LPOLESTR *out) { return alloc_text(rclsid, out); }
DLLAPI HRESULT WINAPI StringFromIID(REFIID riid, LPOLESTR *out) { return alloc_text(riid, out); }

DLLAPI HRESULT WINAPI CLSIDFromString(LPCOLESTR s, LPCLSID out)
{
    if (!out) return E_INVALIDARG;
    if (!s) { memset(out, 0, sizeof *out); return S_OK; }
    if (!text_to_guid(s, out)) { memset(out, 0, sizeof *out); return CO_E_CLASSSTRING; }
    return S_OK;
}

DLLAPI HRESULT WINAPI IIDFromString(LPCOLESTR s, LPIID out)
{
    if (!out) return E_INVALIDARG;
    if (!s) { memset(out, 0, sizeof *out); return S_OK; }
    if (!text_to_guid(s, out)) { memset(out, 0, sizeof *out); return CO_E_IIDSTRING; }
    return S_OK;
}

DLLAPI HRESULT WINAPI CoCreateGuid(GUID *g)
{
    RPC_STATUS st;
    if (!g) return E_INVALIDARG;
    st = UuidCreate(g);
    if (st == RPC_S_OK || st == RPC_S_UUID_LOCAL_ONLY) return S_OK;
    memset(g, 0, sizeof *g);
    return HRESULT_FROM_WIN32(st);
}
