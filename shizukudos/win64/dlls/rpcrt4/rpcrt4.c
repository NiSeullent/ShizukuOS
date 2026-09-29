/* SPDX-License-Identifier: GPL-2.0-only
 * rpcrt4.dll - the UUID half of the RPC runtime. There is no RPC transport in this system, so only the UUID
 * functions exist (creation, text conversion, comparison); nothing that would need an endpoint mapper, bindings or
 * marshaling is exported.
 *
 * UuidCreate returns a version-4 (random) UUID as RFC 4122 section 4.4 defines it: 122 random bits from the kernel RNG
 * (shz_rand.h -> NtShzRandom, a ChaCha20 CSPRNG over an entropy pool; RDRAND is one input when present), version
 * nibble 4, variant bits 10.
 *
 * UuidCreateSequential returns a version-1 (time based) UUID as RFC 4122 section 4.2 defines it: a 60-bit count of 100 ns
 * intervals since 1582-10-15 (from the system clock, forced strictly increasing within the process), a 14-bit clock
 * sequence and a 48-bit node. There is no network adapter, so the node is a random 47-bit value with the multicast bit
 * set (RFC 4122 section 4.5), chosen once per process, and the result is RPC_S_UUID_LOCAL_ONLY - what Windows documents for
 * a UUID that is not based on a real network address. UuidHash is not provided: its exact algorithm is undocumented.
 */
#include "nt.h"
#include "shz_rand.h"
#include <string.h>
#define _RPCRT4_
#include <rpc.h>

static const UUID uuid_nil;

static int is_hex(unsigned c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
static unsigned hexval(unsigned c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }

static void bytes_to_uuid(const unsigned char *b, UUID *u)
{
    u->Data1 = (unsigned long)b[0] << 24 | (unsigned long)b[1] << 16 | (unsigned long)b[2] << 8 | b[3];
    u->Data2 = (unsigned short)(b[4] << 8 | b[5]);
    u->Data3 = (unsigned short)(b[6] << 8 | b[7]);
    memcpy(u->Data4, b + 8, 8);
}

DLLAPI RPC_STATUS RPC_ENTRY UuidCreate(UUID *u)
{
    unsigned char b[16];
    if (!u) return ERROR_INVALID_PARAMETER;
    if (!shz_random_bytes(b, sizeof b)) return ERROR_NOT_SUPPORTED;
    b[6] = (unsigned char)((b[6] & 0x0f) | 0x40);           /* version 4 */
    b[8] = (unsigned char)((b[8] & 0x3f) | 0x80);           /* RFC 4122 variant */
    bytes_to_uuid(b, u);
    return RPC_S_OK;
}

/* ---- UuidCreateSequential (RFC 4122 version 1) ---- */
#define UUID_EPOCH_TO_FILETIME 5748192000000000ull          /* 1601-01-01 minus 1582-10-15, in 100 ns units */
static volatile LONG g_seq_lock;
static ULONGLONG g_seq_last;                                /* last timestamp handed out: strictly increasing */
static unsigned char g_seq_node[6];
static unsigned g_seq_clock;                                /* 14-bit clock sequence, fixed for the life of the process */
static int g_seq_ready;

DLLAPI RPC_STATUS RPC_ENTRY UuidCreateSequential(UUID *u)
{
    FILETIME ft;
    ULONGLONG t;
    unsigned char b[16];
    if (!u) return ERROR_INVALID_PARAMETER;
    while (InterlockedCompareExchange(&g_seq_lock, 1, 0)) SwitchToThread();
    if (!g_seq_ready) {
        unsigned char r[8];
        if (!shz_random_bytes(r, sizeof r)) { InterlockedExchange(&g_seq_lock, 0); return ERROR_NOT_SUPPORTED; }
        memcpy(g_seq_node, r, 6);
        g_seq_node[0] |= 1;                                 /* multicast bit: "not a real IEEE 802 address" (RFC 4122 4.5) */
        g_seq_clock = (unsigned)(r[6] << 8 | r[7]) & 0x3fff;
        g_seq_ready = 1;
    }
    GetSystemTimeAsFileTime(&ft);
    t = ((ULONGLONG)ft.dwHighDateTime << 32 | ft.dwLowDateTime) + UUID_EPOCH_TO_FILETIME;
    if (t <= g_seq_last) t = g_seq_last + 1;                /* the clock is coarse (or stepped back): never repeat a timestamp */
    g_seq_last = t;
    b[0] = (unsigned char)(t >> 24); b[1] = (unsigned char)(t >> 16); b[2] = (unsigned char)(t >> 8); b[3] = (unsigned char)t;      /* time_low */
    b[4] = (unsigned char)(t >> 40); b[5] = (unsigned char)(t >> 32);                                                                 /* time_mid */
    b[6] = (unsigned char)(0x10 | ((t >> 56) & 0x0f)); b[7] = (unsigned char)(t >> 48);                                               /* version 1 + time_hi */
    b[8] = (unsigned char)(0x80 | (g_seq_clock >> 8)); b[9] = (unsigned char)g_seq_clock;                                             /* variant + clock_seq */
    memcpy(b + 10, g_seq_node, 6);
    InterlockedExchange(&g_seq_lock, 0);
    bytes_to_uuid(b, u);
    return RPC_S_UUID_LOCAL_ONLY;
}

DLLAPI RPC_STATUS RPC_ENTRY UuidCreateNil(UUID *u)
{
    if (!u) return ERROR_INVALID_PARAMETER;
    memset(u, 0, sizeof *u);
    return RPC_S_OK;
}

DLLAPI int RPC_ENTRY UuidCompare(UUID *a, UUID *b, RPC_STATUS *status)
{
    int i;
    if (status) *status = RPC_S_OK;
    if (!a) a = (UUID *)&uuid_nil;
    if (!b) b = (UUID *)&uuid_nil;
    if (a->Data1 != b->Data1) return a->Data1 < b->Data1 ? -1 : 1;
    if (a->Data2 != b->Data2) return a->Data2 < b->Data2 ? -1 : 1;
    if (a->Data3 != b->Data3) return a->Data3 < b->Data3 ? -1 : 1;
    for (i = 0; i < 8; ++i)
        if (a->Data4[i] != b->Data4[i]) return a->Data4[i] < b->Data4[i] ? -1 : 1;
    return 0;
}

DLLAPI int RPC_ENTRY UuidEqual(UUID *a, UUID *b, RPC_STATUS *status) { return UuidCompare(a, b, status) == 0; }
DLLAPI int RPC_ENTRY UuidIsNil(UUID *u, RPC_STATUS *status) { return UuidCompare(u, (UUID *)&uuid_nil, status) == 0; }

/* Canonical text form: 8-4-4-4-12 lowercase hex digits, no braces (36 characters + NUL). */
static void format_uuid(const UUID *u, char out[37])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char b[16];
    int i, o = 0;
    b[0] = (unsigned char)(u->Data1 >> 24); b[1] = (unsigned char)(u->Data1 >> 16);
    b[2] = (unsigned char)(u->Data1 >> 8); b[3] = (unsigned char)u->Data1;
    b[4] = (unsigned char)(u->Data2 >> 8); b[5] = (unsigned char)u->Data2;
    b[6] = (unsigned char)(u->Data3 >> 8); b[7] = (unsigned char)u->Data3;
    memcpy(b + 8, u->Data4, 8);
    for (i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out[o++] = '-';
        out[o++] = hex[b[i] >> 4];
        out[o++] = hex[b[i] & 15];
    }
    out[o] = 0;
}

/* Parse exactly "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx": 36 units, case-insensitive hex, no braces. */
static int parse_uuid(const unsigned *s, size_t n, UUID *u)
{
    /* first hex digit of each byte: bytes 0-3 = chars 0-7, 4-5 = 9-12, 6-7 = 14-17, 8-9 = 19-22, 10-15 = 24-35 */
    static const unsigned char pos[16] = { 0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34 };
    unsigned char b[16];
    int i;
    if (n != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-') return 0;
    for (i = 0; i < 36; ++i)
        if (i != 8 && i != 13 && i != 18 && i != 23 && !is_hex(s[i])) return 0;
    for (i = 0; i < 16; ++i) b[i] = (unsigned char)(hexval(s[pos[i]]) << 4 | hexval(s[pos[i] + 1]));
    bytes_to_uuid(b, u);
    return 1;
}

DLLAPI RPC_STATUS RPC_ENTRY UuidToStringA(const UUID *u, RPC_CSTR *out)
{
    char tmp[37];
    char *p;
    if (!out) return ERROR_INVALID_PARAMETER;
    if (!u) u = &uuid_nil;
    format_uuid(u, tmp);
    p = HeapAlloc(GetProcessHeap(), 0, sizeof tmp);
    if (!p) return RPC_S_OUT_OF_MEMORY;
    memcpy(p, tmp, sizeof tmp);
    *out = (RPC_CSTR)p;
    return RPC_S_OK;
}

DLLAPI RPC_STATUS RPC_ENTRY UuidToStringW(const UUID *u, RPC_WSTR *out)
{
    char tmp[37];
    WCHAR *p;
    int i;
    if (!out) return ERROR_INVALID_PARAMETER;
    if (!u) u = &uuid_nil;
    format_uuid(u, tmp);
    p = HeapAlloc(GetProcessHeap(), 0, sizeof tmp * sizeof(WCHAR));
    if (!p) return RPC_S_OUT_OF_MEMORY;
    for (i = 0; i < 37; ++i) p[i] = (WCHAR)(unsigned char)tmp[i];
    *out = (RPC_WSTR)p;
    return RPC_S_OK;
}

DLLAPI RPC_STATUS RPC_ENTRY UuidFromStringA(RPC_CSTR s, UUID *u)
{
    unsigned wide[37];
    size_t n = 0;
    if (!u) return ERROR_INVALID_PARAMETER;
    if (!s) { memset(u, 0, sizeof *u); return RPC_S_OK; }           /* documented: NULL string = nil UUID */
    while (n < 37 && s[n]) { wide[n] = s[n]; ++n; }
    if (n != 36 || !parse_uuid(wide, n, u)) return RPC_S_INVALID_STRING_UUID;
    return RPC_S_OK;
}

DLLAPI RPC_STATUS RPC_ENTRY UuidFromStringW(RPC_WSTR s, UUID *u)
{
    unsigned wide[37];
    size_t n = 0;
    if (!u) return ERROR_INVALID_PARAMETER;
    if (!s) { memset(u, 0, sizeof *u); return RPC_S_OK; }
    while (n < 37 && s[n]) { wide[n] = s[n]; ++n; }
    if (n != 36 || !parse_uuid(wide, n, u)) return RPC_S_INVALID_STRING_UUID;
    return RPC_S_OK;
}

DLLAPI RPC_STATUS RPC_ENTRY RpcStringFreeA(RPC_CSTR *s)
{
    if (!s) return ERROR_INVALID_PARAMETER;
    if (*s) HeapFree(GetProcessHeap(), 0, *s);
    *s = 0;
    return RPC_S_OK;
}

DLLAPI RPC_STATUS RPC_ENTRY RpcStringFreeW(RPC_WSTR *s)
{
    if (!s) return ERROR_INVALID_PARAMETER;
    if (*s) HeapFree(GetProcessHeap(), 0, *s);
    *s = 0;
    return RPC_S_OK;
}
