/* SPDX-License-Identifier: GPL-2.0-only
 * rpcrt4.dll UUID functions. Expected values: RFC 4122 (namespace UUIDs of appendix C, version/variant bits, text
 * format), MSDN UuidCompare/UuidFromString/UuidToString documentation. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <rpc.h>
#include "u_check.h"

static int has_rdrand(void)
{
    unsigned a = 1, b = 0, c = 0, d = 0;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
    return (c >> 30) & 1;
}

static int popcount32(unsigned long v) { int n = 0; while (v) { n += (int)(v & 1); v >>= 1; } return n; }
static int popcount_uuid(const UUID *u)
{
    int i, n = popcount32(u->Data1) + popcount32(u->Data2) + popcount32(u->Data3);
    for (i = 0; i < 8; ++i) n += popcount32(u->Data4[i]);
    return n;
}

int main(void)
{
    /* RFC 4122 appendix C: name space for DNS */
    UUID dns = { 0x6ba7b810, 0x9dad, 0x11d1, { 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8 } };
    UUID url = { 0x6ba7b811, 0x9dad, 0x11d1, { 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8 } };
    UUID u, v, nil;
    RPC_STATUS rs, st;
    RPC_WSTR w = 0;
    RPC_CSTR a = 0;
    unsigned short buf[64];
    int i, j;

    /* ---- text conversion ---- */
    rs = UuidToStringW(&dns, &w);
    U_CHECKF("UuidToStringW returns RPC_S_OK", rs == RPC_S_OK && w, "rs=%u", (unsigned)rs);
    U_CHECK("UuidToStringW gives the RFC 4122 lower-case text 6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            w && u_ascii_eq_w(w, "6ba7b810-9dad-11d1-80b4-00c04fd430c8"));
    rs = RpcStringFreeW(&w);
    U_CHECK("RpcStringFreeW frees and NULLs the pointer", rs == RPC_S_OK && w == 0);
    rs = UuidToStringA(&url, &a);
    U_CHECK("UuidToStringA of the URL namespace UUID", rs == RPC_S_OK && a && !strcmp((char *)a, "6ba7b811-9dad-11d1-80b4-00c04fd430c8"));
    RpcStringFreeA(&a);
    U_CHECK("RpcStringFreeA NULLs the pointer", a == 0);

    memset(&u, 0xcc, sizeof u);
    rs = UuidFromStringW(u_wide("6BA7B810-9DAD-11D1-80B4-00C04FD430C8", buf, 64), &u);
    U_CHECK("UuidFromStringW accepts upper-case hex", rs == RPC_S_OK && !memcmp(&u, &dns, sizeof u));
    rs = UuidFromStringW(u_wide("6ba7b811-9dad-11d1-80b4-00c04fd430c8", buf, 64), &u);
    U_CHECK("UuidFromStringW parses lower-case hex", rs == RPC_S_OK && !memcmp(&u, &url, sizeof u));
    rs = UuidFromStringW(u_wide("ffffffff-ffff-ffff-ffff-ffffffffffff", buf, 64), &u);
    U_CHECK("UuidFromStringW all-ones", rs == RPC_S_OK && u.Data1 == 0xffffffffu && u.Data2 == 0xffff && u.Data3 == 0xffff && u.Data4[7] == 0xff);
    rs = UuidFromStringA((RPC_CSTR)"00010203-0405-0607-0809-0a0b0c0d0e0f", &u);
    U_CHECK("UuidFromStringA field layout (Data1 big-endian text, Data4 bytes in order)",
            rs == RPC_S_OK && u.Data1 == 0x00010203u && u.Data2 == 0x0405 && u.Data3 == 0x0607 && u.Data4[0] == 0x08 && u.Data4[1] == 0x09 &&
            u.Data4[2] == 0x0a && u.Data4[7] == 0x0f);
    rs = UuidFromStringW(0, &u);
    U_CHECK("UuidFromStringW(NULL) yields the nil UUID", rs == RPC_S_OK && u.Data1 == 0 && u.Data2 == 0 && u.Data3 == 0 && u.Data4[0] == 0 && u.Data4[7] == 0);

    {
        static const char *bad[] = {
            "{6ba7b810-9dad-11d1-80b4-00c04fd430c8}",      /* braces are not part of the UuidString format */
            "6ba7b810-9dad-11d1-80b4-00c04fd430c",         /* one digit short */
            "6ba7b810-9dad-11d1-80b4-00c04fd430c88",       /* one digit long */
            "6ba7b810-9dad-11d1-80b4-00c04fd430cg",        /* not a hex digit */
            "6ba7b8109dad-11d1-80b4-00c04fd430c8x",        /* dash missing */
            "6ba7b810-9dad-11d1-80b400c04fd430c8-",        /* dash misplaced */
            "",
        };
        for (i = 0; i < (int)(sizeof bad / sizeof bad[0]); ++i) {
            char nm[128];
            snprintf(nm, sizeof nm, "UuidFromStringW rejects malformed string #%d with RPC_S_INVALID_STRING_UUID", i);
            rs = UuidFromStringW(u_wide(bad[i], buf, 64), &u);
            U_CHECKF(nm, rs == RPC_S_INVALID_STRING_UUID, "rs=%u", (unsigned)rs);
        }
    }

    /* ---- nil / compare / equal ---- */
    memset(&nil, 0x55, sizeof nil);
    rs = UuidCreateNil(&nil);
    U_CHECK("UuidCreateNil zeroes the UUID", rs == RPC_S_OK && UuidIsNil(&nil, &st) == 1 && st == RPC_S_OK);
    U_CHECK("UuidIsNil(NULL) is TRUE", UuidIsNil(0, &st) == 1);
    U_CHECK("UuidIsNil(non-nil) is FALSE", UuidIsNil(&dns, &st) == 0 && st == RPC_S_OK);
    U_CHECK("UuidCompare equal UUIDs = 0", (st = 99, UuidCompare(&dns, &dns, &st) == 0) && st == RPC_S_OK);
    U_CHECK("UuidCompare orders by Data1 first (dns < url)", UuidCompare(&dns, &url, &st) == -1 && UuidCompare(&url, &dns, &st) == 1);
    u = dns; v = dns; v.Data2 = 0x9dae;
    U_CHECK("UuidCompare orders by Data2 next", UuidCompare(&u, &v, &st) == -1 && UuidCompare(&v, &u, &st) == 1);
    v = dns; v.Data3 = 0x11d0;
    U_CHECK("UuidCompare orders by Data3 next (unsigned)", UuidCompare(&u, &v, &st) == 1);
    v = dns; v.Data4[7] = 0xc9;
    U_CHECK("UuidCompare orders by Data4 bytes last, unsigned", UuidCompare(&u, &v, &st) == -1);
    v = dns; v.Data4[0] = 0x00;
    U_CHECK("UuidCompare Data4[0] 0x80 vs 0x00 is unsigned (0x80 is greater)", UuidCompare(&u, &v, &st) == 1);
    u = dns; u.Data1 = 0x80000000u; v = dns; v.Data1 = 0x7fffffffu;
    U_CHECK("UuidCompare treats Data1 as unsigned", UuidCompare(&u, &v, &st) == 1);
    U_CHECK("UuidCompare(NULL, nil) = 0 and (NULL, dns) = -1", UuidCompare(0, &nil, &st) == 0 && UuidCompare(0, &dns, &st) == -1);
    U_CHECK("UuidEqual true/false", UuidEqual(&dns, &dns, &st) == 1 && UuidEqual(&dns, &url, &st) == 0 && st == RPC_S_OK);

    /* ---- UuidCreate ---- */
    if (!has_rdrand()) {
        rs = UuidCreate(&u);
        U_CHECKF("no RDRAND on this CPU: UuidCreate refuses instead of faking randomness", rs != RPC_S_OK, "rs=%u", (unsigned)rs);
    } else {
        UUID set[64];
        int distinct = 1, bits = 0, ver_ok = 1, var_ok = 1;
        for (i = 0; i < 64; ++i) {
            rs = UuidCreate(&set[i]);
            if (rs != RPC_S_OK) { U_CHECKF("UuidCreate returns RPC_S_OK", 0, "rs=%u at %d", (unsigned)rs, i); break; }
            if ((set[i].Data3 >> 12) != 4) ver_ok = 0;
            if ((set[i].Data4[0] >> 6) != 2) var_ok = 0;
            bits += popcount_uuid(&set[i]);
        }
        U_CHECK("UuidCreate returned RPC_S_OK 64 times", i == 64);
        U_CHECK("UuidCreate sets version 4 (Data3 high nibble) on all 64", ver_ok);
        U_CHECK("UuidCreate sets the RFC 4122 variant (Data4[0] top bits 10) on all 64", var_ok);
        for (i = 0; i < 64; ++i)
            for (j = i + 1; j < 64; ++j)
                if (!memcmp(&set[i], &set[j], sizeof(UUID))) distinct = 0;
        U_CHECK("64 UuidCreate results are pairwise distinct", distinct);
        /* 64 UUIDs carry 64*122 random bits (mean 3904 set, sd 44) plus a fixed 64*(1+1... ) pattern of version/variant
         * bits: version 0100 adds 1 set bit, variant 10 adds 1 -> 128 fixed set bits. Accept mean +/- 8 sd. */
        U_CHECKF("set-bit count of 64 UUIDs is statistically plausible for random data", bits > 3904 + 128 - 360 && bits < 3904 + 128 + 360, "bits=%d", bits);
        rs = UuidToStringW(&set[0], &w);
        U_CHECK("UuidCreate output has '4' as the 15th text digit and [89ab] as the 20th",
                rs == RPC_S_OK && w && w[14] == '4' && (w[19] == '8' || w[19] == '9' || w[19] == 'a' || w[19] == 'b'));
        rs = UuidFromStringW(w, &u);
        U_CHECK("text round trip of a created UUID", rs == RPC_S_OK && !memcmp(&u, &set[0], sizeof u));
        RpcStringFreeW(&w);
    }
    U_CHECK("UuidCreate(NULL) is rejected", UuidCreate(0) != RPC_S_OK);
    return u_finish("t_u_rpcrt4");
}
