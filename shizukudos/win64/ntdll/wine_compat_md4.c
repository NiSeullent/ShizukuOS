/* SPDX-License-Identifier: GPL-2.0-only
 * ntdll.dll: MD4Init / MD4Update / MD4Final, the MD4 message digest (RFC 1320) that Windows' ntdll exports and that the
 * CryptoAPI helpers ported from Wine (cryptsp: SystemFunction007, the NT password hash) call.
 * Context layout of the Windows export: { ULONG buf[4]; ULONG i[2]; UCHAR in[64]; UCHAR digest[16]; } where buf is the
 * chaining state, i the message length in bits (low, high), in the pending block and digest the result of MD4Final.
 * Written from RFC 1320; this file is Shizuku-original code (not derived from Wine).
 */
#include "../include/nt.h"

typedef struct {
    ULONG buf[4];
    ULONG i[2];
    UCHAR in[64];
    UCHAR digest[16];
} SHZ_MD4_CTX;

static ULONG rol(ULONG x, unsigned n) { return (x << n) | (x >> (32 - n)); }

static void md4_block(ULONG s[4], const UCHAR *p)
{
    static const unsigned r1[4] = { 3, 7, 11, 19 }, r2[4] = { 3, 5, 9, 13 }, r3[4] = { 3, 9, 11, 15 };
    static const unsigned o3[16] = { 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 };
    ULONG x[16], a = s[0], b = s[1], c = s[2], d = s[3], t;
    unsigned k;
    for (k = 0; k < 16; ++k) x[k] = (ULONG)p[4 * k] | (ULONG)p[4 * k + 1] << 8 | (ULONG)p[4 * k + 2] << 16 | (ULONG)p[4 * k + 3] << 24;
    for (k = 0; k < 16; ++k) {                                   /* round 1: F(x,y,z) = xy | ~x z */
        t = rol(a + ((b & c) | (~b & d)) + x[k], r1[k & 3]);
        a = d; d = c; c = b; b = t;
    }
    for (k = 0; k < 16; ++k) {                                   /* round 2: G = majority, words in column order */
        t = rol(a + ((b & c) | (b & d) | (c & d)) + x[(k & 3) * 4 + (k >> 2)] + 0x5a827999u, r2[k & 3]);
        a = d; d = c; c = b; b = t;
    }
    for (k = 0; k < 16; ++k) {                                   /* round 3: H = parity, bit-reversed word order */
        t = rol(a + (b ^ c ^ d) + x[o3[k]] + 0x6ed9eba1u, r3[k & 3]);
        a = d; d = c; c = b; b = t;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d;
}

VOID NTAPI MD4Init(SHZ_MD4_CTX *ctx)
{
    ctx->buf[0] = 0x67452301u;
    ctx->buf[1] = 0xefcdab89u;
    ctx->buf[2] = 0x98badcfeu;
    ctx->buf[3] = 0x10325476u;
    ctx->i[0] = ctx->i[1] = 0;
}

VOID NTAPI MD4Update(SHZ_MD4_CTX *ctx, const UCHAR *data, UINT len)
{
    ULONG have = (ctx->i[0] >> 3) & 63;
    ULONG lo = ctx->i[0] + ((ULONG)len << 3);
    if (lo < ctx->i[0]) ctx->i[1]++;
    ctx->i[1] += (ULONG)len >> 29;
    ctx->i[0] = lo;
    while (len) {
        ULONG take = 64 - have < len ? 64 - have : len, k;
        for (k = 0; k < take; ++k) ctx->in[have + k] = data[k];
        have += take; data += take; len -= take;
        if (have == 64) { md4_block(ctx->buf, ctx->in); have = 0; }
    }
}

VOID NTAPI MD4Final(SHZ_MD4_CTX *ctx)
{
    UCHAR pad[72], bits[8];
    ULONG have = (ctx->i[0] >> 3) & 63, padlen = have < 56 ? 56 - have : 120 - have, k;
    for (k = 0; k < 4; ++k) { bits[k] = (UCHAR)(ctx->i[0] >> (8 * k)); bits[4 + k] = (UCHAR)(ctx->i[1] >> (8 * k)); }
    pad[0] = 0x80;
    for (k = 1; k < padlen; ++k) pad[k] = 0;
    MD4Update(ctx, pad, padlen);
    MD4Update(ctx, bits, 8);
    for (k = 0; k < 16; ++k) ctx->digest[k] = (UCHAR)(ctx->buf[k >> 2] >> (8 * (k & 3)));
}
