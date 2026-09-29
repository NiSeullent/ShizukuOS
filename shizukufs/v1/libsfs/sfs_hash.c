/* SPDX-License-Identifier: GPL-2.0-only
 * Directory-index (htree) name hashes of the ext3/ext4 format: legacy, half-MD4 and TEA, each in the signed-char and
 * unsigned-char variants, seeded by s_hash_seed. The result has bit 0 clear (it marks hash collisions in the index)
 * and never equals the end-of-directory marker 0xFFFFFFFE. SipHash (casefolded directories) is not provided:
 * those volumes mount read-only.
 */
#include "sfs_internal.h"

static uint32_t rol32(uint32_t v, unsigned s) { return (v << s) | (v >> (32 - s)); }

static void tea_transform(uint32_t buf[4], const uint32_t in[4])
{
    uint32_t sum = 0, b0 = buf[0], b1 = buf[1], a = in[0], b = in[1], c = in[2], d = in[3];
    int n = 16;
    do {
        sum += 0x9E3779B9u;
        b0 += ((b1 << 4) + a) ^ (b1 + sum) ^ ((b1 >> 5) + b);
        b1 += ((b0 << 4) + c) ^ (b0 + sum) ^ ((b0 >> 5) + d);
    } while (--n);
    buf[0] += b0;
    buf[1] += b1;
}

#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z) (((x) & (y)) + (((x) ^ (y)) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define ROUND(f, a, b, c, d, x, s) (a += f(b, c, d) + (x), a = rol32(a, s))
#define K1 0u
#define K2 013240474631u
#define K3 015666365641u

static void half_md4_transform(uint32_t buf[4], const uint32_t in[8])
{
    uint32_t a = buf[0], b = buf[1], c = buf[2], d = buf[3];
    ROUND(F, a, b, c, d, in[0] + K1, 3);
    ROUND(F, d, a, b, c, in[1] + K1, 7);
    ROUND(F, c, d, a, b, in[2] + K1, 11);
    ROUND(F, b, c, d, a, in[3] + K1, 19);
    ROUND(F, a, b, c, d, in[4] + K1, 3);
    ROUND(F, d, a, b, c, in[5] + K1, 7);
    ROUND(F, c, d, a, b, in[6] + K1, 11);
    ROUND(F, b, c, d, a, in[7] + K1, 19);
    ROUND(G, a, b, c, d, in[1] + K2, 3);
    ROUND(G, d, a, b, c, in[3] + K2, 5);
    ROUND(G, c, d, a, b, in[5] + K2, 9);
    ROUND(G, b, c, d, a, in[7] + K2, 13);
    ROUND(G, a, b, c, d, in[0] + K2, 3);
    ROUND(G, d, a, b, c, in[2] + K2, 5);
    ROUND(G, c, d, a, b, in[4] + K2, 9);
    ROUND(G, b, c, d, a, in[6] + K2, 13);
    ROUND(H, a, b, c, d, in[3] + K3, 3);
    ROUND(H, d, a, b, c, in[7] + K3, 9);
    ROUND(H, c, d, a, b, in[2] + K3, 11);
    ROUND(H, b, c, d, a, in[6] + K3, 15);
    ROUND(H, a, b, c, d, in[1] + K3, 3);
    ROUND(H, d, a, b, c, in[5] + K3, 9);
    ROUND(H, c, d, a, b, in[0] + K3, 11);
    ROUND(H, b, c, d, a, in[4] + K3, 15);
    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}

static uint32_t legacy_hash(const char *name, size_t len, int is_unsigned)
{
    uint32_t hash, hash0 = 0x12A3FE2Du, hash1 = 0x37ABE8F9u;
    size_t i;
    for (i = 0; i < len; ++i) {
        int c = is_unsigned ? (int)(unsigned char)name[i] : (int)(signed char)name[i];
        hash = hash1 + (hash0 ^ ((uint32_t)c * 7152373u));
        if (hash & 0x80000000u) hash -= 0x7FFFFFFFu;
        hash1 = hash0;
        hash0 = hash;
    }
    return hash0 << 1;
}

/* Packs up to num*4 bytes of the name into num words, padded with the length pattern. */
static void str2hashbuf(const char *msg, size_t len, uint32_t *buf, int num, int is_unsigned)
{
    uint32_t pad = (uint32_t)len | ((uint32_t)len << 8), val;
    size_t i;
    pad |= pad << 16;
    val = pad;
    if (len > (size_t)num * 4) len = (size_t)num * 4;
    for (i = 0; i < len; ++i) {
        int c = is_unsigned ? (int)(unsigned char)msg[i] : (int)(signed char)msg[i];
        val = (uint32_t)c + (val << 8);
        if ((i % 4) == 3) {
            *buf++ = val;
            val = pad;
            num--;
        }
    }
    if (--num >= 0) *buf++ = val;
    while (--num >= 0) *buf++ = pad;
}

int sfs_dx_hash(const uint32_t seed[4], uint8_t version, const char *name, size_t len, uint32_t *hash_out, uint32_t *minor_out)
{
    uint32_t buf[4] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u}, in[8], hash = 0, minor = 0;
    int is_unsigned = 0;
    const char *p = name;
    long rem = (long)len;
    if (seed && (seed[0] | seed[1] | seed[2] | seed[3])) { buf[0] = seed[0]; buf[1] = seed[1]; buf[2] = seed[2]; buf[3] = seed[3]; }
    switch (version) {
    case DX_HASH_LEGACY_UNSIGNED:
        is_unsigned = 1;
        /* fall through */
    case DX_HASH_LEGACY:
        hash = legacy_hash(name, len, is_unsigned);
        break;
    case DX_HASH_HALF_MD4_UNSIGNED:
        is_unsigned = 1;
        /* fall through */
    case DX_HASH_HALF_MD4:
        while (rem > 0) {
            str2hashbuf(p, (size_t)rem, in, 8, is_unsigned);
            half_md4_transform(buf, in);
            rem -= 32;
            p += 32;
        }
        minor = buf[2];
        hash = buf[1];
        break;
    case DX_HASH_TEA_UNSIGNED:
        is_unsigned = 1;
        /* fall through */
    case DX_HASH_TEA:
        while (rem > 0) {
            str2hashbuf(p, (size_t)rem, in, 4, is_unsigned);
            tea_transform(buf, in);
            rem -= 16;
            p += 16;
        }
        hash = buf[0];
        minor = buf[1];
        break;
    default:
        return SFS_ENOTSUP;
    }
    hash &= ~1u;
    if (hash == (0x7FFFFFFFu << 1)) hash = (0x7FFFFFFFu - 1) << 1;
    *hash_out = hash;
    if (minor_out) *minor_out = minor;
    return 0;
}
