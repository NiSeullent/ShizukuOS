/* SPDX-License-Identifier: GPL-2.0-only
 * MD5, SHA-1, SHA-256, SHA-384, SHA-512, HMAC and PBKDF2. Straight implementations of RFC 1321, FIPS 180-4, RFC 2104
 * and RFC 2898; correctness over speed. */
#include "hashes.h"
#include "hash_consts.h"

static void hcopy(void *d, const void *s, size_t n) { uint8_t *a = d; const uint8_t *b = s; while (n--) *a++ = *b++; }
static void hzero(void *d, size_t n) { uint8_t *a = d; while (n--) *a++ = 0; }

static inline uint32_t rol32(uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); }
static inline uint32_t ror32(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
static inline uint64_t ror64(uint64_t x, unsigned n) { return (x >> n) | (x << (64 - n)); }
static inline uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static inline uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static inline uint64_t be64(const uint8_t *p) { return (uint64_t)be32(p) << 32 | be32(p + 4); }
static inline void put_be32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static inline void put_be64(uint8_t *p, uint64_t v) { put_be32(p, (uint32_t)(v >> 32)); put_be32(p + 4, (uint32_t)v); }
static inline void put_le32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

/* ---------------------------------------------------------------- MD5 */
static void md5_block(uint32_t s[8], const uint8_t *p)
{
    static const uint8_t shifts[4][4] = { { 7, 12, 17, 22 }, { 5, 9, 14, 20 }, { 4, 11, 16, 23 }, { 6, 10, 15, 21 } };
    uint32_t m[16], a = s[0], b = s[1], c = s[2], d = s[3];
    unsigned i;
    for (i = 0; i < 16; ++i) m[i] = le32(p + 4 * i);
    for (i = 0; i < 64; ++i) {
        uint32_t f, t;
        unsigned g;
        switch (i >> 4) {
        case 0: f = (b & c) | (~b & d); g = i; break;
        case 1: f = (d & b) | (~d & c); g = (5 * i + 1) & 15; break;
        case 2: f = b ^ c ^ d; g = (3 * i + 5) & 15; break;
        default: f = c ^ (b | ~d); g = (7 * i) & 15; break;
        }
        t = d; d = c; c = b;
        b = b + rol32(a + f + md5_k[i] + m[g], shifts[i >> 4][i & 3]);
        a = t;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d;
}

/* ---------------------------------------------------------------- SHA-1 */
static void sha1_block(uint32_t s[8], const uint8_t *p)
{
    uint32_t w[80], a = s[0], b = s[1], c = s[2], d = s[3], e = s[4];
    unsigned i;
    for (i = 0; i < 16; ++i) w[i] = be32(p + 4 * i);
    for (; i < 80; ++i) w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    for (i = 0; i < 80; ++i) {
        uint32_t f, k, t;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999u; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcu; }
        else { f = b ^ c ^ d; k = 0xca62c1d6u; }
        t = rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = t;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e;
}

/* ---------------------------------------------------------------- SHA-256 */
static void sha256_block(uint32_t s[8], const uint8_t *p)
{
    uint32_t w[64], v[8];
    unsigned i;
    for (i = 0; i < 16; ++i) w[i] = be32(p + 4 * i);
    for (; i < 64; ++i) {
        uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    for (i = 0; i < 8; ++i) v[i] = s[i];
    for (i = 0; i < 64; ++i) {
        uint32_t S1 = ror32(v[4], 6) ^ ror32(v[4], 11) ^ ror32(v[4], 25);
        uint32_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
        uint32_t t1 = v[7] + S1 + ch + sha256_k[i] + w[i];
        uint32_t S0 = ror32(v[0], 2) ^ ror32(v[0], 13) ^ ror32(v[0], 22);
        uint32_t mj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        uint32_t t2 = S0 + mj;
        v[7] = v[6]; v[6] = v[5]; v[5] = v[4]; v[4] = v[3] + t1;
        v[3] = v[2]; v[2] = v[1]; v[1] = v[0]; v[0] = t1 + t2;
    }
    for (i = 0; i < 8; ++i) s[i] += v[i];
}

/* ---------------------------------------------------------------- SHA-512 / SHA-384 */
static void sha512_block(uint64_t s[8], const uint8_t *p)
{
    uint64_t w[80], v[8];
    unsigned i;
    for (i = 0; i < 16; ++i) w[i] = be64(p + 8 * i);
    for (; i < 80; ++i) {
        uint64_t s0 = ror64(w[i - 15], 1) ^ ror64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ror64(w[i - 2], 19) ^ ror64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    for (i = 0; i < 8; ++i) v[i] = s[i];
    for (i = 0; i < 80; ++i) {
        uint64_t S1 = ror64(v[4], 14) ^ ror64(v[4], 18) ^ ror64(v[4], 41);
        uint64_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
        uint64_t t1 = v[7] + S1 + ch + sha512_k[i] + w[i];
        uint64_t S0 = ror64(v[0], 28) ^ ror64(v[0], 34) ^ ror64(v[0], 39);
        uint64_t mj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        uint64_t t2 = S0 + mj;
        v[7] = v[6]; v[6] = v[5]; v[5] = v[4]; v[4] = v[3] + t1;
        v[3] = v[2]; v[2] = v[1]; v[1] = v[0]; v[0] = t1 + t2;
    }
    for (i = 0; i < 8; ++i) s[i] += v[i];
}

/* ---------------------------------------------------------------- common driver */
size_t shz_hash_digest_len(unsigned alg)
{
    switch (alg) {
    case SHZ_H_MD5: return 16;
    case SHZ_H_SHA1: return 20;
    case SHZ_H_SHA256: return 32;
    case SHZ_H_SHA384: return 48;
    case SHZ_H_SHA512: return 64;
    }
    return 0;
}

size_t shz_hash_block_len(unsigned alg) { return alg == SHZ_H_SHA384 || alg == SHZ_H_SHA512 ? 128 : 64; }

void shz_hash_init(shz_hash_ctx *c, unsigned alg)
{
    unsigned i;
    hzero(c, sizeof *c);
    c->alg = alg;
    switch (alg) {
    case SHZ_H_MD5: c->st.w[0] = 0x67452301u; c->st.w[1] = 0xefcdab89u; c->st.w[2] = 0x98badcfeu; c->st.w[3] = 0x10325476u; break;
    case SHZ_H_SHA1:
        c->st.w[0] = 0x67452301u; c->st.w[1] = 0xefcdab89u; c->st.w[2] = 0x98badcfeu; c->st.w[3] = 0x10325476u; c->st.w[4] = 0xc3d2e1f0u;
        break;
    case SHZ_H_SHA256: for (i = 0; i < 8; ++i) c->st.w[i] = sha256_h0[i]; break;
    case SHZ_H_SHA384: for (i = 0; i < 8; ++i) c->st.q[i] = sha384_h0[i]; break;
    case SHZ_H_SHA512: for (i = 0; i < 8; ++i) c->st.q[i] = sha512_h0[i]; break;
    }
}

static void compress(shz_hash_ctx *c, const uint8_t *p)
{
    switch (c->alg) {
    case SHZ_H_MD5: md5_block(c->st.w, p); break;
    case SHZ_H_SHA1: sha1_block(c->st.w, p); break;
    case SHZ_H_SHA256: sha256_block(c->st.w, p); break;
    default: sha512_block(c->st.q, p); break;
    }
}

void shz_hash_update(shz_hash_ctx *c, const void *data, size_t n)
{
    const uint8_t *p = data;
    const size_t bl = shz_hash_block_len(c->alg);
    c->len += n;
    if (c->bufn) {
        size_t take = bl - c->bufn;
        if (take > n) take = n;
        hcopy(c->buf + c->bufn, p, take);
        c->bufn += (unsigned)take; p += take; n -= take;
        if (c->bufn < bl) return;
        compress(c, c->buf);
        c->bufn = 0;
    }
    while (n >= bl) { compress(c, p); p += bl; n -= bl; }
    if (n) { hcopy(c->buf, p, n); c->bufn = (unsigned)n; }
}

void shz_hash_final(shz_hash_ctx *c, uint8_t *out)
{
    const size_t bl = shz_hash_block_len(c->alg), lenbytes = bl == 128 ? 16 : 8;
    const uint64_t bits_lo = c->len << 3, bits_hi = c->len >> 61;
    uint8_t pad[SHZ_H_MAX_BLOCK * 2];
    size_t padn = bl - c->bufn, dl = shz_hash_digest_len(c->alg), i;
    /* 0x80, zeros up to (block - lenbytes) mod block, then the message length in bits */
    if (padn < lenbytes + 1) padn += bl;
    hzero(pad, padn);
    pad[0] = 0x80;
    if (c->alg == SHZ_H_MD5) {
        put_le32(pad + padn - 8, (uint32_t)bits_lo);
        put_le32(pad + padn - 4, (uint32_t)(bits_lo >> 32));
    } else if (lenbytes == 8) {
        put_be64(pad + padn - 8, bits_lo);
    } else {
        put_be64(pad + padn - 16, bits_hi);
        put_be64(pad + padn - 8, bits_lo);
    }
    {
        const uint64_t saved = c->len;
        shz_hash_update(c, pad, padn);
        c->len = saved;
    }
    if (c->alg == SHZ_H_MD5) for (i = 0; i < 4; ++i) put_le32(out + 4 * i, c->st.w[i]);
    else if (c->alg == SHZ_H_SHA1 || c->alg == SHZ_H_SHA256) for (i = 0; i < dl / 4; ++i) put_be32(out + 4 * i, c->st.w[i]);
    else for (i = 0; i < dl / 8; ++i) put_be64(out + 8 * i, c->st.q[i]);
}

/* ---------------------------------------------------------------- HMAC (RFC 2104) */
void shz_hmac_init(shz_hmac_ctx *c, unsigned alg, const void *key, size_t keylen)
{
    const size_t bl = shz_hash_block_len(alg);
    uint8_t k0[SHZ_H_MAX_BLOCK], ipad[SHZ_H_MAX_BLOCK];
    size_t i;
    hzero(k0, sizeof k0);
    if (keylen > bl) {
        shz_hash_ctx h;
        shz_hash_init(&h, alg);
        shz_hash_update(&h, key, keylen);
        shz_hash_final(&h, k0);
    } else if (keylen) {
        hcopy(k0, key, keylen);
    }
    for (i = 0; i < bl; ++i) { ipad[i] = k0[i] ^ 0x36; c->opad_key[i] = k0[i] ^ 0x5c; }
    shz_hash_init(&c->inner, alg);
    shz_hash_update(&c->inner, ipad, bl);
}

void shz_hmac_update(shz_hmac_ctx *c, const void *data, size_t n) { shz_hash_update(&c->inner, data, n); }

void shz_hmac_final(shz_hmac_ctx *c, uint8_t *out)
{
    uint8_t ih[SHZ_H_MAX_DIGEST];
    shz_hash_ctx o;
    shz_hash_final(&c->inner, ih);
    shz_hash_init(&o, c->inner.alg);
    shz_hash_update(&o, c->opad_key, shz_hash_block_len(c->inner.alg));
    shz_hash_update(&o, ih, shz_hash_digest_len(c->inner.alg));
    shz_hash_final(&o, out);
}

/* ---------------------------------------------------------------- PBKDF2 (RFC 2898 5.2) */
int shz_pbkdf2(unsigned alg, const void *pw, size_t pwlen, const void *salt, size_t saltlen, uint64_t iterations,
               uint8_t *dk, size_t dklen)
{
    const size_t hl = shz_hash_digest_len(alg);
    shz_hmac_ctx keyed, w;
    uint32_t block = 1;
    if (!hl || !iterations || dklen / hl > 0xfffffffeu) return -1;
    shz_hmac_init(&keyed, alg, pw, pwlen);
    while (dklen) {
        uint8_t u[SHZ_H_MAX_DIGEST], t[SHZ_H_MAX_DIGEST], be[4];
        size_t take = dklen < hl ? dklen : hl, i;
        uint64_t j;
        put_be32(be, block);
        w = keyed;                                     /* U1 = PRF(P, S || INT(i)) */
        shz_hmac_update(&w, salt, saltlen);
        shz_hmac_update(&w, be, 4);
        shz_hmac_final(&w, u);
        for (i = 0; i < hl; ++i) t[i] = u[i];
        for (j = 1; j < iterations; ++j) {              /* Uj = PRF(P, Uj-1); T = U1 ^ U2 ^ ... ^ Uc */
            w = keyed;
            shz_hmac_update(&w, u, hl);
            shz_hmac_final(&w, u);
            for (i = 0; i < hl; ++i) t[i] ^= u[i];
        }
        hcopy(dk, t, take);
        dk += take;
        dklen -= take;
        ++block;
    }
    return 0;
}
