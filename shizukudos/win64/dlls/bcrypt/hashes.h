/* SPDX-License-Identifier: GPL-2.0-only
 * MD5 (RFC 1321), SHA-1 and SHA-2 (FIPS 180-4) plus HMAC (RFC 2104) and PBKDF2 (RFC 8018 / RFC 2898) primitives used
 * by bcrypt.dll. Freestanding: no libc, so the same source also builds natively for host-side cross-checks. */
#ifndef SHZ_HASHES_H
#define SHZ_HASHES_H
#include <stdint.h>
#include <stddef.h>

enum { SHZ_H_MD5 = 1, SHZ_H_SHA1, SHZ_H_SHA256, SHZ_H_SHA384, SHZ_H_SHA512 };
#define SHZ_H_MAX_BLOCK 128
#define SHZ_H_MAX_DIGEST 64

typedef struct {
    unsigned alg;
    unsigned bufn;                      /* bytes pending in buf */
    uint64_t len;                       /* total bytes hashed */
    union { uint32_t w[8]; uint64_t q[8]; } st;
    uint8_t buf[SHZ_H_MAX_BLOCK];
} shz_hash_ctx;

typedef struct {
    shz_hash_ctx inner;
    uint8_t opad_key[SHZ_H_MAX_BLOCK];  /* K0 xor opad, kept for the outer hash */
} shz_hmac_ctx;

size_t shz_hash_digest_len(unsigned alg);
size_t shz_hash_block_len(unsigned alg);
void shz_hash_init(shz_hash_ctx *c, unsigned alg);
void shz_hash_update(shz_hash_ctx *c, const void *data, size_t n);
void shz_hash_final(shz_hash_ctx *c, uint8_t *out);            /* writes digest_len bytes */

void shz_hmac_init(shz_hmac_ctx *c, unsigned alg, const void *key, size_t keylen);
void shz_hmac_update(shz_hmac_ctx *c, const void *data, size_t n);
void shz_hmac_final(shz_hmac_ctx *c, uint8_t *out);

/* PBKDF2 with HMAC-alg as the PRF; returns 0 on success, -1 for an invalid request (iterations 0 or dkLen beyond
 * (2^32-1)*hLen). */
int shz_pbkdf2(unsigned alg, const void *pw, size_t pwlen, const void *salt, size_t saltlen, uint64_t iterations,
               uint8_t *dk, size_t dklen);
#endif
