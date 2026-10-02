/* SPDX-License-Identifier: GPL-2.0-only
 * Minimal SHA-256 (FIPS 180-4) for the host tools' content comparisons.
 */
#ifndef SFS_SHA256_H
#define SFS_SHA256_H
#include <stddef.h>
#include <stdint.h>

typedef struct sha256_ctx {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t n;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256_hex(const uint8_t d[32], char out[65]);
#endif
