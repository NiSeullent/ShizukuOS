/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTWST_MBEDTLS_USER_CONFIG_H
#define NTWST_MBEDTLS_USER_CONFIG_H

/* Maintained upstream crypto/TLS; platform RNG and I/O belong to the caller.
 * There is no timing-based entropy fallback and no persistent private-key store.
 * All calls are serialized by the embedder in this initial engine. */
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
#undef MBEDTLS_ENTROPY_C
#undef MBEDTLS_CTR_DRBG_C
/* Keep the upstream HMAC_DRBG primitive for deterministic ECDSA nonces;
 * PSA session/key randomness still uses only the external OS callback. */
#undef MBEDTLS_NET_C
#undef MBEDTLS_TIMING_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_FS_IO
#undef MBEDTLS_SSL_EARLY_DATA

#if defined(_WIN32)
/* Compile the complete native archive for the i486 baseline. Upstream's
 * assembly and optional accelerators can emit instructions newer than i486
 * independently of -march; no runtime hardware-dispatch claim is made here. */
#undef MBEDTLS_HAVE_ASM
#undef MBEDTLS_HAVE_SSE2
#undef MBEDTLS_AESNI_C
#undef MBEDTLS_AESCE_C
#undef MBEDTLS_PADLOCK_C
/* Win98's CRT lacks modern *_s date functions and *_time64 exports.
 * Use its native system clock with a 64-bit Unix epoch; retain date checks. */
#include <stdint.h>
#include "i486_format.h"
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO ntwst_i486_snprintf
#define MBEDTLS_PLATFORM_VSNPRINTF_MACRO ntwst_i486_vsnprintf
#define MBEDTLS_PLATFORM_TIME_TYPE_MACRO int64_t
#define MBEDTLS_PLATFORM_TIME_MACRO ntwst_native_time
#define MBEDTLS_PLATFORM_GMTIME_R_ALT
int64_t ntwst_native_time(int64_t *result);
#endif

#endif
