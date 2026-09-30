/* SPDX-License-Identifier: GPL-2.0-only
 * Appended to the pinned Mbed TLS defaults. No ambient OS entropy or storage.
 */
#ifndef M98_TLS13_CONFIG_H
#define M98_TLS13_CONFIG_H
#include <stdint.h>
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
#undef MBEDTLS_PSA_BUILTIN_GET_ENTROPY
#undef MBEDTLS_PSA_DRIVER_GET_ENTROPY
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_FS_IO
#undef MBEDTLS_THREADING_C
#undef MBEDTLS_THREADING_PTHREAD
#undef MBEDTLS_THREADING_ALT
#define MBEDTLS_PLATFORM_TIME_TYPE_MACRO int64_t
#define MBEDTLS_PLATFORM_TIME_MACRO m98_tls_platform_time
#define MBEDTLS_PLATFORM_GMTIME_R_ALT
int64_t m98_tls_platform_time(int64_t *out);
#endif
