/* SPDX-License-Identifier: GPL-2.0-only */
#include "native_runtime.h"
#include "transport.h"
#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>

static HCRYPTPROV crypto_provider;

static int native_random(void *context, unsigned char *bytes, size_t size)
{
    HCRYPTPROV provider = *(HCRYPTPROV *)context;
    if (!provider || size > UINT32_MAX) return -1;
    if (!size) return 0;
    return CryptGenRandom(provider, (DWORD)size, bytes) ? 0 : -1;
}

int ntwst_native_runtime_init(void)
{
    int result;
    HCRYPTPROV acquired = 0;
    if (crypto_provider) return NTWST_BUSY;
    /* Win9x's Unicode entry point may return ERROR_CALL_NOT_IMPLEMENTED. */
    if (!CryptAcquireContextA(&acquired, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT))
        return NTWST_RANDOM_ERROR;
    crypto_provider = acquired;
    result = ntwst_runtime_init(native_random, &crypto_provider);
    if (result != NTWST_OK) {
        if (!CryptReleaseContext(crypto_provider, 0)) return NTWST_ENGINE_ERROR;
        crypto_provider = 0;
    }
    return result;
}

int ntwst_native_runtime_fini(void)
{
    int result;
    if (!crypto_provider) return NTWST_INVALID;
    result = ntwst_runtime_fini();
    if (result == NTWST_OK) {
        if (!CryptReleaseContext(crypto_provider, 0)) return NTWST_ENGINE_ERROR;
        crypto_provider = 0;
    }
    return result;
}
#endif
