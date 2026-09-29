/* SPDX-License-Identifier: GPL-2.0-only
 * Windows SDK declarations missing from Wine's wincrypt.h (CertFindChainInStore's parameter block), from the SDK
 * documentation; the same layout the wineport crypt32 patch implements. */
#ifndef CERT_CHAIN_FIND_BY_ISSUER_COMPARE_KEY_FLAG
#define CERT_CHAIN_FIND_BY_ISSUER_COMPARE_KEY_FLAG    0x0001
#define CERT_CHAIN_FIND_BY_ISSUER_COMPLEX_CHAIN_FLAG  0x0002
#define CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG 0x0004
#define CERT_CHAIN_FIND_BY_ISSUER_LOCAL_MACHINE_FLAG  0x0008
#define CERT_CHAIN_FIND_BY_ISSUER_NO_KEY_FLAG         0x4000
#define CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG     0x8000
typedef BOOL (WINAPI *PFN_CERT_CHAIN_FIND_BY_ISSUER_CALLBACK)(PCCERT_CONTEXT cert, void *arg);
typedef struct _CERT_CHAIN_FIND_BY_ISSUER_PARA
{
    DWORD cbSize;
    LPCSTR pszUsageIdentifier;
    DWORD dwKeySpec;
    DWORD dwAcquirePrivateKeyFlags;
    DWORD cIssuer;
    CERT_NAME_BLOB *rgIssuer;
    PFN_CERT_CHAIN_FIND_BY_ISSUER_CALLBACK pfnFindCallback;
    void *pvFindArg;
    DWORD *pdwIssuerChainIndex;
    DWORD *pdwIssuerElementIndex;
} CERT_CHAIN_FIND_BY_ISSUER_PARA;
#endif
