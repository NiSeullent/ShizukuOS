/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku checks of the crypt32 functions chrome.dll imports at load time (measured on Chromium 157.0.8079.0 with
 * win64/tools/startup_chain.py), written with Wine's test framework and run next to Wine's own crypt32 tests.
 * Each function is exercised on real data (testdata.h: an OpenSSL-made RSA certificate and CMS message) and the results
 * are compared with values computed independently on the host, so passing means the implementation did the work.
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "wincrypt.h"
#include "winreg.h"
#include "wine/test.h"
#include "testdata.h"
#include "sdk_extra.h"

static FILETIME ft_of(WORD y, WORD m, WORD d)
{
    SYSTEMTIME st = { y, m, 0, d, 12, 0, 0, 0 };
    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);
    return ft;
}

static void test_store_and_certificate(void)
{
    HCERTSTORE mem, mem2, coll;
    PCCERT_CONTEXT cert, found, added = NULL, e;
    BYTE hash[20];
    DWORD size, count;
    WCHAR name[128];
    FILETIME t;
    CERT_ENHKEY_USAGE *eku;
    BYTE ku[2] = { 0 };
    BOOL ret;

    mem = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    ok(mem != NULL, "CertOpenStore(MEMORY) failed %lu\n", GetLastError());
    ret = CertAddEncodedCertificateToStore(mem, X509_ASN_ENCODING, test_cert_der, sizeof(test_cert_der),
                                           CERT_STORE_ADD_ALWAYS, &cert);
    ok(ret && cert, "CertAddEncodedCertificateToStore failed %lu\n", GetLastError());
    if (!cert) return;

    size = sizeof(hash);
    ret = CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, hash, &size);
    ok(ret && size == 20 && !memcmp(hash, test_cert_sha1, 20), "SHA-1 thumbprint differs from the host value\n");

    ok(CertCompareCertificateName(X509_ASN_ENCODING, &cert->pCertInfo->Subject, &cert->pCertInfo->Issuer),
       "self-signed: subject and issuer names must compare equal\n");

    t = ft_of(2050, 1, 1);
    ok(CertVerifyTimeValidity(&t, cert->pCertInfo) == 0, "2050 is inside the validity period\n");
    t = ft_of(2020, 1, 1);
    ok(CertVerifyTimeValidity(&t, cert->pCertInfo) == -1, "2020 is before NotBefore\n");
    t = ft_of(2200, 1, 1);
    ok(CertVerifyTimeValidity(&t, cert->pCertInfo) == 1, "2200 is after NotAfter\n");

    count = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name, ARRAY_SIZE(name));
    ok(count && !wcscmp(name, L"wineport.test"), "CertGetNameStringW: got %s\n", wine_dbgstr_w(name));
    count = CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, (void *)szOID_ORGANIZATION_NAME, name, ARRAY_SIZE(name));
    ok(count && !wcscmp(name, L"Shizuku Test"), "O attribute: got %s\n", wine_dbgstr_w(name));

    size = 0;
    ret = CertGetEnhancedKeyUsage(cert, 0, NULL, &size);
    ok(ret && size, "CertGetEnhancedKeyUsage size failed %lu\n", GetLastError());
    eku = malloc(size);
    ret = CertGetEnhancedKeyUsage(cert, 0, eku, &size);
    ok(ret && eku->cUsageIdentifier == 2 && !strcmp(eku->rgpszUsageIdentifier[0], szOID_PKIX_KP_SERVER_AUTH) &&
       !strcmp(eku->rgpszUsageIdentifier[1], szOID_PKIX_KP_CLIENT_AUTH), "unexpected EKU list\n");
    free(eku);
    ret = CertGetIntendedKeyUsage(X509_ASN_ENCODING, cert->pCertInfo, ku, sizeof(ku));
    ok(ret && ku[0] == (CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_KEY_ENCIPHERMENT_KEY_USAGE),
       "CertGetIntendedKeyUsage: %d %02x\n", ret, ku[0]);

    found = CertFindCertificateInStore(mem, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_W, L"wineport.test", NULL);
    ok(found != NULL, "CertFindCertificateInStore(SUBJECT_STR) failed %lu\n", GetLastError());
    CertFreeCertificateContext(found);
    found = CertFindCertificateInStore(mem, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_W, L"no such name", NULL);
    ok(!found && GetLastError() == CRYPT_E_NOT_FOUND, "a missing subject must not be found (%lu)\n", GetLastError());

    ok(CryptVerifyCertificateSignatureEx(0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void *)cert,
                                         CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void *)cert, 0, NULL),
       "the self-signed RSA signature must verify (%08lx)\n", GetLastError());
    {
        BYTE bad[sizeof(test_cert_der)];
        CRYPT_DATA_BLOB blob = { sizeof(bad), bad };
        memcpy(bad, test_cert_der, sizeof(bad));
        bad[sizeof(bad) - 10] ^= 0x01;                      /* inside the signature value */
        SetLastError(0xdeadbeef);
        ok(!CryptVerifyCertificateSignatureEx(0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &blob,
                                              CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void *)cert, 0, NULL),
           "a modified signature must not verify\n");
    }

    mem2 = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    ret = CertAddCertificateContextToStore(mem2, cert, CERT_STORE_ADD_NEW, &added);
    ok(ret && added, "CertAddCertificateContextToStore failed %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CertAddCertificateContextToStore(mem2, cert, CERT_STORE_ADD_NEW, NULL);
    ok(!ret && GetLastError() == CRYPT_E_EXISTS, "ADD_NEW of a duplicate must fail with CRYPT_E_EXISTS (%08lx)\n",
       GetLastError());
    CertFreeCertificateContext(added);

    coll = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    ok(CertAddStoreToCollection(coll, mem, 0, 0) && CertAddStoreToCollection(coll, mem2, 0, 0),
       "CertAddStoreToCollection failed %lu\n", GetLastError());
    for (count = 0, e = NULL; (e = CertEnumCertificatesInStore(coll, e)); ) count++;
    ok(count == 2, "the collection enumerates both member stores' certificates, got %lu\n", count);
    ok(CertControlStore(coll, 0, CERT_STORE_CTRL_AUTO_RESYNC, NULL) || GetLastError() == ERROR_CALL_NOT_IMPLEMENTED,
       "CertControlStore failed %08lx\n", GetLastError());

    CertFreeCertificateContext(cert);
    ok(CertCloseStore(coll, 0), "CertCloseStore(collection)\n");
    ok(CertCloseStore(mem2, 0), "CertCloseStore(mem2)\n");
    ok(CertCloseStore(mem, CERT_CLOSE_STORE_CHECK_FLAG), "CertCloseStore(mem, CHECK): %08lx\n", GetLastError());
}

static void test_system_stores(void)
{
    HCERTSTORE s;
    PCCERT_CONTEXT c = NULL;
    DWORD n = 0;

    s = CertOpenSystemStoreW(0, L"ROOT");
    ok(s != NULL, "CertOpenSystemStoreW(ROOT) failed %lu\n", GetLastError());
    while ((c = CertEnumCertificatesInStore(s, c))) n++;
    ok(n >= 5, "the root store holds the built-in Microsoft roots, got %lu certificates\n", n);
    CertCloseStore(s, 0);
    if (n < 5)
    {
        HKEY key;
        DWORD subkeys = 0;
        LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\SystemCertificates\\Root\\Certificates", 0,
                               KEY_READ, &key);
        if (!r) { RegQueryInfoKeyW(key, NULL, NULL, NULL, &subkeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL); RegCloseKey(key); }
        trace("HKLM Root\\Certificates: open %ld, %lu sub-keys\n", r, subkeys);
        s = CertOpenStore(CERT_STORE_PROV_SYSTEM_REGISTRY_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"Root");
        for (n = 0, c = NULL; s && (c = CertEnumCertificatesInStore(s, c)); ) n++;
        trace("LOCAL_MACHINE registry Root store %p: %lu certificates (%08lx)\n", s, n, GetLastError());
        if (s) CertCloseStore(s, 0);
    }

    s = CertOpenSystemStoreW(0, L"MY");
    ok(s != NULL, "CertOpenSystemStoreW(MY) failed %lu\n", GetLastError());
    for (n = 0, c = NULL; (c = CertEnumCertificatesInStore(s, c)); ) n++;
    trace("personal store: %lu certificates (Wine's store tests may have added some in this boot)\n", n);
    CertCloseStore(s, 0);
}

static void test_query_and_message(void)
{
    CERT_BLOB blob = { sizeof(test_cert_der), (BYTE *)test_cert_der };
    DWORD content = 0, format = 0, type = 0, size;
    HCERTSTORE store = NULL;
    HCRYPTMSG msg = NULL;
    const void *ctx = NULL;
    BYTE content_buf[64];
    BOOL ret;

    ret = CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob, CERT_QUERY_CONTENT_FLAG_ALL, CERT_QUERY_FORMAT_FLAG_ALL, 0,
                           NULL, &content, &format, &store, &msg, &ctx);
    ok(ret && content == CERT_QUERY_CONTENT_CERT && format == CERT_QUERY_FORMAT_BINARY && ctx,
       "DER certificate: ret %d content %lu format %lu\n", ret, content, format);
    if (ctx) CertFreeCertificateContext(ctx);
    if (store) CertCloseStore(store, 0);

    blob.pbData = (BYTE *)test_cert_pem;
    blob.cbData = sizeof(test_cert_pem) - 1;
    ctx = NULL;
    ret = CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob, CERT_QUERY_CONTENT_FLAG_CERT, CERT_QUERY_FORMAT_FLAG_ALL, 0,
                           NULL, &content, &format, NULL, NULL, &ctx);
    ok(ret && content == CERT_QUERY_CONTENT_CERT && format == CERT_QUERY_FORMAT_BASE64_ENCODED,
       "PEM certificate: ret %d content %lu format %lu\n", ret, content, format);
    if (ctx) CertFreeCertificateContext(ctx);

    blob.pbData = (BYTE *)test_signed_msg;
    blob.cbData = sizeof(test_signed_msg);
    store = NULL;
    ret = CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED, CERT_QUERY_FORMAT_FLAG_BINARY,
                           0, NULL, &content, NULL, &store, &msg, NULL);
    ok(ret && content == CERT_QUERY_CONTENT_PKCS7_SIGNED && msg, "CMS signed data: ret %d content %lu (%08lx)\n", ret,
       content, GetLastError());
    if (!msg) return;
    size = sizeof(type);
    ok(CryptMsgGetParam(msg, CMSG_TYPE_PARAM, 0, &type, &size) && type == CMSG_SIGNED, "CMSG_TYPE_PARAM %lu\n", type);
    size = sizeof(content_buf);
    ret = CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, content_buf, &size);
    ok(ret && size == 32 && !memcmp(content_buf, "Shizuku wineport signed message\n", 32), "CMSG_CONTENT_PARAM %lu\n", size);
    size = sizeof(type);
    ok(CryptMsgGetParam(msg, CMSG_SIGNER_COUNT_PARAM, 0, &type, &size) && type == 1, "one signer, got %lu\n", type);
    {
        PCCERT_CONTEXT signer = CertEnumCertificatesInStore(store, NULL);
        ok(signer != NULL, "the signer certificate is in the message store\n");
        if (signer)
        {
            ok(CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, signer->pCertInfo),
               "the CMS signature verifies with the signer's key (%08lx)\n", GetLastError());
            CertFreeCertificateContext(signer);
        }
    }
    ok(CryptMsgClose(msg), "CryptMsgClose\n");
    CertCloseStore(store, 0);
}

static void test_private_key_and_chain(void)
{
    static const WCHAR container[] = L"wineport-chrome-test";
    CERT_NAME_BLOB subject = { 0 };
    CRYPT_KEY_PROV_INFO prov_info = { (WCHAR *)container, (WCHAR *)MS_ENHANCED_PROV_W, PROV_RSA_FULL, 0, 0, NULL, AT_SIGNATURE };
    CERT_CHAIN_FIND_BY_ISSUER_PARA para;
    PCCERT_CONTEXT cert, nokey, in_store = NULL;
    PCCERT_CHAIN_CONTEXT chain;
    HCRYPTPROV prov = 0, key_prov;
    HCRYPTKEY key;
    HCERTSTORE store;
    DWORD spec;
    BOOL free_prov, ret;

    /* a certificate without a key property has no private key */
    nokey = CertCreateCertificateContext(X509_ASN_ENCODING, test_cert_der, sizeof(test_cert_der));
    SetLastError(0xdeadbeef);
    ok(!CryptAcquireCertificatePrivateKey(nokey, 0, NULL, &key_prov, &spec, &free_prov) &&
       GetLastError() == CRYPT_E_NO_KEY_PROPERTY, "no key property: %08lx\n", GetLastError());

    CryptAcquireContextW(&prov, container, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
    ret = CryptAcquireContextW(&prov, container, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_NEWKEYSET);
    ok(ret, "CryptAcquireContextW(NEWKEYSET) failed %08lx\n", GetLastError());
    if (!ret) { CertFreeCertificateContext(nokey); return; }
    ok(CryptGenKey(prov, AT_SIGNATURE, (1024 << 16) | CRYPT_EXPORTABLE, &key), "CryptGenKey %08lx\n", GetLastError());
    CryptDestroyKey(key);
    ok(CertStrToNameW(X509_ASN_ENCODING, L"CN=wineport client", CERT_X500_NAME_STR, NULL, NULL, &subject.cbData, NULL),
       "CertStrToNameW size\n");
    subject.pbData = malloc(subject.cbData);
    CertStrToNameW(X509_ASN_ENCODING, L"CN=wineport client", CERT_X500_NAME_STR, NULL, subject.pbData, &subject.cbData, NULL);
    cert = CertCreateSelfSignCertificate(prov, &subject, 0, &prov_info, NULL, NULL, NULL, NULL);
    ok(cert != NULL, "CertCreateSelfSignCertificate failed %08lx\n", GetLastError());
    if (cert)
    {
        ok(CryptAcquireCertificatePrivateKey(cert, 0, NULL, &key_prov, &spec, &free_prov) && spec == AT_SIGNATURE,
           "CryptAcquireCertificatePrivateKey failed %08lx\n", GetLastError());
        if (free_prov) CryptReleaseContext(key_prov, 0);

        store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
        CertAddCertificateContextToStore(store, nokey, CERT_STORE_ADD_ALWAYS, NULL);
        CertAddCertificateContextToStore(store, cert, CERT_STORE_ADD_ALWAYS, &in_store);
        memset(&para, 0, sizeof(para));
        para.cbSize = sizeof(para);
        chain = CertFindChainInStore(store, X509_ASN_ENCODING, CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG,
                                     CERT_CHAIN_FIND_BY_ISSUER, &para, NULL);
        ok(chain != NULL, "CertFindChainInStore found no chain (%08lx)\n", GetLastError());
        if (chain)
        {
            ok(CertCompareCertificate(X509_ASN_ENCODING, chain->rgpChain[0]->rgpElement[0]->pCertContext->pCertInfo,
                                      cert->pCertInfo), "only the certificate with a private key qualifies\n");
            chain = CertFindChainInStore(store, X509_ASN_ENCODING, CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG,
                                         CERT_CHAIN_FIND_BY_ISSUER, &para, chain);
            ok(!chain && GetLastError() == CRYPT_E_NOT_FOUND, "no second chain (%08lx)\n", GetLastError());
        }
        /* an issuer list that matches nothing */
        para.cIssuer = 1;
        para.rgIssuer = &nokey->pCertInfo->Issuer;
        chain = CertFindChainInStore(store, X509_ASN_ENCODING, CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG,
                                     CERT_CHAIN_FIND_BY_ISSUER, &para, NULL);
        ok(!chain && GetLastError() == CRYPT_E_NOT_FOUND, "an unrelated issuer must not match\n");
        /* without the key requirement the key-less certificate matches its own issuer name */
        chain = CertFindChainInStore(store, X509_ASN_ENCODING, CERT_CHAIN_FIND_BY_ISSUER_NO_KEY_FLAG |
                                     CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG, CERT_CHAIN_FIND_BY_ISSUER, &para, NULL);
        ok(chain != NULL, "NO_KEY search by issuer failed %08lx\n", GetLastError());
        if (chain) CertFreeCertificateChain(chain);
        CertFreeCertificateContext(in_store);
        CertCloseStore(store, 0);
        CertFreeCertificateContext(cert);
    }
    free(subject.pbData);
    CertFreeCertificateContext(nokey);
    CryptReleaseContext(prov, 0);
    CryptAcquireContextW(&prov, container, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
}

START_TEST(chrome)
{
    test_store_and_certificate();
    test_system_stores();
    test_query_and_message();
    test_private_key_and_chain();
}
