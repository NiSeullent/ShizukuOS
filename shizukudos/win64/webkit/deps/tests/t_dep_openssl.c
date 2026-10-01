/* SPDX-License-Identifier: GPL-2.0-only
 * Guest check of OpenSSL (libcrypto-3-x64.dll, libssl-3-x64.dll): SHA-256 and HMAC known answers, AES-256-GCM round
 * trip with tag check, the OS entropy source (RAND_bytes), an ECDSA P-256 sign/verify and a TLS 1.3 client context. */
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include "deptest.h"

static void hex(const unsigned char *p, size_t n, char *out) { for (size_t i = 0; i < n; ++i) sprintf(out + 2 * i, "%02x", p[i]); }

int main(void)
{
    unsigned char md[64], key[32], iv[12], tag[16], ct[64], pt[64], rnd[32] = {0};
    unsigned int mdlen = 0;
    char h[129];
    printf("%s\n", OpenSSL_version(OPENSSL_VERSION));
    CHECK(EVP_Digest("abc", 3, md, &mdlen, EVP_sha256(), NULL) && mdlen == 32);
    hex(md, 32, h);
    CHECK(!strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    HMAC(EVP_sha256(), "key", 3, (const unsigned char *)"The quick brown fox jumps over the lazy dog", 43, md, &mdlen);
    hex(md, 32, h);
    CHECK(!strcmp(h, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"));
    CHECK(RAND_bytes(rnd, sizeof rnd) == 1);
    int nonzero = 0;
    for (size_t i = 0; i < sizeof rnd; ++i) nonzero += rnd[i] != 0;
    CHECK(nonzero > 16);
    memset(key, 7, sizeof key); memset(iv, 9, sizeof iv);
    const char *msg = "ShizukuDOS WebKit TLS check";
    int len = 0, tot = 0;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    CHECK(EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, iv) && EVP_EncryptUpdate(c, ct, &len, (const unsigned char *)msg, (int)strlen(msg)));
    tot = len;
    CHECK(EVP_EncryptFinal_ex(c, ct + tot, &len) && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag));
    tot += len;
    EVP_CIPHER_CTX_reset(c);
    int pl = 0, ok;
    EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(c, pt, &pl, ct, tot);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, tag);
    ok = EVP_DecryptFinal_ex(c, pt + pl, &len);
    CHECK(ok == 1 && pl == (int)strlen(msg) && !memcmp(pt, msg, strlen(msg)));
    EVP_CIPHER_CTX_reset(c);
    tag[0] ^= 1;                                                /* a forged tag must be rejected */
    EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(c, pt, &pl, ct, tot);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, tag);
    CHECK(EVP_DecryptFinal_ex(c, pt + pl, &len) != 1);
    EVP_CIPHER_CTX_free(c);
    EVP_PKEY *pk = EVP_EC_gen("P-256");
    CHECK(pk != NULL);
    unsigned char sig[128];
    size_t siglen = sizeof sig;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    CHECK(EVP_DigestSignInit(m, NULL, EVP_sha256(), NULL, pk) == 1 && EVP_DigestSign(m, sig, &siglen, (const unsigned char *)msg, strlen(msg)) == 1);
    EVP_MD_CTX_reset(m);
    CHECK(EVP_DigestVerifyInit(m, NULL, EVP_sha256(), NULL, pk) == 1 && EVP_DigestVerify(m, sig, siglen, (const unsigned char *)msg, strlen(msg)) == 1);
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(pk);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    CHECK(ctx && SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) && SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION));
    SSL *s = ctx ? SSL_new(ctx) : NULL;
    CHECK(s && SSL_set_tlsext_host_name(s, "example.test"));
    SSL_free(s);
    SSL_CTX_free(ctx);
    return DONE("t_dep_openssl");
}
