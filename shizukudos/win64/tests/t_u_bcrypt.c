/* SPDX-License-Identifier: GPL-2.0-only
 * bcrypt.dll / bcryptprimitives.dll. Expected values are public standards vectors, none produced by this code base:
 *   MD5      RFC 1321 appendix A.5           SHA-1 / SHA-2  FIPS 180-4 example values (NIST CSRC)
 *   HMAC     RFC 2202 (MD5, SHA-1), RFC 4231 (SHA-256/384/512)
 *   PBKDF2   RFC 6070 (HMAC-SHA1) and the widely published HMAC-SHA256/512 companions
 * The literal table rows are cross-checked against an independent implementation (Python hashlib / hmac / pbkdf2_hmac,
 * i.e. OpenSSL) by tests/u_host_crosscheck.py, which parses this very table; the same script also runs the shipped
 * dlls/bcrypt/hashes.c natively against OpenSSL on ~2000 random inputs. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include "u_check.h"

#define ST_INVALID_HANDLE ((NTSTATUS)0xC0000008)
#define ST_INVALID_PARAMETER ((NTSTATUS)0xC000000D)
#define ST_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023)
#define ST_NOT_SUPPORTED ((NTSTATUS)0xC00000BB)
#define ST_NOT_FOUND ((NTSTATUS)0xC0000225)

BOOL WINAPI ProcessPrng(PBYTE, SIZE_T);

/* byte-string spec: a C string of explicit length, or `n` copies of a fill byte */
typedef struct { const char *s; unsigned n; int fill; } bs_t;
#define S(str) { str, (unsigned)sizeof(str) - 1, 0 }
#define F(b, cnt) { 0, cnt, b }

static const WCHAR *alg_id(const char *name)
{
    if (!strcmp(name, "MD5")) return L"MD5";
    if (!strcmp(name, "SHA1")) return L"SHA1";
    if (!strcmp(name, "SHA256")) return L"SHA256";
    if (!strcmp(name, "SHA384")) return L"SHA384";
    return L"SHA512";
}

static unsigned digest_len(const char *name)
{
    if (!strcmp(name, "MD5")) return 16;
    if (!strcmp(name, "SHA1")) return 20;
    if (!strcmp(name, "SHA256")) return 32;
    if (!strcmp(name, "SHA384")) return 48;
    return 64;
}

static int hex_eq(const unsigned char *d, size_t n, const char *hex)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;
    if (strlen(hex) != n * 2) return 0;
    for (i = 0; i < n; ++i)
        if (hex[2 * i] != digits[d[i] >> 4] || hex[2 * i + 1] != digits[d[i] & 15]) return 0;
    return 1;
}

/* Copy a spec into buf (n <= cap); returns its length. */
static size_t materialize(const bs_t *b, unsigned char *buf, size_t cap)
{
    size_t i;
    if (b->n > cap) return 0;
    if (b->s) for (i = 0; i < b->n; ++i) buf[i] = (unsigned char)b->s[i];
    else for (i = 0; i < b->n; ++i) buf[i] = (unsigned char)b->fill;
    return b->n;
}

/* Feed a spec into a hash object in pieces of `chunk` bytes (fills are streamed, so million-byte messages need no buffer). */
static NTSTATUS feed(BCRYPT_HASH_HANDLE h, const bs_t *b, size_t chunk)
{
    static unsigned char tmp[1000];
    size_t left = b->n, off = 0;
    NTSTATUS st = 0;
    if (!b->s) memset(tmp, b->fill, sizeof tmp);
    while (left && !st) {
        size_t t = left < chunk ? left : chunk;
        if (t > sizeof tmp) t = sizeof tmp;
        st = BCryptHashData(h, b->s ? (PUCHAR)b->s + off : tmp, (ULONG)t, 0);
        off += t; left -= t;
    }
    return st;
}

static NTSTATUS hash_spec(BCRYPT_ALG_HANDLE alg, const bs_t *key, const bs_t *msg, size_t chunk, unsigned char *out, unsigned outlen)
{
    unsigned char kb[300];
    BCRYPT_HASH_HANDLE h = 0;
    size_t kl = key ? materialize(key, kb, sizeof kb) : 0;
    NTSTATUS st = BCryptCreateHash(alg, &h, 0, 0, key ? kb : 0, (ULONG)kl, 0);
    if (st) return st;
    st = feed(h, msg, chunk);
    if (!st) st = BCryptFinishHash(h, out, outlen, 0);
    BCryptDestroyHash(h);
    return st;
}

/* ---- message digests: { algorithm, message, expected digest } ---- */
static const struct { const char *alg; bs_t msg; const char *hex; } hash_vectors[] = {
    { "MD5", S(""), "d41d8cd98f00b204e9800998ecf8427e" },
    { "MD5", S("a"), "0cc175b9c0f1b6a831c399e269772661" },
    { "MD5", S("abc"), "900150983cd24fb0d6963f7d28e17f72" },
    { "MD5", S("message digest"), "f96b697d7cb7938d525a2f31aaf161d0" },
    { "MD5", S("abcdefghijklmnopqrstuvwxyz"), "c3fcd3d76192e4007dfb496cca67e13b" },
    { "MD5", S("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), "d174ab98d277d9f5a5611c2c9f419d9f" },
    { "MD5", S("12345678901234567890123456789012345678901234567890123456789012345678901234567890"), "57edf4a22be3c955ac49da2e2107b67a" },
    { "SHA1", S(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
    { "SHA1", S("abc"), "a9993e364706816aba3e25717850c26c9cd0d89d" },
    { "SHA1", S("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
    { "SHA256", S(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { "SHA256", S("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    { "SHA256", S("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
    { "SHA384", S(""), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" },
    { "SHA384", S("abc"), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" },
    { "SHA384", S("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
      "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039" },
    { "SHA512", S(""), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
    { "SHA512", S("abc"), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
    { "SHA512", S("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
      "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" },
    /* one million 'a' (FIPS 180-4 long-message example values) */
    { "MD5", F(0x61, 1000000), "7707d6ae4e027c70eea2a935c2296f21" },
    { "SHA1", F(0x61, 1000000), "34aa973cd4c4daa4f61eeb2bdbad27316534016f" },
    { "SHA256", F(0x61, 1000000), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" },
    { "SHA384", F(0x61, 1000000), "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985" },
    { "SHA512", F(0x61, 1000000), "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b" },
};

/* ---- HMAC: { algorithm, key, data, expected MAC } (RFC 2202 cases 1,2,3,6; RFC 4231 cases 1,2,3,6) ---- */
static const struct { const char *alg; bs_t key, data; const char *hex; } hmac_vectors[] = {
    { "MD5", F(0x0b, 16), S("Hi There"), "9294727a3638bb1c13f48ef8158bfc9d" },
    { "MD5", S("Jefe"), S("what do ya want for nothing?"), "750c783e6ab0b503eaa86e310a5db738" },
    { "MD5", F(0xaa, 16), F(0xdd, 50), "56be34521d144c88dbb8c733f0e8b3f6" },
    { "MD5", F(0xaa, 80), S("Test Using Larger Than Block-Size Key - Hash Key First"), "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd" },
    { "SHA1", F(0x0b, 20), S("Hi There"), "b617318655057264e28bc0b6fb378c8ef146be00" },
    { "SHA1", S("Jefe"), S("what do ya want for nothing?"), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" },
    { "SHA1", F(0xaa, 20), F(0xdd, 50), "125d7342b9ac11cd91a39af48aa17b4f63f175d3" },
    { "SHA1", F(0xaa, 80), S("Test Using Larger Than Block-Size Key - Hash Key First"), "aa4ae5e15272d00e95705637ce8a3b55ed402112" },
    { "SHA256", F(0x0b, 20), S("Hi There"), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" },
    { "SHA384", F(0x0b, 20), S("Hi There"), "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6" },
    { "SHA512", F(0x0b, 20), S("Hi There"), "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854" },
    { "SHA256", S("Jefe"), S("what do ya want for nothing?"), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" },
    { "SHA384", S("Jefe"), S("what do ya want for nothing?"), "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649" },
    { "SHA512", S("Jefe"), S("what do ya want for nothing?"), "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737" },
    { "SHA256", F(0xaa, 20), F(0xdd, 50), "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe" },
    { "SHA384", F(0xaa, 20), F(0xdd, 50), "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27" },
    { "SHA512", F(0xaa, 20), F(0xdd, 50), "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb" },
    { "SHA256", F(0xaa, 131), S("Test Using Larger Than Block-Size Key - Hash Key First"), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" },
    { "SHA384", F(0xaa, 131), S("Test Using Larger Than Block-Size Key - Hash Key First"), "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952" },
    { "SHA512", F(0xaa, 131), S("Test Using Larger Than Block-Size Key - Hash Key First"), "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598" },
};

/* ---- PBKDF2: { algorithm, password, salt, iterations, dkLen, expected } ---- */
static const struct { const char *alg; bs_t pw, salt; unsigned iter, dklen; const char *hex; } pbkdf2_vectors[] = {
    { "SHA1", S("password"), S("salt"), 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6" },
    { "SHA1", S("password"), S("salt"), 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957" },
    { "SHA1", S("password"), S("salt"), 4096, 20, "4b007901b765489abead49d926f721d065a429c1" },
    { "SHA1", S("passwordPASSWORDpassword"), S("saltSALTsaltSALTsaltSALTsaltSALTsalt"), 4096, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038" },
    { "SHA1", S("pass\0word"), S("sa\0lt"), 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3" },
    { "SHA256", S("password"), S("salt"), 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b" },
    { "SHA256", S("password"), S("salt"), 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43" },
    { "SHA256", S("password"), S("salt"), 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a" },
    { "SHA256", S("passwordPASSWORDpassword"), S("saltSALTsaltSALTsaltSALTsaltSALTsalt"), 4096, 40, "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9" },
    { "SHA256", S("passwd"), S("salt"), 1, 64, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783" },
    { "SHA512", S("password"), S("salt"), 1, 64, "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce" },
    { "SHA512", S("password"), S("salt"), 2, 64, "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e" },
};

int main(void)
{
    unsigned i;
    static unsigned char out[128], key[300], data[4200];
    BCRYPT_ALG_HANDLE alg = 0;
    NTSTATUS st;
    ULONG v, got;
    WCHAR name[16];

    /* ---------------- algorithm providers and properties ---------------- */
    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, 0, 0);
    U_CHECKF("open SHA256 provider", st == 0 && alg, "st=%x", (unsigned)st);
    got = 0; v = 0;
    st = BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&v, sizeof v, &got, 0);
    U_CHECK("SHA256 HashDigestLength = 32", st == 0 && got == 4 && v == 32);
    st = BCryptGetProperty(alg, BCRYPT_HASH_BLOCK_LENGTH, (PUCHAR)&v, sizeof v, &got, 0);
    U_CHECK("SHA256 HashBlockLength = 64", st == 0 && v == 64);
    st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&v, sizeof v, &got, 0);
    U_CHECKF("SHA256 ObjectLength is reported and nonzero", st == 0 && got == 4 && v > 0, "st=%x v=%u", (unsigned)st, (unsigned)v);
    st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, 0, 0, &got, 0);
    U_CHECK("NULL output buffer queries the size (STATUS_SUCCESS, 4)", st == 0 && got == 4);
    got = 0;
    st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&v, 2, &got, 0);
    U_CHECK("too-small buffer gives STATUS_BUFFER_TOO_SMALL and the needed size", st == ST_BUFFER_TOO_SMALL && got == 4);
    memset(name, 0, sizeof name);
    st = BCryptGetProperty(alg, BCRYPT_ALGORITHM_NAME, (PUCHAR)name, sizeof name, &got, 0);
    U_CHECK("AlgorithmName = L\"SHA256\" including the NUL", st == 0 && got == 14 && u_ascii_eq_w((unsigned short *)name, "SHA256"));
    st = BCryptGetProperty(alg, L"NoSuchProperty", (PUCHAR)&v, sizeof v, &got, 0);
    U_CHECK("unknown property is STATUS_NOT_SUPPORTED", st == ST_NOT_SUPPORTED);
    st = BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&v, sizeof v, &got, 1);
    U_CHECK("nonzero flags on GetProperty rejected", st == ST_INVALID_PARAMETER);
    st = BCryptGetProperty(0, BCRYPT_HASH_LENGTH, (PUCHAR)&v, sizeof v, &got, 0);
    U_CHECK("NULL handle is STATUS_INVALID_HANDLE", st == ST_INVALID_HANDLE);
    for (i = 0; i < 5; ++i) {
        static const char *const names[] = { "MD5", "SHA1", "SHA256", "SHA384", "SHA512" };
        static const unsigned blk[] = { 64, 64, 64, 128, 128 };
        BCRYPT_ALG_HANDLE h = 0;
        char nm[64];
        snprintf(nm, sizeof nm, "%s provider: digest length %u, block length %u", names[i], digest_len(names[i]), blk[i]);
        st = BCryptOpenAlgorithmProvider(&h, alg_id(names[i]), MS_PRIMITIVE_PROVIDER, 0);
        got = 0; v = 0;
        if (st == 0) BCryptGetProperty(h, BCRYPT_HASH_LENGTH, (PUCHAR)&v, 4, &got, 0);
        U_CHECK(nm, st == 0 && v == digest_len(names[i]));
        if (st == 0) { BCryptGetProperty(h, BCRYPT_HASH_BLOCK_LENGTH, (PUCHAR)&v, 4, &got, 0); U_CHECK("  block length matches", v == blk[i]); }
        if (h) BCryptCloseAlgorithmProvider(h, 0);
    }
    {
        BCRYPT_ALG_HANDLE h = (BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1234;
        st = BCryptOpenAlgorithmProvider(&h, L"sha256", 0, 0);
        U_CHECK("algorithm ids are matched case-insensitively", st == 0);
        if (!st) BCryptCloseAlgorithmProvider(h, 0);
        h = 0;
        st = BCryptOpenAlgorithmProvider(&h, L"SHA-256", 0, 0);
        U_CHECK("unknown id L\"SHA-256\" is STATUS_NOT_FOUND", st == ST_NOT_FOUND && !h);
        st = BCryptOpenAlgorithmProvider(&h, BCRYPT_AES_ALGORITHM, 0, 0);
        U_CHECK("AES is refused as STATUS_NOT_SUPPORTED (not implemented)", st == ST_NOT_SUPPORTED && !h);
        st = BCryptOpenAlgorithmProvider(&h, BCRYPT_RSA_ALGORITHM, 0, 0);
        U_CHECK("RSA is refused as STATUS_NOT_SUPPORTED (not implemented)", st == ST_NOT_SUPPORTED && !h);
        st = BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA1_ALGORITHM, L"Some Other Provider", 0);
        U_CHECK("unknown implementation name is STATUS_NOT_FOUND", st == ST_NOT_FOUND);
        st = BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA1_ALGORITHM, 0, 0x80000000u);
        U_CHECK("undefined flag bits are STATUS_INVALID_PARAMETER", st == ST_INVALID_PARAMETER);
        st = BCryptOpenAlgorithmProvider(0, BCRYPT_SHA1_ALGORITHM, 0, 0);
        U_CHECK("NULL output pointer is STATUS_INVALID_PARAMETER", st == ST_INVALID_PARAMETER);
    }

    /* ---------------- digests: single call, 7-byte chunks, one-shot BCryptHash ---------------- */
    for (i = 0; i < sizeof hash_vectors / sizeof hash_vectors[0]; ++i) {
        BCRYPT_ALG_HANDLE h = 0;
        const unsigned dl = digest_len(hash_vectors[i].alg);
        char nm[128];
        int ok1, ok2, ok3 = 1;
        size_t ml;
        st = BCryptOpenAlgorithmProvider(&h, alg_id(hash_vectors[i].alg), 0, 0);
        memset(out, 0, sizeof out);
        ok1 = st == 0 && hash_spec(h, 0, &hash_vectors[i].msg, 1000, out, dl) == 0 && hex_eq(out, dl, hash_vectors[i].hex);
        memset(out, 0, sizeof out);
        ok2 = st == 0 && hash_spec(h, 0, &hash_vectors[i].msg, 7, out, dl) == 0 && hex_eq(out, dl, hash_vectors[i].hex);
        if (hash_vectors[i].msg.n <= sizeof data) {
            ml = materialize(&hash_vectors[i].msg, data, sizeof data);
            memset(out, 0, sizeof out);
            ok3 = st == 0 && BCryptHash(h, 0, 0, data, (ULONG)ml, out, dl) == 0 && hex_eq(out, dl, hash_vectors[i].hex);
        }
        if (hash_vectors[i].msg.n > 20)
            snprintf(nm, sizeof nm, "%s vector #%u (%u-byte message)", hash_vectors[i].alg, i, hash_vectors[i].msg.n);
        else
            snprintf(nm, sizeof nm, "%s vector #%u (\"%s\")", hash_vectors[i].alg, i, hash_vectors[i].msg.s ? hash_vectors[i].msg.s : "?");
        U_CHECKF(nm, ok1 && ok2 && ok3, "single/chunked/oneshot=%d%d%d", ok1, ok2, ok3);
        if (h) BCryptCloseAlgorithmProvider(h, 0);
    }

    /* ---------------- HMAC ---------------- */
    for (i = 0; i < sizeof hmac_vectors / sizeof hmac_vectors[0]; ++i) {
        BCRYPT_ALG_HANDLE h = 0;
        const unsigned dl = digest_len(hmac_vectors[i].alg);
        char nm[96];
        int ok1, ok2;
        size_t kl = materialize(&hmac_vectors[i].key, key, sizeof key), ml = materialize(&hmac_vectors[i].data, data, sizeof data);
        st = BCryptOpenAlgorithmProvider(&h, alg_id(hmac_vectors[i].alg), 0, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        memset(out, 0, sizeof out);
        ok1 = st == 0 && hash_spec(h, &hmac_vectors[i].key, &hmac_vectors[i].data, 5, out, dl) == 0 && hex_eq(out, dl, hmac_vectors[i].hex);
        memset(out, 0, sizeof out);
        ok2 = st == 0 && BCryptHash(h, key, (ULONG)kl, data, (ULONG)ml, out, dl) == 0 && hex_eq(out, dl, hmac_vectors[i].hex);
        snprintf(nm, sizeof nm, "HMAC-%s vector #%u (key %u bytes, data %u bytes)", hmac_vectors[i].alg, i, (unsigned)kl, (unsigned)ml);
        U_CHECKF(nm, ok1 && ok2, "handle=%d oneshot=%d", ok1, ok2);
        if (h) BCryptCloseAlgorithmProvider(h, 0);
    }
    {
        /* Windows 10 SDK pseudo handles: BCRYPT_SHA256_ALG_HANDLE = 0x41, BCRYPT_HMAC_SHA256_ALG_HANDLE = 0xb1 */
        unsigned char d[64];
        BCRYPT_ALG_HANDLE p256 = (BCRYPT_ALG_HANDLE)(ULONG_PTR)0x41, phmac = (BCRYPT_ALG_HANDLE)(ULONG_PTR)0xb1;
        st = BCryptHash(p256, 0, 0, (PUCHAR)"abc", 3, d, 32);
        U_CHECK("BCRYPT_SHA256_ALG_HANDLE pseudo handle with BCryptHash: SHA-256(abc)",
                st == 0 && hex_eq(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        memset(key, 0x0b, 20);
        st = BCryptHash(phmac, key, 20, (PUCHAR)"Hi There", 8, d, 32);
        U_CHECK("BCRYPT_HMAC_SHA256_ALG_HANDLE pseudo handle: RFC 4231 case 1",
                st == 0 && hex_eq(d, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    }

    /* ---------------- hash object behaviour ---------------- */
    {
        BCRYPT_HASH_HANDLE h1 = 0, h2 = 0;
        unsigned char d1[32], d2[32], e1[32], e2[32];
        ULONG objlen = 0, got2;
        PUCHAR objbuf, smallbuf;
        st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objlen, 4, &got2, 0);
        objbuf = HeapAlloc(GetProcessHeap(), 0, objlen);
        smallbuf = HeapAlloc(GetProcessHeap(), 0, 8);
        st = BCryptCreateHash(alg, &h1, smallbuf, 8, 0, 0, 0);
        U_CHECK("caller-supplied object smaller than ObjectLength is STATUS_BUFFER_TOO_SMALL", st == ST_BUFFER_TOO_SMALL);
        st = BCryptCreateHash(alg, &h1, objbuf, objlen, 0, 0, 0);
        U_CHECK("BCryptCreateHash with a caller buffer of ObjectLength bytes", st == 0 && h1);
        BCryptHashData(h1, (PUCHAR)"abc", 3, 0);
        st = BCryptDuplicateHash(h1, &h2, 0, 0, 0);
        U_CHECK("BCryptDuplicateHash", st == 0 && h2 && h2 != h1);
        BCryptHashData(h1, (PUCHAR)"def", 3, 0);
        BCryptHashData(h2, (PUCHAR)"xyz", 3, 0);
        U_CHECK("finish original (abcdef) and duplicate (abcxyz)", BCryptFinishHash(h1, d1, 32, 0) == 0 && BCryptFinishHash(h2, d2, 32, 0) == 0);
        BCryptHash(alg, 0, 0, (PUCHAR)"abcdef", 6, e1, 32);
        BCryptHash(alg, 0, 0, (PUCHAR)"abcxyz", 6, e2, 32);
        U_CHECK("original and duplicate diverge after the copy and match one-shot hashes",
                !memcmp(d1, e1, 32) && !memcmp(d2, e2, 32) && memcmp(d1, d2, 32));
        st = BCryptFinishHash(h1, d1, 32, 0);
        U_CHECK("second FinishHash on a non-reusable hash fails", st != 0);
        st = BCryptHashData(h1, (PUCHAR)"x", 1, 0);
        U_CHECK("HashData after FinishHash on a non-reusable hash fails", st != 0);
        BCryptDestroyHash(h1);
        BCryptDestroyHash(h2);
        HeapFree(GetProcessHeap(), 0, smallbuf);
        HeapFree(GetProcessHeap(), 0, objbuf);
    }
    {
        BCRYPT_ALG_HANDLE ra = 0;
        BCRYPT_HASH_HANDLE h = 0;
        unsigned char d1[20], d2[20];
        st = BCryptOpenAlgorithmProvider(&ra, BCRYPT_SHA1_ALGORITHM, 0, BCRYPT_HASH_REUSABLE_FLAG);
        U_CHECK("open with BCRYPT_HASH_REUSABLE_FLAG", st == 0);
        st = BCryptCreateHash(ra, &h, 0, 0, 0, 0, 0);
        BCryptHashData(h, (PUCHAR)"abc", 3, 0);
        BCryptFinishHash(h, d1, 20, 0);
        BCryptHashData(h, (PUCHAR)"abc", 3, 0);
        st = BCryptFinishHash(h, d2, 20, 0);
        U_CHECK("reusable hash: the second message gives the same SHA1(abc)",
                st == 0 && hex_eq(d1, 20, "a9993e364706816aba3e25717850c26c9cd0d89d") && !memcmp(d1, d2, 20));
        BCryptDestroyHash(h);
        BCryptCloseAlgorithmProvider(ra, 0);
    }
    {
        BCRYPT_HASH_HANDLE h = 0;
        unsigned char d[32];
        st = BCryptCreateHash(alg, &h, 0, 0, 0, 0, 0);
        st = BCryptFinishHash(h, d, 31, 0);
        U_CHECK("FinishHash with a too-small output length is STATUS_INVALID_PARAMETER", st == ST_INVALID_PARAMETER);
        st = BCryptFinishHash(h, d, 33, 0);
        U_CHECK("FinishHash with an oversized output length is STATUS_INVALID_PARAMETER", st == ST_INVALID_PARAMETER);
        st = BCryptFinishHash(h, d, 32, 0);
        U_CHECK("...the hash is still usable afterwards (empty-message SHA256)",
                st == 0 && hex_eq(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        BCryptDestroyHash(h);
        st = BCryptHashData(0, (PUCHAR)"a", 1, 0);
        U_CHECK("HashData(NULL handle) is STATUS_INVALID_HANDLE", st == ST_INVALID_HANDLE);
        st = BCryptCreateHash(alg, &h, 0, 0, 0, 0, 0x100);
        U_CHECK("CreateHash with an undefined flag is STATUS_INVALID_PARAMETER", st == ST_INVALID_PARAMETER);
    }

    /* ---------------- PBKDF2 ---------------- */
    for (i = 0; i < sizeof pbkdf2_vectors / sizeof pbkdf2_vectors[0]; ++i) {
        BCRYPT_ALG_HANDLE h = 0;
        static unsigned char pw[100], salt[100];
        size_t pl = materialize(&pbkdf2_vectors[i].pw, pw, sizeof pw), sl = materialize(&pbkdf2_vectors[i].salt, salt, sizeof salt);
        char nm[96];
        int ok;
        st = BCryptOpenAlgorithmProvider(&h, alg_id(pbkdf2_vectors[i].alg), 0, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        memset(out, 0, sizeof out);
        ok = st == 0 && BCryptDeriveKeyPBKDF2(h, pw, (ULONG)pl, salt, (ULONG)sl, pbkdf2_vectors[i].iter, out, pbkdf2_vectors[i].dklen, 0) == 0 &&
             hex_eq(out, pbkdf2_vectors[i].dklen, pbkdf2_vectors[i].hex);
        snprintf(nm, sizeof nm, "PBKDF2-HMAC-%s vector #%u (c=%u, dkLen=%u)", pbkdf2_vectors[i].alg, i, pbkdf2_vectors[i].iter, pbkdf2_vectors[i].dklen);
        U_CHECK(nm, ok);
        if (h) BCryptCloseAlgorithmProvider(h, 0);
    }
    {
        BCRYPT_ALG_HANDLE plain = 0, hm = 0;
        st = BCryptOpenAlgorithmProvider(&plain, BCRYPT_SHA1_ALGORITHM, 0, 0);
        st = BCryptDeriveKeyPBKDF2(plain, (PUCHAR)"p", 1, (PUCHAR)"s", 1, 1, out, 20, 0);
        U_CHECK("PBKDF2 with a non-HMAC provider handle is rejected", st != 0);
        BCryptCloseAlgorithmProvider(plain, 0);
        st = BCryptOpenAlgorithmProvider(&hm, BCRYPT_SHA1_ALGORITHM, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        st = BCryptDeriveKeyPBKDF2(hm, (PUCHAR)"p", 1, (PUCHAR)"s", 1, 0, out, 20, 0);
        U_CHECK("PBKDF2 with zero iterations is STATUS_INVALID_PARAMETER", st == ST_INVALID_PARAMETER);
        st = BCryptDeriveKeyPBKDF2(hm, (PUCHAR)"p", 1, (PUCHAR)"s", 1, 1, out, 0, 0);
        U_CHECK("PBKDF2 with zero output length is STATUS_INVALID_PARAMETER", st == ST_INVALID_PARAMETER);
        BCryptCloseAlgorithmProvider(hm, 0);
    }

    /* ---------------- random numbers ---------------- */
    {                                   /* the kernel RNG (krandom.c) serves every CPU, with or without RDRAND */
        static unsigned char buf[4096], buf2[4096];
        static unsigned hist[256];
        unsigned ones = 0, sz;
        unsigned char tail[64];
        BCRYPT_ALG_HANDLE rng = 0;
        memset(buf, 0, sizeof buf);
        st = BCryptGenRandom(0, buf, sizeof buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        U_CHECKF("BCryptGenRandom(NULL, 4096, USE_SYSTEM_PREFERRED_RNG) succeeds", st == 0, "st=%x", (unsigned)st);
        st = BCryptGenRandom(0, buf2, sizeof buf2, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        U_CHECK("two 4096-byte draws differ", st == 0 && memcmp(buf, buf2, sizeof buf));
        for (i = 0; i < sizeof buf; ++i) {
            unsigned b = buf[i], k;
            for (k = 0; k < 8; ++k) ones += b >> k & 1;
            ++hist[b];
        }
        /* 32768 fair bits: mean 16384, sd 90.5; accept 8 sd = 724 */
        U_CHECKF("bit balance of 4096 random bytes is within 8 standard deviations of 50%", ones > 16384 - 724 && ones < 16384 + 724, "ones=%u", ones);
        {
            /* chi-square over the 256 byte values, expected 16 each; 255 dof, mean 255, sd 22.6: accept < 436 (8 sd) */
            unsigned long long sum = 0;
            for (i = 0; i < 256; ++i) { int d = (int)hist[i] - 16; sum += (unsigned)(d * d); }
            U_CHECKF("byte-value chi-square of 4096 random bytes is plausible (< 436, 255 dof)", sum / 16 < 436, "chi2=%u", (unsigned)(sum / 16));
        }
        st = BCryptGenRandom(0, buf, 0, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        U_CHECK("zero-length request succeeds", st == 0);
        {
            int ok = 1;
            for (sz = 1; sz <= 40; ++sz) {
                memset(tail, 0x77, sizeof tail);
                if (BCryptGenRandom(0, tail, sz, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0 || tail[sz] != 0x77 || tail[sz + 1] != 0x77) ok = 0;
            }
            U_CHECK("lengths 1..40 fill exactly the requested bytes (nothing written past the end)", ok);
        }
        st = BCryptOpenAlgorithmProvider(&rng, BCRYPT_RNG_ALGORITHM, 0, 0);
        U_CHECK("open the RNG algorithm provider", st == 0 && rng);
        memset(buf, 0, 64);
        st = BCryptGenRandom(rng, buf, 64, 0);
        {
            unsigned nz = 0;
            for (i = 0; i < 64; ++i) nz += buf[i] != 0;
            U_CHECKF("BCryptGenRandom with an RNG provider handle", st == 0 && nz > 40, "st=%x nz=%u", (unsigned)st, nz);
        }
        st = BCryptGenRandom(rng, buf, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        U_CHECK("hAlgorithm together with USE_SYSTEM_PREFERRED_RNG is STATUS_INVALID_PARAMETER", st == ST_INVALID_PARAMETER);
        st = BCryptGenRandom(0, buf, 8, 0x100);
        U_CHECK("undefined flag is STATUS_INVALID_PARAMETER", st == ST_INVALID_PARAMETER);
        st = BCryptGenRandom(0, 0, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        U_CHECK("NULL buffer with nonzero length is STATUS_INVALID_PARAMETER", st == ST_INVALID_PARAMETER);
        st = BCryptGenRandom(alg, buf, 8, 0);
        U_CHECK("a hash provider handle is not an RNG (STATUS_INVALID_HANDLE)", st == ST_INVALID_HANDLE);
        st = BCryptGetProperty(rng, BCRYPT_HASH_LENGTH, (PUCHAR)&v, 4, &got, 0);
        U_CHECK("RNG provider has no HashDigestLength (STATUS_NOT_SUPPORTED)", st == ST_NOT_SUPPORTED);
        {
            BCRYPT_HASH_HANDLE hh = 0;
            st = BCryptCreateHash(rng, &hh, 0, 0, 0, 0, 0);
            U_CHECK("CreateHash on an RNG provider is refused", st != 0 && !hh);
        }
        BCryptCloseAlgorithmProvider(rng, 0);
        memset(buf, 0, 256);
        U_CHECK("ProcessPrng (bcryptprimitives.dll) fills a buffer and returns TRUE", ProcessPrng(buf, 256) == TRUE);
        {
            unsigned nz = 0;
            for (i = 0; i < 256; ++i) nz += buf[i] != 0;
            U_CHECKF("ProcessPrng output is not degenerate", nz > 200, "nonzero=%u of 256", nz);
        }
        U_CHECK("ProcessPrng(NULL, 0) is TRUE", ProcessPrng(0, 0) == TRUE);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return u_finish("t_u_bcrypt");
}
