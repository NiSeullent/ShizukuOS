/* SPDX-License-Identifier: GPL-2.0-only
 * bcrypt.dll - the CNG primitive layer, restricted to what can be done exactly:
 *   hash algorithms MD5, SHA1, SHA256, SHA384, SHA512, each also as HMAC (BCRYPT_ALG_HANDLE_HMAC_FLAG),
 *   the RNG algorithm / BCryptGenRandom (hardware RDRAND only, see shz_rand.h), and BCryptDeriveKeyPBKDF2.
 * Every other CNG algorithm (AES, RSA, ECDSA, ...) is refused with STATUS_NOT_SUPPORTED by BCryptOpenAlgorithmProvider;
 * the key-object entry points (BCryptGenerateSymmetricKey, BCryptEncrypt, ...) are not exported at all.
 *
 * The hash objects are kept in memory this DLL allocates; a caller-supplied pbHashObject is only size-checked (it is
 * documented as optional since Windows 7). Behaviour after BCryptFinishHash on a non-reusable hash is not documented;
 * we reject further HashData/FinishHash calls with STATUS_INVALID_PARAMETER.
 */
#include "nt.h"
#include "shz_rand.h"
#include <string.h>
#include <bcrypt.h>
#include "hashes.h"

#define ALG_MAGIC 0x474c4143u           /* 'CALG' */
#define HASH_MAGIC 0x48534843u          /* 'CHSH' */

typedef struct { ULONG magic; ULONG alg; ULONG hmac; ULONG reusable; } alg_obj;          /* alg 0 = RNG */
typedef struct {
    ULONG magic, alg, hmac, reusable, finished, pad;
    union { shz_hash_ctx h; shz_hmac_ctx m; } cur, init;
} hash_obj;

/* Windows 10 SDK pseudo handles (bcrypt.h BCRYPT_*_ALG_HANDLE): usable with BCryptHash / BCryptGenRandom */
#define PSEUDO_MD5 0x21
#define PSEUDO_SHA1 0x31
#define PSEUDO_SHA256 0x41
#define PSEUDO_SHA384 0x51
#define PSEUDO_SHA512 0x61
#define PSEUDO_RNG 0x81
#define PSEUDO_HMAC_MD5 0x91
#define PSEUDO_HMAC_SHA1 0xa1
#define PSEUDO_HMAC_SHA256 0xb1
#define PSEUDO_HMAC_SHA384 0xc1
#define PSEUDO_HMAC_SHA512 0xd1

static const struct { const WCHAR *name; unsigned alg; } algs[] = {
    { L"MD5", SHZ_H_MD5 }, { L"SHA1", SHZ_H_SHA1 }, { L"SHA256", SHZ_H_SHA256 }, { L"SHA384", SHZ_H_SHA384 },
    { L"SHA512", SHZ_H_SHA512 },
};

static int weq_i(const WCHAR *a, const WCHAR *b)
{
    for (;; ++a, ++b) {
        WCHAR x = *a, y = *b;
        if (x >= 'a' && x <= 'z') x = (WCHAR)(x - 32);
        if (y >= 'a' && y <= 'z') y = (WCHAR)(y - 32);
        if (x != y) return 0;
        if (!x) return 1;
    }
}

/* Well-known CNG algorithm identifiers this DLL does not implement: refused as unsupported (not "unknown"). */
static int known_unsupported(const WCHAR *id)
{
    static const WCHAR *const names[] = {
        L"AES", L"RC2", L"RC4", L"DES", L"DESX", L"3DES", L"3DES_112", L"RSA", L"DSA", L"DH", L"ECDH_P256", L"ECDH_P384",
        L"ECDH_P521", L"ECDSA_P256", L"ECDSA_P384", L"ECDSA_P521", L"MD2", L"MD4", L"AES-CMAC", L"AES-GMAC", L"XTS-AES",
        L"SP800_108_CTR_HMAC", L"SP800_56A_CONCAT", L"PBKDF2", L"CAPI_KDF", L"RSA_SIGN", L"DUALECRNG", L"FIPS186DSARNG",
        L"ECDH", L"ECDSA", L"HKDF", L"SHA3-256", L"SHA3-384", L"SHA3-512", 0 };
    int i;
    for (i = 0; names[i]; ++i)
        if (weq_i(id, names[i])) return 1;
    return 0;
}

static void wipe(void *p, size_t n) { volatile unsigned char *b = p; while (n--) *b++ = 0; }

/* Resolve an algorithm handle (real or pseudo). Returns 0 on success. */
static NTSTATUS get_alg(BCRYPT_ALG_HANDLE h, unsigned *alg, int *hmac, int *reusable)
{
    ULONG_PTR v = (ULONG_PTR)h;
    *reusable = 0;
    if (v && v < 0x1000) {
        *hmac = 0;
        switch (v) {
        case PSEUDO_MD5: *alg = SHZ_H_MD5; return 0;
        case PSEUDO_SHA1: *alg = SHZ_H_SHA1; return 0;
        case PSEUDO_SHA256: *alg = SHZ_H_SHA256; return 0;
        case PSEUDO_SHA384: *alg = SHZ_H_SHA384; return 0;
        case PSEUDO_SHA512: *alg = SHZ_H_SHA512; return 0;
        case PSEUDO_RNG: *alg = 0; return 0;
        case PSEUDO_HMAC_MD5: *alg = SHZ_H_MD5; *hmac = 1; return 0;
        case PSEUDO_HMAC_SHA1: *alg = SHZ_H_SHA1; *hmac = 1; return 0;
        case PSEUDO_HMAC_SHA256: *alg = SHZ_H_SHA256; *hmac = 1; return 0;
        case PSEUDO_HMAC_SHA384: *alg = SHZ_H_SHA384; *hmac = 1; return 0;
        case PSEUDO_HMAC_SHA512: *alg = SHZ_H_SHA512; *hmac = 1; return 0;
        }
        return STATUS_INVALID_HANDLE;
    }
    if (!h || ((alg_obj *)h)->magic != ALG_MAGIC) return STATUS_INVALID_HANDLE;
    *alg = ((alg_obj *)h)->alg;
    *hmac = (int)((alg_obj *)h)->hmac;
    *reusable = (int)((alg_obj *)h)->reusable;
    return 0;
}

DLLAPI NTSTATUS WINAPI BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *out, LPCWSTR id, LPCWSTR impl, ULONG flags)
{
    alg_obj *a;
    unsigned alg = 0;
    int i, found = 0;
    if (!out || !id) return STATUS_INVALID_PARAMETER;
    if (flags & ~(ULONG)(BCRYPT_PROV_DISPATCH | BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_CAPI_AES_FLAG | BCRYPT_HASH_REUSABLE_FLAG))
        return STATUS_INVALID_PARAMETER;
    if (impl && !weq_i(impl, MS_PRIMITIVE_PROVIDER)) return STATUS_NOT_FOUND;
    for (i = 0; i < (int)(sizeof algs / sizeof algs[0]); ++i)
        if (weq_i(id, algs[i].name)) { alg = algs[i].alg; found = 1; }
    if (!found && weq_i(id, BCRYPT_RNG_ALGORITHM)) {
        if (flags & (BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG)) return STATUS_INVALID_PARAMETER;
        found = 1;
    }
    if (!found) return known_unsupported(id) ? STATUS_NOT_SUPPORTED : STATUS_NOT_FOUND;
    a = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *a);
    if (!a) return STATUS_NO_MEMORY;
    a->magic = ALG_MAGIC;
    a->alg = alg;
    a->hmac = (flags & BCRYPT_ALG_HANDLE_HMAC_FLAG) ? 1 : 0;
    a->reusable = (flags & BCRYPT_HASH_REUSABLE_FLAG) ? 1 : 0;
    *out = a;
    return STATUS_SUCCESS;
}

DLLAPI NTSTATUS WINAPI BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE h, ULONG flags)
{
    if (flags) return STATUS_INVALID_PARAMETER;
    if ((ULONG_PTR)h && (ULONG_PTR)h < 0x1000) return STATUS_SUCCESS;          /* pseudo handle: nothing to release */
    if (!h || ((alg_obj *)h)->magic != ALG_MAGIC) return STATUS_INVALID_HANDLE;
    ((alg_obj *)h)->magic = 0;
    HeapFree(GetProcessHeap(), 0, h);
    return STATUS_SUCCESS;
}

static NTSTATUS return_bytes(const void *src, ULONG n, PUCHAR out, ULONG cap, ULONG *result)
{
    if (!result) return STATUS_INVALID_PARAMETER;
    *result = n;
    if (!out) return STATUS_SUCCESS;                    /* documented: NULL buffer queries the required size */
    if (cap < n) return STATUS_BUFFER_TOO_SMALL;
    memcpy(out, src, n);
    return STATUS_SUCCESS;
}

DLLAPI NTSTATUS WINAPI BCryptGetProperty(BCRYPT_HANDLE h, LPCWSTR prop, PUCHAR out, ULONG cap, ULONG *result, ULONG flags)
{
    unsigned alg;
    int hmac, reusable;
    NTSTATUS st;
    ULONG v;
    if (!prop) return STATUS_INVALID_PARAMETER;
    if (flags) return STATUS_INVALID_PARAMETER;
    if (h && (ULONG_PTR)h >= 0x1000 && ((hash_obj *)h)->magic == HASH_MAGIC) { alg = ((hash_obj *)h)->alg; hmac = (int)((hash_obj *)h)->hmac; reusable = (int)((hash_obj *)h)->reusable; }
    else if ((st = get_alg(h, &alg, &hmac, &reusable)) != 0) return st;
    if (weq_i(prop, BCRYPT_ALGORITHM_NAME)) {
        int i;
        if (!alg) return return_bytes(L"RNG", 4 * sizeof(WCHAR), out, cap, result);
        for (i = 0; i < (int)(sizeof algs / sizeof algs[0]); ++i)
            if (algs[i].alg == alg) {
                ULONG n = 0;
                while (algs[i].name[n]) ++n;
                return return_bytes(algs[i].name, (n + 1) * sizeof(WCHAR), out, cap, result);
            }
        return STATUS_NOT_SUPPORTED;
    }
    if (!alg) return STATUS_NOT_SUPPORTED;              /* the RNG has no hash properties */
    if (weq_i(prop, BCRYPT_OBJECT_LENGTH)) v = (ULONG)sizeof(hash_obj);
    else if (weq_i(prop, BCRYPT_HASH_LENGTH)) v = (ULONG)shz_hash_digest_len(alg);
    else if (weq_i(prop, BCRYPT_HASH_BLOCK_LENGTH)) v = (ULONG)shz_hash_block_len(alg);
    else if (weq_i(prop, BCRYPT_IS_REUSABLE_HASH)) v = (ULONG)(reusable != 0);
    else return STATUS_NOT_SUPPORTED;
    return return_bytes(&v, sizeof v, out, cap, result);
}

/* ---------------------------------------------------------------- hashing */
static void obj_start(hash_obj *o, const void *key, size_t keylen)
{
    if (o->hmac) shz_hmac_init(&o->cur.m, o->alg, key, keylen);
    else shz_hash_init(&o->cur.h, o->alg);
    o->init = o->cur;
    o->finished = 0;
}

static NTSTATUS get_hash(BCRYPT_HASH_HANDLE h, hash_obj **o)
{
    if (!h || (ULONG_PTR)h < 0x1000 || ((hash_obj *)h)->magic != HASH_MAGIC) return STATUS_INVALID_HANDLE;
    *o = h;
    return STATUS_SUCCESS;
}

DLLAPI NTSTATUS WINAPI BCryptCreateHash(BCRYPT_ALG_HANDLE ha, BCRYPT_HASH_HANDLE *out, PUCHAR obj, ULONG cbobj, PUCHAR secret,
                                        ULONG cbsecret, ULONG flags)
{
    unsigned alg;
    int hmac, reusable;
    hash_obj *o;
    NTSTATUS st = get_alg(ha, &alg, &hmac, &reusable);
    if (st) return st;
    if (!alg) return STATUS_NOT_SUPPORTED;               /* an RNG handle cannot hash */
    if (!out) return STATUS_INVALID_PARAMETER;
    if (flags & ~(ULONG)BCRYPT_HASH_REUSABLE_FLAG) return STATUS_INVALID_PARAMETER;
    if (obj && cbobj < sizeof(hash_obj)) return STATUS_BUFFER_TOO_SMALL;
    if (!secret && cbsecret) return STATUS_INVALID_PARAMETER;
    o = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *o);
    if (!o) return STATUS_NO_MEMORY;
    o->magic = HASH_MAGIC;
    o->alg = alg;
    o->hmac = (ULONG)hmac;
    o->reusable = (reusable || (flags & BCRYPT_HASH_REUSABLE_FLAG)) ? 1 : 0;
    obj_start(o, secret, hmac ? cbsecret : 0);
    *out = o;
    return STATUS_SUCCESS;
}

DLLAPI NTSTATUS WINAPI BCryptHashData(BCRYPT_HASH_HANDLE h, PUCHAR in, ULONG cb, ULONG flags)
{
    hash_obj *o;
    NTSTATUS st = get_hash(h, &o);
    if (st) return st;
    if (flags || (!in && cb)) return STATUS_INVALID_PARAMETER;
    if (o->finished) return STATUS_INVALID_PARAMETER;
    if (o->hmac) shz_hmac_update(&o->cur.m, in, cb);
    else shz_hash_update(&o->cur.h, in, cb);
    return STATUS_SUCCESS;
}

DLLAPI NTSTATUS WINAPI BCryptFinishHash(BCRYPT_HASH_HANDLE h, PUCHAR out, ULONG cb, ULONG flags)
{
    hash_obj *o;
    NTSTATUS st = get_hash(h, &o);
    if (st) return st;
    if (flags || !out || cb != shz_hash_digest_len(o->alg)) return STATUS_INVALID_PARAMETER;
    if (o->finished) return STATUS_INVALID_PARAMETER;
    if (o->hmac) shz_hmac_final(&o->cur.m, out);
    else shz_hash_final(&o->cur.h, out);
    if (o->reusable) o->cur = o->init;                  /* BCRYPT_HASH_REUSABLE_FLAG: ready for a new message */
    else { wipe(&o->cur, sizeof o->cur); wipe(&o->init, sizeof o->init); o->finished = 1; }
    return STATUS_SUCCESS;
}

DLLAPI NTSTATUS WINAPI BCryptDuplicateHash(BCRYPT_HASH_HANDLE h, BCRYPT_HASH_HANDLE *out, PUCHAR obj, ULONG cbobj, ULONG flags)
{
    hash_obj *o, *n;
    NTSTATUS st = get_hash(h, &o);
    if (st) return st;
    if (flags || !out) return STATUS_INVALID_PARAMETER;
    if (obj && cbobj < sizeof(hash_obj)) return STATUS_BUFFER_TOO_SMALL;
    n = HeapAlloc(GetProcessHeap(), 0, sizeof *n);
    if (!n) return STATUS_NO_MEMORY;
    *n = *o;
    *out = n;
    return STATUS_SUCCESS;
}

DLLAPI NTSTATUS WINAPI BCryptDestroyHash(BCRYPT_HASH_HANDLE h)
{
    hash_obj *o;
    NTSTATUS st = get_hash(h, &o);
    if (st) return st;
    wipe(o, sizeof *o);                                  /* also clears the HMAC key material */
    HeapFree(GetProcessHeap(), 0, o);
    return STATUS_SUCCESS;
}

DLLAPI NTSTATUS WINAPI BCryptHash(BCRYPT_ALG_HANDLE ha, PUCHAR secret, ULONG cbsecret, PUCHAR in, ULONG cbin, PUCHAR out,
                                  ULONG cbout)
{
    unsigned alg;
    int hmac, reusable;
    NTSTATUS st = get_alg(ha, &alg, &hmac, &reusable);
    if (st) return st;
    if (!alg) return STATUS_NOT_SUPPORTED;
    if (!out || cbout != shz_hash_digest_len(alg) || (!in && cbin) || (!secret && cbsecret)) return STATUS_INVALID_PARAMETER;
    if (hmac) {
        shz_hmac_ctx c;
        shz_hmac_init(&c, alg, secret, cbsecret);
        shz_hmac_update(&c, in, cbin);
        shz_hmac_final(&c, out);
        wipe(&c, sizeof c);
    } else {
        shz_hash_ctx c;
        shz_hash_init(&c, alg);
        shz_hash_update(&c, in, cbin);
        shz_hash_final(&c, out);
    }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- random numbers */
DLLAPI NTSTATUS WINAPI BCryptGenRandom(BCRYPT_ALG_HANDLE ha, PUCHAR buf, ULONG cb, ULONG flags)
{
    if (flags & ~(ULONG)(BCRYPT_RNG_USE_ENTROPY_IN_BUFFER | BCRYPT_USE_SYSTEM_PREFERRED_RNG)) return STATUS_INVALID_PARAMETER;
    if (ha) {
        unsigned alg;
        int hmac, reusable;
        NTSTATUS st;
        if (flags & BCRYPT_USE_SYSTEM_PREFERRED_RNG) return STATUS_INVALID_PARAMETER;      /* hAlgorithm must be NULL */
        st = get_alg(ha, &alg, &hmac, &reusable);
        if (st) return st;
        if (alg) return STATUS_INVALID_HANDLE;           /* not an RNG provider */
    }
    if (!cb) return STATUS_SUCCESS;
    if (!buf) return STATUS_INVALID_PARAMETER;
    /* BCRYPT_RNG_USE_ENTROPY_IN_BUFFER is ignored since Windows 8; the buffer is overwritten, never read. */
    if (!shz_random_bytes(buf, cb)) {
        memset(buf, 0, cb);                              /* never hand back partially random data */
        return STATUS_NOT_SUPPORTED;                     /* no RDRAND: there is no other entropy source */
    }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- PBKDF2 */
DLLAPI NTSTATUS WINAPI BCryptDeriveKeyPBKDF2(BCRYPT_ALG_HANDLE hprf, PUCHAR pw, ULONG cbpw, PUCHAR salt, ULONG cbsalt,
                                             ULONGLONG iterations, PUCHAR dk, ULONG cbdk, ULONG flags)
{
    unsigned alg;
    int hmac, reusable;
    NTSTATUS st = get_alg(hprf, &alg, &hmac, &reusable);
    if (st) return st;
    if (!alg || !hmac) return STATUS_INVALID_HANDLE;    /* the PRF must be an HMAC-flagged hash provider */
    if (flags || !dk || !cbdk || !iterations || (!pw && cbpw) || (!salt && cbsalt)) return STATUS_INVALID_PARAMETER;
    if (shz_pbkdf2(alg, pw, cbpw, salt, cbsalt, iterations, dk, cbdk)) return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}
