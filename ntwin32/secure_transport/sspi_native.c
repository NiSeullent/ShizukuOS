/* SPDX-License-Identifier: GPL-2.0-only
 * Explicit-loading Win98 ANSI outbound SSPI ABI over the real TLS 1.3 core.
 * Caller buffer pointers must address readable/writable caller memory, as for
 * ordinary C SSPI. Handles are numbers: no caller-supplied handle is dereferenced.
 */
#define _NO_KSECDD_IMPORT_ 1 /* Implementing exports, not importing secur32. */
#include "sspi_native.h"
#include "sspi_stream.h"
#include "native_runtime.h"
#include "transport.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
_Static_assert(sizeof(void *) == 4, "M98SSPI is a Win98 x86 ABI");
_Static_assert(sizeof(SecHandle) == 8 && sizeof(SecBuffer) == 12 &&
               sizeof(SecBufferDesc) == 12, "SSPI descriptor ABI changed");
_Static_assert(sizeof(SecPkgContext_StreamSizes) == 20 && sizeof(SCHANNEL_CRED) == 56 &&
               sizeof(M98SSPI_PRIVATE_CRED) == 24, "credential/attribute ABI changed");
_Static_assert(offsetof(SecurityFunctionTableA, EncryptMessage) == 100 &&
               offsetof(SecurityFunctionTableA, DecryptMessage) == 104,
               "SSPI function-table ABI changed");
#endif

#define CRED_KIND UINT32_C(0x4d430000)
#define CONTEXT_KIND UINT32_C(0x4d580000)
#define ALLOCATIONS 64u
#define MAX_ROOTS 512u
#define ROOT_DER_LIMIT 65536u
#define REQ_SUPPORTED (ISC_REQ_STREAM | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY | \
                       ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | \
                       ISC_REQ_CONNECTION | ISC_REQ_ALLOCATE_MEMORY)
#define RET_SECURITY (ISC_RET_STREAM | ISC_RET_CONFIDENTIALITY | ISC_RET_INTEGRITY | \
                      ISC_RET_REPLAY_DETECT | ISC_RET_SEQUENCE_DETECT | ISC_RET_CONNECTION)

typedef struct credential {
    unsigned char *ca;
    size_t ca_size;
    uint32_t generation;
    unsigned refs;
    int active;
} credential;
typedef struct native_context {
    int used, shutdown, control_pending, handshake_pending;
    uint32_t generation;
    unsigned credential_slot;
    ULONG requirements;
    ntwssp_handle core;
    char hostname[254];
    unsigned char control[NTWSSP_MAX_TOKEN];
    size_t control_size;
    unsigned char plaintext[NTWSSP_MAX_PLAINTEXT];
} native_context;
typedef struct allocation { void *data; size_t size; } allocation;
static CRITICAL_SECTION lock;
static int lock_ready, runtime_ready, runtime_failed;
static ntwssp_pool *pool;
static credential credentials[M98SSPI_MAX_CREDENTIALS];
static native_context contexts[NTWSSP_MAX_CONTEXTS];
static allocation allocations[ALLOCATIONS];
static uint32_t next_generation;

static void wipe(void *data, size_t size)
{
    volatile unsigned char *p = data;
    while (size--) *p++ = 0;
}
static int range_valid(const void *p, size_t n)
{ return (!n || p) && (uintptr_t)p <= UINTPTR_MAX - n; }
static int overlap(const void *a, size_t an, const void *b, size_t bn)
{
    return an && bn && (uintptr_t)a < (uintptr_t)b + bn &&
           (uintptr_t)b < (uintptr_t)a + an;
}
static int enter(void)
{
    if (!lock_ready) return 0;
    EnterCriticalSection(&lock);
    return 1;
}
static void leave(void) { LeaveCriticalSection(&lock); }
static void invalidate(PSecHandle h)
{ if (h) { h->dwLower = (ULONG_PTR)-1; h->dwUpper = (ULONG_PTR)-1; } }
static void make_handle(PSecHandle h, uint32_t kind, unsigned slot, uint32_t generation)
{ h->dwLower = kind | (slot + 1); h->dwUpper = generation; }
static credential *get_credential(PCredHandle h)
{
    ULONG_PTR n;
    credential *c;
    if (!h || h->dwUpper == 0 || h->dwUpper > UINT32_MAX) return NULL;
    n = h->dwLower;
    if ((n & ~(ULONG_PTR)0xffffu) != CRED_KIND || !(n & 0xffffu) ||
        (n & 0xffffu) > M98SSPI_MAX_CREDENTIALS) return NULL;
    c = &credentials[(n & 0xffffu) - 1];
    return c->active && c->generation == h->dwUpper ? c : NULL;
}
static native_context *get_context(PCtxtHandle h)
{
    ULONG_PTR n;
    native_context *c;
    if (!h || h->dwUpper == 0 || h->dwUpper > UINT32_MAX) return NULL;
    n = h->dwLower;
    if ((n & ~(ULONG_PTR)0xffffu) != CONTEXT_KIND || !(n & 0xffffu) ||
        (n & 0xffffu) > NTWSSP_MAX_CONTEXTS) return NULL;
    c = &contexts[(n & 0xffffu) - 1];
    return c->used && c->generation == h->dwUpper ? c : NULL;
}
static int text_equal(const char *a, const char *b)
{
    size_t i;
    if (!a || !b) return 0;
    for (i = 0; i < 254; ++i) {
        unsigned char x = (unsigned char)a[i], y = (unsigned char)b[i];
        if (x >= 'A' && x <= 'Z') x += 'a' - 'A';
        if (y >= 'A' && y <= 'Z') y += 'a' - 'A';
        if (x != y) return 0;
        if (!x) return 1;
    }
    return 0;
}
static int package_valid(const char *s)
{
    return text_equal(s, M98SSPI_PACKAGE_A) || text_equal(s, "Schannel") ||
           text_equal(s, "Microsoft Unified Security Protocol Provider");
}
static int copy_hostname(char *out, const char *s)
{
    size_t i, label = 0;
    int letter = 0;
    if (!s) return 0;
    for (i = 0; i <= 253; ++i) {
        unsigned char ch = (unsigned char)s[i];
        if (!ch) { out[i] = 0; return i && label && s[i - 1] != '-' && letter; }
        if (ch == '.') { if (!label || s[i - 1] == '-') return 0; label = 0; }
        else {
            if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) letter = 1;
            else if (!(ch >= '0' && ch <= '9') && ch != '-') return 0;
            if ((!label && ch == '-') || ++label > 63) return 0;
        }
        out[i] = (char)ch;
    }
    return 0;
}
static void expiry(PTimeStamp out)
{ if (out) { out->LowPart = UINT32_MAX; out->HighPart = INT32_MAX; } }
static void *allocate_buffer(size_t size)
{
    unsigned i;
    void *p;
    if (!size || size > NTWSSP_MAX_TOKEN) return NULL;
    for (i = 0; i < ALLOCATIONS && allocations[i].data; ++i) ;
    if (i == ALLOCATIONS) return NULL;
    p = calloc(1, size);
    if (!p) return NULL;
    allocations[i].data = p;
    allocations[i].size = size;
    return p;
}
static int free_buffer(void *p)
{
    unsigned i;
    for (i = 0; i < ALLOCATIONS; ++i) if (p && allocations[i].data == p) {
        wipe(p, allocations[i].size);
        free(p);
        allocations[i].data = NULL;
        allocations[i].size = 0;
        return 1;
    }
    return 0;
}
static void drop_credential(credential *c)
{
    if (c->active || c->refs) return;
    if (c->ca) { wipe(c->ca, c->ca_size); free(c->ca); }
    memset(c, 0, sizeof *c);
}
static void maybe_stop_runtime(void)
{
    unsigned i;
    for (i = 0; i < M98SSPI_MAX_CREDENTIALS; ++i)
        if (credentials[i].active || credentials[i].refs) return;
    for (i = 0; i < NTWSSP_MAX_CONTEXTS; ++i) if (contexts[i].used) return;
    if (pool) { ntwssp_pool_destroy(pool); pool = NULL; }
    if (runtime_ready) {
        if (ntwst_native_runtime_fini() == NTWST_OK) runtime_ready = 0;
        else runtime_failed = 1; /* Never reuse a partially finalized PSA/RNG. */
    }
}
static SECURITY_STATUS ensure_runtime(void)
{
    int status;
    if (runtime_failed) return SEC_E_INTERNAL_ERROR;
    if (!runtime_ready) {
        status = ntwst_native_runtime_init();
        if (status != NTWST_OK) return SEC_E_INTERNAL_ERROR;
        runtime_ready = 1;
    }
    if (!pool && ntwssp_pool_create(&pool) != NTWSSP_OK) {
        maybe_stop_runtime();
        return SEC_E_INSUFFICIENT_MEMORY;
    }
    return SEC_E_OK;
}

/* Encode actual native DER certificate bytes; no URL retrieval, hardcoded CA
 * or CryptoAPI extension introduced after Win98. Bounds fail the entire policy
 * rather than silently trusting a truncated ROOT store. Enumeration frees the
 * previous context; an early exit frees the current one explicitly. */
static SECURITY_STATUS root_bundle(unsigned char **out, size_t *out_size)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const char begin[] = "-----BEGIN CERTIFICATE-----\n";
    static const char end[] = "-----END CERTIFICATE-----\n";
    HCERTSTORE store;
    PCCERT_CONTEXT cert = NULL;
    unsigned char *bytes = NULL, *grown;
    size_t used = 0, capacity = 0, n, need, i, column;
    unsigned count = 0;
    SECURITY_STATUS result = SEC_E_INTERNAL_ERROR;
    *out = NULL; *out_size = 0;
    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                          CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG |
                          CERT_STORE_READONLY_FLAG, "ROOT");
    if (!store) return SEC_E_NO_CREDENTIALS;
    for (;;) {
        cert = CertEnumCertificatesInStore(store, cert);
        if (!cert) {
            if (GetLastError() != (DWORD)CRYPT_E_NOT_FOUND) goto done;
            result = count ? SEC_E_OK : SEC_E_NO_CREDENTIALS;
            break;
        }
        n = cert->cbCertEncoded;
        if (++count > MAX_ROOTS || !(cert->dwCertEncodingType & X509_ASN_ENCODING) ||
            !n || n > ROOT_DER_LIMIT || !range_valid(cert->pbCertEncoded, n)) {
            result = SEC_E_INVALID_TOKEN; goto done;
        }
        need = ((n + 2) / 3) * 4;
        need += (need + 63) / 64 + sizeof begin - 1 + sizeof end - 1;
        if (need > M98SSPI_MAX_CA - used - 1) { result = SEC_E_INSUFFICIENT_MEMORY; goto done; }
        if (used + need + 1 > capacity) {
            size_t target = capacity ? capacity : 4096;
            while (target < used + need + 1 && target < M98SSPI_MAX_CA) target *= 2;
            if (target > M98SSPI_MAX_CA) target = M98SSPI_MAX_CA;
            grown = realloc(bytes, target);
            if (!grown) { result = SEC_E_INSUFFICIENT_MEMORY; goto done; }
            bytes = grown; capacity = target;
        }
        memcpy(bytes + used, begin, sizeof begin - 1); used += sizeof begin - 1;
        column = 0;
        for (i = 0; i < n; i += 3) {
            uint32_t word = (uint32_t)cert->pbCertEncoded[i] << 16;
            if (i + 1 < n) word |= (uint32_t)cert->pbCertEncoded[i + 1] << 8;
            if (i + 2 < n) word |= cert->pbCertEncoded[i + 2];
            bytes[used++] = alphabet[(word >> 18) & 63];
            bytes[used++] = alphabet[(word >> 12) & 63];
            bytes[used++] = i + 1 < n ? (unsigned char)alphabet[(word >> 6) & 63] : '=';
            bytes[used++] = i + 2 < n ? (unsigned char)alphabet[word & 63] : '=';
            column += 4;
            if (column == 64 || i + 3 >= n) { bytes[used++] = '\n'; column = 0; }
        }
        memcpy(bytes + used, end, sizeof end - 1); used += sizeof end - 1;
        bytes[used] = 0;
    }
done:
    if (cert) CertFreeCertificateContext(cert);
    if (!CertCloseStore(store, 0)) result = SEC_E_INTERNAL_ERROR;
    if (result == SEC_E_OK) { *out = bytes; *out_size = used + 1; }
    else if (bytes) { wipe(bytes, capacity); free(bytes); }
    return result;
}
static SECURITY_STATUS trust_bundle(void *auth, unsigned char **out, size_t *size)
{
    ULONG version;
    *out = NULL; *size = 0;
    if (!auth) return root_bundle(out, size);
    memcpy(&version, auth, sizeof version);
    if (version == M98SSPI_PRIVATE_CRED_VERSION) {
        const M98SSPI_PRIVATE_CRED *c = auth;
        if (c->cbSize != sizeof *c || c->dwFlags || c->reserved || !c->cbCa ||
            c->cbCa > M98SSPI_MAX_CA || !range_valid(c->ca, c->cbCa)) return SEC_E_INVALID_TOKEN;
        *out = malloc(c->cbCa);
        if (!*out) return SEC_E_INSUFFICIENT_MEMORY;
        memcpy(*out, c->ca, c->cbCa); *size = c->cbCa;
        return SEC_E_OK;
    }
    if (version == SCHANNEL_CRED_VERSION) {
        const SCHANNEL_CRED *c = auth;
        if (c->cCreds || c->paCred || c->hRootStore || c->cMappers || c->aphMappers ||
            c->cSupportedAlgs || c->palgSupportedAlgs || c->dwMinimumCipherStrength ||
            c->dwMaximumCipherStrength || c->dwSessionLifespan || c->dwCredFormat ||
            (c->grbitEnabledProtocols && c->grbitEnabledProtocols != SP_PROT_TLS1_3_CLIENT) ||
            (c->dwFlags & ~(SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_AUTO_CRED_VALIDATION)))
            return SEC_E_UNSUPPORTED_FUNCTION;
        return root_bundle(out, size);
    }
    return SEC_E_UNSUPPORTED_FUNCTION;
}
static SECURITY_STATUS translate(native_context *c, int status)
{
    ntwssp_info info;
    switch (status) {
    case NTWSSP_OK: return SEC_E_OK;
    case NTWSSP_CONTINUE: return SEC_I_CONTINUE_NEEDED;
    case NTWSSP_INCOMPLETE: return SEC_E_INCOMPLETE_MESSAGE;
    case NTWSSP_CLOSED: return SEC_I_CONTEXT_EXPIRED;
    case NTWSSP_BUFFER_TOO_SMALL: return SEC_E_BUFFER_TOO_SMALL;
    case NTWSSP_INVALID: return SEC_E_INVALID_TOKEN;
    case NTWSSP_LIMIT: case NTWSSP_NO_MEMORY: return SEC_E_INSUFFICIENT_MEMORY;
    case NTWSSP_STATE: case NTWSSP_BUSY: return SEC_E_OUT_OF_SEQUENCE;
    case NTWSSP_TRUNCATED: return SEC_E_ILLEGAL_MESSAGE;
    case NTWSSP_VERIFY:
        if (ntwssp_query(pool, c->core, &info) == NTWSSP_OK) {
            if (info.verify_flags & (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE))
                return SEC_E_CERT_EXPIRED;
            if (info.verify_flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) return SEC_E_WRONG_PRINCIPAL;
            if (info.verify_flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) return SEC_E_UNTRUSTED_ROOT;
        }
        return SEC_E_CERT_UNKNOWN;
    case NTWSSP_ENGINE:
        if (ntwssp_query(pool, c->core, &info) == NTWSSP_OK &&
            info.backend_error == MBEDTLS_ERR_SSL_INVALID_MAC) return SEC_E_MESSAGE_ALTERED;
        return SEC_E_ILLEGAL_MESSAGE;
    default: return SEC_E_INTERNAL_ERROR;
    }
}
static SECURITY_STATUS descriptor(PSecBufferDesc d, unsigned min, unsigned max)
{
    unsigned i;
    if (!d || d->ulVersion != SECBUFFER_VERSION || d->cBuffers < min || d->cBuffers > max ||
        !range_valid(d->pBuffers, d->cBuffers * sizeof *d->pBuffers)) return SEC_E_INVALID_TOKEN;
    for (i = 0; i < d->cBuffers; ++i) {
        PSecBuffer b = &d->pBuffers[i];
        if (b->BufferType & SECBUFFER_ATTRMASK) return SEC_E_UNSUPPORTED_FUNCTION;
        if (!range_valid(b->pvBuffer, b->cbBuffer)) return SEC_E_INVALID_TOKEN;
    }
    return SEC_E_OK;
}
static SECURITY_STATUS input_token(PSecBufferDesc d, ntwssp_input *in, PSecBuffer *feedback)
{
    SECURITY_STATUS status;
    unsigned i, found = 0;
    memset(in, 0, sizeof *in); *feedback = NULL;
    if (!d) return SEC_E_OK;
    status = descriptor(d, 2, 4);
    if (status != SEC_E_OK) return status;
    for (i = 0; i < d->cBuffers; ++i) {
        PSecBuffer b = &d->pBuffers[i];
        if (b->BufferType == SECBUFFER_TOKEN && !found++) {
            if (b->cbBuffer > NTWSSP_MAX_TOKEN) return SEC_E_INVALID_TOKEN;
            in->data = b->pvBuffer; in->size = b->cbBuffer;
        } else if (b->BufferType == SECBUFFER_EMPTY && !b->pvBuffer && !b->cbBuffer) {
            if (!*feedback) *feedback = b;
        } else return SEC_E_INVALID_TOKEN;
    }
    return found == 1 && *feedback ? SEC_E_OK : SEC_E_INVALID_TOKEN;
}
static void feedback(PSecBuffer b, ntwssp_input *in)
{
    if (!b) return;
    if (in->consumed && in->consumed < in->size) {
        b->BufferType = SECBUFFER_EXTRA; b->cbBuffer = (ULONG)(in->size - in->consumed);
        b->pvBuffer = (void *)(in->data + in->consumed);
    } else if (in->missing) {
        b->BufferType = SECBUFFER_MISSING; b->cbBuffer = (ULONG)in->missing; b->pvBuffer = NULL;
    } else if (!in->consumed && in->size) {
        b->BufferType = SECBUFFER_EXTRA; b->cbBuffer = (ULONG)in->size; b->pvBuffer = (void *)in->data;
    }
}
static SECURITY_STATUS output_token(PSecBufferDesc d, ULONG req, PSecBuffer *token,
                                     ntwssp_buffer *out, int *allocated)
{
    unsigned i;
    SECURITY_STATUS status = descriptor(d, 1, 2);
    *token = NULL; *allocated = 0; memset(out, 0, sizeof *out);
    if (status != SEC_E_OK) return status;
    for (i = 0; i < d->cBuffers; ++i) {
        PSecBuffer b = &d->pBuffers[i];
        if (b->BufferType == SECBUFFER_TOKEN && !*token) *token = b;
        else if (b->BufferType != SECBUFFER_ALERT || b->cbBuffer || b->pvBuffer)
            return SEC_E_INVALID_TOKEN;
    }
    if (!*token) return SEC_E_INVALID_TOKEN;
    if (req & ISC_REQ_ALLOCATE_MEMORY) {
        if ((*token)->pvBuffer || (*token)->cbBuffer) return SEC_E_INVALID_TOKEN;
        out->data = allocate_buffer(NTWSSP_MAX_TOKEN);
        if (!out->data) return SEC_E_INSUFFICIENT_MEMORY;
        out->capacity = NTWSSP_MAX_TOKEN; *allocated = 1;
    } else {
        if ((*token)->cbBuffer > NTWSSP_MAX_TOKEN) return SEC_E_INVALID_TOKEN;
        out->data = (*token)->pvBuffer; out->capacity = (*token)->cbBuffer;
    }
    return SEC_E_OK;
}
static void finish_token(PSecBuffer token, ntwssp_buffer *out, int allocated, int status)
{
    if (allocated) {
        if (out->size) { token->pvBuffer = out->data; token->cbBuffer = (ULONG)out->size; }
        else { free_buffer(out->data); token->pvBuffer = NULL; token->cbBuffer = 0; }
    } else token->cbBuffer = (ULONG)(status == NTWSSP_BUFFER_TOO_SMALL ? out->required : out->size);
}

SECURITY_STATUS WINAPI AcquireCredentialsHandleA(SEC_CHAR *principal, SEC_CHAR *package,
    ULONG use, void *logon, void *auth, SEC_GET_KEY_FN get_key, void *key_arg,
    PCredHandle out, PTimeStamp expires)
{
    SECURITY_STATUS status;
    unsigned slot;
    unsigned char *ca = NULL;
    size_t ca_size = 0;
    if (!out) return SEC_E_INVALID_HANDLE;
    invalidate(out);
    if (!package_valid(package)) return SEC_E_SECPKG_NOT_FOUND;
    if (use != SECPKG_CRED_OUTBOUND || principal || logon || get_key || key_arg)
        return SEC_E_UNSUPPORTED_FUNCTION;
    if (!enter()) return SEC_E_INTERNAL_ERROR;
    for (slot = 0; slot < M98SSPI_MAX_CREDENTIALS && credentials[slot].ca; ++slot) ;
    if (slot == M98SSPI_MAX_CREDENTIALS || next_generation == UINT32_MAX)
        status = SEC_E_INSUFFICIENT_MEMORY;
    else {
        status = trust_bundle(auth, &ca, &ca_size);
        if (status == SEC_E_OK) status = ensure_runtime();
        if (status == SEC_E_OK) {
            credentials[slot].ca = ca; credentials[slot].ca_size = ca_size;
            credentials[slot].generation = ++next_generation;
            credentials[slot].active = 1;
            make_handle(out, CRED_KIND, slot, credentials[slot].generation);
            expiry(expires);
        } else if (ca) { wipe(ca, ca_size); free(ca); }
    }
    leave(); return status;
}
SECURITY_STATUS WINAPI FreeCredentialsHandle(PCredHandle h)
{
    credential *c;
    if (!enter()) return SEC_E_INTERNAL_ERROR;
    c = get_credential(h);
    if (!c) { leave(); return SEC_E_INVALID_HANDLE; }
    c->active = 0; invalidate(h); drop_credential(c); maybe_stop_runtime();
    leave(); return SEC_E_OK;
}
SECURITY_STATUS WINAPI InitializeSecurityContextA(PCredHandle cred, PCtxtHandle old,
    SEC_CHAR *target, ULONG req, ULONG reserved1, ULONG representation,
    PSecBufferDesc input, ULONG reserved2, PCtxtHandle out_handle,
    PSecBufferDesc output, ULONG *attrs, PTimeStamp expires)
{
    SECURITY_STATUS status;
    native_context *c = NULL;
    credential *credential_owner;
    ntwssp_input in;
    ntwssp_buffer token;
    PSecBuffer out_token, extra;
    unsigned slot;
    int allocated, result;
    char hostname[254];
    if (!out_handle || !attrs) return SEC_E_INVALID_HANDLE;
    *attrs = 0;
    memset(hostname, 0, sizeof hostname);
    if (reserved1 || reserved2 || representation || !(req & ISC_REQ_STREAM) ||
        (req & ~REQ_SUPPORTED)) return SEC_E_UNSUPPORTED_FUNCTION;
    status = input_token(input, &in, &extra);
    if (status != SEC_E_OK) return status;
    if (!enter()) return SEC_E_INTERNAL_ERROR;
    if (old) {
        c = get_context(old);
        if (!c) { leave(); return SEC_E_INVALID_HANDLE; }
        if ((req & ~ISC_REQ_ALLOCATE_MEMORY) != c->requirements ||
            (target && (!copy_hostname(hostname, target) || !text_equal(hostname, c->hostname)))) {
            leave(); return SEC_E_UNSUPPORTED_FUNCTION;
        }
        if (cred && (get_credential(cred) != &credentials[c->credential_slot])) {
            leave(); return SEC_E_INVALID_HANDLE;
        }
        if ((c->shutdown || c->control_pending) && in.size) { leave(); return SEC_E_INVALID_TOKEN; }
    } else {
        credential_owner = get_credential(cred);
        if (!credential_owner) { leave(); return SEC_E_INVALID_HANDLE; }
        if (input || !copy_hostname(hostname, target)) { leave(); return SEC_E_INVALID_TOKEN; }
        for (slot = 0; slot < NTWSSP_MAX_CONTEXTS && contexts[slot].used; ++slot) ;
        if (slot == NTWSSP_MAX_CONTEXTS || next_generation == UINT32_MAX) {
            leave(); return SEC_E_INSUFFICIENT_MEMORY;
        }
        c = &contexts[slot];
    }
    status = output_token(output, req, &out_token, &token, &allocated);
    if (status != SEC_E_OK) { leave(); return status; }
    if (!old) {
        ntwssp_options options;
        credential_owner = get_credential(cred);
        memset(&options, 0, sizeof options);
        options.hostname = hostname; options.ca = credential_owner->ca;
        options.ca_size = credential_owner->ca_size;
        result = ntwssp_create(pool, &options, &c->core);
        if (result != NTWSSP_OK) {
            if (allocated) free_buffer(token.data);
            invalidate(out_handle);
            leave(); return result == NTWSSP_NO_MEMORY || result == NTWSSP_LIMIT ?
                SEC_E_INSUFFICIENT_MEMORY : SEC_E_UNKNOWN_CREDENTIALS;
        }
        c->used = 1; c->generation = ++next_generation;
        c->requirements = req & ~ISC_REQ_ALLOCATE_MEMORY;
        c->credential_slot = (unsigned)(credential_owner - credentials);
        ++credential_owner->refs;
        memcpy(c->hostname, hostname, sizeof hostname);
    }
    make_handle(out_handle, CONTEXT_KIND, (unsigned)(c - contexts), c->generation);
    if (c->control_pending) {
        token.required = c->control_size;
        if (token.capacity < token.required) result = NTWSSP_BUFFER_TOO_SMALL;
        else {
            memcpy(token.data, c->control, c->control_size); token.size = c->control_size;
            wipe(c->control, c->control_size); c->control_size = 0; c->control_pending = 0;
            result = NTWSSP_OK;
        }
    } else if (c->shutdown) result = ntwssp_shutdown(pool, c->core, &token);
    else {
        result = ntwssp_handshake(pool, c->core, &in, &token);
        if (result == NTWSSP_BUFFER_TOO_SMALL) c->handshake_pending = 1;
        else if (result != NTWSSP_BUSY && result != NTWSSP_INVALID) c->handshake_pending = 0;
    }
    feedback(extra, &in);
    /* A consumed complete prefix plus incomplete retained tail needs EXTRA.
     * Report continuation now; resubmitting/reassembling that tail then yields
     * zero-consumption INCOMPLETE plus MISSING. Never pair INCOMPLETE with only
     * EXTRA or require the caller to replay a consumed handshake prefix. */
    if (result == NTWSSP_INCOMPLETE && in.consumed && in.consumed < in.size)
        result = NTWSSP_CONTINUE;
    finish_token(out_token, &token, allocated, result);
    status = translate(c, result);
    if (allocated && token.size) *attrs |= ISC_RET_ALLOCATED_MEMORY;
    if (status == SEC_E_OK) { *attrs |= RET_SECURITY; expiry(expires); }
    leave(); return status;
}
SECURITY_STATUS WINAPI DeleteSecurityContext(PCtxtHandle h)
{
    native_context *c;
    credential *owner;
    if (!enter()) return SEC_E_INTERNAL_ERROR;
    c = get_context(h);
    if (!c) { leave(); return SEC_E_INVALID_HANDLE; }
    if (ntwssp_delete(pool, c->core) != NTWSSP_OK) { leave(); return SEC_E_INTERNAL_ERROR; }
    owner = &credentials[c->credential_slot];
    --owner->refs; wipe(c, sizeof *c); invalidate(h); drop_credential(owner); maybe_stop_runtime();
    leave(); return SEC_E_OK;
}
SECURITY_STATUS WINAPI QueryContextAttributesA(PCtxtHandle h, ULONG attribute, void *out)
{
    native_context *c;
    ntwssp_sizes sizes;
    int result;
    SECURITY_STATUS status;
    if (!out) return SEC_E_INVALID_TOKEN;
    if (attribute != SECPKG_ATTR_STREAM_SIZES) return SEC_E_UNSUPPORTED_FUNCTION;
    if (!enter()) return SEC_E_INTERNAL_ERROR;
    c = get_context(h);
    if (!c) { leave(); return SEC_E_INVALID_HANDLE; }
    if (c->handshake_pending) { leave(); return SEC_E_OUT_OF_SEQUENCE; }
    result = ntwssp_stream_sizes(pool, c->core, &sizes);
    status = translate(c, result);
    if (status == SEC_E_OK) {
        SecPkgContext_StreamSizes *s = out;
        s->cbHeader = (ULONG)sizes.header; s->cbTrailer = (ULONG)sizes.trailer;
        s->cbMaximumMessage = (ULONG)sizes.maximum_message;
        s->cBuffers = sizes.buffers; s->cbBlockSize = sizes.block_size;
    }
    leave(); return status;
}
SECURITY_STATUS WINAPI EncryptMessage(PCtxtHandle h, ULONG qop, PSecBufferDesc d, ULONG sequence)
{
    native_context *c;
    PSecBuffer head = NULL, data = NULL, tail = NULL;
    ntwssp_buffer bh, bd, bt;
    SECURITY_STATUS status;
    int result;
    unsigned i;
    if (qop || sequence) return SEC_E_UNSUPPORTED_FUNCTION;
    status = descriptor(d, 4, 4);
    if (status != SEC_E_OK) return status;
    for (i = 0; i < d->cBuffers; ++i) {
        PSecBuffer b = &d->pBuffers[i];
        if (b->BufferType == SECBUFFER_STREAM_HEADER && !head) head = b;
        else if (b->BufferType == SECBUFFER_DATA && !data) data = b;
        else if (b->BufferType == SECBUFFER_STREAM_TRAILER && !tail) tail = b;
        else if (b->BufferType != SECBUFFER_EMPTY || b->cbBuffer || b->pvBuffer)
            return SEC_E_INVALID_TOKEN;
    }
    if (!head || !data || !tail || !data->cbBuffer || data->cbBuffer > NTWSSP_MAX_MESSAGE)
        return SEC_E_INVALID_TOKEN;
    if (overlap(head->pvBuffer, head->cbBuffer, data->pvBuffer, data->cbBuffer) ||
        overlap(head->pvBuffer, head->cbBuffer, tail->pvBuffer, tail->cbBuffer) ||
        overlap(data->pvBuffer, data->cbBuffer, tail->pvBuffer, tail->cbBuffer))
        return SEC_E_INVALID_TOKEN;
    if (!enter()) return SEC_E_INTERNAL_ERROR;
    c = get_context(h);
    if (!c) { leave(); return SEC_E_INVALID_HANDLE; }
    if (c->shutdown || c->control_pending) { leave(); return SEC_E_CONTEXT_EXPIRED; }
    memset(&bh, 0, sizeof bh); memset(&bd, 0, sizeof bd); memset(&bt, 0, sizeof bt);
    bh.data = head->pvBuffer; bh.capacity = head->cbBuffer;
    bd.data = data->pvBuffer; bd.capacity = bd.size = data->cbBuffer;
    bt.data = tail->pvBuffer; bt.capacity = tail->cbBuffer;
    result = ntwssp_encrypt(pool, c->core, &bh, &bd, &bt);
    status = translate(c, result);
    if (status == SEC_E_OK) {
        head->cbBuffer = (ULONG)bh.size; data->cbBuffer = (ULONG)bd.size; tail->cbBuffer = (ULONG)bt.size;
    } else if (status == SEC_E_BUFFER_TOO_SMALL) {
        head->cbBuffer = (ULONG)bh.required; tail->cbBuffer = (ULONG)bt.required;
    }
    leave(); return status;
}
SECURITY_STATUS WINAPI DecryptMessage(PCtxtHandle h, PSecBufferDesc d, ULONG sequence, ULONG *qop)
{
    native_context *c;
    PSecBuffer data = NULL, empty[3];
    unsigned empties = 0, i;
    ntwssp_input in;
    ntwssp_buffer out, control;
    SECURITY_STATUS status;
    int result, token_status;
    if (qop) *qop = 0;
    if (sequence) return SEC_E_UNSUPPORTED_FUNCTION;
    status = descriptor(d, 4, 4);
    if (status != SEC_E_OK) return status;
    for (i = 0; i < 4; ++i) {
        PSecBuffer b = &d->pBuffers[i];
        if (b->BufferType == SECBUFFER_DATA && !data) data = b;
        else if (b->BufferType == SECBUFFER_EMPTY && !b->cbBuffer && !b->pvBuffer && empties < 3)
            empty[empties++] = b;
        else return SEC_E_INVALID_TOKEN;
    }
    if (!data || empties != 3 || data->cbBuffer > NTWSSP_MAX_TOKEN) return SEC_E_INVALID_TOKEN;
    if (!enter()) return SEC_E_INTERNAL_ERROR;
    c = get_context(h);
    if (!c) { leave(); return SEC_E_INVALID_HANDLE; }
    if (c->control_pending) { leave(); return SEC_I_RENEGOTIATE; }
    memset(&in, 0, sizeof in); memset(&out, 0, sizeof out);
    in.data = data->pvBuffer; in.size = data->cbBuffer;
    out.data = c->plaintext; out.capacity = sizeof c->plaintext;
    result = ntwssp_decrypt(pool, c->core, &in, &out);
    status = translate(c, result);
    if (status == SEC_E_INCOMPLETE_MESSAGE) feedback(empty[0], &in);
    else if (result == NTWSSP_CLOSED && !in.consumed) {
        /* Repeated reads after an authenticated close stay idempotently closed. */
    } else if (result == NTWSSP_OK || result == NTWSSP_CONTINUE || result == NTWSSP_CLOSED) {
        if (in.consumed < NTWSSP_HEADER_SIZE || in.consumed > in.size ||
            out.size > in.consumed - NTWSSP_HEADER_SIZE) status = SEC_E_INTERNAL_ERROR;
        else {
            unsigned char *base = data->pvBuffer;
            if (out.size) memcpy(base + NTWSSP_HEADER_SIZE, c->plaintext, out.size);
            data->BufferType = SECBUFFER_STREAM_HEADER; data->cbBuffer = NTWSSP_HEADER_SIZE;
            empty[0]->BufferType = SECBUFFER_DATA; empty[0]->pvBuffer = base + NTWSSP_HEADER_SIZE;
            empty[0]->cbBuffer = (ULONG)out.size;
            empty[1]->BufferType = SECBUFFER_STREAM_TRAILER;
            empty[1]->pvBuffer = base + NTWSSP_HEADER_SIZE + out.size;
            empty[1]->cbBuffer = (ULONG)(in.consumed - NTWSSP_HEADER_SIZE - out.size);
            if (in.consumed < in.size) {
                empty[2]->BufferType = SECBUFFER_EXTRA; empty[2]->pvBuffer = base + in.consumed;
                empty[2]->cbBuffer = (ULONG)(in.size - in.consumed);
            }
            if (result == NTWSSP_CONTINUE) {
                memset(&control, 0, sizeof control);
                control.data = c->control; control.capacity = sizeof c->control;
                token_status = ntwssp_take_token(pool, c->core, &control);
                if (token_status == NTWSSP_CONTINUE && control.size) {
                    c->control_pending = 1; c->control_size = control.size; status = SEC_I_RENEGOTIATE;
                } else if (token_status == NTWSSP_STATE) status = SEC_E_OK;
                else status = SEC_E_INTERNAL_ERROR;
            }
        }
    }
    wipe(c->plaintext, sizeof c->plaintext);
    leave(); return status;
}
SECURITY_STATUS WINAPI ApplyControlToken(PCtxtHandle h, PSecBufferDesc d)
{
    native_context *c;
    ntwssp_info info;
    ULONG token;
    SECURITY_STATUS status = descriptor(d, 1, 1);
    if (status != SEC_E_OK) return status;
    if (d->pBuffers[0].BufferType != SECBUFFER_TOKEN || d->pBuffers[0].cbBuffer != sizeof token)
        return SEC_E_INVALID_TOKEN;
    memcpy(&token, d->pBuffers[0].pvBuffer, sizeof token);
    if (token != SCHANNEL_SHUTDOWN) return SEC_E_UNSUPPORTED_FUNCTION;
    if (!enter()) return SEC_E_INTERNAL_ERROR;
    c = get_context(h);
    if (!c) { leave(); return SEC_E_INVALID_HANDLE; }
    if (c->control_pending || c->handshake_pending || ntwssp_query(pool, c->core, &info) != NTWSSP_OK ||
        !info.established || info.failed) { leave(); return SEC_E_OUT_OF_SEQUENCE; }
    c->shutdown = 1;
    leave(); return SEC_E_OK;
}
SECURITY_STATUS WINAPI M98SspiEndInput(PCtxtHandle h)
{
    native_context *c;
    SECURITY_STATUS status;
    if (!enter()) return SEC_E_INTERNAL_ERROR;
    c = get_context(h);
    if (!c) { leave(); return SEC_E_INVALID_HANDLE; }
    if (c->control_pending) { leave(); return SEC_E_OUT_OF_SEQUENCE; }
    status = translate(c, ntwssp_end_input(pool, c->core));
    leave(); return status;
}
static SECURITY_STATUS package_info(PSecPkgInfoA *out)
{
    static const char comment[] = "Project TLS 1.3 outbound stream; explicit loading; no OS registration";
    SecPkgInfoA *p;
    char *strings;
    if (!out) return SEC_E_INVALID_TOKEN;
    *out = NULL;
    p = allocate_buffer(sizeof *p + sizeof M98SSPI_PACKAGE_A + sizeof comment);
    if (!p) return SEC_E_INSUFFICIENT_MEMORY;
    p->fCapabilities = SECPKG_FLAG_INTEGRITY | SECPKG_FLAG_PRIVACY | SECPKG_FLAG_CONNECTION |
                       SECPKG_FLAG_CLIENT_ONLY | SECPKG_FLAG_STREAM;
    p->wVersion = 1; p->wRPCID = SECPKG_ID_NONE; p->cbMaxToken = NTWSSP_MAX_TOKEN;
    strings = (char *)(p + 1);
    p->Name = strings; memcpy(strings, M98SSPI_PACKAGE_A, sizeof M98SSPI_PACKAGE_A);
    strings += sizeof M98SSPI_PACKAGE_A; p->Comment = strings; memcpy(strings, comment, sizeof comment);
    *out = p; return SEC_E_OK;
}
SECURITY_STATUS WINAPI QuerySecurityPackageInfoA(SEC_CHAR *name, PSecPkgInfoA *out)
{
    SECURITY_STATUS status;
    if (!out) return SEC_E_INVALID_TOKEN;
    *out = NULL;
    if (!package_valid(name)) return SEC_E_SECPKG_NOT_FOUND;
    if (!enter()) return SEC_E_INTERNAL_ERROR;
    status = package_info(out); leave(); return status;
}
SECURITY_STATUS WINAPI EnumerateSecurityPackagesA(ULONG *count, PSecPkgInfoA *out)
{
    SECURITY_STATUS status;
    if (!count || !out) return SEC_E_INVALID_TOKEN;
    *count = 0; *out = NULL;
    if (!enter()) return SEC_E_INTERNAL_ERROR;
    status = package_info(out); if (status == SEC_E_OK) *count = 1;
    leave(); return status;
}
SECURITY_STATUS WINAPI FreeContextBuffer(void *data)
{
    int freed;
    if (!enter()) return SEC_E_INTERNAL_ERROR;
    freed = free_buffer(data); leave(); return freed ? SEC_E_OK : SEC_E_INVALID_HANDLE;
}
SECURITY_STATUS WINAPI ExportSecurityContext(PCtxtHandle h, ULONG flags,
                                            PSecBuffer packed, void **token)
{
    (void)h; (void)flags; (void)packed; (void)token;
    return SEC_E_UNSUPPORTED_FUNCTION;
}
SECURITY_STATUS WINAPI ImportSecurityContextA(SEC_CHAR *name, PSecBuffer packed,
                                             void *token, PCtxtHandle h)
{
    (void)name; (void)packed; (void)token; (void)h;
    return SEC_E_UNSUPPORTED_FUNCTION;
}
PSecurityFunctionTableA WINAPI InitSecurityInterfaceA(void)
{
    /* Unsupported table entries are NULL, matching a client-only capability
     * set. Explicit loaders must check them. No callback is a success stub. */
    static SecurityFunctionTableA table = {
        .dwVersion = 1,
        .EnumerateSecurityPackagesA = EnumerateSecurityPackagesA,
        .AcquireCredentialsHandleA = AcquireCredentialsHandleA,
        .FreeCredentialHandle = FreeCredentialsHandle,
        .InitializeSecurityContextA = InitializeSecurityContextA,
        .DeleteSecurityContext = DeleteSecurityContext,
        .ApplyControlToken = ApplyControlToken,
        .QueryContextAttributesA = QueryContextAttributesA,
        .FreeContextBuffer = FreeContextBuffer,
        .QuerySecurityPackageInfoA = QuerySecurityPackageInfoA,
        .ExportSecurityContext = ExportSecurityContext,
        .ImportSecurityContextA = ImportSecurityContextA,
        .EncryptMessage = EncryptMessage,
        .DecryptMessage = DecryptMessage
    };
    return lock_ready ? &table : NULL;
}
BOOL WINAPI M98SspiDllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    unsigned i;
    (void)instance; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&lock); lock_ready = 1;
    } else if (reason == DLL_PROCESS_DETACH && lock_ready) {
        EnterCriticalSection(&lock);
        if (pool) { ntwssp_pool_destroy(pool); pool = NULL; }
        wipe(contexts, sizeof contexts);
        for (i = 0; i < M98SSPI_MAX_CREDENTIALS; ++i) {
            credentials[i].active = 0; credentials[i].refs = 0; drop_credential(&credentials[i]);
        }
        if (runtime_ready) { ntwst_native_runtime_fini(); runtime_ready = 0; }
        for (i = 0; i < ALLOCATIONS; ++i) if (allocations[i].data) free_buffer(allocations[i].data);
        LeaveCriticalSection(&lock); DeleteCriticalSection(&lock); lock_ready = 0;
    }
    return TRUE;
}
