/* SPDX-License-Identifier: GPL-2.0-only
 * Explicit DLL ANSI SSPI client + separately linked real TLS server.
 * Bounded memory transport only: no sockets or installed OS provider.
 */
#if defined(M98SSPI_GUEST_HOST_TEST)
#include "sspi_guest_probe_test_win32.h"
#endif
#include "sspi_native.h"
#include "transport.h"
#include "native_runtime.h"
#include "mbedtls/sha256.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef M98_PROBE_DLL_SHA256
#define M98_PROBE_DLL_SHA256 "ac3392d878f1e35a107d14111166401d3efb8f7507df3e7e19d61d59b4d2d2b2"
#endif
#ifndef M98_PROBE_DLL_BYTES
#define M98_PROBE_DLL_BYTES 1638356u
#endif
#define SELF_PATH "C:\\GOPLAB\\TLS13PRB.EXE"
#define DLL_PATH "C:\\GOPLAB\\M98SSPI.DLL"
#define LOG_PATH "C:\\GOPLAB\\SSPI13.LOG"
#define CAPACITY 65536u
#define MAX_STEPS 50000u
#define CASE_MS 8000u
#define PROBE_MS 70000u
#define REQ ISC_REQ_STREAM

typedef struct probe_log { HANDLE file; int failed; unsigned records; } probe_log;
typedef struct blob { unsigned char *bytes; size_t size; } blob;
typedef struct queue { unsigned char bytes[CAPACITY]; size_t count; } queue;
typedef struct pair {
    CredHandle credential;
    CtxtHandle client;
    int credential_live, client_live, client_done, server_done;
    ntwst_connection *server;
    queue to_server, from_server, assembled;
    DWORD started;
    unsigned steps, fragments, missing, extra, retries;
    SECURITY_STATUS last_client;
    int last_server;
} pair;
typedef SECURITY_STATUS (WINAPI *end_input_fn)(PCtxtHandle);
static probe_log report = { INVALID_HANDLE_VALUE, 0, 0 };
static char nonce[65];
static HMODULE module;
static HANDLE dll_file = INVALID_HANDLE_VALUE;
static PSecurityFunctionTableA api;
static end_input_fn end_input;
static unsigned failures, cases;
static blob ca, other_ca, certificate, key, expired_cert, expired_key, future;
static const char expected_dll_sha256[] = M98_PROBE_DLL_SHA256;
static int server_runtime;
static DWORD probe_started;

static int probe_live(void)
{ return (DWORD)(GetTickCount() - probe_started) < PROBE_MS; }

/* Exact fixed executable plus a single nonce argument, no shell interpretation. */
static int probe_nonce(const char *command, char out[65])
{
    size_t i = 0, j = 0, n = sizeof SELF_PATH - 1;
    int quoted;
    if (!command || !out) return 0;
    quoted = command[0] == '"';
    if (quoted) ++i;
    for (j = 0; j < n; ++j) {
        unsigned char a = (unsigned char)command[i + j], b = (unsigned char)SELF_PATH[j];
        if (a >= 'a' && a <= 'z') a -= 'a' - 'A';
        if (b >= 'a' && b <= 'z') b -= 'a' - 'A';
        if (a != b || !a) return 0;
    }
    i += n;
    if (quoted) { if (command[i] != '"') return 0; ++i; }
    for (j = 0; j < 9; ++j)
        if (!command[i + j] || command[i + j] != " --nonce "[j]) return 0;
    i += 9;
    for (j = 0; j <= 64; ++j) {
        unsigned char ch = (unsigned char)command[i + j];
        if (!ch) { if (j < 16) return 0; out[j] = 0; return 1; }
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '-')) return 0;
        if (j < 64) out[j] = (char)ch;
    }
    return 0;
}
static int equal_path(const char *a, const char *b)
{
    size_t i;
    for (i = 0; i < 260; ++i) {
        unsigned char x = (unsigned char)a[i], y = (unsigned char)b[i];
        if (x >= 'a' && x <= 'z') x -= 'a' - 'A';
        if (y >= 'a' && y <= 'z') y -= 'a' - 'A';
        if (x != y) return 0;
        if (!x) return 1;
    }
    return 0;
}
static int probe_write(probe_log *log, const char *text)
{
    size_t n, used = 0;
    DWORD written;
    if (!log || !text || log->failed || log->file == INVALID_HANDLE_VALUE) return 0;
    n = strlen(text);
    if (!n || n > 2048) { log->failed = 1; return 0; }
    while (used < n) {
        written = 0;
        if (!WriteFile(log->file, text + used, (DWORD)(n - used), &written, NULL) ||
            !written || written > n - used) { log->failed = 1; return 0; }
        used += written;
    }
    if (!FlushFileBuffers(log->file)) { log->failed = 1; return 0; }
    ++log->records; return 1;
}
static int add(char *out, size_t *used, const char *s)
{
    size_t n = strlen(s);
    if (n >= 2048 - *used) return 0;
    memcpy(out + *used, s, n); *used += n; out[*used] = 0; return 1;
}
static int number(char *out, size_t *used, uint32_t value)
{
    char digits[11]; size_t n = 0;
    do { digits[n++] = (char)('0' + value % 10); value /= 10; } while (value);
    if (n >= 2048 - *used) return 0;
    while (n) out[(*used)++] = digits[--n];
    out[*used] = 0; return 1;
}
static int record(const char *event, int passed, DWORD status, unsigned counter)
{
    char line[2048] = {0}; size_t used = 0;
    if (!add(line, &used, "{\"schema\":\"win98modern.sspi-guest-probe.v1\",\"nonce\":\"") ||
        !add(line, &used, nonce) || !add(line, &used, "\",\"event\":\"") ||
        !add(line, &used, event) || !add(line, &used, "\",\"passed\":") ||
        !add(line, &used, passed ? "true" : "false") || !add(line, &used, ",\"status\":") ||
        !number(line, &used, status) || !add(line, &used, ",\"counter\":") ||
        !number(line, &used, counter) ||
        !add(line, &used, ",\"transport\":\"bounded-memory\",\"sockets_verified\":false,"
                        "\"os_provider_registered\":false,\"native_default_ROOT_certificate_validation\":false,"
                        "\"process_exit_observed\":false}\n")) { report.failed = 1; return 0; }
    return probe_write(&report, line);
}
static void probe_finish(probe_log *log, DWORD candidate)
{
    if (log && log->file != INVALID_HANDLE_VALUE) {
        if (!FlushFileBuffers(log->file)) log->failed = 1;
        if (!CloseHandle(log->file)) log->failed = 1;
        log->file = INVALID_HANDLE_VALUE;
    }
    if (!log || log->failed) candidate = UINT32_C(0x50000003);
    ExitProcess(candidate);
}
static HANDLE probe_dll_file(void)
{
    HANDLE file;
    DWORD high = 0, n, got, total = 0;
    unsigned char bytes[4096], digest[32]; char hex[65]; unsigned i;
    mbedtls_sha256_context hash;
    int ok = 0;
    file = CreateFileA(DLL_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return file;
    n = GetFileSize(file, &high);
    if (high || n != M98_PROBE_DLL_BYTES || n > (16u << 20)) goto done;
    mbedtls_sha256_init(&hash);
    if (mbedtls_sha256_starts(&hash, 0)) goto hash_done;
    while (total < n) {
        DWORD wanted = n - total;
        if (!probe_live()) goto hash_done;
        if (wanted > sizeof bytes) wanted = sizeof bytes;
        got = 0;
        if (!ReadFile(file, bytes, wanted, &got, NULL) || !got || got > wanted ||
            mbedtls_sha256_update(&hash, bytes, got)) goto hash_done;
        total += got;
    }
    got = 0;
    if (!ReadFile(file, bytes, 1, &got, NULL) || got || mbedtls_sha256_finish(&hash, digest)) goto hash_done;
    for (i = 0; i < 32; ++i) {
        static const char alphabet[] = "0123456789abcdef";
        hex[2 * i] = alphabet[digest[i] >> 4]; hex[2 * i + 1] = alphabet[digest[i] & 15];
    }
    hex[64] = 0; ok = !strcmp(hex, expected_dll_sha256);
hash_done:
    mbedtls_sha256_free(&hash);
done:
    if (!ok) { CloseHandle(file); return INVALID_HANDLE_VALUE; }
    return file; /* Retained read-only/share-read handle prevents replacement. */
}
static int load_api(void)
{
    char path[260]; DWORD n;
    INIT_SECURITY_INTERFACE_A init;
    dll_file = probe_dll_file();
    if (dll_file == INVALID_HANDLE_VALUE) return 0;
    module = LoadLibraryA(DLL_PATH);
    if (!module) return 0;
    n = GetModuleFileNameA(module, path, sizeof path);
    if (!n || n >= sizeof path || !equal_path(path, DLL_PATH)) return 0;
    init = (INIT_SECURITY_INTERFACE_A)(uintptr_t)GetProcAddress(module, "InitSecurityInterfaceA");
    if (!init || !(api = init()) || api->dwVersion != 1) return 0;
#define CHECK_EXPORT(field, name) do { if (!api->field || (uintptr_t)api->field != \
    (uintptr_t)GetProcAddress(module, name)) return 0; } while (0)
    CHECK_EXPORT(AcquireCredentialsHandleA, "AcquireCredentialsHandleA");
    CHECK_EXPORT(FreeCredentialHandle, "FreeCredentialsHandle");
    CHECK_EXPORT(InitializeSecurityContextA, "InitializeSecurityContextA");
    CHECK_EXPORT(DeleteSecurityContext, "DeleteSecurityContext");
    CHECK_EXPORT(QueryContextAttributesA, "QueryContextAttributesA");
    CHECK_EXPORT(QuerySecurityPackageInfoA, "QuerySecurityPackageInfoA");
    CHECK_EXPORT(EnumerateSecurityPackagesA, "EnumerateSecurityPackagesA");
    CHECK_EXPORT(FreeContextBuffer, "FreeContextBuffer");
    CHECK_EXPORT(EncryptMessage, "EncryptMessage");
    CHECK_EXPORT(DecryptMessage, "DecryptMessage");
    CHECK_EXPORT(ApplyControlToken, "ApplyControlToken");
    CHECK_EXPORT(ExportSecurityContext, "ExportSecurityContext");
    CHECK_EXPORT(ImportSecurityContextA, "ImportSecurityContextA");
#undef CHECK_EXPORT
    end_input = (end_input_fn)(uintptr_t)GetProcAddress(module, "M98SspiEndInput");
    return end_input != NULL;
}
static int load_blob(const char *path, blob *b)
{
    HANDLE file; DWORD high = 0, n, used = 0, got; int ok = 0;
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    n = GetFileSize(file, &high);
    if (high || !n || n > (1u << 20)) goto done;
    b->bytes = calloc(1, (size_t)n + 1);
    if (!b->bytes) goto done;
    while (used < n) {
        if (!probe_live()) goto done;
        got = 0;
        if (!ReadFile(file, b->bytes + used, n - used, &got, NULL) || !got || got > n - used) goto done;
        used += got;
    }
    b->size = (size_t)n + 1; ok = 1;
done:
    if (!CloseHandle(file)) ok = 0;
    if (!ok) { free(b->bytes); memset(b, 0, sizeof *b); }
    return ok;
}
static void free_blob(blob *b)
{ if (b->bytes) { memset(b->bytes, 0, b->size); free(b->bytes); } memset(b, 0, sizeof *b); }
static int append(queue *q, const void *data, size_t n)
{
    if (n > sizeof q->bytes - q->count) return 0;
    if (n) memcpy(q->bytes + q->count, data, n);
    q->count += n; return 1;
}
static int consume(queue *q, size_t n)
{
    if (n > q->count) return 0;
    memmove(q->bytes, q->bytes + n, q->count - n); q->count -= n; return 1;
}
static int server_send(void *user, const unsigned char *bytes, size_t n)
{
    pair *p = user; size_t free_space = sizeof p->from_server.bytes - p->from_server.count;
    if (!free_space) return NTWST_IO_WOULD_BLOCK;
    if (n > free_space) n = free_space;
    if (n > 17) n = 17;
    return append(&p->from_server, bytes, n) ? (int)n : NTWST_IO_ERROR;
}
static int server_receive(void *user, unsigned char *bytes, size_t n)
{
    pair *p = user;
    if (!p->to_server.count) return NTWST_IO_WOULD_BLOCK;
    if (n > p->to_server.count) n = p->to_server.count;
    if (n > 13) n = 13;
    memcpy(bytes, p->to_server.bytes, n); consume(&p->to_server, n); return (int)n;
}
static int live(pair *p)
{ return probe_live() && ++p->steps < MAX_STEPS && (DWORD)(GetTickCount() - p->started) < CASE_MS; }
static int pair_free(pair *p)
{
    int ok = 1;
    if (!p) return 1;
    if (p->client_live && api->DeleteSecurityContext(&p->client) != SEC_E_OK) ok = 0;
    if (p->credential_live && api->FreeCredentialHandle(&p->credential) != SEC_E_OK) ok = 0;
    ntwst_destroy(p->server); memset(p, 0, sizeof *p); free(p); return ok;
}
static pair *pair_new(const char *name, const blob *trust, const blob *cert, const blob *secret)
{
    pair *p = calloc(1, sizeof *p); ntwst_config server; M98SSPI_PRIVATE_CRED policy;
    (void)name;
    if (!p) return NULL;
    p->started = GetTickCount();
    memset(&policy, 0, sizeof policy); policy.dwVersion = M98SSPI_PRIVATE_CRED_VERSION;
    policy.cbSize = sizeof policy; policy.ca = trust->bytes; policy.cbCa = (ULONG)trust->size;
    p->last_client = api->AcquireCredentialsHandleA(NULL, M98SSPI_PACKAGE_A, SECPKG_CRED_OUTBOUND,
                                                   NULL, &policy, NULL, NULL, &p->credential, NULL);
    if (p->last_client != SEC_E_OK) { pair_free(p); return NULL; }
    p->credential_live = 1;
    memset(&server, 0, sizeof server); server.role = NTWST_SERVER;
    server.own_certificate = cert->bytes; server.own_certificate_size = cert->size;
    server.private_key = secret->bytes; server.private_key_size = secret->size;
    server.send = server_send; server.receive = server_receive; server.io_context = p;
    if (ntwst_create(&server, &p->server) != NTWST_OK) { pair_free(p); return NULL; }
    return p;
}
static int stage_server(pair *p)
{
    size_t n = 1 + p->fragments % 11;
    if (n > p->from_server.count) n = p->from_server.count;
    if (!append(&p->assembled, p->from_server.bytes, n) || !consume(&p->from_server, n)) return 0;
    if (n) ++p->fragments;
    return 1;
}
static int retain_input(pair *p, SecBuffer *hint)
{
    if (hint->BufferType == SECBUFFER_EXTRA) {
        if (hint->cbBuffer > p->assembled.count ||
            hint->pvBuffer != p->assembled.bytes + p->assembled.count - hint->cbBuffer) return 0;
        ++p->extra; return consume(&p->assembled, p->assembled.count - hint->cbBuffer);
    }
    if (hint->BufferType == SECBUFFER_MISSING) {
        if (!hint->cbBuffer || hint->pvBuffer) return 0;
        ++p->missing; return 1;
    }
    if (hint->BufferType != SECBUFFER_EMPTY) return 0;
    return consume(&p->assembled, p->assembled.count);
}
static SECURITY_STATUS client_handshake(pair *p, const char *host)
{
    unsigned char output[CAPACITY]; ULONG attrs = 0;
    SecBuffer ib[2] = {{0}}, ob = {1, SECBUFFER_TOKEN, output};
    SecBufferDesc input = {0, 2, ib}, out = {0, 1, &ob};
    SECURITY_STATUS status; int old = p->client_live;
    if (!old) { p->client.dwLower = (ULONG_PTR)-1; p->client.dwUpper = (ULONG_PTR)-1; }
    ib[0].BufferType = SECBUFFER_TOKEN; ib[0].cbBuffer = (ULONG)p->assembled.count;
    ib[0].pvBuffer = p->assembled.bytes;
    status = api->InitializeSecurityContextA(old ? NULL : &p->credential, old ? &p->client : NULL,
                                           old ? NULL : (SEC_CHAR *)host, REQ, 0, 0,
                                           old ? &input : NULL, 0, &p->client, &out, &attrs, NULL);
    if (!old && p->client.dwLower != (ULONG_PTR)-1 && p->client.dwUpper != (ULONG_PTR)-1)
        p->client_live = 1;
    if (old && !retain_input(p, &ib[1])) return SEC_E_INTERNAL_ERROR;
    if (status == SEC_E_BUFFER_TOO_SMALL) {
        if (!ob.cbBuffer || ob.cbBuffer > sizeof output || !p->client_live) return SEC_E_INTERNAL_ERROR;
        ++p->retries; ob.cbBuffer = sizeof output;
        status = api->InitializeSecurityContextA(NULL, &p->client, NULL, REQ, 0, 0, NULL, 0,
                                               &p->client, &out, &attrs, NULL);
    }
    if (ob.cbBuffer > sizeof output || !append(&p->to_server, output, ob.cbBuffer)) return SEC_E_INTERNAL_ERROR;
    if (status == SEC_E_OK && !(attrs & ISC_RET_STREAM)) return SEC_E_INTERNAL_ERROR;
    return status;
}
static int handshake(pair *p, const char *host)
{
    while (live(p)) {
        if (!p->server_done) {
            p->last_server = ntwst_handshake(p->server);
            if (p->last_server < 0) return 0;
            p->server_done = p->last_server == NTWST_OK;
        }
        if (!p->client_done) {
            if (!stage_server(p)) return 0;
            p->last_client = client_handshake(p, host);
            if (p->last_client != SEC_E_OK && p->last_client != SEC_I_CONTINUE_NEEDED &&
                p->last_client != SEC_E_INCOMPLETE_MESSAGE) return 0;
            p->client_done = p->last_client == SEC_E_OK;
        }
        if (p->client_done && p->server_done) {
            const char *version = ntwst_version(p->server);
            return version && !strcmp(version, "TLSv1.3");
        }
        if (!(p->steps % 128)) Sleep(0);
    }
    return 0;
}
static SECURITY_STATUS client_decrypt(pair *p, unsigned char *plain, size_t capacity, size_t *got)
{
    SecBuffer b[4] = {{0}}; SecBufferDesc desc = {0, 4, b}; ULONG qop = 123;
    SECURITY_STATUS status; unsigned i;
    *got = 0;
    if (!stage_server(p)) return SEC_E_INTERNAL_ERROR;
    b[0].BufferType = SECBUFFER_DATA; b[0].pvBuffer = p->assembled.bytes; b[0].cbBuffer = (ULONG)p->assembled.count;
    status = api->DecryptMessage(&p->client, &desc, 0, &qop);
    if (qop) return SEC_E_INTERNAL_ERROR;
    if (status == SEC_E_INCOMPLETE_MESSAGE) {
        if (b[1].BufferType != SECBUFFER_MISSING || !b[1].cbBuffer) return SEC_E_INTERNAL_ERROR;
        return status;
    }
    if (status == SEC_E_OK || status == SEC_I_CONTEXT_EXPIRED || status == SEC_I_RENEGOTIATE) {
        SecBuffer hint = {0};
        for (i = 0; i < 4; ++i) {
            if (b[i].BufferType == SECBUFFER_DATA) {
                uintptr_t start = (uintptr_t)p->assembled.bytes, ptr = (uintptr_t)b[i].pvBuffer;
                if (b[i].cbBuffer > capacity || ptr < start || ptr > start + p->assembled.count ||
                    b[i].cbBuffer > start + p->assembled.count - ptr) return SEC_E_INTERNAL_ERROR;
                if (b[i].cbBuffer) memcpy(plain, b[i].pvBuffer, b[i].cbBuffer);
                *got = b[i].cbBuffer;
            }
            if (b[i].BufferType == SECBUFFER_EXTRA) hint = b[i];
        }
        if (!retain_input(p, &hint)) return SEC_E_INTERNAL_ERROR;
        if (status == SEC_I_RENEGOTIATE) {
            unsigned char token[CAPACITY]; ULONG attrs;
            SecBuffer out = {sizeof token, SECBUFFER_TOKEN, token}; SecBufferDesc od = {0, 1, &out};
            if (api->InitializeSecurityContextA(NULL, &p->client, NULL, REQ, 0, 0, NULL, 0,
                                              &p->client, &od, &attrs, NULL) != SEC_E_OK ||
                !append(&p->to_server, token, out.cbBuffer)) return SEC_E_INTERNAL_ERROR;
            return SEC_E_OK;
        }
    }
    return status;
}
static int echo(pair *p)
{
    static const unsigned char expected[] = "m98sspi native TLS13 echo";
    unsigned char head[5], data[sizeof expected], tail[32], received[128];
    SecBuffer b[4] = {{sizeof head, SECBUFFER_STREAM_HEADER, head},
                     {sizeof expected, SECBUFFER_DATA, data},
                     {sizeof tail, SECBUFFER_STREAM_TRAILER, tail}, {0}};
    SecBufferDesc desc = {0, 4, b}; size_t got = 0, sent = 0, used = 0; int status;
    memcpy(data, expected, sizeof expected);
    if (api->EncryptMessage(&p->client, 0, &desc, 0) != SEC_E_OK ||
        !append(&p->to_server, head, b[0].cbBuffer) || !append(&p->to_server, data, b[1].cbBuffer) ||
        !append(&p->to_server, tail, b[2].cbBuffer)) return 0;
    while (live(p)) {
        status = ntwst_read(p->server, received, sizeof received, &got);
        if (status == NTWST_OK) break;
        if (status != NTWST_WANT_READ && status != NTWST_WANT_WRITE) return 0;
    }
    if (got != sizeof expected || memcmp(received, expected, sizeof expected)) return 0;
    while (live(p)) {
        status = ntwst_write(p->server, expected, sizeof expected, &sent);
        if (status == NTWST_OK) break;
        if (status != NTWST_WANT_READ && status != NTWST_WANT_WRITE) return 0;
    }
    if (sent != sizeof expected) return 0;
    while (live(p) && used < sizeof expected) {
        SECURITY_STATUS result = client_decrypt(p, received + used, sizeof received - used, &got);
        if (result != SEC_E_OK && result != SEC_E_INCOMPLETE_MESSAGE) return 0;
        used += got;
    }
    return used == sizeof expected && !memcmp(received, expected, sizeof expected);
}
static int extra_records(pair *p)
{
    static const unsigned char one[] = "one", two[] = "two";
    unsigned char plain[128]; size_t sent = 0, got = 0; unsigned before = p->extra;
    if (ntwst_write(p->server, one, sizeof one, &sent) != NTWST_OK || sent != sizeof one ||
        ntwst_write(p->server, two, sizeof two, &sent) != NTWST_OK || sent != sizeof two) return 0;
    /* Deliberately provide both complete records together, forcing real EXTRA. */
    if (!append(&p->assembled, p->from_server.bytes, p->from_server.count) ||
        !consume(&p->from_server, p->from_server.count)) return 0;
    if (client_decrypt(p, plain, sizeof plain, &got) != SEC_E_OK || got != sizeof one ||
        memcmp(plain, one, sizeof one) || p->extra != before + 1 || !p->assembled.count) return 0;
    return client_decrypt(p, plain, sizeof plain, &got) == SEC_E_OK && got == sizeof two &&
           !memcmp(plain, two, sizeof two) && !p->assembled.count;
}
static int drain_control_records(pair *p)
{
    unsigned char plain[128]; size_t got = 0;
    while (p->from_server.count || p->assembled.count) {
        SECURITY_STATUS status;
        if (!live(p)) return 0;
        status = client_decrypt(p, plain, sizeof plain, &got);
        if (got || (status != SEC_E_OK && status != SEC_E_INCOMPLETE_MESSAGE)) return 0;
    }
    return 1;
}
static void check_case(const char *name, int passed, DWORD status, unsigned count)
{ ++cases; if (!passed) ++failures; record(name, passed, status, count); }
static void rejection(const char *name, const char *host, const blob *trust,
                      const blob *cert, const blob *secret, SECURITY_STATUS expected)
{
    pair *p = pair_new(host, trust, cert, secret); int passed = 0; DWORD status = SEC_E_INTERNAL_ERROR;
    if (p) { passed = !handshake(p, host) && p->last_client == expected; status = (DWORD)p->last_client; }
    if (!pair_free(p)) passed = 0;
    check_case(name, passed, status, 0);
}
#if defined(M98SSPI_GUEST_HOST_TEST) && !defined(M98SSPI_GUEST_REAL_PROTOCOL)
extern DWORD run_protocol_cases(void); /* Host injects ONLY protocol result. */
#else
static DWORD run_protocol_cases(void)
{
    pair *p; SecPkgContext_StreamSizes sizes; int ok, status; size_t got, sent;
    unsigned char received[128]; SECURITY_STATUS client_status;
    if (!load_blob("C:\\GOPLAB\\CA.PEM", &ca) || !load_blob("C:\\GOPLAB\\BADCA.PEM", &other_ca) ||
        !load_blob("C:\\GOPLAB\\SRV.PEM", &certificate) || !load_blob("C:\\GOPLAB\\SRV.KEY", &key) ||
        !load_blob("C:\\GOPLAB\\EXP.PEM", &expired_cert) || !load_blob("C:\\GOPLAB\\EXP.KEY", &expired_key) ||
        !load_blob("C:\\GOPLAB\\FUT.PEM", &future)) return UINT32_C(0x50000101);
    if (ntwst_native_runtime_init() != NTWST_OK) return UINT32_C(0x50000102);
    server_runtime = 1;
    p = pair_new("tls13.win98.test", &ca, &certificate, &key);
    ok = p && handshake(p, "tls13.win98.test");
    check_case("fragmented_handshake", ok && p->missing && p->fragments, p ? (DWORD)p->last_client : 0,
               p ? p->missing : 0);
    check_case("retained_token_retry", ok && p->retries, p ? (DWORD)p->last_client : 0, p ? p->retries : 0);
    status = ok ? api->QueryContextAttributesA(&p->client, SECPKG_ATTR_STREAM_SIZES, &sizes) : SEC_E_INTERNAL_ERROR;
    check_case("real_stream_sizes", status == SEC_E_OK && sizes.cbHeader == 5 && sizes.cbTrailer == 32 &&
               sizes.cbMaximumMessage == 16383 && sizes.cBuffers == 4 && sizes.cbBlockSize == 1, (DWORD)status, 0);
    { int echo_ok = ok && echo(p);
      check_case("actual_encrypted_echo", echo_ok, 0, 0);
      check_case("multiple_record_EXTRA", echo_ok && extra_records(p), 0, p ? p->extra : 0); }
    if (ok) {
        ULONG shutdown = SCHANNEL_SHUTDOWN, attrs;
        SecBuffer control = {sizeof shutdown, SECBUFFER_TOKEN, &shutdown}; SecBufferDesc cd = {0, 1, &control};
        unsigned char token[CAPACITY]; SecBuffer b = {1, SECBUFFER_TOKEN, token}; SecBufferDesc od = {0, 1, &b};
        ok = api->ApplyControlToken(&p->client, &cd) == SEC_E_OK;
        client_status = ok ? api->InitializeSecurityContextA(NULL, &p->client, NULL, REQ, 0, 0, NULL, 0,
                                                            &p->client, &od, &attrs, NULL) : SEC_E_INTERNAL_ERROR;
        ok = ok && client_status == SEC_E_BUFFER_TOO_SMALL;
        b.cbBuffer = sizeof token;
        client_status = ok ? api->InitializeSecurityContextA(NULL, &p->client, NULL, REQ, 0, 0, NULL, 0,
                                                            &p->client, &od, &attrs, NULL) : SEC_E_INTERNAL_ERROR;
        ok = ok && client_status == SEC_E_OK && b.cbBuffer && append(&p->to_server, token, b.cbBuffer);
        status = NTWST_WANT_READ;
        while (ok && live(p)) {
            status = ntwst_read(p->server, received, sizeof received, &got);
            if (status == NTWST_CLOSED) break;
            if (status != NTWST_WANT_READ && status != NTWST_WANT_WRITE) { ok = 0; break; }
        }
        ok = ok && status == NTWST_CLOSED;
        status = ok ? ntwst_close_notify(p->server) : NTWST_INVALID;
        ok = ok && status == NTWST_OK;
        client_status = SEC_E_INCOMPLETE_MESSAGE;
        while (ok && live(p)) {
            client_status = client_decrypt(p, received, sizeof received, &got);
            if (client_status == SEC_I_CONTEXT_EXPIRED) break;
            if (client_status != SEC_E_OK && client_status != SEC_E_INCOMPLETE_MESSAGE) { ok = 0; break; }
        }
        ok = ok && client_status == SEC_I_CONTEXT_EXPIRED && end_input(&p->client) == SEC_I_CONTEXT_EXPIRED;
        check_case("authenticated_bidirectional_close", ok, (DWORD)client_status, 0);
        { CtxtHandle stale = p->client;
          status = api->DeleteSecurityContext(&p->client); p->client_live = 0;
          check_case("typed_stale_context", status == SEC_E_OK && api->DeleteSecurityContext(&stale) == SEC_E_INVALID_HANDLE &&
                     api->DeleteSecurityContext((PCtxtHandle)&p->credential) == SEC_E_INVALID_HANDLE, (DWORD)status, 0); }
    } else { check_case("authenticated_bidirectional_close", 0, SEC_E_INTERNAL_ERROR, 0);
             check_case("typed_stale_context", 0, SEC_E_INTERNAL_ERROR, 0); }
    if (!pair_free(p)) ++failures;
    rejection("wrong_dns_rejected", "wrong.win98.test", &ca, &certificate, &key, SEC_E_WRONG_PRINCIPAL);
    rejection("untrusted_root_rejected", "tls13.win98.test", &other_ca, &certificate, &key, SEC_E_UNTRUSTED_ROOT);
    rejection("expired_certificate_rejected", "tls13.win98.test", &ca, &expired_cert, &expired_key, SEC_E_CERT_EXPIRED);
    rejection("future_certificate_rejected", "tls13.win98.test", &future, &future, &key, SEC_E_CERT_EXPIRED);
    p = pair_new("tls13.win98.test", &ca, &certificate, &key);
    ok = p && handshake(p, "tls13.win98.test");
    sent = 0;
    if (ok) {
        status = ntwst_write(p->server, "tamper", 6, &sent);
        ok = status == NTWST_OK && sent == 6 && p->from_server.count > 5;
        if (ok) p->from_server.bytes[p->from_server.count - 1] ^= 1;
    }
    client_status = SEC_E_INCOMPLETE_MESSAGE;
    while (ok && live(p)) {
        client_status = client_decrypt(p, received, sizeof received, &got);
        if (client_status == SEC_E_MESSAGE_ALTERED) break;
        if (client_status != SEC_E_OK && client_status != SEC_E_INCOMPLETE_MESSAGE) { ok = 0; break; }
    }
    check_case("tampered_record_rejected", ok && client_status == SEC_E_MESSAGE_ALTERED, (DWORD)client_status, 0);
    if (!pair_free(p)) ++failures;
    p = pair_new("tls13.win98.test", &ca, &certificate, &key);
    ok = p && handshake(p, "tls13.win98.test") && drain_control_records(p);
    client_status = ok ? end_input(&p->client) : SEC_E_INTERNAL_ERROR;
    check_case("unauthenticated_memory_EOF_rejected", ok && client_status == SEC_E_ILLEGAL_MESSAGE, (DWORD)client_status, 0);
    if (!pair_free(p)) ++failures;
    return failures ? UINT32_C(0x50000103) : 0;
}
#endif
void WINAPI M98SspiProbeEntry(void)
{
    char self[260]; DWORD length, candidate; OSVERSIONINFOA version;
    CredHandle default_credential; SECURITY_STATUS root_status;
    int root_logged;
    probe_started = GetTickCount();
    if (!probe_nonce(GetCommandLineA(), nonce)) ExitProcess(UINT32_C(0x50000001));
    length = GetModuleFileNameA(NULL, self, sizeof self);
    if (!length || length >= sizeof self || !equal_path(self, SELF_PATH)) ExitProcess(UINT32_C(0x50000001));
    report.file = CreateFileA(LOG_PATH, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (report.file == INVALID_HANDLE_VALUE) ExitProcess(UINT32_C(0x50000002));
    candidate = UINT32_C(0x50000004);
    if (!record("entry", 1, 0, 0)) goto done;
    memset(&version, 0, sizeof version); version.dwOSVersionInfoSize = sizeof version;
    if (!GetVersionExA(&version) || version.dwPlatformId != 1 || version.dwMajorVersion != 4 ||
        version.dwMinorVersion != 10 || (version.dwBuildNumber & 0xffffu) != 2222) goto done;
    if (!record("win98se_build", 1, version.dwBuildNumber, version.dwPlatformId)) goto done;
    if (!load_api()) goto done;
    if (!record("explicit_DLL_hash_table_bound", 1, M98_PROBE_DLL_BYTES, 15)) goto done;
    root_status = api->AcquireCredentialsHandleA(NULL, M98SSPI_PACKAGE_A, SECPKG_CRED_OUTBOUND, NULL,
                                                NULL, NULL, NULL, &default_credential, NULL);
    /* This is acquisition-only. Failure/empty ROOT is recorded as unavailable,
     * never counted as private protocol PASS or default ROOT validation. */
    root_logged = record("native_ROOT_acquire_only", root_status == SEC_E_OK, (DWORD)root_status, 0);
    if (root_status == SEC_E_OK && api->FreeCredentialHandle(&default_credential) != SEC_E_OK) goto done;
    if (!root_logged) goto done;
    candidate = run_protocol_cases();
done:
    free_blob(&ca); free_blob(&other_ca); free_blob(&certificate); free_blob(&key);
    free_blob(&expired_cert); free_blob(&expired_key); free_blob(&future);
    if (server_runtime && ntwst_native_runtime_fini() != NTWST_OK) candidate = UINT32_C(0x50000005);
    server_runtime = 0;
    if (module && !FreeLibrary(module)) candidate = UINT32_C(0x50000006);
    module = NULL; api = NULL; end_input = NULL;
    if (dll_file != INVALID_HANDLE_VALUE && !CloseHandle(dll_file)) candidate = UINT32_C(0x50000007);
    dll_file = INVALID_HANDLE_VALUE;
    record("terminal_candidate_only", candidate == 0, candidate, cases);
    probe_finish(&report, candidate);
}
