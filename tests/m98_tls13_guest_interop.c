/* SPDX-License-Identifier: GPL-2.0-only
 * Latest TLS client/LTS server DLL interoperability on native Windows 98.
 * Public ntwst ABI reproduced from transport.h at peer commit 2c5e2a6,
 * SHA256 7f3f364ab97fd58d94c03f80432a94b99c0ad28b71b48bc4d0ee4920e3191cda.
 * No implementation or PSA instance is linked into this probe. Each loaded
 * DLL exclusively owns its own crypto state. This is not a socket/OS TLS test.
 */
#ifndef M98_INTEROP_CONTROLLER_TEST
#include <windows.h>
#include <wincrypt.h>
#endif
#include <stdint.h>
#include "m98_tls13.h"

#ifndef M98_INTEROP_NONCE
#error "A fresh frozen nonce is required"
#endif
#ifndef M98_CLIENT_SHA256
#error "The tested client DLL digest is required"
#endif
#ifndef M98_SERVER_SHA256
#error "The tested server DLL digest is required"
#endif

#define QUEUE_CAPACITY 257u
#define STEP_LIMIT 20000u
#define FIXTURE_LIMIT (1u << 20)
#define NTWST_OK 0
#define NTWST_WANT_READ 1
#define NTWST_WANT_WRITE 2
#define NTWST_CLOSED 3
#define NTWST_INVALID (-1)
#define NTWST_ENGINE_ERROR (-3)

typedef struct ntwst_connection ntwst_connection;
typedef struct ntwst_config {
    int role;
    const char *hostname;
    const unsigned char *ca_certificate;
    size_t ca_certificate_size;
    const unsigned char *own_certificate;
    size_t own_certificate_size;
    const unsigned char *private_key;
    size_t private_key_size;
    int (*send)(void *, const unsigned char *, size_t);
    int (*receive)(void *, unsigned char *, size_t);
    void *io_context;
} ntwst_config;
#ifndef M98_INTEROP_CONTROLLER_TEST
_Static_assert(sizeof(ntwst_config) == 44, "Pinned i386 ntwst ABI layout");
_Static_assert(sizeof(m98_tls_options) == 32, "Pinned i386 latest-client ABI layout");
#endif

typedef struct client_api {
    int (*create)(const m98_tls_options *, m98_tls_client **);
    int (*handshake)(m98_tls_client *);
    int (*write)(m98_tls_client *, const void *, size_t, size_t *);
    int (*read)(m98_tls_client *, void *, size_t, size_t *);
    int (*shutdown)(m98_tls_client *);
    int (*backend_error)(const m98_tls_client *);
    uint32_t (*verify_flags)(const m98_tls_client *);
    int (*is_established)(const m98_tls_client *);
    void (*free)(m98_tls_client *);
} client_api;
typedef struct server_api {
    int (*runtime_init)(int (*)(void *, unsigned char *, size_t), void *);
    int (*runtime_fini)(void);
    int (*native_runtime_init)(void);
    int (*native_runtime_fini)(void);
    int (*create)(const ntwst_config *, ntwst_connection **);
    void (*destroy)(ntwst_connection *);
    int (*handshake)(ntwst_connection *);
    int (*write)(ntwst_connection *, const void *, size_t, size_t *);
    int (*read)(ntwst_connection *, void *, size_t, size_t *);
    int (*close_notify)(ntwst_connection *);
    const char *(*version)(const ntwst_connection *);
    uint32_t (*verify_flags)(const ntwst_connection *);
    int (*engine_error)(const ntwst_connection *);
} server_api;
typedef struct blob { unsigned char *bytes; size_t size; } blob;
typedef struct queue {
    unsigned char bytes[QUEUE_CAPACITY];
    size_t head, count, sent, received, blocked;
} queue;
typedef struct pair {
    queue to_server, to_client;
    m98_tls_client *client;
    ntwst_connection *server;
    int client_status, server_status, entropy_result;
    unsigned entropy_calls;
} pair;

static client_api ca;
static server_api sa;
static unsigned checks, failures;
#ifndef M98_INTEROP_CONTROLLER_TEST
static HCRYPTPROV provider;
static HMODULE crypto_module, client_module, server_module;
static BOOL (WINAPI *crypto_acquire)(HCRYPTPROV *, LPCSTR, LPCSTR, DWORD, DWORD);
static BOOL (WINAPI *crypto_generate)(HCRYPTPROV, DWORD, BYTE *);
static BOOL (WINAPI *crypto_release)(HCRYPTPROV, DWORD);
static HANDLE report = INVALID_HANDLE_VALUE;
static char base[MAX_PATH], path[MAX_PATH];
static DWORD base_size;
static int report_failed;
#endif

/* No CRT entry or compiler static-TLS startup. */
static void clear(void *dst, size_t size)
{ unsigned char *p = dst; while (size--) *p++ = 0; }
static size_t length(const char *s)
{ size_t n = 0; while (s[n]) ++n; return n; }
static int equal(const void *left, const void *right, size_t size)
{
    const unsigned char *a = left, *b = right;
    while (size--) if (*a++ != *b++) return 0;
    return 1;
}
static int text_equal(const char *a, const char *b)
{ size_t n = length(a); return n == length(b) && equal(a, b, n); }
#ifndef M98_INTEROP_CONTROLLER_TEST
static void emit(const char *text)
{
    DWORD count, n = (DWORD)length(text);
    if (report == INVALID_HANDLE_VALUE ||
        !WriteFile(report, text, n, &count, NULL) || count != n)
        report_failed = 1;
}
static void number(unsigned value)
{
    char buffer[12], *p = buffer + sizeof buffer - 1;
    *p = 0;
    do { *--p = (char)('0' + value % 10); value /= 10; } while (value);
    emit(p);
}
static void number64(uint64_t value)
{
    char buffer[24], *p = buffer + sizeof buffer - 1;
    *p = 0;
    do { *--p = (char)('0' + value % 10); value /= 10; } while (value);
    emit(p);
}
static void loader_error(const char *label, DWORD code)
{ emit(label); emit("="); number(code); emit("\r\n"); }
static void check(const char *name, int pass)
{
    ++checks;
    if (!pass) ++failures;
    emit(name); emit(pass ? "=PASS\r\n" : "=FAIL\r\n");
    if (!FlushFileBuffers(report)) report_failed = 1;
}
static int make_path(const char *name)
{
    size_t i, n = length(name);
    if ((size_t)base_size + n >= MAX_PATH) return 0;
    for (i = 0; i < base_size; ++i) path[i] = base[i];
    for (i = 0; i <= n; ++i) path[base_size + i] = name[i];
    return 1;
}
static int initialize_report(void)
{
    DWORD n = GetModuleFileNameA(NULL, base, MAX_PATH), i;
    if (!n || n >= MAX_PATH) return 0;
    for (i = n; i; --i) if (base[i - 1] == '\\') break;
    if (!i) return 0;
    base_size = i;
    if (!make_path("TLSDLL.LOG")) return 0;
    report = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                         FILE_ATTRIBUTE_NORMAL, NULL);
    if (report == INVALID_HANDLE_VALUE) return 0;
    emit("NONCE=" M98_INTEROP_NONCE "\r\n");
    emit("CLIENT_SHA256=" M98_CLIENT_SHA256 "\r\n");
    emit("SERVER_SHA256=" M98_SERVER_SHA256 "\r\n");
    emit("SCOPE=Native DLL interoperability; offline queues; no OS networking\r\n");
    return !report_failed;
}
static int load_blob(const char *name, blob *b)
{
    HANDLE file;
    DWORD high, size, count;
    if (!make_path(name)) return 0;
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    size = GetFileSize(file, &high);
    if (high || !size || size == INVALID_FILE_SIZE || size > FIXTURE_LIMIT) {
        CloseHandle(file); return 0;
    }
    b->bytes = HeapAlloc(GetProcessHeap(), 0, (size_t)size + 1);
    if (!b->bytes) { CloseHandle(file); return 0; }
    if (!ReadFile(file, b->bytes, size, &count, NULL) || count != size) {
        CloseHandle(file); HeapFree(GetProcessHeap(), 0, b->bytes);
        b->bytes = NULL; return 0;
    }
    if (!CloseHandle(file)) {
        HeapFree(GetProcessHeap(), 0, b->bytes); b->bytes = NULL; return 0;
    }
    b->bytes[size] = 0;
    b->size = (size_t)size + 1;
    return 1;
}

/* Resolve each typed C ABI independently; never cast one backend's API to
 * the other. Function pointers here use the DLLs' public cdecl convention. */
#define RESOLVE(module, api, field, symbol) do { \
    FARPROC address = GetProcAddress(module, symbol); \
    if (!address) { DWORD code = GetLastError(); emit("MISSING_EXPORT=" symbol "\r\n"); \
                   loader_error("LOAD_ERROR", code); return 0; } \
    if (sizeof address != sizeof (api).field) { emit("ABI_POINTER_SIZE=FAIL\r\n"); return 0; } \
    { const unsigned char *from = (const unsigned char *)&address; \
      unsigned char *to = (unsigned char *)&(api).field; size_t i; \
      for (i = 0; i < sizeof address; ++i) to[i] = from[i]; } \
} while (0)

static int load_apis(void)
{
    if (!make_path("M98TLS13.DLL")) return 0;
    emit("CLIENT_PATH="); emit(path); emit("\r\n");
    client_module = LoadLibraryA(path);
    if (!client_module) { DWORD code = GetLastError(); loader_error("CLIENT_LOAD_ERROR", code); return 0; }
    RESOLVE(client_module, ca, create, "m98_tls_create");
    RESOLVE(client_module, ca, handshake, "m98_tls_handshake");
    RESOLVE(client_module, ca, write, "m98_tls_write");
    RESOLVE(client_module, ca, read, "m98_tls_read");
    RESOLVE(client_module, ca, shutdown, "m98_tls_shutdown");
    RESOLVE(client_module, ca, backend_error, "m98_tls_backend_error");
    RESOLVE(client_module, ca, verify_flags, "m98_tls_verify_flags");
    RESOLVE(client_module, ca, is_established, "m98_tls_is_established");
    RESOLVE(client_module, ca, free, "m98_tls_free");
    if (!make_path("M98TLS.DLL")) return 0;
    emit("SERVER_PATH="); emit(path); emit("\r\n");
    server_module = LoadLibraryA(path);
    if (!server_module) { DWORD code = GetLastError(); loader_error("SERVER_LOAD_ERROR", code); return 0; }
    if (server_module == client_module) return 0;
    RESOLVE(server_module, sa, runtime_init, "ntwst_runtime_init");
    RESOLVE(server_module, sa, runtime_fini, "ntwst_runtime_fini");
    RESOLVE(server_module, sa, native_runtime_init, "ntwst_native_runtime_init");
    RESOLVE(server_module, sa, native_runtime_fini, "ntwst_native_runtime_fini");
    RESOLVE(server_module, sa, create, "ntwst_create");
    RESOLVE(server_module, sa, destroy, "ntwst_destroy");
    RESOLVE(server_module, sa, handshake, "ntwst_handshake");
    RESOLVE(server_module, sa, write, "ntwst_write");
    RESOLVE(server_module, sa, read, "ntwst_read");
    RESOLVE(server_module, sa, close_notify, "ntwst_close_notify");
    RESOLVE(server_module, sa, version, "ntwst_version");
    RESOLVE(server_module, sa, verify_flags, "ntwst_verify_flags");
    RESOLVE(server_module, sa, engine_error, "ntwst_engine_error");
    crypto_module = LoadLibraryA("ADVAPI32.DLL");
    if (!crypto_module) { DWORD code = GetLastError(); loader_error("CRYPTO_LOAD_ERROR", code); return 0; }
    { FARPROC a = GetProcAddress(crypto_module, "CryptAcquireContextA");
      FARPROC g = GetProcAddress(crypto_module, "CryptGenRandom");
      FARPROC r = GetProcAddress(crypto_module, "CryptReleaseContext");
      if (!a || !g || !r) return 0;
      crypto_acquire = (BOOL (WINAPI *)(HCRYPTPROV *, LPCSTR, LPCSTR, DWORD, DWORD))(uintptr_t)a;
      crypto_generate = (BOOL (WINAPI *)(HCRYPTPROV, DWORD, BYTE *))(uintptr_t)g;
      crypto_release = (BOOL (WINAPI *)(HCRYPTPROV, DWORD))(uintptr_t)r; }
    return 1;
}
static int entropy(void *context, unsigned char *out, size_t bytes)
{
    pair *p = context;
    ++p->entropy_calls;
    if (p->entropy_result != 1) return p->entropy_result;
    if (!provider || bytes > UINT32_MAX) return 0;
    return !bytes || crypto_generate(provider, (DWORD)bytes, out) ? 1 : 0;
}
static int64_t utc_seconds(void *context)
{
    SYSTEMTIME utc;
    FILETIME file;
    uint64_t ticks;
    (void)context;
    GetSystemTime(&utc);
    if (!SystemTimeToFileTime(&utc, &file)) return -1;
    ticks = ((uint64_t)file.dwHighDateTime << 32) | file.dwLowDateTime;
    if (ticks < UINT64_C(116444736000000000)) return -1;
    return (int64_t)((ticks - UINT64_C(116444736000000000)) / UINT64_C(10000000));
}
#else
/* Controller tests supply deliberately hostile API doubles. Their passes are
 * explicitly unrelated to TLS cryptography or Windows compatibility. */
static void check(const char *name, int pass)
{ (void)name; ++checks; if (!pass) ++failures; }
static int entropy(void *context, unsigned char *out, size_t bytes)
{
    pair *p = context;
    ++p->entropy_calls;
    if (p->entropy_result != 1) return p->entropy_result;
    clear(out, bytes);
    return 1;
}
static int64_t utc_seconds(void *context)
{ (void)context; return INT64_C(1780000000); }
#endif
static int queue_send(queue *q, const unsigned char *data, size_t bytes)
{
    size_t n, i;
    if (q->count == QUEUE_CAPACITY) { ++q->blocked; return -1; }
    n = bytes < QUEUE_CAPACITY - q->count ? bytes : QUEUE_CAPACITY - q->count;
    if (n > 17) n = 17;
    for (i = 0; i < n; ++i)
        q->bytes[(q->head + q->count + i) % QUEUE_CAPACITY] = data[i];
    q->count += n; q->sent += n;
    return (int)n;
}
static int queue_recv(queue *q, unsigned char *data, size_t bytes)
{
    size_t n, i;
    if (!q->count) { ++q->blocked; return -1; }
    n = bytes < q->count ? bytes : q->count;
    if (n > 13) n = 13;
    for (i = 0; i < n; ++i) data[i] = q->bytes[(q->head + i) % QUEUE_CAPACITY];
    q->head = (q->head + n) % QUEUE_CAPACITY;
    q->count -= n; q->received += n;
    return (int)n;
}
static int client_send(void *context, const unsigned char *data, size_t bytes)
{ int n = queue_send(&((pair *)context)->to_server, data, bytes); return n < 0 ? -2 : n; }
static int client_recv(void *context, unsigned char *data, size_t bytes)
{ int n = queue_recv(&((pair *)context)->to_client, data, bytes); return n < 0 ? -2 : n; }
static int server_send(void *context, const unsigned char *data, size_t bytes)
{ return queue_send(&((pair *)context)->to_client, data, bytes); }
static int server_recv(void *context, unsigned char *data, size_t bytes)
{ return queue_recv(&((pair *)context)->to_server, data, bytes); }
static void options(m98_tls_options *o, pair *p, const blob *trust, const char *hostname)
{
    clear(o, sizeof *o);
    o->user = p; o->entropy = entropy; o->unix_time = utc_seconds;
    o->send = client_send; o->recv = client_recv;
    o->ca = trust->bytes; o->ca_bytes = trust->size; o->hostname = hostname;
}
static int create_pair(pair *p, const blob *trust, const blob *cert,
                       const blob *key, const char *hostname)
{
    ntwst_config config;
    m98_tls_options o;
    clear(p, sizeof *p); p->entropy_result = 1;
    clear(&config, sizeof config);
    config.role = 1; config.own_certificate = cert->bytes;
    config.own_certificate_size = cert->size;
    config.private_key = key->bytes; config.private_key_size = key->size;
    config.send = server_send; config.receive = server_recv; config.io_context = p;
    p->server_status = sa.create(&config, &p->server);
    if (p->server_status != NTWST_OK) return 0;
    options(&o, p, trust, hostname);
    p->client_status = ca.create(&o, &p->client);
    return p->client_status == M98_TLS_OK;
}
static void destroy_pair(pair *p)
{
    if (p->client) ca.free(p->client);
    if (p->server) sa.destroy(p->server);
    p->client = NULL; p->server = NULL;
}
static int handshake(pair *p)
{
    unsigned step;
    int client_done = 0, server_done = 0;
    for (step = 0; step < STEP_LIMIT; ++step) {
        if (!client_done) {
            p->client_status = ca.handshake(p->client);
            if (p->client_status < 0 || p->client_status == M98_TLS_EOF) return 0;
            client_done = p->client_status == M98_TLS_OK;
        }
        if (!server_done) {
            p->server_status = sa.handshake(p->server);
            if (p->server_status < 0 || p->server_status == NTWST_CLOSED) return 0;
            server_done = p->server_status == NTWST_OK;
        }
        if (client_done && server_done) return 1;
    }
    return 0;
}
static int authenticated_handshake(pair *p)
{
    /* This fixture authenticates the server. It sends no client certificate:
     * the server's VERIFY_NONE result is not client-authentication evidence. */
    return handshake(p) && ca.is_established(p->client) &&
           text_equal(sa.version(p->server), "TLSv1.3") &&
           !ca.verify_flags(p->client);
}
#ifndef M98_INTEROP_CONTROLLER_TEST
static void diagnostic(const char *name, int value)
{
    emit(name); emit("=");
    if (value < 0) { emit("-"); number(0u - (unsigned)value); }
    else number((unsigned)value);
    emit("\r\n");
}
static void positive_diagnostics(pair *p)
{
    diagnostic("POSITIVE_CLIENT_STATUS", p->client_status);
    diagnostic("POSITIVE_SERVER_STATUS", p->server_status);
    diagnostic("POSITIVE_CLIENT_ESTABLISHED", ca.is_established(p->client));
    diagnostic("POSITIVE_CLIENT_BACKEND_ERROR", ca.backend_error(p->client));
    diagnostic("POSITIVE_SERVER_BACKEND_ERROR", sa.engine_error(p->server));
    emit("POSITIVE_CLIENT_VERIFY_FLAGS="); number(ca.verify_flags(p->client)); emit("\r\n");
    emit("POSITIVE_SERVER_VERIFY_FLAGS="); number(sa.verify_flags(p->server)); emit("\r\n");
    emit("POSITIVE_SERVER_VERSION="); emit(sa.version(p->server)); emit("\r\n");
    emit("CLIENT_CERTIFICATE_AUTHENTICATION=not-requested\r\n");
}
#endif
static int transfer(pair *p, int client_to_server, const unsigned char *data, size_t bytes)
{
    unsigned char received[4096];
    size_t sent = 0, got = 0, count;
    unsigned step;
    int status;
    if (bytes > sizeof received) return 0;
    for (step = 0; step < STEP_LIMIT; ++step) {
        if (sent < bytes) {
            count = 0;
            status = client_to_server
                ? ca.write(p->client, data + sent, bytes - sent, &count)
                : sa.write(p->server, data + sent, bytes - sent, &count);
            if (status < 0 || status == 3 || count > bytes - sent) return 0;
            if (status == 0) sent += count;
            else if (count || (status != 1 && status != 2)) return 0;
        }
        if (got < bytes) {
            count = 0;
            status = client_to_server
                ? sa.read(p->server, received + got, bytes - got, &count)
                : ca.read(p->client, received + got, bytes - got, &count);
            if (status < 0 || status == 3 || count > bytes - got) return 0;
            if (status == 0) got += count;
            else if (count || (status != 1 && status != 2)) return 0;
        }
        if (sent == bytes && got == bytes) return equal(data, received, bytes);
    }
    return 0;
}
static void positive(const blob *trust, const blob *cert, const blob *key)
{
    pair p;
    unsigned char forward[3072], reverse[1021], byte = 0;
    size_t i, count;
    unsigned step;
    int pass = create_pair(&p, trust, cert, key, "tls13.win98.test");
    int closed = 0, local_closed = 0;
    check("PAIR_CREATE", pass);
    if (!pass) { destroy_pair(&p); return; }
    pass = authenticated_handshake(&p);
#ifndef M98_INTEROP_CONTROLLER_TEST
    positive_diagnostics(&p);
#endif
    check("TLS13_HANDSHAKE_BOTH_DLLS", pass);
    for (i = 0; i < sizeof forward; ++i) forward[i] = (unsigned char)(i * 17u + 3u);
    for (i = 0; i < sizeof reverse; ++i) reverse[i] = (unsigned char)(i * 31u + 9u);
    if (pass) {
        pass = transfer(&p, 1, forward, sizeof forward) &&
               transfer(&p, 0, reverse, sizeof reverse);
        check("AUTHENTICATED_BIDIRECTIONAL_PAYLOAD", pass);
        check("BOUNDED_PARTIAL_IO_WANT_RETRIES",
              p.to_client.blocked && p.to_server.blocked &&
              p.to_client.sent > sizeof reverse && p.to_server.sent > sizeof forward);
    }
    if (pass) {
        for (step = 0; step < STEP_LIMIT; ++step) {
            if (!local_closed) {
                int status = ca.shutdown(p.client);
                if (status < 0 || status == M98_TLS_EOF) break;
                local_closed = status == M98_TLS_OK;
            }
            p.server_status = sa.read(p.server, &byte, 1, &count);
            if (p.server_status == NTWST_CLOSED) { closed = 1; break; }
            if (p.server_status < 0 || p.server_status == NTWST_OK || count) break;
        }
        check("AUTHENTICATED_CLOSE_NOTIFY", closed && local_closed && !count);
        count = 999;
        check("WRITE_AFTER_CLOSE_DENIED",
              ca.write(p.client, &byte, 1, &count) == M98_TLS_STATE && !count &&
              !ca.is_established(p.client));
    }
    destroy_pair(&p);
}
static void rejection(const char *name, const blob *trust, const blob *cert,
                       const blob *key, const char *hostname)
{
    pair p;
    unsigned char byte = 0;
    size_t count = 999;
    int pass = create_pair(&p, trust, cert, key, hostname) && !handshake(&p) &&
               p.client_status == M98_TLS_VERIFY && ca.verify_flags(p.client) &&
               !ca.is_established(p.client);
    if (pass) pass = ca.read(p.client, &byte, 1, &count) == M98_TLS_STATE && !count;
    count = 999;
    if (pass) pass = ca.write(p.client, &byte, 1, &count) == M98_TLS_STATE && !count;
    check(name, pass);
    destroy_pair(&p);
}
static void failed_entropy(const blob *trust)
{
    pair p;
    m98_tls_options o;
    static const int rejected[] = { 0, -1, 2 };
    static const char *names[] = { "ENTROPY_ZERO_REJECTED", "ENTROPY_MINUS1_REJECTED",
                                 "ENTROPY_TWO_REJECTED" };
    unsigned i;
    unsigned char byte = 0;
    size_t count;
    for (i = 0; i < 3; ++i) {
        clear(&p, sizeof p); p.entropy_result = rejected[i];
        options(&o, &p, trust, "tls13.win98.test");
        check(names[i], ca.create(&o, &p.client) == M98_TLS_ENTROPY && !p.client);
        if (p.client) ca.free(p.client);
    }
    clear(&p, sizeof p); p.entropy_result = 1;
    options(&o, &p, trust, "tls13.win98.test");
    if (ca.create(&o, &p.client) != M98_TLS_OK) {
        check("LATE_ENTROPY_FAILURE_DENIED", 0);
        if (p.client) ca.free(p.client);
        return;
    }
    p.entropy_result = -1;
    count = 999;
    check("LATE_ENTROPY_FAILURE_DENIED",
          ca.handshake(p.client) == M98_TLS_ENTROPY &&
          !ca.is_established(p.client) &&
          ca.write(p.client, &byte, 1, &count) == M98_TLS_STATE && !count &&
          ca.handshake(p.client) == M98_TLS_STATE);
    ca.free(p.client);
}
static void tampered_ciphertext(const blob *trust, const blob *cert, const blob *key)
{
    pair p;
    unsigned char message[32], received[64];
    size_t count = 0;
    unsigned step;
    int status = NTWST_INVALID;
    int pass = create_pair(&p, trust, cert, key, "tls13.win98.test") && handshake(&p);
    clear(message, sizeof message);
    if (pass) {
        for (step = 0; step < STEP_LIMIT; ++step) {
            status = sa.write(p.server, message, sizeof message, &count);
            if (status == NTWST_OK || status < 0 || status == NTWST_CLOSED) break;
        }
        pass = status == NTWST_OK && count == sizeof message && p.to_client.count > 5;
    }
    if (pass) {
        p.to_client.bytes[(p.to_client.head + p.to_client.count - 1) % QUEUE_CAPACITY] ^= 1;
        for (step = 0; step < STEP_LIMIT; ++step) {
            status = ca.read(p.client, received, sizeof received, &count);
            if (status < 0 || status == M98_TLS_OK || status == M98_TLS_EOF) break;
        }
        pass = status == M98_TLS_PROTOCOL && !count && !ca.is_established(p.client);
        count = 999;
        if (pass) pass = ca.write(p.client, message, 1, &count) == M98_TLS_STATE && !count;
    }
    check("LATEST_CLIENT_TAMPERED_CIPHERTEXT_NO_PLAINTEXT", pass);
    destroy_pair(&p);
}

#ifndef M98_INTEROP_CONTROLLER_TEST
void mainCRTStartup(void)
{
    blob trust, cert, key, badtrust;
    OSVERSIONINFOA version;
    int runtime_live = 0, loaded;
    int64_t now;
    DWORD exit_code;
    clear(&trust, sizeof trust); clear(&cert, sizeof cert);
    clear(&key, sizeof key); clear(&badtrust, sizeof badtrust);
    if (!initialize_report()) ExitProcess(3);
    clear(&version, sizeof version); version.dwOSVersionInfoSize = sizeof version;
    loaded = GetVersionExA(&version) && version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS &&
             version.dwMajorVersion == 4 && version.dwMinorVersion == 10;
    check("WIN98_IDENTIFIED", loaded);
    if (!loaded) goto cleanup;
    loaded = load_apis();
    check("LOAD_BOTH_DLLS_AND_9_13_EXPORTS", loaded);
    if (!loaded) goto cleanup;
    loaded = load_blob("CA.PEM", &trust) && load_blob("SRV.PEM", &cert) &&
             load_blob("SRV.KEY", &key) && load_blob("BADCA.PEM", &badtrust);
    check("FIXTURES_LOADED", loaded);
    if (!loaded) goto cleanup;
    loaded = crypto_acquire(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) != 0;
    check("NATIVE_CRYPTOAPI_CSPRNG", loaded);
    if (!loaded) goto cleanup;
    now = utc_seconds(NULL);
    emit("UNIX_TIME=");
    if (now < 0) emit("-1"); else number64((uint64_t)now);
    emit("\r\n");
    check("NATIVE_UTC_VALID", now >= INT64_C(1577836800) && now < INT64_C(2051222400));
    if (failures) goto cleanup;
    runtime_live = sa.native_runtime_init() == NTWST_OK;
    check("INDEPENDENT_SERVER_PSA_NATIVE_INIT", runtime_live);
    if (!runtime_live) goto cleanup;
    failed_entropy(&trust);
    positive(&trust, &cert, &key);
    rejection("WRONG_HOST_REJECTED_WITHOUT_PLAINTEXT", &trust, &cert, &key,
              "wrong-host.invalid");
    rejection("UNTRUSTED_CA_REJECTED_WITHOUT_PLAINTEXT", &badtrust, &cert, &key,
              "tls13.win98.test");
    tampered_ciphertext(&trust, &cert, &key);
cleanup:
    if (runtime_live) check("SERVER_RUNTIME_SHUTDOWN", sa.native_runtime_fini() == NTWST_OK);
    if (provider) check("CRYPTOAPI_PROVIDER_RELEASED", crypto_release(provider, 0) != 0);
    if (key.bytes) clear(key.bytes, key.size);
    if (trust.bytes) HeapFree(GetProcessHeap(), 0, trust.bytes);
    if (cert.bytes) HeapFree(GetProcessHeap(), 0, cert.bytes);
    if (key.bytes) HeapFree(GetProcessHeap(), 0, key.bytes);
    if (badtrust.bytes) HeapFree(GetProcessHeap(), 0, badtrust.bytes);
    if (server_module) check("SERVER_DLL_UNLOADED", FreeLibrary(server_module) != 0);
    if (client_module) check("CLIENT_DLL_UNLOADED", FreeLibrary(client_module) != 0);
    if (crypto_module) check("CRYPTOAPI_DLL_UNLOADED", FreeLibrary(crypto_module) != 0);
    emit("CHECKS="); number(checks); emit("\r\nFAILURES="); number(failures); emit("\r\n");
    exit_code = failures || report_failed ? 1 : 0;
    emit(exit_code ? "FINAL=FAIL\r\n" : "FINAL=PASS\r\n");
    emit("REQUESTED_EXIT="); number(exit_code); emit("\r\n");
    if (!FlushFileBuffers(report)) report_failed = 1;
    if (!CloseHandle(report)) report_failed = 1;
    /* The external parent must observe process exit. The log is not itself an
     * exit/teardown receipt, and a log-close failure forces actual exit 1. */
    ExitProcess(failures || report_failed ? 1 : 0);
}
#endif
