/* SPDX-License-Identifier: GPL-2.0-only
 * Actual TLS 1.3 client/server over bounded memory queues. No network service is
 * required. Compile the same source for the host and the native Win98 guest;
 * successful host execution is not a guest compatibility claim.
 */
#include "transport.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/platform_time.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "psa/crypto.h"
#include "psa/crypto_extra.h"
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <sys/random.h>
#endif

#define QUEUE_CAPACITY 257u
#define STEP_LIMIT 20000u
#define FIXTURE_LIMIT (1u << 20)

typedef struct blob { unsigned char *bytes; size_t size; } blob;
typedef struct queue {
    unsigned char bytes[QUEUE_CAPACITY];
    size_t head, count, sent, received, blocked;
    int eof, force_block;
} queue;
typedef struct endpoint { queue *out, *in; } endpoint;
typedef struct pair {
    queue client_to_server, server_to_client;
    endpoint client_io, server_io;
    ntwst_connection *client, *server;
    int client_status, server_status;
    unsigned steps;
} pair;
typedef struct rng {
    unsigned long calls;
    int fail;
#ifdef _WIN32
    HMODULE module;
    HCRYPTPROV provider;
    BOOL (WINAPI *acquire)(HCRYPTPROV *, LPCSTR, LPCSTR, DWORD, DWORD);
    BOOL (WINAPI *generate)(HCRYPTPROV, DWORD, BYTE *);
    BOOL (WINAPI *release)(HCRYPTPROV, DWORD);
#endif
} rng;

static FILE *report;
static const char *nonce = "unspecified";

static int random_open(rng *source)
{
    memset(source, 0, sizeof *source);
#ifdef _WIN32
    source->module = LoadLibraryA("ADVAPI32.DLL");
    if (!source->module) return -1;
    source->acquire = (BOOL (WINAPI *)(HCRYPTPROV *, LPCSTR, LPCSTR, DWORD, DWORD))
        (uintptr_t)GetProcAddress(source->module, "CryptAcquireContextA");
    source->generate = (BOOL (WINAPI *)(HCRYPTPROV, DWORD, BYTE *))
        (uintptr_t)GetProcAddress(source->module, "CryptGenRandom");
    source->release = (BOOL (WINAPI *)(HCRYPTPROV, DWORD))
        (uintptr_t)GetProcAddress(source->module, "CryptReleaseContext");
    if (!source->acquire || !source->generate || !source->release) return -1;
    /* ANSI acquisition is available on measured Win98; do not import the
     * unsupported Unicode variant or invent an entropy fallback. */
    if (!source->acquire(&source->provider, NULL, NULL, PROV_RSA_FULL,
                         CRYPT_VERIFYCONTEXT)) return -1;
#endif
    return 0;
}

static void random_close(rng *source)
{
#ifdef _WIN32
    if (source->provider && source->release) source->release(source->provider, 0);
    if (source->module) FreeLibrary(source->module);
#endif
    memset(source, 0, sizeof *source);
}

static int random_bytes(void *context, unsigned char *bytes, size_t size)
{
    rng *source = context;
    ++source->calls;
    if (source->fail) return -1;
    while (size) {
#ifdef _WIN32
        DWORD chunk = (DWORD)(size < (1u << 20) ? size : (1u << 20));
        if (!source->generate(source->provider, chunk, bytes)) return -1;
        bytes += chunk;
        size -= chunk;
#else
        ssize_t got = getrandom(bytes, size, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return -1;
        bytes += (size_t)got;
        size -= (size_t)got;
#endif
    }
    return 0;
}

static int memory_send(void *context, const unsigned char *bytes, size_t size)
{
    endpoint *io = context;
    queue *q = io->out;
    size_t count, i;
    if (q->eof) return NTWST_IO_ERROR;
    if (q->force_block) { ++q->blocked; return NTWST_IO_WOULD_BLOCK; }
    if (q->count == QUEUE_CAPACITY) { ++q->blocked; return NTWST_IO_WOULD_BLOCK; }
    count = size < QUEUE_CAPACITY - q->count ? size : QUEUE_CAPACITY - q->count;
    if (count > 17) count = 17;  /* deliberate short transport writes */
    for (i = 0; i < count; ++i)
        q->bytes[(q->head + q->count + i) % QUEUE_CAPACITY] = bytes[i];
    q->count += count;
    q->sent += count;
    return (int)count;
}

static int memory_receive(void *context, unsigned char *bytes, size_t size)
{
    endpoint *io = context;
    queue *q = io->in;
    size_t count, i;
    if (!q->count) {
        if (q->eof) return 0;
        ++q->blocked;
        return NTWST_IO_WOULD_BLOCK;
    }
    count = size < q->count ? size : q->count;
    if (count > 13) count = 13;  /* deliberate short transport reads */
    for (i = 0; i < count; ++i) bytes[i] = q->bytes[(q->head + i) % QUEUE_CAPACITY];
    q->head = (q->head + count) % QUEUE_CAPACITY;
    q->count -= count;
    q->received += count;
    return (int)count;
}

static int load_blob(const char *path, blob *data)
{
    FILE *file = fopen(path, "rb");
    long size;
    if (!file) return -1;
    if (fseek(file, 0, SEEK_END) || (size = ftell(file)) <= 0 ||
        size > (long)FIXTURE_LIMIT || fseek(file, 0, SEEK_SET)) {
        fclose(file);
        return -1;
    }
    data->bytes = malloc((size_t)size + 1);
    if (!data->bytes) { fclose(file); return -1; }
    if (fread(data->bytes, 1, (size_t)size, file) != (size_t)size) {
        fclose(file); free(data->bytes); data->bytes = NULL; return -1;
    }
    fclose(file);
    data->bytes[size] = 0;
    data->size = (size_t)size + 1;  /* PEM parser includes NUL */
    return 0;
}

static void free_blob(blob *data)
{
    if (data->bytes) { memset(data->bytes, 0, data->size); free(data->bytes); }
    memset(data, 0, sizeof *data);
}

static void pair_destroy(pair *p)
{
    ntwst_destroy(p->client);
    ntwst_destroy(p->server);
    free(p);
}

static pair *pair_create(const char *hostname, const blob *ca,
                         const blob *certificate, const blob *key)
{
    pair *p = calloc(1, sizeof *p);
    ntwst_config client, server;
    if (!p) return NULL;
    memset(&client, 0, sizeof client);
    memset(&server, 0, sizeof server);
    p->client_io.out = &p->client_to_server;
    p->client_io.in = &p->server_to_client;
    p->server_io.out = &p->server_to_client;
    p->server_io.in = &p->client_to_server;
    client.role = NTWST_CLIENT;
    client.hostname = hostname;
    client.ca_certificate = ca->bytes;
    client.ca_certificate_size = ca->size;
    client.send = memory_send;
    client.receive = memory_receive;
    client.io_context = &p->client_io;
    server.role = NTWST_SERVER;
    server.own_certificate = certificate->bytes;
    server.own_certificate_size = certificate->size;
    server.private_key = key->bytes;
    server.private_key_size = key->size;
    server.send = memory_send;
    server.receive = memory_receive;
    server.io_context = &p->server_io;
    p->client_status = ntwst_create(&client, &p->client);
    p->server_status = ntwst_create(&server, &p->server);
    if (p->client_status != NTWST_OK || p->server_status != NTWST_OK) {
        fprintf(report, "{\"case\":\"connection_create\",\"passed\":false,"
                "\"client_status\":%d,\"server_status\":%d,\"nonce\":\"%s\"}\n",
                p->client_status, p->server_status, nonce);
        pair_destroy(p);
        return NULL;
    }
    return p;
}

static int pair_handshake(pair *p)
{
    int client_done = 0, server_done = 0;
    for (p->steps = 1; p->steps <= STEP_LIMIT; ++p->steps) {
        if (!client_done) {
            p->client_status = ntwst_handshake(p->client);
            if (p->client_status < 0 || p->client_status == NTWST_CLOSED) return -1;
            client_done = p->client_status == NTWST_OK;
        }
        if (!server_done) {
            p->server_status = ntwst_handshake(p->server);
            if (p->server_status < 0 || p->server_status == NTWST_CLOSED) return -1;
            server_done = p->server_status == NTWST_OK;
        }
        if (client_done && server_done) return 0;
    }
    return -1;
}

static int transfer(ntwst_connection *from, ntwst_connection *to,
                    const unsigned char *message, size_t size)
{
    unsigned char received[4096];
    size_t sent = 0, got = 0, count;
    unsigned step;
    int status;
    if (size > sizeof received) return 0;
    for (step = 0; step < STEP_LIMIT; ++step) {
        if (sent < size) {
            status = ntwst_write(from, message + sent, size - sent, &count);
            if (status < 0 || status == NTWST_CLOSED) return 0;
            if (status == NTWST_OK) sent += count;
        }
        if (got < size) {
            status = ntwst_read(to, received + got, size - got, &count);
            if (status < 0 || status == NTWST_CLOSED) return 0;
            if (status == NTWST_OK) got += count;
        }
        if (sent == size && got == size) return !memcmp(message, received, size);
    }
    return 0;
}

static void case_report(const char *name, int passed, const pair *p)
{
    fprintf(report, "{\"case\":\"%s\",\"passed\":%s,\"client_status\":%d,"
            "\"server_status\":%d,\"version\":\"%s\",\"verify_flags\":%lu,"
            "\"engine_error\":%d,\"steps\":%u,\"nonce\":\"%s\"}\n",
            name, passed ? "true" : "false", p ? p->client_status : NTWST_INVALID,
            p ? p->server_status : NTWST_INVALID, p ? ntwst_version(p->client) : "",
            (unsigned long)(p ? ntwst_verify_flags(p->client) : UINT32_MAX),
            p ? ntwst_engine_error(p->client) : 0, p ? p->steps : 0, nonce);
    fflush(report);
}

static int rejection_case(const char *name, const char *hostname, const blob *ca,
                          const blob *certificate, const blob *key, uint32_t flag)
{
    pair *p = pair_create(hostname, ca, certificate, key);
    int passed = p && pair_handshake(p) != 0 &&
                 p->client_status == NTWST_CERTIFICATE_ERROR &&
                 (ntwst_verify_flags(p->client) & flag) &&
                 !*ntwst_version(p->client);
    if (p && passed) {
        unsigned char byte;
        size_t count = 999;
        /* A failed certificate can never lead to application plaintext. */
        passed = ntwst_read(p->client, &byte, 1, &count) == NTWST_INVALID && !count;
    }
    case_report(name, passed, p);
    if (p) pair_destroy(p);
    return passed;
}

static int valid_case(const char *hostname, const blob *ca, const blob *cert,
                      const blob *key, rng *source)
{
    unsigned char payload[2307], answer[1019], byte = 0;
    size_t i, count;
    unsigned step;
    int passed, closed = 0, status;
    pair *p = pair_create(hostname, ca, cert, key);
    if (!p) { case_report("valid", 0, NULL); return 0; }
    passed = pair_handshake(p) == 0 && !strcmp(ntwst_version(p->client), "TLSv1.3") &&
             !strcmp(ntwst_version(p->server), "TLSv1.3") && !ntwst_verify_flags(p->client);
    for (i = 0; i < sizeof payload; ++i) payload[i] = (unsigned char)(i * 17u + 3u);
    for (i = 0; i < sizeof answer; ++i) answer[i] = (unsigned char)(i * 31u + 9u);
    if (passed) passed = transfer(p->client, p->server, payload, sizeof payload) &&
                         transfer(p->server, p->client, answer, sizeof answer);
    if (passed) passed = p->client_to_server.blocked && p->server_to_client.blocked &&
                         ntwst_runtime_init(random_bytes, source) == NTWST_BUSY &&
                         ntwst_runtime_fini() == NTWST_BUSY;
    if (passed) {
        p->client_to_server.force_block = 1;
        passed = ntwst_close_notify(p->client) == NTWST_WANT_WRITE &&
                 ntwst_handshake(p->client) == NTWST_BUSY &&
                 ntwst_read(p->client, &byte, 1, &count) == NTWST_BUSY && !count &&
                 ntwst_write(p->client, &byte, 1, &count) == NTWST_INVALID && !count;
        p->client_to_server.force_block = 0;
    }
    if (passed) {
        for (step = 0; step < STEP_LIMIT; ++step) {
            status = ntwst_close_notify(p->client);
            if (status < 0) break;
            status = ntwst_read(p->server, &byte, 1, &count);
            if (status == NTWST_CLOSED) { closed = 1; break; }
            if (status < 0) break;
        }
        passed = closed && ntwst_write(p->client, &byte, 1, &count) == NTWST_INVALID &&
                 !count && ntwst_write(p->server, &byte, 1, &count) == NTWST_INVALID && !count;
        if (passed) passed = ntwst_handshake(p->client) == NTWST_CLOSED &&
                             ntwst_handshake(p->server) == NTWST_CLOSED;
    }
    case_report("valid_bidirectional_payload_and_close", passed, p);
    pair_destroy(p);
    return passed;
}

static int truncation_case(const char *hostname, const blob *ca,
                           const blob *cert, const blob *key)
{
    unsigned char payload[2307], byte;
    size_t count;
    unsigned step;
    int status, passed;
    pair *p = pair_create(hostname, ca, cert, key);
    if (!p) { case_report("partial_write_and_truncation", 0, NULL); return 0; }
    memset(payload, 0x5c, sizeof payload);
    passed = pair_handshake(p) == 0;
    if (passed) {
        status = ntwst_write(p->client, payload, sizeof payload, &count);
        passed = status == NTWST_WANT_WRITE && !count &&
                 p->client_to_server.count == QUEUE_CAPACITY;
        if (passed) passed =
            ntwst_write(p->client, payload + 1, sizeof payload - 1, &count) == NTWST_INVALID && !count &&
            ntwst_read(p->client, &byte, 1, &count) == NTWST_BUSY && !count &&
            ntwst_handshake(p->client) == NTWST_BUSY &&
            ntwst_close_notify(p->client) == NTWST_BUSY;
        /* Resume exactly the pending operation, which must deliver the original
         * bytes despite the preceding rejected retry. */
        if (passed) passed = transfer(p->client, p->server, payload, sizeof payload);
        if (passed) {
            status = ntwst_write(p->client, payload, sizeof payload, &count);
            passed = status == NTWST_WANT_WRITE && !count;
            p->client_to_server.eof = 1;  /* close in the middle of an encrypted record */
            for (step = 0; passed && step < STEP_LIMIT; ++step) {
                status = ntwst_read(p->server, &byte, 1, &count);
                if (status == NTWST_TRUNCATED) break;
                if (status != NTWST_WANT_READ && status != NTWST_WANT_WRITE) passed = 0;
            }
            passed = passed && step < STEP_LIMIT && !count &&
                     ntwst_write(p->server, &byte, 1, &count) == NTWST_INVALID && !count;
        }
    }
    case_report("partial_write_and_truncation", passed, p);
    pair_destroy(p);
    return passed;
}

/* The control peer deliberately offers TLS 1.2 only. It uses the same pinned
 * engine and externally serialized PSA lifetime solely inside this probe;
 * production callers must respect the transport runtime's exclusive ownership. */
static int control_send(void *context, const unsigned char *bytes, size_t size)
{
    int result = memory_send(context, bytes, size);
    return result == NTWST_IO_WOULD_BLOCK ? MBEDTLS_ERR_SSL_WANT_WRITE : result;
}
static int control_receive(void *context, unsigned char *bytes, size_t size)
{
    int result = memory_receive(context, bytes, size);
    return result == NTWST_IO_WOULD_BLOCK ? MBEDTLS_ERR_SSL_WANT_READ : result;
}

static int downgrade_case(const char *hostname, const blob *ca,
                          const blob *cert, const blob *key, rng *source)
{
    pair *p = pair_create(hostname, ca, cert, key);
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_x509_crt certificate;
    mbedtls_pk_context private_key;
    int error = 0, passed = 0, server_failed = 0;
    unsigned step;
    if (!p) { case_report("tls12_only_peer_rejected", 0, NULL); return 0; }
    /* Replace only the probe's server endpoint, retaining the real adapter
     * client and the same hostile short-I/O transport. */
    ntwst_destroy(p->server);
    p->server = NULL;
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&config);
    mbedtls_x509_crt_init(&certificate);
    mbedtls_pk_init(&private_key);
    error = mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_SERVER,
                                        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (error) goto cleanup;
    mbedtls_ssl_conf_min_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_rng(&config, random_bytes, source);
    mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_NONE);
    error = mbedtls_x509_crt_parse(&certificate, cert->bytes, cert->size);
    if (error) goto cleanup;
    error = mbedtls_pk_parse_key(&private_key, key->bytes, key->size, NULL, 0, random_bytes, source);
    if (error) goto cleanup;
    error = mbedtls_ssl_conf_own_cert(&config, &certificate, &private_key);
    if (error) goto cleanup;
    error = mbedtls_ssl_setup(&ssl, &config);
    if (error) goto cleanup;
    mbedtls_ssl_set_bio(&ssl, &p->server_io, control_send, control_receive, NULL);
    for (step = 1; step <= STEP_LIMIT; ++step) {
        p->steps = step;
        p->client_status = ntwst_handshake(p->client);
        if (p->client_status == NTWST_OK) break;
        if (!server_failed) {
            error = mbedtls_ssl_handshake(&ssl);
            p->server_status = error;
            if (error != MBEDTLS_ERR_SSL_WANT_READ && error != MBEDTLS_ERR_SSL_WANT_WRITE) {
                server_failed = 1;
                /* Do not call a fatally failed SSL context again. Existing
                 * alert bytes drain before EOF; keep pumping the real client
                 * until it rejects that peer rather than ending at WANT_READ. */
                p->server_to_client.eof = 1;
            }
        }
        if (p->client_status < 0) break;
    }
    passed = step <= STEP_LIMIT && server_failed &&
             (error == MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION || error == MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE) &&
             p->client_status < 0 && !*ntwst_version(p->client);
    if (passed) {
        unsigned char byte = 0;
        size_t count;
        passed = ntwst_read(p->client, &byte, 1, &count) == NTWST_INVALID && !count;
    }
cleanup:
    p->server_status = error;
    case_report("tls12_only_peer_rejected", passed, p);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&config);
    mbedtls_x509_crt_free(&certificate);
    mbedtls_pk_free(&private_key);
    pair_destroy(p);
    return passed;
}

static int late_random_failure_case(const char *hostname, const blob *ca,
                                    const blob *cert, const blob *key, rng *source)
{
    pair *p = pair_create(hostname, ca, cert, key);
    unsigned char byte = 0;
    size_t count;
    int passed = 0;
    if (p) {
        /* Server key parsing and runtime init already succeeded. The OS source
         * now fails when the real TLS handshake requests a key share. */
        source->fail = 1;
        p->client_status = ntwst_handshake(p->client);
        passed = p->client_status < 0 &&
                 ntwst_handshake(p->client) == NTWST_ENGINE_ERROR &&
                 ntwst_write(p->client, &byte, 1, &count) == NTWST_INVALID && !count &&
                 !*ntwst_version(p->client);
        source->fail = 0;
    }
    case_report("os_random_failure_during_handshake", passed, p);
    if (p) pair_destroy(p);
    return passed;
}

static int tamper_case(const char *hostname, const blob *ca,
                       const blob *cert, const blob *key)
{
    unsigned char payload[32], received[64];
    size_t count;
    unsigned step;
    int status = NTWST_INVALID, passed;
    pair *p = pair_create(hostname, ca, cert, key);
    if (!p) { case_report("modified_ciphertext_rejected", 0, NULL); return 0; }
    memset(payload, 0x91, sizeof payload);
    passed = pair_handshake(p) == 0;
    if (passed) {
        status = ntwst_write(p->client, payload, sizeof payload, &count);
        passed = status == NTWST_OK && count == sizeof payload && p->client_to_server.count > 5;
        if (passed) {
            queue *q = &p->client_to_server;
            /* Flip an authenticated ciphertext/tag byte, preserving the TLS
             * header and framing. The application must receive zero plaintext. */
            q->bytes[(q->head + q->count - 1) % QUEUE_CAPACITY] ^= 1;
            for (step = 0; step < STEP_LIMIT; ++step) {
                status = ntwst_read(p->server, received, sizeof received, &count);
                if (status < 0 || status == NTWST_OK || status == NTWST_CLOSED) break;
            }
            passed = step < STEP_LIMIT && status == NTWST_ENGINE_ERROR && !count &&
                     ntwst_engine_error(p->server) == MBEDTLS_ERR_SSL_INVALID_MAC;
        }
    }
    p->server_status = status;
    case_report("modified_ciphertext_rejected", passed, p);
    pair_destroy(p);
    return passed;
}

static int boundary_eof_case(const char *hostname, const blob *ca,
                             const blob *cert, const blob *key)
{
    unsigned char byte;
    size_t count;
    int passed;
    pair *p = pair_create(hostname, ca, cert, key);
    if (!p) { case_report("record_boundary_eof_rejected", 0, NULL); return 0; }
    passed = pair_handshake(p) == 0 && !p->client_to_server.count;
    if (passed) {
        p->client_to_server.eof = 1;
        p->server_status = ntwst_read(p->server, &byte, 1, &count);
        passed = p->server_status == NTWST_TRUNCATED && !count;
    }
    case_report("record_boundary_eof_rejected", passed, p);
    pair_destroy(p);
    return passed;
}

static int nonce_valid(const char *value)
{
    size_t i;
    for (i = 0; value[i]; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (i >= 128 || !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                         (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                         c == '.' || c == ':')) return 0;
    }
    return i != 0;
}

int main(int argc, char **argv)
{
    const char *names[] = {"--server-cert", "--server-key", "--ca", "--untrusted-ca",
                          "--expired-cert", "--expired-key"};
    const char *paths[6] = {NULL, NULL, NULL, NULL, NULL, NULL};
    const char *hostname = "tls13.win98.test", *output = NULL;
    blob fixtures[6];
    rng source;
    int i, j, status, all_passed = 1, valid = 0, wrong_host = 0, untrusted = 0,
        expired = 0, truncation = 0, downgrade = 0, late_random_failure = 0,
        tamper = 0, boundary_eof = 0, zero_random = 0,
        random_failure = 0, runtime_live = 0;
    memset(fixtures, 0, sizeof fixtures);
    memset(&source, 0, sizeof source);
    report = stdout;
    for (i = 1; i < argc; i += 2) {
        int found = 0;
        if (i + 1 >= argc) { all_passed = 0; break; }
        for (j = 0; j < 6; ++j) if (!strcmp(argv[i], names[j])) { paths[j] = argv[i + 1]; found = 1; }
        if (!strcmp(argv[i], "--hostname")) { hostname = argv[i + 1]; found = 1; }
        if (!strcmp(argv[i], "--output")) { output = argv[i + 1]; found = 1; }
        if (!strcmp(argv[i], "--nonce")) { nonce = argv[i + 1]; found = 1; }
        if (!found) { all_passed = 0; break; }
    }
    if (!all_passed || !nonce_valid(nonce) || !*hostname) {
        fprintf(stderr, "Usage: tls13-probe --server-cert FILE --server-key FILE --ca FILE "
                "--untrusted-ca FILE --expired-cert FILE --expired-key FILE "
                "[--hostname DNS] [--output FILE] [--nonce TOKEN]\n");
        return 2;
    }
    if (output) {
        report = fopen(output, "w");
        if (!report) return 2;
    }
    fprintf(report, "{\"case\":\"start\",\"nonce\":\"%s\",\"epoch\":%lld,\"platform\":\"%s\"}\n",
            nonce, (long long)mbedtls_time(NULL),
#ifdef _WIN32
            "windows-native-build"
#else
            "linux-host-build"
#endif
    );
#ifdef _WIN32
    {
        OSVERSIONINFOA version;
        int identified;
        memset(&version, 0, sizeof version);
        version.dwOSVersionInfoSize = sizeof version;
        identified = GetVersionExA(&version) != 0;
        fprintf(report, "{\"case\":\"windows_identity\",\"version_query_ok\":%s,"
                "\"platform_id\":%lu,\"major\":%lu,\"minor\":%lu,\"build\":%lu,"
                "\"win98_identified\":%s,\"nonce\":\"%s\"}\n",
                identified ? "true" : "false", (unsigned long)version.dwPlatformId,
                (unsigned long)version.dwMajorVersion, (unsigned long)version.dwMinorVersion,
                (unsigned long)version.dwBuildNumber,
                identified && version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS &&
                version.dwMajorVersion == 4 && version.dwMinorVersion == 10 ? "true" : "false", nonce);
    }
#endif
    fflush(report);
    for (i = 0; i < 6; ++i) {
        if (!paths[i] || load_blob(paths[i], &fixtures[i])) {
            fprintf(report, "{\"case\":\"fixture_load\",\"passed\":false,\"index\":%d,\"nonce\":\"%s\"}\n", i, nonce);
            all_passed = 0;
            goto cleanup;
        }
    }
    if (random_open(&source)) {
        case_report("os_random_source", 0, NULL);
        all_passed = 0;
        goto cleanup;
    }
    status = ntwst_runtime_init(random_bytes, &source);
    if (status != NTWST_OK) {
        case_report("runtime_init", 0, NULL);
        all_passed = 0;
        goto cleanup;
    }
    runtime_live = 1;
    {
        unsigned long before = source.calls;
        size_t count = 999;
        source.fail = 1;
        zero_random = mbedtls_psa_external_get_random(NULL, NULL, 0, &count) == PSA_SUCCESS &&
                      !count && source.calls == before;
        source.fail = 0;
        case_report("zero_size_random_has_no_os_call", zero_random, NULL);
    }
    valid = valid_case(hostname, &fixtures[2], &fixtures[0], &fixtures[1], &source);
    wrong_host = rejection_case("wrong_host_rejected", "wrong-host.invalid", &fixtures[2],
                                 &fixtures[0], &fixtures[1], MBEDTLS_X509_BADCERT_CN_MISMATCH);
    untrusted = rejection_case("untrusted_ca_rejected", hostname, &fixtures[3],
                                &fixtures[0], &fixtures[1], MBEDTLS_X509_BADCERT_NOT_TRUSTED);
    expired = rejection_case("expired_certificate_rejected", hostname, &fixtures[2],
                              &fixtures[4], &fixtures[5], MBEDTLS_X509_BADCERT_EXPIRED);
    truncation = truncation_case(hostname, &fixtures[2], &fixtures[0], &fixtures[1]);
    downgrade = downgrade_case(hostname, &fixtures[2], &fixtures[0], &fixtures[1], &source);
    late_random_failure = late_random_failure_case(hostname, &fixtures[2], &fixtures[0], &fixtures[1], &source);
    tamper = tamper_case(hostname, &fixtures[2], &fixtures[0], &fixtures[1]);
    boundary_eof = boundary_eof_case(hostname, &fixtures[2], &fixtures[0], &fixtures[1]);
    if (ntwst_runtime_fini() == NTWST_OK) {
        runtime_live = 0;
        source.fail = 1;
        random_failure = ntwst_runtime_init(random_bytes, &source) == NTWST_RANDOM_ERROR;
        source.fail = 0;
    }
    case_report("failed_os_random_rejected", random_failure, NULL);
    all_passed = valid && wrong_host && untrusted && expired && truncation &&
                 downgrade && late_random_failure && tamper && boundary_eof && zero_random && random_failure;
cleanup:
    if (runtime_live && ntwst_runtime_fini() != NTWST_OK) all_passed = 0;
    fprintf(report, "{\"passed\":%s,\"tls13_handshake\":%s,\"authenticated_payload\":%s,"
            "\"wrong_host_rejected\":%s,\"untrusted_ca_rejected\":%s,\"expired_rejected\":%s,"
            "\"partial_io_and_truncation\":%s,\"random_failure_rejected\":%s,"
            "\"tls12_downgrade_rejected\":%s,\"late_random_failure_rejected\":%s,"
            "\"modified_ciphertext_rejected\":%s,\"record_boundary_eof_rejected\":%s,"
            "\"zero_size_random_has_no_os_call\":%s,"
            "\"random_calls\":%lu,\"nonce\":\"%s\"}\n",
            all_passed ? "true" : "false", valid ? "true" : "false", valid ? "true" : "false",
            wrong_host ? "true" : "false", untrusted ? "true" : "false", expired ? "true" : "false",
            truncation ? "true" : "false", random_failure ? "true" : "false",
            downgrade ? "true" : "false", late_random_failure ? "true" : "false",
            tamper ? "true" : "false", boundary_eof ? "true" : "false",
            zero_random ? "true" : "false", source.calls, nonce);
    for (i = 0; i < 6; ++i) free_blob(&fixtures[i]);
    random_close(&source);
    if (fflush(report) || ferror(report)) all_passed = 0;
    if (output && fclose(report)) all_passed = 0;
    return all_passed ? 0 : 1;
}
