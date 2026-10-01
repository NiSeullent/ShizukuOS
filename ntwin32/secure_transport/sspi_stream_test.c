/* SPDX-License-Identifier: GPL-2.0-only
 * Real Mbed TLS client/server protocol checks, not SSPI/OS guest acceptance.
 * Usage: sspi_stream_test PATH_TO_FROZEN_ENGINE_FIXTURES
 */
#include "sspi_stream.h"
#include "transport.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ssl.h"
#include "mbedtls/pk.h"

#define LIMIT 20000u
static unsigned checks, failures, contract_cases;
static int rng_fail;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); } } while (0)

typedef struct blob { unsigned char *p; size_t n; } blob;
typedef struct queue { unsigned char p[NTWSSP_MAX_TOKEN]; size_t n; } queue;
typedef struct pair {
    ntwssp_pool *pool;
    ntwssp_handle client;
    ntwst_connection *server;
    queue server_in, server_out, incoming;
    int client_status, server_status;
} pair;
static blob ca, other_ca, cert, key, expired_cert, expired_key, future_cert;

static int random_bytes(void *user, unsigned char *out, size_t n)
{
    (void)user;
    if (rng_fail) return -1;
    while (n) {
        ssize_t got = getrandom(out, n, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return -1;
        out += (size_t)got; n -= (size_t)got;
    }
    return 0;
}
static blob load(const char *root, const char *name)
{
    char path[4096];
    FILE *f;
    long n;
    blob b = {0};
    if (snprintf(path, sizeof path, "%s/%s", root, name) >= (int)sizeof path) return b;
    f = fopen(path, "rb");
    if (!f) return b;
    if (!fseek(f, 0, SEEK_END) && (n = ftell(f)) > 0 && n < (1 << 20) && !fseek(f, 0, SEEK_SET)) {
        b.p = malloc((size_t)n + 1);
        if (b.p && fread(b.p, 1, (size_t)n, f) == (size_t)n) { b.p[n] = 0; b.n = (size_t)n + 1; }
    }
    fclose(f);
    return b;
}
static void append(queue *q, const void *data, size_t n)
{
    CHECK(n <= sizeof q->p - q->n);
    if (n > sizeof q->p - q->n) return;
    memcpy(q->p + q->n, data, n); q->n += n;
}
static void consume(queue *q, size_t n)
{
    CHECK(n <= q->n);
    if (n > q->n) return;
    memmove(q->p, q->p + n, q->n - n); q->n -= n;
}
static int server_send(void *user, const unsigned char *data, size_t n)
{
    pair *p = user;
    if (n > sizeof p->server_out.p - p->server_out.n) n = sizeof p->server_out.p - p->server_out.n;
    if (n > 11) n = 11;
    if (!n) return NTWST_IO_WOULD_BLOCK;
    append(&p->server_out, data, n);
    return (int)n;
}
static int server_receive(void *user, unsigned char *data, size_t n)
{
    pair *p = user;
    if (n > p->server_in.n) n = p->server_in.n;
    if (n > 17) n = 17;
    if (!n) return NTWST_IO_WOULD_BLOCK;
    memcpy(data, p->server_in.p, n); consume(&p->server_in, n);
    return (int)n;
}
static ntwssp_options options(const char *host, const blob *trust)
{
    ntwssp_options o;
    o.hostname = host; o.ca = trust->p; o.ca_size = trust->n; o.io_quantum = 7;
    return o;
}
static pair *pair_new(const char *host, const blob *trust, int expired)
{
    pair *p = calloc(1, sizeof *p);
    ntwst_config server = {0};
    ntwssp_options o = options(host, trust);
    if (!p) return NULL;
    if (ntwssp_pool_create(&p->pool) || ntwssp_create(p->pool, &o, &p->client)) goto bad;
    server.role = NTWST_SERVER;
    server.own_certificate = expired == 2 ? future_cert.p : expired ? expired_cert.p : cert.p;
    server.own_certificate_size = expired == 2 ? future_cert.n : expired ? expired_cert.n : cert.n;
    server.private_key = expired == 1 ? expired_key.p : key.p;
    server.private_key_size = expired == 1 ? expired_key.n : key.n;
    server.send = server_send; server.receive = server_receive; server.io_context = p;
    if (ntwst_create(&server, &p->server)) goto bad;
    p->client_status = NTWSSP_CONTINUE; p->server_status = NTWST_WANT_READ;
    return p;
bad:
    ntwssp_pool_destroy(p->pool); ntwst_destroy(p->server); free(p); return NULL;
}
static void pair_free(pair *p)
{
    if (!p) return;
    ntwssp_pool_destroy(p->pool); ntwst_destroy(p->server); free(p);
}
static int handshake(pair *p, int exercise_retry)
{
    static const size_t fragments[] = {1, 2, 3, 5, 13, 127};
    unsigned i;
    unsigned char output[NTWSSP_MAX_TOKEN], copy[NTWSSP_MAX_TOKEN];
    ntwssp_input empty = {0};
    ntwssp_buffer out = {output, exercise_retry ? 1 : sizeof output, 0, 0};
    int r = ntwssp_handshake(p->pool, p->client, &empty, &out);
    if (exercise_retry) {
        unsigned char byte = 0;
        ntwssp_input busy = {&byte, 1, 0, 0};
        CHECK(r == NTWSSP_BUFFER_TOO_SMALL && !out.size && out.required > 1);
        CHECK(ntwssp_handshake(p->pool, p->client, &busy, &out) == NTWSSP_BUSY && !busy.consumed);
        out.capacity = sizeof output;
        r = ntwssp_handshake(p->pool, p->client, &empty, &out);
        CHECK(r == NTWSSP_CONTINUE && out.size && out.size == out.required);
    }
    append(&p->server_in, out.data, out.size);
    for (i = 0; i < LIMIT; ++i) {
        size_t n = fragments[i % (sizeof fragments / sizeof fragments[0])];
        if (p->server_status != NTWST_OK) {
            p->server_status = ntwst_handshake(p->server);
            if (p->server_status < 0) return p->server_status;
        }
        if (n > p->server_out.n) n = p->server_out.n;
        if (n) { append(&p->incoming, p->server_out.p, n); consume(&p->server_out, n); }
        if (p->client_status != NTWSSP_OK) {
            ntwssp_input in = {p->incoming.p, p->incoming.n, 0, 0};
            memcpy(copy, p->incoming.p, p->incoming.n);
            out.capacity = exercise_retry ? 1 : sizeof output;
            r = ntwssp_handshake(p->pool, p->client, &in, &out);
            CHECK(!memcmp(copy, p->incoming.p, p->incoming.n));
            CHECK(in.consumed <= in.size);
            if (r == NTWSSP_INCOMPLETE) CHECK(in.missing > 0 && in.consumed <= in.size);
            consume(&p->incoming, in.consumed);
            if (r == NTWSSP_BUFFER_TOO_SMALL) {
                CHECK(out.required > 1 && !out.size);
                out.capacity = sizeof output;
                r = ntwssp_handshake(p->pool, p->client, &empty, &out);
                CHECK(out.size == out.required && !empty.consumed);
            }
            append(&p->server_in, out.data, out.size);
            if (r < 0) return r;
            p->client_status = r;
        }
        if (p->client_status == NTWSSP_OK && p->server_status == NTWST_OK) {
            ntwssp_info info;
            CHECK(ntwssp_query(p->pool, p->client, &info) == NTWSSP_OK && info.established && !info.failed && !info.verify_flags);
            CHECK(!strcmp(ntwst_version(p->server), "TLSv1.3"));
            CHECK(!p->server_in.n && !p->server_out.n && !p->incoming.n);
            return NTWSSP_OK;
        }
    }
    CHECK(!"handshake iteration limit");
    return NTWSSP_ENGINE;
}
static pair *established(void)
{
    pair *p = pair_new("tls13.win98.test", &ca, 0);
    CHECK(p != NULL);
    if (!p) return NULL;
    CHECK(handshake(p, 1) == NTWSSP_OK);
    return p;
}
static void case_done(const char *name, unsigned before)
{
    ++contract_cases;
    printf("%s: %s\n", name, before == failures ? "PASS" : "FAIL");
}
static void test_handles(void)
{
    unsigned before = failures, i;
    ntwssp_pool *p = NULL, *q = NULL;
    ntwssp_handle h[NTWSSP_MAX_CONTEXTS], other, old, ninth, bad;
    ntwssp_info info;
    ntwssp_options o = options("tls13.win98.test", &ca);
    ntwssp_sizes sizes;
    CHECK(ntwssp_pool_create(&p) == NTWSSP_OK);
    CHECK(ntwssp_pool_create(&q) == NTWSSP_OK);
    o.hostname = "127.0.0.1";
    CHECK(ntwssp_create(p, &o, &ninth) == NTWSSP_INVALID && !ninth.kind);
    o.hostname = "-bad.example";
    CHECK(ntwssp_create(p, &o, &ninth) == NTWSSP_INVALID);
    o.hostname = "tls13.win98.test";
    for (i = 0; i < NTWSSP_MAX_CONTEXTS; ++i) CHECK(ntwssp_create(p, &o, &h[i]) == NTWSSP_OK);
    CHECK(ntwssp_create(p, &o, &ninth) == NTWSSP_LIMIT && !ninth.kind);
    CHECK(ntwst_runtime_fini() == NTWST_BUSY);
    CHECK(ntwssp_stream_sizes(p, h[0], &sizes) == NTWSSP_STATE);
    CHECK(ntwssp_create(q, &o, &other) == NTWSSP_OK);
    CHECK(ntwssp_query(p, other, &info) == NTWSSP_INVALID);
    old = h[0]; CHECK(ntwssp_delete(p, old) == NTWSSP_OK);
    CHECK(ntwssp_create(p, &o, &h[0]) == NTWSSP_OK && h[0].slot == old.slot && h[0].generation != old.generation);
    CHECK(ntwssp_query(p, old, &info) == NTWSSP_INVALID && ntwssp_delete(p, old) == NTWSSP_INVALID);
    bad = h[0]; bad.kind ^= 1;
    CHECK(ntwssp_query(p, bad, &info) == NTWSSP_INVALID);
    for (i = 0; i < NTWSSP_MAX_CONTEXTS; ++i) CHECK(ntwssp_delete(p, h[i]) == NTWSSP_OK);
    ntwssp_pool_destroy(p); ntwssp_pool_destroy(q);
    case_done("bounded typed handles, cross-pool generations and runtime lifetime", before);
}
static void test_negative(const char *name, const char *host, const blob *trust, int expired, uint32_t flag)
{
    unsigned before = failures;
    pair *p = pair_new(host, trust, expired);
    ntwssp_info info;
    CHECK(p != NULL);
    if (p) {
        unsigned char bytes[32] = {0};
        ntwssp_buffer head = {bytes, 5, 0, 0}, data = {bytes + 5, 1, 1, 0}, tail = {bytes + 6, 26, 0, 0};
        CHECK(handshake(p, 0) == NTWSSP_VERIFY);
        CHECK(ntwssp_query(p->pool, p->client, &info) == NTWSSP_OK && info.failed && !info.established && (info.verify_flags & flag));
        CHECK(ntwssp_encrypt(p->pool, p->client, &head, &data, &tail) == NTWSSP_VERIFY);
    }
    pair_free(p); case_done(name, before);
}
static void test_handshake_extra(void)
{
    static const unsigned char malformed[] = {23, 3, 3, 255, 255};
    static const unsigned char incomplete[] = {23, 3};
    unsigned before = failures, i;
    for (i = 0; i < 2; ++i) {
        pair *p = pair_new("tls13.win98.test", &ca, 0);
        unsigned char output[NTWSSP_MAX_TOKEN], copy[NTWSSP_MAX_TOKEN];
        const unsigned char *tail = i ? incomplete : malformed;
        size_t tail_size = i ? sizeof incomplete : sizeof malformed, flight;
        ntwssp_input empty = {0}, in;
        ntwssp_buffer out = {output, sizeof output, 0, 0};
        ntwssp_info info;
        CHECK(p != NULL);
        if (!p) continue;
        CHECK(ntwssp_handshake(p->pool, p->client, &empty, &out) == NTWSSP_CONTINUE);
        append(&p->server_in, out.data, out.size);
        CHECK(ntwst_handshake(p->server) == NTWST_WANT_READ && p->server_out.n);
        flight = p->server_out.n;
        append(&p->incoming, p->server_out.p, flight);
        append(&p->incoming, tail, tail_size);
        memcpy(copy, p->incoming.p, p->incoming.n);
        in = (ntwssp_input){p->incoming.p, p->incoming.n, 0, 0};
        CHECK(ntwssp_handshake(p->pool, p->client, &in, &out) == NTWSSP_OK);
        CHECK(in.consumed == flight && !in.missing && out.size);
        CHECK(!memcmp(copy, p->incoming.p, p->incoming.n));
        CHECK(!memcmp(in.data + in.consumed, tail, tail_size));
        append(&p->server_in, out.data, out.size);
        CHECK(ntwst_handshake(p->server) == NTWST_OK);
        CHECK(ntwssp_query(p->pool, p->client, &info) == NTWSSP_OK && info.established && !info.failed);
        pair_free(p);
    }
    case_done("completed handshake preserves malformed/incomplete EXTRA without MISSING", before);
}
static void test_encrypt(void)
{
    unsigned before = failures;
    pair *p = established();
    unsigned char header[5], trailer[32], data[NTWSSP_MAX_MESSAGE], readback[NTWSSP_MAX_MESSAGE];
    ntwssp_buffer h = {header, sizeof header, 0, 0}, d = {data, sizeof data, sizeof data, 0}, t = {trailer, sizeof trailer, 0, 0};
    ntwssp_sizes limits;
    size_t got = 0, i;
    if (!p) return;
    for (i = 0; i < sizeof data; ++i) data[i] = (unsigned char)(i * 17u + 3u);
    CHECK(ntwssp_stream_sizes(p->pool, p->client, &limits) == NTWSSP_OK && limits.header == 5 && limits.trailer == 32 && limits.maximum_message == sizeof data && limits.buffers == 4 && limits.block_size == 1);
    h.capacity = 4;
    CHECK(ntwssp_encrypt(p->pool, p->client, &h, &d, &t) == NTWSSP_BUFFER_TOO_SMALL && !h.size && !t.size && h.required == 5);
    h.capacity = 5; t.capacity = 31;
    CHECK(ntwssp_encrypt(p->pool, p->client, &h, &d, &t) == NTWSSP_BUFFER_TOO_SMALL && t.required == 32);
    for (i = 0; i < sizeof data; ++i) CHECK(data[i] == (unsigned char)(i * 17u + 3u));
    t.capacity = 32;
    {
        int encrypted = ntwssp_encrypt(p->pool, p->client, &h, &d, &t);
        ntwssp_info diagnostic;
        if (encrypted != NTWSSP_OK && ntwssp_query(p->pool, p->client, &diagnostic) == NTWSSP_OK)
            fprintf(stderr, "encrypt diagnostic core=%d backend=%d header=%zu data=%zu trailer=%zu\n", encrypted, diagnostic.backend_error, h.size, d.size, t.size);
        CHECK(encrypted == NTWSSP_OK && h.size == 5 && d.size == sizeof data && t.size > 0 && t.size <= 32);
    }
    CHECK(header[0] == 23 && 5u + ((size_t)header[3] << 8) + header[4] == h.size + d.size + t.size);
    append(&p->server_in, header, h.size); append(&p->server_in, data, d.size); append(&p->server_in, trailer, t.size);
    CHECK(ntwst_read(p->server, readback, sizeof readback, &got) == NTWST_OK && got == sizeof readback);
    for (i = 0; i < got; ++i) CHECK(readback[i] == (unsigned char)(i * 17u + 3u));
    d.size = 0; CHECK(ntwssp_encrypt(p->pool, p->client, &h, &d, &t) == NTWSSP_INVALID);
    d.size = 1; t.data = data; CHECK(ntwssp_encrypt(p->pool, p->client, &h, &d, &t) == NTWSSP_INVALID);
    t.data = trailer; h.capacity = SIZE_MAX; CHECK(ntwssp_encrypt(p->pool, p->client, &h, &d, &t) == NTWSSP_INVALID);
    pair_free(p); case_done("in-place max-size encrypt layout, preflight retry and real peer plaintext", before);
}
static void server_write(pair *p, const void *data, size_t size)
{
    size_t written = 0;
    CHECK(ntwst_write(p->server, data, size, &written) == NTWST_OK && written == size);
}
static void test_decrypt(void)
{
    unsigned before = failures;
    pair *p = established();
    const char first[] = "first authenticated record", second[] = "second record remains EXTRA";
    unsigned char plain[256], copy[NTWSSP_MAX_TOKEN];
    ntwssp_buffer out = {plain, sizeof plain, 0, 0};
    ntwssp_input in, empty = {0};
    size_t first_record, both;
    if (!p) return;
    server_write(p, first, sizeof first);
    first_record = p->server_out.n;
    server_write(p, second, sizeof second);
    both = p->server_out.n;
    memcpy(copy, p->server_out.p, both);
    in = (ntwssp_input){p->server_out.p, 3, 99, 99};
    CHECK(ntwssp_decrypt(p->pool, p->client, &in, &out) == NTWSSP_INCOMPLETE && !in.consumed && in.missing == 2 && !out.size);
    in.size = first_record - 1;
    CHECK(ntwssp_decrypt(p->pool, p->client, &in, &out) == NTWSSP_INCOMPLETE && !in.consumed && in.missing == 1 && !out.size);
    CHECK(!memcmp(copy, p->server_out.p, both));
    out.capacity = 1; in.size = both;
    CHECK(ntwssp_decrypt(p->pool, p->client, &in, &out) == NTWSSP_BUFFER_TOO_SMALL && in.consumed == first_record && !out.size && out.required == sizeof first);
    consume(&p->server_out, in.consumed);
    in = (ntwssp_input){p->server_out.p, p->server_out.n, 0, 0};
    CHECK(ntwssp_decrypt(p->pool, p->client, &in, &out) == NTWSSP_BUSY && !in.consumed);
    CHECK(ntwssp_end_input(p->pool, p->client) == NTWSSP_BUSY);
    out.capacity = sizeof plain;
    CHECK(ntwssp_decrypt(p->pool, p->client, &empty, &out) == NTWSSP_OK && !empty.consumed && out.size == sizeof first && !memcmp(plain, first, sizeof first));
    CHECK(ntwssp_decrypt(p->pool, p->client, &in, &out) == NTWSSP_OK && in.consumed == both - first_record && out.size == sizeof second && !memcmp(plain, second, sizeof second));
    CHECK(!memcmp(copy + first_record, p->server_out.p, p->server_out.n));
    pair_free(p); case_done("fragment preservation, missing bytes, EXTRA and no plaintext loss on retry", before);
}
static void test_tamper(void)
{
    unsigned before = failures;
    pair *p = established();
    unsigned char plain[64];
    ntwssp_buffer out = {plain, sizeof plain, 0, 0};
    ntwssp_input in;
    ntwssp_info info;
    if (!p) return;
    server_write(p, "untrusted ciphertext must yield no plaintext", 43);
    p->server_out.p[p->server_out.n - 1] ^= 1;
    memset(plain, 0xa5, sizeof plain);
    in = (ntwssp_input){p->server_out.p, p->server_out.n, 0, 0};
    CHECK(ntwssp_decrypt(p->pool, p->client, &in, &out) == NTWSSP_ENGINE && !out.size && !out.required);
    for (size_t i = 0; i < sizeof plain; ++i) CHECK(plain[i] == 0xa5);
    CHECK(ntwssp_query(p->pool, p->client, &info) == NTWSSP_OK && info.failed && !info.established && info.backend_error);
    pair_free(p); case_done("tampered real authenticated record releases zero plaintext", before);
}
static void test_close(void)
{
    unsigned before = failures;
    pair *p = established();
    unsigned char token[128], plain[64], h[5], t[32], d[1] = {0};
    ntwssp_buffer out = {token, 1, 0, 0}, pb = {plain, sizeof plain, 0, 0};
    ntwssp_buffer hb = {h, sizeof h, 0, 0}, db = {d, sizeof d, sizeof d, 0}, tb = {t, sizeof t, 0, 0};
    ntwssp_input in;
    size_t n = 0;
    ntwssp_info info;
    if (!p) return;
    CHECK(ntwssp_shutdown(p->pool, p->client, &out) == NTWSSP_BUFFER_TOO_SMALL && !out.size && out.required > 1);
    CHECK(ntwssp_query(p->pool, p->client, &info) == NTWSSP_OK && info.local_closed);
    CHECK(ntwssp_encrypt(p->pool, p->client, &hb, &db, &tb) == NTWSSP_STATE);
    out.capacity = sizeof token;
    CHECK(ntwssp_shutdown(p->pool, p->client, &out) == NTWSSP_OK && out.size > 5);
    append(&p->server_in, token, out.size);
    CHECK(ntwssp_shutdown(p->pool, p->client, &out) == NTWSSP_OK && !out.size);
    CHECK(ntwst_read(p->server, plain, sizeof plain, &n) == NTWST_CLOSED && !n);
    CHECK(ntwst_close_notify(p->server) == NTWST_OK);
    in = (ntwssp_input){p->server_out.p, p->server_out.n, 0, 0};
    CHECK(ntwssp_decrypt(p->pool, p->client, &in, &pb) == NTWSSP_CLOSED && in.consumed == in.size && !pb.size);
    CHECK(ntwssp_end_input(p->pool, p->client) == NTWSSP_CLOSED);
    pair_free(p); case_done("orderly close_notify, shutdown retry, write rejection and authenticated EOF", before);
}
static void test_truncation(int partial)
{
    unsigned before = failures;
    pair *p = established();
    unsigned char plain[64];
    ntwssp_buffer out = {plain, sizeof plain, 0, 0};
    ntwssp_input in;
    if (!p) return;
    if (partial) {
        server_write(p, "incomplete ciphertext", 21);
        in = (ntwssp_input){p->server_out.p, p->server_out.n - 1, 0, 0};
        CHECK(ntwssp_decrypt(p->pool, p->client, &in, &out) == NTWSSP_INCOMPLETE && in.missing == 1 && !in.consumed && !out.size);
    }
    CHECK(ntwssp_end_input(p->pool, p->client) == NTWSSP_TRUNCATED);
    CHECK(ntwssp_end_input(p->pool, p->client) == NTWSSP_TRUNCATED);
    pair_free(p); case_done(partial ? "partial-record unauthenticated EOF fails closed" : "record-boundary unauthenticated EOF fails closed", before);
}
static void test_multiple_and_rng(void)
{
    unsigned before = failures;
    pair *a = established(), *b = established();
    unsigned char plain[64];
    ntwssp_buffer out = {plain, sizeof plain, 0, 0};
    ntwssp_input in;
    if (a && b) {
        server_write(a, "session A", 10); server_write(b, "session B", 10);
        in = (ntwssp_input){b->server_out.p, b->server_out.n, 0, 0};
        CHECK(ntwssp_decrypt(b->pool, b->client, &in, &out) == NTWSSP_OK && out.size == 10 && !memcmp(plain, "session B", 10));
        pair_free(b); b = NULL;
        in = (ntwssp_input){a->server_out.p, a->server_out.n, 0, 0};
        CHECK(ntwssp_decrypt(a->pool, a->client, &in, &out) == NTWSSP_OK && out.size == 10 && !memcmp(plain, "session A", 10));
    }
    pair_free(a); pair_free(b);
    a = pair_new("tls13.win98.test", &ca, 0);
    CHECK(a != NULL);
    if (a) {
        ntwssp_input empty = {0};
        rng_fail = 1;
        CHECK(ntwssp_handshake(a->pool, a->client, &empty, &out) == NTWSSP_ENGINE);
        rng_fail = 0;
    }
    pair_free(a); case_done("independent live contexts survive peer deletion; failed RNG cannot handshake", before);
}
static void make_future_certificate(void)
{
    mbedtls_x509write_cert writer;
    mbedtls_pk_context private_key;
    mbedtls_mpi serial;
    int result;
    future_cert.p = calloc(1, 8192);
    CHECK(future_cert.p != NULL);
    if (!future_cert.p) return;
    mbedtls_x509write_crt_init(&writer);
    mbedtls_pk_init(&private_key); mbedtls_mpi_init(&serial);
    CHECK(mbedtls_pk_parse_key(&private_key, key.p, key.n, NULL, 0, random_bytes, NULL) == 0);
    CHECK(mbedtls_mpi_lset(&serial, 12345) == 0);
    mbedtls_x509write_crt_set_version(&writer, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&writer, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&writer, &private_key);
    mbedtls_x509write_crt_set_issuer_key(&writer, &private_key);
    CHECK(mbedtls_x509write_crt_set_subject_name(&writer, "CN=tls13.win98.test") == 0);
    CHECK(mbedtls_x509write_crt_set_issuer_name(&writer, "CN=tls13.win98.test") == 0);
    CHECK(mbedtls_x509write_crt_set_serial(&writer, &serial) == 0);
    CHECK(mbedtls_x509write_crt_set_validity(&writer, "20380101000000", "20390101000000") == 0);
    CHECK(mbedtls_x509write_crt_set_basic_constraints(&writer, 1, -1) == 0);
    result = mbedtls_x509write_crt_pem(&writer, future_cert.p, 8192, random_bytes, NULL);
    CHECK(result == 0);
    if (!result) future_cert.n = strlen((const char *)future_cert.p) + 1;
    mbedtls_mpi_free(&serial); mbedtls_pk_free(&private_key); mbedtls_x509write_crt_free(&writer);
}
static void test_tls12(void)
{
    unsigned before = failures, i;
    pair *p = pair_new("tls13.win98.test", &ca, 0);
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config cfg;
    mbedtls_x509_crt server_cert;
    mbedtls_pk_context server_key;
    unsigned char output[NTWSSP_MAX_TOKEN];
    ntwssp_buffer out = {output, sizeof output, 0, 0};
    ntwssp_input empty = {0};
    ntwssp_info info;
    int result = NTWSSP_CONTINUE, server_result = MBEDTLS_ERR_SSL_WANT_READ;
    CHECK(p != NULL);
    if (!p) return;
    ntwst_destroy(p->server); p->server = NULL;
    mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&cfg);
    mbedtls_x509_crt_init(&server_cert); mbedtls_pk_init(&server_key);
    CHECK(mbedtls_x509_crt_parse(&server_cert, cert.p, cert.n) == 0);
    CHECK(mbedtls_pk_parse_key(&server_key, key.p, key.n, NULL, 0, random_bytes, NULL) == 0);
    CHECK(mbedtls_ssl_config_defaults(&cfg, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0);
    mbedtls_ssl_conf_min_tls_version(&cfg, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&cfg, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_rng(&cfg, random_bytes, NULL);
    CHECK(mbedtls_ssl_conf_own_cert(&cfg, &server_cert, &server_key) == 0);
    CHECK(mbedtls_ssl_setup(&ssl, &cfg) == 0);
    mbedtls_ssl_set_bio(&ssl, p, server_send, server_receive, NULL);
    CHECK(ntwssp_handshake(p->pool, p->client, &empty, &out) == NTWSSP_CONTINUE);
    append(&p->server_in, out.data, out.size);
    for (i = 0; i < LIMIT && result >= 0; ++i) {
        ntwssp_input in;
        if (server_result == MBEDTLS_ERR_SSL_WANT_READ || server_result == MBEDTLS_ERR_SSL_WANT_WRITE)
            server_result = mbedtls_ssl_handshake(&ssl);
        in = (ntwssp_input){p->server_out.p, p->server_out.n, 0, 0};
        result = ntwssp_handshake(p->pool, p->client, &in, &out);
        consume(&p->server_out, in.consumed);
        append(&p->server_in, out.data, out.size);
    }
    CHECK(result == NTWSSP_ENGINE && server_result < 0 && server_result != MBEDTLS_ERR_SSL_WANT_READ && server_result != MBEDTLS_ERR_SSL_WANT_WRITE);
    CHECK(ntwssp_query(p->pool, p->client, &info) == NTWSSP_OK && info.failed && !info.established);
    mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&cfg);
    mbedtls_x509_crt_free(&server_cert); mbedtls_pk_free(&server_key);
    pair_free(p); case_done("real TLS1.2-only server cannot downgrade client", before);
}
int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s frozen-fixture-directory\n", argv[0]); return 2; }
    ca = load(argv[1], "ca.pem"); other_ca = load(argv[1], "other-ca.pem");
    cert = load(argv[1], "server.pem"); key = load(argv[1], "server.key");
    expired_cert = load(argv[1], "expired.pem"); expired_key = load(argv[1], "expired.key");
    if (!ca.n || !other_ca.n || !cert.n || !key.n || !expired_cert.n || !expired_key.n) return 2;
    CHECK(ntwst_runtime_init(random_bytes, NULL) == NTWST_OK);
    make_future_certificate();
    test_handles();
    test_negative("wrong DNS hostname", "wrong.win98.test", &ca, 0, MBEDTLS_X509_BADCERT_CN_MISMATCH);
    test_negative("untrusted root", "tls13.win98.test", &other_ca, 0, MBEDTLS_X509_BADCERT_NOT_TRUSTED);
    test_negative("expired leaf", "tls13.win98.test", &ca, 1, MBEDTLS_X509_BADCERT_EXPIRED);
    test_negative("not-yet-valid trusted certificate", "tls13.win98.test", &future_cert, 2, MBEDTLS_X509_BADCERT_FUTURE);
    test_tls12();
    test_handshake_extra();
    test_encrypt(); test_decrypt(); test_tamper(); test_close();
    test_truncation(0); test_truncation(1); test_multiple_and_rng();
    CHECK(ntwst_runtime_fini() == NTWST_OK);
    free(ca.p); free(other_ca.p); free(cert.p); free(key.p); free(expired_cert.p); free(expired_key.p); free(future_cert.p);
    printf("RESULT status=%s contract_cases=%u checks=%u failures=%u native_guest_verified=false system_schannel_verified=false application_functionality_verified=false\n",
           failures ? "FAIL" : "PASS", contract_cases, checks, failures);
    return failures ? 1 : 0;
}
