/* SPDX-License-Identifier: GPL-2.0-only
 * Host-only controller checks with hostile API doubles. No TLS engine, entropy,
 * DLL loading or Windows identity is validated by this executable.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define M98_INTEROP_CONTROLLER_TEST
#define M98_INTEROP_NONCE "host-controller-only"
#define M98_CLIENT_SHA256 "not-a-guest-artifact"
#define M98_SERVER_SHA256 "not-a-guest-artifact"
#include "m98_tls13_guest_interop.c"

typedef struct fake_connection {
    pair *owner;
    const void *pending;
    size_t pending_size, queued;
    unsigned calls;
    int failed, established;
} fake_connection;
static int deadlock, handshake_error, dishonest_entropy, dishonest_verify;
static unsigned assertions;
static int expect(int passed, const char *name)
{
    ++assertions;
    if (!passed) { fprintf(stderr, "FAIL host controller: %s\n", name); return 0; }
    return 1;
}
static int fake_client_create(const m98_tls_options *o, m98_tls_client **out)
{
    unsigned char byte;
    fake_connection *c;
    *out = NULL;
    if (o->entropy(o->user, &byte, 1) != 1 && !dishonest_entropy) return M98_TLS_ENTROPY;
    c = calloc(1, sizeof *c);
    if (!c) return M98_TLS_NO_MEMORY;
    c->owner = o->user;
    *out = (m98_tls_client *)c;
    return M98_TLS_OK;
}
static int fake_server_create(const ntwst_config *o, ntwst_connection **out)
{
    fake_connection *c = calloc(1, sizeof *c);
    if (!c) return -2;
    c->owner = o->io_context;
    *out = (ntwst_connection *)c;
    return NTWST_OK;
}
static void fake_client_free(m98_tls_client *c) { free(c); }
static void fake_server_free(ntwst_connection *c) { free(c); }
static int fake_client_handshake(m98_tls_client *handle)
{
    fake_connection *c = (fake_connection *)handle;
    unsigned char byte;
    ++c->calls;
    if (c->failed) return M98_TLS_STATE;
    if (entropy(c->owner, &byte, 1) != 1) { c->failed = 1; return M98_TLS_ENTROPY; }
    if (handshake_error) { c->failed = 1; return M98_TLS_VERIFY; }
    if (deadlock || c->calls < 5) return c->calls & 1 ? M98_TLS_WANT_READ : M98_TLS_WANT_WRITE;
    c->established = 1;
    return M98_TLS_OK;
}
static int fake_server_handshake(ntwst_connection *handle)
{
    fake_connection *c = (fake_connection *)handle;
    ++c->calls;
    if (deadlock || c->calls < 8) return c->calls & 1 ? NTWST_WANT_WRITE : NTWST_WANT_READ;
    c->established = 1;
    return NTWST_OK;
}
/* Simulate a whole-record write: pending retries must retain pointer/length,
 * can fill the queue, and report zero bytes until the whole record is queued.
 * This stresses the controller's public WANT contract without simulating TLS.
 */
static int fake_write(fake_connection *c, int client, const void *data, size_t bytes, size_t *written)
{
    const unsigned char *p = data;
    queue *q = client ? &c->owner->to_server : &c->owner->to_client;
    int n;
    *written = 0;
    if (c->failed || !c->established) return M98_TLS_STATE;
    if (c->pending && (c->pending != data || c->pending_size != bytes)) return -1;
    if (!c->pending) { c->pending = data; c->pending_size = bytes; c->queued = 0; }
    while (c->queued < bytes) {
        n = queue_send(q, p + c->queued, bytes - c->queued);
        if (n < 0) return 2;
        c->queued += (size_t)n;
    }
    *written = bytes;
    c->pending = NULL;
    return 0;
}
static int fake_client_write(m98_tls_client *c, const void *data, size_t bytes, size_t *written)
{ return fake_write((fake_connection *)c, 1, data, bytes, written); }
static int fake_server_write(ntwst_connection *c, const void *data, size_t bytes, size_t *written)
{ return fake_write((fake_connection *)c, 0, data, bytes, written); }
static int fake_read(fake_connection *c, int client, void *out, size_t bytes, size_t *got)
{
    int n;
    *got = 0;
    if (c->failed && !dishonest_verify) return M98_TLS_STATE;
    if (c->failed && dishonest_verify) { *(unsigned char *)out = 42; *got = 1; return 0; }
    n = queue_recv(client ? &c->owner->to_client : &c->owner->to_server, out, bytes);
    if (n < 0) return 1;
    *got = (size_t)n;
    return 0;
}
static int fake_client_read(m98_tls_client *c, void *out, size_t bytes, size_t *got)
{ return fake_read((fake_connection *)c, 1, out, bytes, got); }
static int fake_server_read(ntwst_connection *c, void *out, size_t bytes, size_t *got)
{ return fake_read((fake_connection *)c, 0, out, bytes, got); }
static uint32_t fake_flags(const m98_tls_client *c)
{ return ((const fake_connection *)c)->failed ? 4 : 0; }
static uint32_t fake_server_flags(const ntwst_connection *c)
{ (void)c; return UINT32_MAX; /* No client certificate was requested. */ }
static const char *fake_version(const ntwst_connection *c)
{ return ((const fake_connection *)c)->established ? "TLSv1.3" : ""; }
static int fake_established(const m98_tls_client *c)
{ const fake_connection *f = (const fake_connection *)c; return f->established && !f->failed; }

int main(void)
{
    pair p;
    blob fixture = {(unsigned char *)"fixture", 8};
    unsigned char data[3072], byte = 0;
    unsigned before, i;
    int pass = 1;
    ca.create = fake_client_create; ca.free = fake_client_free;
    ca.handshake = fake_client_handshake; ca.write = fake_client_write;
    ca.read = fake_client_read; ca.verify_flags = fake_flags; ca.is_established = fake_established;
    sa.create = fake_server_create; sa.destroy = fake_server_free;
    sa.handshake = fake_server_handshake; sa.write = fake_server_write; sa.read = fake_server_read;
    sa.version = fake_version; sa.verify_flags = fake_server_flags;
    for (i = 0; i < sizeof data; ++i) data[i] = (unsigned char)(i * 17u + 3u);
    pass &= expect(create_pair(&p, &fixture, &fixture, &fixture, "test.invalid"), "pair creation");
    pass &= expect(handshake(&p), "interleaved WANT handshake");
    pass &= expect(((fake_connection *)p.client)->calls == 5 &&
                   ((fake_connection *)p.server)->calls == 8, "completed endpoint is not reentered");
    pass &= expect(sa.verify_flags(p.server) == UINT32_MAX && authenticated_handshake(&p),
                   "server VERIFY_NONE sentinel does not reject authenticated server handshake");
    pass &= expect(transfer(&p, 1, data, sizeof data), "client pending-write retries preserve pointer/data");
    pass &= expect(transfer(&p, 0, data, sizeof data), "server pending-write retries preserve pointer/data");
    pass &= expect(p.to_server.blocked && p.to_client.blocked, "both bounded queues actually block");
    destroy_pair(&p);
    deadlock = 1;
    pass &= expect(create_pair(&p, &fixture, &fixture, &fixture, "test.invalid"), "deadlock pair creation");
    pass &= expect(!handshake(&p) && ((fake_connection *)p.client)->calls == STEP_LIMIT &&
                   ((fake_connection *)p.server)->calls == STEP_LIMIT, "deadlock has exact finite bound");
    destroy_pair(&p); deadlock = 0;
    clear(&p, sizeof p); p.to_server.count = QUEUE_CAPACITY; p.to_client.count = QUEUE_CAPACITY;
    pass &= expect(client_send(&p, &byte, 1) == -2 && server_send(&p, &byte, 1) == -1,
                   "would-block translation differs across APIs");
    p.to_client.count = 0; p.to_server.count = 0;
    pass &= expect(client_recv(&p, &byte, 1) == -2 && server_recv(&p, &byte, 1) == -1,
                   "empty-queue translation differs across APIs");
    before = failures; failed_entropy(&fixture);
    pass &= expect(failures == before, "proper entropy errors satisfy all controller assertions");
    dishonest_entropy = 1; before = failures; failed_entropy(&fixture); dishonest_entropy = 0;
    pass &= expect(failures == before + 3, "accepting entropy 0/-1/2 is detected");
    handshake_error = 1; before = failures;
    rejection("mock rejection", &fixture, &fixture, &fixture, "wrong.invalid");
    pass &= expect(failures == before, "failed verification denies plaintext");
    dishonest_verify = 1; before = failures;
    rejection("mock unsafe rejection", &fixture, &fixture, &fixture, "wrong.invalid");
    pass &= expect(failures == before + 1, "plaintext after failed verification is detected");
    printf("HOST CONTROLLER %s: %u assertions; no TLS/native Windows claim\n", pass ? "PASS" : "FAIL", assertions);
    return pass ? 0 : 1;
}
