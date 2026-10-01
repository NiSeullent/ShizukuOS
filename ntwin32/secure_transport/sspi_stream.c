/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded SSPI stream bridge. Crypto/X.509/records use ntwst only.
 */
#include "sspi_stream.h"
#include "transport.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/ssl.h"

/* The advertised record limits are for the pinned, reviewed engine config.
 * A differently configured library must rebuild/review this contract too.
 */
_Static_assert(MBEDTLS_SSL_OUT_CONTENT_LEN == NTWSSP_MAX_MESSAGE + 1, "output limit changed");
_Static_assert(MBEDTLS_SSL_IN_CONTENT_LEN == NTWSSP_MAX_PLAINTEXT, "input limit changed");
_Static_assert(MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY == 16, "padding limit changed");
#if defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)
#error "Negotiated smaller record limits require a reviewed engine size accessor"
#endif

enum token_kind { TOKEN_NONE, TOKEN_HANDSHAKE, TOKEN_CONTROL, TOKEN_SHUTDOWN };
typedef struct context {
    ntwst_connection *engine;
    uint32_t generation;
    size_t quantum;
    const unsigned char *input;
    size_t input_size, input_used;
    unsigned char output[NTWSSP_MAX_TOKEN];
    size_t output_size;
    unsigned char plain[NTWSSP_MAX_PLAINTEXT];
    size_t plain_size;
    enum token_kind pending;
    int pending_status, established, failed, local_closed, peer_closed, last_status;
} context;
struct ntwssp_pool { context *slots[NTWSSP_MAX_CONTEXTS]; };
/* Global serialization includes allocation. Never wrap/reissue a generation:
 * exhausted serial space fails closed instead of accepting an ancient handle.
 */
static uint32_t next_generation;

static void wipe(void *data, size_t size)
{
    volatile unsigned char *p = data;
    while (size--) *p++ = 0;
}
static int range_valid(const void *p, size_t n)
{
    return (!n || p) && (uintptr_t)p <= UINTPTR_MAX - n;
}
static int overlap(const void *a, size_t an, const void *b, size_t bn)
{
    return an && bn && (uintptr_t)a < (uintptr_t)b + bn &&
           (uintptr_t)b < (uintptr_t)a + an;
}
static int buffer_valid(const ntwssp_buffer *b)
{
    return b && range_valid(b->data, b->capacity);
}
static int input_valid(ntwssp_input *in)
{
    if (!in) return 0;
    in->consumed = in->missing = 0;
    return in->size <= NTWSSP_MAX_TOKEN && range_valid(in->data, in->size);
}
static void empty_buffer(ntwssp_buffer *b)
{
    if (b) b->size = b->required = 0;
}
static context *lookup(ntwssp_pool *p, ntwssp_handle h)
{
    context *c;
    if (!p || h.kind != NTWSSP_CONTEXT_KIND || !h.slot || h.slot > NTWSSP_MAX_CONTEXTS)
        return NULL;
    c = p->slots[h.slot - 1];
    return c && c->generation == h.generation ? c : NULL;
}
static int fail(context *c, int result)
{
    c->failed = 1;
    c->last_status = result;
    wipe(c->plain, sizeof c->plain);
    c->plain_size = 0;
    return result;
}
static int backend_status(context *c, int result)
{
    switch (result) {
    case NTWST_OK: return NTWSSP_OK;
    case NTWST_WANT_READ: case NTWST_WANT_WRITE: return NTWSSP_CONTINUE;
    case NTWST_CLOSED: c->peer_closed = 1; return NTWSSP_CLOSED;
    case NTWST_CERTIFICATE_ERROR: return fail(c, NTWSSP_VERIFY);
    case NTWST_TRUNCATED: return fail(c, NTWSSP_TRUNCATED);
    default: return fail(c, NTWSSP_ENGINE);
    }
}
static int memory_send(void *user, const unsigned char *data, size_t size)
{
    context *c = user;
    size_t n = sizeof c->output - c->output_size;
    if (!n) return NTWST_IO_WOULD_BLOCK;
    if (n > size) n = size;
    if (c->quantum && n > c->quantum) n = c->quantum;
    memcpy(c->output + c->output_size, data, n);
    c->output_size += n;
    return (int)n;
}
static int memory_receive(void *user, unsigned char *data, size_t size)
{
    context *c = user;
    size_t n = c->input_size - c->input_used;
    if (!n) return NTWST_IO_WOULD_BLOCK;   /* Empty token is NOT transport EOF. */
    if (n > size) n = size;
    if (c->quantum && n > c->quantum) n = c->quantum;
    memcpy(data, c->input + c->input_used, n);
    c->input_used += n;
    return (int)n;
}
static void begin_input(context *c, ntwssp_input *in, size_t ready)
{
    c->input = in->data;
    c->input_size = ready;
    c->input_used = 0;
}
static void finish_input(context *c, ntwssp_input *in)
{
    in->consumed = c->input_used;
    c->input = NULL;
    c->input_size = c->input_used = 0;
}
/* Framing only. The backend still authenticates and validates every record.
 * Partial header/body bytes stay in the caller's unmodified input buffer.
 */
static int record_size(const unsigned char *p, size_t n, size_t *ready, size_t *missing)
{
    size_t total;
    *ready = *missing = 0;
    if (n < NTWSSP_HEADER_SIZE) { *missing = NTWSSP_HEADER_SIZE - n; return NTWSSP_INCOMPLETE; }
    total = NTWSSP_HEADER_SIZE + ((size_t)p[3] << 8) + p[4];
    if (total > NTWSSP_MAX_RECORD) return NTWSSP_INVALID;
    if (n < total) { *missing = total - n; return NTWSSP_INCOMPLETE; }
    *ready = total;
    return NTWSSP_OK;
}
static int complete_prefix(ntwssp_input *in, size_t *ready)
{
    size_t offset = 0, n, missing;
    int result;
    *ready = 0;
    while (offset < in->size) {
        result = record_size(in->data + offset, in->size - offset, &n, &missing);
        /* An unconsumed tail belongs to the next operation. In particular,
         * completing a handshake must not validate/reject application EXTRA.
         * A malformed first record still fails immediately. */
        if (result == NTWSSP_INVALID) {
            if (!offset) return result;
            break;
        }
        if (result == NTWSSP_INCOMPLETE) { in->missing = missing; break; }
        offset += n;
    }
    *ready = offset;
    return NTWSSP_OK;
}
static int drain(context *c, ntwssp_buffer *out)
{
    int status = c->pending_status;
    empty_buffer(out);
    out->required = c->output_size;
    if (out->capacity < c->output_size) return NTWSSP_BUFFER_TOO_SMALL;
    if (c->output_size) memcpy(out->data, c->output, c->output_size);
    out->size = c->output_size;
    wipe(c->output, c->output_size);
    c->output_size = 0;
    c->pending = TOKEN_NONE;
    return status;
}
static int deliver_plain(context *c, ntwssp_buffer *out)
{
    empty_buffer(out);
    out->required = c->plain_size;
    if (out->capacity < c->plain_size) return NTWSSP_BUFFER_TOO_SMALL;
    memcpy(out->data, c->plain, c->plain_size);
    out->size = c->plain_size;
    wipe(c->plain, c->plain_size);
    c->plain_size = 0;
    return NTWSSP_OK;
}
static int valid_hostname(const char *s)
{
    size_t i, label = 0;
    int has_letter = 0;
    if (!s) return 0;
    for (i = 0; i <= 253; ++i) {
        unsigned char ch = (unsigned char)s[i];
        if (!ch) return i && label && s[i - 1] != '-' && has_letter;
        if (ch == '.') { if (!label || s[i - 1] == '-') return 0; label = 0; continue; }
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) has_letter = 1;
        else if (!(ch >= '0' && ch <= '9') && ch != '-') return 0;
        if ((!label && ch == '-') || ++label > 63) return 0;
    }
    return 0;
}
int ntwssp_pool_create(ntwssp_pool **out)
{
    if (!out) return NTWSSP_INVALID;
    *out = calloc(1, sizeof **out);
    return *out ? NTWSSP_OK : NTWSSP_NO_MEMORY;
}
void ntwssp_pool_destroy(ntwssp_pool *p)
{
    size_t i;
    if (!p) return;
    for (i = 0; i < NTWSSP_MAX_CONTEXTS; ++i) if (p->slots[i]) {
        ntwst_destroy(p->slots[i]->engine);
        wipe(p->slots[i], sizeof *p->slots[i]);
        free(p->slots[i]);
    }
    wipe(p, sizeof *p);
    free(p);
}
int ntwssp_create(ntwssp_pool *p, const ntwssp_options *o, ntwssp_handle *out)
{
    ntwst_config cfg;
    context *c;
    size_t slot;
    int result;
    if (!out) return NTWSSP_INVALID;
    memset(out, 0, sizeof *out);
    if (!p || !o || !valid_hostname(o->hostname) || !o->ca || !o->ca_size ||
        o->ca_size > (1u << 20) || o->io_quantum > NTWSSP_MAX_TOKEN ||
        !range_valid(o->ca, o->ca_size)) return NTWSSP_INVALID;
    for (slot = 0; slot < NTWSSP_MAX_CONTEXTS && p->slots[slot]; ++slot) ;
    if (slot == NTWSSP_MAX_CONTEXTS || next_generation == UINT32_MAX) return NTWSSP_LIMIT;
    c = calloc(1, sizeof *c);
    if (!c) return NTWSSP_NO_MEMORY;
    c->quantum = o->io_quantum;
    memset(&cfg, 0, sizeof cfg);
    cfg.role = NTWST_CLIENT;
    cfg.hostname = o->hostname;
    cfg.ca_certificate = o->ca;
    cfg.ca_certificate_size = o->ca_size;
    cfg.send = memory_send;
    cfg.receive = memory_receive;
    cfg.io_context = c;
    result = ntwst_create(&cfg, &c->engine);
    if (result != NTWST_OK) { wipe(c, sizeof *c); free(c); return NTWSSP_ENGINE; }
    c->generation = ++next_generation;
    c->last_status = NTWSSP_CONTINUE;
    p->slots[slot] = c;
    out->kind = NTWSSP_CONTEXT_KIND;
    out->slot = (uint32_t)slot + 1;
    out->generation = c->generation;
    return NTWSSP_OK;
}
int ntwssp_delete(ntwssp_pool *p, ntwssp_handle h)
{
    context *c = lookup(p, h);
    if (!c) return NTWSSP_INVALID;
    p->slots[h.slot - 1] = NULL;
    ntwst_destroy(c->engine);
    wipe(c, sizeof *c);
    free(c);
    return NTWSSP_OK;
}
int ntwssp_query(ntwssp_pool *p, ntwssp_handle h, ntwssp_info *out)
{
    context *c = lookup(p, h);
    if (!c || !out) return NTWSSP_INVALID;
    out->established = c->established && !c->failed;
    out->failed = c->failed;
    out->local_closed = c->local_closed;
    out->peer_closed = c->peer_closed;
    out->last_status = c->last_status;
    out->backend_error = ntwst_engine_error(c->engine);
    out->verify_flags = ntwst_verify_flags(c->engine);
    return NTWSSP_OK;
}
int ntwssp_stream_sizes(ntwssp_pool *p, ntwssp_handle h, ntwssp_sizes *out)
{
    context *c = lookup(p, h);
    if (!c || !out) return NTWSSP_INVALID;
    if (!c->established || c->failed) return NTWSSP_STATE;
    out->header = NTWSSP_HEADER_SIZE;
    out->trailer = NTWSSP_TRAILER_BOUND;
    out->maximum_message = NTWSSP_MAX_MESSAGE;
    out->buffers = 4;
    out->block_size = 1; /* TLS 1.3 AEAD, not a CBC padding/block contract. */
    return NTWSSP_OK;
}
int ntwssp_handshake(ntwssp_pool *p, ntwssp_handle h, ntwssp_input *in, ntwssp_buffer *out)
{
    context *c = lookup(p, h);
    size_t ready;
    int result;
    if (!input_valid(in) || !buffer_valid(out)) return NTWSSP_INVALID;
    empty_buffer(out);
    if (!c || overlap(in->data, in->size, out->data, out->capacity)) return NTWSSP_INVALID;
    if (c->pending != TOKEN_NONE) {
        if (c->pending != TOKEN_HANDSHAKE || in->size) return NTWSSP_BUSY;
        return drain(c, out);
    }
    if (c->failed) return c->last_status;
    if (c->established) return NTWSSP_STATE;
    if (complete_prefix(in, &ready) != NTWSSP_OK) return fail(c, NTWSSP_INVALID);
    begin_input(c, in, ready);
    result = backend_status(c, ntwst_handshake(c->engine));
    finish_input(c, in);
    if (in->consumed < ready || result != NTWSSP_CONTINUE)
        in->missing = 0; /* EXTRA is not a request to complete this operation. */
    if (result == NTWSSP_OK) c->established = 1;
    if (result == NTWSSP_CONTINUE && in->missing && in->consumed == ready && !c->output_size)
        result = NTWSSP_INCOMPLETE;
    c->last_status = result;
    if (c->output_size) {
        c->pending = TOKEN_HANDSHAKE;
        c->pending_status = result;
        return drain(c, out);
    }
    return result;
}
int ntwssp_encrypt(ntwssp_pool *p, ntwssp_handle h, ntwssp_buffer *head,
                   ntwssp_buffer *data, ntwssp_buffer *tail)
{
    context *c = lookup(p, h);
    size_t size, written = 0, trailer, ready, missing;
    int result;
    if (!buffer_valid(head) || !buffer_valid(data) || !buffer_valid(tail)) return NTWSSP_INVALID;
    size = data->size;
    empty_buffer(head); empty_buffer(tail);
    data->required = size;
    if (!c || !size || size > NTWSSP_MAX_MESSAGE) return NTWSSP_INVALID;
    if (c->failed) return c->last_status;
    if (!c->established || c->local_closed || c->peer_closed) return NTWSSP_STATE;
    if (c->pending != TOKEN_NONE || c->plain_size) return NTWSSP_BUSY;
    head->required = NTWSSP_HEADER_SIZE; tail->required = NTWSSP_TRAILER_BOUND;
    if (head->capacity < head->required || data->capacity < size || tail->capacity < tail->required)
        return NTWSSP_BUFFER_TOO_SMALL;
    if (overlap(head->data, head->capacity, data->data, data->capacity) ||
        overlap(head->data, head->capacity, tail->data, tail->capacity) ||
        overlap(data->data, data->capacity, tail->data, tail->capacity)) return NTWSSP_INVALID;
    result = backend_status(c, ntwst_write(c->engine, data->data, size, &written));
    if (result != NTWSSP_OK || written != size || c->output_size < NTWSSP_HEADER_SIZE + size ||
        record_size(c->output, c->output_size, &ready, &missing) != NTWSSP_OK ||
        ready != c->output_size || c->output[0] != 23) {
        wipe(c->output, c->output_size); c->output_size = 0;
        return c->failed ? c->last_status : fail(c, NTWSSP_ENGINE);
    }
    trailer = c->output_size - NTWSSP_HEADER_SIZE - size;
    if (!trailer || trailer > NTWSSP_TRAILER_BOUND) {
        wipe(c->output, c->output_size); c->output_size = 0;
        return fail(c, NTWSSP_ENGINE);
    }
    memcpy(head->data, c->output, NTWSSP_HEADER_SIZE);
    memcpy(data->data, c->output + NTWSSP_HEADER_SIZE, size);
    memcpy(tail->data, c->output + NTWSSP_HEADER_SIZE + size, trailer);
    head->size = head->required = NTWSSP_HEADER_SIZE;
    data->size = size;
    tail->size = tail->required = trailer;
    wipe(c->output, c->output_size); c->output_size = 0;
    c->last_status = NTWSSP_OK;
    return NTWSSP_OK;
}
int ntwssp_decrypt(ntwssp_pool *p, ntwssp_handle h, ntwssp_input *in, ntwssp_buffer *out)
{
    context *c = lookup(p, h);
    size_t ready;
    int result;
    if (!input_valid(in) || !buffer_valid(out)) return NTWSSP_INVALID;
    empty_buffer(out);
    if (!c || overlap(in->data, in->size, out->data, out->capacity)) return NTWSSP_INVALID;
    if (c->plain_size) return in->size ? NTWSSP_BUSY : deliver_plain(c, out);
    if (c->pending != TOKEN_NONE) return NTWSSP_BUSY;
    if (c->failed) return c->last_status;
    if (!c->established) return NTWSSP_STATE;
    if (c->peer_closed) return NTWSSP_CLOSED;
    result = record_size(in->data, in->size, &ready, &in->missing);
    if (result == NTWSSP_INVALID) return fail(c, result);
    if (result != NTWSSP_OK) return result;
    begin_input(c, in, ready);
    result = backend_status(c, ntwst_read(c->engine, c->plain, sizeof c->plain, &c->plain_size));
    finish_input(c, in);
    c->last_status = result;
    if (c->output_size) { c->pending = TOKEN_CONTROL; c->pending_status = NTWSSP_CONTINUE; }
    if (result == NTWSSP_OK) return deliver_plain(c, out);
    return result;
}
int ntwssp_take_token(ntwssp_pool *p, ntwssp_handle h, ntwssp_buffer *out)
{
    context *c = lookup(p, h);
    if (!buffer_valid(out)) return NTWSSP_INVALID;
    empty_buffer(out);
    if (!c) return NTWSSP_INVALID;
    if (c->pending == TOKEN_NONE) return NTWSSP_STATE;
    return drain(c, out);
}
int ntwssp_shutdown(ntwssp_pool *p, ntwssp_handle h, ntwssp_buffer *out)
{
    context *c = lookup(p, h);
    int result;
    if (!buffer_valid(out)) return NTWSSP_INVALID;
    empty_buffer(out);
    if (!c) return NTWSSP_INVALID;
    if (c->pending != TOKEN_NONE) return c->pending == TOKEN_SHUTDOWN ? drain(c, out) : NTWSSP_BUSY;
    if (c->failed) return c->last_status;
    if (!c->established) return NTWSSP_STATE;
    if (c->plain_size) return NTWSSP_BUSY;
    if (c->local_closed) return NTWSSP_OK;
    c->local_closed = 1;               /* Reject writes even while token is pending. */
    result = backend_status(c, ntwst_close_notify(c->engine));
    if (result != NTWSSP_OK) return c->failed ? c->last_status : fail(c, NTWSSP_ENGINE);
    c->pending = TOKEN_SHUTDOWN;
    c->pending_status = result;
    c->last_status = result;
    return drain(c, out);
}
int ntwssp_end_input(ntwssp_pool *p, ntwssp_handle h)
{
    context *c = lookup(p, h);
    if (!c) return NTWSSP_INVALID;
    if (c->pending != TOKEN_NONE || c->plain_size) return NTWSSP_BUSY;
    if (c->failed) return c->last_status;
    if (c->peer_closed) return NTWSSP_CLOSED;
    return fail(c, NTWSSP_TRUNCATED);
}
