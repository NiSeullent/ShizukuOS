/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTWST_SSPI_STREAM_H
#define NTWST_SSPI_STREAM_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Portable outbound TLS stream core, NOT Windows SSPI exports or OS trust.
 * Initialize ntwst_runtime first. Externally serialize ALL pools, connections
 * and ntwst runtime/engine calls; this core neither owns PSA nor adds a lock.
 * Pool pointers are caller-owned objects, valid until pool_destroy. Public
 * handles carry a kind, slot and process-wide generation and never contain a
 * caller-dereferenced context pointer. No callback or concurrent reentry.
 */
#define NTWSSP_MAX_CONTEXTS 8u
#define NTWSSP_MAX_TOKEN 65536u
/* Mbed TLS 3.6.7's 16-KiB TLSInnerPlaintext limit reserves one type byte. */
#define NTWSSP_MAX_MESSAGE 16383u
#define NTWSSP_MAX_PLAINTEXT 16384u
#define NTWSSP_HEADER_SIZE 5u
#define NTWSSP_TRAILER_BOUND 32u
#define NTWSSP_MAX_RECORD (16384u + 256u + 5u)
#define NTWSSP_CONTEXT_KIND UINT32_C(0x53544358)

enum ntwssp_status {
    NTWSSP_OK = 0, NTWSSP_CONTINUE = 1, NTWSSP_INCOMPLETE = 2,
    NTWSSP_CLOSED = 3, NTWSSP_BUFFER_TOO_SMALL = 4,
    NTWSSP_INVALID = -1, NTWSSP_LIMIT = -2, NTWSSP_NO_MEMORY = -3,
    NTWSSP_STATE = -4, NTWSSP_ENGINE = -5, NTWSSP_VERIFY = -6,
    NTWSSP_TRUNCATED = -7, NTWSSP_BUSY = -8
};
typedef struct ntwssp_pool ntwssp_pool;
typedef struct ntwssp_handle {
    uint32_t kind, slot, generation;
} ntwssp_handle;
typedef struct ntwssp_options {
    const char *hostname;                 /* ASCII DNS, no IP literals */
    const unsigned char *ca;              /* Explicit caller policy, NOT hRootStore */
    size_t ca_size;                       /* PEM includes NUL; DER does not */
    size_t io_quantum;                    /* 0: normal; 1..MAX_TOKEN: short BIO I/O */
} ntwssp_options;
typedef struct ntwssp_input {
    const unsigned char *data;
    size_t size;
    size_t consumed, missing;             /* Written on every call */
} ntwssp_input;
typedef struct ntwssp_buffer {
    unsigned char *data;
    size_t capacity;
    size_t size, required;
} ntwssp_buffer;
typedef struct ntwssp_sizes {
    size_t header, trailer, maximum_message;
    unsigned buffers, block_size;
} ntwssp_sizes;
typedef struct ntwssp_info {
    int established, failed, local_closed, peer_closed;
    int last_status, backend_error;
    uint32_t verify_flags;
} ntwssp_info;

int ntwssp_pool_create(ntwssp_pool **out);
void ntwssp_pool_destroy(ntwssp_pool *pool);
int ntwssp_create(ntwssp_pool *pool, const ntwssp_options *options,
                  ntwssp_handle *out);
int ntwssp_delete(ntwssp_pool *pool, ntwssp_handle handle);
int ntwssp_query(ntwssp_pool *pool, ntwssp_handle handle, ntwssp_info *out);
int ntwssp_stream_sizes(ntwssp_pool *pool, ntwssp_handle handle, ntwssp_sizes *out);

/* Borrowed input is NEVER modified. consumed is the prefix handed to the real
 * backend; retain data+consumed and size-consumed (SSPI EXTRA). An incomplete
 * record is not handed to the backend: consumed excludes it, missing reports
 * additional bytes, and the caller retains/reassembles that unchanged tail.
 * The next input includes that tail plus new bytes, not a duplicated prefix.
 * A successful final handshake may still return a token that MUST be sent.
 * BUFFER_TOO_SMALL retains the exact output and operation status: retry with
 * EMPTY input and a larger buffer. New input while output is pending is BUSY.
 */
int ntwssp_handshake(ntwssp_pool *pool, ntwssp_handle handle,
                     ntwssp_input *input, ntwssp_buffer *token);

/* Header, in-place data and trailer ranges must not overlap. data.size on
 * input is a NONZERO plaintext length <= maximum_message; capacity must cover
 * it. Preflight requires header=5 and trailer=32, so insufficient capacity
 * never advances a record sequence or changes plaintext. Success changes
 * data bytes into ciphertext and returns actual header/data/trailer lengths.
 * Empty messages, QOP alerts, readonly buffers and scatter DATA are outside
 * this core; the future ABI adapter must fail those explicitly.
 */
int ntwssp_encrypt(ntwssp_pool *pool, ntwssp_handle handle,
                   ntwssp_buffer *header, ntwssp_buffer *data,
                   ntwssp_buffer *trailer);

/* Input and plaintext destination ranges must not overlap. Processes at most
 * ONE complete record and leaves further records as EXTRA.
 * Authenticated plaintext is privately retained if output is too small. Retry
 * with EMPTY input; consumed=0 then, and no record is decrypted twice. New
 * input while plaintext is pending is BUSY. CONTINUE with required=0 means a
 * control record produced no application plaintext; a generated response
 * token is obtained with take_token before any other operation.
 */
int ntwssp_decrypt(ntwssp_pool *pool, ntwssp_handle handle,
                   ntwssp_input *input, ntwssp_buffer *plaintext);
int ntwssp_take_token(ntwssp_pool *pool, ntwssp_handle handle,
                      ntwssp_buffer *token);
/* Generates real close_notify. Retry BUFFER_TOO_SMALL with a larger token
 * buffer. Writes stop when shutdown begins. Reads remain valid after the
 * token is drained, allowing the peer's authenticated close to be observed.
 */
int ntwssp_shutdown(ntwssp_pool *pool, ntwssp_handle handle, ntwssp_buffer *token);
/* Call on actual transport EOF, after pending plaintext/tokens are drained.
 * EOF is CLOSED only following authenticated peer close; otherwise TRUNCATED.
 */
int ntwssp_end_input(ntwssp_pool *pool, ntwssp_handle handle);

#ifdef __cplusplus
}
#endif
#endif
