/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_SECURE_TRANSPORT_H
#define NTW_SECURE_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ntwst_connection ntwst_connection;
typedef int (*ntwst_random_fn)(void *context, unsigned char *bytes, size_t size);
typedef int (*ntwst_send_fn)(void *context, const unsigned char *bytes, size_t size);
typedef int (*ntwst_recv_fn)(void *context, unsigned char *bytes, size_t size);

enum ntwst_status {
    NTWST_OK = 0, NTWST_WANT_READ = 1, NTWST_WANT_WRITE = 2, NTWST_CLOSED = 3,
    NTWST_INVALID = -1, NTWST_NO_MEMORY = -2, NTWST_ENGINE_ERROR = -3,
    NTWST_CERTIFICATE_ERROR = -4, NTWST_RANDOM_ERROR = -5, NTWST_BUSY = -6,
    NTWST_TRUNCATED = -7
};
enum ntwst_role { NTWST_CLIENT = 0, NTWST_SERVER = 1 };
#define NTWST_IO_WOULD_BLOCK (-1)
#define NTWST_IO_ERROR (-2)

typedef struct ntwst_config {
    enum ntwst_role role;
    /* Client: nonempty expected DNS hostname and explicit trust anchors required.
     * Server: own certificate and key required; this API does not request client
     * certificates. PEM lengths include the terminating NUL; DER lengths do not. */
    const char *hostname;
    const unsigned char *ca_certificate;
    size_t ca_certificate_size;
    const unsigned char *own_certificate;
    size_t own_certificate_size;
    const unsigned char *private_key;
    size_t private_key_size;
    ntwst_send_fn send;
    ntwst_recv_fn receive;
    void *io_context;
} ntwst_config;

/* The runtime exclusively owns this linked Mbed TLS PSA instance. Initialize
 * once before creating connections; the callback and its context remain valid
 * and immutable until fini. The callback returns zero only after filling every
 * requested byte with OS cryptographic randomness, and nonzero on failure.
 *
 * This first port has no threading backend. The caller must externally serialize
 * ALL runtime and connection API calls, including init/fini. A single-threaded
 * event loop satisfies this contract. It must not share the PSA instance with
 * unrelated Mbed TLS callers. No PRNG or entropy fallback is installed. */
int ntwst_runtime_init(ntwst_random_fn random, void *context);
int ntwst_runtime_fini(void);  /* NTWST_BUSY while any connection is allocated */

int ntwst_create(const ntwst_config *config, ntwst_connection **connection);
void ntwst_destroy(ntwst_connection *connection);
/* Call again after the requested transport becomes ready. TLS 1.3 is the only
 * allowed protocol. A fatal handshake error permanently fails that connection. */
int ntwst_handshake(ntwst_connection *connection);
/* WANT_READ/WANT_WRITE from write requires retrying the SAME pointer and size
 * with unchanged bytes until success or fatal failure. A mismatched retry is
 * rejected. read/close return BUSY while a write is pending. A successful write
 * may be partial: advance only by *written after NTWST_OK.
 * CLOSED means an authenticated peer close_notify; raw EOF is TRUNCATED and
 * permanently fails the connection, even at a TLS record boundary. */
int ntwst_write(ntwst_connection *connection, const void *bytes, size_t size,
                size_t *written);
int ntwst_read(ntwst_connection *connection, void *bytes, size_t size, size_t *read);
/* Retry close_notify after WANT_* until its alert flushes. During that pending
 * close, writes are invalid and reads return BUSY; reads are allowed after the
 * local close has completed to obtain the peer's authenticated close. */
int ntwst_close_notify(ntwst_connection *connection);
const char *ntwst_version(const ntwst_connection *connection);
uint32_t ntwst_verify_flags(const ntwst_connection *connection);
int ntwst_engine_error(const ntwst_connection *connection);

#ifdef __cplusplus
}
#endif
#endif
