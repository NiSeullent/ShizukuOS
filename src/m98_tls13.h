/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_TLS13_H
#define M98_TLS13_H
#include <stddef.h>
#include <stdint.h>

/* Transport TLS, unrelated to PE thread-local storage.
 * One live client per process in this first port. Calls on that client must
 * be serialized; callbacks must not re-enter this API. No socket ownership.
 * Entropy must be an already seeded CSPRNG, not merely a jitter/timer sample.
 * send/recv return a byte count, 0 for EOF, -1 for failure, or -2 for would-block.
 * Callers bound callback blocking time and retry WANT_READ/WANT_WRITE themselves.
 */
enum m98_tls_status {
    M98_TLS_OK = 0, M98_TLS_WANT_READ = 1, M98_TLS_WANT_WRITE = 2,
    M98_TLS_EOF = 3, M98_TLS_INVALID = -1, M98_TLS_NO_MEMORY = -2,
    M98_TLS_BUSY = -3, M98_TLS_ENTROPY = -4, M98_TLS_CLOCK = -5,
    M98_TLS_VERIFY = -6, M98_TLS_PROTOCOL = -7, M98_TLS_IO = -8,
    M98_TLS_STATE = -9
};
typedef struct m98_tls_client m98_tls_client;
typedef struct m98_tls_options {
    void *user;
    int (*entropy)(void *user, unsigned char *out, size_t bytes); /* 1: full success */
    int64_t (*unix_time)(void *user); /* reliable UTC seconds, 1..253402300799 */
    int (*send)(void *user, const unsigned char *buf, size_t bytes);
    int (*recv)(void *user, unsigned char *buf, size_t bytes);
    const unsigned char *ca; /* caller-selected PEM (NUL included) or DER */
    size_t ca_bytes;
    const char *hostname; /* nonempty ASCII DNS name, never NULL or an IP literal */
} m98_tls_options;

int m98_tls_create(const m98_tls_options *options, m98_tls_client **out);
int m98_tls_handshake(m98_tls_client *client);
int m98_tls_write(m98_tls_client *client, const void *data, size_t bytes, size_t *written);
int m98_tls_read(m98_tls_client *client, void *data, size_t capacity, size_t *read_bytes);
/* Sends authenticated close_notify. Retry WANT_* with this same function;
 * no further writes are allowed once shutdown begins. Does not close the BIO.
 */
int m98_tls_shutdown(m98_tls_client *client);
int m98_tls_backend_error(const m98_tls_client *client);
uint32_t m98_tls_verify_flags(const m98_tls_client *client);
int m98_tls_is_established(const m98_tls_client *client);
void m98_tls_free(m98_tls_client *client);
#endif
