/* SPDX-License-Identifier: GPL-2.0-only
 * TLS 1.3 over caller-owned byte transport and OS cryptographic randomness.
 * Protocol and certificate processing are the pinned Mbed TLS implementation;
 * this adapter neither implements cryptography nor bypasses authentication.
 */
#include "transport.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/psa_util.h"
#include "psa/crypto.h"
#include "psa/crypto_extra.h"

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3) || !defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
#error "secure_transport requires TLS 1.3 and caller-supplied PSA randomness"
#endif
#if !defined(MBEDTLS_HAVE_TIME) || !defined(MBEDTLS_HAVE_TIME_DATE)
#error "secure_transport requires certificate validity date checking"
#endif

struct ntwst_connection {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_x509_crt ca;
    mbedtls_x509_crt certificate;
    mbedtls_pk_context key;
    ntwst_send_fn send;
    ntwst_recv_fn receive;
    void *io_context;
    enum ntwst_role role;
    int established, failed, last_error, local_closed, peer_closed, closing;
    const void *pending_write;
    size_t pending_write_size;
    uint32_t verify_flags;
};

static ntwst_random_fn runtime_random;
static void *runtime_random_context;
static size_t live_connections;
static int runtime_ready;

/* PSA's TLS 1.3 key generation must use the SAME supplied source as the legacy
 * SSL RNG hook; conf_rng alone does not replace PSA randomness. */
psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t *context, uint8_t *output,
    size_t output_size, size_t *output_length)
{
    (void)context;
    if (!output_length || (!output && output_size)) return PSA_ERROR_INVALID_ARGUMENT;
    *output_length = 0;
    if (!output_size)
        return runtime_random ? PSA_SUCCESS : PSA_ERROR_INSUFFICIENT_ENTROPY;
    if (!runtime_random || runtime_random(runtime_random_context, output, output_size)) {
        if (output && output_size) mbedtls_platform_zeroize(output, output_size);
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    }
    *output_length = output_size;
    return PSA_SUCCESS;
}

static int engine_random(void *context, unsigned char *bytes, size_t size)
{
    size_t written = 0;
    (void)context;
    return mbedtls_psa_external_get_random(NULL, bytes, size, &written) == PSA_SUCCESS
           ? 0 : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

int ntwst_runtime_init(ntwst_random_fn random, void *context)
{
    unsigned char check[32];
    psa_status_t result;
    if (runtime_ready || runtime_random || live_connections) return NTWST_BUSY;
    if (!random) return NTWST_INVALID;
    /* Reject a failed OS source before PSA or any handshake can start. */
    if (random(context, check, sizeof check)) {
        mbedtls_platform_zeroize(check, sizeof check);
        return NTWST_RANDOM_ERROR;
    }
    mbedtls_platform_zeroize(check, sizeof check);
    runtime_random = random;
    runtime_random_context = context;
    result = psa_crypto_init();
    if (result != PSA_SUCCESS) {
        mbedtls_psa_crypto_free();
        runtime_random = NULL;
        runtime_random_context = NULL;
        return NTWST_ENGINE_ERROR;
    }
    runtime_ready = 1;
    return NTWST_OK;
}

int ntwst_runtime_fini(void)
{
    if (live_connections) return NTWST_BUSY;
    if (runtime_ready) mbedtls_psa_crypto_free();
    runtime_ready = 0;
    runtime_random = NULL;
    runtime_random_context = NULL;
    return NTWST_OK;
}

static int bio_send(void *context, const unsigned char *bytes, size_t size)
{
    ntwst_connection *connection = context;
    int result = connection->send(connection->io_context, bytes, size);
    if (result == NTWST_IO_WOULD_BLOCK) return MBEDTLS_ERR_SSL_WANT_WRITE;
    if (result <= 0 || (size_t)result > size) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    return result;
}

static int bio_receive(void *context, unsigned char *bytes, size_t size)
{
    ntwst_connection *connection = context;
    int result = connection->receive(connection->io_context, bytes, size);
    if (result == NTWST_IO_WOULD_BLOCK) return MBEDTLS_ERR_SSL_WANT_READ;
    if (result < 0 || (size_t)result > size) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    return result;  /* zero is transport EOF, never an empty pending buffer */
}

static void release_connection(ntwst_connection *connection)
{
    mbedtls_ssl_free(&connection->ssl);
    mbedtls_ssl_config_free(&connection->config);
    mbedtls_x509_crt_free(&connection->ca);
    mbedtls_x509_crt_free(&connection->certificate);
    mbedtls_pk_free(&connection->key);
    mbedtls_platform_zeroize(connection, sizeof *connection);
    free(connection);
}

int ntwst_create(const ntwst_config *options, ntwst_connection **out)
{
    ntwst_connection *connection;
    int error;
    if (!out) return NTWST_INVALID;
    *out = NULL;
    if (!runtime_ready || !options || !options->send || !options->receive ||
        (options->role != NTWST_CLIENT && options->role != NTWST_SERVER)) return NTWST_INVALID;
    if (options->role == NTWST_CLIENT &&
        (!options->hostname || !*options->hostname || !options->ca_certificate ||
         !options->ca_certificate_size)) return NTWST_INVALID;
    if (options->role == NTWST_SERVER &&
        (!options->own_certificate || !options->own_certificate_size ||
         !options->private_key || !options->private_key_size)) return NTWST_INVALID;
    /* Bound parsing of caller-provided material without truncation. */
    if (options->ca_certificate_size > (1u << 20) ||
        options->own_certificate_size > (1u << 20) ||
        options->private_key_size > (1u << 20)) return NTWST_INVALID;
    connection = calloc(1, sizeof *connection);
    if (!connection) return NTWST_NO_MEMORY;
    mbedtls_ssl_init(&connection->ssl);
    mbedtls_ssl_config_init(&connection->config);
    mbedtls_x509_crt_init(&connection->ca);
    mbedtls_x509_crt_init(&connection->certificate);
    mbedtls_pk_init(&connection->key);
    connection->role = options->role;
    connection->send = options->send;
    connection->receive = options->receive;
    connection->io_context = options->io_context;
    error = mbedtls_ssl_config_defaults(&connection->config,
        options->role == NTWST_CLIENT ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (error) goto failure;
    mbedtls_ssl_conf_min_tls_version(&connection->config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&connection->config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_rng(&connection->config, engine_random, NULL);
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    /* Session persistence and post-handshake ticket delivery are outside this
     * first adapter; do not depend on upstream ticket defaults. */
    if (options->role == NTWST_CLIENT)
        mbedtls_ssl_conf_session_tickets(&connection->config, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
    else
        mbedtls_ssl_conf_new_session_tickets(&connection->config, 0);
#endif
    if (options->role == NTWST_CLIENT) {
        /* Reject even a partially parsed trust bundle (parse returns >0). */
        error = mbedtls_x509_crt_parse(&connection->ca, options->ca_certificate,
                                     options->ca_certificate_size);
        if (error) goto failure;
        mbedtls_ssl_conf_ca_chain(&connection->config, &connection->ca, NULL);
        mbedtls_ssl_conf_authmode(&connection->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    } else {
        error = mbedtls_x509_crt_parse(&connection->certificate, options->own_certificate,
                                     options->own_certificate_size);
        if (error) goto failure;
        error = mbedtls_pk_parse_key(&connection->key, options->private_key,
                                    options->private_key_size, NULL, 0, engine_random, NULL);
        if (error) goto failure;
        error = mbedtls_ssl_conf_own_cert(&connection->config, &connection->certificate,
                                        &connection->key);
        if (error) goto failure;
        mbedtls_ssl_conf_authmode(&connection->config, MBEDTLS_SSL_VERIFY_NONE);
    }
    error = mbedtls_ssl_setup(&connection->ssl, &connection->config);
    if (error) goto failure;
    if (options->role == NTWST_CLIENT) {
        error = mbedtls_ssl_set_hostname(&connection->ssl, options->hostname);
        if (error) goto failure;
    }
    mbedtls_ssl_set_bio(&connection->ssl, connection, bio_send, bio_receive, NULL);
    ++live_connections;
    *out = connection;
    return NTWST_OK;
failure:
    release_connection(connection);
    return NTWST_ENGINE_ERROR;
}

void ntwst_destroy(ntwst_connection *connection)
{
    if (!connection) return;
    release_connection(connection);
    --live_connections;
}

static int engine_status(ntwst_connection *connection, int error)
{
    if (error == MBEDTLS_ERR_SSL_WANT_READ) return NTWST_WANT_READ;
    if (error == MBEDTLS_ERR_SSL_WANT_WRITE) return NTWST_WANT_WRITE;
    if (error == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        connection->peer_closed = 1;
        return NTWST_CLOSED;
    }
    if (!error) return NTWST_OK;
    connection->last_error = error;
    connection->failed = 1;
    connection->verify_flags = mbedtls_ssl_get_verify_result(&connection->ssl);
    if (error == MBEDTLS_ERR_SSL_CONN_EOF) return NTWST_TRUNCATED;
    return error == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED ? NTWST_CERTIFICATE_ERROR
                                                     : NTWST_ENGINE_ERROR;
}

int ntwst_handshake(ntwst_connection *connection)
{
    int result;
    if (!connection) return NTWST_INVALID;
    if (connection->failed) return NTWST_ENGINE_ERROR;
    if (connection->local_closed || connection->peer_closed) return NTWST_CLOSED;
    if (connection->pending_write || connection->closing) return NTWST_BUSY;
    if (connection->established) return NTWST_OK;
    result = engine_status(connection, mbedtls_ssl_handshake(&connection->ssl));
    if (result != NTWST_OK) return result;
    connection->verify_flags = mbedtls_ssl_get_verify_result(&connection->ssl);
    if (connection->role == NTWST_CLIENT && connection->verify_flags) {
        connection->last_error = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        connection->failed = 1;
        return NTWST_CERTIFICATE_ERROR;
    }
    if (strcmp(mbedtls_ssl_get_version(&connection->ssl), "TLSv1.3")) {
        connection->last_error = MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION;
        connection->failed = 1;
        return NTWST_ENGINE_ERROR;
    }
    connection->established = 1;
    return NTWST_OK;
}

int ntwst_write(ntwst_connection *connection, const void *bytes, size_t size,
                size_t *written)
{
    int result;
    if (written) *written = 0;
    if (!connection || !written || (!bytes && size) || size > INT_MAX ||
        !connection->established || connection->failed || connection->local_closed ||
        connection->peer_closed || connection->closing) return NTWST_INVALID;
    if (connection->pending_write &&
        (connection->pending_write != bytes || connection->pending_write_size != size))
        return NTWST_INVALID;
    if (!size) return NTWST_OK;
    result = mbedtls_ssl_write(&connection->ssl, bytes, size);
    if (result > 0) {
        connection->pending_write = NULL;
        connection->pending_write_size = 0;
        *written = (size_t)result;
        return NTWST_OK;
    }
    if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE) {
        connection->pending_write = bytes;
        connection->pending_write_size = size;
    }
    if (!result) result = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    return engine_status(connection, result);
}

int ntwst_read(ntwst_connection *connection, void *bytes, size_t size, size_t *read)
{
    int result;
    if (read) *read = 0;
    if (!connection || !read || !bytes || !size || size > INT_MAX ||
        !connection->established || connection->failed) return NTWST_INVALID;
    if (connection->pending_write || connection->closing) return NTWST_BUSY;
    if (connection->peer_closed) return NTWST_CLOSED;
    result = mbedtls_ssl_read(&connection->ssl, bytes, size);
    if (result > 0) { *read = (size_t)result; return NTWST_OK; }
    if (!result) return engine_status(connection, MBEDTLS_ERR_SSL_CONN_EOF);
    return engine_status(connection, result);
}

int ntwst_close_notify(ntwst_connection *connection)
{
    int result;
    if (!connection || !connection->established || connection->failed) return NTWST_INVALID;
    if (connection->pending_write) return NTWST_BUSY;
    if (connection->local_closed) return NTWST_OK;
    connection->closing = 1;
    result = engine_status(connection, mbedtls_ssl_close_notify(&connection->ssl));
    if (result == NTWST_OK) { connection->local_closed = 1; connection->closing = 0; }
    return result;
}

const char *ntwst_version(const ntwst_connection *connection)
{
    return connection && connection->established && !connection->failed
           ? mbedtls_ssl_get_version(&connection->ssl) : "";
}
uint32_t ntwst_verify_flags(const ntwst_connection *connection)
{
    return connection ? connection->verify_flags : UINT32_MAX;
}
int ntwst_engine_error(const ntwst_connection *connection)
{
    return connection ? connection->last_error : 0;
}
