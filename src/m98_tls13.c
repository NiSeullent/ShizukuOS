/* SPDX-License-Identifier: GPL-2.0-only
 * Original callback-based TLS 1.3 client port using Mbed TLS 4.2.0 under its
 * GPL-2.0-or-later option. This is a library foundation, not OS Schannel.
 */
#include "m98_tls13.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/platform_util.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>

struct m98_tls_client {
    m98_tls_options options;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt ca;
    int established, failed, closing, entropy_failed, clock_failed, backend_error;
    uint32_t verify_flags;
};
/* PSA state is global. An atomic lease prevents creating a second session;
 * the holder serializes its calls. No use of this PSA instance outside here.
 */
static volatile int leased;
static m98_tls_client *active;

#ifdef _WIN32
/* No compiler CRT startup, static TLS, constructor list or NT runtime hook.
 * Calls go directly to the native MSVCRT functions used by the port.
 */
int __attribute__((stdcall)) m98_tls_dll_entry(void *module, unsigned long reason, void *reserved)
{
    (void)module; (void)reason; (void)reserved;
    return 1;
}
#endif

static void wipe(void *buffer, size_t bytes)
{
    volatile unsigned char *p = buffer;
    while (bytes--) *p++ = 0;
}

psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t *context,
    uint8_t *output, size_t bytes, size_t *written)
{
    (void)context;
    *written = 0;
    if (!active || active->entropy_failed ||
        active->options.entropy(active->options.user, output, bytes) != 1) {
        wipe(output, bytes);
        if (active) active->entropy_failed = 1;
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    }
    *written = bytes;
    return PSA_SUCCESS;
}

int64_t m98_tls_platform_time(int64_t *out)
{
    int64_t now = active ? active->options.unix_time(active->options.user) : 0;
    if (now < 1 || now > INT64_C(253402300799)) {
        if (active) active->clock_failed = 1;
        now = 0;
    }
    if (out) *out = now;
    return now;
}

/* UTC conversion without WinNT CRT gmtime_s or a process-wide gmtime buffer.
 * A bounded Gregorian year walk costs at most 8030 iterations through 9999.
 */
struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *tt, struct tm *result)
{
    static const unsigned days_per_month[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
    int year = 1970, month = 0, leap;
    int64_t days, rest;
    if (!tt || !result || *tt < 0 || *tt > INT64_C(253402300799)) return NULL;
    memset(result, 0, sizeof *result);
    days = *tt / 86400;
    rest = *tt % 86400;
    result->tm_wday = (int)((days + 4) % 7);
    result->tm_hour = (int)(rest / 3600);
    result->tm_min = (int)((rest / 60) % 60);
    result->tm_sec = (int)(rest % 60);
    for (;;) {
        leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        if (days < 365 + leap) break;
        days -= 365 + leap;
        ++year;
    }
    result->tm_year = year - 1900;
    result->tm_yday = (int)days;
    while (month < 11) {
        unsigned count = days_per_month[month] + (unsigned)(month == 1 && leap);
        if (days < count) break;
        days -= count;
        ++month;
    }
    result->tm_mon = month;
    result->tm_mday = (int)days + 1;
    return result;
}

static int valid_hostname(const char *s)
{
    size_t total = 0, label = 0;
    int has_alpha = 0;
    unsigned char previous = 0;
    if (!s || !*s) return 0;
    while (*s) {
        unsigned char c = (unsigned char)*s++;
        if (++total > 253) return 0;
        if (c == '.') {
            if (!label || previous == '-') return 0;
            label = 0;
        } else {
            int alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
            if (!alpha && !(c >= '0' && c <= '9') && c != '-') return 0;
            if (!label && c == '-') return 0;
            if (++label > 63) return 0;
            has_alpha |= alpha;
        }
        previous = c;
    }
    return label && previous != '-' && has_alpha;
}

static int bio_send(void *user, const unsigned char *buf, size_t bytes)
{
    m98_tls_client *c = user;
    int n = c->options.send(c->options.user, buf, bytes);
    if (n == -2) return MBEDTLS_ERR_SSL_WANT_WRITE;
    return n > 0 && (size_t)n <= bytes ? n : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static int bio_recv(void *user, unsigned char *buf, size_t bytes)
{
    m98_tls_client *c = user;
    int n = c->options.recv(c->options.user, buf, bytes);
    if (n == -2) return MBEDTLS_ERR_SSL_WANT_READ;
    return n >= 0 && (size_t)n <= bytes ? n : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static int failure(m98_tls_client *c, int backend)
{
    c->failed = 1;
    c->established = 0;
    c->backend_error = backend;
    c->verify_flags = mbedtls_ssl_get_verify_result(&c->ssl);
    if (c->entropy_failed) return M98_TLS_ENTROPY;
    if (c->clock_failed) return M98_TLS_CLOCK;
    if (backend == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED ||
        (c->verify_flags && c->verify_flags != UINT32_MAX)) return M98_TLS_VERIFY;
    if (backend == MBEDTLS_ERR_SSL_INTERNAL_ERROR) return M98_TLS_IO;
    return M98_TLS_PROTOCOL;
}

void m98_tls_free(m98_tls_client *c)
{
    if (!c || c != active) return;
    mbedtls_ssl_free(&c->ssl);
    mbedtls_ssl_config_free(&c->conf);
    mbedtls_x509_crt_free(&c->ca);
    mbedtls_psa_crypto_free();
    active = NULL;
    wipe(c, sizeof *c);
    free(c);
    __sync_lock_release(&leased);
}

int m98_tls_create(const m98_tls_options *options, m98_tls_client **out)
{
    m98_tls_client *c;
    unsigned char probe[32];
    int result;
    if (!out) return M98_TLS_INVALID;
    *out = NULL;
    if (!options || !options->entropy || !options->unix_time ||
        !options->send || !options->recv || !options->ca || !options->ca_bytes ||
        options->ca_bytes > 4u * 1024u * 1024u || !valid_hostname(options->hostname))
        return M98_TLS_INVALID;
    if (!__sync_bool_compare_and_swap(&leased, 0, 1)) return M98_TLS_BUSY;
    c = calloc(1, sizeof *c);
    if (!c) { __sync_lock_release(&leased); return M98_TLS_NO_MEMORY; }
    c->options = *options;
    active = c;
    mbedtls_ssl_init(&c->ssl);
    mbedtls_ssl_config_init(&c->conf);
    mbedtls_x509_crt_init(&c->ca);
    result = M98_TLS_ENTROPY;
    if (options->entropy(options->user, probe, sizeof probe) != 1) {
        wipe(probe, sizeof probe);
        goto bad;
    }
    wipe(probe, sizeof probe);
    result = M98_TLS_CLOCK;
    (void)m98_tls_platform_time(NULL);
    if (c->clock_failed) goto bad;
    result = M98_TLS_PROTOCOL;
    if (psa_crypto_init() != PSA_SUCCESS) goto bad;
    /* Positive parse results mean only part of a CA bundle was accepted. */
    result = M98_TLS_VERIFY;
    c->backend_error = mbedtls_x509_crt_parse(&c->ca, options->ca, options->ca_bytes);
    if (c->backend_error != 0) goto bad;
    result = M98_TLS_PROTOCOL;
    c->backend_error = mbedtls_ssl_config_defaults(&c->conf, MBEDTLS_SSL_IS_CLIENT,
                             MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (c->backend_error != 0) goto bad;
    mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&c->conf, &c->ca, NULL);
    mbedtls_ssl_conf_min_tls_version(&c->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&c->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    c->backend_error = mbedtls_ssl_setup(&c->ssl, &c->conf);
    if (c->backend_error != 0) goto bad;
    c->backend_error = mbedtls_ssl_set_hostname(&c->ssl, options->hostname);
    if (c->backend_error != 0) goto bad;
    mbedtls_ssl_set_bio(&c->ssl, c, bio_send, bio_recv, NULL);
    *out = c;
    return M98_TLS_OK;
bad:
    m98_tls_free(c);
    return result;
}

int m98_tls_handshake(m98_tls_client *c)
{
    int n;
    if (!c || c != active || c->failed) return M98_TLS_STATE;
    if (c->established) return M98_TLS_OK;
    n = mbedtls_ssl_handshake(&c->ssl);
    if (c->entropy_failed || c->clock_failed) return failure(c, n);
    if (n == MBEDTLS_ERR_SSL_WANT_READ) return M98_TLS_WANT_READ;
    if (n == MBEDTLS_ERR_SSL_WANT_WRITE) return M98_TLS_WANT_WRITE;
    if (n != 0) return failure(c, n);
    if (mbedtls_ssl_get_version_number(&c->ssl) != MBEDTLS_SSL_VERSION_TLS1_3)
        return failure(c, MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION);
    c->verify_flags = mbedtls_ssl_get_verify_result(&c->ssl);
    if (c->verify_flags) return failure(c, MBEDTLS_ERR_X509_CERT_VERIFY_FAILED);
    c->established = 1;
    return M98_TLS_OK;
}

static int io_result(m98_tls_client *c, int n, size_t *amount)
{
    if (c->entropy_failed || c->clock_failed) return failure(c, n);
    if (n == MBEDTLS_ERR_SSL_WANT_READ) return M98_TLS_WANT_READ;
    if (n == MBEDTLS_ERR_SSL_WANT_WRITE) return M98_TLS_WANT_WRITE;
    if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        c->established = 0;
        c->failed = 1;
        return M98_TLS_EOF;
    }
    /* EOF without authenticated close_notify is a truncated stream. */
    if (n <= 0) return failure(c, n);
    *amount = (size_t)n;
    return M98_TLS_OK;
}

int m98_tls_write(m98_tls_client *c, const void *data, size_t bytes, size_t *written)
{
    if (!written) return M98_TLS_INVALID;
    *written = 0;
    if (!c || c != active || !c->established || c->failed || c->closing) return M98_TLS_STATE;
    if ((!data && bytes) || bytes > INT_MAX) return M98_TLS_INVALID;
    if (!bytes) return M98_TLS_OK;
    return io_result(c, mbedtls_ssl_write(&c->ssl, data, bytes), written);
}

int m98_tls_read(m98_tls_client *c, void *data, size_t capacity, size_t *read_bytes)
{
    if (!read_bytes) return M98_TLS_INVALID;
    *read_bytes = 0;
    if (!c || c != active || !c->established || c->failed) return M98_TLS_STATE;
    if (!data || !capacity || capacity > INT_MAX) return M98_TLS_INVALID;
    return io_result(c, mbedtls_ssl_read(&c->ssl, data, capacity), read_bytes);
}

int m98_tls_shutdown(m98_tls_client *c)
{
    int n;
    if (!c || c != active || !c->established || c->failed) return M98_TLS_STATE;
    c->closing = 1;
    n = mbedtls_ssl_close_notify(&c->ssl);
    if (c->entropy_failed || c->clock_failed) return failure(c, n);
    if (n == MBEDTLS_ERR_SSL_WANT_READ) return M98_TLS_WANT_READ;
    if (n == MBEDTLS_ERR_SSL_WANT_WRITE) return M98_TLS_WANT_WRITE;
    if (n != 0) return failure(c, n);
    c->established = 0;
    c->failed = 1;
    return M98_TLS_OK;
}

int m98_tls_backend_error(const m98_tls_client *c) { return c && c == active ? c->backend_error : 0; }
uint32_t m98_tls_verify_flags(const m98_tls_client *c) { return c && c == active ? c->verify_flags : UINT32_MAX; }
int m98_tls_is_established(const m98_tls_client *c) { return c && c == active && c->established && !c->failed; }
