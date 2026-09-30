/* SPDX-License-Identifier: GPL-2.0-only
 * Real host-only interoperability probe: Linux socket + getrandom callbacks.
 * These services are not evidence of a Win98 entropy or networking backend.
 */
#define _POSIX_C_SOURCE 200809L
#include "m98_tls13.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

struct services {
    int fd, fail_entropy, fail_after_probe, invalid_clock, entropy_calls, sends;
    int entropy_result, retry_send, retry_recv;
    int corrupt_record, corrupted;
    unsigned char record_header[5];
    size_t header_bytes, payload_left;
};
static int entropy(void *user, unsigned char *buf, size_t count)
{
    struct services *s = user;
    ++s->entropy_calls;
    if (s->fail_entropy || (s->fail_after_probe && s->entropy_calls > 1)) {
        /* Model an errno-style negative result and partial-fill status too. */
        if (s->entropy_result == 2) memset(buf, 0xA5, count / 2);
        return s->entropy_result;
    }
    while (count) {
        ssize_t n = getrandom(buf, count, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        buf += n; count -= (size_t)n;
    }
    return 1;
}
static int64_t clock_now(void *user) { return ((struct services *)user)->invalid_clock ? 0 : (int64_t)time(NULL); }
static int send_data(void *user, const unsigned char *buf, size_t count)
{
    struct services *s = user;
    ssize_t n;
    ++s->sends;
    if (s->retry_send) { s->retry_send = 0; return -2; }
    /* Deliberately fragment outgoing records. */
    if (count > 47) count = 47;
    do { n = send(s->fd, buf, count, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
    return n < 0 ? -1 : (int)n;
}
static int recv_data(void *user, unsigned char *buf, size_t count)
{
    struct services *s = user;
    ssize_t n;
    if (s->retry_recv) { s->retry_recv = 0; return -2; }
    /* Deliberately fragment incoming records. */
    if (count > 31) count = 31;
    do { n = recv(s->fd, buf, count, 0); } while (n < 0 && errno == EINTR);
    if (n > 0 && s->corrupt_record && !s->corrupted) {
        size_t i;
        /* Start at the next TLS record boundary after handshake. Change a
         * ciphertext payload byte, leaving the five-byte record header intact.
         */
        for (i = 0; i < (size_t)n; ++i) {
            if (s->header_bytes < 5) {
                s->record_header[s->header_bytes++] = buf[i];
                if (s->header_bytes == 5)
                    s->payload_left = ((size_t)s->record_header[3] << 8) | s->record_header[4];
            } else if (s->payload_left) {
                if (s->record_header[0] == 23 && s->record_header[1] == 3 && s->record_header[2] == 3) {
                    buf[i] ^= 0x01;
                    s->corrupted = 1;
                    break;
                }
                if (!--s->payload_left) s->header_bytes = 0;
            } else {
                return -1; /* Invalid fixture boundary: never report a pass. */
            }
        }
    }
    return n < 0 ? -1 : (int)n;
}

int main(int argc, char **argv)
{
    struct services svc = {0};
    struct sockaddr_in addr;
    struct timeval timeout = {5,0};
    m98_tls_options options;
    m98_tls_client *client = NULL, *other = NULL;
    unsigned char *ca, response[4096];
    const char request[] = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    const char *mode;
    FILE *file;
    long ca_bytes;
    size_t amount, got = 0, offset = 0;
    int result, blocked_write, duplicate, ok = 0, established, retries = 0;
    if (argc != 5) return 2; /* port CA expected-host mode */
    mode = argv[4];
    svc.fd = -1;
    svc.fail_entropy = !strcmp(mode, "entropy") || !strcmp(mode, "entropy-negative") || !strcmp(mode, "entropy-partial");
    svc.fail_after_probe = !strcmp(mode, "entropy-late") || !strcmp(mode, "entropy-late-negative") || !strcmp(mode, "entropy-late-partial");
    svc.entropy_result = strstr(mode, "negative") ? -1 : strstr(mode, "partial") ? 2 : 0;
    svc.invalid_clock = !strcmp(mode, "clock");
    file = fopen(argv[2], "rb");
    if (!file || fseek(file, 0, SEEK_END) || (ca_bytes = ftell(file)) <= 0 || ca_bytes > 4*1024*1024) return 2;
    rewind(file);
    ca = malloc((size_t)ca_bytes + 1);
    if (!ca || fread(ca, 1, (size_t)ca_bytes, file) != (size_t)ca_bytes) return 2;
    ca[ca_bytes] = 0;
    fclose(file);
    svc.fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)atoi(argv[1]));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (svc.fd < 0 || setsockopt(svc.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) ||
        setsockopt(svc.fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) ||
        connect(svc.fd, (struct sockaddr *)&addr, sizeof addr)) return 2;
    memset(&options, 0, sizeof options);
    options.user = &svc; options.entropy = entropy; options.unix_time = clock_now;
    options.send = send_data; options.recv = recv_data;
    options.ca = ca; options.ca_bytes = (size_t)ca_bytes + 1; options.hostname = argv[3];
    result = m98_tls_create(&options, &client);
    if (svc.fail_entropy || svc.invalid_clock || !strcmp(mode,"invalid-host") || !strcmp(mode,"invalid-ca")) {
        int expect = svc.fail_entropy ? M98_TLS_ENTROPY : svc.invalid_clock ? M98_TLS_CLOCK :
                     !strcmp(mode,"invalid-host") ? M98_TLS_INVALID : M98_TLS_VERIFY;
        ok = result == expect && client == NULL && svc.sends == 0;
        goto done;
    }
    if (result != M98_TLS_OK) goto done;
    duplicate = m98_tls_create(&options, &other);
    if (duplicate != M98_TLS_BUSY || other != NULL) goto done;
    blocked_write = m98_tls_write(client, request, sizeof request - 1, &amount);
    if (blocked_write != M98_TLS_STATE || amount != 0 || svc.sends) goto done;
    svc.retry_send = svc.retry_recv = !strcmp(mode, "retry");
    do {
        result = m98_tls_handshake(client);
        if (result == M98_TLS_WANT_READ || result == M98_TLS_WANT_WRITE) ++retries;
        if (retries > 10) goto done;
    } while (result == M98_TLS_WANT_READ || result == M98_TLS_WANT_WRITE);
    if (strcmp(mode, "valid") && strcmp(mode, "retry") && strcmp(mode, "corrupt-record")) {
        int expect = svc.fail_after_probe ? M98_TLS_ENTROPY : !strcmp(mode,"tls12") ? M98_TLS_PROTOCOL : M98_TLS_VERIFY;
        ok = result == expect && !m98_tls_is_established(client);
        blocked_write = m98_tls_write(client, request, sizeof request - 1, &amount);
        ok = ok && blocked_write == M98_TLS_STATE && amount == 0;
        goto done;
    }
    if (result != M98_TLS_OK || !m98_tls_is_established(client) || m98_tls_verify_flags(client)) goto done;
    svc.corrupt_record = !strcmp(mode, "corrupt-record");
    while (offset < sizeof request - 1) {
        result = m98_tls_write(client, request + offset, sizeof request - 1 - offset, &amount);
        if (result != M98_TLS_OK || !amount) goto done;
        offset += amount;
    }
    while (got < sizeof response - 1) {
        result = m98_tls_read(client, response + got, sizeof response - 1 - got, &amount);
        if (svc.corrupt_record) {
            ok = svc.corrupted && result == M98_TLS_PROTOCOL && amount == 0 && got == 0 &&
                 !m98_tls_is_established(client);
            blocked_write = m98_tls_write(client, request, sizeof request - 1, &amount);
            ok = ok && blocked_write == M98_TLS_STATE && amount == 0;
            goto done;
        }
        if (result == M98_TLS_EOF) break;
        if (result != M98_TLS_OK) goto done;
        got += amount;
        if (got > 12 && memchr(response, '\n', got)) break;
    }
    response[got] = 0;
    ok = got >= 12 && !memcmp(response, "HTTP/1.0 200", 12);
    if (!strcmp(mode, "retry")) ok = ok && retries == 2;
    if (ok) {
        svc.retry_send = 1;
        result = m98_tls_shutdown(client);
        ok = result == M98_TLS_WANT_WRITE;
        blocked_write = m98_tls_write(client, request, sizeof request - 1, &amount);
        ok = ok && blocked_write == M98_TLS_STATE && amount == 0;
        result = m98_tls_shutdown(client);
        ok = ok && result == M98_TLS_OK && !m98_tls_is_established(client);
    }
done:
    established = m98_tls_is_established(client);
    printf("{\"mode\":\"%s\",\"passed\":%s,\"status\":%d,\"established\":%s,\"backend_error\":%d,\"verify_flags\":%u,\"entropy_calls\":%d,\"send_calls\":%d,\"corrupted_payload\":%s,\"response_bytes\":%zu}\n",
           mode, ok ? "true" : "false", result, established ? "true" : "false",
           m98_tls_backend_error(client), m98_tls_verify_flags(client), svc.entropy_calls, svc.sends,
           svc.corrupted ? "true" : "false", got);
    m98_tls_free(client);
    close(svc.fd);
    free(ca);
    return ok ? 0 : 1;
}
