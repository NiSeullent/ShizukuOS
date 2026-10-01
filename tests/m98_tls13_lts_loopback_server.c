/* SPDX-License-Identifier: GPL-2.0-only
 * Actual host-only LTS server; separate process/PSA state from latest client.
 * Public ntwst ABI is supplied through an explicitly frozen build header.
 * This does not provide Windows services or native networking evidence. */
#define _POSIX_C_SOURCE 200809L
#include "transport.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* Opt-in linker instrumentation reports status/length only, never TLS secrets. */
#ifdef M98_LTS_WRITE_DIAGNOSTIC
struct mbedtls_ssl_context;
extern int __real_mbedtls_ssl_write(struct mbedtls_ssl_context *,
                                  const unsigned char *, size_t);
extern int mbedtls_ssl_get_max_out_record_payload(const struct mbedtls_ssl_context *);
int __wrap_mbedtls_ssl_write(struct mbedtls_ssl_context *ssl,
                            const unsigned char *buffer, size_t length)
{
    int maximum = mbedtls_ssl_get_max_out_record_payload(ssl);
    int result = __real_mbedtls_ssl_write(ssl, buffer, length);
    fprintf(stderr, "HOST_SSL_WRITE length=%zu maximum=%d result=%d\n",
            length, maximum, result);
    return result;
}
#endif

static int rng(void *unused, unsigned char *out, size_t n)
{
    (void)unused;
    while (n) {
        ssize_t got = getrandom(out, n, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return -1;
        out += got; n -= (size_t)got;
    }
    return 0;
}
static int send_record(void *user, const unsigned char *out, size_t n)
{
    int fd = *(int *)user; ssize_t got; size_t requested = n;
    if (n > 17) n = 17;
    do { got = send(fd, out, n, MSG_NOSIGNAL); } while (got < 0 && errno == EINTR);
    if (got <= 0) fprintf(stderr, "HOST_SEND_FAILURE requested=%zu result=%zd errno=%d\n", requested, got, errno);
    return got < 0 ? NTWST_IO_ERROR : (int)got;
}
static int recv_record(void *user, unsigned char *out, size_t n)
{
    int fd = *(int *)user; ssize_t got;
    if (n > 13) n = 13;
    do { got = recv(fd, out, n, 0); } while (got < 0 && errno == EINTR);
    return got < 0 ? NTWST_IO_ERROR : (int)got;
}
static unsigned char *pem(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb"); long size; unsigned char *p;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) || (size = ftell(f)) <= 0 || size > 1048576 ||
        fseek(f, 0, SEEK_SET)) { fclose(f); return NULL; }
    p = malloc((size_t)size + 1);
    if (!p || fread(p, 1, (size_t)size, f) != (size_t)size) {
        free(p); fclose(f); return NULL;
    }
    fclose(f); p[size] = 0; *n = (size_t)size + 1; return p;
}
int main(int argc, char **argv)
{
    const char response[] = "HTTP/1.0 200 OK\r\nContent-Length: 21\r\n\r\nlatest-LTS-TLS13-ok!\n";
    ntwst_config options = {0}; ntwst_connection *server = NULL;
    struct sockaddr_in address = {0}; socklen_t size = sizeof(address);
    struct timeval timeout = {5, 0}; unsigned char request[8192];
    unsigned char *cert = NULL, *key = NULL; size_t got = 0, count, sent = 0;
    int listener = -1, fd = -1, status = NTWST_INVALID, ok = 0, initialized = 0, phase = 0;
    unsigned steps;
    if (argc != 3) return 2;
    phase = 1; cert = pem(argv[1], &options.own_certificate_size);
    key = pem(argv[2], &options.private_key_size);
    if (!cert || !key || ntwst_runtime_init(rng, NULL) != NTWST_OK) goto done;
    initialized = 1;
    listener = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) ||
        listen(listener, 1) || getsockname(listener, (struct sockaddr *)&address, &size) ||
        setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) goto done;
    printf("PORT=%u\n", (unsigned)ntohs(address.sin_port)); fflush(stdout);
    phase = 2; fd = accept(listener, NULL, NULL);
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) goto done;
    options.role = NTWST_SERVER; options.own_certificate = cert; options.private_key = key;
    options.send = send_record; options.receive = recv_record; options.io_context = &fd;
    phase = 3; if (ntwst_create(&options, &server) != NTWST_OK) goto done;
    for (steps = 0; steps < 20000; ++steps) {
        status = ntwst_handshake(server);
        if (status != NTWST_WANT_READ && status != NTWST_WANT_WRITE) break;
    }
    printf("SERVER_STATUS=%d\nSERVER_VERIFY_FLAGS=%u\nSERVER_VERSION=%s\nSERVER_BACKEND_ERROR=%d\n",
           status, ntwst_verify_flags(server), ntwst_version(server), ntwst_engine_error(server));
    if (status != NTWST_OK || strcmp(ntwst_version(server), "TLSv1.3")) goto done;
    phase = 4;
    for (steps = 0; steps < 20000 && got < sizeof(request) - 1; ++steps) {
        count = 0; status = ntwst_read(server, request + got, sizeof(request) - 1 - got, &count);
        if (status < 0 || status == NTWST_CLOSED || count > sizeof(request) - 1 - got) goto done;
        got += count; request[got] = 0;
        if (strstr((const char *)request, "\r\n\r\n")) break;
    }
    phase = 5;
    if (got < 16 || memcmp(request, "GET / HTTP/1.0\r\n", 16) ||
        !strstr((const char *)request, "\r\n\r\n")) goto done;
    phase = 6;
    for (steps = 0; steps < 20000 && sent < sizeof(response) - 1; ++steps) {
        count = 0; status = ntwst_write(server, response + sent, sizeof(response) - 1 - sent, &count);
        if (status < 0 || status == NTWST_CLOSED || count > sizeof(response) - 1 - sent) goto done;
        if (status == NTWST_OK) sent += count;
        else if (count) goto done;
    }
    if (sent != sizeof(response) - 1) goto done;
    phase = 7;
    for (steps = 0; steps < 20000; ++steps) {
        status = ntwst_close_notify(server);
        if (status != NTWST_WANT_READ && status != NTWST_WANT_WRITE) break;
    }
    ok = status == NTWST_OK;
done:
    printf("SERVER_PHASE=%d\nSERVER_LAST_STATUS=%d\nSERVER_REQUEST_BYTES=%zu\nSERVER_SENT_BYTES=%zu\n",
           phase, status, got, sent);
    if (server) printf("SERVER_FINAL_BACKEND_ERROR=%d\n", ntwst_engine_error(server));
    if (server) ntwst_destroy(server);
    if (fd >= 0) close(fd);
    if (listener >= 0) close(listener);
    if (initialized && ntwst_runtime_fini() != NTWST_OK) ok = 0;
    free(cert); free(key);
    printf("HOST_LTS_ENCRYPTED_HTTP=%s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
