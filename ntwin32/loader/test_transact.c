/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "winfile.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
static int failures;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
static void wide(const char *ascii, uint16_t *out) {
    while (*ascii) *out++ = (uint16_t)(unsigned char)*ascii++;
    *out = 0;
}
static int host_open(void *u, const char *p, int f, int m) { int fd; (void)u; fd = open(p, f, m); return fd < 0 ? -errno : fd; }
static int host_close(void *u, int fd) { (void)u; return close(fd) == 0 ? 0 : -errno; }
static int host_read(void *u, int fd, void *b, uint32_t n) { ssize_t r; (void)u; r = read(fd, b, n); return r < 0 ? -errno : (int)r; }
static int host_write(void *u, int fd, const void *b, uint32_t n) { ssize_t r; (void)u; r = write(fd, b, n); return r < 0 ? -errno : (int)r; }
static int host_seek(void *u, int fd, uint32_t lo, uint32_t hi, int w, uint32_t *nl, uint32_t *nh) {
    off_t got; (void)u; (void)hi; got = lseek(fd, (off_t)lo, w); if (got < 0) return -errno; *nl = (uint32_t)got; *nh = 0; return 0;
}
static int host_exists(void *u, const char *p) { (void)u; return access(p, F_OK) == 0 ? 1 : 0; }
static int host_unlink(void *u, const char *p) { (void)u; return unlink(p) == 0 ? 0 : -errno; }
static int host_mkdir(void *u, const char *p, int m) { (void)u; (void)m; return mkdir(p, 0755) == 0 || errno == EEXIST ? 0 : -errno; }
static int fill_addr(struct sockaddr_un *addr, const char *path) {
    memset(addr, 0, sizeof *addr);
    addr->sun_family = AF_UNIX;
    if (strlen(path) >= sizeof addr->sun_path) return -1;
    memcpy(addr->sun_path, path, strlen(path) + 1);
    return 0;
}
static int host_bind(void *u, const char *path) {
    struct sockaddr_un addr; int fd; (void)u;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || fill_addr(&addr, path) < 0) return -errno;
    unlink(path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0 || listen(fd, 4) < 0) { close(fd); return -errno; }
    return fd;
}
static int host_pconnect(void *u, const char *path) {
    struct sockaddr_un addr; int fd; (void)u;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || fill_addr(&addr, path) < 0) return -errno;
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) { close(fd); return -errno; }
    return fd;
}
static int host_accept(void *u, int fd) { int got; (void)u; got = accept(fd, 0, 0); return got < 0 ? -errno : got; }
static uint32_t server_handle;
static void *serve(void *unused) {
    char buf[8];
    uint32_t n = 0, error = 0;
    (void)unused;
    if (!ntw_pipe_connect(server_handle, 0, &error)) return 0;
    if (!ntw_winfile_read(server_handle, buf, 4, &n, 0, &error) || n != 4) return 0;
    ntw_winfile_write(server_handle, "pong", 4, &n, 0, &error);
    return 0;
}
int main(void) {
    ntw_disk_ops ops = { 0, host_open, host_close, host_read, host_write, host_seek, host_exists, host_unlink, host_mkdir, host_bind, host_pconnect, host_accept };
    uint16_t name[64];
    uint32_t error = 99, got = 9, client = 0;
    char reply[8];
    pthread_t thread;
    if (system("rm -rf /tmp/ntw-pipe-root && mkdir -p /tmp/ntw-pipe-root") != 0) return 1;
    ntw_winfile_set_ops(&ops);
    ntw_winfile_set_root("/tmp/ntw-pipe-root");
    wide("\\\\.\\pipe\\ping", name);
    C(ntw_pipe_create(name, 3, 0, 1, &server_handle, &error) == 1);
    C(ntw_pipe_transact(server_handle, "ping", 4, reply, 4, &got, 0, &error) == 0 && error == 233);
    C(pthread_create(&thread, 0, serve, 0) == 0);
    wide("\\\\.\\pipe\\ping", name);
    C(ntw_winfile_create(name, 0xc0000000u, 0, 3, 0, 0, &client, &error) == 1);
    got = 0;
    C(ntw_pipe_transact(client, "ping", 4, reply, 4, &got, 0, &error) == 1 && got == 4);
    C(reply[0] == 'p' && reply[1] == 'o' && reply[3] == 'g');
    C(ntw_pipe_transact(client, "ping", 4, reply, 4, &got, (void *)1, &error) == 0 && error == 87);
    pthread_join(thread, 0);
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"transact\":true}\n");
    return 0;
}
