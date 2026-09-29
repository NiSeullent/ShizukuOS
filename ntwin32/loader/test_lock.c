/* SPDX-License-Identifier: GPL-2.0-only */
#include "winfile.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
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
static int host_open(void *user, const char *path, int flags, int mode) {
    int fd = open(path, flags, mode); (void)user; return fd < 0 ? -errno : fd;
}
static int host_close(void *user, int fd) { (void)user; return close(fd) == 0 ? 0 : -errno; }
static int host_read(void *user, int fd, void *buf, uint32_t bytes) {
    ssize_t n = read(fd, buf, bytes); (void)user; return n < 0 ? -errno : (int)n;
}
static int host_write(void *user, int fd, const void *buf, uint32_t bytes) {
    ssize_t n = write(fd, buf, bytes); (void)user; return n < 0 ? -errno : (int)n;
}
static int host_seek(void *user, int fd, uint32_t lo, uint32_t hi, int whence, uint32_t *new_lo, uint32_t *new_hi) {
    off_t got = lseek(fd, (off_t)(((uint64_t)hi << 32) | lo), whence); (void)user;
    if (got < 0) return -errno;
    *new_lo = (uint32_t)got; *new_hi = (uint32_t)((uint64_t)got >> 32); return 0;
}
static int host_exists(void *user, const char *path) { (void)user; return access(path, F_OK) == 0 ? 1 : 0; }
static int host_unlink(void *user, const char *path) { (void)user; return unlink(path) == 0 ? 0 : -errno; }
static int host_trunc(int fd, uint32_t lo, uint32_t hi) {
    off_t length = (off_t)(((uint64_t)hi << 32) | lo);
    return ftruncate(fd, length) == 0 ? 0 : -errno;
}
static int host_lock(int fd, int exclusive, int wait, uint32_t start_lo, uint32_t start_hi, uint32_t len_lo, uint32_t len_hi) {
    struct flock fl;
    memset(&fl, 0, sizeof fl);
    fl.l_type = exclusive == 2 ? F_UNLCK : (exclusive ? F_WRLCK : F_RDLCK);
    fl.l_whence = SEEK_SET;
    fl.l_start = (off_t)(((uint64_t)start_hi << 32) | start_lo);
    fl.l_len = (off_t)(((uint64_t)len_hi << 32) | len_lo);
    if (fcntl(fd, wait ? F_SETLKW : F_SETLK, &fl) == 0) return 0;
    return -errno;
}
int main(void) {
    ntw_disk_ops ops = { 0, host_open, host_close, host_read, host_write, host_seek, host_exists, host_unlink, 0, 0, 0, 0 };
    const char *path = "/tmp/ntw-lock-file";
    uint16_t name[80];
    uint32_t handle = 0, error = 0, count = 0, ov[5];
    int status = 0;
    pid_t child;
    unlink(path);
    wide(path, name);
    ntw_winfile_set_ops(&ops);
    ntw_winfile_set_lock(host_lock);
    ntw_winfile_set_trunc(host_trunc);
    memset(ov, 0, sizeof ov);
    C(ntw_winfile_lock(0x1111u, 3, 0, 4, 0, ov, &error) == 0 && error == 6);
    C(ntw_winfile_create(name, 0x40000000u, 0, 2, 0x80, 0, &handle, &error) == 1);
    C(ntw_winfile_write(handle, "lock", 4, &count, 0, &error) == 1);
    {
        uint32_t lo = 0, hi = 0;
        C(ntw_winfile_seek(handle, 2, 0, &lo, &hi, 0, &error) == 1 && lo == 2);
        C(ntw_winfile_set_end(handle, &error) == 1);
        C(ntw_winfile_size(handle, &lo, &hi, &error) == 1 && lo == 2 && hi == 0);
        C(ntw_winfile_set_end(0x1111u, &error) == 0 && error == 6);
    }
    C(ntw_winfile_lock(handle, 3, 0, 4, 0, 0, &error) == 0 && error == 87);
    C(ntw_winfile_lock(handle, 3, 1, 4, 0, ov, &error) == 0 && error == 87);
    C(ntw_winfile_lock(handle, 3, 0, 4, 0, ov, &error) == 1 && error == 0);
    C(ntw_winfile_lock(handle, 3, 0, 0xffffffffu, 0xffffffffu, ov, &error) == 1);
    C(ntw_winfile_unlock(handle, 1, 4, 0, ov, &error) == 0 && error == 87);
    C(ntw_winfile_unlock(handle, 0, 4, 0, ov, &error) == 1);
    {
        uint16_t got[80], missing[80];
        uint32_t needed = 0;
        wide("/tmp/ntw-lock-missing", missing);
        C(ntw_winfile_longpath(missing, got, 80, &needed, &error) == 0 && error == 2);
        C(ntw_winfile_longpath(name, got, 4, &needed, &error) == 0 && error == 122 && needed == 19);
        C(ntw_winfile_longpath(name, got, 80, &needed, &error) == 1 && needed == 18 && got[0] == '/' && got[18] == 0);
    }
    child = fork();
    if (child == 0) {
        uint32_t child_error = 0;
        int ok = ntw_winfile_lock(handle, 3, 0, 4, 0, ov, &child_error);
        _exit(ok ? 0 : (int)child_error);
    }
    C(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    C(ntw_winfile_delete(name, &error) == 0 && error == 32);
    C(ntw_winfile_close(handle, &error) == 1);
    C(ntw_winfile_delete(name, &error) == 1);
    C(ntw_winfile_delete(name, &error) == 0 && error == 2);
    C(mkdir("/tmp/ntw-lock-dir", 0755) == 0 || errno == EEXIST);
    {
        uint16_t dir[40];
        wide("/tmp/ntw-lock-dir", dir);
        C(ntw_winfile_delete(dir, &error) == 0 && error == 5);
    }
    rmdir("/tmp/ntw-lock-dir");
    {
        const char *shared = "/tmp/ntw-lock-shared";
        uint16_t wshared[80];
        uint32_t h2 = 0, count2 = 0;
        unlink(shared);
        wide(shared, wshared);
        C(ntw_winfile_create(wshared, 0xc0000000u, 4, 2, 0x80, 0, &h2, &error) == 1);
        C(ntw_winfile_write(h2, "z", 1, &count2, 0, &error) == 1);
        C(ntw_winfile_delete(wshared, &error) == 1);
        C(ntw_winfile_close(h2, &error) == 1);
        C(ntw_winfile_delete(wshared, &error) == 0 && error == 2);
    }
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"lock\":true}\n");
    return 0;
}
