/* SPDX-License-Identifier: GPL-2.0-only */
#include "winfile.h"
#include <errno.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static int failures;
static int fake_dir(void *user, const char *directory, uint32_t index, char *name, uint32_t cap, int *is_dir, uint32_t *size_lo) {
    const char *names[] = {".", "..", "settings.dat", "notes.txt"};
    uint32_t n = 0;
    (void)user; (void)directory;
    if (index > 3 || cap < 2) return 0;
    while (names[index][n] && n + 1 < cap) { name[n] = names[index][n]; n++; }
    name[n] = 0;
    *is_dir = 0;
    *size_lo = index == 2 ? 4u : 1u;
    return 1;
}
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
static void wide(const char *ascii, uint16_t *out) {
    while (*ascii) *out++ = (uint16_t)(unsigned char)*ascii++;
    *out = 0;
}
static int host_open(void *user, const char *path, int flags, int mode) {
    int fd;
    (void)user;
    fd = open(path, flags, mode);
    return fd < 0 ? -errno : fd;
}
static int host_close(void *user, int fd) { (void)user; return close(fd) == 0 ? 0 : -errno; }
static int host_read(void *user, int fd, void *buf, uint32_t bytes) {
    ssize_t n;
    (void)user;
    n = read(fd, buf, bytes);
    return n < 0 ? -errno : (int)n;
}
static int host_write(void *user, int fd, const void *buf, uint32_t bytes) {
    ssize_t n;
    (void)user;
    n = write(fd, buf, bytes);
    return n < 0 ? -errno : (int)n;
}
static int host_seek(void *user, int fd, uint32_t lo, uint32_t hi, int whence, uint32_t *new_lo, uint32_t *new_hi) {
    off_t off, got;
    (void)user;
    off = (off_t)(((uint64_t)hi << 32) | lo);
    got = lseek(fd, off, whence);
    if (got < 0) return -errno;
    *new_lo = (uint32_t)got;
    *new_hi = (uint32_t)((uint64_t)got >> 32);
    return 0;
}
static int host_exists(void *user, const char *path) {
    (void)user;
    return access(path, F_OK) == 0 ? 1 : 0;
}
static int host_unlink(void *user, const char *path) {
    (void)user;
    return unlink(path) == 0 ? 0 : -errno;
}
static int host_mkdir(void *user, const char *mkpath, int mode) {
    (void)user; (void)mode;
    if (mkdir(mkpath, 0755) == 0 || errno == EEXIST) return 0;
    return -errno;
}
int main(void) {
    ntw_disk_ops ops = { 0, host_open, host_close, host_read, host_write, host_seek, host_exists, host_unlink, 0, 0, 0, 0 };
    const char *path = "/tmp/ntw-winfile-contract";
    uint16_t name[80], missing[80], bad[4];
    uint32_t handle = 0, error = 0, count = 99, lo = 0, hi = 9, new_lo = 0, new_hi = 0;
    char buf[8];
    unlink(path);
    wide(path, name);
    wide("/tmp/ntw-winfile-missing-no-such", missing);
    ntw_winfile_set_ops(&ops);
    C(ntw_winfile_create(0, 0x80000000u, 1, 3, 0x80, 0, &handle, &error) == 0 && error == 87 && handle == 0);
    C(ntw_winfile_create(missing, 0x80000000u, 1, 3, 0x80, 0, &handle, &error) == 0 && error == 2);
    C(ntw_winfile_create(name, 0x80000000u, 1, 9, 0x80, 0, &handle, &error) == 0 && error == 87);
    C(ntw_winfile_create(name, 0x40000000u, 0, 2, 0x80, 0, &handle, &error) == 1 && handle != 0);
    C(ntw_winfile_write(handle, "ab", 2, &count, 0, &error) == 1 && count == 2);
    C(ntw_winfile_read(handle, buf, 2, &count, 0, &error) == 0 && error == 5);
    C(ntw_winfile_size(handle, &lo, &hi, &error) == 1 && lo == 2 && hi == 0);
    C(ntw_winfile_close(handle, &error) == 1);
    C(ntw_winfile_read(handle, buf, 2, &count, 0, &error) == 0 && error == 6);
    error = 0;
    C(ntw_winfile_create(name, 0x80000000u, 1, 1, 0x80, 0, &handle, &error) == 0 && error == 80);
    C(ntw_winfile_create(name, 0xc0000000u, 1, 3, 0x80, 0, &handle, &error) == 1 && error == 0);
    C(ntw_winfile_read(handle, buf, 2, &count, 0, &error) == 1 && count == 2 && buf[0] == 'a' && buf[1] == 'b');
    C(ntw_winfile_seek(handle, 1, 0, &new_lo, &new_hi, 0, &error) == 1 && new_lo == 1);
    C(ntw_winfile_read(handle, buf, 1, &count, 0, &error) == 1 && count == 1 && buf[0] == 'b');
    C(ntw_winfile_seek(handle, 0xffffffffu, 0xffffffffu, &new_lo, &new_hi, 0, &error) == 0 && error == 131);
    C(ntw_winfile_close(handle, &error) == 1);
    C(ntw_winfile_close(handle, &error) == 0 && error == 6);
    bad[0] = 'Z'; bad[1] = 'Z'; bad[2] = 0;
    C(ntw_winfile_create(bad, 0x80000000u, 0, 3, 0x80, 1, &handle, &error) == 0 && error == 87 && handle == 0);
    wide("\\\\.\\pipe\\crashpad", name);
    C(ntw_pipe_create(0, 3, 0, 1, &handle, &error) == 0 && error == 87);
    C(ntw_pipe_create(name, 0, 0, 1, &handle, &error) == 0 && error == 87);
    wide("C:\\not\\a\\pipe", missing);
    C(ntw_pipe_create(missing, 3, 0, 1, &handle, &error) == 0 && error == 123);
    wide("\\\\.\\pipe\\crashpad", name);
    C(ntw_pipe_create(name, 3, 1, 1, &handle, &error) == 1);
    C(ntw_pipe_connect(handle, 0, &error) == 0 && error == 536);
    C(ntw_winfile_write(handle, "x", 1, &count, 0, &error) == 0 && error == 233);
    {
        uint32_t second = 0;
        C(ntw_pipe_create(name, 3, 0, 1, &second, &error) == 0 && error == 231);
    }
    C(ntw_winfile_close(handle, &error) == 1);
    C(ntw_event_create(1, 0, 0, &handle, &error) == 1 && error == 0);
    C(ntw_event_wait(handle, &count) == 1 && count == 258);
    C(ntw_event_set(handle, &error) == 1);
    C(ntw_event_wait(handle, &count) == 1 && count == 0);
    C(ntw_event_wait(handle, &count) == 1 && count == 0);
    C(ntw_event_reset(handle, &error) == 1);
    C(ntw_event_wait(handle, &count) == 1 && count == 258);
    C(ntw_event_close(handle, &error) == 1);
    C(ntw_event_wait(handle, &count) == 0 && count == 0xffffffffu);
    wide("chrome-ready", name);
    C(ntw_event_create(0, 1, name, &handle, &error) == 1);
    C(ntw_event_wait(handle, &count) == 1 && count == 0);
    C(ntw_event_wait(handle, &count) == 1 && count == 258);
    {
        uint32_t again = 0;
        C(ntw_event_create(0, 0, name, &again, &error) == 1 && error == 183 && again == handle);
    }
    {
        uint16_t dir[32], created[64], badunc[32], baddrive[32], missingf[48];
        char data[8];
        ops.mkdir = host_mkdir;
        ntw_winfile_set_root("/tmp/ntw-drive-root");
        ntw_winfile_set_ops(&ops);
        if (system("rm -rf /tmp/ntw-drive-root") != 0) { /* fresh root */ }
        wide("\\Crashpad", dir);
        C(ntw_winfile_mkdirs(dir, &error) == 1 && error == 0);
        {
            uint16_t user[64], bad[16], unc[24];
            wide("C:\\AppData\\Local\\Google\\Chrome\\User Data", user);
            C(ntw_winfile_mkdirs(user, &error) == 1 && error == 0);
            C(access("/tmp/ntw-drive-root/AppData/Local/Google/Chrome/User Data", F_OK) == 0);
            C(ntw_winfile_mkdirs(user, &error) == 0 && error == 183);
            wide("D:\\Nope", bad);
            C(ntw_winfile_mkdirs(bad, &error) == 0 && error == 3);
            wide("\\\\server\\share", unc);
            C(ntw_winfile_mkdirs(unc, &error) == 0 && error == 3);
        }
        C(access("/tmp/ntw-drive-root/Crashpad", F_OK) == 0);
        {
            uint32_t attrs = 0;
            C(ntw_winfile_attributes(dir, &attrs, &error) == 1 && attrs == 0x10u);
            wide("\\Crashpad\\absent.dat", missingf);
            C(ntw_winfile_attributes(missingf, &attrs, &error) == 0 && error == 2);
        }
        C(ntw_winfile_mkdirs(dir, &error) == 0 && error == 183);
        wide("\\Crashpad\\settings.dat", created);
        C(ntw_winfile_create(created, 0x40000000u, 0, 2, 0x80, 0, &handle, &error) == 1);
        C(ntw_winfile_write(handle, "ok", 2, &count, 0, &error) == 1 && count == 2);
        C(ntw_winfile_close(handle, &error) == 1);
        C(ntw_winfile_create(created, 0x80000000u, 1, 3, 0x80, 0, &handle, &error) == 1);
        C(ntw_winfile_read(handle, data, 2, &count, 0, &error) == 1 && count == 2 && data[0] == 'o');
        C(ntw_winfile_close(handle, &error) == 1);
        wide("\\Crashpad\\missing.dat", missingf);
        C(ntw_winfile_create(missingf, 0x80000000u, 1, 3, 0x80, 0, &handle, &error) == 0 && error == 2);
        wide("\\\\server\\share", badunc);
        C(ntw_winfile_mkdirs(badunc, &error) == 0 && error == 3);
        wide("D:\\Crashpad", baddrive);
        C(ntw_winfile_create(baddrive, 0x40000000u, 0, 2, 0x80, 0, &handle, &error) == 0 && error == 3);
        C(ntw_winfile_create(created, 0x80000000u, 1, 3, 0x80, 0, &handle, &error) == 1);
        {
            uint32_t bits = 99;
            C(ntw_winfile_flags(handle, 0, 0, 0, &bits) == 1 && bits == 0);
            C(ntw_winfile_flags(0, 1, 1, 1, &bits) == 0);
            C(ntw_winfile_flags(handle, 1, 1, 1, 0) == 1);
            C(ntw_winfile_flags(handle, 1, 2, 2, 0) == 1);
            C(ntw_winfile_flags(handle, 0, 0, 0, &bits) == 1 && bits == 3);
            C(ntw_winfile_close(handle, &error) == 0 && error == 6);
            C(ntw_winfile_flags(handle, 1, 2, 0, 0) == 1);
            C(ntw_winfile_close(handle, &error) == 1);
        }
        ntw_winfile_set_dir(fake_dir, 0);
        {
            uint8_t data[592];
            uint32_t found = 0;
            uint16_t pat[40];
            wide("\\Crashpad\\*.dat", pat);
            C(ntw_find_first(pat, 2, 0, 0, 0, data, 592, &found, &error) == 0 && error == 87);
            C(ntw_find_first(pat, 0, 0, 0, 0, data, 592, &found, &error) == 1 && error == 0);
            C(data[44] == 's' && data[46] == 'e');
            C(ntw_find_next(found, data, 592, &error) == 0 && error == 18);
            C(ntw_find_close(found, &error) == 1);
            wide("\\Crashpad\\none.bin", pat);
            C(ntw_find_first(pat, 0, 0, 0, 0, data, 592, &found, &error) == 0 && error == 2);
            wide("\\Missing\\*.dat", pat);
            C(ntw_find_first(pat, 0, 0, 0, 0, data, 592, &found, &error) == 0 && error == 3);
        }
    }
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"winfile\":true}\n");
    unlink(path);
    return 0;
}
