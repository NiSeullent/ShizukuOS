/* SPDX-License-Identifier: GPL-2.0-only */
#include "winfile.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
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
static void filetime(time_t sec, long nsec, uint32_t *lo, uint32_t *hi) {
    unsigned long long ticks = (unsigned long long)sec * 10000000ull + 116444736000000000ull + (unsigned long long)(nsec / 100);
    *lo = (uint32_t)ticks;
    *hi = (uint32_t)(ticks >> 32);
}
static int host_open(void *user, const char *path, int flags, int mode) {
    int fd = open(path, flags, mode);
    (void)user;
    return fd < 0 ? -errno : fd;
}
static int host_close(void *user, int fd) { (void)user; return close(fd) == 0 ? 0 : -errno; }
static int host_read(void *user, int fd, void *buf, uint32_t bytes) {
    ssize_t n = read(fd, buf, bytes);
    (void)user;
    return n < 0 ? -errno : (int)n;
}
static int host_write(void *user, int fd, const void *buf, uint32_t bytes) {
    ssize_t n = write(fd, buf, bytes);
    (void)user;
    return n < 0 ? -errno : (int)n;
}
static int host_seek(void *user, int fd, uint32_t lo, uint32_t hi, int whence, uint32_t *new_lo, uint32_t *new_hi) {
    off_t got = lseek(fd, (off_t)(((uint64_t)hi << 32) | lo), whence);
    (void)user;
    if (got < 0) return -errno;
    *new_lo = (uint32_t)got;
    *new_hi = (uint32_t)((uint64_t)got >> 32);
    return 0;
}
static int host_exists(void *user, const char *path) { (void)user; return access(path, F_OK) == 0 ? 1 : 0; }
static int host_unlink(void *user, const char *path) { (void)user; return unlink(path) == 0 ? 0 : -errno; }
static int host_mkdir(void *user, const char *path, int mode) {
    (void)user; (void)mode;
    if (mkdir(path, 0755) == 0 || errno == EEXIST) return 0;
    return -errno;
}
static int host_meta(int fd, ntw_file_meta *out) {
    struct stat st;
    if (fstat(fd, &st) != 0) return -errno;
    out->attrs = S_ISDIR(st.st_mode) ? 0x10u : 0x20u;
    out->nlink = (uint32_t)st.st_nlink;
    out->size_lo = (uint32_t)st.st_size;
    out->size_hi = (uint32_t)((uint64_t)st.st_size >> 32);
    filetime(st.st_ctime, st.st_ctim.tv_nsec, &out->c_lo, &out->c_hi);
    filetime(st.st_atime, st.st_atim.tv_nsec, &out->a_lo, &out->a_hi);
    filetime(st.st_mtime, st.st_mtim.tv_nsec, &out->m_lo, &out->m_hi);
    out->ch_lo = out->c_lo;
    out->ch_hi = out->c_hi;
    return 0;
}
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
int main(void) {
    ntw_disk_ops ops = { 0, host_open, host_close, host_read, host_write, host_seek, host_exists, host_unlink, host_mkdir, 0, 0, 0 };
    const char *file = "/tmp/ntw-fileinfo-data";
    const char *dir = "/tmp/ntw-fileinfo-dir";
    uint16_t wfile[80], wdir[80];
    uint32_t handle = 0, dhandle = 0, error = 0, count = 0;
    uint8_t info[64];
    unlink(file);
    rmdir(dir);
    wide(file, wfile);
    wide(dir, wdir);
    ntw_winfile_set_ops(&ops);
    ntw_winfile_set_meta(host_meta);
    C(ntw_winfile_info(0x1111u, 1, info, 24, &error) == 0 && error == 6);
    C(ntw_winfile_create(wfile, 0x40000000u, 0, 2, 0x80, 0, &handle, &error) == 1);
    C(ntw_winfile_write(handle, "hello", 5, &count, 0, &error) == 1 && count == 5);
    C(ntw_winfile_info(handle, 1, 0, 24, &error) == 0 && error == 87);
    C(ntw_winfile_info(handle, 1, info, 8, &error) == 0 && error == 122);
    C(ntw_winfile_info(handle, 99, info, 24, &error) == 0 && error == 87);
    C(ntw_winfile_info(handle, 1, info, 24, &error) == 1 && rd32(info + 8) == 5 && info[21] == 0);
    C(ntw_winfile_info(handle, 0, info, 40, &error) == 1 && rd32(info + 32) == 0x20u && rd32(info + 20) != 0);
    C(ntw_winfile_info(handle, 9, info, 8, &error) == 1 && rd32(info) == 0x20u && rd32(info + 4) == 0);
    C(ntw_winfile_close(handle, &error) == 1);
    C(mkdir(dir, 0755) == 0 || errno == EEXIST);
    C(ntw_winfile_create(wdir, 0x80000000u, 1, 3, 0x80, 0, &dhandle, &error) == 1);
    C(ntw_winfile_info(dhandle, 1, info, 24, &error) == 1 && info[21] == 1);
    C(ntw_winfile_info(dhandle, 0, info, 40, &error) == 1 && rd32(info + 32) == 0x10u);
    C(ntw_winfile_close(dhandle, &error) == 1);
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"fileinfo\":true}\n");
    return 0;
}
