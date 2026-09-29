/* SPDX-License-Identifier: GPL-2.0-only */
#include "filemap.h"
#include "winfile.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
static int host_open(void *user, const char *path, int flags, int mode) {
    int fd; (void)user; fd = open(path, flags, mode); return fd < 0 ? -errno : fd;
}
static int host_close(void *user, int fd) { (void)user; return close(fd) == 0 ? 0 : -errno; }
static int host_read(void *user, int fd, void *buf, uint32_t bytes) {
    ssize_t n; (void)user; n = read(fd, buf, bytes); return n < 0 ? -errno : (int)n;
}
static int host_write(void *user, int fd, const void *buf, uint32_t bytes) {
    ssize_t n; (void)user; n = write(fd, buf, bytes); return n < 0 ? -errno : (int)n;
}
static int host_seek(void *user, int fd, uint32_t lo, uint32_t hi, int whence, uint32_t *new_lo, uint32_t *new_hi) {
    off_t got; (void)user; (void)hi; got = lseek(fd, (off_t)lo, whence); if (got < 0) return -errno;
    if (new_lo) *new_lo = (uint32_t)got;
    if (new_hi) *new_hi = 0;
    return 0;
}
static int host_exists(void *user, const char *path) { (void)user; return access(path, F_OK) == 0; }
static int host_unlink(void *user, const char *path) { (void)user; return unlink(path) == 0 ? 0 : -errno; }
static int failures;
static void *place(void *user, void *addr, uint32_t length, int prot, int flags) {
    void *memory;
    (void)user; (void)addr; (void)flags;
    memory = mmap(0, length, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return memory == MAP_FAILED ? 0 : memory;
}
static int remove_map(void *user, void *addr, uint32_t length) {
    (void)user;
    return munmap(addr, length);
}
static int protect(void *user, void *addr, uint32_t length, int prot) {
    (void)user;
    return mprotect(addr, length, prot);
}
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
int main(void) {
    uint32_t error = 0, mapping, again;
    uintptr_t view;
    static const uint16_t name[] = {'M','a','p',0};
    unsigned char *bytes;
    ntw_filemap_set_ops(place, remove_map, protect, 0);
    ntw_filemap_reset();
    C(ntw_filemap_create(NTW_MAP_INVALID_FILE, NTW_MAP_PAGE_READWRITE, 0, 0, 0, &error) == 0 && error == 87);
    C(ntw_filemap_create(NTW_MAP_INVALID_FILE, 1, 0, 4096, 0, &error) == 0 && error == 87);
    C(ntw_filemap_create(0x1234, NTW_MAP_PAGE_READWRITE, 0, 4096, 0, &error) == 0 && error == 6);
    C(ntw_filemap_create(NTW_MAP_INVALID_FILE, NTW_MAP_PAGE_READWRITE, 1, 4096, 0, &error) == 0 && error == 87);
    C(ntw_filemap_create(NTW_MAP_INVALID_FILE, NTW_MAP_PAGE_READWRITE | 0x1000000u, 0, 4096, 0, &error) == 0 && error == 87);
    mapping = ntw_filemap_create(NTW_MAP_INVALID_FILE, NTW_MAP_PAGE_READWRITE | NTW_MAP_SEC_COMMIT, 0, 8192, name, &error);
    C(mapping == 0x3000 && error == 0);
    again = ntw_filemap_create(NTW_MAP_INVALID_FILE, NTW_MAP_PAGE_READWRITE, 0, 100, name, &error);
    C(again == mapping && error == 183);
    C(ntw_filemap_create(NTW_MAP_INVALID_FILE, NTW_MAP_PAGE_READONLY, 0, 8192, name, &error) == 0 && error == 5);
    C(ntw_filemap_view(mapping, NTW_MAP_WRITE, 0, 100, 100, &error) == 0 && error == 87);
    C(ntw_filemap_view(mapping, NTW_MAP_WRITE, 0, 0, 9000, &error) == 0 && error == 87);
    view = ntw_filemap_view(mapping, NTW_MAP_READ | NTW_MAP_WRITE, 0, 0, 16, &error);
    C(view && error == 0);
    bytes = (unsigned char *)view;
    bytes[0] = 0x5a;
    C(bytes[0] == 0x5a);
    C(ntw_filemap_unmap(0, &error) == 0 && error == 87);
    C(ntw_filemap_unmap(0x10, &error) == 0 && error == 487);
    C(ntw_filemap_unmap(view, &error) == 1);
    C(ntw_filemap_view(0x111, NTW_MAP_READ, 0, 0, 16, &error) == 0 && error == 6);
    {
        uint32_t ro = ntw_filemap_create(NTW_MAP_INVALID_FILE, NTW_MAP_PAGE_READONLY, 0, 4096, 0, &error);
        C(ro && ntw_filemap_view(ro, NTW_MAP_WRITE, 0, 0, 16, &error) == 0 && error == 5);
        C(ntw_filemap_close(ro, &error) == 1);
    }
    C(ntw_filemap_close(mapping, &error) == 1);
    {
        uint32_t copy = 0;
        mapping = ntw_filemap_create(NTW_MAP_INVALID_FILE, NTW_MAP_PAGE_READWRITE, 0, 4096, 0, &error);
        C(ntw_filemap_duplicate(mapping, 1, &copy, &error) == 1 && copy != mapping);
        C(ntw_filemap_view(mapping, NTW_MAP_READ, 0, 0, 16, &error) == 0);
        C(ntw_filemap_view(copy, NTW_MAP_READ, 0, 0, 16, &error) != 0);
        C(ntw_filemap_close(copy, &error) == 1);
    }
    {
        ntw_disk_ops ops;
        uint16_t path[32];
        uint32_t file = 0, count = 0;
        const char *text = "ICU!";
        unsigned i;
        memset(&ops, 0, sizeof ops);
        ops.open = host_open; ops.close = host_close; ops.read = host_read; ops.write = host_write;
        ops.seek = host_seek; ops.exists = host_exists; ops.unlink = host_unlink;
        ntw_winfile_set_ops(&ops);
        for (i = 0; text[i]; ++i) path[i] = (uint16_t)text[i];
        path[0] = '/'; path[1] = 't'; path[2] = 'm'; path[3] = 'p'; path[4] = '/';
        path[5] = 'n'; path[6] = 't'; path[7] = 'w'; path[8] = '-'; path[9] = 'i';
        path[10] = 'c'; path[11] = 'u'; path[12] = '-'; path[13] = 'm'; path[14] = 'a';
        path[15] = 'p'; path[16] = 0;
        unlink("/tmp/ntw-icu-map");
        C(ntw_winfile_create(path, 0xc0000000u, 0, 2, 0, 0, &file, &error) == 1);
        C(ntw_winfile_write(file, "ICU!", 4, &count, 0, &error) == 1 && count == 4);
        mapping = ntw_filemap_create(file, NTW_MAP_PAGE_READONLY, 0, 0, 0, &error);
        C(mapping != 0 && error == 0);
        view = ntw_filemap_view(mapping, NTW_MAP_READ, 0, 0, 0, &error);
        bytes = (unsigned char *)view;
        C(view && bytes[0] == 'I' && bytes[3] == '!');
        C(ntw_filemap_unmap(view, &error) == 1);
        C(ntw_filemap_close(mapping, &error) == 1);
        C(ntw_winfile_close(file, &error) == 1);
        unlink("/tmp/ntw-icu-map");
    }
    if (failures) return 1;
    printf("{\"passed\":true,\"filemap\":true}\n");
    return 0;
}
