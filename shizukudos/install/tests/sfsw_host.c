/* SPDX-License-Identifier: GPL-2.0-only
 * Host harness for win64/setup/sfsw.c: formats <image> (size <bytes>) as ShizukuFS v1 and copies the host
 * directory <tree> into it with the installer's writer, then reads every file back through the installer's
 * reader and compares. The caller (run_host_install.py) then runs e2fsck -fn and debugfs on the image.
 *   sfsw_host <image> <bytes> <tree> [ratio]
 */
#define _DEFAULT_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../win64/setup/sfsw.h"

static int img_fd;
static int rd(void *c, uint64_t b, uint32_t n, void *buf) { (void)c; return pread(img_fd, buf, (size_t)n * SFSW_BLOCK, (off_t)(b * SFSW_BLOCK)) == (ssize_t)n * SFSW_BLOCK ? 0 : -1; }
static int wr(void *c, uint64_t b, uint32_t n, const void *buf) { (void)c; return pwrite(img_fd, buf, (size_t)n * SFSW_BLOCK, (off_t)(b * SFSW_BLOCK)) == (ssize_t)n * SFSW_BLOCK ? 0 : -1; }
static void *al(void *c, size_t n) { (void)c; return calloc(1, n); }
static void fr(void *c, void *p) { (void)c; free(p); }

struct item { char host[1024], path[1024]; int dir; uint64_t size; uint32_t h; };
static struct item items[4096];
static int nitems;

static void scan(const char *host, const char *path)
{
    struct dirent **list;
    int n = scandir(host, &list, 0, alphasort), i;
    if (n < 0) { perror(host); exit(2); }
    for (i = 0; i < n; ++i) {
        struct item *it;
        struct stat st;
        if (!strcmp(list[i]->d_name, ".") || !strcmp(list[i]->d_name, "..")) { free(list[i]); continue; }
        it = &items[nitems++];
        snprintf(it->host, sizeof it->host, "%s/%s", host, list[i]->d_name);
        snprintf(it->path, sizeof it->path, "%s/%s", path, list[i]->d_name);
        if (stat(it->host, &st)) { perror(it->host); exit(2); }
        it->dir = S_ISDIR(st.st_mode);
        it->size = (uint64_t)st.st_size;
        free(list[i]);
        if (it->dir) scan(it->host, it->path);
    }
    free(list);
}

int main(int argc, char **argv)
{
    sfsw_io io = {0, rd, wr, al, fr};
    sfsw_params p;
    sfsw_info info;
    sfsw_t *w;
    sfsr_t *r;
    int err, i;
    static uint8_t buf[1 << 20], back[1 << 20];
    if (argc < 4) { fprintf(stderr, "usage: %s image bytes tree [ratio]\n", argv[0]); return 2; }
    img_fd = open(argv[1], O_RDWR | O_CREAT, 0644);
    if (img_fd < 0 || ftruncate(img_fd, (off_t)strtoull(argv[2], 0, 0))) { perror(argv[1]); return 2; }
    memset(&p, 0, sizeof p);
    p.bytes = strtoull(argv[2], 0, 0);
    p.inode_ratio = argc > 4 ? (uint32_t)atoi(argv[4]) : 0;
    p.time = 1790000000u;
    for (i = 0; i < 16; ++i) p.uuid[i] = (uint8_t)(0x53 + i * 7);
    memcpy(p.label, "SHZSYS", 6);
    w = sfsw_create(&io, &p, &err);
    if (!w) { fprintf(stderr, "create: %s\n", sfsw_strerror(err)); return 1; }
    scan(argv[3], "");
    for (i = 0; i < nitems; ++i) {
        err = items[i].dir ? sfsw_mkdir(w, items[i].path) : sfsw_add_file(w, items[i].path, items[i].size, &items[i].h);
        if (err) { fprintf(stderr, "add %s: %s\n", items[i].path, sfsw_strerror(err)); return 1; }
    }
    if ((err = sfsw_layout(w))) { fprintf(stderr, "layout: %s\n", sfsw_strerror(err)); return 1; }
    for (i = 0; i < nitems; ++i) {
        uint64_t off = 0;
        int fd;
        if (items[i].dir) continue;
        fd = open(items[i].host, O_RDONLY);
        for (;;) {
            ssize_t n = read(fd, buf, sizeof buf);
            if (n <= 0) break;
            if ((err = sfsw_write(w, items[i].h, off, buf, (uint32_t)n))) { fprintf(stderr, "write %s: %s\n", items[i].path, sfsw_strerror(err)); return 1; }
            off += (uint64_t)n;
        }
        close(fd);
    }
    if ((err = sfsw_commit(w))) { fprintf(stderr, "commit: %s\n", sfsw_strerror(err)); return 1; }
    sfsw_get_info(w, &info);
    printf("blocks=%llu free=%llu groups=%u ipg=%u files=%u dirs=%u\n", (unsigned long long)info.blocks,
           (unsigned long long)info.free_blocks, info.groups, info.inodes_per_group, info.files, info.dirs);
    sfsw_destroy(w);
    r = sfsr_open(&io, &err);
    if (!r) { fprintf(stderr, "reader: %s\n", sfsw_strerror(err)); return 1; }
    for (i = 0; i < nitems; ++i) {
        uint32_t ino, done;
        uint64_t size, off = 0;
        int is_dir, fd;
        if ((err = sfsr_lookup(r, items[i].path, &ino, &size, &is_dir))) { fprintf(stderr, "lookup %s: %s\n", items[i].path, sfsw_strerror(err)); return 1; }
        if (is_dir != items[i].dir || (!is_dir && size != items[i].size)) { fprintf(stderr, "%s: type/size mismatch\n", items[i].path); return 1; }
        if (is_dir) continue;
        fd = open(items[i].host, O_RDONLY);
        for (;;) {
            ssize_t n = read(fd, buf, sizeof buf);
            if (n <= 0) break;
            if ((err = sfsr_read(r, ino, off, back, (uint32_t)n, &done)) || done != (uint32_t)n || memcmp(buf, back, (size_t)n)) {
                fprintf(stderr, "read-back %s at %llu differs (%s)\n", items[i].path, (unsigned long long)off, sfsw_strerror(err));
                return 1;
            }
            off += (uint64_t)n;
        }
        close(fd);
    }
    sfsr_close(r);
    printf("read-back OK: %d entries\n", nitems);
    return 0;
}
