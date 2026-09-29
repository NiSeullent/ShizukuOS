/* SPDX-License-Identifier: GPL-2.0-only
 * Host glue for libsfs (see sfs_host.h).
 */
#define _GNU_SOURCE
#include "sfs_host.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int full_pread(int fd, void *buf, size_t n, uint64_t off)
{
    uint8_t *p = buf;
    while (n) {
        ssize_t r = pread(fd, p, n, (off_t)off);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        p += r;
        n -= (size_t)r;
        off += (uint64_t)r;
    }
    return 0;
}

static int full_pwrite(int fd, const void *buf, size_t n, uint64_t off)
{
    const uint8_t *p = buf;
    while (n) {
        ssize_t r = pwrite(fd, p, n, (off_t)off);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        p += r;
        n -= (size_t)r;
        off += (uint64_t)r;
    }
    return 0;
}

static int h_read(void *ctx, uint64_t off, void *buf, uint32_t bytes)
{
    host_dev *d = ctx;
    uint32_t i;
    if (off + bytes > d->size) return -1;
    if (full_pread(d->fd, buf, bytes, off)) return -1;
    /* volatile cache: newer unflushed data wins */
    for (i = 0; i < d->pend_count; ++i) {
        struct pend *p = &d->pend[i];
        uint64_t s = p->off > off ? p->off : off;
        uint64_t e = p->off + p->len < off + bytes ? p->off + p->len : off + bytes;
        if (s < e) memcpy((uint8_t *)buf + (s - off), p->data + (s - p->off), (size_t)(e - s));
    }
    return 0;
}

void host_power_cut(host_dev *d)
{
    uint32_t i, seed = d->cut_seed ? d->cut_seed : 1;
    for (i = 0; i < d->pend_count; ++i) {
        seed = seed * 1103515245u + 12345u;
        if ((seed >> 16) & 1) full_pwrite(d->fd, d->pend[i].data, d->pend[i].len, d->pend[i].off);
    }
    if (!d->quiet) fprintf(stderr, "power cut after %llu writes: %u unflushed writes, random subset applied\n",
                           (unsigned long long)d->writes, d->pend_count);
    fsync(d->fd);
    _exit(d->cut_code ? d->cut_code : 77);
}

static int h_write(void *ctx, uint64_t off, const void *buf, uint32_t bytes)
{
    host_dev *d = ctx;
    if (off + bytes > d->size) return -1;
    d->writes++;
    if (d->cut_after && d->writes >= d->cut_after) {
        if (!d->volatile_cache) {
            if (!d->quiet) fprintf(stderr, "crash after %llu writes\n", (unsigned long long)d->writes);
            _exit(d->cut_code ? d->cut_code : 77);
        }
        host_power_cut(d);
    }
    if (d->volatile_cache) {
        struct pend *p;
        if (d->pend_count == d->pend_cap) {
            d->pend_cap = d->pend_cap ? d->pend_cap * 2 : 256;
            d->pend = realloc(d->pend, d->pend_cap * sizeof *d->pend);
            if (!d->pend) return -1;
        }
        p = &d->pend[d->pend_count++];
        p->off = off;
        p->len = bytes;
        p->data = malloc(bytes);
        if (!p->data) return -1;
        memcpy(p->data, buf, bytes);
        return 0;
    }
    return full_pwrite(d->fd, buf, bytes, off);
}

static int h_flush(void *ctx)
{
    host_dev *d = ctx;
    uint32_t i;
    d->flushes++;
    for (i = 0; i < d->pend_count; ++i) {
        if (full_pwrite(d->fd, d->pend[i].data, d->pend[i].len, d->pend[i].off)) return -1;
        free(d->pend[i].data);
    }
    d->pend_count = 0;
    if (d->do_fsync && fdatasync(d->fd)) return -1;
    return 0;
}

static void *h_alloc(void *ctx, size_t bytes)
{
    host_dev *d = ctx;
    void *p;
    if (bytes > SFS_MAX_ALLOC) {
        fprintf(stderr, "libsfs asked for %zu bytes (> SFS_MAX_ALLOC)\n", bytes);
        abort();
    }
    p = calloc(1, bytes);
    if (p) {
        d->live_bytes += (int64_t)bytes;
        d->live_objs++;
        if (d->live_bytes > d->peak_bytes) d->peak_bytes = d->live_bytes;
    }
    return p;
}

static void h_free(void *ctx, void *p, size_t bytes)
{
    host_dev *d = ctx;
    d->live_bytes -= (int64_t)bytes;
    d->live_objs--;
    free(p);
}

static uint64_t h_now(void *ctx)
{
    (void)ctx;
    return (uint64_t)time(0);
}

static void h_log(void *ctx, const char *msg)
{
    host_dev *d = ctx;
    if (!d->quiet) fprintf(stderr, "%s\n", msg);
}

int host_open(host_dev *d, const char *path, int writable)
{
    struct stat st;
    memset(d, 0, sizeof *d);
    d->fd = open(path, writable ? O_RDWR : O_RDONLY);
    if (d->fd < 0) return -1;
    if (fstat(d->fd, &st)) { close(d->fd); return -1; }
    if (S_ISBLK(st.st_mode)) {
        off_t e = lseek(d->fd, 0, SEEK_END);
        d->size = e > 0 ? (uint64_t)e : 0;
    } else {
        d->size = (uint64_t)st.st_size;
    }
    return 0;
}

void host_close(host_dev *d)
{
    uint32_t i;
    for (i = 0; i < d->pend_count; ++i) free(d->pend[i].data);
    free(d->pend);
    d->pend = 0;
    d->pend_count = 0;
    if (d->fd >= 0) close(d->fd);
    d->fd = -1;
}

void host_ops(host_dev *d, sfs_ops *ops, uint32_t cache_blocks)
{
    memset(ops, 0, sizeof *ops);
    ops->ctx = d;
    ops->read = h_read;
    ops->write = h_write;
    ops->flush = h_flush;
    ops->alloc = h_alloc;
    ops->free = h_free;
    ops->now = h_now;
    ops->log = h_log;
    ops->size = d->size;
    ops->cache_blocks = cache_blocks;
}
