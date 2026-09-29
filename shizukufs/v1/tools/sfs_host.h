/* SPDX-License-Identifier: GPL-2.0-only
 * Host glue for libsfs: an image file as the block device, malloc as the allocator (with leak accounting), the
 * wall clock. Optional "volatile write cache" mode for power-cut simulation: writes are held until the next flush
 * and a simulated power cut applies only a random subset of them (the disk may reorder or drop unflushed writes).
 */
#ifndef SFS_HOST_H
#define SFS_HOST_H
#include <stdint.h>
#include <stddef.h>
#include "../libsfs/sfs.h"

typedef struct host_dev {
    int fd;
    uint64_t size;
    int do_fsync;                   /* flush = fdatasync(2) */
    int quiet;
    /* allocator accounting */
    int64_t live_bytes, live_objs, peak_bytes;
    /* volatile cache simulation */
    int volatile_cache;
    uint32_t pend_count, pend_cap;
    struct pend { uint64_t off; uint32_t len; uint8_t *data; } *pend;
    uint64_t writes, flushes;
    /* power cut: after `cut_after` device writes, apply a random subset of the pending writes and _exit(cut_code) */
    uint64_t cut_after;
    uint32_t cut_seed;
    int cut_code;
} host_dev;

int host_open(host_dev *d, const char *path, int writable);
void host_close(host_dev *d);
void host_ops(host_dev *d, sfs_ops *ops, uint32_t cache_blocks);
void host_power_cut(host_dev *d);   /* apply a random subset of pending writes, then _exit */
#endif
