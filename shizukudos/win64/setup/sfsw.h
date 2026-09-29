/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP: one-pass ShizukuFS v1 volume writer and a small verifying reader.
 *
 * ShizukuFS v1 is the ext4 on-disk format (see shizukufs/v1/libsfs/sfs.h, agent S2). Until S2's portable
 * libsfs (with its mkfs) is merged, the installer formats and populates the system partition with this
 * writer, which does what `mke2fs -d <tree>` does: it formats a fresh volume and lays out a tree that is
 * known in full before the first byte is written (the installer's manifest). It is NOT a general file
 * system: no journal, no later modification, no deletion. Written from the ext4 on-disk specification
 * (Linux Documentation/filesystems/ext4/); no e2fsprogs or kernel code is copied.
 *
 * Volume features: 4 KiB blocks, 32768 blocks per group, 256-byte inodes, sparse_super, filetype, extents,
 * large_file, extra_isize. No journal, no metadata_csum, no flex_bg, no dir_index (the result passes
 * `e2fsck -fn` and mounts as ext4 on Linux; tests/run_install.py and install/tests/run_host_install.py check it).
 *
 * Use: sfsw_create -> sfsw_mkdir / sfsw_add_file (whole tree) -> sfsw_layout -> sfsw_write (file data, any
 * order) -> sfsw_commit (metadata). sfsw_shrink + sfsw_commit may follow (the install log is written last).
 * The reader (sfsr_*) decodes the on-disk structures again from the device, independent of the writer's
 * memory, so the installer can verify what actually reached the disk.
 *
 * Portable C99; needs memcpy/memset/memcmp/strlen only. Block numbers are 4 KiB units relative to the volume.
 */
#ifndef SHZ_SFSW_H
#define SHZ_SFSW_H
#include <stddef.h>
#include <stdint.h>

#define SFSW_BLOCK 4096u
#define SFSW_NAME_MAX 255u

enum {
    SFSW_OK = 0,
    SFSW_EIO = -1,
    SFSW_ENOMEM = -2,
    SFSW_EINVAL = -3,
    SFSW_ENOSPC = -4,
    SFSW_EEXIST = -5,
    SFSW_ENOENT = -6,
    SFSW_ESTATE = -7,       /* call out of order (e.g. sfsw_add_file after sfsw_layout) */
    SFSW_ECORRUPT = -8,     /* reader: structure failed validation */
    SFSW_ENAMETOOLONG = -9,
    SFSW_ENOTDIR = -10,
    SFSW_EUNSUPP = -11      /* reader: valid ext4 but outside what this reader decodes */
};

typedef struct sfsw_io {
    void *ctx;
    int (*read)(void *ctx, uint64_t block, uint32_t count, void *buf);           /* 0 = ok */
    int (*write)(void *ctx, uint64_t block, uint32_t count, const void *buf);    /* 0 = ok */
    void *(*alloc)(void *ctx, size_t bytes);                                     /* zeroed memory or NULL */
    void (*free)(void *ctx, void *p);
} sfsw_io;

typedef struct sfsw_params {
    uint64_t bytes;             /* volume size in bytes (rounded down to 4 KiB) */
    uint32_t inode_ratio;       /* bytes of volume per inode; 0 = 16384 (mke2fs default) */
    uint32_t time;              /* seconds since 1970 for every timestamp */
    uint8_t uuid[16];
    char label[16];             /* not necessarily NUL-terminated when 16 characters long */
} sfsw_params;

typedef struct sfsw_info {
    uint64_t blocks, free_blocks;
    uint32_t groups, inodes_per_group, inodes, free_inodes;
    uint32_t files, dirs;
} sfsw_info;

typedef struct sfsw sfsw_t;

sfsw_t *sfsw_create(const sfsw_io *io, const sfsw_params *p, int *err);
int sfsw_mkdir(sfsw_t *w, const char *path);                                    /* "/a/b"; parent must exist */
int sfsw_add_file(sfsw_t *w, const char *path, uint64_t size, uint32_t *handle);
int sfsw_layout(sfsw_t *w);                                                     /* inode and block assignment, no I/O */
int sfsw_write(sfsw_t *w, uint32_t handle, uint64_t off, const void *buf, uint32_t len);   /* off: multiple of 4096 */
int sfsw_shrink(sfsw_t *w, uint32_t handle, uint64_t size);                     /* size <= planned size */
int sfsw_commit(sfsw_t *w);                                                     /* all metadata; repeatable */
void sfsw_get_info(const sfsw_t *w, sfsw_info *out);
uint32_t sfsw_inode_of(const sfsw_t *w, uint32_t handle);
void sfsw_destroy(sfsw_t *w);
const char *sfsw_strerror(int err);

/* Verifying reader (4 KiB-block ext4 volumes with linear directories and extent-mapped files). */
typedef struct sfsr sfsr_t;
sfsr_t *sfsr_open(const sfsw_io *io, int *err);
int sfsr_lookup(sfsr_t *r, const char *path, uint32_t *ino, uint64_t *size, int *is_dir);
int sfsr_read(sfsr_t *r, uint32_t ino, uint64_t off, void *buf, uint32_t len, uint32_t *done);    /* off: multiple of 4096 */
void sfsr_close(sfsr_t *r);
#endif
