/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS v1 (libsfs): a read/write implementation of the ext4 on-disk format.
 *
 * ShizukuFS v1 IS the ext4 on-disk format (Linux ext2/3/4 as documented in the kernel's
 * Documentation/filesystems/ext4/ and the public e2fsprogs layout): a volume created by mkfs.ext4 is
 * read and written here, and a volume written here passes `e2fsck -f` and is readable by Linux.
 * This is an original implementation written from the specification; no GPL sources are copied.
 *
 * Portable C11, freestanding-capable: the only external dependencies are memcpy/memset/memmove/memcmp/
 * strlen (provided by libc on the host and by lib.c in Kernel64) and the callback table below (block I/O,
 * an allocator that hands out objects of at most SFS_MAX_ALLOC bytes, a clock). The same object code runs
 * in the host tools and inside Kernel64 (see kernel64/sfs_mount.c).
 *
 * Threading: one volume must be driven by one thread at a time (the callers serialise; Kernel64 uses a
 * mutex per mount).
 */
#ifndef SFS_H
#define SFS_H
#include <stddef.h>
#include <stdint.h>

#define SFS_MAX_ALLOC 4096u            /* the library never asks the allocator for more than this */
#define SFS_NAME_MAX 255u

/* Error codes (negative). */
enum {
    SFS_OK = 0,
    SFS_EIO = -1,           /* block I/O failure */
    SFS_ENOENT = -2,
    SFS_EEXIST = -3,
    SFS_ENOTDIR = -4,
    SFS_EISDIR = -5,
    SFS_ENOTEMPTY = -6,
    SFS_ENOSPC = -7,
    SFS_ENOMEM = -8,
    SFS_EINVAL = -9,
    SFS_EROFS = -10,        /* read-only mount (feature set or caller's choice) */
    SFS_ECORRUPT = -11,     /* on-disk structure failed validation (checksum, bounds, magic) */
    SFS_ENOTSUP = -12,      /* valid but unsupported (inline data, encrypted inode, block-map write ...) */
    SFS_ENAMETOOLONG = -13,
    SFS_EFBIG = -14,
    SFS_EBUSY = -15,
    SFS_ERANGE = -16
};

/* Mount flags. */
#define SFS_MOUNT_RDONLY 1u            /* never write; the journal is not replayed either (like mount -o ro,noload) */
#define SFS_MOUNT_NOREPLAY 2u          /* refuse to mount read-write if the journal needs replay (diagnostics) */
#define SFS_MOUNT_CLEAN_ON_SYNC 4u     /* after every sfs_sync() leave the volume in the "cleanly unmounted" state
                                          (and do not mark it in use at mount: the first update does) */
#define SFS_MOUNT_NAIVE 8u             /* benchmark baseline: no preallocation, no extent cache, tiny block cache */
#define SFS_MOUNT_SMALL_TXN 16u        /* tests: commit at 64 journal blocks, so multi-step operations commit mid-way */

/* Callback table filled by the host/kernel glue. Byte offsets are always multiples of the volume block size. */
typedef struct sfs_ops {
    void *ctx;
    int (*read)(void *ctx, uint64_t offset, void *buf, uint32_t bytes);           /* 0 = ok */
    int (*write)(void *ctx, uint64_t offset, const void *buf, uint32_t bytes);    /* 0 = ok */
    int (*flush)(void *ctx);                                                     /* durable barrier, 0 = ok */
    void *(*alloc)(void *ctx, size_t bytes);                                     /* zeroed, bytes <= SFS_MAX_ALLOC */
    void (*free)(void *ctx, void *p, size_t bytes);
    uint64_t (*now)(void *ctx);                                                  /* seconds since 1970 (0 = unknown) */
    void (*log)(void *ctx, const char *msg);                                     /* optional diagnostics */
    uint64_t size;                                                               /* device size in bytes */
    uint32_t cache_blocks;                                                       /* block cache size (0 = default) */
    /* optional: writes `count` buffers of `buf_bytes` each to consecutive locations starting at `offset` in one
     * request (0 = ok). Without it every block is a separate write(). */
    int (*writev)(void *ctx, uint64_t offset, const void *const *bufs, uint32_t count, uint32_t buf_bytes);
} sfs_ops;

typedef struct sfs_fs sfs_fs;           /* opaque volume handle */

#define SFS_ROOT_INO 2u

/* Inode types (from i_mode). */
#define SFS_S_IFMT 0xF000u
#define SFS_S_IFREG 0x8000u
#define SFS_S_IFDIR 0x4000u
#define SFS_S_IFLNK 0xA000u

/* Directory entry file types. */
enum { SFS_FT_UNKNOWN = 0, SFS_FT_REG = 1, SFS_FT_DIR = 2, SFS_FT_CHR = 3, SFS_FT_BLK = 4, SFS_FT_FIFO = 5,
       SFS_FT_SOCK = 6, SFS_FT_SYMLINK = 7 };

typedef struct sfs_stat {
    uint32_t ino;
    uint16_t mode;
    uint16_t links;
    uint32_t uid, gid;
    uint64_t size;
    uint64_t blocks;            /* 512-byte units, as i_blocks */
    int64_t atime, mtime, ctime, crtime;    /* seconds since 1970 (with the extra epoch bits applied) */
    uint32_t atime_ns, mtime_ns, ctime_ns, crtime_ns;
    uint32_t flags;             /* i_flags */
    uint32_t generation;
} sfs_stat_t;

typedef struct sfs_dirent {
    uint32_t ino;
    uint8_t type;               /* SFS_FT_* */
    uint8_t name_len;
    char name[SFS_NAME_MAX + 1];
} sfs_dirent;

typedef struct sfs_statfs {
    uint32_t block_size;
    uint64_t blocks, free_blocks;
    uint32_t inodes, free_inodes;
    uint32_t groups;
    uint32_t feature_compat, feature_incompat, feature_ro_compat;
    uint32_t journal_features;
    int read_only;              /* effective read-only state */
    uint32_t ro_reason;         /* SFS_RO_* bit set explaining a forced read-only mount */
    uint8_t uuid[16];
    char label[17];
} sfs_statfs_t;

/* Reasons for a forced read-only mount (bit set, see sfs_statfs.ro_reason). */
#define SFS_RO_CALLER 0x1u
#define SFS_RO_NO_EXTENTS 0x2u
#define SFS_RO_UNKNOWN_RO_COMPAT 0x4u
#define SFS_RO_INLINE_DATA 0x8u
#define SFS_RO_ENCRYPT 0x10u
#define SFS_RO_CASEFOLD 0x20u
#define SFS_RO_QUOTA 0x40u
#define SFS_RO_VERITY 0x80u
#define SFS_RO_READONLY_FLAG 0x100u
#define SFS_RO_EA_INODE 0x200u
#define SFS_RO_JOURNAL_FAST_COMMIT 0x400u
#define SFS_RO_ORPHAN_FILE 0x800u
#define SFS_RO_ERRORS 0x1000u          /* s_state has the error bit set */
#define SFS_RO_JOURNAL_ERRNO 0x2000u   /* journal superblock recorded an error */
#define SFS_RO_NEEDS_REPLAY 0x4000u    /* SFS_MOUNT_NOREPLAY and the journal is dirty */
#define SFS_RO_LARGE_BLOCK 0x8000u

/* Statistics (for the performance harness and diagnostics). */
typedef struct sfs_stats {
    uint64_t reads, read_bytes, writes, write_bytes, flushes;
    uint64_t cache_hits, cache_misses, cache_evictions;
    uint64_t commits, journal_blocks_written, checkpoint_blocks;
    uint64_t extent_cache_hits, extent_cache_misses;
    uint64_t dx_lookups, linear_lookups;
    uint64_t replayed_transactions, replayed_blocks, revoked_blocks;
} sfs_stats;

/* Volume life cycle. */
int sfs_mount(const sfs_ops *ops, unsigned flags, sfs_fs **out);
int sfs_unmount(sfs_fs *fs);                    /* commits, checkpoints, marks clean, frees everything */
int sfs_sync(sfs_fs *fs);                       /* commit the running transaction, checkpoint, flush */
int sfs_statfs(sfs_fs *fs, sfs_statfs_t *out);
void sfs_get_stats(sfs_fs *fs, sfs_stats *out);
int sfs_is_readonly(sfs_fs *fs);
uint32_t sfs_block_size(sfs_fs *fs);

/* Names are byte strings (UTF-8 on Linux volumes), compared bytewise (case-sensitive). */
int sfs_lookup(sfs_fs *fs, uint32_t dir, const char *name, size_t len, uint32_t *ino, uint8_t *type);
int sfs_stat(sfs_fs *fs, uint32_t ino, sfs_stat_t *st);
/* Enumerates a directory: *cookie starts at 0; returns 1 with an entry, 0 at the end, < 0 on error. */
int sfs_readdir(sfs_fs *fs, uint32_t dir, uint64_t *cookie, sfs_dirent *out);
int sfs_read(sfs_fs *fs, uint32_t ino, uint64_t off, void *buf, uint64_t len, uint64_t *done);
int sfs_write(sfs_fs *fs, uint32_t ino, uint64_t off, const void *buf, uint64_t len, uint64_t *done);
int sfs_truncate(sfs_fs *fs, uint32_t ino, uint64_t size);          /* shrink or extend (extension is sparse) */
int sfs_create(sfs_fs *fs, uint32_t dir, const char *name, size_t len, uint16_t mode, uint32_t *ino);
int sfs_mkdir(sfs_fs *fs, uint32_t dir, const char *name, size_t len, uint16_t mode, uint32_t *ino);
int sfs_symlink(sfs_fs *fs, uint32_t dir, const char *name, size_t len, const char *target, size_t tlen, uint32_t *ino);
int sfs_readlink(sfs_fs *fs, uint32_t ino, char *buf, size_t cap, size_t *len);
int sfs_unlink(sfs_fs *fs, uint32_t dir, const char *name, size_t len);      /* files, symlinks, specials */
int sfs_rmdir(sfs_fs *fs, uint32_t dir, const char *name, size_t len);
int sfs_rename(sfs_fs *fs, uint32_t odir, const char *oname, size_t olen, uint32_t ndir, const char *nname, size_t nlen,
               int replace);
int sfs_set_times(sfs_fs *fs, uint32_t ino, const int64_t *atime, const int64_t *mtime);
int sfs_set_mode(sfs_fs *fs, uint32_t ino, uint16_t mode);
/* Resolves a '/'-separated absolute path (host tools; symlinks are not followed). */
int sfs_path_lookup(sfs_fs *fs, const char *path, uint32_t *ino, uint32_t *parent, const char **leaf, size_t *leaf_len);

/* Diagnostics: what the media says right now (read from the device, not the cache): the superblock's
 * needs_recovery flag / VALID_FS state and the journal superblock's s_start (0 = empty log). */
int sfs_ondisk_state(sfs_fs *fs, int *needs_recovery, int *valid_fs, uint32_t *journal_start);

/* Fault injection for the crash test (host only): the writer stops after `n` block writes. */
void sfs_set_write_limit(sfs_fs *fs, uint64_t n, void (*hit)(void *ctx));

const char *sfs_strerror(int err);
#endif
