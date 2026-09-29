/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS v1 internals shared by the libsfs modules. Not part of the public interface.
 */
#ifndef SFS_INTERNAL_H
#define SFS_INTERNAL_H
#include "sfs.h"
#include "sfs_disk.h"

/* The freestanding environment supplies these (libc on the host, kernel64/lib.c in the kernel). */
void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);
void *memmove(void *, const void *, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);

/* ---- little/big-endian field access at byte offsets ---- */
static inline uint16_t rd16(const void *p, size_t off) { const uint8_t *b = (const uint8_t *)p + off; return (uint16_t)(b[0] | (b[1] << 8)); }
static inline uint32_t rd32(const void *p, size_t off) { const uint8_t *b = (const uint8_t *)p + off; return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24); }
static inline uint64_t rd64(const void *p, size_t off) { return (uint64_t)rd32(p, off) | ((uint64_t)rd32(p, off + 4) << 32); }
static inline void wr16(void *p, size_t off, uint16_t v) { uint8_t *b = (uint8_t *)p + off; b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8); }
static inline void wr32(void *p, size_t off, uint32_t v) { uint8_t *b = (uint8_t *)p + off; b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8); b[2] = (uint8_t)(v >> 16); b[3] = (uint8_t)(v >> 24); }
static inline void wr64(void *p, size_t off, uint64_t v) { wr32(p, off, (uint32_t)v); wr32(p, off + 4, (uint32_t)(v >> 32)); }
static inline uint32_t rdbe32(const void *p, size_t off) { const uint8_t *b = (const uint8_t *)p + off; return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3]; }
static inline uint16_t rdbe16(const void *p, size_t off) { const uint8_t *b = (const uint8_t *)p + off; return (uint16_t)((b[0] << 8) | b[1]); }
static inline uint64_t rdbe64(const void *p, size_t off) { return ((uint64_t)rdbe32(p, off) << 32) | rdbe32(p, off + 4); }
static inline void wrbe32(void *p, size_t off, uint32_t v) { uint8_t *b = (uint8_t *)p + off; b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16); b[2] = (uint8_t)(v >> 8); b[3] = (uint8_t)v; }
static inline void wrbe16(void *p, size_t off, uint16_t v) { uint8_t *b = (uint8_t *)p + off; b[0] = (uint8_t)(v >> 8); b[1] = (uint8_t)v; }
static inline void wrbe64(void *p, size_t off, uint64_t v) { wrbe32(p, off, (uint32_t)(v >> 32)); wrbe32(p, off + 4, (uint32_t)v); }

/* ---- checksums (sfs_crc.c) ---- */
uint32_t sfs_crc32c(uint32_t crc, const void *data, size_t len);     /* Castagnoli, as ext4 uses it (no final inversion) */
uint16_t sfs_crc16(uint16_t crc, const void *data, size_t len);      /* CRC-16 (0x8005 reflected), as gdt_csum uses it */

/* ---- block cache ---- */
#define B_UPTODATE 0x1u
#define B_DIRTY 0x2u            /* data block: may be written back at any time */
#define B_JDIRTY 0x4u           /* metadata block dirtied in the running transaction: pinned until checkpointed */
#define B_NEW 0x8u              /* freshly allocated, never read from disk */
#define B_VERIFIED 0x10u        /* checksum/structure verified since it was read (cleared on every re-read) */
#define B_COMPUTED 0x20u        /* content computed in memory (uninitialised bitmap), not what the disk holds */
#define B_LATE 0x40u            /* dirty data that must not reach the disk before the running transaction commits */
typedef struct sfs_buf {
    uint64_t blk;
    uint8_t *data;
    uint32_t flags;
    uint32_t refs;
    struct sfs_buf *hnext;
    struct sfs_buf *lru_next, *lru_prev;
    struct sfs_buf *tnext;      /* running transaction list */
} sfs_buf;
#define BUF_HASH 512u

/* ---- in-memory inode ---- */
typedef struct sfs_inode {
    uint32_t ino;
    uint32_t refs;
    uint32_t dirty;
    uint16_t mode, links;
    uint32_t uid, gid;
    uint64_t size;
    uint64_t nblocks;           /* i_blocks in file system blocks (data + tree + xattr block) */
    uint32_t flags;
    uint32_t generation;
    uint64_t file_acl;
    uint32_t dtime;
    int64_t atime, mtime, ctime, crtime;
    uint32_t atime_ns, mtime_ns, ctime_ns, crtime_ns;
    uint16_t extra_isize;
    uint32_t csum_seed;
    uint8_t iblock[IN_BLOCK_BYTES];
    /* one-entry extent cache (last mapping found) */
    int ec_valid, ec_unwritten;
    uint32_t ec_lblk, ec_len;
    uint64_t ec_pblk;
    /* last allocated physical block (locality goal for the next allocation) */
    uint32_t last_lblk;
    uint64_t last_pblk;
    struct sfs_inode *hnext;
    struct sfs_inode *lru_next, *lru_prev;
} sfs_inode;
#define INO_HASH 64u

/* Group descriptor, decoded. */
typedef struct sfs_gd {
    uint64_t block_bitmap, inode_bitmap, inode_table;
    uint32_t free_blocks, free_inodes, used_dirs, itable_unused;
    uint16_t flags;
    uint32_t block_bitmap_csum, inode_bitmap_csum;
} sfs_gd;

/* Lists of (start, count) block runs, in pages of at most SFS_MAX_ALLOC bytes. */
#define RUNS_PER_PAGE 250u
typedef struct sfs_runpage {
    struct sfs_runpage *next;
    uint32_t count;
    struct { uint64_t start; uint32_t len; uint32_t meta; } run[RUNS_PER_PAGE];
} sfs_runpage;

/* Preallocation windows: in-memory reservations of physical runs for a growing file (never on disk, so a crash
 * cannot leak them). Other inodes' allocations skip reserved ranges while free space elsewhere exists. */
#define PA_MAX 48u
typedef struct sfs_pa {
    uint32_t ino;
    uint32_t lblk;              /* logical block the window starts at */
    uint64_t pblk;
    uint32_t len;
    uint32_t age;
} sfs_pa;
typedef struct sfs_patab {
    sfs_pa w[PA_MAX];
    uint32_t clock;
} sfs_patab;

typedef struct sfs_txn {
    sfs_buf *bufs;              /* B_JDIRTY buffers */
    uint32_t nbufs;
    sfs_runpage *frees;         /* blocks freed by this transaction: applied to bitmaps at commit */
    uint32_t nfrees;
    uint64_t free_blocks_pending;
    sfs_runpage *revokes;       /* metadata blocks freed: revoke records */
    uint32_t nrevokes;
    int sb_dirty;
    int force_commit;           /* commit at the end of the current operation */
    sfs_buf *late;              /* B_LATE buffers (linked through tnext) */
} sfs_txn;

/* Journal extent map (journal inode logical block -> physical). */
#define JMAP_MAX 200u
typedef struct sfs_jmap {
    uint32_t count;
    struct { uint32_t lblk, len; uint64_t pblk; } e[JMAP_MAX];
} sfs_jmap;

typedef struct sfs_journal {
    int present;                /* journal inode exists and is usable */
    uint32_t inum;
    uint32_t maxlen, first;
    uint32_t feat_incompat, feat_compat, feat_ro;
    uint8_t uuid[16];
    uint32_t csum_seed;
    int csum_v3, csum_v2, has64;
    uint32_t next_seq;          /* sequence of the next transaction to commit */
    uint32_t head;              /* next free log block */
    uint32_t disk_start;        /* s_start as last written (0 = empty on disk) */
    uint32_t tag_bytes;
    sfs_jmap *map;
    int map_complete;           /* the whole journal is described by map (else sfs_map_block per block) */
} sfs_journal;

struct sfs_fs {
    sfs_ops ops;
    unsigned mflags;
    int ro;
    uint32_t ro_reason;
    int dead;                   /* aborted after an I/O or consistency failure: read-only, transaction dropped */
    int mounted_dirty;          /* we set INCOMPAT_RECOVER / cleared VALID_FS on disk */
    uint8_t *sbraw;             /* 1024-byte in-memory superblock */
    /* geometry */
    uint32_t bs, bs_bits;
    uint64_t nblocks;
    uint32_t ngroups, bpg, ipg, isize, gd_size, first_data_block, inodes_count, first_ino;
    uint32_t desc_per_block, inodes_per_block, itable_blocks, gdt_blocks;
    uint32_t feat_compat, feat_incompat, feat_ro;
    int has64, csum, gdt_csum, sparse, meta_bg, dir_index, filetype, extents, huge_file, dir_nlink, largedir;
    uint32_t csum_seed;
    uint8_t uuid[16];
    uint32_t hash_seed[4];
    uint8_t hash_version;
    int hash_unsigned;
    uint32_t reserved_gdt, first_meta_bg, log_groups_per_flex;
    uint32_t want_extra_isize;
    uint32_t backup_bgs[2];
    int sparse2;
    uint64_t free_blocks;
    uint32_t free_inodes;
    uint64_t kbytes_written_base;
    uint32_t last_orphan;
    uint32_t ext_per_block;     /* extent entries in a tree block */
    /* block cache */
    sfs_buf **hash;
    sfs_buf *lru_head, *lru_tail;
    uint32_t nbufs, max_bufs;
    /* inode cache */
    sfs_inode *ihash[INO_HASH];
    sfs_inode *ilru_head, *ilru_tail;
    uint32_t ninodes, max_inodes;
    /* transaction + journal */
    sfs_txn txn;
    int in_op;
    uint64_t mods, op_mods;     /* modification counter: an op that failed after modifying aborts the transaction */
    sfs_journal jnl;
    uint32_t txn_soft, txn_hard;   /* commit thresholds (buffers) */
    uint8_t *scratch;           /* one block, journal descriptor/commit assembly */
    uint8_t *scratch2;          /* one block, escaped data copies / revoke blocks */
    sfs_patab *pa;
    uint32_t alloc_hint_group;
    uint32_t dir_rotor;
    uint64_t next_generation;
    sfs_stats st;
    uint64_t write_limit;
    void (*write_hit)(void *);
    int write_stopped;
};

/* ---- sfs_cache.c ---- */
int sfs_cache_init(sfs_fs *fs, uint32_t blocks);
void sfs_cache_destroy(sfs_fs *fs);
void sfs_cache_drop_clean(sfs_fs *fs);                                 /* forget every unpinned clean buffer */
int sfs_bread(sfs_fs *fs, uint64_t blk, sfs_buf **out);              /* read through the cache */
int sfs_bnew(sfs_fs *fs, uint64_t blk, sfs_buf **out);               /* zeroed, without reading */
sfs_buf *sfs_bfind(sfs_fs *fs, uint64_t blk);                          /* cached only (ref taken), or NULL */
void sfs_bput(sfs_fs *fs, sfs_buf *b);
int sfs_bdirty_meta(sfs_fs *fs, sfs_buf *b);                          /* join the running transaction */
void sfs_bdirty_data(sfs_fs *fs, sfs_buf *b);
void sfs_bdirty_late(sfs_fs *fs, sfs_buf *b);                          /* dirty data held back until the next commit */
void sfs_release_late(sfs_fs *fs);                                     /* after a commit: late buffers become ordinary */
void sfs_bforget(sfs_fs *fs, uint64_t blk);                            /* drop a freed block from the cache/transaction */
void sfs_binval_data(sfs_fs *fs, uint64_t blk, uint32_t count);        /* direct I/O overwrote these data blocks */
void sfs_boverlay(sfs_fs *fs, uint64_t blk, uint32_t count, uint8_t *dst);  /* copy newer cached content over dst */
int sfs_cache_write_data(sfs_fs *fs);                                  /* write every B_DIRTY data block */
int sfs_cache_write_meta_direct(sfs_fs *fs);                           /* no journal: write B_JDIRTY blocks in place */
void sfs_txn_sort(sfs_fs *fs);                                         /* sort the transaction list by block number */
int sfs_dev_read(sfs_fs *fs, uint64_t blk, void *buf, uint32_t count);
int sfs_dev_write(sfs_fs *fs, uint64_t blk, const void *buf, uint32_t count);
int sfs_dev_flush(sfs_fs *fs);
int sfs_dev_writev(sfs_fs *fs, uint64_t blk, const void *const *bufs, uint32_t count);
/* Write coalescing: blocks added in ascending, adjacent order go out as one vectored request. */
#define WRUN_MAX 64u
typedef struct sfs_wrun { uint64_t start; uint32_t n; const void *bufs[WRUN_MAX]; } sfs_wrun;
int sfs_wrun_add(sfs_fs *fs, sfs_wrun *r, uint64_t blk, const void *data);
int sfs_wrun_flush(sfs_fs *fs, sfs_wrun *r);
void *sfs_alloc(sfs_fs *fs, size_t bytes);
void sfs_free(sfs_fs *fs, void *p, size_t bytes);

/* ---- sfs_super.c ---- */
int sfs_gd_read(sfs_fs *fs, uint32_t group, sfs_gd *gd);
int sfs_gd_write(sfs_fs *fs, uint32_t group, const sfs_gd *gd);
int sfs_group_has_super(sfs_fs *fs, uint32_t group);
uint64_t sfs_group_first_block(sfs_fs *fs, uint32_t group);
uint32_t sfs_group_block_count(sfs_fs *fs, uint32_t group);
uint32_t sfs_group_super_blocks(sfs_fs *fs, uint32_t group);             /* superblock + GDT + reserved GDT at the group head */
int sfs_block_bitmap(sfs_fs *fs, uint32_t group, sfs_gd *gd, sfs_buf **out);
int sfs_inode_bitmap(sfs_fs *fs, uint32_t group, sfs_gd *gd, sfs_buf **out);
void sfs_block_bitmap_csum_set(sfs_fs *fs, sfs_gd *gd, const uint8_t *bitmap);
void sfs_inode_bitmap_csum_set(sfs_fs *fs, sfs_gd *gd, const uint8_t *bitmap);
int sfs_is_group_meta_block(sfs_fs *fs, uint64_t blk);                 /* superblock/GDT/bitmaps/inode tables */
int sfs_sb_write(sfs_fs *fs);                                          /* in-memory superblock -> its (journaled) block */
uint64_t sfs_now(sfs_fs *fs);
void sfs_log(sfs_fs *fs, const char *msg);
void sfs_logu(sfs_fs *fs, const char *msg, uint64_t v);
int sfs_op_begin(sfs_fs *fs);
int sfs_op_end(sfs_fs *fs, int rc);
int sfs_safe_point(sfs_fs *fs);                                         /* commit now if the transaction is large */
int sfs_commit(sfs_fs *fs);
int sfs_fail(sfs_fs *fs, int rc);                                       /* EIO/ECORRUPT inside an update: abort */
int sfs_orphan_add(sfs_fs *fs, sfs_inode *in);
int sfs_orphan_del(sfs_fs *fs, sfs_inode *in);
int sfs_orphan_cleanup(sfs_fs *fs);

/* ---- sfs_inode.c ---- */
int sfs_iget(sfs_fs *fs, uint32_t ino, sfs_inode **out);
int sfs_iget_new(sfs_fs *fs, uint32_t ino, uint16_t mode, sfs_inode **out);   /* freshly allocated inode */
void sfs_iput(sfs_fs *fs, sfs_inode *in);
void sfs_idirty(sfs_fs *fs, sfs_inode *in);
int sfs_iflush(sfs_fs *fs, sfs_inode *in);                             /* write the fields into the table block */
int sfs_iflush_all(sfs_fs *fs);
void sfs_iforget(sfs_fs *fs, uint32_t ino);
void sfs_icache_destroy(sfs_fs *fs);
int sfs_inode_loc(sfs_fs *fs, uint32_t ino, uint64_t *blk, uint32_t *off);
void sfs_inode_touch(sfs_fs *fs, sfs_inode *in, int mtime, int ctime, int atime);
int sfs_inode_csum_ok(sfs_fs *fs, uint32_t ino, const uint8_t *raw);
void sfs_inode_csum_set(sfs_fs *fs, uint32_t ino, uint8_t *raw);
uint32_t sfs_inode_seed(sfs_fs *fs, uint32_t ino, uint32_t gen);
int sfs_add_blocks(sfs_fs *fs, sfs_inode *in, int64_t delta);          /* i_blocks bookkeeping with the huge_file limits */

/* ---- sfs_extent.c ---- */
/* Maps logical block `lblk`: returns 1 with the physical block and the run length, 0 for a hole (len = hole length
 * up to the next mapping, capped), < 0 on error. `unwritten` set for unwritten extents (read as zeros). */
int sfs_map_block(sfs_fs *fs, sfs_inode *in, uint32_t lblk, uint64_t *pblk, uint32_t *len, int *unwritten);
int sfs_ext_insert(sfs_fs *fs, sfs_inode *in, uint32_t lblk, uint64_t pblk, uint32_t len);   /* map new blocks */
int sfs_ext_truncate(sfs_fs *fs, sfs_inode *in, uint32_t first_lblk, int metadata);   /* frees every mapping >= first_lblk */
int sfs_ext_mark_written(sfs_fs *fs, sfs_inode *in, uint32_t lblk);           /* whole unwritten extent -> written */
int sfs_ext_iterate(sfs_fs *fs, sfs_inode *in, int (*fn)(void *ctx, uint32_t lblk, uint64_t pblk, uint32_t len, int unwritten), void *ctx);
int sfs_ext_verify_block(sfs_fs *fs, sfs_inode *in, sfs_buf *b, int depth);
int sfs_bmap_lookup(sfs_fs *fs, sfs_inode *in, uint32_t lblk, uint64_t *pblk, uint32_t *len);
int sfs_bmap_release(sfs_fs *fs, sfs_inode *in, int metadata);
void sfs_ext_root_init(uint8_t *iblock);

/* ---- sfs_alloc.c ---- */
int sfs_alloc_blocks(sfs_fs *fs, sfs_inode *in, uint32_t lblk, uint64_t goal, uint32_t want, uint64_t *start, uint32_t *got);
int sfs_alloc_meta_block(sfs_fs *fs, sfs_inode *in, uint64_t goal, uint64_t *blk);
int sfs_free_blocks(sfs_fs *fs, uint64_t start, uint32_t count, int metadata); /* deferred to commit */
int sfs_alloc_inode(sfs_fs *fs, uint32_t parent, int is_dir, uint32_t *ino);
int sfs_free_inode(sfs_fs *fs, uint32_t ino, int is_dir);
int sfs_apply_pending_frees(sfs_fs *fs);
void sfs_pa_release(sfs_fs *fs, uint32_t ino);
int sfs_runpage_add(sfs_fs *fs, sfs_runpage **head, uint64_t start, uint32_t len, uint32_t meta);
void sfs_runpage_free(sfs_fs *fs, sfs_runpage **head);
uint64_t sfs_goal_for(sfs_fs *fs, sfs_inode *in, uint32_t lblk);

/* ---- sfs_hash.c ---- */
int sfs_dx_hash(const uint32_t seed[4], uint8_t version, const char *name, size_t len, uint32_t *hash, uint32_t *minor);

/* ---- sfs_dir.c ---- */
int sfs_dir_lookup(sfs_fs *fs, sfs_inode *dir, const char *name, size_t len, uint32_t *ino, uint8_t *type);
int sfs_dir_add(sfs_fs *fs, sfs_inode *dir, const char *name, size_t len, uint32_t ino, uint8_t type);
int sfs_dir_remove(sfs_fs *fs, sfs_inode *dir, const char *name, size_t len, uint32_t expect_ino);
int sfs_dir_set_inode(sfs_fs *fs, sfs_inode *dir, const char *name, size_t len, uint32_t ino, uint8_t type);
int sfs_dir_is_empty(sfs_fs *fs, sfs_inode *dir);
int sfs_dir_init(sfs_fs *fs, sfs_inode *dir, uint32_t parent);
int sfs_dir_set_parent(sfs_fs *fs, sfs_inode *dir, uint32_t parent);
int sfs_dir_get_parent(sfs_fs *fs, sfs_inode *dir, uint32_t *parent);
int sfs_dir_next(sfs_fs *fs, sfs_inode *dir, uint64_t *cookie, sfs_dirent *out);
uint8_t sfs_mode_to_ft(uint16_t mode);

/* ---- sfs_file.c ---- */
int sfs_file_read(sfs_fs *fs, sfs_inode *in, uint64_t off, void *buf, uint64_t len, uint64_t *done);
int sfs_file_write(sfs_fs *fs, sfs_inode *in, uint64_t off, const void *buf, uint64_t len, uint64_t *done);
int sfs_file_truncate(sfs_fs *fs, sfs_inode *in, uint64_t size);
int sfs_file_trim_orphan(sfs_fs *fs, sfs_inode *in);                 /* blocks beyond i_size of a truncate orphan */
int sfs_inode_release_all(sfs_fs *fs, sfs_inode *in);                 /* frees everything (data, tree, xattr block) */
int sfs_symlink_read(sfs_fs *fs, sfs_inode *in, char *buf, size_t cap, size_t *len);
int sfs_inline_read(sfs_fs *fs, sfs_inode *in, uint64_t off, void *buf, uint64_t len, uint64_t *done);

/* ---- sfs_jbd2.c ---- */
int sfs_journal_load(sfs_fs *fs, int replay);                          /* validates and, if asked and needed, replays */
int sfs_journal_commit(sfs_fs *fs);                                    /* ordered commit + checkpoint */
int sfs_journal_mark_clean(sfs_fs *fs);                                /* s_start = 0 on disk */
void sfs_journal_unload(sfs_fs *fs);
uint32_t sfs_journal_capacity(sfs_fs *fs);

static inline int sfs_test_bit(const uint8_t *map, uint32_t bit) { return (map[bit >> 3] >> (bit & 7)) & 1; }
static inline void sfs_set_bit(uint8_t *map, uint32_t bit) { map[bit >> 3] |= (uint8_t)(1u << (bit & 7)); }
static inline void sfs_clear_bit(uint8_t *map, uint32_t bit) { map[bit >> 3] &= (uint8_t)~(1u << (bit & 7)); }
static inline uint32_t sfs_group_of_block(sfs_fs *fs, uint64_t blk) { return (uint32_t)((blk - fs->first_data_block) / fs->bpg); }
static inline uint32_t sfs_group_of_inode(sfs_fs *fs, uint32_t ino) { return (ino - 1) / fs->ipg; }
static inline int sfs_block_valid(sfs_fs *fs, uint64_t blk) { return blk >= fs->first_data_block && blk < fs->nblocks; }
static inline int sfs_range_valid(sfs_fs *fs, uint64_t blk, uint64_t n) { return blk >= fs->first_data_block && n <= fs->nblocks && blk <= fs->nblocks - n; }
static inline int sfs_ino_valid(sfs_fs *fs, uint32_t ino) { return ino >= 1 && ino <= fs->inodes_count; }
static inline int sfs_is_dir(const sfs_inode *in) { return (in->mode & SFS_S_IFMT) == SFS_S_IFDIR; }
static inline int sfs_is_reg(const sfs_inode *in) { return (in->mode & SFS_S_IFMT) == SFS_S_IFREG; }
static inline int sfs_is_lnk(const sfs_inode *in) { return (in->mode & SFS_S_IFMT) == SFS_S_IFLNK; }
static inline uint32_t sfs_min32(uint32_t a, uint32_t b) { return a < b ? a : b; }
static inline uint64_t sfs_min64(uint64_t a, uint64_t b) { return a < b ? a : b; }
/* Blocks freed from directories/symlinks/tree nodes were journaled: they need revoke records. */
static inline int sfs_inode_meta_data(const sfs_inode *in) { return !sfs_is_reg(in); }
#endif
