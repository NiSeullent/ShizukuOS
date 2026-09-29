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
    int64_t atime, mtime, ctime, crtime;
    uint32_t atime_ns, mtime_ns, ctime_ns, crtime_ns;
    uint16_t extra_isize;
    uint32_t csum_seed;
    uint8_t iblock[IN_BLOCK_BYTES];
    /* one-entry extent cache */
    int ec_valid, ec_unwritten;
    uint32_t ec_lblk, ec_len;
    uint64_t ec_pblk;
    /* preallocation window (in memory only): physical run reserved for this file's next logical blocks */
    uint64_t pa_pblk;
    uint32_t pa_lblk, pa_len;
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

/* Lists of (start, count) block runs and of single block numbers, in pages of at most SFS_MAX_ALLOC bytes. */
typedef struct sfs_runpage {
    struct sfs_runpage *next;
    uint32_t count;
    struct { uint64_t start; uint32_t len; uint32_t meta; } run[250];
} sfs_runpage;

typedef struct sfs_txn {
    sfs_buf *bufs;              /* B_JDIRTY buffers */
    uint32_t nbufs;
    sfs_runpage *frees;         /* blocks freed by this transaction: applied to bitmaps at commit */
    sfs_runpage *revokes;       /* metadata blocks freed: revoke records */
    uint32_t nrevokes;
    uint32_t nfrees;
    int inode_frees;            /* number of pending inode frees, see fs->ifree */
} sfs_txn;

typedef struct sfs_journal {
    int present;                /* journal inode exists and is usable */
    int active;                 /* transactions are being written to it */
    uint32_t inum;
    uint32_t maxlen, first;
    uint32_t feat_incompat, feat_compat;
    uint8_t uuid[16];
    uint32_t csum_seed;
    int csum_v3, csum_v2, has64;
    uint32_t next_seq;          /* sequence of the next transaction to commit */
    uint32_t head;              /* next free log block */
    uint32_t tail;              /* first log block of the oldest transaction not yet marked clean on disk */
    uint32_t tail_seq;
    int sb_dirty;               /* the journal superblock must be written before reuse/unmount */
    uint32_t tag_bytes;
    uint32_t disk_start, disk_seq;   /* what the on-disk journal superblock currently says */
} sfs_journal;

struct sfs_fs {
    sfs_ops ops;
    unsigned mflags;
    int ro;
    uint32_t ro_reason;
    int mounted_dirty;          /* we set INCOMPAT_RECOVER / cleared VALID_FS on disk */
    /* geometry */
    uint32_t bs, bs_bits;
    uint64_t nblocks;
    uint32_t ngroups, bpg, ipg, isize, gd_size, first_data_block, inodes_count, first_ino;
    uint32_t desc_per_block, inodes_per_block, itable_blocks;
    uint32_t feat_compat, feat_incompat, feat_ro;
    int has64, csum, gdt_csum, sparse, meta_bg, dir_index, filetype;
    uint32_t csum_seed;
    uint8_t uuid[16];
    uint32_t hash_seed[4];
    uint8_t hash_version;
    int hash_unsigned;
    uint32_t reserved_gdt, first_meta_bg, groups_per_flex;
    uint32_t want_extra_isize;
    uint32_t backup_bgs[2];
    int sparse2;
    uint64_t free_blocks;
    uint32_t free_inodes;
    uint64_t sb_kbytes_written;
    uint32_t last_orphan;
    uint32_t max_dir_blocks;    /* 3 levels with largedir */
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
    sfs_journal jnl;
    uint8_t *scratch;           /* one block, journal descriptor/commit assembly */
    uint8_t *scratch2;          /* one block, escaped data copies */
    uint32_t alloc_hint_group;
    uint64_t next_generation;
    uint64_t now_cached;
    int replaying;
    sfs_stats st;
    uint64_t write_limit;
    void (*write_hit)(void *);
    int write_stopped;
    uint32_t ifree_ring[32];    /* inodes freed in the running transaction (not reusable until commit) */
    uint32_t ifree_count;
};

/* ---- sfs_cache.c ---- */
int sfs_cache_init(sfs_fs *fs, uint32_t blocks);
void sfs_cache_destroy(sfs_fs *fs);
int sfs_bread(sfs_fs *fs, uint64_t blk, sfs_buf **out);              /* read through the cache */
int sfs_bnew(sfs_fs *fs, uint64_t blk, sfs_buf **out);               /* zeroed, without reading */
sfs_buf *sfs_bfind(sfs_fs *fs, uint64_t blk);                          /* cached only (ref taken), or NULL */
void sfs_bput(sfs_fs *fs, sfs_buf *b);
int sfs_bdirty_meta(sfs_fs *fs, sfs_buf *b);                          /* join the running transaction */
void sfs_bdirty_data(sfs_fs *fs, sfs_buf *b);
void sfs_bforget(sfs_fs *fs, uint64_t blk);                            /* drop a freed block from the cache/transaction */
int sfs_cache_write_data(sfs_fs *fs);                                  /* write every B_DIRTY data block */
int sfs_cache_write_meta_direct(sfs_fs *fs);                           /* no journal: write B_JDIRTY blocks in place */
int sfs_dev_read(sfs_fs *fs, uint64_t blk, void *buf, uint32_t count);
int sfs_dev_write(sfs_fs *fs, uint64_t blk, const void *buf, uint32_t count);
int sfs_dev_flush(sfs_fs *fs);
void *sfs_alloc(sfs_fs *fs, size_t bytes);
void sfs_free(sfs_fs *fs, void *p, size_t bytes);

/* ---- sfs_super.c ---- */
int sfs_gd_read(sfs_fs *fs, uint32_t group, sfs_gd *gd);
int sfs_gd_write(sfs_fs *fs, uint32_t group, const sfs_gd *gd);
int sfs_group_has_super(sfs_fs *fs, uint32_t group);
uint64_t sfs_group_first_block(sfs_fs *fs, uint32_t group);
uint32_t sfs_group_block_count(sfs_fs *fs, uint32_t group);
int sfs_block_bitmap(sfs_fs *fs, uint32_t group, sfs_gd *gd, int for_write, sfs_buf **out);
int sfs_inode_bitmap(sfs_fs *fs, uint32_t group, sfs_gd *gd, int for_write, sfs_buf **out);
void sfs_bitmap_csum_update(sfs_fs *fs, uint32_t group, sfs_gd *gd, const sfs_buf *bb, const sfs_buf *ib);
int sfs_sb_write(sfs_fs *fs);
int sfs_sb_set_dirty_state(sfs_fs *fs, int dirty);                    /* RECOVER flag + VALID_FS state */
uint64_t sfs_now(sfs_fs *fs);
void sfs_log(sfs_fs *fs, const char *msg);
void sfs_logu(sfs_fs *fs, const char *msg, uint64_t v);
int sfs_op_begin(sfs_fs *fs);
int sfs_op_end(sfs_fs *fs, int rc);
int sfs_orphan_cleanup(sfs_fs *fs);

/* ---- sfs_inode.c ---- */
int sfs_iget(sfs_fs *fs, uint32_t ino, sfs_inode **out);
void sfs_iput(sfs_fs *fs, sfs_inode *in);
int sfs_iflush(sfs_fs *fs, sfs_inode *in);                             /* write the fields into the table block */
int sfs_iflush_all(sfs_fs *fs);
void sfs_iforget(sfs_fs *fs, uint32_t ino);
int sfs_inode_loc(sfs_fs *fs, uint32_t ino, uint64_t *blk, uint32_t *off);
int sfs_inode_raw_init(sfs_fs *fs, sfs_inode *in, uint32_t ino, uint16_t mode);   /* fresh inode with an empty extent root */
void sfs_inode_touch(sfs_fs *fs, sfs_inode *in, int mtime, int ctime, int atime);
int sfs_inode_verify_csum(sfs_fs *fs, uint32_t ino, const uint8_t *raw);
/* Maps logical block `lblk`: returns 1 with the physical block and the run length, 0 for a hole (len = hole length
 * up to the next mapping when known), < 0 on error. `unwritten` set for unwritten extents (read as zeros). */
int sfs_map_block(sfs_fs *fs, sfs_inode *in, uint32_t lblk, uint64_t *pblk, uint32_t *len, int *unwritten);
int sfs_ext_insert(sfs_fs *fs, sfs_inode *in, uint32_t lblk, uint64_t pblk, uint32_t len);   /* map new blocks */
int sfs_ext_truncate(sfs_fs *fs, sfs_inode *in, uint32_t first_lblk);         /* frees every mapping >= first_lblk */
int sfs_ext_convert_unwritten(sfs_fs *fs, sfs_inode *in, uint32_t lblk);      /* marks the extent holding lblk written */
int sfs_ext_iterate(sfs_fs *fs, sfs_inode *in, int (*fn)(void *ctx, uint32_t lblk, uint64_t pblk, uint32_t len, int unwritten), void *ctx);
int sfs_blockmap_lookup(sfs_fs *fs, sfs_inode *in, uint32_t lblk, uint64_t *pblk, uint32_t *len);

/* ---- sfs_alloc.c ---- */
int sfs_alloc_blocks(sfs_fs *fs, sfs_inode *in, uint32_t lblk, uint64_t goal, uint32_t want, uint32_t min, uint64_t *start, uint32_t *got);
int sfs_alloc_meta_block(sfs_fs *fs, uint64_t goal, uint64_t *blk);           /* one block near goal, zeroed buffer not implied */
int sfs_free_blocks(sfs_fs *fs, uint64_t start, uint32_t count, int metadata); /* deferred to commit */
int sfs_alloc_inode(sfs_fs *fs, uint32_t parent, int is_dir, uint32_t *ino);
int sfs_free_inode(sfs_fs *fs, uint32_t ino, int is_dir);
int sfs_apply_pending_frees(sfs_fs *fs);
void sfs_pa_release(sfs_fs *fs, sfs_inode *in);
int sfs_block_is_pending_free(sfs_fs *fs, uint64_t blk);
int sfs_runpage_add(sfs_fs *fs, sfs_runpage **head, uint64_t start, uint32_t len, uint32_t meta);
void sfs_runpage_free(sfs_fs *fs, sfs_runpage **head);
uint64_t sfs_alloc_goal_for(sfs_fs *fs, sfs_inode *in);

/* ---- sfs_hash.c ---- */
int sfs_dx_hash(sfs_fs *fs, uint8_t version, const char *name, size_t len, uint32_t *hash, uint32_t *minor);

/* ---- sfs_dir.c ---- */
int sfs_dir_lookup(sfs_fs *fs, sfs_inode *dir, const char *name, size_t len, uint32_t *ino, uint8_t *type,
                   uint32_t *blk_out, uint32_t *off_out);
int sfs_dir_add(sfs_fs *fs, sfs_inode *dir, const char *name, size_t len, uint32_t ino, uint8_t type);
int sfs_dir_remove(sfs_fs *fs, sfs_inode *dir, const char *name, size_t len);
int sfs_dir_set_inode(sfs_fs *fs, sfs_inode *dir, const char *name, size_t len, uint32_t ino, uint8_t type);
int sfs_dir_is_empty(sfs_fs *fs, sfs_inode *dir);
int sfs_dir_make_empty(sfs_fs *fs, sfs_inode *dir, uint32_t parent);
int sfs_dir_set_parent(sfs_fs *fs, sfs_inode *dir, uint32_t parent);
int sfs_dir_free_blocks(sfs_fs *fs, sfs_inode *dir);
uint32_t sfs_dirblock_csum(sfs_fs *fs, sfs_inode *dir, const uint8_t *blk, uint32_t size);
int sfs_dirblock_verify(sfs_fs *fs, sfs_inode *dir, const uint8_t *blk);
void sfs_dirblock_csum_set(sfs_fs *fs, sfs_inode *dir, uint8_t *blk);
int sfs_dir_read_block(sfs_fs *fs, sfs_inode *dir, uint32_t lblk, sfs_buf **out, uint64_t *pblk);
int sfs_symlink_read(sfs_fs *fs, sfs_inode *in, char *buf, size_t cap, size_t *len);

/* ---- sfs_file.c ---- */
int sfs_file_read(sfs_fs *fs, sfs_inode *in, uint64_t off, void *buf, uint64_t len, uint64_t *done);
int sfs_file_write(sfs_fs *fs, sfs_inode *in, uint64_t off, const void *buf, uint64_t len, uint64_t *done);
int sfs_file_truncate(sfs_fs *fs, sfs_inode *in, uint64_t size);
int sfs_inode_release_blocks(sfs_fs *fs, sfs_inode *in);              /* frees everything (data, tree, xattr block) */

/* ---- sfs_jbd2.c ---- */
int sfs_journal_load(sfs_fs *fs);                                      /* validates and, if needed, replays */
int sfs_journal_start_writing(sfs_fs *fs);                             /* set journal features, prepare head/tail */
int sfs_journal_commit(sfs_fs *fs);                                    /* ordered commit + checkpoint */
int sfs_journal_mark_clean(sfs_fs *fs);                                /* s_start = 0 on disk */
int sfs_journal_map(sfs_fs *fs, uint32_t jblk, uint64_t *pblk);
uint32_t sfs_journal_txn_limit(sfs_fs *fs);

static inline int sfs_test_bit(const uint8_t *map, uint32_t bit) { return (map[bit >> 3] >> (bit & 7)) & 1; }
static inline void sfs_set_bit(uint8_t *map, uint32_t bit) { map[bit >> 3] |= (uint8_t)(1u << (bit & 7)); }
static inline void sfs_clear_bit(uint8_t *map, uint32_t bit) { map[bit >> 3] &= (uint8_t)~(1u << (bit & 7)); }
static inline uint32_t sfs_group_of_block(sfs_fs *fs, uint64_t blk) { return (uint32_t)((blk - fs->first_data_block) / fs->bpg); }
static inline uint32_t sfs_group_of_inode(sfs_fs *fs, uint32_t ino) { return (ino - 1) / fs->ipg; }
static inline int sfs_block_valid(sfs_fs *fs, uint64_t blk) { return blk >= fs->first_data_block && blk < fs->nblocks; }
static inline int sfs_ino_valid(sfs_fs *fs, uint32_t ino) { return ino >= 1 && ino <= fs->inodes_count; }
#endif
