/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS v1 inodes: the in-memory inode cache (hashed, LRU, write-back into the inode-table blocks at commit),
 * raw inode decoding/encoding with the extra-epoch timestamps and i_blocks limits, and the inode checksum.
 */
#include "sfs_internal.h"

static uint32_t ihash(uint32_t ino) { return (ino * 2654435761u) >> 26 & (INO_HASH - 1); }

static void ilru_unlink(sfs_fs *fs, sfs_inode *in)
{
    if (in->lru_prev) in->lru_prev->lru_next = in->lru_next; else fs->ilru_head = in->lru_next;
    if (in->lru_next) in->lru_next->lru_prev = in->lru_prev; else fs->ilru_tail = in->lru_prev;
    in->lru_prev = in->lru_next = 0;
}

static void ilru_front(sfs_fs *fs, sfs_inode *in)
{
    in->lru_prev = 0;
    in->lru_next = fs->ilru_head;
    if (fs->ilru_head) fs->ilru_head->lru_prev = in; else fs->ilru_tail = in;
    fs->ilru_head = in;
}

static void ihash_unlink(sfs_fs *fs, sfs_inode *in)
{
    sfs_inode **pp = &fs->ihash[ihash(in->ino)];
    while (*pp && *pp != in) pp = &(*pp)->hnext;
    if (*pp) *pp = in->hnext;
    in->hnext = 0;
}

static void idestroy(sfs_fs *fs, sfs_inode *in)
{
    ilru_unlink(fs, in);
    ihash_unlink(fs, in);
    sfs_free(fs, in, sizeof *in);
    fs->ninodes--;
}

int sfs_inode_loc(sfs_fs *fs, uint32_t ino, uint64_t *blk, uint32_t *off)
{
    sfs_gd gd;
    uint32_t g, idx;
    int rc;
    if (!sfs_ino_valid(fs, ino)) return SFS_ECORRUPT;
    g = (ino - 1) / fs->ipg;
    idx = (ino - 1) % fs->ipg;
    rc = sfs_gd_read(fs, g, &gd);
    if (rc) return rc;
    *blk = gd.inode_table + idx / fs->inodes_per_block;
    *off = (idx % fs->inodes_per_block) * fs->isize;
    return 0;
}

uint32_t sfs_inode_seed(sfs_fs *fs, uint32_t ino, uint32_t gen)
{
    uint8_t le[4];
    uint32_t c;
    wr32(le, 0, ino);
    c = sfs_crc32c(fs->csum_seed, le, 4);
    wr32(le, 0, gen);
    return sfs_crc32c(c, le, 4);
}

static uint32_t inode_csum(sfs_fs *fs, uint32_t ino, const uint8_t *raw, int *has_hi)
{
    static const uint8_t zero2[2] = {0, 0};
    uint32_t c = sfs_inode_seed(fs, ino, rd32(raw, IN_generation));
    c = sfs_crc32c(c, raw, IN_checksum_lo);
    c = sfs_crc32c(c, zero2, 2);
    c = sfs_crc32c(c, raw + IN_checksum_lo + 2, 128 - IN_checksum_lo - 2);
    *has_hi = 0;
    if (fs->isize > 128) {
        uint32_t extra = rd16(raw, IN_extra_isize);
        c = sfs_crc32c(c, raw + 128, IN_checksum_hi - 128);
        if (128 + extra >= IN_checksum_hi + 2) {
            c = sfs_crc32c(c, zero2, 2);
            c = sfs_crc32c(c, raw + IN_checksum_hi + 2, fs->isize - IN_checksum_hi - 2);
            *has_hi = 1;
        } else {
            c = sfs_crc32c(c, raw + IN_checksum_hi, fs->isize - IN_checksum_hi);
        }
    }
    return c;
}

int sfs_inode_csum_ok(sfs_fs *fs, uint32_t ino, const uint8_t *raw)
{
    int hi;
    uint32_t c, stored;
    uint32_t i;
    if (!fs->csum) return 1;
    c = inode_csum(fs, ino, raw, &hi);
    stored = rd16(raw, IN_checksum_lo);
    if (hi) stored |= (uint32_t)rd16(raw, IN_checksum_hi) << 16; else c &= 0xFFFF;
    if (c == stored) return 1;
    for (i = 0; i < fs->isize; ++i) if (raw[i]) return 0;   /* an all-zero inode is valid (never used) */
    return 1;
}

void sfs_inode_csum_set(sfs_fs *fs, uint32_t ino, uint8_t *raw)
{
    int hi;
    uint32_t c;
    if (!fs->csum) return;
    c = inode_csum(fs, ino, raw, &hi);
    wr16(raw, IN_checksum_lo, (uint16_t)c);
    if (hi) wr16(raw, IN_checksum_hi, (uint16_t)(c >> 16));
}

/* ---- timestamps: 32-bit seconds + (epoch:2, nsec:30) in the extra field when the inode is large enough ---- */
static int fits(const sfs_inode *in, uint32_t field_off, uint32_t size) { return field_off + size <= 128u + in->extra_isize; }

static void time_decode(const uint8_t *raw, const sfs_inode *in, uint32_t off, uint32_t xoff, int64_t *sec, uint32_t *ns)
{
    *sec = (int32_t)rd32(raw, off);
    *ns = 0;
    if (xoff && fits(in, xoff, 4)) {
        uint32_t x = rd32(raw, xoff);
        *sec += (int64_t)(x & 3u) << 32;
        *ns = x >> 2;
        if (*ns > 999999999u) *ns = 0;
    }
}

static void time_encode(uint8_t *raw, const sfs_inode *in, uint32_t off, uint32_t xoff, int64_t sec, uint32_t ns)
{
    wr32(raw, off, (uint32_t)sec);
    if (xoff && fits(in, xoff, 4)) {
        uint32_t epoch = (uint32_t)(((sec - (int64_t)(int32_t)sec) >> 32) & 3);
        wr32(raw, xoff, epoch | (ns << 2));
    }
}

static int decode(sfs_fs *fs, sfs_inode *in, const uint8_t *raw)
{
    uint64_t blocks;
    in->mode = rd16(raw, IN_mode);
    in->uid = rd16(raw, IN_uid) | ((uint32_t)rd16(raw, IN_uid_high) << 16);
    in->gid = rd16(raw, IN_gid) | ((uint32_t)rd16(raw, IN_gid_high) << 16);
    in->size = rd32(raw, IN_size_lo);
    if ((in->mode & SFS_S_IFMT) == SFS_S_IFREG || fs->largedir) in->size |= (uint64_t)rd32(raw, IN_size_high) << 32;
    in->links = rd16(raw, IN_links_count);
    in->flags = rd32(raw, IN_flags);
    in->generation = rd32(raw, IN_generation);
    in->file_acl = rd32(raw, IN_file_acl_lo) | ((uint64_t)rd16(raw, IN_file_acl_high) << 32);
    in->dtime = rd32(raw, IN_dtime);
    in->extra_isize = 0;
    if (fs->isize > 128) {
        in->extra_isize = rd16(raw, IN_extra_isize);
        if (in->extra_isize & 3 || 128u + in->extra_isize > fs->isize) return SFS_ECORRUPT;
    }
    time_decode(raw, in, IN_atime, IN_atime_extra, &in->atime, &in->atime_ns);
    time_decode(raw, in, IN_mtime, IN_mtime_extra, &in->mtime, &in->mtime_ns);
    time_decode(raw, in, IN_ctime, IN_ctime_extra, &in->ctime, &in->ctime_ns);
    if (fits(in, IN_crtime, 4)) time_decode(raw, in, IN_crtime, IN_crtime_extra, &in->crtime, &in->crtime_ns);
    else in->crtime = 0, in->crtime_ns = 0;
    blocks = rd32(raw, IN_blocks_lo);
    if (fs->huge_file) {
        blocks |= (uint64_t)rd16(raw, IN_blocks_high) << 32;
        if (in->flags & IFL_HUGE_FILE) in->nblocks = blocks;
        else in->nblocks = blocks >> (fs->bs_bits - 9);
    } else {
        in->nblocks = blocks >> (fs->bs_bits - 9);
    }
    memcpy(in->iblock, raw + IN_block, IN_BLOCK_BYTES);
    in->csum_seed = fs->csum ? sfs_inode_seed(fs, in->ino, in->generation) : 0;
    return 0;
}

static int encode(sfs_fs *fs, sfs_inode *in, uint8_t *raw)
{
    uint64_t sectors = in->nblocks << (fs->bs_bits - 9);
    wr16(raw, IN_mode, in->mode);
    wr16(raw, IN_uid, (uint16_t)in->uid);
    wr16(raw, IN_uid_high, (uint16_t)(in->uid >> 16));
    wr16(raw, IN_gid, (uint16_t)in->gid);
    wr16(raw, IN_gid_high, (uint16_t)(in->gid >> 16));
    wr32(raw, IN_size_lo, (uint32_t)in->size);
    wr32(raw, IN_size_high, (uint32_t)(in->size >> 32));
    wr16(raw, IN_links_count, in->links);
    wr32(raw, IN_dtime, in->dtime);
    if (sectors <= 0xFFFFFFFFull) {
        wr32(raw, IN_blocks_lo, (uint32_t)sectors);
        wr16(raw, IN_blocks_high, 0);
        in->flags &= ~IFL_HUGE_FILE;
    } else if (!fs->huge_file) {
        return SFS_EFBIG;
    } else if (sectors <= 0xFFFFFFFFFFFFull) {
        wr32(raw, IN_blocks_lo, (uint32_t)sectors);
        wr16(raw, IN_blocks_high, (uint16_t)(sectors >> 32));
        in->flags &= ~IFL_HUGE_FILE;
    } else {
        in->flags |= IFL_HUGE_FILE;
        wr32(raw, IN_blocks_lo, (uint32_t)in->nblocks);
        wr16(raw, IN_blocks_high, (uint16_t)(in->nblocks >> 32));
    }
    wr32(raw, IN_flags, in->flags);
    wr32(raw, IN_generation, in->generation);
    wr32(raw, IN_file_acl_lo, (uint32_t)in->file_acl);
    wr16(raw, IN_file_acl_high, (uint16_t)(in->file_acl >> 32));
    memcpy(raw + IN_block, in->iblock, IN_BLOCK_BYTES);
    if (fs->isize > 128) wr16(raw, IN_extra_isize, in->extra_isize);
    time_encode(raw, in, IN_atime, IN_atime_extra, in->atime, in->atime_ns);
    time_encode(raw, in, IN_mtime, IN_mtime_extra, in->mtime, in->mtime_ns);
    time_encode(raw, in, IN_ctime, IN_ctime_extra, in->ctime, in->ctime_ns);
    if (fits(in, IN_crtime, 4)) time_encode(raw, in, IN_crtime, IN_crtime_extra, in->crtime, in->crtime_ns);
    sfs_inode_csum_set(fs, in->ino, raw);
    return 0;
}

int sfs_add_blocks(sfs_fs *fs, sfs_inode *in, int64_t delta)
{
    if (delta < 0 && (uint64_t)(-delta) > in->nblocks) in->nblocks = 0;
    else in->nblocks += (uint64_t)delta;
    if (!fs->huge_file && (in->nblocks << (fs->bs_bits - 9)) > 0xFFFFFFFFull) return SFS_EFBIG;
    sfs_idirty(fs, in);
    return 0;
}

static int evict_some(sfs_fs *fs)
{
    sfs_inode *in, *prev;
    for (in = fs->ilru_tail; in && fs->ninodes >= fs->max_inodes; in = prev) {
        prev = in->lru_prev;
        if (in->refs) continue;
        if (in->dirty) {
            int rc = sfs_iflush(fs, in);
            if (rc) return rc;
        }
        idestroy(fs, in);
    }
    return 0;
}

static sfs_inode *ilookup(sfs_fs *fs, uint32_t ino)
{
    sfs_inode *in;
    for (in = fs->ihash[ihash(ino)]; in; in = in->hnext)
        if (in->ino == ino) return in;
    return 0;
}

static int iinsert_new(sfs_fs *fs, uint32_t ino, sfs_inode **out)
{
    sfs_inode *in;
    int rc;
    if (fs->ninodes >= fs->max_inodes) {
        rc = evict_some(fs);
        if (rc) return rc;
    }
    in = sfs_alloc(fs, sizeof *in);
    if (!in) return SFS_ENOMEM;
    memset(in, 0, sizeof *in);
    in->ino = ino;
    in->refs = 1;
    in->hnext = fs->ihash[ihash(ino)];
    fs->ihash[ihash(ino)] = in;
    ilru_front(fs, in);
    fs->ninodes++;
    *out = in;
    return 0;
}

int sfs_iget(sfs_fs *fs, uint32_t ino, sfs_inode **out)
{
    sfs_inode *in;
    sfs_buf *b;
    uint64_t blk;
    uint32_t off;
    int rc;
    if (!sfs_ino_valid(fs, ino)) return SFS_ECORRUPT;
    in = ilookup(fs, ino);
    if (in) {
        in->refs++;
        if (in != fs->ilru_head) { ilru_unlink(fs, in); ilru_front(fs, in); }
        *out = in;
        return 0;
    }
    rc = sfs_inode_loc(fs, ino, &blk, &off);
    if (rc) return rc;
    rc = sfs_bread(fs, blk, &b);
    if (rc) return rc;
    if (!sfs_inode_csum_ok(fs, ino, b->data + off)) {
        sfs_logu(fs, "sfs: inode checksum mismatch, inode ", ino);
        sfs_bput(fs, b);
        return SFS_ECORRUPT;
    }
    rc = iinsert_new(fs, ino, &in);
    if (rc) { sfs_bput(fs, b); return rc; }
    rc = decode(fs, in, b->data + off);
    sfs_bput(fs, b);
    if (!rc && in->mode == 0) rc = SFS_ENOENT;
    if (rc) { idestroy(fs, in); return rc; }
    *out = in;
    return 0;
}

void sfs_ext_root_init(uint8_t *iblock)
{
    memset(iblock, 0, IN_BLOCK_BYTES);
    wr16(iblock, EH_magic, EXT_MAGIC);
    wr16(iblock, EH_entries, 0);
    wr16(iblock, EH_max, (IN_BLOCK_BYTES - EH_SIZE) / EE_SIZE);
    wr16(iblock, EH_depth, 0);
}

int sfs_iget_new(sfs_fs *fs, uint32_t ino, uint16_t mode, sfs_inode **out)
{
    sfs_inode *in;
    sfs_buf *b;
    uint64_t blk, now = sfs_now(fs);
    uint32_t off;
    int rc;
    sfs_iforget(fs, ino);
    if (ilookup(fs, ino)) return SFS_ECORRUPT;          /* a free inode must not be in use in memory */
    rc = sfs_inode_loc(fs, ino, &blk, &off);
    if (rc) return rc;
    rc = sfs_bread(fs, blk, &b);
    if (rc) return rc;
    memset(b->data + off, 0, fs->isize);                    /* no stale in-inode xattrs from a previous owner */
    rc = sfs_bdirty_meta(fs, b);
    sfs_bput(fs, b);
    if (rc) return rc;
    rc = iinsert_new(fs, ino, &in);
    if (rc) return rc;
    in->mode = mode;
    in->links = 1;
    in->generation = (uint32_t)(fs->next_generation++ * 0x9E3779B1u);
    in->extra_isize = (uint16_t)fs->want_extra_isize;
    in->atime = in->mtime = in->ctime = in->crtime = (int64_t)now;
    in->csum_seed = fs->csum ? sfs_inode_seed(fs, ino, in->generation) : 0;
    if (fs->extents) {
        in->flags = IFL_EXTENTS;
        sfs_ext_root_init(in->iblock);
    }
    in->dirty = 1;
    fs->mods++;
    *out = in;
    return 0;
}

void sfs_iput(sfs_fs *fs, sfs_inode *in)
{
    (void)fs;
    if (in && in->refs) in->refs--;
}

void sfs_idirty(sfs_fs *fs, sfs_inode *in)
{
    in->dirty = 1;
    fs->mods++;
}

int sfs_iflush(sfs_fs *fs, sfs_inode *in)
{
    sfs_buf *b;
    uint64_t blk;
    uint32_t off;
    int rc;
    if (!in->dirty) return 0;
    rc = sfs_inode_loc(fs, in->ino, &blk, &off);
    if (rc) return rc;
    rc = sfs_bread(fs, blk, &b);
    if (rc) return rc;
    rc = encode(fs, in, b->data + off);
    if (!rc) rc = sfs_bdirty_meta(fs, b);
    sfs_bput(fs, b);
    if (!rc) in->dirty = 0;
    return rc;
}

int sfs_iflush_all(sfs_fs *fs)
{
    sfs_inode *in, *prev;
    for (in = fs->ilru_tail; in; in = prev) {
        int rc;
        prev = in->lru_prev;
        rc = sfs_iflush(fs, in);
        if (rc) return rc;
        if (!in->refs && fs->ninodes > fs->max_inodes) idestroy(fs, in);
    }
    return 0;
}

void sfs_iforget(sfs_fs *fs, uint32_t ino)
{
    sfs_inode *in = ilookup(fs, ino);
    if (!in || in->refs) return;
    if (in->dirty && sfs_iflush(fs, in)) {
        sfs_logu(fs, "sfs: could not write back inode before dropping it: ", ino);
        return;                                          /* keep it: the next commit retries */
    }
    idestroy(fs, in);
}

void sfs_icache_destroy(sfs_fs *fs)
{
    while (fs->ilru_head) idestroy(fs, fs->ilru_head);
}

void sfs_inode_touch(sfs_fs *fs, sfs_inode *in, int m, int c, int a)
{
    uint64_t now = sfs_now(fs);
    if (!now) return;
    if (m) { in->mtime = (int64_t)now; in->mtime_ns = 0; }
    if (c) { in->ctime = (int64_t)now; in->ctime_ns = 0; }
    if (a) { in->atime = (int64_t)now; in->atime_ns = 0; }
    sfs_idirty(fs, in);
}
