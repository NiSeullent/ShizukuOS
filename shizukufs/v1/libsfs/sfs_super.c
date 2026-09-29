/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS v1: superblock, group descriptors, bitmaps, mount/unmount, transactions and the orphan list.
 */
#include "sfs_internal.h"

uint64_t sfs_now(sfs_fs *fs) { return fs->ops.now ? fs->ops.now(fs->ops.ctx) : 0; }

void sfs_log(sfs_fs *fs, const char *msg) { if (fs->ops.log) fs->ops.log(fs->ops.ctx, msg); }

void sfs_logu(sfs_fs *fs, const char *msg, uint64_t v)
{
    char buf[160], num[24];
    size_t n = 0, k = 0;
    if (!fs->ops.log) return;
    while (msg[n] && n < sizeof buf - 24) { buf[n] = msg[n]; n++; }
    do { num[k++] = (char)('0' + v % 10); v /= 10; } while (v && k < sizeof num);
    while (k) buf[n++] = num[--k];
    buf[n] = 0;
    fs->ops.log(fs->ops.ctx, buf);
}

/* ---- group geometry ---- */
static int is_power_of(uint32_t n, uint32_t b)
{
    while (n > 1 && n % b == 0) n /= b;
    return n == 1;
}

int sfs_group_has_super(sfs_fs *fs, uint32_t g)
{
    if (g == 0) return 1;
    if (fs->sparse2) return g == fs->backup_bgs[0] || g == fs->backup_bgs[1];
    if (g <= 1 || !fs->sparse) return 1;
    if (!(g & 1)) return 0;
    return is_power_of(g, 3) || is_power_of(g, 5) || is_power_of(g, 7);
}

uint64_t sfs_group_first_block(sfs_fs *fs, uint32_t g) { return fs->first_data_block + (uint64_t)g * fs->bpg; }

uint32_t sfs_group_block_count(sfs_fs *fs, uint32_t g)
{
    if (g + 1 < fs->ngroups) return fs->bpg;
    return (uint32_t)(fs->nblocks - sfs_group_first_block(fs, g));
}

/* Blocks at the start of group g taken by the superblock copy, the GDT (or its meta_bg block) and the reserved GDT. */
uint32_t sfs_group_super_blocks(sfs_fs *fs, uint32_t g)
{
    uint32_t n = 0;
    int hs = sfs_group_has_super(fs, g);
    if (hs) n = 1;
    if (!fs->meta_bg || g / fs->desc_per_block < fs->first_meta_bg) {
        if (hs) n += (fs->meta_bg ? fs->first_meta_bg : fs->gdt_blocks) + fs->reserved_gdt;
    } else {
        uint32_t r = g % fs->desc_per_block;
        if (r == 0 || r == 1 || r == fs->desc_per_block - 1) n += 1;
    }
    return n;
}

/* Primary location of GDT block i. */
static uint64_t gdt_block(sfs_fs *fs, uint32_t i)
{
    uint32_t g;
    if (!fs->meta_bg || i < fs->first_meta_bg) return fs->first_data_block + 1 + (uint64_t)i;
    g = i * fs->desc_per_block;
    return sfs_group_first_block(fs, g) + (uint64_t)sfs_group_has_super(fs, g);
}

/* ---- group descriptors ---- */
static uint16_t gd_csum(sfs_fs *fs, uint32_t group, const uint8_t *d)
{
    uint8_t le[4];
    wr32(le, 0, group);
    if (fs->csum) {
        static const uint8_t zero2[2] = {0, 0};
        uint32_t c = sfs_crc32c(fs->csum_seed, le, 4);
        c = sfs_crc32c(c, d, GD_checksum);
        c = sfs_crc32c(c, zero2, 2);
        if (fs->gd_size > GD_checksum + 2) c = sfs_crc32c(c, d + GD_checksum + 2, fs->gd_size - GD_checksum - 2);
        return (uint16_t)(c & 0xFFFF);
    }
    if (fs->gdt_csum) {
        uint16_t c = sfs_crc16(0xFFFF, fs->uuid, 16);
        c = sfs_crc16(c, le, 4);
        c = sfs_crc16(c, d, GD_checksum);
        if (fs->has64 && fs->gd_size > GD_checksum + 2) c = sfs_crc16(c, d + GD_checksum + 2, fs->gd_size - GD_checksum - 2);
        return c;
    }
    return 0;
}

static int gd_locate(sfs_fs *fs, uint32_t group, sfs_buf **b, uint32_t *off)
{
    int rc;
    if (group >= fs->ngroups) return SFS_EINVAL;
    rc = sfs_bread(fs, gdt_block(fs, group / fs->desc_per_block), b);
    if (rc) return rc;
    *off = (group % fs->desc_per_block) * fs->gd_size;
    return 0;
}

static void gd_decode(sfs_fs *fs, const uint8_t *d, sfs_gd *gd)
{
    int hi = fs->gd_size >= GD_MIN_SIZE_64BIT;
    gd->block_bitmap = rd32(d, GD_block_bitmap_lo) | (hi ? (uint64_t)rd32(d, GD_block_bitmap_hi) << 32 : 0);
    gd->inode_bitmap = rd32(d, GD_inode_bitmap_lo) | (hi ? (uint64_t)rd32(d, GD_inode_bitmap_hi) << 32 : 0);
    gd->inode_table = rd32(d, GD_inode_table_lo) | (hi ? (uint64_t)rd32(d, GD_inode_table_hi) << 32 : 0);
    gd->free_blocks = rd16(d, GD_free_blocks_count_lo) | (hi ? (uint32_t)rd16(d, GD_free_blocks_count_hi) << 16 : 0);
    gd->free_inodes = rd16(d, GD_free_inodes_count_lo) | (hi ? (uint32_t)rd16(d, GD_free_inodes_count_hi) << 16 : 0);
    gd->used_dirs = rd16(d, GD_used_dirs_count_lo) | (hi ? (uint32_t)rd16(d, GD_used_dirs_count_hi) << 16 : 0);
    gd->itable_unused = rd16(d, GD_itable_unused_lo) | (hi ? (uint32_t)rd16(d, GD_itable_unused_hi) << 16 : 0);
    gd->flags = rd16(d, GD_flags);
    gd->block_bitmap_csum = rd16(d, GD_block_bitmap_csum_lo) | (hi ? (uint32_t)rd16(d, GD_block_bitmap_csum_hi) << 16 : 0);
    gd->inode_bitmap_csum = rd16(d, GD_inode_bitmap_csum_lo) | (hi ? (uint32_t)rd16(d, GD_inode_bitmap_csum_hi) << 16 : 0);
}

static int gd_sane(sfs_fs *fs, const sfs_gd *gd)
{
    if (!sfs_block_valid(fs, gd->block_bitmap) || !sfs_block_valid(fs, gd->inode_bitmap)) return 0;
    if (!sfs_range_valid(fs, gd->inode_table, fs->itable_blocks)) return 0;
    if (gd->free_blocks > fs->bpg || gd->free_inodes > fs->ipg || gd->used_dirs > fs->ipg || gd->itable_unused > fs->ipg) return 0;
    return 1;
}

int sfs_gd_read(sfs_fs *fs, uint32_t group, sfs_gd *gd)
{
    sfs_buf *b;
    uint32_t off;
    int rc = gd_locate(fs, group, &b, &off);
    if (rc) return rc;
    gd_decode(fs, b->data + off, gd);
    sfs_bput(fs, b);
    return gd_sane(fs, gd) ? 0 : SFS_ECORRUPT;
}

int sfs_gd_write(sfs_fs *fs, uint32_t group, const sfs_gd *gd)
{
    sfs_buf *b;
    uint32_t off;
    uint8_t *d;
    int hi = fs->gd_size >= GD_MIN_SIZE_64BIT;
    int rc = gd_locate(fs, group, &b, &off);
    if (rc) return rc;
    d = b->data + off;
    wr16(d, GD_free_blocks_count_lo, (uint16_t)gd->free_blocks);
    wr16(d, GD_free_inodes_count_lo, (uint16_t)gd->free_inodes);
    wr16(d, GD_used_dirs_count_lo, (uint16_t)gd->used_dirs);
    wr16(d, GD_itable_unused_lo, (uint16_t)gd->itable_unused);
    wr16(d, GD_flags, gd->flags);
    wr16(d, GD_block_bitmap_csum_lo, (uint16_t)gd->block_bitmap_csum);
    wr16(d, GD_inode_bitmap_csum_lo, (uint16_t)gd->inode_bitmap_csum);
    if (hi) {
        wr16(d, GD_free_blocks_count_hi, (uint16_t)(gd->free_blocks >> 16));
        wr16(d, GD_free_inodes_count_hi, (uint16_t)(gd->free_inodes >> 16));
        wr16(d, GD_used_dirs_count_hi, (uint16_t)(gd->used_dirs >> 16));
        wr16(d, GD_itable_unused_hi, (uint16_t)(gd->itable_unused >> 16));
        if (fs->gd_size >= GD_block_bitmap_csum_hi + 2) wr16(d, GD_block_bitmap_csum_hi, (uint16_t)(gd->block_bitmap_csum >> 16));
        if (fs->gd_size >= GD_inode_bitmap_csum_hi + 2) wr16(d, GD_inode_bitmap_csum_hi, (uint16_t)(gd->inode_bitmap_csum >> 16));
    }
    if (fs->csum || fs->gdt_csum) wr16(d, GD_checksum, gd_csum(fs, group, d));
    rc = sfs_bdirty_meta(fs, b);
    sfs_bput(fs, b);
    return rc;
}

/* Verifies every descriptor (checksum + bounds). */
static int gd_check_all(sfs_fs *fs, int *csum_bad)
{
    uint32_t g;
    *csum_bad = 0;
    for (g = 0; g < fs->ngroups; ++g) {
        sfs_buf *b;
        uint32_t off;
        sfs_gd gd;
        int rc = gd_locate(fs, g, &b, &off);
        if (rc) return rc;
        gd_decode(fs, b->data + off, &gd);
        if ((fs->csum || fs->gdt_csum) && rd16(b->data + off, GD_checksum) != gd_csum(fs, g, b->data + off)) (*csum_bad)++;
        sfs_bput(fs, b);
        if (!gd_sane(fs, &gd)) return SFS_ECORRUPT;
    }
    return 0;
}

/* ---- bitmaps ---- */
void sfs_block_bitmap_csum_set(sfs_fs *fs, sfs_gd *gd, const uint8_t *bitmap)
{
    if (fs->csum) gd->block_bitmap_csum = sfs_crc32c(fs->csum_seed, bitmap, fs->bpg / 8);
}

void sfs_inode_bitmap_csum_set(sfs_fs *fs, sfs_gd *gd, const uint8_t *bitmap)
{
    if (fs->csum) gd->inode_bitmap_csum = sfs_crc32c(fs->csum_seed, bitmap, fs->ipg / 8);
}

static int bitmap_csum_ok(sfs_fs *fs, uint32_t stored, const uint8_t *bitmap, uint32_t bytes, uint32_t hi_end)
{
    uint32_t c;
    if (!fs->csum) return 1;
    c = sfs_crc32c(fs->csum_seed, bitmap, bytes);
    if (fs->gd_size < hi_end) { c &= 0xFFFF; stored &= 0xFFFF; }
    return c == stored;
}

static int in_group(sfs_fs *fs, uint32_t g, uint64_t blk) { return blk >= sfs_group_first_block(fs, g) && blk - sfs_group_first_block(fs, g) < sfs_group_block_count(fs, g); }

int sfs_block_bitmap(sfs_fs *fs, uint32_t group, sfs_gd *gd, sfs_buf **out)
{
    sfs_buf *b;
    int rc;
    if (gd->flags & BG_BLOCK_UNINIT) {
        /* Never initialised on disk: compute what it would contain (like the kernel does). */
        uint32_t i, n, used = 0, cnt = sfs_group_block_count(fs, group);
        uint64_t first = sfs_group_first_block(fs, group);
        b = sfs_bfind(fs, gd->block_bitmap);
        if (b && (b->flags & (B_COMPUTED | B_JDIRTY))) { *out = b; return 0; }
        if (b) sfs_bput(fs, b);
        rc = sfs_bnew(fs, gd->block_bitmap, &b);
        if (rc) return rc;
        n = sfs_group_super_blocks(fs, group);
        for (i = 0; i < n && i < cnt; ++i) sfs_set_bit(b->data, i);
        if (in_group(fs, group, gd->block_bitmap)) sfs_set_bit(b->data, (uint32_t)(gd->block_bitmap - first));
        if (in_group(fs, group, gd->inode_bitmap)) sfs_set_bit(b->data, (uint32_t)(gd->inode_bitmap - first));
        for (i = 0; i < fs->itable_blocks; ++i)
            if (in_group(fs, group, gd->inode_table + i)) sfs_set_bit(b->data, (uint32_t)(gd->inode_table + i - first));
        for (i = cnt; i < fs->bs * 8; ++i) sfs_set_bit(b->data, i);
        for (i = 0; i < cnt; ++i) used += sfs_test_bit(b->data, i);
        b->flags |= B_COMPUTED;
        if (cnt - used != gd->free_blocks) {
            sfs_logu(fs, "sfs: uninitialised block bitmap disagrees with the free count, group ", group);
            b->flags &= ~B_COMPUTED;
            sfs_bforget(fs, gd->block_bitmap);
            sfs_bput(fs, b);
            return SFS_ECORRUPT;
        }
        *out = b;
        return 0;
    }
    rc = sfs_bread(fs, gd->block_bitmap, &b);
    if (rc) return rc;
    if (!(b->flags & B_VERIFIED)) {
        if (!(b->flags & B_JDIRTY) && !bitmap_csum_ok(fs, gd->block_bitmap_csum, b->data, fs->bpg / 8, GD_block_bitmap_csum_hi + 2)) {
            sfs_logu(fs, "sfs: block bitmap checksum mismatch, group ", group);
            sfs_bput(fs, b);
            return SFS_ECORRUPT;
        }
        b->flags |= B_VERIFIED;
    }
    *out = b;
    return 0;
}

int sfs_inode_bitmap(sfs_fs *fs, uint32_t group, sfs_gd *gd, sfs_buf **out)
{
    sfs_buf *b;
    int rc;
    if (gd->flags & BG_INODE_UNINIT) {
        uint32_t i;
        b = sfs_bfind(fs, gd->inode_bitmap);
        if (b && (b->flags & (B_COMPUTED | B_JDIRTY))) { *out = b; return 0; }
        if (b) sfs_bput(fs, b);
        rc = sfs_bnew(fs, gd->inode_bitmap, &b);
        if (rc) return rc;
        for (i = fs->ipg; i < fs->bs * 8; ++i) sfs_set_bit(b->data, i);
        b->flags |= B_COMPUTED;
        if (gd->free_inodes != fs->ipg) {
            sfs_logu(fs, "sfs: uninitialised inode bitmap with inodes in use, group ", group);
            b->flags &= ~B_COMPUTED;
            sfs_bforget(fs, gd->inode_bitmap);
            sfs_bput(fs, b);
            return SFS_ECORRUPT;
        }
        *out = b;
        return 0;
    }
    rc = sfs_bread(fs, gd->inode_bitmap, &b);
    if (rc) return rc;
    if (!(b->flags & B_VERIFIED)) {
        if (!(b->flags & B_JDIRTY) && !bitmap_csum_ok(fs, gd->inode_bitmap_csum, b->data, fs->ipg / 8, GD_inode_bitmap_csum_hi + 2)) {
            sfs_logu(fs, "sfs: inode bitmap checksum mismatch, group ", group);
            sfs_bput(fs, b);
            return SFS_ECORRUPT;
        }
        b->flags |= B_VERIFIED;
    }
    *out = b;
    return 0;
}

/* True when blk holds file system metadata that no file may own (superblock/GDT copies, bitmaps, inode tables).
 * With flex_bg a group's tables live in the flex leader's range, so the whole flex group is consulted. */
int sfs_is_group_meta_block(sfs_fs *fs, uint64_t blk)
{
    uint32_t g, g0, g1, i;
    if (blk < fs->first_data_block || blk >= fs->nblocks) return 1;
    g = sfs_group_of_block(fs, blk);
    if (blk - sfs_group_first_block(fs, g) < sfs_group_super_blocks(fs, g)) return 1;
    if (fs->log_groups_per_flex && fs->log_groups_per_flex < 31) {
        uint32_t per = 1u << fs->log_groups_per_flex;
        g0 = g - g % per;
        g1 = g0 + per;
    } else {
        g0 = g;
        g1 = g + 1;
    }
    if (g1 > fs->ngroups) g1 = fs->ngroups;
    for (i = g0; i < g1; ++i) {
        sfs_gd gd;
        if (sfs_gd_read(fs, i, &gd)) return 1;
        if (blk == gd.block_bitmap || blk == gd.inode_bitmap) return 1;
        if (blk >= gd.inode_table && blk < gd.inode_table + fs->itable_blocks) return 1;
    }
    return 0;
}

/* ---- superblock ---- */
static uint32_t sb_block(sfs_fs *fs) { return fs->bs == 1024 ? 1 : 0; }
static uint32_t sb_offset(sfs_fs *fs) { return fs->bs == 1024 ? 0 : 1024; }

static void sb_fill(sfs_fs *fs)
{
    uint8_t *s = fs->sbraw;
    uint64_t now = sfs_now(fs);
    wr32(s, SB_free_blocks_count_lo, (uint32_t)fs->free_blocks);
    if (fs->has64) wr32(s, SB_free_blocks_count_hi, (uint32_t)(fs->free_blocks >> 32));
    wr32(s, SB_free_inodes_count, fs->free_inodes);
    wr32(s, SB_last_orphan, fs->last_orphan);
    wr32(s, SB_feature_compat, fs->feat_compat);
    wr32(s, SB_feature_incompat, fs->feat_incompat);
    wr32(s, SB_feature_ro_compat, fs->feat_ro);
    if (now) {
        wr32(s, SB_wtime, (uint32_t)now);
        s[SB_wtime_hi] = (uint8_t)(now >> 32);
    }
    wr64(s, SB_kbytes_written, fs->kbytes_written_base + (fs->st.write_bytes >> 10));
    if (fs->csum) wr32(s, SB_checksum, sfs_crc32c(0xFFFFFFFFu, s, SB_checksum));
}

int sfs_sb_write(sfs_fs *fs)
{
    sfs_buf *b;
    int rc;
    sb_fill(fs);
    rc = sfs_bread(fs, sb_block(fs), &b);
    if (rc) return rc;
    memcpy(b->data + sb_offset(fs), fs->sbraw, 1024);
    rc = sfs_bdirty_meta(fs, b);
    sfs_bput(fs, b);
    fs->txn.sb_dirty = 0;
    return rc;
}

/* Writes the superblock in place, outside any transaction (mount/unmount state changes), and flushes. */
static int sb_write_direct(sfs_fs *fs)
{
    sfs_buf *b;
    int rc;
    sb_fill(fs);
    rc = sfs_bread(fs, sb_block(fs), &b);
    if (rc) return rc;
    memcpy(b->data + sb_offset(fs), fs->sbraw, 1024);
    rc = sfs_dev_write(fs, b->blk, b->data, 1);
    sfs_bput(fs, b);
    if (!rc) rc = sfs_dev_flush(fs);
    return rc;
}

/* ---- transactions ---- */
int sfs_op_begin(sfs_fs *fs)
{
    if (fs->dead) return SFS_EIO;
    if (fs->ro) return SFS_EROFS;
    fs->in_op++;
    fs->op_mods = fs->mods;
    return 0;
}

static uint32_t txn_weight(sfs_fs *fs) { return fs->txn.nbufs + fs->txn.nfrees * 2 + fs->txn.nrevokes / 64u + 8u; }

int sfs_safe_point(sfs_fs *fs)
{
    if (fs->dead) return SFS_EIO;
    if (txn_weight(fs) >= fs->txn_soft || fs->ninodes > fs->max_inodes * 2) return sfs_commit(fs);
    return 0;
}

int sfs_op_end(sfs_fs *fs, int rc)
{
    if (fs->in_op) fs->in_op--;
    if (fs->dead) return rc ? rc : SFS_EIO;
    if (rc == SFS_EIO || rc == SFS_ECORRUPT || rc == SFS_ENOMEM) {
        /* An update failed half-way: the running transaction may describe a partial change. Drop it (the disk still
         * holds the last committed state) and stop writing. */
        if (fs->mods != fs->op_mods) return sfs_fail(fs, rc);
    }
    if (txn_weight(fs) >= fs->txn_soft) {
        int c = sfs_commit(fs);
        if (!rc) rc = c;
    }
    return rc;
}

int sfs_fail(sfs_fs *fs, int rc)
{
    sfs_buf *b, *next;
    if (fs->dead) return rc;
    sfs_logu(fs, "sfs: aborting the running transaction, volume now read-only; error ", (uint64_t)(-rc));
    fs->dead = 1;
    fs->ro = 1;
    fs->ro_reason |= SFS_RO_ERRORS;
    for (b = fs->txn.bufs; b; b = next) {
        next = b->tnext;
        b->tnext = 0;
        b->flags &= ~(B_JDIRTY | B_UPTODATE | B_VERIFIED | B_COMPUTED);
    }
    fs->txn.bufs = 0;
    fs->txn.nbufs = 0;
    sfs_runpage_free(fs, &fs->txn.frees);
    sfs_runpage_free(fs, &fs->txn.revokes);
    fs->txn.nfrees = fs->txn.nrevokes = 0;
    fs->txn.free_blocks_pending = 0;
    return rc;
}

int sfs_commit(sfs_fs *fs)
{
    int rc;
    if (fs->dead) return SFS_EIO;
    if (fs->ro) return 0;
    rc = sfs_apply_pending_frees(fs);
    if (!rc) rc = sfs_iflush_all(fs);
    if (!rc && (fs->txn.nbufs || fs->txn.sb_dirty)) rc = sfs_sb_write(fs);
    if (rc) return sfs_fail(fs, rc);
    if (fs->jnl.present) {
        rc = sfs_journal_commit(fs);
    } else {
        rc = sfs_cache_write_data(fs);
        if (!rc) rc = sfs_dev_flush(fs);          /* ordered: data before the metadata that points at it */
        if (!rc && fs->txn.nbufs) {
            sfs_txn_sort(fs);
            rc = sfs_cache_write_meta_direct(fs);
            if (!rc) rc = sfs_dev_flush(fs);
        }
        fs->st.commits++;
    }
    sfs_runpage_free(fs, &fs->txn.revokes);
    fs->txn.nrevokes = 0;
    if (rc) return sfs_fail(fs, rc);
    return 0;
}

/* ---- orphan list (s_last_orphan, chained through i_dtime) ---- */
int sfs_orphan_add(sfs_fs *fs, sfs_inode *in)
{
    in->dtime = fs->last_orphan;
    fs->last_orphan = in->ino;
    fs->txn.sb_dirty = 1;
    sfs_idirty(fs, in);
    return 0;
}

int sfs_orphan_del(sfs_fs *fs, sfs_inode *in)
{
    uint32_t cur = fs->last_orphan, guard = 0;
    if (cur == in->ino) {
        fs->last_orphan = in->dtime;
        fs->txn.sb_dirty = 1;
        in->dtime = 0;
        sfs_idirty(fs, in);
        return 0;
    }
    while (cur && guard++ < fs->inodes_count) {
        sfs_inode *p;
        int rc = sfs_iget(fs, cur, &p);
        if (rc) return rc;
        if (p->dtime == in->ino) {
            p->dtime = in->dtime;
            sfs_idirty(fs, p);
            sfs_iput(fs, p);
            in->dtime = 0;
            sfs_idirty(fs, in);
            return 0;
        }
        cur = p->dtime;
        sfs_iput(fs, p);
    }
    return SFS_ECORRUPT;
}

int sfs_orphan_cleanup(sfs_fs *fs)
{
    uint32_t guard = 0;
    int rc = 0;
    while (fs->last_orphan && !rc) {
        sfs_inode *in;
        uint32_t ino = fs->last_orphan;
        if (!sfs_ino_valid(fs, ino) || ino < fs->first_ino || guard++ > fs->inodes_count) {
            sfs_log(fs, "sfs: corrupt orphan list dropped");
            fs->last_orphan = 0;
            fs->txn.sb_dirty = 1;
            break;
        }
        rc = sfs_op_begin(fs);
        if (rc) return rc;
        rc = sfs_iget(fs, ino, &in);
        if (rc) {
            fs->last_orphan = 0;
            fs->txn.sb_dirty = 1;
            return sfs_op_end(fs, 0);
        }
        fs->last_orphan = in->dtime;
        fs->txn.sb_dirty = 1;
        in->dtime = 0;
        if (in->links == 0) {
            sfs_logu(fs, "sfs: releasing orphan inode ", ino);
            rc = sfs_inode_release_all(fs, in);
            if (!rc) {
                in->dtime = (uint32_t)sfs_now(fs);
                if (!in->dtime) in->dtime = 1;
                sfs_idirty(fs, in);
                rc = sfs_free_inode(fs, ino, sfs_is_dir(in));
            }
        } else if (sfs_is_reg(in)) {
            sfs_logu(fs, "sfs: finishing truncate of orphan inode ", ino);
            rc = sfs_file_truncate(fs, in, in->size);
            sfs_idirty(fs, in);
        }
        sfs_iput(fs, in);
        if (!rc) sfs_iforget(fs, ino);
        rc = sfs_op_end(fs, rc);
    }
    if (!rc) rc = sfs_commit(fs);
    return rc;
}

/* ---- mount ---- */
static int parse_super(sfs_fs *fs)
{
    const uint8_t *s = fs->sbraw;
    uint32_t log_bs, rev, bpg, ipg, cpg;
    uint64_t groups;
    if (rd16(s, SB_magic) != SB_MAGIC) return SFS_EINVAL;
    rev = rd32(s, SB_rev_level);
    if (rev > SB_REV_DYNAMIC) return SFS_ENOTSUP;
    log_bs = rd32(s, SB_log_block_size);
    if (log_bs > 2) return SFS_ENOTSUP;                  /* 1, 2 or 4 KiB blocks */
    fs->bs_bits = 10 + log_bs;
    fs->bs = 1u << fs->bs_bits;
    fs->feat_compat = rev ? rd32(s, SB_feature_compat) : 0;
    fs->feat_incompat = rev ? rd32(s, SB_feature_incompat) : 0;
    fs->feat_ro = rev ? rd32(s, SB_feature_ro_compat) : 0;
    if (fs->feat_incompat & ~INCOMPAT_SUPPORTED) return SFS_ENOTSUP;
    if (fs->feat_ro & RO_COMPAT_BIGALLOC) return SFS_ENOTSUP;
    if (rd32(s, SB_log_cluster_size) != log_bs) return SFS_ECORRUPT;
    fs->has64 = !!(fs->feat_incompat & INCOMPAT_64BIT);
    fs->nblocks = rd32(s, SB_blocks_count_lo) | (fs->has64 ? (uint64_t)rd32(s, SB_blocks_count_hi) << 32 : 0);
    fs->first_data_block = rd32(s, SB_first_data_block);
    if (fs->first_data_block != (fs->bs == 1024 ? 1u : 0u)) return SFS_ECORRUPT;
    if (fs->nblocks <= fs->first_data_block + 1) return SFS_ECORRUPT;
    if (fs->ops.size && (fs->nblocks << fs->bs_bits) > fs->ops.size) {
        sfs_log(fs, "sfs: file system is larger than the device");
        return SFS_ECORRUPT;
    }
    bpg = rd32(s, SB_blocks_per_group);
    cpg = rd32(s, SB_clusters_per_group);
    ipg = rd32(s, SB_inodes_per_group);
    if (!bpg || bpg > fs->bs * 8 || (bpg & 7) || cpg != bpg) return SFS_ECORRUPT;
    if (!ipg || ipg > fs->bs * 8 || (ipg & 7)) return SFS_ECORRUPT;
    fs->bpg = bpg;
    fs->ipg = ipg;
    groups = (fs->nblocks - fs->first_data_block + bpg - 1) / bpg;
    if (!groups || groups > 0xFFFFFFFFull / ipg) return SFS_ECORRUPT;
    fs->ngroups = (uint32_t)groups;
    fs->inodes_count = rd32(s, SB_inodes_count);
    if ((uint64_t)fs->inodes_count != groups * ipg) return SFS_ECORRUPT;
    if (rev == 0) {
        fs->isize = SB_GOOD_OLD_INODE_SIZE;
        fs->first_ino = SB_GOOD_OLD_FIRST_INO;
    } else {
        fs->isize = rd16(s, SB_inode_size);
        fs->first_ino = rd32(s, SB_first_ino);
        if (fs->isize < 128 || fs->isize > fs->bs || (fs->isize & (fs->isize - 1))) return SFS_ECORRUPT;
        if (fs->first_ino < SB_GOOD_OLD_FIRST_INO || fs->first_ino >= fs->inodes_count) return SFS_ECORRUPT;
    }
    fs->inodes_per_block = fs->bs / fs->isize;
    if ((ipg % fs->inodes_per_block) != 0) return SFS_ECORRUPT;
    fs->itable_blocks = ipg / fs->inodes_per_block;
    if (fs->has64) {
        fs->gd_size = rd16(s, SB_desc_size);
        if (fs->gd_size < GD_MIN_SIZE_64BIT || fs->gd_size > 1024 || (fs->gd_size & (fs->gd_size - 1))) return SFS_ECORRUPT;
    } else {
        fs->gd_size = GD_MIN_SIZE;
    }
    fs->desc_per_block = fs->bs / fs->gd_size;
    fs->gdt_blocks = (fs->ngroups + fs->desc_per_block - 1) / fs->desc_per_block;
    fs->csum = !!(fs->feat_ro & RO_COMPAT_METADATA_CSUM);
    fs->gdt_csum = !fs->csum && (fs->feat_ro & RO_COMPAT_GDT_CSUM);
    fs->sparse = !!(fs->feat_ro & RO_COMPAT_SPARSE_SUPER);
    fs->sparse2 = !!(fs->feat_compat & COMPAT_SPARSE_SUPER2);
    fs->backup_bgs[0] = rd32(s, SB_backup_bgs);
    fs->backup_bgs[1] = rd32(s, SB_backup_bgs + 4);
    fs->meta_bg = !!(fs->feat_incompat & INCOMPAT_META_BG);
    fs->first_meta_bg = rd32(s, SB_first_meta_bg);
    if (fs->meta_bg && fs->first_meta_bg > fs->gdt_blocks) return SFS_ECORRUPT;
    fs->reserved_gdt = rd16(s, SB_reserved_gdt_blocks);
    if (fs->reserved_gdt > fs->bs / 4) return SFS_ECORRUPT;
    fs->dir_index = !!(fs->feat_compat & COMPAT_DIR_INDEX);
    fs->filetype = !!(fs->feat_incompat & INCOMPAT_FILETYPE);
    fs->extents = !!(fs->feat_incompat & INCOMPAT_EXTENTS);
    fs->huge_file = !!(fs->feat_ro & RO_COMPAT_HUGE_FILE);
    fs->dir_nlink = !!(fs->feat_ro & RO_COMPAT_DIR_NLINK);
    fs->largedir = !!(fs->feat_incompat & INCOMPAT_LARGEDIR);
    fs->log_groups_per_flex = (fs->feat_incompat & INCOMPAT_FLEX_BG) ? s[SB_log_groups_per_flex] : 0;
    if (fs->log_groups_per_flex > 31) fs->log_groups_per_flex = 0;
    memcpy(fs->uuid, s + SB_uuid, 16);
    if (fs->csum) {
        if (s[SB_checksum_type] != SB_CHECKSUM_CRC32C) return SFS_ENOTSUP;
        if (rd32(s, SB_checksum) != sfs_crc32c(0xFFFFFFFFu, s, SB_checksum)) {
            sfs_log(fs, "sfs: superblock checksum mismatch");
            return SFS_ECORRUPT;
        }
        fs->csum_seed = (fs->feat_incompat & INCOMPAT_CSUM_SEED) ? rd32(s, SB_checksum_seed) : sfs_crc32c(0xFFFFFFFFu, fs->uuid, 16);
    }
    fs->hash_seed[0] = rd32(s, SB_hash_seed);
    fs->hash_seed[1] = rd32(s, SB_hash_seed + 4);
    fs->hash_seed[2] = rd32(s, SB_hash_seed + 8);
    fs->hash_seed[3] = rd32(s, SB_hash_seed + 12);
    fs->hash_version = s[SB_def_hash_version];
    if (fs->hash_version > DX_HASH_TEA) fs->hash_version = DX_HASH_HALF_MD4;
    fs->hash_unsigned = (rd32(s, SB_flags) & SB_FLAG_UNSIGNED_HASH) ? 3 : 0;
    fs->want_extra_isize = 0;
    if (fs->isize > 128) {
        fs->want_extra_isize = rd16(s, SB_want_extra_isize);
        if (fs->want_extra_isize < 32) fs->want_extra_isize = 32;
        if (fs->want_extra_isize > fs->isize - 128) fs->want_extra_isize = fs->isize - 128;
        fs->want_extra_isize &= ~3u;
    }
    fs->free_blocks = rd32(s, SB_free_blocks_count_lo) | (fs->has64 ? (uint64_t)rd32(s, SB_free_blocks_count_hi) << 32 : 0);
    fs->free_inodes = rd32(s, SB_free_inodes_count);
    fs->last_orphan = rd32(s, SB_last_orphan);
    fs->kbytes_written_base = rd64(s, SB_kbytes_written);
    fs->ext_per_block = (fs->bs - EH_SIZE) / EE_SIZE;
    return 0;
}

static void decide_read_only(sfs_fs *fs)
{
    const uint8_t *s = fs->sbraw;
    if (fs->mflags & SFS_MOUNT_RDONLY) fs->ro_reason |= SFS_RO_CALLER;
    if (!fs->extents) fs->ro_reason |= SFS_RO_NO_EXTENTS;
    if (fs->feat_ro & ~RO_COMPAT_SUPPORTED & ~RO_COMPAT_FORCES_RO) fs->ro_reason |= SFS_RO_UNKNOWN_RO_COMPAT;
    if (fs->feat_ro & RO_COMPAT_QUOTA) fs->ro_reason |= SFS_RO_QUOTA;
    if (fs->feat_ro & RO_COMPAT_VERITY) fs->ro_reason |= SFS_RO_VERITY;
    if (fs->feat_ro & RO_COMPAT_READONLY) fs->ro_reason |= SFS_RO_READONLY_FLAG;
    if (fs->feat_ro & RO_COMPAT_ORPHAN_PRESENT) fs->ro_reason |= SFS_RO_ORPHAN_FILE;
    if (fs->feat_compat & COMPAT_ORPHAN_FILE) fs->ro_reason |= SFS_RO_ORPHAN_FILE;
    if (fs->feat_incompat & INCOMPAT_INLINE_DATA) fs->ro_reason |= SFS_RO_INLINE_DATA;
    if (fs->feat_incompat & INCOMPAT_ENCRYPT) fs->ro_reason |= SFS_RO_ENCRYPT;
    if (fs->feat_incompat & INCOMPAT_CASEFOLD) fs->ro_reason |= SFS_RO_CASEFOLD;
    if (fs->feat_incompat & INCOMPAT_EA_INODE) fs->ro_reason |= SFS_RO_EA_INODE;
    if (fs->feat_compat & COMPAT_FAST_COMMIT) fs->ro_reason |= SFS_RO_JOURNAL_FAST_COMMIT;
    if (rd16(s, SB_state) & SB_STATE_ERROR) fs->ro_reason |= SFS_RO_ERRORS;
    if ((fs->feat_compat & COMPAT_HAS_JOURNAL) && rd32(s, SB_journal_inum) == 0) fs->ro_reason |= SFS_RO_UNKNOWN_RO_COMPAT;
    if (fs->ro_reason) fs->ro = 1;
}

static int load_geometry(sfs_fs *fs)
{
    int rc, bad = 0;
    rc = parse_super(fs);
    if (rc) return rc;
    rc = gd_check_all(fs, &bad);
    if (rc) return rc;
    if (bad) {
        sfs_logu(fs, "sfs: group descriptor checksum mismatches: ", (uint64_t)bad);
        if (!(fs->mflags & SFS_MOUNT_RDONLY)) return SFS_ECORRUPT;
    }
    return 0;
}

static void fs_release(sfs_fs *fs)
{
    sfs_icache_destroy(fs);
    sfs_journal_unload(fs);
    sfs_cache_destroy(fs);
    sfs_runpage_free(fs, &fs->txn.frees);
    sfs_runpage_free(fs, &fs->txn.revokes);
    sfs_free(fs, fs->scratch, fs->bs);
    sfs_free(fs, fs->scratch2, fs->bs);
    sfs_free(fs, fs->pa, sizeof(sfs_patab));
    sfs_free(fs, fs->sbraw, 1024);
    fs->ops.free(fs->ops.ctx, fs, sizeof *fs);
}

int sfs_mount(const sfs_ops *ops, unsigned flags, sfs_fs **out)
{
    sfs_fs *fs;
    int rc;
    typedef char fs_fits_one_allocation[sizeof(sfs_fs) <= SFS_MAX_ALLOC ? 1 : -1];
    (void)sizeof(fs_fits_one_allocation);
    *out = 0;
    if (!ops || !ops->read || !ops->alloc || !ops->free) return SFS_EINVAL;
    fs = ops->alloc(ops->ctx, sizeof *fs);
    if (!fs) return SFS_ENOMEM;
    memset(fs, 0, sizeof *fs);
    fs->ops = *ops;
    fs->mflags = flags;
    if (!ops->write) fs->mflags |= SFS_MOUNT_RDONLY;
    fs->sbraw = sfs_alloc(fs, 1024);
    fs->pa = sfs_alloc(fs, sizeof(sfs_patab));
    if (!fs->sbraw || !fs->pa) { rc = SFS_ENOMEM; goto fail; }
    if (ops->size && ops->size < 2048) { rc = SFS_EINVAL; goto fail; }
    if (ops->read(ops->ctx, SB_OFFSET, fs->sbraw, 1024)) { rc = SFS_EIO; goto fail; }
    rc = parse_super(fs);
    if (rc) goto fail;
    fs->scratch = sfs_alloc(fs, fs->bs);
    fs->scratch2 = sfs_alloc(fs, fs->bs);
    if (!fs->scratch || !fs->scratch2) { rc = SFS_ENOMEM; goto fail; }
    rc = sfs_cache_init(fs, (fs->mflags & SFS_MOUNT_NAIVE) ? 64 : (ops->cache_blocks ? ops->cache_blocks : 2048));
    if (rc) goto fail;
    fs->max_inodes = (fs->mflags & SFS_MOUNT_NAIVE) ? 16 : 512;
    rc = load_geometry(fs);
    if (rc) goto fail;
    decide_read_only(fs);
    fs->next_generation = sfs_now(fs) * 2654435761u + 1;
    if (fs->feat_compat & COMPAT_HAS_JOURNAL) {
        rc = sfs_journal_load(fs, !fs->ro && !(fs->mflags & SFS_MOUNT_NOREPLAY));
        if (rc == 1) {
            /* The journal was replayed: everything read so far may be stale. */
            sfs_icache_destroy(fs);
            sfs_cache_drop_clean(fs);
            if (ops->read(ops->ctx, SB_OFFSET, fs->sbraw, 1024)) { rc = SFS_EIO; goto fail; }
            rc = load_geometry(fs);
            if (rc) goto fail;
            fs->feat_incompat &= ~INCOMPAT_RECOVER;
        } else if (rc < 0) {
            goto fail;
        }
    } else if (fs->feat_incompat & INCOMPAT_RECOVER) {
        rc = SFS_ECORRUPT;
        goto fail;
    }
    if (!fs->ro) {
        uint64_t now = sfs_now(fs);
        uint8_t *s = fs->sbraw;
        if (fs->jnl.present) fs->feat_incompat |= INCOMPAT_RECOVER;
        else wr16(s, SB_state, (uint16_t)(rd16(s, SB_state) & ~SB_STATE_VALID));
        wr16(s, SB_mnt_count, (uint16_t)(rd16(s, SB_mnt_count) + 1));
        if (now) { wr32(s, SB_mtime, (uint32_t)now); s[SB_mtime_hi] = (uint8_t)(now >> 32); }
        rc = sb_write_direct(fs);
        if (rc) goto fail;
        fs->mounted_dirty = 1;
        if (fs->last_orphan) {
            rc = sfs_orphan_cleanup(fs);
            if (rc) goto fail;
        }
    }
    *out = fs;
    return 0;
fail:
    fs_release(fs);
    return rc;
}

int sfs_sync(sfs_fs *fs)
{
    int rc;
    if (fs->dead) return SFS_EIO;
    if (fs->ro) return 0;
    rc = sfs_commit(fs);
    if (!rc) rc = sfs_dev_flush(fs);
    if (!rc && (fs->mflags & SFS_MOUNT_CLEAN_ON_SYNC) && fs->jnl.present) rc = sfs_journal_mark_clean(fs);
    return rc;
}

int sfs_unmount(sfs_fs *fs)
{
    int rc = 0;
    if (!fs) return SFS_EINVAL;
    if (!fs->ro && !fs->dead) {
        uint8_t *s = fs->sbraw;
        uint32_t i;
        for (i = 0; i < PA_MAX; ++i) fs->pa->w[i].len = 0;
        rc = sfs_commit(fs);
        if (!rc && fs->jnl.present) rc = sfs_journal_mark_clean(fs);
        if (!rc && fs->mounted_dirty) {
            fs->feat_incompat &= ~INCOMPAT_RECOVER;
            if (!fs->jnl.present) wr16(s, SB_state, (uint16_t)(rd16(s, SB_state) | SB_STATE_VALID));
            rc = sb_write_direct(fs);
        }
    }
    fs_release(fs);
    return rc;
}

int sfs_statfs(sfs_fs *fs, sfs_statfs_t *o)
{
    memset(o, 0, sizeof *o);
    o->block_size = fs->bs;
    o->blocks = fs->nblocks;
    o->free_blocks = fs->free_blocks + fs->txn.free_blocks_pending;
    o->inodes = fs->inodes_count;
    o->free_inodes = fs->free_inodes;
    o->groups = fs->ngroups;
    o->feature_compat = fs->feat_compat;
    o->feature_incompat = fs->feat_incompat;
    o->feature_ro_compat = fs->feat_ro;
    o->journal_features = fs->jnl.present ? fs->jnl.feat_incompat : 0;
    o->read_only = fs->ro;
    o->ro_reason = fs->ro_reason;
    memcpy(o->uuid, fs->uuid, 16);
    memcpy(o->label, fs->sbraw + SB_volume_name, 16);
    o->label[16] = 0;
    return 0;
}

void sfs_get_stats(sfs_fs *fs, sfs_stats *out) { *out = fs->st; }
int sfs_is_readonly(sfs_fs *fs) { return fs->ro; }
uint32_t sfs_block_size(sfs_fs *fs) { return fs->bs; }

void sfs_set_write_limit(sfs_fs *fs, uint64_t n, void (*hit)(void *ctx))
{
    fs->write_limit = n ? fs->st.writes + n : 0;
    fs->write_hit = hit;
}

const char *sfs_strerror(int err)
{
    switch (err) {
    case SFS_OK: return "ok";
    case SFS_EIO: return "I/O error";
    case SFS_ENOENT: return "no such file or directory";
    case SFS_EEXIST: return "file exists";
    case SFS_ENOTDIR: return "not a directory";
    case SFS_EISDIR: return "is a directory";
    case SFS_ENOTEMPTY: return "directory not empty";
    case SFS_ENOSPC: return "no space left on device";
    case SFS_ENOMEM: return "out of memory";
    case SFS_EINVAL: return "invalid argument";
    case SFS_EROFS: return "read-only file system";
    case SFS_ECORRUPT: return "file system structure is corrupt";
    case SFS_ENOTSUP: return "unsupported feature";
    case SFS_ENAMETOOLONG: return "name too long";
    case SFS_EFBIG: return "file too large";
    case SFS_EBUSY: return "busy";
    case SFS_ERANGE: return "out of range";
    default: return "unknown error";
    }
}
