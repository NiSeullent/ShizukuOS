/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS v1 file data.
 *
 * Reads and writes of whole, aligned blocks go straight between the caller's buffer and the device in runs as long
 * as the extent (one request per extent instead of one per block); partial blocks go through the block cache.
 * Holes read as zeros; writing into a hole allocates the whole remaining range at once (goal = the physical
 * successor of the previous block, plus the file's preallocation window), so a sequential writer gets one extent
 * per 128 MiB. Data is written before the metadata that references it is committed (ordered mode).
 *
 * Truncation that spans more than a few groups runs in steps with the inode on the orphan list, so a crash between
 * steps leaves a consistent volume whose next mount (or e2fsck) finishes the job.
 */
#include "sfs_internal.h"

#define DIRECT_MAX_BYTES (8u << 20)             /* largest single device request */

static uint32_t direct_cap(sfs_fs *fs) { return DIRECT_MAX_BYTES >> fs->bs_bits; }

/* ---- inline data (read only) ---- */
static int inline_xattr_value(sfs_fs *fs, sfs_inode *in, uint8_t *dst, uint64_t off, uint64_t len, uint64_t *got)
{
    sfs_buf *b;
    uint64_t blk;
    uint32_t ioff, start, end, e;
    const uint8_t *raw;
    int rc;
    *got = 0;
    rc = sfs_inode_loc(fs, in->ino, &blk, &ioff);
    if (!rc) rc = sfs_bread(fs, blk, &b);
    if (rc) return rc;
    raw = b->data + ioff;
    start = 128u + in->extra_isize;
    end = fs->isize;
    if (start + 4 > end || rd32(raw, start) != 0xEA020000u) { sfs_bput(fs, b); return 0; }
    e = start + 4;
    while (e + 16 <= end && rd32(raw, e) != 0) {
        uint32_t nl = raw[e], idx = raw[e + 1], voff = rd16(raw, e + 2), vsize = rd32(raw, e + 8);
        if (e + 16 + nl > end) break;
        if (idx == 7 && nl == 4 && !memcmp(raw + e + 16, "data", 4)) {
            uint32_t vstart = start + 4 + voff;
            if (vstart > end || vsize > end - vstart) break;
            if (off < vsize) {
                uint64_t n = sfs_min64(len, vsize - off);
                memcpy(dst, raw + vstart + off, (size_t)n);
                *got = n;
            }
            break;
        }
        e += (16 + nl + 3) & ~3u;
    }
    sfs_bput(fs, b);
    return 0;
}

int sfs_inline_read(sfs_fs *fs, sfs_inode *in, uint64_t off, void *buf, uint64_t len, uint64_t *done)
{
    uint8_t *dst = buf;
    uint64_t n = 0;
    *done = 0;
    if (off < IN_BLOCK_BYTES) {
        n = sfs_min64(len, IN_BLOCK_BYTES - off);
        memcpy(dst, in->iblock + off, (size_t)n);
        dst += n;
        len -= n;
        off += n;
    }
    if (len) {
        uint64_t got;
        int rc = inline_xattr_value(fs, in, dst, off - IN_BLOCK_BYTES, len, &got);
        if (rc) return rc;
        if (got < len) memset(dst + got, 0, (size_t)(len - got));
        n += len;
    }
    *done = n;
    return 0;
}

/* ---- read ---- */
int sfs_file_read(sfs_fs *fs, sfs_inode *in, uint64_t off, void *buf, uint64_t len, uint64_t *done)
{
    uint8_t *dst = buf;
    uint64_t total = 0;
    int rc = 0;
    *done = 0;
    if (off >= in->size) return 0;
    if (len > in->size - off) len = in->size - off;
    if (in->flags & IFL_ENCRYPT) return SFS_ENOTSUP;
    if (in->flags & IFL_INLINE_DATA) return sfs_inline_read(fs, in, off, buf, len, done);
    while (len) {
        uint32_t lblk = (uint32_t)(off >> fs->bs_bits), boff = (uint32_t)(off & (fs->bs - 1)), run;
        uint64_t pblk, n;
        int unw;
        if ((off >> fs->bs_bits) > 0xFFFFFFFFull) break;
        rc = sfs_map_block(fs, in, lblk, &pblk, &run, &unw);
        if (rc < 0) break;
        if (rc == 0 || unw) {
            n = sfs_min64(len, ((uint64_t)run << fs->bs_bits) - boff);
            memset(dst, 0, (size_t)n);
        } else if (boff == 0 && len >= fs->bs && !(fs->mflags & SFS_MOUNT_NAIVE)) {
            uint32_t nb = (uint32_t)sfs_min64(sfs_min64(run, len >> fs->bs_bits), direct_cap(fs));
            rc = sfs_dev_read(fs, pblk, dst, nb);
            if (rc) break;
            sfs_boverlay(fs, pblk, nb, dst);
            n = (uint64_t)nb << fs->bs_bits;
        } else {
            sfs_buf *b;
            n = sfs_min64(len, fs->bs - boff);
            rc = sfs_bread(fs, pblk, &b);
            if (rc) break;
            memcpy(dst, b->data + boff, (size_t)n);
            sfs_bput(fs, b);
        }
        rc = 0;
        dst += n;
        off += n;
        len -= n;
        total += n;
    }
    *done = total;
    return rc;
}

/* ---- write ---- */
static int zero_unwritten(sfs_fs *fs, sfs_inode *in, uint32_t lblk)
{
    /* An unwritten (preallocated) extent is being written: its blocks are zeroed on disk and the extent becomes
     * initialised as a whole (simple and always correct; such extents only come from fallocate on Linux). */
    uint64_t pblk;
    uint32_t run, i, first = lblk;
    int unw, rc;
    uint8_t *z;
    rc = sfs_map_block(fs, in, lblk, &pblk, &run, &unw);
    if (rc != 1 || !unw) return rc < 0 ? rc : 0;
    /* walk back to the extent start */
    while (first > 0) {
        uint64_t p2;
        uint32_t r2;
        int u2;
        if (sfs_map_block(fs, in, first - 1, &p2, &r2, &u2) != 1 || !u2 || p2 + 1 != pblk - (lblk - first)) break;
        first--;
    }
    rc = sfs_map_block(fs, in, first, &pblk, &run, &unw);
    if (rc != 1) return rc < 0 ? rc : SFS_ECORRUPT;
    z = sfs_alloc(fs, fs->bs);
    if (!z) return SFS_ENOMEM;
    for (i = 0; i < run && !rc; ++i) {
        sfs_binval_data(fs, pblk + i, 1);
        rc = sfs_dev_write(fs, pblk + i, z, 1);
    }
    sfs_free(fs, z, fs->bs);
    if (rc) return rc;
    return sfs_ext_mark_written(fs, in, first);
}

static int write_new_blocks(sfs_fs *fs, uint64_t start, uint32_t got, uint32_t boff, const uint8_t **src, uint64_t *len, uint64_t *off)
{
    uint32_t i = 0;
    int rc = 0;
    while (i < got && *len) {
        if (boff == 0 && *len >= fs->bs && !(fs->mflags & SFS_MOUNT_NAIVE)) {
            uint32_t n = (uint32_t)sfs_min64(sfs_min64(got - i, *len >> fs->bs_bits), direct_cap(fs));
            sfs_binval_data(fs, start + i, n);
            rc = sfs_dev_write(fs, start + i, *src, n);
            if (rc) return rc;
            *src += (size_t)n << fs->bs_bits;
            *len -= (uint64_t)n << fs->bs_bits;
            *off += (uint64_t)n << fs->bs_bits;
            i += n;
        } else {
            sfs_buf *b;
            uint32_t n = (uint32_t)sfs_min64(*len, fs->bs - boff);
            rc = sfs_bnew(fs, start + i, &b);
            if (rc) return rc;
            memcpy(b->data + boff, *src, n);
            sfs_bdirty_data(fs, b);
            sfs_bput(fs, b);
            *src += n;
            *len -= n;
            *off += n;
            boff = 0;
            i++;
        }
    }
    return 0;
}

int sfs_file_write(sfs_fs *fs, sfs_inode *in, uint64_t off, const void *buf, uint64_t len, uint64_t *done)
{
    const uint8_t *src = buf;
    uint64_t start_off = off, maxbytes = (uint64_t)EXT_MAX_LBLK << fs->bs_bits;
    int rc = 0, retried = 0;
    *done = 0;
    if (!sfs_is_reg(in)) return sfs_is_dir(in) ? SFS_EISDIR : SFS_EINVAL;
    if (in->flags & (IFL_INLINE_DATA | IFL_ENCRYPT | IFL_VERITY)) return SFS_ENOTSUP;
    if (in->flags & IFL_IMMUTABLE) return SFS_EROFS;
    if (!len) return 0;
    if (!(in->flags & IFL_EXTENTS)) {
        if (in->nblocks || !fs->extents) return SFS_ENOTSUP;    /* block-mapped files are read-only */
        in->flags |= IFL_EXTENTS;
        sfs_ext_root_init(in->iblock);
        sfs_idirty(fs, in);
    }
    if (off >= maxbytes) return SFS_EFBIG;
    if (len > maxbytes - off) len = maxbytes - off;
    if (off + len > 0x7FFFFFFFull && !(fs->feat_ro & RO_COMPAT_LARGE_FILE)) {
        fs->feat_ro |= RO_COMPAT_LARGE_FILE;
        fs->txn.sb_dirty = 1;
    }
    while (len) {
        uint32_t lblk = (uint32_t)(off >> fs->bs_bits), boff = (uint32_t)(off & (fs->bs - 1)), run;
        uint64_t pblk;
        int unw;
        rc = sfs_map_block(fs, in, lblk, &pblk, &run, &unw);
        if (rc < 0) break;
        if (rc == 1 && unw) {
            rc = zero_unwritten(fs, in, lblk);
            if (rc) break;
            continue;
        }
        if (rc == 1) {
            if (boff == 0 && len >= fs->bs && !(fs->mflags & SFS_MOUNT_NAIVE)) {
                uint32_t nb = (uint32_t)sfs_min64(sfs_min64(run, len >> fs->bs_bits), direct_cap(fs));
                sfs_binval_data(fs, pblk, nb);
                rc = sfs_dev_write(fs, pblk, src, nb);
                if (rc) break;
                src += (size_t)nb << fs->bs_bits;
                len -= (uint64_t)nb << fs->bs_bits;
                off += (uint64_t)nb << fs->bs_bits;
            } else {
                sfs_buf *b;
                uint32_t n = (uint32_t)sfs_min64(len, fs->bs - boff);
                rc = (boff == 0 && n == fs->bs) ? sfs_bnew(fs, pblk, &b) : sfs_bread(fs, pblk, &b);
                if (rc) break;
                memcpy(b->data + boff, src, n);
                sfs_bdirty_data(fs, b);
                sfs_bput(fs, b);
                src += n;
                len -= n;
                off += n;
            }
        } else {
            uint64_t need = ((uint64_t)boff + len + fs->bs - 1) >> fs->bs_bits, start;
            uint32_t want = (uint32_t)sfs_min64(sfs_min64(need, run), EXT_INIT_MAX_LEN), got;
            if (fs->mflags & SFS_MOUNT_NAIVE) want = 1;
            rc = sfs_alloc_blocks(fs, in, lblk, sfs_goal_for(fs, in, lblk), want, &start, &got);
            if (rc == SFS_ENOSPC && !retried && fs->txn.nfrees) {
                /* blocks freed by the running transaction become usable once it commits */
                retried = 1;
                if (off > in->size) { in->size = off; sfs_idirty(fs, in); }
                rc = sfs_commit(fs);
                if (!rc) continue;
            }
            if (rc) break;
            rc = sfs_ext_insert(fs, in, lblk, start, got);
            if (!rc) rc = sfs_add_blocks(fs, in, got);
            if (rc) { sfs_free_blocks(fs, start, got, 0); break; }
            rc = write_new_blocks(fs, start, got, boff, &src, &len, &off);
            if (rc) break;
        }
        if (off > in->size) { in->size = off; sfs_idirty(fs, in); }
        rc = sfs_safe_point(fs);
        if (rc) break;
    }
    if (off > in->size) { in->size = off; sfs_idirty(fs, in); }
    *done = off - start_off;
    if (*done) sfs_inode_touch(fs, in, 1, 1, 0);
    if (rc == SFS_ENOSPC && *done) rc = 0;                  /* short write */
    return rc;
}

/* ---- truncate / release ---- */
static int zero_tail(sfs_fs *fs, sfs_inode *in, uint64_t size)
{
    uint32_t boff = (uint32_t)(size & (fs->bs - 1)), run;
    uint64_t pblk;
    int unw, rc;
    sfs_buf *b;
    if (!boff) return 0;
    rc = sfs_map_block(fs, in, (uint32_t)(size >> fs->bs_bits), &pblk, &run, &unw);
    if (rc != 1 || unw) return rc < 0 ? rc : 0;
    rc = sfs_bread(fs, pblk, &b);
    if (rc) return rc;
    memset(b->data + boff, 0, fs->bs - boff);
    /* The zeroed tail lies inside the old size: it may reach the disk only once the smaller size is committed,
     * otherwise a crash could leave the old size with a zeroed hole (a torn truncate). */
    sfs_bdirty_late(fs, b);
    fs->txn.force_commit = 1;
    sfs_bput(fs, b);
    return 0;
}

static int last_cb(void *ctx, uint32_t lblk, uint64_t pblk, uint32_t len, int unwritten)
{
    uint64_t *end = ctx;
    (void)pblk; (void)unwritten;
    if ((uint64_t)lblk + len > *end) *end = (uint64_t)lblk + len;
    return 0;
}

/* One past the last mapped logical block (0 for an empty tree). */
static int mapped_end(sfs_fs *fs, sfs_inode *in, uint64_t *end)
{
    *end = 0;
    return (in->flags & IFL_EXTENTS) ? sfs_ext_iterate(fs, in, last_cb, end) : 0;
}

/* Frees every block at or beyond byte `size`, in steps bounded by the journal; with `on_list` the inode is already
 * on the orphan list (the caller keeps it there), otherwise a multi-step run adds it for the duration. */
static int truncate_blocks_ex(sfs_fs *fs, sfs_inode *in, uint64_t old_size, uint64_t size, int meta, int on_list)
{
    uint64_t first = (size + fs->bs - 1) >> fs->bs_bits;
    uint64_t end = (old_size + fs->bs - 1) >> fs->bs_bits, mend;
    uint64_t step = (fs->mflags & SFS_MOUNT_SMALL_TXN) ? 256 : (uint64_t)fs->bpg * 8;
    int rc = 0, orphan = 0;
    if (first > EXT_MAX_LBLK) return 0;
    rc = mapped_end(fs, in, &mend);
    if (rc) return rc;
    if (mend > end) end = mend;
    if (in->last_lblk >= first) { in->last_lblk = 0; in->last_pblk = 0; }
    sfs_pa_release(fs, in->ino);
    if (end > first + step && in->links && !on_list) {
        rc = sfs_orphan_add(fs, in);
        if (rc) return rc;
        orphan = 1;
    }
    while (end > first) {
        uint64_t cut = end > first + step ? end - step : first;
        rc = sfs_ext_truncate(fs, in, (uint32_t)cut, meta);
        if (rc) return rc;
        end = cut;
        if (end > first) {
            rc = sfs_safe_point(fs);
            if (rc) return rc;
        }
    }
    /* anything mapped beyond the old size (e.g. after a crash) */
    rc = sfs_ext_truncate(fs, in, (uint32_t)first, meta);
    if (!rc && orphan) rc = sfs_orphan_del(fs, in);
    return rc;
}

static int truncate_blocks(sfs_fs *fs, sfs_inode *in, uint64_t old_size, uint64_t size, int meta)
{
    return truncate_blocks_ex(fs, in, old_size, size, meta, 0);
}

/* Orphan recovery of a truncate: i_size is already the new size, blocks beyond it may remain. */
int sfs_file_trim_orphan(sfs_fs *fs, sfs_inode *in)
{
    if (!sfs_is_reg(in) || !(in->flags & IFL_EXTENTS)) return 0;
    return truncate_blocks_ex(fs, in, in->size, in->size, 0, 1);
}

int sfs_file_truncate(sfs_fs *fs, sfs_inode *in, uint64_t size)
{
    int rc = 0;
    uint64_t old = in->size;
    if (!sfs_is_reg(in)) return sfs_is_dir(in) ? SFS_EISDIR : SFS_EINVAL;
    if (in->flags & (IFL_INLINE_DATA | IFL_ENCRYPT | IFL_VERITY)) return SFS_ENOTSUP;
    if (in->flags & IFL_IMMUTABLE) return SFS_EROFS;
    if (size > ((uint64_t)EXT_MAX_LBLK << fs->bs_bits)) return SFS_EFBIG;
    if (!(in->flags & IFL_EXTENTS)) {
        if (size != 0) {
            if (size >= old) { in->size = size; sfs_inode_touch(fs, in, 1, 1, 0); return 0; }
            return SFS_ENOTSUP;
        }
        rc = sfs_bmap_release(fs, in, 0);
        if (rc) return rc;
        in->size = 0;
        if (fs->extents) { in->flags |= IFL_EXTENTS; sfs_ext_root_init(in->iblock); }
        sfs_inode_touch(fs, in, 1, 1, 0);
        return 0;
    }
    if (size > 0x7FFFFFFFull && !(fs->feat_ro & RO_COMPAT_LARGE_FILE)) {
        fs->feat_ro |= RO_COMPAT_LARGE_FILE;
        fs->txn.sb_dirty = 1;
    }
    if (size < old) {
        rc = zero_tail(fs, in, size);
        if (rc) return rc;
        in->size = size;                         /* i_size first: blocks beyond it are then only waiting to be freed */
        sfs_idirty(fs, in);
        rc = truncate_blocks(fs, in, old, size, 0);
    } else {
        in->size = size;
    }
    sfs_inode_touch(fs, in, 1, 1, 0);
    return rc;
}

static uint32_t xattr_block_csum(sfs_fs *fs, uint64_t blk, const uint8_t *d)
{
    static const uint8_t zero4[4] = {0, 0, 0, 0};
    uint8_t le[8];
    uint32_t c;
    wr64(le, 0, blk);
    c = sfs_crc32c(fs->csum_seed, le, 8);
    c = sfs_crc32c(c, d, 0x10);
    c = sfs_crc32c(c, zero4, 4);
    return sfs_crc32c(c, d + 0x14, fs->bs - 0x14);
}

static int release_xattr_block(sfs_fs *fs, sfs_inode *in)
{
    sfs_buf *b;
    uint64_t blk = in->file_acl;
    uint32_t refs;
    int rc;
    if (!blk) return 0;
    if (!sfs_block_valid(fs, blk)) return SFS_ECORRUPT;
    rc = sfs_bread(fs, blk, &b);
    if (rc) return rc;
    if (rd32(b->data, 0) != 0xEA020000u) { sfs_bput(fs, b); return SFS_ECORRUPT; }
    refs = rd32(b->data, 4);
    if (refs > 1) {
        wr32(b->data, 4, refs - 1);
        if (fs->csum) wr32(b->data, 0x10, xattr_block_csum(fs, blk, b->data));
        rc = sfs_bdirty_meta(fs, b);
        sfs_bput(fs, b);
    } else {
        sfs_bput(fs, b);
        rc = sfs_free_blocks(fs, blk, 1, 1);
    }
    if (rc) return rc;
    in->file_acl = 0;
    return sfs_add_blocks(fs, in, -1);
}

int sfs_inode_release_all(sfs_fs *fs, sfs_inode *in)
{
    int rc = 0;
    int meta = sfs_inode_meta_data(in);
    int fast_link = sfs_is_lnk(in) && in->nblocks == (in->file_acl ? 1u : 0u) && !(in->flags & IFL_EXTENTS);
    sfs_pa_release(fs, in->ino);
    if (in->flags & IFL_INLINE_DATA) {
        /* nothing outside the inode (and its xattr block) */
    } else if (in->flags & IFL_EXTENTS) {
        rc = sfs_is_reg(in) ? truncate_blocks(fs, in, in->size, 0, 0) : sfs_ext_truncate(fs, in, 0, meta);
        if (!rc) rc = sfs_ext_truncate(fs, in, 0, meta);
    } else if (!fast_link) {
        rc = sfs_bmap_release(fs, in, meta);
    }
    if (!rc) rc = release_xattr_block(fs, in);
    if (rc) return rc;
    in->size = 0;
    sfs_idirty(fs, in);
    return 0;
}

/* ---- symlinks ---- */
int sfs_symlink_read(sfs_fs *fs, sfs_inode *in, char *buf, size_t cap, size_t *len)
{
    uint64_t done;
    uint32_t ea = in->file_acl ? 1u : 0u;
    int rc;
    if (!sfs_is_lnk(in)) return SFS_EINVAL;
    if (in->size > 4096) return SFS_ECORRUPT;
    if (cap < in->size) return SFS_ERANGE;
    if (!(in->flags & (IFL_EXTENTS | IFL_INLINE_DATA)) && in->nblocks == ea) {
        if (in->size >= IN_BLOCK_BYTES) return SFS_ECORRUPT;
        memcpy(buf, in->iblock, (size_t)in->size);
        *len = (size_t)in->size;
        return 0;
    }
    rc = sfs_file_read(fs, in, 0, buf, in->size, &done);
    if (rc) return rc;
    *len = (size_t)done;
    return 0;
}
