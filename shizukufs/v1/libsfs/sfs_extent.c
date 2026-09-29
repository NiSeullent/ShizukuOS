/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS v1 block mapping: ext4 extent trees (root in i_block, index and leaf nodes in blocks with a crc32c tail),
 * and the legacy ext2/ext3 direct/indirect block maps (read, release).
 *
 * Invariants kept on every update (e2fsck checks them): entries sorted and non-overlapping, an index key equals
 * the first key of its child, no empty non-root node survives an operation, the tree is collapsed into the inode
 * when it fits, and i_blocks counts every data and tree block.
 */
#include "sfs_internal.h"

#define ENT(h, i) ((h) + EH_SIZE + (size_t)(i) * EE_SIZE)

typedef struct xpath {
    sfs_buf *b;                 /* NULL at level 0 (the root lives in the inode) */
    uint8_t *h;
    int idx;
} xpath;

static uint64_t ee_start(const uint8_t *e) { return rd32(e, EE_start_lo) | ((uint64_t)rd16(e, EE_start_hi) << 32); }
static uint32_t ee_len(const uint8_t *e) { uint32_t l = rd16(e, EE_len); return l > EXT_INIT_MAX_LEN ? l - EXT_INIT_MAX_LEN : l; }
static int ee_unwritten(const uint8_t *e) { return rd16(e, EE_len) > EXT_INIT_MAX_LEN; }
static uint64_t ei_leaf(const uint8_t *e) { return rd32(e, EI_leaf_lo) | ((uint64_t)rd16(e, EI_leaf_hi) << 32); }
static void ee_set(uint8_t *e, uint32_t lblk, uint64_t pblk, uint32_t len, int unwritten)
{
    wr32(e, EE_block, lblk);
    wr16(e, EE_len, (uint16_t)(unwritten ? len + EXT_INIT_MAX_LEN : len));
    wr16(e, EE_start_hi, (uint16_t)(pblk >> 32));
    wr32(e, EE_start_lo, (uint32_t)pblk);
}
static void ei_set(uint8_t *e, uint32_t lblk, uint64_t leaf)
{
    wr32(e, EI_block, lblk);
    wr32(e, EI_leaf_lo, (uint32_t)leaf);
    wr16(e, EI_leaf_hi, (uint16_t)(leaf >> 32));
    wr16(e, 10, 0);
}

/* Structural validation of one node: header, capacity, ordering, block ranges. */
static int node_ok(sfs_fs *fs, const uint8_t *h, int is_root, int want_depth)
{
    uint32_t n = rd16(h, EH_entries), max = rd16(h, EH_max), depth = rd16(h, EH_depth), i;
    uint32_t cap = is_root ? (IN_BLOCK_BYTES - EH_SIZE) / EE_SIZE : fs->ext_per_block;
    uint64_t prev_end = 0;
    if (rd16(h, EH_magic) != EXT_MAGIC || n > max || max == 0 || max > cap) return 0;
    if (depth > EXT_MAX_DEPTH || (want_depth >= 0 && depth != (uint32_t)want_depth)) return 0;
    for (i = 0; i < n; ++i) {
        const uint8_t *e = ENT(h, i);
        uint32_t lb = rd32(e, EE_block);
        if (i && lb < prev_end) return 0;
        if (depth == 0) {
            uint32_t len = ee_len(e);
            uint64_t st = ee_start(e);
            if (len == 0 || (uint64_t)lb + len > 0x100000000ull || !sfs_range_valid(fs, st, len)) return 0;
            prev_end = (uint64_t)lb + len;
        } else {
            if (!sfs_block_valid(fs, ei_leaf(e))) return 0;
            prev_end = (uint64_t)lb + 1;
        }
    }
    return 1;
}

static void node_csum_set(sfs_fs *fs, sfs_inode *in, sfs_buf *b)
{
    if (fs->csum) {
        uint32_t off = EH_SIZE + rd16(b->data, EH_max) * EE_SIZE;
        wr32(b->data, off, sfs_crc32c(in->csum_seed, b->data, off));
    }
}

int sfs_ext_verify_block(sfs_fs *fs, sfs_inode *in, sfs_buf *b, int depth)
{
    if (b->flags & B_VERIFIED) return 0;
    if (!node_ok(fs, b->data, 0, depth)) return SFS_ECORRUPT;
    if (fs->csum) {
        uint32_t off = EH_SIZE + rd16(b->data, EH_max) * EE_SIZE;
        if (off + 4 > fs->bs || rd32(b->data, off) != sfs_crc32c(in->csum_seed, b->data, off)) {
            sfs_logu(fs, "sfs: extent block checksum mismatch, inode ", in->ino);
            return SFS_ECORRUPT;
        }
    }
    b->flags |= B_VERIFIED;
    return 0;
}

static int read_node(sfs_fs *fs, sfs_inode *in, uint64_t blk, int depth, sfs_buf **out)
{
    sfs_buf *b;
    int rc;
    if (!sfs_block_valid(fs, blk)) return SFS_ECORRUPT;
    rc = sfs_bread(fs, blk, &b);
    if (rc) return rc;
    rc = sfs_ext_verify_block(fs, in, b, depth);
    if (rc) { sfs_bput(fs, b); return rc; }
    *out = b;
    return 0;
}

static void path_put(sfs_fs *fs, xpath *p, int depth)
{
    int l;
    for (l = 1; l <= depth; ++l) if (p[l].b) { sfs_bput(fs, p[l].b); p[l].b = 0; }
}

/* Last entry with key <= lblk, -1 when lblk precedes every key. */
static int search(const uint8_t *h, uint32_t lblk)
{
    int lo = 0, hi = (int)rd16(h, EH_entries) - 1, ans = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (rd32(ENT(h, mid), EE_block) <= lblk) { ans = mid; lo = mid + 1; }
        else hi = mid - 1;
    }
    return ans;
}

static int find_path(sfs_fs *fs, sfs_inode *in, uint32_t lblk, xpath *p, int *depth_out)
{
    int depth, l;
    if (!node_ok(fs, in->iblock, 1, -1)) return SFS_ECORRUPT;
    depth = rd16(in->iblock, EH_depth);
    p[0].b = 0;
    p[0].h = in->iblock;
    for (l = 0;; ++l) {
        const uint8_t *h = p[l].h;
        int idx = search(h, lblk);
        if (l == depth) { p[l].idx = idx; break; }
        if (rd16(h, EH_entries) == 0) { path_put(fs, p, l); return SFS_ECORRUPT; }
        if (idx < 0) idx = 0;
        p[l].idx = idx;
        {
            sfs_buf *b;
            int rc = read_node(fs, in, ei_leaf(ENT(h, idx)), depth - l - 1, &b);
            if (rc) { path_put(fs, p, l); return rc; }
            p[l + 1].b = b;
            p[l + 1].h = b->data;
        }
    }
    *depth_out = depth;
    return 0;
}

static int node_dirty(sfs_fs *fs, sfs_inode *in, xpath *pe)
{
    if (!pe->b) { sfs_idirty(fs, in); return 0; }
    node_csum_set(fs, in, pe->b);
    return sfs_bdirty_meta(fs, pe->b);
}

/* ---- lookup ---- */
int sfs_map_block(sfs_fs *fs, sfs_inode *in, uint32_t lblk, uint64_t *pblk, uint32_t *len, int *unwritten)
{
    xpath p[EXT_MAX_DEPTH + 1];
    int depth, rc, l, idx;
    uint64_t next = 0x100000000ull;
    const uint8_t *h;
    *unwritten = 0;
    if (!(in->flags & IFL_EXTENTS)) return sfs_bmap_lookup(fs, in, lblk, pblk, len);
    if (in->ec_valid && lblk >= in->ec_lblk && lblk - in->ec_lblk < in->ec_len) {
        fs->st.extent_cache_hits++;
        *pblk = in->ec_pblk + (lblk - in->ec_lblk);
        *len = in->ec_len - (lblk - in->ec_lblk);
        *unwritten = in->ec_unwritten;
        return 1;
    }
    fs->st.extent_cache_misses++;
    rc = find_path(fs, in, lblk, p, &depth);
    if (rc) return rc;
    h = p[depth].h;
    idx = p[depth].idx;
    if (idx >= 0) {
        const uint8_t *e = ENT(h, idx);
        uint32_t eb = rd32(e, EE_block), el = ee_len(e);
        if (lblk - eb < el) {
            uint64_t st = ee_start(e);
            *pblk = st + (lblk - eb);
            *len = el - (lblk - eb);
            *unwritten = ee_unwritten(e);
            if (!(fs->mflags & SFS_MOUNT_NAIVE)) {
                in->ec_valid = 1;
                in->ec_lblk = eb;
                in->ec_len = el;
                in->ec_pblk = st;
                in->ec_unwritten = *unwritten;
            }
            path_put(fs, p, depth);
            return 1;
        }
    }
    if (idx + 1 < (int)rd16(h, EH_entries)) next = rd32(ENT(h, idx + 1), EE_block);
    else {
        for (l = depth - 1; l >= 0; --l) {
            if (p[l].idx + 1 < (int)rd16(p[l].h, EH_entries)) { next = rd32(ENT(p[l].h, p[l].idx + 1), EI_block); break; }
        }
    }
    path_put(fs, p, depth);
    *len = next - lblk > 0xFFFFFFFFull ? 0xFFFFFFFFu : (uint32_t)(next - lblk);
    if (*len == 0) *len = 1;
    return 0;
}

/* ---- insertion ---- */
static void fix_parents(sfs_fs *fs, sfs_inode *in, xpath *p, int level)
{
    uint32_t key = rd32(ENT(p[level].h, 0), EE_block);
    int l;
    for (l = level - 1; l >= 0; --l) {
        uint8_t *e = ENT(p[l].h, p[l].idx);
        if (rd32(e, EI_block) != key) {
            wr32(e, EI_block, key);
            node_dirty(fs, in, &p[l]);
        }
        if (p[l].idx != 0) break;
    }
}

static int new_node_block(sfs_fs *fs, sfs_inode *in, uint64_t near, sfs_buf **out)
{
    uint64_t blk;
    int rc = sfs_alloc_meta_block(fs, in, near, &blk);
    if (rc) return rc;
    rc = sfs_bnew(fs, blk, out);
    if (rc) { sfs_free_blocks(fs, blk, 1, 1); return rc; }
    rc = sfs_add_blocks(fs, in, 1);
    if (rc) { sfs_bput(fs, *out); sfs_free_blocks(fs, blk, 1, 1); return rc; }
    return 0;
}

static int grow_root(sfs_fs *fs, sfs_inode *in)
{
    uint8_t *r = in->iblock;
    uint32_t n = rd16(r, EH_entries), depth = rd16(r, EH_depth);
    sfs_buf *b;
    int rc;
    if (depth >= EXT_MAX_DEPTH) return SFS_EFBIG;
    rc = new_node_block(fs, in, in->last_pblk ? in->last_pblk : sfs_goal_for(fs, in, 0), &b);
    if (rc) return rc;
    wr16(b->data, EH_magic, EXT_MAGIC);
    wr16(b->data, EH_entries, (uint16_t)n);
    wr16(b->data, EH_max, (uint16_t)fs->ext_per_block);
    wr16(b->data, EH_depth, (uint16_t)depth);
    memcpy(ENT(b->data, 0), ENT(r, 0), n * EE_SIZE);
    node_csum_set(fs, in, b);
    rc = sfs_bdirty_meta(fs, b);
    wr16(r, EH_entries, 1);
    wr16(r, EH_depth, (uint16_t)(depth + 1));
    memset(ENT(r, 0), 0, 4 * EE_SIZE);
    ei_set(ENT(r, 0), n ? rd32(ENT(b->data, 0), EE_block) : 0, b->blk);
    sfs_bput(fs, b);
    sfs_idirty(fs, in);
    return rc;
}

/* Makes room in the node at `level` of the path (splitting parents first if needed). The caller re-walks. */
static int split(sfs_fs *fs, sfs_inode *in, xpath *p, int depth, int level, uint32_t lblk)
{
    uint8_t *h, *ph;
    uint32_t n, m, key;
    sfs_buf *nb;
    int rc, pidx;
    if (level == 0) return grow_root(fs, in);
    ph = p[level - 1].h;
    if (rd16(ph, EH_entries) >= rd16(ph, EH_max)) return split(fs, in, p, depth, level - 1, lblk);
    h = p[level].h;
    n = rd16(h, EH_entries);
    if (level == depth && p[level].idx == (int)n - 1 && n &&
        lblk >= rd32(ENT(h, n - 1), EE_block) + ee_len(ENT(h, n - 1)))
        m = n;                                   /* appending: start a fresh leaf, keep this one full */
    else
        m = n / 2;
    rc = new_node_block(fs, in, p[level].b->blk, &nb);
    if (rc) return rc;
    wr16(nb->data, EH_magic, EXT_MAGIC);
    wr16(nb->data, EH_entries, (uint16_t)(n - m));
    wr16(nb->data, EH_max, (uint16_t)fs->ext_per_block);
    wr16(nb->data, EH_depth, rd16(h, EH_depth));
    memcpy(ENT(nb->data, 0), ENT(h, m), (n - m) * EE_SIZE);
    key = n > m ? rd32(ENT(nb->data, 0), EE_block) : lblk;
    wr16(h, EH_entries, (uint16_t)m);
    memset(ENT(h, m), 0, (n - m) * EE_SIZE);
    node_csum_set(fs, in, nb);
    rc = sfs_bdirty_meta(fs, nb);
    if (!rc) rc = node_dirty(fs, in, &p[level]);
    pidx = p[level - 1].idx + 1;
    memmove(ENT(ph, pidx + 1), ENT(ph, pidx), (rd16(ph, EH_entries) - pidx) * EE_SIZE);
    ei_set(ENT(ph, pidx), key, nb->blk);
    wr16(ph, EH_entries, (uint16_t)(rd16(ph, EH_entries) + 1));
    if (!rc) rc = node_dirty(fs, in, &p[level - 1]);
    sfs_bput(fs, nb);
    return rc;
}

static int insert_one(sfs_fs *fs, sfs_inode *in, uint32_t lblk, uint64_t pblk, uint32_t len, int unwritten)
{
    int tries;
    for (tries = 0; tries < (int)(3 * (EXT_MAX_DEPTH + 2)); ++tries) {
        xpath p[EXT_MAX_DEPTH + 1];
        int depth, idx, rc;
        uint32_t n;
        uint8_t *h;
        rc = find_path(fs, in, lblk, p, &depth);
        if (rc) return rc;
        h = p[depth].h;
        idx = p[depth].idx;
        n = rd16(h, EH_entries);
        if (idx >= 0) {
            uint8_t *e = ENT(h, idx);
            uint32_t eb = rd32(e, EE_block), el = ee_len(e);
            if (lblk - eb < el) { path_put(fs, p, depth); return SFS_ECORRUPT; }      /* already mapped */
            if (!unwritten && !ee_unwritten(e) && eb + el == lblk && ee_start(e) + el == pblk && el + len <= EXT_INIT_MAX_LEN) {
                ee_set(e, eb, ee_start(e), el + len, 0);
                rc = node_dirty(fs, in, &p[depth]);
                path_put(fs, p, depth);
                return rc;
            }
        }
        if (idx + 1 < (int)n) {
            uint8_t *e = ENT(h, idx + 1);
            uint32_t eb = rd32(e, EE_block), el = ee_len(e);
            if ((uint64_t)lblk + len > eb) { path_put(fs, p, depth); return SFS_ECORRUPT; }
            if (!unwritten && !ee_unwritten(e) && lblk + len == eb && pblk + len == ee_start(e) && el + len <= EXT_INIT_MAX_LEN) {
                ee_set(e, lblk, pblk, el + len, 0);
                rc = node_dirty(fs, in, &p[depth]);
                if (idx + 1 == 0 && depth) fix_parents(fs, in, p, depth);
                path_put(fs, p, depth);
                return rc;
            }
        }
        if (n < rd16(h, EH_max)) {
            memmove(ENT(h, idx + 2), ENT(h, idx + 1), (n - (uint32_t)(idx + 1)) * EE_SIZE);
            ee_set(ENT(h, idx + 1), lblk, pblk, len, unwritten);
            wr16(h, EH_entries, (uint16_t)(n + 1));
            rc = node_dirty(fs, in, &p[depth]);
            if (idx + 1 == 0 && depth) fix_parents(fs, in, p, depth);
            path_put(fs, p, depth);
            return rc;
        }
        rc = split(fs, in, p, depth, depth, lblk);
        path_put(fs, p, depth);
        if (rc) return rc;
    }
    return SFS_ECORRUPT;
}

int sfs_ext_insert(sfs_fs *fs, sfs_inode *in, uint32_t lblk, uint64_t pblk, uint32_t len)
{
    in->ec_valid = 0;
    while (len) {
        uint32_t n = len > EXT_INIT_MAX_LEN ? EXT_INIT_MAX_LEN : len;
        int rc = insert_one(fs, in, lblk, pblk, n, 0);
        if (rc) return rc;
        in->last_lblk = lblk + n - 1;
        in->last_pblk = pblk + n - 1;
        lblk += n;
        pblk += n;
        len -= n;
    }
    return 0;
}

int sfs_ext_mark_written(sfs_fs *fs, sfs_inode *in, uint32_t lblk)
{
    xpath p[EXT_MAX_DEPTH + 1];
    int depth, rc;
    in->ec_valid = 0;
    rc = find_path(fs, in, lblk, p, &depth);
    if (rc) return rc;
    if (p[depth].idx >= 0) {
        uint8_t *e = ENT(p[depth].h, p[depth].idx);
        if (ee_unwritten(e) && lblk - rd32(e, EE_block) < ee_len(e)) {
            ee_set(e, rd32(e, EE_block), ee_start(e), ee_len(e), 0);
            rc = node_dirty(fs, in, &p[depth]);
        }
    }
    path_put(fs, p, depth);
    return rc;
}

/* ---- truncation ---- */
static int free_tree_block(sfs_fs *fs, sfs_inode *in, uint64_t blk)
{
    int rc = sfs_free_blocks(fs, blk, 1, 1);
    if (!rc) rc = sfs_add_blocks(fs, in, -1);
    return rc;
}

static int rm_node(sfs_fs *fs, sfs_inode *in, xpath *pe, int depth, uint32_t first, int meta, int level)
{
    uint8_t *h = pe->h;
    int i, rc = 0, changed = 0;
    if (depth == 0) {
        for (i = (int)rd16(h, EH_entries) - 1; i >= 0; --i) {
            uint8_t *e = ENT(h, i);
            uint32_t eb = rd32(e, EE_block), el = ee_len(e);
            uint64_t st = ee_start(e);
            if (eb >= first) {
                rc = sfs_free_blocks(fs, st, el, meta);
                if (!rc) rc = sfs_add_blocks(fs, in, -(int64_t)el);
                memset(e, 0, EE_SIZE);
                wr16(h, EH_entries, (uint16_t)i);
                changed = 1;
            } else if (eb + el > first) {
                uint32_t keep = first - eb;
                rc = sfs_free_blocks(fs, st + keep, el - keep, meta);
                if (!rc) rc = sfs_add_blocks(fs, in, -(int64_t)(el - keep));
                ee_set(e, eb, st, keep, ee_unwritten(e));
                changed = 1;
                break;
            } else {
                break;
            }
            if (rc) break;
        }
    } else {
        for (i = (int)rd16(h, EH_entries) - 1; i >= 0 && !rc; --i) {
            uint8_t *e = ENT(h, i);
            uint32_t key = rd32(e, EI_block);
            xpath child;
            if (level >= (int)EXT_MAX_DEPTH) return SFS_ECORRUPT;
            rc = read_node(fs, in, ei_leaf(e), depth - 1, &child.b);
            if (rc) break;
            child.h = child.b->data;
            rc = rm_node(fs, in, &child, depth - 1, first, meta, level + 1);
            if (!rc && rd16(child.h, EH_entries) == 0) {
                uint64_t cb = child.b->blk;
                sfs_bput(fs, child.b);
                rc = free_tree_block(fs, in, cb);
                memset(e, 0, EE_SIZE);
                wr16(h, EH_entries, (uint16_t)i);
                changed = 1;
            } else {
                sfs_bput(fs, child.b);
            }
            if (key < first) break;
        }
    }
    if (changed) {
        int d = node_dirty(fs, in, pe);
        if (!rc) rc = d;
    }
    return rc;
}

int sfs_ext_truncate(sfs_fs *fs, sfs_inode *in, uint32_t first, int meta)
{
    xpath root;
    uint8_t *r = in->iblock;
    int rc;
    in->ec_valid = 0;
    if (!node_ok(fs, r, 1, -1)) return SFS_ECORRUPT;
    root.b = 0;
    root.h = r;
    rc = rm_node(fs, in, &root, rd16(r, EH_depth), first, meta, 0);
    if (rc) return rc;
    if (rd16(r, EH_entries) == 0) {
        sfs_ext_root_init(r);
        sfs_idirty(fs, in);
    }
    /* Collapse: a single child whose entries fit in the inode moves up. */
    while (rd16(r, EH_depth) > 0 && rd16(r, EH_entries) == 1) {
        sfs_buf *b;
        uint32_t cn, cd = rd16(r, EH_depth) - 1u;
        uint64_t cb = ei_leaf(ENT(r, 0));
        rc = read_node(fs, in, cb, (int)cd, &b);
        if (rc) return rc;
        cn = rd16(b->data, EH_entries);
        if (cn > (IN_BLOCK_BYTES - EH_SIZE) / EE_SIZE || cn == 0) { sfs_bput(fs, b); break; }
        memset(ENT(r, 0), 0, 4 * EE_SIZE);
        memcpy(ENT(r, 0), ENT(b->data, 0), cn * EE_SIZE);
        wr16(r, EH_entries, (uint16_t)cn);
        wr16(r, EH_depth, (uint16_t)cd);
        sfs_bput(fs, b);
        sfs_idirty(fs, in);
        rc = free_tree_block(fs, in, cb);
        if (rc) return rc;
    }
    return 0;
}

/* ---- iteration ---- */
typedef int (*ext_fn)(void *ctx, uint32_t lblk, uint64_t pblk, uint32_t len, int unwritten);

static int iter_node(sfs_fs *fs, sfs_inode *in, const uint8_t *h, int depth, ext_fn fn, void *ctx, int level)
{
    uint32_t i, n = rd16(h, EH_entries);
    for (i = 0; i < n; ++i) {
        const uint8_t *e = ENT(h, i);
        int rc;
        if (depth == 0) {
            rc = fn(ctx, rd32(e, EE_block), ee_start(e), ee_len(e), ee_unwritten(e));
        } else {
            sfs_buf *b;
            if (level >= (int)EXT_MAX_DEPTH) return SFS_ECORRUPT;
            rc = read_node(fs, in, ei_leaf(e), depth - 1, &b);
            if (rc) return rc;
            rc = iter_node(fs, in, b->data, depth - 1, fn, ctx, level + 1);
            sfs_bput(fs, b);
        }
        if (rc) return rc;
    }
    return 0;
}

int sfs_ext_iterate(sfs_fs *fs, sfs_inode *in, ext_fn fn, void *ctx)
{
    if (!(in->flags & IFL_EXTENTS)) return SFS_ENOTSUP;
    if (!node_ok(fs, in->iblock, 1, -1)) return SFS_ECORRUPT;
    return iter_node(fs, in, in->iblock, rd16(in->iblock, EH_depth), fn, ctx, 0);
}

/* ---- legacy block maps (ext2/ext3): i_block[0..11] direct, [12] indirect, [13] double, [14] triple ---- */
static int bmap_read_ptr(sfs_fs *fs, uint64_t blk, uint32_t idx, uint32_t *out)
{
    sfs_buf *b;
    int rc;
    if (!sfs_block_valid(fs, blk)) return SFS_ECORRUPT;
    rc = sfs_bread(fs, blk, &b);
    if (rc) return rc;
    *out = rd32(b->data, (size_t)idx * 4);
    sfs_bput(fs, b);
    return 0;
}

int sfs_bmap_lookup(sfs_fs *fs, sfs_inode *in, uint32_t lblk, uint64_t *pblk, uint32_t *len)
{
    uint32_t apb = fs->bs / 4, level, idx[4], i, p;
    uint64_t span = 1;
    uint32_t rel = lblk;
    if (lblk < 12) {
        p = rd32(in->iblock, lblk * 4);
        if (!p) { *len = 1; return 0; }
        if (!sfs_block_valid(fs, p)) return SFS_ECORRUPT;
        for (i = lblk + 1; i < 12 && rd32(in->iblock, i * 4) == p + (i - lblk); ++i) {}
        *pblk = p;
        *len = i - lblk;
        return 1;
    }
    rel -= 12;
    for (level = 1; level <= 3; ++level) {
        span *= apb;
        if (rel < span) break;
        rel -= (uint32_t)span;
    }
    if (level > 3) { *len = 1; return 0; }
    p = rd32(in->iblock, (11 + level) * 4);
    for (i = level; i > 0; --i) { idx[i - 1] = rel % apb; rel /= apb; }
    for (i = 0; i < level; ++i) {
        uint32_t next;
        int rc;
        if (!p) { *len = 1; return 0; }
        if (i + 1 == level) {
            sfs_buf *b;
            uint32_t j, first;
            if (!sfs_block_valid(fs, p)) return SFS_ECORRUPT;
            rc = sfs_bread(fs, p, &b);
            if (rc) return rc;
            first = rd32(b->data, (size_t)idx[i] * 4);
            if (!first) { sfs_bput(fs, b); *len = 1; return 0; }
            for (j = idx[i] + 1; j < apb && rd32(b->data, (size_t)j * 4) == first + (j - idx[i]); ++j) {}
            sfs_bput(fs, b);
            if (!sfs_range_valid(fs, first, j - idx[i])) return SFS_ECORRUPT;
            *pblk = first;
            *len = j - idx[i];
            return 1;
        }
        rc = bmap_read_ptr(fs, p, idx[i], &next);
        if (rc) return rc;
        p = next;
    }
    *len = 1;
    return 0;
}

typedef struct { uint64_t start; uint32_t len; } run_acc;

static int acc_flush(sfs_fs *fs, run_acc *a, int meta)
{
    int rc = 0;
    if (a->len) rc = sfs_free_blocks(fs, a->start, a->len, meta);
    a->len = 0;
    return rc;
}

static int acc_add(sfs_fs *fs, run_acc *a, uint64_t blk, int meta)
{
    if (a->len && a->start + a->len == blk && a->len < 0x10000) { a->len++; return 0; }
    {
        int rc = acc_flush(fs, a, meta);
        a->start = blk;
        a->len = 1;
        return rc;
    }
}

static int bmap_rel_ind(sfs_fs *fs, uint64_t blk, int level, run_acc *a, int meta, uint64_t *freed)
{
    sfs_buf *b;
    uint32_t i, apb = fs->bs / 4;
    int rc;
    if (!sfs_block_valid(fs, blk)) return SFS_ECORRUPT;
    rc = sfs_bread(fs, blk, &b);
    if (rc) return rc;
    for (i = 0; i < apb && !rc; ++i) {
        uint32_t p = rd32(b->data, (size_t)i * 4);
        if (!p) continue;
        if (!sfs_block_valid(fs, p)) { rc = SFS_ECORRUPT; break; }
        if (level > 1) rc = bmap_rel_ind(fs, p, level - 1, a, meta, freed);
        else { rc = acc_add(fs, a, p, meta); (*freed)++; }
    }
    sfs_bput(fs, b);
    if (!rc) rc = acc_flush(fs, a, meta);
    if (!rc) { rc = sfs_free_blocks(fs, blk, 1, 1); (*freed)++; }
    return rc;
}

int sfs_bmap_release(sfs_fs *fs, sfs_inode *in, int meta)
{
    run_acc a = {0, 0};
    uint64_t freed = 0;
    uint32_t i;
    int rc = 0;
    for (i = 0; i < 12 && !rc; ++i) {
        uint32_t p = rd32(in->iblock, i * 4);
        if (!p) continue;
        if (!sfs_block_valid(fs, p)) return SFS_ECORRUPT;
        rc = acc_add(fs, &a, p, meta);
        freed++;
    }
    if (!rc) rc = acc_flush(fs, &a, meta);
    for (i = 0; i < 3 && !rc; ++i) {
        uint32_t p = rd32(in->iblock, (12 + i) * 4);
        if (p) rc = bmap_rel_ind(fs, p, (int)i + 1, &a, meta, &freed);
    }
    if (rc) return rc;
    memset(in->iblock, 0, IN_BLOCK_BYTES);
    return sfs_add_blocks(fs, in, -(int64_t)freed);
}
