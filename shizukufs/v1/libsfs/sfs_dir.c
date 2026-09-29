/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS v1 directories.
 *
 * Leaf blocks hold ext4 directory entries (inode, rec_len, name_len, file_type, name) and, with metadata_csum, a
 * 12-byte tail entry carrying the block's crc32c. Indexed (htree) directories keep a dx root in block 0 ("." and
 * ".." followed by dx_root_info and the hash -> block index), optional interior dx nodes and hash-ordered leaves.
 *
 * Lookups hash the name and walk the index (following collision continuations); linear directories are scanned.
 * Inserts keep the index valid: full leaves are split at the middle by size with the continuation bit set when a
 * hash straddles the split, full index nodes are split, a full root grows a level, and a single-block linear
 * directory that fills up is converted to an indexed one. When the index cannot grow further (root full at the
 * maximum depth), the index is dropped as the format allows: the root and interior blocks are rewritten as ordinary
 * leaf blocks and the index flag is cleared, leaving a valid linear directory.
 */
#include "sfs_internal.h"

#define KIND_LEAF 0
#define KIND_ROOT 1
#define KIND_NODE 2

static uint32_t name_len_of(sfs_fs *fs, const uint8_t *de) { return fs->filetype ? de[DE_name_len] : rd16(de, DE_name_len); }
static uint32_t rec_min(uint32_t name_len) { return (DE_HDR + name_len + 3) & ~3u; }
static uint32_t leaf_limit(sfs_fs *fs) { return fs->csum ? fs->bs - DE_TAIL_SIZE : fs->bs; }

uint8_t sfs_mode_to_ft(uint16_t mode)
{
    switch (mode & SFS_S_IFMT) {
    case 0x8000: return SFS_FT_REG;
    case 0x4000: return SFS_FT_DIR;
    case 0x2000: return SFS_FT_CHR;
    case 0x6000: return SFS_FT_BLK;
    case 0x1000: return SFS_FT_FIFO;
    case 0xC000: return SFS_FT_SOCK;
    case 0xA000: return SFS_FT_SYMLINK;
    default: return SFS_FT_UNKNOWN;
    }
}

static void de_set(sfs_fs *fs, uint8_t *de, uint32_t ino, uint32_t rec_len, const char *name, uint32_t len, uint8_t type)
{
    wr32(de, DE_inode, ino);
    wr16(de, DE_rec_len, (uint16_t)rec_len);
    if (fs->filetype) {
        de[DE_name_len] = (uint8_t)len;
        de[DE_file_type] = type;
    } else {
        wr16(de, DE_name_len, (uint16_t)len);
    }
    memcpy(de + DE_name, name, len);
}

/* ---- checksums ---- */
static void leaf_tail_set(sfs_fs *fs, sfs_inode *dir, uint8_t *blk)
{
    uint8_t *t;
    if (!fs->csum) return;
    t = blk + fs->bs - DE_TAIL_SIZE;
    wr32(t, 0, 0);
    wr16(t, 4, DE_TAIL_SIZE);
    t[6] = 0;
    t[7] = DE_TAIL_FT;
    wr32(t, 8, sfs_crc32c(dir->csum_seed, blk, fs->bs - DE_TAIL_SIZE));
}

static int leaf_tail_ok(sfs_fs *fs, sfs_inode *dir, const uint8_t *blk)
{
    const uint8_t *t = blk + fs->bs - DE_TAIL_SIZE;
    if (rd32(t, 0) != 0 || rd16(t, 4) != DE_TAIL_SIZE || t[6] != 0 || t[7] != DE_TAIL_FT) return 0;
    return rd32(t, 8) == sfs_crc32c(dir->csum_seed, blk, fs->bs - DE_TAIL_SIZE);
}

static uint32_t dx_limit_for(sfs_fs *fs, uint32_t cl) { return (fs->bs - cl - (fs->csum ? DX_TAIL_SIZE : 0)) / DXE_SIZE; }

static uint32_t dx_csum(sfs_fs *fs, sfs_inode *dir, const uint8_t *blk, uint32_t cl)
{
    static const uint8_t zero4[4] = {0, 0, 0, 0};
    uint32_t limit = rd16(blk, cl), count = rd16(blk, cl + 2);
    uint32_t c = sfs_crc32c(dir->csum_seed, blk, cl + count * DXE_SIZE);
    c = sfs_crc32c(c, blk + cl + limit * DXE_SIZE, 4);
    return sfs_crc32c(c, zero4, 4);
}

static void dx_csum_set(sfs_fs *fs, sfs_inode *dir, uint8_t *blk, uint32_t cl)
{
    if (!fs->csum) return;
    wr32(blk, cl + rd16(blk, cl) * DXE_SIZE + 4, dx_csum(fs, dir, blk, cl));
}

/* ---- verification ---- */
static int leaf_ok(sfs_fs *fs, sfs_inode *dir, const uint8_t *blk)
{
    uint32_t off = 0, limit = leaf_limit(fs);
    if (fs->csum && !leaf_tail_ok(fs, dir, blk)) return 0;
    while (off < limit) {
        const uint8_t *de = blk + off;
        uint32_t rl, nl;
        if (limit - off < DE_HDR) return 0;
        rl = rd16(de, DE_rec_len);
        nl = name_len_of(fs, de);
        if (rl < 12 || (rl & 3) || rl > limit - off || DE_HDR + nl > rl || nl > SFS_NAME_MAX) return 0;
        if (rd32(de, DE_inode) > fs->inodes_count) return 0;
        off += rl;
    }
    return off == limit;
}

static int dx_countlimit_ok(sfs_fs *fs, sfs_inode *dir, const uint8_t *blk, uint32_t cl)
{
    uint32_t limit = rd16(blk, cl), count = rd16(blk, cl + 2);
    if (limit != dx_limit_for(fs, cl) || count == 0 || count > limit) return 0;
    if (fs->csum && rd32(blk, cl + limit * DXE_SIZE + 4) != dx_csum(fs, dir, blk, cl)) return 0;
    return 1;
}

static int root_ok(sfs_fs *fs, sfs_inode *dir, const uint8_t *blk)
{
    const uint8_t *info = blk + DX_ROOT_INFO;
    uint32_t maxlev = fs->largedir ? 2 : 1;
    if (rd16(blk, DE_rec_len) != 12 || name_len_of(fs, blk) != 1 || blk[DE_name] != '.') return 0;
    if (rd16(blk + 12, DE_rec_len) != fs->bs - 12 || name_len_of(fs, blk + 12) != 2) return 0;
    if (rd32(info, DXI_reserved_zero) != 0 || info[DXI_info_length] != 8 || info[DXI_indirect_levels] > maxlev) return 0;
    return dx_countlimit_ok(fs, dir, blk, DX_ROOT_ENTRIES);
}

static int node_ok(sfs_fs *fs, sfs_inode *dir, const uint8_t *blk)
{
    if (rd32(blk, DE_inode) != 0 || rd16(blk, DE_rec_len) != fs->bs) return 0;
    return dx_countlimit_ok(fs, dir, blk, DX_NODE_ENTRIES);
}

/* Reads directory block lblk and verifies it as `kind`. Returns 1 (and no buffer) for a hole. */
static int dir_block(sfs_fs *fs, sfs_inode *dir, uint32_t lblk, int kind, sfs_buf **out)
{
    uint64_t pblk;
    uint32_t len;
    int unw, rc;
    sfs_buf *b;
    *out = 0;
    if ((uint64_t)lblk >= dir->size >> fs->bs_bits) return SFS_ECORRUPT;
    rc = sfs_map_block(fs, dir, lblk, &pblk, &len, &unw);
    if (rc < 0) return rc;
    if (rc == 0 || unw) return 1;
    rc = sfs_bread(fs, pblk, &b);
    if (rc) return rc;
    if (!(b->flags & B_VERIFIED)) {
        int ok = kind == KIND_LEAF ? leaf_ok(fs, dir, b->data) : kind == KIND_ROOT ? root_ok(fs, dir, b->data) : node_ok(fs, dir, b->data);
        if (!ok) {
            sfs_logu(fs, "sfs: corrupt directory block in inode ", dir->ino);
            sfs_bput(fs, b);
            return SFS_ECORRUPT;
        }
        if (kind == KIND_LEAF) b->flags |= B_VERIFIED;     /* dx blocks are re-checked (cheap, few) */
    }
    *out = b;
    return 0;
}

static int dir_dirty(sfs_fs *fs, sfs_inode *dir, sfs_buf *b, int kind)
{
    if (kind == KIND_LEAF) leaf_tail_set(fs, dir, b->data);
    else dx_csum_set(fs, dir, b->data, kind == KIND_ROOT ? DX_ROOT_ENTRIES : DX_NODE_ENTRIES);
    return sfs_bdirty_meta(fs, b);
}

static int is_indexed(sfs_fs *fs, sfs_inode *dir) { return fs->dir_index && (dir->flags & IFL_INDEX); }

/* ---- leaf operations ---- */
static int leaf_find(sfs_fs *fs, const uint8_t *blk, const char *name, uint32_t len, uint32_t *off_out, uint32_t *prev_out)
{
    uint32_t off = 0, prev = 0xFFFFFFFFu, limit = leaf_limit(fs);
    while (off < limit) {
        const uint8_t *de = blk + off;
        uint32_t rl = rd16(de, DE_rec_len);
        if (rd32(de, DE_inode) && name_len_of(fs, de) == len && !memcmp(de + DE_name, name, len)) {
            *off_out = off;
            if (prev_out) *prev_out = prev;
            return 1;
        }
        prev = off;
        off += rl;
    }
    return 0;
}

static int leaf_insert(sfs_fs *fs, uint8_t *blk, const char *name, uint32_t len, uint32_t ino, uint8_t type)
{
    uint32_t off = 0, limit = leaf_limit(fs), need = rec_min(len);
    while (off < limit) {
        uint8_t *de = blk + off;
        uint32_t rl = rd16(de, DE_rec_len);
        uint32_t used = rd32(de, DE_inode) ? rec_min(name_len_of(fs, de)) : 0;
        if (rl >= used + need) {
            if (used) {
                wr16(de, DE_rec_len, (uint16_t)used);
                de += used;
                rl -= used;
            }
            de_set(fs, de, ino, rl, name, len, type);
            return 1;
        }
        off += rl;
    }
    return 0;
}

/* Builds a leaf block holding the given entries (packed; the last one takes the remaining space). */
typedef struct dmap { uint32_t hash; uint16_t off; uint16_t size; } dmap;

static void leaf_build(sfs_fs *fs, uint8_t *dst, const uint8_t *src, const dmap *m, uint32_t n)
{
    uint32_t i, off = 0, limit = leaf_limit(fs);
    memset(dst, 0, fs->bs);
    for (i = 0; i < n; ++i) {
        const uint8_t *de = src + m[i].off;
        uint32_t sz = rec_min(name_len_of(fs, de));
        memcpy(dst + off, de, sz);
        wr16(dst + off, DE_rec_len, (uint16_t)(i + 1 == n ? limit - off : sz));
        off += sz;
    }
    if (!n) wr16(dst, DE_rec_len, (uint16_t)limit);
}

/* ---- block allocation for directories ---- */
static int dir_append(sfs_fs *fs, sfs_inode *dir, uint32_t *lblk_out, sfs_buf **out)
{
    uint64_t pblk;
    uint32_t got, lblk;
    int rc;
    if (!(dir->flags & IFL_EXTENTS)) return SFS_ENOTSUP;
    if ((dir->size >> fs->bs_bits) >= 0xFFFFFFFFull || (!fs->largedir && dir->size >= 0x80000000ull)) return SFS_ENOSPC;
    lblk = (uint32_t)(dir->size >> fs->bs_bits);
    rc = sfs_alloc_blocks(fs, dir, lblk, sfs_goal_for(fs, dir, lblk), 1, &pblk, &got);
    if (rc) return rc;
    rc = sfs_ext_insert(fs, dir, lblk, pblk, 1);
    if (!rc) rc = sfs_add_blocks(fs, dir, 1);
    if (!rc) rc = sfs_bnew(fs, pblk, out);
    if (rc) return rc;
    dir->size += fs->bs;
    sfs_idirty(fs, dir);
    *lblk_out = lblk;
    return 0;
}

/* ---- dx index ---- */
typedef struct dxframe { sfs_buf *b; uint32_t cl; uint32_t at; } dxframe;

static uint32_t dx_count(const dxframe *f) { return rd16(f->b->data, f->cl + 2); }
static uint32_t dx_limit(const dxframe *f) { return rd16(f->b->data, f->cl); }
static uint32_t dx_hash(const dxframe *f, uint32_t i) { return i ? rd32(f->b->data, f->cl + i * DXE_SIZE) : 0; }
static uint32_t dx_blk(const dxframe *f, uint32_t i) { return rd32(f->b->data, f->cl + i * DXE_SIZE + 4) & 0x0FFFFFFFu; }

static void frames_put(sfs_fs *fs, dxframe *fr, int n)
{
    int i;
    for (i = 0; i < n; ++i) if (fr[i].b) { sfs_bput(fs, fr[i].b); fr[i].b = 0; }
}

static int dx_version(sfs_fs *fs, const uint8_t *root, uint8_t *ver)
{
    uint8_t v = root[DX_ROOT_INFO + DXI_hash_version];
    if (v <= DX_HASH_TEA) v = (uint8_t)(v + fs->hash_unsigned);
    if (v > DX_HASH_TEA_UNSIGNED) return SFS_ENOTSUP;
    *ver = v;
    return 0;
}

static void dx_search(dxframe *f, uint32_t hash)
{
    uint32_t lo = 1, hi = dx_count(f) - 1, at = 0;
    while (lo <= hi && hi != 0xFFFFFFFFu) {
        uint32_t mid = (lo + hi) / 2;
        if (dx_hash(f, mid) <= hash) { at = mid; lo = mid + 1; }
        else hi = mid - 1;
    }
    f->at = at;
}

/* Walks the index for `hash`: fills fr[0..levels], returns the leaf's logical block in *leaf. */
static int dx_probe(sfs_fs *fs, sfs_inode *dir, uint32_t hash, dxframe *fr, int *nfr, uint32_t *leaf)
{
    uint32_t levels, l, nblk = (uint32_t)(dir->size >> fs->bs_bits);
    int rc;
    memset(fr, 0, 3 * sizeof *fr);
    rc = dir_block(fs, dir, 0, KIND_ROOT, &fr[0].b);
    if (rc) return rc > 0 ? SFS_ECORRUPT : rc;
    fr[0].cl = DX_ROOT_ENTRIES;
    levels = fr[0].b->data[DX_ROOT_INFO + DXI_indirect_levels];
    for (l = 0;; ++l) {
        uint32_t blk;
        dx_search(&fr[l], hash);
        blk = dx_blk(&fr[l], fr[l].at);
        if (blk == 0 || blk >= nblk) { frames_put(fs, fr, (int)l + 1); return SFS_ECORRUPT; }
        if (l == levels) { *leaf = blk; break; }
        rc = dir_block(fs, dir, blk, KIND_NODE, &fr[l + 1].b);
        if (rc) { frames_put(fs, fr, (int)l + 1); return rc > 0 ? SFS_ECORRUPT : rc; }
        fr[l + 1].cl = DX_NODE_ENTRIES;
    }
    *nfr = (int)levels + 1;
    return 0;
}

/* Moves to the next leaf when the following index entry continues the same hash. 1 = moved, 0 = done. */
static int dx_next(sfs_fs *fs, sfs_inode *dir, dxframe *fr, int nfr, uint32_t hash, uint32_t *leaf)
{
    int p = nfr - 1;
    for (;;) {
        if (++fr[p].at < dx_count(&fr[p])) break;
        if (p == 0) return 0;
        p--;
    }
    if ((dx_hash(&fr[p], fr[p].at) & ~1u) != hash) return 0;
    while (p < nfr - 1) {
        sfs_buf *b;
        int rc = dir_block(fs, dir, dx_blk(&fr[p], fr[p].at), KIND_NODE, &b);
        if (rc) return rc > 0 ? SFS_ECORRUPT : rc;
        p++;
        sfs_bput(fs, fr[p].b);
        fr[p].b = b;
        fr[p].cl = DX_NODE_ENTRIES;
        fr[p].at = 0;
    }
    *leaf = dx_blk(&fr[nfr - 1], fr[nfr - 1].at);
    if (*leaf == 0 || *leaf >= (uint32_t)(dir->size >> fs->bs_bits)) return SFS_ECORRUPT;
    return 1;
}

/* Finds `name`: returns 0 with the leaf buffer (ref held), entry offset and its predecessor, or an error. */
static int find_entry(sfs_fs *fs, sfs_inode *dir, const char *name, uint32_t len, sfs_buf **bout, uint32_t *off, uint32_t *prev)
{
    int rc;
    if (dir->flags & IFL_INLINE_DATA) return SFS_ENOTSUP;
    if (is_indexed(fs, dir)) {
        dxframe fr[3];
        int nfr;
        uint32_t hash, leaf;
        uint8_t ver;
        sfs_buf *root;
        rc = dir_block(fs, dir, 0, KIND_ROOT, &root);
        if (rc) return rc > 0 ? SFS_ECORRUPT : rc;
        rc = dx_version(fs, root->data, &ver);
        sfs_bput(fs, root);
        if (rc) return rc;
        rc = sfs_dx_hash(fs->hash_seed, ver, name, len, &hash, 0);
        if (rc) return rc;
        fs->st.dx_lookups++;
        rc = dx_probe(fs, dir, hash, fr, &nfr, &leaf);
        if (rc) return rc;
        for (;;) {
            sfs_buf *b;
            rc = dir_block(fs, dir, leaf, KIND_LEAF, &b);
            if (rc) { frames_put(fs, fr, nfr); return rc > 0 ? SFS_ECORRUPT : rc; }
            if (leaf_find(fs, b->data, name, len, off, prev)) {
                frames_put(fs, fr, nfr);
                *bout = b;
                return 0;
            }
            sfs_bput(fs, b);
            rc = dx_next(fs, dir, fr, nfr, hash, &leaf);
            if (rc <= 0) { frames_put(fs, fr, nfr); return rc < 0 ? rc : SFS_ENOENT; }
        }
    } else {
        uint32_t lblk, nblk = (uint32_t)(dir->size >> fs->bs_bits);
        fs->st.linear_lookups++;
        for (lblk = 0; lblk < nblk; ++lblk) {
            sfs_buf *b;
            rc = dir_block(fs, dir, lblk, KIND_LEAF, &b);
            if (rc == 1) continue;
            if (rc) return rc;
            if (leaf_find(fs, b->data, name, len, off, prev)) { *bout = b; return 0; }
            sfs_bput(fs, b);
        }
        return SFS_ENOENT;
    }
}

int sfs_dir_lookup(sfs_fs *fs, sfs_inode *dir, const char *name, size_t len, uint32_t *ino, uint8_t *type)
{
    sfs_buf *b;
    uint32_t off, prev;
    int rc;
    if (!sfs_is_dir(dir)) return SFS_ENOTDIR;
    if (len == 0 || len > SFS_NAME_MAX) return len ? SFS_ENAMETOOLONG : SFS_ENOENT;
    rc = find_entry(fs, dir, name, (uint32_t)len, &b, &off, &prev);
    if (rc) return rc;
    *ino = rd32(b->data + off, DE_inode);
    if (type) *type = fs->filetype ? b->data[off + DE_file_type] : SFS_FT_UNKNOWN;
    sfs_bput(fs, b);
    return 0;
}

/* Drops the index: every dx block becomes an ordinary (empty or "."/"..") leaf and the flag is cleared. */
static int dx_clear(sfs_fs *fs, sfs_inode *dir)
{
    sfs_buf *root;
    uint32_t i, j, levels, limit = leaf_limit(fs);
    int rc = dir_block(fs, dir, 0, KIND_ROOT, &root);
    dxframe f;
    if (rc) return rc > 0 ? SFS_ECORRUPT : rc;
    sfs_log(fs, "sfs: directory index full, converting to a linear directory");
    levels = root->data[DX_ROOT_INFO + DXI_indirect_levels];
    f.b = root;
    f.cl = DX_ROOT_ENTRIES;
    for (i = 0; i < dx_count(&f) && levels >= 1; ++i) {
        sfs_buf *nb;
        dxframe nf;
        rc = dir_block(fs, dir, dx_blk(&f, i), KIND_NODE, &nb);
        if (rc) break;
        nf.b = nb;
        nf.cl = DX_NODE_ENTRIES;
        for (j = 0; j < dx_count(&nf) && levels >= 2; ++j) {
            sfs_buf *nb2;
            rc = dir_block(fs, dir, dx_blk(&nf, j), KIND_NODE, &nb2);
            if (rc) break;
            memset(nb2->data, 0, fs->bs);
            wr16(nb2->data, DE_rec_len, (uint16_t)limit);
            rc = dir_dirty(fs, dir, nb2, KIND_LEAF);
            sfs_bput(fs, nb2);
            if (rc) break;
        }
        if (!rc) {
            memset(nb->data, 0, fs->bs);
            wr16(nb->data, DE_rec_len, (uint16_t)limit);
            rc = dir_dirty(fs, dir, nb, KIND_LEAF);
        }
        sfs_bput(fs, nb);
        if (rc) break;
    }
    if (!rc) {
        memset(root->data + 24, 0, fs->bs - 24);
        wr16(root->data + 12, DE_rec_len, (uint16_t)(limit - 12));
        rc = dir_dirty(fs, dir, root, KIND_LEAF);
        root->flags |= B_VERIFIED;
    }
    sfs_bput(fs, root);
    if (rc) return rc < 0 ? rc : SFS_ECORRUPT;
    dir->flags &= ~IFL_INDEX;
    sfs_idirty(fs, dir);
    return 0;
}

static int hash_name(sfs_fs *fs, uint8_t ver, const uint8_t *de, uint32_t *h)
{
    return sfs_dx_hash(fs->hash_seed, ver, (const char *)de + DE_name, name_len_of(fs, de), h, 0);
}

/* Splits a full leaf: upper half (by size, hash order) moves to a new block referenced from frame `f`. */
static int split_leaf(sfs_fs *fs, sfs_inode *dir, uint8_t ver, dxframe *f, sfs_buf *leaf, uint32_t *hash2_out, sfs_buf **newb, uint32_t *newlblk)
{
    dmap *m = sfs_alloc(fs, SFS_MAX_ALLOC);
    uint8_t *tmp = fs->scratch;
    uint32_t n = 0, off = 0, limit = leaf_limit(fs), i, j, size, move, split, hash2, continued, pos;
    int rc;
    if (!m) return SFS_ENOMEM;
    memcpy(tmp, leaf->data, fs->bs);
    while (off < limit && n < SFS_MAX_ALLOC / sizeof(dmap)) {
        uint8_t *de = tmp + off;
        uint32_t rl = rd16(de, DE_rec_len);
        if (rd32(de, DE_inode)) {
            rc = hash_name(fs, ver, de, &m[n].hash);
            if (rc) { sfs_free(fs, m, SFS_MAX_ALLOC); return rc; }
            m[n].off = (uint16_t)off;
            m[n].size = (uint16_t)rec_min(name_len_of(fs, de));
            n++;
        }
        off += rl;
    }
    for (i = 1; i < n; ++i) {                          /* insertion sort by hash (a few hundred entries at most) */
        dmap t = m[i];
        for (j = i; j > 0 && m[j - 1].hash > t.hash; --j) m[j] = m[j - 1];
        m[j] = t;
    }
    size = 0;
    move = 0;
    for (i = n; i-- > 0;) {
        if (size + m[i].size / 2u > fs->bs / 2) break;
        size += m[i].size;
        move++;
    }
    split = n - move;
    if (split == 0) split = 1;
    if (split >= n) split = n - 1;
    if (n < 2) { sfs_free(fs, m, SFS_MAX_ALLOC); return SFS_ECORRUPT; }
    hash2 = m[split].hash;
    continued = hash2 == m[split - 1].hash;
    rc = dir_append(fs, dir, newlblk, newb);
    if (rc) { sfs_free(fs, m, SFS_MAX_ALLOC); return rc; }
    leaf_build(fs, (*newb)->data, tmp, m + split, n - split);
    leaf_build(fs, leaf->data, tmp, m, split);
    sfs_free(fs, m, SFS_MAX_ALLOC);
    rc = dir_dirty(fs, dir, *newb, KIND_LEAF);
    if (!rc) rc = dir_dirty(fs, dir, leaf, KIND_LEAF);
    /* index entry for the new leaf right after the current one */
    pos = f->at + 1;
    memmove(f->b->data + f->cl + (pos + 1) * DXE_SIZE, f->b->data + f->cl + pos * DXE_SIZE, (dx_count(f) - pos) * DXE_SIZE);
    wr32(f->b->data, f->cl + pos * DXE_SIZE, hash2 | continued);
    wr32(f->b->data, f->cl + pos * DXE_SIZE + 4, *newlblk);
    wr16(f->b->data, f->cl + 2, (uint16_t)(dx_count(f) + 1));
    if (!rc) rc = dir_dirty(fs, dir, f->b, f->cl == DX_ROOT_ENTRIES ? KIND_ROOT : KIND_NODE);
    *hash2_out = hash2;
    return rc;
}

/* Makes room for one more entry in frame `level` (all frames up to it are loaded). The caller re-probes. */
static int dx_make_room(sfs_fs *fs, sfs_inode *dir, dxframe *fr, int level, int nfr)
{
    uint32_t maxlev = fs->largedir ? 2 : 1;
    dxframe *f = &fr[level];
    sfs_buf *nb;
    uint32_t nlblk, n, half;
    int rc;
    if (dx_count(f) < dx_limit(f)) return 0;
    if (level == 0) {
        uint8_t *root = f->b->data;
        uint32_t levels = root[DX_ROOT_INFO + DXI_indirect_levels];
        if (levels >= maxlev) return 1;                         /* cannot grow: caller drops the index */
        rc = dir_append(fs, dir, &nlblk, &nb);
        if (rc) return rc;
        n = dx_count(f);
        wr32(nb->data, DE_inode, 0);
        wr16(nb->data, DE_rec_len, (uint16_t)fs->bs);
        memcpy(nb->data + DX_NODE_ENTRIES, root + DX_ROOT_ENTRIES, n * DXE_SIZE);
        wr16(nb->data, DX_NODE_ENTRIES, (uint16_t)dx_limit_for(fs, DX_NODE_ENTRIES));
        wr16(nb->data, DX_NODE_ENTRIES + 2, (uint16_t)n);
        rc = dir_dirty(fs, dir, nb, KIND_NODE);
        sfs_bput(fs, nb);
        memset(root + DX_ROOT_ENTRIES + 8, 0, (n - 1) * DXE_SIZE);
        wr16(root, DX_ROOT_ENTRIES + 2, 1);
        wr32(root, DX_ROOT_ENTRIES + 4, nlblk);
        root[DX_ROOT_INFO + DXI_indirect_levels] = (uint8_t)(levels + 1);
        if (!rc) rc = dir_dirty(fs, dir, f->b, KIND_ROOT);
        return rc ? rc : 2;
    }
    rc = dx_make_room(fs, dir, fr, level - 1, nfr);
    if (rc) return rc;                                           /* restructured (re-probe) or cannot grow */
    /* split this interior node: its upper half moves to a new node referenced from the parent */
    rc = dir_append(fs, dir, &nlblk, &nb);
    if (rc) return rc;
    n = dx_count(f);
    half = n / 2;
    wr32(nb->data, DE_inode, 0);
    wr16(nb->data, DE_rec_len, (uint16_t)fs->bs);
    memcpy(nb->data + DX_NODE_ENTRIES, f->b->data + f->cl + half * DXE_SIZE, (n - half) * DXE_SIZE);
    wr16(nb->data, DX_NODE_ENTRIES, (uint16_t)dx_limit_for(fs, DX_NODE_ENTRIES));
    wr16(nb->data, DX_NODE_ENTRIES + 2, (uint16_t)(n - half));
    {
        uint32_t key = dx_hash(f, half);
        dxframe *p = &fr[level - 1];
        uint32_t pos = p->at + 1;
        memset(f->b->data + f->cl + half * DXE_SIZE, 0, (n - half) * DXE_SIZE);
        wr16(f->b->data, f->cl + 2, (uint16_t)half);
        rc = dir_dirty(fs, dir, nb, KIND_NODE);
        if (!rc) rc = dir_dirty(fs, dir, f->b, KIND_NODE);
        memmove(p->b->data + p->cl + (pos + 1) * DXE_SIZE, p->b->data + p->cl + pos * DXE_SIZE, (dx_count(p) - pos) * DXE_SIZE);
        wr32(p->b->data, p->cl + pos * DXE_SIZE, key);
        wr32(p->b->data, p->cl + pos * DXE_SIZE + 4, nlblk);
        wr16(p->b->data, p->cl + 2, (uint16_t)(dx_count(p) + 1));
        if (!rc) rc = dir_dirty(fs, dir, p->b, p->cl == DX_ROOT_ENTRIES ? KIND_ROOT : KIND_NODE);
    }
    sfs_bput(fs, nb);
    (void)nfr;
    return rc ? rc : 2;
}

static int dx_add(sfs_fs *fs, sfs_inode *dir, const char *name, uint32_t len, uint32_t ino, uint8_t type)
{
    int tries;
    for (tries = 0; tries < 8; ++tries) {
        dxframe fr[3];
        int nfr, rc;
        uint32_t hash, leaf, hash2, nlblk;
        uint8_t ver;
        sfs_buf *lb, *nb;
        rc = dir_block(fs, dir, 0, KIND_ROOT, &lb);
        if (rc) return rc > 0 ? SFS_ECORRUPT : rc;
        rc = dx_version(fs, lb->data, &ver);
        sfs_bput(fs, lb);
        if (!rc) rc = sfs_dx_hash(fs->hash_seed, ver, name, len, &hash, 0);
        if (!rc) rc = dx_probe(fs, dir, hash, fr, &nfr, &leaf);
        if (rc) return rc;
        rc = dir_block(fs, dir, leaf, KIND_LEAF, &lb);
        if (rc) { frames_put(fs, fr, nfr); return rc > 0 ? SFS_ECORRUPT : rc; }
        if (leaf_insert(fs, lb->data, name, len, ino, type)) {
            rc = dir_dirty(fs, dir, lb, KIND_LEAF);
            sfs_bput(fs, lb);
            frames_put(fs, fr, nfr);
            return rc;
        }
        rc = dx_make_room(fs, dir, fr, nfr - 1, nfr);
        if (rc == 1) {                                   /* index at its maximum size: fall back to linear */
            sfs_bput(fs, lb);
            frames_put(fs, fr, nfr);
            rc = dx_clear(fs, dir);
            return rc ? rc : -1000;
        }
        if (rc) {                                        /* 2: restructured, re-probe; < 0: error */
            sfs_bput(fs, lb);
            frames_put(fs, fr, nfr);
            if (rc < 0) return rc;
            continue;
        }
        rc = split_leaf(fs, dir, ver, &fr[nfr - 1], lb, &hash2, &nb, &nlblk);
        if (!rc) {
            sfs_buf *t = hash >= hash2 ? nb : lb;
            if (!leaf_insert(fs, t->data, name, len, ino, type)) rc = SFS_ECORRUPT;
            else rc = dir_dirty(fs, dir, t, KIND_LEAF);
            sfs_bput(fs, nb);
        }
        sfs_bput(fs, lb);
        frames_put(fs, fr, nfr);
        return rc;
    }
    return SFS_ECORRUPT;
}

/* A one-block linear directory that is full becomes indexed: block 0 turns into the dx root, its entries move
 * to a new leaf (block 1). */
static int make_indexed(sfs_fs *fs, sfs_inode *dir, sfs_buf *b0)
{
    sfs_buf *nb;
    uint32_t nlblk, off, limit = leaf_limit(fs), n = 0, parent;
    uint8_t *tmp = fs->scratch;
    dmap *m;
    int rc;
    uint8_t *d = b0->data;
    if (rd16(d, DE_rec_len) != 12 || name_len_of(fs, d) != 1 || name_len_of(fs, d + 12) != 2) return 1;  /* unusual layout */
    m = sfs_alloc(fs, SFS_MAX_ALLOC);
    if (!m) return SFS_ENOMEM;
    parent = rd32(d + 12, DE_inode);
    memcpy(tmp, d, fs->bs);
    off = 12 + rd16(tmp + 12, DE_rec_len);
    while (off < limit && n < SFS_MAX_ALLOC / sizeof(dmap)) {
        uint32_t rl = rd16(tmp + off, DE_rec_len);
        if (rd32(tmp + off, DE_inode)) { m[n].off = (uint16_t)off; m[n].hash = 0; n++; }
        off += rl;
    }
    rc = dir_append(fs, dir, &nlblk, &nb);
    if (rc) { sfs_free(fs, m, SFS_MAX_ALLOC); return rc; }
    leaf_build(fs, nb->data, tmp, m, n);
    sfs_free(fs, m, SFS_MAX_ALLOC);
    rc = dir_dirty(fs, dir, nb, KIND_LEAF);
    sfs_bput(fs, nb);
    if (rc) return rc;
    memset(d, 0, fs->bs);
    de_set(fs, d, dir->ino, 12, ".", 1, SFS_FT_DIR);
    de_set(fs, d + 12, parent, fs->bs - 12, "..", 2, SFS_FT_DIR);
    d[DX_ROOT_INFO + DXI_hash_version] = fs->hash_version;
    d[DX_ROOT_INFO + DXI_info_length] = 8;
    wr16(d, DX_ROOT_ENTRIES, (uint16_t)dx_limit_for(fs, DX_ROOT_ENTRIES));
    wr16(d, DX_ROOT_ENTRIES + 2, 1);
    wr32(d, DX_ROOT_ENTRIES + 4, nlblk);
    b0->flags &= ~B_VERIFIED;
    rc = dir_dirty(fs, dir, b0, KIND_ROOT);
    if (rc) return rc;
    dir->flags |= IFL_INDEX;
    sfs_idirty(fs, dir);
    return 0;
}

int sfs_dir_add(sfs_fs *fs, sfs_inode *dir, const char *name, size_t len, uint32_t ino, uint8_t type)
{
    uint32_t lblk, nblk;
    sfs_buf *b;
    int rc;
    if (!sfs_is_dir(dir)) return SFS_ENOTDIR;
    if (!len || len > SFS_NAME_MAX) return SFS_ENAMETOOLONG;
    if (dir->flags & IFL_INLINE_DATA) return SFS_ENOTSUP;
    if (!fs->filetype) type = 0;
    if (is_indexed(fs, dir)) {
        rc = dx_add(fs, dir, name, (uint32_t)len, ino, type);
        if (rc != -1000) return rc;
    }
    nblk = (uint32_t)(dir->size >> fs->bs_bits);
    for (lblk = 0; lblk < nblk; ++lblk) {
        rc = dir_block(fs, dir, lblk, KIND_LEAF, &b);
        if (rc == 1) continue;
        if (rc) return rc;
        if (leaf_insert(fs, b->data, name, (uint32_t)len, ino, type)) {
            rc = dir_dirty(fs, dir, b, KIND_LEAF);
            sfs_bput(fs, b);
            return rc;
        }
        if (nblk == 1 && fs->dir_index && !(dir->flags & IFL_INDEX) && (dir->flags & IFL_EXTENTS) && !(fs->mflags & SFS_MOUNT_NAIVE)) {
            rc = make_indexed(fs, dir, b);
            sfs_bput(fs, b);
            if (rc < 0) return rc;
            if (rc == 0) {
                rc = dx_add(fs, dir, name, (uint32_t)len, ino, type);
                if (rc != -1000) return rc;
                nblk = (uint32_t)(dir->size >> fs->bs_bits);
                lblk = (uint32_t)-1;
            }
            continue;
        }
        sfs_bput(fs, b);
    }
    rc = dir_append(fs, dir, &lblk, &b);
    if (rc) return rc;
    wr16(b->data, DE_rec_len, (uint16_t)leaf_limit(fs));
    if (!leaf_insert(fs, b->data, name, (uint32_t)len, ino, type)) rc = SFS_ECORRUPT;
    else rc = dir_dirty(fs, dir, b, KIND_LEAF);
    sfs_bput(fs, b);
    return rc;
}

int sfs_dir_remove(sfs_fs *fs, sfs_inode *dir, const char *name, size_t len, uint32_t expect_ino)
{
    sfs_buf *b;
    uint32_t off, prev;
    int rc = find_entry(fs, dir, name, (uint32_t)len, &b, &off, &prev);
    if (rc) return rc;
    if (expect_ino && rd32(b->data + off, DE_inode) != expect_ino) { sfs_bput(fs, b); return SFS_ENOENT; }
    if (prev != 0xFFFFFFFFu) {
        uint8_t *p = b->data + prev;
        wr16(p, DE_rec_len, (uint16_t)(rd16(p, DE_rec_len) + rd16(b->data + off, DE_rec_len)));
        memset(b->data + off, 0, DE_HDR);
    } else {
        wr32(b->data + off, DE_inode, 0);
    }
    rc = dir_dirty(fs, dir, b, KIND_LEAF);
    sfs_bput(fs, b);
    return rc;
}

/* Replaces the inode (and type) of an existing entry (rename over an existing name). */
int sfs_dir_set_inode(sfs_fs *fs, sfs_inode *dir, const char *name, size_t len, uint32_t ino, uint8_t type)
{
    sfs_buf *b;
    uint32_t off, prev;
    int rc = find_entry(fs, dir, name, (uint32_t)len, &b, &off, &prev);
    if (rc) return rc;
    wr32(b->data + off, DE_inode, ino);
    if (fs->filetype) b->data[off + DE_file_type] = type;
    rc = dir_dirty(fs, dir, b, KIND_LEAF);
    sfs_bput(fs, b);
    return rc;
}

/* ---- "." / ".." ---- */
int sfs_dir_init(sfs_fs *fs, sfs_inode *dir, uint32_t parent)
{
    sfs_buf *b;
    uint32_t lblk;
    int rc = dir_append(fs, dir, &lblk, &b);
    if (rc) return rc;
    de_set(fs, b->data, dir->ino, 12, ".", 1, SFS_FT_DIR);
    de_set(fs, b->data + 12, parent, leaf_limit(fs) - 12, "..", 2, SFS_FT_DIR);
    if (!fs->filetype) { b->data[DE_file_type] = 0; b->data[12 + DE_file_type] = 0; }
    rc = dir_dirty(fs, dir, b, KIND_LEAF);
    sfs_bput(fs, b);
    return rc;
}

static int dotdot(sfs_fs *fs, sfs_inode *dir, sfs_buf **bout, int *kind)
{
    sfs_buf *b;
    int rc;
    *kind = is_indexed(fs, dir) ? KIND_ROOT : KIND_LEAF;
    rc = dir_block(fs, dir, 0, *kind, &b);
    if (rc) return rc > 0 ? SFS_ECORRUPT : rc;
    if (name_len_of(fs, b->data) != 1 || b->data[DE_name] != '.' || rd16(b->data, DE_rec_len) != 12 ||
        name_len_of(fs, b->data + 12) != 2 || memcmp(b->data + 12 + DE_name, "..", 2)) {
        sfs_bput(fs, b);
        return SFS_ECORRUPT;
    }
    *bout = b;
    return 0;
}

int sfs_dir_get_parent(sfs_fs *fs, sfs_inode *dir, uint32_t *parent)
{
    sfs_buf *b;
    int kind, rc = dotdot(fs, dir, &b, &kind);
    if (rc) return rc;
    *parent = rd32(b->data + 12, DE_inode);
    sfs_bput(fs, b);
    return 0;
}

int sfs_dir_set_parent(sfs_fs *fs, sfs_inode *dir, uint32_t parent)
{
    sfs_buf *b;
    int kind, rc = dotdot(fs, dir, &b, &kind);
    if (rc) return rc;
    wr32(b->data + 12, DE_inode, parent);
    rc = dir_dirty(fs, dir, b, kind);
    sfs_bput(fs, b);
    return rc;
}

/* ---- enumeration (block order; the cookie is the byte position of the next entry) ---- */
int sfs_dir_next(sfs_fs *fs, sfs_inode *dir, uint64_t *cookie, sfs_dirent *out)
{
    uint64_t nblk = dir->size >> fs->bs_bits;
    if (!sfs_is_dir(dir)) return SFS_ENOTDIR;
    if (dir->flags & IFL_INLINE_DATA) return SFS_ENOTSUP;
    for (;;) {
        uint64_t pos = *cookie;
        uint32_t lblk = (uint32_t)(pos >> fs->bs_bits), start = (uint32_t)(pos & (fs->bs - 1)), off = 0, limit;
        sfs_buf *b;
        int rc, kind = KIND_LEAF;
        if (pos >> fs->bs_bits >= nblk) return 0;
        if (lblk == 0 && is_indexed(fs, dir)) kind = KIND_ROOT;
        {
            uint64_t pblk;
            uint32_t run;
            int unw;
            rc = sfs_map_block(fs, dir, lblk, &pblk, &run, &unw);
            if (rc < 0) return rc;
            if (rc == 0 || unw) { *cookie = (uint64_t)(lblk + 1) << fs->bs_bits; continue; }
            rc = sfs_bread(fs, pblk, &b);
            if (rc) return rc;
        }
        if (kind == KIND_LEAF && rd32(b->data, DE_inode) == 0 && rd16(b->data, DE_rec_len) == fs->bs) {
            /* an index node (or an empty leaf without a tail): no entries */
            if (is_indexed(fs, dir) && !(b->flags & B_VERIFIED) && !node_ok(fs, dir, b->data) && fs->csum) {
                sfs_bput(fs, b);
                return SFS_ECORRUPT;
            }
            sfs_bput(fs, b);
            *cookie = (uint64_t)(lblk + 1) << fs->bs_bits;
            continue;
        }
        if (!(b->flags & B_VERIFIED)) {
            int ok = kind == KIND_ROOT ? root_ok(fs, dir, b->data) : leaf_ok(fs, dir, b->data);
            if (!ok) { sfs_bput(fs, b); return SFS_ECORRUPT; }
            if (kind == KIND_LEAF) b->flags |= B_VERIFIED;
        }
        limit = kind == KIND_ROOT ? 24 : leaf_limit(fs);
        while (off < limit) {
            const uint8_t *de = b->data + off;
            uint32_t rl = rd16(de, DE_rec_len), ino = rd32(de, DE_inode);
            if (kind == KIND_ROOT && off == 12) rl = 12;
            if (off >= start && ino) {
                uint32_t nl = name_len_of(fs, de);
                out->ino = ino;
                out->type = fs->filetype ? de[DE_file_type] : SFS_FT_UNKNOWN;
                out->name_len = (uint8_t)nl;
                memcpy(out->name, de + DE_name, nl);
                out->name[nl] = 0;
                *cookie = ((uint64_t)lblk << fs->bs_bits) + off + rl;
                if (kind == KIND_ROOT && off == 12) *cookie = (uint64_t)(lblk + 1) << fs->bs_bits;
                sfs_bput(fs, b);
                return 1;
            }
            off += rl;
        }
        sfs_bput(fs, b);
        *cookie = (uint64_t)(lblk + 1) << fs->bs_bits;
    }
}

int sfs_dir_is_empty(sfs_fs *fs, sfs_inode *dir)
{
    uint64_t cookie = 0;
    sfs_dirent *de = sfs_alloc(fs, sizeof *de);
    int rc;
    if (!de) return SFS_ENOMEM;
    for (;;) {
        rc = sfs_dir_next(fs, dir, &cookie, de);
        if (rc <= 0) break;
        if ((de->name_len == 1 && de->name[0] == '.') || (de->name_len == 2 && de->name[0] == '.' && de->name[1] == '.')) continue;
        rc = 0;
        goto out;
    }
    if (rc == 0) rc = 1;
out:
    sfs_free(fs, de, sizeof *de);
    return rc;
}
