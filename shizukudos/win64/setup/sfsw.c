/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP: one-pass ShizukuFS v1 (ext4 on-disk format) volume writer and verifying reader. See sfsw.h.
 * Field offsets follow the ext4 on-disk specification (struct ext4_super_block, ext4_group_desc, ext4_inode,
 * ext4_extent_header/ext4_extent/ext4_extent_idx, ext4_dir_entry_2); all fields are little-endian.
 */
#include "sfsw.h"
#include <string.h>

#define B SFSW_BLOCK
#define BPG 32768u                          /* blocks per group = bits in one bitmap block */
#define ISZ 256u                            /* inode size */
#define IPB (B / ISZ)                       /* inodes per block */
#define FIRST_INO 11u
#define ROOT_INO 2u
#define LF_INO 11u
#define LF_BLOCKS 4u                        /* lost+found: 16 KiB like mke2fs */
#define DESC 32u                            /* group descriptor size (no 64bit feature) */
#define MAX_INLINE_EXT 4u
#define LEAF_MAX ((B - 12u) / 12u)          /* 340 extents in one leaf block */
#define EXT_MAX_LEN 32768u

#define COMPAT 0u
#define INCOMPAT_FILETYPE 0x2u
#define INCOMPAT_EXTENTS 0x40u
#define INCOMPAT_64BIT 0x80u
#define INCOMPAT_FLEX_BG 0x200u
#define RO_SPARSE_SUPER 0x1u
#define RO_LARGE_FILE 0x2u
#define RO_EXTRA_ISIZE 0x40u
#define EXTENTS_FL 0x80000u
#define EXT_MAGIC 0xF30Au

typedef struct { uint64_t start; uint32_t lblock, len; } ext_t;

typedef struct {
    char *name;
    uint32_t parent, ino, nsub, first_child, last_child, next_sibling;
    uint16_t name_len;
    uint8_t is_dir;
    uint64_t size;                          /* files: bytes; directories: blocks * 4096 after layout */
    uint32_t nblocks;                       /* data blocks */
    ext_t *ext;
    uint32_t next, ext_cap;
    uint64_t leaf;                          /* depth-1 extent leaf block, 0 = extents live in the inode */
} node_t;

#define NONE 0xffffffffu

struct sfsw {
    sfsw_io io;
    sfsw_params p;
    uint64_t blocks;
    uint32_t groups, ipg, itb, gdt_blocks;
    node_t *n;
    uint32_t count, cap;
    int laid_out, tables_zeroed;
    uint8_t *buf;                           /* one block of scratch */
    uint8_t *big;                           /* ZBUF_BLOCKS blocks of scratch */
};
#define ZBUF_BLOCKS 16u

static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { put16(p, v); put16(p + 2, v >> 16); }
static uint32_t get16(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8; }
static uint32_t get32(const uint8_t *p) { return get16(p) | get16(p + 2) << 16; }

const char *sfsw_strerror(int err)
{
    switch (err) {
    case SFSW_OK: return "ok";
    case SFSW_EIO: return "block I/O error";
    case SFSW_ENOMEM: return "out of memory";
    case SFSW_EINVAL: return "invalid argument";
    case SFSW_ENOSPC: return "volume too small";
    case SFSW_EEXIST: return "name exists";
    case SFSW_ENOENT: return "no such file or directory";
    case SFSW_ESTATE: return "call out of order";
    case SFSW_ECORRUPT: return "on-disk structure is corrupt";
    case SFSW_ENAMETOOLONG: return "name too long";
    case SFSW_ENOTDIR: return "not a directory";
    case SFSW_EUNSUPP: return "unsupported on-disk feature";
    default: return "unknown error";
    }
}

static void *zalloc(sfsw_t *w, size_t n) { return w->io.alloc(w->io.ctx, n); }
static void zfree(sfsw_t *w, void *p) { if (p) w->io.free(w->io.ctx, p); }

/* ---------------------------------------------------------------- geometry */
static int has_super(uint32_t g)
{
    uint32_t b;
    if (g <= 1) return 1;
    for (b = 3; b <= 7; b += 2) {
        uint64_t x = b;
        while (x < g) x *= b;
        if (x == g) return 1;
    }
    return 0;
}

static uint64_t group_start(uint32_t g) { return (uint64_t)g * BPG; }
static uint32_t group_size(const sfsw_t *w, uint32_t g)
{
    const uint64_t end = group_start(g) + BPG;
    return (uint32_t)((end > w->blocks ? w->blocks : end) - group_start(g));
}
static uint32_t group_overhead(const sfsw_t *w, uint32_t g) { return (has_super(g) ? 1 + w->gdt_blocks : 0) + 2 + w->itb; }
static uint64_t block_bitmap_of(const sfsw_t *w, uint32_t g) { return group_start(g) + (has_super(g) ? 1 + w->gdt_blocks : 0); }
static uint64_t inode_bitmap_of(const sfsw_t *w, uint32_t g) { return block_bitmap_of(w, g) + 1; }
static uint64_t inode_table_of(const sfsw_t *w, uint32_t g) { return block_bitmap_of(w, g) + 2; }

static int geometry(sfsw_t *w)
{
    const uint32_t ratio = w->p.inode_ratio ? w->p.inode_ratio : 16384u;
    uint64_t inodes;
    uint32_t last;
    w->blocks = w->p.bytes / B;
    if (w->blocks >= 0xffffffffull) return SFSW_EINVAL;             /* 32-bit block numbers (16 TiB) */
    for (;;) {
        if (w->blocks < 64) return SFSW_ENOSPC;
        w->groups = (uint32_t)((w->blocks + BPG - 1) / BPG);
        inodes = (w->blocks * B) / ratio;
        w->ipg = (uint32_t)((inodes + w->groups - 1) / w->groups);
        w->ipg = (w->ipg + IPB - 1) / IPB * IPB;
        if (w->ipg < 2 * IPB) w->ipg = 2 * IPB;
        if (w->ipg > BPG) w->ipg = BPG;
        w->itb = w->ipg / IPB;
        w->gdt_blocks = (w->groups * DESC + B - 1) / B;
        last = group_size(w, w->groups - 1);
        if (last >= group_overhead(w, w->groups - 1) + 64u) break;
        if (w->groups == 1) return SFSW_ENOSPC;
        w->blocks = group_start(w->groups - 1);                       /* drop a runt last group, like mke2fs */
    }
    return SFSW_OK;
}

/* ---------------------------------------------------------------- tree */
static int grow_nodes(sfsw_t *w)
{
    uint32_t cap = w->cap ? w->cap * 2 : 64;
    node_t *n = zalloc(w, (size_t)cap * sizeof *n);
    if (!n) return SFSW_ENOMEM;
    if (w->n) memcpy(n, w->n, (size_t)w->count * sizeof *n);
    zfree(w, w->n);
    w->n = n;
    w->cap = cap;
    return SFSW_OK;
}

static int new_node(sfsw_t *w, uint32_t parent, const char *name, size_t len, int is_dir, uint32_t *out)
{
    node_t *x;
    int st;
    if (len == 0 || len > SFSW_NAME_MAX) return len ? SFSW_ENAMETOOLONG : SFSW_EINVAL;
    if (w->count == w->cap && (st = grow_nodes(w))) return st;
    x = &w->n[w->count];
    memset(x, 0, sizeof *x);
    x->name = zalloc(w, len + 1);
    if (!x->name) return SFSW_ENOMEM;
    memcpy(x->name, name, len);
    x->name_len = (uint16_t)len;
    x->is_dir = (uint8_t)is_dir;
    x->parent = parent;
    x->first_child = x->last_child = x->next_sibling = NONE;
    if (parent != NONE) {
        node_t *p = &w->n[parent];
        if (p->last_child == NONE) p->first_child = w->count;
        else w->n[p->last_child].next_sibling = w->count;
        p->last_child = w->count;
        if (is_dir) p->nsub++;
    }
    *out = w->count++;
    return SFSW_OK;
}

static uint32_t child_named(const sfsw_t *w, uint32_t dir, const char *name, size_t len)
{
    uint32_t c;
    for (c = w->n[dir].first_child; c != NONE; c = w->n[c].next_sibling)
        if (w->n[c].name_len == len && !memcmp(w->n[c].name, name, len)) return c;
    return NONE;
}

/* Resolves every component but the last; returns the parent directory node and the leaf name. */
static int walk_parent(const sfsw_t *w, const char *path, uint32_t *dir, const char **leaf, size_t *leaf_len)
{
    uint32_t cur = 0;
    const char *p = path;
    if (*p != '/') return SFSW_EINVAL;
    for (;;) {
        const char *s;
        size_t n;
        while (*p == '/') ++p;
        s = p;
        while (*p && *p != '/') ++p;
        n = (size_t)(p - s);
        while (*p == '/') ++p;
        if (!n) return SFSW_EINVAL;
        if ((n == 1 && s[0] == '.') || (n == 2 && s[0] == '.' && s[1] == '.')) return SFSW_EINVAL;
        if (!*p) { *dir = cur; *leaf = s; *leaf_len = n; return SFSW_OK; }
        cur = child_named(w, cur, s, n);
        if (cur == NONE) return SFSW_ENOENT;
        if (!w->n[cur].is_dir) return SFSW_ENOTDIR;
    }
}

sfsw_t *sfsw_create(const sfsw_io *io, const sfsw_params *p, int *err)
{
    sfsw_t *w;
    uint32_t id;
    int st;
    if (err) *err = SFSW_ENOMEM;
    if (!io || !p || !io->alloc || !io->free || !io->write || !io->read) { if (err) *err = SFSW_EINVAL; return 0; }
    w = io->alloc(io->ctx, sizeof *w);
    if (!w) return 0;
    w->io = *io;
    w->p = *p;
    st = geometry(w);
    if (!st) {
        w->buf = zalloc(w, B);
        w->big = zalloc(w, (size_t)B * ZBUF_BLOCKS);
        st = w->buf && w->big ? SFSW_OK : SFSW_ENOMEM;
    }
    if (!st) st = new_node(w, NONE, "/", 1, 1, &id);                 /* node 0: root, inode 2 */
    if (!st) st = new_node(w, 0, "lost+found", 10, 1, &id);         /* node 1: inode 11 */
    if (st) { if (err) *err = st; sfsw_destroy(w); return 0; }
    if (err) *err = SFSW_OK;
    return w;
}

void sfsw_destroy(sfsw_t *w)
{
    uint32_t i;
    if (!w) return;
    for (i = 0; i < w->count; ++i) { zfree(w, w->n[i].name); zfree(w, w->n[i].ext); }
    zfree(w, w->n);
    zfree(w, w->buf);
    zfree(w, w->big);
    w->io.free(w->io.ctx, w);
}

int sfsw_mkdir(sfsw_t *w, const char *path)
{
    uint32_t dir, id;
    const char *leaf;
    size_t len;
    int st;
    if (w->laid_out) return SFSW_ESTATE;
    if ((st = walk_parent(w, path, &dir, &leaf, &len))) return st;
    if (child_named(w, dir, leaf, len) != NONE) return SFSW_EEXIST;
    return new_node(w, dir, leaf, len, 1, &id);
}

int sfsw_add_file(sfsw_t *w, const char *path, uint64_t size, uint32_t *handle)
{
    uint32_t dir, id;
    const char *leaf;
    size_t len;
    int st;
    if (w->laid_out) return SFSW_ESTATE;
    if ((st = walk_parent(w, path, &dir, &leaf, &len))) return st;
    if (child_named(w, dir, leaf, len) != NONE) return SFSW_EEXIST;
    if ((st = new_node(w, dir, leaf, len, 0, &id))) return st;
    w->n[id].size = size;
    if (handle) *handle = id;
    return SFSW_OK;
}

uint32_t sfsw_inode_of(const sfsw_t *w, uint32_t handle) { return handle < w->count ? w->n[handle].ino : 0; }

static uint32_t node_of_ino(const sfsw_t *w, uint32_t ino)
{
    if (ino == ROOT_INO) return 0;
    if (ino == LF_INO) return 1;
    if (ino >= 12 && ino - 10 < w->count) return ino - 10;
    return NONE;
}

static uint32_t rec_len_for(uint32_t name_len) { return (8u + name_len + 3u) & ~3u; }

static uint32_t dir_blocks(const sfsw_t *w, uint32_t d)
{
    uint32_t c, used = rec_len_for(1) + rec_len_for(2), blocks = 1;
    if (d == 1) return LF_BLOCKS;
    for (c = w->n[d].first_child; c != NONE; c = w->n[c].next_sibling) {
        const uint32_t e = rec_len_for(w->n[c].name_len);
        if (used + e > B) { ++blocks; used = 0; }
        used += e;
    }
    return blocks;
}

/* ---------------------------------------------------------------- block allocation */
typedef struct { uint32_t g; uint64_t next; } cursor_t;

static int push_ext(sfsw_t *w, node_t *x, uint64_t start, uint32_t len)
{
    if (x->next && x->ext[x->next - 1].start + x->ext[x->next - 1].len == start &&
        x->ext[x->next - 1].len + len <= EXT_MAX_LEN) {
        x->ext[x->next - 1].len += len;
        return SFSW_OK;
    }
    if (x->next == x->ext_cap) {
        uint32_t cap = x->ext_cap ? x->ext_cap * 2 : 4;
        ext_t *e = zalloc(w, (size_t)cap * sizeof *e);
        if (!e) return SFSW_ENOMEM;
        if (x->ext) memcpy(e, x->ext, (size_t)x->next * sizeof *e);
        zfree(w, x->ext);
        x->ext = e;
        x->ext_cap = cap;
    }
    x->ext[x->next].start = start;
    x->ext[x->next].len = len;
    x->ext[x->next].lblock = x->next ? x->ext[x->next - 1].lblock + x->ext[x->next - 1].len : 0;
    x->next++;
    return SFSW_OK;
}

/* Hands out `want` blocks (possibly split at group metadata) to node x. */
static int allocate(sfsw_t *w, cursor_t *c, node_t *x, uint32_t want)
{
    while (want) {
        uint64_t data0, end;
        uint32_t take;
        int st;
        if (c->g >= w->groups) return SFSW_ENOSPC;
        data0 = group_start(c->g) + group_overhead(w, c->g);
        end = group_start(c->g) + group_size(w, c->g);
        if (c->next < data0) c->next = data0;
        if (c->next >= end) { c->g++; continue; }
        take = (uint32_t)(end - c->next < want ? end - c->next : want);
        if (take > EXT_MAX_LEN) take = EXT_MAX_LEN;
        if ((st = push_ext(w, x, c->next, take))) return st;
        c->next += take;
        want -= take;
    }
    return SFSW_OK;
}

static int allocate_one(sfsw_t *w, cursor_t *c, uint64_t *out)
{
    node_t tmp;
    int st;
    memset(&tmp, 0, sizeof tmp);
    st = allocate(w, c, &tmp, 1);
    if (!st) *out = tmp.ext[0].start;
    zfree(w, tmp.ext);
    return st;
}

int sfsw_layout(sfsw_t *w)
{
    cursor_t c = {0, 0};
    uint32_t i;
    int st;
    if (w->laid_out) return SFSW_ESTATE;
    if ((uint64_t)w->count + 9 > (uint64_t)w->ipg * w->groups) return SFSW_ENOSPC;
    for (i = 0; i < w->count; ++i) {
        node_t *x = &w->n[i];
        x->ino = i == 0 ? ROOT_INO : i == 1 ? LF_INO : i + 10;
        if (x->is_dir) {
            x->nblocks = dir_blocks(w, i);
            x->size = (uint64_t)x->nblocks * B;
        } else {
            const uint64_t nb = (x->size + B - 1) / B;
            if (nb > 0xffffffffull) return SFSW_ENOSPC;
            x->nblocks = (uint32_t)nb;
        }
        if ((st = allocate(w, &c, x, x->nblocks))) return st;
        if (x->next > MAX_INLINE_EXT) {
            if (x->next > LEAF_MAX) return SFSW_ENOSPC;
            if ((st = allocate_one(w, &c, &x->leaf))) return st;
        }
    }
    w->laid_out = 1;
    return SFSW_OK;
}

void sfsw_get_info(const sfsw_t *w, sfsw_info *out)
{
    uint32_t i, g;
    uint64_t used = 0;
    memset(out, 0, sizeof *out);
    out->blocks = w->blocks;
    out->groups = w->groups;
    out->inodes_per_group = w->ipg;
    out->inodes = w->ipg * w->groups;
    for (g = 0; g < w->groups; ++g) used += group_overhead(w, g);
    for (i = 0; i < w->count; ++i) {
        used += w->n[i].nblocks + (w->n[i].leaf ? 1 : 0);
        if (w->n[i].is_dir) out->dirs++; else out->files++;
    }
    out->free_blocks = w->blocks - used;
    out->free_inodes = out->inodes - (w->count + 9u);              /* inodes 1..10 reserved, 11.. the tree */
}

/* ---------------------------------------------------------------- data */
static int map_block(const node_t *x, uint32_t lblock, uint64_t *pblock, uint32_t *run)
{
    uint32_t i;
    for (i = 0; i < x->next; ++i) {
        const ext_t *e = &x->ext[i];
        if (lblock >= e->lblock && lblock < e->lblock + e->len) {
            *pblock = e->start + (lblock - e->lblock);
            *run = e->lblock + e->len - lblock;
            return SFSW_OK;
        }
    }
    return SFSW_EINVAL;
}

int sfsw_write(sfsw_t *w, uint32_t handle, uint64_t off, const void *buf, uint32_t len)
{
    const uint8_t *src = buf;
    node_t *x;
    if (!w->laid_out) return SFSW_ESTATE;
    if (handle >= w->count || w->n[handle].is_dir || off % B) return SFSW_EINVAL;
    x = &w->n[handle];
    if (off + len > (uint64_t)x->nblocks * B) return SFSW_EINVAL;
    while (len) {
        const uint32_t lb = (uint32_t)(off / B);
        uint64_t pb;
        uint32_t run, n;
        int st = map_block(x, lb, &pb, &run);
        if (st) return st;
        if (len < B) {                                              /* the file's last, partial block */
            memset(w->buf, 0, B);
            memcpy(w->buf, src, len);
            return w->io.write(w->io.ctx, pb, 1, w->buf) ? SFSW_EIO : SFSW_OK;
        }
        n = len / B < run ? len / B : run;
        if (w->io.write(w->io.ctx, pb, n, src)) return SFSW_EIO;
        src += (size_t)n * B;
        off += (uint64_t)n * B;
        len -= n * B;
    }
    return SFSW_OK;
}

int sfsw_shrink(sfsw_t *w, uint32_t handle, uint64_t size)
{
    node_t *x;
    uint32_t keep;
    if (!w->laid_out) return SFSW_ESTATE;
    if (handle >= w->count || w->n[handle].is_dir) return SFSW_EINVAL;
    x = &w->n[handle];
    if (size > x->size) return SFSW_EINVAL;
    keep = (uint32_t)((size + B - 1) / B);
    while (x->next && x->ext[x->next - 1].lblock >= keep) x->next--;
    if (x->next && x->ext[x->next - 1].lblock + x->ext[x->next - 1].len > keep)
        x->ext[x->next - 1].len = keep - x->ext[x->next - 1].lblock;
    if (x->next <= MAX_INLINE_EXT) x->leaf = 0;                     /* the leaf block becomes free again */
    x->nblocks = keep;
    x->size = size;
    return SFSW_OK;
}

/* ---------------------------------------------------------------- metadata */
static void mark(uint8_t *bm, uint64_t first, uint64_t count, uint64_t lo, uint64_t hi)
{
    uint64_t b = first < lo ? lo : first, e = first + count > hi ? hi : first + count;
    for (; b < e; ++b) bm[(b - lo) >> 3] |= (uint8_t)(1u << ((b - lo) & 7));
}

static uint32_t count_zero_bits(const uint8_t *bm, uint32_t bits)
{
    uint32_t i, n = 0;
    for (i = 0; i < bits; ++i) if (!(bm[i >> 3] & (1u << (i & 7)))) ++n;
    return n;
}

/* Builds the block bitmap of group g into bm (one block); returns free blocks. */
static uint32_t block_bitmap(const sfsw_t *w, uint32_t g, uint8_t *bm)
{
    const uint64_t lo = group_start(g), hi = lo + group_size(w, g);
    uint32_t i, j;
    memset(bm, 0, B);
    mark(bm, lo, group_overhead(w, g), lo, hi);
    for (i = 0; i < w->count; ++i) {
        const node_t *x = &w->n[i];
        for (j = 0; j < x->next; ++j) mark(bm, x->ext[j].start, x->ext[j].len, lo, hi);
        if (x->leaf) mark(bm, x->leaf, 1, lo, hi);
    }
    for (i = group_size(w, g); i < BPG; ++i) bm[i >> 3] |= (uint8_t)(1u << (i & 7));   /* padding past the end */
    return count_zero_bits(bm, group_size(w, g));
}

/* Inodes 1..10 are reserved, 2 is the root (node 0), 11 lost+found (node 1), node k >= 2 is inode k + 10. */
static uint32_t max_ino(const sfsw_t *w) { return w->count + 9u; }

static void inode_bitmap(const sfsw_t *w, uint32_t g, uint8_t *bm, uint32_t *free_inodes, uint32_t *dirs)
{
    const uint32_t first = g * w->ipg + 1, top = max_ino(w);
    uint32_t i;
    memset(bm, 0, B);
    *dirs = 0;
    for (i = 0; i < w->ipg; ++i) {
        const uint32_t ino = first + i;
        if (ino <= top) {
            const uint32_t k = node_of_ino(w, ino);
            bm[i >> 3] |= (uint8_t)(1u << (i & 7));
            if (k != NONE && w->n[k].is_dir) ++*dirs;
        }
    }
    for (i = w->ipg; i < BPG; ++i) bm[i >> 3] |= (uint8_t)(1u << (i & 7));
    *free_inodes = count_zero_bits(bm, w->ipg);
}

static void encode_inode(const sfsw_t *w, const node_t *x, uint8_t *in)
{
    const uint32_t t = w->p.time;
    uint8_t *eh = in + 0x28;
    uint32_t links = x->is_dir ? 2u + x->nsub : 1u, i;
    const uint64_t i_blocks = ((uint64_t)x->nblocks + (x->leaf ? 1u : 0u)) * (B / 512u);
    memset(in, 0, ISZ);
    put16(in + 0x00, x->is_dir ? (x->ino == LF_INO ? 040700u : 040755u) : 0100644u);
    put32(in + 0x04, (uint32_t)x->size);
    put32(in + 0x08, t);
    put32(in + 0x0c, t);
    put32(in + 0x10, t);
    put16(in + 0x1a, links);
    put32(in + 0x1c, (uint32_t)i_blocks);
    put32(in + 0x20, EXTENTS_FL);
    put32(in + 0x6c, (uint32_t)(x->size >> 32));
    put16(in + 0x74, (uint32_t)(i_blocks >> 32));
    put16(in + 0x80, 32);                                           /* i_extra_isize */
    put32(in + 0x90, t);                                            /* i_crtime */
    put16(eh + 0, EXT_MAGIC);
    put16(eh + 4, MAX_INLINE_EXT);
    if (!x->leaf) {
        put16(eh + 2, x->next);
        put16(eh + 6, 0);
        for (i = 0; i < x->next; ++i) {
            uint8_t *e = eh + 12 + 12 * i;
            put32(e + 0, x->ext[i].lblock);
            put16(e + 4, x->ext[i].len);
            put16(e + 6, (uint32_t)(x->ext[i].start >> 32));
            put32(e + 8, (uint32_t)x->ext[i].start);
        }
    } else {
        uint8_t *ix = eh + 12;
        put16(eh + 2, 1);
        put16(eh + 6, 1);                                           /* depth 1: one index entry -> leaf block */
        put32(ix + 0, 0);
        put32(ix + 4, (uint32_t)x->leaf);
        put16(ix + 8, (uint32_t)(x->leaf >> 32));
    }
}

static void encode_leaf(const node_t *x, uint8_t *blk)
{
    uint32_t i;
    memset(blk, 0, B);
    put16(blk + 0, EXT_MAGIC);
    put16(blk + 2, x->next);
    put16(blk + 4, LEAF_MAX);
    for (i = 0; i < x->next; ++i) {
        uint8_t *e = blk + 12 + 12 * i;
        put32(e + 0, x->ext[i].lblock);
        put16(e + 4, x->ext[i].len);
        put16(e + 6, (uint32_t)(x->ext[i].start >> 32));
        put32(e + 8, (uint32_t)x->ext[i].start);
    }
}

static int wblk(sfsw_t *w, uint64_t block, uint32_t count, const void *buf)
{
    return w->io.write(w->io.ctx, block, count, buf) ? SFSW_EIO : SFSW_OK;
}

static int write_zero(sfsw_t *w, uint64_t block, uint64_t count)
{
    memset(w->big, 0, (size_t)B * ZBUF_BLOCKS);
    while (count) {
        const uint32_t n = count < ZBUF_BLOCKS ? (uint32_t)count : ZBUF_BLOCKS;
        if (wblk(w, block, n, w->big)) return SFSW_EIO;
        block += n;
        count -= n;
    }
    return SFSW_OK;
}

/* Directory blocks of node d, one at a time, written through its extents. */
static int write_dir(sfsw_t *w, uint32_t d)
{
    const node_t *x = &w->n[d];
    uint8_t *blk = w->buf;
    uint32_t used = 0, lb = 0, c, last = 0, run;
    uint64_t pb;
    int st;
    memset(blk, 0, B);
#define EMIT(INO, NAME, LEN, TYPE)                                                                              \
    do {                                                                                                     \
        const uint32_t rl = rec_len_for(LEN);                                                                \
        if (used + rl > B) {                                                                                 \
            put16(blk + last + 4, B - last);                                                                 \
            if ((st = map_block(x, lb, &pb, &run)) || (st = wblk(w, pb, 1, blk))) return st;                 \
            ++lb; used = 0; memset(blk, 0, B);                                                               \
        }                                                                                                    \
        put32(blk + used, INO); put16(blk + used + 4, rl); blk[used + 6] = (uint8_t)(LEN); blk[used + 7] = TYPE; \
        memcpy(blk + used + 8, NAME, LEN);                                                                   \
        last = used; used += rl;                                                                             \
    } while (0)
    EMIT(x->ino, ".", 1u, 2);
    EMIT(w->n[x->parent == NONE ? 0 : x->parent].ino, "..", 2u, 2);
    for (c = x->first_child; c != NONE; c = w->n[c].next_sibling)
        EMIT(w->n[c].ino, w->n[c].name, (uint32_t)w->n[c].name_len, w->n[c].is_dir ? 2 : 1);
#undef EMIT
    put16(blk + last + 4, B - last);
    if ((st = map_block(x, lb, &pb, &run)) || (st = wblk(w, pb, 1, blk))) return st;
    for (++lb; lb < x->nblocks; ++lb) {                             /* lost+found's spare blocks: one empty entry each */
        memset(blk, 0, B);
        put16(blk + 4, B);
        if ((st = map_block(x, lb, &pb, &run)) || (st = wblk(w, pb, 1, blk))) return st;
    }
    return SFSW_OK;
}

static void encode_super(const sfsw_t *w, uint8_t *sb, uint64_t free_blocks, uint32_t free_inodes, uint32_t group)
{
    const uint32_t t = w->p.time;
    memset(sb, 0, 1024);
    put32(sb + 0x00, w->ipg * w->groups);
    put32(sb + 0x04, (uint32_t)w->blocks);
    put32(sb + 0x08, 0);                                            /* no root-reserved blocks */
    put32(sb + 0x0c, (uint32_t)free_blocks);
    put32(sb + 0x10, free_inodes);
    put32(sb + 0x14, 0);                                            /* first data block (4 KiB blocks) */
    put32(sb + 0x18, 2);                                            /* 1024 << 2 */
    put32(sb + 0x1c, 2);
    put32(sb + 0x20, BPG);
    put32(sb + 0x24, BPG);
    put32(sb + 0x28, w->ipg);
    put32(sb + 0x30, t);                                            /* s_wtime */
    put16(sb + 0x36, 0xffff);                                       /* s_max_mnt_count = -1 */
    put16(sb + 0x38, 0xef53);
    put16(sb + 0x3a, 1);                                            /* cleanly unmounted */
    put16(sb + 0x3c, 1);                                            /* errors: continue */
    put32(sb + 0x40, t);                                            /* s_lastcheck */
    put32(sb + 0x4c, 1);                                            /* dynamic revision */
    put32(sb + 0x54, FIRST_INO);
    put16(sb + 0x58, ISZ);
    put16(sb + 0x5a, group);
    put32(sb + 0x5c, COMPAT);
    put32(sb + 0x60, INCOMPAT_FILETYPE | INCOMPAT_EXTENTS);
    put32(sb + 0x64, RO_SPARSE_SUPER | RO_LARGE_FILE | RO_EXTRA_ISIZE);
    memcpy(sb + 0x68, w->p.uuid, 16);
    memcpy(sb + 0x78, w->p.label, strlen(w->p.label) < 16 ? strlen(w->p.label) : 16);
    put32(sb + 0x108, t);                                           /* s_mkfs_time */
    put16(sb + 0x15c, 32);                                          /* s_min_extra_isize */
    put16(sb + 0x15e, 32);                                          /* s_want_extra_isize */
}

int sfsw_commit(sfsw_t *w)
{
    uint8_t *gdt, *blk = w->buf;
    uint64_t free_blocks = 0;
    uint32_t free_inodes = 0, g, i;
    int st = SFSW_OK;
    if (!w->laid_out) return SFSW_ESTATE;
    gdt = zalloc(w, (size_t)w->gdt_blocks * B);
    if (!gdt) return SFSW_ENOMEM;
    /* bitmaps and descriptors */
    for (g = 0; g < w->groups && !st; ++g) {
        uint8_t *d = gdt + (size_t)g * DESC;
        uint32_t fb, fi, dirs;
        fb = block_bitmap(w, g, blk);
        st = wblk(w, block_bitmap_of(w, g), 1, blk);
        if (st) break;
        inode_bitmap(w, g, blk, &fi, &dirs);
        st = wblk(w, inode_bitmap_of(w, g), 1, blk);
        put32(d + 0x00, (uint32_t)block_bitmap_of(w, g));
        put32(d + 0x04, (uint32_t)inode_bitmap_of(w, g));
        put32(d + 0x08, (uint32_t)inode_table_of(w, g));
        put16(d + 0x0c, fb);
        put16(d + 0x0e, fi);
        put16(d + 0x10, dirs);
        free_blocks += fb;
        free_inodes += fi;
    }
    /* inode tables: the whole table once (unused inodes must read as zero), afterwards only blocks in use */
    for (g = 0; g < w->groups && !st; ++g) {
        const uint32_t first = g * w->ipg + 1;
        uint32_t tb;
        for (tb = 0; tb < w->itb && !st; ++tb) {
            const uint32_t ino0 = first + tb * IPB;
            if (ino0 > max_ino(w)) {
                if (!w->tables_zeroed) st = write_zero(w, inode_table_of(w, g) + tb, w->itb - tb);
                break;
            }
            memset(blk, 0, B);
            for (i = 0; i < IPB; ++i) {
                const uint32_t k = node_of_ino(w, ino0 + i);
                if (k != NONE) encode_inode(w, &w->n[k], blk + i * ISZ);
            }
            st = wblk(w, inode_table_of(w, g) + tb, 1, blk);
        }
    }
    /* extent leaves and directories */
    for (i = 0; i < w->count && !st; ++i) {
        if (w->n[i].leaf) {
            encode_leaf(&w->n[i], blk);
            st = wblk(w, w->n[i].leaf, 1, blk);
        }
        if (!st && w->n[i].is_dir) st = write_dir(w, i);
    }
    /* superblock + descriptor copies in group 0 and the sparse_super backup groups */
    for (g = 0; g < w->groups && !st; ++g) {
        if (!has_super(g)) continue;
        memset(blk, 0, B);
        encode_super(w, blk + (g == 0 ? 1024 : 0), free_blocks, free_inodes, g);
        st = wblk(w, group_start(g), 1, blk);
        if (!st) st = wblk(w, group_start(g) + 1, w->gdt_blocks, gdt);
    }
    zfree(w, gdt);
    if (!st) w->tables_zeroed = 1;
    return st;
}

/* ---------------------------------------------------------------- reader */
struct sfsr {
    sfsw_io io;
    uint64_t blocks;
    uint32_t groups, ipg, isz, desc;
    uint64_t *itable;
    uint8_t *blk, *tmp;
};

static void *ralloc(sfsr_t *r, size_t n) { return r->io.alloc(r->io.ctx, n); }
static int rblk(sfsr_t *r, uint64_t b, void *buf) { return b < r->blocks && !r->io.read(r->io.ctx, b, 1, buf) ? SFSW_OK : SFSW_EIO; }

void sfsr_close(sfsr_t *r)
{
    if (!r) return;
    if (r->itable) r->io.free(r->io.ctx, r->itable);
    if (r->blk) r->io.free(r->io.ctx, r->blk);
    if (r->tmp) r->io.free(r->io.ctx, r->tmp);
    r->io.free(r->io.ctx, r);
}

sfsr_t *sfsr_open(const sfsw_io *io, int *err)
{
    sfsr_t *r = io->alloc(io->ctx, sizeof *r);
    const uint8_t *sb;
    uint32_t incompat, g, bpg, gdt_blocks;
    int st = SFSW_ECORRUPT;
    if (!r) { if (err) *err = SFSW_ENOMEM; return 0; }
    r->io = *io;
    r->blk = ralloc(r, B);
    r->tmp = ralloc(r, B);
    if (!r->blk || !r->tmp) { st = SFSW_ENOMEM; goto fail; }
    r->blocks = 1;
    if (rblk(r, 0, r->blk)) { st = SFSW_EIO; goto fail; }
    sb = r->blk + 1024;
    if (get16(sb + 0x38) != 0xef53 || get32(sb + 0x18) != 2 || get32(sb + 0x14) != 0) goto fail;
    incompat = get32(sb + 0x60);
    if (incompat & ~(INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_FLEX_BG)) { st = SFSW_EUNSUPP; goto fail; }
    r->blocks = get32(sb + 0x04);
    bpg = get32(sb + 0x20);
    r->ipg = get32(sb + 0x28);
    r->isz = get32(sb + 0x4c) >= 1 ? get16(sb + 0x58) : 128;
    r->desc = incompat & INCOMPAT_64BIT ? get16(sb + 0xfe) : 32;
    if (!bpg || !r->ipg || r->isz < 128 || r->isz > B || (r->isz & (r->isz - 1)) || r->desc < 32 || r->desc > 64) goto fail;
    r->groups = (uint32_t)((r->blocks + bpg - 1) / bpg);
    if (!r->groups || (uint64_t)r->groups * r->ipg != get32(sb + 0x00)) goto fail;
    r->itable = ralloc(r, (size_t)r->groups * sizeof *r->itable);
    if (!r->itable) { st = SFSW_ENOMEM; goto fail; }
    gdt_blocks = (r->groups * r->desc + B - 1) / B;
    for (g = 0; g < r->groups; ++g) {
        const uint32_t off = (g * r->desc) % B;
        if (off == 0 && rblk(r, 1 + (g * r->desc) / B, r->tmp)) { st = SFSW_EIO; goto fail; }
        r->itable[g] = get32(r->tmp + off + 8) | (r->desc >= 64 ? (uint64_t)get32(r->tmp + off + 0x28) << 32 : 0);
        if (r->itable[g] <= gdt_blocks || r->itable[g] >= r->blocks) goto fail;
    }
    if (err) *err = SFSW_OK;
    return r;
fail:
    if (err) *err = st;
    sfsr_close(r);
    return 0;
}

static int read_inode(sfsr_t *r, uint32_t ino, uint8_t *out)
{
    uint32_t g, idx;
    uint64_t byte;
    if (!ino || ino > r->groups * r->ipg) return SFSW_ECORRUPT;
    g = (ino - 1) / r->ipg;
    idx = (ino - 1) % r->ipg;
    byte = (uint64_t)idx * r->isz;
    if (rblk(r, r->itable[g] + byte / B, r->tmp)) return SFSW_EIO;
    memcpy(out, r->tmp + byte % B, r->isz < ISZ ? r->isz : ISZ);
    return SFSW_OK;
}

/* Maps a logical block through the inode's extent tree (any depth up to 5). *pb = 0 for a hole. */
static int map_inode(sfsr_t *r, const uint8_t *inode, uint32_t lb, uint64_t *pb)
{
    const uint8_t *h = inode + 0x28;
    int depth_guard = 6;
    if (!(get32(inode + 0x20) & EXTENTS_FL)) return SFSW_EUNSUPP;
    for (;;) {
        uint32_t n = get16(h + 2), depth = get16(h + 6), i;
        if (get16(h) != EXT_MAGIC || !depth_guard--) return SFSW_ECORRUPT;
        if (depth == 0) {
            for (i = 0; i < n; ++i) {
                const uint8_t *e = h + 12 + 12 * i;
                uint32_t start = get32(e), len = get16(e + 4);
                if (len > EXT_MAX_LEN) len -= EXT_MAX_LEN;              /* uninitialised extent: reads as zero */
                if (lb >= start && lb < start + len) {
                    if (get16(e + 4) > EXT_MAX_LEN) { *pb = 0; return SFSW_OK; }
                    *pb = ((uint64_t)get16(e + 6) << 32 | get32(e + 8)) + (lb - start);
                    return SFSW_OK;
                }
            }
            *pb = 0;
            return SFSW_OK;
        } else {
            const uint8_t *pick = 0;
            uint64_t child;
            for (i = 0; i < n; ++i) {
                const uint8_t *ix = h + 12 + 12 * i;
                if (get32(ix) <= lb) pick = ix;
            }
            if (!pick) { *pb = 0; return SFSW_OK; }
            child = (uint64_t)get16(pick + 8) << 32 | get32(pick + 4);
            if (rblk(r, child, r->blk)) return SFSW_EIO;
            h = r->blk;
        }
    }
}

int sfsr_read(sfsr_t *r, uint32_t ino, uint64_t off, void *buf, uint32_t len, uint32_t *done)
{
    uint8_t inode[ISZ];
    uint8_t *dst = buf;
    uint64_t size;
    int st;
    *done = 0;
    if (off % B) return SFSW_EINVAL;
    if ((st = read_inode(r, ino, inode))) return st;
    size = (uint64_t)get32(inode + 0x6c) << 32 | get32(inode + 0x04);
    if (off >= size) return SFSW_OK;
    if (len > size - off) len = (uint32_t)(size - off);
    while (*done < len) {
        uint64_t pb;
        const uint32_t n = len - *done < B ? len - *done : B;
        if ((st = map_inode(r, inode, (uint32_t)((off + *done) / B), &pb))) return st;
        if (!pb) memset(dst + *done, 0, n);
        else {
            if (rblk(r, pb, r->blk)) return SFSW_EIO;
            memcpy(dst + *done, r->blk, n);
        }
        *done += n;
    }
    return SFSW_OK;
}

static int dir_find(sfsr_t *r, uint32_t dir, const char *name, size_t len, uint32_t *ino, uint8_t *type)
{
    uint8_t inode[ISZ];
    uint64_t size, lb;
    int st;
    if ((st = read_inode(r, dir, inode))) return st;
    if ((get16(inode) & 0xf000u) != 0x4000u) return SFSW_ENOTDIR;
    size = (uint64_t)get32(inode + 0x6c) << 32 | get32(inode + 0x04);
    for (lb = 0; lb * B < size; ++lb) {
        uint64_t pb;
        uint32_t o = 0;
        if ((st = map_inode(r, inode, (uint32_t)lb, &pb))) return st;
        if (!pb) continue;
        if (rblk(r, pb, r->tmp)) return SFSW_EIO;
        while (o + 8 <= B) {
            const uint32_t e_ino = get32(r->tmp + o), rl = get16(r->tmp + o + 4), nl = r->tmp[o + 6];
            if (rl < 8 || rl % 4 || o + rl > B || 8 + nl > rl) return SFSW_ECORRUPT;
            if (e_ino && nl == len && !memcmp(r->tmp + o + 8, name, len)) {
                *ino = e_ino;
                *type = r->tmp[o + 7];
                return SFSW_OK;
            }
            o += rl;
        }
    }
    return SFSW_ENOENT;
}

int sfsr_lookup(sfsr_t *r, const char *path, uint32_t *ino, uint64_t *size, int *is_dir)
{
    uint8_t inode[ISZ];
    uint32_t cur = ROOT_INO;
    const char *p = path;
    int st;
    if (*p != '/') return SFSW_EINVAL;
    for (;;) {
        const char *s;
        size_t n;
        uint8_t type;
        while (*p == '/') ++p;
        if (!*p) break;
        s = p;
        while (*p && *p != '/') ++p;
        n = (size_t)(p - s);
        if ((st = dir_find(r, cur, s, n, &cur, &type))) return st;
    }
    if ((st = read_inode(r, cur, inode))) return st;
    *ino = cur;
    *size = (uint64_t)get32(inode + 0x6c) << 32 | get32(inode + 0x04);
    *is_dir = (get16(inode) & 0xf000u) == 0x4000u;
    return SFSW_OK;
}
