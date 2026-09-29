/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS v1 block cache: hashed, LRU, write-back. Data blocks (B_DIRTY) may be written back at any time; metadata
 * blocks joined to the running transaction (B_JDIRTY) are pinned in memory until the transaction has been committed
 * to the journal and checkpointed (sfs_jbd2.c), which is what makes an interrupted operation leave the volume
 * consistent. Every allocation is at most one block (<= SFS_MAX_ALLOC), so the same code runs inside Kernel64.
 */
#include "sfs_internal.h"

void *sfs_alloc(sfs_fs *fs, size_t bytes) { return bytes && bytes <= SFS_MAX_ALLOC ? fs->ops.alloc(fs->ops.ctx, bytes) : 0; }
void sfs_free(sfs_fs *fs, void *p, size_t bytes) { if (p) fs->ops.free(fs->ops.ctx, p, bytes); }

int sfs_dev_read(sfs_fs *fs, uint64_t blk, void *buf, uint32_t count)
{
    const uint64_t off = blk << fs->bs_bits;
    const uint32_t bytes = count << fs->bs_bits;
    if (blk >= fs->nblocks || count > fs->nblocks - blk || off + bytes > fs->ops.size) return SFS_EIO;
    fs->st.reads++;
    fs->st.read_bytes += bytes;
    return fs->ops.read(fs->ops.ctx, off, buf, bytes) ? SFS_EIO : 0;
}

int sfs_dev_write(sfs_fs *fs, uint64_t blk, const void *buf, uint32_t count)
{
    const uint64_t off = blk << fs->bs_bits;
    const uint32_t bytes = count << fs->bs_bits;
    if (fs->ro) return SFS_EROFS;
    if (blk >= fs->nblocks || count > fs->nblocks - blk || off + bytes > fs->ops.size) return SFS_EIO;
    if (fs->write_stopped) return SFS_EIO;
    if (fs->write_limit) {                                  /* crash-test fault injection */
        if (fs->st.writes + 1 >= fs->write_limit) {
            fs->write_stopped = 1;
            if (fs->write_hit) fs->write_hit(fs->ops.ctx);
            return SFS_EIO;
        }
    }
    fs->st.writes++;
    fs->st.write_bytes += bytes;
    
    return fs->ops.write(fs->ops.ctx, off, buf, bytes) ? SFS_EIO : 0;
}

int sfs_dev_writev(sfs_fs *fs, uint64_t blk, const void *const *bufs, uint32_t count)
{
    const uint64_t off = blk << fs->bs_bits;
    uint32_t i;
    if (fs->ro) return SFS_EROFS;
    if (blk >= fs->nblocks || count > fs->nblocks - blk || off + ((uint64_t)count << fs->bs_bits) > fs->ops.size) return SFS_EIO;
    if (!fs->ops.writev || fs->write_limit) {
        for (i = 0; i < count; ++i) {
            int rc = sfs_dev_write(fs, blk + i, bufs[i], 1);
            if (rc) return rc;
        }
        return 0;
    }
    if (fs->write_stopped) return SFS_EIO;
    fs->st.writes++;
    fs->st.write_bytes += (uint64_t)count << fs->bs_bits;
    return fs->ops.writev(fs->ops.ctx, off, bufs, count, fs->bs) ? SFS_EIO : 0;
}

int sfs_wrun_flush(sfs_fs *fs, sfs_wrun *r)
{
    int rc = 0;
    if (r->n == 1) rc = sfs_dev_write(fs, r->start, r->bufs[0], 1);
    else if (r->n) rc = sfs_dev_writev(fs, r->start, r->bufs, r->n);
    r->n = 0;
    return rc;
}

int sfs_wrun_add(sfs_fs *fs, sfs_wrun *r, uint64_t blk, const void *data)
{
    if (r->n && (r->start + r->n != blk || r->n == WRUN_MAX)) {
        int rc = sfs_wrun_flush(fs, r);
        if (rc) return rc;
    }
    if (!r->n) r->start = blk;
    r->bufs[r->n++] = data;
    return 0;
}

int sfs_dev_flush(sfs_fs *fs)
{
    if (fs->write_stopped) return SFS_EIO;
    fs->st.flushes++;
    return fs->ops.flush && fs->ops.flush(fs->ops.ctx) ? SFS_EIO : 0;
}

/* ---- cache structure ---- */
static uint32_t hash_of(uint64_t blk) { return (uint32_t)((blk * 0x9E3779B97F4A7C15ull) >> 55) & (BUF_HASH - 1); }

int sfs_cache_init(sfs_fs *fs, uint32_t blocks)
{
    fs->hash = sfs_alloc(fs, BUF_HASH * sizeof(sfs_buf *));
    if (!fs->hash) return SFS_ENOMEM;
    fs->max_bufs = blocks < 16 ? 16 : blocks;
    fs->nbufs = 0;
    fs->lru_head = fs->lru_tail = 0;
    return 0;
}

static void lru_unlink(sfs_fs *fs, sfs_buf *b)
{
    if (b->lru_prev) b->lru_prev->lru_next = b->lru_next; else fs->lru_head = b->lru_next;
    if (b->lru_next) b->lru_next->lru_prev = b->lru_prev; else fs->lru_tail = b->lru_prev;
    b->lru_prev = b->lru_next = 0;
}

static void lru_push_front(sfs_fs *fs, sfs_buf *b)
{
    b->lru_prev = 0;
    b->lru_next = fs->lru_head;
    if (fs->lru_head) fs->lru_head->lru_prev = b; else fs->lru_tail = b;
    fs->lru_head = b;
}

static void hash_unlink(sfs_fs *fs, sfs_buf *b)
{
    sfs_buf **pp = &fs->hash[hash_of(b->blk)];
    while (*pp && *pp != b) pp = &(*pp)->hnext;
    if (*pp) *pp = b->hnext;
    b->hnext = 0;
}

static void buf_destroy(sfs_fs *fs, sfs_buf *b)
{
    sfs_free(fs, b->data, fs->bs);
    sfs_free(fs, b, sizeof *b);
    fs->nbufs--;
}

static sfs_buf *lookup(sfs_fs *fs, uint64_t blk)
{
    sfs_buf *b;
    for (b = fs->hash[hash_of(blk)]; b; b = b->hnext)
        if (b->blk == blk) return b;
    return 0;
}

static int write_buf(sfs_fs *fs, sfs_buf *b)
{
    int rc = sfs_dev_write(fs, b->blk, b->data, 1);
    if (rc) return rc;
    b->flags &= ~B_DIRTY;
    return 0;
}

static sfs_buf *lookup(sfs_fs *fs, uint64_t blk);

static int writable_data(const sfs_buf *b)
{
    return b && (b->flags & (B_DIRTY | B_UPTODATE | B_JDIRTY | B_LATE)) == (B_DIRTY | B_UPTODATE);
}

/* Write-behind clustering: a dirty data buffer leaving the cache takes its dirty neighbours along in one request. */
static int write_cluster(sfs_fs *fs, sfs_buf *b)
{
    sfs_buf *run[WRUN_MAX];
    sfs_wrun w;
    uint64_t first = b->blk;
    uint32_t n = 0, i;
    int rc = 0;
    if (fs->mflags & SFS_MOUNT_NAIVE) return write_buf(fs, b);
    while (first > 0 && b->blk - first < WRUN_MAX / 2 && writable_data(lookup(fs, first - 1))) first--;
    for (i = 0; i < WRUN_MAX; ++i) {
        sfs_buf *c = first + i == b->blk ? b : lookup(fs, first + i);
        if (!writable_data(c) || first + i >= fs->nblocks) break;
        run[n++] = c;
    }
    w.n = 0;
    for (i = 0; i < n && !rc; ++i) rc = sfs_wrun_add(fs, &w, run[i]->blk, run[i]->data);
    if (!rc) rc = sfs_wrun_flush(fs, &w);
    if (rc) return rc;
    for (i = 0; i < n; ++i) run[i]->flags &= ~B_DIRTY;
    return 0;
}

/* Evicts one unpinned buffer from the LRU tail; dirty data is written first. 0 = evicted, SFS_EBUSY = nothing evictable. */
static int evict_one(sfs_fs *fs)
{
    sfs_buf *b;
    for (b = fs->lru_tail; b; b = b->lru_prev) {
        if (b->refs || (b->flags & (B_JDIRTY | B_LATE))) continue;
        if (b->flags & B_DIRTY) {
            int rc = write_cluster(fs, b);
            if (rc) return rc;
        }
        lru_unlink(fs, b);
        hash_unlink(fs, b);
        buf_destroy(fs, b);
        fs->st.cache_evictions++;
        return 0;
    }
    return SFS_EBUSY;
}

static int get_buf(sfs_fs *fs, uint64_t blk, int read, sfs_buf **out)
{
    sfs_buf *b = lookup(fs, blk);
    int rc;
    if (b) {
        fs->st.cache_hits++;
        if (b->refs == 0 || b != fs->lru_head) { lru_unlink(fs, b); lru_push_front(fs, b); }
        b->refs++;
        if (read && !(b->flags & B_UPTODATE)) {
            rc = sfs_dev_read(fs, blk, b->data, 1);
            if (rc) { b->refs--; return rc; }
            b->flags = (b->flags & ~(B_VERIFIED | B_COMPUTED)) | B_UPTODATE;
        }
        *out = b;
        return 0;
    }
    fs->st.cache_misses++;
    while (fs->nbufs >= fs->max_bufs) {
        rc = evict_one(fs);
        if (rc == SFS_EBUSY) break;                          /* over budget: allow growth rather than fail */
        if (rc) return rc;
    }
    b = sfs_alloc(fs, sizeof *b);
    if (!b) return SFS_ENOMEM;
    b->data = sfs_alloc(fs, fs->bs);
    if (!b->data) { sfs_free(fs, b, sizeof *b); return SFS_ENOMEM; }
    fs->nbufs++;
    b->blk = blk;
    b->flags = 0;
    if (read) {
        rc = sfs_dev_read(fs, blk, b->data, 1);
        if (rc) { buf_destroy(fs, b); return rc; }
        b->flags = B_UPTODATE;
    } else {
        b->flags = B_UPTODATE | B_NEW;                       /* zeroed by the allocator */
    }
    b->refs = 1;
    b->hnext = fs->hash[hash_of(blk)];
    fs->hash[hash_of(blk)] = b;
    lru_push_front(fs, b);
    *out = b;
    return 0;
}

int sfs_bread(sfs_fs *fs, uint64_t blk, sfs_buf **out)
{
    if (blk >= fs->nblocks) return SFS_ECORRUPT;
    return get_buf(fs, blk, 1, out);
}

int sfs_bnew(sfs_fs *fs, uint64_t blk, sfs_buf **out)
{
    sfs_buf *b;
    int rc;
    if (blk >= fs->nblocks) return SFS_ECORRUPT;
    rc = get_buf(fs, blk, 0, &b);
    if (rc) return rc;
    if (!(b->flags & B_NEW)) memset(b->data, 0, fs->bs);       /* was cached: reset the content */
    b->flags = (b->flags & (B_DIRTY | B_JDIRTY | B_LATE)) | B_UPTODATE | B_VERIFIED;
    *out = b;
    return 0;
}

sfs_buf *sfs_bfind(sfs_fs *fs, uint64_t blk)
{
    sfs_buf *b = lookup(fs, blk);
    if (!b || !(b->flags & B_UPTODATE)) return 0;
    b->refs++;
    return b;
}

void sfs_bput(sfs_fs *fs, sfs_buf *b)
{
    (void)fs;
    if (b && b->refs) b->refs--;
}

int sfs_bdirty_meta(sfs_fs *fs, sfs_buf *b)
{
    if (fs->ro) return SFS_EROFS;
    fs->mods++;
    b->flags &= ~(B_NEW | B_COMPUTED);
    if (b->flags & B_JDIRTY) return 0;
    b->flags |= B_JDIRTY;
    b->tnext = fs->txn.bufs;
    fs->txn.bufs = b;
    fs->txn.nbufs++;
    return 0;
}

void sfs_bdirty_data(sfs_fs *fs, sfs_buf *b)
{
    (void)fs;
    b->flags = (b->flags & ~B_NEW) | B_DIRTY;
}

void sfs_bdirty_late(sfs_fs *fs, sfs_buf *b)
{
    b->flags = (b->flags & ~B_NEW) | B_DIRTY;
    if (b->flags & (B_LATE | B_JDIRTY)) return;
    b->flags |= B_LATE;
    b->tnext = fs->txn.late;
    fs->txn.late = b;
}

void sfs_release_late(sfs_fs *fs)
{
    sfs_buf *b, *next;
    for (b = fs->txn.late; b; b = next) {
        next = b->tnext;
        b->tnext = 0;
        b->flags &= ~B_LATE;
    }
    fs->txn.late = 0;
}

/* A block was freed: its cached content is meaningless. Drop it from the running transaction (its old on-disk
 * content stays valid if the transaction never commits) and from the cache. Pinned buffers are only marked. */
void sfs_bforget(sfs_fs *fs, uint64_t blk)
{
    sfs_buf *b = lookup(fs, blk);
    if (!b) return;
    if (b->flags & (B_JDIRTY | B_LATE)) {
        sfs_buf **pp = (b->flags & B_JDIRTY) ? &fs->txn.bufs : &fs->txn.late;
        while (*pp && *pp != b) pp = &(*pp)->tnext;
        if (*pp) { *pp = b->tnext; if (b->flags & B_JDIRTY) fs->txn.nbufs--; }
        b->tnext = 0;
        b->flags &= ~(B_JDIRTY | B_LATE);
    }
    b->flags &= ~(B_DIRTY | B_UPTODATE | B_VERIFIED | B_COMPUTED);
    if (b->refs) return;
    lru_unlink(fs, b);
    hash_unlink(fs, b);
    buf_destroy(fs, b);
}

static void late_unlink(sfs_fs *fs, sfs_buf *b)
{
    sfs_buf **pp = &fs->txn.late;
    while (*pp && *pp != b) pp = &(*pp)->tnext;
    if (*pp) *pp = b->tnext;
    b->tnext = 0;
    b->flags &= ~B_LATE;
}

void sfs_binval_data(sfs_fs *fs, uint64_t blk, uint32_t count)
{
    uint32_t i;
    if (!fs->nbufs) return;
    for (i = 0; i < count; ++i) {
        sfs_buf *b = lookup(fs, blk + i);
        if (!b || (b->flags & B_JDIRTY)) continue;
        if (b->flags & B_LATE) late_unlink(fs, b);
        b->flags &= ~(B_DIRTY | B_UPTODATE | B_VERIFIED);
        if (b->refs) continue;
        lru_unlink(fs, b);
        hash_unlink(fs, b);
        buf_destroy(fs, b);
    }
}

void sfs_boverlay(sfs_fs *fs, uint64_t blk, uint32_t count, uint8_t *dst)
{
    uint32_t i;
    if (!fs->nbufs) return;
    for (i = 0; i < count; ++i) {
        sfs_buf *b = lookup(fs, blk + i);
        if (b && (b->flags & (B_UPTODATE | B_DIRTY)) == (B_UPTODATE | B_DIRTY))
            memcpy(dst + ((size_t)i << fs->bs_bits), b->data, fs->bs);
    }
}

void sfs_cache_drop_clean(sfs_fs *fs)
{
    sfs_buf *b, *prev;
    for (b = fs->lru_tail; b; b = prev) {
        prev = b->lru_prev;
        if (b->refs || (b->flags & (B_JDIRTY | B_DIRTY))) continue;
        lru_unlink(fs, b);
        hash_unlink(fs, b);
        buf_destroy(fs, b);
    }
}

/* Merge sort of the transaction list by block number: checkpoint and journal writes then go out in disk order. */
static sfs_buf *merge_sorted(sfs_buf *a, sfs_buf *b)
{
    sfs_buf head, *t = &head;
    head.tnext = 0;
    while (a && b) {
        if (a->blk <= b->blk) { t->tnext = a; a = a->tnext; }
        else { t->tnext = b; b = b->tnext; }
        t = t->tnext;
    }
    t->tnext = a ? a : b;
    return head.tnext;
}

void sfs_txn_sort(sfs_fs *fs)
{
    sfs_buf *runs[48];
    sfs_buf *b = fs->txn.bufs, *next;
    unsigned i, n = 0;
    for (i = 0; i < 48; ++i) runs[i] = 0;
    while (b) {
        next = b->tnext;
        b->tnext = 0;
        for (i = 0; i < 47 && runs[i]; ++i) { b = merge_sorted(runs[i], b); runs[i] = 0; }
        runs[i] = runs[i] ? merge_sorted(runs[i], b) : b;
        if (i + 1 > n) n = i + 1;
        b = next;
    }
    b = 0;
    for (i = 0; i < n; ++i) if (runs[i]) b = b ? merge_sorted(runs[i], b) : runs[i];
    fs->txn.bufs = b;
}

/* Writes every dirty data buffer: in batches sorted by block number, adjacent blocks coalesced into one request. */
int sfs_cache_write_data(sfs_fs *fs)
{
    sfs_buf *b = fs->lru_tail, **arr = sfs_alloc(fs, SFS_MAX_ALLOC);
    const uint32_t cap = SFS_MAX_ALLOC / sizeof(sfs_buf *);
    if (!arr) {
        for (; b; b = b->lru_prev) {
            if ((b->flags & (B_DIRTY | B_UPTODATE | B_LATE)) == (B_DIRTY | B_UPTODATE)) {
                int rc = write_buf(fs, b);
                if (rc) return rc;
            }
        }
        return 0;
    }
    while (b) {
        uint32_t n = 0, i, gap;
        sfs_wrun run;
        int rc = 0;
        for (; b && n < cap; b = b->lru_prev)
            if ((b->flags & (B_DIRTY | B_UPTODATE | B_LATE)) == (B_DIRTY | B_UPTODATE)) arr[n++] = b;
        for (gap = n / 2; gap; gap /= 2)                       /* shell sort by block number */
            for (i = gap; i < n; ++i) {
                sfs_buf *t = arr[i];
                uint32_t j = i;
                while (j >= gap && arr[j - gap]->blk > t->blk) { arr[j] = arr[j - gap]; j -= gap; }
                arr[j] = t;
            }
        run.n = 0;
        for (i = 0; i < n && !rc; ++i) rc = sfs_wrun_add(fs, &run, arr[i]->blk, arr[i]->data);
        if (!rc) rc = sfs_wrun_flush(fs, &run);
        if (rc) { sfs_free(fs, arr, SFS_MAX_ALLOC); return rc; }
        for (i = 0; i < n; ++i) arr[i]->flags &= ~B_DIRTY;
    }
    sfs_free(fs, arr, SFS_MAX_ALLOC);
    return 0;
}

/* Writes the (sorted) transaction list in place, coalescing adjacent blocks; clears the pins. */
int sfs_cache_write_meta_direct(sfs_fs *fs)
{
    sfs_buf *b, *next;
    sfs_wrun run;
    int rc = 0;
    run.n = 0;
    for (b = fs->txn.bufs; b; b = b->tnext)
        if (!rc && (b->flags & B_UPTODATE)) rc = sfs_wrun_add(fs, &run, b->blk, b->data);
    if (!rc) rc = sfs_wrun_flush(fs, &run);
    for (b = fs->txn.bufs; b; b = next) {
        next = b->tnext;
        b->tnext = 0;
        b->flags &= ~B_JDIRTY;
        fs->st.checkpoint_blocks++;
    }
    fs->txn.bufs = 0;
    fs->txn.nbufs = 0;
    return rc;
}

void sfs_cache_destroy(sfs_fs *fs)
{
    sfs_buf *b, *next;
    for (b = fs->lru_head; b; b = next) {
        next = b->lru_next;
        buf_destroy(fs, b);
    }
    fs->lru_head = fs->lru_tail = 0;
    fs->txn.late = 0;
    if (fs->hash) sfs_free(fs, fs->hash, BUF_HASH * sizeof(sfs_buf *));
    fs->hash = 0;
}
