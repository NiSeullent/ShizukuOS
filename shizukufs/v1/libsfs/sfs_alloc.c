/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS v1 allocation.
 *
 * Blocks: goal-directed first fit (the goal is the physical successor of the file's previous block, else the start
 * of the inode's flex group), group by group, word-at-a-time bitmap scans. A file growing at its end gets an
 * in-memory preallocation window: the free run after its last allocation is reserved for it, and other inodes'
 * allocations skip reserved runs while any other free space exists. Windows never reach the disk, so a crash
 * cannot leak blocks and e2fsck sees exact bitmaps.
 *
 * Frees are deferred: blocks released by the running transaction stay marked in the bitmaps until it commits, so
 * ordered-mode data written into a reallocated block can never land on a block still referenced by the last
 * committed metadata. Freed metadata blocks also get jbd2 revoke records.
 *
 * Inodes: files near their parent directory, directories under the root spread across groups with above-average
 * free space (Orlov-style), lowest free inode first so the lazily-initialised inode table tail stays unused.
 */
#include "sfs_internal.h"

/* ---- run lists ---- */
int sfs_runpage_add(sfs_fs *fs, sfs_runpage **head, uint64_t start, uint32_t len, uint32_t meta)
{
    sfs_runpage *p = *head;
    if (p && p->count) {
        /* coalesce with the previous run when contiguous */
        uint32_t i = p->count - 1;
        if (p->run[i].meta == meta && p->run[i].start + p->run[i].len == start && p->run[i].len + (uint64_t)len <= 0x7FFFFFFFu) {
            p->run[i].len += len;
            return 0;
        }
    }
    if (!p || p->count == RUNS_PER_PAGE) {
        p = sfs_alloc(fs, sizeof *p);
        if (!p) return SFS_ENOMEM;
        p->next = *head;
        p->count = 0;
        *head = p;
    }
    p->run[p->count].start = start;
    p->run[p->count].len = len;
    p->run[p->count].meta = meta;
    p->count++;
    return 0;
}

void sfs_runpage_free(sfs_fs *fs, sfs_runpage **head)
{
    while (*head) {
        sfs_runpage *n = (*head)->next;
        sfs_free(fs, *head, sizeof **head);
        *head = n;
    }
}

/* ---- bitmap helpers ---- */
static uint32_t find_zero(const uint8_t *map, uint32_t from, uint32_t limit)
{
    uint32_t i = from;
    while (i < limit && (i & 63)) {
        if (!sfs_test_bit(map, i)) return i;
        i++;
    }
    while (i + 64 <= limit) {
        uint64_t w;
        memcpy(&w, map + (i >> 3), 8);
        if (w != ~0ull) break;
        i += 64;
    }
    for (; i < limit; ++i) if (!sfs_test_bit(map, i)) return i;
    return limit;
}

static uint32_t find_one(const uint8_t *map, uint32_t from, uint32_t limit)
{
    uint32_t i = from;
    while (i < limit && (i & 63)) {
        if (sfs_test_bit(map, i)) return i;
        i++;
    }
    while (i + 64 <= limit) {
        uint64_t w;
        memcpy(&w, map + (i >> 3), 8);
        if (w) break;
        i += 64;
    }
    for (; i < limit; ++i) if (sfs_test_bit(map, i)) return i;
    return limit;
}

static void set_bits(uint8_t *map, uint32_t from, uint32_t n)
{
    while (n && (from & 7)) { sfs_set_bit(map, from++); n--; }
    if (n >= 8) { memset(map + (from >> 3), 0xFF, n >> 3); from += n & ~7u; n &= 7; }
    while (n--) sfs_set_bit(map, from++);
}

/* Clears n bits; returns how many were already clear (double frees). */
static uint32_t clear_bits(uint8_t *map, uint32_t from, uint32_t n)
{
    uint32_t bad = 0;
    while (n--) {
        if (!sfs_test_bit(map, from)) bad++;
        sfs_clear_bit(map, from);
        from++;
    }
    return bad;
}

/* ---- preallocation windows ---- */
static sfs_pa *pa_of(sfs_fs *fs, uint32_t ino)
{
    uint32_t i;
    for (i = 0; i < PA_MAX; ++i) if (fs->pa->w[i].len && fs->pa->w[i].ino == ino) return &fs->pa->w[i];
    return 0;
}

void sfs_pa_release(sfs_fs *fs, uint32_t ino)
{
    sfs_pa *w = pa_of(fs, ino);
    if (w) w->len = 0;
}

/* First window of another inode overlapping [s, s+n): returns its start and end, or 0. */
static int pa_conflict(sfs_fs *fs, uint32_t ino, uint64_t s, uint64_t n, uint64_t *ws, uint64_t *we)
{
    uint32_t i;
    int found = 0;
    for (i = 0; i < PA_MAX; ++i) {
        sfs_pa *w = &fs->pa->w[i];
        if (!w->len || w->ino == ino) continue;
        if (w->pblk < s + n && s < w->pblk + w->len) {
            if (!found || w->pblk < *ws) { *ws = w->pblk; *we = w->pblk + w->len; }
            found = 1;
        }
    }
    return found;
}

static void pa_drop_overlap(sfs_fs *fs, uint64_t s, uint64_t n)
{
    uint32_t i;
    for (i = 0; i < PA_MAX; ++i) {
        sfs_pa *w = &fs->pa->w[i];
        if (w->len && w->pblk < s + n && s < w->pblk + w->len) w->len = 0;
    }
}

static void pa_set(sfs_fs *fs, uint32_t ino, uint32_t lblk, uint64_t pblk, uint32_t len)
{
    sfs_pa *w = pa_of(fs, ino), *victim = 0;
    uint32_t i;
    if (!w) {
        for (i = 0; i < PA_MAX; ++i) {
            sfs_pa *c = &fs->pa->w[i];
            if (!c->len) { victim = c; break; }
            if (!victim || c->age < victim->age) victim = c;
        }
        w = victim;
    }
    w->ino = ino;
    w->lblk = lblk;
    w->pblk = pblk;
    w->len = len;
    w->age = ++fs->pa->clock;
}

/* ---- goals ---- */
uint64_t sfs_goal_for(sfs_fs *fs, sfs_inode *in, uint32_t lblk)
{
    uint32_t g;
    if (in) {
        if (in->last_pblk && lblk > in->last_lblk && lblk - in->last_lblk < fs->bpg) {
            uint64_t goal = in->last_pblk + (lblk - in->last_lblk);
            if (goal < fs->nblocks) return goal;
        }
        if (lblk && (in->flags & IFL_EXTENTS)) {
            uint64_t p;
            uint32_t len;
            int unw;
            if (sfs_map_block(fs, in, lblk - 1, &p, &len, &unw) == 1 && p + 1 < fs->nblocks) return p + 1;
        }
        g = sfs_group_of_inode(fs, in->ino);
    } else {
        g = fs->alloc_hint_group;
    }
    if (fs->log_groups_per_flex && fs->log_groups_per_flex < 31) g -= g % (1u << fs->log_groups_per_flex);
    if (g >= fs->ngroups) g = 0;
    return sfs_group_first_block(fs, g);
}

/* ---- block allocation ---- */
static int take_run(sfs_fs *fs, uint32_t g, sfs_gd *gd, sfs_buf *bb, uint32_t bit, uint32_t n)
{
    int rc;
    set_bits(bb->data, bit, n);
    gd->free_blocks -= n;
    gd->flags &= (uint16_t)~BG_BLOCK_UNINIT;
    sfs_block_bitmap_csum_set(fs, gd, bb->data);
    rc = sfs_bdirty_meta(fs, bb);
    if (!rc) rc = sfs_gd_write(fs, g, gd);
    fs->free_blocks -= n;
    fs->txn.sb_dirty = 1;
    return rc;
}

/* Searches group g from bit `from` for a free run (up to want) that avoids other inodes' windows when strict. */
static int search_group(sfs_fs *fs, uint32_t ino, uint32_t g, uint32_t from, uint32_t want, int strict,
                        uint64_t *start, uint32_t *got)
{
    sfs_gd gd;
    sfs_buf *bb;
    uint32_t cnt, bit;
    uint64_t first = sfs_group_first_block(fs, g);
    int rc = sfs_gd_read(fs, g, &gd);
    if (rc) return rc;
    if (gd.free_blocks == 0) return SFS_ENOSPC;
    rc = sfs_block_bitmap(fs, g, &gd, &bb);
    if (rc == SFS_ECORRUPT) return SFS_ENOSPC;          /* unusable group: skip it, never allocate from it */
    if (rc) return rc;
    cnt = sfs_group_block_count(fs, g);
    bit = from < cnt ? from : 0;
    while (bit < cnt) {
        uint32_t s = find_zero(bb->data, bit, cnt), e, lim;
        uint64_t ws, we;
        if (s >= cnt) break;
        lim = s + want < cnt ? s + want : cnt;
        e = find_one(bb->data, s, lim);
        if (strict && pa_conflict(fs, ino, first + s, e - s, &ws, &we)) {
            if (ws > first + s) {
                e = (uint32_t)(ws - first);            /* the free piece in front of the window */
            } else {
                bit = (uint32_t)(we - first);
                continue;
            }
        }
        if (!strict) pa_drop_overlap(fs, first + s, e - s);
        rc = take_run(fs, g, &gd, bb, s, e - s);
        sfs_bput(fs, bb);
        if (rc) return rc;
        *start = first + s;
        *got = e - s;
        return 0;
    }
    sfs_bput(fs, bb);
    return SFS_ENOSPC;
}

static int alloc_search(sfs_fs *fs, uint32_t ino, uint64_t goal, uint32_t want, uint64_t *start, uint32_t *got)
{
    uint32_t g0, i, pass;
    if (!sfs_block_valid(fs, goal)) goal = fs->first_data_block;
    g0 = sfs_group_of_block(fs, goal);
    for (pass = 0; pass < 2; ++pass) {
        uint32_t goal_off = (uint32_t)(goal - sfs_group_first_block(fs, g0));
        for (i = 0; i <= fs->ngroups; ++i) {
            uint32_t g = (g0 + i) % fs->ngroups, from;
            int rc;
            if (i == fs->ngroups) {                             /* wrapped: the goal group's head */
                if (!goal_off) break;
                from = 0;
            } else {
                from = i == 0 ? goal_off : 0;
            }
            rc = search_group(fs, ino, g, from, want, pass == 0 && !(fs->mflags & SFS_MOUNT_NAIVE), start, got);
            if (rc != SFS_ENOSPC) {
                if (!rc) fs->alloc_hint_group = g;
                return rc;
            }
        }
    }
    return SFS_ENOSPC;
}

int sfs_alloc_blocks(sfs_fs *fs, sfs_inode *in, uint32_t lblk, uint64_t goal, uint32_t want, uint64_t *start, uint32_t *got)
{
    int rc;
    uint32_t ino = in ? in->ino : 0;
    if (!want) return SFS_EINVAL;
    if (want > EXT_INIT_MAX_LEN) want = EXT_INIT_MAX_LEN;
    if (fs->free_blocks == 0) return SFS_ENOSPC;
    if (in && !(fs->mflags & SFS_MOUNT_NAIVE)) {
        sfs_pa *w = pa_of(fs, ino);
        if (w && w->lblk == lblk) {
            /* consume the front of this file's window (still free: only this inode allocates from it) */
            uint32_t g = sfs_group_of_block(fs, w->pblk);
            uint64_t first = sfs_group_first_block(fs, g);
            uint32_t bit = (uint32_t)(w->pblk - first), cnt = sfs_group_block_count(fs, g);
            sfs_gd gd;
            sfs_buf *bb;
            rc = sfs_gd_read(fs, g, &gd);
            if (!rc) rc = sfs_block_bitmap(fs, g, &gd, &bb);
            if (!rc) {
                uint32_t lim = bit + sfs_min32(want, w->len), e;
                if (lim > cnt) lim = cnt;
                e = find_one(bb->data, bit, lim);
                if (e > bit) {
                    rc = take_run(fs, g, &gd, bb, bit, e - bit);
                    sfs_bput(fs, bb);
                    if (rc) return rc;
                    *start = w->pblk;
                    *got = e - bit;
                    w->pblk += *got;
                    w->lblk += *got;
                    w->len -= *got;
                    w->age = ++fs->pa->clock;
                    goto done;
                }
                sfs_bput(fs, bb);
            } else if (rc != SFS_ECORRUPT) {
                return rc;
            }
            w->len = 0;
        } else if (w) {
            w->len = 0;                                  /* not sequential any more */
        }
    }
    rc = alloc_search(fs, ino, goal, want, start, got);
    if (rc) return rc;
done:
    if (in) {
        in->last_lblk = lblk + *got - 1;
        in->last_pblk = *start + *got - 1;
        if (!(fs->mflags & SFS_MOUNT_NAIVE) && sfs_is_reg(in)) {
            sfs_pa *w = pa_of(fs, ino);
            if (!w || !w->len) {
                /* reserve the free run behind this allocation for the file's next blocks */
                uint64_t nb = *start + *got;
                uint32_t size_blocks = (uint32_t)sfs_min64(in->nblocks + *got, 0x7FFFFFFFu);
                uint32_t wlen = size_blocks < 32 ? 32 : size_blocks > 2048 ? 2048 : size_blocks;
                if (nb < fs->nblocks) {
                    uint32_t g = sfs_group_of_block(fs, nb);
                    uint64_t first = sfs_group_first_block(fs, g);
                    sfs_gd gd;
                    sfs_buf *bb;
                    if (!sfs_gd_read(fs, g, &gd) && gd.free_blocks && !sfs_block_bitmap(fs, g, &gd, &bb)) {
                        uint32_t bit = (uint32_t)(nb - first), cnt = sfs_group_block_count(fs, g);
                        uint32_t lim = bit + wlen < cnt ? bit + wlen : cnt;
                        uint32_t e = find_one(bb->data, bit, lim);
                        uint64_t ws, we;
                        if (e > bit && pa_conflict(fs, ino, nb, e - bit, &ws, &we)) e = ws > nb ? (uint32_t)(ws - first) : bit;
                        if (e > bit) pa_set(fs, ino, lblk + *got, nb, e - bit);
                        sfs_bput(fs, bb);
                    }
                }
            }
        }
    }
    return 0;
}

int sfs_alloc_meta_block(sfs_fs *fs, sfs_inode *in, uint64_t goal, uint64_t *blk)
{
    uint32_t got;
    (void)in;
    if (fs->free_blocks == 0) return SFS_ENOSPC;
    return alloc_search(fs, 0, goal, 1, blk, &got);
}

/* Refuses to free blocks that belong to the file system's own metadata (a corrupt pointer must not free the
 * inode table). Checks the groups the run touches and their flex group's tables. */
static int run_hits_meta(sfs_fs *fs, uint64_t start, uint32_t count)
{
    uint32_t g = sfs_group_of_block(fs, start), gl = sfs_group_of_block(fs, start + count - 1);
    uint64_t end = start + count;
    for (; g <= gl; ++g) {
        uint32_t h, h0 = g, h1 = g + 1;
        uint64_t first = sfs_group_first_block(fs, g);
        uint32_t nsb = sfs_group_super_blocks(fs, g);
        if (nsb && start < first + nsb && end > first) return 1;
        if (fs->log_groups_per_flex && fs->log_groups_per_flex < 31) {
            uint32_t per = 1u << fs->log_groups_per_flex;
            h0 = g - g % per;
            h1 = h0 + per;
        }
        if (h1 > fs->ngroups) h1 = fs->ngroups;
        for (h = h0; h < h1; ++h) {
            sfs_gd gd;
            if (sfs_gd_read(fs, h, &gd)) return 1;
            if ((gd.block_bitmap >= start && gd.block_bitmap < end) || (gd.inode_bitmap >= start && gd.inode_bitmap < end)) return 1;
            if (gd.inode_table < end && start < gd.inode_table + fs->itable_blocks) return 1;
        }
    }
    return 0;
}

int sfs_free_blocks(sfs_fs *fs, uint64_t start, uint32_t count, int metadata)
{
    uint32_t i;
    int rc;
    if (!count) return 0;
    if (!sfs_range_valid(fs, start, count) || run_hits_meta(fs, start, count)) {
        sfs_logu(fs, "sfs: refusing to free a metadata or out-of-range block run at ", start);
        return SFS_ECORRUPT;
    }
    for (i = 0; i < count; ++i) sfs_bforget(fs, start + i);
    rc = sfs_runpage_add(fs, &fs->txn.frees, start, count, (uint32_t)metadata);
    if (rc) return rc;
    fs->txn.nfrees++;
    fs->txn.free_blocks_pending += count;
    fs->mods++;
    if (metadata && fs->jnl.present) {
        rc = sfs_runpage_add(fs, &fs->txn.revokes, start, count, 1);
        if (rc) return rc;
        fs->txn.nrevokes += count;
    }
    return 0;
}

int sfs_apply_pending_frees(sfs_fs *fs)
{
    sfs_runpage *p;
    int rc = 0;
    for (p = fs->txn.frees; p && !rc; p = p->next) {
        uint32_t i;
        for (i = 0; i < p->count && !rc; ++i) {
            uint64_t s = p->run[i].start;
            uint64_t n = p->run[i].len;
            while (n && !rc) {
                uint32_t g = sfs_group_of_block(fs, s);
                uint64_t first = sfs_group_first_block(fs, g);
                uint32_t off = (uint32_t)(s - first);
                uint32_t k = (uint32_t)sfs_min64(n, sfs_group_block_count(fs, g) - off);
                sfs_gd gd;
                sfs_buf *bb;
                uint32_t bad;
                rc = sfs_gd_read(fs, g, &gd);
                if (!rc) rc = sfs_block_bitmap(fs, g, &gd, &bb);
                if (rc) break;
                bad = clear_bits(bb->data, off, k);
                if (bad) {
                    sfs_logu(fs, "sfs: freeing blocks that were already free at ", s);
                    sfs_bput(fs, bb);
                    rc = SFS_ECORRUPT;
                    break;
                }
                gd.free_blocks += k;
                sfs_block_bitmap_csum_set(fs, &gd, bb->data);
                rc = sfs_bdirty_meta(fs, bb);
                sfs_bput(fs, bb);
                if (!rc) rc = sfs_gd_write(fs, g, &gd);
                fs->free_blocks += k;
                s += k;
                n -= k;
            }
        }
    }
    if (fs->txn.frees) fs->txn.sb_dirty = 1;
    sfs_runpage_free(fs, &fs->txn.frees);
    fs->txn.nfrees = 0;
    fs->txn.free_blocks_pending = 0;
    return rc;
}

/* ---- inodes ---- */
static int zero_inode_slots(sfs_fs *fs, uint32_t g, uint32_t from, uint32_t to)
{
    uint32_t idx;
    for (idx = from; idx < to; ++idx) {
        uint64_t blk;
        uint32_t off;
        sfs_buf *b;
        int rc = sfs_inode_loc(fs, g * fs->ipg + idx + 1, &blk, &off);
        if (!rc) rc = sfs_bread(fs, blk, &b);
        if (rc) return rc;
        memset(b->data + off, 0, fs->isize);
        rc = sfs_bdirty_meta(fs, b);
        sfs_bput(fs, b);
        if (rc) return rc;
    }
    return 0;
}

static int try_group_inode(sfs_fs *fs, uint32_t g, int is_dir, uint32_t *ino)
{
    sfs_gd gd;
    sfs_buf *ib;
    uint32_t start = 0, idx;
    int rc = sfs_gd_read(fs, g, &gd);
    if (rc) return rc;
    if (!gd.free_inodes) return SFS_ENOSPC;
    rc = sfs_inode_bitmap(fs, g, &gd, &ib);
    if (rc == SFS_ECORRUPT) return SFS_ENOSPC;
    if (rc) return rc;
    if (g == 0) start = fs->first_ino - 1;
    idx = find_zero(ib->data, start, fs->ipg);
    if (idx >= fs->ipg) { sfs_bput(fs, ib); return SFS_ENOSPC; }
    if (fs->csum || fs->gdt_csum) {
        uint32_t ub = fs->ipg - gd.itable_unused;
        if (idx >= ub) {
            if (idx > ub && !(gd.flags & BG_INODE_ZEROED)) {
                rc = zero_inode_slots(fs, g, ub, idx);
                if (rc) { sfs_bput(fs, ib); return rc; }
            }
            gd.itable_unused = fs->ipg - idx - 1;
        }
    }
    sfs_set_bit(ib->data, idx);
    gd.free_inodes--;
    if (is_dir) gd.used_dirs++;
    gd.flags &= (uint16_t)~BG_INODE_UNINIT;
    sfs_inode_bitmap_csum_set(fs, &gd, ib->data);
    rc = sfs_bdirty_meta(fs, ib);
    sfs_bput(fs, ib);
    if (!rc) rc = sfs_gd_write(fs, g, &gd);
    if (rc) return rc;
    fs->free_inodes--;
    fs->txn.sb_dirty = 1;
    *ino = g * fs->ipg + idx + 1;
    return 0;
}

int sfs_alloc_inode(sfs_fs *fs, uint32_t parent, int is_dir, uint32_t *ino)
{
    uint32_t g0 = sfs_ino_valid(fs, parent) ? sfs_group_of_inode(fs, parent) : 0, i;
    int rc;
    if (!fs->free_inodes) return SFS_ENOSPC;
    if (is_dir && parent == SFS_ROOT_INO && fs->ngroups > 1) {
        /* spread top-level directories over groups with at least average free inodes and blocks */
        uint64_t avg_blocks = fs->free_blocks / fs->ngroups;
        uint32_t avg_inodes = fs->free_inodes / fs->ngroups;
        for (i = 0; i < fs->ngroups; ++i) {
            uint32_t g = (fs->dir_rotor + i) % fs->ngroups;
            sfs_gd gd;
            if (sfs_gd_read(fs, g, &gd)) continue;
            if (gd.free_inodes && gd.free_inodes >= avg_inodes && gd.free_blocks >= avg_blocks) {
                rc = try_group_inode(fs, g, is_dir, ino);
                if (rc != SFS_ENOSPC) {
                    if (!rc) fs->dir_rotor = g + 1;
                    return rc;
                }
            }
        }
    }
    for (i = 0; i < fs->ngroups; ++i) {
        rc = try_group_inode(fs, (g0 + i) % fs->ngroups, is_dir, ino);
        if (rc != SFS_ENOSPC) return rc;
    }
    return SFS_ENOSPC;
}

int sfs_free_inode(sfs_fs *fs, uint32_t ino, int is_dir)
{
    uint32_t g = sfs_group_of_inode(fs, ino), idx = (ino - 1) % fs->ipg;
    sfs_gd gd;
    sfs_buf *ib;
    int rc;
    if (!sfs_ino_valid(fs, ino) || ino < fs->first_ino) return SFS_ECORRUPT;
    rc = sfs_gd_read(fs, g, &gd);
    if (!rc) rc = sfs_inode_bitmap(fs, g, &gd, &ib);
    if (rc) return rc;
    if (!sfs_test_bit(ib->data, idx)) {
        sfs_bput(fs, ib);
        sfs_logu(fs, "sfs: freeing an inode that was already free: ", ino);
        return SFS_ECORRUPT;
    }
    sfs_clear_bit(ib->data, idx);
    gd.free_inodes++;
    if (is_dir && gd.used_dirs) gd.used_dirs--;
    sfs_inode_bitmap_csum_set(fs, &gd, ib->data);
    rc = sfs_bdirty_meta(fs, ib);
    sfs_bput(fs, ib);
    if (!rc) rc = sfs_gd_write(fs, g, &gd);
    fs->free_inodes++;
    fs->txn.sb_dirty = 1;
    sfs_pa_release(fs, ino);
    return rc;
}
