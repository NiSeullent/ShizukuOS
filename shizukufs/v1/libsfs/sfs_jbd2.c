/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS v1 journal: the jbd2 format of ext4 (internal journal in inode s_journal_inum, big-endian records).
 *
 * Recovery follows the three jbd2 passes: SCAN finds the last complete transaction (descriptor/commit/revoke
 * blocks with matching sequence numbers, checksums v2/v3 verified), REVOKE collects revoke records, REPLAY writes
 * every logged block that is not revoked by the same or a later transaction (per-block tag checksums verified,
 * escaped blocks restored).
 *
 * Commits are ordered-mode: dirty file data first, then revoke records, descriptor blocks and the metadata copies,
 * a flush, the commit block, a flush; then the metadata is checkpointed in place. The on-disk log tail moves only
 * when the log wraps (after a flush that makes every checkpoint durable) and at unmount, so a crash replays at
 * most the transactions since the last wrap, which is idempotent.
 */
#include "sfs_internal.h"

#define TAIL(j) ((j)->csum_v2 || (j)->csum_v3 ? 4u : 0u)

static uint32_t jwrap(sfs_journal *j, uint32_t b) { return b >= j->maxlen ? b - j->maxlen + j->first : b; }

static int jmap(sfs_fs *fs, uint32_t jblk, uint64_t *pblk)
{
    sfs_jmap *m = fs->jnl.map;
    uint32_t lo = 0, hi;
    if (!m || !m->count) return SFS_ECORRUPT;
    hi = m->count;
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        if (jblk < m->e[mid].lblk) hi = mid;
        else if (jblk - m->e[mid].lblk >= m->e[mid].len) lo = mid + 1;
        else { *pblk = m->e[mid].pblk + (jblk - m->e[mid].lblk); return 0; }
    }
    return SFS_ECORRUPT;
}

static int jread(sfs_fs *fs, uint32_t jblk, void *buf)
{
    uint64_t p;
    int rc = jmap(fs, jblk, &p);
    return rc ? rc : sfs_dev_read(fs, p, buf, 1);
}

static int jwrite(sfs_fs *fs, uint32_t jblk, const void *buf)
{
    uint64_t p;
    int rc = jmap(fs, jblk, &p);
    if (rc) return rc;
    fs->st.journal_blocks_written++;
    return sfs_dev_write(fs, p, buf, 1);
}

static int jmap_add(sfs_fs *fs, uint32_t lblk, uint64_t pblk, uint32_t len)
{
    sfs_jmap *m = fs->jnl.map;
    if (m->count) {
        uint32_t i = m->count - 1;
        if (m->e[i].lblk + m->e[i].len == lblk && m->e[i].pblk + m->e[i].len == pblk) { m->e[i].len += len; return 0; }
        if (lblk < m->e[i].lblk + m->e[i].len) return SFS_ECORRUPT;
    }
    if (m->count >= JMAP_MAX) return SFS_ENOTSUP;
    m->e[m->count].lblk = lblk;
    m->e[m->count].pblk = pblk;
    m->e[m->count].len = len;
    m->count++;
    return 0;
}

static int jmap_cb(void *ctx, uint32_t lblk, uint64_t pblk, uint32_t len, int unwritten)
{
    (void)unwritten;
    return jmap_add((sfs_fs *)ctx, lblk, pblk, len);
}

/* ---- checksums ---- */
static uint32_t jsb_csum(const uint8_t *sb)
{
    static const uint8_t zero4[4] = {0, 0, 0, 0};
    uint32_t c = sfs_crc32c(0xFFFFFFFFu, sb, JS_checksum);
    c = sfs_crc32c(c, zero4, 4);
    return sfs_crc32c(c, sb + JS_checksum + 4, JS_SIZE - JS_checksum - 4);
}

static int block_tail_ok(sfs_fs *fs, const uint8_t *b)
{
    static const uint8_t zero4[4] = {0, 0, 0, 0};
    uint32_t c;
    if (!TAIL(&fs->jnl)) return 1;
    c = sfs_crc32c(fs->jnl.csum_seed, b, fs->bs - 4);
    c = sfs_crc32c(c, zero4, 4);
    return rdbe32(b, fs->bs - 4) == c;
}

static void block_tail_set(sfs_fs *fs, uint8_t *b)
{
    if (!TAIL(&fs->jnl)) return;
    wrbe32(b, fs->bs - 4, 0);
    wrbe32(b, fs->bs - 4, sfs_crc32c(fs->jnl.csum_seed, b, fs->bs));
}

static uint32_t commit_csum(sfs_fs *fs, const uint8_t *b)
{
    static const uint8_t zero[JC_commit_sec - JC_chksum_type];
    uint32_t c = sfs_crc32c(fs->jnl.csum_seed, b, JC_chksum_type);
    c = sfs_crc32c(c, zero, sizeof zero);
    return sfs_crc32c(c, b + JC_commit_sec, fs->bs - JC_commit_sec);
}

static uint32_t tag_csum(sfs_fs *fs, uint32_t seq, const uint8_t *data)
{
    uint8_t be[4];
    wrbe32(be, 0, seq);
    return sfs_crc32c(sfs_crc32c(fs->jnl.csum_seed, be, 4), data, fs->bs);
}

/* ---- tags ---- */
typedef struct jtag { uint64_t blk; uint32_t flags; uint32_t csum; } jtag;

static int tag_next(sfs_fs *fs, const uint8_t *d, uint32_t *off, jtag *t)
{
    sfs_journal *j = &fs->jnl;
    const uint8_t *p;
    uint32_t limit = fs->bs - TAIL(j);
    if (*off + j->tag_bytes > limit) return 0;
    p = d + *off;
    t->blk = rdbe32(p, 0);
    if (j->csum_v3) {
        t->flags = rdbe32(p, 4);
        if (j->has64) t->blk |= (uint64_t)rdbe32(p, 8) << 32;
        t->csum = rdbe32(p, 12);
    } else {
        t->flags = rdbe16(p, 6);
        if (j->has64) t->blk |= (uint64_t)rdbe32(p, 8) << 32;
        t->csum = j->csum_v2 ? rdbe16(p, 4) : 0;
    }
    *off += j->tag_bytes;
    if (!(t->flags & JBD2_FLAG_SAME_UUID)) *off += 16;
    return 1;
}

static uint32_t count_tags(sfs_fs *fs, const uint8_t *d)
{
    uint32_t off = JH_SIZE, n = 0;
    jtag t;
    while (tag_next(fs, d, &off, &t)) {
        n++;
        if (t.flags & JBD2_FLAG_LAST_TAG) break;
    }
    return n;
}

/* ---- revoke table used during replay ---- */
typedef struct rvk { uint64_t blk; uint32_t seq; struct rvk *next; } rvk;
#define RVK_BUCKETS (SFS_MAX_ALLOC / sizeof(rvk *))

static int rvk_set(sfs_fs *fs, rvk **tab, uint64_t blk, uint32_t seq)
{
    uint32_t h = (uint32_t)((blk * 0x9E3779B97F4A7C15ull) >> 40) % RVK_BUCKETS;
    rvk *r;
    for (r = tab[h]; r; r = r->next)
        if (r->blk == blk) { if ((int32_t)(seq - r->seq) > 0) r->seq = seq; return 0; }
    r = sfs_alloc(fs, sizeof *r);
    if (!r) return SFS_ENOMEM;
    r->blk = blk;
    r->seq = seq;
    r->next = tab[h];
    tab[h] = r;
    return 0;
}

static int rvk_test(rvk **tab, uint64_t blk, uint32_t seq)
{
    uint32_t h = (uint32_t)((blk * 0x9E3779B97F4A7C15ull) >> 40) % RVK_BUCKETS;
    rvk *r;
    for (r = tab[h]; r; r = r->next)
        if (r->blk == blk) return (int32_t)(seq - r->seq) <= 0;
    return 0;
}

static void rvk_free(sfs_fs *fs, rvk **tab)
{
    uint32_t i;
    for (i = 0; i < RVK_BUCKETS; ++i) {
        while (tab[i]) { rvk *n = tab[i]->next; sfs_free(fs, tab[i], sizeof *tab[i]); tab[i] = n; }
    }
    sfs_free(fs, tab, SFS_MAX_ALLOC);
}

/* ---- recovery ---- */
enum { PASS_SCAN, PASS_REVOKE, PASS_REPLAY };

static int do_pass(sfs_fs *fs, int pass, uint32_t start, uint32_t seq, uint32_t *end_seq, rvk **tab)
{
    sfs_journal *j = &fs->jnl;
    uint8_t *b = fs->scratch, *data = fs->scratch2;
    uint32_t blk = start, guard = 0, next = seq;
    int rc;
    for (;;) {
        uint32_t type;
        if (pass != PASS_SCAN && (int32_t)(next - *end_seq) >= 0) break;
        if (guard++ > 2 * j->maxlen) break;
        rc = jread(fs, blk, b);
        if (rc) return rc;
        if (rdbe32(b, JH_magic) != JBD2_MAGIC || rdbe32(b, JH_sequence) != next) break;
        type = rdbe32(b, JH_blocktype);
        if (type == JBD2_DESCRIPTOR_BLOCK) {
            uint32_t n, off = JH_SIZE, i = 0;
            jtag t;
            if (!block_tail_ok(fs, b)) { if (pass == PASS_SCAN) break; return SFS_ECORRUPT; }
            n = count_tags(fs, b);
            if (pass == PASS_REPLAY) {
                uint8_t *desc = sfs_alloc(fs, fs->bs);
                if (!desc) return SFS_ENOMEM;
                memcpy(desc, b, fs->bs);
                while (i < n && tag_next(fs, desc, &off, &t)) {
                    uint32_t jb = jwrap(j, blk + 1 + i);
                    i++;
                    if (rvk_test(tab, t.blk, next)) { fs->st.revoked_blocks++; continue; }
                    rc = jread(fs, jb, data);
                    if (rc) { sfs_free(fs, desc, fs->bs); return rc; }
                    if (j->csum_v3 || j->csum_v2) {
                        uint32_t c = tag_csum(fs, next, data);
                        if (j->csum_v2 && !j->csum_v3) c &= 0xFFFF;
                        if (c != t.csum) { sfs_logu(fs, "sfs: journal block checksum mismatch, skipping block ", t.blk); continue; }
                    }
                    if (t.flags & JBD2_FLAG_ESCAPE) wrbe32(data, 0, JBD2_MAGIC);
                    if (t.blk < fs->first_data_block && !(t.blk == 0 && fs->bs > 1024)) continue;
                    if (t.blk >= fs->nblocks) { sfs_logu(fs, "sfs: journal names a block beyond the volume: ", t.blk); continue; }
                    sfs_bforget(fs, t.blk);
                    rc = sfs_dev_write(fs, t.blk, data, 1);
                    if (rc) { sfs_free(fs, desc, fs->bs); return rc; }
                    fs->st.replayed_blocks++;
                }
                sfs_free(fs, desc, fs->bs);
            }
            blk = jwrap(j, blk + 1 + n);
        } else if (type == JBD2_COMMIT_BLOCK) {
            if (pass == PASS_SCAN && TAIL(j) && rdbe32(b, JC_chksum) != commit_csum(fs, b)) break;
            if (pass == PASS_REPLAY) fs->st.replayed_transactions++;
            next++;
            blk = jwrap(j, blk + 1);
        } else if (type == JBD2_REVOKE_BLOCK) {
            if (!block_tail_ok(fs, b)) { if (pass == PASS_SCAN) break; return SFS_ECORRUPT; }
            if (pass == PASS_REVOKE) {
                uint32_t cnt = rdbe32(b, JR_count), off, rs = j->has64 ? 8 : 4;
                if (cnt > fs->bs - TAIL(j)) return SFS_ECORRUPT;
                for (off = JR_HDR; off + rs <= cnt; off += rs) {
                    uint64_t rb = j->has64 ? rdbe64(b, off) : rdbe32(b, off);
                    rc = rvk_set(fs, tab, rb, next);
                    if (rc) return rc;
                }
            }
            blk = jwrap(j, blk + 1);
        } else {
            break;
        }
    }
    if (pass == PASS_SCAN) *end_seq = next;
    return 0;
}

static int write_jsb(sfs_fs *fs, uint32_t start, uint32_t seq);

static int recover(sfs_fs *fs, uint32_t start, uint32_t seq)
{
    uint32_t end_seq = seq;
    rvk **tab;
    int rc;
    rc = do_pass(fs, PASS_SCAN, start, seq, &end_seq, 0);
    if (rc) return rc;
    tab = sfs_alloc(fs, SFS_MAX_ALLOC);
    if (!tab) return SFS_ENOMEM;
    memset(tab, 0, SFS_MAX_ALLOC);
    if (end_seq != seq) {
        rc = do_pass(fs, PASS_REVOKE, start, seq, &end_seq, tab);
        if (!rc) rc = do_pass(fs, PASS_REPLAY, start, seq, &end_seq, tab);
    }
    rvk_free(fs, tab);
    if (rc) return rc;
    sfs_logu(fs, "sfs: journal replayed, transactions: ", end_seq - seq);
    rc = sfs_dev_flush(fs);
    if (rc) return rc;
    fs->jnl.next_seq = end_seq + 1;
    rc = write_jsb(fs, 0, fs->jnl.next_seq);
    if (!rc) rc = sfs_dev_flush(fs);
    if (rc) return rc;
    /* the superblock on disk may have been replaced by the replay: clear needs_recovery on the fresh copy */
    if (fs->ops.read(fs->ops.ctx, SB_OFFSET, fs->sbraw, 1024)) return SFS_EIO;
    wr32(fs->sbraw, SB_feature_incompat, rd32(fs->sbraw, SB_feature_incompat) & ~INCOMPAT_RECOVER);
    if (rd32(fs->sbraw, SB_feature_ro_compat) & RO_COMPAT_METADATA_CSUM)
        wr32(fs->sbraw, SB_checksum, sfs_crc32c(0xFFFFFFFFu, fs->sbraw, SB_checksum));
    {
        uint32_t sbblk = fs->bs == 1024 ? 1 : 0;
        uint8_t *blk = fs->scratch;
        rc = sfs_dev_read(fs, sbblk, blk, 1);
        if (rc) return rc;
        memcpy(blk + (fs->bs == 1024 ? 0 : 1024), fs->sbraw, 1024);
        rc = sfs_dev_write(fs, sbblk, blk, 1);
        sfs_bforget(fs, sbblk);
    }
    if (!rc) rc = sfs_dev_flush(fs);
    return rc;
}

/* ---- journal superblock ---- */
static int write_jsb(sfs_fs *fs, uint32_t start, uint32_t seq)
{
    uint8_t *b = fs->scratch2;
    int rc = jread(fs, 0, b);
    if (rc) return rc;
    wrbe32(b, JS_start, start);
    wrbe32(b, JS_sequence, seq);
    if (rdbe32(b, JH_blocktype) == JBD2_SUPERBLOCK_V2) {
        wrbe32(b, JS_feature_compat, fs->jnl.feat_compat);
        wrbe32(b, JS_feature_incompat, fs->jnl.feat_incompat);
        if (fs->jnl.csum_v2 || fs->jnl.csum_v3) b[JS_checksum_type] = JBD2_CRC32C_CHKSUM;
    }
    if (fs->jnl.csum_v2 || fs->jnl.csum_v3) wrbe32(b, JS_checksum, jsb_csum(b));
    rc = jwrite(fs, 0, b);
    if (!rc) fs->jnl.disk_start = start;
    return rc;
}

uint32_t sfs_journal_capacity(sfs_fs *fs) { return fs->jnl.maxlen > fs->jnl.first ? fs->jnl.maxlen - fs->jnl.first : 0; }

int sfs_journal_load(sfs_fs *fs, int replay)
{
    sfs_journal *j = &fs->jnl;
    sfs_inode *ji;
    uint8_t *b;
    uint32_t inum = rd32(fs->sbraw, SB_journal_inum), type, start, seq, nblk;
    int rc;
    sfs_journal_unload(fs);
    memset(j, 0, sizeof *j);
    if (!inum || !sfs_ino_valid(fs, inum)) { fs->ro = 1; fs->ro_reason |= SFS_RO_UNKNOWN_RO_COMPAT; return 0; }
    j->inum = inum;
    rc = sfs_iget(fs, inum, &ji);
    if (rc) return rc;
    j->map = sfs_alloc(fs, sizeof(sfs_jmap));
    if (!j->map) { sfs_iput(fs, ji); return SFS_ENOMEM; }
    nblk = (uint32_t)sfs_min64(ji->size >> fs->bs_bits, 0xFFFFFFFFu);
    if (ji->flags & IFL_EXTENTS) {
        rc = sfs_ext_iterate(fs, ji, jmap_cb, fs);
    } else {
        uint32_t l = 0;
        while (!rc && l < nblk) {
            uint64_t p;
            uint32_t len;
            int r = sfs_bmap_lookup(fs, ji, l, &p, &len);
            if (r < 0) rc = r;
            else if (r == 0) rc = SFS_ECORRUPT;
            else { len = sfs_min32(len, nblk - l); rc = jmap_add(fs, l, p, len); l += len; }
        }
    }
    sfs_iput(fs, ji);
    sfs_iforget(fs, inum);
    if (rc) return rc == SFS_ENOTSUP ? (fs->ro = 1, fs->ro_reason |= SFS_RO_UNKNOWN_RO_COMPAT, 0) : rc;
    if (nblk < 1024 || !j->map->count || j->map->e[0].lblk != 0) return SFS_ECORRUPT;
    {
        uint32_t i, covered = 0;
        for (i = 0; i < j->map->count; ++i) { if (j->map->e[i].lblk != covered) return SFS_ECORRUPT; covered += j->map->e[i].len; }
        if (covered < nblk) return SFS_ECORRUPT;
    }
    b = fs->scratch;
    rc = jread(fs, 0, b);
    if (rc) return rc;
    type = rdbe32(b, JH_blocktype);
    if (rdbe32(b, JH_magic) != JBD2_MAGIC || (type != JBD2_SUPERBLOCK_V1 && type != JBD2_SUPERBLOCK_V2)) return SFS_ECORRUPT;
    if (rdbe32(b, JS_blocksize) != fs->bs) return SFS_ECORRUPT;
    j->maxlen = rdbe32(b, JS_maxlen);
    j->first = rdbe32(b, JS_first);
    if (j->maxlen > nblk || j->maxlen < 1024 || j->first == 0 || j->first >= j->maxlen) return SFS_ECORRUPT;
    if (type == JBD2_SUPERBLOCK_V2) {
        j->feat_compat = rdbe32(b, JS_feature_compat);
        j->feat_incompat = rdbe32(b, JS_feature_incompat);
        j->feat_ro = rdbe32(b, JS_feature_ro_compat);
    }
    memcpy(j->uuid, b + JS_uuid, 16);
    j->csum_v2 = !!(j->feat_incompat & JBD2_INCOMPAT_CSUM_V2);
    j->csum_v3 = !!(j->feat_incompat & JBD2_INCOMPAT_CSUM_V3);
    j->has64 = !!(j->feat_incompat & JBD2_INCOMPAT_64BIT);
    if (j->csum_v2 || j->csum_v3) {
        if (b[JS_checksum_type] != JBD2_CRC32C_CHKSUM) return SFS_ENOTSUP;
        if (rdbe32(b, JS_checksum) != jsb_csum(b)) { sfs_log(fs, "sfs: journal superblock checksum mismatch"); return SFS_ECORRUPT; }
        j->csum_seed = sfs_crc32c(0xFFFFFFFFu, j->uuid, 16);
    }
    if (j->csum_v3) j->tag_bytes = 16;
    else j->tag_bytes = 8 + (j->csum_v2 ? 2u : 0u) + (j->has64 ? 4u : 0u);
    start = rdbe32(b, JS_start);
    seq = rdbe32(b, JS_sequence);
    if (rdbe32(b, JS_errno)) { fs->ro = 1; fs->ro_reason |= SFS_RO_JOURNAL_ERRNO; }
    if ((j->feat_incompat & ~JBD2_INCOMPAT_SUPPORTED) || (j->feat_incompat & JBD2_INCOMPAT_FAST_COMMIT)) {
        fs->ro = 1;
        fs->ro_reason |= SFS_RO_JOURNAL_FAST_COMMIT;
        if (start) return SFS_ENOTSUP;                  /* cannot replay what we do not understand */
        return 0;
    }
    if (start && (start < j->first || start >= j->maxlen)) return SFS_ECORRUPT;
    j->next_seq = seq;
    j->head = j->first;
    j->disk_start = start;
    if (start || (fs->feat_incompat & INCOMPAT_RECOVER)) {
        if (!replay) {
            if (start) {
                sfs_log(fs, "sfs: journal needs recovery; mounted read-only without replay (contents may be stale)");
                fs->ro = 1;
                fs->ro_reason |= SFS_RO_NEEDS_REPLAY;
            }
            return 0;
        }
        if (start) {
            rc = recover(fs, start, seq);
            if (rc) return rc;
        } else {
            fs->jnl.next_seq = seq;
        }
        j->present = 1;
        j->head = j->first;
        j->disk_start = 0;
        return 1;
    }
    j->present = 1;
    if (replay && type == JBD2_SUPERBLOCK_V2) {
        /* Writing: set the journal features the way the Linux ext4 driver does at mount (revoke records, 64-bit
         * block numbers on 64bit volumes, v3 checksums with metadata_csum). The log is empty, so this is safe. */
        uint32_t inc = j->feat_incompat | JBD2_INCOMPAT_REVOKE;
        uint32_t comp = j->feat_compat & ~JBD2_COMPAT_CHECKSUM;   /* v1 crc32 commit checksums are not produced */
        if (fs->has64) inc |= JBD2_INCOMPAT_64BIT;
        if (fs->csum) inc = (inc | JBD2_INCOMPAT_CSUM_V3) & ~JBD2_INCOMPAT_CSUM_V2;
        if (inc != j->feat_incompat || comp != j->feat_compat) {
            j->feat_incompat = inc;
            j->feat_compat = comp;
            j->csum_v2 = !!(inc & JBD2_INCOMPAT_CSUM_V2);
            j->csum_v3 = !!(inc & JBD2_INCOMPAT_CSUM_V3);
            j->has64 = !!(inc & JBD2_INCOMPAT_64BIT);
            if (j->csum_v2 || j->csum_v3) j->csum_seed = sfs_crc32c(0xFFFFFFFFu, j->uuid, 16);
            j->tag_bytes = j->csum_v3 ? 16 : 8 + (j->csum_v2 ? 2u : 0u) + (j->has64 ? 4u : 0u);
            rc = write_jsb(fs, 0, j->next_seq);
            if (!rc) rc = sfs_dev_flush(fs);
            if (rc) return rc;
        }
    }
    return 0;
}

void sfs_journal_unload(sfs_fs *fs)
{
    if (fs->jnl.map) sfs_free(fs, fs->jnl.map, sizeof(sfs_jmap));
    fs->jnl.map = 0;
    fs->jnl.present = 0;
}

int sfs_journal_mark_clean(sfs_fs *fs)
{
    int rc;
    if (!fs->jnl.present) return 0;
    rc = sfs_dev_flush(fs);
    if (!rc && fs->jnl.disk_start != 0) {
        rc = write_jsb(fs, 0, fs->jnl.next_seq);
        if (!rc) rc = sfs_dev_flush(fs);
    }
    if (!rc) fs->jnl.head = fs->jnl.first;
    return rc;
}

/* ---- commit ---- */
static uint32_t tags_per_desc(sfs_fs *fs)
{
    uint32_t space = fs->bs - JH_SIZE - TAIL(&fs->jnl);
    return 1 + (space - fs->jnl.tag_bytes - 16) / fs->jnl.tag_bytes;
}

static void tag_put(sfs_fs *fs, uint8_t *d, uint32_t off, uint64_t blk, uint32_t flags, uint32_t csum)
{
    sfs_journal *j = &fs->jnl;
    uint8_t *p = d + off;
    wrbe32(p, 0, (uint32_t)blk);
    if (j->csum_v3) {
        wrbe32(p, 4, flags);
        wrbe32(p, 8, (uint32_t)(blk >> 32));
        wrbe32(p, 12, csum);
    } else {
        wrbe16(p, 4, j->csum_v2 ? (uint16_t)csum : 0);
        wrbe16(p, 6, (uint16_t)flags);
        if (j->has64) wrbe32(p, 8, (uint32_t)(blk >> 32));
    }
}

static int write_revokes(sfs_fs *fs, uint32_t seq, uint32_t *pos)
{
    sfs_journal *j = &fs->jnl;
    uint8_t *b = fs->scratch;
    uint32_t rs = j->has64 ? 8 : 4, limit = fs->bs - TAIL(j), off = JR_HDR;
    sfs_runpage *p;
    int rc;
    memset(b, 0, fs->bs);
    for (p = fs->txn.revokes; p; p = p->next) {
        uint32_t i;
        for (i = 0; i < p->count; ++i) {
            uint64_t k;
            for (k = 0; k < p->run[i].len; ++k) {
                uint64_t blk = p->run[i].start + k;
                if (off + rs > limit) {
                    wrbe32(b, JH_magic, JBD2_MAGIC);
                    wrbe32(b, JH_blocktype, JBD2_REVOKE_BLOCK);
                    wrbe32(b, JH_sequence, seq);
                    wrbe32(b, JR_count, off);
                    block_tail_set(fs, b);
                    rc = jwrite(fs, *pos, b);
                    if (rc) return rc;
                    *pos = *pos + 1;
                    memset(b, 0, fs->bs);
                    off = JR_HDR;
                }
                if (rs == 8) wrbe64(b, off, blk); else wrbe32(b, off, (uint32_t)blk);
                off += rs;
            }
        }
    }
    if (off > JR_HDR) {
        wrbe32(b, JH_magic, JBD2_MAGIC);
        wrbe32(b, JH_blocktype, JBD2_REVOKE_BLOCK);
        wrbe32(b, JH_sequence, seq);
        wrbe32(b, JR_count, off);
        block_tail_set(fs, b);
        rc = jwrite(fs, *pos, b);
        if (rc) return rc;
        *pos = *pos + 1;
    }
    return 0;
}

int sfs_journal_commit(sfs_fs *fs)
{
    sfs_journal *j = &fs->jnl;
    uint32_t seq = j->next_seq, tpd, ndesc, nrev, need, pos, cap = sfs_journal_capacity(fs);
    uint32_t rs = j->has64 ? 8 : 4;
    sfs_buf *b, *next;
    uint64_t now = sfs_now(fs);
    int rc;
    rc = sfs_cache_write_data(fs);                       /* ordered mode: data first */
    if (rc) return rc;
    if (!fs->txn.nbufs && !fs->txn.nrevokes) {
        fs->st.commits++;
        return sfs_dev_flush(fs);
    }
    sfs_txn_sort(fs);
    tpd = tags_per_desc(fs);
    ndesc = (fs->txn.nbufs + tpd - 1) / tpd;
    nrev = (uint32_t)(((uint64_t)fs->txn.nrevokes * rs + (fs->bs - JR_HDR - TAIL(j)) - 1) / (fs->bs - JR_HDR - TAIL(j)));
    need = fs->txn.nbufs + ndesc + nrev + 1;
    if (need > cap) {
        sfs_logu(fs, "sfs: transaction larger than the journal, blocks: ", need);
        return SFS_ENOSPC;
    }
    for (b = fs->txn.bufs; b; b = b->tnext)
        if (!j->has64 && b->blk > 0xFFFFFFFFull) return SFS_ENOTSUP;
    if (j->head + need > j->maxlen) {
        /* wrap: every earlier transaction is checkpointed; make that durable, then restart the log */
        rc = sfs_dev_flush(fs);
        if (rc) return rc;
        j->head = j->first;
        rc = write_jsb(fs, j->head, seq);
        if (rc) return rc;
    } else if (j->disk_start == 0) {
        rc = write_jsb(fs, j->head, seq);
        if (rc) return rc;
    }
    pos = j->head;
    rc = write_revokes(fs, seq, &pos);
    if (rc) return rc;
    b = fs->txn.bufs;
    while (b) {
        uint8_t *d = fs->scratch;
        uint32_t dpos = pos++, off = JH_SIZE, n = 0, last_off = 0, last_flags = 0;
        uint64_t last_blk = 0;
        uint32_t last_csum = 0;
        memset(d, 0, fs->bs);
        wrbe32(d, JH_magic, JBD2_MAGIC);
        wrbe32(d, JH_blocktype, JBD2_DESCRIPTOR_BLOCK);
        wrbe32(d, JH_sequence, seq);
        for (; b && n < tpd; b = b->tnext, ++n) {
            const uint8_t *src = b->data;
            uint32_t flags = n ? JBD2_FLAG_SAME_UUID : 0, csum = 0;
            if (rdbe32(src, 0) == JBD2_MAGIC) {
                memcpy(fs->scratch2, src, fs->bs);
                wrbe32(fs->scratch2, 0, 0);
                src = fs->scratch2;
                flags |= JBD2_FLAG_ESCAPE;
            }
            if (j->csum_v2 || j->csum_v3) csum = tag_csum(fs, seq, src);
            rc = jwrite(fs, pos++, src);
            if (rc) return rc;
            tag_put(fs, d, off, b->blk, flags, csum);
            last_off = off;
            last_flags = flags;
            last_blk = b->blk;
            last_csum = csum;
            off += j->tag_bytes;
            if (!n) { memcpy(d + off, j->uuid, 16); off += 16; }
        }
        tag_put(fs, d, last_off, last_blk, last_flags | JBD2_FLAG_LAST_TAG, last_csum);
        block_tail_set(fs, d);
        rc = jwrite(fs, dpos, d);
        if (rc) return rc;
    }
    rc = sfs_dev_flush(fs);
    if (rc) return rc;
    {
        uint8_t *c = fs->scratch;
        memset(c, 0, fs->bs);
        wrbe32(c, JH_magic, JBD2_MAGIC);
        wrbe32(c, JH_blocktype, JBD2_COMMIT_BLOCK);
        wrbe32(c, JH_sequence, seq);
        wrbe64(c, JC_commit_sec, now);
        wrbe32(c, JC_commit_nsec, 0);
        if (TAIL(j)) wrbe32(c, JC_chksum, commit_csum(fs, c));
        rc = jwrite(fs, pos++, c);
        if (!rc) rc = sfs_dev_flush(fs);
        if (rc) return rc;
    }
    /* committed: checkpoint in place */
    for (b = fs->txn.bufs; b; b = next) {
        next = b->tnext;
        b->tnext = 0;
        b->flags &= ~B_JDIRTY;
        if (!rc && (b->flags & B_UPTODATE)) rc = sfs_dev_write(fs, b->blk, b->data, 1);
        fs->st.checkpoint_blocks++;
    }
    fs->txn.bufs = 0;
    fs->txn.nbufs = 0;
    j->head = pos;
    j->next_seq = seq + 1;
    fs->st.commits++;
    return rc;
}

int sfs_ondisk_state(sfs_fs *fs, int *needs_recovery, int *valid_fs, uint32_t *journal_start)
{
    uint8_t *b = sfs_alloc(fs, fs->bs);
    int rc;
    if (!b) return SFS_ENOMEM;
    rc = fs->ops.read(fs->ops.ctx, SB_OFFSET, b, 1024) ? SFS_EIO : 0;
    if (!rc) {
        *needs_recovery = !!(rd32(b, SB_feature_incompat) & INCOMPAT_RECOVER);
        *valid_fs = !!(rd16(b, SB_state) & SB_STATE_VALID);
        *journal_start = 0;
        if (fs->jnl.map && fs->jnl.map->count) {
            rc = jread(fs, 0, b);
            if (!rc) *journal_start = rdbe32(b, JS_start);
        }
    }
    sfs_free(fs, b, fs->bs);
    return rc;
}
