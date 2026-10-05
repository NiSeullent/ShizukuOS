/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS v1 atomic record store: small named records (account/credential persistence, installer state) kept as
 * ordinary regular files inside one directory of an ext4-format volume. No on-disk layout change: a record is a
 * regular file whose *contents* carry a self-validating header, so Linux/e2fsck see an ordinary file and older
 * libsfs builds read the volume unchanged.
 *
 * Update protocol (write-then-commit with readback verification):
 *   1. the new contents are written to the staging file "<name>.~nw" (any stale staging file is removed first);
 *   2. sfs_sync(): the staging file's data and metadata are committed through the jbd2 journal and the device
 *      write cache is flushed;
 *   3. the staging file is read back through libsfs and compared byte for byte with the caller's payload;
 *   4. sfs_rename(staging -> name, replace): one journaled metadata operation, so after a crash the directory
 *      holds either the complete previous record or the complete new one (journal replay at the next mount);
 *   5. sfs_sync() again (the commit record of step 4 is durable) and the committed record is read back, its
 *      header and payload CRC32C validated and compared with the payload.
 * A crash before step 4 leaves only an uncommitted staging file: sfs_record_get() never reads staging files and
 * sfs_record_recover() (called by the mount glue) deletes them.
 *
 * Record file contents (little endian):
 *   0  char  magic[8]  "SZREC001"
 *   8  u32   version   1
 *  12  u32   length    payload bytes (<= SFS_RECORD_MAX)
 *  16  u64   sequence  1 for a new record, previous + 1 on every replacement
 *  24  u32   crc       CRC32C (seed ~0, ext4 polynomial) of the payload
 *  28  u32   hcrc      CRC32C of bytes 0..27
 *  32  payload
 * The readback in steps 3 and 5 goes through the libsfs block cache; it proves that the committed file maps to
 * the expected contents, not that the media returned them (the device flush is the durability barrier).
 */
#include "sfs_internal.h"

#define REC_HDR 32u
#define REC_CHUNK 512u
static const char rec_magic[8] = {'S', 'Z', 'R', 'E', 'C', '0', '0', '1'};
static const char stage_sfx[4] = {'.', '~', 'n', 'w'};

static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static uint32_t get32(const uint8_t *p) { return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

static int rec_name_ok(const char *name, size_t len)
{
    size_t i;
    if (!name || !len || len + sizeof stage_sfx > SFS_NAME_MAX) return SFS_ENAMETOOLONG;
    for (i = 0; i < len; ++i) if (name[i] == '/' || name[i] == 0) return SFS_EINVAL;
    if (name[0] == '.') return SFS_EINVAL;                               /* ".", "..", hidden names */
    if (len >= sizeof stage_sfx && !memcmp(name + len - sizeof stage_sfx, stage_sfx, sizeof stage_sfx)) return SFS_EINVAL;
    return 0;
}

static void make_header(uint8_t h[REC_HDR], uint32_t len, uint64_t seq, uint32_t crc)
{
    memcpy(h, rec_magic, 8);
    put32(h + 8, 1);
    put32(h + 12, len);
    put32(h + 16, (uint32_t)seq);
    put32(h + 20, (uint32_t)(seq >> 32));
    put32(h + 24, crc);
    put32(h + 28, sfs_crc32c(~0u, h, 28));
}

/* Reads and validates the header of the record file `ino`; size is checked against the stated length. */
static int read_header(sfs_fs *fs, uint32_t ino, uint32_t *len, uint64_t *seq, uint32_t *crc)
{
    uint8_t h[REC_HDR];
    sfs_stat_t st;
    uint64_t done = 0;
    int rc = sfs_stat(fs, ino, &st);
    if (rc) return rc;
    if ((st.mode & SFS_S_IFMT) != SFS_S_IFREG) return SFS_EISDIR;
    if (st.size < REC_HDR) return SFS_ECORRUPT;
    rc = sfs_read(fs, ino, 0, h, REC_HDR, &done);
    if (rc) return rc;
    if (done != REC_HDR || memcmp(h, rec_magic, 8) || get32(h + 8) != 1 || get32(h + 28) != sfs_crc32c(~0u, h, 28))
        return SFS_ECORRUPT;
    *len = get32(h + 12);
    if (*len > SFS_RECORD_MAX || st.size != (uint64_t)REC_HDR + *len) return SFS_ECORRUPT;
    *seq = get32(h + 16) | (uint64_t)get32(h + 20) << 32;
    *crc = get32(h + 24);
    return 0;
}

/* Reads the payload of `ino` into buf (cap bytes) or, with buf NULL, compares it with `expect`. CRC-checked. */
static int read_payload(sfs_fs *fs, uint32_t ino, uint32_t len, uint32_t crc, void *buf, const void *expect)
{
    uint8_t *chunk = sfs_alloc(fs, REC_CHUNK);
    uint32_t off = 0, c = ~0u;
    int rc = 0;
    if (!chunk) return SFS_ENOMEM;
    while (off < len && !rc) {
        const uint32_t n = len - off < REC_CHUNK ? len - off : REC_CHUNK;
        uint64_t done = 0;
        rc = sfs_read(fs, ino, REC_HDR + (uint64_t)off, chunk, n, &done);
        if (!rc && done != n) rc = SFS_ECORRUPT;
        if (!rc) {
            c = sfs_crc32c(c, chunk, n);
            if (expect && memcmp(chunk, (const uint8_t *)expect + off, n)) rc = SFS_ECORRUPT;
            if (buf) memcpy((uint8_t *)buf + off, chunk, n);
        }
        off += n;
    }
    sfs_free(fs, chunk, REC_CHUNK);
    if (!rc && c != crc) rc = SFS_ECORRUPT;
    return rc;
}

int sfs_record_get(sfs_fs *fs, uint32_t dir, const char *name, size_t len, void *buf, uint32_t cap, uint32_t *dlen,
                   uint64_t *seq)
{
    uint32_t ino, plen = 0, crc = 0;
    uint64_t s = 0;
    uint8_t type;
    int rc = rec_name_ok(name, len);
    if (dlen) *dlen = 0;
    if (seq) *seq = 0;
    if (rc) return rc;
    rc = sfs_lookup(fs, dir, name, len, &ino, &type);
    if (!rc) rc = read_header(fs, ino, &plen, &s, &crc);
    if (rc) return rc;
    if (dlen) *dlen = plen;
    if (seq) *seq = s;
    if (!buf) return plen ? SFS_ERANGE : read_payload(fs, ino, 0, crc, 0, 0);
    if (plen > cap) return SFS_ERANGE;
    return read_payload(fs, ino, plen, crc, buf, 0);
}

static int verify_file(sfs_fs *fs, uint32_t ino, const void *data, uint32_t dlen, uint64_t seq, uint32_t crc)
{
    uint32_t plen = 0, c = 0;
    uint64_t s = 0;
    int rc = read_header(fs, ino, &plen, &s, &c);
    if (rc) return rc;
    if (plen != dlen || s != seq || c != crc) return SFS_ECORRUPT;
    return read_payload(fs, ino, dlen, crc, 0, data);
}

int sfs_record_put(sfs_fs *fs, uint32_t dir, const char *name, size_t len, const void *data, uint32_t dlen,
                   uint64_t *seq_out)
{
    char stage[SFS_NAME_MAX + 1];
    uint8_t h[REC_HDR];
    uint32_t ino, oplen, ocrc, crc;
    uint64_t seq = 1, oseq = 0, done = 0;
    uint8_t type;
    int rc = rec_name_ok(name, len), staged = 0;
    if (seq_out) *seq_out = 0;
    if (rc) return rc;
    if (dlen > SFS_RECORD_MAX || (dlen && !data)) return SFS_EINVAL;
    if (sfs_is_readonly(fs)) return SFS_EROFS;
    memcpy(stage, name, len);
    memcpy(stage + len, stage_sfx, sizeof stage_sfx);
    stage[len + sizeof stage_sfx] = 0;

    if (!sfs_lookup(fs, dir, name, len, &ino, &type)) {
        rc = read_header(fs, ino, &oplen, &oseq, &ocrc);
        if (!rc) seq = oseq + 1;
        else if (rc == SFS_ECORRUPT) sfs_log(fs, "sfs: record: replacing a damaged record");
        else return rc;                                            /* a directory, or an I/O error */
    }
    crc = sfs_crc32c(~0u, data, dlen);
    make_header(h, dlen, seq, crc);

    rc = sfs_unlink(fs, dir, stage, len + sizeof stage_sfx);       /* stale staging file of an interrupted put */
    if (rc == SFS_ENOENT) rc = 0;
    if (!rc) rc = sfs_create(fs, dir, stage, len + sizeof stage_sfx, 0600, &ino);
    if (rc) return rc;
    staged = 1;
    rc = sfs_write(fs, ino, 0, h, REC_HDR, &done);
    if (!rc && done != REC_HDR) rc = SFS_ENOSPC;
    if (!rc && dlen) {
        rc = sfs_write(fs, ino, REC_HDR, data, dlen, &done);
        if (!rc && done != dlen) rc = SFS_ENOSPC;
    }
    if (!rc) rc = sfs_sync(fs);                                    /* staged contents durable */
    if (!rc) rc = verify_file(fs, ino, data, dlen, seq, crc);      /* readback before commit */
    if (!rc) rc = sfs_rename(fs, dir, stage, len + sizeof stage_sfx, dir, name, len, 1);
    if (!rc) {
        staged = 0;
        rc = sfs_sync(fs);                                         /* commit record durable */
    }
    if (!rc) rc = sfs_lookup(fs, dir, name, len, &ino, &type);
    if (!rc) rc = verify_file(fs, ino, data, dlen, seq, crc);      /* readback after commit */
    if (rc && staged && !sfs_is_readonly(fs)) {
        (void)sfs_unlink(fs, dir, stage, len + sizeof stage_sfx);  /* the committed record is untouched */
        (void)sfs_sync(fs);
    }
    if (!rc && seq_out) *seq_out = seq;
    return rc;
}

int sfs_record_delete(sfs_fs *fs, uint32_t dir, const char *name, size_t len)
{
    int rc = rec_name_ok(name, len);
    if (rc) return rc;
    rc = sfs_unlink(fs, dir, name, len);
    if (!rc) rc = sfs_sync(fs);
    return rc;
}

int sfs_record_recover(sfs_fs *fs, uint32_t dir)
{
    sfs_dirent *de;
    uint64_t cookie = 0;
    int rc, removed = 0;
    if (sfs_is_readonly(fs)) return 0;
    de = sfs_alloc(fs, sizeof *de);
    if (!de) return SFS_ENOMEM;
    while ((rc = sfs_readdir(fs, dir, &cookie, de)) == 1) {
        if (de->type != SFS_FT_REG || de->name_len <= sizeof stage_sfx ||
            memcmp(de->name + de->name_len - sizeof stage_sfx, stage_sfx, sizeof stage_sfx))
            continue;
        rc = sfs_unlink(fs, dir, de->name, de->name_len);
        if (rc) break;
        sfs_log(fs, "sfs: record: removed an uncommitted staging file");
        ++removed;
        cookie = 0;                                                /* the directory changed: rescan */
    }
    sfs_free(fs, de, sizeof *de);
    if (rc < 0) return rc;
    if (removed) {
        rc = sfs_sync(fs);
        if (rc) return rc;
    }
    return removed;
}
