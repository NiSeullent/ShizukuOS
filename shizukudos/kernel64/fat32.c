/* SPDX-License-Identifier: GPL-2.0-only
 * FAT32 volume reader/writer (see fat32.h). Freestanding: no libc, no kernel headers; all I/O and memory come
 * through the callbacks in fat32_vol_t, so shizukudos/tests/test_fat32.c runs the same code on the host.
 */
#include "fat32.h"

#define EOC 0x0ffffff8u
#define MAX_FAT_PAGES 4096u                     /* 16 MiB of FAT = 4M clusters */

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void wr16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void wr32(uint8_t *p, uint32_t v) { wr16(p, v); wr16(p + 2, v >> 16); }
static void f32_copy(void *d, const void *s, uint64_t n) { uint8_t *dd = d; const uint8_t *ss = s; while (n--) *dd++ = *ss++; }
static void f32_zero(void *d, uint64_t n) { uint8_t *dd = d; while (n--) *dd++ = 0; }

typedef struct undo_sector {
    struct undo_sector *next;
    uint64_t lba;
    uint8_t before[FAT32_SECTOR];
} undo_sector_t;
typedef struct fat32_undo {
    undo_sector_t *sectors;
    uint8_t *cache;
    uint64_t cache_bytes, sector_limit, sector_count;
    uint32_t free_clusters, alloc_hint, fsinfo_dirty;
    int error, in_callback;
} fat32_undo_t;

static int operation_guard(const fat32_vol_t *v)
{
    if (v->recovery_required) return FAT32_E_RECOVERY;
    if (v->rename_undo && v->rename_undo->in_callback) return FAT32_E_BUSY;
    return v->rename_undo ? v->rename_undo->error : 0;
}

static int read_sector(fat32_vol_t *v, uint64_t lba, void *buf)
{
    fat32_undo_t *tx = v->rename_undo;
    int rc = operation_guard(v);
    if (rc) return rc;
    if (lba >= v->disk_sectors) return FAT32_E_RANGE;
    ++v->sector_reads;
    if (tx) tx->in_callback = 1;
    rc = v->read(v->ctx, lba, buf) ? FAT32_E_IO : FAT32_OK;
    if (tx) { tx->in_callback = 0; if (rc) tx->error = rc; }
    return rc;
}

/* Reads `lba` into the bounce buffer unless it is already there (nested directory walks and partial file reads
 * share the buffer, so the cached LBA, not the caller's position, decides whether a read is needed). */
static int bounce(fat32_vol_t *v, uint64_t lba)
{
    int rc;
    if (v->sector_lba == lba) return FAT32_OK;
    v->sector_lba = ~0ull;
    if ((rc = read_sector(v, lba, v->sector))) return rc;
    v->sector_lba = lba;
    return FAT32_OK;
}

uint32_t fat32_fat_entry(const fat32_vol_t *v, uint32_t cluster)
{
    const uint32_t page = cluster >> 10, idx = cluster & 1023;
    if (page >= v->fat_npages) return 0x0fffffffu;
    return v->fat_pages[page][idx] & 0x0fffffffu;
}

uint64_t fat32_cluster_lba(const fat32_vol_t *v, uint32_t cluster)
{
    return v->part_lba + v->first_data + (uint64_t)(cluster - 2) * v->spc;
}

static int valid_cluster(const fat32_vol_t *v, uint32_t c) { return c >= 2 && c < v->cluster_count + 2; }

static int looks_like_fat32_vbr(const uint8_t *s)
{
    return (s[0] == 0xeb || s[0] == 0xe9) && rd16(s + 510) == 0xaa55 && rd16(s + 11) == FAT32_SECTOR && rd16(s + 22) == 0 &&
           rd16(s + 17) == 0 && rd32(s + 36) != 0;
}

int fat32_mount(fat32_vol_t *v)
{
    uint8_t *s = v->sector;
    uint32_t i, total, fatsz, spc, reserved, nfats, root, clusters;
    uint64_t first_data;
    int rc;
    v->rename_undo = 0; v->recovery_required = 0;
    if (!v->read || !v->alloc || !v->free || !v->alloc_page || !v->disk_sectors) return FAT32_E_FORMAT;
    v->fat_pages = 0; v->fat_npages = 0; v->part_lba = 0; v->part_sectors = 0; v->sector_reads = 0; v->sector_lba = ~0ull;
    v->sector_writes = 0; v->fat_dirty = 0; v->fsinfo_sector = 0; v->fsinfo_dirty = 0; v->free_clusters = 0; v->alloc_hint = 2;
    if ((rc = read_sector(v, 0, s))) return rc;
    if (looks_like_fat32_vbr(s)) {
        v->part_lba = 0;
        v->part_sectors = (uint32_t)(v->disk_sectors > 0xffffffffull ? 0xffffffffu : v->disk_sectors);
    } else {
        if (rd16(s + 510) != 0xaa55) return FAT32_E_FORMAT;
        for (i = 0; i < 4; ++i) {                            /* first primary partition of a FAT32 type */
            const uint8_t *e = s + 446 + 16 * i;
            const uint8_t type = e[4];
            const uint32_t start = rd32(e + 8), count = rd32(e + 12);
            if ((type == 0x0b || type == 0x0c) && start && count && (uint64_t)start + count <= v->disk_sectors) {
                v->part_lba = start;
                v->part_sectors = count;
                break;
            }
        }
        if (!v->part_sectors) return FAT32_E_FORMAT;
        if ((rc = read_sector(v, v->part_lba, s))) return rc;
        if (!looks_like_fat32_vbr(s)) return FAT32_E_FORMAT;
    }
    spc = s[13]; reserved = rd16(s + 14); nfats = s[16]; total = rd32(s + 32); fatsz = rd32(s + 36); root = rd32(s + 44);
    if (!spc || spc > 128 || (spc & (spc - 1)) || !reserved || !nfats || nfats > 2 || !total || !fatsz || rd16(s + 42) != 0)
        return FAT32_E_FORMAT;
    if (total > v->part_sectors) return FAT32_E_FORMAT;
    first_data = (uint64_t)reserved + (uint64_t)nfats * fatsz;
    if (first_data >= total) return FAT32_E_FORMAT;
    clusters = (uint32_t)((total - first_data) / spc);
    /* The spec derives the FAT type from the cluster count (>= 65525 for FAT32) but mkfs.fat -F 32 also produces
     * smaller FAT32 volumes with FAT32-only BPB fields (fatsz16 == 0, fatsz32 != 0); those are accepted. */
    if (clusters < 1 || clusters >= 0x0ffffff6u) return FAT32_E_FORMAT;
    if ((uint64_t)fatsz * (FAT32_SECTOR / 4) < (uint64_t)clusters + 2) return FAT32_E_FORMAT;
    if (root < 2 || root >= clusters + 2) return FAT32_E_FORMAT;
    v->spc = spc; v->reserved = reserved; v->nfats = nfats; v->total_sectors = total; v->fat_sectors = fatsz;
    v->root_cluster = root; v->first_data = (uint32_t)first_data; v->cluster_count = clusters;
    v->bytes_per_cluster = spc * FAT32_SECTOR;
    v->volume_id = s[66] == 0x29 ? rd32(s + 67) : 0;
    if (rd16(s + 40) & 0x80) v->write = 0;                  /* FAT mirroring disabled: FAT 0 may not be active, no writes */
    v->fsinfo_sector = rd16(s + 48);
    if (!v->fsinfo_sector || v->fsinfo_sector >= reserved) v->fsinfo_sector = 0;
    f32_zero(v->label, sizeof v->label);
    if (s[66] == 0x29) { f32_copy(v->label, s + 71, 11); for (i = 11; i > 0 && v->label[i - 1] == ' '; --i) v->label[i - 1] = 0; }
    /* copy the (first) FAT: only the entries that exist (clusters + 2) matter */
    {
        const uint32_t entries = clusters + 2, npages = (entries + 1023) / 1024;
        uint32_t page, sec;
        if (npages > MAX_FAT_PAGES) return FAT32_E_FORMAT;
        v->fat_pages = v->alloc(v->ctx, (uint64_t)npages * sizeof(uint32_t *));
        if (!v->fat_pages) return FAT32_E_NOMEM;
        v->fat_npages = npages;
        for (page = 0; page < npages; ++page) {
            v->fat_pages[page] = v->alloc_page(v->ctx);
            if (!v->fat_pages[page]) { fat32_unmount(v); return FAT32_E_NOMEM; }
            for (sec = 0; sec < 8;) {
                const uint32_t fat_sector = page * 8 + sec;
                const uint64_t lba = v->part_lba + reserved + fat_sector;
                uint32_t count = 1, left;
                uint8_t *dst = (uint8_t *)v->fat_pages[page] + sec * FAT32_SECTOR;
                if (fat_sector >= fatsz) break;
                left = fatsz - fat_sector;
                if (left > 8 - sec) left = 8 - sec;
                if (v->read_many && left >= 2) count = left > FAT32_READ_MAX_SECTORS ? FAT32_READ_MAX_SECTORS : left;
                if (count > 1) {
                    /* bounded chunk inside this page; staged so a failed callback never touches page contents */
                    if ((rc = operation_guard(v))) { fat32_unmount(v); return rc; }
                    if (lba >= v->disk_sectors || count > v->disk_sectors - lba) { fat32_unmount(v); return FAT32_E_RANGE; }
                    v->sector_reads += count;
                    if (v->read_many(v->ctx, lba, count, v->read_batch)) { fat32_unmount(v); return FAT32_E_IO; }
                    f32_copy(dst, v->read_batch, (uint64_t)count * FAT32_SECTOR);
                } else if ((rc = read_sector(v, lba, dst))) {
                    fat32_unmount(v);
                    return rc;
                }
                sec += count;
            }
        }
    }
    if ((fat32_fat_entry(v, 0) & 0x0fffff00u) != 0x0fffff00u || (fat32_fat_entry(v, 1) & 0x03ffffffu) != 0x03ffffffu) {
        fat32_unmount(v);
        return FAT32_E_CORRUPT;
    }
    for (i = 2; i < clusters + 2; ++i)
        if (!fat32_fat_entry(v, i)) ++v->free_clusters;
    if (v->write) {
        v->fat_dirty = v->alloc(v->ctx, (uint64_t)v->fat_npages * 8 / 8 + 1);
        if (!v->fat_dirty) { fat32_unmount(v); return FAT32_E_NOMEM; }
        if (v->fsinfo_sector) {                              /* FSInfo: lead/struct signatures, else ignored */
            if ((rc = read_sector(v, v->part_lba + v->fsinfo_sector, s))) { fat32_unmount(v); return rc; }
            if (rd32(s) != 0x41615252u || rd32(s + 484) != 0x61417272u) v->fsinfo_sector = 0;
            else if (rd32(s + 492) >= 2 && rd32(s + 492) < clusters + 2) v->alloc_hint = rd32(s + 492);
            v->fsinfo_dirty = v->fsinfo_sector && rd32(s + 488) != v->free_clusters;
        }
    }
    return FAT32_OK;
}

void fat32_unmount(fat32_vol_t *v)
{
    if (v->fat_pages) {
        uint32_t i;
        for (i = 0; i < v->fat_npages; ++i)
            if (v->fat_pages[i]) v->free(v->ctx, v->fat_pages[i], 4096);
        v->free(v->ctx, v->fat_pages, (uint64_t)v->fat_npages * sizeof(uint32_t *));
    }
    if (v->fat_dirty) v->free(v->ctx, v->fat_dirty, (uint64_t)v->fat_npages * 8 / 8 + 1);
    v->fat_dirty = 0;
    v->fat_pages = 0;
    v->fat_npages = 0;
}

/* ---------------------------------------------------------------- directories */
void fat32_dir_open(const fat32_vol_t *v, uint32_t first_cluster, fat32_dir_t *d)
{
    d->cluster = first_cluster ? first_cluster : v->root_cluster;
    d->offset = 0;
    d->ended = 0;
}

static uint8_t short_checksum(const uint8_t *name)
{
    uint8_t sum = 0;
    unsigned i;
    for (i = 0; i < 11; ++i) sum = (uint8_t)(((sum & 1) << 7) + (sum >> 1) + name[i]);
    return sum;
}

static void short_to_name(const uint8_t *sn, uint8_t ntres, fat32_dirent_t *out)
{
    unsigned i, n = 0, base = 8, ext = 3;
    while (base > 0 && sn[base - 1] == ' ') --base;
    while (ext > 0 && sn[8 + ext - 1] == ' ') --ext;
    for (i = 0; i < base; ++i) {
        uint8_t c = i == 0 && sn[0] == 0x05 ? 0xe5 : sn[i];
        if (c >= 0x80) c = '_';                                   /* OEM code page bytes are not translated */
        if ((ntres & 0x08) && c >= 'A' && c <= 'Z') c = (uint8_t)(c + 32);
        out->name[n++] = c;
    }
    if (ext) {
        out->name[n++] = '.';
        for (i = 0; i < ext; ++i) {
            uint8_t c = sn[8 + i];
            if (c >= 0x80) c = '_';
            if ((ntres & 0x10) && c >= 'A' && c <= 'Z') c = (uint8_t)(c + 32);
            out->name[n++] = c;
        }
    }
    out->name[n] = 0;
    out->name_len = (uint16_t)n;
}

int fat32_dir_next(fat32_vol_t *v, fat32_dir_t *d, fat32_dirent_t *out)
{
    uint16_t lfn[260];
    uint8_t lfn_sum = 0, lfn_expect = 0;
    int lfn_len = 0, lfn_valid = 0;
    uint32_t guard = 0;
    int blocked = operation_guard(v);
    if (blocked) return blocked;
    f32_zero(lfn, sizeof lfn);
    while (!d->ended) {
        const uint8_t *e;
        uint8_t attr;
        if (!valid_cluster(v, d->cluster)) return FAT32_E_CORRUPT;
        if (d->offset >= v->bytes_per_cluster) {
            const uint32_t next = fat32_fat_entry(v, d->cluster);
            if (next >= EOC) { d->ended = 1; break; }
            if (!valid_cluster(v, next) || ++guard > v->cluster_count) return FAT32_E_CORRUPT;
            d->cluster = next;
            d->offset = 0;
            continue;
        }
        {
            const int rc = bounce(v, fat32_cluster_lba(v, d->cluster) + d->offset / FAT32_SECTOR);
            if (rc) return rc;
        }
        e = v->sector + (d->offset & (FAT32_SECTOR - 1));
        d->offset += 32;
        if (e[0] == 0) { d->ended = 1; break; }
        if (e[0] == 0xe5) { lfn_len = 0; lfn_valid = 0; continue; }
        attr = e[11];
        if ((attr & 0x3f) == FAT32_ATTR_LFN) {
            const unsigned seq = e[0] & 0x1f;
            unsigned k, pos;
            if (!seq || seq > 20 || e[26] != 0 || e[27] != 0) { lfn_valid = 0; continue; }
            if (e[0] & 0x40) { f32_zero(lfn, sizeof lfn); lfn_expect = e[13]; lfn_valid = 1; lfn_len = 0; }
            else if (!lfn_valid || e[13] != lfn_expect) { lfn_valid = 0; continue; }
            pos = (seq - 1) * 13;
            for (k = 0; k < 5; ++k) lfn[pos + k] = rd16(e + 1 + k * 2);
            for (k = 0; k < 6; ++k) lfn[pos + 5 + k] = rd16(e + 14 + k * 2);
            for (k = 0; k < 2; ++k) lfn[pos + 11 + k] = rd16(e + 28 + k * 2);
            if (e[0] & 0x40) {
                lfn_len = (int)(pos + 13);
                while (lfn_len > 0 && (lfn[lfn_len - 1] == 0 || lfn[lfn_len - 1] == 0xffff)) --lfn_len;
            }
            continue;
        }
        if (attr & FAT32_ATTR_LABEL) { lfn_valid = 0; continue; }         /* volume label */
        if (e[0] == '.' ) { lfn_valid = 0; continue; }                     /* "." and ".." (the RAM fs lists neither) */
        f32_zero(out, sizeof *out);
        out->dir_cluster = d->cluster;
        out->dir_offset = d->offset - 32;
        f32_copy(out->short_name, e, 11);
        out->attr = attr;
        out->first_cluster = ((uint32_t)rd16(e + 20) << 16) | rd16(e + 26);
        out->size = rd32(e + 28);
        out->ctenth = e[13]; out->ctime = rd16(e + 14); out->cdate = rd16(e + 16); out->adate = rd16(e + 18);
        out->mtime = rd16(e + 22); out->mdate = rd16(e + 24);
        lfn_sum = short_checksum(e);
        if (lfn_valid && lfn_len > 0 && lfn_len <= 255 && lfn_sum == lfn_expect) {
            f32_copy(out->name, lfn, (uint64_t)lfn_len * 2);
            out->name[lfn_len] = 0;
            out->name_len = (uint16_t)lfn_len;
            out->has_lfn = 1;
        } else {
            short_to_name(e, e[12], out);
        }
        if (out->attr & FAT32_ATTR_DIR) out->size = 0;
        return 1;
    }
    return 0;
}

/* ---------------------------------------------------------------- files */
/* Appends cluster `cur` as the chain's next cluster (extends the last run when contiguous). */
static int chain_add(fat32_vol_t *v, fat32_chain_t *c, uint32_t cur)
{
    if (c->nruns && c->runs[c->nruns - 1].start + c->runs[c->nruns - 1].count == cur) {
        ++c->runs[c->nruns - 1].count;
    } else {
        if (c->nruns == c->cap) {
            const uint32_t ncap = c->cap ? c->cap * 2 : 8;
            fat32_run_t *nr = v->alloc(v->ctx, (uint64_t)ncap * sizeof *nr);
            if (!nr) return FAT32_E_NOMEM;
            if (c->runs) { f32_copy(nr, c->runs, (uint64_t)c->nruns * sizeof *nr); v->free(v->ctx, c->runs, (uint64_t)c->cap * sizeof *nr); }
            c->runs = nr;
            c->cap = ncap;
        }
        c->runs[c->nruns].start = cur;
        c->runs[c->nruns].count = 1;
        c->runs[c->nruns].first_index = c->total_clusters;
        ++c->nruns;
    }
    ++c->total_clusters;
    return FAT32_OK;
}

int fat32_chain_build(fat32_vol_t *v, uint32_t first_cluster, fat32_chain_t *c)
{
    int blocked = operation_guard(v);
    if (blocked) return blocked;
    uint32_t cur = first_cluster, n = 0;
    c->runs = 0; c->nruns = 0; c->cap = 0; c->total_clusters = 0;
    if (!first_cluster) return FAT32_OK;                                   /* empty file */
    while (cur < EOC) {
        if (!valid_cluster(v, cur) || ++n > v->cluster_count) { fat32_chain_free(v, c); return FAT32_E_CORRUPT; }
        if (chain_add(v, c, cur)) { fat32_chain_free(v, c); return FAT32_E_NOMEM; }
        cur = fat32_fat_entry(v, cur);
    }
    return FAT32_OK;
}

void fat32_chain_free(fat32_vol_t *v, fat32_chain_t *c)
{
    if (c->runs) v->free(v->ctx, c->runs, (uint64_t)c->cap * sizeof *c->runs);
    c->runs = 0; c->nruns = 0; c->cap = 0; c->total_clusters = 0;
}

/* Cluster number of the file's cluster index `idx` (binary search over the runs). */
static uint32_t chain_cluster(const fat32_chain_t *c, uint32_t idx)
{
    uint32_t lo = 0, hi = c->nruns;
    while (lo + 1 < hi) {
        const uint32_t mid = (lo + hi) / 2;
        if (c->runs[mid].first_index <= idx) lo = mid; else hi = mid;
    }
    if (!c->nruns || idx < c->runs[lo].first_index || idx - c->runs[lo].first_index >= c->runs[lo].count) return 0;
    return c->runs[lo].start + (idx - c->runs[lo].first_index);
}

int fat32_read(fat32_vol_t *v, const fat32_chain_t *c, uint32_t size, uint64_t off, void *buf, uint64_t len, uint64_t *done)
{
    int blocked = operation_guard(v);
    if (blocked) { *done = 0; return blocked; }
    uint8_t *dst = buf;
    *done = 0;
    if (off >= size) return FAT32_OK;
    if (len > size - off) len = size - off;
    while (len) {
        const uint32_t idx = (uint32_t)(off / v->bytes_per_cluster), in_cluster = (uint32_t)(off % v->bytes_per_cluster);
        const uint32_t cluster = chain_cluster(c, idx);
        const uint32_t sec = in_cluster / FAT32_SECTOR, in_sec = in_cluster % FAT32_SECTOR;
        uint64_t lba, n;
        int rc;
        if (!cluster) return FAT32_E_CORRUPT;                              /* chain shorter than the size */
        lba = fat32_cluster_lba(v, cluster) + sec;
        if (in_sec == 0 && len >= FAT32_SECTOR) {
            unsigned count = 1;
            if (v->read_many && len >= FAT32_SECTOR * 2u) {
                unsigned wanted = (unsigned)(len / FAT32_SECTOR > FAT32_READ_MAX_SECTORS ?
                                             FAT32_READ_MAX_SECTORS : len / FAT32_SECTOR);
                /* Verify each requested sector is physically consecutive, even
                 * across cluster boundaries. Never bridge a fragmented run. */
                for (count = 1; count < wanted; ++count) {
                    const uint64_t next = off + (uint64_t)count * FAT32_SECTOR;
                    const uint32_t next_cluster = chain_cluster(c, (uint32_t)(next / v->bytes_per_cluster));
                    if (!next_cluster || fat32_cluster_lba(v, next_cluster) +
                        (next % v->bytes_per_cluster) / FAT32_SECTOR != lba + count) break;
                }
            }
            n = (uint64_t)count * FAT32_SECTOR;
            if (count > 1) {
                if (lba >= v->disk_sectors || count > v->disk_sectors - lba) return FAT32_E_RANGE;
                v->sector_reads += count;
                if (v->read_many(v->ctx, lba, count, v->read_batch)) return FAT32_E_IO;
                f32_copy(dst, v->read_batch, n);
            } else if ((rc = read_sector(v, lba, dst))) return rc;
        } else {
            if ((rc = bounce(v, lba))) return rc;
            n = FAT32_SECTOR - in_sec;
            if (n > len) n = len;
            f32_copy(dst, v->sector + in_sec, n);
        }
        dst += n; off += n; len -= n; *done += n;
    }
    return FAT32_OK;
}

/* ---------------------------------------------------------------- time */
uint64_t fat32_filetime(uint16_t date, uint16_t time, uint8_t tenth)
{
    static const uint16_t cum[12] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
    uint32_t year = 1980 + (date >> 9), mon = (date >> 5) & 15, day = date & 31, y;
    uint32_t hour = time >> 11, min = (time >> 5) & 63, sec = (time & 31) * 2;
    uint64_t days = 0, unix_s;
    if (!date) return 0;
    if (mon < 1 || mon > 12) mon = 1;
    if (!day) day = 1;
    for (y = 1970; y < year; ++y) days += 365 + ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0);
    days += cum[mon - 1] + (mon > 2 && ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0));
    days += day - 1;
    unix_s = days * 86400 + hour * 3600 + min * 60 + sec + tenth / 100;
    return (unix_s + 11644473600ull) * 10000000ull + (uint64_t)(tenth % 100) * 100000ull;
}

void fat32_dostime(uint64_t t, uint16_t *date, uint16_t *time)
{
    static const uint8_t mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    uint64_t days = t / 86400, rem = t % 86400;
    uint32_t year = 1970, mon = 0, leap;
    if (t < 315532800ull) { *date = (1 << 5) | 1; *time = 0; return; }           /* before 1980: 1980-01-01 */
    for (;;) {
        leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        if (days < 365u + leap) break;
        days -= 365u + leap;
        ++year;
    }
    while (mon < 12) {
        const uint32_t md = mdays[mon] + (mon == 1 ? leap : 0);
        if (days < md) break;
        days -= md;
        ++mon;
    }
    if (year > 2107) { *date = (uint16_t)((127u << 9) | (12u << 5) | 31u); *time = (uint16_t)((23u << 11) | (59u << 5) | 29u); return; }
    *date = (uint16_t)(((year - 1980) << 9) | ((mon + 1) << 5) | (uint32_t)(days + 1));
    *time = (uint16_t)(((rem / 3600) << 11) | (((rem / 60) % 60) << 5) | ((rem % 60) / 2));
}

/* ---------------------------------------------------------------- writing */
static int write_sector(fat32_vol_t *v, uint64_t lba, const void *buf)
{
    fat32_undo_t *tx = v->rename_undo;
    int rc = operation_guard(v);
    if (rc) return rc;
    if (!v->write) return FAT32_E_RDONLY;
    if (lba < v->part_lba || lba >= v->disk_sectors) return FAT32_E_RANGE;
    if (tx) {
        undo_sector_t *node;
        for (node = tx->sectors; node && node->lba != lba; node = node->next) {}
        if (!node) {
            if (tx->sector_count == tx->sector_limit) return tx->error = FAT32_E_FULL;
            tx->in_callback = 1;
            node = v->alloc(v->ctx, sizeof *node);
            tx->in_callback = 0;
            if (!node) return tx->error = FAT32_E_NOMEM;
            rc = read_sector(v, lba, node->before); /* actual media, never the already-edited bounce buffer */
            if (rc) { tx->in_callback = 1; v->free(v->ctx, node, sizeof *node); tx->in_callback = 0; return rc; }
            node->lba = lba; node->next = tx->sectors; tx->sectors = node; ++tx->sector_count;
        }
        tx->in_callback = 1;
    }
    ++v->sector_writes;
    rc = v->write(v->ctx, lba, buf);
    if (tx) { tx->in_callback = 0; if (rc) tx->error = FAT32_E_IO; }
    if (rc) {
        if (v->sector_lba == lba) v->sector_lba = ~0ull;                /* content unknown after a failed write */
        return FAT32_E_IO;
    }
    if (v->sector_lba == lba && buf != v->sector) f32_copy(v->sector, buf, FAT32_SECTOR);   /* keep the cache coherent */
    return FAT32_OK;
}

static void fat_set(fat32_vol_t *v, uint32_t cluster, uint32_t value)
{
    uint32_t *e = &v->fat_pages[cluster >> 10][cluster & 1023];
    const uint32_t sec = cluster / (FAT32_SECTOR / 4);
    if (!(*e & 0x0fffffffu) && value) --v->free_clusters;
    else if ((*e & 0x0fffffffu) && !value) ++v->free_clusters;
    *e = (*e & 0xf0000000u) | (value & 0x0fffffffu);                /* the top four bits are reserved: preserved */
    v->fat_dirty[sec >> 3] |= (uint8_t)(1u << (sec & 7));
    v->fsinfo_dirty = 1;
}

int fat32_sync(fat32_vol_t *v)
{
    uint32_t sec, k;
    int rc;
    int blocked = operation_guard(v);
    if (blocked) return blocked;
    if (!v->write || !v->fat_dirty) return FAT32_E_RDONLY;
    for (sec = 0; sec < v->fat_sectors && sec < v->fat_npages * 8; ++sec) {
        if (!(v->fat_dirty[sec >> 3] & (1u << (sec & 7)))) continue;
        for (k = 0; k < v->nfats; ++k)
            if ((rc = write_sector(v, v->part_lba + v->reserved + (uint64_t)k * v->fat_sectors + sec,
                                   (const uint8_t *)v->fat_pages[sec / 8] + (sec % 8) * FAT32_SECTOR)))
                return rc;
        v->fat_dirty[sec >> 3] &= (uint8_t)~(1u << (sec & 7));
    }
    if (v->fsinfo_sector && v->fsinfo_dirty) {
        const uint64_t lba = v->part_lba + v->fsinfo_sector;
        if ((rc = bounce(v, lba))) return rc;
        wr32(v->sector + 488, v->free_clusters);
        wr32(v->sector + 492, v->alloc_hint);
        if ((rc = write_sector(v, lba, v->sector))) return rc;
        v->fsinfo_dirty = 0;
    }
    return FAT32_OK;
}

/* A free cluster marked end-of-chain, 0 when the volume is full. */
static uint32_t alloc_cluster(fat32_vol_t *v)
{
    uint32_t i;
    for (i = 0; i < v->cluster_count; ++i) {
        const uint32_t c = 2 + (v->alloc_hint - 2 + i) % v->cluster_count;
        if (!fat32_fat_entry(v, c)) {
            fat_set(v, c, 0x0fffffffu);
            v->alloc_hint = c + 1 < v->cluster_count + 2 ? c + 1 : 2;
            return c;
        }
    }
    return 0;
}

static int zero_cluster(fat32_vol_t *v, uint32_t cluster)
{
    uint8_t z[FAT32_SECTOR];
    uint32_t i;
    int rc;
    f32_zero(z, sizeof z);
    for (i = 0; i < v->spc; ++i)
        if ((rc = write_sector(v, fat32_cluster_lba(v, cluster) + i, z))) return rc;
    return FAT32_OK;
}

/* Grows the chain to at least `need` clusters (new clusters linked behind the last one). */
static int grow_chain(fat32_vol_t *v, fat32_chain_t *c, uint32_t *first_cluster, uint32_t need)
{
    while (c->total_clusters < need) {
        const uint32_t n = alloc_cluster(v);
        int rc;
        if (!n) return FAT32_E_FULL;
        if (c->total_clusters) {
            const fat32_run_t *r = &c->runs[c->nruns - 1];
            fat_set(v, r->start + r->count - 1, n);
        } else {
            *first_cluster = n;
        }
        if ((rc = chain_add(v, c, n))) return rc;
    }
    return FAT32_OK;
}

/* Writes [off, off+len) inside the chain (which must already cover it); buf NULL writes zeros. */
static int write_range(fat32_vol_t *v, const fat32_chain_t *c, uint64_t off, const uint8_t *buf, uint64_t len)
{
    uint8_t z[FAT32_SECTOR];
    f32_zero(z, sizeof z);
    while (len) {
        const uint32_t idx = (uint32_t)(off / v->bytes_per_cluster), in_cluster = (uint32_t)(off % v->bytes_per_cluster);
        const uint32_t cluster = chain_cluster(c, idx), in_sec = in_cluster % FAT32_SECTOR;
        uint64_t lba, n;
        int rc;
        if (!cluster) return FAT32_E_CORRUPT;
        lba = fat32_cluster_lba(v, cluster) + in_cluster / FAT32_SECTOR;
        n = FAT32_SECTOR - in_sec;
        if (n > len) n = len;
        if (n == FAT32_SECTOR) {
            if ((rc = write_sector(v, lba, buf ? buf : z))) return rc;
        } else {
            if ((rc = bounce(v, lba))) return rc;
            if (buf) f32_copy(v->sector + in_sec, buf, n); else f32_zero(v->sector + in_sec, n);
            if ((rc = write_sector(v, lba, v->sector))) return rc;
        }
        if (buf) buf += n;
        off += n; len -= n;
    }
    return FAT32_OK;
}

int fat32_write(fat32_vol_t *v, fat32_chain_t *c, uint32_t *first_cluster, uint32_t *size, uint64_t off, const void *buf,
                uint64_t len)
{
    int blocked = operation_guard(v);
    if (blocked) return blocked;
    const uint64_t end = off + len;
    int rc, rc2;
    if (!v->write) return FAT32_E_RDONLY;
    if (!len) return FAT32_OK;
    if (end < off || end > 0xffffffffull) return FAT32_E_RANGE;
    rc = grow_chain(v, c, first_cluster, (uint32_t)((end + v->bytes_per_cluster - 1) / v->bytes_per_cluster));
    if (!rc && off > *size) rc = write_range(v, c, *size, 0, off - *size);          /* the gap reads as zero */
    if (!rc) rc = write_range(v, c, off, buf, len);
    if (!rc && end > *size) *size = (uint32_t)end;
    rc2 = fat32_sync(v);
    return rc ? rc : rc2;
}

int fat32_truncate(fat32_vol_t *v, fat32_chain_t *c, uint32_t *first_cluster, uint32_t *size, uint32_t new_size)
{
    int blocked = operation_guard(v);
    if (blocked) return blocked;
    int rc = FAT32_OK, rc2;
    if (!v->write) return FAT32_E_RDONLY;
    if (new_size > *size) {
        rc = grow_chain(v, c, first_cluster, (uint32_t)(((uint64_t)new_size + v->bytes_per_cluster - 1) / v->bytes_per_cluster));
        if (!rc) rc = write_range(v, c, *size, 0, new_size - *size);
        if (!rc) *size = new_size;
    } else if (new_size < *size || c->total_clusters * (uint64_t)v->bytes_per_cluster >= (uint64_t)new_size + v->bytes_per_cluster) {
        const uint32_t keep = (uint32_t)(((uint64_t)new_size + v->bytes_per_cluster - 1) / v->bytes_per_cluster);
        uint32_t cur, guard = 0;
        if (keep == 0) {
            cur = *first_cluster;
            *first_cluster = 0;
        } else {
            const uint32_t last = chain_cluster(c, keep - 1);
            if (!last) return FAT32_E_CORRUPT;
            cur = fat32_fat_entry(v, last);
            fat_set(v, last, 0x0fffffffu);
        }
        while (cur >= 2 && cur < EOC) {                                  /* release the tail */
            const uint32_t next = fat32_fat_entry(v, cur);
            if (!valid_cluster(v, cur) || ++guard > v->cluster_count) { rc = FAT32_E_CORRUPT; break; }
            fat_set(v, cur, 0);
            cur = next;
        }
        fat32_chain_free(v, c);
        if (!rc) rc = fat32_chain_build(v, *first_cluster, c);
        if (!rc) *size = new_size;
    }
    rc2 = fat32_sync(v);
    return rc ? rc : rc2;
}

int fat32_set_entry(fat32_vol_t *v, uint32_t dir_cluster, uint32_t dir_offset, uint32_t first_cluster, uint32_t size,
                    uint16_t date, uint16_t time)
{
    int blocked = operation_guard(v);
    if (blocked) return blocked;
    uint64_t lba;
    uint8_t *e;
    int rc;
    if (!v->write) return FAT32_E_RDONLY;
    if (!valid_cluster(v, dir_cluster) || dir_offset >= v->bytes_per_cluster || (dir_offset & 31)) return FAT32_E_RANGE;
    lba = fat32_cluster_lba(v, dir_cluster) + dir_offset / FAT32_SECTOR;
    if ((rc = bounce(v, lba))) return rc;
    e = v->sector + (dir_offset % FAT32_SECTOR);
    if (e[0] == 0 || e[0] == 0xe5 || (e[11] & 0x3f) == FAT32_ATTR_LFN) return FAT32_E_CORRUPT;   /* not a live short entry */
    wr16(e + 20, first_cluster >> 16);
    wr16(e + 26, first_cluster & 0xffff);
    if (!(e[11] & FAT32_ATTR_DIR)) { wr32(e + 28, size); e[11] |= FAT32_ATTR_ARCHIVE; }
    wr16(e + 22, time); wr16(e + 24, date); wr16(e + 18, date);
    return write_sector(v, lba, v->sector);
}

/* ---- creation ---- */
static uint16_t up16(uint16_t c) { return c >= 'a' && c <= 'z' ? (uint16_t)(c - 32) : c; }

static int short_char_ok(uint16_t c)
{
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= '0' && c <= '9') return 1;
    return c == '$' || c == '%' || c == '\'' || c == '-' || c == '_' || c == '@' || c == '~' || c == '`' || c == '!' ||
           c == '(' || c == ')' || c == '{' || c == '}' || c == '^' || c == '#' || c == '&';
}

/* Exact upper-case 8.3 name: returns 1 and fills sn[11]. */
static int exact_short(const uint16_t *name, unsigned n, uint8_t sn[11])
{
    unsigned i, dot = n, base, ext;
    for (i = 0; i < n; ++i) if (name[i] == '.') { if (dot != n) return 0; dot = i; }
    base = dot; ext = dot < n ? n - dot - 1 : 0;
    if (!base || base > 8 || ext > 3 || (dot < n && !ext)) return 0;
    for (i = 0; i < 11; ++i) sn[i] = ' ';
    for (i = 0; i < base; ++i) { if (!short_char_ok(name[i])) return 0; sn[i] = (uint8_t)name[i]; }
    for (i = 0; i < ext; ++i) { if (!short_char_ok(name[dot + 1 + i])) return 0; sn[8 + i] = (uint8_t)name[dot + 1 + i]; }
    if (sn[0] == 0xe5) return 0;
    return 1;
}

/* Basis name for an alias: upper case, invalid characters -> '_', spaces and embedded dots dropped. */
static void basis_name(const uint16_t *name, unsigned n, uint8_t sn[11], unsigned *base_len)
{
    unsigned i, last_dot = n, b = 0, e = 0, start = 0;
    for (i = 0; i < 11; ++i) sn[i] = ' ';
    while (start < n && (name[start] == '.' || name[start] == ' ')) ++start;
    for (i = start; i < n; ++i) if (name[i] == '.') last_dot = i;
    for (i = start; i < last_dot && b < 8; ++i) {
        const uint16_t c = up16(name[i]);
        if (c == ' ' || c == '.') continue;
        sn[b++] = (uint8_t)(short_char_ok(c) ? c : '_');
    }
    for (i = last_dot + 1; i < n && e < 3; ++i) {
        const uint16_t c = up16(name[i]);
        if (c == ' ' || c == '.') continue;
        sn[8 + e++] = (uint8_t)(short_char_ok(c) ? c : '_');
    }
    if (!b) sn[b++] = '_';
    *base_len = b;
}

static int name_valid(const uint16_t *name, unsigned n)
{
    unsigned i;
    if (!n || n > 255) return 0;
    if ((n == 1 && name[0] == '.') || (n == 2 && name[0] == '.' && name[1] == '.')) return 0;
    if (name[n - 1] == ' ' || name[n - 1] == '.') return 0;
    for (i = 0; i < n; ++i) {
        const uint16_t c = name[i];
        if (c < 0x20 || c == '"' || c == '*' || c == '/' || c == ':' || c == '<' || c == '>' || c == '?' || c == '\\' || c == '|')
            return 0;
    }
    return 1;
}

static int names_equal_ci(const uint16_t *a, unsigned an, const uint16_t *b, unsigned bn)
{
    unsigned i;
    if (an != bn) return 0;
    for (i = 0; i < an; ++i) if (up16(a[i]) != up16(b[i])) return 0;
    return 1;
}

static int short_equal(const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0; i < 11; ++i) if (a[i] != b[i]) return 0;
    return 1;
}

/* 1 when `sn` (or, with name != NULL, the long/short name `name`) is already used in the directory by an entry other
 * than the one whose short entry is at (skip_cluster, skip_offset) (skip_cluster 0: none). */
static int dir_has_other(fat32_vol_t *v, uint32_t dir_first, const uint8_t *sn, const uint16_t *name, unsigned n, int *err,
                         uint32_t skip_cluster, uint32_t skip_offset)
{
    fat32_dir_t d;
    fat32_dirent_t e;
    int rc;
    fat32_dir_open(v, dir_first, &d);
    while ((rc = fat32_dir_next(v, &d, &e)) == 1) {
        if (skip_cluster && e.dir_cluster == skip_cluster && e.dir_offset == skip_offset) continue;
        if (sn && short_equal(e.short_name, sn)) return 1;
        if (name && names_equal_ci(e.name, e.name_len, name, n)) return 1;
    }
    *err = rc;
    return 0;
}

/* The directory entries of a new name in the directory starting at dir_first_cluster. `tmpl` (32 bytes) is NULL for a new
 * file or directory (fat32_create), or the short entry of an existing file or directory whose attributes, first
 * cluster, size and times the new entry takes over (fat32_rename; its old entry, at (skip_cluster, skip_offset), does
 * not count as a name conflict). */
static int make_entry(fat32_vol_t *v, uint32_t dir_first_cluster, const uint16_t *name, unsigned name_len, int is_dir,
                      uint16_t date, uint16_t time, const uint8_t *tmpl, uint32_t skip_cluster, uint32_t skip_offset,
                      fat32_dirent_t *out)
{
    uint8_t sn[11], ent[32];
    uint32_t pos_cluster[21], pos_offset[21], cl, off, guard = 0, newdir = 0;
    unsigned nlfn = 0, need, run = 0, i, base_len, k;
    const uint32_t dir_first = dir_first_cluster ? dir_first_cluster : v->root_cluster;
    int err = 0, rc, rc2;
    int blocked = operation_guard(v);
    if (blocked) return blocked;
    if (!v->write) return FAT32_E_RDONLY;
    if (!name_valid(name, name_len)) return FAT32_E_NAME;
    if (dir_has_other(v, dir_first_cluster, 0, name, name_len, &err, skip_cluster, skip_offset)) return FAT32_E_EXISTS;
    if (err < 0) return err;
    if (!exact_short(name, name_len, sn)) {
        basis_name(name, name_len, sn, &base_len);
        for (k = 1; k < 1000000; ++k) {                       /* BASIS~N, unique in this directory */
            char tail[8];
            unsigned t = 0, keep, x = k;
            char digits[7];
            unsigned nd = 0;
            while (x) { digits[nd++] = (char)('0' + x % 10); x /= 10; }
            tail[t++] = '~';
            while (nd) tail[t++] = digits[--nd];
            keep = base_len + t > 8 ? 8 - t : base_len;
            for (i = keep; i < 8; ++i) sn[i] = ' ';
            for (i = 0; i < t; ++i) sn[keep + i] = (uint8_t)tail[i];
            if (!dir_has_other(v, dir_first_cluster, sn, 0, 0, &err, skip_cluster, skip_offset)) { if (err < 0) return err; break; }
        }
        if (k == 1000000) return FAT32_E_EXISTS;
        nlfn = (name_len + 12) / 13;
    } else if (dir_has_other(v, dir_first_cluster, sn, 0, 0, &err, skip_cluster, skip_offset)) {
        return FAT32_E_EXISTS;
    }
    if (err < 0) return err;
    need = nlfn + 1;
    /* find `need` consecutive free slots (deleted or past the end marker); grow the directory by a cluster if none */
    cl = dir_first; off = 0;
    for (;;) {
        const uint8_t *e;
        if (!valid_cluster(v, cl) || ++guard > 65536 * 32) return FAT32_E_CORRUPT;
        if (off >= v->bytes_per_cluster) {
            uint32_t next = fat32_fat_entry(v, cl);
            if (next >= EOC) {
                next = alloc_cluster(v);
                if (!next) { fat32_sync(v); return FAT32_E_FULL; }
                fat_set(v, cl, next);
                if ((rc = zero_cluster(v, next))) { fat32_sync(v); return rc; }
            }
            cl = next; off = 0;
            continue;
        }
        if ((rc = bounce(v, fat32_cluster_lba(v, cl) + off / FAT32_SECTOR))) return rc;
        e = v->sector + (off % FAT32_SECTOR);
        if (e[0] == 0 || e[0] == 0xe5) {
            pos_cluster[run] = cl; pos_offset[run] = off;
            if (++run == need) break;
        } else {
            run = 0;
        }
        off += 32;
    }
    if (is_dir && !tmpl) {                                    /* the new directory's first cluster: ".", ".." */
        newdir = alloc_cluster(v);
        if (!newdir) { fat32_sync(v); return FAT32_E_FULL; }
        if ((rc = zero_cluster(v, newdir))) { fat32_sync(v); return rc; }
        f32_zero(ent, sizeof ent);
        for (i = 0; i < 11; ++i) ent[i] = ' ';
        ent[0] = '.'; ent[11] = FAT32_ATTR_DIR;
        wr16(ent + 14, time); wr16(ent + 16, date); wr16(ent + 18, date); wr16(ent + 22, time); wr16(ent + 24, date);
        wr16(ent + 20, newdir >> 16); wr16(ent + 26, newdir & 0xffff);
        if ((rc = bounce(v, fat32_cluster_lba(v, newdir)))) return rc;
        f32_copy(v->sector, ent, 32);
        ent[1] = '.';
        {
            const uint32_t parent = dir_first == v->root_cluster ? 0 : dir_first;    /* ".." of a root child is 0 */
            wr16(ent + 20, parent >> 16); wr16(ent + 26, parent & 0xffff);
        }
        f32_copy(v->sector + 32, ent, 32);
        if ((rc = write_sector(v, fat32_cluster_lba(v, newdir), v->sector))) { fat32_sync(v); return rc; }
    }
    /* long-name entries, highest sequence first, then the short entry */
    {
        const uint8_t sum = short_checksum(sn);
        for (k = 0; k < nlfn; ++k) {
            const unsigned seq = nlfn - k, start = (seq - 1) * 13;
            static const uint8_t at[13] = { 1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30 };
            f32_zero(ent, sizeof ent);
            ent[0] = (uint8_t)(seq | (k == 0 ? 0x40 : 0));
            ent[11] = FAT32_ATTR_LFN;
            ent[13] = sum;
            for (i = 0; i < 13; ++i) {
                const unsigned c = start + i;
                const uint32_t ch = c < name_len ? name[c] : c == name_len ? 0 : 0xffff;
                wr16(ent + at[i], ch);
            }
            if ((rc = bounce(v, fat32_cluster_lba(v, pos_cluster[k]) + pos_offset[k] / FAT32_SECTOR))) { fat32_sync(v); return rc; }
            f32_copy(v->sector + pos_offset[k] % FAT32_SECTOR, ent, 32);
            if ((rc = write_sector(v, fat32_cluster_lba(v, pos_cluster[k]) + pos_offset[k] / FAT32_SECTOR, v->sector))) { fat32_sync(v); return rc; }
        }
        f32_zero(ent, sizeof ent);
        if (tmpl) {                                           /* renamed: everything but the name (and its case flags) */
            f32_copy(ent, tmpl, 32);
            ent[12] = 0;
        } else {
            ent[11] = is_dir ? FAT32_ATTR_DIR : FAT32_ATTR_ARCHIVE;
            wr16(ent + 14, time); wr16(ent + 16, date); wr16(ent + 18, date); wr16(ent + 22, time); wr16(ent + 24, date);
            wr16(ent + 20, newdir >> 16); wr16(ent + 26, newdir & 0xffff);
        }
        f32_copy(ent, sn, 11);
        if ((rc = bounce(v, fat32_cluster_lba(v, pos_cluster[nlfn]) + pos_offset[nlfn] / FAT32_SECTOR))) { fat32_sync(v); return rc; }
        f32_copy(v->sector + pos_offset[nlfn] % FAT32_SECTOR, ent, 32);
        rc = write_sector(v, fat32_cluster_lba(v, pos_cluster[nlfn]) + pos_offset[nlfn] / FAT32_SECTOR, v->sector);
    }
    rc2 = fat32_sync(v);
    if (rc || rc2) return rc ? rc : rc2;
    f32_zero(out, sizeof *out);
    f32_copy(out->name, name, (uint64_t)name_len * 2);
    out->name_len = (uint16_t)name_len;
    out->has_lfn = nlfn != 0;
    out->attr = ent[11];
    out->first_cluster = ((uint32_t)rd16(ent + 20) << 16) | rd16(ent + 26);
    out->size = (ent[11] & FAT32_ATTR_DIR) ? 0 : rd32(ent + 28);
    out->ctenth = ent[13]; out->ctime = rd16(ent + 14); out->cdate = rd16(ent + 16); out->adate = rd16(ent + 18);
    out->mtime = rd16(ent + 22); out->mdate = rd16(ent + 24);
    f32_copy(out->short_name, sn, 11);
    out->dir_cluster = pos_cluster[nlfn];
    out->dir_offset = pos_offset[nlfn];
    return FAT32_OK;
}

int fat32_create(fat32_vol_t *v, uint32_t dir_first_cluster, const uint16_t *name, unsigned name_len, int is_dir,
                 uint16_t date, uint16_t time, fat32_dirent_t *out)
{
    return make_entry(v, dir_first_cluster, name, name_len, is_dir, date, time, 0, 0, 0, out);
}

/* ---- deletion and renaming ---- */
/* The short entry at (dir_cluster, dir_offset) into e[32]; it must be live (not free, deleted, LFN, "." or ".."). */
static int read_short(fat32_vol_t *v, uint32_t dir_cluster, uint32_t dir_offset, uint8_t e[32])
{
    int rc;
    if (!valid_cluster(v, dir_cluster) || dir_offset >= v->bytes_per_cluster || (dir_offset & 31)) return FAT32_E_RANGE;
    if ((rc = bounce(v, fat32_cluster_lba(v, dir_cluster) + dir_offset / FAT32_SECTOR))) return rc;
    f32_copy(e, v->sector + dir_offset % FAT32_SECTOR, 32);
    if (e[0] == 0 || e[0] == 0xe5 || e[0] == '.' || (e[11] & 0x3f) == FAT32_ATTR_LFN || (e[11] & FAT32_ATTR_LABEL))
        return FAT32_E_CORRUPT;
    return FAT32_OK;
}

/* Marks the short entry at (dir_cluster, dir_offset) and the long-name entries that belong to it (the run of LFN entries
 * right in front of it whose checksum matches) as deleted (0xE5). The directory is walked from its start because the
 * entries in front may lie in the previous cluster of the chain. */
static int erase_entry(fat32_vol_t *v, uint32_t dir_first, uint32_t dir_cluster, uint32_t dir_offset)
{
    uint32_t lc[20], lo[20], cl = dir_first ? dir_first : v->root_cluster, off = 0, guard = 0;
    unsigned nl = 0, i;
    uint8_t sum = 0;
    int rc;
    for (;;) {
        const uint8_t *e;
        if (!valid_cluster(v, cl) || ++guard > 65536 * 32) return FAT32_E_CORRUPT;
        if (off >= v->bytes_per_cluster) {
            const uint32_t next = fat32_fat_entry(v, cl);
            if (next >= EOC) return FAT32_E_CORRUPT;              /* the entry is not in this directory */
            cl = next; off = 0;
            continue;
        }
        if ((rc = bounce(v, fat32_cluster_lba(v, cl) + off / FAT32_SECTOR))) return rc;
        e = v->sector + off % FAT32_SECTOR;
        if (e[0] == 0) return FAT32_E_CORRUPT;
        if (cl == dir_cluster && off == dir_offset) { sum = short_checksum(e); break; }
        if (e[0] != 0xe5 && (e[11] & 0x3f) == FAT32_ATTR_LFN) {
            if (e[0] & 0x40) nl = 0;                               /* the first (highest) entry of a long name */
            if (nl < 20) { lc[nl] = cl; lo[nl] = off; ++nl; }
        } else {
            nl = 0;
        }
        off += 32;
    }
    for (i = 0; i <= nl; ++i) {
        const uint32_t c = i < nl ? lc[i] : dir_cluster, o = i < nl ? lo[i] : dir_offset;
        const uint64_t lba = fat32_cluster_lba(v, c) + o / FAT32_SECTOR;
        uint8_t *e;
        if ((rc = bounce(v, lba))) return rc;
        e = v->sector + o % FAT32_SECTOR;
        if (i < nl && e[13] != sum) continue;                     /* a stale long name of another entry: left alone */
        e[0] = 0xe5;
        if ((rc = write_sector(v, lba, v->sector))) return rc;
    }
    return FAT32_OK;
}

/* 1 when the directory starting at `first` holds nothing but ".", ".." and deleted or orphaned long-name entries. */
static int dir_empty(fat32_vol_t *v, uint32_t first, int *err)
{
    fat32_dir_t d;
    fat32_dirent_t e;
    int rc;
    fat32_dir_open(v, first, &d);
    rc = fat32_dir_next(v, &d, &e);                               /* skips ".", "..", deleted and LFN entries */
    *err = rc < 0 ? rc : 0;
    return rc == 0;
}

static int free_chain(fat32_vol_t *v, uint32_t first)
{
    uint32_t cur = first, guard = 0;
    while (cur >= 2 && cur < EOC) {
        const uint32_t next = fat32_fat_entry(v, cur);
        if (!valid_cluster(v, cur) || ++guard > v->cluster_count) return FAT32_E_CORRUPT;
        fat_set(v, cur, 0);
        cur = next;
    }
    return FAT32_OK;
}

int fat32_remove(fat32_vol_t *v, uint32_t dir_first_cluster, uint32_t dir_cluster, uint32_t dir_offset)
{
    int blocked = operation_guard(v);
    if (blocked) return blocked;
    uint8_t e[32];
    uint32_t first;
    int rc, rc2, err = 0;
    if (!v->write) return FAT32_E_RDONLY;
    if ((rc = read_short(v, dir_cluster, dir_offset, e))) return rc;
    first = ((uint32_t)rd16(e + 20) << 16) | rd16(e + 26);
    if (e[11] & FAT32_ATTR_DIR) {
        if (!first) return FAT32_E_CORRUPT;
        if (!dir_empty(v, first, &err)) return err ? err : FAT32_E_NOTEMPTY;
    }
    rc = erase_entry(v, dir_first_cluster, dir_cluster, dir_offset);      /* the name goes first: no entry to freed clusters */
    if (!rc && first) rc = free_chain(v, first);
    rc2 = fat32_sync(v);
    return rc ? rc : rc2;
}

static int rename_impl(fat32_vol_t *v, uint32_t src_dir_first, uint32_t dir_cluster, uint32_t dir_offset, uint32_t dst_dir_first,
                 const uint16_t *name, unsigned name_len, int replace, fat32_dirent_t *out)
{
    uint8_t e[32];
    const uint32_t src_dir = src_dir_first ? src_dir_first : v->root_cluster;
    const uint32_t dst_dir = dst_dir_first ? dst_dir_first : v->root_cluster;
    fat32_dir_t d;
    fat32_dirent_t *old = out;                                    /* scratch until make_entry fills it */
    uint32_t first;
    int rc, rc2, is_dir;
    if (!v->write) return FAT32_E_RDONLY;
    if (!name_valid(name, name_len)) return FAT32_E_NAME;
    if ((rc = read_short(v, dir_cluster, dir_offset, e))) return rc;
    is_dir = (e[11] & FAT32_ATTR_DIR) != 0;
    first = ((uint32_t)rd16(e + 20) << 16) | rd16(e + 26);
    if (is_dir && first) {                                        /* not into itself or its own subtree */
        uint32_t walk = dst_dir, guard = 0;
        while (walk && walk != v->root_cluster) {
            uint8_t dd[32];
            if (walk == first) return FAT32_E_NAME;
            if (++guard > 4096 || !valid_cluster(v, walk)) return FAT32_E_CORRUPT;
            if ((rc = bounce(v, fat32_cluster_lba(v, walk)))) return rc;
            f32_copy(dd, v->sector + 32, 32);                     /* ".." */
            if (dd[0] != '.' || dd[1] != '.') return FAT32_E_CORRUPT;
            walk = ((uint32_t)rd16(dd + 20) << 16) | rd16(dd + 26);
        }
    }
    /* an existing entry of that name (other than the source itself): replaced when allowed and it is a file */
    fat32_dir_open(v, dst_dir_first, &d);
    while ((rc = fat32_dir_next(v, &d, old)) == 1) {
        if (old->dir_cluster == dir_cluster && old->dir_offset == dir_offset) continue;
        if (!names_equal_ci(old->name, old->name_len, name, name_len)) continue;
        if (!replace || (old->attr & FAT32_ATTR_DIR) || (old->attr & FAT32_ATTR_RO)) return FAT32_E_EXISTS;
        if ((rc = fat32_remove(v, dst_dir_first, old->dir_cluster, old->dir_offset))) return rc;
        break;
    }
    if (rc < 0) return rc;
    rc = make_entry(v, dst_dir_first, name, name_len, is_dir, 0, 0, e, dst_dir == src_dir ? dir_cluster : 0,
                    dst_dir == src_dir ? dir_offset : 0, out);
    if (rc) return rc;
    rc = erase_entry(v, src_dir_first, dir_cluster, dir_offset);
    if (!rc && is_dir && first && dst_dir != src_dir) {            /* the moved directory's ".." names its new parent */
        const uint64_t lba = fat32_cluster_lba(v, first);
        const uint32_t parent = dst_dir == v->root_cluster ? 0 : dst_dir;
        if (!(rc = bounce(v, lba))) {
            uint8_t *dd = v->sector + 32;
            if (dd[0] != '.' || dd[1] != '.') rc = FAT32_E_CORRUPT;
            else { wr16(dd + 20, parent >> 16); wr16(dd + 26, parent & 0xffff); rc = write_sector(v, lba, v->sector); }
        }
    }
    rc2 = fat32_sync(v);
    return rc ? rc : rc2;
}

int fat32_rename(fat32_vol_t *v, uint32_t src_dir_first, uint32_t dir_cluster, uint32_t dir_offset, uint32_t dst_dir_first,
                 const uint16_t *name, unsigned name_len, int replace, fat32_dirent_t *out)
{
    fat32_undo_t tx;
    undo_sector_t *node;
    uint32_t page;
    uint64_t fat_bytes, dirty_bytes, cached_sectors;
    int rc = operation_guard(v), uncertain = 0;
    if (rc) return rc;
    if (v->rename_undo) return FAT32_E_BUSY;
    if (!v->write || !v->fat_dirty) return FAT32_E_RDONLY;
    if (!v->fat_npages || v->fat_npages > MAX_FAT_PAGES || !out) return FAT32_E_FORMAT;
    f32_zero(&tx, sizeof tx);
    fat_bytes = (uint64_t)v->fat_npages * 4096;
    dirty_bytes = v->fat_npages + 1;
    tx.cache_bytes = fat_bytes + dirty_bytes;
    tx.free_clusters = v->free_clusters; tx.alloc_hint = v->alloc_hint; tx.fsinfo_dirty = v->fsinfo_dirty;
    cached_sectors = (uint64_t)v->fat_npages * 8;
    if (cached_sectors > v->fat_sectors) cached_sectors = v->fat_sectors;
    /* All mirrored cached FAT sectors + at most two directory-growth clusters,
     * source/target LFNs, '..' and FSInfo. No file-size/128-sector ceiling. */
    tx.sector_limit = (uint64_t)v->nfats * cached_sectors + 2u * v->spc + 32u;
    v->rename_undo = &tx;
    tx.in_callback = 1;
    tx.cache = v->alloc(v->ctx, tx.cache_bytes);
    tx.in_callback = 0;
    if (!tx.cache) { v->rename_undo = 0; return FAT32_E_NOMEM; }
    for (page = 0; page < v->fat_npages; ++page) f32_copy(tx.cache + (uint64_t)page * 4096, v->fat_pages[page], 4096);
    f32_copy(tx.cache + fat_bytes, v->fat_dirty, dirty_bytes);
    rc = rename_impl(v, src_dir_first, dir_cluster, dir_offset, dst_dir_first, name, name_len, replace, out);
    if (!rc && tx.error) rc = tx.error;
    if (rc) {
        uint8_t verify[FAT32_SECTOR];
        for (node = tx.sectors; node; node = node->next) {
            tx.in_callback = 1; ++v->sector_writes;
            if (v->write(v->ctx, node->lba, node->before)) uncertain = 1;
            tx.in_callback = 0;
        }
        for (node = tx.sectors; node; node = node->next) {
            unsigned byte;
            tx.in_callback = 1; ++v->sector_reads;
            if (v->read(v->ctx, node->lba, verify)) uncertain = 1;
            else for (byte = 0; byte < FAT32_SECTOR; ++byte) if (verify[byte] != node->before[byte]) { uncertain = 1; break; }
            tx.in_callback = 0;
        }
        for (page = 0; page < v->fat_npages; ++page) f32_copy(v->fat_pages[page], tx.cache + (uint64_t)page * 4096, 4096);
        f32_copy(v->fat_dirty, tx.cache + fat_bytes, dirty_bytes);
        v->free_clusters = tx.free_clusters; v->alloc_hint = tx.alloc_hint; v->fsinfo_dirty = tx.fsinfo_dirty;
        v->sector_lba = ~0ull; f32_zero(v->sector, sizeof v->sector);
        if (uncertain) { v->recovery_required = 1; rc = FAT32_E_RECOVERY; }
    }
    while ((node = tx.sectors)) {
        tx.sectors = node->next; tx.in_callback = 1;
        v->free(v->ctx, node, sizeof *node); tx.in_callback = 0;
    }
    tx.in_callback = 1; v->free(v->ctx, tx.cache, tx.cache_bytes); tx.in_callback = 0;
    v->rename_undo = 0;
    return rc;
}
