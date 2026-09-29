/* SPDX-License-Identifier: GPL-2.0-only
 * Read-only FAT32 volume reader (see fat32.h). Freestanding: no libc, no kernel headers; all I/O and memory come
 * through the callbacks in fat32_vol_t, so shizukudos/tests/test_fat32.c runs the same code on the host.
 */
#include "fat32.h"

#define EOC 0x0ffffff8u
#define MAX_FAT_PAGES 4096u                     /* 16 MiB of FAT = 4M clusters */

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void f32_copy(void *d, const void *s, uint64_t n) { uint8_t *dd = d; const uint8_t *ss = s; while (n--) *dd++ = *ss++; }
static void f32_zero(void *d, uint64_t n) { uint8_t *dd = d; while (n--) *dd++ = 0; }

static int read_sector(fat32_vol_t *v, uint64_t lba, void *buf)
{
    if (lba >= v->disk_sectors) return FAT32_E_RANGE;
    ++v->sector_reads;
    return v->read(v->ctx, lba, buf) ? FAT32_E_IO : FAT32_OK;
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
    if (!v->read || !v->alloc || !v->free || !v->alloc_page || !v->disk_sectors) return FAT32_E_FORMAT;
    v->fat_pages = 0; v->fat_npages = 0; v->part_lba = 0; v->part_sectors = 0; v->sector_reads = 0; v->sector_lba = ~0ull;
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
            for (sec = 0; sec < 8; ++sec) {
                const uint32_t fat_sector = page * 8 + sec;
                if (fat_sector >= fatsz) break;
                if ((rc = read_sector(v, v->part_lba + reserved + fat_sector, (uint8_t *)v->fat_pages[page] + sec * FAT32_SECTOR))) {
                    fat32_unmount(v);
                    return rc;
                }
            }
        }
    }
    if ((fat32_fat_entry(v, 0) & 0x0fffff00u) != 0x0fffff00u || (fat32_fat_entry(v, 1) & 0x03ffffffu) != 0x03ffffffu) {
        fat32_unmount(v);
        return FAT32_E_CORRUPT;
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
int fat32_chain_build(fat32_vol_t *v, uint32_t first_cluster, fat32_chain_t *c)
{
    uint32_t cur = first_cluster, n = 0;
    c->runs = 0; c->nruns = 0; c->cap = 0; c->total_clusters = 0;
    if (!first_cluster) return FAT32_OK;                                   /* empty file */
    while (cur < EOC) {
        if (!valid_cluster(v, cur) || ++n > v->cluster_count) { fat32_chain_free(v, c); return FAT32_E_CORRUPT; }
        if (c->nruns && c->runs[c->nruns - 1].start + c->runs[c->nruns - 1].count == cur) {
            ++c->runs[c->nruns - 1].count;
        } else {
            if (c->nruns == c->cap) {
                const uint32_t ncap = c->cap ? c->cap * 2 : 8;
                fat32_run_t *nr = v->alloc(v->ctx, (uint64_t)ncap * sizeof *nr);
                if (!nr) { fat32_chain_free(v, c); return FAT32_E_NOMEM; }
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
            if ((rc = read_sector(v, lba, dst))) return rc;
            n = FAT32_SECTOR;
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
