/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP: empty FAT32 volume formatter. See fat32fmt.h.
 */
#include "fat32fmt.h"
#include <string.h>

#define SS 512u
#define RSVD 32u
#define CHUNK 32u                                   /* sectors per write when zeroing */

static uint8_t zero_chunk[SS * CHUNK];

static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { put16(p, v); put16(p + 2, v >> 16); }

static uint32_t cluster_sectors(uint64_t sectors)
{
    if (sectors < 66600) return 0;                   /* too small for FAT32 */
    if (sectors <= 532480) return 1;
    if (sectors <= 16777216) return 8;
    if (sectors <= 33554432) return 16;
    if (sectors <= 67108864) return 32;
    return 64;
}

static int wr(const fat32_io *io, uint64_t s, uint32_t n, const void *buf) { return io->write(io->ctx, s, n, buf) ? -2 : 0; }

static int zero(const fat32_io *io, uint64_t s, uint64_t n)
{
    while (n) {
        const uint32_t k = n < CHUNK ? (uint32_t)n : CHUNK;
        if (wr(io, s, k, zero_chunk)) return -2;
        s += k;
        n -= k;
    }
    return 0;
}

int fat32_format(const fat32_io *io, const fat32_params *p, uint32_t *clusters_out)
{
    uint8_t bs[SS], fsinfo[SS], sec[SS];
    const uint32_t spc = cluster_sectors(p->sectors);
    uint64_t tmp1, tmp2, fatsz, clusters, data;
    int st;
    if (!spc || p->sectors > 0xffffffffull) return -1;
    tmp1 = p->sectors - RSVD;
    tmp2 = (256u * spc + 2u) / 2u;
    fatsz = (tmp1 + tmp2 - 1) / tmp2;
    data = RSVD + 2 * fatsz;
    clusters = (p->sectors - data) / spc;
    if (clusters < 65525 || clusters >= 0x0ffffff5u || (clusters + 2) * 4 > fatsz * SS) return -1;
    memset(bs, 0, sizeof bs);
    bs[0] = 0xeb; bs[1] = 0x58; bs[2] = 0x90;
    memcpy(bs + 3, "MSWIN4.1", 8);                  /* OEM id legacy drivers expect; not Microsoft code */
    put16(bs + 0x0b, SS);
    bs[0x0d] = (uint8_t)spc;
    put16(bs + 0x0e, RSVD);
    bs[0x10] = 2;
    bs[0x15] = 0xf8;
    put16(bs + 0x18, 63);
    put16(bs + 0x1a, 255);
    put32(bs + 0x1c, p->hidden);
    put32(bs + 0x20, (uint32_t)p->sectors);
    put32(bs + 0x24, (uint32_t)fatsz);
    put32(bs + 0x2c, 2);                            /* root directory cluster */
    put16(bs + 0x30, 1);                            /* FSInfo sector */
    put16(bs + 0x32, 6);                            /* backup boot sector */
    bs[0x40] = 0x80;
    bs[0x42] = 0x29;
    put32(bs + 0x43, p->volume_id);
    memcpy(bs + 0x47, p->label, 11);
    memcpy(bs + 0x52, "FAT32   ", 8);
    bs[0x5a] = 0xcd; bs[0x5b] = 0x18;               /* not bootable until the user installs a system: INT 18h */
    bs[0x5c] = 0xf4; bs[0x5d] = 0xeb; bs[0x5e] = 0xfd;
    bs[510] = 0x55; bs[511] = 0xaa;
    memset(fsinfo, 0, sizeof fsinfo);
    put32(fsinfo + 0, 0x41615252u);
    put32(fsinfo + 484, 0x61417272u);
    put32(fsinfo + 488, (uint32_t)clusters - 1);    /* the root directory uses cluster 2 */
    put32(fsinfo + 492, 3);
    put32(fsinfo + 508, 0xaa550000u);
    if ((st = zero(io, 0, RSVD))) return st;
    if ((st = zero(io, RSVD, 2 * fatsz))) return st;
    if ((st = zero(io, data, spc))) return st;
    memset(sec, 0, sizeof sec);
    put32(sec + 0, 0x0ffffff8u);                    /* media descriptor */
    put32(sec + 4, 0x0fffffffu);                    /* clean shutdown, no hard error */
    put32(sec + 8, 0x0fffffffu);                    /* root directory: one cluster, end of chain */
    if ((st = wr(io, RSVD, 1, sec)) || (st = wr(io, RSVD + fatsz, 1, sec))) return st;
    memset(sec, 0, sizeof sec);
    memcpy(sec, p->label, 11);
    sec[11] = 0x08;                                 /* volume label entry */
    if ((st = wr(io, data, 1, sec))) return st;
    if ((st = wr(io, 6, 1, bs)) || (st = wr(io, 7, 1, fsinfo))) return st;
    if ((st = wr(io, 1, 1, fsinfo)) || (st = wr(io, 0, 1, bs))) return st;       /* primary boot sector last */
    if (clusters_out) *clusters_out = (uint32_t)clusters;
    return 0;
}

/* ---------------------------------------------------------------- independent read-only decoder (see fat32fmt.h) */
static uint32_t rd16(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8; }
static uint32_t rd32(const uint8_t *p) { return rd16(p) | rd16(p + 2) << 16; }

static int vread(fat32_vol *v, uint64_t sector, uint32_t count, void *buf)
{
    if (!count || sector >= v->io.sectors || count > v->io.sectors - sector) return FAT32R_ECORRUPT;
    return v->io.read(v->io.ctx, sector, count, buf) ? FAT32R_EIO : FAT32R_OK;
}

const char *fat32_rstrerror(int err)
{
    switch (err) {
    case FAT32R_OK: return "ok";
    case FAT32R_EBPB: return "not a valid FAT32 volume";
    case FAT32R_EIO: return "read error";
    case FAT32R_ENOENT: return "not found";
    case FAT32R_ECORRUPT: return "corrupt cluster chain or directory";
    case FAT32R_ESINK: return "consumer rejected the data";
    case FAT32R_ESIZE: return "not a regular file of the expected size";
    case FAT32R_EWRITE: return "write error";
    default: return "unknown error";
    }
}

int fat32_mount(fat32_vol *v, const fat32_rio *io)
{
    uint8_t *b = v->dir;
    uint64_t total, fats, data;
    int st;
    memset(v, 0, sizeof *v);
    v->io = *io;
    v->fat_cached = 0xffffffffu;
    if ((st = vread(v, 0, 1, b))) return st == FAT32R_EIO ? st : FAT32R_EBPB;
    if (b[510] != 0x55 || b[511] != 0xaa || rd16(b + 11) != SS) return FAT32R_EBPB;
    v->spc = b[13];
    v->rsvd = rd16(b + 14);
    v->nfats = b[16];
    total = rd16(b + 19) ? rd16(b + 19) : rd32(b + 32);
    v->fat_sectors = rd32(b + 36);
    v->root = rd32(b + 44);
    v->hidden = rd32(b + 28);
    if (!v->spc || (v->spc & (v->spc - 1)) || v->spc > 128 || !v->rsvd || !v->nfats || v->nfats > 2 ||
        rd16(b + 17) || rd16(b + 22) || !v->fat_sectors || total > io->sectors || total < 66600)
        return FAT32R_EBPB;
    fats = (uint64_t)v->nfats * v->fat_sectors;
    v->data_start = v->rsvd + fats;
    if (v->data_start >= total) return FAT32R_EBPB;
    data = (total - v->data_start) / v->spc;
    if (data < 65525 || data > 0x0ffffff4u || (data + 2) * 4 > (uint64_t)v->fat_sectors * SS) return FAT32R_EBPB;
    v->clusters = (uint32_t)data;
    v->io.sectors = total;                                 /* never read beyond the BPB's own volume */
    if (v->root < 2 || v->root > v->clusters + 1) return FAT32R_EBPB;
    return FAT32R_OK;
}

static int fat_next(fat32_vol *v, uint32_t c, uint32_t *next)
{
    const uint32_t sector = v->rsvd + c / (SS / 4);
    int st;
    if (sector != v->fat_cached) {
        if ((st = vread(v, sector, 1, v->fat))) return st;
        v->fat_cached = sector;
    }
    *next = rd32(v->fat + (c % (SS / 4)) * 4) & 0x0fffffffu;
    return FAT32R_OK;
}

static int valid_cluster(const fat32_vol *v, uint32_t c) { return c >= 2 && c <= v->clusters + 1; }
static int is_eoc(uint32_t c) { return c >= 0x0ffffff8u; }
static uint64_t cluster_lba(const fat32_vol *v, uint32_t c) { return v->data_start + (uint64_t)(c - 2) * v->spc; }
static char fold(char c) { return c >= 'a' && c <= 'z' ? (char)(c - 32) : c; }

static int name_eq(const char *a, size_t alen, const char *b)
{
    size_t i;
    for (i = 0; i < alen; ++i) if (!b[i] || fold(a[i]) != fold(b[i])) return 0;
    return b[alen] == 0;
}

/* Finds `name` (length n) in the directory chain at `dirc`. */
static int dir_find(fat32_vol *v, uint32_t dirc, const char *name, size_t n, uint32_t *first, uint32_t *size, int *is_dir)
{
    char lfn[261];
    unsigned lfn_ok = 0, lfn_ord = 0;
    uint8_t lfn_sum = 0;
    uint32_t c = dirc, steps = 0, s, e, k;
    int st;
    while (1) {
        if (!valid_cluster(v, c) || ++steps > v->clusters) return FAT32R_ECORRUPT;
        for (s = 0; s < v->spc; ++s) {
            if ((st = vread(v, cluster_lba(v, c) + s, 1, v->dir))) return st;
            for (e = 0; e < SS; e += 32) {
                const uint8_t *d = v->dir + e;
                if (!d[0]) return FAT32R_ENOENT;                 /* end of directory */
                if (d[0] == 0xe5) { lfn_ok = 0; continue; }
                if (d[11] == 0x0f) {                             /* VFAT long-name slot */
                    static const uint8_t off[13] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
                    const unsigned ord = d[0] & 0x1fu;
                    if (!ord || ord > 20) { lfn_ok = 0; continue; }
                    if (d[0] & 0x40) { memset(lfn, 0, sizeof lfn); lfn_ord = ord; lfn_sum = d[13]; lfn_ok = 1; }
                    else if (!lfn_ok || ord != lfn_ord - 1 || d[13] != lfn_sum) { lfn_ok = 0; continue; }
                    lfn_ord = ord;
                    for (k = 0; k < 13; ++k) {
                        const uint32_t ch = rd16(d + off[k]);
                        if (ch == 0 || ch == 0xffff) continue;
                        lfn[(ord - 1) * 13 + k] = ch < 0x80 ? (char)ch : '?';  /* non-ASCII never matches a request */
                    }
                    continue;
                }
                if (d[11] & 0x08) { lfn_ok = 0; continue; }             /* volume label */
                {
                    char sn[13];
                    size_t m = 0;
                    uint8_t sum = 0;
                    int hit = 0;
                    for (k = 0; k < 11; ++k) sum = (uint8_t)(((sum & 1) ? 0x80 : 0) + (sum >> 1) + d[k]);
                    if (lfn_ok && lfn_ord == 1 && sum == lfn_sum) hit = name_eq(name, n, lfn);
                    for (k = 0; k < 8 && d[k] != ' '; ++k) sn[m++] = (char)(k == 0 && d[0] == 0x05 ? 0xe5 : d[k]);
                    if (d[8] != ' ') { sn[m++] = '.'; for (k = 8; k < 11 && d[k] != ' '; ++k) sn[m++] = (char)d[k]; }
                    sn[m] = 0;
                    if (!hit) hit = name_eq(name, n, sn);
                    lfn_ok = 0;
                    if (hit) {
                        *first = rd16(d + 20) << 16 | rd16(d + 26);
                        *size = rd32(d + 28);
                        *is_dir = (d[11] & 0x10) != 0;
                        if (*first && !valid_cluster(v, *first)) return FAT32R_ECORRUPT;
                        return FAT32R_OK;
                    }
                }
            }
        }
        if ((st = fat_next(v, c, &c))) return st;
        if (is_eoc(c)) return FAT32R_ENOENT;
    }
}

int fat32_lookup(fat32_vol *v, const char *path, uint32_t *first, uint32_t *size, int *is_dir)
{
    uint32_t c = v->root, sz = 0;
    int dir = 1, st;
    if (!path || *path != '/') return FAT32R_ENOENT;
    while (*path) {
        const char *s;
        size_t n;
        while (*path == '/') ++path;
        if (!*path) break;
        if (!dir) return FAT32R_ENOENT;
        s = path;
        while (*path && *path != '/') ++path;
        n = (size_t)(path - s);
        if (n > 255 || (n <= 2 && s[0] == '.')) return FAT32R_ENOENT;
        if ((st = dir_find(v, c, s, n, &c, &sz, &dir))) return st;
        if (dir && !c) return FAT32R_ECORRUPT;
    }
    *first = c;
    *size = sz;
    *is_dir = dir;
    return FAT32R_OK;
}

int fat32_stream(fat32_vol *v, uint32_t first, uint32_t size, uint8_t *cbuf, fat32_sink sink, void *sink_ctx)
{
    const uint32_t cb = v->spc * SS;
    uint32_t c = first, left = size, steps = 0;
    int st;
    if (!size) return first ? FAT32R_ECORRUPT : FAT32R_OK;
    while (left) {
        const uint32_t n = left < cb ? left : cb;
        if (!valid_cluster(v, c) || ++steps > v->clusters) return FAT32R_ECORRUPT;
        if ((st = vread(v, cluster_lba(v, c), v->spc, cbuf))) return st;
        if (sink(sink_ctx, cbuf, n)) return FAT32R_ESINK;
        left -= n;
        if ((st = fat_next(v, c, &c))) return st;
    }
    return is_eoc(c) ? FAT32R_OK : FAT32R_ECORRUPT;      /* the chain must end exactly at the file size */
}

int fat32_overwrite_file(fat32_vol *v, fat32_wfn write, void *wctx, const char *path, const void *data, uint32_t size,
                         uint8_t *cbuf)
{
    const uint32_t cb = v->spc * SS;
    const uint8_t *src = data;
    uint32_t first, fsize, c, left, steps, need;
    int st, is_dir;
    if (!write || !data || !size || !cbuf) return FAT32R_ESIZE;
    if ((st = fat32_lookup(v, path, &first, &fsize, &is_dir))) return st;
    if (is_dir || fsize != size || !first) return FAT32R_ESIZE;
    need = size / cb + (size % cb != 0);
    /* Pass 1: the whole chain is valid, loop free and exactly `need` clusters long before any byte is written. */
    for (c = first, steps = 0; steps < need; ++steps) {
        if (!valid_cluster(v, c) || steps >= v->clusters) return FAT32R_ECORRUPT;
        if ((st = fat_next(v, c, &c))) return st;
        if (steps + 1 < need && is_eoc(c)) return FAT32R_ECORRUPT;
    }
    if (!is_eoc(c)) return FAT32R_ECORRUPT;
    /* Pass 2: read-modify-write of data clusters only. */
    for (c = first, left = size, steps = 0; left; ++steps) {
        const uint32_t n = left < cb ? left : cb;
        const uint64_t lba = cluster_lba(v, c);
        if (steps >= need || !valid_cluster(v, c) || lba >= v->io.sectors || v->spc > v->io.sectors - lba)
            return FAT32R_ECORRUPT;
        if ((st = vread(v, lba, v->spc, cbuf))) return st;
        memcpy(cbuf, src, n);
        if (write(wctx, lba, v->spc, cbuf)) return FAT32R_EWRITE;
        src += n;
        left -= n;
        if (left && (st = fat_next(v, c, &c))) return st;
    }
    return FAT32R_OK;
}
