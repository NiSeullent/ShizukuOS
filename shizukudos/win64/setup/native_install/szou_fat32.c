/* SPDX-License-Identifier: GPL-2.0-only
 * Setup-side FAT32 file writer for SZOU staging. Written from the Microsoft
 * FAT32 on-disk specification (fatgen103); no external code copied.
 * Freestanding C99: memcpy/memset/memcmp only.
 */
#include "szou_fat32.h"
#include "../plat.h"
#include <string.h>

#define EOC 0x0FFFFFFFu
#define A_RO 0x01u
#define A_VOL 0x08u
#define A_DIR 0x10u
#define A_LFN 0x0Fu

static uint16_t fx_rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t fx_rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void fx_wr16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void fx_wr32(uint8_t *p, uint32_t v) { fx_wr16(p, v); fx_wr16(p + 2, v >> 16); }

typedef struct { uint64_t lba; uint32_t off; } loc_t;

/* ---- device ---- */
static int dev_io(szou_fat32_t *fs, int w, uint64_t lba, uint32_t n, void *buf)
{
    uint8_t *p = buf;
    if (lba >= fs->dev.sectors || n > fs->dev.sectors - lba) return SZOU_E_IO;
    while (n) {
        uint32_t c = n < fs->dev.max_io_sectors ? n : fs->dev.max_io_sectors;
        int rc = w ? fs->dev.write(fs->dev.ctx, lba, c, p) : fs->dev.read(fs->dev.ctx, lba, c, p);
        if (rc) return SZOU_E_IO;
        lba += c; n -= c; p += (size_t)c * fs->bps;
    }
    return 0;
}
static int dev_rd(szou_fat32_t *fs, uint64_t lba, uint32_t n, void *b) { return dev_io(fs, 0, lba, n, b); }
static int dev_wr(szou_fat32_t *fs, uint64_t lba, uint32_t n, const void *b) { return dev_io(fs, 1, lba, n, (void *)b); }
static int dev_flush(szou_fat32_t *fs) { return fs->dev.flush(fs->dev.ctx) ? SZOU_E_IO : 0; }

/* ---- FAT ---- */
static int valid_clus(const szou_fat32_t *fs, uint32_t c) { return c >= 2 && c <= fs->nclusters + 1; }
static uint64_t clus_lba(const szou_fat32_t *fs, uint32_t c) { return fs->data_lba + (uint64_t)(c - 2) * fs->spc; }

static int fat_sync(szou_fat32_t *fs)
{
    uint32_t i;
    if (!fs->fat_dirty) return 0;
    for (i = 0; i < fs->nfats; i++)
        if (dev_wr(fs, (uint64_t)fs->reserved + (uint64_t)i * fs->fatsz + fs->fat_sec, 1, fs->fatbuf)) return SZOU_E_IO;
    fs->fat_dirty = 0;
    return 0;
}
static int fat_load(szou_fat32_t *fs, uint32_t sec)
{
    int rc;
    if (fs->fat_valid && fs->fat_sec == sec) return 0;
    if ((rc = fat_sync(fs))) return rc;
    fs->fat_valid = 0;
    if (dev_rd(fs, (uint64_t)fs->reserved + sec, 1, fs->fatbuf)) return SZOU_E_IO;
    fs->fat_sec = sec;
    fs->fat_valid = 1;
    return 0;
}
static int fat_get(szou_fat32_t *fs, uint32_t c, uint32_t *v)
{
    int rc;
    if (!valid_clus(fs, c)) return SZOU_E_STATE;
    if ((rc = fat_load(fs, (uint32_t)(((uint64_t)c * 4) / fs->bps)))) return rc;
    *v = fx_rd32(fs->fatbuf + ((uint64_t)c * 4) % fs->bps) & 0x0FFFFFFFu;
    return 0;
}
static int fat_put(szou_fat32_t *fs, uint32_t c, uint32_t v)
{
    uint8_t *p;
    int rc;
    if (!valid_clus(fs, c)) return SZOU_E_STATE;
    if ((rc = fat_load(fs, (uint32_t)(((uint64_t)c * 4) / fs->bps)))) return rc;
    p = fs->fatbuf + ((uint64_t)c * 4) % fs->bps;
    fx_wr32(p, (fx_rd32(p) & 0xF0000000u) | (v & 0x0FFFFFFFu));
    fs->fat_dirty = 1;
    return 0;
}
/* next cluster or 0 at end of chain; corrupt links refuse. */
static int chain_next(szou_fat32_t *fs, uint32_t c, uint32_t *nx)
{
    uint32_t v;
    int rc = fat_get(fs, c, &v);
    if (rc) return rc;
    if (v >= 0x0FFFFFF8u) { *nx = 0; return 0; }
    if (!valid_clus(fs, v)) return SZOU_E_STATE;
    *nx = v;
    return 0;
}
/* Find `count` free clusters without marking them (single writer). */
static int alloc_scan(szou_fat32_t *fs, uint32_t count, uint32_t *out)
{
    uint32_t c = valid_clus(fs, fs->next_free) ? fs->next_free : 2, seen, got = 0, v;
    int rc;
    if (count > fs->free_count) return SZOU_E_FULL;
    for (seen = 0; seen < fs->nclusters && got < count; seen++) {
        if ((rc = fat_get(fs, c, &v))) return rc;
        if (v == 0) out[got++] = c;
        c = c + 1 > fs->nclusters + 1 ? 2 : c + 1;
    }
    if (got < count) return SZOU_E_FULL;
    fs->next_free = c;
    return 0;
}
static int chain_commit(szou_fat32_t *fs, const uint32_t *cl, uint32_t n)
{
    uint32_t i;
    int rc;
    for (i = 0; i < n; i++)
        if ((rc = fat_put(fs, cl[i], i + 1 < n ? cl[i + 1] : EOC))) return rc;
    fs->free_count -= n;
    return fat_sync(fs);
}
static int chain_free(szou_fat32_t *fs, uint32_t c)
{
    uint32_t n = 0, nx;
    int rc;
    while (c) {
        if (++n > fs->nclusters) return SZOU_E_STATE;          /* loop */
        if ((rc = chain_next(fs, c, &nx))) return rc;
        if ((rc = fat_put(fs, c, 0))) return rc;
        fs->free_count++;
        c = nx;
    }
    return fat_sync(fs);
}

/* ---- names ---- */
static int ok83(uint8_t c)
{
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= '0' && c <= '9') return 1;
    {
        static const char extra[] = "!#$%&'()-@^_`{}~";
        const char *x;
        for (x = extra; *x; x++) if ((uint8_t)*x == c) return 1;
    }
    return 0;
}
static int to83(const char *s, size_t n, uint8_t out[11])
{
    size_t i, dot = n, b = 0, e = 0;
    memset(out, ' ', 11);
    for (i = 0; i < n; i++) if (s[i] == '.') { if (dot != n) return SZOU_E_UNSUPPORTED; dot = i; }
    if (dot == 0 || dot > 8 || (dot < n && (n - dot - 1 == 0 || n - dot - 1 > 3))) return SZOU_E_UNSUPPORTED;
    for (i = 0; i < n; i++) {
        uint8_t c = (uint8_t)s[i];
        if (i == dot) continue;
        if (c >= 'a' && c <= 'z') c = (uint8_t)(c - 32);
        if (!ok83(c)) return SZOU_E_UNSUPPORTED;               /* would need an LFN */
        if (i < dot) out[b++] = c; else out[8 + e++] = c;
    }
    return 0;
}
static uint32_t ent_clus(const uint8_t *e) { return ((uint32_t)fx_rd16(e + 20) << 16) | fx_rd16(e + 26); }
static void make_ent(szou_fat32_t *fs, uint8_t *e, const uint8_t name[11], uint8_t attr, uint32_t clus, uint32_t size)
{
    memset(e, 0, 32);
    memcpy(e, name, 11);
    e[11] = attr;
    fx_wr16(e + 14, fs->dos_time); fx_wr16(e + 16, fs->dos_date); fx_wr16(e + 18, fs->dos_date);
    fx_wr16(e + 20, clus >> 16); fx_wr16(e + 22, fs->dos_time); fx_wr16(e + 24, fs->dos_date);
    fx_wr16(e + 26, clus & 0xFFFFu); fx_wr32(e + 28, size);
}

/* ---- directories ---- */
#define LFN_MAX 20
typedef struct { loc_t at; uint8_t ent[32]; loc_t lfn[LFN_MAX]; uint32_t nlfn; } found_t;

/* Iterate dir; mode 0: find name; mode 1: find free slot (else SZOU_ABSENT with *last);
 * mode 2: emptiness check (0 empty / SZOU_E_STATE not empty). */
static int dir_walk(szou_fat32_t *fs, uint32_t dir, int mode, const uint8_t *name, found_t *f, uint32_t *last)
{
    uint32_t c = dir, n = 0, s, o;
    int rc;
    if (f) f->nlfn = 0;
    while (c) {
        if (++n > fs->nclusters) return SZOU_E_STATE;
        for (s = 0; s < fs->spc; s++) {
            uint64_t lba = clus_lba(fs, c) + s;
            if (dev_rd(fs, lba, 1, fs->dbuf)) return SZOU_E_IO;
            for (o = 0; o < fs->bps; o += 32) {
                const uint8_t *e = fs->dbuf + o;
                if (e[0] == 0x00) {
                    if (mode == 1) { f->at.lba = lba; f->at.off = o; return 0; }
                    return mode == 2 ? 0 : SZOU_ABSENT;
                }
                if (e[0] == 0xE5) {
                    if (mode == 1) { f->at.lba = lba; f->at.off = o; return 0; }
                    if (f) f->nlfn = 0;
                    continue;
                }
                if (mode == 2) {
                    if (e[0] == '.' && (e[11] & A_DIR)) continue;
                    return SZOU_E_STATE;
                }
                if (mode == 1) continue;
                if ((e[11] & 0x3F) == A_LFN) {
                    if (f->nlfn < LFN_MAX) { f->lfn[f->nlfn].lba = lba; f->lfn[f->nlfn].off = o; f->nlfn++; }
                    continue;
                }
                if (!(e[11] & A_VOL) && memcmp(e, name, 11) == 0) {
                    f->at.lba = lba; f->at.off = o; memcpy(f->ent, e, 32);
                    return 0;
                }
                f->nlfn = 0;
            }
        }
        if (last) *last = c;
        if ((rc = chain_next(fs, c, &c))) return rc;
    }
    return mode == 2 ? 0 : SZOU_ABSENT;
}
static int ent_write(szou_fat32_t *fs, loc_t at, const uint8_t *e32)
{
    if (dev_rd(fs, at.lba, 1, fs->sec)) return SZOU_E_IO;
    memcpy(fs->sec + at.off, e32, 32);
    return dev_wr(fs, at.lba, 1, fs->sec);
}
static int ent_delete(szou_fat32_t *fs, const found_t *f)
{
    uint32_t i;
    if (dev_rd(fs, f->at.lba, 1, fs->sec)) return SZOU_E_IO;
    fs->sec[f->at.off] = 0xE5;
    if (dev_wr(fs, f->at.lba, 1, fs->sec)) return SZOU_E_IO;
    for (i = 0; i < f->nlfn; i++) {                              /* orphan LFN run of an existing entry */
        if (dev_rd(fs, f->lfn[i].lba, 1, fs->sec)) return SZOU_E_IO;
        fs->sec[f->lfn[i].off] = 0xE5;
        if (dev_wr(fs, f->lfn[i].lba, 1, fs->sec)) return SZOU_E_IO;
    }
    return 0;
}
static int zero_cluster(szou_fat32_t *fs, uint32_t c, const uint8_t *first)
{
    uint32_t s;
    for (s = 0; s < fs->spc; s++) {
        memset(fs->sec, 0, fs->bps);
        if (s == 0 && first) memcpy(fs->sec, first, 64);
        if (dev_wr(fs, clus_lba(fs, c) + s, 1, fs->sec)) return SZOU_E_IO;
    }
    return 0;
}
/* Free slot in dir, extending the chain by a zeroed cluster if needed. */
static int dir_slot(szou_fat32_t *fs, uint32_t dir, loc_t *at)
{
    found_t f;
    uint32_t last = dir, c;
    int rc = dir_walk(fs, dir, 1, 0, &f, &last);
    if (rc == 0) { *at = f.at; return 0; }
    if (rc != SZOU_ABSENT) return rc;
    if ((rc = alloc_scan(fs, 1, &c))) return rc;
    if ((rc = zero_cluster(fs, c, 0)) || (rc = dev_flush(fs))) return rc;
    if ((rc = fat_put(fs, c, EOC)) || (rc = fat_put(fs, last, c))) return rc;
    fs->free_count--;
    if ((rc = fat_sync(fs)) || (rc = dev_flush(fs))) return rc;
    at->lba = clus_lba(fs, c); at->off = 0;
    return 0;
}
/* Resolve parent directory cluster and final 8.3 name. */
static int resolve(szou_fat32_t *fs, const char *path, uint32_t *parent, uint8_t name[11])
{
    uint32_t cur = fs->root;
    size_t st = 0, i;
    found_t f;
    int rc;
    if (!path || !path[0]) return SZOU_E_ARG;
    for (i = 0;; i++) {
        if (path[i] == '\\' || path[i] == 0) {
            if (i == st) return SZOU_E_PATH;
            if ((rc = to83(path + st, i - st, name))) return rc;
            if (!path[i]) break;
            if ((rc = dir_walk(fs, cur, 0, name, &f, 0))) return rc;   /* SZOU_ABSENT propagates */
            if (!(f.ent[11] & A_DIR)) return SZOU_E_CONFLICT;
            cur = ent_clus(f.ent);
            if (cur == 0) cur = fs->root;
            if (!valid_clus(fs, cur)) return SZOU_E_STATE;
            st = i + 1;
        }
    }
    *parent = cur;
    return 0;
}
static int lookup(szou_fat32_t *fs, const char *path, uint32_t *parent, uint8_t name[11], found_t *f)
{
    int rc = resolve(fs, path, parent, name);
    if (rc) return rc;
    return dir_walk(fs, *parent, 0, name, f, 0);
}

/* ---- sink ops ---- */
static void *s_alloc(void *c, size_t n) { szou_fat32_t *fs = c; return fs->alloc(fs->mctx, n); }
static void s_free(void *c, void *p) { szou_fat32_t *fs = c; if (p) fs->free(fs->mctx, p); }

static int s_mkdir(void *c, const char *path)
{
    szou_fat32_t *fs = c;
    uint32_t parent, nc;
    uint8_t name[11], dots[64], e[32];
    found_t f;
    loc_t at;
    int rc;
    if (fs->writer_open) return SZOU_E_STATE;
    rc = lookup(fs, path, &parent, name, &f);
    if (rc == 0) return (f.ent[11] & A_DIR) ? SZOU_E_EXISTS : SZOU_E_CONFLICT;
    if (rc != SZOU_ABSENT) return rc;
    if ((rc = resolve(fs, path, &parent, name))) return rc == SZOU_ABSENT ? SZOU_E_IO : rc;
    if ((rc = alloc_scan(fs, 1, &nc))) return rc;
    make_ent(fs, dots, (const uint8_t *)".          ", A_DIR, nc, 0);
    make_ent(fs, dots + 32, (const uint8_t *)"..         ", A_DIR, parent == fs->root ? 0 : parent, 0);
    if ((rc = zero_cluster(fs, nc, dots)) || (rc = dev_flush(fs))) return rc;
    if ((rc = fat_put(fs, nc, EOC))) return rc;
    fs->free_count--;
    if ((rc = fat_sync(fs)) || (rc = dev_flush(fs))) return rc;
    if ((rc = dir_slot(fs, parent, &at))) return rc;
    make_ent(fs, e, name, A_DIR, nc, 0);
    return ent_write(fs, at, e);
}

static int del_common(szou_fat32_t *fs, const char *path, int want_dir)
{
    uint32_t parent, clus;
    uint8_t name[11];
    found_t f;
    int rc;
    if (fs->writer_open) return SZOU_E_STATE;
    rc = lookup(fs, path, &parent, name, &f);
    if (rc) return rc;                                    /* SZOU_ABSENT when missing */
    if (!!(f.ent[11] & A_DIR) != want_dir) return SZOU_E_CONFLICT;
    clus = ent_clus(f.ent);
    if (clus && !valid_clus(fs, clus)) return SZOU_E_STATE;
    if (want_dir && (rc = dir_walk(fs, clus, 2, 0, 0, 0))) return rc;
    if ((rc = ent_delete(fs, &f)) || (rc = dev_flush(fs))) return rc;
    return clus ? chain_free(fs, clus) : 0;
}
static int s_rmdir(void *c, const char *path) { return del_common(c, path, 1); }
static int s_remove(void *c, const char *path) { return del_common(c, path, 0); }

static szou_fat32_file_t *new_handle(szou_fat32_t *fs)
{
    uint32_t i;
    for (i = 0; i < SZOU_FAT32_HANDLES; i++)
        if (!fs->files[i].used) { memset(&fs->files[i], 0, sizeof fs->files[i]); fs->files[i].used = 1; return &fs->files[i]; }
    return 0;
}

static int s_create(void *c, const char *path, uint64_t size, void **file)
{
    szou_fat32_t *fs = c;
    szou_fat32_file_t *h;
    uint32_t parent;
    uint8_t name[11];
    found_t f;
    int rc;
    if (fs->writer_open) return SZOU_E_STATE;
    if (size > 0xFFFFFFFFull) return SZOU_E_UNSUPPORTED;
    rc = lookup(fs, path, &parent, name, &f);
    if (rc == 0) return SZOU_E_EXISTS;
    if (rc != SZOU_ABSENT) return rc;
    if ((rc = resolve(fs, path, &parent, name))) return rc == SZOU_ABSENT ? SZOU_E_IO : rc;
    if (!(h = new_handle(fs))) return SZOU_E_STATE;
    h->writing = 1; h->size = size; h->parent = parent; memcpy(h->name, name, 11);
    h->ncl = (uint32_t)((size + fs->cb - 1) / fs->cb);
    if (h->ncl) {
        if (!(h->cl = fs->alloc(fs->mctx, (size_t)h->ncl * 4))) { h->used = 0; return SZOU_E_NOMEM; }
        if ((rc = alloc_scan(fs, h->ncl, h->cl))) { fs->free(fs->mctx, h->cl); h->used = 0; return rc; }
        h->first = h->cl[0];
    }
    fs->writer_open = 1;
    *file = h;
    return 0;
}

static int s_open(void *c, const char *path, void **file, uint64_t *size)
{
    szou_fat32_t *fs = c;
    szou_fat32_file_t *h;
    uint32_t parent;
    uint8_t name[11];
    found_t f;
    int rc = lookup(fs, path, &parent, name, &f);
    if (rc) return rc;
    if (f.ent[11] & A_DIR) return SZOU_E_CONFLICT;
    if (!(h = new_handle(fs))) return SZOU_E_STATE;
    h->first = ent_clus(f.ent);
    h->size = fx_rd32(f.ent + 28);
    if ((h->first && !valid_clus(fs, h->first)) || (!h->first && h->size)) { h->used = 0; return SZOU_E_STATE; }
    h->cur_idx = 0; h->cur_clus = h->first;
    *file = h; *size = h->size;
    return 0;
}

static int clus_at(szou_fat32_t *fs, szou_fat32_file_t *h, uint32_t idx, uint32_t *out)
{
    uint32_t i, c;
    int rc;
    if (h->writing) { if (idx >= h->ncl) return SZOU_E_IO; *out = h->cl[idx]; return 0; }
    if (idx < h->cur_idx || !h->cur_clus) { h->cur_idx = 0; h->cur_clus = h->first; }
    c = h->cur_clus;
    for (i = h->cur_idx; i < idx; i++) {
        if ((rc = chain_next(fs, c, &c))) return rc;
        if (!c) return SZOU_E_STATE;                     /* chain shorter than size */
    }
    if (!c) return SZOU_E_STATE;
    h->cur_idx = idx; h->cur_clus = c;
    *out = c;
    return 0;
}

static int rw(szou_fat32_t *fs, szou_fat32_file_t *h, int w, uint64_t off, uint8_t *p, uint32_t len)
{
    if (!h || !h->used || (w && !h->writing) || off > h->size || len > h->size - off) return SZOU_E_IO;
    while (len) {
        uint32_t idx = (uint32_t)(off / fs->cb), within = (uint32_t)(off % fs->cb), cl, s = within / fs->bps,
                 so = within % fs->bps, n;
        uint64_t lba;
        int rc = clus_at(fs, h, idx, &cl);
        if (rc) return rc;
        lba = clus_lba(fs, cl) + s;
        if (so == 0 && len >= fs->bps) {
            n = len / fs->bps;
            if (n > fs->spc - s) n = fs->spc - s;
            if (w ? dev_wr(fs, lba, n, p) : dev_rd(fs, lba, n, p)) return SZOU_E_IO;
            n *= fs->bps;
        } else {
            n = fs->bps - so < len ? fs->bps - so : len;
            if (dev_rd(fs, lba, 1, fs->sec)) return SZOU_E_IO;
            if (w) { memcpy(fs->sec + so, p, n); if (dev_wr(fs, lba, 1, fs->sec)) return SZOU_E_IO; }
            else memcpy(p, fs->sec + so, n);
        }
        off += n; p += n; len -= n;
    }
    return 0;
}
static int s_read(void *c, void *f, uint64_t off, void *b, uint32_t n) { return rw(c, f, 0, off, b, n); }
static int s_write(void *c, void *f, uint64_t off, const void *b, uint32_t n) { return rw(c, f, 1, off, (uint8_t *)b, n); }

static int s_close(void *c, void *file)
{
    szou_fat32_t *fs = c;
    szou_fat32_file_t *h = file;
    uint8_t e[32];
    loc_t at;
    int rc = 0;
    if (!h || !h->used) return SZOU_E_ARG;
    if (h->writing) {
        /* data -> FAT -> directory entry, each separated by a device flush */
        if (!(rc = dev_flush(fs)) && !(rc = chain_commit(fs, h->cl, h->ncl)) && !(rc = dev_flush(fs)) &&
            !(rc = dir_slot(fs, h->parent, &at))) {
            make_ent(fs, e, h->name, 0x20, h->first, (uint32_t)h->size);
            if (!(rc = ent_write(fs, at, e))) rc = dev_flush(fs);
        }
        if (h->cl) fs->free(fs->mctx, h->cl);
        fs->writer_open = 0;
    }
    memset(h, 0, sizeof *h);
    return rc;
}

static int s_rename(void *c, const char *from, const char *to)
{
    szou_fat32_t *fs = c;
    uint32_t sp, dp, old = 0;
    uint8_t sn[11], dn[11], e[32];
    found_t sf, df;
    loc_t at;
    int rc;
    if (fs->writer_open) return SZOU_E_STATE;
    if ((rc = lookup(fs, from, &sp, sn, &sf))) return rc == SZOU_ABSENT ? SZOU_E_IO : rc;
    if (sf.ent[11] & A_DIR) return SZOU_E_UNSUPPORTED;        /* would need '..' rewrite */
    rc = lookup(fs, to, &dp, dn, &df);
    if (rc == 0) {
        if (df.ent[11] & A_DIR) return SZOU_E_CONFLICT;
        if (sp == dp && df.at.lba == sf.at.lba && df.at.off == sf.at.off) return 0;
        old = ent_clus(df.ent);
        memcpy(e, sf.ent, 32);
        memcpy(e, dn, 11);
        if ((rc = ent_write(fs, df.at, e)) || (rc = dev_flush(fs))) return rc;   /* replace point */
    } else if (rc == SZOU_ABSENT) {
        if ((rc = resolve(fs, to, &dp, dn))) return rc == SZOU_ABSENT ? SZOU_E_IO : rc;
        if ((rc = dir_slot(fs, dp, &at))) return rc;
        memcpy(e, sf.ent, 32);
        memcpy(e, dn, 11);
        if ((rc = ent_write(fs, at, e)) || (rc = dev_flush(fs))) return rc;
        /* the slot may have reused the source's own sector; re-find source */
        if ((rc = dir_walk(fs, sp, 0, sn, &sf, 0))) return rc == SZOU_ABSENT ? SZOU_E_STATE : rc;
    } else return rc;
    if ((rc = ent_delete(fs, &sf)) || (rc = dev_flush(fs))) return rc;
    if (old && old != ent_clus(sf.ent)) return chain_free(fs, old);
    return 0;
}

static int s_set_attr(void *c, const char *path, uint32_t a)
{
    szou_fat32_t *fs = c;
    uint32_t parent;
    uint8_t name[11];
    found_t f;
    int rc;
    if (a & ~SZOU_ATTR_ALLOWED) return SZOU_E_ATTR;
    if ((rc = lookup(fs, path, &parent, name, &f))) return rc == SZOU_ABSENT ? SZOU_E_IO : rc;
    if (f.ent[11] & A_DIR) return SZOU_E_CONFLICT;
    f.ent[11] = (uint8_t)a;
    return ent_write(fs, f.at, f.ent);
}

static int s_flush(void *c)
{
    szou_fat32_t *fs = c;
    int rc;
    if ((rc = fat_sync(fs))) return rc;
    if (fs->fsinfo) {
        if (dev_rd(fs, fs->fsinfo, 1, fs->sec)) return SZOU_E_IO;
        fx_wr32(fs->sec + 488, fs->free_count);
        fx_wr32(fs->sec + 492, fs->next_free);
        if (dev_wr(fs, fs->fsinfo, 1, fs->sec)) return SZOU_E_IO;
    }
    return dev_flush(fs);
}

/* ---- VFAT long names (v2) ----
 * Publication order (crash-safe): orphan LFN slots in the target directory
 * are scrubbed (0xE5), a run of n LFN slots + 1 short slot is found (free
 * 0xE5 slots or the 0x00 tail, extending the chain with zeroed clusters),
 * then the run is written sector by sector in chain order with a device flush
 * after every sector except the last; the short entry is the last slot and
 * lives in the last sector. A crash therefore never exposes a short entry
 * without its complete LFN chain: at worst orphan LFN slots exist, which
 * Windows ignores and the next scrub in that directory removes. Deletion
 * marks the short entry first, then its LFN slots. */
static const uint8_t lfn_pos[13] = { 1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30 };
static uint8_t lfn_sum(const uint8_t *n)
{
    uint8_t s = 0;
    int i;
    for (i = 0; i < 11; i++) s = (uint8_t)(((s & 1) << 7) + (s >> 1) + n[i]);
    return s;
}
static void lfn_make(uint8_t *e, const uint16_t *u, uint32_t units, uint32_t ord, int last, uint8_t sum)
{
    uint32_t k;
    memset(e, 0, 32);
    e[0] = (uint8_t)(ord | (last ? 0x40u : 0));
    e[11] = A_LFN; e[13] = sum;
    for (k = 0; k < 13; k++) {
        uint32_t i = (ord - 1) * 13 + k;
        fx_wr16(e + lfn_pos[k], i < units ? u[i] : (i == units ? 0x0000u : 0xFFFFu));
    }
}
static int slot_mark_free(szou_fat32_t *fs, loc_t at)
{
    if (dev_rd(fs, at.lba, 1, fs->sec)) return SZOU_E_IO;
    fs->sec[at.off] = 0xE5;
    return dev_wr(fs, at.lba, 1, fs->sec);
}
/* Remove LFN slots that do not form a complete chain bound (ordinal +
 * checksum) to the immediately following short entry. */
static int dir_scrub(szou_fat32_t *fs, uint32_t dir)
{
    loc_t pend[LFN_MAX];
    uint32_t c = dir, n = 0, s, o, np = 0, rem = 0, i, any = 0;
    uint8_t sum = 0;
    int rc;
#define ORPHAN_PEND() do { for (i = 0; i < np; i++) { if ((rc = slot_mark_free(fs, pend[i]))) return rc; any = 1; } np = 0; } while (0)
    while (c) {
        if (++n > fs->nclusters) return SZOU_E_STATE;
        for (s = 0; s < fs->spc; s++) {
            uint64_t lba = clus_lba(fs, c) + s;
            if (dev_rd(fs, lba, 1, fs->dbuf)) return SZOU_E_IO;
            for (o = 0; o < fs->bps; o += 32) {
                const uint8_t *e = fs->dbuf + o;
                loc_t here;
                here.lba = lba; here.off = o;
                if (e[0] == 0x00) { ORPHAN_PEND(); return any ? dev_flush(fs) : 0; }
                if (e[0] == 0xE5) { ORPHAN_PEND(); continue; }
                if ((e[11] & 0x3F) == A_LFN) {
                    uint32_t ord = e[0] & 0x3Fu;
                    if (e[0] & 0x40) {
                        ORPHAN_PEND();
                        if (ord < 1 || ord > LFN_MAX) { if ((rc = slot_mark_free(fs, here))) return rc; any = 1; continue; }
                        pend[np++] = here; rem = ord - 1; sum = e[13];
                    } else if (np && rem && ord == rem && e[13] == sum) {
                        pend[np++] = here; rem--;
                    } else {
                        ORPHAN_PEND();
                        if ((rc = slot_mark_free(fs, here))) return rc;
                        any = 1;
                    }
                    continue;
                }
                if (np && (rem || (e[11] & A_VOL) || lfn_sum(e) != sum)) ORPHAN_PEND();
                np = 0;
            }
        }
        if ((rc = chain_next(fs, c, &c))) return rc;
    }
    ORPHAN_PEND();
#undef ORPHAN_PEND
    return any ? dev_flush(fs) : 0;
}
/* n consecutive free slots; entries at/after the first 0x00 are free. */
static int dir_run(szou_fat32_t *fs, uint32_t dir, uint32_t n, loc_t *run)
{
    uint32_t c = dir, cn = 0, s, o, got = 0, last = dir, nc;
    int end = 0, rc;
    while (c) {
        if (++cn > fs->nclusters) return SZOU_E_STATE;
        for (s = 0; s < fs->spc; s++) {
            uint64_t lba = clus_lba(fs, c) + s;
            if (!end && dev_rd(fs, lba, 1, fs->dbuf)) return SZOU_E_IO;
            for (o = 0; o < fs->bps; o += 32) {
                if (!end && fs->dbuf[o] == 0x00) end = 1;
                if (end || fs->dbuf[o] == 0xE5) {
                    run[got].lba = lba; run[got].off = o;
                    if (++got == n) return 0;
                } else got = 0;
            }
        }
        last = c;
        if ((rc = chain_next(fs, c, &c))) return rc;
    }
    while (got < n) {                                  /* extend with zeroed clusters */
        if ((rc = alloc_scan(fs, 1, &nc))) return rc;
        if ((rc = zero_cluster(fs, nc, 0)) || (rc = dev_flush(fs))) return rc;
        if ((rc = fat_put(fs, nc, EOC)) || (rc = fat_put(fs, last, nc))) return rc;
        fs->free_count--;
        if ((rc = fat_sync(fs)) || (rc = dev_flush(fs))) return rc;
        for (s = 0; s < fs->spc && got < n; s++)
            for (o = 0; o < fs->bps && got < n; o += 32) { run[got].lba = clus_lba(fs, nc) + s; run[got].off = o; got++; }
        last = nc;
    }
    return 0;
}
/* Publish LFN chain (if units) + the given short entry in directory dir. */
static int publish(szou_fat32_t *fs, uint32_t dir, const uint16_t *ln, uint32_t units, const uint8_t *short32)
{
    uint8_t ents[(LFN_MAX + 1) * 32];
    loc_t run[LFN_MAX + 1];
    uint32_t n = units ? (units + 12) / 13 : 0, j, i;
    int rc;
    if (n > LFN_MAX) return SZOU_E_ARG;
    if ((rc = dir_scrub(fs, dir)) || (rc = dir_run(fs, dir, n + 1, run))) return rc;
    for (j = 0; j < n; j++) lfn_make(ents + 32 * j, ln, units, n - j, j == 0, lfn_sum(short32));
    memcpy(ents + 32 * n, short32, 32);
    for (i = 0; i <= n;) {
        uint64_t lba = run[i].lba;
        if (dev_rd(fs, lba, 1, fs->sec)) return SZOU_E_IO;
        for (j = i; j <= n && run[j].lba == lba; j++) memcpy(fs->sec + run[j].off, ents + 32 * j, 32);
        if (dev_wr(fs, lba, 1, fs->sec)) return SZOU_E_IO;
        if (dev_flush(fs)) return SZOU_E_IO;           /* LFN sectors durable before the short entry's */
        i = j;
    }
    return 0;
}
/* Long name of a found entry: valid chain bound to its short entry, else 0 units. */
static int lfn_read(szou_fat32_t *fs, const found_t *f, uint16_t *out, uint32_t *units)
{
    uint8_t sum = lfn_sum(f->ent);
    uint32_t ord = 1, k, total = 0;
    int j, done = 0;
    *units = 0;
    for (j = (int)f->nlfn - 1; j >= 0 && !done; j--, ord++) {
        uint8_t e[32];
        if (dev_rd(fs, f->lfn[j].lba, 1, fs->sec)) return SZOU_E_IO;
        memcpy(e, fs->sec + f->lfn[j].off, 32);
        if ((e[0] & 0x3Fu) != ord || e[13] != sum || e[11] != A_LFN || fx_rd16(e + 26)) return 0;
        for (k = 0; k < 13; k++) {
            uint16_t u = fx_rd16(e + lfn_pos[k]);
            if (total == (ord - 1) * 13 + k && u && !(total > 0 && out[total - 1] == 0)) {
                if (total >= SZLN_NAME_UNITS) return 0;
                out[total++] = u;
            }
        }
        if (e[0] & 0x40) done = 1;
    }
    if (!done) return 0;
    *units = total;
    return 0;
}
static int name_matches(szou_fat32_t *fs, const found_t *f, const uint16_t *ln, uint32_t units)
{
    uint16_t got[SZLN_NAME_UNITS + 1];
    uint32_t n, i;
    int rc = lfn_read(fs, f, got, &n);
    if (rc) return rc;
    if (n != units) return 0;
    for (i = 0; i < n; i++) if (got[i] != ln[i]) return 0;
    return 1;
}

static int s_mkdir_named(void *c, const char *path, const uint16_t *ln, uint16_t units, uint32_t attr)
{
    szou_fat32_t *fs = c;
    uint32_t parent, nc;
    uint8_t name[11], dots[64], e[32];
    found_t f;
    int rc;
    if (fs->writer_open) return SZOU_E_STATE;
    if (attr & ~SZOU_ATTR_ALLOWED) return SZOU_E_ATTR;
    if (units > SZLN_NAME_UNITS || (units && !ln)) return SZOU_E_ARG;
    rc = lookup(fs, path, &parent, name, &f);
    if (rc == 0) {
        if (!(f.ent[11] & A_DIR)) return SZOU_E_CONFLICT;
        if ((rc = name_matches(fs, &f, ln, units)) <= 0) return rc < 0 ? rc : SZOU_E_CONFLICT;
        if ((f.ent[11] & SZOU_ATTR_ALLOWED) != attr) {
            f.ent[11] = (uint8_t)(A_DIR | attr);
            if ((rc = ent_write(fs, f.at, f.ent)) || (rc = dev_flush(fs))) return rc;
        }
        return SZOU_E_EXISTS;
    }
    if (rc != SZOU_ABSENT) return rc;
    if ((rc = resolve(fs, path, &parent, name))) return rc == SZOU_ABSENT ? SZOU_E_IO : rc;
    if ((rc = alloc_scan(fs, 1, &nc))) return rc;
    make_ent(fs, dots, (const uint8_t *)".          ", A_DIR, nc, 0);
    make_ent(fs, dots + 32, (const uint8_t *)"..         ", A_DIR, parent == fs->root ? 0 : parent, 0);
    if ((rc = zero_cluster(fs, nc, dots)) || (rc = dev_flush(fs))) return rc;
    if ((rc = fat_put(fs, nc, EOC))) return rc;
    fs->free_count--;
    if ((rc = fat_sync(fs)) || (rc = dev_flush(fs))) return rc;
    make_ent(fs, e, name, (uint8_t)(A_DIR | attr), nc, 0);
    return publish(fs, parent, ln, units, e);
}

/* Rename/replace a file; the destination is published with its LFN chain.
 * Existing destination with the same long name: one-sector in-place replace.
 * Existing destination with a different/stale long name: destination entry
 * (short first, then LFN) and its old chain are removed, then published anew;
 * the staged source keeps the content, so a crash in between is rerun. */
static int s_rename_named(void *c, const char *from, const char *to, const uint16_t *ln, uint16_t units)
{
    szou_fat32_t *fs = c;
    uint32_t sp, dp, old = 0;
    uint8_t sn[11], dn[11], e[32];
    found_t sf, df;
    int rc;
    if (fs->writer_open) return SZOU_E_STATE;
    if (units > SZLN_NAME_UNITS || (units && !ln)) return SZOU_E_ARG;
    if ((rc = lookup(fs, from, &sp, sn, &sf))) return rc == SZOU_ABSENT ? SZOU_E_IO : rc;
    if (sf.ent[11] & A_DIR) return SZOU_E_UNSUPPORTED;
    rc = lookup(fs, to, &dp, dn, &df);
    if (rc == 0) {
        if (df.ent[11] & A_DIR) return SZOU_E_CONFLICT;
        if (sp == dp && df.at.lba == sf.at.lba && df.at.off == sf.at.off) return 0;
        old = ent_clus(df.ent);
        if ((rc = name_matches(fs, &df, ln, units)) < 0) return rc;
        if (rc == 1) {
            memcpy(e, sf.ent, 32); memcpy(e, dn, 11);
            if ((rc = ent_write(fs, df.at, e)) || (rc = dev_flush(fs))) return rc;   /* replace point */
            goto drop_source;
        }
        if ((rc = ent_delete(fs, &df)) || (rc = dev_flush(fs))) return rc;
        if (old && old != ent_clus(sf.ent) && (rc = chain_free(fs, old))) return rc;
        old = 0;
    } else if (rc != SZOU_ABSENT) return rc;
    if ((rc = resolve(fs, to, &dp, dn))) return rc == SZOU_ABSENT ? SZOU_E_IO : rc;
    memcpy(e, sf.ent, 32); memcpy(e, dn, 11);
    if ((rc = publish(fs, dp, ln, units, e))) return rc;
drop_source:
    if ((rc = dir_walk(fs, sp, 0, sn, &sf, 0))) return rc == SZOU_ABSENT ? SZOU_E_STATE : rc;
    if ((rc = ent_delete(fs, &sf)) || (rc = dev_flush(fs))) return rc;
    if (old && old != ent_clus(sf.ent)) return chain_free(fs, old);
    return 0;
}

int szou_fat32_long_name(szou_fat32_t *fs, const char *path, uint16_t out[SZLN_NAME_UNITS + 1], uint32_t *units)
{
    uint32_t parent;
    uint8_t name[11];
    found_t f;
    int rc;
    if (!fs || !fs->mounted || !path || !out || !units) return SZOU_E_ARG;
    if ((rc = lookup(fs, path, &parent, name, &f))) return rc;
    return lfn_read(fs, &f, out, units);
}

void szou_fat32_sink(szou_fat32_t *fs, szou_sink_ops_t *o)
{
    memset(o, 0, sizeof *o);
    if (!fs || !fs->mounted) return;                 /* unmounted: all NULL -> SZOU_E_NO_AUTHORITY */
    o->ctx = fs; o->alloc = s_alloc; o->free = s_free; o->mkdir = s_mkdir; o->rmdir = s_rmdir;
    o->create = s_create; o->open = s_open; o->read = s_read; o->write = s_write; o->close = s_close;
    o->rename_replace = s_rename; o->remove = s_remove; o->set_attr = s_set_attr; o->flush = s_flush;
    o->mkdir_named = s_mkdir_named; o->rename_named = s_rename_named;
}

int szou_fat32_mount(szou_fat32_t *fs, const szou_blkdev_t *dev,
                     void *(*alloc)(void *, size_t), void (*free_fn)(void *, void *), void *mctx,
                     uint16_t dos_date, uint16_t dos_time)
{
    uint8_t *b;
    uint32_t total, i, v;
    uint64_t data_sec, meta;
    int rc;
    if (!fs || !dev || !dev->read || !dev->write || !dev->flush || !alloc || !free_fn || !dev->max_io_sectors)
        return SZOU_E_ARG;
    memset(fs, 0, sizeof *fs);
    fs->dev = *dev; fs->alloc = alloc; fs->free = free_fn; fs->mctx = mctx;
    fs->dos_date = dos_date ? dos_date : 0x0021; fs->dos_time = dos_time;
    if (dev->sector_size < 512 || dev->sector_size > SZOU_FAT32_MAX_SECTOR || (dev->sector_size & (dev->sector_size - 1)))
        return SZOU_E_UNSUPPORTED;
    fs->bps = dev->sector_size;
    b = fs->sec;
    if (dev_rd(fs, 0, 1, b)) return SZOU_E_IO;
    if (b[510] != 0x55 || b[511] != 0xAA || (b[0] != 0xEB && b[0] != 0xE9)) return SZOU_E_STATE;
    if (fx_rd16(b + 11) != fs->bps) return SZOU_E_UNSUPPORTED;
    fs->spc = b[13];
    if (!fs->spc || (fs->spc & (fs->spc - 1)) || (uint64_t)fs->spc * fs->bps > 65536u) return SZOU_E_UNSUPPORTED;
    fs->cb = fs->spc * fs->bps;
    fs->reserved = fx_rd16(b + 14);
    fs->nfats = b[16];
    if (!fs->reserved || fs->nfats < 1 || fs->nfats > 4) return SZOU_E_STATE;
    /* FAT12/16 have root entries, 16-bit totals/FAT size, or too few clusters. */
    if (fx_rd16(b + 17) || fx_rd16(b + 22) || fx_rd16(b + 19)) return SZOU_E_UNSUPPORTED;
    fs->fatsz = fx_rd32(b + 36);
    total = fx_rd32(b + 32);
    if (!fs->fatsz || !total || total > dev->sectors) return SZOU_E_STATE;
    if (fx_rd16(b + 40) & 0x80) return SZOU_E_UNSUPPORTED;      /* non-mirrored FAT */
    if (fx_rd16(b + 42) != 0) return SZOU_E_UNSUPPORTED;
    fs->root = fx_rd32(b + 44);
    fs->fsinfo = fx_rd16(b + 48);
    if (fs->fsinfo == 0xFFFF) fs->fsinfo = 0;
    meta = (uint64_t)fs->reserved + (uint64_t)fs->nfats * fs->fatsz;
    if (meta >= total) return SZOU_E_STATE;
    data_sec = total - meta;
    fs->nclusters = (uint32_t)(data_sec / fs->spc);
    if (fs->nclusters < 65525u) return SZOU_E_UNSUPPORTED;   /* not FAT32 by definition */
    if ((uint64_t)fs->fatsz * fs->bps / 4 < (uint64_t)fs->nclusters + 2 || fs->nclusters > 0x0FFFFFF5u) return SZOU_E_STATE;
    fs->data_lba = meta;
    fs->dev.sectors = total;
    if (!valid_clus(fs, fs->root)) return SZOU_E_STATE;
    if (fs->fsinfo) {
        if (fs->fsinfo >= fs->reserved) return SZOU_E_STATE;
        if (dev_rd(fs, fs->fsinfo, 1, b)) return SZOU_E_IO;
        if (fx_rd32(b) != 0x41615252u || fx_rd32(b + 484) != 0x61417272u || fx_rd32(b + 508) != 0xAA550000u) return SZOU_E_STATE;
        fs->next_free = fx_rd32(b + 492);
    }
    for (i = 2; i <= fs->nclusters + 1; i++) {              /* actual free count from the FAT */
        if ((rc = fat_get(fs, i, &v))) return rc;
        if (v == 0) fs->free_count++;
    }
    if ((rc = fat_get(fs, fs->root, &v))) return rc;
    if (v == 0) return SZOU_E_STATE;
    fs->mounted = 1;
    return 0;
}

int szou_fat32_unmount(szou_fat32_t *fs)
{
    int rc;
    if (!fs || !fs->mounted) return SZOU_E_ARG;
    if (fs->writer_open) return SZOU_E_STATE;
    rc = s_flush(fs);
    fs->mounted = 0;
    return rc;
}

/* ---- plat binding ---- */
static int pb_guard(szou_plat_blk_t *pb) { return pb->guard ? pb->guard(pb->gctx) : 0; }
static int pb_read(void *c, uint64_t lba, uint32_t n, void *buf)
{
    szou_plat_blk_t *pb = c;
    if (lba >= pb->sectors || n > pb->sectors - lba || pb_guard(pb)) return -1;
    if (pb->p->disk_read(pb->p->ctx, pb->index, pb->first_lba + lba, n, buf)) return -1;
    return pb_guard(pb);
}
static int pb_write(void *c, uint64_t lba, uint32_t n, const void *buf)
{
    szou_plat_blk_t *pb = c;
    if (lba >= pb->sectors || n > pb->sectors - lba || pb_guard(pb)) return -1;
    if (pb->p->disk_write(pb->p->ctx, pb->index, pb->first_lba + lba, n, buf)) return -1;
    return pb_guard(pb);
}
static int pb_flush(void *c)
{
    szou_plat_blk_t *pb = c;
    if (pb_guard(pb) || pb->p->disk_flush(pb->p->ctx, pb->index)) return -1;
    return pb_guard(pb);
}
int szou_blk_from_plat(szou_plat_blk_t *pb, szou_blkdev_t *out, uint32_t sector_size, uint32_t max_io_sectors)
{
    if (!pb || !out || !pb->p || !pb->p->disk_read || !pb->p->disk_write || !pb->p->disk_flush ||
        !pb->sectors || pb->first_lba > UINT64_MAX - pb->sectors || !max_io_sectors)
        return SZOU_E_NO_AUTHORITY;
    memset(out, 0, sizeof *out);
    out->ctx = pb; out->sector_size = sector_size; out->sectors = pb->sectors;
    out->max_io_sectors = max_io_sectors;
    out->read = pb_read; out->write = pb_write; out->flush = pb_flush;
    return 0;
}
