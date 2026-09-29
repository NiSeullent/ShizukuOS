/* SPDX-License-Identifier: GPL-2.0-only
 * sfsfuzz: corrupted-metadata robustness test for libsfs (built with ASan/UBSan).
 *
 *   sfsfuzz IMAGE METABLOCKS ITERATIONS SEED
 *
 * IMAGE is a pristine ext4 volume, METABLOCKS a text file listing its metadata block numbers (superblock, GDT,
 * bitmaps, inode tables, directory and extent-tree blocks, journal; produced from `e2image -r`). Every iteration
 * copies the image in memory, corrupts 1-3 metadata blocks (bit flips, random bytes, 16/32-bit fields forced to
 * extreme values, zeroed or 0xFF-filled blocks, swapped blocks), then mounts it (read-only or read-write), walks
 * the whole tree (readdir, stat, full reads, readlink), and on read-write mounts performs updates (create, write,
 * mkdir, rename, truncate, unlink) and unmounts. The library must never crash, trip a sanitizer, leak or hang
 * (a 20 s watchdog aborts the iteration); returning errors is expected.
 */
#define _GNU_SOURCE
#include "../libsfs/sfs.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct memdev { uint8_t *img; uint64_t size; int64_t live; uint64_t writes; } memdev;

static int m_read(void *c, uint64_t off, void *buf, uint32_t n)
{
    memdev *d = c;
    if (off > d->size || n > d->size - off) return -1;
    memcpy(buf, d->img + off, n);
    return 0;
}

static int m_write(void *c, uint64_t off, const void *buf, uint32_t n)
{
    memdev *d = c;
    if (off > d->size || n > d->size - off) return -1;
    memcpy(d->img + off, buf, n);
    d->writes++;
    return 0;
}

static int m_flush(void *c) { (void)c; return 0; }
static void *m_alloc(void *c, size_t n) { memdev *d = c; void *p = calloc(1, n); if (p) d->live += (int64_t)n; return p; }
static void m_free(void *c, void *p, size_t n) { memdev *d = c; d->live -= (int64_t)n; free(p); }
static uint64_t m_now(void *c) { (void)c; return 1700000000u; }

static uint64_t rng_state;
static uint64_t rnd(void) { rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17; return rng_state; }

static uint64_t cur_iter, cur_seed;
static void on_alarm(int sig)
{
    (void)sig;
    fprintf(stderr, "HANG: iteration %llu (seed %llu) exceeded the watchdog\n", (unsigned long long)cur_iter, (unsigned long long)cur_seed);
    abort();
}

typedef struct stats { uint64_t mount_fail, mount_ro, mount_rw, walk_err, entries, bytes, updates_ok, updates_err, unmount_err; } stats;

static void walk(sfs_fs *fs, uint32_t dir, int depth, stats *st, uint8_t *buf)
{
    uint64_t cookie = 0;
    sfs_dirent de;
    int rc, guard = 0;
    if (depth > 20) return;
    while ((rc = sfs_readdir(fs, dir, &cookie, &de)) == 1 && guard++ < 20000) {
        sfs_stat_t s;
        st->entries++;
        if (!strcmp(de.name, ".") || !strcmp(de.name, "..")) continue;
        if (sfs_stat(fs, de.ino, &s)) { st->walk_err++; continue; }
        if ((s.mode & SFS_S_IFMT) == SFS_S_IFDIR) {
            uint32_t ino;
            walk(fs, de.ino, depth + 1, st, buf);
            if (sfs_lookup(fs, dir, de.name, de.name_len, &ino, 0)) st->walk_err++;
        } else if ((s.mode & SFS_S_IFMT) == SFS_S_IFLNK) {
            size_t n;
            if (sfs_readlink(fs, de.ino, (char *)buf, 4096, &n)) st->walk_err++;
        } else {
            uint64_t off = 0, done;
            /* read the head and the tail (sparse multi-GiB files would take too long) */
            while (off < s.size && off < (8u << 20)) {
                if (sfs_read(fs, de.ino, off, buf, 1 << 20, &done) || !done) { st->walk_err++; break; }
                st->bytes += done;
                off += done;
            }
            if (s.size > (8u << 20) && sfs_read(fs, de.ino, s.size - 4096, buf, 4096, &done)) st->walk_err++;
        }
    }
    if (rc < 0) st->walk_err++;
}

static void updates(sfs_fs *fs, stats *st, uint8_t *buf)
{
    uint32_t ino, d;
    uint64_t done;
    int rc;
    memset(buf, 0x5A, 1 << 20);
#define U(x) do { rc = (x); if (rc) st->updates_err++; else st->updates_ok++; } while (0)
    U(sfs_mkdir(fs, SFS_ROOT_INO, "fz_dir", 6, 0755, &d));
    if (rc) d = SFS_ROOT_INO;
    U(sfs_create(fs, d, "fz_file", 7, 0644, &ino));
    if (!rc) {
        U(sfs_write(fs, ino, 0, buf, 300000, &done));
        U(sfs_write(fs, ino, 5000000, buf, 70000, &done));
        U(sfs_truncate(fs, ino, 100));
        U(sfs_rename(fs, d, "fz_file", 7, SFS_ROOT_INO, "fz_moved", 8, 1));
        U(sfs_unlink(fs, SFS_ROOT_INO, "fz_moved", 8));
    }
    {
        /* also touch existing entries: delete/rename whatever the root holds */
        uint64_t cookie = 0;
        sfs_dirent de;
        int n = 0;
        while (sfs_readdir(fs, SFS_ROOT_INO, &cookie, &de) == 1 && n < 6) {
            if (de.name[0] == '.' || !strcmp(de.name, "lost+found") || !strncmp(de.name, "fz_", 3)) continue;
            n++;
            if (de.type == SFS_FT_DIR) U(sfs_rename(fs, SFS_ROOT_INO, de.name, de.name_len, SFS_ROOT_INO, "fz_rn", 5, 1));
            else U(sfs_unlink(fs, SFS_ROOT_INO, de.name, de.name_len));
            break;
        }
    }
    U(sfs_sync(fs));
#undef U
}

int main(int argc, char **argv)
{
    FILE *f;
    uint8_t *pristine, *buf;
    uint64_t size, *meta = 0, nmeta = 0, cap = 0, iters, i, blk;
    uint32_t bs = 4096;
    stats st;
    if (argc < 5) { fprintf(stderr, "usage: sfsfuzz IMAGE METABLOCKS ITERATIONS SEED\n"); return 2; }
    f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 1; }
    fseek(f, 0, SEEK_END);
    size = (uint64_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    pristine = malloc(size);
    if (fread(pristine, 1, size, f) != size) { perror("read"); return 1; }
    fclose(f);
    bs = 1024u << (pristine[1024 + 0x18] | pristine[1024 + 0x19] << 8);
    f = fopen(argv[2], "r");
    if (!f) { perror(argv[2]); return 1; }
    while (fscanf(f, "%llu", (unsigned long long *)&blk) == 1) {
        if ((blk + 1) * bs > size) continue;
        if (nmeta == cap) { cap = cap ? cap * 2 : 1024; meta = realloc(meta, cap * sizeof *meta); }
        meta[nmeta++] = blk;
    }
    fclose(f);
    if (!nmeta) { fprintf(stderr, "no metadata blocks\n"); return 1; }
    iters = strtoull(argv[3], 0, 0);
    rng_state = strtoull(argv[4], 0, 0) * 0x9E3779B97F4A7C15ull + 1;
    buf = malloc(1 << 20);
    memset(&st, 0, sizeof st);
    signal(SIGALRM, on_alarm);
    for (i = 0; i < iters; ++i) {
        memdev d;
        sfs_ops ops;
        sfs_fs *fs;
        int nb = 1 + (int)(rnd() % 3), k, rc, rw = (int)(rnd() % 2);
        cur_iter = i;
        cur_seed = rng_state;
        d.img = malloc(size);
        memcpy(d.img, pristine, size);
        d.size = size;
        d.live = 0;
        d.writes = 0;
        for (k = 0; k < nb; ++k) {
            uint64_t b = meta[rnd() % nmeta];
            uint8_t *p = d.img + b * bs;
            uint32_t mode = (uint32_t)(rnd() % 8), n, j;
            if (b == 0 && bs > 1024 && rnd() % 2) p += 1024;          /* aim at the superblock half of block 0 */
            switch (mode) {
            case 0: case 1:                                           /* bit flips */
                n = 1 + (uint32_t)(rnd() % 8);
                for (j = 0; j < n; ++j) { uint32_t o = (uint32_t)(rnd() % bs); p[o] ^= (uint8_t)(1u << (rnd() % 8)); }
                break;
            case 2:                                                   /* random bytes */
                n = 1 + (uint32_t)(rnd() % 32);
                for (j = 0; j < n; ++j) p[rnd() % bs] = (uint8_t)rnd();
                break;
            case 3: case 4: {                                         /* a 16/32-bit field forced to an extreme */
                static const uint32_t ext[] = {0, 1, 0x7FFFFFFFu, 0xFFFFFFFFu, 0x8000u, 0xFFFFu, 12, 0xF30Au};
                uint32_t o = (uint32_t)(rnd() % (bs - 4)) & ~1u, v = ext[rnd() % 8];
                if (mode == 3) { p[o] = (uint8_t)v; p[o + 1] = (uint8_t)(v >> 8); }
                else { o &= ~3u; p[o] = (uint8_t)v; p[o + 1] = (uint8_t)(v >> 8); p[o + 2] = (uint8_t)(v >> 16); p[o + 3] = (uint8_t)(v >> 24); }
                break;
            }
            case 5: memset(p, 0, bs); break;
            case 6: memset(p, 0xFF, bs); break;
            default: {                                                /* copy another metadata block over it */
                uint64_t o = meta[rnd() % nmeta];
                memmove(p, d.img + o * bs, bs);
                break;
            }
            }
        }
        memset(&ops, 0, sizeof ops);
        ops.ctx = &d;
        ops.read = m_read;
        ops.write = m_write;
        ops.flush = m_flush;
        ops.alloc = m_alloc;
        ops.free = m_free;
        ops.now = m_now;
        ops.size = size;
        ops.cache_blocks = 256;
        alarm(20);
        rc = sfs_mount(&ops, rw ? 0 : SFS_MOUNT_RDONLY, &fs);
        if (rc) {
            st.mount_fail++;
        } else {
            if (sfs_is_readonly(fs)) st.mount_ro++; else st.mount_rw++;
            walk(fs, SFS_ROOT_INO, 0, &st, buf);
            if (!sfs_is_readonly(fs)) updates(fs, &st, buf);
            if (sfs_unmount(fs)) st.unmount_err++;
        }
        alarm(0);
        if (d.live) {
            fprintf(stderr, "LEAK: iteration %llu leaked %lld bytes\n", (unsigned long long)i, (long long)d.live);
            return 3;
        }
        free(d.img);
        if ((i + 1) % 500 == 0) fprintf(stderr, "  %llu iterations...\n", (unsigned long long)(i + 1));
    }
    printf("sfsfuzz: %llu iterations over %llu metadata blocks: mount refused %llu, mounted ro %llu, rw %llu; "
           "entries walked %llu, bytes read %llu, walk errors %llu; updates ok %llu, failed %llu; unmount errors %llu\n",
           (unsigned long long)iters, (unsigned long long)nmeta, (unsigned long long)st.mount_fail, (unsigned long long)st.mount_ro,
           (unsigned long long)st.mount_rw, (unsigned long long)st.entries, (unsigned long long)st.bytes,
           (unsigned long long)st.walk_err, (unsigned long long)st.updates_ok, (unsigned long long)st.updates_err,
           (unsigned long long)st.unmount_err);
    free(buf);
    free(pristine);
    free(meta);
    return 0;
}
