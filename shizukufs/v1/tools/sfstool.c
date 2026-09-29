/* SPDX-License-Identifier: GPL-2.0-only
 * sfstool: host front end for libsfs (ShizukuFS v1 = the ext4 format).
 *
 *   sfstool [options] IMAGE COMMAND [ARGS...]
 *     info | ls PATH | tree [PATH] | cat PATH | get PATH HOSTFILE | stat PATH | readlink PATH
 *     put HOSTFILE PATH | pattern PATH OFFSET LENGTH SEED | mkdir PATH | rm PATH | rmdir PATH | mv OLD NEW
 *     mvx OLD NEW (no replace) | truncate PATH SIZE | symlink TARGET PATH | sync | stats
 *     batch            (commands from stdin, one per line, one mount)
 *     crashload LOG SEED ROUNDS   /  crashverify LOG SEED   (crash-consistency workload, see below)
 *   options: -r read-only, -c N cache blocks, -N naive (no optimisations), -F fsync on flush, -q quiet,
 *            -V volatile write cache, -K N crash after N device writes (with -V: power cut), -S seed for the cut
 *
 * `tree` prints "type mode size links sha256-or-target path" for every entry below PATH (files hashed), the form
 * the test scripts compare against the host directory and against debugfs.
 */
#define _GNU_SOURCE
#include "sfs_host.h"
#include "sha256.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

static sfs_fs *g_fs;
static host_dev g_dev;
static int g_quiet, g_times;

static int fail(const char *what, int rc)
{
    fprintf(stderr, "%s: %s (%d)\n", what, sfs_strerror(rc), rc);
    return 1;
}

static int resolve(const char *path, uint32_t *ino)
{
    return sfs_path_lookup(g_fs, path, ino, 0, 0, 0);
}

static int resolve_parent(const char *path, uint32_t *dir, const char **leaf, size_t *len)
{
    uint32_t ino, parent = 0;
    int rc = sfs_path_lookup(g_fs, path, &ino, &parent, leaf, len);
    if (rc == 0 || (rc == SFS_ENOENT && parent)) { *dir = parent; return 0; }
    return rc;
}

/* deterministic content: xorshift stream per (seed, offset) */
static uint64_t mix(uint64_t x) { x ^= x >> 33; x *= 0xff51afd7ed558ccdull; x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ull; x ^= x >> 33; return x; }
static void pattern_fill(uint8_t *buf, uint64_t off, size_t len, uint64_t seed)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        uint64_t pos = off + i;
        buf[i] = (uint8_t)(mix(seed * 0x9E3779B97F4A7C15ull + (pos >> 3)) >> ((pos & 7) * 8));
    }
}

static int write_pattern(uint32_t ino, uint64_t off, uint64_t len, uint64_t seed)
{
    size_t chunk = 1 << 20;
    uint8_t *buf = malloc(chunk);
    int rc = 0;
    while (len && !rc) {
        size_t n = len < chunk ? (size_t)len : chunk;
        uint64_t done;
        pattern_fill(buf, off, n, seed);
        rc = sfs_write(g_fs, ino, off, buf, n, &done);
        if (!rc && done != n) rc = SFS_ENOSPC;
        off += n;
        len -= n;
    }
    free(buf);
    return rc;
}

/* Content fingerprint used by the tests: SHA-256 over (le64 offset || block) for every 4 KiB block that is not
 * all zero, then le64 size. Equal for equal contents, and cheap for large sparse files on both sides. */
static int hash_file(uint32_t ino, uint64_t size, char hex[65])
{
    sha256_ctx c;
    uint8_t d[32], le[8];
    size_t chunk = 1 << 20;
    uint8_t *buf = malloc(chunk);
    static const uint8_t zero[4096];
    uint64_t off = 0;
    int rc = 0, i;
    sha256_init(&c);
    while (off < size) {
        uint64_t done, b;
        size_t n = size - off < chunk ? (size_t)(size - off) : chunk;
        rc = sfs_read(g_fs, ino, off, buf, n, &done);
        if (rc) break;
        if (done != n) { rc = SFS_EIO; break; }
        for (b = 0; b < n; b += 4096) {
            size_t k = n - b < 4096 ? n - b : 4096;
            if (!memcmp(buf + b, zero, k)) continue;
            for (i = 0; i < 8; ++i) le[i] = (uint8_t)((off + b) >> (8 * i));
            sha256_update(&c, le, 8);
            sha256_update(&c, buf + b, k);
        }
        off += n;
    }
    for (i = 0; i < 8; ++i) le[i] = (uint8_t)(size >> (8 * i));
    sha256_update(&c, le, 8);
    free(buf);
    sha256_final(&c, d);
    sha256_hex(d, hex);
    return rc;
}

static int tree_walk(uint32_t dir, const char *prefix, int depth)
{
    uint64_t cookie = 0;
    sfs_dirent de;
    int rc;
    if (depth > 64) return SFS_ECORRUPT;
    while ((rc = sfs_readdir(g_fs, dir, &cookie, &de)) == 1) {
        sfs_stat_t st;
        char path[4096];
        if (!strcmp(de.name, ".") || !strcmp(de.name, "..")) continue;
        snprintf(path, sizeof path, "%s/%s", prefix, de.name);
        rc = sfs_stat(g_fs, de.ino, &st);
        if (rc) { fprintf(stderr, "stat %s: %s\n", path, sfs_strerror(rc)); return rc; }
        if ((st.mode & SFS_S_IFMT) == SFS_S_IFDIR) {
            printf("d %04o 0 %u - %s\n", st.mode & 07777, st.links, path);
            rc = tree_walk(de.ino, path, depth + 1);
            if (rc) return rc;
        } else if ((st.mode & SFS_S_IFMT) == SFS_S_IFREG) {
            char hex[65];
            rc = hash_file(de.ino, st.size, hex);
            if (rc) { fprintf(stderr, "read %s: %s\n", path, sfs_strerror(rc)); return rc; }
            if (g_times) printf("f %04o %llu %u %s @%lld %s\n", st.mode & 07777, (unsigned long long)st.size, st.links, hex, (long long)st.mtime, path);
            else printf("f %04o %llu %u %s %s\n", st.mode & 07777, (unsigned long long)st.size, st.links, hex, path);
        } else if ((st.mode & SFS_S_IFMT) == SFS_S_IFLNK) {
            char t[4097];
            size_t n;
            rc = sfs_readlink(g_fs, de.ino, t, sizeof t - 1, &n);
            if (rc) { fprintf(stderr, "readlink %s: %s\n", path, sfs_strerror(rc)); return rc; }
            t[n] = 0;
            printf("l %04o %llu %u %s %s\n", st.mode & 07777, (unsigned long long)st.size, st.links, t, path);
        } else {
            printf("o %04o 0 %u - %s\n", st.mode & 07777, st.links, path);
        }
    }
    return rc < 0 ? rc : 0;
}

/* ================= crash workload ================= */
/* A deterministic sequence of rounds of updates (create/append/overwrite/truncate/delete/rename/mkdir/rmdir),
 * sfs_sync() after every round, logged. The verifier replays the same sequence in memory. */
#define CW_MAXF 4096
typedef struct cw_file { char path[64]; uint8_t *data; uint64_t size; int live; int is_dir; int touched_round; } cw_file;
typedef struct cw { cw_file f[CW_MAXF]; int n; uint64_t rng; uint64_t total; int next_name; } cw;

static uint64_t cw_rand(cw *w) { w->rng ^= w->rng << 13; w->rng ^= w->rng >> 7; w->rng ^= w->rng << 17; return w->rng; }
static int cw_pick(cw *w, int dirs)
{
    int tries;
    for (tries = 0; tries < 64; ++tries) {
        int i = (int)(cw_rand(w) % (uint64_t)(w->n ? w->n : 1));
        if (i < w->n && w->f[i].live && w->f[i].is_dir == dirs && (dirs ? strncmp(w->f[i].path, "/e", 2) == 0 : 1)) return i;
    }
    return -1;
}

typedef int (*cw_apply)(void *ctx, int kind, cw_file *a, cw_file *b, uint64_t off, uint64_t len, uint64_t seed);

enum { OP_CREATE, OP_APPEND, OP_OVERWRITE, OP_TRUNC, OP_DELETE, OP_RENAME, OP_MKDIR, OP_RMDIR };

static uint64_t cw_size(cw *w)
{
    uint64_t r = cw_rand(w) % 100;
    if (r < 10) return 0;
    if (r < 60) return 1 + cw_rand(w) % 8192;
    if (r < 95) return 8192 + cw_rand(w) % (256 * 1024);
    return (1 << 20) + cw_rand(w) % (3 << 20);
}

static void cw_setsize(cw_file *f, uint64_t size)
{
    f->data = realloc(f->data, size ? size : 1);
    if (size > f->size) memset(f->data + f->size, 0, size - f->size);
    f->size = size;
}

/* One round: applies ops to the model and (through `fn`) to the file system. Returns 0 or the first error. */
static int cw_round(cw *w, int round, cw_apply fn, void *ctx)
{
    int nops = 4 + (int)(cw_rand(w) % 12), k, rc = 0;
    for (k = 0; k < nops && !rc; ++k) {
        uint64_t r = cw_rand(w) % 100, seed = cw_rand(w);
        int i, j;
        if (w->total > (48u << 20)) r = 60;            /* keep the model small: delete */
        if (r < 30 || w->n < 4) {
            if (w->n >= CW_MAXF) continue;
            i = w->n++;
            memset(&w->f[i], 0, sizeof w->f[i]);
            snprintf(w->f[i].path, sizeof w->f[i].path, "/d%d/f%05d", (int)(seed % 4), w->next_name++);
            w->f[i].live = 1;
            w->f[i].touched_round = round;
            {
                uint64_t size = cw_size(w);
                cw_setsize(&w->f[i], size);
                pattern_fill(w->f[i].data, 0, size, seed);
                w->total += size;
                rc = fn(ctx, OP_CREATE, &w->f[i], 0, 0, size, seed);
            }
        } else if (r < 42) {
            i = cw_pick(w, 0);
            if (i < 0) continue;
            {
                uint64_t add = cw_size(w) / 2 + 1, old = w->f[i].size;
                cw_setsize(&w->f[i], old + add);
                pattern_fill(w->f[i].data + old, old, add, seed);
                w->total += add;
                w->f[i].touched_round = round;
                rc = fn(ctx, OP_APPEND, &w->f[i], 0, old, add, seed);
            }
        } else if (r < 52) {
            i = cw_pick(w, 0);
            if (i < 0 || !w->f[i].size) continue;
            {
                uint64_t off = cw_rand(w) % w->f[i].size, len = 1 + cw_rand(w) % 20000;
                if (off + len > w->f[i].size) { w->total += off + len - w->f[i].size; cw_setsize(&w->f[i], off + len); }
                pattern_fill(w->f[i].data + off, off, len, seed);
                w->f[i].touched_round = round;
                rc = fn(ctx, OP_OVERWRITE, &w->f[i], 0, off, len, seed);
            }
        } else if (r < 60) {
            i = cw_pick(w, 0);
            if (i < 0) continue;
            {
                uint64_t ns = w->f[i].size ? cw_rand(w) % (w->f[i].size * 2 + 1) : cw_rand(w) % 100000;
                if (ns > w->f[i].size) w->total += ns - w->f[i].size; else w->total -= w->f[i].size - ns;
                cw_setsize(&w->f[i], ns);
                w->f[i].touched_round = round;
                rc = fn(ctx, OP_TRUNC, &w->f[i], 0, ns, 0, 0);
            }
        } else if (r < 78) {
            i = cw_pick(w, 0);
            if (i < 0) continue;
            w->f[i].live = 0;
            w->total -= w->f[i].size;
            w->f[i].touched_round = round;
            rc = fn(ctx, OP_DELETE, &w->f[i], 0, 0, 0, 0);
        } else if (r < 92) {
            i = cw_pick(w, 0);
            if (i < 0 || w->n >= CW_MAXF) continue;
            j = cw_pick(w, 0);
            if (j >= 0 && j != i && (seed & 1)) {
                /* rename over an existing file */
                cw_file *t = &w->f[j];
                w->total -= t->size;
                free(t->data);
                t->data = w->f[i].data;
                t->size = w->f[i].size;
                t->touched_round = round;
                w->f[i].data = 0;
                w->f[i].live = 0;
                w->f[i].touched_round = round;
                rc = fn(ctx, OP_RENAME, &w->f[i], t, 0, 0, 0);
            } else {
                int n2 = w->n++;
                memset(&w->f[n2], 0, sizeof w->f[n2]);
                snprintf(w->f[n2].path, sizeof w->f[n2].path, "/d%d/r%05d", (int)(seed % 4), w->next_name++);
                w->f[n2].live = 1;
                w->f[n2].data = w->f[i].data;
                w->f[n2].size = w->f[i].size;
                w->f[n2].touched_round = round;
                w->f[i].data = 0;
                w->f[i].live = 0;
                w->f[i].touched_round = round;
                rc = fn(ctx, OP_RENAME, &w->f[i], &w->f[n2], 0, 0, 0);
            }
        } else if (r < 96) {
            if (w->n >= CW_MAXF) continue;
            i = w->n++;
            memset(&w->f[i], 0, sizeof w->f[i]);
            snprintf(w->f[i].path, sizeof w->f[i].path, "/e%05d", w->next_name++);
            w->f[i].live = 1;
            w->f[i].is_dir = 1;
            w->f[i].touched_round = round;
            rc = fn(ctx, OP_MKDIR, &w->f[i], 0, 0, 0, 0);
        } else {
            i = cw_pick(w, 1);
            if (i < 0) continue;
            w->f[i].live = 0;
            w->f[i].touched_round = round;
            rc = fn(ctx, OP_RMDIR, &w->f[i], 0, 0, 0, 0);
        }
    }
    return rc;
}

static int fs_apply(void *ctx, int kind, cw_file *a, cw_file *b, uint64_t off, uint64_t len, uint64_t seed)
{
    uint32_t dir, ino;
    const char *leaf;
    size_t ll;
    int rc;
    (void)ctx;
    switch (kind) {
    case OP_CREATE:
        rc = resolve_parent(a->path, &dir, &leaf, &ll);
        if (!rc) rc = sfs_create(g_fs, dir, leaf, ll, 0644, &ino);
        if (!rc && len) rc = write_pattern(ino, 0, len, seed);
        return rc;
    case OP_APPEND:
    case OP_OVERWRITE:
        rc = resolve(a->path, &ino);
        if (!rc) rc = write_pattern(ino, off, len, seed);
        return rc;
    case OP_TRUNC:
        rc = resolve(a->path, &ino);
        if (!rc) rc = sfs_truncate(g_fs, ino, off);
        return rc;
    case OP_DELETE:
        rc = resolve_parent(a->path, &dir, &leaf, &ll);
        if (!rc) rc = sfs_unlink(g_fs, dir, leaf, ll);
        return rc;
    case OP_RENAME: {
        uint32_t d2;
        const char *l2;
        size_t n2;
        rc = resolve_parent(a->path, &dir, &leaf, &ll);
        if (!rc) rc = resolve_parent(b->path, &d2, &l2, &n2);
        if (!rc) rc = sfs_rename(g_fs, dir, leaf, ll, d2, l2, n2, 1);
        return rc;
    }
    case OP_MKDIR:
        rc = resolve_parent(a->path, &dir, &leaf, &ll);
        if (!rc) rc = sfs_mkdir(g_fs, dir, leaf, ll, 0755, &ino);
        return rc;
    case OP_RMDIR:
        rc = resolve_parent(a->path, &dir, &leaf, &ll);
        if (!rc) rc = sfs_rmdir(g_fs, dir, leaf, ll);
        return rc;
    }
    return SFS_EINVAL;
}

static int nop_apply(void *ctx, int kind, cw_file *a, cw_file *b, uint64_t off, uint64_t len, uint64_t seed)
{
    (void)ctx; (void)kind; (void)a; (void)b; (void)off; (void)len; (void)seed;
    return 0;
}

static int print_apply(void *ctx, int kind, cw_file *a, cw_file *b, uint64_t off, uint64_t len, uint64_t seed)
{
    static const char *const names[] = {"create", "append", "overwrite", "trunc", "delete", "rename", "mkdir", "rmdir"};
    (void)ctx; (void)seed;
    printf("  %-9s %s%s%s off %llu len %llu (size now %llu)\n", names[kind], a->path, b ? " -> " : "", b ? b->path : "",
           (unsigned long long)off, (unsigned long long)len, (unsigned long long)(b ? b->size : a->size));
    return 0;
}

static cw *cw_new(uint64_t seed)
{
    cw *w = calloc(1, sizeof *w);
    w->rng = seed * 2654435761u + 88172645463325252ull;
    return w;
}

static void cw_free(cw *w)
{
    int i;
    for (i = 0; i < w->n; ++i) free(w->f[i].data);
    free(w);
}

static int cmd_crashload(const char *logpath, uint64_t seed, int rounds)
{
    cw *w = cw_new(seed);
    int fd = open(logpath, O_WRONLY | O_CREAT | O_APPEND, 0644), r, rc = 0;
    uint32_t ino;
    const char *dirs[4] = {"d0", "d1", "d2", "d3"};
    if (fd < 0) { perror(logpath); return 1; }
    for (r = 0; r < 4 && !rc; ++r) {
        rc = sfs_mkdir(g_fs, SFS_ROOT_INO, dirs[r], 2, 0755, &ino);
        if (rc == SFS_EEXIST) rc = 0;
    }
    if (!rc) rc = sfs_sync(g_fs);
    if (!rc) dprintf(fd, "START\n");
    for (r = 0; (rounds <= 0 || r < rounds) && !rc; ++r) {
        rc = cw_round(w, r, fs_apply, 0);
        if (rc) { fail("crashload op", rc); break; }
        rc = sfs_sync(g_fs);
        if (rc) { fail("crashload sync", rc); break; }
        dprintf(fd, "SYNC %d\n", r);
        fsync(fd);
    }
    close(fd);
    cw_free(w);
    return rc ? 1 : 0;
}

/* Verifies the volume against the model: entries untouched since the last logged sync must be exact; entries
 * touched afterwards may hold any state of their history, but every block must be one of their versions or zero. */
static int read_all(uint32_t ino, uint64_t size, uint8_t **out)
{
    uint8_t *buf = malloc(size ? size : 1);
    uint64_t done;
    int rc = sfs_read(g_fs, ino, 0, buf, size, &done);
    if (!rc && done != size) rc = SFS_EIO;
    *out = buf;
    return rc;
}

typedef struct ver { char path[64]; uint8_t *data; uint64_t size; int deleted; } ver;
typedef struct snap_ctx { ver *vs; int nv; } snap_ctx;

static void snap_one(snap_ctx *sc, cw_file *f)
{
    ver *v;
    if (sc->nv >= 65536) return;
    v = &sc->vs[sc->nv++];
    memcpy(v->path, f->path, 64);
    v->size = f->size;
    v->deleted = !f->live;
    v->data = f->live && !f->is_dir ? malloc(f->size ? f->size : 1) : 0;
    if (v->data && f->size) memcpy(v->data, f->data, f->size);
}

static int snap_apply(void *ctx, int kind, cw_file *a, cw_file *b, uint64_t off, uint64_t len, uint64_t seed)
{
    (void)kind; (void)off; (void)len; (void)seed;
    snap_one(ctx, a);
    if (b) snap_one(ctx, b);
    return 0;
}

static int cmd_crashverify(const char *logpath, uint64_t seed)
{
    FILE *lf = fopen(logpath, "r");
    char line[128];
    int last = -1, r, i, errors = 0, checked_exact = 0, checked_loose = 0;
    cw *w, *hist;
    if (!lf) { perror(logpath); return 1; }
    while (fgets(line, sizeof line, lf)) { int k; if (sscanf(line, "SYNC %d", &k) == 1) last = k; }
    fclose(lf);
    w = cw_new(seed);
    for (r = 0; r <= last; ++r) cw_round(w, r, nop_apply, 0);
    /* candidate versions: the next two rounds (the crash may follow an unlogged sync) */
    hist = cw_new(seed);
    for (r = 0; r <= last; ++r) cw_round(hist, r, nop_apply, 0);
    {
        /* every state each path passes through after the last logged sync (per operation, so intermediate states
         * inside a round count too) */
        snap_ctx sc;
        int rr;
        ver *vs;
        int nv;
        sc.vs = calloc(65536, sizeof *sc.vs);
        sc.nv = 0;
        for (rr = last + 1; rr <= last + 2; ++rr) cw_round(hist, rr, snap_apply, &sc);
        vs = sc.vs;
        nv = sc.nv;
        for (i = 0; i < w->n; ++i) {
            cw_file *f = &w->f[i];
            int touched = 0, k;
            uint32_t ino;
            int rc;
            for (k = 0; k < nv; ++k) if (!strcmp(vs[k].path, f->path)) touched = 1;
            rc = resolve(f->path, &ino);
            if (!touched) {
                if (!f->live) {
                    if (rc == 0) { fprintf(stderr, "VERIFY: %s exists but was deleted before the sync\n", f->path); errors++; }
                    continue;
                }
                if (rc) { fprintf(stderr, "VERIFY: synced %s missing: %s\n", f->path, sfs_strerror(rc)); errors++; continue; }
                if (!f->is_dir) {
                    sfs_stat_t st;
                    uint8_t *data;
                    sfs_stat(g_fs, ino, &st);
                    if (st.size != f->size) { fprintf(stderr, "VERIFY: synced %s size %llu expected %llu\n", f->path, (unsigned long long)st.size, (unsigned long long)f->size); errors++; continue; }
                    rc = read_all(ino, st.size, &data);
                    if (rc || (st.size && memcmp(data, f->data, st.size))) { fprintf(stderr, "VERIFY: synced %s content differs\n", f->path); errors++; }
                    free(data);
                }
                checked_exact++;
            } else if (rc == 0 && !f->is_dir) {
                /* touched later: every block must match some version (synced, later) or be zero */
                sfs_stat_t st;
                uint8_t *data;
                uint64_t b;
                sfs_stat(g_fs, ino, &st);
                rc = read_all(ino, st.size, &data);
                if (rc) { fprintf(stderr, "VERIFY: read %s: %s\n", f->path, sfs_strerror(rc)); errors++; free(data); continue; }
                /* granularity = the volume's block: each block is an independent device write */
                const uint64_t vbs = sfs_block_size(g_fs);
                for (b = 0; b < st.size; b += vbs) {
                    uint64_t n = st.size - b < vbs ? st.size - b : vbs, z;
                    int ok = 0;
                    if (f->live && b + n <= f->size && !memcmp(data + b, f->data + b, n)) ok = 1;
                    for (k = 0; k < nv && !ok; ++k)
                        if (vs[k].data && !strcmp(vs[k].path, f->path) && b + n <= vs[k].size && !memcmp(data + b, vs[k].data + b, n)) ok = 1;
                    for (z = 0; z < n && !ok && !data[b + z]; ++z) {}
                    if (!ok && z == n) ok = 1;
                    if (!ok) {
                        /* a rename moved content under this name: accept any version of any path */
                        for (k = 0; k < nv && !ok; ++k)
                            if (vs[k].data && b + n <= vs[k].size && !memcmp(data + b, vs[k].data + b, n)) ok = 1;
                        for (k = 0; k < w->n && !ok; ++k)
                            if (w->f[k].live && w->f[k].data && b + n <= w->f[k].size && !memcmp(data + b, w->f[k].data + b, n)) ok = 1;
                    }
                    if (!ok) { fprintf(stderr, "VERIFY: %s block %llu holds data from no version\n", f->path, (unsigned long long)(b / vbs)); errors++; break; }
                }
                free(data);
                checked_loose++;
            }
        }
        for (i = 0; i < nv; ++i) free(vs[i].data);
        free(vs);
    }
    printf("crashverify: last sync %d, exact %d, touched-after-sync %d, errors %d\n", last, checked_exact, checked_loose, errors);
    cw_free(w);
    cw_free(hist);
    return errors ? 2 : 0;
}

/* ================= commands ================= */
static int run_cmd(int argc, char **argv);

static int cmd_batch(void)
{
    char line[8192];
    int rc = 0, lineno = 0;
    while (fgets(line, sizeof line, stdin)) {
        char *args[16];
        int n = 0;
        char *p = line;
        lineno++;
        while (*p && n < 16) {
            while (*p == ' ' || *p == '\t' || *p == '\n') *p++ = 0;
            if (!*p) break;
            args[n++] = p;
            while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        }
        if (!n || args[0][0] == '#') continue;
        rc = run_cmd(n, args);
        if (rc) { fprintf(stderr, "batch line %d failed\n", lineno); return rc; }
    }
    return 0;
}

static int run_cmd(int argc, char **argv)
{
    const char *c = argv[0];
    uint32_t ino, dir;
    const char *leaf;
    size_t ll;
    int rc;
    if (!strcmp(c, "info")) {
        sfs_statfs_t s;
        sfs_statfs(g_fs, &s);
        printf("block_size %u blocks %llu free_blocks %llu inodes %u free_inodes %u groups %u\n", s.block_size,
               (unsigned long long)s.blocks, (unsigned long long)s.free_blocks, s.inodes, s.free_inodes, s.groups);
        printf("compat 0x%x incompat 0x%x ro_compat 0x%x journal 0x%x read_only %d ro_reason 0x%x label '%s'\n",
               s.feature_compat, s.feature_incompat, s.feature_ro_compat, s.journal_features, s.read_only, s.ro_reason, s.label);
        return 0;
    }
    if (!strcmp(c, "stats")) {
        sfs_stats s;
        sfs_get_stats(g_fs, &s);
        printf("reads %llu read_bytes %llu writes %llu write_bytes %llu flushes %llu\n", (unsigned long long)s.reads,
               (unsigned long long)s.read_bytes, (unsigned long long)s.writes, (unsigned long long)s.write_bytes, (unsigned long long)s.flushes);
        printf("cache_hits %llu cache_misses %llu evictions %llu commits %llu journal_blocks %llu checkpoint_blocks %llu\n",
               (unsigned long long)s.cache_hits, (unsigned long long)s.cache_misses, (unsigned long long)s.cache_evictions,
               (unsigned long long)s.commits, (unsigned long long)s.journal_blocks_written, (unsigned long long)s.checkpoint_blocks);
        printf("extent_cache_hits %llu misses %llu dx_lookups %llu linear_lookups %llu replayed_tx %llu replayed_blocks %llu revoked %llu\n",
               (unsigned long long)s.extent_cache_hits, (unsigned long long)s.extent_cache_misses, (unsigned long long)s.dx_lookups,
               (unsigned long long)s.linear_lookups, (unsigned long long)s.replayed_transactions, (unsigned long long)s.replayed_blocks,
               (unsigned long long)s.revoked_blocks);
        return 0;
    }
    if (!strcmp(c, "sync")) { rc = sfs_sync(g_fs); return rc ? fail("sync", rc) : 0; }
    if (!strcmp(c, "ondisk")) {
        /* on-disk state; "ondisk clean" also requires the cleanly-unmounted state. Invariant: a non-empty
         * journal is only allowed while needs_recovery is set. */
        int nr, valid;
        uint32_t js;
        rc = sfs_ondisk_state(g_fs, &nr, &valid, &js);
        if (rc) return fail("ondisk", rc);
        printf("ondisk needs_recovery %d valid_fs %d journal_start %u\n", nr, valid, js);
        if (js && !nr) { fprintf(stderr, "INVARIANT VIOLATED: journal has data but needs_recovery is clear\n"); return 1; }
        if (argc > 1 && !strcmp(argv[1], "clean") && (nr || js || !valid)) { fprintf(stderr, "volume not clean\n"); return 1; }
        return 0;
    }
    if (!strcmp(c, "batch")) return cmd_batch();
    if (!strcmp(c, "tree")) {
        rc = resolve(argc > 1 ? argv[1] : "/", &ino);
        if (!rc) rc = tree_walk(ino, argc > 1 && strcmp(argv[1], "/") ? argv[1] : "", 0);
        return rc ? fail("tree", rc) : 0;
    }
    if (argc < 2) { fprintf(stderr, "%s: missing argument\n", c); return 2; }
    if (!strcmp(c, "ls")) {
        uint64_t cookie = 0;
        sfs_dirent de;
        rc = resolve(argv[1], &ino);
        if (!rc)
            while ((rc = sfs_readdir(g_fs, ino, &cookie, &de)) == 1) printf("%u %u %s\n", de.ino, de.type, de.name);
        return rc < 0 ? fail("ls", rc) : 0;
    }
    if (!strcmp(c, "stat")) {
        sfs_stat_t st;
        rc = resolve(argv[1], &ino);
        if (!rc) rc = sfs_stat(g_fs, ino, &st);
        if (rc) return fail("stat", rc);
        printf("ino %u mode %o links %u uid %u gid %u size %llu blocks %llu flags 0x%x mtime %lld.%09u ctime %lld atime %lld crtime %lld\n",
               st.ino, st.mode, st.links, st.uid, st.gid, (unsigned long long)st.size, (unsigned long long)st.blocks, st.flags,
               (long long)st.mtime, st.mtime_ns, (long long)st.ctime, (long long)st.atime, (long long)st.crtime);
        return 0;
    }
    if (!strcmp(c, "readlink")) {
        char t[4097];
        size_t n;
        rc = resolve(argv[1], &ino);
        if (!rc) rc = sfs_readlink(g_fs, ino, t, sizeof t - 1, &n);
        if (rc) return fail("readlink", rc);
        t[n] = 0;
        printf("%s\n", t);
        return 0;
    }
    if (!strcmp(c, "cat") || (!strcmp(c, "get") && argc > 2)) {
        sfs_stat_t st;
        FILE *out = stdout;
        uint8_t *buf = malloc(1 << 20);
        uint64_t off = 0;
        rc = resolve(argv[1], &ino);
        if (!rc) rc = sfs_stat(g_fs, ino, &st);
        if (!rc && !strcmp(c, "get")) { out = fopen(argv[2], "wb"); if (!out) { perror(argv[2]); free(buf); return 1; } }
        while (!rc && off < st.size) {
            uint64_t done;
            rc = sfs_read(g_fs, ino, off, buf, 1 << 20, &done);
            if (!rc && !done) break;
            fwrite(buf, 1, (size_t)done, out);
            off += done;
        }
        if (out != stdout) fclose(out);
        free(buf);
        return rc ? fail(c, rc) : 0;
    }
    if (!strcmp(c, "mkdir")) {
        rc = resolve_parent(argv[1], &dir, &leaf, &ll);
        if (!rc) rc = sfs_mkdir(g_fs, dir, leaf, ll, 0755, &ino);
        return rc ? fail("mkdir", rc) : 0;
    }
    if (!strcmp(c, "rm") || !strcmp(c, "rmdir")) {
        rc = resolve_parent(argv[1], &dir, &leaf, &ll);
        if (!rc) rc = !strcmp(c, "rm") ? sfs_unlink(g_fs, dir, leaf, ll) : sfs_rmdir(g_fs, dir, leaf, ll);
        return rc ? fail(c, rc) : 0;
    }
    if (argc < 3) { fprintf(stderr, "%s: missing argument\n", c); return 2; }
    if (!strcmp(c, "put")) {
        int fd = open(argv[1], O_RDONLY);
        uint8_t *buf;
        uint64_t off = 0;
        ssize_t n;
        if (fd < 0) { perror(argv[1]); return 1; }
        rc = resolve(argv[2], &ino);
        if (rc == SFS_ENOENT) {
            rc = resolve_parent(argv[2], &dir, &leaf, &ll);
            if (!rc) rc = sfs_create(g_fs, dir, leaf, ll, 0644, &ino);
        } else if (!rc) {
            rc = sfs_truncate(g_fs, ino, 0);
        }
        buf = malloc(1 << 20);
        while (!rc && (n = read(fd, buf, 1 << 20)) > 0) {
            uint64_t done;
            rc = sfs_write(g_fs, ino, off, buf, (uint64_t)n, &done);
            if (!rc && done != (uint64_t)n) rc = SFS_ENOSPC;
            off += (uint64_t)n;
        }
        free(buf);
        close(fd);
        return rc ? fail("put", rc) : 0;
    }
    if (!strcmp(c, "mv") || !strcmp(c, "mvx")) {
        uint32_t d2;
        const char *l2;
        size_t n2;
        rc = resolve_parent(argv[1], &dir, &leaf, &ll);
        if (!rc) rc = resolve_parent(argv[2], &d2, &l2, &n2);
        if (!rc) rc = sfs_rename(g_fs, dir, leaf, ll, d2, l2, n2, !strcmp(c, "mv"));
        return rc ? fail(c, rc) : 0;
    }
    if (!strcmp(c, "truncate")) {
        rc = resolve(argv[1], &ino);
        if (!rc) rc = sfs_truncate(g_fs, ino, strtoull(argv[2], 0, 0));
        return rc ? fail("truncate", rc) : 0;
    }
    if (!strcmp(c, "symlink")) {
        rc = resolve_parent(argv[2], &dir, &leaf, &ll);
        if (!rc) rc = sfs_symlink(g_fs, dir, leaf, ll, argv[1], strlen(argv[1]), &ino);
        return rc ? fail("symlink", rc) : 0;
    }
    if (!strcmp(c, "settime")) {
        int64_t t = strtoll(argv[2], 0, 0);
        rc = resolve(argv[1], &ino);
        if (!rc) rc = sfs_set_times(g_fs, ino, &t, &t);
        return rc ? fail("settime", rc) : 0;
    }
    if (!strcmp(c, "crashverify")) return cmd_crashverify(argv[1], strtoull(argv[2], 0, 0));
    if (!strcmp(c, "crashtrace")) {                       /* the model's ops of rounds FROM..TO */
        cw *w = cw_new(strtoull(argv[1], 0, 0));
        int r, from = atoi(argv[2]), to = argc > 3 ? atoi(argv[3]) : from;
        for (r = 0; r <= to; ++r) {
            if (r >= from) printf("round %d\n", r);
            cw_round(w, r, r >= from ? print_apply : nop_apply, 0);
        }
        cw_free(w);
        return 0;
    }
    if (argc < 4) { fprintf(stderr, "%s: missing argument\n", c); return 2; }
    if (!strcmp(c, "crashload")) return cmd_crashload(argv[1], strtoull(argv[2], 0, 0), atoi(argv[3]));
    if (!strcmp(c, "putat")) {
        int fd = open(argv[1], O_RDONLY);
        uint8_t *buf;
        uint64_t off = strtoull(argv[3], 0, 0);
        ssize_t n;
        if (fd < 0) { perror(argv[1]); return 1; }
        rc = resolve(argv[2], &ino);
        if (rc == SFS_ENOENT) {
            rc = resolve_parent(argv[2], &dir, &leaf, &ll);
            if (!rc) rc = sfs_create(g_fs, dir, leaf, ll, 0644, &ino);
        }
        buf = malloc(1 << 20);
        while (!rc && (n = read(fd, buf, 1 << 20)) > 0) {
            uint64_t done;
            rc = sfs_write(g_fs, ino, off, buf, (uint64_t)n, &done);
            if (!rc && done != (uint64_t)n) rc = SFS_ENOSPC;
            off += (uint64_t)n;
        }
        free(buf);
        close(fd);
        return rc ? fail("putat", rc) : 0;
    }
    if (!strcmp(c, "pattern") && argc >= 5) {
        rc = resolve(argv[1], &ino);
        if (rc == SFS_ENOENT) {
            rc = resolve_parent(argv[1], &dir, &leaf, &ll);
            if (!rc) rc = sfs_create(g_fs, dir, leaf, ll, 0644, &ino);
        }
        if (!rc) rc = write_pattern(ino, strtoull(argv[2], 0, 0), strtoull(argv[3], 0, 0), strtoull(argv[4], 0, 0));
        return rc ? fail("pattern", rc) : 0;
    }
    fprintf(stderr, "unknown command %s\n", c);
    return 2;
}

int main(int argc, char **argv)
{
    int opt, ro = 0, rc, rc2;
    unsigned flags = 0;
    uint32_t cache = 4096;
    sfs_ops ops;
    uint64_t cut = 0;
    uint32_t cut_seed = 1;
    int volatile_cache = 0, do_fsync = 0;
    while ((opt = getopt(argc, argv, "rc:NFqVK:S:TCs")) != -1) {
        switch (opt) {
        case 's': flags |= SFS_MOUNT_SMALL_TXN; break;
        case 'C': flags |= SFS_MOUNT_CLEAN_ON_SYNC; break;
        case 'T': g_times = 1; break;
        case 'r': ro = 1; break;
        case 'c': cache = (uint32_t)strtoul(optarg, 0, 0); break;
        case 'N': flags |= SFS_MOUNT_NAIVE; break;
        case 'F': do_fsync = 1; break;
        case 'q': g_quiet = 1; break;
        case 'V': volatile_cache = 1; break;
        case 'K': cut = strtoull(optarg, 0, 0); break;
        case 'S': cut_seed = (uint32_t)strtoul(optarg, 0, 0); break;
        default: return 2;
        }
    }
    if (argc - optind < 2) {
        fprintf(stderr, "usage: sfstool [-r] [-c blocks] [-N] [-F] [-q] [-V] [-K n] [-S seed] IMAGE COMMAND [ARGS]\n");
        return 2;
    }
    if (host_open(&g_dev, argv[optind], !ro)) { perror(argv[optind]); return 1; }
    g_dev.quiet = g_quiet;
    g_dev.do_fsync = do_fsync;
    g_dev.volatile_cache = volatile_cache;
    g_dev.cut_after = cut;
    g_dev.cut_seed = cut_seed;
    host_ops(&g_dev, &ops, cache);
    if (ro) flags |= SFS_MOUNT_RDONLY;
    rc = sfs_mount(&ops, flags, &g_fs);
    if (rc) { fail("mount", rc); host_close(&g_dev); return 1; }
    rc = run_cmd(argc - optind - 1, argv + optind + 1);
    rc2 = sfs_unmount(g_fs);
    if (rc2) { fail("unmount", rc2); rc = rc ? rc : 1; }
    if (g_dev.live_objs || g_dev.live_bytes) {
        fprintf(stderr, "LEAK: %lld objects, %lld bytes still allocated after unmount\n", (long long)g_dev.live_objs, (long long)g_dev.live_bytes);
        rc = rc ? rc : 3;
    }
    if (volatile_cache) {
        rc2 = ops.flush(ops.ctx);
        (void)rc2;
    }
    host_close(&g_dev);
    return rc;
}
