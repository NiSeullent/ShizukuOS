/* SPDX-License-Identifier: GPL-2.0-only
 * sfsperf: ShizukuFS v1 performance harness.
 *
 *   sfsperf [-N] [-F] [-s MiB] [-n files] IMAGE
 *
 * On a freshly made ext4 image (run_perf.py makes it with mkfs.ext4): 1) sequential write of a large file in
 * 1 MiB requests + sync, 2) sequential read of it after a remount (cold libsfs caches), 3) creation of many small
 * (1 KiB) files spread over directories + sync, 4) random lookups (path resolution + stat) after a remount and
 * again warm, 5) deletion of all small files + sync. -N mounts with SFS_MOUNT_NAIVE (the baseline without the
 * optimisations: no direct extent-sized I/O, no extent cache, tiny block/inode caches, no preallocation windows,
 * no htree creation); -F makes every flush an fdatasync. Prints one line per phase with rates and device I/O.
 */
#define _GNU_SOURCE
#include "../tools/sfs_host.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static host_dev dev;
static sfs_ops ops;
static unsigned mflags;

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static sfs_fs *mnt(void)
{
    sfs_fs *fs;
    int rc = sfs_mount(&ops, mflags, &fs);
    if (rc) { fprintf(stderr, "mount: %s\n", sfs_strerror(rc)); exit(1); }
    return fs;
}

static void umnt(sfs_fs *fs)
{
    int rc = sfs_unmount(fs);
    if (rc) { fprintf(stderr, "unmount: %s\n", sfs_strerror(rc)); exit(1); }
}

static void report(const char *phase, double secs, double units, const char *unit, sfs_stats *a, sfs_stats *b)
{
    printf("%-28s %8.2f s  %12.1f %-8s  dev_writes %8llu (%7.1f MiB)  dev_reads %8llu (%7.1f MiB)  flushes %6llu  commits %6llu\n",
           phase, secs, units / secs, unit, (unsigned long long)(b->writes - a->writes), (double)(b->write_bytes - a->write_bytes) / 1048576.0,
           (unsigned long long)(b->reads - a->reads), (double)(b->read_bytes - a->read_bytes) / 1048576.0,
           (unsigned long long)(b->flushes - a->flushes), (unsigned long long)(b->commits - a->commits));
    fflush(stdout);
}

static void die(const char *what, int rc)
{
    fprintf(stderr, "%s: %s\n", what, sfs_strerror(rc));
    exit(1);
}

int main(int argc, char **argv)
{
    int opt, rc;
    uint64_t big_mib = 1024, nfiles = 100000, i, done;
    uint32_t ndirs = 10, ino, dirs[64];
    uint8_t *buf;
    sfs_fs *fs;
    sfs_stats a, b;
    double t0;
    while ((opt = getopt(argc, argv, "NFs:n:")) != -1) {
        if (opt == 'N') mflags |= SFS_MOUNT_NAIVE;
        else if (opt == 'F') dev.do_fsync = 1;
        else if (opt == 's') big_mib = strtoull(optarg, 0, 0);
        else if (opt == 'n') nfiles = strtoull(optarg, 0, 0);
        else return 2;
    }
    if (optind >= argc) { fprintf(stderr, "usage: sfsperf [-N] [-F] [-s MiB] [-n files] IMAGE\n"); return 2; }
    {
        int fsync_flag = dev.do_fsync;
        if (host_open(&dev, argv[optind], 1)) { perror(argv[optind]); return 1; }
        dev.do_fsync = fsync_flag;
        dev.quiet = 1;
    }
    host_ops(&dev, &ops, 8192);
    buf = malloc(1 << 20);
    for (i = 0; i < (1 << 20); ++i) buf[i] = (uint8_t)(i * 2654435761u >> 13);
    printf("mode: %s%s\n", (mflags & SFS_MOUNT_NAIVE) ? "naive baseline" : "optimised", dev.do_fsync ? ", fdatasync on flush" : "");

    /* 1. sequential write */
    fs = mnt();
    rc = sfs_create(fs, SFS_ROOT_INO, "seq.bin", 7, 0644, &ino);
    if (rc) die("create", rc);
    sfs_get_stats(fs, &a);
    t0 = now_s();
    for (i = 0; i < big_mib; ++i) {
        buf[0] = (uint8_t)i;
        rc = sfs_write(fs, ino, i << 20, buf, 1 << 20, &done);
        if (rc || done != (1u << 20)) die("write", rc ? rc : SFS_ENOSPC);
    }
    rc = sfs_sync(fs);
    if (rc) die("sync", rc);
    sfs_get_stats(fs, &b);
    report("sequential write + sync", now_s() - t0, (double)big_mib, "MiB/s", &a, &b);
    umnt(fs);

    /* 2. sequential read, cold library caches */
    fs = mnt();
    sfs_get_stats(fs, &a);
    t0 = now_s();
    for (i = 0; i < big_mib; ++i) {
        rc = sfs_read(fs, ino, i << 20, buf, 1 << 20, &done);
        if (rc || done != (1u << 20) || buf[0] != (uint8_t)i) die("read/verify", rc ? rc : SFS_EIO);
    }
    sfs_get_stats(fs, &b);
    report("sequential read (cold)", now_s() - t0, (double)big_mib, "MiB/s", &a, &b);
    {
        sfs_stat_t st;
        sfs_stat(fs, ino, &st);
        printf("  seq.bin: %llu bytes, %llu blocks allocated\n", (unsigned long long)st.size, (unsigned long long)st.blocks / 8);
    }
    umnt(fs);

    /* 3. small files */
    fs = mnt();
    if (nfiles / ndirs > 20000) ndirs = (uint32_t)(nfiles / 20000 + 1);
    if (ndirs > 64) ndirs = 64;
    for (i = 0; i < ndirs; ++i) {
        char n[16];
        int len = snprintf(n, sizeof n, "dir%02u", (unsigned)i);
        rc = sfs_mkdir(fs, SFS_ROOT_INO, n, (size_t)len, 0755, &dirs[i]);
        if (rc) die("mkdir", rc);
    }
    sfs_get_stats(fs, &a);
    t0 = now_s();
    for (i = 0; i < nfiles; ++i) {
        char n[32];
        int len = snprintf(n, sizeof n, "file-%07llu.dat", (unsigned long long)i);
        rc = sfs_create(fs, dirs[i % ndirs], n, (size_t)len, 0644, &ino);
        if (rc) die("create small", rc);
        rc = sfs_write(fs, ino, 0, buf, 1024, &done);
        if (rc) die("write small", rc);
    }
    rc = sfs_sync(fs);
    if (rc) die("sync", rc);
    sfs_get_stats(fs, &b);
    report("create+write 1 KiB files", now_s() - t0, (double)nfiles, "files/s", &a, &b);
    umnt(fs);

    /* 4. lookups: cold then warm */
    fs = mnt();
    {
        int pass;
        for (pass = 0; pass < 2; ++pass) {
            uint64_t x = 12345;
            sfs_get_stats(fs, &a);
            t0 = now_s();
            for (i = 0; i < nfiles; ++i) {
                char path[64];
                uint64_t k;
                sfs_stat_t st;
                x ^= x << 13; x ^= x >> 7; x ^= x << 17;
                k = x % nfiles;
                snprintf(path, sizeof path, "/dir%02u/file-%07llu.dat", (unsigned)(k % ndirs), (unsigned long long)k);
                rc = sfs_path_lookup(fs, path, &ino, 0, 0, 0);
                if (!rc) rc = sfs_stat(fs, ino, &st);
                if (rc || st.size != 1024) die("lookup", rc ? rc : SFS_ECORRUPT);
            }
            sfs_get_stats(fs, &b);
            report(pass ? "random lookup+stat (warm)" : "random lookup+stat (cold)", now_s() - t0, (double)nfiles, "ops/s", &a, &b);
        }
        printf("  htree lookups %llu, linear lookups %llu\n", (unsigned long long)b.dx_lookups, (unsigned long long)b.linear_lookups);
    }
    umnt(fs);

    /* 5. delete everything */
    fs = mnt();
    sfs_get_stats(fs, &a);
    t0 = now_s();
    for (i = 0; i < nfiles; ++i) {
        char n[32];
        int len = snprintf(n, sizeof n, "file-%07llu.dat", (unsigned long long)i);
        rc = sfs_unlink(fs, dirs[i % ndirs], n, (size_t)len);
        if (rc) die("unlink", rc);
    }
    rc = sfs_unlink(fs, SFS_ROOT_INO, "seq.bin", 7);
    if (!rc) rc = sfs_sync(fs);
    if (rc) die("unlink/sync", rc);
    sfs_get_stats(fs, &b);
    report("unlink all + sync", now_s() - t0, (double)(nfiles + 1), "files/s", &a, &b);
    umnt(fs);
    free(buf);
    if (dev.live_objs) { fprintf(stderr, "LEAK: %lld objects\n", (long long)dev.live_objs); return 3; }
    host_close(&dev);
    return 0;
}
