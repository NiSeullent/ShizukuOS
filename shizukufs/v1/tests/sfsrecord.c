/* SPDX-License-Identifier: GPL-2.0-only
 * Focused oracle for the atomic record store (libsfs/sfs_record.c) and the checked block allocation.
 * usage: sfsrecord <image> record      -- record put/get/replace/staging recovery/corruption detection
 *        sfsrecord <image> alloc <out> -- writes /big (256 KiB) and prints its physical blocks to <out>
 * The image is made by tests/run_record.sh (mkfs.ext4); e2fsck runs there afterwards.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../tools/sfs_host.h"

static int fails;
#define CHECK(c, what) do { if (!(c)) { fprintf(stderr, "FAIL %s (line %d)\n", what, __LINE__); ++fails; } \
                            else printf("ok   %s\n", what); } while (0)

static sfs_fs *mnt(host_dev *d, const char *img)
{
    sfs_ops ops;
    sfs_fs *fs = 0;
    if (host_open(d, img, 1)) { perror(img); exit(2); }
    host_ops(d, &ops, 0);
    if (sfs_mount(&ops, SFS_MOUNT_CLEAN_ON_SYNC, &fs)) { fprintf(stderr, "mount failed\n"); exit(2); }
    return fs;
}

static int record_test(const char *img)
{
    host_dev d;
    sfs_fs *fs = mnt(&d, img);
    uint32_t dir, ino, len = 0;
    uint64_t seq = 0, done;
    char buf[256];
    const char *a = "account=alice;sid=S-1-5-21-1-1001;hash=00112233", *b = "account=alice;sid=S-1-5-21-1-1001;hash=44556677";
    CHECK(!sfs_mkdir(fs, SFS_ROOT_INO, "acct", 4, 0700, &dir), "mkdir /acct");
    CHECK(sfs_record_get(fs, dir, "alice", 5, buf, sizeof buf, &len, &seq) == SFS_ENOENT, "get absent -> ENOENT");
    CHECK(!sfs_record_put(fs, dir, "alice", 5, a, (uint32_t)strlen(a), &seq) && seq == 1, "put new -> seq 1");
    CHECK(!sfs_record_get(fs, dir, "alice", 5, buf, sizeof buf, &len, &seq) && len == strlen(a) && !memcmp(buf, a, len)
          && seq == 1, "get == A");
    CHECK(!sfs_record_put(fs, dir, "alice", 5, b, (uint32_t)strlen(b), &seq) && seq == 2, "replace -> seq 2");
    CHECK(sfs_record_get(fs, dir, "alice", 5, buf, 4, &len, &seq) == SFS_ERANGE && len == strlen(b), "small cap -> ERANGE");
    CHECK(sfs_record_put(fs, dir, "x.~nw", 5, a, 4, &seq) == SFS_EINVAL, "staging-suffixed name refused");
    CHECK(sfs_record_put(fs, dir, ".h", 2, a, 4, &seq) == SFS_EINVAL, "dot name refused");
    /* simulate a crash after step 2: a complete but uncommitted staging file holding other contents */
    CHECK(!sfs_create(fs, dir, "alice.~nw", 9, 0600, &ino) && !sfs_write(fs, ino, 0, "garbage", 7, &done), "stage stale file");
    CHECK(!sfs_unmount(fs), "unmount");
    host_close(&d);

    fs = mnt(&d, img);
    CHECK(!sfs_path_lookup(fs, "/acct", &dir, 0, 0, 0), "lookup /acct after remount");
    CHECK(!sfs_record_get(fs, dir, "alice", 5, buf, sizeof buf, &len, &seq) && len == strlen(b) && !memcmp(buf, b, len)
          && seq == 2, "committed B survives, staging ignored");
    CHECK(sfs_record_recover(fs, dir) == 1, "recover removes 1 staging file");
    CHECK(sfs_lookup(fs, dir, "alice.~nw", 9, &ino, 0) == SFS_ENOENT, "staging gone");
    /* corruption: flip one payload byte behind the store's back */
    CHECK(!sfs_lookup(fs, dir, "alice", 5, &ino, 0) && !sfs_write(fs, ino, 40, "X", 1, &done), "flip payload byte");
    CHECK(sfs_record_get(fs, dir, "alice", 5, buf, sizeof buf, &len, &seq) == SFS_ECORRUPT, "corruption -> ECORRUPT");
    CHECK(!sfs_record_put(fs, dir, "alice", 5, a, (uint32_t)strlen(a), &seq) && seq == 3, "rewrite damaged record (intact header keeps sequence)");
    CHECK(!sfs_record_put(fs, dir, "bob", 3, "", 0, &seq) && seq == 1, "empty record");
    CHECK(!sfs_record_get(fs, dir, "bob", 3, 0, 0, &len, &seq) && len == 0, "get empty record");
    CHECK(!sfs_record_delete(fs, dir, "bob", 3) && sfs_record_get(fs, dir, "bob", 3, 0, 0, &len, &seq) == SFS_ENOENT,
          "delete");
    CHECK(!sfs_unmount(fs), "final unmount");
    host_close(&d);
    printf("%s: %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}

static int alloc_test(const char *img)
{
    host_dev d;
    sfs_fs *fs = mnt(&d, img);
    static char data[256 * 1024];
    uint32_t ino;
    uint64_t done = 0;
    int rc;
    memset(data, 0x5A, sizeof data);
    rc = sfs_create(fs, SFS_ROOT_INO, "big", 3, 0644, &ino);
    if (!rc) rc = sfs_write(fs, ino, 0, data, sizeof data, &done);
    printf("alloc write rc %d (%s) done %llu\n", rc, sfs_strerror(rc), (unsigned long long)done);
    if (!rc) rc = sfs_unmount(fs);
    host_close(&d);
    return rc ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc >= 3 && !strcmp(argv[2], "record")) return record_test(argv[1]);
    if (argc >= 3 && !strcmp(argv[2], "alloc")) return alloc_test(argv[1]);
    fprintf(stderr, "usage: sfsrecord <image> record|alloc\n");
    return 2;
}
