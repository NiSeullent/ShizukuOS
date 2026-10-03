/* SPDX-License-Identifier: GPL-2.0-only
 * Host test for ShizukuFS v1 ownership/access checks (libsfs/sfs_access.c).
 *   usage: sfsaccess SCRATCH_DIR
 * 1. pure decision matrix (sfs_permission_st);
 * 2. multi-user behaviour on a real mkfs.ext4 image through libsfs;
 * 3. crash ordering: the checked create/mkdir/chown sequence is cut after the 1st, 2nd, ... Nth device write (every
 *    write before the cut is on the image, none after), the image is remounted (libsfs jbd2 replay + orphan cleanup)
 *    and every inode must be in an allowed state (absent / intended owner+mode / root-owned 0000), and `e2fsck -fn`
 *    must pass. Done for the default and the SFS_MOUNT_SMALL_TXN commit threshold.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "../libsfs/sfs_access.h"
#include "../tools/sfs_host.h"

static int fails;
#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)
#define EQ(a, b) do { long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { fprintf(stderr, "FAIL %s:%d: %s = %lld, want %lld\n", __FILE__, __LINE__, #a, _a, _b); fails++; } } while (0)

static sfs_cred cred(uint32_t uid, uint32_t gid, uint32_t caps)
{
    sfs_cred c;
    memset(&c, 0, sizeof c);
    c.uid = uid; c.gid = gid; c.caps = caps;
    return c;
}

static sfs_stat_t st_of(uint16_t mode, uint32_t uid, uint32_t gid)
{
    sfs_stat_t s;
    memset(&s, 0, sizeof s);
    s.mode = mode; s.uid = uid; s.gid = gid;
    return s;
}

static void test_matrix(void)
{
    sfs_cred alice = cred(1000, 1000, 0), bob = cred(1001, 100, 0), admin = cred(0, 0, SFS_CAP_ALL);
    sfs_cred backup = cred(34, 34, SFS_CAP_DAC_READ_SEARCH), root_nocap = cred(0, 0, 0);
    sfs_stat_t f600 = st_of(0100600, 1000, 1000), f604 = st_of(0100604, 1000, 1000), f077 = st_of(0100077, 1000, 100);
    sfs_stat_t d700 = st_of(040700, 1000, 1000), f644 = st_of(0100644, 0, 0);
    bob.ngroups = 1; bob.groups[0] = 1000;
    EQ(sfs_permission_st(&alice, &f600, SFS_MAY_READ | SFS_MAY_WRITE), 0);
    EQ(sfs_permission_st(&alice, &f600, SFS_MAY_EXEC), SFS_EACCES);
    EQ(sfs_permission_st(&bob, &f600, SFS_MAY_READ), SFS_EACCES);            /* group member, group bits 0 */
    EQ(sfs_permission_st(&bob, &f604, SFS_MAY_READ), SFS_EACCES);            /* group class wins over other */
    EQ(sfs_permission_st(&alice, &f077, SFS_MAY_READ), SFS_EACCES);          /* owner class wins over group/other */
    EQ(sfs_permission_st(&root_nocap, &f600, SFS_MAY_READ), SFS_EACCES);     /* uid 0 alone has no power */
    EQ(sfs_permission_st(&admin, &f600, SFS_MAY_READ | SFS_MAY_WRITE), 0);
    EQ(sfs_permission_st(&admin, &f600, SFS_MAY_EXEC), SFS_EACCES);          /* no x bit anywhere */
    EQ(sfs_permission_st(&admin, &d700, SFS_MAY_EXEC | SFS_MAY_WRITE), 0);
    EQ(sfs_permission_st(&backup, &f600, SFS_MAY_READ), 0);
    EQ(sfs_permission_st(&backup, &f600, SFS_MAY_WRITE), SFS_EACCES);
    EQ(sfs_permission_st(&backup, &d700, SFS_MAY_READ | SFS_MAY_EXEC), 0);
    EQ(sfs_permission_st(&backup, &d700, SFS_MAY_WRITE), SFS_EACCES);
    EQ(sfs_permission_st(&bob, &f644, SFS_MAY_READ), 0);
    EQ(sfs_permission_st(&bob, &f644, 8), SFS_EINVAL);
    bob.ngroups = SFS_CRED_NGROUPS + 1;
    EQ(sfs_permission_st(&bob, &f644, SFS_MAY_READ), SFS_EINVAL);
}

static host_dev g_dev;
static sfs_fs *g_fs;

static int vmount(const char *img, unsigned flags)
{
    sfs_ops ops;
    if (host_open(&g_dev, img, 1)) { perror(img); return -1; }
    g_dev.quiet = 1;
    host_ops(&g_dev, &ops, 0);
    return sfs_mount(&ops, flags, &g_fs);
}

static void vumount(void)
{
    EQ(sfs_unmount(g_fs), 0);
    g_fs = 0;
    host_close(&g_dev);
}

static uint32_t look(const char *path)
{
    uint32_t ino = 0;
    return sfs_path_lookup(g_fs, path, &ino, 0, 0, 0) ? 0 : ino;
}

static sfs_stat_t stat_of(uint32_t ino)
{
    sfs_stat_t s;
    memset(&s, 0, sizeof s);
    CHECK(sfs_stat(g_fs, ino, &s) == 0);
    return s;
}

/* Layout: /home 0755 root, /home/alice 0700 alice, /tmp 1777 root, /srv 2775 root:50, /etc/conf 0644 root. */
static void setup(const char *img)
{
    char cmd[512];
    uint32_t home, a, t, srv, etc, conf;
    sfs_cred admin = cred(0, 0, SFS_CAP_ALL);
    snprintf(cmd, sizeof cmd, "rm -f '%s' && mkfs.ext4 -q -F -b 1024 '%s' 8M >/dev/null 2>&1", img, img);
    if (system(cmd) != 0) { fprintf(stderr, "mkfs.ext4 failed\n"); exit(2); }
    if (vmount(img, 0)) { fprintf(stderr, "mount failed\n"); exit(2); }
    EQ(sfs_mkdir_as(g_fs, &admin, SFS_ROOT_INO, "home", 4, 0755, &home), 0);
    EQ(sfs_mkdir_as(g_fs, &admin, home, "alice", 5, 0700, &a), 0);
    EQ(sfs_chown_as(g_fs, &admin, a, 1000, 1000), 0);
    EQ(sfs_mkdir_as(g_fs, &admin, SFS_ROOT_INO, "tmp", 3, 01777, &t), 0);
    EQ(sfs_mkdir_as(g_fs, &admin, SFS_ROOT_INO, "srv", 3, 0775, &srv), 0);
    EQ(sfs_chown_as(g_fs, &admin, srv, SFS_ID_KEEP, 50), 0);
    EQ(sfs_chmod_as(g_fs, &admin, srv, 02775), 0);
    EQ(sfs_mkdir_as(g_fs, &admin, SFS_ROOT_INO, "etc", 3, 0755, &etc), 0);
    EQ(sfs_open_as(g_fs, &admin, etc, "conf", 4, SFS_O_WRITE | SFS_O_CREATE, 0644, &conf), 0);
    vumount();
}

static void test_volume(const char *img)
{
    sfs_cred alice = cred(1000, 1000, 0), bob = cred(1001, 1001, 0), admin = cred(0, 0, SFS_CAP_ALL);
    sfs_cred carol = cred(1002, 1002, 0);
    uint32_t ino, home, a, t, srv, conf, par;
    const char *leaf;
    size_t ll;
    sfs_stat_t s;
    uint64_t done;
    setup(img);
    if (vmount(img, 0)) { fprintf(stderr, "mount failed\n"); exit(2); }
    home = look("/home"); a = look("/home/alice"); t = look("/tmp"); srv = look("/srv"); conf = look("/etc/conf");
    CHECK(home && a && t && srv && conf);
    s = stat_of(a); EQ(s.uid, 1000); EQ(s.gid, 1000); EQ(s.mode, 040700);
    s = stat_of(srv); EQ(s.gid, 50); EQ(s.mode, 042775);

    /* private home */
    EQ(sfs_open_as(g_fs, &alice, a, "diary", 5, SFS_O_WRITE | SFS_O_CREATE | SFS_O_EXCL, 0600, &ino), 0);
    s = stat_of(ino); EQ(s.uid, 1000); EQ(s.gid, 1000); EQ(s.mode, 0100600);
    EQ(sfs_write(g_fs, ino, 0, "secret", 6, &done), 0);
    EQ(sfs_open_as(g_fs, &alice, a, "diary", 5, SFS_O_CREATE | SFS_O_EXCL | SFS_O_WRITE, 0600, &ino), SFS_EEXIST);
    EQ(sfs_open_as(g_fs, &bob, a, "diary", 5, SFS_O_READ, 0, &ino), SFS_EACCES);          /* no search on 0700 */
    EQ(sfs_open_as(g_fs, &bob, a, "x", 1, SFS_O_WRITE | SFS_O_CREATE, 0666, &ino), SFS_EACCES);
    EQ(sfs_walk_as(g_fs, &bob, "/home/alice/diary", &ino, &par, &leaf, &ll), SFS_EACCES);
    EQ(sfs_walk_as(g_fs, &alice, "/home/alice/diary", &ino, &par, &leaf, &ll), 0);
    EQ(par, a); EQ(ll, 5);
    EQ(sfs_walk_as(g_fs, &alice, "/home/alice/new", &ino, &par, &leaf, &ll), SFS_ENOENT);
    EQ(par, a); CHECK(leaf && ll == 3 && !memcmp(leaf, "new", 3));
    EQ(sfs_walk_as(g_fs, &alice, "/nope/new", &ino, &par, &leaf, &ll), SFS_ENOENT);
    CHECK(leaf == 0 && ll == 0);
    EQ(sfs_unlink_as(g_fs, &bob, a, "diary", 5), SFS_EACCES);
    EQ(sfs_chmod_as(g_fs, &bob, a, 0777), SFS_EPERM);
    EQ(sfs_chown_as(g_fs, &alice, a, 1001, SFS_ID_KEEP), SFS_EPERM);                    /* giving away needs CHOWN */
    EQ(sfs_chown_as(g_fs, &alice, a, SFS_ID_KEEP, 1001), SFS_EPERM);                    /* not in group 1001 */
    EQ(sfs_open_as(g_fs, &admin, a, "diary", 5, SFS_O_READ, 0, &ino), 0);                /* DAC override */

    /* read-only world file */
    EQ(sfs_open_as(g_fs, &bob, look("/etc"), "conf", 4, SFS_O_READ, 0, &ino), 0);
    EQ(sfs_open_as(g_fs, &bob, look("/etc"), "conf", 4, SFS_O_WRITE, 0, &ino), SFS_EACCES);
    EQ(sfs_open_as(g_fs, &bob, look("/etc"), "conf", 4, SFS_O_TRUNC, 0, &ino), SFS_EACCES);
    EQ(sfs_open_as(g_fs, &bob, SFS_ROOT_INO, "etc", 3, SFS_O_WRITE, 0, &ino), SFS_EISDIR);
    EQ(sfs_open_as(g_fs, &bob, look("/etc"), "conf", 4, SFS_O_READ | SFS_O_DIRECTORY, 0, &ino), SFS_ENOTDIR);

    /* sticky /tmp */
    EQ(sfs_open_as(g_fs, &alice, t, "a.tmp", 5, SFS_O_WRITE | SFS_O_CREATE, 0666, &ino), 0);
    EQ(sfs_unlink_as(g_fs, &bob, t, "a.tmp", 5), SFS_EPERM);
    EQ(sfs_open_as(g_fs, &bob, t, "b.tmp", 5, SFS_O_WRITE | SFS_O_CREATE, 0644, &ino), 0);
    EQ(sfs_rename_as(g_fs, &bob, t, "b.tmp", 5, t, "a.tmp", 5, 1), SFS_EPERM);          /* may not replace alice's */
    EQ(sfs_rename_as(g_fs, &bob, t, "b.tmp", 5, t, "c.tmp", 5, 0), 0);
    EQ(sfs_open_as(g_fs, &bob, t, "a.tmp", 5, SFS_O_WRITE | SFS_O_TRUNC, 0, &ino), 0);  /* 0666: data writable */
    EQ(sfs_unlink_as(g_fs, &alice, t, "a.tmp", 5), 0);
    EQ(sfs_unlink_as(g_fs, &admin, t, "c.tmp", 5), 0);                                  /* FOWNER */

    /* setgid project directory */
    EQ(sfs_mkdir_as(g_fs, &alice, srv, "p", 1, 0755, &ino), SFS_EACCES);                /* other: r-x */
    carol.ngroups = 1; carol.groups[0] = 50;
    EQ(sfs_mkdir_as(g_fs, &carol, srv, "p", 1, 0755, &ino), 0);
    s = stat_of(ino); EQ(s.uid, 1002); EQ(s.gid, 50); EQ(s.mode, 042755);                /* inherits gid + S_ISGID */
    EQ(sfs_open_as(g_fs, &carol, ino, "f", 1, SFS_O_WRITE | SFS_O_CREATE, 02755, &ino), 0);
    s = stat_of(ino); EQ(s.gid, 50); EQ(s.mode, 0102755);
    EQ(sfs_chown_as(g_fs, &carol, ino, SFS_ID_KEEP, 1002), 0);                           /* own group, clears sgid */
    s = stat_of(ino); EQ(s.gid, 1002); EQ(s.mode, 0100755);
    EQ(sfs_chmod_as(g_fs, &carol, ino, 02750), 0);
    s = stat_of(ino); EQ(s.mode, 0102750);
    EQ(sfs_chown_as(g_fs, &admin, ino, 1000, 50), 0);
    s = stat_of(ino); EQ(s.uid, 1000); EQ(s.gid, 50); EQ(s.mode, 0100750);
    /* moving a directory to another parent needs write on it */
    EQ(sfs_mkdir_as(g_fs, &carol, look("/srv/p"), "sub", 3, 0555, &ino), 0);
    EQ(sfs_rename_as(g_fs, &carol, look("/srv/p"), "sub", 3, t, "sub", 3, 0), SFS_EACCES);
    vumount();

    /* the policy survives remount with the owner bits libsfs serialised (incl. uid/gid high halves) */
    if (vmount(img, SFS_MOUNT_RDONLY)) { fprintf(stderr, "remount failed\n"); exit(2); }
    s = stat_of(look("/home/alice/diary")); EQ(s.uid, 1000); EQ(s.mode, 0100600);
    EQ(sfs_open_as(g_fs, &alice, look("/home/alice"), "diary", 5, SFS_O_WRITE, 0, &ino), SFS_EROFS);
    EQ(sfs_open_as(g_fs, &alice, look("/home/alice"), "diary", 5, SFS_O_READ, 0, &ino), 0);
    vumount();
}

/* ---- crash ordering ---- */
static void hit(void *ctx) { (void)ctx; _exit(3); }

static void workload(void)
{
    sfs_cred alice = cred(70000, 70001, 0), admin = cred(0, 0, SFS_CAP_ALL), carol = cred(1002, 1002, 0);
    uint32_t ino;
    carol.ngroups = 1; carol.groups[0] = 50;
    if (sfs_open_as(g_fs, &alice, look("/tmp"), "secret", 6, SFS_O_WRITE | SFS_O_CREATE | SFS_O_EXCL, 0600,
                    &ino)) _exit(4);
    if (sfs_mkdir_as(g_fs, &carol, look("/srv"), "proj", 4, 0750, &ino)) _exit(5);
    if (sfs_chown_as(g_fs, &admin, look("/etc/conf"), 70000, 70001)) _exit(6);
    if (sfs_sync(g_fs)) _exit(7);
    if (sfs_unmount(g_fs)) _exit(8);
    _exit(0);
}

/* 0 absent, 1 intended, 2 fail-closed root 0000; -1 any other state */
static int classify(const char *path, uint32_t uid, uint32_t gid, uint16_t mode, uint16_t type)
{
    uint32_t ino = look(path);
    sfs_stat_t s;
    if (!ino) return 0;
    if (sfs_stat(g_fs, ino, &s)) return -1;
    if (s.uid == uid && s.gid == gid && s.mode == mode) return 1;
    if (s.uid == 0 && s.gid == 0 && s.mode == type) return 2;
    fprintf(stderr, "  %s: uid %u gid %u mode %o\n", path, s.uid, s.gid, s.mode);
    return -1;
}

static void test_crash(const char *dir, unsigned mflags, const char *tag)
{
    char base[400], img[400], cmd[1024];
    uint64_t n;
    int seen[3][3], completed = 0;
    unsigned trials = 0;
    memset(seen, 0, sizeof seen);
    snprintf(base, sizeof base, "%s/access-base.img", dir);
    snprintf(img, sizeof img, "%s/access-trial.img", dir);
    setup(base);
    for (n = 1; n < 4000 && !completed; ++n) {
        pid_t pid;
        int status, c1, c2, c3;
        snprintf(cmd, sizeof cmd, "cp --sparse=always '%s' '%s'", base, img);
        if (system(cmd)) { fprintf(stderr, "cp failed\n"); exit(2); }
        pid = fork();
        if (pid == 0) {
            if (vmount(img, mflags)) _exit(9);
            sfs_set_write_limit(g_fs, n, hit);
            workload();
        }
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 3)) {
            fprintf(stderr, "FAIL %s: write %llu: child status %d\n", tag, (unsigned long long)n, status);
            fails++;
            break;
        }
        completed = WEXITSTATUS(status) == 0;
        ++trials;
        if (vmount(img, 0)) { fprintf(stderr, "FAIL %s: remount after cut %llu\n", tag, (unsigned long long)n); fails++; break; }
        c1 = classify("/tmp/secret", 70000, 70001, 0100600, 0100000);
        c2 = classify("/srv/proj", 1002, 50, 042750, 040000);
        {
            sfs_stat_t s = stat_of(look("/etc/conf"));
            c3 = (s.uid == 0 && s.gid == 0) ? 0 : (s.uid == 70000 && s.gid == 70001) ? 1 : -1;
            if (s.mode != 0100644) c3 = -1;
        }
        if (c1 < 0 || c2 < 0 || c3 < 0) {
            fprintf(stderr, "FAIL %s: cut after write %llu: states %d %d %d\n", tag, (unsigned long long)n, c1, c2, c3);
            fails++;
        } else {
            seen[0][c1]++; seen[1][c2]++; seen[2][c3]++;
        }
        if (completed && (c1 != 1 || c2 != 1 || c3 != 1)) { fprintf(stderr, "FAIL %s: completed run incomplete\n", tag); fails++; }
        vumount();
        snprintf(cmd, sizeof cmd, "e2fsck -fn '%s' >/dev/null 2>&1", img);
        if (system(cmd) != 0) { fprintf(stderr, "FAIL %s: e2fsck -fn after cut %llu\n", tag, (unsigned long long)n); fails++; }
    }
    CHECK(completed);
    printf("crash[%s]: %u cut points; secret absent/intended/closed %d/%d/%d, proj %d/%d/%d, chown old/new %d/%d\n",
           tag, trials, seen[0][0], seen[0][1], seen[0][2], seen[1][0], seen[1][1], seen[1][2], seen[2][0], seen[2][1]);
    unlink(img);
    unlink(base);
}

int main(int argc, char **argv)
{
    char img[400];
    if (argc != 2) { fprintf(stderr, "usage: %s SCRATCH_DIR\n", argv[0]); return 2; }
    test_matrix();
    snprintf(img, sizeof img, "%s/access.img", argv[1]);
    test_volume(img);
    unlink(img);
    test_crash(argv[1], 0, "default");
    test_crash(argv[1], SFS_MOUNT_SMALL_TXN, "small-txn");
    printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
    return fails ? 1 : 0;
}
