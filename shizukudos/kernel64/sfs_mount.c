/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 ShizukuFS mount: libsfs (shizukufs/v1/libsfs, the ext4 on-disk format with its jbd2 journal) over the
 * generic block registry (blk.h), exposed in the fs.c name space as the next free drive letter (vfs_mounts.c).
 *
 * disk_init() calls sfs_probe_all() after the partition scan: every partition (MBR type 0x83 / GPT Linux file
 * system data 0FC63DAF-8483-4772-8E79-3D69D8477DE4 are the usual ones, but the superblock magic decides) and every
 * unpartitioned whole device whose byte 1024 holds an ext2/3/4 superblock is mounted; read/write when the device
 * can write and libsfs accepts the feature set, read-only otherwise (reasons are logged).
 *
 * The volume is mounted with SFS_MOUNT_CLEAN_ON_SYNC: updates are journaled and written back lazily (libsfs
 * commits when its running transaction grows); NtFlushBuffersFile (fsvol flush) and the normal-exit shutdown hook
 * (vfs_shutdown) commit, checkpoint, FLUSH the device and leave the volume marked cleanly unmounted, so the media
 * passes `e2fsck -fn` and mounts under Linux without replay. A crash in between is repaired by journal replay
 * (libsfs at the next mount, or e2fsck / Linux).
 *
 * Name space mapping: directory entries become fsnodes on first enumeration (FSB_DISK backing, `first_cluster`
 * holds the inode number); regular files and directories are shown, other inode types (symlinks, devices, FIFOs,
 * sockets) are not; names longer than FS_NAME_MAX-1 bytes are skipped (logged). Lookups are case-insensitive in
 * fs.c while ext4 names are case-sensitive: of two names differing only in case, the first enumerated wins.
 * Supported: read, write (sparse extension), truncate, create file/directory, delete (file, empty directory,
 * delete-on-close), rename/move within the volume (replace allowed), flush. One kernel mutex per volume.
 */
#include "fs.h"
#include "fs_policy.h"
#include "sfs_mount.h"
#include "blk.h"
#include "vfs_mounts.h"
#include "../../shizukufs/v1/libsfs/sfs.h"

#define SFSK_MAX 8
#define SFSK_CACHE_BLOCKS 512u

typedef struct sfsk_vol {
    sfs_fs *fs;
    blk_dev_t *dev;
    kmutex_t lock;
    fsvol_t vol;
    fsnode_t root;
    uint32_t ss;
    int ro;
    uint64_t reads, writes, creates, removes, renames, syncs, skipped;
} sfsk_vol;

static sfsk_vol vols[SFSK_MAX];
static unsigned nvols;
static int sys_vol = -1;                               /* index of the installed system volume, -1 none */

/* ---------------------------------------------------------------- libsfs callbacks */
static int io_unaligned(sfsk_vol *v, uint64_t off, uint8_t *buf, uint32_t bytes, int write)
{
    uint8_t *sec = kmalloc(v->ss);
    int rc = 0;
    if (!sec) return -1;
    while (bytes && !rc) {
        const uint64_t lba = off / v->ss;
        const uint32_t in = (uint32_t)(off % v->ss), n = v->ss - in < bytes ? v->ss - in : bytes;
        rc = blk_read(v->dev, lba, 1, sec);
        if (!rc) {
            if (write) {
                memcpy(sec + in, buf, n);
                rc = blk_write(v->dev, lba, 1, sec);
            } else {
                memcpy(buf, sec + in, n);
            }
        }
        off += n;
        buf += n;
        bytes -= n;
    }
    kfree(sec);
    return rc ? -1 : 0;
}

static int cb_read(void *ctx, uint64_t off, void *buf, uint32_t bytes)
{
    sfsk_vol *v = ctx;
    if (off % v->ss || bytes % v->ss) return io_unaligned(v, off, buf, bytes, 0);
    return blk_read(v->dev, off / v->ss, bytes / v->ss, buf) ? -1 : 0;
}

static int cb_write(void *ctx, uint64_t off, const void *buf, uint32_t bytes)
{
    sfsk_vol *v = ctx;
    if (off % v->ss || bytes % v->ss) return io_unaligned(v, off, (uint8_t *)buf, bytes, 1);
    return blk_write(v->dev, off / v->ss, bytes / v->ss, buf) ? -1 : 0;
}

static int cb_flush(void *ctx) { return blk_flush(((sfsk_vol *)ctx)->dev) ? -1 : 0; }

/* Block-sized objects (cache buffers, bitmaps, run lists) come from the page allocator, the rest from the heap. */
static void *cb_alloc(void *ctx, size_t bytes)
{
    (void)ctx;
    if (bytes == PAGE_SIZE) {
        const uint64_t pa = pmm_alloc();                    /* zeroed */
        return pa ? (void *)p2v(pa) : 0;
    }
    return kzalloc(bytes);
}

static void cb_free(void *ctx, void *p, size_t bytes)
{
    (void)ctx;
    if (!p) return;
    if (bytes == PAGE_SIZE) pmm_free((uint64_t)p - phys_base_va);
    else kfree(p);
}

static uint64_t cb_now(void *ctx)
{
    hcreg_t secs = 0;
    (void)ctx;
    shz_hcall(SHZ_HC_WALLTIME, 0, 0, &secs);
    return secs;
}

static void cb_log(void *ctx, const char *msg)
{
    (void)ctx;
    kprintf("K64 sfs: %s\n", msg);
}

/* ---------------------------------------------------------------- fsnode mapping */
static uint64_t filetime(int64_t sec, uint32_t ns)
{
    if (sec < -11644473600ll) return 0;
    return (uint64_t)(sec + 11644473600ll) * 10000000ull + ns / 100;
}

static void fill_node(sfsk_vol *v, fsnode_t *c, uint32_t ino, const sfs_stat_t *st)
{
    const int dir = (st->mode & SFS_S_IFMT) == SFS_S_IFDIR;
    c->first_cluster = ino;
    c->size = dir ? 0 : st->size;
    c->ftime_c = filetime(st->crtime ? st->crtime : st->ctime, st->crtime ? st->crtime_ns : st->ctime_ns);
    c->ftime_m = filetime(st->mtime, st->mtime_ns);
    c->ctime = c->mtime = 0;
    c->readonly = v->ro || !(st->mode & 0200);
    c->attrs = dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
    if (c->readonly) c->attrs |= FILE_ATTRIBUTE_READONLY;
    if (dir) c->populated = 0;
}

static int errno_of(int rc) { return rc == SFS_ENOSPC ? -2 : rc == SFS_ENOTEMPTY ? -3 : -1; }

/* ---------------------------------------------------------------- fsvol operations */
static int vol_read(fsvol_t *fv, fsnode_t *n, uint64_t off, void *buf, uint64_t len, uint64_t *done)
{
    sfsk_vol *v = fv->priv;
    int rc;
    mutex_lock(&v->lock);
    rc = sfs_read(v->fs, n->first_cluster, off, buf, len, done);
    if (!rc) v->reads++;
    mutex_unlock(&v->lock);
    return rc ? -1 : 0;
}

static int vol_write(fsvol_t *fv, fsnode_t *n, uint64_t off, const void *buf, uint64_t len)
{
    sfsk_vol *v = fv->priv;
    uint64_t done = 0;
    int rc;
    if (n->view) return -1;                             /* the file backs a mapped image: its pages must not change */
    mutex_lock(&v->lock);
    rc = sfs_write(v->fs, n->first_cluster, off, buf, len, &done);
    if (done && off + done > n->size) n->size = off + done;
    if (done) n->ftime_m = filetime((int64_t)cb_now(0), 0);
    if (!rc) v->writes++;
    mutex_unlock(&v->lock);
    if (rc) kprintf("K64 sfs: write %s at %llu (+%llu) failed: %s\n", n->name, off, len, sfs_strerror(rc));
    return rc ? errno_of(rc) : done == len ? 0 : -2;
}

static int vol_truncate(fsvol_t *fv, fsnode_t *n, uint64_t size)
{
    sfsk_vol *v = fv->priv;
    int rc;
    if (n->view) return -1;
    mutex_lock(&v->lock);
    rc = sfs_truncate(v->fs, n->first_cluster, size);
    if (!rc) { n->size = size; n->ftime_m = filetime((int64_t)cb_now(0), 0); }
    mutex_unlock(&v->lock);
    return rc ? errno_of(rc) : 0;
}

static fsnode_t *vol_create(fsvol_t *fv, fsnode_t *dir, const char *name, int is_dir)
{
    sfsk_vol *v = fv->priv;
    uint32_t ino;
    sfs_stat_t st;
    fsnode_t *c = 0;
    int rc;
    mutex_lock(&v->lock);
    rc = is_dir ? sfs_mkdir(v->fs, dir->first_cluster, name, strlen(name), 0755, &ino)
                : sfs_create(v->fs, dir->first_cluster, name, strlen(name), 0644, &ino);
    if (!rc) rc = sfs_stat(v->fs, ino, &st);
    if (!rc) {
        c = fs_new_child(dir, name, is_dir);
        if (c) {
            fill_node(v, c, ino, &st);
            if (is_dir) c->populated = 1;               /* only "." and ".." */
            v->creates++;
        }
    } else {
        kprintf("K64 sfs: create %s failed: %s\n", name, sfs_strerror(rc));
    }
    mutex_unlock(&v->lock);
    return c;
}

static int vol_remove(fsvol_t *fv, fsnode_t *n)
{
    sfsk_vol *v = fv->priv;
    int rc;
    if (!n->parent || n->view) return -1;
    mutex_lock(&v->lock);
    rc = n->is_dir ? sfs_rmdir(v->fs, n->parent->first_cluster, n->name, strlen(n->name))
                   : sfs_unlink(v->fs, n->parent->first_cluster, n->name, strlen(n->name));
    if (!rc) v->removes++;
    mutex_unlock(&v->lock);
    if (rc) kprintf("K64 sfs: delete %s failed: %s\n", n->name, sfs_strerror(rc));
    return rc ? errno_of(rc) : 0;
}

static int vol_rename(fsvol_t *fv, fsnode_t *n, fsnode_t *newdir, const char *newname, int replace)
{
    sfsk_vol *v = fv->priv;
    int rc;
    if (!n->parent || n->view) return -1;
    mutex_lock(&v->lock);
    rc = sfs_rename(v->fs, n->parent->first_cluster, n->name, strlen(n->name), newdir->first_cluster, newname,
                    strlen(newname), replace);
    if (!rc) v->renames++;
    mutex_unlock(&v->lock);
    if (rc) kprintf("K64 sfs: rename %s -> %s failed: %s\n", n->name, newname, sfs_strerror(rc));
    return rc == SFS_EEXIST ? -3 : rc ? errno_of(rc) : 0;
}

static int vol_populate(fsvol_t *fv, fsnode_t *dir)
{
    sfsk_vol *v = fv->priv;
    uint64_t cookie = 0;
    sfs_dirent *de = kmalloc(sizeof *de);
    int rc, n = 0;
    if (!de) return -1;
    mutex_lock(&v->lock);
    while ((rc = sfs_readdir(v->fs, dir->first_cluster, &cookie, de)) == 1) {
        sfs_stat_t st;
        fsnode_t *c;
        uint16_t fmt;
        if ((de->name_len == 1 && de->name[0] == '.') || (de->name_len == 2 && de->name[0] == '.' && de->name[1] == '.'))
            continue;
        if (de->name_len >= FS_NAME_MAX) { v->skipped++; kprintf("K64 sfs: name longer than %u bytes skipped\n", FS_NAME_MAX - 1); continue; }
        if (sfs_stat(v->fs, de->ino, &st)) { v->skipped++; continue; }
        fmt = st.mode & SFS_S_IFMT;
        if (fmt != SFS_S_IFREG && fmt != SFS_S_IFDIR) { v->skipped++; continue; }
        c = fs_new_child(dir, de->name, fmt == SFS_S_IFDIR);
        if (!c) { rc = -1; break; }
        fill_node(v, c, de->ino, &st);
        ++n;
    }
    mutex_unlock(&v->lock);
    kfree(de);
    if (rc < 0) kprintf("K64 sfs: enumeration of %s failed (%d) after %d entries\n", dir->name[0] ? dir->name : "\\", rc, n);
    return rc < 0 ? -1 : n;
}

static void log_counters(sfsk_vol *v, const char *what, int rc)
{
    {
        sfs_stats s;
        sfs_statfs_t f;
        sfs_get_stats(v->fs, &s);
        sfs_statfs(v->fs, &f);
        kprintf("K64 sfs: %s %c: rc %d; %llu reads %llu writes %llu creates %llu deletes %llu renames; dev %llu reads "
                "%llu writes %llu flushes; %llu commits %llu journal blocks %llu checkpointed; %llu/%llu blocks free, "
                "%u/%u inodes free\n", what, v->vol.letter, rc, v->reads, v->writes, v->creates, v->removes, v->renames,
                s.reads, s.writes, s.flushes, s.commits, s.journal_blocks_written, s.checkpoint_blocks, f.free_blocks, f.blocks,
                f.free_inodes, f.inodes);
    }
}

static int vol_flush(fsvol_t *fv)
{
    sfsk_vol *v = fv->priv;
    int rc;
    mutex_lock(&v->lock);
    rc = sfs_sync(v->fs);
    v->syncs++;
    log_counters(v, "flush", rc);
    mutex_unlock(&v->lock);
    return rc ? -1 : 0;
}

static int vol_shutdown(fsvol_t *fv)
{
    sfsk_vol *v = fv->priv;
    int rc;
    if (v->lock.locked) {                               /* an update was interrupted: leave it to journal replay */
        kprintf("K64 sfs: %c: busy at shutdown, not synced (the journal covers it)\n", fv->letter);
        return -1;
    }
    mutex_lock(&v->lock);
    rc = sfs_sync(v->fs);
    log_counters(v, "shutdown sync", rc);
    mutex_unlock(&v->lock);
    return rc ? -1 : 0;
}

/* ---------------------------------------------------------------- record store + file access policy */
#define SFSK_PROT_MAX 8
static struct { sfsk_vol *v; uint32_t ino; } prot[SFSK_PROT_MAX];
static unsigned nprot;

/* fs.c policy: nothing below a record directory is reachable through the name space (see fs_policy.h). */
static int sfsk_policy(const fsnode_t *n, unsigned op)
{
    unsigned i;
    (void)op;
    if (!nprot || n->backing != FSB_DISK || !n->vol || n->vol->populate != vol_populate) return 0;
    for (; n; n = n->parent)
        if (n->is_dir)
            for (i = 0; i < nprot; ++i)
                if (prot[i].v == n->vol->priv && prot[i].ino == n->first_cluster) return 1;
    return 0;
}

/* Called with v->lock held. Returns 1 when the directory was newly walled off (the caller then recovers it). */
static int protect_dir(sfsk_vol *v, uint32_t ino)
{
    unsigned i;
    for (i = 0; i < nprot; ++i)
        if (prot[i].v == v && prot[i].ino == ino) return 0;
    if (nprot >= SFSK_PROT_MAX) return -1;
    if (fs_policy_register(sfsk_policy)) return -1;
    prot[nprot].v = v;
    prot[nprot].ino = ino;
    ++nprot;
    return 1;
}

static sfsk_vol *vol_of_letter(char l)
{
    unsigned i;
    if (l >= 'a' && l <= 'z') l = (char)(l - 32);
    for (i = 0; i < nvols; ++i)
        if (vols[i].vol.letter == l) return &vols[i];
    return 0;
}

/* Splits "X:\A\B" (also "\??\X:..."); NULL / "" selects the account directory of the system volume. */
static sfsk_vol *parse_dir(const char *path, const char **rest)
{
    if (!path || !path[0]) {
        *rest = SFSK_ACCOUNT_DIR;
        return sys_vol >= 0 ? &vols[sys_vol] : 0;
    }
    if (path[0] == '\\' && path[1] == '?' && path[2] == '?' && path[3] == '\\') path += 4;
    if (!path[0] || path[1] != ':') return 0;
    *rest = path + 2;
    return vol_of_letter(path[0]);
}

/* Resolves (and with `create` makes, mode 0700) the directory chain `rest` from the root. v->lock held. */
static int resolve_dir(sfsk_vol *v, const char *rest, int create, uint32_t *out)
{
    uint32_t ino = SFS_ROOT_INO;
    while (*rest) {
        const char *e;
        uint32_t next;
        uint8_t type = 0;
        int rc;
        while (*rest == '\\' || *rest == '/') ++rest;
        if (!*rest) break;
        for (e = rest; *e && *e != '\\' && *e != '/'; ++e) ;
        if ((size_t)(e - rest) > SFS_NAME_MAX) return SFS_ENAMETOOLONG;
        rc = sfs_lookup(v->fs, ino, rest, (size_t)(e - rest), &next, &type);
        if (rc == SFS_ENOENT && create) {
            rc = sfs_mkdir(v->fs, ino, rest, (size_t)(e - rest), 0700, &next);
            type = SFS_FT_DIR;
        }
        if (rc) return rc;
        if (type != SFS_FT_DIR) return SFS_ENOTDIR;
        ino = next;
        rest = e;
    }
    *out = ino;
    return 0;
}

/* Walls the directory off and, the first time, removes staging files of puts interrupted by a crash. */
static void guard_dir(sfsk_vol *v, uint32_t dir)
{
    if (protect_dir(v, dir) == 1 && !v->ro) {
        const int rc = sfs_record_recover(v->fs, dir);
        if (rc) kprintf("K64 sfs: %c: record directory %u recovery: %d\n", v->vol.letter, dir, rc);
    }
}

static int record_name_ok(const char *name)
{
    const char *p;
    if (!name || !name[0]) return 0;
    for (p = name; *p; ++p) if (*p == '\\') return 0;
    return 1;
}

int sfsk_record_put(const char *dir_path, const char *name, const void *data, uint32_t len, uint64_t *seq)
{
    const char *rest;
    sfsk_vol *v = parse_dir(dir_path, &rest);
    uint32_t dir;
    int rc;
    if (seq) *seq = 0;
    if (!v) return SFSK_ENOVOL;
    if (!record_name_ok(name)) return SFS_EINVAL;
    if (v->ro) return SFS_EROFS;
    mutex_lock(&v->lock);
    rc = resolve_dir(v, rest, 1, &dir);
    if (!rc) {
        guard_dir(v, dir);
        rc = sfs_record_put(v->fs, dir, name, strlen(name), data, len, seq);
    }
    if (!rc) v->writes++;
    mutex_unlock(&v->lock);
    if (rc) kprintf("K64 sfs: %c: record put %s failed: %s\n", v->vol.letter, name, sfs_strerror(rc));
    return rc;
}

int sfsk_record_get(const char *dir_path, const char *name, void *buf, uint32_t cap, uint32_t *len, uint64_t *seq)
{
    const char *rest;
    sfsk_vol *v = parse_dir(dir_path, &rest);
    uint32_t dir;
    int rc;
    if (len) *len = 0;
    if (seq) *seq = 0;
    if (!v) return SFSK_ENOVOL;
    if (!record_name_ok(name)) return SFS_EINVAL;
    mutex_lock(&v->lock);
    rc = resolve_dir(v, rest, 0, &dir);
    if (!rc) {
        guard_dir(v, dir);
        rc = sfs_record_get(v->fs, dir, name, strlen(name), buf, cap, len, seq);
    }
    if (!rc) v->reads++;
    mutex_unlock(&v->lock);
    if (rc == SFS_ECORRUPT) kprintf("K64 sfs: %c: record %s failed validation\n", v->vol.letter, name);
    return rc;
}

int sfsk_record_delete(const char *dir_path, const char *name)
{
    const char *rest;
    sfsk_vol *v = parse_dir(dir_path, &rest);
    uint32_t dir;
    int rc;
    if (!v) return SFSK_ENOVOL;
    if (!record_name_ok(name)) return SFS_EINVAL;
    if (v->ro) return SFS_EROFS;
    mutex_lock(&v->lock);
    rc = resolve_dir(v, rest, 0, &dir);
    if (!rc) {
        guard_dir(v, dir);
        rc = sfs_record_delete(v->fs, dir, name, strlen(name));
    }
    if (!rc) v->removes++;
    mutex_unlock(&v->lock);
    return rc;
}

/* The project installer (win64/setup/install.c) lays the system volume out with SHZ\SETUP. The first such volume
 * is the installed system volume; its account directory (if present) is walled off and recovered at mount. */
static void detect_system_volume(sfsk_vol *v)
{
    uint32_t shz, setup, acct;
    uint8_t t1 = 0, t2 = 0;
    sfs_statfs_t f;
    if (sys_vol >= 0) return;
    mutex_lock(&v->lock);
    if (sfs_lookup(v->fs, SFS_ROOT_INO, "SHZ", 3, &shz, &t1) || t1 != SFS_FT_DIR ||
        sfs_lookup(v->fs, shz, "SETUP", 5, &setup, &t2) || t2 != SFS_FT_DIR) {
        mutex_unlock(&v->lock);
        return;
    }
    sys_vol = (int)(v - vols);
    if (!resolve_dir(v, SFSK_ACCOUNT_DIR, 0, &acct)) guard_dir(v, acct);
    sfs_statfs(v->fs, &f);
    mutex_unlock(&v->lock);
    kprintf("K64 sfs: %c: installed system volume, %s%s (ro reason %x)\n", v->vol.letter,
            v->ro ? "read-only" : "read/write", v->ro ? ": account persistence unavailable" : "", f.ro_reason);
}

char sfsk_system_volume(int *writable)
{
    if (writable) *writable = sys_vol >= 0 && !vols[sys_vol].ro;
    return sys_vol >= 0 ? vols[sys_vol].vol.letter : 0;
}

/* ---------------------------------------------------------------- probe + mount */
static int probe_one(blk_dev_t *d)
{
    sfsk_vol *v;
    sfs_ops ops;
    sfs_statfs_t f;
    uint8_t *sb;
    unsigned flags = SFS_MOUNT_CLEAN_ON_SYNC;
    char letter;
    int rc;
    if (nvols >= SFSK_MAX || vfs_mount_by_device(d->name) || !d->sector_size || d->sector_size > PAGE_SIZE) return -1;
    sb = kmalloc(PAGE_SIZE);
    if (!sb) return -1;
    rc = blk_read(d, 0, PAGE_SIZE / d->sector_size, sb);          /* bytes 0..4095 hold the superblock at 1024 */
    if (rc || sb[1024 + 0x38] != 0x53 || sb[1024 + 0x39] != 0xEF) { kfree(sb); return -1; }
    kfree(sb);
    v = &vols[nvols];
    memset(v, 0, sizeof *v);
    v->dev = d;
    v->ss = d->sector_size;
    mutex_init(&v->lock);
    memset(&ops, 0, sizeof ops);
    ops.ctx = v;
    ops.read = cb_read;
    ops.write = d->write && !(d->flags & BLK_F_READONLY) ? cb_write : 0;
    ops.flush = cb_flush;
    ops.alloc = cb_alloc;
    ops.free = cb_free;
    ops.now = cb_now;
    ops.log = cb_log;
    ops.size = d->sectors * d->sector_size;
    ops.cache_blocks = SFSK_CACHE_BLOCKS;
    if (!ops.write) flags |= SFS_MOUNT_RDONLY;
    rc = sfs_mount(&ops, flags, &v->fs);
    if (rc) {
        kprintf("K64 sfs: %s has an ext superblock but was not mounted: %s\n", d->name, sfs_strerror(rc));
        return -1;
    }
    sfs_statfs(v->fs, &f);
    v->ro = f.read_only;
    v->vol.read = vol_read;
    v->vol.populate = vol_populate;
    v->vol.flush = vol_flush;
    if (!v->ro) {
        v->vol.write = vol_write;
        v->vol.truncate = vol_truncate;
        v->vol.create = vol_create;
        v->vol.remove = vol_remove;
        v->vol.rename = vol_rename;
    }
    v->vol.priv = v;
    v->root.is_dir = 1;
    v->root.readonly = v->ro;
    v->root.attrs = FILE_ATTRIBUTE_DIRECTORY;
    v->root.backing = FSB_DISK;
    v->root.vol = &v->vol;
    v->root.first_cluster = SFS_ROOT_INO;
    letter = vfs_mount_next(&v->root, &v->vol, "shizukufs", d->name, vol_shutdown);
    if (!letter) {
        kprintf("K64 sfs: %s: no free drive letter\n", d->name);
        sfs_unmount(v->fs);
        return -1;
    }
    ++nvols;
    kprintf("K64 sfs: %c: = %s (mbr type %x%s), ShizukuFS/ext4 \"%s\", %u-byte blocks, %llu blocks (%llu free), %u inodes "
            "(%u free), %u groups, features compat %x incompat %x ro_compat %x journal %x, %s (ro reason %x)\n",
            letter, d->name, d->mbr_type, d->type_guid[3] == 0x0f && d->type_guid[2] == 0xc6 ? ", GPT Linux data" : "",
            f.label, f.block_size, f.blocks, f.free_blocks, f.inodes, f.free_inodes, f.groups, f.feature_compat,
            f.feature_incompat, f.feature_ro_compat, f.journal_features, v->ro ? "read-only" : "read/write", f.ro_reason);
    detect_system_volume(v);
    fs_populate(&v->root);
    {
        fsnode_t *c;
        unsigned n = 0;
        for (c = v->root.child; c; c = c->sibling) ++n;
        kprintf("K64 sfs: %c: root holds %u entries shown (%llu skipped)\n", letter, n, v->skipped);
    }
    return 0;
}

char sfsk_mount_device(blk_dev_t *d)
{
    if (!d || probe_one(d)) return 0;
    return vols[nvols - 1].vol.letter;
}

int sfs_probe_all(blk_dev_t *skip)
{
    blk_dev_t *d, *p;
    int mounted = 0;
    for (d = blk_first(); d; d = d->next)
        if ((d->flags & BLK_F_PARTITION) && d != skip && !probe_one(d)) mounted++;
    for (d = blk_first(); d; d = d->next) {
        int has_parts = 0;
        if ((d->flags & BLK_F_PARTITION) || d == skip) continue;
        for (p = blk_first(); p; p = p->next)
            if (p->parent == d) has_parts = 1;
        if (!has_parts && !probe_one(d)) mounted++;       /* unpartitioned ("superfloppy") ext volume */
    }
    return mounted;
}
