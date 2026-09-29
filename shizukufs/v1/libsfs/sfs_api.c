/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS v1 public operations. Every update runs inside one operation (sfs_op_begin/sfs_op_end): its metadata
 * changes join the running transaction, which commits atomically through the journal. An update that fails with
 * an I/O or consistency error after modifying anything aborts the transaction and leaves the volume read-only;
 * expected failures (exists, not found, no space ...) are detected before anything is modified or are undone.
 */
#include "sfs_internal.h"

#define LINK_MAX 65000u

static int name_ok(const char *name, size_t len)
{
    size_t i;
    if (len == 0) return SFS_EINVAL;
    if (len > SFS_NAME_MAX) return SFS_ENAMETOOLONG;
    for (i = 0; i < len; ++i) if (name[i] == '/' || name[i] == 0) return SFS_EINVAL;
    if ((len == 1 && name[0] == '.') || (len == 2 && name[0] == '.' && name[1] == '.')) return SFS_EINVAL;
    return 0;
}

static int get_dir(sfs_fs *fs, uint32_t ino, sfs_inode **out)
{
    int rc = sfs_iget(fs, ino, out);
    if (rc) return rc;
    if (!sfs_is_dir(*out)) { sfs_iput(fs, *out); return SFS_ENOTDIR; }
    if ((*out)->links == 0) { sfs_iput(fs, *out); return SFS_ENOENT; }
    return 0;
}

static int is_dx(sfs_fs *fs, sfs_inode *d) { return fs->dir_index && (d->flags & IFL_INDEX); }

static void dir_link_inc(sfs_fs *fs, sfs_inode *d)
{
    if (d->links == 1 && fs->dir_nlink) { sfs_idirty(fs, d); return; }     /* already past the 16-bit limit */
    if (d->links + 1u > LINK_MAX) d->links = 1;
    else d->links++;
    sfs_idirty(fs, d);
}

static void dir_link_dec(sfs_fs *fs, sfs_inode *d)
{
    if (d->links > 2) d->links--;
    sfs_idirty(fs, d);
}

/* ---- read-side ---- */
int sfs_lookup(sfs_fs *fs, uint32_t dir, const char *name, size_t len, uint32_t *ino, uint8_t *type)
{
    sfs_inode *d;
    int rc;
    if (fs->dead) return SFS_EIO;
    rc = get_dir(fs, dir, &d);
    if (rc) return rc;
    rc = sfs_dir_lookup(fs, d, name, len, ino, type);
    sfs_iput(fs, d);
    if (!rc && !sfs_ino_valid(fs, *ino)) rc = SFS_ECORRUPT;
    return rc;
}

int sfs_stat(sfs_fs *fs, uint32_t ino, sfs_stat_t *st)
{
    sfs_inode *in;
    int rc;
    if (fs->dead) return SFS_EIO;
    rc = sfs_iget(fs, ino, &in);
    if (rc) return rc;
    memset(st, 0, sizeof *st);
    st->ino = ino;
    st->mode = in->mode;
    st->links = in->links;
    st->uid = in->uid;
    st->gid = in->gid;
    st->size = in->size;
    st->blocks = in->nblocks << (fs->bs_bits - 9);
    st->atime = in->atime; st->atime_ns = in->atime_ns;
    st->mtime = in->mtime; st->mtime_ns = in->mtime_ns;
    st->ctime = in->ctime; st->ctime_ns = in->ctime_ns;
    st->crtime = in->crtime; st->crtime_ns = in->crtime_ns;
    st->flags = in->flags;
    st->generation = in->generation;
    sfs_iput(fs, in);
    return 0;
}

int sfs_readdir(sfs_fs *fs, uint32_t dir, uint64_t *cookie, sfs_dirent *out)
{
    sfs_inode *d;
    int rc;
    if (fs->dead) return SFS_EIO;
    rc = sfs_iget(fs, dir, &d);
    if (rc) return rc;
    rc = sfs_dir_next(fs, d, cookie, out);
    sfs_iput(fs, d);
    return rc;
}

int sfs_read(sfs_fs *fs, uint32_t ino, uint64_t off, void *buf, uint64_t len, uint64_t *done)
{
    sfs_inode *in;
    int rc;
    *done = 0;
    if (fs->dead) return SFS_EIO;
    rc = sfs_iget(fs, ino, &in);
    if (rc) return rc;
    if (sfs_is_dir(in)) rc = SFS_EISDIR;
    else rc = sfs_file_read(fs, in, off, buf, len, done);
    sfs_iput(fs, in);
    return rc;
}

int sfs_readlink(sfs_fs *fs, uint32_t ino, char *buf, size_t cap, size_t *len)
{
    sfs_inode *in;
    int rc;
    if (fs->dead) return SFS_EIO;
    rc = sfs_iget(fs, ino, &in);
    if (rc) return rc;
    rc = sfs_symlink_read(fs, in, buf, cap, len);
    sfs_iput(fs, in);
    return rc;
}

/* ---- data updates ---- */
int sfs_write(sfs_fs *fs, uint32_t ino, uint64_t off, const void *buf, uint64_t len, uint64_t *done)
{
    sfs_inode *in;
    int rc;
    *done = 0;
    rc = sfs_op_begin(fs);
    if (rc) return rc;
    rc = sfs_iget(fs, ino, &in);
    if (!rc) {
        rc = sfs_file_write(fs, in, off, buf, len, done);
        sfs_iput(fs, in);
    }
    return sfs_op_end(fs, rc);
}

int sfs_truncate(sfs_fs *fs, uint32_t ino, uint64_t size)
{
    sfs_inode *in;
    int rc = sfs_op_begin(fs);
    if (rc) return rc;
    rc = sfs_iget(fs, ino, &in);
    if (!rc) {
        rc = sfs_file_truncate(fs, in, size);
        sfs_iput(fs, in);
    }
    return sfs_op_end(fs, rc);
}

int sfs_set_times(sfs_fs *fs, uint32_t ino, const int64_t *atime, const int64_t *mtime)
{
    sfs_inode *in;
    int rc = sfs_op_begin(fs);
    if (rc) return rc;
    rc = sfs_iget(fs, ino, &in);
    if (!rc) {
        if (atime) { in->atime = *atime; in->atime_ns = 0; }
        if (mtime) { in->mtime = *mtime; in->mtime_ns = 0; }
        sfs_inode_touch(fs, in, 0, 1, 0);
        sfs_idirty(fs, in);
        sfs_iput(fs, in);
    }
    return sfs_op_end(fs, rc);
}

int sfs_set_mode(sfs_fs *fs, uint32_t ino, uint16_t mode)
{
    sfs_inode *in;
    int rc = sfs_op_begin(fs);
    if (rc) return rc;
    rc = sfs_iget(fs, ino, &in);
    if (!rc) {
        in->mode = (uint16_t)((in->mode & SFS_S_IFMT) | (mode & 07777));
        sfs_inode_touch(fs, in, 0, 1, 0);
        sfs_idirty(fs, in);
        sfs_iput(fs, in);
    }
    return sfs_op_end(fs, rc);
}

/* ---- deleting an inode whose last link went away ---- */
static int destroy_inode(sfs_fs *fs, sfs_inode *in)
{
    uint32_t now = (uint32_t)sfs_now(fs);
    int rc = sfs_orphan_add(fs, in);                     /* a multi-step release survives a crash */
    if (!rc) rc = sfs_inode_release_all(fs, in);
    if (!rc) rc = sfs_orphan_del(fs, in);
    if (rc) return rc;
    in->links = 0;
    in->dtime = now ? now : 1;
    sfs_idirty(fs, in);
    rc = sfs_free_inode(fs, in->ino, sfs_is_dir(in));
    if (!rc) rc = sfs_iflush(fs, in);
    return rc;
}

/* ---- creation ---- */
static int slow_symlink(sfs_fs *fs, sfs_inode *in, const char *target, size_t tlen)
{
    uint64_t pblk;
    uint32_t got;
    sfs_buf *b;
    int rc = sfs_alloc_blocks(fs, in, 0, sfs_goal_for(fs, in, 0), 1, &pblk, &got);
    if (rc) return rc;
    rc = sfs_ext_insert(fs, in, 0, pblk, 1);
    if (!rc) rc = sfs_add_blocks(fs, in, 1);
    if (!rc) rc = sfs_bnew(fs, pblk, &b);
    if (rc) return rc;
    memcpy(b->data, target, tlen);
    rc = sfs_bdirty_meta(fs, b);
    sfs_bput(fs, b);
    in->size = tlen;
    return rc;
}

static int create_common(sfs_fs *fs, uint32_t dir, const char *name, size_t len, uint16_t mode,
                         const char *target, size_t tlen, uint32_t *ino_out)
{
    sfs_inode *d, *in;
    uint32_t ino, found;
    int rc, is_dir = (mode & SFS_S_IFMT) == SFS_S_IFDIR;
    rc = name_ok(name, len);
    if (rc) return rc;
    if (target && (tlen == 0 || tlen >= fs->bs || tlen > 4095)) return tlen ? SFS_ENAMETOOLONG : SFS_EINVAL;
    rc = sfs_op_begin(fs);
    if (rc) return rc;
    rc = get_dir(fs, dir, &d);
    if (rc) return sfs_op_end(fs, rc);
    rc = sfs_dir_lookup(fs, d, name, len, &found, 0);
    if (rc == 0) rc = SFS_EEXIST;
    else if (rc == SFS_ENOENT) rc = 0;
    if (!rc && is_dir && d->links >= LINK_MAX && !(fs->dir_nlink && is_dx(fs, d))) rc = SFS_ERANGE;
    if (!rc && is_dir && d->links == 1 && !fs->dir_nlink) rc = SFS_ERANGE;
    if (!rc) rc = sfs_alloc_inode(fs, dir, is_dir, &ino);
    if (rc) { sfs_iput(fs, d); return sfs_op_end(fs, rc); }
    rc = sfs_iget_new(fs, ino, mode, &in);
    if (rc) { sfs_free_inode(fs, ino, is_dir); sfs_iput(fs, d); return sfs_op_end(fs, rc); }
    if (is_dir) {
        in->links = 2;
        rc = sfs_dir_init(fs, in, dir);
    } else if (target) {
        if (tlen < IN_BLOCK_BYTES) {
            in->flags &= ~IFL_EXTENTS;
            memset(in->iblock, 0, IN_BLOCK_BYTES);
            memcpy(in->iblock, target, tlen);
            in->size = tlen;
        } else {
            rc = slow_symlink(fs, in, target, tlen);
        }
    }
    if (!rc) rc = sfs_dir_add(fs, d, name, len, ino, sfs_mode_to_ft(mode));
    if (rc) {
        /* undo: nothing may point at the new inode */
        int urc = sfs_inode_release_all(fs, in);
        in->links = 0;
        in->dtime = (uint32_t)sfs_now(fs) | 1u;
        sfs_idirty(fs, in);
        if (!urc) urc = sfs_free_inode(fs, ino, is_dir);
        if (!urc) urc = sfs_iflush(fs, in);
        sfs_iput(fs, in);
        sfs_iforget(fs, ino);
        sfs_iput(fs, d);
        return sfs_op_end(fs, urc ? urc : rc);
    }
    if (is_dir) dir_link_inc(fs, d);
    sfs_inode_touch(fs, d, 1, 1, 0);
    sfs_iput(fs, in);
    sfs_iput(fs, d);
    if (ino_out) *ino_out = ino;
    return sfs_op_end(fs, 0);
}

int sfs_create(sfs_fs *fs, uint32_t dir, const char *name, size_t len, uint16_t mode, uint32_t *ino)
{
    return create_common(fs, dir, name, len, (uint16_t)(SFS_S_IFREG | (mode & 07777)), 0, 0, ino);
}

int sfs_mkdir(sfs_fs *fs, uint32_t dir, const char *name, size_t len, uint16_t mode, uint32_t *ino)
{
    return create_common(fs, dir, name, len, (uint16_t)(SFS_S_IFDIR | (mode & 07777)), 0, 0, ino);
}

int sfs_symlink(sfs_fs *fs, uint32_t dir, const char *name, size_t len, const char *target, size_t tlen, uint32_t *ino)
{
    return create_common(fs, dir, name, len, (uint16_t)(SFS_S_IFLNK | 0777), target, tlen, ino);
}

/* ---- removal ---- */
int sfs_unlink(sfs_fs *fs, uint32_t dir, const char *name, size_t len)
{
    sfs_inode *d, *in;
    uint32_t ino;
    int rc = name_ok(name, len);
    if (rc) return rc;
    rc = sfs_op_begin(fs);
    if (rc) return rc;
    rc = get_dir(fs, dir, &d);
    if (rc) return sfs_op_end(fs, rc);
    rc = sfs_dir_lookup(fs, d, name, len, &ino, 0);
    if (!rc) rc = sfs_iget(fs, ino, &in);
    if (rc) { sfs_iput(fs, d); return sfs_op_end(fs, rc); }
    if (sfs_is_dir(in)) rc = SFS_EISDIR;
    else if (in->flags & (IFL_IMMUTABLE | IFL_APPEND)) rc = SFS_EROFS;
    if (!rc) rc = sfs_dir_remove(fs, d, name, len, ino);
    if (!rc) {
        if (in->links) in->links--;
        sfs_inode_touch(fs, in, 0, 1, 0);
        sfs_inode_touch(fs, d, 1, 1, 0);
        if (in->links == 0) rc = destroy_inode(fs, in);
    }
    sfs_iput(fs, in);
    if (!rc && in->links == 0) sfs_iforget(fs, ino);
    sfs_iput(fs, d);
    return sfs_op_end(fs, rc);
}

int sfs_rmdir(sfs_fs *fs, uint32_t dir, const char *name, size_t len)
{
    sfs_inode *d, *c;
    uint32_t ino;
    int rc = name_ok(name, len);
    if (rc) return rc;
    rc = sfs_op_begin(fs);
    if (rc) return rc;
    rc = get_dir(fs, dir, &d);
    if (rc) return sfs_op_end(fs, rc);
    rc = sfs_dir_lookup(fs, d, name, len, &ino, 0);
    if (!rc) rc = sfs_iget(fs, ino, &c);
    if (rc) { sfs_iput(fs, d); return sfs_op_end(fs, rc); }
    if (!sfs_is_dir(c)) rc = SFS_ENOTDIR;
    else if (ino == SFS_ROOT_INO) rc = SFS_EBUSY;
    else {
        rc = sfs_dir_is_empty(fs, c);
        rc = rc == 1 ? 0 : rc == 0 ? SFS_ENOTEMPTY : rc;
    }
    if (!rc) rc = sfs_dir_remove(fs, d, name, len, ino);
    if (!rc) {
        dir_link_dec(fs, d);
        sfs_inode_touch(fs, d, 1, 1, 0);
        c->links = 0;
        rc = destroy_inode(fs, c);
    }
    sfs_iput(fs, c);
    if (!rc) sfs_iforget(fs, ino);
    sfs_iput(fs, d);
    return sfs_op_end(fs, rc);
}

/* ---- rename ---- */
static int is_ancestor(sfs_fs *fs, uint32_t anc, uint32_t dir)
{
    uint32_t cur = dir, guard = 0;
    while (cur != SFS_ROOT_INO && guard++ < 4096) {
        sfs_inode *d;
        uint32_t parent;
        int rc;
        if (cur == anc) return 1;
        rc = sfs_iget(fs, cur, &d);
        if (rc) return rc;
        rc = sfs_dir_get_parent(fs, d, &parent);
        sfs_iput(fs, d);
        if (rc) return rc;
        if (parent == cur) break;
        cur = parent;
    }
    return cur == anc;
}

int sfs_rename(sfs_fs *fs, uint32_t odir, const char *oname, size_t olen, uint32_t ndir, const char *nname, size_t nlen,
               int replace)
{
    sfs_inode *od = 0, *nd = 0, *src = 0, *tgt = 0;
    uint32_t sino, tino = 0;
    int rc, src_dir;
    rc = name_ok(oname, olen);
    if (!rc) rc = name_ok(nname, nlen);
    if (rc) return rc;
    rc = sfs_op_begin(fs);
    if (rc) return rc;
    rc = get_dir(fs, odir, &od);
    if (!rc) rc = get_dir(fs, ndir, &nd);
    if (!rc) rc = sfs_dir_lookup(fs, od, oname, olen, &sino, 0);
    if (!rc) rc = sfs_iget(fs, sino, &src);
    if (rc) goto out;
    src_dir = sfs_is_dir(src);
    if (src_dir && odir != ndir) {
        rc = is_ancestor(fs, sino, ndir);
        if (rc == 1) rc = SFS_EINVAL;
        if (rc) goto out;
    }
    rc = sfs_dir_lookup(fs, nd, nname, nlen, &tino, 0);
    if (rc == SFS_ENOENT) { rc = 0; tino = 0; }
    if (rc) goto out;
    if (tino) {
        if (tino == sino) goto out;                           /* same file: nothing to do */
        if (!replace) { rc = SFS_EEXIST; goto out; }
        rc = sfs_iget(fs, tino, &tgt);
        if (rc) goto out;
        if (sfs_is_dir(tgt)) {
            if (!src_dir) { rc = SFS_EISDIR; goto out; }
            rc = sfs_dir_is_empty(fs, tgt);
            rc = rc == 1 ? 0 : rc == 0 ? SFS_ENOTEMPTY : rc;
            if (rc) goto out;
        } else if (src_dir) {
            rc = SFS_ENOTDIR;
            goto out;
        }
        rc = sfs_dir_set_inode(fs, nd, nname, nlen, sino, sfs_mode_to_ft(src->mode));
    } else {
        if (src_dir && odir != ndir && nd->links >= LINK_MAX && !(fs->dir_nlink && is_dx(fs, nd))) { rc = SFS_ERANGE; goto out; }
        rc = sfs_dir_add(fs, nd, nname, nlen, sino, sfs_mode_to_ft(src->mode));
    }
    if (rc) goto out;
    rc = sfs_dir_remove(fs, od, oname, olen, sino);
    if (rc) goto out;
    if (src_dir && odir != ndir) {
        rc = sfs_dir_set_parent(fs, src, ndir);
        if (rc) goto out;
        dir_link_dec(fs, od);
        if (!tgt) dir_link_inc(fs, nd);
    }
    if (tgt) {
        if (sfs_is_dir(tgt)) {
            tgt->links = 0;
            if (odir == ndir || !src_dir) dir_link_dec(fs, nd);
        } else if (tgt->links) {
            tgt->links--;
        }
        sfs_inode_touch(fs, tgt, 0, 1, 0);
        if (tgt->links == 0) rc = destroy_inode(fs, tgt);
    }
    sfs_inode_touch(fs, src, 0, 1, 0);
    sfs_inode_touch(fs, od, 1, 1, 0);
    if (nd != od) sfs_inode_touch(fs, nd, 1, 1, 0);
out:
    if (tgt) { uint32_t gone = tgt->links == 0; sfs_iput(fs, tgt); if (gone && !rc) sfs_iforget(fs, tino); }
    if (src) sfs_iput(fs, src);
    if (nd) sfs_iput(fs, nd);
    if (od) sfs_iput(fs, od);
    return sfs_op_end(fs, rc);
}

/* ---- paths ---- */
int sfs_path_lookup(sfs_fs *fs, const char *path, uint32_t *ino, uint32_t *parent, const char **leaf, size_t *leaf_len)
{
    uint32_t cur = SFS_ROOT_INO, par = SFS_ROOT_INO;
    const char *p = path;
    int rc = 0;
    if (leaf) { *leaf = 0; *leaf_len = 0; }
    while (*p == '/') p++;
    while (*p) {
        const char *s = p;
        size_t n;
        uint32_t next;
        while (*p && *p != '/') p++;
        n = (size_t)(p - s);
        while (*p == '/') p++;
        if (n == 1 && s[0] == '.') continue;
        par = cur;
        if (leaf) { *leaf = s; *leaf_len = n; }
        rc = sfs_lookup(fs, cur, s, n, &next, 0);
        if (rc) {
            if (parent) *parent = *p ? 0 : cur;
            return rc;
        }
        cur = next;
    }
    if (ino) *ino = cur;
    if (parent) *parent = par;
    return 0;
}
