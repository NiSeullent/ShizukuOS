/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS v1 ownership and access checks (policy layer over libsfs; see sfs_access.h).
 * Original implementation of the POSIX discretionary access rules; no GPL sources are copied.
 */
#include "sfs_access.h"
#include "sfs_internal.h"

#define S_ISUID_ 04000u
#define S_ISGID_ 02000u
#define S_ISVTX_ 01000u

int sfs_cred_check(const sfs_cred *c)
{
    if (!c || c->ngroups > SFS_CRED_NGROUPS || (c->caps & ~SFS_CAP_ALL)) return SFS_EINVAL;
    return 0;
}

int sfs_cred_in_group(const sfs_cred *c, uint32_t gid)
{
    uint32_t i;
    if (c->gid == gid) return 1;
    for (i = 0; i < c->ngroups && i < SFS_CRED_NGROUPS; ++i)
        if (c->groups[i] == gid) return 1;
    return 0;
}

int sfs_permission_st(const sfs_cred *c, const sfs_stat_t *st, uint32_t mask)
{
    uint32_t mode = st->mode, bits;
    int isdir = (mode & SFS_S_IFMT) == SFS_S_IFDIR;
    if (sfs_cred_check(c) || (mask & ~7u)) return SFS_EINVAL;
    if (c->uid == st->uid) bits = (mode >> 6) & 7u;
    else if (sfs_cred_in_group(c, st->gid)) bits = (mode >> 3) & 7u;
    else bits = mode & 7u;
    if ((bits & mask) == mask) return 0;
    if (c->caps & SFS_CAP_DAC_OVERRIDE) {
        if (!(mask & SFS_MAY_EXEC) || isdir || (mode & 0111u)) return 0;
    }
    if (c->caps & SFS_CAP_DAC_READ_SEARCH) {
        if (isdir ? !(mask & SFS_MAY_WRITE) : mask == SFS_MAY_READ) return 0;
    }
    return SFS_EACCES;
}

int sfs_permission(sfs_fs *fs, const sfs_cred *c, uint32_t ino, uint32_t mask)
{
    sfs_stat_t st;
    int rc = sfs_stat(fs, ino, &st);
    return rc ? rc : sfs_permission_st(c, &st, mask);
}

/* `dir` must be a live directory the credential may search (and, with `write`, modify). */
static int dir_check(sfs_fs *fs, const sfs_cred *c, uint32_t dir, int write, sfs_stat_t *dst)
{
    int rc = sfs_cred_check(c);
    if (!rc) rc = sfs_stat(fs, dir, dst);
    if (rc) return rc;
    if ((dst->mode & SFS_S_IFMT) != SFS_S_IFDIR) return SFS_ENOTDIR;
    return sfs_permission_st(c, dst, write ? (SFS_MAY_WRITE | SFS_MAY_EXEC) : SFS_MAY_EXEC);
}

static int sticky_ok(const sfs_cred *c, const sfs_stat_t *dst, const sfs_stat_t *victim)
{
    if (!(dst->mode & S_ISVTX_)) return 0;
    if (c->uid == victim->uid || c->uid == dst->uid || (c->caps & SFS_CAP_FOWNER)) return 0;
    return SFS_EPERM;
}

int sfs_walk_as(sfs_fs *fs, const sfs_cred *c, const char *path, uint32_t *ino, uint32_t *parent,
                const char **leaf, size_t *leaf_len)
{
    uint32_t cur = SFS_ROOT_INO, par = SFS_ROOT_INO, next;
    const char *p = path, *lf = 0;
    size_t ll = 0;
    sfs_stat_t st;
    int rc = sfs_cred_check(c);
    if (rc) return rc;
    if (!path || path[0] != '/') return SFS_EINVAL;
    for (;;) {
        const char *s;
        size_t n;
        while (*p == '/') ++p;
        if (!*p) break;
        s = p;
        while (*p && *p != '/') ++p;
        n = (size_t)(p - s);
        if (n > SFS_NAME_MAX) return SFS_ENAMETOOLONG;
        rc = sfs_stat(fs, cur, &st);
        if (rc) return rc;
        if ((st.mode & SFS_S_IFMT) != SFS_S_IFDIR) return SFS_ENOTDIR;
        rc = sfs_permission_st(c, &st, SFS_MAY_EXEC);
        if (rc) return rc;
        par = cur;
        lf = s;
        ll = n;
        if (parent) *parent = par;
        if (leaf) *leaf = lf;
        if (leaf_len) *leaf_len = ll;
        rc = sfs_lookup(fs, cur, s, n, &next, 0);
        if (rc == SFS_ENOENT) {
            const char *q = p;
            while (*q == '/') ++q;
            if (*q) {                               /* a missing intermediate directory: nothing to create in */
                if (leaf) *leaf = 0;
                if (leaf_len) *leaf_len = 0;
            }
            return SFS_ENOENT;
        }
        if (rc) return rc;
        cur = next;
    }
    if (ino) *ino = cur;
    if (parent) *parent = par;
    if (leaf) *leaf = lf;
    if (leaf_len) *leaf_len = ll;
    return 0;
}

static int set_owner_in_op(sfs_fs *fs, uint32_t ino, uint32_t uid, uint32_t gid, uint16_t mode)
{
    sfs_inode *in;
    int rc = sfs_iget(fs, ino, &in);
    if (rc) return rc;
    in->uid = uid;
    in->gid = gid;
    in->mode = (uint16_t)((in->mode & SFS_S_IFMT) | (mode & 07777u));
    sfs_inode_touch(fs, in, 0, 1, 0);
    sfs_idirty(fs, in);
    sfs_iput(fs, in);
    return 0;
}

int sfs_set_owner(sfs_fs *fs, uint32_t ino, uint32_t uid, uint32_t gid, uint16_t mode)
{
    int rc = sfs_op_begin(fs);
    if (rc) return rc;
    return sfs_op_end(fs, set_owner_in_op(fs, ino, uid, gid, mode));
}

/* Creates with uid 0/gid 0/0000 first, then applies the caller's owner+mode in the same operation (fail closed). */
static int create_owned(sfs_fs *fs, const sfs_cred *c, uint32_t dir, const sfs_stat_t *dst, const char *name,
                        size_t len, uint16_t mode, int is_dir, uint32_t *out)
{
    uint32_t ino = 0, gid = c->gid;
    uint16_t perm = (uint16_t)(mode & 07777u);
    int rc;
    if (dst->mode & S_ISGID_) {
        gid = dst->gid;
        if (is_dir) perm |= S_ISGID_;
    }
    if (!is_dir && (perm & S_ISGID_) && !sfs_cred_in_group(c, gid) && !(c->caps & SFS_CAP_FSETID))
        perm &= (uint16_t)~S_ISGID_;
    rc = sfs_op_begin(fs);
    if (rc) return rc;
    rc = is_dir ? sfs_mkdir(fs, dir, name, len, 0, &ino) : sfs_create(fs, dir, name, len, 0, &ino);
    if (!rc) rc = set_owner_in_op(fs, ino, c->uid, gid, perm);
    rc = sfs_op_end(fs, rc);
    if (!rc && out) *out = ino;
    return rc;
}

int sfs_open_as(sfs_fs *fs, const sfs_cred *c, uint32_t dir, const char *name, size_t len, uint32_t oflags,
                uint16_t mode, uint32_t *out)
{
    sfs_stat_t dst, st;
    uint32_t ino, mask = 0;
    int rc;
    if (oflags & ~0x3Fu) return SFS_EINVAL;
    rc = dir_check(fs, c, dir, 0, &dst);
    if (rc) return rc;
    rc = sfs_lookup(fs, dir, name, len, &ino, 0);
    if (rc == SFS_ENOENT && (oflags & SFS_O_CREATE)) {
        if (oflags & SFS_O_DIRECTORY) return SFS_EINVAL;
        rc = sfs_permission_st(c, &dst, SFS_MAY_WRITE | SFS_MAY_EXEC);
        if (rc) return rc;
        if (sfs_is_readonly(fs)) return SFS_EROFS;
        return create_owned(fs, c, dir, &dst, name, len, mode, 0, out);
    }
    if (rc) return rc;
    if ((oflags & SFS_O_CREATE) && (oflags & SFS_O_EXCL)) return SFS_EEXIST;
    rc = sfs_stat(fs, ino, &st);
    if (rc) return rc;
    switch (st.mode & SFS_S_IFMT) {
    case SFS_S_IFLNK: return SFS_ENOTSUP;
    case SFS_S_IFDIR: if (oflags & (SFS_O_WRITE | SFS_O_TRUNC)) return SFS_EISDIR; break;
    default: if (oflags & SFS_O_DIRECTORY) return SFS_ENOTDIR; break;
    }
    if (oflags & SFS_O_READ) mask |= SFS_MAY_READ;
    if (oflags & (SFS_O_WRITE | SFS_O_TRUNC)) mask |= SFS_MAY_WRITE;
    rc = sfs_permission_st(c, &st, mask);
    if (rc) return rc;
    if ((mask & SFS_MAY_WRITE) && sfs_is_readonly(fs)) return SFS_EROFS;
    if ((oflags & SFS_O_TRUNC) && (st.mode & SFS_S_IFMT) == SFS_S_IFREG && st.size) {
        rc = sfs_truncate(fs, ino, 0);
        if (rc) return rc;
    }
    if (out) *out = ino;
    return 0;
}

int sfs_mkdir_as(sfs_fs *fs, const sfs_cred *c, uint32_t dir, const char *name, size_t len, uint16_t mode,
                 uint32_t *out)
{
    sfs_stat_t dst;
    uint32_t ino;
    int rc = dir_check(fs, c, dir, 1, &dst);
    if (rc) return rc;
    rc = sfs_lookup(fs, dir, name, len, &ino, 0);
    if (rc == 0) return SFS_EEXIST;
    if (rc != SFS_ENOENT) return rc;
    if (sfs_is_readonly(fs)) return SFS_EROFS;
    return create_owned(fs, c, dir, &dst, name, len, mode, 1, out);
}

/* w+x on `dir`, the entry exists, sticky rule. */
static int may_delete(sfs_fs *fs, const sfs_cred *c, uint32_t dir, const char *name, size_t len, sfs_stat_t *dst,
                      sfs_stat_t *vst)
{
    uint32_t ino;
    int rc = dir_check(fs, c, dir, 1, dst);
    if (!rc) rc = sfs_lookup(fs, dir, name, len, &ino, 0);
    if (!rc) rc = sfs_stat(fs, ino, vst);
    if (!rc) rc = sticky_ok(c, dst, vst);
    return rc;
}

int sfs_unlink_as(sfs_fs *fs, const sfs_cred *c, uint32_t dir, const char *name, size_t len)
{
    sfs_stat_t dst, vst;
    int rc = may_delete(fs, c, dir, name, len, &dst, &vst);
    return rc ? rc : sfs_unlink(fs, dir, name, len);
}

int sfs_rmdir_as(sfs_fs *fs, const sfs_cred *c, uint32_t dir, const char *name, size_t len)
{
    sfs_stat_t dst, vst;
    int rc = may_delete(fs, c, dir, name, len, &dst, &vst);
    return rc ? rc : sfs_rmdir(fs, dir, name, len);
}

int sfs_rename_as(sfs_fs *fs, const sfs_cred *c, uint32_t odir, const char *oname, size_t olen, uint32_t ndir,
                  const char *nname, size_t nlen, int replace)
{
    sfs_stat_t odst, ndst, sst, tst;
    uint32_t tino;
    int rc = may_delete(fs, c, odir, oname, olen, &odst, &sst);
    if (rc) return rc;
    rc = dir_check(fs, c, ndir, 1, &ndst);
    if (rc) return rc;
    rc = sfs_lookup(fs, ndir, nname, nlen, &tino, 0);
    if (rc == 0) {
        if (!replace) return SFS_EEXIST;
        rc = sfs_stat(fs, tino, &tst);
        if (!rc) rc = sticky_ok(c, &ndst, &tst);
        if (rc) return rc;
    } else if (rc != SFS_ENOENT) {
        return rc;
    }
    /* a directory moved to another parent gets its ".." rewritten: needs write on the directory itself */
    if ((sst.mode & SFS_S_IFMT) == SFS_S_IFDIR && odir != ndir) {
        rc = sfs_permission_st(c, &sst, SFS_MAY_WRITE);
        if (rc) return rc;
    }
    return sfs_rename(fs, odir, oname, olen, ndir, nname, nlen, replace);
}

int sfs_chmod_as(sfs_fs *fs, const sfs_cred *c, uint32_t ino, uint16_t mode)
{
    sfs_stat_t st;
    uint16_t perm = (uint16_t)(mode & 07777u);
    int rc = sfs_cred_check(c);
    if (!rc) rc = sfs_stat(fs, ino, &st);
    if (rc) return rc;
    if (c->uid != st.uid && !(c->caps & SFS_CAP_FOWNER)) return SFS_EPERM;
    if ((perm & S_ISGID_) && !sfs_cred_in_group(c, st.gid) && !(c->caps & SFS_CAP_FSETID))
        perm &= (uint16_t)~S_ISGID_;
    return sfs_set_mode(fs, ino, perm);
}

int sfs_chown_as(sfs_fs *fs, const sfs_cred *c, uint32_t ino, uint32_t uid, uint32_t gid)
{
    sfs_stat_t st;
    uint32_t nuid, ngid;
    uint16_t perm;
    int priv, rc = sfs_cred_check(c);
    if (!rc) rc = sfs_stat(fs, ino, &st);
    if (rc) return rc;
    priv = (c->caps & SFS_CAP_CHOWN) != 0;
    nuid = uid == SFS_ID_KEEP ? st.uid : uid;
    ngid = gid == SFS_ID_KEEP ? st.gid : gid;
    if (!priv) {
        if (c->uid != st.uid || nuid != st.uid) return SFS_EPERM;
        if (ngid != st.gid && !sfs_cred_in_group(c, ngid)) return SFS_EPERM;
    }
    perm = (uint16_t)(st.mode & 07777u);
    if ((st.mode & SFS_S_IFMT) != SFS_S_IFDIR) {
        perm &= (uint16_t)~S_ISUID_;
        if (perm & 010u) perm &= (uint16_t)~S_ISGID_;
    }
    return sfs_set_owner(fs, ino, nuid, ngid, perm);
}
