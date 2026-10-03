/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS v1 ownership and access checks.
 *
 * libsfs itself (sfs.h) is a mechanism layer: it never looks at i_uid/i_gid/i_mode bits, so a caller that uses it
 * directly runs with full authority. This module is the policy layer a multi-user caller (Kernel64 file service,
 * host tools acting for a named user) puts in front of it. The rules are the POSIX/ext4 discretionary access rules
 * the on-disk format was designed for, so a volume shared with Linux keeps the same meaning:
 *
 *   - exactly one class applies: owner (cred uid == i_uid), else group (i_gid is the cred's primary or a
 *     supplementary group), else other; a more permissive "other" never widens a matching owner/group class;
 *   - every directory traversed needs search (x); creating/removing/renaming entries needs w+x on the directory;
 *   - a sticky (S_ISVTX) directory allows removing/replacing an entry only for the entry's owner, the directory's
 *     owner or SFS_CAP_FOWNER;
 *   - new inodes are owned by the credential's uid; their gid is the parent's gid when the parent has S_ISGID
 *     (directories then inherit S_ISGID), else the credential's gid;
 *   - chmod needs ownership or SFS_CAP_FOWNER; chown of the uid needs SFS_CAP_CHOWN, chown of the gid needs
 *     ownership plus membership in the new group (or SFS_CAP_CHOWN); a chown of a non-directory by anybody clears
 *     S_ISUID and (if group-executable) S_ISGID.
 *
 * Capabilities are explicit bits in the credential; uid 0 has no implicit power here. Who receives which bits is
 * decided by the account/elevation authority (not this module).
 *
 * Crash ordering: a checked create writes the new inode with uid 0, gid 0 and permission bits 0000 first and sets
 * the caller's owner/mode in the same libsfs operation. Both land in the same jbd2 transaction unless the
 * transaction reaches its commit threshold in between; in that case a crash can leave a root-owned 0000 entry
 * (fail closed, removable by an administrator), never a file readable or writable by a wrong user.
 */
#ifndef SFS_ACCESS_H
#define SFS_ACCESS_H
#include "sfs.h"

#define SFS_CRED_NGROUPS 32u

#define SFS_CAP_DAC_OVERRIDE 0x1u      /* bypass r/w checks; x on files only if some x bit is set */
#define SFS_CAP_DAC_READ_SEARCH 0x2u   /* bypass read on files and read/search on directories */
#define SFS_CAP_FOWNER 0x4u            /* act as owner for chmod/set_times/sticky removal */
#define SFS_CAP_CHOWN 0x8u             /* change uid/gid arbitrarily */
#define SFS_CAP_FSETID 0x10u           /* keep S_ISGID on create/chmod without group membership */
#define SFS_CAP_ALL 0x1Fu

typedef struct sfs_cred {
    uint32_t uid, gid;
    uint32_t ngroups;                           /* <= SFS_CRED_NGROUPS */
    uint32_t groups[SFS_CRED_NGROUPS];          /* supplementary groups */
    uint32_t caps;                              /* SFS_CAP_* */
} sfs_cred;

#define SFS_MAY_EXEC 1u
#define SFS_MAY_WRITE 2u
#define SFS_MAY_READ 4u

#define SFS_O_READ 0x01u
#define SFS_O_WRITE 0x02u
#define SFS_O_CREATE 0x04u
#define SFS_O_EXCL 0x08u
#define SFS_O_TRUNC 0x10u
#define SFS_O_DIRECTORY 0x20u                   /* the target must be a directory */

#define SFS_ID_KEEP 0xFFFFFFFFu                 /* sfs_chown_as: leave this id unchanged */

/* SFS_EINVAL for a malformed credential (too many groups). */
int sfs_cred_check(const sfs_cred *c);
int sfs_cred_in_group(const sfs_cred *c, uint32_t gid);

/* Pure decision over an already-read inode (mode, uid, gid): 0 or SFS_EACCES. `mask` is SFS_MAY_*. */
int sfs_permission_st(const sfs_cred *c, const sfs_stat_t *st, uint32_t mask);
/* The same against the inode on the volume. */
int sfs_permission(sfs_fs *fs, const sfs_cred *c, uint32_t ino, uint32_t mask);

/* Resolves an absolute '/'-separated path, requiring search permission on every directory traversed (the leaf
 * itself is not checked). Symlinks are not followed. Same outputs as sfs_path_lookup; *ino is valid only on 0,
 * *parent/leaf whenever the parent was reached (also on SFS_ENOENT for the leaf, so the caller can create it). */
int sfs_walk_as(sfs_fs *fs, const sfs_cred *c, const char *path, uint32_t *ino, uint32_t *parent,
                const char **leaf, size_t *leaf_len);

/* Opens (and with SFS_O_CREATE creates) `name` in `dir` for `c`. The caller must already hold search permission
 * on the path up to `dir` (sfs_walk_as). `mode` holds the permission bits for a new file (caller applies umask).
 * Write intent on a directory is SFS_EISDIR; a symlink leaf is SFS_ENOTSUP (no following at this layer). */
int sfs_open_as(sfs_fs *fs, const sfs_cred *c, uint32_t dir, const char *name, size_t len, uint32_t oflags,
                uint16_t mode, uint32_t *ino);
int sfs_mkdir_as(sfs_fs *fs, const sfs_cred *c, uint32_t dir, const char *name, size_t len, uint16_t mode,
                 uint32_t *ino);
int sfs_unlink_as(sfs_fs *fs, const sfs_cred *c, uint32_t dir, const char *name, size_t len);
int sfs_rmdir_as(sfs_fs *fs, const sfs_cred *c, uint32_t dir, const char *name, size_t len);
int sfs_rename_as(sfs_fs *fs, const sfs_cred *c, uint32_t odir, const char *oname, size_t olen, uint32_t ndir,
                  const char *nname, size_t nlen, int replace);
int sfs_chmod_as(sfs_fs *fs, const sfs_cred *c, uint32_t ino, uint16_t mode);
int sfs_chown_as(sfs_fs *fs, const sfs_cred *c, uint32_t ino, uint32_t uid, uint32_t gid);

/* Mechanism (no policy): set uid, gid and permission bits of `ino` in one journaled inode update. */
int sfs_set_owner(sfs_fs *fs, uint32_t ino, uint32_t uid, uint32_t gid, uint16_t mode);
#endif
