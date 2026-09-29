/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 volume mount table: which file system serves which drive letter, on which block device.
 *
 * fs.c keeps the name space (drive letter -> root fsnode); this table adds what the name space does not need to
 * know: the file-system type, the device, and a flush/shutdown hook per volume. A volume registered here gets the
 * next free letter from D: on, and vfs_shutdown() (called on the normal-exit path) and vfs_flush_all() commit and
 * flush every registered volume so write-back file systems (ShizukuFS) leave their media clean.
 */
#ifndef K64_VFS_MOUNTS_H
#define K64_VFS_MOUNTS_H
#include "fs.h"

#define VFS_MAX_MOUNTS 16

typedef struct vfs_mount {
    char letter;                    /* 'D' ... 'Z' */
    char fstype[12];                /* "shizukufs", ... */
    char device[16];                /* block device name, e.g. "ahci0p2" */
    fsvol_t *vol;
    fsnode_t *root;
    int (*shutdown)(fsvol_t *v);    /* commit + flush + leave the media clean; NULL: vol->flush */
} vfs_mount_t;

/* Mounts `root` at the next free drive letter (D: .. Z:) and records it. Returns the letter, or 0 when none is free. */
char vfs_mount_next(fsnode_t *root, fsvol_t *vol, const char *fstype, const char *device, int (*shutdown)(fsvol_t *));
const vfs_mount_t *vfs_mount_by_device(const char *device);   /* NULL when that device is not mounted through here */
const vfs_mount_t *vfs_mount_at(unsigned index);                /* NULL past the end */
unsigned vfs_mount_count(void);
int vfs_flush_all(void);            /* 0 when every volume flushed */
void vfs_shutdown(void);            /* normal exit: shutdown hook of every volume (skips a volume whose lock is held) */
#endif
