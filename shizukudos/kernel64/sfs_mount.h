/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 ShizukuFS mount services (sfs_mount.c) for other kernel components: the installed system volume and the
 * atomic record store used for account/credential persistence. Return values are 0 or a negative SFS_* code from
 * shizukufs/v1/libsfs/sfs.h; SFSK_ENOVOL when the path names no mounted read/write ShizukuFS volume.
 */
#ifndef K64_SFS_MOUNT_H
#define K64_SFS_MOUNT_H
#include "fs.h"
#include "blk.h"

#define SFSK_ENOVOL (-100)
#define SFSK_ACCOUNT_DIR "\\SHZ\\ACCOUNTS"     /* default record directory on the installed system volume */
#define SFSK_RECORD_MAX 65536u                  /* = SFS_RECORD_MAX */

int sfs_probe_all(blk_dev_t *skip);             /* disk.c, after the partition scan */
/* Explicit mount of one device (e.g. the system partition after the installer wrote it; the interactive installer
 * profile skips automatic mounting). Returns the drive letter, 0 when it was not mounted. */
char sfsk_mount_device(blk_dev_t *d);
/* Drive letter of the installed system volume (a ShizukuFS volume whose root holds SHZ\SETUP, as the project
 * installer lays it out), 0 when none; *writable (optional) = 1 when it is mounted read/write. */
char sfsk_system_volume(int *writable);

/* Atomic record store (libsfs sfs_record.c protocol: staged write, sync, readback, journaled rename, sync, readback).
 * dir_path: "X:\DIR\SUB" on a ShizukuFS volume, or NULL / "" for SFSK_ACCOUNT_DIR on the system volume; put creates
 * missing directories (mode 0700). name: one component, no '\' or '/', not starting with '.', not ending ".~nw".
 * The record directory is walled off from every fs.c path (fs_policy.h) once the store touches it. */
int sfsk_record_put(const char *dir_path, const char *name, const void *data, uint32_t len, uint64_t *seq);
int sfsk_record_get(const char *dir_path, const char *name, void *buf, uint32_t cap, uint32_t *len, uint64_t *seq);
int sfsk_record_delete(const char *dir_path, const char *name);
#endif
