/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 file access policy hooks (fs.c). Every name-space access path in fs.c -- fs_read, fs_write, fs_truncate,
 * fs_create (checked on the parent directory), fs_remove, fs_rename (source node and destination directory) and the
 * enumeration of disk directories (fs_populate) -- asks the registered policies first; any policy returning nonzero
 * refuses the operation (fs.c reports it as -1 / NULL / not deleted, like a read-only node). Policies run without fs
 * locks, must not sleep on file-system locks and must not call back into fs.c.
 *
 * ShizukuFS (sfs_mount.c) registers one policy that walls off the record-store directories (account/credential
 * persistence): no fs.c path can read, list, modify, delete or rename into them; only the kernel record API
 * (sfsk_record_*) reaches their contents. Candidate header: the parent may fold these lines into fs.h.
 */
#ifndef K64_FS_POLICY_H
#define K64_FS_POLICY_H
#include "fs.h"

enum { FS_OP_READ = 1, FS_OP_WRITE = 2, FS_OP_CREATE = 3, FS_OP_DELETE = 4, FS_OP_LIST = 5 };
#define FS_POLICY_MAX 4
typedef int (*fs_policy_fn)(const fsnode_t *n, unsigned op);     /* nonzero: refuse */
int fs_policy_register(fs_policy_fn fn);                           /* 0 = ok, -1 table full / NULL */
int fs_policy_denied(const fsnode_t *n, unsigned op);              /* nonzero when any policy refuses */
#endif
