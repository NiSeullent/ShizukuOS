/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS: map an authenticated ShizukuCore account subject to an sfs_cred.
 *
 * Input is a plain copy of the kernel's shz_subject fields (shizukudos/accounts/account.h)
 * plus the authority's "accounts active" bit, as returned by the 74b0 account authority.
 * libsfs does not include kernel headers and never derives identity itself: a caller that
 * cannot obtain an authority-produced subject must not call this and must refuse the I/O.
 *
 * Mapping (version SFS_SUBJECT_MAP_VERSION):
 *   - development realm (authority has no accounts, subject carries no flags): uid 0/gid 0,
 *     SFS_CAP_ALL. This mirrors shz_auth_node_access(), which allows everything there, and
 *     the current Kernel64 behaviour; it is not a security boundary.
 *   - sandbox subject (SHZ_SUBJECT_SANDBOX flag or integrity below medium): uid/gid
 *     SFS_UID_SANDBOX, no groups, no capabilities (only world-accessible objects).
 *   - account subject (uid in [SFS_UID_ACCOUNT_BASE, +SFS_ACCOUNT_SLOTS), nonzero session,
 *     auth_id == uid<<32|session): uid = account uid, gid = SFS_GID_USERS; administrators
 *     additionally get SFS_GID_ADMINS as a supplementary group. Capabilities only when the
 *     subject is a high-integrity administrator (elevated child), never at medium integrity.
 *   - anything else (anonymous subject while accounts are active, system/unknown integrity,
 *     unknown flags/roles, inconsistent auth_id): SFS_EACCES. Never guessed.
 */
#ifndef SFS_SUBJECT_H
#define SFS_SUBJECT_H
#include "sfs_access.h"

#define SFS_SUBJECT_MAP_VERSION 1u
#define SFS_UID_ACCOUNT_BASE 1000u
#define SFS_ACCOUNT_SLOTS 16u            /* == SHZ_ACCOUNT_LIMIT */
#define SFS_UID_SANDBOX 65534u
#define SFS_GID_USERS 100u
#define SFS_GID_ADMINS 544u              /* BUILTIN\Administrators RID, as a POSIX gid */
#define SFS_SUBJ_ROLE_ADMIN 1u           /* == SHZ_ROLE_ADMIN */
#define SFS_SUBJ_FLAG_SANDBOX 1u         /* == SHZ_SUBJECT_SANDBOX */
#define SFS_SUBJ_INTEGRITY_LOW 0x1000u
#define SFS_SUBJ_INTEGRITY_MEDIUM 0x2000u
#define SFS_SUBJ_INTEGRITY_HIGH 0x3000u

typedef struct sfs_subject_in {
    uint32_t uid, session, integrity, roles, flags, reserved;
    uint64_t auth_id;
    uint32_t accounts_active;            /* authority has at least one enrolled account */
} sfs_subject_in;

/* 0 and *out filled, or SFS_EACCES / SFS_EINVAL with *out zeroed. */
int sfs_cred_from_subject(const sfs_subject_in *s, sfs_cred *out);
#endif
