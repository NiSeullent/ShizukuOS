/* SPDX-License-Identifier: GPL-2.0-only
 * Account subject -> sfs_cred mapping; policy documented in sfs_subject.h. */
#include "sfs_subject.h"

static void clear(sfs_cred *c)
{
    unsigned char *p = (unsigned char *)c;
    for (unsigned i = 0; i < sizeof *c; i++) p[i] = 0;
}

int sfs_cred_from_subject(const sfs_subject_in *s, sfs_cred *out)
{
    if (!out) return SFS_EINVAL;
    clear(out);
    if (!s) return SFS_EINVAL;
    if (s->reserved || (s->flags & ~SFS_SUBJ_FLAG_SANDBOX) || (s->roles & ~SFS_SUBJ_ROLE_ADMIN))
        return SFS_EACCES;
    if (!s->accounts_active && !s->flags) {
        /* Development realm: same answer as the kernel's own node authorization. */
        out->caps = SFS_CAP_ALL;
        return 0;
    }
    if ((s->flags & SFS_SUBJ_FLAG_SANDBOX) || s->integrity < SFS_SUBJ_INTEGRITY_MEDIUM) {
        out->uid = out->gid = SFS_UID_SANDBOX;
        return 0;
    }
    if (s->uid < SFS_UID_ACCOUNT_BASE || s->uid - SFS_UID_ACCOUNT_BASE >= SFS_ACCOUNT_SLOTS || !s->session ||
        s->auth_id != (((uint64_t)s->uid << 32) | s->session))
        return SFS_EACCES;
    if (s->integrity != SFS_SUBJ_INTEGRITY_MEDIUM && s->integrity != SFS_SUBJ_INTEGRITY_HIGH)
        return SFS_EACCES;
    if (s->integrity == SFS_SUBJ_INTEGRITY_HIGH && s->roles != SFS_SUBJ_ROLE_ADMIN)
        return SFS_EACCES;                /* the account authority only elevates administrators */
    out->uid = s->uid;
    out->gid = SFS_GID_USERS;
    if (s->roles & SFS_SUBJ_ROLE_ADMIN) {
        out->groups[0] = SFS_GID_ADMINS;
        out->ngroups = 1;
        if (s->integrity == SFS_SUBJ_INTEGRITY_HIGH) out->caps = SFS_CAP_ALL;
    }
    return 0;
}
