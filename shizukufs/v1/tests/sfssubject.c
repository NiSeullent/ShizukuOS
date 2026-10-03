/* SPDX-License-Identifier: GPL-2.0-only
 * Host control for sfs_cred_from_subject(): account-authority subject shapes taken from
 * shizukudos/kernel64/sysk32_auth.c (anonymous 0x2000/0x4e7, login 0x2000, elevate 0x3000,
 * sandbox 0x1000+flag) mapped to credentials, then fed to the real sfs_permission_st()
 * decision. Pure policy; no kernel, no volume. */
#include <stdio.h>
#include <string.h>
#include "../libsfs/sfs_subject.h"

static unsigned checks, failures;
#define C(name, v) do { ++checks; if (!(v)) { ++failures; fprintf(stderr, "FAIL %s line %d\n", name, __LINE__); } } while (0)

static sfs_subject_in acct(uint32_t uid, uint32_t session, uint32_t integrity, uint32_t roles)
{
    sfs_subject_in s = {uid, session, integrity, roles, 0, 0, ((uint64_t)uid << 32) | session, 1};
    return s;
}
static int may(const sfs_cred *c, uint32_t mode, uint32_t uid, uint32_t gid, uint32_t mask)
{
    sfs_stat_t st; memset(&st, 0, sizeof st);
    st.mode = mode; st.uid = uid; st.gid = gid;
    return sfs_permission_st(c, &st, mask) == 0;
}
static int zeroed(const sfs_cred *c)
{
    const unsigned char *p = (const unsigned char *)c;
    for (unsigned i = 0; i < sizeof *c; i++) if (p[i]) return 0;
    return 1;
}

int main(void)
{
    sfs_cred c; sfs_subject_in s;
    /* development realm: anonymous kernel default subject, no accounts enrolled */
    s = (sfs_subject_in){0, 0, 0x2000, 0, 0, 0, 0x4e7, 0};
    C("dev realm maps", sfs_cred_from_subject(&s, &c) == 0 && c.uid == 0 && c.caps == SFS_CAP_ALL);
    /* same anonymous subject once accounts exist: refused, never guessed */
    s.accounts_active = 1;
    C("anonymous refused when active", sfs_cred_from_subject(&s, &c) == SFS_EACCES && zeroed(&c));
    /* login (medium) member */
    s = acct(1001, 3, 0x2000, 0);
    C("member maps", sfs_cred_from_subject(&s, &c) == 0 && c.uid == 1001 && c.gid == SFS_GID_USERS && !c.caps && !c.ngroups);
    C("member own file rw", may(&c, 0100600, 1001, 100, SFS_MAY_READ | SFS_MAY_WRITE));
    C("member other's private file denied", !may(&c, 0100600, 1002, 100, SFS_MAY_READ));
    C("member root-owned 0644 read only", may(&c, 0100644, 0, 0, SFS_MAY_READ) && !may(&c, 0100644, 0, 0, SFS_MAY_WRITE));
    /* administrator at medium integrity: group membership, no capabilities */
    s = acct(1000, 4, 0x2000, 1);
    C("medium admin maps", sfs_cred_from_subject(&s, &c) == 0 && c.ngroups == 1 && c.groups[0] == SFS_GID_ADMINS && !c.caps);
    C("medium admin cannot override", !may(&c, 0100600, 1001, 100, SFS_MAY_READ));
    C("admins group grant honoured", may(&c, 0100660, 0, SFS_GID_ADMINS, SFS_MAY_WRITE));
    /* elevated child (sysk32_auth shz_account_elevate: integrity 0x3000, admin) */
    s = acct(1000, 5, 0x3000, 1);
    C("elevated admin caps", sfs_cred_from_subject(&s, &c) == 0 && c.caps == SFS_CAP_ALL);
    C("elevated override", may(&c, 0100600, 1001, 100, SFS_MAY_READ | SFS_MAY_WRITE));
    s = acct(1001, 5, 0x3000, 0);
    C("high integrity non-admin refused", sfs_cred_from_subject(&s, &c) == SFS_EACCES && zeroed(&c));
    /* sandbox: kernel copies caller subject, integrity 0x1000, roles 0, flag */
    s = acct(1001, 3, 0x1000, 0); s.flags = SFS_SUBJ_FLAG_SANDBOX;
    C("sandbox maps to nobody", sfs_cred_from_subject(&s, &c) == 0 && c.uid == SFS_UID_SANDBOX && !c.caps && !c.ngroups);
    C("sandbox cannot write caller's file", !may(&c, 0100644, 1001, 100, SFS_MAY_WRITE));
    C("sandbox reads world-readable", may(&c, 0100644, 1001, 100, SFS_MAY_READ));
    s = (sfs_subject_in){0, 0, 0x1000, 0, SFS_SUBJ_FLAG_SANDBOX, 0, 0x4e7, 0};
    C("dev-realm sandbox still confined", sfs_cred_from_subject(&s, &c) == 0 && c.uid == SFS_UID_SANDBOX && !c.caps);
    s = acct(1000, 4, 0x1000, 1);
    C("lowered admin token confined", sfs_cred_from_subject(&s, &c) == 0 && c.uid == SFS_UID_SANDBOX && !c.caps);
    /* malformed / forged shapes */
    s = acct(1001, 3, 0x2000, 0); s.auth_id ^= 1;
    C("auth_id mismatch refused", sfs_cred_from_subject(&s, &c) == SFS_EACCES);
    s = acct(1001, 0, 0x2000, 0);
    C("no session refused", sfs_cred_from_subject(&s, &c) == SFS_EACCES);
    s = acct(1000 + SFS_ACCOUNT_SLOTS, 3, 0x2000, 0);
    C("uid beyond account table refused", sfs_cred_from_subject(&s, &c) == SFS_EACCES);
    s = acct(999, 3, 0x2000, 0);
    C("uid below account base refused", sfs_cred_from_subject(&s, &c) == SFS_EACCES);
    s = (sfs_subject_in){0xffffffffu, 0xffffffffu, 0x4000, 0, 0, 0, UINT64_MAX, 1};
    C("system integrity refused", sfs_cred_from_subject(&s, &c) == SFS_EACCES);
    s = acct(1001, 3, 0x2000, 2);
    C("unknown role refused", sfs_cred_from_subject(&s, &c) == SFS_EACCES);
    s = acct(1001, 3, 0x2000, 0); s.flags = 4;
    C("unknown flag refused", sfs_cred_from_subject(&s, &c) == SFS_EACCES);
    s = acct(1001, 3, 0x2000, 0); s.reserved = 1;
    C("reserved refused", sfs_cred_from_subject(&s, &c) == SFS_EACCES);
    C("null subject", sfs_cred_from_subject(NULL, &c) == SFS_EINVAL && zeroed(&c));
    C("null out", sfs_cred_from_subject(&s, NULL) == SFS_EINVAL);
    /* Kernel64 sfs_mount.c decisions (vol_create owner = requester, vol_write/vol_truncate need
     * MAY_WRITE, vol_read MAY_READ, vol_populate MAY_READ|MAY_EXEC on the directory), applied to the
     * credentials the mapper yields for two accounts and a sandboxed child of the first one. */
    {
        sfs_cred a, b, sb, dev;
        sfs_subject_in sa = acct(1001, 7, 0x2000, 0), sbb = acct(1002, 9, 0x2000, 0), ss = acct(1001, 8, 0x1000, 0);
        ss.flags = SFS_SUBJ_FLAG_SANDBOX;
        s = (sfs_subject_in){0, 0, 0x2000, 0, 0, 0, 0x4e7, 0};
        C("callsite map a", sfs_cred_from_subject(&sa, &a) == 0);
        C("callsite map b", sfs_cred_from_subject(&sbb, &b) == 0);
        C("callsite map sandbox", sfs_cred_from_subject(&ss, &sb) == 0);
        C("callsite map dev realm", sfs_cred_from_subject(&s, &dev) == 0 && dev.uid == 0);
        /* file created by a: 0644 owned by a.uid/a.gid */
        C("owner writes own file", may(&a, SFS_S_IFREG | 0644, a.uid, a.gid, SFS_MAY_WRITE));
        C("other account cannot write", !may(&b, SFS_S_IFREG | 0644, a.uid, a.gid, SFS_MAY_WRITE));
        C("other account reads 0644", may(&b, SFS_S_IFREG | 0644, a.uid, a.gid, SFS_MAY_READ));
        C("sandbox cannot write owner file", !may(&sb, SFS_S_IFREG | 0644, a.uid, a.gid, SFS_MAY_WRITE));
        C("dev realm keeps existing behaviour", may(&dev, SFS_S_IFREG | 0600, a.uid, a.gid, SFS_MAY_WRITE));
        /* private directory 0700 of a: listing / create by others refused */
        C("owner lists private dir", may(&a, SFS_S_IFDIR | 0700, a.uid, a.gid, SFS_MAY_READ | SFS_MAY_EXEC));
        C("other cannot list private dir", !may(&b, SFS_S_IFDIR | 0700, a.uid, a.gid, SFS_MAY_READ | SFS_MAY_EXEC));
        C("other cannot create in 0755 dir", !may(&b, SFS_S_IFDIR | 0755, a.uid, a.gid, SFS_MAY_WRITE | SFS_MAY_EXEC));
        C("sandbox cannot create in 0755 dir", !may(&sb, SFS_S_IFDIR | 0755, a.uid, a.gid, SFS_MAY_WRITE | SFS_MAY_EXEC));
        /* anonymous medium subject while accounts are active (the kernel default for an unbound
         * process) must be refused, not mapped to uid 0 */
        s.accounts_active = 1;
        C("anonymous while active refused", sfs_cred_from_subject(&s, &c) == SFS_EACCES && zeroed(&c));
    }
    printf("sfssubject: %u checks, %u failures (map v%u; host policy; Kernel64 caller sfs_mount.c task_cred)\n",
           checks, failures, SFS_SUBJECT_MAP_VERSION);
    return failures ? 1 : 0;
}
