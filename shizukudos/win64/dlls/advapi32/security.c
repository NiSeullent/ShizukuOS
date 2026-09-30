/* SPDX-License-Identifier: GPL-2.0-only
 * advapi32.dll: access-control lists and security descriptors as data (the documented binary formats), SDDL in both
 * directions, and the trustee / explicit-access helpers (SetEntriesInAcl, BuildSecurityDescriptor).
 *
 * These functions only build, inspect and convert structures; nothing here claims that Kernel64 enforces access control
 * (it does not: see objsec.c). Supported ACE types: ACCESS_ALLOWED, ACCESS_DENIED, SYSTEM_AUDIT, SYSTEM_MANDATORY_LABEL
 * (and the callback/object forms are carried through AddAce/GetAce/DeleteAce unchanged). SDDL: owner, group, DACL and
 * SACL with the flags P, AI, AR, NO_ACCESS_CONTROL; ACE types A, D, AU, ML; ACE flags CI OI NP IO ID SA FA; rights as
 * hexadecimal or the two-letter codes; SIDs as strings or the fixed-value abbreviations of sid.c. Conditional ACEs
 * (AddConditionalAce, "XA"/"XD") need an expression compiler that is not provided: they fail with ERROR_NOT_SUPPORTED /
 * ERROR_INVALID_PARAMETER.
 */
#define _ADVAPI32_
#include "nt.h"
#include <string.h>
#include <sddl.h>
#include <securitybaseapi.h>
#include <aclapi.h>
#include "sec_int.h"

/* ---------------------------------------------------------------- ACL */
DLLAPI BOOL WINAPI InitializeAcl(PACL acl, DWORD len, DWORD rev)
{
    if (!acl || len < sizeof(ACL) || len > 0xffff || (rev != ACL_REVISION && rev != ACL_REVISION_DS)) {
        shz_set_last_error(len < sizeof(ACL) ? ERROR_INSUFFICIENT_BUFFER : ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    acl->AclRevision = (BYTE)rev;
    acl->Sbz1 = 0;
    acl->AclSize = (WORD)(len & ~3u);
    acl->AceCount = 0;
    acl->Sbz2 = 0;
    return TRUE;
}

/* Bytes used by the header and the ACEs; 0 when the ACL is malformed. */
DWORD sec_acl_used(const ACL *acl)
{
    const BYTE *p = (const BYTE *)(acl + 1), *end = (const BYTE *)acl + acl->AclSize;
    WORD i;
    for (i = 0; i < acl->AceCount; ++i) {
        const ACE_HEADER *h = (const ACE_HEADER *)p;
        if (p + sizeof *h > end || h->AceSize < sizeof *h || (h->AceSize & 3) || p + h->AceSize > end) return 0;
        p += h->AceSize;
    }
    return (DWORD)(p - (const BYTE *)acl);
}

DLLAPI BOOL WINAPI IsValidAcl(PACL acl)
{
    if (!acl || (acl->AclRevision != ACL_REVISION && acl->AclRevision != ACL_REVISION_DS) || acl->AclSize < sizeof(ACL)) return FALSE;
    return sec_acl_used(acl) != 0;
}

DLLAPI BOOL WINAPI GetAclInformation(PACL acl, LPVOID info, DWORD len, ACL_INFORMATION_CLASS cls)
{
    if (!IsValidAcl(acl)) { shz_set_last_error(ERROR_INVALID_ACL); return FALSE; }
    if (cls == AclRevisionInformation) {
        if (len < sizeof(ACL_REVISION_INFORMATION)) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        ((ACL_REVISION_INFORMATION *)info)->AclRevision = acl->AclRevision;
        return TRUE;
    }
    if (cls == AclSizeInformation) {
        ACL_SIZE_INFORMATION *s = info;
        const DWORD used = sec_acl_used(acl);
        if (len < sizeof *s) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        s->AceCount = acl->AceCount;
        s->AclBytesInUse = used;
        s->AclBytesFree = acl->AclSize - used;
        return TRUE;
    }
    shz_set_last_error(ERROR_INVALID_PARAMETER);
    return FALSE;
}

static BYTE *ace_at(const ACL *acl, DWORD index)
{
    BYTE *p = (BYTE *)(acl + 1);
    DWORD i;
    for (i = 0; i < index; ++i) p += ((ACE_HEADER *)p)->AceSize;
    return p;
}

DLLAPI BOOL WINAPI GetAce(PACL acl, DWORD index, LPVOID *ace)
{
    if (!IsValidAcl(acl) || index >= acl->AceCount) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    *ace = ace_at(acl, index);
    return TRUE;
}

DLLAPI BOOL WINAPI FindFirstFreeAce(PACL acl, LPVOID *ace)
{
    const DWORD used = acl ? sec_acl_used(acl) : 0;
    if (!used) { shz_set_last_error(ERROR_INVALID_ACL); *ace = 0; return FALSE; }
    *ace = (BYTE *)acl + used;
    return TRUE;
}

/* Inserts `len` bytes of ACEs (count ACEs) before ACE `start` (MAXDWORD = at the end). */
static BOOL insert_aces(PACL acl, DWORD start, const void *aces, DWORD len, DWORD count)
{
    const DWORD used = sec_acl_used(acl);
    BYTE *at;
    if (!used) { shz_set_last_error(ERROR_INVALID_ACL); return FALSE; }
    if (used + len > acl->AclSize) { shz_set_last_error(ERROR_ALLOTTED_SPACE_EXCEEDED); return FALSE; }
    if (start > acl->AceCount) start = acl->AceCount;
    at = ace_at(acl, start);
    memmove(at + len, at, (size_t)((BYTE *)acl + used - at));
    memcpy(at, aces, len);
    acl->AceCount = (WORD)(acl->AceCount + count);
    return TRUE;
}

DLLAPI BOOL WINAPI AddAce(PACL acl, DWORD rev, DWORD start, LPVOID list, DWORD len)
{
    const BYTE *p = list, *end = (const BYTE *)list + len;
    DWORD count = 0;
    (void)rev;
    if (!IsValidAcl(acl)) { shz_set_last_error(ERROR_INVALID_ACL); return FALSE; }
    while (p < end) {
        const ACE_HEADER *h = (const ACE_HEADER *)p;
        if (h->AceSize < sizeof *h || p + h->AceSize > end) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
        if (h->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE || h->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE) acl->AclRevision = ACL_REVISION_DS;
        p += h->AceSize;
        ++count;
    }
    return insert_aces(acl, start, list, len, count);
}

DLLAPI BOOL WINAPI DeleteAce(PACL acl, DWORD index)
{
    const DWORD used = acl ? sec_acl_used(acl) : 0;
    BYTE *at;
    WORD size;
    if (!used || index >= acl->AceCount) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    at = ace_at(acl, index);
    size = ((ACE_HEADER *)at)->AceSize;
    memmove(at, at + size, (size_t)((BYTE *)acl + used - at - size));
    --acl->AceCount;
    return TRUE;
}

/* ACE of the simple form {header, mask, SID}. */
BOOL sec_add_simple_ace(PACL acl, BYTE type, BYTE flags, DWORD mask, PSID sid, DWORD start)
{
    BYTE buf[8 + 8 + 4 * SID_MAX_SUB_AUTHORITIES];
    ACE_HEADER *h = (ACE_HEADER *)buf;
    DWORD sl;
    if (!IsValidSid(sid)) { shz_set_last_error(ERROR_INVALID_SID); return FALSE; }
    sl = GetLengthSid(sid);
    h->AceType = type;
    h->AceFlags = flags;
    h->AceSize = (WORD)(8 + sl);
    memcpy(buf + 4, &mask, 4);
    memcpy(buf + 8, sid, sl);
    return insert_aces(acl, start, buf, h->AceSize, 1);
}

#define ACE_FLAGS_VALID (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE | INHERITED_ACE | \
                         SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG)

DLLAPI BOOL WINAPI AddAccessAllowedAce(PACL acl, DWORD rev, DWORD mask, PSID sid)
{
    (void)rev;
    return sec_add_simple_ace(acl, ACCESS_ALLOWED_ACE_TYPE, 0, mask, sid, MAXDWORD);
}
DLLAPI BOOL WINAPI AddAccessAllowedAceEx(PACL acl, DWORD rev, DWORD flags, DWORD mask, PSID sid)
{
    (void)rev;
    if (flags & ~ACE_FLAGS_VALID) { shz_set_last_error(ERROR_INVALID_FLAGS); return FALSE; }
    return sec_add_simple_ace(acl, ACCESS_ALLOWED_ACE_TYPE, (BYTE)flags, mask, sid, MAXDWORD);
}
DLLAPI BOOL WINAPI AddAccessDeniedAce(PACL acl, DWORD rev, DWORD mask, PSID sid)
{
    (void)rev;
    return sec_add_simple_ace(acl, ACCESS_DENIED_ACE_TYPE, 0, mask, sid, MAXDWORD);
}
DLLAPI BOOL WINAPI AddAccessDeniedAceEx(PACL acl, DWORD rev, DWORD flags, DWORD mask, PSID sid)
{
    (void)rev;
    if (flags & ~ACE_FLAGS_VALID) { shz_set_last_error(ERROR_INVALID_FLAGS); return FALSE; }
    return sec_add_simple_ace(acl, ACCESS_DENIED_ACE_TYPE, (BYTE)flags, mask, sid, MAXDWORD);
}
DLLAPI BOOL WINAPI AddAuditAccessAceEx(PACL acl, DWORD rev, DWORD flags, DWORD mask, PSID sid, BOOL success, BOOL failure)
{
    (void)rev;
    if (flags & ~ACE_FLAGS_VALID) { shz_set_last_error(ERROR_INVALID_FLAGS); return FALSE; }
    flags |= (success ? SUCCESSFUL_ACCESS_ACE_FLAG : 0) | (failure ? FAILED_ACCESS_ACE_FLAG : 0);
    return sec_add_simple_ace(acl, SYSTEM_AUDIT_ACE_TYPE, (BYTE)flags, mask, sid, MAXDWORD);
}
DLLAPI BOOL WINAPI AddAuditAccessAce(PACL acl, DWORD rev, DWORD mask, PSID sid, BOOL success, BOOL failure)
{
    return AddAuditAccessAceEx(acl, rev, 0, mask, sid, success, failure);
}
/* A mandatory label: `policy` is SYSTEM_MANDATORY_LABEL_NO_WRITE_UP / NO_READ_UP / NO_EXECUTE_UP, `label` an S-1-16-x SID. */
DLLAPI BOOL WINAPI AddMandatoryAce(PACL acl, DWORD rev, DWORD flags, DWORD policy, PSID label)
{
    const SID *s = label;
    (void)rev;
    if (flags & ~ACE_FLAGS_VALID) { shz_set_last_error(ERROR_INVALID_FLAGS); return FALSE; }
    if (policy & ~7u) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!IsValidSid(label) || s->IdentifierAuthority.Value[5] != 16 || s->SubAuthorityCount != 1) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return sec_add_simple_ace(acl, SYSTEM_MANDATORY_LABEL_ACE_TYPE, (BYTE)flags, policy, label, MAXDWORD);
}
DLLAPI BOOL WINAPI AddConditionalAce(PACL acl, DWORD rev, DWORD flags, UCHAR type, DWORD mask, PSID sid, PWCHAR condition, DWORD *ret)
{
    (void)acl; (void)rev; (void)flags; (void)type; (void)mask; (void)sid; (void)condition; (void)ret;
    return sec_unsupported("AddConditionalAce", "conditional-expression ACEs need an expression compiler", ERROR_NOT_SUPPORTED);
}

/* ---------------------------------------------------------------- security descriptors */
DLLAPI BOOL WINAPI InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR psd, DWORD rev)
{
    SECURITY_DESCRIPTOR *sd = psd;
    if (rev != SECURITY_DESCRIPTOR_REVISION) { shz_set_last_error(ERROR_UNKNOWN_REVISION); return FALSE; }
    memset(sd, 0, sizeof *sd);
    sd->Revision = SECURITY_DESCRIPTOR_REVISION;
    return TRUE;
}

/* Parts of any descriptor, absolute or self-relative. */
void sec_parts(PSECURITY_DESCRIPTOR psd, sec_parts_t *o)
{
    const SECURITY_DESCRIPTOR *sd = psd;
    memset(o, 0, sizeof *o);
    o->control = sd->Control;
    if (sd->Control & SE_SELF_RELATIVE) {
        const SECURITY_DESCRIPTOR_RELATIVE *r = psd;
        o->owner = r->Owner ? (PSID)((BYTE *)psd + r->Owner) : 0;
        o->group = r->Group ? (PSID)((BYTE *)psd + r->Group) : 0;
        o->sacl = (r->Control & SE_SACL_PRESENT) && r->Sacl ? (PACL)((BYTE *)psd + r->Sacl) : 0;
        o->dacl = (r->Control & SE_DACL_PRESENT) && r->Dacl ? (PACL)((BYTE *)psd + r->Dacl) : 0;
    } else {
        o->owner = sd->Owner;
        o->group = sd->Group;
        o->sacl = (sd->Control & SE_SACL_PRESENT) ? sd->Sacl : 0;
        o->dacl = (sd->Control & SE_DACL_PRESENT) ? sd->Dacl : 0;
    }
}

DLLAPI BOOL WINAPI IsValidSecurityDescriptor(PSECURITY_DESCRIPTOR psd)
{
    sec_parts_t p;
    if (!psd || ((SECURITY_DESCRIPTOR *)psd)->Revision != SECURITY_DESCRIPTOR_REVISION) { shz_set_last_error(ERROR_INVALID_SECURITY_DESCR); return FALSE; }
    sec_parts(psd, &p);
    if ((p.owner && !IsValidSid(p.owner)) || (p.group && !IsValidSid(p.group)) || (p.dacl && !IsValidAcl(p.dacl)) ||
        (p.sacl && !IsValidAcl(p.sacl))) {
        shz_set_last_error(ERROR_INVALID_SECURITY_DESCR);
        return FALSE;
    }
    return TRUE;
}

static DWORD acl_len(const ACL *a) { return a ? a->AclSize : 0; }
static DWORD sid_len_or0(PSID s) { return s ? GetLengthSid(s) : 0; }

DLLAPI DWORD WINAPI GetSecurityDescriptorLength(PSECURITY_DESCRIPTOR psd)
{
    sec_parts_t p;
    sec_parts(psd, &p);
    return (DWORD)sizeof(SECURITY_DESCRIPTOR_RELATIVE) + sid_len_or0(p.owner) + sid_len_or0(p.group) + acl_len(p.dacl) + acl_len(p.sacl);
}

DLLAPI BOOL WINAPI GetSecurityDescriptorControl(PSECURITY_DESCRIPTOR psd, PSECURITY_DESCRIPTOR_CONTROL control, LPDWORD rev)
{
    const SECURITY_DESCRIPTOR *sd = psd;
    *rev = sd->Revision;
    *control = sd->Control;
    if (sd->Revision != SECURITY_DESCRIPTOR_REVISION) { shz_set_last_error(ERROR_UNKNOWN_REVISION); return FALSE; }
    return TRUE;
}

DLLAPI BOOL WINAPI SetSecurityDescriptorControl(PSECURITY_DESCRIPTOR psd, SECURITY_DESCRIPTOR_CONTROL mask, SECURITY_DESCRIPTOR_CONTROL bits)
{
    const SECURITY_DESCRIPTOR_CONTROL settable = SE_DACL_AUTO_INHERIT_REQ | SE_SACL_AUTO_INHERIT_REQ | SE_DACL_AUTO_INHERITED |
                                                 SE_SACL_AUTO_INHERITED | SE_DACL_PROTECTED | SE_SACL_PROTECTED | SE_RM_CONTROL_VALID;
    SECURITY_DESCRIPTOR *sd = psd;
    if ((mask | bits) & ~settable) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    sd->Control = (SECURITY_DESCRIPTOR_CONTROL)((sd->Control & ~mask) | (bits & mask));
    return TRUE;
}

#define ABS_ONLY(sd) do { if (((SECURITY_DESCRIPTOR *)(sd))->Control & SE_SELF_RELATIVE) { \
    shz_set_last_error(ERROR_INVALID_SECURITY_DESCR); return FALSE; } } while (0)

DLLAPI BOOL WINAPI SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR psd, BOOL present, PACL dacl, BOOL defaulted)
{
    SECURITY_DESCRIPTOR *sd = psd;
    ABS_ONLY(sd);
    sd->Control &= ~(SE_DACL_PRESENT | SE_DACL_DEFAULTED);
    sd->Dacl = present ? dacl : 0;
    if (present) sd->Control |= SE_DACL_PRESENT | (defaulted ? SE_DACL_DEFAULTED : 0);
    return TRUE;
}
DLLAPI BOOL WINAPI SetSecurityDescriptorSacl(PSECURITY_DESCRIPTOR psd, BOOL present, PACL sacl, BOOL defaulted)
{
    SECURITY_DESCRIPTOR *sd = psd;
    ABS_ONLY(sd);
    sd->Control &= ~(SE_SACL_PRESENT | SE_SACL_DEFAULTED);
    sd->Sacl = present ? sacl : 0;
    if (present) sd->Control |= SE_SACL_PRESENT | (defaulted ? SE_SACL_DEFAULTED : 0);
    return TRUE;
}
DLLAPI BOOL WINAPI SetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR psd, PSID owner, BOOL defaulted)
{
    SECURITY_DESCRIPTOR *sd = psd;
    ABS_ONLY(sd);
    sd->Owner = owner;
    sd->Control = (SECURITY_DESCRIPTOR_CONTROL)((sd->Control & ~SE_OWNER_DEFAULTED) | (defaulted ? SE_OWNER_DEFAULTED : 0));
    return TRUE;
}
DLLAPI BOOL WINAPI SetSecurityDescriptorGroup(PSECURITY_DESCRIPTOR psd, PSID group, BOOL defaulted)
{
    SECURITY_DESCRIPTOR *sd = psd;
    ABS_ONLY(sd);
    sd->Group = group;
    sd->Control = (SECURITY_DESCRIPTOR_CONTROL)((sd->Control & ~SE_GROUP_DEFAULTED) | (defaulted ? SE_GROUP_DEFAULTED : 0));
    return TRUE;
}
DLLAPI BOOL WINAPI GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR psd, LPBOOL present, PACL *dacl, LPBOOL defaulted)
{
    sec_parts_t p;
    sec_parts(psd, &p);
    *present = (p.control & SE_DACL_PRESENT) != 0;
    *dacl = p.dacl;
    *defaulted = (p.control & SE_DACL_DEFAULTED) != 0;
    return TRUE;
}
DLLAPI BOOL WINAPI GetSecurityDescriptorSacl(PSECURITY_DESCRIPTOR psd, LPBOOL present, PACL *sacl, LPBOOL defaulted)
{
    sec_parts_t p;
    sec_parts(psd, &p);
    *present = (p.control & SE_SACL_PRESENT) != 0;
    *sacl = p.sacl;
    *defaulted = (p.control & SE_SACL_DEFAULTED) != 0;
    return TRUE;
}
DLLAPI BOOL WINAPI GetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR psd, PSID *owner, LPBOOL defaulted)
{
    sec_parts_t p;
    sec_parts(psd, &p);
    *owner = p.owner;
    *defaulted = (p.control & SE_OWNER_DEFAULTED) != 0;
    return TRUE;
}
DLLAPI BOOL WINAPI GetSecurityDescriptorGroup(PSECURITY_DESCRIPTOR psd, PSID *group, LPBOOL defaulted)
{
    sec_parts_t p;
    sec_parts(psd, &p);
    *group = p.group;
    *defaulted = (p.control & SE_GROUP_DEFAULTED) != 0;
    return TRUE;
}

/* Writes a self-relative descriptor of the given parts into out (need bytes); returns the size. */
DWORD sec_build_relative(const sec_parts_t *p, void *out, DWORD cap)
{
    const DWORD need = (DWORD)sizeof(SECURITY_DESCRIPTOR_RELATIVE) + sid_len_or0(p->owner) + sid_len_or0(p->group) +
                       acl_len(p->sacl) + acl_len(p->dacl);
    SECURITY_DESCRIPTOR_RELATIVE *r = out;
    DWORD at = sizeof *r;
    if (!out || cap < need) return need;
    memset(r, 0, sizeof *r);
    r->Revision = SECURITY_DESCRIPTOR_REVISION;
    r->Control = (SECURITY_DESCRIPTOR_CONTROL)((p->control & ~(SE_SACL_PRESENT | SE_DACL_PRESENT)) | SE_SELF_RELATIVE);
    if (p->control & SE_SACL_PRESENT) r->Control |= SE_SACL_PRESENT;
    if (p->control & SE_DACL_PRESENT) r->Control |= SE_DACL_PRESENT;
    if (p->sacl) { r->Sacl = at; memcpy((BYTE *)out + at, p->sacl, p->sacl->AclSize); at += p->sacl->AclSize; }
    if (p->dacl) { r->Dacl = at; memcpy((BYTE *)out + at, p->dacl, p->dacl->AclSize); at += p->dacl->AclSize; }
    if (p->owner) { r->Owner = at; memcpy((BYTE *)out + at, p->owner, GetLengthSid(p->owner)); at += GetLengthSid(p->owner); }
    if (p->group) { r->Group = at; memcpy((BYTE *)out + at, p->group, GetLengthSid(p->group)); at += GetLengthSid(p->group); }
    return need;
}

DLLAPI BOOL WINAPI MakeSelfRelativeSD(PSECURITY_DESCRIPTOR abs, PSECURITY_DESCRIPTOR rel, LPDWORD len)
{
    sec_parts_t p;
    DWORD need;
    if (((SECURITY_DESCRIPTOR *)abs)->Control & SE_SELF_RELATIVE) { shz_set_last_error(ERROR_BAD_DESCRIPTOR_FORMAT); return FALSE; }
    sec_parts(abs, &p);
    need = sec_build_relative(&p, 0, 0);
    if (!rel || *len < need) { *len = need; shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    sec_build_relative(&p, rel, *len);
    *len = need;
    return TRUE;
}

DLLAPI BOOL WINAPI MakeAbsoluteSD(PSECURITY_DESCRIPTOR rel, PSECURITY_DESCRIPTOR abs, LPDWORD abs_len, PACL dacl, LPDWORD dacl_len,
                                  PACL sacl, LPDWORD sacl_len, PSID owner, LPDWORD owner_len, PSID group, LPDWORD group_len)
{
    sec_parts_t p;
    SECURITY_DESCRIPTOR *sd = abs;
    int small = 0;
    if (!(((SECURITY_DESCRIPTOR *)rel)->Control & SE_SELF_RELATIVE)) { shz_set_last_error(ERROR_BAD_DESCRIPTOR_FORMAT); return FALSE; }
    sec_parts(rel, &p);
    if (*abs_len < sizeof(SECURITY_DESCRIPTOR)) { *abs_len = sizeof(SECURITY_DESCRIPTOR); small = 1; }
    if (*dacl_len < acl_len(p.dacl)) { *dacl_len = acl_len(p.dacl); small = 1; }
    if (*sacl_len < acl_len(p.sacl)) { *sacl_len = acl_len(p.sacl); small = 1; }
    if (*owner_len < sid_len_or0(p.owner)) { *owner_len = sid_len_or0(p.owner); small = 1; }
    if (*group_len < sid_len_or0(p.group)) { *group_len = sid_len_or0(p.group); small = 1; }
    if (small) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    memset(sd, 0, sizeof *sd);
    sd->Revision = SECURITY_DESCRIPTOR_REVISION;
    sd->Control = (SECURITY_DESCRIPTOR_CONTROL)(p.control & ~SE_SELF_RELATIVE);
    if (p.dacl) { memcpy(dacl, p.dacl, p.dacl->AclSize); sd->Dacl = dacl; }
    if (p.sacl) { memcpy(sacl, p.sacl, p.sacl->AclSize); sd->Sacl = sacl; }
    if (p.owner) { memcpy(owner, p.owner, GetLengthSid(p.owner)); sd->Owner = owner; }
    if (p.group) { memcpy(group, p.group, GetLengthSid(p.group)); sd->Group = group; }
    return TRUE;
}

/* ---------------------------------------------------------------- SDDL */
static const struct { const char *code; DWORD mask; } sddl_rights[] = {
    {"GA", GENERIC_ALL}, {"GR", GENERIC_READ}, {"GW", GENERIC_WRITE}, {"GX", GENERIC_EXECUTE},
    {"RC", READ_CONTROL}, {"SD", DELETE}, {"WD", WRITE_DAC}, {"WO", WRITE_OWNER},
    {"RP", 0x10}, {"WP", 0x20}, {"CC", 0x1}, {"DC", 0x2}, {"LC", 0x4}, {"SW", 0x8}, {"LO", 0x80}, {"DT", 0x40}, {"CR", 0x100},
    {"FA", FILE_ALL_ACCESS}, {"FR", FILE_GENERIC_READ}, {"FW", FILE_GENERIC_WRITE}, {"FX", FILE_GENERIC_EXECUTE},
    {"KA", KEY_ALL_ACCESS}, {"KR", KEY_READ}, {"KW", KEY_WRITE}, {"KX", KEY_EXECUTE},
    {"NR", SYSTEM_MANDATORY_LABEL_NO_READ_UP}, {"NW", SYSTEM_MANDATORY_LABEL_NO_WRITE_UP}, {"NX", SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP},
};
static const struct { const char *code; BYTE flag; } sddl_ace_flags[] = {
    {"CI", CONTAINER_INHERIT_ACE}, {"OI", OBJECT_INHERIT_ACE}, {"NP", NO_PROPAGATE_INHERIT_ACE}, {"IO", INHERIT_ONLY_ACE},
    {"ID", INHERITED_ACE}, {"SA", SUCCESSFUL_ACCESS_ACE_FLAG}, {"FA", FAILED_ACCESS_ACE_FLAG},
};
static const struct { const char *code; BYTE type; } sddl_ace_types[] = {
    {"A", ACCESS_ALLOWED_ACE_TYPE}, {"D", ACCESS_DENIED_ACE_TYPE}, {"AU", SYSTEM_AUDIT_ACE_TYPE}, {"ML", SYSTEM_MANDATORY_LABEL_ACE_TYPE},
};

static int wmatch(const WCHAR *s, const char *code)
{
    size_t i;
    for (i = 0; code[i]; ++i) if ((s[i] & ~0x20) != (code[i] & ~0x20) || !s[i]) return 0;
    return (int)i;
}

/* One SID token (up to ';' or ')'): heap SID. */
static PSID parse_sid_token(const WCHAR *s, size_t n)
{
    WCHAR tmp[200];
    PSID sid = 0;
    if (!n || n >= 200) return 0;
    memcpy(tmp, s, n * sizeof(WCHAR));
    tmp[n] = 0;
    if (!ConvertStringSidToSidW(tmp, &sid)) return 0;
    return sid;
}

/* Parses "(type;flags;rights;;;sid)" ACEs into acl (sized by the caller). *pp advances. */
static BOOL parse_aces(const WCHAR **pp, PACL acl)
{
    const WCHAR *p = *pp;
    while (*p == '(') {
        const WCHAR *f[6];
        size_t fl[6];
        int k = 0;
        BYTE type = 0, flags = 0;
        DWORD mask = 0, i;
        PSID sid;
        const WCHAR *q = p + 1;
        f[0] = q;
        for (;;) {
            if (!*q) goto bad;
            if (*q == ';' || *q == ')') {
                if (k < 6) fl[k] = (size_t)(q - f[k]);
                ++k;
                if (*q == ')') break;
                if (k < 6) f[k] = q + 1;
            }
            ++q;
        }
        if (k != 6) goto bad;                                            /* resource-attribute ACEs (7 fields) are not supported */
        for (i = 0; i < sizeof sddl_ace_types / sizeof sddl_ace_types[0]; ++i)
            if (fl[0] == strlen(sddl_ace_types[i].code) && wmatch(f[0], sddl_ace_types[i].code)) type = sddl_ace_types[i].type;
        if (!type && !(fl[0] == 1 && (f[0][0] | 0x20) == 'a')) goto bad;
        {
            const WCHAR *x = f[1], *e = f[1] + fl[1];
            while (x < e) {
                int hit = 0;
                for (i = 0; i < sizeof sddl_ace_flags / sizeof sddl_ace_flags[0]; ++i)
                    if (x + 2 <= e && wmatch(x, sddl_ace_flags[i].code)) { flags |= sddl_ace_flags[i].flag; x += 2; hit = 1; break; }
                if (!hit) goto bad;
            }
        }
        {
            const WCHAR *x = f[2], *e = f[2] + fl[2];
            if (e - x > 2 && x[0] == '0' && (x[1] | 0x20) == 'x') {
                for (x += 2; x < e; ++x) {
                    const WCHAR c = *x;
                    const unsigned d = c >= '0' && c <= '9' ? (unsigned)(c - '0') : ((c | 0x20) >= 'a' && (c | 0x20) <= 'f') ? (unsigned)((c | 0x20) - 'a' + 10) : 99;
                    if (d > 15) goto bad;
                    mask = mask * 16 + d;
                }
            } else {
                while (x < e) {
                    int hit = 0;
                    for (i = 0; i < sizeof sddl_rights / sizeof sddl_rights[0]; ++i)
                        if (x + 2 <= e && wmatch(x, sddl_rights[i].code)) { mask |= sddl_rights[i].mask; x += 2; hit = 1; break; }
                    if (!hit) goto bad;
                }
            }
        }
        if (fl[3] || fl[4]) goto bad;                                    /* object GUIDs: object ACEs are not produced */
        sid = parse_sid_token(f[5], fl[5]);
        if (!sid) goto bad;
        if (!sec_add_simple_ace(acl, type, flags, mask, sid, MAXDWORD)) { LocalFree(sid); return FALSE; }
        LocalFree(sid);
        p = q + 1;
    }
    *pp = p;
    return TRUE;
bad:
    shz_set_last_error(ERROR_INVALID_PARAMETER);
    return FALSE;
}

static SECURITY_DESCRIPTOR_CONTROL parse_acl_flags(const WCHAR **pp, int *null_acl)
{
    const WCHAR *p = *pp;
    SECURITY_DESCRIPTOR_CONTROL c = 0;
    int n;
    *null_acl = 0;
    for (;;) {
        if ((n = wmatch(p, "NO_ACCESS_CONTROL"))) { *null_acl = 1; p += n; }
        else if ((n = wmatch(p, "AI")) && p[2] != ':') { c |= SE_DACL_AUTO_INHERITED; p += n; }
        else if ((n = wmatch(p, "AR")) && p[2] != ':') { c |= SE_DACL_AUTO_INHERIT_REQ; p += n; }
        else if (*p == 'P' || *p == 'p') { c |= SE_DACL_PROTECTED; ++p; }
        else break;
    }
    *pp = p;
    return c;
}

DLLAPI BOOL WINAPI ConvertStringSecurityDescriptorToSecurityDescriptorW(LPCWSTR str, DWORD rev, PSECURITY_DESCRIPTOR *out, PULONG out_len)
{
    sec_parts_t parts;
    BYTE dacl_buf[4096], sacl_buf[2048];
    PACL dacl = (PACL)dacl_buf, sacl = (PACL)sacl_buf;
    PSID owner = 0, group = 0;
    const WCHAR *p = str;
    DWORD need;
    BOOL ok = FALSE;
    if (!str || !out) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (rev != SDDL_REVISION_1) { shz_set_last_error(ERROR_UNKNOWN_REVISION); return FALSE; }
    memset(&parts, 0, sizeof parts);
    InitializeAcl(dacl, sizeof dacl_buf, ACL_REVISION);
    InitializeAcl(sacl, sizeof sacl_buf, ACL_REVISION);
    while (*p) {
        WCHAR tag;
        while (*p == ' ') ++p;
        if (!*p) break;
        tag = (WCHAR)(*p & ~0x20);
        if (p[1] != ':') goto bad;
        p += 2;
        if (tag == 'O' || tag == 'G') {
            const WCHAR *s = p;
            PSID sid;
            while (*p && !(p[1] == ':' && ((*p & ~0x20) == 'O' || (*p & ~0x20) == 'G' || (*p & ~0x20) == 'D' || (*p & ~0x20) == 'S') &&
                           p != s)) ++p;
            sid = parse_sid_token(s, (size_t)(p - s));
            if (!sid) goto bad;
            if (tag == 'O') { if (owner) LocalFree(owner); owner = sid; } else { if (group) LocalFree(group); group = sid; }
        } else if (tag == 'D' || tag == 'S') {
            int null_acl;
            SECURITY_DESCRIPTOR_CONTROL c = parse_acl_flags(&p, &null_acl);
            if (tag == 'S') c = (SECURITY_DESCRIPTOR_CONTROL)(((c & SE_DACL_AUTO_INHERITED) ? SE_SACL_AUTO_INHERITED : 0) |
                                                               ((c & SE_DACL_AUTO_INHERIT_REQ) ? SE_SACL_AUTO_INHERIT_REQ : 0) |
                                                               ((c & SE_DACL_PROTECTED) ? SE_SACL_PROTECTED : 0));
            parts.control |= c | (tag == 'D' ? SE_DACL_PRESENT : SE_SACL_PRESENT);
            if (!parse_aces(&p, tag == 'D' ? dacl : sacl)) goto fail;
            if (tag == 'D') parts.dacl = null_acl ? 0 : dacl; else parts.sacl = null_acl ? 0 : sacl;
        } else {
            goto bad;
        }
    }
    /* keep only the bytes in use */
    if (parts.dacl) dacl->AclSize = (WORD)sec_acl_used(dacl);
    if (parts.sacl) sacl->AclSize = (WORD)sec_acl_used(sacl);
    parts.owner = owner;
    parts.group = group;
    need = sec_build_relative(&parts, 0, 0);
    *out = LocalAlloc(LMEM_FIXED, need);
    if (!*out) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); goto fail; }
    sec_build_relative(&parts, *out, need);
    if (out_len) *out_len = need;
    ok = TRUE;
    goto fail;
bad:
    shz_set_last_error(ERROR_INVALID_PARAMETER);
fail:
    if (owner) LocalFree(owner);
    if (group) LocalFree(group);
    return ok;
}

DLLAPI BOOL WINAPI ConvertStringSecurityDescriptorToSecurityDescriptorA(LPCSTR str, DWORD rev, PSECURITY_DESCRIPTOR *out, PULONG out_len)
{
    WCHAR w[1024];
    size_t i;
    if (!str) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; str[i] && i < 1023; ++i) w[i] = (unsigned char)str[i];
    if (str[i]) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    w[i] = 0;
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(w, rev, out, out_len);
}

/* ---- descriptor -> SDDL */
typedef struct { WCHAR *b; size_t n, cap; } wbuf;
static void wput(wbuf *w, const char *s) { while (*s) { if (w->n + 1 < w->cap) w->b[w->n] = (WCHAR)*s; ++w->n; ++s; } }
static void wputw(wbuf *w, const WCHAR *s) { while (*s) { if (w->n + 1 < w->cap) w->b[w->n] = *s; ++w->n; ++s; } }
static void wput_sid(wbuf *w, PSID sid)
{
    LPWSTR s = 0;
    if (ConvertSidToStringSidW(sid, &s)) { wputw(w, s); LocalFree(s); }
}
static void wput_hex(wbuf *w, DWORD v)
{
    char t[12];
    int i, n = 0;
    wput(w, "0x");
    do { t[n++] = "0123456789abcdef"[v & 15]; v >>= 4; } while (v);
    for (i = n - 1; i >= 0; --i) { char c[2] = { t[i], 0 }; wput(w, c); }
}
static void wput_acl(wbuf *w, const ACL *acl)
{
    WORD i;
    const BYTE *p = (const BYTE *)(acl + 1);
    for (i = 0; i < acl->AceCount; ++i) {
        const ACE_HEADER *h = (const ACE_HEADER *)p;
        unsigned k;
        wput(w, "(");
        wput(w, h->AceType == ACCESS_ALLOWED_ACE_TYPE ? "A" : h->AceType == ACCESS_DENIED_ACE_TYPE ? "D" :
                h->AceType == SYSTEM_AUDIT_ACE_TYPE ? "AU" : h->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE ? "ML" : "?");
        wput(w, ";");
        for (k = 0; k < sizeof sddl_ace_flags / sizeof sddl_ace_flags[0]; ++k) if (h->AceFlags & sddl_ace_flags[k].flag) wput(w, sddl_ace_flags[k].code);
        wput(w, ";");
        {
            DWORD mask;
            memcpy(&mask, p + 4, 4);
            if (h->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
                if (mask & 1) wput(w, "NW");
                if (mask & 2) wput(w, "NR");
                if (mask & 4) wput(w, "NX");
            } else if (mask == GENERIC_ALL) wput(w, "GA");
            else if (mask == GENERIC_READ) wput(w, "GR");
            else if (mask == FILE_ALL_ACCESS) wput(w, "FA");
            else wput_hex(w, mask);
        }
        wput(w, ";;;");
        wput_sid(w, (PSID)(p + 8));
        wput(w, ")");
        p += h->AceSize;
    }
}

DLLAPI BOOL WINAPI ConvertSecurityDescriptorToStringSecurityDescriptorW(PSECURITY_DESCRIPTOR psd, DWORD rev, SECURITY_INFORMATION info,
                                                                        LPWSTR *out, PULONG out_len)
{
    sec_parts_t p;
    wbuf w = { 0, 0, 0 };
    int pass;
    if (rev != SDDL_REVISION_1) { shz_set_last_error(ERROR_UNKNOWN_REVISION); return FALSE; }
    if (!IsValidSecurityDescriptor(psd)) return FALSE;
    sec_parts(psd, &p);
    for (pass = 0; pass < 2; ++pass) {
        if (pass) {
            w.cap = w.n + 1;
            w.b = LocalAlloc(LMEM_FIXED, w.cap * sizeof(WCHAR));
            if (!w.b) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
            w.n = 0;
        }
        if ((info & OWNER_SECURITY_INFORMATION) && p.owner) { wput(&w, "O:"); wput_sid(&w, p.owner); }
        if ((info & GROUP_SECURITY_INFORMATION) && p.group) { wput(&w, "G:"); wput_sid(&w, p.group); }
        if ((info & DACL_SECURITY_INFORMATION) && (p.control & SE_DACL_PRESENT)) {
            wput(&w, "D:");
            if (p.control & SE_DACL_PROTECTED) wput(&w, "P");
            if (p.control & SE_DACL_AUTO_INHERITED) wput(&w, "AI");
            if (p.dacl) wput_acl(&w, p.dacl); else wput(&w, "NO_ACCESS_CONTROL");
        }
        if ((info & (SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION)) && (p.control & SE_SACL_PRESENT) && p.sacl) {
            wput(&w, "S:");
            wput_acl(&w, p.sacl);
        }
    }
    w.b[w.n] = 0;
    *out = w.b;
    if (out_len) *out_len = (ULONG)w.n + 1;
    return TRUE;
}

/* ---------------------------------------------------------------- trustees and explicit access */
DLLAPI VOID WINAPI BuildTrusteeWithSidW(PTRUSTEEW t, PSID sid)
{
    t->pMultipleTrustee = 0;
    t->MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    t->TrusteeForm = TRUSTEE_IS_SID;
    t->TrusteeType = TRUSTEE_IS_UNKNOWN;
    t->ptstrName = (LPWSTR)sid;
}
DLLAPI VOID WINAPI BuildTrusteeWithNameW(PTRUSTEEW t, LPWSTR name)
{
    t->pMultipleTrustee = 0;
    t->MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    t->TrusteeForm = TRUSTEE_IS_NAME;
    t->TrusteeType = TRUSTEE_IS_UNKNOWN;
    t->ptstrName = name;
}
DLLAPI VOID WINAPI BuildExplicitAccessWithNameW(PEXPLICIT_ACCESSW e, LPWSTR name, DWORD perms, ACCESS_MODE mode, DWORD inherit)
{
    e->grfAccessPermissions = perms;
    e->grfAccessMode = mode;
    e->grfInheritance = inherit;
    BuildTrusteeWithNameW(&e->Trustee, name);
}

/* The SID a trustee names, heap-allocated (LocalAlloc) or NULL. */
static PSID trustee_sid(const TRUSTEEW *t)
{
    if (t->TrusteeForm == TRUSTEE_IS_SID) {
        PSID s = LocalAlloc(LMEM_FIXED, GetLengthSid((PSID)t->ptstrName));
        if (s) CopySid(GetLengthSid((PSID)t->ptstrName), s, (PSID)t->ptstrName);
        return s;
    }
    if (t->TrusteeForm == TRUSTEE_IS_NAME) return sec_sid_for_name(t->ptstrName);
    return 0;
}

static BOOL sid_is(const BYTE *ace, PSID sid) { return EqualSid((PSID)(ace + 8), sid); }

/* SetEntriesInAclW: the new ACL is the old one with REVOKE/SET entries removing the trustee's ACEs, then the new deny ACEs,
 * then the old ACEs, then the new allow ACEs (Windows' canonical order: explicit deny before allow). */
DLLAPI DWORD WINAPI SetEntriesInAclW(ULONG count, PEXPLICIT_ACCESSW entries, PACL old, PACL *out)
{
    BYTE buf[8192];
    PACL acl = (PACL)buf;
    PSID sids[64];
    ULONG i;
    WORD k;
    DWORD used, err = ERROR_SUCCESS;
    if (!out || count > 64) return ERROR_INVALID_PARAMETER;
    InitializeAcl(acl, sizeof buf, ACL_REVISION);
    for (i = 0; i < count; ++i) {
        sids[i] = trustee_sid(&entries[i].Trustee);
        if (!sids[i]) { err = ERROR_NONE_MAPPED; count = i; goto done; }
    }
    for (i = 0; i < count; ++i)                                             /* explicit denies first */
        if (entries[i].grfAccessMode == DENY_ACCESS &&
            !sec_add_simple_ace(acl, ACCESS_DENIED_ACE_TYPE, (BYTE)(entries[i].grfInheritance & ACE_FLAGS_VALID),
                                entries[i].grfAccessPermissions, sids[i], MAXDWORD)) { err = GetLastError(); goto done; }
    if (old) {
        const BYTE *p = (const BYTE *)(old + 1);
        for (k = 0; k < old->AceCount; ++k) {
            const ACE_HEADER *h = (const ACE_HEADER *)p;
            int drop = 0;
            for (i = 0; i < count; ++i)
                if ((entries[i].grfAccessMode == SET_ACCESS || entries[i].grfAccessMode == REVOKE_ACCESS) &&
                    (h->AceType == ACCESS_ALLOWED_ACE_TYPE || h->AceType == ACCESS_DENIED_ACE_TYPE) && sid_is(p, sids[i]) &&
                    !(h->AceFlags & INHERITED_ACE)) drop = 1;
            if (!drop && !insert_aces(acl, MAXDWORD, p, h->AceSize, 1)) { err = GetLastError(); goto done; }
            p += h->AceSize;
        }
    }
    for (i = 0; i < count; ++i)
        if ((entries[i].grfAccessMode == GRANT_ACCESS || entries[i].grfAccessMode == SET_ACCESS) &&
            !sec_add_simple_ace(acl, ACCESS_ALLOWED_ACE_TYPE, (BYTE)(entries[i].grfInheritance & ACE_FLAGS_VALID),
                                entries[i].grfAccessPermissions, sids[i], MAXDWORD)) { err = GetLastError(); goto done; }
    used = sec_acl_used(acl);
    *out = LocalAlloc(LMEM_FIXED, used);
    if (!*out) { err = ERROR_NOT_ENOUGH_MEMORY; goto done; }
    memcpy(*out, acl, used);
    (*out)->AclSize = (WORD)used;
done:
    for (i = 0; i < count; ++i) LocalFree(sids[i]);
    return err;
}

DLLAPI DWORD WINAPI BuildSecurityDescriptorW(PTRUSTEEW owner, PTRUSTEEW group, ULONG naccess, PEXPLICIT_ACCESSW access, ULONG naudit,
                                             PEXPLICIT_ACCESSW audit, PSECURITY_DESCRIPTOR old, PULONG size, PSECURITY_DESCRIPTOR *out)
{
    sec_parts_t p, o;
    PACL dacl = 0;
    DWORD err, need;
    if (naudit || audit) return ERROR_NOT_SUPPORTED;                         /* audit entries: SACLs are not built from trustees here */
    memset(&p, 0, sizeof p);
    if (old) {
        sec_parts(old, &o);
        p = o;
    }
    if (owner && !(p.owner = trustee_sid(owner))) return ERROR_NONE_MAPPED;
    if (group && !(p.group = trustee_sid(group))) { if (owner) LocalFree(p.owner); return ERROR_NONE_MAPPED; }
    err = SetEntriesInAclW(naccess, access, p.dacl, &dacl);
    if (err) goto done;
    p.dacl = dacl;
    p.control |= SE_DACL_PRESENT;
    need = sec_build_relative(&p, 0, 0);
    *out = LocalAlloc(LMEM_FIXED, need);
    if (!*out) { err = ERROR_NOT_ENOUGH_MEMORY; goto done; }
    sec_build_relative(&p, *out, need);
    if (size) *size = need;
done:
    if (dacl) LocalFree(dacl);
    if (owner && p.owner) LocalFree(p.owner);
    if (group && p.group) LocalFree(p.group);
    return err;
}
