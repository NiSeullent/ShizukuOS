/* SPDX-License-Identifier: GPL-2.0-only
 * advapi32.dll: security of objects - GetSecurityInfo / SetSecurityInfo / GetKernelObjectSecurity / SetKernelObjectSecurity
 * on handles, GetNamedSecurityInfoW / SetNamedSecurityInfoW on names.
 *
 * Kernel objects (events, sections, pipes, processes, ...) store the descriptor last set on them (kernel64/sysk32_obj.c,
 * NtShzSecurityObject); an object nobody set a descriptor on reports the default one a new object of this user gets
 * (owner and group the user, DACL: the user and SYSTEM with full access). Kernel64 performs no access checks, so a
 * stored descriptor documents intent and is returned faithfully, but it does not restrict anybody.
 * Files: the Kernel64 file systems (RAM, FAT32, ShizukuFS) keep no security information. GetNamedSecurityInfo reports what
 * holds for every file - owner the user and a NULL DACL (everyone has full access); SetNamedSecurityInfo on a file fails
 * with ERROR_NOT_SUPPORTED rather than pretending to store a descriptor. Registry keys and other named objects are not
 * reachable by name here (ERROR_NOT_SUPPORTED as well).
 */
#define _ADVAPI32_
#include "nt.h"
#include <string.h>
#include <sddl.h>
#include <securitybaseapi.h>
#include <aclapi.h>
#include "sec_int.h"

BOOL sec_default_sd(PSECURITY_DESCRIPTOR *out, DWORD *len)
{
    BYTE aclbuf[128], sys[12];
    PACL acl = (PACL)aclbuf;
    sec_parts_t p;
    DWORD need;
    SID *s = (SID *)sys;
    s->Revision = SID_REVISION;
    s->SubAuthorityCount = 1;
    memset(&s->IdentifierAuthority, 0, 6);
    s->IdentifierAuthority.Value[5] = 5;
    s->SubAuthority[0] = 18;                                               /* SYSTEM */
    InitializeAcl(acl, sizeof aclbuf, ACL_REVISION);
    sec_add_simple_ace(acl, ACCESS_ALLOWED_ACE_TYPE, 0, GENERIC_ALL, sec_user_sid(), MAXDWORD);
    sec_add_simple_ace(acl, ACCESS_ALLOWED_ACE_TYPE, 0, GENERIC_ALL, (PSID)sys, MAXDWORD);
    acl->AclSize = (WORD)sec_acl_used(acl);
    memset(&p, 0, sizeof p);
    p.control = SE_DACL_PRESENT;
    p.owner = sec_user_sid();
    p.group = sec_primary_group_sid();
    p.dacl = acl;
    need = sec_build_relative(&p, 0, 0);
    *out = LocalAlloc(LMEM_FIXED, need);
    if (!*out) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    sec_build_relative(&p, *out, need);
    if (len) *len = need;
    return TRUE;
}

/* The descriptor stored on a kernel object (or the default one), LocalAlloc'd, self-relative. */
static BOOL object_sd(HANDLE h, PSECURITY_DESCRIPTOR *out)
{
    ULONG need = 0;
    NTSTATUS st = NtShzSecurityObject(SHZ_SOB_QUERY, (ULONG_PTR)h, 0, 0, (ULONG_PTR)&need);
    if (st == (NTSTATUS)0xC0000225) return sec_default_sd(out, 0);        /* STATUS_NOT_FOUND: never set */
    if (st != STATUS_BUFFER_TOO_SMALL || !need) { shz_set_last_error(RtlNtStatusToDosError(st)); return FALSE; }
    *out = LocalAlloc(LMEM_FIXED, need);
    if (!*out) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    st = NtShzSecurityObject(SHZ_SOB_QUERY, (ULONG_PTR)h, (ULONG_PTR)*out, need, (ULONG_PTR)&need);
    if (st) { LocalFree(*out); *out = 0; shz_set_last_error(RtlNtStatusToDosError(st)); return FALSE; }
    return TRUE;
}

/* Keeps only the requested parts of `sd` (a fresh LocalAlloc'd copy). */
static PSECURITY_DESCRIPTOR select_parts(PSECURITY_DESCRIPTOR sd, SECURITY_INFORMATION info)
{
    sec_parts_t p;
    PSECURITY_DESCRIPTOR out;
    DWORD need;
    sec_parts(sd, &p);
    if (!(info & OWNER_SECURITY_INFORMATION)) p.owner = 0;
    if (!(info & GROUP_SECURITY_INFORMATION)) p.group = 0;
    if (!(info & DACL_SECURITY_INFORMATION)) { p.dacl = 0; p.control &= ~(SE_DACL_PRESENT | SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED); }
    if (!(info & (SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION))) { p.sacl = 0; p.control &= ~SE_SACL_PRESENT; }
    need = sec_build_relative(&p, 0, 0);
    out = LocalAlloc(LMEM_FIXED, need);
    if (out) sec_build_relative(&p, out, need);
    return out;
}

static DWORD give_parts(PSECURITY_DESCRIPTOR sd, SECURITY_INFORMATION info, PSID *owner, PSID *group, PACL *dacl, PACL *sacl,
                        PSECURITY_DESCRIPTOR *out)
{
    PSECURITY_DESCRIPTOR sel;
    sec_parts_t p;
    if ((owner || group || dacl || sacl) && !out) return ERROR_INVALID_PARAMETER;
    sel = select_parts(sd, info);
    if (!sel) return ERROR_NOT_ENOUGH_MEMORY;
    sec_parts(sel, &p);
    if (owner) *owner = p.owner;
    if (group) *group = p.group;
    if (dacl) *dacl = p.dacl;
    if (sacl) *sacl = p.sacl;
    if (out) *out = sel; else LocalFree(sel);
    return ERROR_SUCCESS;
}

DLLAPI DWORD WINAPI GetSecurityInfo(HANDLE h, SE_OBJECT_TYPE type, SECURITY_INFORMATION info, PSID *owner, PSID *group, PACL *dacl,
                                    PACL *sacl, PSECURITY_DESCRIPTOR *out)
{
    PSECURITY_DESCRIPTOR sd = 0;
    DWORD err;
    (void)type;
    if (!object_sd(h, &sd)) return GetLastError();
    err = give_parts(sd, info, owner, group, dacl, sacl, out);
    LocalFree(sd);
    return err;
}

/* Merges the requested parts of `newsd` into the object's stored descriptor. */
static DWORD set_object(HANDLE h, SECURITY_INFORMATION info, PSID owner, PSID group, PACL dacl, PACL sacl, int protect_bits)
{
    PSECURITY_DESCRIPTOR cur = 0, merged;
    sec_parts_t p;
    DWORD need;
    NTSTATUS st;
    if (!object_sd(h, &cur)) return GetLastError();
    sec_parts(cur, &p);
    if (info & OWNER_SECURITY_INFORMATION) p.owner = owner;
    if (info & GROUP_SECURITY_INFORMATION) p.group = group;
    if (info & DACL_SECURITY_INFORMATION) {
        p.dacl = dacl;
        p.control |= SE_DACL_PRESENT;
        if (protect_bits) {
            p.control &= ~SE_DACL_PROTECTED;
            if (info & PROTECTED_DACL_SECURITY_INFORMATION) p.control |= SE_DACL_PROTECTED;
        }
    }
    if (info & (SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION)) {
        p.sacl = sacl;
        p.control |= SE_SACL_PRESENT;
    }
    need = sec_build_relative(&p, 0, 0);
    merged = LocalAlloc(LMEM_FIXED, need);
    if (!merged) { LocalFree(cur); return ERROR_NOT_ENOUGH_MEMORY; }
    sec_build_relative(&p, merged, need);
    st = NtShzSecurityObject(SHZ_SOB_SET, (ULONG_PTR)h, (ULONG_PTR)merged, need, 0);
    LocalFree(merged);
    LocalFree(cur);
    return st ? RtlNtStatusToDosError(st) : ERROR_SUCCESS;
}

DLLAPI DWORD WINAPI SetSecurityInfo(HANDLE h, SE_OBJECT_TYPE type, SECURITY_INFORMATION info, PSID owner, PSID group, PACL dacl, PACL sacl)
{
    (void)type;
    if ((info & OWNER_SECURITY_INFORMATION) && (!owner || !IsValidSid(owner))) return ERROR_INVALID_PARAMETER;
    if ((info & GROUP_SECURITY_INFORMATION) && (!group || !IsValidSid(group))) return ERROR_INVALID_PARAMETER;
    if ((info & DACL_SECURITY_INFORMATION) && dacl && !IsValidAcl(dacl)) return ERROR_INVALID_ACL;
    if ((info & (SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION)) && sacl && !IsValidAcl(sacl)) return ERROR_INVALID_ACL;
    return set_object(h, info, owner, group, dacl, sacl, 1);
}

DLLAPI BOOL WINAPI GetKernelObjectSecurity(HANDLE h, SECURITY_INFORMATION info, PSECURITY_DESCRIPTOR out, DWORD len, LPDWORD need)
{
    PSECURITY_DESCRIPTOR sd = 0, sel;
    DWORD n;
    if (!object_sd(h, &sd)) return FALSE;
    sel = select_parts(sd, info);
    LocalFree(sd);
    if (!sel) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    n = GetSecurityDescriptorLength(sel);
    *need = n;
    if (!out || len < n) { LocalFree(sel); shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    memcpy(out, sel, n);
    LocalFree(sel);
    return TRUE;
}

DLLAPI BOOL WINAPI SetKernelObjectSecurity(HANDLE h, SECURITY_INFORMATION info, PSECURITY_DESCRIPTOR sd)
{
    sec_parts_t p;
    DWORD err;
    if (!IsValidSecurityDescriptor(sd)) { shz_set_last_error(ERROR_INVALID_SECURITY_DESCR); return FALSE; }
    sec_parts(sd, &p);
    err = set_object(h, info, p.owner, p.group, p.dacl, p.sacl, 0);
    if (err) { shz_set_last_error(err); return FALSE; }
    return TRUE;
}

DLLAPI DWORD WINAPI GetNamedSecurityInfoW(LPCWSTR name, SE_OBJECT_TYPE type, SECURITY_INFORMATION info, PSID *owner, PSID *group,
                                          PACL *dacl, PACL *sacl, PSECURITY_DESCRIPTOR *out)
{
    sec_parts_t p;
    PSECURITY_DESCRIPTOR sd;
    DWORD need, err;
    if (!name) return ERROR_INVALID_PARAMETER;
    if (type != SE_FILE_OBJECT) {
        sec_unsupported("GetNamedSecurityInfoW", "object type other than files", ERROR_NOT_SUPPORTED);
        return ERROR_NOT_SUPPORTED;
    }
    if (GetFileAttributesW(name) == INVALID_FILE_ATTRIBUTES) return GetLastError();
    memset(&p, 0, sizeof p);
    p.control = SE_DACL_PRESENT;                                           /* present and NULL: the file system has no ACLs */
    p.owner = sec_user_sid();
    p.group = sec_primary_group_sid();
    need = sec_build_relative(&p, 0, 0);
    sd = LocalAlloc(LMEM_FIXED, need);
    if (!sd) return ERROR_NOT_ENOUGH_MEMORY;
    sec_build_relative(&p, sd, need);
    err = give_parts(sd, info, owner, group, dacl, sacl, out);
    LocalFree(sd);
    return err;
}

DLLAPI DWORD WINAPI SetNamedSecurityInfoW(LPWSTR name, SE_OBJECT_TYPE type, SECURITY_INFORMATION info, PSID owner, PSID group, PACL dacl,
                                          PACL sacl)
{
    (void)name; (void)type; (void)info; (void)owner; (void)group; (void)dacl; (void)sacl;
    sec_unsupported("SetNamedSecurityInfoW", "the Kernel64 file systems store no security descriptors", ERROR_NOT_SUPPORTED);
    return ERROR_NOT_SUPPORTED;
}
