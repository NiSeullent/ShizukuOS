/* SPDX-License-Identifier: GPL-2.0-only
 * advapi32.dll: access tokens, privileges, impersonation, AccessCheck and account-name lookup.
 *
 * Kernel64 has one interactive user (ntreg.h SHZ_USER_SID_A, name SHZ_USER_NAME_W) in logon session 1 at medium
 * integrity, without administrator rights. Every process has a primary token (kernel64/sysk32_obj.c) that describes
 * exactly that identity; this module renders it in the Windows information classes: user, groups (Everyone, Local,
 * Console Logon, Interactive, Authenticated Users, This Organization, Users, the logon SID, the integrity label),
 * the standard-user privileges (SeShutdown, SeChangeNotify [enabled], SeUndock, SeIncreaseWorkingSet, SeTimeZone),
 * owner, primary group, default DACL, statistics, elevation (not elevated, default type, no linked token), session 1.
 * Integrity can be lowered (SetTokenInformation(TokenIntegrityLevel)), privileges enabled/disabled among those held.
 *
 * What the kernel does not have is refused explicitly: restricted tokens (CreateRestrictedToken), AppContainer tokens,
 * CreateProcessAsUser with a token different from the caller's. AccessCheck evaluates a descriptor against a token as
 * Windows does (it is pure computation); Kernel64 itself performs no access checks on its objects.
 */
#define _ADVAPI32_
#include "nt.h"
#include "ntreg.h"
#include <string.h>
#include <sddl.h>
#include <securitybaseapi.h>
#include <aclapi.h>
#include "sec_int.h"

/* ---------------------------------------------------------------- diagnostics */
BOOL sec_unsupported(const char *fn, const char *what, DWORD err)
{
    static int trace = -1;
    if (trace < 0) {
        WCHAR v[4];
        trace = GetEnvironmentVariableW(L"SHZ_K32TRACE", v, 4) == 1 && v[0] == '1';
    }
    if (trace) {
        char line[240];
        unsigned n = 0;
        const char *parts[] = { "K32 unsupported: advapi32 ", fn, " (", what, ")\n" };
        unsigned k;
        for (k = 0; k < 5; ++k) { const char *s = parts[k]; while (*s && n + 1 < sizeof line) line[n++] = *s++; }
        NtShzDebugPrint(line, n);
    }
    shz_set_last_error(err);
    return FALSE;
}

/* ---------------------------------------------------------------- the identity */
static BYTE user_sid_buf[SECURITY_MAX_SID_SIZE], group_sid_buf[SECURITY_MAX_SID_SIZE];
static volatile LONG ident_ready;

static void ident_init(void)
{
    if (ident_ready) return;
    {
        PSID s = 0;
        if (ConvertStringSidToSidW(SHZ_USER_SID_W, &s)) {
            memcpy(user_sid_buf, s, GetLengthSid(s));
            memcpy(group_sid_buf, s, GetLengthSid(s));
            *GetSidSubAuthority((PSID)group_sid_buf, *GetSidSubAuthorityCount((PSID)group_sid_buf) - 1) = 513;   /* "None" */
            LocalFree(s);
        }
    }
    ident_ready = 1;
}
PSID sec_user_sid(void) { ident_init(); return (PSID)user_sid_buf; }
PSID sec_primary_group_sid(void) { ident_init(); return (PSID)group_sid_buf; }

typedef struct { BYTE auth; BYTE count; DWORD sub[2]; DWORD attrs; } group_def;
#define GRP_STD (SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED)
static const group_def groups[] = {
    {1, 1, {0, 0}, GRP_STD},                                               /* Everyone */
    {2, 1, {0, 0}, GRP_STD},                                               /* LOCAL */
    {2, 1, {1, 0}, GRP_STD},                                               /* CONSOLE LOGON */
    {5, 1, {4, 0}, GRP_STD},                                               /* INTERACTIVE */
    {5, 1, {11, 0}, GRP_STD},                                              /* Authenticated Users */
    {5, 1, {15, 0}, GRP_STD},                                              /* This Organization */
    {5, 2, {32, 545}, GRP_STD},                                            /* BUILTIN\Users */
    {5, 3, {5, 0}, GRP_STD | SE_GROUP_LOGON_ID},                           /* logon SID S-1-5-5-0-<id> (third sub-authority below) */
};
#define NGROUPS (sizeof groups / sizeof groups[0])

static DWORD group_sid(unsigned i, const shz_token_info *t, BYTE *out)
{
    SID *s = (SID *)out;
    unsigned k;
    memset(s, 0, 16);
    s->Revision = SID_REVISION;
    s->SubAuthorityCount = groups[i].count;
    s->IdentifierAuthority.Value[5] = groups[i].auth;
    for (k = 0; k < groups[i].count && k < 2; ++k) s->SubAuthority[k] = groups[i].sub[k];
    if (groups[i].attrs & SE_GROUP_LOGON_ID) s->SubAuthority[2] = (DWORD)(t->auth_id & 0xffffffff);
    return GetLengthSid(s);
}

static DWORD label_sid(DWORD rid, BYTE *out)
{
    SID *s = (SID *)out;
    s->Revision = SID_REVISION;
    s->SubAuthorityCount = 1;
    memset(&s->IdentifierAuthority, 0, 6);
    s->IdentifierAuthority.Value[5] = 16;                                  /* SECURITY_MANDATORY_LABEL_AUTHORITY */
    s->SubAuthority[0] = rid;
    return 12;
}

/* privileges of a standard user (winnt.h SE_*_PRIVILEGE values) */
static const struct { DWORD luid; const WCHAR *name; int enabled_by_default; } privs[] = {
    {19, L"SeShutdownPrivilege", 0}, {23, L"SeChangeNotifyPrivilege", 1}, {25, L"SeUndockPrivilege", 0},
    {33, L"SeIncreaseWorkingSetPrivilege", 0}, {34, L"SeTimeZonePrivilege", 0},
};
#define NPRIVS (sizeof privs / sizeof privs[0])
static const struct { DWORD luid; const WCHAR *name; } all_priv_names[] = {
    {2, L"SeCreateTokenPrivilege"}, {3, L"SeAssignPrimaryTokenPrivilege"}, {4, L"SeLockMemoryPrivilege"},
    {5, L"SeIncreaseQuotaPrivilege"}, {6, L"SeMachineAccountPrivilege"}, {7, L"SeTcbPrivilege"}, {8, L"SeSecurityPrivilege"},
    {9, L"SeTakeOwnershipPrivilege"}, {10, L"SeLoadDriverPrivilege"}, {11, L"SeSystemProfilePrivilege"},
    {12, L"SeSystemtimePrivilege"}, {13, L"SeProfileSingleProcessPrivilege"}, {14, L"SeIncreaseBasePriorityPrivilege"},
    {15, L"SeCreatePagefilePrivilege"}, {16, L"SeCreatePermanentPrivilege"}, {17, L"SeBackupPrivilege"},
    {18, L"SeRestorePrivilege"}, {19, L"SeShutdownPrivilege"}, {20, L"SeDebugPrivilege"}, {21, L"SeAuditPrivilege"},
    {22, L"SeSystemEnvironmentPrivilege"}, {23, L"SeChangeNotifyPrivilege"}, {24, L"SeRemoteShutdownPrivilege"},
    {25, L"SeUndockPrivilege"}, {26, L"SeSyncAgentPrivilege"}, {27, L"SeEnableDelegationPrivilege"},
    {28, L"SeManageVolumePrivilege"}, {29, L"SeImpersonatePrivilege"}, {30, L"SeCreateGlobalPrivilege"},
    {31, L"SeTrustedCredManAccessPrivilege"}, {32, L"SeRelabelPrivilege"}, {33, L"SeIncreaseWorkingSetPrivilege"},
    {34, L"SeTimeZonePrivilege"}, {35, L"SeCreateSymbolicLinkPrivilege"}, {36, L"SeDelegateSessionUserImpersonatePrivilege"},
};

static int priv_enabled(const shz_token_info *t, unsigned i) { return privs[i].enabled_by_default ^ (int)((t->flags >> i) & 1); }

static int wieq(const WCHAR *a, const WCHAR *b)
{
    for (; *a && *b; ++a, ++b) {
        WCHAR x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = (WCHAR)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (WCHAR)(y + 32);
        if (x != y) return 0;
    }
    return !*a && !*b;
}

/* ---------------------------------------------------------------- opening and duplicating */
static BOOL nt_ok(NTSTATUS st)
{
    if (st) { shz_set_last_error(RtlNtStatusToDosError(st)); return FALSE; }
    return TRUE;
}

DLLAPI BOOL WINAPI OpenProcessToken(HANDLE process, DWORD access, PHANDLE token) { return nt_ok(NtOpenProcessToken(process, access, token)); }
DLLAPI BOOL WINAPI OpenThreadToken(HANDLE thread, DWORD access, BOOL self, PHANDLE token)
{
    return nt_ok(NtOpenThreadToken(thread, access, (BOOLEAN)self, token));
}

DLLAPI BOOL WINAPI DuplicateTokenEx(HANDLE token, DWORD access, LPSECURITY_ATTRIBUTES sa, SECURITY_IMPERSONATION_LEVEL level,
                                    TOKEN_TYPE type, PHANDLE out)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SECURITY_QUALITY_OF_SERVICE qos;
    (void)sa;
    memset(&oa, 0, sizeof oa);
    oa.Length = sizeof oa;
    qos.Length = sizeof qos;
    qos.ImpersonationLevel = level;
    qos.ContextTrackingMode = 0;
    qos.EffectiveOnly = FALSE;
    oa.SecurityQualityOfService = &qos;
    return nt_ok(NtDuplicateToken(token, access, &oa, FALSE, type, out));
}
DLLAPI BOOL WINAPI DuplicateToken(HANDLE token, SECURITY_IMPERSONATION_LEVEL level, PHANDLE out)
{
    return DuplicateTokenEx(token, TOKEN_IMPERSONATE | TOKEN_QUERY, 0, level, TokenImpersonation, out);
}

static BOOL token_info(HANDLE token, shz_token_info *t)
{
    return nt_ok(NtShzToken(SHZ_TOK_QUERY, (ULONG_PTR)token, (ULONG_PTR)t, sizeof *t));
}

/* ---------------------------------------------------------------- GetTokenInformation */
typedef struct { BYTE *b; DWORD cap, need; } obuf;
static void *oreserve(obuf *o, DWORD n, DWORD align)
{
    void *p;
    o->need = (o->need + align - 1) & ~(align - 1);
    p = o->b && o->need + n <= o->cap ? o->b + o->need : 0;
    o->need += n;
    return p;
}
static PSID oput_sid(obuf *o, const void *sid)
{
    const DWORD n = GetLengthSid((PSID)sid);
    void *p = oreserve(o, n, 4);
    if (p) memcpy(p, sid, n);
    return p;
}

DLLAPI BOOL WINAPI GetTokenInformation(HANDLE token, TOKEN_INFORMATION_CLASS cls, LPVOID buf, DWORD len, PDWORD ret)
{
    shz_token_info t;
    obuf o = { buf, len, 0 };
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD i;
    if (!ret) { shz_set_last_error(ERROR_NOACCESS); return FALSE; }
    if (!token_info(token, &t)) return FALSE;
    switch (cls) {
    case TokenUser: case TokenOwner: case TokenPrimaryGroup: {
        const PSID s = cls == TokenPrimaryGroup ? sec_primary_group_sid() : sec_user_sid();
        if (cls == TokenUser) {
            TOKEN_USER *u = oreserve(&o, sizeof *u, 8);
            PSID p = oput_sid(&o, s);
            if (u && p) { u->User.Sid = p; u->User.Attributes = 0; }
        } else {
            PSID *pp = oreserve(&o, sizeof(PSID), 8);
            PSID p = oput_sid(&o, s);
            if (pp && p) *pp = p;
        }
        break;
    }
    case TokenGroups: case TokenLogonSid: case TokenRestrictedSids: case TokenCapabilities: {
        const DWORD n = cls == TokenGroups ? (DWORD)NGROUPS + 1 : cls == TokenLogonSid ? 1 : 0;
        TOKEN_GROUPS *g = oreserve(&o, (DWORD)(8 + (n ? n : 1) * sizeof(SID_AND_ATTRIBUTES)), 8);
        if (g) g->GroupCount = n;
        for (i = 0; i < n; ++i) {
            DWORD attrs;
            PSID p;
            if (cls == TokenLogonSid) { group_sid(NGROUPS - 1, &t, sid); attrs = groups[NGROUPS - 1].attrs; }
            else if (i < NGROUPS) { group_sid(i, &t, sid); attrs = groups[i].attrs; }
            else { label_sid(t.integrity_rid, sid); attrs = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED; }
            p = oput_sid(&o, sid);
            if (g && p) { g->Groups[i].Sid = p; g->Groups[i].Attributes = attrs; }
        }
        break;
    }
    case TokenPrivileges: {
        TOKEN_PRIVILEGES *tp = oreserve(&o, (DWORD)(4 + NPRIVS * sizeof(LUID_AND_ATTRIBUTES)), 4);
        if (tp) {
            tp->PrivilegeCount = NPRIVS;
            for (i = 0; i < NPRIVS; ++i) {
                tp->Privileges[i].Luid.LowPart = privs[i].luid;
                tp->Privileges[i].Luid.HighPart = 0;
                tp->Privileges[i].Attributes = (priv_enabled(&t, i) ? SE_PRIVILEGE_ENABLED : 0) |
                                               (privs[i].enabled_by_default ? SE_PRIVILEGE_ENABLED_BY_DEFAULT : 0);
            }
        }
        break;
    }
    case TokenDefaultDacl: {
        BYTE aclbuf[256];
        PACL acl = (PACL)aclbuf;
        PACL *pp = oreserve(&o, sizeof(PACL), 8);
        void *p;
        BYTE sys[12];
        label_sid(0, sys);
        sys[7] = 5; ((SID *)sys)->SubAuthority[0] = 18;                   /* S-1-5-18 SYSTEM */
        InitializeAcl(acl, sizeof aclbuf, ACL_REVISION);
        sec_add_simple_ace(acl, ACCESS_ALLOWED_ACE_TYPE, 0, GENERIC_ALL, sec_user_sid(), MAXDWORD);
        sec_add_simple_ace(acl, ACCESS_ALLOWED_ACE_TYPE, 0, GENERIC_ALL, (PSID)sys, MAXDWORD);
        acl->AclSize = (WORD)sec_acl_used(acl);
        p = oreserve(&o, acl->AclSize, 4);
        if (pp && p) { memcpy(p, acl, acl->AclSize); *pp = p; }
        break;
    }
    case TokenSource: {
        TOKEN_SOURCE *s = oreserve(&o, sizeof *s, 4);
        if (s) { memcpy(s->SourceName, "User32  ", 8); s->SourceIdentifier.LowPart = 0x3e8; s->SourceIdentifier.HighPart = 0; }
        break;
    }
    case TokenType: { DWORD *v = oreserve(&o, 4, 4); if (v) *v = t.type; break; }
    case TokenImpersonationLevel:
        if (t.type != TokenImpersonation) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
        { DWORD *v = oreserve(&o, 4, 4); if (v) *v = t.imp_level; }
        break;
    case TokenStatistics: {
        TOKEN_STATISTICS *s = oreserve(&o, sizeof *s, 8);
        if (s) {
            memset(s, 0, sizeof *s);
            s->TokenId.LowPart = (DWORD)t.id; s->TokenId.HighPart = (LONG)(t.id >> 32);
            s->AuthenticationId.LowPart = (DWORD)t.auth_id; s->AuthenticationId.HighPart = (LONG)(t.auth_id >> 32);
            s->ExpirationTime.QuadPart = 0x7fffffffffffffffll;
            s->TokenType = (TOKEN_TYPE)t.type;
            s->ImpersonationLevel = (SECURITY_IMPERSONATION_LEVEL)t.imp_level;
            s->DynamicCharged = 4096;
            s->DynamicAvailable = 4096;
            s->GroupCount = NGROUPS + 1;
            s->PrivilegeCount = NPRIVS;
            s->ModifiedId.LowPart = (DWORD)t.modified_id; s->ModifiedId.HighPart = (LONG)(t.modified_id >> 32);
        }
        break;
    }
    case TokenSessionId: { DWORD *v = oreserve(&o, 4, 4); if (v) *v = t.session; break; }
    case TokenOrigin: { LUID *v = oreserve(&o, sizeof *v, 4); if (v) { v->LowPart = 0x3e7; v->HighPart = 0; } break; }
    case TokenElevationType: { DWORD *v = oreserve(&o, 4, 4); if (v) *v = t.elevation_type; break; }
    case TokenLinkedToken:
        shz_set_last_error(ERROR_NO_SUCH_LOGON_SESSION);                  /* not a split (UAC) token */
        return FALSE;
    case TokenElevation: case TokenHasRestrictions: case TokenVirtualizationAllowed: case TokenVirtualizationEnabled:
    case TokenUIAccess: case TokenIsAppContainer: case TokenAppContainerNumber: case TokenIsRestricted: {
        DWORD *v = oreserve(&o, 4, 4);
        if (v) *v = 0;
        break;
    }
    case TokenIntegrityLevel: {
        TOKEN_MANDATORY_LABEL *l = oreserve(&o, sizeof *l, 8);
        PSID p;
        label_sid(t.integrity_rid, sid);
        p = oput_sid(&o, sid);
        if (l && p) { l->Label.Sid = p; l->Label.Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED; }
        break;
    }
    case TokenMandatoryPolicy: {
        TOKEN_MANDATORY_POLICY *v = oreserve(&o, sizeof *v, 4);
        if (v) v->Policy = TOKEN_MANDATORY_POLICY_NO_WRITE_UP | TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN;
        break;
    }
    case TokenAppContainerSid: { PSID *v = oreserve(&o, sizeof(PSID), 8); if (v) *v = 0; break; }   /* not an AppContainer */
    case 15:                        /* TokenSandBoxInert: not created with SANDBOX_INERT */
    case 42:                        /* TokenPrivateNameSpace: no private object namespace */
    case 46:                        /* TokenIsLessPrivilegedAppContainer */
    case 47: {                      /* TokenIsSandboxed: no AppContainer, not restricted, medium integrity */
        DWORD *v = oreserve(&o, 4, 4);
        if (v) *v = 0;
        break;
    }
    case 41: {                      /* TokenProcessTrustLevel: TOKEN_PROCESS_TRUST_LEVEL {TrustLevelSid}; not a protected process */
        PSID *v = oreserve(&o, sizeof(PSID), 8);
        if (v) *v = 0;
        break;
    }
    case 33: case 34: case 39: {    /* user / device claims, security attributes: CLAIM_SECURITY_ATTRIBUTES_INFORMATION, none */
        struct { WORD version, reserved; DWORD count; PVOID attrs; } *v = oreserve(&o, 16, 8);
        if (v) { v->version = 1; v->reserved = 0; v->count = 0; v->attrs = 0; }
        break;
    }
    case 37: {                      /* TokenDeviceGroups: no device (compound identity) groups */
        TOKEN_GROUPS *g = oreserve(&o, (DWORD)(8 + sizeof(SID_AND_ATTRIBUTES)), 8);
        if (g) g->GroupCount = 0;
        break;
    }
    default: {
        char what[40] = "information class ";
        unsigned n = 18, v = (unsigned)cls, d = 1;
        while (v / d >= 10) d *= 10;
        for (; d && n + 1 < sizeof what; d /= 10) what[n++] = (char)('0' + v / d % 10);
        what[n] = 0;
        return sec_unsupported("GetTokenInformation", what, ERROR_INVALID_PARAMETER);
    }
    }
    *ret = o.need;
    if (!buf || o.need > len) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    return TRUE;
}

DLLAPI BOOL WINAPI SetTokenInformation(HANDLE token, TOKEN_INFORMATION_CLASS cls, LPVOID buf, DWORD len)
{
    if (cls == TokenIntegrityLevel) {
        const TOKEN_MANDATORY_LABEL *l = buf;
        const SID *s;
        if (len < sizeof *l || !l->Label.Sid) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
        s = l->Label.Sid;
        if (!IsValidSid(l->Label.Sid) || s->IdentifierAuthority.Value[5] != 16 || s->SubAuthorityCount != 1) {
            shz_set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        return nt_ok(NtShzToken(SHZ_TOK_SET, (ULONG_PTR)token, SHZ_TOKF_INTEGRITY, s->SubAuthority[0]));
    }
    if (cls == TokenSessionId) {
        if (len < 4) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
        return nt_ok(NtShzToken(SHZ_TOK_SET, (ULONG_PTR)token, SHZ_TOKF_SESSION, *(const DWORD *)buf));
    }
    return sec_unsupported("SetTokenInformation", "information class (owner, group, default DACL, policy are fixed)", ERROR_NOT_SUPPORTED);
}

/* ---------------------------------------------------------------- privileges */
DLLAPI BOOL WINAPI LookupPrivilegeValueW(LPCWSTR system, LPCWSTR name, PLUID luid)
{
    unsigned i;
    if (system && system[0]) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < sizeof all_priv_names / sizeof all_priv_names[0]; ++i)
        if (wieq(name, all_priv_names[i].name)) { luid->LowPart = all_priv_names[i].luid; luid->HighPart = 0; return TRUE; }
    shz_set_last_error(ERROR_NO_SUCH_PRIVILEGE);
    return FALSE;
}
DLLAPI BOOL WINAPI LookupPrivilegeValueA(LPCSTR system, LPCSTR name, PLUID luid)
{
    WCHAR w[64];
    size_t i;
    for (i = 0; name[i] && i < 63; ++i) w[i] = (unsigned char)name[i];
    w[i] = 0;
    return LookupPrivilegeValueW(system && system[0] ? L"x" : 0, w, luid);
}
DLLAPI BOOL WINAPI LookupPrivilegeNameW(LPCWSTR system, PLUID luid, LPWSTR name, LPDWORD len)
{
    unsigned i;
    if (system && system[0]) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < sizeof all_priv_names / sizeof all_priv_names[0]; ++i)
        if (!luid->HighPart && luid->LowPart == all_priv_names[i].luid) {
            const size_t n = wcslen(all_priv_names[i].name);
            if (*len <= n) { *len = (DWORD)n + 1; shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
            memcpy(name, all_priv_names[i].name, (n + 1) * sizeof(WCHAR));
            *len = (DWORD)n;
            return TRUE;
        }
    shz_set_last_error(ERROR_NO_SUCH_PRIVILEGE);
    return FALSE;
}

DLLAPI BOOL WINAPI AdjustTokenPrivileges(HANDLE token, BOOL disable_all, PTOKEN_PRIVILEGES state, DWORD len, PTOKEN_PRIVILEGES prev, PDWORD ret)
{
    shz_token_info t;
    ULONG flags;
    DWORD i, k, not_all = 0, nprev = 0;
    if (!token_info(token, &t)) return FALSE;
    flags = t.flags;
    if (!disable_all && !state) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    for (k = 0; k < NPRIVS; ++k) {
        int want = -1;
        if (disable_all) want = 0;
        else
            for (i = 0; i < state->PrivilegeCount; ++i)
                if (!state->Privileges[i].Luid.HighPart && state->Privileges[i].Luid.LowPart == privs[k].luid)
                    want = (state->Privileges[i].Attributes & SE_PRIVILEGE_REMOVED) ? 0 : (state->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
        if (want < 0 || want == priv_enabled(&t, k)) continue;
        if (prev && len >= 4 + (nprev + 1) * sizeof(LUID_AND_ATTRIBUTES)) {
            prev->Privileges[nprev].Luid.LowPart = privs[k].luid;
            prev->Privileges[nprev].Luid.HighPart = 0;
            prev->Privileges[nprev].Attributes = priv_enabled(&t, k) ? SE_PRIVILEGE_ENABLED : 0;
        }
        ++nprev;
        flags ^= 1u << k;
    }
    if (!disable_all)
        for (i = 0; i < state->PrivilegeCount; ++i) {
            int held = 0;
            for (k = 0; k < NPRIVS; ++k) if (!state->Privileges[i].Luid.HighPart && state->Privileges[i].Luid.LowPart == privs[k].luid) held = 1;
            if (!held && (state->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)) not_all = 1;
        }
    if (prev) {
        if (len < 4 + nprev * sizeof(LUID_AND_ATTRIBUTES)) {
            if (ret) *ret = 4 + nprev * (DWORD)sizeof(LUID_AND_ATTRIBUTES);
            shz_set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        prev->PrivilegeCount = nprev;
    }
    if (ret) *ret = 4 + nprev * (DWORD)sizeof(LUID_AND_ATTRIBUTES);
    if (flags != t.flags && !nt_ok(NtShzToken(SHZ_TOK_SET, (ULONG_PTR)token, SHZ_TOKF_PRIVS, flags))) return FALSE;
    shz_set_last_error(not_all ? ERROR_NOT_ALL_ASSIGNED : ERROR_SUCCESS);
    return TRUE;
}

DLLAPI BOOL WINAPI PrivilegeCheck(HANDLE token, PPRIVILEGE_SET set, LPBOOL result)
{
    shz_token_info t;
    DWORD i, k, have = 0;
    if (!token_info(token, &t)) return FALSE;
    for (i = 0; i < set->PrivilegeCount; ++i) {
        int en = 0;
        for (k = 0; k < NPRIVS; ++k) if (!set->Privilege[i].Luid.HighPart && set->Privilege[i].Luid.LowPart == privs[k].luid) en = priv_enabled(&t, k);
        if (en) { set->Privilege[i].Attributes |= SE_PRIVILEGE_USED_FOR_ACCESS; ++have; }
    }
    *result = (set->Control & PRIVILEGE_SET_ALL_NECESSARY) ? have == set->PrivilegeCount : have > 0;
    return TRUE;
}

/* ---------------------------------------------------------------- membership, restriction */
/* Whether `sid` is the token's user or an enabled group of it. */
static BOOL token_has_sid(const shz_token_info *t, PSID sid)
{
    BYTE buf[SECURITY_MAX_SID_SIZE];
    unsigned i;
    if (EqualSid(sid, sec_user_sid())) return TRUE;
    for (i = 0; i < NGROUPS; ++i) { group_sid(i, t, buf); if (EqualSid(sid, (PSID)buf)) return TRUE; }
    return FALSE;
}

DLLAPI BOOL WINAPI CheckTokenMembership(HANDLE token, PSID sid, PBOOL member)
{
    shz_token_info t;
    HANDLE h = token, own = 0;
    if (!member || !IsValidSid(sid)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!h) {                                                              /* the thread's impersonation token, else the primary */
        if (NtOpenThreadToken(CURRENT_THREAD, TOKEN_QUERY, TRUE, &own) && NtOpenProcessToken(CURRENT_PROCESS, TOKEN_QUERY, &own))
            return nt_ok(STATUS_NO_TOKEN);
        h = own;
    } else {
        if (!token_info(h, &t)) return FALSE;
        if (t.type != TokenImpersonation) { shz_set_last_error(ERROR_NO_IMPERSONATION_TOKEN); return FALSE; }
    }
    if (!token_info(h, &t)) { if (own) NtClose(own); return FALSE; }
    *member = token_has_sid(&t, sid);
    if (own) NtClose(own);
    return TRUE;
}

DLLAPI BOOL WINAPI IsTokenRestricted(HANDLE token)
{
    shz_token_info t;
    if (!token_info(token, &t)) return FALSE;
    shz_set_last_error(0);
    return FALSE;                                                          /* restricted tokens cannot be created here */
}

DLLAPI BOOL WINAPI CreateRestrictedToken(HANDLE token, DWORD flags, DWORD ndisable, PSID_AND_ATTRIBUTES disable, DWORD ndelete,
                                         PLUID_AND_ATTRIBUTES del, DWORD nrestrict, PSID_AND_ATTRIBUTES restrict_sids, PHANDLE out)
{
    (void)token; (void)flags; (void)ndisable; (void)disable; (void)ndelete; (void)del; (void)nrestrict; (void)restrict_sids; (void)out;
    return sec_unsupported("CreateRestrictedToken", "restricted tokens are not modelled by the kernel", ERROR_NOT_SUPPORTED);
}

/* ---------------------------------------------------------------- impersonation */
static BOOL set_thread_token(HANDLE thread, HANDLE token)
{
    return nt_ok(NtShzToken(SHZ_TOK_IMPERSONATE, (ULONG_PTR)(thread ? thread : CURRENT_THREAD), (ULONG_PTR)token, 0));
}

DLLAPI BOOL WINAPI SetThreadToken(PHANDLE thread, HANDLE token) { return set_thread_token(thread ? *thread : 0, token); }
DLLAPI BOOL WINAPI RevertToSelf(void) { return set_thread_token(0, 0); }

static BOOL impersonate_copy(HANDLE token, SECURITY_IMPERSONATION_LEVEL level)
{
    HANDLE dup = 0;
    BOOL ok;
    if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, 0, level, TokenImpersonation, &dup)) return FALSE;
    ok = set_thread_token(0, dup);
    NtClose(dup);
    return ok;
}

DLLAPI BOOL WINAPI ImpersonateSelf(SECURITY_IMPERSONATION_LEVEL level)
{
    HANDLE tok = 0;
    BOOL ok;
    if (!OpenProcessToken(CURRENT_PROCESS, TOKEN_DUPLICATE, &tok)) return FALSE;
    ok = impersonate_copy(tok, level);
    NtClose(tok);
    return ok;
}

DLLAPI BOOL WINAPI ImpersonateLoggedOnUser(HANDLE token)
{
    shz_token_info t;
    if (!token_info(token, &t)) return FALSE;
    if (t.type == TokenImpersonation) return set_thread_token(0, token);
    return impersonate_copy(token, SecurityImpersonation);
}

/* The client of a named pipe is a process of the same (only) user: its token is duplicated for impersonation, as the
 * server would get it on Windows (at SecurityImpersonation). */
DLLAPI BOOL WINAPI ImpersonateNamedPipeClient(HANDLE pipe)
{
    ULONG pid = 0;
    HANDLE proc, tok = 0;
    BOOL ok;
    if (!GetNamedPipeClientProcessId(pipe, &pid)) return FALSE;
    proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc) return FALSE;
    ok = OpenProcessToken(proc, TOKEN_DUPLICATE, &tok) && impersonate_copy(tok, SecurityImpersonation);
    if (tok) NtClose(tok);
    NtClose(proc);
    return ok;
}

/* ---------------------------------------------------------------- AccessCheck */
DLLAPI BOOL WINAPI AccessCheck(PSECURITY_DESCRIPTOR psd, HANDLE token, DWORD desired, PGENERIC_MAPPING mapping, PPRIVILEGE_SET privs_out,
                               LPDWORD privs_len, LPDWORD granted, LPBOOL status)
{
    shz_token_info t;
    sec_parts_t p;
    DWORD want = desired, allowed = 0, denied = 0;
    WORD i;
    if (!psd || !mapping || !granted || !status) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!token_info(token, &t)) return FALSE;
    if (t.type != TokenImpersonation) { shz_set_last_error(ERROR_NO_IMPERSONATION_TOKEN); return FALSE; }
    if (!IsValidSecurityDescriptor(psd)) { shz_set_last_error(ERROR_INVALID_SECURITY_DESCR); return FALSE; }
    if (privs_len && *privs_len >= sizeof(PRIVILEGE_SET) && privs_out) privs_out->PrivilegeCount = 0;
    MapGenericMask(&want, mapping);
    sec_parts(psd, &p);
    if (p.owner && token_has_sid(&t, p.owner)) allowed |= READ_CONTROL | WRITE_DAC;          /* implicit owner rights */
    if (!(p.control & SE_DACL_PRESENT) || !p.dacl) {
        allowed |= mapping->GenericAll | STANDARD_RIGHTS_ALL | ACCESS_SYSTEM_SECURITY;       /* no DACL: everything */
    } else {
        const BYTE *a = (const BYTE *)(p.dacl + 1);
        for (i = 0; i < p.dacl->AceCount; ++i) {
            const ACE_HEADER *h = (const ACE_HEADER *)a;
            DWORD m;
            memcpy(&m, a + 4, 4);
            MapGenericMask(&m, mapping);
            if (!(h->AceFlags & INHERIT_ONLY_ACE) && token_has_sid(&t, (PSID)(a + 8))) {
                if (h->AceType == ACCESS_ALLOWED_ACE_TYPE) allowed |= m & ~denied;
                else if (h->AceType == ACCESS_DENIED_ACE_TYPE) denied |= m & ~allowed;
            }
            a += h->AceSize;
        }
    }
    if (p.sacl) {                                                          /* mandatory label: no write/read/execute up */
        const BYTE *a = (const BYTE *)(p.sacl + 1);
        for (i = 0; i < p.sacl->AceCount; ++i) {
            const ACE_HEADER *h = (const ACE_HEADER *)a;
            if (h->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
                DWORD policy, rid;
                memcpy(&policy, a + 4, 4);
                rid = ((const SID *)(a + 8))->SubAuthority[0];
                if (t.integrity_rid < rid) {
                    if (policy & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP) allowed &= ~(mapping->GenericWrite | WRITE_DAC | WRITE_OWNER | DELETE);
                    if (policy & SYSTEM_MANDATORY_LABEL_NO_READ_UP) allowed &= ~mapping->GenericRead;
                    if (policy & SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP) allowed &= ~mapping->GenericExecute;
                }
            }
            a += h->AceSize;
        }
    }
    if (want & MAXIMUM_ALLOWED) {
        *granted = allowed;
        *status = allowed != 0;
    } else {
        *granted = (want & allowed) == want ? want : 0;
        *status = *granted == want;
    }
    if (!*status) shz_set_last_error(ERROR_ACCESS_DENIED);
    return TRUE;
}

/* ---------------------------------------------------------------- CreateProcessAsUserW */
DLLAPI BOOL WINAPI CreateProcessAsUserW(HANDLE token, LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                        BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
    shz_token_info t;
    if (!token_info(token, &t)) return FALSE;
    if (t.type != TokenPrimary) { shz_set_last_error(ERROR_BAD_TOKEN_TYPE); return FALSE; }
    if (t.integrity_rid != 0x2000 || t.session != 1)                        /* a child always gets the default token */
        return sec_unsupported("CreateProcessAsUserW", "a token that differs from the default one", ERROR_NOT_SUPPORTED);
    return CreateProcessW(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
}

/* ---------------------------------------------------------------- account names */
static const struct { const WCHAR *name, *domain; const WCHAR *sid; SID_NAME_USE use; } accounts[] = {
    {L"Everyone", L"", L"S-1-1-0", SidTypeWellKnownGroup}, {L"LOCAL", L"", L"S-1-2-0", SidTypeWellKnownGroup},
    {L"CONSOLE LOGON", L"", L"S-1-2-1", SidTypeWellKnownGroup}, {L"CREATOR OWNER", L"", L"S-1-3-0", SidTypeWellKnownGroup},
    {L"INTERACTIVE", L"NT AUTHORITY", L"S-1-5-4", SidTypeWellKnownGroup}, {L"SYSTEM", L"NT AUTHORITY", L"S-1-5-18", SidTypeWellKnownGroup},
    {L"Authenticated Users", L"NT AUTHORITY", L"S-1-5-11", SidTypeWellKnownGroup},
    {L"This Organization", L"NT AUTHORITY", L"S-1-5-15", SidTypeWellKnownGroup},
    {L"LOCAL SERVICE", L"NT AUTHORITY", L"S-1-5-19", SidTypeWellKnownGroup}, {L"NETWORK SERVICE", L"NT AUTHORITY", L"S-1-5-20", SidTypeWellKnownGroup},
    {L"Administrators", L"BUILTIN", L"S-1-5-32-544", SidTypeAlias}, {L"Users", L"BUILTIN", L"S-1-5-32-545", SidTypeAlias},
    {L"Guests", L"BUILTIN", L"S-1-5-32-546", SidTypeAlias},
    {L"ALL APPLICATION PACKAGES", L"APPLICATION PACKAGE AUTHORITY", L"S-1-15-2-1", SidTypeWellKnownGroup},
    {L"Low Mandatory Level", L"Mandatory Label", L"S-1-16-4096", SidTypeLabel},
    {L"Medium Mandatory Level", L"Mandatory Label", L"S-1-16-8192", SidTypeLabel},
    {L"High Mandatory Level", L"Mandatory Label", L"S-1-16-12288", SidTypeLabel},
    {L"System Mandatory Level", L"Mandatory Label", L"S-1-16-16384", SidTypeLabel},
};
static const WCHAR machine[] = L"SHZ-K64";

PSID sec_sid_for_name(LPCWSTR name)
{
    PSID s = 0;
    unsigned i;
    const WCHAR *bs = name;
    for (; *name; ++name) if (*name == '\\') bs = name + 1;                  /* DOMAIN\name -> name */
    name = bs;
    if (wieq(name, L"CURRENT_USER") || wieq(name, SHZ_USER_NAME_W)) {
        const DWORD n = GetLengthSid(sec_user_sid());
        s = LocalAlloc(LMEM_FIXED, n);
        if (s) memcpy(s, sec_user_sid(), n);
        return s;
    }
    for (i = 0; i < sizeof accounts / sizeof accounts[0]; ++i)
        if (wieq(name, accounts[i].name)) { ConvertStringSidToSidW(accounts[i].sid, &s); return s; }
    return 0;
}

static BOOL put_name(LPWSTR out, LPDWORD cap, const WCHAR *s, BOOL *small)
{
    const DWORD n = (DWORD)wcslen(s);
    if (*cap <= n || !out) { *cap = n + 1; *small = TRUE; return FALSE; }
    memcpy(out, s, (n + 1) * sizeof(WCHAR));
    *cap = n;
    return TRUE;
}

DLLAPI BOOL WINAPI LookupAccountSidW(LPCWSTR system, PSID sid, LPWSTR name, LPDWORD name_len, LPWSTR domain, LPDWORD domain_len,
                                     PSID_NAME_USE use)
{
    const WCHAR *n = 0, *d = 0;
    SID_NAME_USE u = SidTypeUnknown;
    BOOL small = FALSE;
    unsigned i;
    if (system && system[0]) { shz_set_last_error(ERROR_NONE_MAPPED); return FALSE; }
    if (!IsValidSid(sid)) { shz_set_last_error(ERROR_INVALID_SID); return FALSE; }
    if (EqualSid(sid, sec_user_sid())) { n = SHZ_USER_NAME_W; d = machine; u = SidTypeUser; }
    else if (EqualSid(sid, sec_primary_group_sid())) { n = L"None"; d = machine; u = SidTypeGroup; }
    else
        for (i = 0; i < sizeof accounts / sizeof accounts[0] && !n; ++i) {
            PSID s = 0;
            if (ConvertStringSidToSidW(accounts[i].sid, &s)) {
                if (EqualSid(s, sid)) { n = accounts[i].name; d = accounts[i].domain; u = accounts[i].use; }
                LocalFree(s);
            }
        }
    if (!n) { shz_set_last_error(ERROR_NONE_MAPPED); return FALSE; }
    put_name(name, name_len, n, &small);
    put_name(domain, domain_len, d, &small);
    if (small) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    if (use) *use = u;
    return TRUE;
}

DLLAPI BOOL WINAPI LookupAccountNameW(LPCWSTR system, LPCWSTR account, PSID sid, LPDWORD sid_len, LPWSTR domain, LPDWORD domain_len,
                                      PSID_NAME_USE use)
{
    PSID s;
    DWORD n;
    WCHAR nm[64];
    DWORD nml = 64;
    SID_NAME_USE u;
    BOOL small = FALSE;
    if (system && system[0]) { shz_set_last_error(ERROR_NONE_MAPPED); return FALSE; }
    s = sec_sid_for_name(account);
    if (!s) { shz_set_last_error(ERROR_NONE_MAPPED); return FALSE; }
    n = GetLengthSid(s);
    if (!sid || *sid_len < n) { *sid_len = n; small = TRUE; } else { memcpy(sid, s, n); *sid_len = n; }
    {
        WCHAR dom[64];
        DWORD dl = 64;
        if (!LookupAccountSidW(0, s, nm, &nml, dom, &dl, &u)) { LocalFree(s); return FALSE; }
        put_name(domain, domain_len, dom, &small);
    }
    LocalFree(s);
    if (small) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    if (use) *use = u;
    return TRUE;
}
