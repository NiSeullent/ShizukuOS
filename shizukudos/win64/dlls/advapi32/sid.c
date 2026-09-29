/* SPDX-License-Identifier: GPL-2.0-only
 * advapi32.dll: security identifiers (SID) and the pure helpers around them.
 *
 * A SID is plain data (revision, authority, sub-authorities), so these functions have their full Windows semantics here:
 * validation, copying, comparison, allocation, the "S-1-5-32-544" string forms in both directions, and the well-known SID
 * table. What is deliberately NOT here: everything that needs a logon session or a kernel security object (access tokens,
 * LookupAccountSid, AccessCheck, ACL/SD editing). Kernel64 has a single user and no tokens.
 *
 * Deviations, all limits of an incomplete table rather than different answers: ConvertStringSidToSidW knows the SDDL
 * abbreviations listed in sddl_abbrev[] (the fixed-value ones) and rejects others with ERROR_INVALID_SID; CreateWellKnownSid
 * covers the types listed in well_known[] and answers the rest with ERROR_INVALID_PARAMETER.
 */
#define _ADVAPI32_
#include "nt.h"
#include <string.h>
#include <sddl.h>
#include <securitybaseapi.h>
#include <ntsecapi.h>

#define SID_HEADER 8u

static BOOL sid_valid(const SID *s) { return s && s->Revision == SID_REVISION && s->SubAuthorityCount <= SID_MAX_SUB_AUTHORITIES; }
static DWORD sid_len(const SID *s) { return SID_HEADER + 4u * s->SubAuthorityCount; }

DLLAPI BOOL WINAPI IsValidSid(PSID pSid) { return sid_valid((const SID *)pSid); }

DLLAPI DWORD WINAPI GetLengthSid(PSID pSid) { return sid_len((const SID *)pSid); }

DLLAPI BOOL WINAPI EqualSid(PSID pSid1, PSID pSid2)
{
    const SID *a = pSid1, *b = pSid2;
    if (a->Revision != b->Revision || a->SubAuthorityCount != b->SubAuthorityCount) return FALSE;
    return memcmp(a, b, sid_len(a)) == 0;
}

DLLAPI BOOL WINAPI CopySid(DWORD nDestinationSidLength, PSID pDestinationSid, PSID pSourceSid)
{
    const DWORD n = sid_len((const SID *)pSourceSid);
    if (nDestinationSidLength < n) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    memcpy(pDestinationSid, pSourceSid, n);
    return TRUE;
}

DLLAPI PUCHAR WINAPI GetSidSubAuthorityCount(PSID pSid) { return &((SID *)pSid)->SubAuthorityCount; }

DLLAPI PDWORD WINAPI GetSidSubAuthority(PSID pSid, DWORD nSubAuthority) { return &((SID *)pSid)->SubAuthority[nSubAuthority]; }

DLLAPI DWORD WINAPI GetSidLengthRequired(UCHAR nSubAuthorityCount) { return SID_HEADER + 4u * nSubAuthorityCount; }

DLLAPI BOOL WINAPI InitializeSid(PSID pSid, PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount)
{
    SID *s = pSid;
    if (nSubAuthorityCount > SID_MAX_SUB_AUTHORITIES) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    s->Revision = SID_REVISION;
    s->SubAuthorityCount = nSubAuthorityCount;
    s->IdentifierAuthority = *pIdentifierAuthority;
    return TRUE;
}

DLLAPI BOOL WINAPI AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD nSubAuthority0,
                                            DWORD nSubAuthority1, DWORD nSubAuthority2, DWORD nSubAuthority3, DWORD nSubAuthority4,
                                            DWORD nSubAuthority5, DWORD nSubAuthority6, DWORD nSubAuthority7, PSID *pSid)
{
    const DWORD sub[8] = { nSubAuthority0, nSubAuthority1, nSubAuthority2, nSubAuthority3, nSubAuthority4, nSubAuthority5, nSubAuthority6, nSubAuthority7 };
    SID *s;
    DWORD i;
    if (nSubAuthorityCount > 8) { shz_set_last_error(ERROR_INVALID_SID); return FALSE; }
    s = RtlAllocateHeap(ShzProcessHeap(), 0, GetSidLengthRequired(nSubAuthorityCount));
    if (!s) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    s->Revision = SID_REVISION;
    s->SubAuthorityCount = nSubAuthorityCount;
    s->IdentifierAuthority = *pIdentifierAuthority;
    for (i = 0; i < nSubAuthorityCount; ++i) s->SubAuthority[i] = sub[i];
    *pSid = s;
    return TRUE;
}

DLLAPI PVOID WINAPI FreeSid(PSID pSid)
{
    if (pSid) RtlFreeHeap(ShzProcessHeap(), 0, pSid);
    return 0;
}

/* ---------------------------------------------------------------- SID <-> string */
/* Text form per the Windows conversion: "S-<revision>-<authority>-<sub>...". The authority is decimal when it fits in the
 * last 32 bits (first two bytes zero), otherwise "0x" followed by its six bytes in lower-case hex. */
static size_t sid_to_text(const SID *s, char *out, size_t cap)
{
    size_t n = 0;
    DWORD i;
    static const char hex[] = "0123456789abcdef";
    char tmp[16];
#define PUTC(c) do { const char c_ = (c); if (out && n < cap) out[n] = c_; ++n; } while (0)   /* c has side effects: evaluate it once */
#define PUTDEC(v) do { unsigned long long q_ = (v); int t_ = 0; if (!q_) tmp[t_++] = '0'; while (q_) { tmp[t_++] = (char)('0' + q_ % 10); q_ /= 10; } while (t_) PUTC(tmp[--t_]); } while (0)
    PUTC('S'); PUTC('-');
    PUTDEC(s->Revision);
    PUTC('-');
    if (s->IdentifierAuthority.Value[0] || s->IdentifierAuthority.Value[1]) {
        PUTC('0'); PUTC('x');
        for (i = 0; i < 6; ++i) { PUTC(hex[s->IdentifierAuthority.Value[i] >> 4]); PUTC(hex[s->IdentifierAuthority.Value[i] & 15]); }
    } else {
        const unsigned long long a = ((unsigned long long)s->IdentifierAuthority.Value[2] << 24) | ((unsigned long long)s->IdentifierAuthority.Value[3] << 16) |
                                     ((unsigned long long)s->IdentifierAuthority.Value[4] << 8) | s->IdentifierAuthority.Value[5];
        PUTDEC(a);
    }
    for (i = 0; i < s->SubAuthorityCount; ++i) { PUTC('-'); PUTDEC(s->SubAuthority[i]); }
#undef PUTDEC
#undef PUTC
    return n;
}

DLLAPI BOOL WINAPI ConvertSidToStringSidW(PSID Sid, LPWSTR *StringSid)
{
    char *tmp;
    WCHAR *w;
    size_t n, i;
    if (!sid_valid(Sid) || !StringSid) { shz_set_last_error(sid_valid(Sid) ? ERROR_INVALID_PARAMETER : ERROR_INVALID_SID); return FALSE; }
    n = sid_to_text(Sid, 0, 0);
    tmp = RtlAllocateHeap(ShzProcessHeap(), 0, n + 1);
    if (!tmp) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    sid_to_text(Sid, tmp, n);
    w = LocalAlloc(LMEM_FIXED, (n + 1) * sizeof(WCHAR));                 /* the caller releases it with LocalFree */
    if (!w) { RtlFreeHeap(ShzProcessHeap(), 0, tmp); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    for (i = 0; i < n; ++i) w[i] = (WCHAR)(unsigned char)tmp[i];
    w[n] = 0;
    RtlFreeHeap(ShzProcessHeap(), 0, tmp);
    *StringSid = w;
    return TRUE;
}

DLLAPI BOOL WINAPI ConvertSidToStringSidA(PSID Sid, LPSTR *StringSid)
{
    char *a;
    size_t n;
    if (!sid_valid(Sid) || !StringSid) { shz_set_last_error(sid_valid(Sid) ? ERROR_INVALID_PARAMETER : ERROR_INVALID_SID); return FALSE; }
    n = sid_to_text(Sid, 0, 0);
    a = LocalAlloc(LMEM_FIXED, n + 1);
    if (!a) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    sid_to_text(Sid, a, n);
    a[n] = 0;
    *StringSid = a;
    return TRUE;
}

/* SDDL two-letter SID abbreviations with a fixed value (sddl.h documentation). Domain-relative ones (DA, DU, ...) are not listed. */
static const struct { char a, b; BYTE auth; BYTE count; DWORD sub[2]; } sddl_abbrev[] = {
    {'W', 'D', 1, 1, {0, 0}},                       /* Everyone S-1-1-0 */
    {'C', 'O', 3, 1, {0, 0}}, {'C', 'G', 3, 1, {1, 0}}, {'O', 'W', 3, 1, {4, 0}},
    {'N', 'U', 5, 1, {2, 0}}, {'I', 'U', 5, 1, {4, 0}}, {'S', 'U', 5, 1, {6, 0}}, {'A', 'N', 5, 1, {7, 0}},
    {'P', 'S', 5, 1, {10, 0}}, {'A', 'U', 5, 1, {11, 0}}, {'R', 'C', 5, 1, {12, 0}}, {'S', 'Y', 5, 1, {18, 0}},
    {'L', 'S', 5, 1, {19, 0}}, {'N', 'S', 5, 1, {20, 0}},
    {'B', 'A', 5, 2, {32, 544}}, {'B', 'U', 5, 2, {32, 545}}, {'B', 'G', 5, 2, {32, 546}}, {'P', 'U', 5, 2, {32, 547}},
    {'A', 'O', 5, 2, {32, 548}}, {'S', 'O', 5, 2, {32, 549}}, {'P', 'O', 5, 2, {32, 550}}, {'B', 'O', 5, 2, {32, 551}},
    {'R', 'E', 5, 2, {32, 552}}, {'R', 'U', 5, 2, {32, 554}}, {'R', 'D', 5, 2, {32, 555}}, {'N', 'O', 5, 2, {32, 556}},
    {'L', 'W', 16, 1, {4096, 0}}, {'M', 'E', 16, 1, {8192, 0}}, {'H', 'I', 16, 1, {12288, 0}}, {'S', 'I', 16, 1, {16384, 0}},
};

/* Parses one unsigned number (decimal, or hex with 0x) from `s` up to the next '-' or end. Returns the end or 0. */
static const WCHAR *parse_number(const WCHAR *s, unsigned long long *out, unsigned long long max)
{
    unsigned long long v = 0;
    int digits = 0;
    if (s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) {
        s += 2;
        for (; (*s >= L'0' && *s <= L'9') || (*s >= L'a' && *s <= L'f') || (*s >= L'A' && *s <= L'F'); ++s, ++digits) {
            const unsigned d = *s <= L'9' ? (unsigned)(*s - L'0') : (unsigned)((*s | 0x20) - L'a' + 10);
            if (v > (max >> 4)) return 0;
            v = v * 16 + d;
        }
    } else {
        for (; *s >= L'0' && *s <= L'9'; ++s, ++digits) {
            const unsigned d = (unsigned)(*s - L'0');
            if (v > (max - d) / 10) return 0;
            v = v * 10 + d;
        }
    }
    if (!digits || v > max) return 0;
    *out = v;
    return s;
}

DLLAPI BOOL WINAPI ConvertStringSidToSidW(LPCWSTR StringSid, PSID *Sid)
{
    SID_IDENTIFIER_AUTHORITY auth;
    DWORD sub[SID_MAX_SUB_AUTHORITIES];
    unsigned count = 0, i;
    unsigned long long v;
    const WCHAR *p = StringSid;
    SID *out;
    if (!StringSid || !Sid) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    memset(&auth, 0, sizeof auth);
    if (p[0] && p[1] && !p[2]) {                                          /* two-letter SDDL abbreviation */
        for (i = 0; i < sizeof sddl_abbrev / sizeof sddl_abbrev[0]; ++i)
            if ((p[0] & ~0x20) == sddl_abbrev[i].a && (p[1] & ~0x20) == sddl_abbrev[i].b) {
                auth.Value[5] = sddl_abbrev[i].auth;
                count = sddl_abbrev[i].count;
                sub[0] = sddl_abbrev[i].sub[0];
                sub[1] = sddl_abbrev[i].sub[1];
                goto build;
            }
        goto invalid;
    }
    if ((p[0] != L'S' && p[0] != L's') || p[1] != L'-') goto invalid;
    p += 2;
    p = parse_number(p, &v, 255);                                         /* revision */
    if (!p || v != SID_REVISION || *p != L'-') goto invalid;
    ++p;
    /* identifier authority: decimal up to 32 bits, or 0x-prefixed hexadecimal up to 48 bits */
    p = parse_number(p, &v, (p[0] == L'0' && (p[1] == L'x' || p[1] == L'X')) ? 0xFFFFFFFFFFFFull : 0xFFFFFFFFull);
    if (!p) goto invalid;
    for (i = 0; i < 6; ++i) auth.Value[i] = (BYTE)(v >> (8 * (5 - i)));
    while (*p == L'-') {
        if (count >= SID_MAX_SUB_AUTHORITIES) goto invalid;
        p = parse_number(p + 1, &v, 0xFFFFFFFFull);
        if (!p) goto invalid;
        sub[count++] = (DWORD)v;
    }
    if (*p) goto invalid;
build:
    out = LocalAlloc(LMEM_FIXED, GetSidLengthRequired((UCHAR)count));
    if (!out) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    out->Revision = SID_REVISION;
    out->SubAuthorityCount = (BYTE)count;
    out->IdentifierAuthority = auth;
    for (i = 0; i < count; ++i) out->SubAuthority[i] = sub[i];
    *Sid = out;
    return TRUE;
invalid:
    shz_set_last_error(ERROR_INVALID_SID);
    return FALSE;
}

/* ---------------------------------------------------------------- well-known SIDs */
static const struct { WELL_KNOWN_SID_TYPE type; BYTE auth; BYTE count; DWORD sub[2]; } well_known[] = {
    {WinNullSid, 0, 1, {0, 0}}, {WinWorldSid, 1, 1, {0, 0}}, {WinLocalSid, 2, 1, {0, 0}},
    {WinCreatorOwnerSid, 3, 1, {0, 0}}, {WinCreatorGroupSid, 3, 1, {1, 0}}, {WinCreatorOwnerServerSid, 3, 1, {2, 0}},
    {WinCreatorGroupServerSid, 3, 1, {3, 0}}, {WinCreatorOwnerRightsSid, 3, 1, {4, 0}},
    {WinNtAuthoritySid, 5, 0, {0, 0}}, {WinDialupSid, 5, 1, {1, 0}}, {WinNetworkSid, 5, 1, {2, 0}}, {WinBatchSid, 5, 1, {3, 0}},
    {WinInteractiveSid, 5, 1, {4, 0}}, {WinServiceSid, 5, 1, {6, 0}}, {WinAnonymousSid, 5, 1, {7, 0}}, {WinProxySid, 5, 1, {8, 0}},
    {WinEnterpriseControllersSid, 5, 1, {9, 0}}, {WinSelfSid, 5, 1, {10, 0}}, {WinAuthenticatedUserSid, 5, 1, {11, 0}},
    {WinRestrictedCodeSid, 5, 1, {12, 0}}, {WinTerminalServerSid, 5, 1, {13, 0}}, {WinRemoteLogonIdSid, 5, 1, {14, 0}},
    {WinThisOrganizationSid, 5, 1, {15, 0}}, {WinIUserSid, 5, 1, {17, 0}},
    {WinLocalSystemSid, 5, 1, {18, 0}}, {WinLocalServiceSid, 5, 1, {19, 0}}, {WinNetworkServiceSid, 5, 1, {20, 0}},
    {WinWriteRestrictedCodeSid, 5, 1, {33, 0}}, {WinOtherOrganizationSid, 5, 1, {1000, 0}},
    {WinBuiltinDomainSid, 5, 1, {32, 0}},
    {WinBuiltinAdministratorsSid, 5, 2, {32, 544}}, {WinBuiltinUsersSid, 5, 2, {32, 545}}, {WinBuiltinGuestsSid, 5, 2, {32, 546}},
    {WinBuiltinPowerUsersSid, 5, 2, {32, 547}}, {WinBuiltinAccountOperatorsSid, 5, 2, {32, 548}},
    {WinBuiltinSystemOperatorsSid, 5, 2, {32, 549}}, {WinBuiltinPrintOperatorsSid, 5, 2, {32, 550}},
    {WinBuiltinBackupOperatorsSid, 5, 2, {32, 551}}, {WinBuiltinReplicatorSid, 5, 2, {32, 552}},
    {WinBuiltinPreWindows2000CompatibleAccessSid, 5, 2, {32, 554}}, {WinBuiltinRemoteDesktopUsersSid, 5, 2, {32, 555}},
    {WinBuiltinNetworkConfigurationOperatorsSid, 5, 2, {32, 556}}, {WinBuiltinIncomingForestTrustBuildersSid, 5, 2, {32, 557}},
    {WinBuiltinPerfMonitoringUsersSid, 5, 2, {32, 558}}, {WinBuiltinPerfLoggingUsersSid, 5, 2, {32, 559}},
    {WinBuiltinAuthorizationAccessSid, 5, 2, {32, 560}}, {WinBuiltinTerminalServerLicenseServersSid, 5, 2, {32, 561}},
    {WinBuiltinDCOMUsersSid, 5, 2, {32, 562}}, {WinBuiltinIUsersSid, 5, 2, {32, 568}}, {WinBuiltinCryptoOperatorsSid, 5, 2, {32, 569}},
    {WinNTLMAuthenticationSid, 5, 2, {64, 10}}, {WinSChannelAuthenticationSid, 5, 2, {64, 14}}, {WinDigestAuthenticationSid, 5, 2, {64, 21}},
    {WinUntrustedLabelSid, 16, 1, {0, 0}}, {WinLowLabelSid, 16, 1, {4096, 0}}, {WinMediumLabelSid, 16, 1, {8192, 0}},
    {WinMediumPlusLabelSid, 16, 1, {8448, 0}}, {WinHighLabelSid, 16, 1, {12288, 0}}, {WinSystemLabelSid, 16, 1, {16384, 0}},
    {WinApplicationPackageAuthoritySid, 15, 1, {2, 0}}, {WinBuiltinAnyPackageSid, 15, 2, {2, 1}},
};

/* Domain-relative types: the domain SID plus one RID. */
static const struct { WELL_KNOWN_SID_TYPE type; DWORD rid; } domain_rid[] = {
    {WinAccountAdministratorSid, 500}, {WinAccountGuestSid, 501}, {WinAccountKrbtgtSid, 502}, {WinAccountDomainAdminsSid, 512},
    {WinAccountDomainUsersSid, 513}, {WinAccountDomainGuestsSid, 514}, {WinAccountComputersSid, 515},
    {WinAccountControllersSid, 516}, {WinAccountCertAdminsSid, 517}, {WinAccountSchemaAdminsSid, 518},
    {WinAccountEnterpriseAdminsSid, 519}, {WinAccountPolicyAdminsSid, 520}, {WinAccountRasAndIasServersSid, 553},
};

DLLAPI BOOL WINAPI CreateWellKnownSid(WELL_KNOWN_SID_TYPE WellKnownSidType, PSID DomainSid, PSID pSid, DWORD *cbSid)
{
    unsigned i;
    DWORD need, k;
    SID *s = pSid;
    if (!cbSid) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < sizeof well_known / sizeof well_known[0]; ++i) {
        if (well_known[i].type != WellKnownSidType) continue;
        need = GetSidLengthRequired(well_known[i].count);
        if (*cbSid < need) { *cbSid = need; shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        if (!s) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
        memset(&s->IdentifierAuthority, 0, sizeof s->IdentifierAuthority);
        s->Revision = SID_REVISION;
        s->SubAuthorityCount = well_known[i].count;
        s->IdentifierAuthority.Value[5] = well_known[i].auth;
        for (k = 0; k < well_known[i].count; ++k) s->SubAuthority[k] = well_known[i].sub[k];
        *cbSid = need;
        return TRUE;
    }
    for (i = 0; i < sizeof domain_rid / sizeof domain_rid[0]; ++i) {
        const SID *d = DomainSid;
        if (domain_rid[i].type != WellKnownSidType) continue;
        if (!d || !sid_valid(d) || d->SubAuthorityCount >= SID_MAX_SUB_AUTHORITIES) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
        need = GetSidLengthRequired((UCHAR)(d->SubAuthorityCount + 1));
        if (*cbSid < need) { *cbSid = need; shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        if (!s) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
        memmove(s, d, sid_len(d));                                        /* the domain SID may already be at pSid */
        s->SubAuthority[d->SubAuthorityCount] = domain_rid[i].rid;
        s->SubAuthorityCount = (BYTE)(d->SubAuthorityCount + 1);
        *cbSid = need;
        return TRUE;
    }
    shz_set_last_error(ERROR_INVALID_PARAMETER);                          /* type not in the table above */
    return FALSE;
}

/* ---------------------------------------------------------------- access-mask helper and status translation */
DLLAPI VOID WINAPI MapGenericMask(PDWORD AccessMask, PGENERIC_MAPPING GenericMapping)
{
    DWORD m = *AccessMask;
    if (m & GENERIC_READ) m |= GenericMapping->GenericRead;
    if (m & GENERIC_WRITE) m |= GenericMapping->GenericWrite;
    if (m & GENERIC_EXECUTE) m |= GenericMapping->GenericExecute;
    if (m & GENERIC_ALL) m |= GenericMapping->GenericAll;
    *AccessMask = m & ~(DWORD)(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

DLLAPI ULONG WINAPI LsaNtStatusToWinError(NTSTATUS Status) { return RtlNtStatusToDosError(Status); }
