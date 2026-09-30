/* SPDX-License-Identifier: GPL-2.0-only
 * netapi32.dll - domain membership and local user information, as far as this single-user, stand-alone system has them.
 *
 *   NetGetJoinInformation            the machine is a stand-alone workstation in Windows' default workgroup
 *                                    ("WORKGROUP", NetSetupWorkgroupName): there is no domain-join facility.
 *   DsRoleGetPrimaryDomainInformation  DsRolePrimaryDomainInfoBasic: DsRole_RoleStandaloneWorkstation, flat name
 *                                    "WORKGROUP", no DNS domain, no forest, no GUID. Other levels: ERROR_INVALID_PARAMETER.
 *   NetGetAadJoinInformation         not joined to Azure AD: S_OK with *join_info = NULL (the documented answer).
 *   NetUserGetInfo                   the local account advapi32 reports (GetUserNameW), levels 0 (name) and 10 (name,
 *                                    comments, full name - empty); other levels ERROR_INVALID_LEVEL, other users
 *                                    NERR_UserNotFound, a remote server ERROR_BAD_NETPATH (no network client here).
 *   NetApiBufferAllocate/Free/Size, DsRoleFreeMemory, NetFreeAadJoinInformation   one process-heap allocator.
 */
#include "nt.h"
#include <string.h>

#define NERR_Success 0
#define NERR_UserNotFound 2221
#define NETSETUP_WORKGROUP_NAME 2
#define DSROLE_STANDALONE_WORKSTATION 0
#define DSROLE_PRIMARY_DOMAIN_INFO_BASIC 1

static const WCHAR g_workgroup[] = L"WORKGROUP";

static size_t wlen(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }

static int is_local_server(LPCWSTR server)
{
    WCHAR me[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD n = MAX_COMPUTERNAME_LENGTH + 1;
    size_t i;
    if (!server || !server[0]) return 1;
    if (server[0] == '\\' && server[1] == '\\') server += 2;
    if (!GetComputerNameW(me, &n)) return 0;
    for (i = 0; me[i] && server[i]; ++i) {
        WCHAR a = me[i], b = server[i];
        if (a >= 'a' && a <= 'z') a = (WCHAR)(a - 32);
        if (b >= 'a' && b <= 'z') b = (WCHAR)(b - 32);
        if (a != b) return 0;
    }
    return !me[i] && !server[i];
}

DLLAPI DWORD WINAPI NetApiBufferAllocate(DWORD size, LPVOID *buf)
{
    if (!buf) return ERROR_INVALID_PARAMETER;
    *buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size ? size : 1);
    return *buf ? NERR_Success : ERROR_NOT_ENOUGH_MEMORY;
}

DLLAPI DWORD WINAPI NetApiBufferFree(LPVOID buf)
{
    if (buf && !HeapFree(GetProcessHeap(), 0, buf)) return ERROR_INVALID_PARAMETER;
    return NERR_Success;
}

DLLAPI DWORD WINAPI NetApiBufferSize(LPVOID buf, LPDWORD size)
{
    SIZE_T n;
    if (!buf || !size) return ERROR_INVALID_PARAMETER;
    n = HeapSize(GetProcessHeap(), 0, buf);
    if (n == (SIZE_T)-1) return ERROR_INVALID_PARAMETER;
    *size = (DWORD)n;
    return NERR_Success;
}

static WCHAR *dup_w(const WCHAR *s)
{
    const size_t n = wlen(s) + 1;
    WCHAR *d = 0;
    if (NetApiBufferAllocate((DWORD)(n * sizeof(WCHAR)), (LPVOID *)&d)) return 0;
    memcpy(d, s, n * sizeof(WCHAR));
    return d;
}

DLLAPI DWORD WINAPI NetGetJoinInformation(LPCWSTR server, LPWSTR *name, DWORD *type)
{
    if (!name || !type) return ERROR_INVALID_PARAMETER;
    if (!is_local_server(server)) return ERROR_BAD_NETPATH;
    *name = dup_w(g_workgroup);
    if (!*name) return ERROR_NOT_ENOUGH_MEMORY;
    *type = NETSETUP_WORKGROUP_NAME;
    return NERR_Success;
}

typedef struct {
    DWORD MachineRole, Flags;
    LPWSTR DomainNameFlat, DomainNameDns, DomainForestName;
    GUID DomainGuid;
} dsrole_basic;

DLLAPI DWORD WINAPI DsRoleGetPrimaryDomainInformation(LPCWSTR server, int level, PBYTE *buffer)
{
    dsrole_basic *b = 0;
    const size_t n = wlen(g_workgroup) + 1;
    if (!buffer) return ERROR_INVALID_PARAMETER;
    *buffer = 0;
    if (!is_local_server(server)) return ERROR_BAD_NETPATH;
    if (level != DSROLE_PRIMARY_DOMAIN_INFO_BASIC) return ERROR_INVALID_PARAMETER;
    if (NetApiBufferAllocate((DWORD)(sizeof *b + n * sizeof(WCHAR)), (LPVOID *)&b)) return ERROR_NOT_ENOUGH_MEMORY;
    b->MachineRole = DSROLE_STANDALONE_WORKSTATION;
    b->DomainNameFlat = (LPWSTR)(b + 1);
    memcpy(b->DomainNameFlat, g_workgroup, n * sizeof(WCHAR));
    *buffer = (PBYTE)b;
    return ERROR_SUCCESS;
}

DLLAPI VOID WINAPI DsRoleFreeMemory(PVOID buf) { NetApiBufferFree(buf); }

DLLAPI HRESULT WINAPI NetGetAadJoinInformation(LPCWSTR tenant, PVOID *join_info)
{
    (void)tenant;
    if (!join_info) return E_INVALIDARG;
    *join_info = 0;                                             /* not joined to Azure AD */
    return S_OK;
}

DLLAPI VOID WINAPI NetFreeAadJoinInformation(PVOID join_info) { NetApiBufferFree(join_info); }

DLLAPI DWORD WINAPI NetUserGetInfo(LPCWSTR server, LPCWSTR user, DWORD level, LPBYTE *buf)
{
    WCHAR me[257];
    DWORD n = 257;
    size_t i, len;
    if (!buf || !user) return ERROR_INVALID_PARAMETER;
    *buf = 0;
    if (!is_local_server(server)) return ERROR_BAD_NETPATH;
    if (!GetUserNameW(me, &n)) return GetLastError();
    for (i = 0; me[i] && user[i]; ++i) {
        WCHAR a = me[i], b = user[i];
        if (a >= 'a' && a <= 'z') a = (WCHAR)(a - 32);
        if (b >= 'a' && b <= 'z') b = (WCHAR)(b - 32);
        if (a != b) break;
    }
    if (me[i] || user[i]) return NERR_UserNotFound;
    len = wlen(me) + 1;
    if (level == 0) {                                           /* USER_INFO_0 {usri0_name} */
        LPWSTR *u0 = 0;
        if (NetApiBufferAllocate((DWORD)(sizeof(LPWSTR) + len * sizeof(WCHAR)), (LPVOID *)&u0)) return ERROR_NOT_ENOUGH_MEMORY;
        u0[0] = (LPWSTR)(u0 + 1);
        memcpy(u0[0], me, len * sizeof(WCHAR));
        *buf = (LPBYTE)u0;
        return NERR_Success;
    }
    if (level == 10) {                                          /* USER_INFO_10 {name, comment, usr_comment, full_name} */
        LPWSTR *u10 = 0;
        WCHAR *strings;
        if (NetApiBufferAllocate((DWORD)(4 * sizeof(LPWSTR) + (len + 1) * sizeof(WCHAR)), (LPVOID *)&u10)) return ERROR_NOT_ENOUGH_MEMORY;
        strings = (WCHAR *)(u10 + 4);
        memcpy(strings, me, len * sizeof(WCHAR));
        strings[len] = 0;                                       /* the shared empty string of the three comments / full name */
        u10[0] = strings;
        u10[1] = u10[2] = u10[3] = strings + len;
        *buf = (LPBYTE)u10;
        return NERR_Success;
    }
    return ERROR_INVALID_LEVEL;
}
