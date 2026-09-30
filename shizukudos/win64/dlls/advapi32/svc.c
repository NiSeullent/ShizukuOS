/* SPDX-License-Identifier: GPL-2.0-only
 * advapi32.dll: the service control manager, event log, LSA policy and secondary-logon entry points, and locally unique
 * ids. None of those servers exists on this system (no services.exe, no EventLog service, no LSA, no seclogon), and
 * nothing here pretends otherwise: every call fails with the code Windows gives when that server is absent, and every
 * handle-taking call rejects the handle (none can ever have been issued).
 *
 *   OpenSCManagerW/A                ERROR_DATABASE_DOES_NOT_EXIST (there is no services database)
 *   OpenServiceW/A, QueryServiceStatus, QueryServiceStatusEx, StartServiceW, ControlService, CloseServiceHandle
 *                                   ERROR_INVALID_HANDLE
 *   RegisterEventSourceW/A          NULL, RPC_S_SERVER_UNAVAILABLE (the EventLog RPC server does not exist)
 *   ReportEventW/A, DeregisterEventSource   ERROR_INVALID_HANDLE
 *   LsaOpenPolicy                   RPC_NT_SERVER_UNAVAILABLE; LsaClose / LsaAddAccountRights / LsaRemoveAccountRights /
 *                                   LsaEnumerateAccountRights / LsaFreeMemory: STATUS_INVALID_HANDLE (LsaFreeMemory(NULL) ok)
 *   LogonUserW/A                    ERROR_NOT_SUPPORTED (no LSA to authenticate against)
 *   CreateProcessWithTokenW         CreateProcessAsUserW's rules (token.c): the default primary token starts the process,
 *                                   any other token is refused (that needs the secondary logon service)
 *   CreateProcessWithLogonW         ERROR_NOT_SUPPORTED (a logon needs the LSA)
 *   ImpersonateAnonymousToken       ERROR_NOT_SUPPORTED (the kernel has no anonymous logon token to impersonate)
 *   AllocateLocallyUniqueId         {LowPart = a per-process counter, HighPart = the process id}: unique among the
 *                                   processes alive at once. (A system-wide allocator would need a kernel service.)
 *   GetFileSecurityW/A              the descriptor GetNamedSecurityInfoW reports for every file (objsec.c)
 *   SetFileSecurityW/A              ERROR_NOT_SUPPORTED (the file systems store no descriptors; as SetNamedSecurityInfoW)
 * The CryptoAPI entry points advapi32 exports on Windows (CryptAcquireContextW, CryptGenRandom, ...) are forwarders to
 * cryptsp.dll (module.json "forwarders"), exactly as Windows' advapi32 forwards them.
 */
#define _ADVAPI32_
#include "nt.h"
#include <string.h>
#include <winsvc.h>
#include <aclapi.h>
#include <ntsecapi.h>
#include "sec_int.h"

#define ERROR_DATABASE_DOES_NOT_EXIST_ 1065
#define RPC_S_SERVER_UNAVAILABLE_ 1722
#define RPC_NT_SERVER_UNAVAILABLE_ ((NTSTATUS)0xC0020017)
#define STATUS_INVALID_HANDLE_ ((NTSTATUS)0xC0000008)

/* ---------------------------------------------------------------- service control manager */
DLLAPI SC_HANDLE WINAPI OpenSCManagerW(LPCWSTR machine, LPCWSTR database, DWORD access)
{
    (void)machine; (void)database; (void)access;
    sec_unsupported("OpenSCManagerW", "no service control manager", ERROR_DATABASE_DOES_NOT_EXIST_);
    return 0;
}

DLLAPI SC_HANDLE WINAPI OpenSCManagerA(LPCSTR machine, LPCSTR database, DWORD access)
{
    (void)machine; (void)database; (void)access;
    sec_unsupported("OpenSCManagerA", "no service control manager", ERROR_DATABASE_DOES_NOT_EXIST_);
    return 0;
}

DLLAPI SC_HANDLE WINAPI OpenServiceW(SC_HANDLE scm, LPCWSTR name, DWORD access)
{
    (void)scm; (void)name; (void)access;
    shz_set_last_error(ERROR_INVALID_HANDLE);
    return 0;
}

DLLAPI SC_HANDLE WINAPI OpenServiceA(SC_HANDLE scm, LPCSTR name, DWORD access)
{
    (void)scm; (void)name; (void)access;
    shz_set_last_error(ERROR_INVALID_HANDLE);
    return 0;
}

DLLAPI BOOL WINAPI CloseServiceHandle(SC_HANDLE h) { (void)h; shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
DLLAPI BOOL WINAPI QueryServiceStatus(SC_HANDLE h, LPSERVICE_STATUS s) { (void)h; (void)s; shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }

DLLAPI BOOL WINAPI QueryServiceStatusEx(SC_HANDLE h, SC_STATUS_TYPE level, LPBYTE buf, DWORD len, LPDWORD needed)
{
    (void)h; (void)level; (void)buf; (void)len;
    if (needed) *needed = 0;
    shz_set_last_error(ERROR_INVALID_HANDLE);
    return FALSE;
}

DLLAPI BOOL WINAPI StartServiceW(SC_HANDLE h, DWORD argc, LPCWSTR *argv) { (void)h; (void)argc; (void)argv; shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
DLLAPI BOOL WINAPI ControlService(SC_HANDLE h, DWORD control, LPSERVICE_STATUS s) { (void)h; (void)control; (void)s; shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }

/* ---------------------------------------------------------------- event log */
DLLAPI HANDLE WINAPI RegisterEventSourceW(LPCWSTR server, LPCWSTR source)
{
    (void)server; (void)source;
    sec_unsupported("RegisterEventSourceW", "no EventLog service", RPC_S_SERVER_UNAVAILABLE_);
    return 0;
}

DLLAPI HANDLE WINAPI RegisterEventSourceA(LPCSTR server, LPCSTR source)
{
    (void)server; (void)source;
    sec_unsupported("RegisterEventSourceA", "no EventLog service", RPC_S_SERVER_UNAVAILABLE_);
    return 0;
}

DLLAPI BOOL WINAPI DeregisterEventSource(HANDLE h) { (void)h; shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }

DLLAPI BOOL WINAPI ReportEventW(HANDLE h, WORD type, WORD category, DWORD id, PSID sid, WORD nstrings, DWORD datasize, LPCWSTR *strings, LPVOID data)
{
    (void)h; (void)type; (void)category; (void)id; (void)sid; (void)nstrings; (void)datasize; (void)strings; (void)data;
    shz_set_last_error(ERROR_INVALID_HANDLE);
    return FALSE;
}

DLLAPI BOOL WINAPI ReportEventA(HANDLE h, WORD type, WORD category, DWORD id, PSID sid, WORD nstrings, DWORD datasize, LPCSTR *strings, LPVOID data)
{
    (void)h; (void)type; (void)category; (void)id; (void)sid; (void)nstrings; (void)datasize; (void)strings; (void)data;
    shz_set_last_error(ERROR_INVALID_HANDLE);
    return FALSE;
}

/* ---------------------------------------------------------------- LSA policy */
DLLAPI NTSTATUS WINAPI LsaOpenPolicy(PLSA_UNICODE_STRING system, PLSA_OBJECT_ATTRIBUTES attr, ACCESS_MASK access, PLSA_HANDLE out)
{
    (void)system; (void)attr; (void)access;
    if (out) *out = 0;
    sec_unsupported("LsaOpenPolicy", "no LSA server", RPC_S_SERVER_UNAVAILABLE_);
    return RPC_NT_SERVER_UNAVAILABLE_;
}

DLLAPI NTSTATUS WINAPI LsaClose(LSA_HANDLE h) { (void)h; return STATUS_INVALID_HANDLE_; }
DLLAPI NTSTATUS WINAPI LsaFreeMemory(PVOID p) { (void)p; return p ? STATUS_INVALID_HANDLE_ : 0; }

DLLAPI NTSTATUS WINAPI LsaAddAccountRights(LSA_HANDLE h, PSID sid, PLSA_UNICODE_STRING rights, ULONG count)
{ (void)h; (void)sid; (void)rights; (void)count; return STATUS_INVALID_HANDLE_; }

DLLAPI NTSTATUS WINAPI LsaRemoveAccountRights(LSA_HANDLE h, PSID sid, BOOLEAN all, PLSA_UNICODE_STRING rights, ULONG count)
{ (void)h; (void)sid; (void)all; (void)rights; (void)count; return STATUS_INVALID_HANDLE_; }

DLLAPI NTSTATUS WINAPI LsaEnumerateAccountRights(LSA_HANDLE h, PSID sid, PLSA_UNICODE_STRING *rights, PULONG count)
{
    (void)h; (void)sid;
    if (rights) *rights = 0;
    if (count) *count = 0;
    return STATUS_INVALID_HANDLE_;
}

/* ---------------------------------------------------------------- logon */
DLLAPI BOOL WINAPI LogonUserW(LPCWSTR user, LPCWSTR domain, LPCWSTR password, DWORD type, DWORD provider, PHANDLE token)
{
    (void)user; (void)domain; (void)password; (void)type; (void)provider;
    if (token) *token = 0;
    return sec_unsupported("LogonUserW", "no LSA to authenticate against", ERROR_NOT_SUPPORTED);
}

DLLAPI BOOL WINAPI LogonUserA(LPCSTR user, LPCSTR domain, LPCSTR password, DWORD type, DWORD provider, PHANDLE token)
{
    (void)user; (void)domain; (void)password; (void)type; (void)provider;
    if (token) *token = 0;
    return sec_unsupported("LogonUserA", "no LSA to authenticate against", ERROR_NOT_SUPPORTED);
}

DLLAPI BOOL WINAPI CreateProcessWithTokenW(HANDLE token, DWORD logon_flags, LPCWSTR app, LPWSTR cmd, DWORD flags, LPVOID env,
                                           LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
    (void)logon_flags;                                                     /* LOGON_WITH_PROFILE: no profiles exist to load */
    return CreateProcessAsUserW(token, app, cmd, 0, 0, FALSE, flags, env, dir, si, pi);
}

DLLAPI BOOL WINAPI CreateProcessWithLogonW(LPCWSTR user, LPCWSTR domain, LPCWSTR password, DWORD logon_flags, LPCWSTR app, LPWSTR cmd,
                                           DWORD flags, LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
    (void)user; (void)domain; (void)password; (void)logon_flags; (void)app; (void)cmd; (void)flags; (void)env; (void)dir; (void)si; (void)pi;
    return sec_unsupported("CreateProcessWithLogonW", "no LSA to log on with", ERROR_NOT_SUPPORTED);
}

DLLAPI BOOL WINAPI ImpersonateAnonymousToken(HANDLE thread)
{
    (void)thread;
    return sec_unsupported("ImpersonateAnonymousToken", "no anonymous logon token in the kernel", ERROR_NOT_SUPPORTED);
}

/* ---------------------------------------------------------------- LUIDs */
static LONG g_luid_counter = 0x10000;

DLLAPI BOOL WINAPI AllocateLocallyUniqueId(PLUID luid)
{
    if (!luid) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    luid->LowPart = (DWORD)InterlockedIncrement(&g_luid_counter);
    luid->HighPart = (LONG)shz_pid();
    return TRUE;
}

/* ---------------------------------------------------------------- file security */
DLLAPI BOOL WINAPI GetFileSecurityW(LPCWSTR name, SECURITY_INFORMATION info, PSECURITY_DESCRIPTOR sd, DWORD len, LPDWORD needed)
{
    PSECURITY_DESCRIPTOR rel = 0;
    DWORD err, n;
    if (!name || !needed) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    err = GetNamedSecurityInfoW(name, SE_FILE_OBJECT, info, 0, 0, 0, 0, &rel);
    if (err) { shz_set_last_error(err); return FALSE; }
    n = GetSecurityDescriptorLength(rel);
    *needed = n;
    if (!sd || len < n) { LocalFree(rel); shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    memcpy(sd, rel, n);
    LocalFree(rel);
    return TRUE;
}

DLLAPI BOOL WINAPI GetFileSecurityA(LPCSTR name, SECURITY_INFORMATION info, PSECURITY_DESCRIPTOR sd, DWORD len, LPDWORD needed)
{
    WCHAR w[MAX_PATH];
    size_t i;
    if (!name) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < MAX_PATH - 1 && name[i]; ++i) w[i] = (WCHAR)(unsigned char)name[i];
    w[i] = 0;
    return GetFileSecurityW(w, info, sd, len, needed);
}

DLLAPI BOOL WINAPI SetFileSecurityW(LPCWSTR name, SECURITY_INFORMATION info, PSECURITY_DESCRIPTOR sd)
{
    (void)info; (void)sd;
    if (!name) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (GetFileAttributesW(name) == INVALID_FILE_ATTRIBUTES) return FALSE;      /* the file must exist: last error from the lookup */
    return sec_unsupported("SetFileSecurityW", "the Kernel64 file systems store no security descriptors", ERROR_NOT_SUPPORTED);
}

DLLAPI BOOL WINAPI SetFileSecurityA(LPCSTR name, SECURITY_INFORMATION info, PSECURITY_DESCRIPTOR sd)
{
    WCHAR w[MAX_PATH];
    size_t i;
    if (!name) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < MAX_PATH - 1 && name[i]; ++i) w[i] = (WCHAR)(unsigned char)name[i];
    w[i] = 0;
    return SetFileSecurityW(w, info, sd);
}
