/* SPDX-License-Identifier: GPL-2.0-only
 * secur32.dll - user names in the Windows name formats, and the SSPI / LSA entry points of a system that has no security
 * packages and no LSA authentication service.
 *
 *   GetUserNameExW   NameSamCompatible: "<COMPUTERNAME>\<user>" (the local account, advapi32 GetUserNameW). The other formats
 *                    exist only for domain accounts (distinguished names, UPNs, canonical names, GUIDs) or need a full name
 *                    the account does not have: ERROR_NONE_MAPPED, as Windows answers for a local account.
 *   SSPI             no security package is installed: QuerySecurityPackageInfoW and AcquireCredentialsHandleW report
 *                    SEC_E_SECPKG_NOT_FOUND; no credential or context handle can therefore exist, so the functions that take
 *                    one report SEC_E_INVALID_HANDLE. FreeContextBuffer accepts NULL (nothing was ever allocated).
 *   LSA              no logon-process connection can be made: LsaConnectUntrusted fails with STATUS_NOT_SUPPORTED;
 *                    LsaLogonUser / LsaDeregisterLogonProcess get an invalid handle (STATUS_INVALID_HANDLE).
 */
#include "nt.h"
#include <string.h>

#define NAME_SAM_COMPATIBLE 2
#define SEC_E_OK_ 0
#define SEC_E_INVALID_HANDLE_ ((LONG)0x80090301)
#define SEC_E_SECPKG_NOT_FOUND_ ((LONG)0x80090305)
#define STATUS_NOT_SUPPORTED_ ((NTSTATUS)0xC00000BB)

static size_t wlen(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }

DLLAPI BOOLEAN WINAPI GetUserNameExW(int format, LPWSTR buf, PULONG size)
{
    WCHAR comp[MAX_COMPUTERNAME_LENGTH + 1], user[257];
    DWORD cn = MAX_COMPUTERNAME_LENGTH + 1, un = 257;
    size_t need;
    if (!size) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (format != NAME_SAM_COMPATIBLE) { SetLastError(ERROR_NONE_MAPPED); return FALSE; }
    if (!GetComputerNameW(comp, &cn) || !GetUserNameW(user, &un)) return FALSE;
    need = wlen(comp) + 1 + wlen(user) + 1;
    if (!buf || *size < need) { *size = (ULONG)need; SetLastError(ERROR_MORE_DATA); return FALSE; }
    memcpy(buf, comp, wlen(comp) * sizeof(WCHAR));
    buf[wlen(comp)] = '\\';
    memcpy(buf + wlen(comp) + 1, user, (wlen(user) + 1) * sizeof(WCHAR));
    *size = (ULONG)(need - 1);                                  /* characters copied, without the terminator */
    return TRUE;
}

DLLAPI LONG WINAPI QuerySecurityPackageInfoW(LPWSTR name, PVOID *info)
{
    (void)name;
    if (info) *info = 0;
    return SEC_E_SECPKG_NOT_FOUND_;
}

DLLAPI LONG WINAPI AcquireCredentialsHandleW(LPWSTR principal, LPWSTR package, ULONG use, PVOID logon_id, PVOID auth_data,
                                              PVOID get_key, PVOID key_arg, PVOID cred, PVOID expiry)
{
    (void)principal; (void)package; (void)use; (void)logon_id; (void)auth_data; (void)get_key; (void)key_arg; (void)cred;
    (void)expiry;
    return SEC_E_SECPKG_NOT_FOUND_;
}

DLLAPI LONG WINAPI InitializeSecurityContextW(PVOID cred, PVOID ctx, LPWSTR target, ULONG req, ULONG reserved1, ULONG rep,
                                               PVOID input, ULONG reserved2, PVOID new_ctx, PVOID output, PULONG attrs,
                                               PVOID expiry)
{
    (void)cred; (void)ctx; (void)target; (void)req; (void)reserved1; (void)rep; (void)input; (void)reserved2; (void)new_ctx;
    (void)output; (void)attrs; (void)expiry;
    return SEC_E_INVALID_HANDLE_;                               /* no credentials handle can have been acquired */
}

DLLAPI LONG WINAPI QueryContextAttributesW(PVOID ctx, ULONG attr, PVOID buf)
{
    (void)ctx; (void)attr; (void)buf;
    return SEC_E_INVALID_HANDLE_;
}

DLLAPI LONG WINAPI DeleteSecurityContext(PVOID ctx) { (void)ctx; return SEC_E_INVALID_HANDLE_; }
DLLAPI LONG WINAPI FreeCredentialsHandle(PVOID cred) { (void)cred; return SEC_E_INVALID_HANDLE_; }
DLLAPI LONG WINAPI FreeContextBuffer(PVOID buf) { return buf ? SEC_E_INVALID_HANDLE_ : SEC_E_OK_; }

DLLAPI NTSTATUS WINAPI LsaConnectUntrusted(PHANDLE handle)
{
    if (handle) *handle = 0;
    return STATUS_NOT_SUPPORTED_;                               /* no LSA authentication service */
}

DLLAPI NTSTATUS WINAPI LsaDeregisterLogonProcess(HANDLE handle) { (void)handle; return STATUS_INVALID_HANDLE; }

DLLAPI NTSTATUS WINAPI LsaLogonUser(HANDLE lsa, PVOID origin, int type, ULONG package, PVOID auth, ULONG auth_len, PVOID groups,
                                    PVOID source, PVOID *profile, PULONG profile_len, PVOID logon_id, PHANDLE token,
                                    PVOID quotas, NTSTATUS *sub_status)
{
    (void)lsa; (void)origin; (void)type; (void)package; (void)auth; (void)auth_len; (void)groups; (void)source; (void)logon_id;
    (void)quotas;
    if (profile) *profile = 0;
    if (profile_len) *profile_len = 0;
    if (token) *token = 0;
    if (sub_status) *sub_status = 0;
    return STATUS_INVALID_HANDLE;                               /* LsaConnectUntrusted never hands out a handle */
}

DLLAPI NTSTATUS WINAPI LsaFreeReturnBuffer(PVOID buf) { return buf ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS; }
