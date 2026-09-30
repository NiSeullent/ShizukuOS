/* SPDX-License-Identifier: GPL-2.0-only
 * advapi32.dll additions for Chromium: the service control manager, event log, LSA and logon entry points fail exactly as
 * documented for a system without those servers (dlls/advapi32/svc.c), the CryptoAPI names are forwarders to cryptsp.dll
 * (the same code both ways, and a CryptGenRandom that really produces bytes), locally unique ids are unique, and the file
 * security calls agree with GetNamedSecurityInfoW. Expected codes come from the Windows documentation of each function. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <wincrypt.h>
#include <aclapi.h>
#include <ntsecapi.h>
#include "u_check.h"

int main(void)
{
    /* ---- service control manager ---- */
    SetLastError(0);
    U_CHECK("OpenSCManagerW fails with ERROR_DATABASE_DOES_NOT_EXIST (no services database)", OpenSCManagerW(0, 0, SC_MANAGER_CONNECT) == 0 && GetLastError() == 1065);
    U_CHECK("OpenSCManagerA the same", OpenSCManagerA(0, 0, SC_MANAGER_ALL_ACCESS) == 0 && GetLastError() == 1065);
    U_CHECK("OpenServiceW / QueryServiceStatus / CloseServiceHandle reject every handle with ERROR_INVALID_HANDLE",
            OpenServiceW((SC_HANDLE)0x1234, L"Spooler", SERVICE_QUERY_STATUS) == 0 && GetLastError() == ERROR_INVALID_HANDLE &&
            !QueryServiceStatus((SC_HANDLE)0x1234, 0) && GetLastError() == ERROR_INVALID_HANDLE &&
            !CloseServiceHandle((SC_HANDLE)0x1234) && GetLastError() == ERROR_INVALID_HANDLE);
    {
        DWORD needed = 5;
        U_CHECK("QueryServiceStatusEx: ERROR_INVALID_HANDLE and needed = 0", !QueryServiceStatusEx((SC_HANDLE)1, SC_STATUS_PROCESS_INFO, 0, 0, &needed) && GetLastError() == ERROR_INVALID_HANDLE && needed == 0);
    }

    /* ---- event log ---- */
    SetLastError(0);
    U_CHECK("RegisterEventSourceA fails with RPC_S_SERVER_UNAVAILABLE (no EventLog service)", RegisterEventSourceA(0, "Chrome") == 0 && GetLastError() == 1722);
    U_CHECK("RegisterEventSourceW the same", RegisterEventSourceW(0, L"Chrome") == 0 && GetLastError() == 1722);
    {
        LPCSTR s[1] = { "x" };
        U_CHECK("ReportEventA / DeregisterEventSource reject every handle with ERROR_INVALID_HANDLE",
                !ReportEventA((HANDLE)0x77, EVENTLOG_INFORMATION_TYPE, 0, 1, 0, 1, 0, s, 0) && GetLastError() == ERROR_INVALID_HANDLE &&
                !DeregisterEventSource((HANDLE)0x77) && GetLastError() == ERROR_INVALID_HANDLE);
    }

    /* ---- LSA ---- */
    {
        LSA_OBJECT_ATTRIBUTES oa;
        LSA_HANDLE pol = (LSA_HANDLE)1;
        NTSTATUS st;
        memset(&oa, 0, sizeof oa);
        oa.Length = sizeof oa;
        st = LsaOpenPolicy(0, &oa, POLICY_ALL_ACCESS, &pol);
        U_CHECKF("LsaOpenPolicy fails with RPC_NT_SERVER_UNAVAILABLE and clears the handle", st == (NTSTATUS)0xC0020017 && pol == 0, "st=%x", (unsigned)st);
        U_CHECK("LsaNtStatusToWinError maps it to RPC_S_SERVER_UNAVAILABLE", LsaNtStatusToWinError(st) == 1722);
        U_CHECK("LsaClose / LsaAddAccountRights on an unknown handle: STATUS_INVALID_HANDLE", LsaClose((LSA_HANDLE)0x5) == (NTSTATUS)0xC0000008 && LsaAddAccountRights((LSA_HANDLE)0x5, 0, 0, 0) == (NTSTATUS)0xC0000008);
        U_CHECK("LsaFreeMemory(NULL) succeeds", LsaFreeMemory(0) == 0);
    }

    /* ---- logon, secondary logon ---- */
    {
        HANDLE tok = (HANDLE)1;
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        U_CHECK("LogonUserW fails with ERROR_NOT_SUPPORTED and clears the token", !LogonUserW(L"user", L".", L"pw", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &tok) && GetLastError() == ERROR_NOT_SUPPORTED && tok == 0);
        memset(&si, 0, sizeof si);
        si.cb = sizeof si;
        U_CHECK("CreateProcessWithLogonW fails with ERROR_NOT_SUPPORTED", !CreateProcessWithLogonW(L"u", L".", L"p", 0, L"C:\\SHZ\\TESTS\\T_HELLO.EXE", 0, 0, 0, 0, &si, &pi) && GetLastError() == ERROR_NOT_SUPPORTED);
        U_CHECK("CreateProcessWithTokenW with a bad token fails like CreateProcessAsUserW (not a crash, not success)", !CreateProcessWithTokenW((HANDLE)0x99, 0, L"C:\\SHZ\\TESTS\\T_HELLO.EXE", 0, 0, 0, 0, &si, &pi) && GetLastError() != 0);
        U_CHECK("ImpersonateAnonymousToken fails with ERROR_NOT_SUPPORTED", !ImpersonateAnonymousToken(GetCurrentThread()) && GetLastError() == ERROR_NOT_SUPPORTED);
    }

    /* ---- LUIDs ---- */
    {
        LUID a, b, c;
        U_CHECK("AllocateLocallyUniqueId gives three distinct ids with HighPart = the process id",
                AllocateLocallyUniqueId(&a) && AllocateLocallyUniqueId(&b) && AllocateLocallyUniqueId(&c) &&
                a.LowPart != b.LowPart && b.LowPart != c.LowPart && a.LowPart != c.LowPart && a.HighPart == (LONG)GetCurrentProcessId() && b.HighPart == a.HighPart);
        U_CHECK("AllocateLocallyUniqueId(NULL) fails with ERROR_INVALID_PARAMETER", !AllocateLocallyUniqueId(0) && GetLastError() == ERROR_INVALID_PARAMETER);
    }

    /* ---- CryptoAPI forwarders ---- */
    {
        HMODULE adv = GetModuleHandleW(L"advapi32.dll"), sp;
        FARPROC a = GetProcAddress(adv, "CryptGenRandom"), s = 0;
        HCRYPTPROV prov = 0;
        BYTE r1[16], r2[16];
        BOOL ok;
        sp = GetModuleHandleW(L"cryptsp.dll");
        if (sp) s = GetProcAddress(sp, "CryptGenRandom");
        U_CHECKF("advapi32!CryptGenRandom is the cryptsp.dll export (forwarder followed, cryptsp loaded on demand)", adv && a && sp && s && a == s, "adv=%p a=%p sp=%p s=%p", (void *)adv, (void *)a, (void *)sp, (void *)s);
        ok = CryptAcquireContextW(&prov, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        U_CHECKF("CryptAcquireContextW(PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) through advapi32", ok && prov, "err=%u", (unsigned)GetLastError());
        if (ok) {
            memset(r1, 0, sizeof r1); memset(r2, 0, sizeof r2);
            U_CHECK("CryptGenRandom fills 16 bytes twice with different values", CryptGenRandom(prov, 16, r1) && CryptGenRandom(prov, 16, r2) && memcmp(r1, r2, 16) != 0);
            U_CHECK("CryptReleaseContext succeeds", CryptReleaseContext(prov, 0));
        }
    }

    /* ---- file security ---- */
    {
        static BYTE sd[512];
        DWORD needed = 0;
        PSECURITY_DESCRIPTOR rel = 0;
        BOOL ok;
        U_CHECK("GetFileSecurityW(NULL buffer): ERROR_INSUFFICIENT_BUFFER with the size needed", !GetFileSecurityW(L"C:\\SHZ\\TESTS\\T_HELLO.EXE", OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, 0, 0, &needed) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && needed > 0 && needed <= sizeof sd);
        ok = GetFileSecurityW(L"C:\\SHZ\\TESTS\\T_HELLO.EXE", OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sd, sizeof sd, &needed);
        U_CHECK("GetFileSecurityW fills a valid self-relative descriptor", ok && IsValidSecurityDescriptor(sd) && GetSecurityDescriptorLength(sd) == needed);
        if (GetNamedSecurityInfoW(L"C:\\SHZ\\TESTS\\T_HELLO.EXE", SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, 0, 0, 0, 0, &rel) == 0 && rel) {
            U_CHECK("...identical to what GetNamedSecurityInfoW reports", GetSecurityDescriptorLength(rel) == needed && !memcmp(rel, sd, needed));
            LocalFree(rel);
        }
        U_CHECK("GetFileSecurityW of a missing file fails with ERROR_FILE_NOT_FOUND", !GetFileSecurityW(L"C:\\SHZ\\TESTS\\NOPE.EXE", OWNER_SECURITY_INFORMATION, sd, sizeof sd, &needed) && GetLastError() == ERROR_FILE_NOT_FOUND);
        U_CHECK("SetFileSecurityW fails with ERROR_NOT_SUPPORTED on an existing file, ERROR_FILE_NOT_FOUND on a missing one",
                !SetFileSecurityW(L"C:\\SHZ\\TESTS\\T_HELLO.EXE", DACL_SECURITY_INFORMATION, sd) && GetLastError() == ERROR_NOT_SUPPORTED &&
                !SetFileSecurityW(L"C:\\SHZ\\TESTS\\NOPE.EXE", DACL_SECURITY_INFORMATION, sd) && GetLastError() == ERROR_FILE_NOT_FOUND);
    }
    return u_finish("t_u_advapi32");
}
