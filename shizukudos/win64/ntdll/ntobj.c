/* SPDX-License-Identifier: GPL-2.0-only
 * ntdll.dll: access tokens (Kernel64's multiplexed NtShzToken, kernel64/sysk32_sec.c) under their NT names and
 * signatures, and whole-process suspension (NtShzSetK32 classes, kernel64/sysk32_proc.c). Each wrapper only re-packs
 * arguments; the semantics are the kernel's.
 */
#include "ntdll_int.h"

/* ---------------------------------------------------------------- tokens */
NTSTATUS NTAPI NtOpenProcessTokenEx(HANDLE process, ACCESS_MASK access, ULONG attrs, PHANDLE token)
{
    (void)attrs;
    return NtShzToken(SHZ_TOK_OPEN_PROCESS, (ULONG_PTR)process, access, (ULONG_PTR)token);
}
NTSTATUS NTAPI NtOpenProcessToken(HANDLE process, ACCESS_MASK access, PHANDLE token)
{
    return NtOpenProcessTokenEx(process, access, 0, token);
}
NTSTATUS NTAPI NtOpenThreadTokenEx(HANDLE thread, ACCESS_MASK access, BOOLEAN as_self, ULONG attrs, PHANDLE token)
{
    (void)as_self; (void)attrs;
    return NtShzToken(SHZ_TOK_OPEN_THREAD, (ULONG_PTR)thread, access, (ULONG_PTR)token);
}
NTSTATUS NTAPI NtOpenThreadToken(HANDLE thread, ACCESS_MASK access, BOOLEAN as_self, PHANDLE token)
{
    return NtOpenThreadTokenEx(thread, access, as_self, 0, token);
}
/* NtDuplicateToken: TokenType 1 primary / 2 impersonation; the impersonation level comes from the
 * SECURITY_QUALITY_OF_SERVICE of the object attributes (SecurityAnonymous when none is given). */
NTSTATUS NTAPI NtDuplicateToken(HANDLE token, ACCESS_MASK access, SHZ_OBJECT_ATTRIBUTES *oa, BOOLEAN effective_only, ULONG type,
                                PHANDLE out)
{
    ULONG level = 0;
    (void)access; (void)effective_only;
    if (oa && oa->SecurityQualityOfService) level = ((const ULONG *)oa->SecurityQualityOfService)[1];
    return NtShzToken(SHZ_TOK_DUPLICATE, (ULONG_PTR)token, type | (level << 8), (ULONG_PTR)out);
}

/* ---------------------------------------------------------------- whole-process suspension (kernel64/sysk32_proc.c) */
NTSTATUS NTAPI NtSuspendProcess(HANDLE process) { return NtShzSetK32(K32S_SUSPEND_PROCESS, process, 0, 0); }
NTSTATUS NTAPI NtResumeProcess(HANDLE process) { return NtShzSetK32(K32S_RESUME_PROCESS, process, 0, 0); }
