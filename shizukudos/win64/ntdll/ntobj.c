/* SPDX-License-Identifier: GPL-2.0-only
 * ntdll.dll: the NT services Kernel64 provides through its multiplexed calls NtShzSection, NtShzIoCompletion, NtShzJob and
 * NtShzToken (kernel64/sysk32_obj.c), under their NT names and signatures: sections and views, I/O completion ports,
 * job objects and access tokens. Each wrapper only re-packs arguments; the semantics are the kernel's.
 */
#include "ntdll_int.h"

/* ---------------------------------------------------------------- sections */
NTSTATUS NTAPI NtCreateSection(PHANDLE h, ACCESS_MASK access, SHZ_OBJECT_ATTRIBUTES *oa, PLARGE_INTEGER max, ULONG prot, ULONG attrs,
                               HANDLE file)
{
    return NtShzSection(SHZ_SEC_CREATE, (ULONG_PTR)h, (ULONG_PTR)max, prot, attrs, (ULONG_PTR)file, (ULONG_PTR)oa, access);
}

NTSTATUS NTAPI NtOpenSection(PHANDLE h, ACCESS_MASK access, SHZ_OBJECT_ATTRIBUTES *oa)
{
    return NtShzSection(SHZ_SEC_OPEN, (ULONG_PTR)h, access, (ULONG_PTR)oa, 0, 0, 0, 0);
}

/* InheritDisposition (ViewShare/ViewUnmap) and ZeroBits/CommitSize change nothing here: views are never inherited by
 * children (Kernel64 creates processes from images, not by forking address spaces) and every committed page of a view is
 * produced on first touch. */
NTSTATUS NTAPI NtMapViewOfSection(HANDLE section, HANDLE process, PVOID *base, ULONG_PTR zero_bits, SIZE_T commit,
                                  PLARGE_INTEGER offset, PSIZE_T view_size, ULONG inherit, ULONG alloc_type, ULONG prot)
{
    (void)zero_bits; (void)commit; (void)inherit;
    return NtShzSection(SHZ_SEC_MAP, (ULONG_PTR)section, (ULONG_PTR)process, (ULONG_PTR)base,
                        offset ? (ULONG_PTR)offset->QuadPart : 0, (ULONG_PTR)view_size, alloc_type, prot);
}

NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE process, PVOID base)
{
    return NtShzSection(SHZ_SEC_UNMAP, (ULONG_PTR)process, (ULONG_PTR)base, 0, 0, 0, 0, 0);
}

NTSTATUS NTAPI NtFlushVirtualMemory(HANDLE process, PVOID *base, PSIZE_T size, SHZ_IO_STATUS_BLOCK *io)
{
    NTSTATUS st = NtShzSection(SHZ_SEC_FLUSH, (ULONG_PTR)process, (ULONG_PTR)base, (ULONG_PTR)size, 0, 0, 0, 0);
    if (io) { io->Status = (ULONG_PTR)st; io->Information = 0; }
    return st;
}

NTSTATUS NTAPI NtQuerySection(HANDLE section, ULONG cls, PVOID buf, SIZE_T len, PSIZE_T ret)
{
    NTSTATUS st;
    if (cls != 0) return STATUS_INVALID_INFO_CLASS;                   /* SectionBasicInformation only (no image sections) */
    st = NtShzSection(SHZ_SEC_QUERY, (ULONG_PTR)section, (ULONG_PTR)buf, len, 0, 0, 0, 0);
    if (!st && ret) *ret = 24;
    return st;
}

/* ---------------------------------------------------------------- I/O completion ports */
NTSTATUS NTAPI NtCreateIoCompletion(PHANDLE h, ACCESS_MASK access, SHZ_OBJECT_ATTRIBUTES *oa, ULONG concurrency)
{
    (void)access;
    return NtShzIoCompletion(SHZ_IOC_CREATE, (ULONG_PTR)h, concurrency, (ULONG_PTR)oa, 0, 0, 0, 0);
}

NTSTATUS NTAPI NtSetIoCompletion(HANDLE port, ULONG_PTR key, ULONG_PTR ctx, NTSTATUS status, ULONG_PTR info)
{
    return NtShzIoCompletion(SHZ_IOC_SET, (ULONG_PTR)port, key, ctx, (ULONG_PTR)(LONG_PTR)status, info, 0, 0);
}

NTSTATUS NTAPI NtRemoveIoCompletion(HANDLE port, PULONG_PTR key, PULONG_PTR ctx, SHZ_IO_STATUS_BLOCK *io, PLARGE_INTEGER timeout)
{
    ULONG_PTR e[4];
    ULONG got = 0;
    NTSTATUS st = NtShzIoCompletion(SHZ_IOC_REMOVE, (ULONG_PTR)port, (ULONG_PTR)e, 1, (ULONG_PTR)&got, (ULONG_PTR)timeout, 0, 0);
    if (st) return st;
    if (key) *key = e[0];
    if (ctx) *ctx = e[1];
    if (io) { io->Status = e[2]; io->Information = e[3]; }
    return STATUS_SUCCESS;
}

/* FILE_IO_COMPLETION_INFORMATION {KeyContext, ApcContext, IoStatusBlock} is the kernel's packet layout. */
NTSTATUS NTAPI NtRemoveIoCompletionEx(HANDLE port, PVOID info, ULONG count, PULONG removed, PLARGE_INTEGER timeout, BOOLEAN alertable)
{
    return NtShzIoCompletion(SHZ_IOC_REMOVE, (ULONG_PTR)port, (ULONG_PTR)info, count, (ULONG_PTR)removed, (ULONG_PTR)timeout, alertable, 0);
}

NTSTATUS NTAPI NtCancelIoFileEx(HANDLE file, SHZ_IO_STATUS_BLOCK *request, SHZ_IO_STATUS_BLOCK *io)
{
    NTSTATUS st = NtShzIoCompletion(SHZ_IOC_CANCEL, (ULONG_PTR)file, (ULONG_PTR)request, 0, 0, 0, 0, 0);
    if (io && !st) { io->Status = 0; io->Information = 0; }
    return st;
}

/* ---------------------------------------------------------------- jobs */
NTSTATUS NTAPI NtCreateJobObject(PHANDLE h, ACCESS_MASK access, SHZ_OBJECT_ATTRIBUTES *oa)
{
    return NtShzJob(SHZ_JOB_CREATE, (ULONG_PTR)h, access, (ULONG_PTR)oa, 0, 0);
}
NTSTATUS NTAPI NtOpenJobObject(PHANDLE h, ACCESS_MASK access, SHZ_OBJECT_ATTRIBUTES *oa)
{
    return NtShzJob(SHZ_JOB_OPEN, (ULONG_PTR)h, access, (ULONG_PTR)oa, 0, 0);
}
NTSTATUS NTAPI NtAssignProcessToJobObject(HANDLE job, HANDLE process)
{
    return NtShzJob(SHZ_JOB_ASSIGN, (ULONG_PTR)job, (ULONG_PTR)process, 0, 0, 0);
}
NTSTATUS NTAPI NtTerminateJobObject(HANDLE job, NTSTATUS status)
{
    return NtShzJob(SHZ_JOB_TERMINATE, (ULONG_PTR)job, (ULONG_PTR)(LONG_PTR)status, 0, 0, 0);
}
NTSTATUS NTAPI NtIsProcessInJob(HANDLE process, HANDLE job)
{
    BOOLEAN in = 0;
    return NtShzJob(SHZ_JOB_IS_IN_JOB, (ULONG_PTR)process, (ULONG_PTR)job, (ULONG_PTR)&in, 0, 0);
}
NTSTATUS NTAPI NtQueryInformationJobObject(HANDLE job, ULONG cls, PVOID buf, ULONG len, PULONG ret)
{
    return NtShzJob(SHZ_JOB_QUERY, (ULONG_PTR)job, cls, (ULONG_PTR)buf, len, (ULONG_PTR)ret);
}
NTSTATUS NTAPI NtSetInformationJobObject(HANDLE job, ULONG cls, PVOID buf, ULONG len)
{
    return NtShzJob(SHZ_JOB_SET, (ULONG_PTR)job, cls, (ULONG_PTR)buf, len, 0);
}

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
