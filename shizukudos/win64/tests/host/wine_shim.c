/* SPDX-License-Identifier: GPL-2.0-only
 * Glue for run_wine_tests.py: the few kernel32-internal helpers that live in files which are not linked into the Wine test
 * programs (they need Kernel64-specific system calls). Each maps to the equivalent over Wine's ntdll. */
#include "../../kernel32/k32.h"

ULONG NTAPI RtlNtStatusToDosError(NTSTATUS status);

DWORD k32_nt_error(NTSTATUS st)
{
    const DWORD e = RtlNtStatusToDosError(st);
    shz_set_last_error(e);
    return e;
}

/* Wine's NtLockFile / NtUnlockFile return STATUS_NOT_IMPLEMENTED when given an IoStatusBlock or a key; the NT originals take an
 * IoStatusBlock. The Shizuku code calls the NT form; under Wine (-DNtLockFile=shz_wine_NtLockFile) it is adapted here. */
typedef NTSTATUS (NTAPI *wine_lock_fn)(HANDLE, HANDLE, PVOID, PVOID, PVOID, PLARGE_INTEGER, PLARGE_INTEGER, PULONG, BOOLEAN, BOOLEAN);
typedef NTSTATUS (NTAPI *wine_unlock_fn)(HANDLE, PVOID, PLARGE_INTEGER, PLARGE_INTEGER, PULONG);

NTSTATUS NTAPI shz_wine_NtLockFile(HANDLE h, HANDLE ev, PVOID apc, PVOID ctx, SHZ_IO_STATUS_BLOCK *io, PLARGE_INTEGER off, PLARGE_INTEGER len,
                                   ULONG key, BOOLEAN fail_now, BOOLEAN exclusive)
{
    static wine_lock_fn fn;
    NTSTATUS st;
    (void)key;
    if (!fn) fn = (wine_lock_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtLockFile");
    st = fn(h, ev, apc, ctx, NULL, off, len, NULL, fail_now, exclusive);
    if (io) { io->Status = (ULONG_PTR)st; io->Information = 0; }
    return st;
}

NTSTATUS NTAPI shz_wine_NtUnlockFile(HANDLE h, SHZ_IO_STATUS_BLOCK *io, PLARGE_INTEGER off, PLARGE_INTEGER len, ULONG key)
{
    static wine_unlock_fn fn;
    NTSTATUS st;
    (void)key;
    if (!fn) fn = (wine_unlock_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnlockFile");
    st = fn(h, NULL, off, len, NULL);
    if (io) { io->Status = (ULONG_PTR)st; io->Information = 0; }
    return st;
}
