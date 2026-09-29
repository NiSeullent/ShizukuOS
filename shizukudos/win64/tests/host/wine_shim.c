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
