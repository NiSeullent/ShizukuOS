/* SPDX-License-Identifier: GPL-2.0-only
 * Measured current Kernel64 capabilities, used by Steam's eager imports.
 * The scheduler runs only CPU 0. The actual ntdll heap is a registered standard
 * first-fit/coalescing allocator; RtlSetHeapInformation refuses LFH mode.
 */
#include "k32.h"

K32API BOOL WINAPI SetProcessAffinityMask(HANDLE process, DWORD_PTR mask)
{
    ULONG64 native_mask = (ULONG64)mask;
    NTSTATUS status = NtShzSetK32(K32S_PROCESS_AFFINITY, process, &native_mask, sizeof native_mask);
    if (status) { k32_nt_error(status); return FALSE; }
    /* Every existing/future thread already executes only CPU 0. No synthetic
     * affinity state is necessary. The backend checks SET rights and active
     * process identity before accepting the existing CPU0 mask. */
    return TRUE;
}
