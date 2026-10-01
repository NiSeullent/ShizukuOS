/* SPDX-License-Identifier: GPL-2.0-only
 * Measured current Kernel64 capabilities, used by Steam's eager imports.
 * The scheduler runs only CPU 0. The actual ntdll heap is a registered standard
 * first-fit/coalescing allocator; RtlSetHeapInformation refuses LFH mode.
 */
#include "k32.h"

K32API BOOL WINAPI SetProcessAffinityMask(HANDLE process, DWORD_PTR mask)
{
    ULONG measured[6];
    NTSTATUS status = NtShzQueryK32(K32Q_PROCESS_INFO, process, measured, sizeof measured, 0);
    if (status) { k32_nt_error(status); return FALSE; }
    if (mask != 1) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    /* Every existing/future thread already executes only CPU 0. No synthetic
     * affinity state is necessary. Handle access rights inherit the existing
     * NtShzQueryK32 contract; SET_INFORMATION enforcement needs kernel work. */
    return TRUE;
}
