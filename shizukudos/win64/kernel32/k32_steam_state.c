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

K32API BOOL WINAPI HeapQueryInformation(HANDLE heap, HEAP_INFORMATION_CLASS information_class,
                                       PVOID output, SIZE_T capacity, PSIZE_T returned)
{
    HANDLE registered[64];                   /* actual ntdll MAX_HEAPS is 64 */
    DWORD count, i;
    if (information_class != HeapCompatibilityInformation) {
        return k32_unsupported("HeapQueryInformation", "information class not supported by this allocator", ERROR_NOT_SUPPORTED);
    }
    count = GetProcessHeaps(64, registered);
    if (count > 64) return k32_unsupported("HeapQueryInformation", "heap registry exceeds query capacity", ERROR_NOT_SUPPORTED);
    for (i = 0; i < count && registered[i] != heap; ++i) { }
    if (i == count) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    if (returned) *returned = sizeof(ULONG);
    if (capacity < sizeof(ULONG)) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    if (!output) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    *(ULONG *)output = 0;                     /* real standard mode, no look-aside list or LFH */
    return TRUE;
}
