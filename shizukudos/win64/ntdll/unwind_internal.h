/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_UNWIND_INTERNAL_H
#define SHZ_UNWIND_INTERNAL_H
#define SHZ_UNWIND_CHAIN_LIMIT 32u
/* Same ABI as include/nt_ipc.h; the narrow host shim lacks that declaration. */
NTSTATUS NTAPI NtReadVirtualMemory(PVOID, PVOID, PVOID, size_t, size_t *);
#ifdef SHZ_UNWIND_HOST_TEST
/* Host fixtures provide real emulated stack bounds, exercising the production range checks. */
void shz_unwind_stack_limits(DWORD64 *low, DWORD64 *high);
#else
static inline void shz_unwind_stack_limits(DWORD64 *low, DWORD64 *high)
{
    const uint64_t teb = shz_teb();
    *high = *(const DWORD64 *)(uintptr_t)(teb + 8);
    *low = *(const DWORD64 *)(uintptr_t)(teb + 16);
}
#endif
#endif
