/* SPDX-License-Identifier: GPL-2.0-only
 * ntdll-internal helpers shared between its translation units. */
#ifndef SHZ_NTDLL_INT_H
#define SHZ_NTDLL_INT_H
#include "nt.h"

/* TEB.LastStatusValue (x64 offset 0x1250): the NTSTATUS behind the last Win32 error. RtlNtStatusToDosError stores into it,
 * exactly as the Windows function does, so RtlGetLastNtStatus reports the status of the last translated failure. */
#define SHZ_TEB_LAST_STATUS 0x1250
static inline NTSTATUS shz_last_status(void)
{
    NTSTATUS v;
    __asm__ volatile("movl %%gs:%c1, %0" : "=r"(v) : "i"(SHZ_TEB_LAST_STATUS));
    return v;
}
static inline void shz_set_last_status(NTSTATUS s) { __asm__ volatile("movl %0, %%gs:%c1" : : "r"(s), "i"(SHZ_TEB_LAST_STATUS) : "memory"); }
#endif
