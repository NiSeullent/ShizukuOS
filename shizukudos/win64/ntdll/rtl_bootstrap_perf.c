/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine NT performance counter wrapper. Preserve syscall failure instead
 * of the unconditional success in Wine's wrapper; no synthetic clock. */
#ifdef SHZ_RTL_BOOTSTRAP_HOST
#include "../tests/rtl_bootstrap_host_contract.h"
#else
#include "nt.h"
#endif
SHZ_EXPORT BOOL NTAPI RtlQueryPerformanceCounter(PLARGE_INTEGER counter)
{
    return NT_SUCCESS(NtQueryPerformanceCounter(counter,0));
}
