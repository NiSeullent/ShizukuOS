/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32 wrappers over ../appcompat/k32_runtime_topology_core.h (pure decision core, host-tested by
 * appcompat/tests). Every K32API function here is exported by build.py's kernel32 scan. The process handle goes through
 * GetProcessAffinityMask -> NtShzQueryK32(K32Q_PROCESS_INFO) -> ref_query_object(OB_PROCESS, PROCESS_QUERY_*), so invalid
 * handles and insufficient rights are refused by Kernel64. TEB offset 0x1748 is the one used by k32_steam_fiber.c. */
#include "k32.h"
#include "../appcompat/k32_runtime_topology_core.h"

#define TEB_GUARANTEED_STACK 0x1748

K32API BOOL WINAPI SetThreadStackGuarantee(PULONG size)
{
    uint32_t cur = *(volatile uint32_t *)(shz_teb() + TEB_GUARANTEED_STACK), keep, e;
    uint32_t req;
    if (!size) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    req = *size;
    e = shzrt_stack_guarantee(&req, cur, &keep);
    if (e) { shz_set_last_error(e); return FALSE; }
    *size = req;
    return TRUE;
}

K32API BOOL WINAPI GetNumaHighestNodeNumber(PULONG node)
{
    uint32_t v, e = shzrt_numa_highest(node ? &v : 0);
    if (e) { shz_set_last_error(e); return FALSE; }
    *node = v;
    return TRUE;
}

K32API BOOL WINAPI GetNumaNodeProcessorMaskEx(USHORT node, PGROUP_AFFINITY ga)
{
    uint64_t m; uint16_t g;
    uint32_t e = shzrt_numa_node_mask(node, ga ? &m : 0, ga ? &g : 0, 1);
    if (e) { shz_set_last_error(e); return FALSE; }
    memset(ga, 0, sizeof *ga);
    ga->Mask = (KAFFINITY)m; ga->Group = g;
    return TRUE;
}

K32API BOOL WINAPI GetProcessGroupAffinity(HANDLE process, PUSHORT count, PUSHORT groups)
{
    DWORD_PTR pm, sm; uint16_t n; uint32_t e;
    if (!count) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!GetProcessAffinityMask(process, &pm, &sm)) return FALSE;   /* invalid handle -> its real last error */
    n = *count;
    e = shzrt_process_groups(&n, groups);
    *count = n;
    if (e) { shz_set_last_error(e); return FALSE; }
    return TRUE;
}

K32API SIZE_T WINAPI GetLargePageMinimum(void) { return (SIZE_T)shzrt_large_page_minimum(); }
