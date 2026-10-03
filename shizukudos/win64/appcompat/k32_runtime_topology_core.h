/* SPDX-License-Identifier: GPL-2.0-only
 * Pure, host-testable decision core for four kernel32 runtime-startup APIs that Rust std, V8/Chromium/Electron
 * and the .NET/Go runtimes probe at start-up and that Shizuku64 kernel32 does not export yet:
 *   SetThreadStackGuarantee, GetNumaHighestNodeNumber, GetNumaNodeProcessorMaskEx, GetProcessGroupAffinity,
 *   GetLargePageMinimum.
 * Truth model (matches k32_sysinfo.c): one logical CPU, one processor group, one NUMA node, no large-page support.
 * Kernel64 has no automatic stack-guard growth (see k32_steam_fiber.c header), so a stack guarantee LARGER than the one
 * already recorded in the TEB cannot be honoured; that request fails with ERROR_NOT_SUPPORTED instead of pretending.
 * Error numbers are the documented Win32 values. Contracts follow learn.microsoft.com; no upstream code copied. */
#ifndef SHZ_K32_RUNTIME_TOPOLOGY_CORE_H
#define SHZ_K32_RUNTIME_TOPOLOGY_CORE_H
#include <stdint.h>

#define SHZRT_OK 0u
#define SHZRT_ERROR_NOT_SUPPORTED 50u
#define SHZRT_ERROR_INVALID_PARAMETER 87u
#define SHZRT_ERROR_INSUFFICIENT_BUFFER 122u
#define SHZRT_PAGE 4096u

/* In/out: *request is the requested guarantee (0 = query only); on success it receives the previous value.
 * `current` is the TEB GuaranteedStackBytes; `*new_current` the value to store (unchanged unless request grows it
 * and growth is supportable, which Kernel64 cannot do). `reserve` = bytes between stack dealloc base and base. */
static inline uint32_t shzrt_stack_guarantee(uint32_t *request, uint32_t current, uint32_t *new_current)
{
    uint32_t req;
    if (!request || !new_current) return SHZRT_ERROR_INVALID_PARAMETER;
    req = *request;
    *new_current = current;
    if (req != 0) {
        uint32_t rounded = (req + (SHZRT_PAGE - 1)) & ~(SHZRT_PAGE - 1);
        if (rounded < req) return SHZRT_ERROR_INVALID_PARAMETER;          /* ULONG overflow */
        if (rounded > current) return SHZRT_ERROR_NOT_SUPPORTED;          /* cannot reserve guard pages */
        /* rounded <= current: Windows never shrinks the guarantee; nothing to change */
    }
    *request = current;
    return SHZRT_OK;
}

static inline uint32_t shzrt_numa_highest(uint32_t *out)
{
    if (!out) return SHZRT_ERROR_INVALID_PARAMETER;
    *out = 0;
    return SHZRT_OK;
}

/* mask/group output of GROUP_AFFINITY: {KAFFINITY Mask; WORD Group; WORD Reserved[3]} */
static inline uint32_t shzrt_numa_node_mask(uint16_t node, uint64_t *mask, uint16_t *group, uint64_t cpu_mask)
{
    if (!mask || !group) return SHZRT_ERROR_INVALID_PARAMETER;
    if (node != 0) return SHZRT_ERROR_INVALID_PARAMETER;
    *mask = cpu_mask; *group = 0;
    return SHZRT_OK;
}

/* *count: in = capacity of groups[], out = groups used (or required on INSUFFICIENT_BUFFER). */
static inline uint32_t shzrt_process_groups(uint16_t *count, uint16_t *groups)
{
    if (!count) return SHZRT_ERROR_INVALID_PARAMETER;
    if (*count < 1) { *count = 1; return SHZRT_ERROR_INSUFFICIENT_BUFFER; }
    if (!groups) return SHZRT_ERROR_INVALID_PARAMETER;
    groups[0] = 0; *count = 1;
    return SHZRT_OK;
}

static inline uint64_t shzrt_large_page_minimum(void) { return 0; }    /* 0 = large pages unsupported (documented) */
#endif
