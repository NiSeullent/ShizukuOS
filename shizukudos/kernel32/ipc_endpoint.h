/* SPDX-License-Identifier: GPL-2.0-only
 * Pure admission shared by entry and IPC binding. Entry uses it before the
 * memory manager walks the channel array or narrows GPA/extent to 32 bits.
 */
#ifndef K32_IPC_ENDPOINT_H
#define K32_IPC_ENDPOINT_H
#include "service_policy.h"

/* 1: descriptor index selected; 0: supported endpoint absent; <0: refused.
 * Channel1 names a DOS peer but has no K32 service implementation. Selection
 * never dereferences shared memory or publishes IRQ/semaphore ownership.
 */
static inline int k32_ipc_select_endpoint(const shz_bootinfo_t *bi, unsigned *selected, int *mode)
{
    unsigned c, seen = 0;
    if (!selected || !mode) return SHZ_E_INVALID;
    *selected = SHZ_MAX_CHANNELS;
    if (!bi || bi->magic != SHZ_BOOTINFO_MAGIC || bi->abi_major != SHZ_ABI_MAJOR ||
        bi->domain_id != SHZ_DOM_KERNEL32 || !bi->generation ||
        bi->size < __builtin_offsetof(shz_bootinfo_t, fb_base) ||
        bi->channel_count > SHZ_MAX_CHANNELS ||
        bi->size < __builtin_offsetof(shz_bootinfo_t, channel) +
                   bi->channel_count * sizeof bi->channel[0]) return SHZ_E_INVALID;
    *mode = k32_boot_runtime_service_mode(bi);
    if (*mode < 0) return SHZ_E_INVALID;
    for (c = 0; c < bi->channel_count; ++c) {
        const uint32_t id = bi->channel[c].channel_id;
        const uint32_t remote = bi->channel[c].peer_domain;
        const uint64_t base = bi->channel[c].gpa, bytes = bi->channel[c].size;
        if (id >= SHZ_MAX_CHANNELS || (seen & (1u << id)) ||
            (id == 0 ? remote != SHZ_DOM_KERNEL64 : id == 1 ? remote != SHZ_DOM_DOS16 : 1))
            return SHZ_E_INVALID;
        if (base != SHZ_IPC_GPA_BASE + (uint64_t)id * SHZ_IPC_REGION_SIZE ||
            bytes != SHZ_IPC_REGION_SIZE || base > UINTPTR_MAX || bytes > SIZE_MAX ||
            bytes - 1 > UINTPTR_MAX - base) return SHZ_E_RANGE;
        seen |= 1u << id;
        if (remote == SHZ_DOM_KERNEL64) *selected = c;
    }
    if (*selected == SHZ_MAX_CHANNELS) return *mode ? SHZ_E_INVALID : 0;
    return 1;
}
#endif
