/* SPDX-License-Identifier: GPL-2.0-only
 * Opt-in Windows98 component lifetime through the existing ABI1.1 cmdline.
 * Supervisor owns the writer; this does not add an ABI flag or a Windows RPC.
 */
#ifndef K32_SERVICE_POLICY_H
#define K32_SERVICE_POLICY_H
#include "../abi/shz_abi.h"
#include "../boot_profile/win98_foundation.h"

#define K32_WIN98_SERVICE_CMDLINE "shz.k32-service=win98"

/* 0: original QA profile; 1: explicit native Win98 service; -1: refused.
 * Older writers have no cmdline tail and retain the original QA profile.
 * A nonempty K32 cmdline is a policy request, never silently treated as QA.
 */
static inline int k32_boot_service_mode(const shz_bootinfo_t *bi)
{
    const char expected[] = K32_WIN98_SERVICE_CMDLINE;
    uint32_t i;
    if (!bi || bi->magic != SHZ_BOOTINFO_MAGIC || bi->abi_major != SHZ_ABI_MAJOR ||
        bi->domain_id != SHZ_DOM_KERNEL32)
        return -1;
    if (!SHZ_BOOTINFO_HAS(bi, cmdline_size))
        return 0;
    if (bi->cmdline_size == 0) {
        if (bi->size > __builtin_offsetof(shz_bootinfo_t, cmdline) && bi->cmdline[0])
            return -1;
        return 0;
    }
    if (!SHZ_BOOTINFO_HAS(bi, cmdline) || bi->abi_minor < 1 || bi->flags || !bi->generation ||
        bi->cmdline_size != sizeof expected - 1 || bi->channel_count != 1)
        return -1;
    for (i = 0; i < sizeof expected; ++i)
        if (bi->cmdline[i] != expected[i])
            return -1;
    if (bi->channel[0].peer_domain != SHZ_DOM_KERNEL64 || bi->channel[0].channel_id >= SHZ_MAX_CHANNELS ||
        bi->channel[0].gpa != SHZ_IPC_GPA_BASE + (uint64_t)bi->channel[0].channel_id * SHZ_IPC_REGION_SIZE ||
        bi->channel[0].size != SHZ_IPC_REGION_SIZE)
        return -1;
    return 1;
}

/* Entry and IPC must select the same lifetime from the original handoff.
 * An explicit malformed foundation is refused; only its zero decision may
 * fall back to the reviewed legacy service or diagnostic profile.
 */
static inline int k32_boot_runtime_service_mode(const shz_bootinfo_t *bi)
{
    int mode;
    if (!bi || bi->magic != SHZ_BOOTINFO_MAGIC || bi->abi_major != SHZ_ABI_MAJOR ||
        bi->domain_id != SHZ_DOM_KERNEL32)
        return -1;
    mode = shz_win98_foundation_policy(bi);
    if (mode != 0)
        return mode;
    return k32_boot_service_mode(bi);
}
#endif
