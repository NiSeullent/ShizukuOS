/* SPDX-License-Identifier: GPL-2.0-only
 * Select the genuine K32 IPC client only when that peer actually exists.
 * The independent Win98 subsystem server uses its actual channel separately.
 */
#ifndef K64_BOOT_CHANNEL_PEER_H
#define K64_BOOT_CHANNEL_PEER_H
#include "../abi/shz_abi.h"

/* -1 malformed bounded handoff; 0 no K32 peer; 1 real K32 peer present. */
static inline int k64_boot_has_kernel32_peer(const shz_bootinfo_t *bi)
{
    uint32_t i;
    if (!bi || !SHZ_BOOTINFO_HAS(bi, channel_count) || bi->channel_count > SHZ_MAX_CHANNELS)
        return -1;
    if (bi->size < __builtin_offsetof(shz_bootinfo_t, channel) +
                   bi->channel_count * sizeof bi->channel[0])
        return -1;
    for (i = 0; i < bi->channel_count; ++i)
        if (bi->channel[i].peer_domain == SHZ_DOM_KERNEL32)
            return 1;
    return 0;
}
#endif
