/* SPDX-License-Identifier: GPL-2.0-only */
#include "paging.h"

int sd32_identity_page(uint64_t cr3, uint64_t address, int levels, int writable,
                       int executable, sd32_read_pte read, void *context)
{
    uint64_t table = cr3 & UINT64_C(0x000ffffffffff000), entry, mask, physical;
    int level;
    if (!read || (levels != 4 && levels != 5) || address >= UINT64_C(0x100000000))
        return 0;
    for (level = levels; level >= 1; --level) {
        unsigned shift = 12 + 9 * (unsigned)(level - 1);
        uint64_t slot = (address >> shift) & 511;
        if (!read(context, table + slot * 8, &entry) || !(entry & 1) ||
            (writable && !(entry & 2)) || (executable && (entry >> 63)))
            return 0;
        if (level > 3 && (entry & 128)) return 0;
        if (level == 1 || (entry & 128)) {
            mask = (UINT64_C(1) << shift) - 1;
            /* Large-page low address bits are reserved (bit 12 is PAT). */
            if (level > 1 && (entry & (mask & ~UINT64_C(0x1fff)))) return 0;
            physical = (entry & UINT64_C(0x000ffffffffff000) & ~mask) | (address & mask);
            return physical == address;
        }
        table = entry & UINT64_C(0x000ffffffffff000);
    }
    return 0;
}
