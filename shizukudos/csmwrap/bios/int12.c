/* SPDX-License-Identifier: GPL-2.0-only */
#include "int12.h"

uint16_t csm_int12(const csm_e820_entry *map, size_t count)
{
    int found = 0;
    uint16_t kb;
    if (!map || !count)
        return CSM_CONVENTIONAL_KB;
    kb = csm_e820_conventional_kb(map, count, &found);
    return found ? kb : 0;
}
