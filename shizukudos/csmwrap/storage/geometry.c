/* SPDX-License-Identifier: GPL-2.0-only
 * CHS geometry used by INT 13h AH=08h and AH=48h.
 * Cylinders stay within the 10-bit INT 13h field (1..1024).
 * Sectors past cylinders*heads*sectors_per_track are LBA-only.
 */
#include "block.h"

int csmwrap_derive_geometry(uint64_t sectors, int floppy,
                            struct csmwrap_geometry *out)
{
    static const uint32_t heads_try[] = {16u, 32u, 64u, 128u, 255u};
    uint32_t heads = 16u;
    uint32_t cyl;
    uint64_t usable, per_cyl;
    unsigned i;
    if (!out || sectors == 0) return CSMWRAP_BLK_INVALID;
    if (floppy && sectors == 2880u) {
        out->cylinders = 80u;
        out->heads = 2u;
        out->sectors_per_track = 18u;
        return CSMWRAP_BLK_OK;
    }
    if (sectors < 63u) {
        out->cylinders = 1u;
        out->heads = 1u;
        out->sectors_per_track = (uint32_t)sectors;
        return CSMWRAP_BLK_OK;
    }
    for (i = 0; i < sizeof heads_try / sizeof heads_try[0]; ++i) {
        uint64_t span = 1024ull * (uint64_t)heads_try[i] * 63ull;
        heads = heads_try[i];
        if (sectors <= span || i + 1u == sizeof heads_try / sizeof heads_try[0])
            break;
    }
    per_cyl = (uint64_t)heads * 63ull;
    usable = sectors;
    if (usable > 1024ull * per_cyl) usable = 1024ull * per_cyl;
    cyl = (uint32_t)(usable / per_cyl);
    if (cyl == 0) {
        heads = 1u;
        per_cyl = 63u;
        cyl = (uint32_t)(sectors / per_cyl);
        if (cyl == 0) cyl = 1u;
        if (cyl > 1024u) cyl = 1024u;
    }
    out->cylinders = cyl;
    out->heads = heads;
    out->sectors_per_track = 63u;
    return CSMWRAP_BLK_OK;
}
