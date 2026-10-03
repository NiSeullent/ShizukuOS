/* SPDX-License-Identifier: GPL-2.0-only */
#include "office_sal_diag.h"

uint32_t ofd_walk_frames(uintptr_t frame, ofd_read2 rd, void *ctx, uint32_t skip, uint32_t max, uintptr_t *out)
{
    uint32_t n = 0, seen = 0;
    if (!rd || !out || !max) return 0;
    while (n < max && seen < 4096u) {
        uintptr_t w[2];
        if (!frame || (frame & (sizeof(uintptr_t) - 1)) || !rd(ctx, frame, w)) break;
        if (!w[1]) break;
        if (seen++ >= skip) out[n++] = w[1];
        if (w[0] <= frame || w[0] - frame > 0x100000u) break;
        frame = w[0];
    }
    return n;
}
