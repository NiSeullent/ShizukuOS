/* SPDX-License-Identifier: GPL-2.0-only
 * Contract from Microsoft ProcessPrng and Chromium base/rand_util_win.cc,
 * which loads bcryptprimitives.dll and requires ProcessPrng. Not a copy of
 * that file. Entropy is supplied by the caller so tests need no kernel RNG.
 */
#include "prng.h"
int ntw_process_prng(void *buffer, uint32_t bytes, ntw_entropy_fn fill, void *user, uint32_t *error) {
    uint8_t *out = buffer;
    uint32_t filled = 0;
    if (!error) return 0;
    if (bytes && !buffer) { *error = 87; return 0; }
    if (!fill && bytes) { *error = 8; return 0; }
    while (filled < bytes) {
        uint32_t chunk = bytes - filled;
        int got;
        if (chunk > 256u) chunk = 256u;
        got = fill(user, out + filled, chunk);
        if (got <= 0 || (uint32_t)got > chunk) { *error = 8; return 0; }
        filled += (uint32_t)got;
    }
    *error = 0;
    return 1;
}
