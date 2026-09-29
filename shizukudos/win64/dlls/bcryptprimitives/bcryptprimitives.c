/* SPDX-License-Identifier: GPL-2.0-only
 * bcryptprimitives.dll - only ProcessPrng, the entry point the Rust standard library and Chromium's base use to
 * obtain random bytes. Backed by the CPU's RDRAND instruction (shz_rand.h). Real Windows always returns TRUE; this
 * system has no other entropy source, so without RDRAND it zeroes the buffer and returns FALSE rather than pretend.
 */
#include "nt.h"
#include "shz_rand.h"
#include <string.h>

DLLAPI BOOL WINAPI ProcessPrng(PBYTE data, SIZE_T len)
{
    if (!len) return TRUE;
    if (!data) return FALSE;
    if (!shz_random_bytes(data, len)) {
        memset(data, 0, len);
        return FALSE;
    }
    return TRUE;
}
