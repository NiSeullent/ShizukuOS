/* SPDX-License-Identifier: GPL-2.0-only
 * bcryptprimitives.dll - only ProcessPrng, the entry point the Rust standard library and Chromium's base use to
 * obtain random bytes, from the kernel RNG (shz_rand.h -> NtShzRandom). Like Windows it returns TRUE; only a buffer the
 * kernel cannot write makes it zero what it can and return FALSE.
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
