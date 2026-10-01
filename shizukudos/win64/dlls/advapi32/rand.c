/* SPDX-License-Identifier: GPL-2.0-only
 * SystemFunction036 (RtlGenRandom), originally proposed in E1/0001 for CRT rand_s and V8 seeding.
 * Uses the existing shz_rand.h / NtShzRandom backend, also used by BCryptGenRandom: no local PRNG or invented entropy.
 * Contract: Microsoft Learn RtlGenRandom (BOOLEAN, ULONG byte count).
 * Reviewed Wine df15af3652511150490934682202d45af892f887 dlls/cryptbase/cryptbase_main.c and ReactOS
 * 9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8 dll/win32/advapi32/misc/sysfunc.c; no upstream code copied.
 * In particular the referenced ReactOS tick-count generator is NOT used. The backend chunks at 1 MiB and can fail.
 */
#define _ADVAPI32_
#include "nt.h"
#include "shz_rand.h"

DLLAPI BOOLEAN WINAPI SystemFunction036(PVOID buffer, ULONG length)
{
    if (!length) return TRUE;
    if (!buffer) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!shz_random_bytes(buffer, length)) { shz_set_last_error(ERROR_GEN_FAILURE); return FALSE; }
    return TRUE;
}
