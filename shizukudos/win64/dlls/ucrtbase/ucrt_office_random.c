/* SPDX-License-Identifier: GPL-2.0-only
 * rand_s uses the same real NtShzRandom entropy backend as ProcessPrng and
 * BCryptGenRandom. It never reads or changes the CRT rand/srand sequence.
 * Contract: Microsoft Learn CRT rand_s; reviewed Wine11
 * db11d0fe6a169c457e23d007e20404643d067aa8 dlls/msvcrt/misc.c
 * and ReactOS 9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8
 * dll/win32/msvcrt/misc.c. Original code, no upstream implementation copied.
 */
#include "crtint.h"
#ifndef SHZ_HOST_TEST
#include "shz_rand.h"
#else
int shz_random_bytes(void *, size_t);
#endif

DLLAPI crt_errno_t CRTAPI rand_s(unsigned int *value)
{
    CRT_VALIDATE(value != 0, CRT_EINVAL, CRT_EINVAL);
    if (!shz_random_bytes(value, sizeof *value)) {
        *value = 0;
        crt_set_errno(CRT_EINVAL);
        return CRT_EINVAL;
    }
    return 0;
}
