/* SPDX-License-Identifier: GPL-2.0-only
 * ABI of a test-only genuinely empty MPR provider, never a network backend. */
#ifndef SHZ_MPR_EMPTY_PROVIDER_H
#define SHZ_MPR_EMPTY_PROVIDER_H
#include <windows.h>
typedef struct {
    DWORD caps, opens, enumerations, closes;
    HANDLE event;
} MPR_FIXTURE_STATS;
typedef DWORD (WINAPI *MPR_FIXTURE_QUERY)(MPR_FIXTURE_STATS *, DWORD);
#endif
