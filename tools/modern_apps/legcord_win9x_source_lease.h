/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LEGCORD_WIN9X_SOURCE_LEASE_H
#define LEGCORD_WIN9X_SOURCE_LEASE_H
#include <windows.h>
typedef struct legcord_source_lease legcord_source_lease;
/* The Node/Electron port binding must keep this process-local token live until
 * application shutdown. Exclusive token ownership, no copied/double release.
 * Frozen staging paths are absolute ASCII DOS paths; no network/share paths.
 */
BOOL WINAPI legcord_win9x_AcquireSourceReadLeases(LPCSTR const *paths,
                                                DWORD count,
                                                legcord_source_lease **result);
VOID WINAPI legcord_win9x_ReleaseSourceReadLeases(legcord_source_lease *lease);
#endif
