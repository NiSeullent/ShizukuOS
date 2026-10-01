/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CHROMIUM_WIN9X_WAIT_H
#define CHROMIUM_WIN9X_WAIT_H
#include <windows.h>

/* Process-local, statically linked Win9x prerequisite. No NT kernel emulation.
 * Addresses must remain valid through every wait and wake. The comparison is
 * not an atomic snapshot; callers must recheck their predicate after waking.
 * This module has process lifetime and must not be unloaded with active waits.
 * All modules must route all three APIs to one shared process-wide provider;
 * separately linking this source into different DLLs creates separate queues.
 * Cross-DLL provider integration and lifetime remain native-unverified.
 * Waiters must exit cooperatively. Forcible thread termination can strand a
 * stack waiter; cancellation/unload recovery is not implemented or verified.
 */
BOOL WINAPI chromium_win9x_WaitOnAddress(volatile VOID *address,
                                        PVOID compare, SIZE_T bytes,
                                        DWORD milliseconds);
VOID WINAPI chromium_win9x_WakeByAddressSingle(PVOID address);
VOID WINAPI chromium_win9x_WakeByAddressAll(PVOID address);

#ifdef CHROMIUM_WIN9X_WAIT_TESTING
DWORD chromium_win9x_waiter_count(PVOID address);
VOID chromium_win9x_test_fail_next_event(VOID);
#endif
#endif
