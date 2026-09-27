/* SPDX-License-Identifier: GPL-2.0-only
 * Original app-local PE32 provider. Only stock Win98 imports, no CRT. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "sync.h"
typedef char pointer_width_must_be_32[(sizeof(void *) == 4) ? 1 : -1];
static ntw_srw tick_lock;
static struct ntw_tick_clock tick_clock;
static void yield_thread(void) { Sleep(0); }
void WINAPI NtwInitializeSRWLock(void *lock) { ntw_srw_init((ntw_srw *)lock); }
void WINAPI NtwAcquireSRWLockExclusive(void *lock) { ntw_srw_acquire_exclusive(lock, yield_thread); }
void WINAPI NtwAcquireSRWLockShared(void *lock) { ntw_srw_acquire_shared(lock, yield_thread); }
void WINAPI NtwReleaseSRWLockExclusive(void *lock) { ntw_srw_release_exclusive(lock); }
void WINAPI NtwReleaseSRWLockShared(void *lock) { ntw_srw_release_shared(lock); }
BOOLEAN WINAPI NtwTryAcquireSRWLockExclusive(void *lock) { return (BOOLEAN)ntw_srw_try_exclusive(lock); }
BOOLEAN WINAPI NtwTryAcquireSRWLockShared(void *lock) { return (BOOLEAN)ntw_srw_try_shared(lock); }
ULONGLONG WINAPI NtwGetTickCount64(void) {
    ULONGLONG result;
    ntw_srw_acquire_exclusive(&tick_lock, yield_thread);
    result = ntw_tick_sample(&tick_clock, GetTickCount());
    ntw_srw_release_exclusive(&tick_lock);
    return result;
}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance; (void)reason; (void)reserved;
    return TRUE;
}
