/* SPDX-License-Identifier: GPL-2.0-only
 * Recursive locale lock required by the publisher's VC14.44 C++ runtime.
 *
 * Source review: Wine11 db11d0fe6a169c457e23d007e20404643d067aa8
 * dlls/msvcrt/locale.c (_lock_locales/_unlock_locales) and lock.c;
 * ReactOS 9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8
 * dll/win32/msvcrt/lock.c. No upstream code is copied. Their locale lock is
 * a recursive critical section, so the UCRT's nonrecursive crt_lock/SRW
 * locks are unsuitable. Publish initialization before concurrent entry.
 *
 * The existing C-locale tables and locale object are immutable, and
 * _configthreadlocale changes only per-thread state. Any future global
 * locale mutation must acquire this same lock. The lock lives for this
 * module's lifetime; unloading a CRT with active callers is unsupported.
 */
#include "crtint.h"
#ifndef SHZ_UCRT_LOCALE_HOST_TEST
#include "crtos.h"
#endif

static os_critsec g_locale_lock;
static int g_locale_lock_state; /* 0 unused, 1 initializing, 2 published */

static void locale_lock_initialize(void)
{
    int expected = 0;
    if (__atomic_load_n(&g_locale_lock_state, __ATOMIC_ACQUIRE) == 2) return;
    if (__atomic_compare_exchange_n(&g_locale_lock_state, &expected, 1, 0,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        InitializeCriticalSection(&g_locale_lock);
        __atomic_store_n(&g_locale_lock_state, 2, __ATOMIC_RELEASE);
    } else {
        while (__atomic_load_n(&g_locale_lock_state, __ATOMIC_ACQUIRE) != 2)
            Sleep(0);
    }
}

DLLAPI void CRTAPI _lock_locales(void)
{
    locale_lock_initialize();
    EnterCriticalSection(&g_locale_lock);
}

DLLAPI void CRTAPI _unlock_locales(void)
{
    /* As with the native CRT, the caller must own a matching lock entry. */
    LeaveCriticalSection(&g_locale_lock);
}
