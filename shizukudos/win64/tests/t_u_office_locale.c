/* SPDX-License-Identifier: GPL-2.0-only
 * Actual UCRT locale API-set and recursive critical-section ownership.
 */
#include "k32test.h"
typedef void (__cdecl *locale_lock_fn)(void);
static locale_lock_fn lock_locales, unlock_locales;
static HANDLE start, attempting, acquired;
static volatile LONG protected_counter;

static DWORD WINAPI initialization_racer(void *unused)
{
    unsigned i;
    (void)unused;
    if (WaitForSingleObject(start, 5000) != WAIT_OBJECT_0) return 2;
    for (i = 0; i < 1000; ++i) {
        lock_locales();
        lock_locales();
        ++protected_counter;
        unlock_locales();
        unlock_locales();
    }
    return 0;
}

static DWORD WINAPI ownership_contender(void *unused)
{
    (void)unused;
    if (!SetEvent(attempting)) return 2;
    lock_locales();
    if (!SetEvent(acquired)) { unlock_locales(); return 3; }
    unlock_locales();
    return 0;
}

int main(void)
{
    HMODULE module = LoadLibraryW(L"api-ms-win-crt-locale-l1-1-0.dll");
    HANDLE threads[8] = {0}, other;
    DWORD exit_code, result;
    unsigned i, created = 0;
    CHECK(module != 0, "load actual UCRT locale API-set");
    if (!module) return 1;
    lock_locales = (locale_lock_fn)GetProcAddress(module, "_lock_locales");
    unlock_locales = (locale_lock_fn)GetProcAddress(module, "_unlock_locales");
    CHECK(lock_locales && unlock_locales, "publisher recursive locale locks resolve");
    if (!lock_locales || !unlock_locales) { FreeLibrary(module); return 1; }

    start = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(start != 0, "create simultaneous initialization gate");
    if (!start) { FreeLibrary(module); return 1; }
    for (i = 0; i < 8; ++i) {
        threads[i] = CreateThread(NULL, 0, initialization_racer, NULL, 0, NULL);
        CHECK(threads[i] != 0, "create concurrent first locale-lock caller");
        if (threads[i]) ++created;
    }
    CHECK(SetEvent(start), "release all first callers");
    for (i = 0; i < 8; ++i) if (threads[i]) {
        result = WaitForSingleObject(threads[i], 5000);
        CHECK(result == WAIT_OBJECT_0, "concurrent recursion completes without deadlock");
        if (result != WAIT_OBJECT_0) return 1;
        CHECK(GetExitCodeThread(threads[i], &exit_code) && exit_code == 0,
              "concurrent locale caller returns normally");
        CHECK(CloseHandle(threads[i]), "close completed locale caller");
    }
    CHECK(protected_counter == (LONG)(created * 1000), "locale lock protects exact concurrent update count");
    CHECK(CloseHandle(start), "release initialization gate");

    attempting = CreateEventW(NULL, TRUE, FALSE, NULL);
    acquired = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(attempting && acquired, "create recursive ownership observation gates");
    if (!attempting || !acquired) return 1;
    lock_locales();
    lock_locales();
    other = CreateThread(NULL, 0, ownership_contender, NULL, 0, NULL);
    CHECK(other != 0, "create other-thread lock contender");
    if (!other) { unlock_locales(); unlock_locales(); return 1; }
    CHECK(WaitForSingleObject(attempting, 5000) == WAIT_OBJECT_0, "contender reaches lock attempt");
    CHECK(WaitForSingleObject(acquired, 40) == WAIT_TIMEOUT, "other thread cannot enter recursively held locale lock");
    unlock_locales();
    CHECK(WaitForSingleObject(acquired, 40) == WAIT_TIMEOUT, "inner unlock retains outer ownership");
    unlock_locales();
    CHECK(WaitForSingleObject(acquired, 5000) == WAIT_OBJECT_0, "outer unlock admits another thread");
    result = WaitForSingleObject(other, 5000);
    CHECK(result == WAIT_OBJECT_0, "ownership contender terminates");
    if (result != WAIT_OBJECT_0) return 1;
    CHECK(GetExitCodeThread(other, &exit_code) && exit_code == 0, "ownership contender returns normally");
    CHECK(CloseHandle(other) && CloseHandle(attempting) && CloseHandle(acquired), "release ownership observation handles");
    CHECK(FreeLibrary(module), "release actual locale API-set reference");
    return k32t_finish("T_U_OFFICE_LOCALE");
}
