/* Native Win98 prerequisite probe; not Chromium/Electron acceptance.
 * Compile both units with CHROMIUM_WIN9X_WAIT_TESTING. SPDX-License-Identifier: GPL-2.0-only */
#define CHROMIUM_WIN9X_WAIT_TESTING 1
#include "chromium_win9x_wait.h"
#include <stdio.h>
#include <string.h>

static volatile LONG address_a, address_b, completed_a, completed_b;
static volatile LONG timeout_address, timeout_verified, race_address;
typedef struct worker_argument {
    volatile LONG *address;
    volatile LONG *completed;
} worker_argument;
static worker_argument arguments[3];

static DWORD WINAPI worker(PVOID opaque)
{
    worker_argument *argument = (worker_argument *)opaque;
    LONG previous = 0;
    if (!chromium_win9x_WaitOnAddress(argument->address, &previous,
                                     sizeof(previous), 15000))
        return 1;
    InterlockedIncrement(argument->completed);
    return 0;
}

static DWORD WINAPI timeout_worker(PVOID opaque)
{
    LONG previous = 0;
    BOOL timed_out;
    (void)opaque;
    timed_out = !chromium_win9x_WaitOnAddress(&timeout_address, &previous, 4, 1000) &&
        GetLastError() == 1460;
    InterlockedExchange(&timeout_verified, timed_out ? 1 : -1);
    return timed_out ? 0 : 1;
}

static DWORD WINAPI race_worker(PVOID opaque)
{
    LONG previous = 0;
    (void)opaque;
    if (!chromium_win9x_WaitOnAddress(&race_address, &previous, 4, 1000))
        return 1;
    return InterlockedCompareExchange(&race_address, 0, 0) == 1 ? 0 : 1;
}

static BOOL until_count(PVOID address, DWORD count)
{
    DWORD start = GetTickCount();
    while (chromium_win9x_waiter_count(address) != count) {
        if ((DWORD)(GetTickCount() - start) >= 5000)
            return FALSE;
        Sleep(1);
    }
    return TRUE;
}

int main(int argc, char **argv)
{
    OSVERSIONINFOA version;
    HANDLE threads[3], extra;
    BYTE different[8] = { 1 }, previous[8] = { 0 };
    SIZE_T sizes[4] = { 1, 2, 4, 8 };
    DWORD index, waited, exit_code;
    BOOL target, changed = TRUE, timed_out, invalid, single = FALSE;
    BOOL isolated = FALSE, all = FALSE, joined = FALSE, pass;
    BOOL enqueued_timeout = FALSE, low_resource, registration_race = TRUE;
    FILE *log;
    if (argc != 3 || !strlen(argv[2]) || strlen(argv[2]) > 80 ||
        strspn(argv[2], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != strlen(argv[2]))
        return 10;
    log = fopen(argv[1], "wb");
    if (!log)
        return 2;
    memset(&version, 0, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    target = GetVersionExA(&version) &&
        version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS &&
        version.dwMajorVersion == 4 && version.dwMinorVersion == 10 &&
        LOWORD(version.dwBuildNumber) == 2222;
    fprintf(log, "scope=chromium-win9x-address-wait-prerequisite\r\nnonce=%s\r\nos.exact-target=%u\r\n", argv[2], !!target);
    fflush(log);
    if (!target) {
        fprintf(log, "exit=3\r\n");
        fclose(log);
        return 3;
    }
    for (index = 0; index < 4; ++index)
        changed = changed && chromium_win9x_WaitOnAddress(different, previous, sizes[index], 0);
    timed_out = !chromium_win9x_WaitOnAddress(&address_a, previous, 4, 0) && GetLastError() == 1460;
    invalid = !chromium_win9x_WaitOnAddress(&address_a, previous, 3, 0) && GetLastError() == ERROR_INVALID_PARAMETER;
    chromium_win9x_test_fail_next_event();
    low_resource = chromium_win9x_WaitOnAddress(&address_a, previous, 4, 1000) &&
        address_a == 0 && chromium_win9x_waiter_count((PVOID)&address_a) == 0;
    extra = CreateThread(NULL, 0, timeout_worker, NULL, 0, NULL);
    if (extra) {
        enqueued_timeout = until_count((PVOID)&timeout_address, 1);
        waited = WaitForSingleObject(extra, 20000);
        enqueued_timeout = enqueued_timeout && waited == WAIT_OBJECT_0 && timeout_verified == 1 &&
            chromium_win9x_waiter_count((PVOID)&timeout_address) == 0;
        CloseHandle(extra);
    }
    /* The mutation/wake deliberately races queue registration. Either the
     * under-lock comparison sees the mutation or the registered waiter wakes. */
    for (index = 0; index < 16; ++index) {
        InterlockedExchange(&race_address, 0);
        extra = CreateThread(NULL, 0, race_worker, NULL, 0, NULL);
        InterlockedExchange(&race_address, 1);
        chromium_win9x_WakeByAddressAll((PVOID)&race_address);
        if (!extra) { registration_race = FALSE; break; }
        waited = WaitForSingleObject(extra, 20000);
        exit_code = STILL_ACTIVE;
        registration_race = registration_race && waited == WAIT_OBJECT_0 &&
            GetExitCodeThread(extra, &exit_code) && exit_code == 0 &&
            chromium_win9x_waiter_count((PVOID)&race_address) == 0;
        CloseHandle(extra);
        if (!registration_race) break;
    }
    for (index = 0; index < 3; ++index) {
        arguments[index].address = index < 2 ? &address_a : &address_b;
        arguments[index].completed = index < 2 ? &completed_a : &completed_b;
        threads[index] = CreateThread(NULL, 0, worker, &arguments[index], 0, NULL);
    }
    if (threads[0] && threads[1] && threads[2] &&
        until_count((PVOID)&address_a, 2) && until_count((PVOID)&address_b, 1)) {
        chromium_win9x_WakeByAddressSingle((PVOID)&address_a);
        single = until_count((PVOID)&address_a, 1);
        isolated = chromium_win9x_waiter_count((PVOID)&address_b) == 1 && completed_b == 0;
        chromium_win9x_WakeByAddressAll((PVOID)&address_a);
        all = until_count((PVOID)&address_a, 0) && chromium_win9x_waiter_count((PVOID)&address_b) == 1;
    }
    /* Changed predicates make late-starting workers exit too. Always join
     * every successfully created worker, including a partial creation failure. */
    InterlockedExchange(&address_a, 1);
    InterlockedExchange(&address_b, 1);
    chromium_win9x_WakeByAddressAll((PVOID)&address_a);
    chromium_win9x_WakeByAddressAll((PVOID)&address_b);
    joined = threads[0] && threads[1] && threads[2];
    for (index = 0; index < 3; ++index) {
        if (threads[index]) {
            waited = WaitForSingleObject(threads[index], 20000);
            exit_code = STILL_ACTIVE;
            if (waited != WAIT_OBJECT_0 || !GetExitCodeThread(threads[index], &exit_code) || exit_code != 0)
                joined = FALSE;
            CloseHandle(threads[index]);
        }
    }
    joined = joined && completed_a == 2 && completed_b == 1;
    pass = changed && timed_out && enqueued_timeout && low_resource && registration_race &&
        invalid && single && isolated && all && joined;
    fprintf(log, "wait.sizes-1-2-4-8=%u\r\nwait.timeout-error=%u\r\nwait.enqueued-timeout=%u\r\nwait.low-resource-early-wake=%u\r\nwait.registration-race-16=%u\r\nwait.invalid-size=%u\r\nwait.single-one=%u\r\nwait.address-isolation=%u\r\nwait.all=%u\r\nworker.joined=%u\r\nexit=%u\r\n",
            !!changed, !!timed_out, !!enqueued_timeout, !!low_resource, !!registration_race,
            !!invalid, !!single, !!isolated, !!all, !!joined, pass ? 0 : 5);
    fclose(log);
    return pass ? 0 : 5;
}
