/* Event-backed address waits for a source-built x86 Win9x browser runtime.
 * SPDX-License-Identifier: GPL-2.0-only
 * This is a prerequisite implementation, not browser execution evidence.
 */
#include "chromium_win9x_wait.h"

#ifndef ERROR_TIMEOUT
#define ERROR_TIMEOUT 1460L
#endif

typedef struct address_waiter {
    struct address_waiter *next;
    volatile VOID *address;
    HANDLE event;
    BOOL signaled;
} address_waiter;

static volatile LONG queue_lock;
static address_waiter *waiters;
#ifdef CHROMIUM_WIN9X_WAIT_TESTING
static volatile LONG fail_next_event;
#endif

static VOID enter_queue(VOID)
{
    /* This bounded queue lock needs no initialization allocation/exception.
     * Sleep(1), rather than Sleep(0), also yields to a lower-priority holder
     * on the legacy scheduler. Event creation never runs under this lock. */
    while (InterlockedCompareExchange(&queue_lock, 1, 0) != 0)
        Sleep(1);
}

static VOID leave_queue(VOID)
{
    InterlockedExchange(&queue_lock, 0);
}

static BOOL differs(volatile VOID *address, PVOID compare, SIZE_T bytes)
{
    volatile const BYTE *current = (volatile const BYTE *)address;
    const BYTE *wanted = (const BYTE *)compare;
    SIZE_T index;
    for (index = 0; index < bytes; ++index)
        if (current[index] != wanted[index])
            return TRUE;
    return FALSE;
}

BOOL WINAPI chromium_win9x_WaitOnAddress(volatile VOID *address,
                                        PVOID compare, SIZE_T bytes,
                                        DWORD milliseconds)
{
    address_waiter waiter, **link;
    DWORD result, error;
    BOOL signaled;
    if (!address || !compare ||
        (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    /* Avoid event allocation for an already changed predicate. */
    if (differs(address, compare, bytes))
        return TRUE;
#ifdef CHROMIUM_WIN9X_WAIT_TESTING
    if (InterlockedExchange(&fail_next_event, 0)) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        waiter.event = NULL;
    } else
#endif
    waiter.event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!waiter.event)
        return TRUE; /* Documented low-resource early wake; recheck predicate. */
    waiter.address = address;
    waiter.next = NULL;
    waiter.signaled = FALSE;
    enter_queue();
    /* Recheck under the same lock that protects wake traversal, eliminating
     * a lost wake between predicate inspection and queue publication. */
    if (differs(address, compare, bytes)) {
        leave_queue();
        CloseHandle(waiter.event);
        return TRUE;
    }
    for (link = &waiters; *link; link = &(*link)->next) { }
    *link = &waiter;
    leave_queue();
    result = WaitForSingleObject(waiter.event, milliseconds);
    error = result == WAIT_FAILED ? GetLastError() :
        result == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_GEN_FAILURE;
    enter_queue();
    for (link = &waiters; *link && *link != &waiter;
         link = &(*link)->next) { }
    if (*link == &waiter)
        *link = waiter.next;
    signaled = waiter.signaled;
    /* Wake holds this lock while SetEvent runs; the stack record and event
     * therefore cannot be freed underneath a simultaneous wake. */
    leave_queue();
    CloseHandle(waiter.event);
    if (result == WAIT_OBJECT_0 || (result == WAIT_TIMEOUT && signaled))
        return TRUE; /* A wake racing timeout is an allowed early wake. */
    SetLastError(error);
    return FALSE;
}

static VOID wake(PVOID address, BOOL all)
{
    address_waiter *item;
    if (!address)
        return;
    enter_queue();
    for (item = waiters; item; item = item->next) {
        if (item->address == address && !item->signaled) {
            /* Publish only a successful event signal. Single wakes skip
             * already signaled waiters that have not yet dequeued. */
            if (SetEvent(item->event)) {
                item->signaled = TRUE;
                if (!all)
                    break;
            }
        }
    }
    leave_queue();
}

VOID WINAPI chromium_win9x_WakeByAddressSingle(PVOID address)
{
    wake(address, FALSE);
}

VOID WINAPI chromium_win9x_WakeByAddressAll(PVOID address)
{
    wake(address, TRUE);
}

#ifdef CHROMIUM_WIN9X_WAIT_TESTING
DWORD chromium_win9x_waiter_count(PVOID address)
{
    address_waiter *item;
    DWORD count = 0;
    enter_queue();
    for (item = waiters; item; item = item->next)
        if (item->address == address && !item->signaled)
            ++count;
    leave_queue();
    return count;
}

VOID chromium_win9x_test_fail_next_event(VOID)
{
    InterlockedExchange(&fail_next_event, 1);
}
#endif
