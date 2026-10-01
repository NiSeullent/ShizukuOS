/* SPDX-License-Identifier: GPL-2.0-only
 * Original PDH query/counter lifecycle and actual local CPU-time sampling.
 * Microsoft PDH contracts and pinned Chromium/Wine review are in README.md.
 * No upstream implementation copied. In particular Wine11's fixed 500000
 * processor sample is not used. Counter handles are opaque generation tokens,
 * never caller-dereferenced pointers. One lock owns every query/counter state.
 */
#ifndef SHZ_PDH_HOST_TEST
#define WIN32_LEAN_AND_MEAN
#include "nt.h"
#include <pdh.h>
#include <pdhmsg.h>
#include <winperf.h>
#endif

struct pdh_sample { ULONGLONG idle, total, uptime; FILETIME stamp; };
struct pdh_counter {
    struct pdh_counter *next;
    ULONG_PTR id;
    unsigned kind, samples, read;
    struct pdh_sample previous, current, last_read;
};
struct pdh_query { struct pdh_query *next; ULONG_PTR id; struct pdh_counter *counters; };
static struct pdh_query *queries;
static ULONG_PTR sequence;
static volatile LONG mutex;

static void lock(void) { while (InterlockedCompareExchange(&mutex, 1, 0)) Sleep(0); }
static void unlock(void) { InterlockedExchange(&mutex, 0); }
static ULONG_PTR token(unsigned kind)
{
    if (sequence == (~(ULONG_PTR)0 >> 2)) return 0;
    return (++sequence << 2) | kind;
}
static struct pdh_query *query_find(PDH_HQUERY id)
{
    struct pdh_query *query;
    for (query = queries; query; query = query->next) if (query->id == (ULONG_PTR)id) return query;
    return NULL;
}
static struct pdh_counter *counter_find(PDH_HCOUNTER id)
{
    struct pdh_query *query; struct pdh_counter *counter;
    for (query = queries; query; query = query->next)
        for (counter = query->counters; counter; counter = counter->next)
            if (counter->id == (ULONG_PTR)id) return counter;
    return NULL;
}
static int equal(const WCHAR *a, const WCHAR *b)
{
    while (*a && *b) {
        unsigned x = *a++, y = *b++;
        if (x >= 'A' && x <= 'Z') x += 'a' - 'A';
        if (y >= 'A' && y <= 'Z') y += 'a' - 'A';
        if (x != y) return 0;
    }
    return !*a && !*b;
}
static PDH_STATUS path_kind(const WCHAR *path, unsigned *kind)
{
    if (!path || !*path) return PDH_INVALID_ARGUMENT;
    if (path[0] == '\\' && path[1] == '\\') {
        WCHAR machine[16], local[16]; DWORD size = 16; unsigned n = 0;
        path += 2;
        while (*path && *path != '\\' && n < 15) machine[n++] = *path++;
        machine[n] = 0;
        if (*path != '\\' || !GetComputerNameW(local, &size) || !equal(machine, local))
            return PDH_CSTATUS_NO_MACHINE;
    }
    if (equal(path, L"\\Processor(_Total)\\% Processor Time") ||
        equal(path, L"\\Processor(0)\\% Processor Time")) { *kind = 1; return 0; }
    if (equal(path, L"\\System\\System Up Time")) { *kind = 2; return 0; }
    /* Frequency, Hyper-V host, remote-machine and other object providers do
     * not exist in this single-CPU runtime; they are never fabricated. */
    return PDH_CSTATUS_NO_COUNTER;
}
static DWORD counter_type(const struct pdh_counter *counter)
{ return counter->kind == 1 ? PERF_100NSEC_TIMER_INV : PERF_ELAPSED_TIME; }
static DWORD data_status(struct pdh_counter *counter)
{
    int same = counter->kind == 1 ? counter->last_read.idle == counter->current.idle &&
                                   counter->last_read.total == counter->current.total :
                                   counter->last_read.uptime == counter->current.uptime;
    DWORD status = counter->read && same ? PDH_CSTATUS_VALID_DATA : PDH_CSTATUS_NEW_DATA;
    counter->last_read = counter->current; counter->read = 1; return status;
}
static ULONGLONG filetime_value(FILETIME value)
{ return ((ULONGLONG)value.dwHighDateTime << 32) | value.dwLowDateTime; }

DLLAPI PDH_STATUS WINAPI PdhOpenQueryW(LPCWSTR source, DWORD_PTR user, PDH_HQUERY *output)
{
    struct pdh_query *query; (void)user;
    if (!output) return PDH_INVALID_ARGUMENT;
    *output = NULL;
    if (source) return PDH_NOT_IMPLEMENTED; /* live local data only; no log file parsing */
    query = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *query);
    if (!query) return PDH_MEMORY_ALLOCATION_FAILURE;
    lock(); query->id = token(1);
    if (!query->id) { unlock(); HeapFree(GetProcessHeap(), 0, query); return PDH_MEMORY_ALLOCATION_FAILURE; }
    query->next = queries; queries = query; *output = (PDH_HQUERY)query->id; unlock();
    return 0;
}
DLLAPI PDH_STATUS WINAPI PdhAddEnglishCounterW(PDH_HQUERY handle, LPCWSTR path, DWORD_PTR user, PDH_HCOUNTER *output)
{
    struct pdh_query *query; struct pdh_counter *counter; unsigned kind; PDH_STATUS result; (void)user;
    if (!output) return PDH_INVALID_ARGUMENT;
    *output = NULL;
    lock(); query = query_find(handle);
    if (!query) { unlock(); return PDH_INVALID_HANDLE; }
    result = path_kind(path, &kind);
    if (result) { unlock(); return result; }
    counter = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *counter);
    if (!counter) { unlock(); return PDH_MEMORY_ALLOCATION_FAILURE; }
    counter->id = token(2);
    if (!counter->id) { HeapFree(GetProcessHeap(), 0, counter); unlock(); return PDH_MEMORY_ALLOCATION_FAILURE; }
    counter->kind = kind; counter->next = query->counters; query->counters = counter;
    *output = (PDH_HCOUNTER)counter->id; unlock(); return 0;
}
DLLAPI PDH_STATUS WINAPI PdhCollectQueryData(PDH_HQUERY handle)
{
    struct pdh_query *query; struct pdh_counter *counter; struct pdh_sample sample;
    FILETIME idle, kernel, user;
    lock(); query = query_find(handle);
    if (!query) { unlock(); return PDH_INVALID_HANDLE; }
    if (!query->counters) { unlock(); return PDH_NO_DATA; }
    if (!GetSystemTimes(&idle, &kernel, &user)) { unlock(); return PDH_INVALID_DATA; }
    sample.idle = filetime_value(idle); sample.total = filetime_value(kernel) + filetime_value(user);
    sample.uptime = GetTickCount64(); GetSystemTimeAsFileTime(&sample.stamp);
    for (counter = query->counters; counter; counter = counter->next) {
        counter->previous = counter->current; counter->current = sample;
        if (counter->samples < 2) ++counter->samples;
    }
    unlock(); return 0;
}
DLLAPI PDH_STATUS WINAPI PdhGetFormattedCounterValue(PDH_HCOUNTER handle, DWORD format, LPDWORD type, PPDH_FMT_COUNTERVALUE value)
{
    struct pdh_counter *counter; double number; DWORD numeric = format & (PDH_FMT_LONG | PDH_FMT_LARGE | PDH_FMT_DOUBLE);
    const DWORD accepted = PDH_FMT_LONG | PDH_FMT_LARGE | PDH_FMT_DOUBLE | PDH_FMT_NOSCALE | PDH_FMT_1000 | PDH_FMT_NOCAP100;
    if (!value || (format & ~accepted) || !numeric || (numeric & (numeric - 1))) return PDH_INVALID_ARGUMENT;
    lock(); counter = counter_find(handle);
    if (!counter) { unlock(); return PDH_INVALID_HANDLE; }
    value->CStatus = PDH_CSTATUS_INVALID_DATA;
    if (!counter->samples || (counter->kind == 1 && counter->samples < 2)) { unlock(); return PDH_INVALID_DATA; }
    if (counter->kind == 1) {
        ULONGLONG total, idle;
        if (counter->current.total <= counter->previous.total || counter->current.idle < counter->previous.idle) {
            unlock(); return PDH_INVALID_DATA;
        }
        total = counter->current.total - counter->previous.total;
        idle = counter->current.idle - counter->previous.idle;
        if (idle > total) { unlock(); return PDH_INVALID_DATA; }
        number = 100.0 * (double)(total - idle) / (double)total;
    } else number = (double)counter->current.uptime / 1000.0;
    if (format & PDH_FMT_1000) number *= 1000.0;
    if (numeric == PDH_FMT_LONG) {
        if (number > 2147483647.0) { unlock(); return PDH_INVALID_DATA; }
        value->longValue = (LONG)number;
    } else if (numeric == PDH_FMT_LARGE) {
        if (number >= 9223372036854775808.0) { unlock(); return PDH_INVALID_DATA; }
        value->largeValue = (LONGLONG)number;
    } else value->doubleValue = number;
    value->CStatus = data_status(counter);
    if (type) *type = counter_type(counter);
    unlock(); return 0;
}
DLLAPI PDH_STATUS WINAPI PdhGetRawCounterValue(PDH_HCOUNTER handle, LPDWORD type, PPDH_RAW_COUNTER value)
{
    struct pdh_counter *counter;
    if (!value) return PDH_INVALID_ARGUMENT;
    lock(); counter = counter_find(handle);
    if (!counter) { unlock(); return PDH_INVALID_HANDLE; }
    value->CStatus = PDH_CSTATUS_INVALID_DATA;
    if (!counter->samples) { unlock(); return PDH_INVALID_DATA; }
    if (counter->kind != 1) { unlock(); return PDH_NOT_IMPLEMENTED; } /* no invented elapsed raw time base */
    value->CStatus = data_status(counter); value->TimeStamp = counter->current.stamp; value->MultiCount = 1;
    value->FirstValue = (LONGLONG)counter->current.idle;
    value->SecondValue = (LONGLONG)counter->current.total;
    if (type) *type = counter_type(counter);
    unlock(); return 0;
}
DLLAPI PDH_STATUS WINAPI PdhRemoveCounter(PDH_HCOUNTER handle)
{
    struct pdh_query *query; struct pdh_counter **link, *counter;
    lock();
    for (query = queries; query; query = query->next)
        for (link = &query->counters; (counter = *link); link = &counter->next)
            if (counter->id == (ULONG_PTR)handle) {
                *link = counter->next; HeapFree(GetProcessHeap(), 0, counter); unlock(); return 0;
            }
    unlock(); return PDH_INVALID_HANDLE;
}
DLLAPI PDH_STATUS WINAPI PdhCloseQuery(PDH_HQUERY handle)
{
    struct pdh_query **link, *query; struct pdh_counter *counter;
    lock();
    for (link = &queries; (query = *link); link = &query->next)
        if (query->id == (ULONG_PTR)handle) {
            *link = query->next;
            while ((counter = query->counters)) { query->counters = counter->next; HeapFree(GetProcessHeap(), 0, counter); }
            HeapFree(GetProcessHeap(), 0, query); unlock(); return 0;
        }
    unlock(); return PDH_INVALID_HANDLE;
}
