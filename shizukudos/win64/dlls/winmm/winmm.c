/* SPDX-License-Identifier: GPL-2.0-only
 * winmm.dll - the multimedia *timer* API only (timeGetTime, timeBeginPeriod/EndPeriod, timeGetDevCaps,
 * timeGetSystemTime, timeSetEvent/timeKillEvent). There is no audio, MIDI or joystick hardware layer, so the wave*, midi*,
 * mixer*, aux* and joy* families are not exported and PlaySound does not exist.
 *
 * Time base: kernel32 GetTickCount64 (the Kernel64 1 kHz system tick). Kernel64 already ticks at 1 ms, so the
 * timer period range reported by timeGetDevCaps is [1 ms, 1000000 ms] and timeBeginPeriod cannot make anything finer;
 * it only keeps the documented per-period reference counts (a period request that is in range succeeds, an unmatched
 * timeEndPeriod fails with TIMERR_NOCANDO).
 *
 * timeSetEvent runs callbacks on one worker thread per process, created on first use (Windows does the same). A timer
 * never fires before its delay has elapsed; periodic timers keep a fixed cadence and skip missed periods instead of
 * bursting. TIME_CALLBACK_EVENT_PULSE is not supported (PulseEvent does not exist in this kernel32): timeSetEvent
 * fails with 0 for it.
 */
#include "nt.h"
#include <string.h>
#define _WINMM_
#include <mmsystem.h>

#define PERIOD_MIN 1u
#define PERIOD_MAX 1000000u

typedef struct timer {
    struct timer *next;
    UINT id, flags;
    ULONGLONG due;
    UINT delay;
    LPTIMECALLBACK proc;
    DWORD_PTR user;
} timer_t_;

static CRITICAL_SECTION g_lock;
static timer_t_ *g_timers;
static UINT g_next_id = 1;
static UINT g_running;                  /* id of the callback the worker is executing now, 0 if none */
static HANDLE g_wake, g_thread;
static DWORD g_thread_id;
static volatile LONG g_quit;
/* The worker never blocks for longer than this: Kernel64 terminates the other threads of an exiting process only when
 * they next leave the kernel, so a thread parked in an INFINITE wait would keep ExitProcess from completing. */
#define MAX_WAIT_MS 50u

/* timeBeginPeriod bookkeeping: distinct periods with reference counts */
static struct { UINT period, count; } g_periods[64];

DLLAPI DWORD WINAPI timeGetTime(void) { return (DWORD)GetTickCount64(); }

DLLAPI MMRESULT WINAPI timeGetSystemTime(LPMMTIME t, UINT cb)
{
    if (!t || cb < sizeof(MMTIME)) return MMSYSERR_INVALPARAM;
    t->wType = TIME_MS;
    t->u.ms = timeGetTime();
    return MMSYSERR_NOERROR;
}

DLLAPI MMRESULT WINAPI timeGetDevCaps(LPTIMECAPS caps, UINT cb)
{
    if (!caps || cb < sizeof(TIMECAPS)) return MMSYSERR_INVALPARAM;
    caps->wPeriodMin = PERIOD_MIN;
    caps->wPeriodMax = PERIOD_MAX;
    return TIMERR_NOERROR;
}

DLLAPI MMRESULT WINAPI timeBeginPeriod(UINT period)
{
    int i, free_slot = -1;
    MMRESULT rc = TIMERR_NOCANDO;
    if (period < PERIOD_MIN || period > PERIOD_MAX) return TIMERR_NOCANDO;
    EnterCriticalSection(&g_lock);
    for (i = 0; i < 64; ++i) {
        if (g_periods[i].count && g_periods[i].period == period) { ++g_periods[i].count; rc = TIMERR_NOERROR; break; }
        if (!g_periods[i].count && free_slot < 0) free_slot = i;
    }
    if (rc != TIMERR_NOERROR && free_slot >= 0) { g_periods[free_slot].period = period; g_periods[free_slot].count = 1; rc = TIMERR_NOERROR; }
    LeaveCriticalSection(&g_lock);
    return rc;
}

DLLAPI MMRESULT WINAPI timeEndPeriod(UINT period)
{
    int i;
    MMRESULT rc = TIMERR_NOCANDO;
    if (period < PERIOD_MIN || period > PERIOD_MAX) return TIMERR_NOCANDO;
    EnterCriticalSection(&g_lock);
    for (i = 0; i < 64; ++i)
        if (g_periods[i].count && g_periods[i].period == period) { --g_periods[i].count; rc = TIMERR_NOERROR; break; }
    LeaveCriticalSection(&g_lock);
    return rc;
}

static void fire(const timer_t_ *t)
{
    if ((t->flags & 0x30) == TIME_CALLBACK_EVENT_SET) SetEvent((HANDLE)t->proc);
    else t->proc(t->id, 0, t->user, 0, 0);
}

static DWORD WINAPI timer_thread(LPVOID unused)
{
    (void)unused;
    g_thread_id = GetCurrentThreadId();             /* callbacks only run after this point */
    while (!g_quit) {
        timer_t_ *t, *best = 0;
        ULONGLONG now;
        DWORD wait = MAX_WAIT_MS;
        EnterCriticalSection(&g_lock);
        now = GetTickCount64();
        for (t = g_timers; t; t = t->next)
            if (!best || t->due < best->due) best = t;
        if (best && best->due <= now) {
            timer_t_ copy = *best;
            if (best->flags & TIME_PERIODIC) {
                best->due += best->delay;
                if (best->due <= now) best->due = now + best->delay;        /* fell behind: skip, do not burst */
            } else {
                timer_t_ **pp = &g_timers;
                while (*pp != best) pp = &(*pp)->next;
                *pp = best->next;
                HeapFree(GetProcessHeap(), 0, best);
            }
            g_running = copy.id;
            LeaveCriticalSection(&g_lock);
            fire(&copy);
            EnterCriticalSection(&g_lock);
            g_running = 0;
            LeaveCriticalSection(&g_lock);
            continue;
        }
        if (best) {
            ULONGLONG d = best->due - now;
            if (d < wait) wait = (DWORD)d;
        }
        LeaveCriticalSection(&g_lock);
        WaitForSingleObject(g_wake, wait);
    }
    return 0;
}

DLLAPI MMRESULT WINAPI timeSetEvent(UINT delay, UINT resolution, LPTIMECALLBACK proc, DWORD_PTR user, UINT flags)
{
    timer_t_ *t;
    UINT id;
    (void)resolution;                    /* accuracy hint; the system tick is already the finest available */
    if (!proc || delay < PERIOD_MIN || delay > PERIOD_MAX) return 0;
    if (flags & ~(UINT)(TIME_PERIODIC | 0x30 | TIME_KILL_SYNCHRONOUS)) return 0;
    if ((flags & 0x30) == TIME_CALLBACK_EVENT_PULSE || (flags & 0x30) == 0x30) return 0;      /* PulseEvent is not available */
    t = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *t);
    if (!t) return 0;
    EnterCriticalSection(&g_lock);
    if (!g_thread) {
        if (!g_wake) g_wake = CreateEventW(0, FALSE, FALSE, 0);
        if (g_wake) g_thread = CreateThread(0, 0, timer_thread, 0, 0, 0);
        if (!g_wake || !g_thread) {
            LeaveCriticalSection(&g_lock);
            HeapFree(GetProcessHeap(), 0, t);
            return 0;
        }
    }
    id = g_next_id++;
    if (!g_next_id) g_next_id = 1;
    t->id = id;
    t->flags = flags;
    t->delay = delay;
    t->due = GetTickCount64() + delay;
    t->proc = proc;
    t->user = user;
    t->next = g_timers;
    g_timers = t;
    LeaveCriticalSection(&g_lock);
    SetEvent(g_wake);                    /* re-evaluate the earliest deadline */
    return id;
}

DLLAPI MMRESULT WINAPI timeKillEvent(UINT id)
{
    timer_t_ **pp, *t = 0;
    UINT flags = 0;
    if (!id) return MMSYSERR_INVALPARAM;
    EnterCriticalSection(&g_lock);
    for (pp = &g_timers; *pp; pp = &(*pp)->next)
        if ((*pp)->id == id) { t = *pp; *pp = t->next; flags = t->flags; break; }
    LeaveCriticalSection(&g_lock);
    if (t) HeapFree(GetProcessHeap(), 0, t);
    /* TIME_KILL_SYNCHRONOUS: no callback of this timer runs after timeKillEvent returns (unless we are inside it). */
    if (t && (flags & TIME_KILL_SYNCHRONOUS) && GetCurrentThreadId() != g_thread_id) {
        for (;;) {
            UINT running;
            EnterCriticalSection(&g_lock);
            running = g_running;
            LeaveCriticalSection(&g_lock);
            if (running != id) break;
            Sleep(1);
        }
    }
    return t ? TIMERR_NOERROR : MMSYSERR_INVALPARAM;         /* documented: MMSYSERR_INVALPARAM if the event does not exist */
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID res)
{
    (void)h; (void)res;
    if (reason == DLL_PROCESS_ATTACH) InitializeCriticalSection(&g_lock);
    else if (reason == DLL_PROCESS_DETACH && g_wake) {
        InterlockedExchange((LONG *)&g_quit, 1);         /* let the worker leave promptly */
        SetEvent(g_wake);
    }
    return TRUE;
}
