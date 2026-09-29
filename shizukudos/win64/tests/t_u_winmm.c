/* SPDX-License-Identifier: GPL-2.0-only
 * winmm.dll multimedia timers. Expected behaviour is the documented one (MSDN timeapi.h / mmiscapi2.h): a timer never
 * fires before its delay, periodic timers do not run faster than their period, timeKillEvent removes a timer, a killed
 * or already-fired one-shot no longer exists (MMSYSERR_INVALPARAM), timeBeginPeriod/timeEndPeriod are reference counted.
 * Time is measured with kernel32 GetTickCount64 (the same 1 kHz Kernel64 tick that Sleep and the timers use). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include "u_check.h"

static volatile LONG g_count;
static volatile ULONGLONG g_first, g_last;
static volatile UINT g_id_seen, g_msg_seen;
static volatile DWORD_PTR g_user_seen;
static volatile LONG g_order[8], g_order_n;

static void CALLBACK count_cb(UINT id, UINT msg, DWORD_PTR user, DWORD_PTR d1, DWORD_PTR d2)
{
    ULONGLONG now = GetTickCount64();
    (void)d1; (void)d2;
    if (!g_count) g_first = now;
    g_last = now;
    g_id_seen = id; g_msg_seen = msg; g_user_seen = user;
    InterlockedIncrement((LONG *)&g_count);
}

static void CALLBACK order_cb(UINT id, UINT msg, DWORD_PTR user, DWORD_PTR d1, DWORD_PTR d2)
{
    LONG n = InterlockedIncrement((LONG *)&g_order_n) - 1;
    (void)id; (void)msg; (void)d1; (void)d2;
    if (n < 8) g_order[n] = (LONG)user;
}

static volatile LONG g_self_kill_rc = -1, g_self_calls;
static void CALLBACK self_kill_cb(UINT id, UINT msg, DWORD_PTR user, DWORD_PTR d1, DWORD_PTR d2)
{
    (void)msg; (void)user; (void)d1; (void)d2;
    if (InterlockedIncrement((LONG *)&g_self_calls) == 3) g_self_kill_rc = (LONG)timeKillEvent(id);   /* TIME_KILL_SYNCHRONOUS from inside */
}

static volatile LONG g_slow_started, g_slow_done;
static void CALLBACK slow_cb(UINT id, UINT msg, DWORD_PTR user, DWORD_PTR d1, DWORD_PTR d2)
{
    (void)id; (void)msg; (void)user; (void)d1; (void)d2;
    InterlockedExchange((LONG *)&g_slow_started, 1);
    Sleep(80);
    InterlockedExchange((LONG *)&g_slow_done, 1);
}

/* wait (bounded) until *v >= n; the timing assertions below keep their strict lower bounds (never early, never faster than
 * the period) but only loose upper bounds, so a starved host cannot make this test flaky */
static void wait_at_least(volatile LONG *v, LONG n, DWORD max_ms)
{
    DWORD i;
    for (i = 0; i < max_ms && *v < n; ++i) Sleep(1);
}

int main(void)
{
    TIMECAPS caps;
    MMRESULT rc;
    UINT id, id2, id3;
    ULONGLONG t0, t1;
    DWORD w;
    HANDLE ev;
    MMTIME mt;

    /* ---- capabilities and time ---- */
    memset(&caps, 0, sizeof caps);
    rc = timeGetDevCaps(&caps, sizeof caps);
    U_CHECKF("timeGetDevCaps: 1 ms .. 1000000 ms (Kernel64 tick is 1 ms)", rc == TIMERR_NOERROR && caps.wPeriodMin == 1 && caps.wPeriodMax == 1000000,
             "rc=%u min=%u max=%u", (unsigned)rc, caps.wPeriodMin, caps.wPeriodMax);
    U_CHECK("timeGetDevCaps(NULL) is MMSYSERR_INVALPARAM", timeGetDevCaps(0, sizeof caps) == MMSYSERR_INVALPARAM);
    U_CHECK("timeGetDevCaps with a too-small size is MMSYSERR_INVALPARAM", timeGetDevCaps(&caps, 4) == MMSYSERR_INVALPARAM);

    {
        DWORD a = timeGetTime(), b;
        Sleep(50);
        b = timeGetTime();
        U_CHECKF("timeGetTime advances by at least the slept 50 ms", (DWORD)(b - a) >= 50 && (DWORD)(b - a) < 1000, "delta=%u", (unsigned)(b - a));
        {
            ULONGLONG ta = GetTickCount64(), tc;
            DWORD tb = timeGetTime();
            tc = GetTickCount64();
            U_CHECK("timeGetTime lies between two GetTickCount64 readings", (DWORD)(tb - (DWORD)ta) <= (DWORD)((DWORD)tc - (DWORD)ta));
        }
    }
    memset(&mt, 0, sizeof mt);
    rc = timeGetSystemTime(&mt, sizeof mt);
    U_CHECK("timeGetSystemTime reports milliseconds (TIME_MS)", rc == MMSYSERR_NOERROR && mt.wType == TIME_MS && mt.u.ms > 0);
    U_CHECK("timeGetSystemTime with a too-small size is MMSYSERR_INVALPARAM", timeGetSystemTime(&mt, 4) == MMSYSERR_INVALPARAM);

    /* ---- timeBeginPeriod / timeEndPeriod reference counting ---- */
    U_CHECK("timeBeginPeriod(1) succeeds", timeBeginPeriod(1) == TIMERR_NOERROR);
    U_CHECK("timeBeginPeriod(0) is TIMERR_NOCANDO (below the minimum)", timeBeginPeriod(0) == TIMERR_NOCANDO);
    U_CHECK("timeBeginPeriod(1000001) is TIMERR_NOCANDO (above the maximum)", timeBeginPeriod(1000001) == TIMERR_NOCANDO);
    U_CHECK("timeEndPeriod(1) matches the begin", timeEndPeriod(1) == TIMERR_NOERROR);
    U_CHECK("unmatched timeEndPeriod(1) is TIMERR_NOCANDO", timeEndPeriod(1) == TIMERR_NOCANDO);
    U_CHECK("timeBeginPeriod(5) twice", timeBeginPeriod(5) == TIMERR_NOERROR && timeBeginPeriod(5) == TIMERR_NOERROR);
    U_CHECK("timeEndPeriod(5) twice succeeds, third fails",
            timeEndPeriod(5) == TIMERR_NOERROR && timeEndPeriod(5) == TIMERR_NOERROR && timeEndPeriod(5) == TIMERR_NOCANDO);
    U_CHECK("timeEndPeriod of a different period than begun is TIMERR_NOCANDO", timeBeginPeriod(2) == TIMERR_NOERROR && timeEndPeriod(3) == TIMERR_NOCANDO &&
            timeEndPeriod(2) == TIMERR_NOERROR);

    /* ---- argument validation of timeSetEvent ---- */
    U_CHECK("timeSetEvent(delay 0) fails (returns 0)", timeSetEvent(0, 0, count_cb, 0, TIME_ONESHOT) == 0);
    U_CHECK("timeSetEvent(delay above the maximum) fails", timeSetEvent(1000001, 0, count_cb, 0, TIME_ONESHOT) == 0);
    U_CHECK("timeSetEvent(NULL callback) fails", timeSetEvent(10, 0, 0, 0, TIME_ONESHOT) == 0);
    U_CHECK("TIME_CALLBACK_EVENT_PULSE is refused (no PulseEvent in this system)",
            timeSetEvent(10, 0, (LPTIMECALLBACK)CreateEventW(0, FALSE, FALSE, 0), 0, TIME_CALLBACK_EVENT_PULSE) == 0);
    U_CHECK("timeKillEvent(0) is MMSYSERR_INVALPARAM", timeKillEvent(0) == MMSYSERR_INVALPARAM);
    U_CHECK("timeKillEvent(unknown id) is MMSYSERR_INVALPARAM", timeKillEvent(0x7fffff) == MMSYSERR_INVALPARAM);

    /* ---- one-shot: exactly once, never early, right arguments ---- */
    g_count = 0; g_id_seen = g_msg_seen = 0; g_user_seen = 0;
    t0 = GetTickCount64();
    id = timeSetEvent(30, 1, count_cb, 0x1234abcd, TIME_ONESHOT | TIME_CALLBACK_FUNCTION);
    U_CHECK("timeSetEvent(30 ms one-shot) returns a nonzero id", id != 0);
    wait_at_least(&g_count, 1, 5000);
    Sleep(120);                                                  /* a second (wrong) firing would show up here */
    U_CHECKF("one-shot fired exactly once", g_count == 1, "count=%d", (int)g_count);
    U_CHECKF("one-shot did not fire early (>= 30 ms)", g_first >= t0 + 30, "delta=%u", (unsigned)(g_first - t0));
    U_CHECKF("one-shot fired within a generous bound (< 2 s)", g_first < t0 + 2000, "delta=%u", (unsigned)(g_first - t0));
    U_CHECK("callback got its timer id, uMsg 0 and dwUser", g_id_seen == id && g_msg_seen == 0 && g_user_seen == 0x1234abcd);
    U_CHECK("timeKillEvent on an already-fired one-shot is MMSYSERR_INVALPARAM", timeKillEvent(id) == MMSYSERR_INVALPARAM);

    /* killing a pending one-shot cancels it */
    g_count = 0;
    id = timeSetEvent(100, 0, count_cb, 0, TIME_ONESHOT);
    rc = timeKillEvent(id);
    Sleep(180);
    U_CHECK("a killed pending one-shot never fires", rc == TIMERR_NOERROR && g_count == 0);

    /* ---- periodic ---- */
    g_count = 0;
    t0 = GetTickCount64();
    id = timeSetEvent(20, 0, count_cb, 7, TIME_PERIODIC | TIME_KILL_SYNCHRONOUS);
    Sleep(310);
    rc = timeKillEvent(id);
    t1 = GetTickCount64();
    {
        LONG c1 = g_count;
        U_CHECK("timeKillEvent(periodic) succeeds", rc == TIMERR_NOERROR);
        U_CHECKF("periodic 20 ms timer fired repeatedly (>= 3 times in ~310 ms)", c1 >= 3, "count=%d", (int)c1);
        U_CHECKF("periodic timer never runs faster than its period", (ULONGLONG)c1 <= (t1 - t0) / 20 + 1, "count=%d elapsed=%u", (int)c1, (unsigned)(t1 - t0));
        U_CHECKF("first periodic callback not before one period", g_first >= t0 + 20, "delta=%u", (unsigned)(g_first - t0));
        Sleep(100);
        U_CHECKF("no callback after a TIME_KILL_SYNCHRONOUS kill", g_count == c1, "before=%d after=%d", (int)c1, (int)g_count);
    }
    U_CHECK("killing the same timer again is MMSYSERR_INVALPARAM", timeKillEvent(id) == MMSYSERR_INVALPARAM);

    /* ---- several timers fire in deadline order ---- */
    g_order_n = 0;
    id = timeSetEvent(90, 0, order_cb, 1, TIME_ONESHOT);
    id2 = timeSetEvent(30, 0, order_cb, 2, TIME_ONESHOT);
    id3 = timeSetEvent(60, 0, order_cb, 3, TIME_ONESHOT);
    U_CHECK("three timers get distinct ids", id && id2 && id3 && id != id2 && id != id3 && id2 != id3);
    wait_at_least(&g_order_n, 3, 5000);
    Sleep(50);
    U_CHECKF("deadline order 30, 60, 90 ms", g_order_n == 3 && g_order[0] == 2 && g_order[1] == 3 && g_order[2] == 1, "n=%d %d %d %d", (int)g_order_n,
             (int)g_order[0], (int)g_order[1], (int)g_order[2]);

    /* ---- TIME_CALLBACK_EVENT_SET ---- */
    ev = CreateEventW(0, FALSE, FALSE, 0);
    t0 = GetTickCount64();
    id = timeSetEvent(40, 0, (LPTIMECALLBACK)ev, 0, TIME_ONESHOT | TIME_CALLBACK_EVENT_SET);
    U_CHECK("timeSetEvent with TIME_CALLBACK_EVENT_SET returns an id", id != 0);
    w = WaitForSingleObject(ev, 5000);
    t1 = GetTickCount64();
    U_CHECKF("the event is signalled, not before the delay", w == WAIT_OBJECT_0 && t1 >= t0 + 40 && t1 < t0 + 4000, "w=%u delta=%u", (unsigned)w, (unsigned)(t1 - t0));
    U_CHECK("the (auto-reset) event was consumed by the wait", WaitForSingleObject(ev, 0) == WAIT_TIMEOUT);
    id = timeSetEvent(25, 0, (LPTIMECALLBACK)ev, 0, TIME_PERIODIC | TIME_CALLBACK_EVENT_SET);
    U_CHECK("periodic event timer signals repeatedly", WaitForSingleObject(ev, 5000) == WAIT_OBJECT_0 && WaitForSingleObject(ev, 5000) == WAIT_OBJECT_0 &&
            WaitForSingleObject(ev, 5000) == WAIT_OBJECT_0);
    timeKillEvent(id);
    CloseHandle(ev);

    /* ---- a periodic timer may kill itself from its own callback (TIME_KILL_SYNCHRONOUS must not deadlock) ---- */
    g_self_calls = 0; g_self_kill_rc = -1;
    id = timeSetEvent(10, 0, self_kill_cb, 0, TIME_PERIODIC | TIME_KILL_SYNCHRONOUS);
    wait_at_least(&g_self_calls, 3, 5000);
    Sleep(150);                                                  /* a 4th call after the self-kill would show up here */
    U_CHECKF("self-kill from the callback: killed on the 3rd call, none after", g_self_kill_rc == TIMERR_NOERROR && g_self_calls == 3, "rc=%d calls=%d",
             (int)g_self_kill_rc, (int)g_self_calls);

    /* ---- TIME_KILL_SYNCHRONOUS also waits for a callback that is running on the timer thread right now ---- */
    g_slow_started = g_slow_done = 0;
    id = timeSetEvent(10, 0, slow_cb, 0, TIME_PERIODIC | TIME_KILL_SYNCHRONOUS);
    while (!g_slow_started) Sleep(1);
    rc = timeKillEvent(id);
    U_CHECK("timeKillEvent(TIME_KILL_SYNCHRONOUS) returned only after the running 80 ms callback finished", rc == TIMERR_NOERROR && g_slow_done == 1);
    g_slow_started = 0;
    Sleep(150);
    U_CHECK("...and the periodic timer never fired again", g_slow_started == 0);

    return u_finish("t_u_winmm");
}
