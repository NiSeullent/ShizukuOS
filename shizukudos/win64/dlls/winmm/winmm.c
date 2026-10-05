/* SPDX-License-Identifier: GPL-2.0-only
 * winmm.dll - the multimedia timer API (timeGetTime, timeBeginPeriod/EndPeriod, timeGetDevCaps, timeGetSystemTime,
 * timeSetEvent/timeKillEvent) and the waveOut/waveIn/midiOut/midiIn device APIs over the audio drivers of this system.
 *
 * waveOut* (wavout.c) and PlaySound/sndPlaySound (playsnd.c) are real consumers of the ShizukuOS Core audio service
 * (NtShzSound, shizukudos/abi/shz_audio.h): waveOutGetNumDevs is 1 only while Core reports an initialised AC97 function and 0
 * otherwise (then device id 0 is MMSYSERR_BADDEVICEID and the mapper MMSYSERR_NODRIVER). waveIn and all MIDI remain absent:
 * *GetNumDevs is 0, opening fails as documented and handle calls find no open device (MMSYSERR_INVALHANDLE). The mixer*, aux*
 * and joy* families are not exported.
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
#include "wavxp.h"

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

void shz_wave_attach(void); void shz_wave_detach(int dynamic_unload);
void shz_play_attach(void); void shz_play_detach(int dynamic_unload);
static CRITICAL_SECTION g_lock;
static timer_t_ *g_timers;
static UINT g_next_id = 1;
static UINT g_running;                  /* id of the callback the worker is executing now, 0 if none */
static HANDLE g_wake, g_thread;
static HMODULE g_thread_mod;            /* loader reference owned by the timer worker while it exists */
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
        if (!g_timers) {
            /* Idle worker ends (recreated by the next timeSetEvent) and drops its loader reference from kernel32 code, so
             * FreeLibrary can unload winmm and the worker never runs unmapped code. */
            HMODULE m = g_thread_mod;
            CloseHandle(g_thread);
            g_thread = 0; g_thread_id = 0; g_thread_mod = 0;
            LeaveCriticalSection(&g_lock);
            xp_modexit(m);
        }
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
        g_thread_mod = g_wake ? xp_modref() : 0;
        if (g_thread_mod) g_thread = CreateThread(0, 0, timer_thread, 0, 0, 0);
        if (!g_wake || !g_thread) {
            xp_modunref(g_thread_mod); g_thread_mod = 0;
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

/* ---------------------------------------------------------------- wave / MIDI devices */
/* Devices this winmm can drive: none (no audio / MIDI driver exists). An open device would be recorded here with its kind; a
 * handle is valid only if it is in this table. */
enum { DEV_WAVEOUT = 1, DEV_WAVEIN, DEV_MIDIOUT, DEV_MIDIIN };
static struct { HANDLE h; int kind; } g_open[16];
static const UINT g_num_devs[5] = { 0, 0, 0, 0, 0 };          /* per kind: installed devices (none) */

static int open_handle(HANDLE h, int kind)
{
    unsigned i;
    if (!h) return 0;
    for (i = 0; i < sizeof g_open / sizeof g_open[0]; ++i)
        if (g_open[i].h == h && g_open[i].kind == kind) return 1;
    return 0;
}

#define CALLBACK_TYPES (CALLBACK_WINDOW | CALLBACK_TASK | CALLBACK_FUNCTION | CALLBACK_EVENT)

DLLAPI UINT WINAPI waveInGetNumDevs(void) { return g_num_devs[DEV_WAVEIN]; }
DLLAPI UINT WINAPI midiOutGetNumDevs(void) { return g_num_devs[DEV_MIDIOUT]; }
DLLAPI UINT WINAPI midiInGetNumDevs(void) { return g_num_devs[DEV_MIDIIN]; }

static MMRESULT header_op(HANDLE h, int kind, const void *hdr, UINT cb, UINT need)
{
    if (!open_handle(h, kind)) return MMSYSERR_INVALHANDLE;
    if (!hdr || cb < need) return MMSYSERR_INVALPARAM;
    return MMSYSERR_ERROR;                                    /* unreachable: no MIDI device is ever open */
}

/* waveOut* and PlaySound live in wavout.c / playsnd.c: real Core audio service consumers. */

DLLAPI MMRESULT WINAPI midiOutOpen(LPHMIDIOUT phmo, UINT id, DWORD_PTR cb, DWORD_PTR inst, DWORD flags)
{
    (void)cb; (void)inst;
    if (!phmo) return MMSYSERR_INVALPARAM;
    if (flags & ~(DWORD)(CALLBACK_TYPES | MIDI_IO_STATUS)) return MMSYSERR_INVALFLAG;
    *phmo = 0;
    if (id == MIDI_MAPPER) return MIDIERR_NODEVICE;           /* documented mapper error: no MIDI port was found */
    return id < g_num_devs[DEV_MIDIOUT] ? MMSYSERR_ERROR : MMSYSERR_BADDEVICEID;
}

DLLAPI MMRESULT WINAPI midiInOpen(LPHMIDIIN phmi, UINT id, DWORD_PTR cb, DWORD_PTR inst, DWORD flags)
{
    (void)cb; (void)inst;
    if (!phmi) return MMSYSERR_INVALPARAM;
    if (flags & ~(DWORD)(CALLBACK_TYPES | MIDI_IO_STATUS)) return MMSYSERR_INVALFLAG;
    *phmi = 0;
    return id < g_num_devs[DEV_MIDIIN] ? MMSYSERR_ERROR : MMSYSERR_BADDEVICEID;      /* MIDI input has no mapper */
}

static MMRESULT devcaps(UINT_PTR id, int kind, const void *caps, UINT cb)
{
    if (!caps || !cb) return MMSYSERR_INVALPARAM;
    if (kind == DEV_MIDIOUT && id == (UINT_PTR)MIDI_MAPPER) return MMSYSERR_NODRIVER;
    if (id < g_num_devs[kind]) return MMSYSERR_ERROR;
    return open_handle((HANDLE)id, kind) ? MMSYSERR_ERROR : MMSYSERR_BADDEVICEID;    /* an id may also be an open handle */
}

DLLAPI MMRESULT WINAPI midiOutGetDevCapsW(UINT_PTR id, LPMIDIOUTCAPSW caps, UINT cb) { return devcaps(id, DEV_MIDIOUT, caps, cb); }
DLLAPI MMRESULT WINAPI midiInGetDevCapsW(UINT_PTR id, LPMIDIINCAPSW caps, UINT cb) { return devcaps(id, DEV_MIDIIN, caps, cb); }

DLLAPI MMRESULT WINAPI midiOutClose(HMIDIOUT h) { return open_handle(h, DEV_MIDIOUT) ? MMSYSERR_ERROR : MMSYSERR_INVALHANDLE; }
DLLAPI MMRESULT WINAPI midiOutReset(HMIDIOUT h) { return open_handle(h, DEV_MIDIOUT) ? MMSYSERR_ERROR : MMSYSERR_INVALHANDLE; }
DLLAPI MMRESULT WINAPI midiOutShortMsg(HMIDIOUT h, DWORD msg) { (void)msg; return open_handle(h, DEV_MIDIOUT) ? MMSYSERR_ERROR : MMSYSERR_INVALHANDLE; }
DLLAPI MMRESULT WINAPI midiOutLongMsg(HMIDIOUT h, LPMIDIHDR hdr, UINT cb) { return header_op(h, DEV_MIDIOUT, hdr, cb, sizeof(MIDIHDR)); }
DLLAPI MMRESULT WINAPI midiOutPrepareHeader(HMIDIOUT h, LPMIDIHDR hdr, UINT cb) { return header_op(h, DEV_MIDIOUT, hdr, cb, sizeof(MIDIHDR)); }
DLLAPI MMRESULT WINAPI midiOutUnprepareHeader(HMIDIOUT h, LPMIDIHDR hdr, UINT cb) { return header_op(h, DEV_MIDIOUT, hdr, cb, sizeof(MIDIHDR)); }

DLLAPI MMRESULT WINAPI midiInClose(HMIDIIN h) { return open_handle(h, DEV_MIDIIN) ? MMSYSERR_ERROR : MMSYSERR_INVALHANDLE; }
DLLAPI MMRESULT WINAPI midiInReset(HMIDIIN h) { return open_handle(h, DEV_MIDIIN) ? MMSYSERR_ERROR : MMSYSERR_INVALHANDLE; }
DLLAPI MMRESULT WINAPI midiInStart(HMIDIIN h) { return open_handle(h, DEV_MIDIIN) ? MMSYSERR_ERROR : MMSYSERR_INVALHANDLE; }
DLLAPI MMRESULT WINAPI midiInAddBuffer(HMIDIIN h, LPMIDIHDR hdr, UINT cb) { return header_op(h, DEV_MIDIIN, hdr, cb, sizeof(MIDIHDR)); }
DLLAPI MMRESULT WINAPI midiInPrepareHeader(HMIDIIN h, LPMIDIHDR hdr, UINT cb) { return header_op(h, DEV_MIDIIN, hdr, cb, sizeof(MIDIHDR)); }
DLLAPI MMRESULT WINAPI midiInUnprepareHeader(HMIDIIN h, LPMIDIHDR hdr, UINT cb) { return header_op(h, DEV_MIDIIN, hdr, cb, sizeof(MIDIHDR)); }

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID res)
{
    (void)h;
    if (reason == DLL_PROCESS_DETACH) { shz_play_detach(!res); shz_wave_detach(!res); }     /* owned audio workers first */
    if (reason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_lock);
        shz_wave_attach();
        shz_play_attach();
    } else if (reason == DLL_PROCESS_DETACH && g_wake && !res) {
        /* FreeLibrary: the timer worker holds a loader reference, so it is gone (or is the thread running this very
         * detach from FreeLibraryAndExitThread). Never wait here: thread exit needs the loader lock held by DllMain. */
        CloseHandle(g_wake); g_wake = 0;
    }
    return TRUE;
}
