/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: registered waits (RegisterWaitForSingleObject, UnregisterWait, UnregisterWaitEx) and waitable timers
 * (CreateWaitableTimer[Ex]W/A, OpenWaitableTimerW, SetWaitableTimer[Ex], CancelWaitableTimer).
 *
 * Registered waits run on wait threads of this module, as the Windows thread pool does: each wait thread waits for up to
 * 63 registered objects plus its control event with WaitForMultipleObjects and the nearest time-out. A satisfied or timed-
 * out wait runs the callback on the wait thread (WT_EXECUTEINWAITTHREAD) or on a callback worker (up to CB_WORKERS threads,
 * started on demand). WT_EXECUTEONLYONCE waits are dropped after their first callback. UnregisterWaitEx removes the wait
 * from its thread before it returns (the thread acknowledges), and with INVALID_HANDLE_VALUE also waits for callbacks in
 * progress; with NULL it reports ERROR_IO_PENDING when a callback is still running; with an event it signals the event once
 * the last callback finished.
 * Waitable timers are kernel timer objects (1 ms resolution; CREATE_WAITABLE_TIMER_HIGH_RESOLUTION gets the same timer).
 * Timer completion routines need user APCs, which Kernel64 does not deliver, so a non-NULL routine fails with
 * ERROR_NOT_SUPPORTED.
 */
#include "k32.h"

#define WT_MAX 63
#define CB_WORKERS 4

typedef struct wait_rec {
    struct wait_rec *next;                  /* in its wait thread's list */
    struct wait_thread *wt;
    HANDLE object;
    WAITORTIMERCALLBACK cb;
    PVOID ctx;
    ULONG flags;
    DWORD timeout;                          /* INFINITE or ms */
    ULONGLONG deadline;                     /* GetTickCount64 of the time-out */
    volatile LONG running;                  /* callbacks in progress */
    volatile LONG removed;                  /* unregistered */
    volatile LONG done_once;                /* WT_EXECUTEONLYONCE fired */
    HANDLE completion;                      /* event to set when the last callback of a removed wait ends */
    volatile LONG refs;                     /* the registration + queued callbacks */
} wait_rec;

typedef struct wait_thread {
    struct wait_thread *next;
    HANDLE thread, control, ack;
    DWORD tid;
    wait_rec *list;
    unsigned count;
    volatile LONG generation, seen;
} wait_thread;

typedef struct cb_item { struct cb_item *next; wait_rec *w; BOOLEAN timed_out; } cb_item;

static CRITICAL_SECTION wlock;
static volatile LONG wlock_ready;
static wait_thread *threads;
static cb_item *cb_head, *cb_tail;
static HANDLE cb_sem;
static unsigned cb_workers, cb_idle;

static void init_lock(void)
{
    if (wlock_ready == 2) return;
    if (__sync_bool_compare_and_swap(&wlock_ready, 0, 1)) {
        InitializeCriticalSection(&wlock);
        wlock_ready = 2;
    }
    while (wlock_ready != 2) SwitchToThread();
}

static void rec_release(wait_rec *w)
{
    if (__sync_sub_and_fetch(&w->refs, 1) == 0) RtlFreeHeap(ShzProcessHeap(), 0, w);
}

/* A callback finished (running--): a removed wait may complete its unregistration. */
static void callback_done(wait_rec *w)
{
    if (__sync_sub_and_fetch(&w->running, 1) == 0 && w->removed && w->completion && w->completion != INVALID_HANDLE_VALUE) {
        HANDLE ev = w->completion;
        w->completion = 0;
        SetEvent(ev);
    }
    rec_release(w);
}

static DWORD WINAPI cb_worker(LPVOID arg)
{
    (void)arg;
    for (;;) {
        cb_item *it;
        WaitForSingleObject(cb_sem, INFINITE);
        EnterCriticalSection(&wlock);
        it = cb_head;
        if (it) { cb_head = it->next; if (!cb_head) cb_tail = 0; }
        --cb_idle;
        LeaveCriticalSection(&wlock);
        if (it) {
            it->w->cb(it->w->ctx, it->timed_out);            /* a dispatched callback runs even if the wait was unregistered since */
            callback_done(it->w);
            RtlFreeHeap(ShzProcessHeap(), 0, it);
        }
        EnterCriticalSection(&wlock);
        ++cb_idle;
        LeaveCriticalSection(&wlock);
    }
    return 0;
}

/* Runs or queues a callback (wlock held by the caller; w->running and w->refs already taken). */
static void dispatch(wait_rec *w, BOOLEAN timed_out)
{
    cb_item *it = RtlAllocateHeap(ShzProcessHeap(), 0, sizeof *it);
    if (!it) { callback_done(w); return; }
    it->next = 0;
    it->w = w;
    it->timed_out = timed_out;
    if (cb_tail) cb_tail->next = it; else cb_head = it;
    cb_tail = it;
    if (!cb_sem) cb_sem = CreateSemaphoreW(0, 0, 0x7fffffff, 0);
    if (!cb_idle && cb_workers < CB_WORKERS) {
        HANDLE t = CreateThread(0, 0, cb_worker, 0, 0, 0);
        if (t) { CloseHandle(t); ++cb_workers; ++cb_idle; }
    }
    ReleaseSemaphore(cb_sem, 1, 0);
}

static DWORD WINAPI wait_main(LPVOID arg)
{
    wait_thread *t = arg;
    for (;;) {
        HANDLE hs[WT_MAX + 1];
        wait_rec *recs[WT_MAX + 1];
        DWORD n = 1, r, ms = INFINITE;
        ULONGLONG now = GetTickCount64();
        wait_rec *w;
        LONG gen;
        EnterCriticalSection(&wlock);
        gen = t->generation;
        hs[0] = t->control;
        recs[0] = 0;
        for (w = t->list; w && n <= WT_MAX; w = w->next) {
            if (w->removed || w->done_once) continue;
            hs[n] = w->object;
            recs[n++] = w;
            if (w->timeout != INFINITE) {
                const DWORD left = w->deadline > now ? (DWORD)(w->deadline - now) : 0;
                if (left < ms) ms = left;
            }
        }
        LeaveCriticalSection(&wlock);
        if (t->seen != gen) { t->seen = gen; SetEvent(t->ack); }            /* the new set is in effect */
        r = WaitForMultipleObjects(n, hs, FALSE, ms);
        EnterCriticalSection(&wlock);
        now = GetTickCount64();
        if (r >= WAIT_OBJECT_0 + 1 && r < WAIT_OBJECT_0 + n) {
            w = recs[r - WAIT_OBJECT_0];
            if (!w->removed) {
                if (w->flags & WT_EXECUTEONLYONCE) w->done_once = 1;
                else if (w->timeout != INFINITE) w->deadline = now + w->timeout;
                __sync_add_and_fetch(&w->running, 1);
                __sync_add_and_fetch(&w->refs, 1);
                if (w->flags & WT_EXECUTEINWAITTHREAD) {
                    LeaveCriticalSection(&wlock);
                    w->cb(w->ctx, FALSE);
                    callback_done(w);
                    continue;
                }
                dispatch(w, FALSE);
            }
        } else if (r == WAIT_TIMEOUT || r == WAIT_FAILED) {
            DWORD k;
            for (k = 1; k < n; ++k) {
                w = recs[k];
                if (w->removed || w->done_once || w->timeout == INFINITE || w->deadline > now) continue;
                if (r == WAIT_FAILED && w->deadline > now) continue;
                if (w->flags & WT_EXECUTEONLYONCE) w->done_once = 1;
                else w->deadline = now + w->timeout;
                __sync_add_and_fetch(&w->running, 1);
                __sync_add_and_fetch(&w->refs, 1);
                if (w->flags & WT_EXECUTEINWAITTHREAD) {
                    LeaveCriticalSection(&wlock);
                    w->cb(w->ctx, TRUE);
                    callback_done(w);
                    EnterCriticalSection(&wlock);
                } else {
                    dispatch(w, TRUE);
                }
            }
            if (r == WAIT_FAILED) {                                          /* a registered handle went bad: drop it */
                for (k = 1; k < n; ++k)
                    if (WaitForSingleObject(recs[k]->object, 0) == WAIT_FAILED) recs[k]->done_once = 1;
            }
        }
        LeaveCriticalSection(&wlock);
    }
    return 0;
}

static wait_thread *thread_for_new_wait(void)
{
    wait_thread *t;
    for (t = threads; t; t = t->next) if (t->count < WT_MAX) return t;
    t = RtlAllocateHeap(ShzProcessHeap(), HEAP_ZERO_MEMORY, sizeof *t);
    if (!t) return 0;
    t->control = CreateEventW(0, FALSE, FALSE, 0);
    t->ack = CreateEventW(0, FALSE, FALSE, 0);
    t->generation = 1;
    if (!t->control || !t->ack) goto fail;
    t->thread = CreateThread(0, 0, wait_main, t, 0, &t->tid);
    if (!t->thread) goto fail;
    t->next = threads;
    threads = t;
    return t;
fail:
    if (t->control) CloseHandle(t->control);
    if (t->ack) CloseHandle(t->ack);
    RtlFreeHeap(ShzProcessHeap(), 0, t);
    return 0;
}

/* The wait thread `t` rebuilds its set; unless we are that thread, wait until it did. wlock not held. */
static void sync_thread(wait_thread *t)
{
    if (GetCurrentThreadId() == t->tid) return;
    SetEvent(t->control);
    while (t->seen != t->generation) WaitForSingleObject(t->ack, 100);
}

K32API BOOL WINAPI RegisterWaitForSingleObject(PHANDLE out, HANDLE object, WAITORTIMERCALLBACK cb, PVOID ctx, ULONG ms, ULONG flags)
{
    wait_rec *w;
    wait_thread *t;
    if (!out || !cb) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    init_lock();
    w = RtlAllocateHeap(ShzProcessHeap(), HEAP_ZERO_MEMORY, sizeof *w);
    if (!w) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    w->object = object;
    w->cb = cb;
    w->ctx = ctx;
    w->flags = flags;
    w->timeout = ms;
    w->deadline = GetTickCount64() + (ms == INFINITE ? 0 : ms);
    w->refs = 1;
    EnterCriticalSection(&wlock);
    t = thread_for_new_wait();
    if (!t) { LeaveCriticalSection(&wlock); RtlFreeHeap(ShzProcessHeap(), 0, w); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    w->wt = t;
    w->next = t->list;
    t->list = w;
    ++t->count;
    ++t->generation;
    LeaveCriticalSection(&wlock);
    sync_thread(t);
    *out = (HANDLE)w;
    return TRUE;
}

K32API BOOL WINAPI UnregisterWaitEx(HANDLE handle, HANDLE completion)
{
    wait_rec *w = (wait_rec *)handle, **pp;
    wait_thread *t;
    LONG running;
    if (!w) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    init_lock();
    EnterCriticalSection(&wlock);
    t = w->wt;
    for (pp = t ? &t->list : 0; pp && *pp; pp = &(*pp)->next)
        if (*pp == w) break;
    if (!pp || !*pp || w->removed) { LeaveCriticalSection(&wlock); shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    *pp = w->next;
    --t->count;
    ++t->generation;
    w->removed = 1;
    running = w->running;
    if (running && completion && completion != INVALID_HANDLE_VALUE) w->completion = completion;
    LeaveCriticalSection(&wlock);
    sync_thread(t);
    if (running) {
        if (completion == INVALID_HANDLE_VALUE) {
            while (w->running) Sleep(1);                                     /* blocking unregistration */
        } else if (!completion) {
            rec_release(w);
            shz_set_last_error(ERROR_IO_PENDING);                            /* a callback is still running */
            return FALSE;
        }
    } else if (completion && completion != INVALID_HANDLE_VALUE) {
        SetEvent(completion);
    }
    rec_release(w);
    return TRUE;
}

K32API BOOL WINAPI UnregisterWait(HANDLE handle) { return UnregisterWaitEx(handle, 0); }

/* ---------------------------------------------------------------- waitable timers */
static HANDLE timer_create(LPCWSTR name, BOOL inherit, DWORD access, int manual)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    HANDLE h = 0;
    NTSTATUS st;
    memset(&oa, 0, sizeof oa);
    oa.Length = sizeof oa;
    oa.Attributes = inherit ? 2 : 0;
    if (name && name[0]) {
        const size_t n = k32_wlen(name);
        if (n >= 127) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
        us.Buffer = (PWSTR)name;
        us.Length = (USHORT)(n * 2);
        us.MaximumLength = us.Length;
        oa.ObjectName = &us;
    }
    st = NtCreateTimer(&h, access, &oa, manual ? 0 : 1);
    if (st == (NTSTATUS)0x40000000) { shz_set_last_error(ERROR_ALREADY_EXISTS); return h; }
    if (st) { k32_nt_error(st); return 0; }
    shz_set_last_error(0);
    return h;
}

K32API HANDLE WINAPI CreateWaitableTimerExW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name, DWORD flags, DWORD access)
{
    if (flags & ~(DWORD)(CREATE_WAITABLE_TIMER_MANUAL_RESET | 2 /* CREATE_WAITABLE_TIMER_HIGH_RESOLUTION */)) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if ((flags & 2) && name && name[0]) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }   /* as on Windows: unnamed only */
    return timer_create(name, sa && sa->bInheritHandle, access ? access : TIMER_ALL_ACCESS, (flags & CREATE_WAITABLE_TIMER_MANUAL_RESET) != 0);
}

K32API HANDLE WINAPI CreateWaitableTimerW(LPSECURITY_ATTRIBUTES sa, BOOL manual, LPCWSTR name)
{
    return timer_create(name, sa && sa->bInheritHandle, TIMER_ALL_ACCESS, manual);
}

K32API HANDLE WINAPI CreateWaitableTimerA(LPSECURITY_ATTRIBUTES sa, BOOL manual, LPCSTR name)
{
    WCHAR w[128];
    if (name && k32_utf8_to_wide(name, -1, w, 128) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    return CreateWaitableTimerW(sa, manual, name ? w : 0);
}

K32API BOOL WINAPI SetWaitableTimerEx(HANDLE h, const LARGE_INTEGER *due, LONG period, PTIMERAPCROUTINE routine, LPVOID arg,
                                      PREASON_CONTEXT wake, ULONG tolerable_delay)
{
    NTSTATUS st;
    (void)arg; (void)wake; (void)tolerable_delay;
    if (routine) return k32_unsupported("SetWaitableTimer", "completion routine (needs user APCs)", ERROR_NOT_SUPPORTED);
    if (!due || period < 0) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    st = NtSetTimer(h, (PLARGE_INTEGER)due, 0, 0, FALSE, period, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI SetWaitableTimer(HANDLE h, const LARGE_INTEGER *due, LONG period, PTIMERAPCROUTINE routine, LPVOID arg, BOOL resume)
{
    (void)resume;                                                            /* there is no sleep state to leave */
    return SetWaitableTimerEx(h, due, period, routine, arg, 0, 0);
}

K32API BOOL WINAPI CancelWaitableTimer(HANDLE h)
{
    NTSTATUS st = NtCancelTimer(h, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}
