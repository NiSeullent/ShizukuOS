/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: registered waits (RegisterWaitForSingleObject / UnregisterWait / UnregisterWaitEx) and QueueUserWorkItem.
 *
 * Wait threads each watch up to 63 objects with WaitForMultipleObjects (index 0 is a control event that makes the thread
 * re-read its list). When an object is signaled - or a wait's timeout elapses - its callback runs, by default on a worker
 * thread (a small pool that also serves QueueUserWorkItem), with WT_EXECUTEINWAITTHREAD on the wait thread itself.
 * WT_EXECUTEONLYONCE disarms the wait after the first callback. Waiting consumes the signal of auto-reset objects, as on
 * Windows. UnregisterWaitEx(INVALID_HANDLE_VALUE) waits for running callbacks; with NULL it fails with ERROR_IO_PENDING
 * when a callback is still running; with an event it signals that event once the last callback has returned.
 */
#include "k32_ipc.h"

#define WAITS_PER_THREAD 63
#define MAX_WAIT_THREADS 16
#define MAX_WORKERS 4

typedef struct k32_wait {
    HANDLE obj;
    WAITORTIMERCALLBACK cb;
    PVOID ctx;
    DWORD ms, deadline;
    ULONG flags;
    int active, unregistered, running;
    HANDLE done_event;                  /* UnregisterWaitEx(event): set when the last callback returns */
    struct wait_thread *wt;
} k32_wait_t;

typedef struct wait_thread {
    HANDLE thread, control;
    k32_wait_t *w[WAITS_PER_THREAD];
    DWORD count;
} wait_thread_t;

typedef struct work {
    struct work *next;
    k32_wait_t *wait;                   /* a registered-wait callback, or ... */
    BOOLEAN timed_out;
    LPTHREAD_START_ROUTINE fn;          /* ... a QueueUserWorkItem item */
    PVOID ctx;
} work_t;

static volatile LONG g_lock;
static wait_thread_t g_threads[MAX_WAIT_THREADS];
static DWORD g_nthreads;
static work_t *g_work_head, *g_work_tail;
static HANDLE g_work_sem;
static LONG g_workers, g_idle;

static void lock(void) { while (__sync_lock_test_and_set(&g_lock, 1)) NtYieldExecution(); }
static void unlock(void) { __sync_lock_release(&g_lock); }

/* ---------------------------------------------------------------- worker pool */
static DWORD WINAPI worker_main(LPVOID arg);

static void finish(k32_wait_t *w)
{
    HANDLE ev = 0;
    int free_it = 0;
    lock();
    if (--w->running == 0 && w->unregistered) {
        ev = w->done_event;
        free_it = 1;
    }
    unlock();
    if (ev && ev != INVALID_HANDLE_VALUE) SetEvent(ev);
    if (free_it && (!ev || ev != INVALID_HANDLE_VALUE)) HeapFree(GetProcessHeap(), 0, w);
    /* INVALID_HANDLE_VALUE: the unregistering thread frees it after seeing running == 0 */
}

static void run_item(work_t *it)
{
    if (it->wait) {
        it->wait->cb(it->wait->ctx, it->timed_out);
        finish(it->wait);
    } else {
        it->fn(it->ctx);
    }
    HeapFree(GetProcessHeap(), 0, it);
}

static DWORD WINAPI worker_main(LPVOID arg)
{
    (void)arg;
    for (;;) {
        work_t *it;
        WaitForSingleObject(g_work_sem, INFINITE);
        lock();
        it = g_work_head;
        if (it) { g_work_head = it->next; if (!g_work_head) g_work_tail = 0; }
        --g_idle;
        unlock();
        if (it) run_item(it);
        lock();
        ++g_idle;
        unlock();
    }
    return 0;                                                   /* not reached: pool threads end with the process */
}

static BOOL post_work(work_t *it)
{
    int spawn = 0;
    lock();
    if (!g_work_sem) g_work_sem = CreateSemaphoreW(0, 0, 0x7fffffff, 0);
    if (!g_work_sem) { unlock(); return FALSE; }
    it->next = 0;
    if (g_work_tail) g_work_tail->next = it; else g_work_head = it;
    g_work_tail = it;
    if (g_idle == 0 && g_workers < MAX_WORKERS) { ++g_workers; ++g_idle; spawn = 1; }
    unlock();
    if (spawn) {
        HANDLE t = CreateThread(0, 0, worker_main, 0, 0, 0);
        if (t) CloseHandle(t);
        else { lock(); --g_workers; --g_idle; unlock(); }
    }
    ReleaseSemaphore(g_work_sem, 1, 0);
    return TRUE;
}

K32API BOOL WINAPI QueueUserWorkItem(LPTHREAD_START_ROUTINE fn, PVOID ctx, ULONG flags)
{
    work_t *it;
    (void)flags;                                                /* WT_EXECUTELONGFUNCTION etc.: scheduling hints */
    if (!fn) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    it = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *it);
    if (!it) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    it->fn = fn;
    it->ctx = ctx;
    if (!post_work(it)) { HeapFree(GetProcessHeap(), 0, it); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    return TRUE;
}

/* ---------------------------------------------------------------- wait threads */
static int still_listed(wait_thread_t *wt, k32_wait_t *w)
{
    DWORD i;
    for (i = 0; i < wt->count; ++i) if (wt->w[i] == w) return 1;
    return 0;
}

/* Runs `w`'s callback if it is still registered on `wt` and armed; `timed_out` waits also need their deadline to have
 * passed. The check and the running count change under one lock, so an unregistering thread never frees a wait that is
 * about to run. */
static void dispatch(wait_thread_t *wt, k32_wait_t *w, HANDLE obj, BOOLEAN timed_out)
{
    work_t *it;
    lock();
    if (!still_listed(wt, w) || !w->active || w->obj != obj ||
        (timed_out && (w->ms == INFINITE || (LONG)(w->deadline - GetTickCount()) > 0))) {
        unlock();
        return;
    }
    if (w->flags & WT_EXECUTEONLYONCE) w->active = 0;
    else if (w->ms != INFINITE) w->deadline = GetTickCount() + w->ms;
    ++w->running;
    unlock();
    if (w->flags & WT_EXECUTEINWAITTHREAD) {
        w->cb(w->ctx, timed_out);
        finish(w);
        return;
    }
    it = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *it);
    if (!it || (it->wait = w, it->timed_out = timed_out, !post_work(it))) {
        if (it) HeapFree(GetProcessHeap(), 0, it);
        w->cb(w->ctx, timed_out);                               /* no worker available: run it here rather than lose it */
        finish(w);
    }
}

static DWORD WINAPI wait_thread_main(LPVOID arg)
{
    wait_thread_t *wt = arg;
    HANDLE hs[WAITS_PER_THREAD + 1];
    k32_wait_t *ws[WAITS_PER_THREAD + 1];
    for (;;) {
        DWORD n = 1, i, timeout = INFINITE, now, r;
        lock();
        hs[0] = wt->control;
        now = GetTickCount();
        for (i = 0; i < wt->count; ++i) {
            k32_wait_t *w = wt->w[i];
            if (!w->active) continue;
            hs[n] = w->obj;
            ws[n++] = w;
            if (w->ms != INFINITE) {
                const DWORD left = (LONG)(w->deadline - now) > 0 ? w->deadline - now : 0;
                if (left < timeout) timeout = left;
            }
        }
        unlock();
        r = WaitForMultipleObjectsEx(n, hs, FALSE, timeout, FALSE);
        if (r == WAIT_OBJECT_0) continue;                       /* the list changed */
        if (r > WAIT_OBJECT_0 && r < WAIT_OBJECT_0 + n) {
            dispatch(wt, ws[r - WAIT_OBJECT_0], hs[r - WAIT_OBJECT_0], FALSE);
            continue;
        }
        if (r == WAIT_TIMEOUT) {
            for (i = 1; i < n; ++i) dispatch(wt, ws[i], hs[i], TRUE);
            continue;
        }
        /* WAIT_FAILED: a registered handle went bad (closed by its owner). Disarm the waits whose handle fails. */
        for (i = 1; i < n; ++i)
            if (WaitForSingleObject(hs[i], 0) == WAIT_FAILED) { lock(); if (still_listed(wt, ws[i])) ws[i]->active = 0; unlock(); }
        Sleep(1);
    }
    return 0;                                                   /* not reached */
}

K32API BOOL WINAPI RegisterWaitForSingleObject(PHANDLE out, HANDLE obj, WAITORTIMERCALLBACK cb, PVOID ctx, ULONG ms, ULONG flags)
{
    k32_wait_t *w;
    wait_thread_t *wt = 0;
    DWORD i;
    if (!out || !cb || !obj || obj == INVALID_HANDLE_VALUE) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    w = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *w);
    if (!w) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    w->obj = obj;
    w->cb = cb;
    w->ctx = ctx;
    w->ms = ms;
    w->flags = flags;
    w->deadline = GetTickCount() + ms;
    w->active = 1;
    lock();
    for (i = 0; i < g_nthreads; ++i) if (g_threads[i].count < WAITS_PER_THREAD) { wt = &g_threads[i]; break; }
    if (!wt && g_nthreads < MAX_WAIT_THREADS) {
        wt = &g_threads[g_nthreads];
        wt->control = CreateEventW(0, FALSE, FALSE, 0);
        wt->thread = wt->control ? CreateThread(0, 0, wait_thread_main, wt, 0, 0) : 0;
        if (!wt->thread) { if (wt->control) CloseHandle(wt->control); wt->control = 0; wt = 0; }
        else ++g_nthreads;
    }
    if (!wt) { unlock(); HeapFree(GetProcessHeap(), 0, w); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    wt->w[wt->count++] = w;
    w->wt = wt;
    unlock();
    SetEvent(wt->control);
    *out = (HANDLE)w;
    return TRUE;
}

K32API BOOL WINAPI UnregisterWaitEx(HANDLE h, HANDLE done)
{
    k32_wait_t *w = (k32_wait_t *)h;
    wait_thread_t *wt;
    int running;
    DWORD i;
    if (!w) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    lock();
    wt = w->wt;
    if (!wt || w->unregistered) { unlock(); shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    for (i = 0; i < wt->count; ++i) if (wt->w[i] == w) { wt->w[i] = wt->w[--wt->count]; break; }
    w->active = 0;
    w->unregistered = 1;
    w->done_event = done;
    running = w->running;
    unlock();
    SetEvent(wt->control);                                      /* the wait thread drops the handle from its wait */
    if (done == INVALID_HANDLE_VALUE) {                         /* block until every callback has returned */
        for (;;) {
            lock();
            running = w->running;
            unlock();
            if (!running) break;
            Sleep(1);
        }
        HeapFree(GetProcessHeap(), 0, w);
        return TRUE;
    }
    if (!running) {
        if (done) SetEvent(done);
        HeapFree(GetProcessHeap(), 0, w);
        return TRUE;
    }
    if (!done) { shz_set_last_error(ERROR_IO_PENDING); return FALSE; }   /* unregistered; a callback is still running */
    return TRUE;
}

K32API BOOL WINAPI UnregisterWait(HANDLE h) { return UnregisterWaitEx(h, 0); }
