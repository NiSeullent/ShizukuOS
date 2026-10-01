/*
 * Standalone AMD64 owned threadpool work, timers and waits.
 * Adapted from original project src/m98_threadpool.c; no upstream code copied.
 * Process-lifetime Kernel32 provider, lazy initialization outside DllMain.
 * Copyright (C) 2026 Win98-Modern contributors. GPL-2.0-only.
 *
 * Source review: Wine df15af365251 dlls/ntdll/threadpool.c (TpAllocWork,
 * tp_object_submit/cancel/execute, TpReleaseWork and TpWaitForWork), Wine
 * dlls/kernelbase/thread.c, ReactOS 9dc3ca8720 sdk/lib/rtl/threadpool.c and
 * dll/win32/kernel32/kernel32_vista/threadpool.c. No upstream code is copied.
 * Win98 lacks the NT completion-port and condition-variable implementation;
 * this independent adapter uses original Win98 threads, a semaphore and a
 * critical section. See docs/THREADPOOL_WORK_PORT.md for its scope.
 */
#ifdef SHZ_HOST_TEST
#include "../tests/office_threadpool_host_api.h"
#else
#include "k32_ipc.h"
#endif

#define K64_TP_WORK_MAGIC 0x4d395457UL /* M9TW */
#define K64_TP_INSTANCE_MAGIC 0x4d395449UL /* M9TI */
#define K64_TP_WORKER_COUNT 4
#define K64_TP_MAX_WORKERS 500

typedef struct k64_tp_work k64_tp_work;
struct k64_tp_bucket;
static k64_tp_work *k64_tp_timers;
static unsigned k64_tp_ensure_initialized(void);
static void k64_tp_timer_scan(DWORD *);
typedef struct k64_tp_callback_instance {
    DWORD magic;
    DWORD thread_id;
    k64_tp_work *work;
    BOOL associated;
    BOOL may_run_long;
    PCRITICAL_SECTION deferred_section;
    HANDLE deferred_mutex, deferred_semaphore, deferred_event;
    DWORD deferred_semaphore_count;
    HMODULE deferred_library;
} k64_tp_callback_instance;

struct k64_tp_work {
    DWORD magic;
    k64_tp_work *next;
    PTP_WORK_CALLBACK callback;
    PTP_SIMPLE_CALLBACK simple_callback;
    PTP_SIMPLE_CALLBACK finalization;
    PVOID context;
    HANDLE idle_event; /* pending + associated callbacks == 0 */
    DWORD pending;
    DWORD running;
    ULONGLONG references; /* caller ownership + one per outstanding callback */
    BOOL queued;
    BOOL closed;
    BOOL runs_long;
    unsigned kind; /* 0 work, 1 timer, 2 wait */
    DWORD signaled_pending, period;
    ULONGLONG due, generation;
    BOOL armed;
    struct k64_tp_work *timer_next;
    struct k64_tp_bucket *bucket;
    HANDLE watched;
};

/* MS ABI V1 prefix and V3 continuation; V1 ends after flags. */
typedef struct k64_tp_environment {
    DWORD version;
    PVOID pool, cleanup, cancel, race_dll, activation;
    PTP_SIMPLE_CALLBACK finalization;
    DWORD flags, priority, size;
} k64_tp_environment;
_Static_assert(offsetof(k64_tp_environment, flags) == 56, "x64 environment flags");
_Static_assert(offsetof(k64_tp_environment, priority) == 60, "x64 V3 priority");
_Static_assert(sizeof(k64_tp_environment) == 72, "x64 V3 extent");

static CRITICAL_SECTION k64_tp_lock;
static HANDLE k64_tp_semaphore;
static k64_tp_work *k64_tp_first, *k64_tp_last;
static DWORD k64_tp_workers;
static DWORD k64_tp_busy;
static HANDLE k64_tp_growth_event;
static BOOL k64_tp_monitor_started, k64_tp_retry_growth;
static BOOL k64_tp_initialized, k64_tp_shutdown;

static BOOL k64_tp_grow_workers(DWORD target);

/* A control thread retries failed growth even when every callback is blocked.
 * This is also a shared scheduling foundation for later timer/wait objects.
 * It never invokes application callbacks and is not counted as a pool worker. */
static DWORD WINAPI k64_tp_monitor(void *unused)
{
    DWORD timeout = 200;
    (void)unused;
    for (;;) {
        WaitForSingleObject(k64_tp_growth_event, timeout);
        EnterCriticalSection(&k64_tp_lock);
        if (k64_tp_shutdown) {
            LeaveCriticalSection(&k64_tp_lock);
            return 0;
        }
        timeout = 200;
        k64_tp_timer_scan(&timeout);
        if (k64_tp_first && k64_tp_busy >= k64_tp_workers) k64_tp_retry_growth = TRUE;
        if (k64_tp_retry_growth) {
            if (k64_tp_busy < k64_tp_workers ||
                (k64_tp_workers < K64_TP_MAX_WORKERS &&
                 k64_tp_grow_workers(k64_tp_workers + 1)))
                k64_tp_retry_growth = FALSE;
        }
        LeaveCriticalSection(&k64_tp_lock);
    }
}

static k64_tp_callback_instance *k64_tp_instance(PTP_CALLBACK_INSTANCE opaque)
{
    k64_tp_callback_instance *instance = (k64_tp_callback_instance *)opaque;
    if (!instance || instance->magic != K64_TP_INSTANCE_MAGIC ||
        instance->thread_id != GetCurrentThreadId()) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    return instance;
}

/* Source review: pinned Wine ntdll/threadpool.c tp_object_execute_callbacks
 * and ReactOS rtl/threadpool.c use one deferred resource of each kind, after
 * finalization, and stop later cleanup on a failed native handle operation.
 * Independent Win98 implementation: use original KERNEL32 handle functions. */
static void k64_tp_cleanup(k64_tp_callback_instance *instance)
{
    if (instance->deferred_section)
        LeaveCriticalSection(instance->deferred_section);
    if (instance->deferred_mutex && !ReleaseMutex(instance->deferred_mutex)) return;
    if (instance->deferred_semaphore &&
        !ReleaseSemaphore(instance->deferred_semaphore,
                          instance->deferred_semaphore_count, NULL)) return;
    if (instance->deferred_event && !SetEvent(instance->deferred_event)) return;
    if (instance->deferred_library) FreeLibrary(instance->deferred_library);
}

static void k64_tp_queue_push(k64_tp_work *work)
{
    work->next = NULL;
    work->queued = TRUE;
    if (k64_tp_last) k64_tp_last->next = work;
    else k64_tp_first = work;
    k64_tp_last = work;
}

static k64_tp_work *k64_tp_queue_pop(void)
{
    k64_tp_work *work = k64_tp_first;
    if (work) {
        k64_tp_first = work->next;
        if (!k64_tp_first) k64_tp_last = NULL;
        work->next = NULL;
        work->queued = FALSE;
    }
    return work;
}

static void k64_tp_queue_remove(k64_tp_work *work)
{
    k64_tp_work *previous = NULL, *cursor = k64_tp_first;
    while (cursor && cursor != work) {
        previous = cursor;
        cursor = cursor->next;
    }
    if (!cursor) return;
    if (previous) previous->next = work->next;
    else k64_tp_first = work->next;
    if (k64_tp_last == work) k64_tp_last = previous;
    work->next = NULL;
    work->queued = FALSE;
}

static void k64_tp_destroy_work(k64_tp_work *work)
{
    CloseHandle(work->idle_event);
    work->magic = 0;
    HeapFree(GetProcessHeap(), 0, work);
}

static DWORD WINAPI k64_tp_worker(void *unused)
{
    (void)unused;
    for (;;) {
        k64_tp_work *work;
        k64_tp_callback_instance instance;
        BOOL destroy;
        BOOL signaled = FALSE;

        if (WaitForSingleObject(k64_tp_semaphore, INFINITE) != WAIT_OBJECT_0)
            return 0;
        EnterCriticalSection(&k64_tp_lock);
        if (k64_tp_shutdown) {
            LeaveCriticalSection(&k64_tp_lock);
            return 0;
        }
        work = k64_tp_queue_pop();
        if (!work) {
            /* Close/Wait may have canceled a queued work object's permit. */
            LeaveCriticalSection(&k64_tp_lock);
            continue;
        }
        --work->pending;
        if (work->kind == 2 && work->signaled_pending) { --work->signaled_pending; signaled = TRUE; }
        ++work->running;
        ++k64_tp_busy;
        if (work->pending) {
            k64_tp_queue_push(work);
            ReleaseSemaphore(k64_tp_semaphore, 1, NULL);
        }
        LeaveCriticalSection(&k64_tp_lock);

        instance.magic = K64_TP_INSTANCE_MAGIC;
        instance.thread_id = GetCurrentThreadId();
        instance.work = work;
        instance.associated = TRUE;
        instance.may_run_long = FALSE;
        instance.deferred_section = NULL;
        instance.deferred_mutex = NULL;
        instance.deferred_semaphore = NULL;
        instance.deferred_event = NULL;
        instance.deferred_semaphore_count = 0;
        instance.deferred_library = NULL;
        if (work->runs_long) CallbackMayRunLong((PTP_CALLBACK_INSTANCE)&instance);
        if (work->simple_callback)
            work->simple_callback((PTP_CALLBACK_INSTANCE)&instance, work->context);
        else if (work->kind == 1)
            ((PTP_TIMER_CALLBACK)work->callback)((PTP_CALLBACK_INSTANCE)&instance, work->context, (PTP_TIMER)work);
        else if (work->kind == 2)
            ((PTP_WAIT_CALLBACK)work->callback)((PTP_CALLBACK_INSTANCE)&instance, work->context, (PTP_WAIT)work, signaled ? WAIT_OBJECT_0 : WAIT_TIMEOUT);
        else
            work->callback((PTP_CALLBACK_INSTANCE)&instance, work->context,
                           (PTP_WORK)work);
        if (work->finalization)
            work->finalization((PTP_CALLBACK_INSTANCE)&instance, work->context);
        k64_tp_cleanup(&instance);
        instance.magic = 0;

        EnterCriticalSection(&k64_tp_lock);
        if (instance.associated) --work->running;
        --k64_tp_busy;
        --work->references;
        if (!work->pending && !work->running) SetEvent(work->idle_event);
        destroy = work->closed && !work->references;
        LeaveCriticalSection(&k64_tp_lock);
        if (destroy) k64_tp_destroy_work(work);
    }
}

static BOOL k64_tp_grow_workers(DWORD target)
{
    DWORD error = 0;
    while (k64_tp_workers < target) {
        DWORD thread_id;
        /* Original Win9x CreateThread requires a writable lpThreadId. The
         * KernelEx CreateThread_fix supplies a dummy for NULL, but an API
         * provider can import the original function before that override is
         * active. Never rely on the fix here. */
        HANDLE thread = CreateThread(NULL, 0, k64_tp_worker, NULL, 0,
                                     &thread_id);
        if (!thread) {
            error = GetLastError();
            break;
        }
        ++k64_tp_workers;
        CloseHandle(thread);
    }
    if (k64_tp_workers < target) {
        SetLastError(error ? error : ERROR_GEN_FAILURE);
        return FALSE;
    }
    return TRUE;
}

static BOOL k64_tp_ensure_workers(void)
{
    if (!k64_tp_monitor_started) {
        DWORD thread_id;
        HANDLE thread = CreateThread(NULL, 0, k64_tp_monitor, NULL, 0, &thread_id);
        if (!thread) return FALSE;
        CloseHandle(thread);
        k64_tp_monitor_started = TRUE;
    }
    k64_tp_grow_workers(K64_TP_WORKER_COUNT);
    return k64_tp_workers != 0;
}

static BOOL k64_tp_supported_environment(PTP_CALLBACK_ENVIRON opaque)
{
    const k64_tp_environment *env = (const k64_tp_environment *)opaque;
    if (!env) return TRUE;
    if (env->version != 1 && env->version != 3) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (env->pool || env->cleanup || env->cancel || env->race_dll || env->activation || (env->flags & ~1u)) {
        SetLastError(ERROR_NOT_SUPPORTED); return FALSE;
    }
    if (env->version == 3 && (env->size != sizeof(*env) || env->priority != TP_CALLBACK_PRIORITY_NORMAL)) {
        SetLastError(ERROR_NOT_SUPPORTED); return FALSE;
    }
    return TRUE;
}

static BOOL k64_tp_initialize(void)
{
    InitializeCriticalSection(&k64_tp_lock);
    k64_tp_semaphore = CreateSemaphoreA(NULL, 0, 0x7fffffff, NULL);
    if (!k64_tp_semaphore) {
        DWORD error = GetLastError();
        DeleteCriticalSection(&k64_tp_lock);
        SetLastError(error ? error : ERROR_GEN_FAILURE);
        return FALSE;
    }
    k64_tp_growth_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!k64_tp_growth_event) {
        DWORD error = GetLastError();
        CloseHandle(k64_tp_semaphore);
        DeleteCriticalSection(&k64_tp_lock);
        SetLastError(error ? error : ERROR_GEN_FAILURE);
        return FALSE;
    }
    k64_tp_first = k64_tp_last = NULL;
    k64_tp_workers = 0;
    k64_tp_busy = 0;
    k64_tp_monitor_started = k64_tp_retry_growth = FALSE;
    k64_tp_shutdown = FALSE;
    k64_tp_initialized = TRUE;
    return TRUE;
}

/* Kernel32 is process-lifetime. Never wait on worker/callback threads from
 * process-termination DllMain, where killed owners can retain locks. */
static unsigned k64_tp_ensure_initialized(void)
{
    static LONG phase;
    LONG expected;
    for (;;) {
        if (__atomic_load_n(&phase, __ATOMIC_ACQUIRE) == 2) return 1;
        expected = 0;
        if (__atomic_compare_exchange_n(&phase, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            BOOL ok = k64_tp_initialize();
            DWORD error = ok ? 0 : GetLastError();
            __atomic_store_n(&phase, ok ? 2 : 0, __ATOMIC_RELEASE);
            if (!ok) SetLastError(error);
            return ok != FALSE;
        }
        Sleep(0);
    }
}

static void k64_tp_close(PTP_WORK);
static PTP_WORK k64_tp_create(PTP_WORK_CALLBACK callback,
                              PTP_SIMPLE_CALLBACK simple_callback,
                              PVOID context, PTP_CALLBACK_ENVIRON environment)
{
    k64_tp_work *work;
    if (!callback && !simple_callback) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!k64_tp_supported_environment(environment)) return NULL;
    if (!k64_tp_ensure_initialized()) return NULL;
    work = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*work));
    if (!work) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    work->idle_event = CreateEventA(NULL, TRUE, TRUE, NULL);
    if (!work->idle_event) {
        DWORD error = GetLastError();
        HeapFree(GetProcessHeap(), 0, work);
        SetLastError(error ? error : ERROR_GEN_FAILURE);
        return NULL;
    }
    work->magic = K64_TP_WORK_MAGIC;
    work->callback = callback;
    work->simple_callback = simple_callback;
    work->context = context;
    work->finalization = environment ? ((k64_tp_environment *)environment)->finalization : NULL;
    work->runs_long = environment && (((k64_tp_environment *)environment)->flags & 1);
    work->references = 1;
    EnterCriticalSection(&k64_tp_lock);
    if (!k64_tp_ensure_workers()) {
        DWORD error = GetLastError();
        LeaveCriticalSection(&k64_tp_lock);
        k64_tp_destroy_work(work);
        SetLastError(error ? error : ERROR_GEN_FAILURE);
        return NULL;
    }
    LeaveCriticalSection(&k64_tp_lock);
    return (PTP_WORK)work;
}

K32API PTP_WORK WINAPI CreateThreadpoolWork(PTP_WORK_CALLBACK callback,
                                         PVOID context,
                                         PTP_CALLBACK_ENVIRON environment)
{
    return k64_tp_create(callback, NULL, context, environment);
}

K32API BOOL WINAPI TrySubmitThreadpoolCallback(PTP_SIMPLE_CALLBACK callback,
                                            PVOID context,
                                            PTP_CALLBACK_ENVIRON environment)
{
    PTP_WORK work = k64_tp_create(NULL, callback, context, environment);
    if (!work) return FALSE;
    SubmitThreadpoolWork(work);
    k64_tp_close(work);
    return TRUE;
}

static BOOL k64_tp_submit_locked(k64_tp_work *work, BOOL signaled)
{
    if (work->closed || work->pending == 0xffffffffu) { SetLastError(ERROR_TOO_MANY_POSTS); return FALSE; }
    if (!work->pending && !work->running) ResetEvent(work->idle_event);
    ++work->pending; ++work->references;
    if (signaled) ++work->signaled_pending;
    if (!work->queued) {
        k64_tp_queue_push(work);
        if (!ReleaseSemaphore(k64_tp_semaphore, 1, NULL)) {
            k64_tp_queue_remove(work); --work->pending; --work->references;
            if (signaled) --work->signaled_pending;
            if (!work->pending && !work->running) SetEvent(work->idle_event);
            return FALSE;
        }
    }
    if (k64_tp_busy >= k64_tp_workers) { k64_tp_retry_growth = TRUE; SetEvent(k64_tp_growth_event); }
    return TRUE;
}
K32API void WINAPI SubmitThreadpoolWork(PTP_WORK opaque)
{
    k64_tp_work *work = (k64_tp_work *)opaque;
    if (!work || work->magic != K64_TP_WORK_MAGIC || work->kind != 0) { SetLastError(ERROR_INVALID_PARAMETER); return; }
    EnterCriticalSection(&k64_tp_lock); k64_tp_submit_locked(work, FALSE); LeaveCriticalSection(&k64_tp_lock);
}

static void k64_tp_wait_callbacks(PTP_WORK opaque,
                                                BOOL cancel_pending)
{
    k64_tp_work *work = (k64_tp_work *)opaque;
    if (!work || work->magic != K64_TP_WORK_MAGIC) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return;
    }
    EnterCriticalSection(&k64_tp_lock);
    ++work->references; /* an entered waiter survives a concurrent close */
    if (cancel_pending) {
        if (work->queued) k64_tp_queue_remove(work);
        work->references -= work->pending;
        work->pending = 0;
        work->signaled_pending = 0;
        if (!work->running) SetEvent(work->idle_event);
    }
    LeaveCriticalSection(&k64_tp_lock);
    WaitForSingleObject(work->idle_event, INFINITE);
    EnterCriticalSection(&k64_tp_lock);
    --work->references;
    if (work->closed && !work->references) k64_tp_destroy_work(work);
    LeaveCriticalSection(&k64_tp_lock);
}

static void k64_tp_close(PTP_WORK opaque)
{
    k64_tp_work *work = (k64_tp_work *)opaque;
    BOOL destroy;
    if (!work || work->magic != K64_TP_WORK_MAGIC) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return;
    }
    EnterCriticalSection(&k64_tp_lock);
    if (work->closed) {
        LeaveCriticalSection(&k64_tp_lock);
        SetLastError(ERROR_INVALID_HANDLE);
        return;
    }
    work->closed = TRUE;
    /* Closing drops caller ownership, but callbacks already submitted still
     * run. WaitForThreadpoolWorkCallbacks(..., TRUE) is the cancel operation. */
    --work->references;
    destroy = !work->references;
    LeaveCriticalSection(&k64_tp_lock);
    if (destroy) k64_tp_destroy_work(work);
}

K32API void WINAPI FreeLibraryWhenCallbackReturns(PTP_CALLBACK_INSTANCE opaque,
                                                HMODULE module)
{
    k64_tp_callback_instance *instance = k64_tp_instance(opaque);
    if (!instance || !module) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return;
    }
    /* Windows/Wine keep one deferred library per callback instance. */
    if (!instance->deferred_library)
        instance->deferred_library = module;
}

K32API void WINAPI LeaveCriticalSectionWhenCallbackReturns(PTP_CALLBACK_INSTANCE opaque,
                                                        PCRITICAL_SECTION section)
{
    k64_tp_callback_instance *instance = k64_tp_instance(opaque);
    if (instance && !instance->deferred_section) instance->deferred_section = section;
}

K32API void WINAPI ReleaseMutexWhenCallbackReturns(PTP_CALLBACK_INSTANCE opaque, HANDLE mutex)
{
    k64_tp_callback_instance *instance = k64_tp_instance(opaque);
    if (instance && !instance->deferred_mutex) instance->deferred_mutex = mutex;
}

K32API void WINAPI ReleaseSemaphoreWhenCallbackReturns(PTP_CALLBACK_INSTANCE opaque,
                                                    HANDLE semaphore, DWORD count)
{
    k64_tp_callback_instance *instance = k64_tp_instance(opaque);
    if (instance && !instance->deferred_semaphore) {
        instance->deferred_semaphore = semaphore;
        instance->deferred_semaphore_count = count;
    }
}

K32API void WINAPI SetEventWhenCallbackReturns(PTP_CALLBACK_INSTANCE opaque, HANDLE event)
{
    k64_tp_callback_instance *instance = k64_tp_instance(opaque);
    if (instance && !instance->deferred_event) instance->deferred_event = event;
}

/* Disassociation releases waiters but does not drop the callback's reference.
 * Native Windows and both reviewed upstreams retain the object through actual
 * callback return, finalization and resource cleanup. */
K32API void WINAPI DisassociateCurrentThreadFromCallback(PTP_CALLBACK_INSTANCE opaque)
{
    k64_tp_callback_instance *instance = k64_tp_instance(opaque);
    k64_tp_work *work;
    if (!instance || !instance->associated) return;
    work = instance->work;
    EnterCriticalSection(&k64_tp_lock);
    instance->associated = FALSE;
    --work->running;
    if (!work->pending && !work->running) SetEvent(work->idle_event);
    LeaveCriticalSection(&k64_tp_lock);
}

K32API BOOL WINAPI CallbackMayRunLong(PTP_CALLBACK_INSTANCE opaque)
{
    k64_tp_callback_instance *instance = k64_tp_instance(opaque);
    BOOL available = TRUE;
    if (!instance) return FALSE;
    if (instance->may_run_long) return TRUE;
    EnterCriticalSection(&k64_tp_lock);
    if (k64_tp_busy >= k64_tp_workers) {
        if (k64_tp_workers < K64_TP_MAX_WORKERS)
            available = k64_tp_grow_workers(k64_tp_workers + 1);
        else {
            SetLastError(ERROR_MAX_THRDS_REACHED);
            available = FALSE;
        }
        if (!available) k64_tp_retry_growth = TRUE;
    }
    instance->may_run_long = TRUE;
    LeaveCriticalSection(&k64_tp_lock);
    return available;
}

static k64_tp_work *k64_tp_typed(PVOID opaque, unsigned kind)
{
    k64_tp_work *object = opaque;
    if (!object || object->magic != K64_TP_WORK_MAGIC || object->kind != kind) {
        SetLastError(ERROR_INVALID_PARAMETER); return NULL;
    }
    return object;
}
K32API void WINAPI WaitForThreadpoolWorkCallbacks(PTP_WORK work, BOOL cancel)
{ if (k64_tp_typed(work, 0)) k64_tp_wait_callbacks(work, cancel); }
K32API void WINAPI CloseThreadpoolWork(PTP_WORK work)
{ if (k64_tp_typed(work, 0)) k64_tp_close(work); }

static ULONGLONG k64_tp_now(void)
{
    LARGE_INTEGER now;
    if (NtQuerySystemTime(&now)) return 0;
    return (ULONGLONG)now.QuadPart;
}
static ULONGLONG k64_tp_due(const FILETIME *time, ULONGLONG now)
{
    ULONGLONG value = ((ULONGLONG)time->dwHighDateTime << 32) | time->dwLowDateTime;
    if ((LONGLONG)value < 0) {
        ULONGLONG delta = 0 - value;
        return delta > ~(ULONGLONG)0 - now ? ~(ULONGLONG)0 : now + delta;
    }
    return value;
}
static DWORD k64_tp_timeout(ULONGLONG due, ULONGLONG now)
{
    ULONGLONG delta, ms;
    if (due <= now) return 0;
    delta = due - now;
    ms = delta / 10000 + (delta % 10000 != 0);
    return ms >= INFINITE ? INFINITE - 1 : (DWORD)ms;
}
/* Called with the scheduler lock held. Dispatch uses the same callback-owned
 * queue as work objects; the scheduler thread never invokes user callbacks. */
static void k64_tp_timer_scan(DWORD *timeout)
{
    k64_tp_work *timer;
    ULONGLONG now = k64_tp_now();
    for (timer = k64_tp_timers; timer; timer = timer->timer_next) {
        DWORD left;
        if (!timer->armed) continue;
        if (timer->due <= now) {
            if (!k64_tp_submit_locked(timer, FALSE)) { *timeout = 1; continue; }
            if (timer->period) {
                ULONGLONG step = (ULONGLONG)timer->period * 10000;
                timer->due = step > ~(ULONGLONG)0 - timer->due ? ~(ULONGLONG)0 : timer->due + step;
                if (timer->due <= now) timer->due = now + 1;
            } else timer->armed = FALSE;
        }
        if (timer->armed) { left = k64_tp_timeout(timer->due, now); if (left < *timeout) *timeout = left; }
    }
}
K32API PTP_TIMER WINAPI CreateThreadpoolTimer(PTP_TIMER_CALLBACK callback, PVOID context, PTP_CALLBACK_ENVIRON environment)
{
    k64_tp_work *timer = (k64_tp_work *)k64_tp_create((PTP_WORK_CALLBACK)callback, NULL, context, environment);
    if (!timer) return NULL;
    EnterCriticalSection(&k64_tp_lock);
    timer->kind = 1; ++timer->references; /* timer-list membership */
    timer->timer_next = k64_tp_timers; k64_tp_timers = timer;
    LeaveCriticalSection(&k64_tp_lock);
    return (PTP_TIMER)timer;
}
K32API void WINAPI SetThreadpoolTimer(PTP_TIMER opaque, PFILETIME due, DWORD period, DWORD window)
{
    k64_tp_work *timer = k64_tp_typed(opaque, 1);
    (void)window; /* coalescing allowance is optional; this scheduler never fires early */
    if (!timer) return;
    EnterCriticalSection(&k64_tp_lock);
    if (timer->closed) { LeaveCriticalSection(&k64_tp_lock); SetLastError(ERROR_INVALID_HANDLE); return; }
    ++timer->generation;
    timer->armed = due != NULL;
    timer->period = period;
    if (due) timer->due = k64_tp_due(due, k64_tp_now());
    LeaveCriticalSection(&k64_tp_lock);
    SetEvent(k64_tp_growth_event);
}
K32API void WINAPI WaitForThreadpoolTimerCallbacks(PTP_TIMER timer, BOOL cancel)
{ if (k64_tp_typed(timer, 1)) k64_tp_wait_callbacks((PTP_WORK)timer, cancel); }
K32API void WINAPI CloseThreadpoolTimer(PTP_TIMER opaque)
{
    k64_tp_work *timer = k64_tp_typed(opaque, 1), **cursor;
    if (!timer) return;
    EnterCriticalSection(&k64_tp_lock);
    for (cursor = &k64_tp_timers; *cursor && *cursor != timer; cursor = &(*cursor)->timer_next) {}
    if (!*cursor) { LeaveCriticalSection(&k64_tp_lock); SetLastError(ERROR_INVALID_HANDLE); return; }
    *cursor = timer->timer_next; timer->armed = FALSE; ++timer->generation;
    --timer->references; /* caller reference still exists through k64_tp_close */
    LeaveCriticalSection(&k64_tp_lock);
    SetEvent(k64_tp_growth_event);
    k64_tp_close((PTP_WORK)timer);
}

#define K64_TP_BUCKET_CAPACITY 63
struct k64_tp_bucket {
    struct k64_tp_bucket *next;
    HANDLE control;
    DWORD count;
    k64_tp_work *objects[K64_TP_BUCKET_CAPACITY];
};
static struct k64_tp_bucket *k64_tp_buckets;
static void k64_tp_release_locked(k64_tp_work *object)
{
    --object->references;
    if (object->closed && !object->references) k64_tp_destroy_work(object);
}
static DWORD WINAPI k64_tp_wait_monitor(PVOID parameter)
{
    struct k64_tp_bucket *bucket = parameter;
    HANDLE handles[K64_TP_BUCKET_CAPACITY + 1];
    k64_tp_work *objects[K64_TP_BUCKET_CAPACITY];
    ULONGLONG generations[K64_TP_BUCKET_CAPACITY];
    for (;;) {
        DWORD i, count = 0, timeout = INFINITE, result;
        ULONGLONG now;
        EnterCriticalSection(&k64_tp_lock);
        now = k64_tp_now(); handles[0] = bucket->control;
        for (i = 0; i < bucket->count; ++i) {
            k64_tp_work *wait = bucket->objects[i];
            DWORD left;
            if (!wait->armed) continue;
            if (wait->due != ~(ULONGLONG)0 && wait->due <= now) {
                if (k64_tp_submit_locked(wait, FALSE)) wait->armed = FALSE;
                else timeout = 1;
                continue;
            }
            objects[count] = wait; generations[count] = wait->generation;
            ++wait->references; /* keep the object through unlocked native wait */
            handles[++count] = wait->watched;
            if (wait->due != ~(ULONGLONG)0) {
                left = k64_tp_timeout(wait->due, now); if (left < timeout) timeout = left;
            }
        }
        LeaveCriticalSection(&k64_tp_lock);
        result = WaitForMultipleObjects(count + 1, handles, FALSE, timeout);
        EnterCriticalSection(&k64_tp_lock);
        now = k64_tp_now();
        for (i = 0; i < count; ++i) {
            k64_tp_work *wait = objects[i];
            BOOL signaled = result == WAIT_OBJECT_0 + i + 1;
            BOOL expired = result == WAIT_TIMEOUT && wait->due != ~(ULONGLONG)0 && wait->due <= now;
            if ((signaled || expired) && !wait->closed && wait->armed && wait->bucket == bucket && wait->generation == generations[i]) {
                if (k64_tp_submit_locked(wait, signaled)) wait->armed = FALSE; /* one shot until rearmed */
            }
            k64_tp_release_locked(wait);
        }
        LeaveCriticalSection(&k64_tp_lock);
        /* A replacement can close an old snapshot handle before NtWait captures
         * it. Its epoch prevents dispatch, and the control event rebuilds the
         * snapshot. Do not probe other auto-reset handles and consume signals. */
        if (result == WAIT_FAILED) Sleep(1);
    }
    return 0;
}
K32API PTP_WAIT WINAPI CreateThreadpoolWait(PTP_WAIT_CALLBACK callback, PVOID context, PTP_CALLBACK_ENVIRON environment)
{
    k64_tp_work *wait = (k64_tp_work *)k64_tp_create((PTP_WORK_CALLBACK)callback, NULL, context, environment);
    struct k64_tp_bucket *bucket;
    if (!wait) return NULL;
    EnterCriticalSection(&k64_tp_lock);
    for (bucket = k64_tp_buckets; bucket && bucket->count == K64_TP_BUCKET_CAPACITY; bucket = bucket->next) {}
    if (!bucket) {
        HANDLE thread = NULL;
        DWORD thread_id, error;
        bucket = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *bucket);
        if (bucket) bucket->control = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (bucket && bucket->control) thread = CreateThread(NULL, 0, k64_tp_wait_monitor, bucket, 0, &thread_id);
        if (!thread) {
            error = GetLastError();
            if (bucket) { if (bucket->control) CloseHandle(bucket->control); HeapFree(GetProcessHeap(), 0, bucket); }
            LeaveCriticalSection(&k64_tp_lock); k64_tp_close((PTP_WORK)wait);
            SetLastError(error ? error : ERROR_NOT_ENOUGH_MEMORY); return NULL;
        }
        CloseHandle(thread);
        bucket->next = k64_tp_buckets; k64_tp_buckets = bucket;
    }
    wait->kind = 2; wait->bucket = bucket; wait->due = ~(ULONGLONG)0;
    ++wait->references; /* bucket membership, separate from native wait snapshots */
    bucket->objects[bucket->count++] = wait;
    LeaveCriticalSection(&k64_tp_lock);
    return (PTP_WAIT)wait;
}
static BOOL k64_tp_type_is(const SHZ_UNICODE_STRING *name, const char *type)
{
    unsigned i;
    for(i=0;type[i];++i) if(i>=name->Length/2 || name->Buffer[i]!=(unsigned char)type[i])return FALSE;
    return i*2==name->Length;
}
K32API void WINAPI SetThreadpoolWait(PTP_WAIT opaque, HANDLE handle, PFILETIME timeout)
{
    k64_tp_work *wait = k64_tp_typed(opaque, 2);
    HANDLE owned = NULL, previous;
    if (!wait) return;
    if (handle) {
        union { ULONGLONG alignment; unsigned char bytes[256]; } info;
        SHZ_UNICODE_STRING *name = (SHZ_UNICODE_STRING *)info.bytes;
        NTSTATUS status = NtQueryObject(handle, 2, info.bytes, sizeof info.bytes, NULL);
        uintptr_t begin=(uintptr_t)info.bytes, end=begin+sizeof info.bytes, string;
        DWORD granted;
        if (status) { k32_nt_error(status); return; }
        string=(uintptr_t)name->Buffer;
        if((name->Length&1u) || string<begin || string>end || name->Length>end-string){SetLastError(ERROR_INVALID_PARAMETER);return;}
        if (k64_tp_type_is(name,"Mutant")) {
                ULONG_PTR parameter = (ULONG_PTR)(ULONG)STATUS_INVALID_PARAMETER_3;
                RaiseException((DWORD)STATUS_THREADPOOL_HANDLE_EXCEPTION, 0, 1, &parameter);
                return; /* preserve the previous registration if a handler resumes */
        }
        if(!k64_tp_type_is(name,"Event") && !k64_tp_type_is(name,"Semaphore") && !k64_tp_type_is(name,"Timer") && !k64_tp_type_is(name,"Thread") && !k64_tp_type_is(name,"Process")){
            SetLastError(ERROR_NOT_SUPPORTED);return; /* other native object waits remain outside this backend */
        }
        status=NtQueryObject(handle,0,info.bytes,sizeof info.bytes,NULL);
        if(status){k32_nt_error(status);return;}
        memcpy(&granted,info.bytes+4,sizeof granted);
        if(!(granted & 0x00100000u)){SetLastError(ERROR_ACCESS_DENIED);return;}
        if (!DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &owned, 0, FALSE, DUPLICATE_SAME_ACCESS)) return;
    }
    EnterCriticalSection(&k64_tp_lock);
    if (wait->closed) {
        LeaveCriticalSection(&k64_tp_lock); if (owned) CloseHandle(owned); SetLastError(ERROR_INVALID_HANDLE); return;
    }
    previous = wait->watched; wait->watched = owned; ++wait->generation;
    wait->armed = owned != NULL;
    wait->due = owned && timeout ? k64_tp_due(timeout, k64_tp_now()) : ~(ULONGLONG)0;
    SetEvent(wait->bucket->control);
    LeaveCriticalSection(&k64_tp_lock);
    if (previous) CloseHandle(previous);
}
K32API void WINAPI WaitForThreadpoolWaitCallbacks(PTP_WAIT wait, BOOL cancel)
{ if (k64_tp_typed(wait, 2)) k64_tp_wait_callbacks((PTP_WORK)wait, cancel); }
K32API void WINAPI CloseThreadpoolWait(PTP_WAIT opaque)
{
    k64_tp_work *wait = k64_tp_typed(opaque, 2);
    struct k64_tp_bucket *bucket;
    HANDLE watched;
    DWORD i;
    if (!wait) return;
    EnterCriticalSection(&k64_tp_lock);
    bucket = wait->bucket;
    if (!bucket) { LeaveCriticalSection(&k64_tp_lock); SetLastError(ERROR_INVALID_HANDLE); return; }
    for (i = 0; i < bucket->count; ++i) if (bucket->objects[i] == wait) { bucket->objects[i] = bucket->objects[--bucket->count]; break; }
    wait->bucket = NULL; wait->armed = FALSE; ++wait->generation;
    watched = wait->watched; wait->watched = NULL;
    --wait->references; /* membership */
    SetEvent(bucket->control);
    LeaveCriticalSection(&k64_tp_lock);
    if (watched) CloseHandle(watched);
    k64_tp_close((PTP_WORK)wait);
}
