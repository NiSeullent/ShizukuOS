/* SPDX-License-Identifier: GPL-2.0-only
 * msvcp140.dll for the Shizuku Win64 runtime: the parts of Microsoft's C++ standard library DLL that the STL headers
 * call out of line and that thread/timing code needs -- the std::_X* throw helpers (std::length_error, out_of_range, ...
 * with MSVC's class layout and RTTI, so compiled code catches them by type), the C11-style mutex / condition variable /
 * thread layer (_Mtx_*, _Cnd_*, _Thrd_*) over SRW locks and condition variables, and the tick/performance-counter
 * helpers. None of the measured application trees imports msvcp140.dll (see CRT.md), so this is deliberately small;
 * iostreams, locales and filesystem are not provided. Own implementation.
 * The C++-named exports are listed in module.json as aliases of the msvcp_* functions here.
 */
#include "../vcruntime140/vcrint.h"
#include "../vcruntime140/cxxclass.h"

__declspec(dllimport) void __std_exception_copy(const vcr_exc_data *from, vcr_exc_data *to);
__declspec(dllimport) void __std_exception_destroy(vcr_exc_data *d);
__declspec(dllimport) uintptr_t _beginthreadex(void *security, unsigned stack, unsigned (__stdcall *fn)(void *), void *arg,
                                               unsigned flags, unsigned *id);
static void vcr_exc_copy_data(const vcr_exc_data *from, vcr_exc_data *to) { __std_exception_copy(from, to); }
static void vcr_exc_free_data(vcr_exc_data *d) { __std_exception_destroy(d); }

/* ------------------------------------------------------------------ exceptions */
static cxx_class g_exception, g_logic_error, g_length_error, g_out_of_range, g_invalid_argument, g_runtime_error,
    g_overflow_error, g_bad_alloc, g_bad_function_call;
CXX_COPY_CTOR(exception)
CXX_COPY_CTOR(logic_error)
CXX_COPY_CTOR(length_error)
CXX_COPY_CTOR(out_of_range)
CXX_COPY_CTOR(invalid_argument)
CXX_COPY_CTOR(runtime_error)
CXX_COPY_CTOR(overflow_error)
CXX_COPY_CTOR(bad_alloc)
CXX_COPY_CTOR(bad_function_call)

static void classes_init(void)
{
    cxx_class_init(&g_exception, ".?AVexception@std@@", 0, cxx_copy_exception);
    cxx_class_init(&g_logic_error, ".?AVlogic_error@std@@", &g_exception, cxx_copy_logic_error);
    cxx_class_init(&g_length_error, ".?AVlength_error@std@@", &g_logic_error, cxx_copy_length_error);
    cxx_class_init(&g_out_of_range, ".?AVout_of_range@std@@", &g_logic_error, cxx_copy_out_of_range);
    cxx_class_init(&g_invalid_argument, ".?AVinvalid_argument@std@@", &g_logic_error, cxx_copy_invalid_argument);
    cxx_class_init(&g_runtime_error, ".?AVruntime_error@std@@", &g_exception, cxx_copy_runtime_error);
    cxx_class_init(&g_overflow_error, ".?AVoverflow_error@std@@", &g_runtime_error, cxx_copy_overflow_error);
    cxx_class_init(&g_bad_alloc, ".?AVbad_alloc@std@@", &g_exception, cxx_copy_bad_alloc);
    cxx_class_init(&g_bad_function_call, ".?AVbad_function_call@std@@", &g_exception, cxx_copy_bad_function_call);
}

VCR_NORETURN void msvcp_Xlength_error(const char *msg) { cxx_throw(&g_length_error, msg); }
VCR_NORETURN void msvcp_Xout_of_range(const char *msg) { cxx_throw(&g_out_of_range, msg); }
VCR_NORETURN void msvcp_Xinvalid_argument(const char *msg) { cxx_throw(&g_invalid_argument, msg); }
VCR_NORETURN void msvcp_Xruntime_error(const char *msg) { cxx_throw(&g_runtime_error, msg); }
VCR_NORETURN void msvcp_Xoverflow_error(const char *msg) { cxx_throw(&g_overflow_error, msg); }
VCR_NORETURN void msvcp_Xbad_alloc(void)
{
    vcr_exc e;                                       /* bad_alloc keeps a static message, as MSVC's does */
    e.vfptr = &g_bad_alloc.vtbl[1];
    e.data.what = "bad allocation";
    e.data.do_free = 0;
    _CxxThrowException(&e, &g_bad_alloc.ti);
}
VCR_NORETURN void msvcp_Xbad_function_call(void)
{
    vcr_exc e;
    e.vfptr = &g_bad_function_call.vtbl[1];
    e.data.what = "bad function call";
    e.data.do_free = 0;
    _CxxThrowException(&e, &g_bad_function_call.ti);
}

/* ------------------------------------------------------------------ mutexes (layout of MSVC's _Mtx_internal_imp_t) */
enum { THRD_SUCCESS = 0, THRD_NOMEM = 1, THRD_TIMEDOUT = 2, THRD_BUSY = 3, THRD_ERROR = 4 };
enum { MTX_PLAIN = 0x01, MTX_TRY = 0x02, MTX_TIMED = 0x04, MTX_RECURSIVE = 0x100 };
typedef struct {
    int type;
    int pad;
    void *unused;                                    /* _Stl_critical_section: former vtable slot */
    SRWLOCK srw;
    long thread_id;
    int count;
} msvcp_mtx;
typedef struct { void *unused; CONDITION_VARIABLE cv; } msvcp_cnd;
typedef struct { int64_t sec; long nsec; } msvcp_timespec64;
typedef struct { void *handle; unsigned id; } msvcp_thrd;

DLLAPI void _Mtx_init_in_situ(msvcp_mtx *m, int flags)
{
    m->type = flags;
    m->unused = 0;
    InitializeSRWLock(&m->srw);
    m->thread_id = -1;
    m->count = 0;
}
DLLAPI void _Mtx_destroy_in_situ(msvcp_mtx *m) { (void)m; }
DLLAPI int _Mtx_init(msvcp_mtx **pm, int flags)
{
    msvcp_mtx *m = malloc(sizeof *m);
    *pm = m;
    if (!m) return THRD_NOMEM;
    _Mtx_init_in_situ(m, flags);
    return THRD_SUCCESS;
}
DLLAPI void _Mtx_destroy(msvcp_mtx *m) { free(m); }

static int64_t now_ticks(void);
static int mtx_do_lock(msvcp_mtx *m, const msvcp_timespec64 *deadline)
{
    const long me = (long)GetCurrentThreadId();
    if ((m->type & ~MTX_RECURSIVE) == MTX_PLAIN) {
        if (m->thread_id != me) {
            AcquireSRWLockExclusive(&m->srw);
            m->thread_id = me;
        }
        ++m->count;
        return THRD_SUCCESS;
    }
    if (m->thread_id == me) {                        /* already owned: recursive mutexes nest, others are busy */
        if (!(m->type & MTX_RECURSIVE)) return THRD_BUSY;
        ++m->count;
        return THRD_SUCCESS;
    }
    if (!deadline) {
        AcquireSRWLockExclusive(&m->srw);
    } else {
        const int64_t until = deadline->sec * 10000000ll + deadline->nsec / 100;
        while (!TryAcquireSRWLockExclusive(&m->srw)) {
            if (now_ticks() >= until) return THRD_TIMEDOUT;
            Sleep(1);
        }
    }
    m->thread_id = me;
    m->count = 1;
    return THRD_SUCCESS;
}
DLLAPI int _Mtx_lock(msvcp_mtx *m) { return mtx_do_lock(m, 0); }
DLLAPI int _Mtx_timedlock(msvcp_mtx *m, const msvcp_timespec64 *deadline) { return mtx_do_lock(m, deadline); }
DLLAPI int _Mtx_trylock(msvcp_mtx *m)
{
    const long me = (long)GetCurrentThreadId();
    if (m->thread_id == me) {
        if (!(m->type & MTX_RECURSIVE)) return THRD_BUSY;
        ++m->count;
        return THRD_SUCCESS;
    }
    if (!TryAcquireSRWLockExclusive(&m->srw)) return THRD_BUSY;
    m->thread_id = me;
    m->count = 1;
    return THRD_SUCCESS;
}
DLLAPI int _Mtx_unlock(msvcp_mtx *m)
{
    if (--m->count == 0) {
        m->thread_id = -1;
        ReleaseSRWLockExclusive(&m->srw);
    }
    return THRD_SUCCESS;
}
DLLAPI BOOL _Mtx_current_owns(msvcp_mtx *m) { return m->count != 0 && m->thread_id == (long)GetCurrentThreadId(); }
DLLAPI void *_Mtx_getconcrtcs(msvcp_mtx *m) { return &m->unused; }
DLLAPI void _Mtx_clear_owner(msvcp_mtx *m) { m->thread_id = -1; --m->count; }
DLLAPI void _Mtx_reset_owner(msvcp_mtx *m) { m->thread_id = (long)GetCurrentThreadId(); ++m->count; }

/* ------------------------------------------------------------------ condition variables */
DLLAPI void _Cnd_init_in_situ(msvcp_cnd *c) { c->unused = 0; InitializeConditionVariable(&c->cv); }
DLLAPI void _Cnd_destroy_in_situ(msvcp_cnd *c) { (void)c; }
DLLAPI int _Cnd_init(msvcp_cnd **pc)
{
    msvcp_cnd *c = malloc(sizeof *c);
    *pc = c;
    if (!c) return THRD_NOMEM;
    _Cnd_init_in_situ(c);
    return THRD_SUCCESS;
}
DLLAPI void _Cnd_destroy(msvcp_cnd *c) { free(c); }
DLLAPI int _Cnd_wait(msvcp_cnd *c, msvcp_mtx *m)
{
    _Mtx_clear_owner(m);
    SleepConditionVariableSRW(&c->cv, &m->srw, INFINITE, 0);
    _Mtx_reset_owner(m);
    return THRD_SUCCESS;
}
DLLAPI int _Cnd_timedwait(msvcp_cnd *c, msvcp_mtx *m, const msvcp_timespec64 *deadline)
{
    const int64_t until = deadline->sec * 10000000ll + deadline->nsec / 100, left = until - now_ticks();
    DWORD ms = left <= 0 ? 0 : (DWORD)((left + 9999) / 10000);
    int r = THRD_SUCCESS;
    _Mtx_clear_owner(m);
    if (!SleepConditionVariableSRW(&c->cv, &m->srw, ms, 0)) r = GetLastError() == ERROR_TIMEOUT ? THRD_TIMEDOUT : THRD_ERROR;
    _Mtx_reset_owner(m);
    return r;
}
DLLAPI int _Cnd_signal(msvcp_cnd *c) { WakeConditionVariable(&c->cv); return THRD_SUCCESS; }
DLLAPI int _Cnd_broadcast(msvcp_cnd *c) { WakeAllConditionVariable(&c->cv); return THRD_SUCCESS; }

/* ------------------------------------------------------------------ time */
#define EPOCH_1601_TO_1970 116444736000000000ll
static int64_t now_ticks(void)                       /* 100 ns units since 1970-01-01 UTC */
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return (int64_t)(((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime) - EPOCH_1601_TO_1970;
}
DLLAPI int64_t _Xtime_get_ticks(void) { return now_ticks(); }
DLLAPI int64_t _Query_perf_counter(void)
{
    LARGE_INTEGER v;
    QueryPerformanceCounter(&v);
    return v.QuadPart;
}
DLLAPI int64_t _Query_perf_frequency(void)
{
    LARGE_INTEGER v;
    QueryPerformanceFrequency(&v);
    return v.QuadPart;
}

/* ------------------------------------------------------------------ threads */
DLLAPI unsigned _Thrd_id(void) { return GetCurrentThreadId(); }
DLLAPI msvcp_thrd _Thrd_current(void)
{
    msvcp_thrd t;
    t.handle = GetCurrentThread();
    t.id = GetCurrentThreadId();
    return t;
}
DLLAPI void _Thrd_yield(void) { SwitchToThread(); }
DLLAPI unsigned _Thrd_hardware_concurrency(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors;
}
DLLAPI void _Thrd_sleep_for(unsigned long ms) { Sleep(ms); }
DLLAPI void _Thrd_sleep(const msvcp_timespec64 *deadline)
{
    const int64_t until = deadline->sec * 10000000ll + deadline->nsec / 100;
    for (;;) {
        const int64_t left = until - now_ticks();
        if (left <= 0) return;
        Sleep((DWORD)((left + 9999) / 10000));
    }
}
DLLAPI int _Thrd_start(msvcp_thrd *t, unsigned (__stdcall *fn)(void *), void *arg)
{
    t->handle = (void *)_beginthreadex(0, 0, fn, arg, 0, &t->id);
    return t->handle ? THRD_SUCCESS : THRD_ERROR;
}
DLLAPI int _Thrd_join(msvcp_thrd t, int *result)
{
    DWORD code = 0;
    if (WaitForSingleObject(t.handle, INFINITE) != WAIT_OBJECT_0 || !GetExitCodeThread(t.handle, &code)) return THRD_ERROR;
    if (result) *result = (int)code;
    CloseHandle(t.handle);
    return THRD_SUCCESS;
}
DLLAPI int _Thrd_detach(msvcp_thrd t) { return CloseHandle(t.handle) ? THRD_SUCCESS : THRD_ERROR; }

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) classes_init();
    return TRUE;
}
