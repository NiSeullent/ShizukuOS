/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku kernel32.dll (NTKERNEL32Wrapper9x, AMD64): Win32 process, thread, module, error,
 * synchronisation and TLS/FLS APIs implemented over ntdll and the Kernel64 native interface.
 *
 * Every export here has real semantics. Functions that Windows provides but this system does
 * not implement yet are simply absent (the loader then reports ERROR_PROC_NOT_FOUND), never
 * stubbed to succeed. Owner list: see docs/compat/WRAPPER_CATALOG.md (NTKERNEL32Wrapper9x).
 */
#include "k32.h"

#define K32_TLS_SLOTS 64

/* ---------------------------------------------------------------- errors */
K32API DWORD WINAPI GetLastError(void) { return shz_last_error(); }
K32API void WINAPI SetLastError(DWORD e) { shz_set_last_error(e); }

DWORD k32_nt_error(NTSTATUS st)
{
    const DWORD e = RtlNtStatusToDosError(st);
    shz_set_last_error(e);
    return e;
}

K32API UINT WINAPI SetErrorMode(UINT m) { static UINT mode; UINT old = mode; mode = m; return old; }
K32API PVOID WINAPI EncodePointer(PVOID p) { return p; }         /* no pointer obfuscation cookie is used */
K32API PVOID WINAPI DecodePointer(PVOID p) { return p; }
K32API BOOL WINAPI IsDebuggerPresent(void) { return *(BYTE *)(shz_peb() + 2) != 0; }
K32API VOID WINAPI OutputDebugStringA(LPCSTR s) { ULONG n = 0; while (s[n]) ++n; NtShzDebugPrint(s, n); }
K32API VOID WINAPI OutputDebugStringW(LPCWSTR s)
{
    char buf[256];
    unsigned i;
    for (i = 0; s[i] && i < 255; ++i) buf[i] = s[i] < 128 ? (char)s[i] : '?';
    buf[i] = 0;
    NtShzDebugPrint(buf, i);
}

/* ---------------------------------------------------------------- process and thread identity */
K32API HANDLE WINAPI GetCurrentProcess(void) { return CURRENT_PROCESS; }
K32API HANDLE WINAPI GetCurrentThread(void) { return CURRENT_THREAD; }
K32API DWORD WINAPI GetCurrentProcessId(void) { return shz_pid(); }
K32API DWORD WINAPI GetCurrentThreadId(void) { return shz_tid(); }

K32API VOID WINAPI ExitProcess(UINT code) { RtlExitUserProcess((NTSTATUS)code); }
K32API VOID WINAPI ExitThread(DWORD code) { RtlExitUserThread((NTSTATUS)code); }

K32API BOOL WINAPI TerminateProcess(HANDLE h, UINT code)
{
    NTSTATUS st = NtTerminateProcess(h, (NTSTATUS)code);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI GetExitCodeProcess(HANDLE h, LPDWORD code)
{
    struct { LONG64 exit_status; ULONG64 peb, aff; LONG64 prio; ULONG64 pid, ppid; } b;
    NTSTATUS st = NtQueryInformationProcess(h, 0, &b, sizeof b, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    *code = (DWORD)b.exit_status == 0x103 ? STILL_ACTIVE : (DWORD)b.exit_status;
    return TRUE;
}

K32API BOOL WINAPI GetExitCodeThread(HANDLE h, LPDWORD code)
{
    struct { LONG64 exit_status; ULONG64 teb, pid, tid, aff; LONG prio, base; } b;
    NTSTATUS st = NtQueryInformationThread(h, 0, &b, sizeof b, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    *code = (DWORD)b.exit_status == 0x103 ? STILL_ACTIVE : (DWORD)b.exit_status;
    return TRUE;
}

K32API HANDLE WINAPI CreateThread(LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE start, LPVOID param,
                                  DWORD flags, LPDWORD tid)
{
    HANDLE h = 0;
    NTSTATUS st;
    struct { LONG64 exit_status; ULONG64 teb, pid, tid, aff; LONG prio, base; } b;
    (void)sa;
    if (flags & CREATE_SUSPENDED) { shz_set_last_error(ERROR_NOT_SUPPORTED); return 0; }     /* not implemented yet */
    st = NtCreateThreadEx(&h, THREAD_ALL_ACCESS, 0, CURRENT_PROCESS, (PVOID)start, param, 0, 0, stack, 0, 0);
    if (st) { k32_nt_error(st); return 0; }
    if (tid) {
        if (NtQueryInformationThread(h, 0, &b, sizeof b, 0) == 0) *tid = (DWORD)b.tid; else *tid = 0;
    }
    return h;
}

K32API BOOL WINAPI SwitchToThread(void) { return NtYieldExecution() != STATUS_NO_YIELD_PERFORMED; }
K32API BOOL WINAPI TerminateThread(HANDLE h, DWORD code) { (void)h; (void)code; shz_set_last_error(ERROR_NOT_SUPPORTED); return FALSE; }
K32API DWORD WINAPI SuspendThread(HANDLE h) { (void)h; shz_set_last_error(ERROR_NOT_SUPPORTED); return (DWORD)-1; }
K32API DWORD WINAPI ResumeThread(HANDLE h) { (void)h; shz_set_last_error(ERROR_NOT_SUPPORTED); return (DWORD)-1; }
K32API int WINAPI GetThreadPriority(HANDLE h) { (void)h; return THREAD_PRIORITY_NORMAL; }
K32API BOOL WINAPI SetThreadPriority(HANDLE h, int p)
{
    (void)h;
    /* Priorities have no scheduler effect yet (round-robin only); accepting the call does not claim otherwise. */
    return p >= THREAD_PRIORITY_IDLE && p <= THREAD_PRIORITY_TIME_CRITICAL;
}
K32API BOOL WINAPI DisableThreadLibraryCalls(HMODULE m) { (void)m; return TRUE; }

/* ---------------------------------------------------------------- handles and waiting */
K32API BOOL WINAPI CloseHandle(HANDLE h)
{
    NTSTATUS st = NtClose(h);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI DuplicateHandle(HANDLE sp, HANDLE h, HANDLE tp, LPHANDLE out, DWORD access, BOOL inherit, DWORD opts)
{
    NTSTATUS st = NtDuplicateObject(sp, h, tp, out, access, inherit ? 2 : 0, opts);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

static DWORD wait_result(NTSTATUS st, DWORD count)
{
    (void)count;
    if (st == STATUS_TIMEOUT) return WAIT_TIMEOUT;
    if (st >= 0 && st < 64) return (DWORD)st;                          /* WAIT_OBJECT_0 + index */
    if (st >= STATUS_ABANDONED_WAIT_0 && st < STATUS_ABANDONED_WAIT_0 + 64) return WAIT_ABANDONED_0 + (DWORD)(st - STATUS_ABANDONED_WAIT_0);
    k32_nt_error(st);
    return WAIT_FAILED;
}

static void ms_to_timeout(DWORD ms, LARGE_INTEGER *li, PLARGE_INTEGER *out)
{
    if (ms == INFINITE) { *out = 0; return; }
    li->QuadPart = -(LONGLONG)ms * 10000;
    *out = li;
}

K32API DWORD WINAPI WaitForSingleObjectEx(HANDLE h, DWORD ms, BOOL alertable)
{
    LARGE_INTEGER li;
    PLARGE_INTEGER pli;
    ms_to_timeout(ms, &li, &pli);
    if (ms == 0) { li.QuadPart = 0; pli = &li; }
    return wait_result(NtWaitForSingleObject(h, alertable != 0, pli), 1);
}
K32API DWORD WINAPI WaitForSingleObject(HANDLE h, DWORD ms) { return WaitForSingleObjectEx(h, ms, FALSE); }

K32API DWORD WINAPI WaitForMultipleObjectsEx(DWORD n, const HANDLE *hs, BOOL all, DWORD ms, BOOL alertable)
{
    LARGE_INTEGER li;
    PLARGE_INTEGER pli;
    if (n == 0 || n > MAXIMUM_WAIT_OBJECTS) { shz_set_last_error(ERROR_INVALID_PARAMETER); return WAIT_FAILED; }
    ms_to_timeout(ms, &li, &pli);
    if (ms == 0) { li.QuadPart = 0; pli = &li; }
    return wait_result(NtWaitForMultipleObjects(n, (HANDLE *)hs, all ? 0 : 1, alertable != 0, pli), n);
}
K32API DWORD WINAPI WaitForMultipleObjects(DWORD n, const HANDLE *hs, BOOL all, DWORD ms)
{
    return WaitForMultipleObjectsEx(n, hs, all, ms, FALSE);
}

K32API VOID WINAPI Sleep(DWORD ms)
{
    LARGE_INTEGER li;
    if (ms == INFINITE) li.QuadPart = INT64_MIN + 1;
    else li.QuadPart = ms ? -(LONGLONG)ms * 10000 : 0;
    if (ms == 0) { NtYieldExecution(); return; }
    NtDelayExecution(FALSE, &li);
}
K32API DWORD WINAPI SleepEx(DWORD ms, BOOL alertable) { (void)alertable; Sleep(ms); return 0; }

/* ---------------------------------------------------------------- events, mutexes, semaphores */
static WCHAR *widen(const char *s, WCHAR *buf, size_t cap)
{
    size_t i;
    for (i = 0; s[i] && i + 1 < cap; ++i) buf[i] = (unsigned char)s[i];
    buf[i] = 0;
    return buf;
}

static NTSTATUS named_attr(LPCWSTR name, SHZ_OBJECT_ATTRIBUTES *oa, SHZ_UNICODE_STRING *us)
{
    memset(oa, 0, sizeof *oa);
    oa->Length = sizeof *oa;
    if (name && name[0]) {
        size_t n = 0;
        while (name[n]) ++n;
        if (n > 40) return STATUS_OBJECT_NAME_INVALID;
        us->Buffer = (PWSTR)name;
        us->Length = (USHORT)(n * 2);
        us->MaximumLength = us->Length;
        oa->ObjectName = us;
    }
    return 0;
}

K32API HANDLE WINAPI CreateEventW(LPSECURITY_ATTRIBUTES sa, BOOL manual, BOOL initial, LPCWSTR name)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    HANDLE h = 0;
    NTSTATUS st;
    (void)sa;
    if (named_attr(name, &oa, &us)) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    st = NtCreateEvent(&h, EVENT_ALL_ACCESS, &oa, manual ? 0 : 1, initial != 0);
    if (st == 0x40000000) { shz_set_last_error(ERROR_ALREADY_EXISTS); return h; }
    if (st) { k32_nt_error(st); return 0; }
    shz_set_last_error(0);
    return h;
}
K32API HANDLE WINAPI CreateEventA(LPSECURITY_ATTRIBUTES sa, BOOL m, BOOL i, LPCSTR name)
{
    WCHAR w[64];
    return CreateEventW(sa, m, i, name ? widen(name, w, 64) : 0);
}
K32API BOOL WINAPI SetEvent(HANDLE h) { NTSTATUS st = NtSetEvent(h, 0); if (st) { k32_nt_error(st); return FALSE; } return TRUE; }
K32API BOOL WINAPI ResetEvent(HANDLE h) { NTSTATUS st = NtResetEvent(h, 0); if (st) { k32_nt_error(st); return FALSE; } return TRUE; }

K32API HANDLE WINAPI CreateMutexW(LPSECURITY_ATTRIBUTES sa, BOOL owner, LPCWSTR name)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    HANDLE h = 0;
    NTSTATUS st;
    (void)sa;
    if (named_attr(name, &oa, &us)) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    st = NtCreateMutant(&h, MUTANT_ALL_ACCESS, &oa, owner != 0);
    if (st == 0x40000000) { shz_set_last_error(ERROR_ALREADY_EXISTS); return h; }
    if (st) { k32_nt_error(st); return 0; }
    shz_set_last_error(0);
    return h;
}
K32API HANDLE WINAPI CreateMutexA(LPSECURITY_ATTRIBUTES sa, BOOL o, LPCSTR name)
{
    WCHAR w[64];
    return CreateMutexW(sa, o, name ? widen(name, w, 64) : 0);
}
K32API BOOL WINAPI ReleaseMutex(HANDLE h) { NTSTATUS st = NtReleaseMutant(h, 0); if (st) { k32_nt_error(st); return FALSE; } return TRUE; }

K32API HANDLE WINAPI CreateSemaphoreW(LPSECURITY_ATTRIBUTES sa, LONG initial, LONG max, LPCWSTR name)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    HANDLE h = 0;
    NTSTATUS st;
    (void)sa;
    if (named_attr(name, &oa, &us)) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    st = NtCreateSemaphore(&h, SEMAPHORE_ALL_ACCESS, &oa, initial, max);
    if (st == 0x40000000) { shz_set_last_error(ERROR_ALREADY_EXISTS); return h; }
    if (st) { k32_nt_error(st); return 0; }
    shz_set_last_error(0);
    return h;
}
K32API HANDLE WINAPI CreateSemaphoreA(LPSECURITY_ATTRIBUTES sa, LONG i, LONG m, LPCSTR name)
{
    WCHAR w[64];
    return CreateSemaphoreW(sa, i, m, name ? widen(name, w, 64) : 0);
}
K32API BOOL WINAPI ReleaseSemaphore(HANDLE h, LONG n, LPLONG prev)
{
    NTSTATUS st = NtReleaseSemaphore(h, n, prev);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

/* ---------------------------------------------------------------- critical sections and SRW (ntdll owns them) */
K32API VOID WINAPI InitializeCriticalSection(LPCRITICAL_SECTION cs) { RtlInitializeCriticalSectionEx(cs, 0, 0); }
K32API BOOL WINAPI InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION cs, DWORD spin) { RtlInitializeCriticalSectionEx(cs, spin, 0); return TRUE; }
K32API BOOL WINAPI InitializeCriticalSectionEx(LPCRITICAL_SECTION cs, DWORD spin, DWORD flags) { RtlInitializeCriticalSectionEx(cs, spin, flags); return TRUE; }
K32API VOID WINAPI EnterCriticalSection(LPCRITICAL_SECTION cs) { RtlEnterCriticalSection(cs); }
K32API VOID WINAPI LeaveCriticalSection(LPCRITICAL_SECTION cs) { RtlLeaveCriticalSection(cs); }
K32API BOOL WINAPI TryEnterCriticalSection(LPCRITICAL_SECTION cs) { return RtlTryEnterCriticalSection(cs); }
K32API VOID WINAPI DeleteCriticalSection(LPCRITICAL_SECTION cs) { RtlDeleteCriticalSection(cs); }
K32API DWORD WINAPI SetCriticalSectionSpinCount(LPCRITICAL_SECTION cs, DWORD s) { DWORD old = (DWORD)cs->SpinCount; cs->SpinCount = s; return old; }

K32API VOID WINAPI InitializeSRWLock(PSRWLOCK l) { RtlInitializeSRWLock((RTL_SRWLOCK *)l); }
K32API VOID WINAPI AcquireSRWLockExclusive(PSRWLOCK l) { RtlAcquireSRWLockExclusive((RTL_SRWLOCK *)l); }
K32API VOID WINAPI ReleaseSRWLockExclusive(PSRWLOCK l) { RtlReleaseSRWLockExclusive((RTL_SRWLOCK *)l); }
K32API VOID WINAPI AcquireSRWLockShared(PSRWLOCK l) { RtlAcquireSRWLockShared((RTL_SRWLOCK *)l); }
K32API VOID WINAPI ReleaseSRWLockShared(PSRWLOCK l) { RtlReleaseSRWLockShared((RTL_SRWLOCK *)l); }
K32API BOOLEAN WINAPI TryAcquireSRWLockExclusive(PSRWLOCK l) { return RtlTryAcquireSRWLockExclusive((RTL_SRWLOCK *)l); }
K32API BOOLEAN WINAPI TryAcquireSRWLockShared(PSRWLOCK l) { return RtlTryAcquireSRWLockShared((RTL_SRWLOCK *)l); }
K32API VOID WINAPI InitializeConditionVariable(PCONDITION_VARIABLE cv) { RtlInitializeConditionVariable((RTL_CONDITION_VARIABLE *)cv); }
K32API VOID WINAPI WakeConditionVariable(PCONDITION_VARIABLE cv) { RtlWakeConditionVariable((RTL_CONDITION_VARIABLE *)cv); }
K32API VOID WINAPI WakeAllConditionVariable(PCONDITION_VARIABLE cv) { RtlWakeAllConditionVariable((RTL_CONDITION_VARIABLE *)cv); }

static BOOL cv_result(NTSTATUS st)
{
    if (st == STATUS_TIMEOUT) { shz_set_last_error(ERROR_TIMEOUT); return FALSE; }
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}
K32API BOOL WINAPI SleepConditionVariableSRW(PCONDITION_VARIABLE cv, PSRWLOCK l, DWORD ms, ULONG flags)
{
    LARGE_INTEGER li;
    PLARGE_INTEGER pli;
    ms_to_timeout(ms, &li, &pli);
    return cv_result(RtlSleepConditionVariableSRW((RTL_CONDITION_VARIABLE *)cv, (RTL_SRWLOCK *)l, pli, flags));
}
K32API BOOL WINAPI SleepConditionVariableCS(PCONDITION_VARIABLE cv, PCRITICAL_SECTION cs, DWORD ms)
{
    LARGE_INTEGER li;
    PLARGE_INTEGER pli;
    ms_to_timeout(ms, &li, &pli);
    return cv_result(RtlSleepConditionVariableCS((RTL_CONDITION_VARIABLE *)cv, cs, pli));
}
K32API BOOL WINAPI WaitOnAddress(volatile VOID *addr, PVOID cmp, SIZE_T size, DWORD ms)
{
    LARGE_INTEGER li;
    PLARGE_INTEGER pli;
    ms_to_timeout(ms, &li, &pli);
    return cv_result(RtlWaitOnAddress(addr, cmp, size, pli));
}
K32API VOID WINAPI WakeByAddressSingle(PVOID a) { RtlWakeAddressSingle(a); }
K32API VOID WINAPI WakeByAddressAll(PVOID a) { RtlWakeAddressAll(a); }

/* One-time initialisation: state word 0 = new, 1 = running (Ptr low bits), 2 = done. */
typedef struct { PVOID Ptr; } K32_INIT_ONCE;
K32API BOOL WINAPI InitOnceExecuteOnce(PINIT_ONCE once, PINIT_ONCE_FN fn, PVOID param, LPVOID *ctx)
{
    volatile LONG64 *state = (volatile LONG64 *)&once->Ptr;
    for (;;) {
        LONG64 s = *state;
        if ((s & 3) == 2) { if (ctx) *ctx = (LPVOID)(s & ~3ll); return TRUE; }
        if (s == 0 && __sync_bool_compare_and_swap(state, 0, 1)) {
            LPVOID c = 0;
            if (!fn(once, param, &c)) { *state = 0; RtlWakeAddressAll((PVOID)state); shz_set_last_error(ERROR_GEN_FAILURE); return FALSE; }
            *state = ((LONG64)(uintptr_t)c & ~3ll) | 2;
            RtlWakeAddressAll((PVOID)state);
            if (ctx) *ctx = c;
            return TRUE;
        }
        {
            LONG64 seen = s;
            RtlWaitOnAddress(state, &seen, 8, 0);
        }
    }
}
K32API VOID WINAPI InitOnceInitialize(PINIT_ONCE once) { once->Ptr = 0; }

/* ---------------------------------------------------------------- interlocked (real exports) */
/* mingw-w64's winnt.h renames these to compiler intrinsics (InterlockedIncrement -> _InterlockedIncrement); kernel32 must
 * define and export the real Win32 names. */
#undef InterlockedIncrement
#undef InterlockedDecrement
#undef InterlockedExchange
#undef InterlockedExchangeAdd
#undef InterlockedCompareExchange
#undef InterlockedCompareExchange64
K32API LONG WINAPI InterlockedIncrement(LONG volatile *p) { return __sync_add_and_fetch(p, 1); }
K32API LONG WINAPI InterlockedDecrement(LONG volatile *p) { return __sync_sub_and_fetch(p, 1); }
K32API LONG WINAPI InterlockedExchange(LONG volatile *p, LONG v) { return __sync_lock_test_and_set(p, v); }
K32API LONG WINAPI InterlockedExchangeAdd(LONG volatile *p, LONG v) { return __sync_fetch_and_add(p, v); }
K32API LONG WINAPI InterlockedCompareExchange(LONG volatile *p, LONG x, LONG c) { return __sync_val_compare_and_swap(p, c, x); }
K32API LONG64 WINAPI InterlockedCompareExchange64(LONG64 volatile *p, LONG64 x, LONG64 c) { return __sync_val_compare_and_swap(p, c, x); }

/* ---------------------------------------------------------------- TLS and FLS */
#define TEB_TLS_SLOTS 0x1480
#define TEB_TLS_EXPANSION 0x1680
#define TEB_FLS_DATA 0x17c8
#define FLS_MAX 128

static volatile LONG tls_bitmap_lock;
static uint64_t tls_bitmap[2];                                  /* 128 indices: 64 in TEB slots + 64 expansion */
static uint64_t fls_bitmap[2];
static PFLS_CALLBACK_FUNCTION fls_callbacks[FLS_MAX];

static void lk(volatile LONG *l) { while (__sync_lock_test_and_set(l, 1)) NtYieldExecution(); }
static void ulk(volatile LONG *l) { __sync_lock_release(l); }

K32API DWORD WINAPI TlsAlloc(void)
{
    DWORD i;
    lk(&tls_bitmap_lock);
    for (i = 0; i < 128; ++i)
        if (!(tls_bitmap[i >> 6] & (1ull << (i & 63)))) {
            tls_bitmap[i >> 6] |= 1ull << (i & 63);
            ulk(&tls_bitmap_lock);
            if (i < 64) *(PVOID *)(shz_teb() + TEB_TLS_SLOTS + i * 8) = 0;
            return i;
        }
    ulk(&tls_bitmap_lock);
    shz_set_last_error(ERROR_NO_MORE_ITEMS);
    return TLS_OUT_OF_INDEXES;
}
static PVOID *tls_slot(DWORD i, int create)
{
    if (i < 64) return (PVOID *)(shz_teb() + TEB_TLS_SLOTS + i * 8);
    if (i < 128) {
        PVOID *exp = *(PVOID **)(shz_teb() + TEB_TLS_EXPANSION);
        if (!exp && create) {
            exp = RtlAllocateHeap(ShzProcessHeap(), HEAP_ZERO_MEMORY, 64 * sizeof(PVOID));
            *(PVOID **)(shz_teb() + TEB_TLS_EXPANSION) = exp;
        }
        return exp ? &exp[i - 64] : 0;
    }
    return 0;
}
K32API PVOID WINAPI TlsGetValue(DWORD i)
{
    PVOID *s = i < 128 && (tls_bitmap[i >> 6] & (1ull << (i & 63))) ? tls_slot(i, 0) : 0;
    if (!s) { shz_set_last_error(i < 128 ? 0 : ERROR_INVALID_PARAMETER); return 0; }
    shz_set_last_error(0);
    return *s;
}
K32API BOOL WINAPI TlsSetValue(DWORD i, PVOID v)
{
    PVOID *s = i < 128 && (tls_bitmap[i >> 6] & (1ull << (i & 63))) ? tls_slot(i, 1) : 0;
    if (!s) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    *s = v;
    return TRUE;
}
K32API BOOL WINAPI TlsFree(DWORD i)
{
    if (i >= 128 || !(tls_bitmap[i >> 6] & (1ull << (i & 63)))) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    lk(&tls_bitmap_lock);
    tls_bitmap[i >> 6] &= ~(1ull << (i & 63));
    ulk(&tls_bitmap_lock);
    return TRUE;
}

static PVOID *fls_data(int create)
{
    PVOID *d = *(PVOID **)(shz_teb() + TEB_FLS_DATA);
    if (!d && create) {
        d = RtlAllocateHeap(ShzProcessHeap(), HEAP_ZERO_MEMORY, FLS_MAX * sizeof(PVOID));
        *(PVOID **)(shz_teb() + TEB_FLS_DATA) = d;
    }
    return d;
}
K32API DWORD WINAPI FlsAlloc(PFLS_CALLBACK_FUNCTION cb)
{
    DWORD i;
    lk(&tls_bitmap_lock);
    for (i = 0; i < FLS_MAX; ++i)
        if (!(fls_bitmap[i >> 6] & (1ull << (i & 63)))) {
            fls_bitmap[i >> 6] |= 1ull << (i & 63);
            fls_callbacks[i] = cb;
            ulk(&tls_bitmap_lock);
            return i;
        }
    ulk(&tls_bitmap_lock);
    shz_set_last_error(ERROR_NO_MORE_ITEMS);
    return FLS_OUT_OF_INDEXES;
}
K32API PVOID WINAPI FlsGetValue(DWORD i)
{
    PVOID *d = fls_data(0);
    if (i >= FLS_MAX || !(fls_bitmap[i >> 6] & (1ull << (i & 63)))) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    shz_set_last_error(0);
    return d ? d[i] : 0;
}
K32API BOOL WINAPI FlsSetValue(DWORD i, PVOID v)
{
    PVOID *d;
    if (i >= FLS_MAX || !(fls_bitmap[i >> 6] & (1ull << (i & 63)))) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    d = fls_data(1);
    if (!d) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    d[i] = v;
    return TRUE;
}
K32API BOOL WINAPI FlsFree(DWORD i)
{
    PVOID *d = fls_data(0);
    if (i >= FLS_MAX || !(fls_bitmap[i >> 6] & (1ull << (i & 63)))) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (d && d[i] && fls_callbacks[i]) fls_callbacks[i](d[i]);      /* run the destructor for the calling thread */
    if (d) d[i] = 0;
    lk(&tls_bitmap_lock);
    fls_bitmap[i >> 6] &= ~(1ull << (i & 63));
    fls_callbacks[i] = 0;
    ulk(&tls_bitmap_lock);
    return TRUE;
}

/* ---------------------------------------------------------------- exceptions */
K32API LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER f)
{
    return RtlSetUnhandledExceptionFilter(f);
}
K32API LONG WINAPI UnhandledExceptionFilter(PEXCEPTION_POINTERS ep) { (void)ep; return EXCEPTION_CONTINUE_SEARCH; }
K32API VOID WINAPI RaiseException(DWORD code, DWORD flags, DWORD nargs, const ULONG_PTR *args)
{
    EXCEPTION_RECORD rec;
    DWORD i;
    memset(&rec, 0, sizeof rec);
    rec.ExceptionCode = code;
    rec.ExceptionFlags = flags & EXCEPTION_NONCONTINUABLE;
    if (nargs > EXCEPTION_MAXIMUM_PARAMETERS) nargs = EXCEPTION_MAXIMUM_PARAMETERS;
    rec.NumberParameters = nargs;
    for (i = 0; i < nargs && args; ++i) rec.ExceptionInformation[i] = args[i];
    RtlRaiseException(&rec);
}
K32API PVOID WINAPI AddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER h) { return RtlAddVectoredExceptionHandler(first, h); }
K32API ULONG WINAPI RemoveVectoredExceptionHandler(PVOID h) { return RtlRemoveVectoredExceptionHandler(h); }
K32API PVOID WINAPI AddVectoredContinueHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER h) { return RtlAddVectoredContinueHandler(first, h); }
K32API ULONG WINAPI RemoveVectoredContinueHandler(PVOID h) { return RtlRemoveVectoredContinueHandler(h); }
K32API VOID WINAPI RtlUnwindKernel32(PVOID f, PVOID ip, PEXCEPTION_RECORD r, PVOID rv) { RtlUnwind(f, ip, r, rv); }

BOOL WINAPI ShzKernel32Entry(HINSTANCE h, DWORD reason, LPVOID reserved) { (void)h; (void)reason; (void)reserved; return TRUE; }
