/* SPDX-License-Identifier: GPL-2.0-only
 * ucrtbase.dll: DLL entry, per-thread data (errno, _doserrno, strtok contexts, per-thread signal handlers), global
 * locks, the invalid-parameter machinery, Win32-error -> errno mapping and the heap (malloc family over the process
 * heap, as the Universal CRT does since it stopped keeping a private heap).
 */
#include "crtint.h"
#include "crtos.h"

static os_dword g_tls = 0xffffffffu;
static crt_ptd g_emergency_ptd;                   /* used only when the per-thread block cannot be allocated */
static os_srwlock g_locks[CRT_LOCK_COUNT];
static crt_inv_handler g_inv_handler;
os_handle crt_heap;
void crt_stdio_init(void);
void crt_stdio_terminate(void);
void crt_time_init(void);
void crt_env_free(void);
void crt_process_detach(int terminating);

void crt_lock(int which) { AcquireSRWLockExclusive(&g_locks[which]); }
void crt_unlock(int which) { ReleaseSRWLockExclusive(&g_locks[which]); }

/* ---------------------------------------------------------------- per-thread data */
crt_ptd *crt_getptd(void)
{
    const os_dword saved = GetLastError();          /* TlsGetValue and friends must not disturb GetLastError */
    crt_ptd *p = g_tls != 0xffffffffu ? TlsGetValue(g_tls) : 0;
    if (!p) {
        p = HeapAlloc(GetProcessHeap(), OS_HEAP_ZERO_MEMORY, sizeof *p);
        if (!p || g_tls == 0xffffffffu || !TlsSetValue(g_tls, p)) {
            if (p) HeapFree(GetProcessHeap(), 0, p);
            p = &g_emergency_ptd;
        } else p->rand_next = 1;
    }
    SetLastError(saved);
    return p;
}

static void free_ptd(void)
{
    crt_ptd *p;
    if (g_tls == 0xffffffffu) return;
    p = TlsGetValue(g_tls);
    if (p && p != &g_emergency_ptd) {
        TlsSetValue(g_tls, 0);
        HeapFree(GetProcessHeap(), 0, p);
    }
}

int *crt_errno_ptr(void) { return &crt_getptd()->err; }
unsigned long *crt_doserrno_ptr(void) { return &crt_getptd()->doserr; }
DLLAPI int *CRTAPI _errno(void) { return crt_errno_ptr(); }
DLLAPI unsigned long *CRTAPI __doserrno(void) { return crt_doserrno_ptr(); }
DLLAPI crt_errno_t CRTAPI _get_errno(int *v)
{
    CRT_VALIDATE(v != 0, CRT_EINVAL, CRT_EINVAL);
    *v = crt_get_errno();
    return 0;
}
DLLAPI crt_errno_t CRTAPI _set_errno(int v) { crt_set_errno(v); return 0; }
DLLAPI crt_errno_t CRTAPI _get_doserrno(unsigned long *v)
{
    CRT_VALIDATE(v != 0, CRT_EINVAL, CRT_EINVAL);
    *v = *crt_doserrno_ptr();
    return 0;
}
DLLAPI crt_errno_t CRTAPI _set_doserrno(unsigned long v) { *crt_doserrno_ptr() = v; return 0; }

/* Win32 error -> errno, the mapping documented for _doserrno / errno in the CRT reference */
static const struct { unsigned short os; unsigned char e; } g_errmap[] = {
    {1, CRT_EINVAL}, {2, CRT_ENOENT}, {3, CRT_ENOENT}, {4, CRT_EMFILE}, {5, CRT_EACCES}, {6, CRT_EBADF}, {7, CRT_ENOMEM},
    {8, CRT_ENOMEM}, {9, CRT_ENOMEM}, {10, CRT_E2BIG}, {11, CRT_ENOEXEC}, {12, CRT_EACCES}, {13, CRT_EINVAL}, {15, CRT_ENOENT},
    {16, CRT_EACCES}, {17, CRT_EXDEV}, {18, CRT_ENOENT}, {19, CRT_EACCES}, {32, CRT_EACCES}, {33, CRT_EACCES}, {53, CRT_ENOENT},
    {65, CRT_EACCES}, {67, CRT_ENOENT}, {80, CRT_EEXIST}, {82, CRT_EACCES}, {83, CRT_EACCES}, {87, CRT_EINVAL}, {89, CRT_EAGAIN},
    {108, CRT_EACCES}, {109, CRT_EPIPE}, {112, CRT_ENOSPC}, {114, CRT_EBADF}, {128, CRT_ECHILD}, {129, CRT_ECHILD},
    {130, CRT_EBADF}, {131, CRT_EINVAL}, {132, CRT_EACCES}, {145, CRT_ENOTEMPTY}, {158, CRT_EACCES}, {161, CRT_ENOENT},
    {164, CRT_EAGAIN}, {167, CRT_EACCES}, {183, CRT_EEXIST}, {206, CRT_ENOENT}, {215, CRT_EAGAIN}, {1816, CRT_ENOMEM},
};
void crt_dosmaperr(unsigned long oserr)
{
    unsigned i;
    *crt_doserrno_ptr() = oserr;
    for (i = 0; i < sizeof g_errmap / sizeof g_errmap[0]; ++i)
        if (g_errmap[i].os == oserr) { crt_set_errno(g_errmap[i].e); return; }
    if (oserr >= 19 && oserr <= 36) crt_set_errno(CRT_EACCES);            /* write-protect .. sharing buffer exceeded */
    else if (oserr >= 188 && oserr <= 202) crt_set_errno(CRT_ENOEXEC);   /* invalid exe signatures */
    else crt_set_errno(CRT_EINVAL);
}

/* ---------------------------------------------------------------- invalid parameter */
#define STATUS_INVALID_CRUNTIME_PARAMETER 0xC0000417u

DLLAPI CRT_NORETURN void CRTAPI _invoke_watson(const wchar16 *expr, const wchar16 *func, const wchar16 *file, unsigned line, uintptr_t r)
{
    (void)expr; (void)func; (void)file; (void)line; (void)r;
    /* Microsoft documents that the default handler ends the process with STATUS_INVALID_CRUNTIME_PARAMETER. (The
     * UCRT prefers __fastfail(FAST_FAIL_INVALID_ARG) when the processor feature is reported; this system reports
     * no fast-fail support, so the documented TerminateProcess path is taken.) */
    TerminateProcess(GetCurrentProcess(), STATUS_INVALID_CRUNTIME_PARAMETER);
    for (;;) ExitProcess(STATUS_INVALID_CRUNTIME_PARAMETER);
}

static void invalid_parameter_core(const wchar16 *expr, const wchar16 *func, const wchar16 *file, unsigned line, uintptr_t r)
{
    crt_inv_handler h = crt_getptd()->inv_handler;
    if (!h) h = g_inv_handler;
    if (h) { h(expr, func, file, line, r); return; }
    _invoke_watson(expr, func, file, line, r);
}
DLLAPI void CRTAPI _invalid_parameter_noinfo(void) { invalid_parameter_core(0, 0, 0, 0, 0); }
DLLAPI CRT_NORETURN void CRTAPI _invalid_parameter_noinfo_noreturn(void)
{
    invalid_parameter_core(0, 0, 0, 0, 0);
    _invoke_watson(0, 0, 0, 0, 0);
}
void crt_invalid_parameter(void) { invalid_parameter_core(0, 0, 0, 0, 0); }

DLLAPI crt_inv_handler CRTAPI _set_invalid_parameter_handler(crt_inv_handler h)
{
    crt_inv_handler old;
    crt_lock(CRT_LOCK_MISC);
    old = g_inv_handler;
    g_inv_handler = h;
    crt_unlock(CRT_LOCK_MISC);
    return old;
}
DLLAPI crt_inv_handler CRTAPI _get_invalid_parameter_handler(void) { return g_inv_handler; }
DLLAPI crt_inv_handler CRTAPI _set_thread_local_invalid_parameter_handler(crt_inv_handler h)
{
    crt_ptd *p = crt_getptd();
    crt_inv_handler old = p->inv_handler;
    p->inv_handler = h;
    return old;
}
DLLAPI crt_inv_handler CRTAPI _get_thread_local_invalid_parameter_handler(void) { return crt_getptd()->inv_handler; }

/* ---------------------------------------------------------------- heap */
static int g_new_mode;
typedef int (CRTAPI *crt_new_handler)(size_t);
static crt_new_handler g_new_handler;

DLLAPI int CRTAPI _set_new_mode(int m)
{
    int old;
    CRT_VALIDATE(m == 0 || m == 1, CRT_EINVAL, -1);
    old = g_new_mode;
    g_new_mode = m;
    return old;
}
DLLAPI int CRTAPI _query_new_mode(void) { return g_new_mode; }
DLLAPI crt_new_handler CRTAPI _set_new_handler(crt_new_handler h)
{
    crt_new_handler old;
    crt_lock(CRT_LOCK_HEAP);
    old = g_new_handler;
    g_new_handler = h;
    crt_unlock(CRT_LOCK_HEAP);
    return old;
}
DLLAPI crt_new_handler CRTAPI _query_new_handler(void) { return g_new_handler; }
/* Calls the installed new handler; returns nonzero when the allocation should be retried. */
DLLAPI int CRTAPI _callnewh(size_t n)
{
    crt_new_handler h = g_new_handler;
    return h && h(n) != 0;
}

static void *heap_alloc(size_t n, int zero)
{
    for (;;) {
        void *p;
        if (n > (size_t)0xffffffffffffffe0ull) break;
        p = HeapAlloc(crt_heap, zero ? OS_HEAP_ZERO_MEMORY : 0, n ? n : 1);
        if (p) return p;
        if (!g_new_mode || !_callnewh(n)) break;
    }
    crt_set_errno(CRT_ENOMEM);
    return 0;
}
void *crt_malloc(size_t n) { return heap_alloc(n, 0); }
void *crt_calloc(size_t n, size_t m)
{
    if (m && n > (size_t)-1 / m) { crt_set_errno(CRT_ENOMEM); return 0; }
    return heap_alloc(n * m, 1);
}
void crt_free(void *p) { if (p) HeapFree(crt_heap, 0, p); }
void *crt_realloc(void *p, size_t n)
{
    if (!p) return crt_malloc(n);
    if (!n) { crt_free(p); return 0; }
    for (;;) {
        void *q = HeapReAlloc(crt_heap, 0, p, n);
        if (q) return q;
        if (!g_new_mode || !_callnewh(n)) break;
    }
    crt_set_errno(CRT_ENOMEM);
    return 0;
}

DLLAPI void *CRTAPI malloc(size_t n) { return crt_malloc(n); }
DLLAPI void *CRTAPI _malloc_base(size_t n) { return crt_malloc(n); }
DLLAPI void *CRTAPI calloc(size_t n, size_t m) { return crt_calloc(n, m); }
DLLAPI void *CRTAPI _calloc_base(size_t n, size_t m) { return crt_calloc(n, m); }
DLLAPI void CRTAPI free(void *p) { crt_free(p); }
DLLAPI void CRTAPI _free_base(void *p) { crt_free(p); }
DLLAPI void *CRTAPI realloc(void *p, size_t n) { return crt_realloc(p, n); }
DLLAPI void *CRTAPI _realloc_base(void *p, size_t n) { return crt_realloc(p, n); }
DLLAPI size_t CRTAPI _msize(void *p)
{
    CRT_VALIDATE(p != 0, CRT_EINVAL, (size_t)-1);
    return HeapSize(crt_heap, 0, p);
}
DLLAPI void *CRTAPI _recalloc(void *p, size_t n, size_t m)
{
    size_t old = p ? HeapSize(crt_heap, 0, p) : 0, sz;
    unsigned char *q;
    if (m && n > (size_t)-1 / m) { crt_set_errno(CRT_ENOMEM); return 0; }
    sz = n * m;
    q = crt_realloc(p, sz ? sz : 1);
    if (q && sz > old) crt_memset(q + old, 0, sz - old);
    return q;
}
DLLAPI void *CRTAPI _expand(void *p, size_t n)
{
    void *q;
    CRT_VALIDATE(p != 0, CRT_EINVAL, 0);
    q = HeapReAlloc(crt_heap, 0x10 /* HEAP_REALLOC_IN_PLACE_ONLY */, p, n ? n : 1);
    if (!q) crt_set_errno(CRT_ENOMEM);
    return q;
}
DLLAPI int CRTAPI _heapchk(void) { return HeapValidate(crt_heap, 0, 0) ? -2 /* _HEAPOK */ : -3 /* _HEAPBADNODE */; }
DLLAPI int CRTAPI _heapmin(void) { return 0; }
DLLAPI intptr_t CRTAPI _get_heap_handle(void) { return (intptr_t)crt_heap; }

/* _aligned_*: the block stores the original pointer just below the aligned address (layout private to this DLL) */
static int is_pow2(size_t a) { return a && !(a & (a - 1)); }
DLLAPI void *CRTAPI _aligned_offset_malloc(size_t n, size_t align, size_t off)
{
    uintptr_t raw, r;
    CRT_VALIDATE(is_pow2(align) && (off == 0 || off < n), CRT_EINVAL, 0);
    if (align < sizeof(void *)) align = sizeof(void *);
    if (n > (size_t)-1 - align - sizeof(void *) - off) { crt_set_errno(CRT_ENOMEM); return 0; }
    raw = (uintptr_t)crt_malloc(n + align + sizeof(void *) + off);
    if (!raw) return 0;
    r = ((raw + sizeof(void *) + off + align - 1) & ~(uintptr_t)(align - 1)) - off;
    ((uintptr_t *)r)[-1] = raw;
    return (void *)r;
}
DLLAPI void *CRTAPI _aligned_malloc(size_t n, size_t align) { return _aligned_offset_malloc(n, align, 0); }
DLLAPI void CRTAPI _aligned_free(void *p) { if (p) crt_free((void *)((uintptr_t *)p)[-1]); }
DLLAPI size_t CRTAPI _aligned_msize(void *p, size_t align, size_t off)
{
    uintptr_t raw;
    (void)off;
    CRT_VALIDATE(p != 0 && is_pow2(align), CRT_EINVAL, (size_t)-1);
    raw = ((uintptr_t *)p)[-1];
    return HeapSize(crt_heap, 0, (void *)raw) - ((uintptr_t)p - raw);       /* usable bytes from p to the block end */
}
DLLAPI void *CRTAPI _aligned_offset_realloc(void *p, size_t n, size_t align, size_t off)
{
    void *q;
    size_t old;
    if (!p) return _aligned_offset_malloc(n, align, off);
    if (!n) { _aligned_free(p); return 0; }
    old = _aligned_msize(p, align, off);
    q = _aligned_offset_malloc(n, align, off);
    if (!q) return 0;
    crt_memcpy(q, p, old < n ? old : n);
    _aligned_free(p);
    return q;
}
DLLAPI void *CRTAPI _aligned_realloc(void *p, size_t n, size_t align) { return _aligned_offset_realloc(p, n, align, 0); }
DLLAPI void *CRTAPI _aligned_offset_recalloc(void *p, size_t n, size_t m, size_t align, size_t off)
{
    size_t old = p ? _aligned_msize(p, align, off) : 0, sz;
    unsigned char *q;
    if (m && n > (size_t)-1 / m) { crt_set_errno(CRT_ENOMEM); return 0; }
    sz = n * m;
    q = _aligned_offset_realloc(p, sz, align, off);
    if (q && sz > old) crt_memset(q + old, 0, sz - old);
    return q;
}
DLLAPI void *CRTAPI _aligned_recalloc(void *p, size_t n, size_t m, size_t align) { return _aligned_offset_recalloc(p, n, m, align, 0); }

/* ---------------------------------------------------------------- DLL entry */
int __stdcall DllMain(void *inst, os_dword reason, void *reserved)
{
    (void)inst;
    switch (reason) {
    case 1:                                             /* DLL_PROCESS_ATTACH */
        crt_heap = GetProcessHeap();
        g_tls = TlsAlloc();
        if (g_tls == 0xffffffffu) return 0;
        crt_time_init();
        crt_stdio_init();
        break;
    case 3:                                             /* DLL_THREAD_DETACH */
        free_ptd();
        break;
    case 0:                                             /* DLL_PROCESS_DETACH */
        crt_process_detach(reserved != 0);
        free_ptd();
        break;
    default:
        break;
    }
    return 1;
}
