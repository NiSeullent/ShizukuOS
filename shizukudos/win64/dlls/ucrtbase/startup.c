/* SPDX-License-Identifier: GPL-2.0-only
 * Program startup and termination services the MSVC startup code (vcstartup, statically linked into every
 * MSVC-built EXE/DLL) imports from the Universal CRT: _initterm / _initterm_e, the onexit tables, exit / _exit /
 * _cexit / quick_exit / abort / terminate, the argv and environment configuration, the _seh_filter_* exception
 * filters, signal / raise, and _beginthread[ex].
 *
 * Documented behaviour reproduced: exit() runs the executable's thread_local destructors callback, then the
 * process atexit table in reverse registration order, flushes and closes all streams and calls ExitProcess (which
 * runs every DLL's DLL_PROCESS_DETACH, where each DLL's startup code executes its module-local onexit table);
 * abort() raises SIGABRT and ends the process with exit code 3; argv parsing follows Microsoft's documented
 * "Parsing C command-line arguments" rules (backslashes before quotes, "" inside quotes).
 */
#include "crtint.h"
#include "crtos.h"

typedef void (CRTAPI *crt_pvfv)(void);
typedef int (CRTAPI *crt_pifv)(void);
typedef struct { crt_pvfv *first, *last, *end; } crt_onexit_table;

extern os_handle crt_heap;
CRT_NORETURN void CRTAPI _invoke_watson(const wchar16 *, const wchar16 *, const wchar16 *, unsigned, uintptr_t);
void crt_flushall_close(int close);
void crt_stdio_terminate(void);

/* ---------------------------------------------------------------- initializer tables */
DLLAPI void CRTAPI _initterm(crt_pvfv *first, crt_pvfv *last)
{
    for (; first < last; ++first)
        if (*first) (*first)();
}
DLLAPI int CRTAPI _initterm_e(crt_pifv *first, crt_pifv *last)
{
    for (; first < last; ++first)
        if (*first) {
            int r = (*first)();
            if (r) return r;
        }
    return 0;
}

/* ---------------------------------------------------------------- onexit tables (pointers kept encoded) */
DLLAPI int CRTAPI _initialize_onexit_table(crt_onexit_table *t)
{
    if (!t) return -1;
    if (t->first != t->end) return 0;                      /* already initialised */
    t->first = t->last = t->end = EncodePointer(0);
    return 0;
}

DLLAPI int CRTAPI _register_onexit_function(crt_onexit_table *t, crt_pvfv fn)
{
    crt_pvfv *first, *last, *end;
    if (!t) return -1;
    crt_lock(CRT_LOCK_ONEXIT);
    first = DecodePointer(t->first);
    last = DecodePointer(t->last);
    end = DecodePointer(t->end);
    if (last == end) {
        const size_t count = (size_t)(end - first), grow = count ? (count < 512 ? count : 512) : 32;
        crt_pvfv *n = crt_realloc(first, (count + grow) * sizeof *n);
        if (!n) { crt_unlock(CRT_LOCK_ONEXIT); return -1; }
        last = n + (last - first);
        first = n;
        end = n + count + grow;
    }
    *last++ = EncodePointer((void *)fn);
    t->first = EncodePointer(first);
    t->last = EncodePointer(last);
    t->end = EncodePointer(end);
    crt_unlock(CRT_LOCK_ONEXIT);
    return 0;
}

/* Runs the table in reverse order. Functions may register further functions while it runs; those run too. */
DLLAPI int CRTAPI _execute_onexit_table(crt_onexit_table *t)
{
    crt_pvfv *first, *last;
    if (!t) return -1;
    crt_lock(CRT_LOCK_ONEXIT);
    first = DecodePointer(t->first);
    last = DecodePointer(t->last);
    crt_unlock(CRT_LOCK_ONEXIT);
    if (first) {
        void *const null_enc = EncodePointer(0);
        crt_pvfv *p = last;
        while (--p >= first) {
            crt_pvfv fn;
            if (*p == null_enc) continue;
            fn = (crt_pvfv)DecodePointer(*p);
            *p = null_enc;
            fn();
            /* the table may have been reallocated or extended by fn */
            crt_lock(CRT_LOCK_ONEXIT);
            {
                crt_pvfv *nf = DecodePointer(t->first), *nl = DecodePointer(t->last);
                if (nf != first || nl != last) { p = nl; first = nf; last = nl; }
            }
            crt_unlock(CRT_LOCK_ONEXIT);
        }
    }
    crt_lock(CRT_LOCK_ONEXIT);
    crt_free(DecodePointer(t->first));
    t->first = t->last = t->end = EncodePointer(0);
    crt_unlock(CRT_LOCK_ONEXIT);
    return 0;
}

static crt_onexit_table g_atexit, g_quick_exit;
static int g_tables_ready;
static void tables_init(void)
{
    if (g_tables_ready) return;
    crt_lock(CRT_LOCK_ONEXIT);
    if (!g_tables_ready) {
        g_atexit.first = g_atexit.last = g_atexit.end = EncodePointer(0);
        g_quick_exit = g_atexit;
        g_tables_ready = 1;
    }
    crt_unlock(CRT_LOCK_ONEXIT);
}
DLLAPI int CRTAPI _crt_atexit(crt_pvfv fn) { tables_init(); return _register_onexit_function(&g_atexit, fn); }
DLLAPI int CRTAPI _crt_at_quick_exit(crt_pvfv fn) { tables_init(); return _register_onexit_function(&g_quick_exit, fn); }

typedef void (__stdcall *crt_tls_callback)(void *, unsigned long, void *);
static void *g_tls_exit_cb;                                /* encoded */
DLLAPI void CRTAPI _register_thread_local_exe_atexit_callback(crt_tls_callback cb)
{
    /* Called once by the executable's startup code. A second registration is a fatal error in the UCRT. */
    if (g_tls_exit_cb) { _invoke_watson(0, 0, 0, 0, 0); }
    g_tls_exit_cb = EncodePointer((void *)cb);
}

/* ---------------------------------------------------------------- termination */
static int g_exit_done;

enum { EXIT_FULL, EXIT_QUICK, EXIT_NONE };
static void common_exit(int code, int cleanup, int terminate)
{
    crt_lock(CRT_LOCK_MISC);                                /* one thread performs the termination sequence */
    if (!g_exit_done) {
        g_exit_done = 1;
        crt_unlock(CRT_LOCK_MISC);
        tables_init();
        if (cleanup == EXIT_FULL) {
            if (g_tls_exit_cb) ((crt_tls_callback)DecodePointer(g_tls_exit_cb))(0, 0 /* DLL_PROCESS_DETACH */, 0);
            _execute_onexit_table(&g_atexit);
        } else if (cleanup == EXIT_QUICK) {
            _execute_onexit_table(&g_quick_exit);
        }
        if (cleanup != EXIT_NONE || terminate) crt_flushall_close(cleanup == EXIT_FULL && terminate);
    } else {
        crt_unlock(CRT_LOCK_MISC);
    }
    if (terminate) {
        ExitProcess((unsigned)code);
        for (;;) TerminateProcess(GetCurrentProcess(), (unsigned)code);
    }
}

DLLAPI CRT_NORETURN void CRTAPI exit(int code) { common_exit(code, EXIT_FULL, 1); for (;;) {} }
DLLAPI CRT_NORETURN void CRTAPI _exit(int code) { common_exit(code, EXIT_NONE, 1); for (;;) {} }
DLLAPI CRT_NORETURN void CRTAPI _Exit(int code) { common_exit(code, EXIT_NONE, 1); for (;;) {} }
DLLAPI CRT_NORETURN void CRTAPI quick_exit(int code) { common_exit(code, EXIT_QUICK, 1); for (;;) {} }
DLLAPI void CRTAPI _cexit(void) { common_exit(0, EXIT_FULL, 0); }
DLLAPI void CRTAPI _c_exit(void) { common_exit(0, EXIT_NONE, 0); }

/* Process detach of ucrtbase itself (ExitProcess without exit(), or FreeLibrary never happens for it): streams that
 * were not flushed by exit() are flushed now, as the UCRT's uninitializer does. */
void crt_process_detach(int terminating)
{
    (void)terminating;
    if (!g_exit_done) {
        g_exit_done = 1;
        crt_flushall_close(0);
    }
}

/* ---------------------------------------------------------------- signals */
#define CRT_SIGINT 2
#define CRT_SIGILL 4
#define CRT_SIGABRT_COMPAT 6
#define CRT_SIGFPE 8
#define CRT_SIGSEGV 11
#define CRT_SIGTERM 15
#define CRT_SIGBREAK 21
#define CRT_SIGABRT 22
#define SIG_DFL_ ((crt_sighandler)0)
#define SIG_IGN_ ((crt_sighandler)1)
#define SIG_GET_ ((crt_sighandler)2)
#define SIG_SGE_ ((crt_sighandler)3)
#define SIG_ACK_ ((crt_sighandler)4)
#define SIG_ERR_ ((crt_sighandler)(intptr_t)-1)
#define FPE_EXPLICITGEN 0x8c

static crt_sighandler g_sigint, g_sigbreak, g_sigabrt, g_sigterm;
static void *g_xcptinfo_global;

static crt_sighandler *sig_slot(int sig)
{
    crt_ptd *p;
    switch (sig) {
    case CRT_SIGINT: return &g_sigint;
    case CRT_SIGBREAK: return &g_sigbreak;
    case CRT_SIGABRT: case CRT_SIGABRT_COMPAT: return &g_sigabrt;
    case CRT_SIGTERM: return &g_sigterm;
    case CRT_SIGFPE: p = crt_getptd(); return &p->sig_fpe;
    case CRT_SIGILL: p = crt_getptd(); return &p->sig_ill;
    case CRT_SIGSEGV: p = crt_getptd(); return &p->sig_segv;
    default: return 0;
    }
}

DLLAPI crt_sighandler CRTAPI signal(int sig, crt_sighandler fn)
{
    crt_sighandler *slot = sig_slot(sig), old;
    if (fn == SIG_ACK_ || fn == SIG_SGE_) slot = 0;           /* only meaningful for the obsolete SIGFPE protocol */
    if (!slot) { crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return SIG_ERR_; }
    if (fn == SIG_GET_) return *slot;
    crt_lock(CRT_LOCK_SIGNAL);
    old = *slot;
    *slot = fn;
    crt_unlock(CRT_LOCK_SIGNAL);
    return old;
}

DLLAPI int *CRTAPI __fpecode(void) { static int code; return &code; }
DLLAPI void **CRTAPI __pxcptinfoptrs(void) { return &g_xcptinfo_global; }

DLLAPI int CRTAPI raise(int sig)
{
    crt_sighandler *slot = sig_slot(sig), fn;
    if (!slot) { crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return -1; }
    crt_lock(CRT_LOCK_SIGNAL);
    fn = *slot;
    /* the handler is reset to SIG_DFL before it is called (except for SIGFPE's documented protocol, kept the same here) */
    if (fn != SIG_IGN_) *slot = SIG_DFL_;
    crt_unlock(CRT_LOCK_SIGNAL);
    if (fn == SIG_IGN_) return 0;
    if (fn == SIG_DFL_) _exit(3);
    if (sig == CRT_SIGFPE) ((void (CRTAPI *)(int, int))fn)(sig, FPE_EXPLICITGEN);
    else fn(sig);
    return 0;
}

/* abort behaviour flags: _WRITE_ABORT_MSG 1, _CALL_REPORTFAULT 2 (both set by default) */
static unsigned g_abort_flags = 3;
DLLAPI unsigned CRTAPI _set_abort_behavior(unsigned flags, unsigned mask)
{
    unsigned old = g_abort_flags;
    g_abort_flags = (old & ~mask) | (flags & mask);
    return old;
}

DLLAPI CRT_NORETURN void CRTAPI abort(void)
{
    crt_sighandler fn = g_sigabrt;
    if (fn != SIG_DFL_ && fn != SIG_IGN_) raise(CRT_SIGABRT);
    /* default action: terminate with exit code 3 (no fast-fail on this system; see _invoke_watson) */
    _exit(3);
}

/* ---------------------------------------------------------------- terminate / unexpected */
typedef void (CRTAPI *crt_term_fn)(void);
static crt_term_fn g_terminate, g_unexpected;
DLLAPI crt_term_fn CRTAPI set_terminate(crt_term_fn f)
{
    crt_term_fn old = g_terminate;
    g_terminate = f;
    return old;
}
DLLAPI crt_term_fn CRTAPI _get_terminate(void) { return g_terminate; }
DLLAPI CRT_NORETURN void CRTAPI terminate(void)
{
    crt_term_fn f = g_terminate;
    if (f) f();                                            /* a terminate handler must not return; if it does, abort */
    abort();
}
DLLAPI crt_term_fn CRTAPI set_unexpected(crt_term_fn f)
{
    crt_term_fn old = g_unexpected;
    g_unexpected = f;
    return old;
}
DLLAPI crt_term_fn CRTAPI _get_unexpected(void) { return g_unexpected; }
DLLAPI void CRTAPI unexpected(void)
{
    crt_term_fn f = g_unexpected;
    if (f) f();
    terminate();
}

/* ---------------------------------------------------------------- exception filters */
typedef struct { struct { unsigned long code, flags; } *rec; void *ctx; } crt_xptrs;
#define EXCEPTION_EXECUTE_HANDLER_ 1
#define EXCEPTION_CONTINUE_SEARCH_ 0
#define EXCEPTION_CONTINUE_EXECUTION_ (-1)

/* Maps structured exceptions to C signals: when a handler is installed for the matching signal it is called and
 * execution continues; SIG_IGN continues too; otherwise the search goes on (the UCRT's _XcptFilter semantics). */
DLLAPI int CRTAPI _seh_filter_exe(unsigned long code, crt_xptrs *ptrs)
{
    int sig;
    crt_sighandler *slot, fn;
    switch (code) {
    case 0xC0000005u: sig = CRT_SIGSEGV; break;                                   /* access violation */
    case 0xC000001Du: case 0xC0000096u: sig = CRT_SIGILL; break;                  /* illegal / privileged instruction */
    case 0xC000008Du: case 0xC000008Eu: case 0xC000008Fu: case 0xC0000090u:       /* float denormal .. invalid */
    case 0xC0000091u: case 0xC0000092u: case 0xC0000093u: case 0xC00002B4u: case 0xC00002B5u:
        sig = CRT_SIGFPE; break;
    default: return EXCEPTION_CONTINUE_SEARCH_;
    }
    slot = sig_slot(sig);
    fn = *slot;
    if (fn == SIG_DFL_) return EXCEPTION_CONTINUE_SEARCH_;
    if (fn == SIG_IGN_) return EXCEPTION_CONTINUE_EXECUTION_;
    *slot = SIG_DFL_;
    {
        void *saved = g_xcptinfo_global;
        g_xcptinfo_global = ptrs;
        if (sig == CRT_SIGFPE) {
            int *fc = __fpecode();
            *fc = (int)code;
            ((void (CRTAPI *)(int, int))fn)(sig, *fc);
        } else fn(sig);
        g_xcptinfo_global = saved;
    }
    return EXCEPTION_CONTINUE_EXECUTION_;
}
/* DLL startup code filters its DllMain calls with this: only the MSVC C++ exception code is passed on to the
 * executable filter (which has no signal for it), so the result is always "continue search". */
DLLAPI int CRTAPI _seh_filter_dll(unsigned long code, crt_xptrs *ptrs)
{
    if (code != 0xE06D7363u) return EXCEPTION_CONTINUE_SEARCH_;
    return _seh_filter_exe(code, ptrs);
}

/* ---------------------------------------------------------------- app type, modes */
static int g_app_type, g_commode, g_fmode = 0x4000 /* _O_TEXT */, g_error_mode;
DLLAPI void CRTAPI _set_app_type(int t) { g_app_type = t; }
DLLAPI int CRTAPI _query_app_type(void) { return g_app_type; }
DLLAPI int *CRTAPI __p__commode(void) { return &g_commode; }
DLLAPI int *CRTAPI __p__fmode(void) { return &g_fmode; }
DLLAPI crt_errno_t CRTAPI _set_fmode(int m)
{
    CRT_VALIDATE(m == 0x4000 || m == 0x8000 || m == 0x10000 || m == 0x20000 || m == 0x40000, CRT_EINVAL, CRT_EINVAL);
    g_fmode = m;
    return 0;
}
DLLAPI crt_errno_t CRTAPI _get_fmode(int *m)
{
    CRT_VALIDATE(m != 0, CRT_EINVAL, CRT_EINVAL);
    *m = g_fmode;
    return 0;
}
int crt_default_fmode(void) { return g_fmode; }
DLLAPI int CRTAPI _set_error_mode(int m)
{
    int old = g_error_mode;
    if (m == 3) return old;                                   /* _REPORT_ERRMODE */
    CRT_VALIDATE(m >= 0 && m <= 2, CRT_EINVAL, -1);
    g_error_mode = m;
    return old;
}
DLLAPI int CRTAPI _getpid(void) { return (int)GetCurrentProcessId(); }
DLLAPI unsigned long CRTAPI __threadid(void) { return GetCurrentThreadId(); }
DLLAPI uintptr_t CRTAPI __threadhandle(void) { return (uintptr_t)GetCurrentThread(); }

/* ---------------------------------------------------------------- command line and argv */
static int g_argc;
static char **g_argv;
static wchar16 **g_wargv;
static char *g_acmdln, *g_pgmptr;
static wchar16 *g_wcmdln, *g_wpgmptr;
static char g_pgm_buf[520];
static wchar16 g_wpgm_buf[260];

/* Splits a command line with Microsoft's rules. Returns argc; fills argv (array of pointers) and the character
 * buffer when they are non-null. The first argument ends at the first space or tab outside quotes, and quotes in it
 * are removed without escape processing. */
#define DEFINE_PARSE(NAME, CH)                                                                                         \
    static int NAME(const CH *cmd, CH **argv, CH *buf, size_t *nchars)                                                 \
    {                                                                                                                  \
        const CH *p = cmd;                                                                                             \
        size_t n = 0;                                                                                                  \
        int argc = 0, inq = 0;                                                                                         \
        /* program name */                                                                                             \
        if (argv) argv[argc] = buf ? buf + n : 0;                                                                     \
        ++argc;                                                                                                        \
        for (;; ++p) {                                                                                                 \
            if (*p == '"') { inq = !inq; continue; }                                                                   \
            if (!*p || (!inq && (*p == ' ' || *p == '\t'))) break;                                                     \
            if (buf) buf[n] = *p;                                                                                      \
            ++n;                                                                                                       \
        }                                                                                                              \
        if (buf) buf[n] = 0;                                                                                           \
        ++n;                                                                                                           \
        inq = 0;                                                                                                       \
        for (;;) {                                                                                                     \
            while (*p == ' ' || *p == '\t') ++p;                                                                       \
            if (!*p) break;                                                                                            \
            if (argv) argv[argc] = buf ? buf + n : 0;                                                                 \
            ++argc;                                                                                                    \
            for (;;) {                                                                                                 \
                size_t bs = 0;                                                                                         \
                while (*p == '\\') { ++p; ++bs; }                                                                      \
                if (*p == '"') {                                                                                       \
                    size_t k;                                                                                          \
                    for (k = 0; k < bs / 2; ++k) { if (buf) buf[n] = '\\'; ++n; }                                      \
                    if (bs & 1) { if (buf) buf[n] = '"'; ++n; ++p; continue; }                                         \
                    if (inq && p[1] == '"') { if (buf) buf[n] = '"'; ++n; p += 2; continue; }                          \
                    inq = !inq;                                                                                        \
                    ++p;                                                                                               \
                    continue;                                                                                          \
                }                                                                                                      \
                { size_t k; for (k = 0; k < bs; ++k) { if (buf) buf[n] = '\\'; ++n; } }                                \
                if (!*p || (!inq && (*p == ' ' || *p == '\t'))) break;                                                 \
                if (buf) buf[n] = *p;                                                                                  \
                ++n;                                                                                                   \
                ++p;                                                                                                   \
            }                                                                                                          \
            if (buf) buf[n] = 0;                                                                                       \
            ++n;                                                                                                       \
        }                                                                                                              \
        if (argv) argv[argc] = 0;                                                                                      \
        *nchars = n;                                                                                                   \
        return argc;                                                                                                   \
    }
DEFINE_PARSE(parse_narrow, char)
DEFINE_PARSE(parse_wide, wchar16)

static void pgm_names(void)
{
    if (g_pgmptr) return;
    if (GetModuleFileNameW(0, g_wpgm_buf, 260)) g_wpgmptr = g_wpgm_buf;
    else g_wpgm_buf[0] = 0, g_wpgmptr = g_wpgm_buf;
    WideCharToMultiByte(OS_CP_ACP, 0, g_wpgm_buf, -1, g_pgm_buf, (int)sizeof g_pgm_buf, 0, 0);
    g_pgmptr = g_pgm_buf;
}

DLLAPI int CRTAPI _configure_narrow_argv(int mode)
{
    size_t nchars = 0;
    int argc;
    char **argv;
    CRT_VALIDATE(mode >= 0 && mode <= 2, CRT_EINVAL, CRT_EINVAL);
    pgm_names();
    g_acmdln = GetCommandLineA();
    if (mode == 0) return 0;                                   /* _crt_argv_no_arguments */
    /* _crt_argv_expanded_arguments (wildcard expansion) is treated like unexpanded: see docs/shizukudos10/CRT.md */
    argc = parse_narrow(g_acmdln, 0, 0, &nchars);
    argv = crt_malloc((size_t)(argc + 1) * sizeof(char *) + nchars);
    if (!argv) return CRT_ENOMEM;
    parse_narrow(g_acmdln, argv, (char *)(argv + argc + 1), &nchars);
    g_argc = argc;
    g_argv = argv;
    return 0;
}
DLLAPI int CRTAPI _configure_wide_argv(int mode)
{
    size_t nchars = 0;
    int argc;
    wchar16 **argv;
    CRT_VALIDATE(mode >= 0 && mode <= 2, CRT_EINVAL, CRT_EINVAL);
    pgm_names();
    g_wcmdln = GetCommandLineW();
    if (mode == 0) return 0;
    argc = parse_wide(g_wcmdln, 0, 0, &nchars);
    argv = crt_malloc((size_t)(argc + 1) * sizeof(wchar16 *) + nchars * sizeof(wchar16));
    if (!argv) return CRT_ENOMEM;
    parse_wide(g_wcmdln, argv, (wchar16 *)(argv + argc + 1), &nchars);
    g_argc = argc;
    g_wargv = argv;
    return 0;
}
DLLAPI int *CRTAPI __p___argc(void) { return &g_argc; }
DLLAPI char ***CRTAPI __p___argv(void) { return &g_argv; }
DLLAPI wchar16 ***CRTAPI __p___wargv(void) { return &g_wargv; }
DLLAPI char **CRTAPI __p__acmdln(void) { if (!g_acmdln) g_acmdln = GetCommandLineA(); return &g_acmdln; }
DLLAPI wchar16 **CRTAPI __p__wcmdln(void) { if (!g_wcmdln) g_wcmdln = GetCommandLineW(); return &g_wcmdln; }
DLLAPI char **CRTAPI __p__pgmptr(void) { pgm_names(); return &g_pgmptr; }
DLLAPI wchar16 **CRTAPI __p__wpgmptr(void) { pgm_names(); return &g_wpgmptr; }
DLLAPI crt_errno_t CRTAPI _get_pgmptr(char **p)
{
    CRT_VALIDATE(p != 0, CRT_EINVAL, CRT_EINVAL);
    pgm_names();
    *p = g_pgmptr;
    return 0;
}
DLLAPI crt_errno_t CRTAPI _get_wpgmptr(wchar16 **p)
{
    CRT_VALIDATE(p != 0, CRT_EINVAL, CRT_EINVAL);
    pgm_names();
    *p = g_wpgmptr;
    return 0;
}

/* WinMain's lpCmdLine: the command line after the program name and the blanks that follow it */
#define DEFINE_WINMAIN(NAME, CH, GET)                                                                                  \
    DLLAPI CH *CRTAPI NAME(void)                                                                                       \
    {                                                                                                                  \
        CH *p = GET();                                                                                                 \
        int inq = 0;                                                                                                   \
        if (!p) return 0;                                                                                              \
        for (; *p; ++p) {                                                                                              \
            if (*p == '"') inq = !inq;                                                                                 \
            else if (!inq && (*p == ' ' || *p == '\t')) break;                                                         \
        }                                                                                                              \
        while (*p == ' ' || *p == '\t') ++p;                                                                           \
        return p;                                                                                                      \
    }
DEFINE_WINMAIN(_get_narrow_winmain_command_line, char, GetCommandLineA)
DEFINE_WINMAIN(_get_wide_winmain_command_line, wchar16, GetCommandLineW)

/* ---------------------------------------------------------------- environment */
static char **g_environ, **g_initial_environ;
static wchar16 **g_wenviron, **g_initial_wenviron;

static size_t wlen(const wchar16 *s) { size_t n = 0; while (s[n]) ++n; return n; }
static size_t nlen(const char *s) { size_t n = 0; while (s[n]) ++n; return n; }

/* builds a NULL-terminated array of heap strings from the OS block; entries starting with '=' (per-drive current
 * directories) are skipped, as in the UCRT */
static wchar16 **wide_env_from_os(void)
{
    wchar16 *block = GetEnvironmentStringsW(), *p, **arr;
    size_t count = 0, i = 0;
    if (!block) return 0;
    for (p = block; *p; p += wlen(p) + 1) if (*p != '=') ++count;
    arr = crt_calloc(count + 1, sizeof *arr);
    if (arr)
        for (p = block; *p; p += wlen(p) + 1) {
            size_t n = wlen(p);
            if (*p == '=') continue;
            arr[i] = crt_malloc((n + 1) * sizeof(wchar16));
            if (!arr[i]) break;
            crt_memcpy(arr[i], p, (n + 1) * sizeof(wchar16));
            ++i;
        }
    FreeEnvironmentStringsW(block);
    return arr;
}
static char *narrow_dup(const wchar16 *w)
{
    int n = WideCharToMultiByte(OS_CP_ACP, 0, w, -1, 0, 0, 0, 0);
    char *s = n > 0 ? crt_malloc((size_t)n) : 0;
    if (s) WideCharToMultiByte(OS_CP_ACP, 0, w, -1, s, n, 0, 0);
    return s;
}
static wchar16 *wide_dup(const char *a)
{
    int n = MultiByteToWideChar(OS_CP_ACP, 0, a, -1, 0, 0);
    wchar16 *s = n > 0 ? crt_malloc((size_t)n * sizeof(wchar16)) : 0;
    if (s) MultiByteToWideChar(OS_CP_ACP, 0, a, -1, s, n);
    return s;
}

static int init_narrow_env_locked(void)
{
    wchar16 **w;
    size_t count = 0, i;
    char **arr;
    if (g_environ) return 0;
    w = wide_env_from_os();
    if (!w) return -1;
    while (w[count]) ++count;
    arr = crt_calloc(count + 1, sizeof *arr);
    if (!arr) return -1;
    for (i = 0; i < count; ++i) { arr[i] = narrow_dup(w[i]); crt_free(w[i]); }
    crt_free(w);
    g_environ = arr;
    if (!g_initial_environ) g_initial_environ = arr;
    return 0;
}
static int init_wide_env_locked(void)
{
    if (g_wenviron) return 0;
    g_wenviron = wide_env_from_os();
    if (!g_wenviron) return -1;
    if (!g_initial_wenviron) g_initial_wenviron = g_wenviron;
    return 0;
}
DLLAPI int CRTAPI _initialize_narrow_environment(void)
{
    int r;
    crt_lock(CRT_LOCK_ENV);
    r = init_narrow_env_locked();
    crt_unlock(CRT_LOCK_ENV);
    return r;
}
DLLAPI int CRTAPI _initialize_wide_environment(void)
{
    int r;
    crt_lock(CRT_LOCK_ENV);
    r = init_wide_env_locked();
    crt_unlock(CRT_LOCK_ENV);
    return r;
}
DLLAPI char **CRTAPI _get_initial_narrow_environment(void) { return g_initial_environ; }
DLLAPI wchar16 **CRTAPI _get_initial_wide_environment(void) { return g_initial_wenviron; }
DLLAPI char ***CRTAPI __p__environ(void) { return &g_environ; }
DLLAPI wchar16 ***CRTAPI __p__wenviron(void) { return &g_wenviron; }

static int name_match_n(const char *entry, const char *name, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i)
        if (crt_toupper_c((unsigned char)entry[i]) != crt_toupper_c((unsigned char)name[i])) return 0;
    return entry[n] == '=';
}
static int name_match_w(const wchar16 *entry, const wchar16 *name, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i)
        if (crt_towupper_c(entry[i]) != crt_towupper_c(name[i])) return 0;
    return entry[n] == '=';
}

static char *getenv_locked(const char *name)
{
    size_t n = nlen(name);
    char **e;
    if (!g_environ && init_narrow_env_locked() != 0) return 0;
    for (e = g_environ; *e; ++e)
        if (name_match_n(*e, name, n)) return *e + n + 1;
    return 0;
}
static wchar16 *wgetenv_locked(const wchar16 *name)
{
    size_t n = wlen(name);
    wchar16 **e;
    if (!g_wenviron && init_wide_env_locked() != 0) return 0;
    for (e = g_wenviron; *e; ++e)
        if (name_match_w(*e, name, n)) return *e + n + 1;
    return 0;
}
DLLAPI char *CRTAPI getenv(const char *name)
{
    char *r;
    CRT_VALIDATE(name != 0 && nlen(name) < 32767, CRT_EINVAL, 0);
    crt_lock(CRT_LOCK_ENV);
    r = getenv_locked(name);
    crt_unlock(CRT_LOCK_ENV);
    return r;
}
DLLAPI wchar16 *CRTAPI _wgetenv(const wchar16 *name)
{
    wchar16 *r;
    CRT_VALIDATE(name != 0 && wlen(name) < 32767, CRT_EINVAL, 0);
    crt_lock(CRT_LOCK_ENV);
    r = wgetenv_locked(name);
    crt_unlock(CRT_LOCK_ENV);
    return r;
}
DLLAPI crt_errno_t CRTAPI getenv_s(size_t *req, char *buf, size_t cap, const char *name)
{
    const char *v;
    size_t n;
    CRT_VALIDATE(req != 0 && name != 0 && (buf != 0 || cap == 0), CRT_EINVAL, CRT_EINVAL);
    if (buf && cap) buf[0] = 0;
    crt_lock(CRT_LOCK_ENV);
    v = getenv_locked(name);
    if (!v) { *req = 0; crt_unlock(CRT_LOCK_ENV); return 0; }
    n = nlen(v) + 1;
    *req = n;
    if (!cap) { crt_unlock(CRT_LOCK_ENV); return 0; }
    if (n > cap) { crt_unlock(CRT_LOCK_ENV); crt_set_errno(CRT_ERANGE); crt_invalid_parameter(); return CRT_ERANGE; }
    crt_memcpy(buf, v, n);
    crt_unlock(CRT_LOCK_ENV);
    return 0;
}
DLLAPI crt_errno_t CRTAPI _wgetenv_s(size_t *req, wchar16 *buf, size_t cap, const wchar16 *name)
{
    const wchar16 *v;
    size_t n;
    CRT_VALIDATE(req != 0 && name != 0 && (buf != 0 || cap == 0), CRT_EINVAL, CRT_EINVAL);
    if (buf && cap) buf[0] = 0;
    crt_lock(CRT_LOCK_ENV);
    v = wgetenv_locked(name);
    if (!v) { *req = 0; crt_unlock(CRT_LOCK_ENV); return 0; }
    n = wlen(v) + 1;
    *req = n;
    if (!cap) { crt_unlock(CRT_LOCK_ENV); return 0; }
    if (n > cap) { crt_unlock(CRT_LOCK_ENV); crt_set_errno(CRT_ERANGE); crt_invalid_parameter(); return CRT_ERANGE; }
    crt_memcpy(buf, v, n * sizeof(wchar16));
    crt_unlock(CRT_LOCK_ENV);
    return 0;
}
DLLAPI crt_errno_t CRTAPI _dupenv_s(char **out, size_t *len, const char *name)
{
    const char *v;
    CRT_VALIDATE(out != 0 && name != 0, CRT_EINVAL, CRT_EINVAL);
    *out = 0;
    if (len) *len = 0;
    crt_lock(CRT_LOCK_ENV);
    v = getenv_locked(name);
    if (v) {
        size_t n = nlen(v) + 1;
        *out = crt_malloc(n);
        if (!*out) { crt_unlock(CRT_LOCK_ENV); return CRT_ENOMEM; }
        crt_memcpy(*out, v, n);
        if (len) *len = n;
    }
    crt_unlock(CRT_LOCK_ENV);
    return 0;
}
DLLAPI crt_errno_t CRTAPI _wdupenv_s(wchar16 **out, size_t *len, const wchar16 *name)
{
    const wchar16 *v;
    CRT_VALIDATE(out != 0 && name != 0, CRT_EINVAL, CRT_EINVAL);
    *out = 0;
    if (len) *len = 0;
    crt_lock(CRT_LOCK_ENV);
    v = wgetenv_locked(name);
    if (v) {
        size_t n = wlen(v) + 1;
        *out = crt_malloc(n * sizeof(wchar16));
        if (!*out) { crt_unlock(CRT_LOCK_ENV); return CRT_ENOMEM; }
        crt_memcpy(*out, v, n * sizeof(wchar16));
        if (len) *len = n;
    }
    crt_unlock(CRT_LOCK_ENV);
    return 0;
}

/* "NAME=value" sets, "NAME=" removes. Both CRT copies (narrow and wide, when they exist) and the OS block change. */
static int env_set_narrow_locked(const char *entry, size_t namelen, int remove)
{
    size_t count = 0, i;
    char **e;
    if (!g_environ && init_narrow_env_locked() != 0) return -1;
    for (e = g_environ; *e; ++e) ++count;
    for (i = 0; i < count; ++i)
        if (name_match_n(g_environ[i], entry, namelen)) break;
    if (remove) {
        if (i < count) {
            crt_free(g_environ[i]);
            for (; i < count; ++i) g_environ[i] = g_environ[i + 1];
        }
        return 0;
    }
    {
        size_t n = nlen(entry) + 1;
        char *copy = crt_malloc(n);
        if (!copy) return -1;
        crt_memcpy(copy, entry, n);
        if (i < count) { crt_free(g_environ[i]); g_environ[i] = copy; return 0; }
        e = crt_realloc(g_environ, (count + 2) * sizeof *e);
        if (!e) { crt_free(copy); return -1; }
        if (g_initial_environ == g_environ) g_initial_environ = e;
        g_environ = e;
        e[count] = copy;
        e[count + 1] = 0;
    }
    return 0;
}
static int env_set_wide_locked(const wchar16 *entry, size_t namelen, int remove)
{
    size_t count = 0, i;
    wchar16 **e;
    if (!g_wenviron && init_wide_env_locked() != 0) return -1;
    for (e = g_wenviron; *e; ++e) ++count;
    for (i = 0; i < count; ++i)
        if (name_match_w(g_wenviron[i], entry, namelen)) break;
    if (remove) {
        if (i < count) {
            crt_free(g_wenviron[i]);
            for (; i < count; ++i) g_wenviron[i] = g_wenviron[i + 1];
        }
        return 0;
    }
    {
        size_t n = wlen(entry) + 1;
        wchar16 *copy = crt_malloc(n * sizeof(wchar16));
        if (!copy) return -1;
        crt_memcpy(copy, entry, n * sizeof(wchar16));
        if (i < count) { crt_free(g_wenviron[i]); g_wenviron[i] = copy; return 0; }
        e = crt_realloc(g_wenviron, (count + 2) * sizeof *e);
        if (!e) { crt_free(copy); return -1; }
        if (g_initial_wenviron == g_wenviron) g_initial_wenviron = e;
        g_wenviron = e;
        e[count] = copy;
        e[count + 1] = 0;
    }
    return 0;
}

/* NAME=value sets, NAME= removes; the narrow and wide CRT copies (whichever exist) and the OS block all change */
static int putenv_common(const char *nentry, const wchar16 *wentry)
{
    char *nconv = 0;
    wchar16 *wconv = 0, *wname = 0;
    size_t nlen_name = 0, wlen_name = 0;
    int remove, r = 0;
    if (!wentry) wentry = wconv = wide_dup(nentry);
    if (!nentry) nentry = nconv = narrow_dup(wentry);
    if (!wentry || !nentry) { crt_free(nconv); crt_free(wconv); crt_set_errno(CRT_ENOMEM); return -1; }
    while (wentry[wlen_name] && wentry[wlen_name] != '=') ++wlen_name;
    while (nentry[nlen_name] && nentry[nlen_name] != '=') ++nlen_name;
    if (!wlen_name || wentry[wlen_name] != '=' || !nlen_name || nentry[nlen_name] != '=') {
        crt_free(nconv);
        crt_free(wconv);
        crt_set_errno(CRT_EINVAL);
        return -1;
    }
    remove = wentry[wlen_name + 1] == 0;
    wname = crt_malloc((wlen_name + 1) * sizeof(wchar16));
    if (!wname) { crt_free(nconv); crt_free(wconv); crt_set_errno(CRT_ENOMEM); return -1; }
    crt_memcpy(wname, wentry, wlen_name * sizeof(wchar16));
    wname[wlen_name] = 0;
    crt_lock(CRT_LOCK_ENV);
    if (!g_environ && !g_wenviron) r |= init_narrow_env_locked();
    if (g_environ) r |= env_set_narrow_locked(nentry, nlen_name, remove);
    if (g_wenviron) r |= env_set_wide_locked(wentry, wlen_name, remove);
    crt_unlock(CRT_LOCK_ENV);
    if (!SetEnvironmentVariableW(wname, remove ? 0 : wentry + wlen_name + 1)) r = -1;
    crt_free(wname);
    crt_free(nconv);
    crt_free(wconv);
    if (r) crt_set_errno(CRT_ENOMEM);
    return r ? -1 : 0;
}
DLLAPI int CRTAPI _putenv(const char *entry)
{
    CRT_VALIDATE(entry != 0, CRT_EINVAL, -1);
    return putenv_common(entry, 0);
}
DLLAPI int CRTAPI _wputenv(const wchar16 *entry)
{
    CRT_VALIDATE(entry != 0, CRT_EINVAL, -1);
    return putenv_common(0, entry);
}
DLLAPI crt_errno_t CRTAPI _putenv_s(const char *name, const char *value)
{
    size_t a, b;
    char *e;
    int r;
    CRT_VALIDATE(name != 0 && value != 0 && name[0], CRT_EINVAL, CRT_EINVAL);
    for (a = 0; name[a]; ++a) CRT_VALIDATE(name[a] != '=', CRT_EINVAL, CRT_EINVAL);
    a = nlen(name);
    b = nlen(value);
    e = crt_malloc(a + b + 2);
    if (!e) return CRT_ENOMEM;
    crt_memcpy(e, name, a);
    e[a] = '=';
    crt_memcpy(e + a + 1, value, b + 1);
    r = putenv_common(e, 0);
    crt_free(e);
    return r ? crt_get_errno() : 0;
}
DLLAPI crt_errno_t CRTAPI _wputenv_s(const wchar16 *name, const wchar16 *value)
{
    size_t a, b, i;
    wchar16 *e;
    int r;
    CRT_VALIDATE(name != 0 && value != 0 && name[0], CRT_EINVAL, CRT_EINVAL);
    for (i = 0; name[i]; ++i) CRT_VALIDATE(name[i] != '=', CRT_EINVAL, CRT_EINVAL);
    a = wlen(name);
    b = wlen(value);
    e = crt_malloc((a + b + 2) * sizeof(wchar16));
    if (!e) return CRT_ENOMEM;
    crt_memcpy(e, name, a * sizeof(wchar16));
    e[a] = '=';
    crt_memcpy(e + a + 1, value, (b + 1) * sizeof(wchar16));
    r = putenv_common(0, e);
    crt_free(e);
    return r ? crt_get_errno() : 0;
}

/* ---------------------------------------------------------------- threads */
typedef unsigned (__stdcall *crt_thread_ex_fn)(void *);
typedef void (CRTAPI *crt_thread_fn)(void *);
typedef struct { void *start, *arg; int ex; os_handle handle; } thread_start_t;

DLLAPI CRT_NORETURN void CRTAPI _endthreadex(unsigned code)
{
    crt_ptd *p = crt_getptd();
    if (!p->thread_ex && p->thread_handle) { CloseHandle(p->thread_handle); p->thread_handle = 0; }
    ExitThread(code);
    for (;;) {}
}
DLLAPI CRT_NORETURN void CRTAPI _endthread(void) { _endthreadex(0); }

static os_dword __stdcall thread_entry(void *param)
{
    thread_start_t ts = *(thread_start_t *)param;
    crt_ptd *p = crt_getptd();
    crt_free(param);
    p->thread_ex = ts.ex;
    p->thread_handle = ts.handle;
    if (ts.ex) _endthreadex(((crt_thread_ex_fn)ts.start)(ts.arg));
    ((crt_thread_fn)ts.start)(ts.arg);
    _endthreadex(0);
}

DLLAPI uintptr_t CRTAPI _beginthreadex(void *sa, unsigned stack, crt_thread_ex_fn fn, void *arg, unsigned flags, unsigned *tid)
{
    thread_start_t *ts;
    os_handle h;
    os_dword id = 0;
    CRT_VALIDATE(fn != 0, CRT_EINVAL, 0);
    ts = crt_malloc(sizeof *ts);
    if (!ts) return 0;
    ts->start = (void *)fn;
    ts->arg = arg;
    ts->ex = 1;
    ts->handle = 0;
    h = CreateThread(sa, stack, thread_entry, ts, flags, &id);
    if (!h) { crt_free(ts); crt_dosmaperr(GetLastError()); return 0; }
    if (tid) *tid = (unsigned)id;
    return (uintptr_t)h;
}

/* _beginthread: the thread closes its own handle when it ends, so the thread starts suspended until the handle is
 * recorded, then resumes. Returns -1 on failure. */
DLLAPI uintptr_t CRTAPI _beginthread(crt_thread_fn fn, unsigned stack, void *arg)
{
    thread_start_t *ts;
    os_handle h;
    os_dword id;
    CRT_VALIDATE(fn != 0, CRT_EINVAL, (uintptr_t)-1);
    ts = crt_malloc(sizeof *ts);
    if (!ts) return (uintptr_t)-1;
    ts->start = (void *)fn;
    ts->arg = arg;
    ts->ex = 0;
    ts->handle = 0;
    h = CreateThread(0, stack, thread_entry, ts, 4 /* CREATE_SUSPENDED */, &id);
    if (!h) { crt_free(ts); crt_dosmaperr(GetLastError()); return (uintptr_t)-1; }
    ts->handle = h;
    ResumeThread(h);
    return (uintptr_t)h;
}
