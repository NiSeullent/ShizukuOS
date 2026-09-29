/* SPDX-License-Identifier: GPL-2.0-only
 * ucrtbase.dll on the Shizuku Win64 runtime: the services MSVC startup code and programs rely on, exercised through
 * the import table (crt_imp.h): heap, per-thread errno, _initterm, onexit tables, argv / environment configuration,
 * exit() running atexit handlers and flushing stdio (in a child process), _beginthreadex, signal / raise and the
 * _seh_filter_* mapping, the invalid-parameter handler, printf / scanf / strtod, math and the floating-point control
 * word, time, and the api-ms-win-crt-* contracts. Expected values come from the C standard and Microsoft's CRT
 * documentation; the bulk accuracy of the conversion and math code is checked on the host (tests/host_ucrt).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "u_check.h"
#include "crt_imp.h"

static int order[8], order_n;
static void on1(void) { order[order_n++] = 1; }
static void on2(void) { order[order_n++] = 2; }
static void on3(void) { order[order_n++] = 3; }
static int init_e_calls;
static int ie_ok(void) { ++init_e_calls; return 0; }
static int ie_fail(void) { ++init_e_calls; return 7; }
static int sig_seen;
static void on_sig(int s) { sig_seen = s; }
static int inv_calls;
static void inv_handler(const unsigned short *e, const unsigned short *f, const unsigned short *file, unsigned line, uintptr_t r)
{
    (void)e; (void)f; (void)file; (void)line; (void)r;
    ++inv_calls;
}
static volatile LONG thread_errno_ok;
static unsigned __stdcall thread_fn(void *arg)
{
    int *e = crt__errno();
    *e = 77;
    Sleep(20);
    thread_errno_ok = (*crt__errno() == 77 && e != (int *)arg) ? 1 : 0;
    return 123;
}
static int cmp_int(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }

/* child mode: buffered output, an atexit handler that appends to the same still-buffered stream, then exit(5).
 * C requires exit() to call the atexit functions first and then flush every stream, so both lines reach the file. */
static void *child_file;
static char exit_file[300];
static void make_exit_path(void)                              /* <directory of this exe>\CRTEXIT.TXT, the same in both */
{
    int n = (int)GetModuleFileNameA(0, exit_file, 260);
    while (n > 0 && exit_file[n - 1] != '\\') --n;
    memcpy(exit_file + n, "CRTEXIT.TXT", 12);
}
static void child_on_exit(void) { crt_fputs("atexit-ran\n", child_file); }
static int child_main(void)
{
    make_exit_path();
    child_file = crt_fopen(exit_file, "w");
    crt_setvbuf(child_file, 0, 0, 512);                     /* fully buffered: only exit() writes it out */
    crt_fputs("buffered-before-exit\n", child_file);
    crt__crt_atexit(child_on_exit);
    crt_exit(5);
    return 99;
}

int main(int argc, char **argv)
{
    U_CHECK("ucrtbase.dll is mapped and its string functions resolve", crt_imp_init());
    if (argc >= 2 && !strcmp(argv[1], "child")) return child_main();

    /* ---- heap */
    {
        char *p = crt_malloc(100), *q;
        void *a = crt__aligned_malloc(200, 64);
        U_CHECK("malloc returns memory from the process heap", p && HeapSize(GetProcessHeap(), 0, p) >= 100);
        U_CHECK("_msize reports at least the requested size", p && crt__msize(p) >= 100);
        crt_memset(p, 0x5a, 100);
        q = crt_realloc(p, 5000);
        U_CHECK("realloc keeps the contents", q && q[0] == 0x5a && q[99] == 0x5a);
        crt_free(q);
        U_CHECK("_aligned_malloc honours the alignment", a && ((uintptr_t)a & 63) == 0);
        crt__aligned_free(a);
        {
            int *z = crt_calloc(1000, sizeof(int)), i, all0 = 1;
            for (i = 0; z && i < 1000; ++i) if (z[i]) all0 = 0;
            U_CHECK("calloc zero-fills", z && all0);
            crt_free(z);
        }
        *crt__errno() = 0;
        U_CHECK("calloc overflow fails with ENOMEM", crt_calloc((size_t)1 << 62, 16) == 0 && *crt__errno() == 12);
        U_CHECK("_callnewh without a handler returns 0", crt__callnewh(16) == 0);
    }
    /* ---- per-thread errno and _beginthreadex */
    {
        unsigned tid = 0;
        uintptr_t h;
        DWORD code = 0;
        *crt__errno() = 5;
        h = crt__beginthreadex(0, 0, thread_fn, crt__errno(), 0, &tid);
        U_CHECK("_beginthreadex starts a thread", h != 0 && tid != 0);
        if (h) {
            WaitForSingleObject((HANDLE)h, 5000);
            GetExitCodeThread((HANDLE)h, &code);
            CloseHandle((HANDLE)h);
        }
        U_CHECK("the thread's return value is its exit code", code == 123);
        U_CHECK("errno is per thread", thread_errno_ok == 1 && *crt__errno() == 5);
    }
    /* ---- _initterm, onexit tables */
    {
        crt_pvfv tab[] = { on1, 0, on2 };
        crt_pifv tabe[] = { ie_ok, ie_fail, ie_ok };
        crt_onexit_table t = { 0, 0, 0 };
        order_n = 0;
        crt__initterm(tab, tab + 3);
        U_CHECK("_initterm calls the non-null entries in order", order_n == 2 && order[0] == 1 && order[1] == 2);
        U_CHECK("_initterm_e stops at the first nonzero result", crt__initterm_e(tabe, tabe + 3) == 7 && init_e_calls == 2);
        order_n = 0;
        U_CHECK("_initialize_onexit_table", crt__initialize_onexit_table(&t) == 0);
        crt__register_onexit_function(&t, on1);
        crt__register_onexit_function(&t, on2);
        crt__register_onexit_function(&t, on3);
        U_CHECK("_execute_onexit_table", crt__execute_onexit_table(&t) == 0);
        U_CHECK("onexit functions run in reverse registration order", order_n == 3 && order[0] == 3 && order[1] == 2 && order[2] == 1);
        order_n = 0;
        crt__execute_onexit_table(&t);
        U_CHECK("an executed table is empty afterwards", order_n == 0);
    }
    /* ---- argv and environment */
    {
        char **av;
        const char *wm;
        U_CHECK("_configure_narrow_argv(unexpanded)", crt__configure_narrow_argv(1) == 0);
        av = *crt___p___argv();
        U_CHECK("__p___argc / __p___argv see the command line", *crt___p___argc() == argc && av && av[0] && !crt_strcmp(av[0], argv[0]) &&
                av[argc] == 0);
        U_CHECK("_configure_wide_argv", crt__configure_wide_argv(1) == 0 && *crt___p___wargv() && (*crt___p___wargv())[0]);
        wm = crt__get_narrow_winmain_command_line();
        U_CHECK("WinMain command line skips the program name", wm && *wm == 0);
        U_CHECK("_initialize_narrow_environment", crt__initialize_narrow_environment() == 0 && *crt___p__environ());
        U_CHECK("_putenv adds a variable", crt__putenv("SHZ_CRT_TEST=42") == 0);
        U_CHECK("getenv finds it", crt_getenv("SHZ_CRT_TEST") && !crt_strcmp(crt_getenv("SHZ_CRT_TEST"), "42"));
        U_CHECK("getenv ignores case", crt_getenv("shz_crt_test") != 0);
        {
            char buf[16];
            U_CHECK("_putenv updates the process environment block", GetEnvironmentVariableA("SHZ_CRT_TEST", buf, 16) == 2 && buf[0] == '4');
        }
        U_CHECK("_putenv_s with an empty value removes it", crt__putenv_s("SHZ_CRT_TEST", "") == 0 && crt_getenv("SHZ_CRT_TEST") == 0);
    }
    /* ---- signals and exception filters */
    {
        struct { EXCEPTION_RECORD *r; CONTEXT *c; } ptrs = { 0, 0 };
        crt_sig old = crt_signal(2 /* SIGINT */, on_sig);
        U_CHECK("signal returns the previous handler (SIG_DFL)", old == 0);
        U_CHECK("raise calls the handler", crt_raise(2) == 0 && sig_seen == 2);
        U_CHECK("the handler was reset to SIG_DFL", crt_signal(2, 0) == 0);
        U_CHECK("_seh_filter_exe: access violation without handler continues the search", crt__seh_filter_exe(0xC0000005u, &ptrs) == 0);
        crt_signal(11 /* SIGSEGV */, on_sig);
        sig_seen = 0;
        U_CHECK("_seh_filter_exe: SIGSEGV handler -> continue execution", crt__seh_filter_exe(0xC0000005u, &ptrs) == -1 && sig_seen == 11);
        U_CHECK("_seh_filter_dll passes only C++ exceptions on", crt__seh_filter_dll(0xC0000005u, &ptrs) == 0 &&
                crt__seh_filter_dll(0xE06D7363u, &ptrs) == 0);
    }
    /* ---- invalid parameter handler */
    {
        char small[4];
        crt_inv_handler old = crt__set_invalid_parameter_handler(inv_handler);
        inv_calls = 0;
        U_CHECK("strcpy_s overflow -> ERANGE through the handler", crt_strcpy_s(small, 4, "toolong") == 34 && small[0] == 0 && inv_calls == 1);
        crt__set_thread_local_invalid_parameter_handler(inv_handler);
        crt__invalid_parameter_noinfo();
        U_CHECK("thread-local invalid parameter handler", inv_calls == 2);
        crt__set_thread_local_invalid_parameter_handler(0);
        crt__set_invalid_parameter_handler(old);
    }
    /* ---- strings, conversions, formatting */
    {
        char buf[128];
        int n = 0, v = 0;
        double d = 0;
        int arr[] = { 5, 3, 9, 1, 7 };
        static const unsigned short w1[] = { 'a', 'B', 'c', 0 }, w2[] = { 'a', 'B', 'd', 0 }, w3[] = { ' ', '-', '1', '7', 'z', 0 };
        unsigned short *end;
        U_CHECK("strlen / strcmp", crt_strlen("hello") == 5 && crt_strcmp("a", "b") < 0);
        U_CHECK("wcsncmp / towlower / toupper / isalpha", crt_wcsncmp(w1, w2, 2) == 0 && crt_wcsncmp(w1, w2, 3) < 0 && crt_towlower('Q') == 'q' &&
                crt_toupper('x') == 'X' && crt_isalpha('A') && !crt_isalpha('1'));
        U_CHECK("wcstol stops at the first non-digit", crt_wcstol(w3, &end, 10) == -17 && end == w3 + 4);
        U_CHECK("atoi / strtod", crt_atoi("  -45x") == -45 && crt_strtod("2.5e-3", 0) == 0.0025);
        crt_qsort(arr, 5, sizeof arr[0], cmp_int);
        U_CHECK("qsort", arr[0] == 1 && arr[1] == 3 && arr[2] == 5 && arr[3] == 7 && arr[4] == 9);
        crt_snprintf(buf, sizeof buf, "%d|%5.2f|%-4s|%x|%e|%g", -12, 3.14159, "ab", 255u, 12345.678, 0.0001);
        U_CHECK("printf family formatting", !crt_strcmp(buf, "-12| 3.14|ab  |ff|1.234568e+04|0.0001"));
        crt_snprintf(buf, sizeof buf, "%.17g %a", 0.1, 1.0);
        U_CHECK("exact floating-point digits and %a", !crt_strcmp(buf, "0.10000000000000001 0x1.0000000000000p+0"));
        U_CHECK("printf returns the full length", crt_snprintf(buf, 4, "%s", "abcdef") == 6 && !crt_strcmp(buf, "abc"));
        U_CHECK("sscanf", crt_sscanf("  42 3.5e1 xyz", "%d %lf %n", &v, &d, &n) == 2 && v == 42 && d == 35.0 && n == 11);
        U_CHECK("C locale: code page 0, setlocale(\"C\")", crt____lc_codepage_func() == 0 && crt_setlocale(0, 0) && !crt_strcmp(crt_setlocale(0, 0), "C"));
        U_CHECK("_configthreadlocale reports the default", crt__configthreadlocale(0) == 2);
    }
    /* ---- math and the floating-point environment */
    {
        unsigned cw = 0;
        U_CHECK("exp/log/pow/sqrt exact cases", crt_exp(0) == 1.0 && crt_log(1.0) == 0.0 && crt_pow(2.0, 10.0) == 1024.0 && crt_sqrt(2.25) == 1.5 &&
                crt_log10(1000.0) == 3.0);
        U_CHECK("sin(1e22) with exact argument reduction", crt_sin(1e22) == -0x1.b453ab76bf397p-1);
        U_CHECK("cos(1e300)", crt_cos(1e300) == -0x1.2699022adc4c1p-1);
        U_CHECK("atan2 / tgamma / erf", crt_atan2(1.0, -1.0) == 0x1.2d97c7f3321d2p+1 && crt_tgamma(5.0) == 24.0 && crt_erf(1.0) == 0x1.af767a741088bp-1);
        U_CHECK("float rounding helpers", crt_ceilf(1.2f) == 2.0f && crt_floorf(-1.2f) == -2.0f && crt_roundf(2.5f) == 3.0f && crt_lrintf(2.5f) == 2 &&
                crt_lroundf(-2.5f) == -3 && crt_lround(2.5) == 3 && crt_ceil(-0.5) == 0.0);
        U_CHECK("powf", crt_powf(2.0f, 0.5f) == 0x1.6a09e6p+0f);
        U_CHECK("fma rounds once", crt_fma(0x1.00000004p0, 0x1.00000004p0, -1.0) == 0x1.00000002p-29);   /* (1+2^-30)^2 - 1 */
        U_CHECK("fmod", crt_fmod(-7.5, 2.0) == -1.5);
        U_CHECK("_fpclass", crt__fpclass(-0.0) == 0x20 && crt__fpclass(1.0) == 0x100);
        U_CHECK("_controlfp_s reads the default control word (all exceptions masked, round to nearest)",
                crt__controlfp_s(&cw, 0, 0) == 0 && (cw & 0x8031f) == 0x8001f);
        U_CHECK("fesetround(FE_DOWNWARD) changes rint", crt_fesetround(0x100) == 0 && crt_fegetround() == 0x100 && crt_rint(2.5) == 2.0 &&
                crt_rint(-2.5) == -3.0);
        crt_fesetround(0);
        crt__clearfp();
        {
            volatile double z = 0.0, r = 1.0 / z;
            (void)r;
        }
        U_CHECK("_statusfp sees the zero-divide flag", (crt__statusfp() & 0x08) != 0);
        crt__clearfp();
    }
    /* ---- time */
    {
        long long t = crt__time64(0), t2;
        crt_tm tm;
        char buf[64];
        static const long long fixed = 794666489;          /* 1995-03-08 12:41:29 UTC */
        U_CHECK("_time64 is after 2020", t > 1577836800LL);
        U_CHECK("_gmtime64_s", crt__gmtime64_s(&tm, &fixed) == 0 && tm.tm_year == 95 && tm.tm_mon == 2 && tm.tm_mday == 8 && tm.tm_hour == 12 &&
                tm.tm_wday == 3);
        U_CHECK("strftime (C locale, Microsoft %c)", crt_strftime(buf, sizeof buf, "%c %j %A", &tm) > 0 && !crt_strcmp(buf, "03/08/95 12:41:29 067 Wednesday"));
        tm.tm_mday += 30;
        t2 = crt__mkgmtime64(&tm);
        U_CHECK("_mkgmtime64 normalises", t2 == fixed + 30 * 86400LL && tm.tm_mon == 3 && tm.tm_mday == 7);
        U_CHECK("clock advances", crt_clock() >= 0);
    }
    /* ---- api-ms-win-crt-* contracts map onto ucrtbase.dll */
    {
        HMODULE u = GetModuleHandleW(L"ucrtbase.dll"), c = LoadLibraryW(L"api-ms-win-crt-runtime-l1-1-0.dll"),
                s = LoadLibraryW(L"api-ms-win-crt-stdio-l1-1-0.dll"), m = LoadLibraryW(L"api-ms-win-crt-math-l1-1-0.dll");
        U_CHECK("ucrtbase.dll is loaded by the import table", u != 0);
        U_CHECK("api-ms-win-crt-runtime-l1-1-0 resolves to ucrtbase", c == u && GetProcAddress(c, "_initterm") == (FARPROC)crt__initterm);
        U_CHECK("api-ms-win-crt-stdio-l1-1-0 resolves to ucrtbase", s == u && GetProcAddress(s, "__stdio_common_vsprintf") != 0);
        U_CHECK("api-ms-win-crt-math-l1-1-0 resolves to ucrtbase (and long double aliases exist)", m == u && GetProcAddress(m, "cbrtl") != 0 &&
                GetProcAddress(m, "cbrtl") == GetProcAddress(m, "cbrt"));
        U_CHECK("an unimplemented function is not exported (no stub)", GetProcAddress(u, "_cputs") == 0);
    }
    /* ---- exit() in a child: atexit handlers run, buffered streams are flushed, exit code is kept */
    {
        WCHAR path[300], cmd[340];
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        DWORD code = 0;
        int n = (int)GetModuleFileNameW(0, path, 300), i;
        cmd[0] = '"';
        for (i = 0; i < n; ++i) cmd[1 + i] = path[i];
        cmd[1 + n] = '"';
        { static const WCHAR tail[] = { ' ', 'c', 'h', 'i', 'l', 'd', 0 }; for (i = 0; i < 7; ++i) cmd[2 + n + i] = tail[i]; }
        memset(&si, 0, sizeof si);
        si.cb = sizeof si;
        {
            WCHAR cwd[300];
            GetCurrentDirectoryW(300, cwd);
            U_CHECK("the child process starts", CreateProcessW(path, cmd, 0, 0, FALSE, 0, 0, cwd, &si, &pi));
        }
        WaitForSingleObject(pi.hProcess, 20000);
        GetExitCodeProcess(pi.hProcess, &code);
        U_CHECK("exit(5) sets the exit code", code == 5);
        {
            void *f;
            make_exit_path();
            f = crt_fopen(exit_file, "r");
            char l1[64] = "", l2[64] = "";
            if (f) { crt_fgets(l1, 64, f); crt_fgets(l2, 64, f); crt_fclose(f); }
            U_CHECKF("exit() ran the atexit handler, then flushed the buffered stream", !crt_strcmp(l1, "buffered-before-exit\n") &&
                     !crt_strcmp(l2, "atexit-ran\n"), "file=%s l1=[%s] l2=[%s]", f ? "found" : "missing", l1, l2);
            crt_remove(exit_file);
        }
    }
    return u_finish("t_crt_rt");
}
