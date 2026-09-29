/* SPDX-License-Identifier: GPL-2.0-only
 * Access to ucrtbase.dll exports from the mingw-built T_CRT_* tests. Each function is reached through its import
 * address table slot (__imp_<name>, from the import library build.py generates), so the Kernel64 loader binds
 * ucrtbase.dll at process start exactly as it would for an MSVC-built program, and the C names cannot collide with the
 * mingw-w64 headers or with the stage-0 test CRT (shzcrt.c). Types are the Microsoft x64 ABI ones (long = 32 bits,
 * wchar_t = 16 bits, long double = double). */
#ifndef CRT_IMP_H
#define CRT_IMP_H
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

#define CRT_IMPORT(ret, name, args) extern ret (*crt_##name) args __asm__("__imp_" #name)
typedef void (*crt_pvfv)(void);
typedef int (*crt_pifv)(void);
typedef struct { crt_pvfv *first, *last, *end; } crt_onexit_table;
typedef struct { int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst; } crt_tm;
typedef void (*crt_sig)(int);
typedef void (*crt_inv_handler)(const unsigned short *, const unsigned short *, const unsigned short *, unsigned, uintptr_t);
typedef struct { unsigned attrib; long long time_create, time_access, time_write, size; char name[260]; } crt_finddata64;
typedef struct { unsigned st_dev; unsigned short st_ino, st_mode; short st_nlink, st_uid, st_gid; unsigned st_rdev;
                 long long st_size, st_atime_, st_mtime_, st_ctime_; } crt_stat64;

/* runtime */
CRT_IMPORT(int *, _errno, (void));
CRT_IMPORT(void *, malloc, (size_t));
CRT_IMPORT(void *, calloc, (size_t, size_t));
CRT_IMPORT(void *, realloc, (void *, size_t));
CRT_IMPORT(void, free, (void *));
CRT_IMPORT(size_t, _msize, (void *));
CRT_IMPORT(void *, _aligned_malloc, (size_t, size_t));
CRT_IMPORT(void, _aligned_free, (void *));
CRT_IMPORT(int, _callnewh, (size_t));
CRT_IMPORT(int, _set_new_mode, (int));
CRT_IMPORT(void, _initterm, (crt_pvfv *, crt_pvfv *));
CRT_IMPORT(int, _initterm_e, (crt_pifv *, crt_pifv *));
CRT_IMPORT(int, _initialize_onexit_table, (crt_onexit_table *));
CRT_IMPORT(int, _register_onexit_function, (crt_onexit_table *, crt_pvfv));
CRT_IMPORT(int, _execute_onexit_table, (crt_onexit_table *));
CRT_IMPORT(int, _crt_atexit, (crt_pvfv));
CRT_IMPORT(void, exit, (int));
CRT_IMPORT(int, _configure_narrow_argv, (int));
CRT_IMPORT(int, _configure_wide_argv, (int));
CRT_IMPORT(int *, __p___argc, (void));
CRT_IMPORT(char ***, __p___argv, (void));
CRT_IMPORT(unsigned short ***, __p___wargv, (void));
CRT_IMPORT(int, _initialize_narrow_environment, (void));
CRT_IMPORT(char ***, __p__environ, (void));
CRT_IMPORT(char *, getenv, (const char *));
CRT_IMPORT(int, _putenv, (const char *));
CRT_IMPORT(int, _putenv_s, (const char *, const char *));
CRT_IMPORT(uintptr_t, _beginthreadex, (void *, unsigned, unsigned (__stdcall *)(void *), void *, unsigned, unsigned *));
CRT_IMPORT(crt_sig, signal, (int, crt_sig));
CRT_IMPORT(int, raise, (int));
CRT_IMPORT(int, _seh_filter_exe, (unsigned long, void *));
CRT_IMPORT(int, _seh_filter_dll, (unsigned long, void *));
CRT_IMPORT(crt_inv_handler, _set_invalid_parameter_handler, (crt_inv_handler));
CRT_IMPORT(crt_inv_handler, _set_thread_local_invalid_parameter_handler, (crt_inv_handler));
CRT_IMPORT(void, _invalid_parameter_noinfo, (void));
CRT_IMPORT(void, _set_app_type, (int));
CRT_IMPORT(int, _set_fmode, (int));
CRT_IMPORT(int *, __p__commode, (void));
CRT_IMPORT(char *, _get_narrow_winmain_command_line, (void));
/* strings, conversion, utility */
/* strlen, strcmp, memset, memcpy, memmove are also defined by the stage-0 test CRT (shzcrt.c): their import-library
 * members would clash with those definitions, so these are looked up with GetProcAddress (crt_imp_init) instead */
static size_t (*crt_strlen)(const char *);
static int (*crt_strcmp)(const char *, const char *);
static void *(*crt_memset)(void *, int, size_t);
static void *(*crt_memcpy)(void *, const void *, size_t);
static void *(*crt_memmove)(void *, const void *, size_t);
CRT_IMPORT(int, strcpy_s, (char *, size_t, const char *));
CRT_IMPORT(int, wcsncmp, (const unsigned short *, const unsigned short *, size_t));
CRT_IMPORT(unsigned short, towlower, (unsigned short));
CRT_IMPORT(int, toupper, (int));
CRT_IMPORT(int, isalpha, (int));
CRT_IMPORT(int, atoi, (const char *));
CRT_IMPORT(int32_t, wcstol, (const unsigned short *, unsigned short **, int));
CRT_IMPORT(double, strtod, (const char *, char **));
CRT_IMPORT(void, qsort, (void *, size_t, size_t, int (*)(const void *, const void *)));
CRT_IMPORT(int, __stdio_common_vsprintf, (uint64_t, char *, size_t, const char *, void *, va_list));
CRT_IMPORT(int, __stdio_common_vsnprintf_s, (uint64_t, char *, size_t, size_t, const char *, void *, va_list));
CRT_IMPORT(int, __stdio_common_vswprintf, (uint64_t, unsigned short *, size_t, const unsigned short *, void *, va_list));
CRT_IMPORT(int, __stdio_common_vsscanf, (uint64_t, const char *, size_t, const char *, void *, va_list));
CRT_IMPORT(unsigned, ___lc_codepage_func, (void));
CRT_IMPORT(int, _configthreadlocale, (int));
CRT_IMPORT(char *, setlocale, (int, const char *));
/* math and floating-point environment */
CRT_IMPORT(double, exp, (double));
CRT_IMPORT(double, log, (double));
CRT_IMPORT(double, log10, (double));
CRT_IMPORT(double, pow, (double, double));
CRT_IMPORT(float, powf, (float, float));
CRT_IMPORT(double, sin, (double));
CRT_IMPORT(double, cos, (double));
CRT_IMPORT(double, atan2, (double, double));
CRT_IMPORT(double, sqrt, (double));
CRT_IMPORT(double, ceil, (double));
CRT_IMPORT(float, ceilf, (float));
CRT_IMPORT(float, floorf, (float));
CRT_IMPORT(float, roundf, (float));
CRT_IMPORT(int32_t, lrintf, (float));
CRT_IMPORT(int32_t, lround, (double));
CRT_IMPORT(int32_t, lroundf, (float));
CRT_IMPORT(double, fma, (double, double, double));
CRT_IMPORT(double, fmod, (double, double));
CRT_IMPORT(double, tgamma, (double));
CRT_IMPORT(double, erf, (double));
CRT_IMPORT(int, _fpclass, (double));
CRT_IMPORT(unsigned, _controlfp, (unsigned, unsigned));
CRT_IMPORT(int, _controlfp_s, (unsigned *, unsigned, unsigned));
CRT_IMPORT(int, fesetround, (int));
CRT_IMPORT(int, fegetround, (void));
CRT_IMPORT(double, rint, (double));
CRT_IMPORT(unsigned, _clearfp, (void));
CRT_IMPORT(unsigned, _statusfp, (void));
/* time */
CRT_IMPORT(long long, _time64, (long long *));
CRT_IMPORT(int, _gmtime64_s, (crt_tm *, const long long *));
CRT_IMPORT(long long, _mkgmtime64, (crt_tm *));
CRT_IMPORT(size_t, strftime, (char *, size_t, const char *, const crt_tm *));
CRT_IMPORT(int32_t, clock, (void));
/* stdio and low-level I/O */
CRT_IMPORT(void *, __acrt_iob_func, (unsigned));
CRT_IMPORT(int, __stdio_common_vfprintf, (uint64_t, void *, const char *, void *, va_list));
CRT_IMPORT(int, __stdio_common_vfscanf, (uint64_t, void *, const char *, void *, va_list));
CRT_IMPORT(void *, fopen, (const char *, const char *));
CRT_IMPORT(int, fopen_s, (void **, const char *, const char *));
CRT_IMPORT(int, fclose, (void *));
CRT_IMPORT(size_t, fwrite, (const void *, size_t, size_t, void *));
CRT_IMPORT(size_t, fread, (void *, size_t, size_t, void *));
CRT_IMPORT(int, fputs, (const char *, void *));
CRT_IMPORT(char *, fgets, (char *, int, void *));
CRT_IMPORT(int, fgetc, (void *));
CRT_IMPORT(int, ungetc, (int, void *));
CRT_IMPORT(int, fseek, (void *, int32_t, int));
CRT_IMPORT(int32_t, ftell, (void *));
CRT_IMPORT(int, feof, (void *));
CRT_IMPORT(int, fflush, (void *));
CRT_IMPORT(int, _fileno, (void *));
CRT_IMPORT(int, setvbuf, (void *, char *, int, size_t));
CRT_IMPORT(unsigned short, fputwc, (unsigned short, void *));
CRT_IMPORT(int, _open, (const char *, int, ...));
CRT_IMPORT(int, _wsopen_dispatch, (const unsigned short *, int, int, int, int *, int));
CRT_IMPORT(int, _read, (int, void *, unsigned));
CRT_IMPORT(int, _write, (int, const void *, unsigned));
CRT_IMPORT(int32_t, _lseek, (int, int32_t, int));
CRT_IMPORT(int, _close, (int));
CRT_IMPORT(int, _chsize, (int, int32_t));
CRT_IMPORT(int, _setmode, (int, int));
CRT_IMPORT(intptr_t, _get_osfhandle, (int));
CRT_IMPORT(int, _open_osfhandle, (intptr_t, int));
CRT_IMPORT(int, _dup, (int));
CRT_IMPORT(int, _isatty, (int));
CRT_IMPORT(void *, _fdopen, (int, const char *));
CRT_IMPORT(int, remove, (const char *));
CRT_IMPORT(int, rename, (const char *, const char *));
CRT_IMPORT(int, _access, (const char *, int));
CRT_IMPORT(int, _stat64, (const char *, crt_stat64 *));
CRT_IMPORT(intptr_t, _findfirst64, (const char *, crt_finddata64 *));
CRT_IMPORT(int, _findclose, (intptr_t));
CRT_IMPORT(void *, tmpfile, (void));
CRT_IMPORT(char *, _getcwd, (char *, int));

/* call first in main(): resolves the functions above in the ucrtbase.dll the import table loaded */
static inline int crt_imp_init(void)
{
    HMODULE u = GetModuleHandleW(L"ucrtbase.dll");
    if (!u) return 0;
    crt_strlen = (size_t (*)(const char *))(void *)GetProcAddress(u, "strlen");
    crt_strcmp = (int (*)(const char *, const char *))(void *)GetProcAddress(u, "strcmp");
    crt_memset = (void *(*)(void *, int, size_t))(void *)GetProcAddress(u, "memset");
    crt_memcpy = (void *(*)(void *, const void *, size_t))(void *)GetProcAddress(u, "memcpy");
    crt_memmove = (void *(*)(void *, const void *, size_t))(void *)GetProcAddress(u, "memmove");
    return crt_strlen && crt_strcmp && crt_memset && crt_memcpy && crt_memmove;
}

/* printf-style helpers over the imported engines (the headers' inline wrappers do the same in MSVC programs) */
#define CRT_PRINTF_OPTS (2ull | 32ull)            /* _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR | STANDARD_ROUNDING */
static inline int crt_snprintf(char *b, size_t n, const char *f, ...)
{
    va_list ap;
    int r;
    va_start(ap, f);
    r = crt___stdio_common_vsprintf(CRT_PRINTF_OPTS, b, n, f, 0, ap);
    va_end(ap);
    return r;
}
static inline int crt_fprintf(void *fp, const char *f, ...)
{
    va_list ap;
    int r;
    va_start(ap, f);
    r = crt___stdio_common_vfprintf(CRT_PRINTF_OPTS, fp, f, 0, ap);
    va_end(ap);
    return r;
}
static inline int crt_sscanf(const char *s, const char *f, ...)
{
    va_list ap;
    int r;
    va_start(ap, f);
    r = crt___stdio_common_vsscanf(0, s, (size_t)-1, f, 0, ap);
    va_end(ap);
    return r;
}
static inline int crt_fscanf(void *fp, const char *f, ...)
{
    va_list ap;
    int r;
    va_start(ap, f);
    r = crt___stdio_common_vfscanf(0, fp, f, 0, ap);
    va_end(ap);
    return r;
}
#endif
