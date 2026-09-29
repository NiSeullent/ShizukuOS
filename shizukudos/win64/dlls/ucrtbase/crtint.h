/* SPDX-License-Identifier: GPL-2.0-only
 * Internal header of the Shizuku Universal C runtime (ucrtbase.dll). Own implementation written from the C standard,
 * the POSIX specification and Microsoft's public CRT documentation; no Microsoft or third-party CRT source is used.
 *
 * The "core" translation units (number formatting/parsing, printf/scanf engines, math, strings, conversions, time
 * arithmetic) are written against this header only, so they also compile for the Linux host (-DSHZ_HOST_TEST) where
 * shizukudos/win64/tests/host_ucrt compares them with glibc and Python on millions of cases. Win64 is LLP64: MSVC `long`
 * is 32 bits and `wchar_t` is 16 bits, hence crt_long and wchar16 instead of the host's types. MSVC `long double` is
 * the 64-bit double, so no exported function uses the C `long double` type.
 */
#ifndef SHZ_CRTINT_H
#define SHZ_CRTINT_H
/* mingw-w64's <stddef.h> declares a few CRT functions dllimport (via crtdefs.h); keep those declarations out of the
 * way of the definitions below */
#define _errno shz_mingw_decl__errno
#define __threadid shz_mingw_decl___threadid
#define __threadhandle shz_mingw_decl___threadhandle
#define __doserrno shz_mingw_decl___doserrno
#define _invalid_parameter shz_mingw_decl__invalid_parameter
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#undef _errno
#undef __threadid
#undef __threadhandle
#undef __doserrno
#undef _invalid_parameter

#ifdef SHZ_HOST_TEST
#define DLLAPI
#define CRTAPI
#else
#define DLLAPI __declspec(dllexport)
#define CRTAPI __cdecl
#endif
#define CRT_NORETURN __attribute__((noreturn))

typedef unsigned short wchar16;          /* Windows wchar_t / wint_t code unit */
typedef int32_t crt_long;                /* Windows long */
typedef uint32_t crt_ulong;
typedef int64_t crt_time64;
typedef unsigned short crt_wint;
typedef int crt_errno_t;
#define CRT_WEOF ((crt_wint)0xffff)
#define CRT_EOF (-1)
#define CRT_LONG_MAX 2147483647
#define CRT_LONG_MIN (-2147483647 - 1)
#define CRT_ULONG_MAX 4294967295u
#define CRT_INT_MAX 2147483647

/* errno values of the Microsoft C runtime (errno.h) */
#define CRT_EPERM 1
#define CRT_ENOENT 2
#define CRT_ESRCH 3
#define CRT_EINTR 4
#define CRT_EIO 5
#define CRT_ENXIO 6
#define CRT_E2BIG 7
#define CRT_ENOEXEC 8
#define CRT_EBADF 9
#define CRT_ECHILD 10
#define CRT_EAGAIN 11
#define CRT_ENOMEM 12
#define CRT_EACCES 13
#define CRT_EFAULT 14
#define CRT_EBUSY 16
#define CRT_EEXIST 17
#define CRT_EXDEV 18
#define CRT_ENODEV 19
#define CRT_ENOTDIR 20
#define CRT_EISDIR 21
#define CRT_EINVAL 22
#define CRT_ENFILE 23
#define CRT_EMFILE 24
#define CRT_ENOTTY 25
#define CRT_EFBIG 27
#define CRT_ENOSPC 28
#define CRT_ESPIPE 29
#define CRT_EROFS 30
#define CRT_EMLINK 31
#define CRT_EPIPE 32
#define CRT_EDOM 33
#define CRT_ERANGE 34
#define CRT_EDEADLK 36
#define CRT_ENAMETOOLONG 38
#define CRT_ENOLCK 39
#define CRT_ENOSYS 40
#define CRT_ENOTEMPTY 41
#define CRT_EILSEQ 42
#define CRT_STRUNCATE 80
#define CRT_EOVERFLOW 132

/* printf / scanf option bits (corecrt_stdio_config.h, documented ABI of __stdio_common_*) */
#define PRINTF_LEGACY_VSPRINTF_NULL_TERMINATION (1ull << 0)
#define PRINTF_STANDARD_SNPRINTF_BEHAVIOR (1ull << 1)
#define PRINTF_LEGACY_WIDE_SPECIFIERS (1ull << 2)
#define PRINTF_LEGACY_MSVCRT_COMPATIBILITY (1ull << 3)
#define PRINTF_LEGACY_THREE_DIGIT_EXPONENTS (1ull << 4)
#define PRINTF_STANDARD_ROUNDING (1ull << 5)
#define SCANF_SECURECRT (1ull << 0)
#define SCANF_LEGACY_WIDE_SPECIFIERS (1ull << 1)
#define SCANF_LEGACY_MSVCRT_COMPATIBILITY (1ull << 2)

/* ---------------------------------------------------------------- per-thread state and error reporting */
struct crt_tm { int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst; };
typedef void (CRTAPI *crt_inv_handler)(const wchar16 *, const wchar16 *, const wchar16 *, unsigned, uintptr_t);
typedef void (CRTAPI *crt_sighandler)(int);
typedef struct crt_ptd {
    int err;
    unsigned long doserr;
    unsigned rand_next;
    char *strtok_ctx;
    wchar16 *wcstok_ctx;
    crt_inv_handler inv_handler;          /* _set_thread_local_invalid_parameter_handler */
    crt_sighandler sig_fpe, sig_ill, sig_segv; /* per-thread signals, as in the UCRT */
    int locale_mode;                      /* _configthreadlocale */
    struct crt_tm tm_buf;
    char time_buf[32];
    wchar16 wtime_buf[32];
    char errbuf[96];
    wchar16 werrbuf[96];
    void *thread_arg;                     /* _beginthread[ex] bookkeeping */
    void *thread_start;
    int thread_ex;
    void *thread_handle;
    void *cur_exception;                  /* terminate / unexpected bookkeeping shared with vcruntime is not here */
    void (*terminate_handler)(void);
} crt_ptd;
crt_ptd *crt_getptd(void);               /* never null (falls back to a static block if memory is exhausted) */
int *crt_errno_ptr(void);
unsigned long *crt_doserrno_ptr(void);
#define crt_set_errno(e) (*crt_errno_ptr() = (e))
#define crt_get_errno() (*crt_errno_ptr())
/* The invalid-parameter path: calls the thread's or the global handler, and terminates the process with
 * STATUS_INVALID_CRUNTIME_PARAMETER when none is installed (Microsoft's documented default). */
void crt_invalid_parameter(void);
#define CRT_VALIDATE(cond, err, ret) do { if (!(cond)) { crt_set_errno(err); crt_invalid_parameter(); return (ret); } } while (0)
#define CRT_VALIDATE_NORET(cond, err) do { if (!(cond)) { crt_set_errno(err); crt_invalid_parameter(); return; } } while (0)
void crt_dosmaperr(unsigned long oserr);   /* Win32 error -> errno + _doserrno */

/* global locks (Win64: SRW locks; host: no-ops) */
enum { CRT_LOCK_HEAP, CRT_LOCK_ENV, CRT_LOCK_ONEXIT, CRT_LOCK_STREAMS, CRT_LOCK_FDS, CRT_LOCK_TIME, CRT_LOCK_SIGNAL, CRT_LOCK_MISC,
       CRT_LOCK_COUNT };
void crt_lock(int which);
void crt_unlock(int which);

/* ---------------------------------------------------------------- memory (heap.c, host: libc) */
void *crt_malloc(size_t n);
void crt_free(void *p);
void *crt_realloc(void *p, size_t n);
void *crt_calloc(size_t n, size_t m);

/* ---------------------------------------------------------------- floating point helpers (fltfmt.c / fltparse.c) */
typedef union { double d; uint64_t u; } crt_dbits;
typedef union { float f; uint32_t u; } crt_fbits;
static inline uint64_t crt_d2u(double d) { crt_dbits b; b.d = d; return b.u; }
static inline double crt_u2d(uint64_t u) { crt_dbits b; b.u = u; return b.d; }
static inline uint32_t crt_f2u(float f) { crt_fbits b; b.f = f; return b.u; }
static inline float crt_u2f(uint32_t u) { crt_fbits b; b.u = u; return b.f; }

/* Rounding direction for decimal output: 0 nearest-even, 1 toward -inf, 2 toward +inf, 3 toward zero, 4 half away
 * from zero (the legacy UCRT rule for exactly representable ties). */
enum { CRT_RND_NEAREST = 0, CRT_RND_DOWN = 1, CRT_RND_UP = 2, CRT_RND_ZERO = 3, CRT_RND_HALF_AWAY = 4 };
int crt_current_rounding(void);          /* MXCSR RC field mapped to the enum above */

/* Exact decimal digits of |v| (finite): mode 'f' -> `prec` digits after the decimal point, mode 'e' -> prec+1
 * significant digits. Writes the digit characters (no point) to buf, returns the digit count and sets *exp10 so the
 * value is d1.d2d3... * 10^*exp10 ('e') or the integer part has *exp10 digits ('f'). rnd is a CRT_RND_* value, neg
 * the sign of v for directed rounding. buf must hold prec + 340 bytes. */
int crt_dtoa_fixed(double v, int prec, char mode, int rnd, int neg, char *buf, int *exp10);

/* Correctly rounded decimal/hex string -> double/float. Returns the value, sets *consumed to the number of code units
 * used (0 when nothing was parsed) and *range_err when the result overflowed or underflowed. `get` abstracts
 * narrow/wide input: it returns the code unit at index i (0 past the end). */
typedef unsigned (*crt_getch_fn)(const void *s, size_t i);
double crt_strtod_core(const void *s, crt_getch_fn get, size_t *consumed, int *range_err, int want_float);
unsigned crt_get_narrow(const void *s, size_t i);
unsigned crt_get_wide(const void *s, size_t i);

/* ---------------------------------------------------------------- formatting engine (printf.c) */
typedef struct crt_out {
    int wide;                                            /* sink takes 16-bit code units */
    int (*put)(struct crt_out *o, const void *units, size_t n);   /* returns 0, or -1 to stop (buffer full / I/O error) */
    size_t count;                                        /* units produced so far (including ones the sink dropped) */
    int stopped;
    void *ctx;
} crt_out;
/* Returns the number of units produced or -1 (format error: errno set, invalid parameter raised). */
int crt_format(crt_out *o, uint64_t options, const void *format, int wide_format, va_list *ap);
int crt_format_p(crt_out *o, uint64_t options, const void *format, int wide_format, va_list *ap);

/* ---------------------------------------------------------------- scanning engine (scanf.c) */
typedef struct crt_in {
    int (*get)(struct crt_in *in);                        /* next code unit or -1 at end */
    void (*unget)(struct crt_in *in, int c);
    void *ctx;
    size_t pos, lim;
    const void *str;
} crt_in;
int crt_scan(crt_in *in, uint64_t options, const void *format, int wide_format, va_list *ap);

/* ---------------------------------------------------------------- misc shared helpers */
int crt_wctomb_c(char *out, unsigned wc);                /* C locale: 1 byte or -1 (EILSEQ) */
/* Integer parsing shared by strtol & co. and scanf: base 0/2..36, `bits` 32 or 64. Returns the (wrapped) value;
 * *range_err on overflow, *consumed = 0 when no digits. */
uint64_t crt_strtoint_core(const void *s, crt_getch_fn get, size_t *consumed, int base, int is_unsigned, int bits, int *range_err);
size_t crt_strlen(const char *s);
size_t crt_wcslen(const wchar16 *s);
void *crt_memcpy(void *d, const void *s, size_t n);
void *crt_memset(void *d, int c, size_t n);
int crt_toupper_c(int c);
int crt_tolower_c(int c);
int crt_isspace_c(int c);
unsigned crt_towlower_c(unsigned c);
unsigned crt_towupper_c(unsigned c);

/* time arithmetic (time.c) */
int crt_gmtime_core(crt_time64 t, struct crt_tm *tm);       /* 0 or errno */
crt_time64 crt_mkgmtime_core(struct crt_tm *tm);            /* normalises *tm; -1 on range error */
size_t crt_strftime_core(void *out, size_t max, int wide, const void *fmt, int wide_fmt, const struct crt_tm *tm, long tz_bias_min,
                         const char *tzname);
#endif
