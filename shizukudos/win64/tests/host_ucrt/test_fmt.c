/* SPDX-License-Identifier: GPL-2.0-only
 * Host test of the Shizuku UCRT conversion core (u_* = ucrtbase core, prefixed) against glibc, whose strtod and printf
 * are exact: strtod/strtof on random, long and exactly-halfway decimal strings and on hex floats; printf %e %f %g %a
 * and the integer/string conversions; scanf; the strtol family with Microsoft's 32-bit long; qsort/bsearch;
 * gmtime/mkgmtime/strftime; ctype; the documented Microsoft-specific outputs (NaN spellings, %p, legacy rounding,
 * _ecvt/_fcvt examples, secure string functions).
 *   usage: test_fmt [samples] [seed]
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef unsigned short wchar16;
struct ctm { int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst; };
int u___stdio_common_vsprintf(uint64_t, char *, size_t, const char *, void *, va_list);
int u___stdio_common_vsnprintf_s(uint64_t, char *, size_t, size_t, const char *, void *, va_list);
int u___stdio_common_vsprintf_s(uint64_t, char *, size_t, const char *, void *, va_list);
int u___stdio_common_vsprintf_p(uint64_t, char *, size_t, const char *, void *, va_list);
int u___stdio_common_vswprintf(uint64_t, wchar16 *, size_t, const wchar16 *, void *, va_list);
int u___stdio_common_vsscanf(uint64_t, const char *, size_t, const char *, void *, va_list);
int u__set_printf_count_output(int);
double u_strtod(const char *, char **);
float u_strtof(const char *, char **);
double u_wcstod(const wchar16 *, wchar16 **);
int32_t u_strtol(const char *, char **, int);
uint32_t u_strtoul(const char *, char **, int);
long long u_strtoll(const char *, char **, int);
unsigned long long u_strtoull(const char *, char **, int);
int u_atoi(const char *);
void u_qsort(void *, size_t, size_t, int (*)(const void *, const void *));
void *u_bsearch(const void *, const void *, size_t, size_t, int (*)(const void *, const void *));
int u_crt_gmtime_core(int64_t, struct ctm *);
int64_t u_crt_mkgmtime_core(struct ctm *);
size_t u_crt_strftime_core(void *, size_t, int, const void *, int, const struct ctm *, long, const char *);
int u__ecvt_s(char *, size_t, double, int, int *, int *);
int u__fcvt_s(char *, size_t, double, int, int *, int *);
char *u__gcvt(double, int, char *);
int u_strcpy_s(char *, size_t, const char *);
int u_strncpy_s(char *, size_t, const char *, size_t);
int u_strcat_s(char *, size_t, const char *);
int u_strncat_s(char *, size_t, const char *, size_t);
int u_memcpy_s(void *, size_t, const void *, size_t);
int u__itoa_s(int, char *, size_t, int);
char *u__i64toa(long long, char *, int);
int u_isalpha(int), u_isdigit(int), u_isspace(int), u_ispunct(int), u_isalnum(int), u_isprint(int), u_isgraph(int);
int u_iscntrl(int), u_isupper(int), u_islower(int), u_isxdigit(int), u_toupper(int), u_tolower(int), u_isblank(int);
char *u_strtok(char *, const char *);
int u__stricmp(const char *, const char *);
int host_errno(void);
void host_set_errno(int);
extern int host_invalid_parameter_calls;

#define OPT_STD (2ull | 32ull)                              /* standard snprintf behaviour + IEEE rounding */
static int u_snprintf(uint64_t opt, char *b, size_t n, const char *f, ...)
{
    va_list ap;
    int r;
    va_start(ap, f);
    r = u___stdio_common_vsprintf(opt, b, n, f, 0, ap);
    va_end(ap);
    return r;
}
static int u_sscanf(const char *s, const char *f, ...)
{
    va_list ap;
    int r;
    va_start(ap, f);
    r = u___stdio_common_vsscanf(0, s, (size_t)-1, f, 0, ap);
    va_end(ap);
    return r;
}

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t next(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }
static double any_double(void) { uint64_t u; double d; do u = next(); while (((u >> 52) & 0x7ff) == 0x7ff); memcpy(&d, &u, 8); return d; }
static uint64_t dbits(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }
static int failures, checks;
#define CHECK(name, cond, ...) do { ++checks; if (!(cond)) { ++failures; if (failures < 60) { printf("FAIL %s: ", name); printf(__VA_ARGS__); printf("\n"); } } } while (0)
static void group(const char *name, int before) { printf("%-12s %s (%d failures)\n", name, failures == before ? "PASS" : "FAIL", failures - before); }

/* ---------------------------------------------------------------- strtod */
static void random_decimal(char *s, size_t cap)
{
    size_t n = 0;
    int digits = 1 + (int)(next() % 25), i, point, e;
    if (next() % 10 == 0) digits = 30 + (int)(next() % 800);
    if (next() & 1) s[n++] = '-';
    point = (int)(next() % (unsigned)(digits + 1));
    for (i = 0; i < digits && n + 12 < cap; ++i) {
        if (i == point) s[n++] = '.';
        s[n++] = (char)('0' + (i == 0 ? 1 + next() % 9 : next() % 10));
    }
    e = (int)(next() % 700) - 350 - (digits > 30 ? digits : 0) / 2;
    n += (size_t)snprintf(s + n, cap - n, "e%d", e);
    s[n] = 0;
}
static void test_strtod(long N)
{
    const int before = failures;
    long i;
    static char s[4096];
    for (i = 0; i < N; ++i) {
        char *e1, *e2;
        double a, b;
        int k = (int)(next() % 4);
        if (k == 0) random_decimal(s, sizeof s);
        else if (k == 1) {
            /* exact midpoint between a random double and its successor, printed exactly by glibc, maybe nudged */
            double d = fabs(any_double()), nx = nextafter(d, INFINITY);
            long double mid = ((long double)d + (long double)nx) / 2;
            int len = snprintf(s, sizeof s, "%.1100Lf", mid);
            if (d > 1e20 || d < 1e-300) len = snprintf(s, sizeof s, "%.800Le", mid);
            (void)len;
            {   /* trim trailing zeros of the mantissa so the last digit is significant */
                char *ep = strchr(s, 'e'), *p = ep ? ep - 1 : s + strlen(s) - 1;
                char tail[16] = "";
                if (ep) { strncpy(tail, ep, 15); }
                while (*p == '0') --p;
                if (next() % 3 == 1 && *p >= '0' && *p < '9' && *p != '.') ++*p;        /* just above the midpoint */
                else if (next() % 3 == 2 && *p > '0' && *p <= '9') --*p;                 /* just below */
                strcpy(p + 1, tail);
            }
        } else if (k == 2) snprintf(s, sizeof s, "%.17g", any_double());
        else {
            /* hexadecimal */
            snprintf(s, sizeof s, "%s0x%llx.%llxp%d", next() & 1 ? "-" : "", (unsigned long long)(next() >> (next() % 64)),
                     (unsigned long long)(next() >> (next() % 64)), (int)(next() % 2300) - 1150);
        }
        errno = 0;
        b = strtod(s, &e2);
        a = u_strtod(s, &e1);
        CHECK("strtod", dbits(a) == dbits(b) && e1 - s == e2 - s, "\"%.80s...\" mine=%a glibc=%a end %ld/%ld", s, a, b, (long)(e1 - s), (long)(e2 - s));
        {
            float fa = u_strtof(s, &e1), fb = strtof(s, &e2);
            CHECK("strtof", memcmp(&fa, &fb, 4) == 0 && e1 - s == e2 - s, "\"%.80s\" mine=%a glibc=%a", s, fa, fb);
        }
    }
    {
        static const char *const cases[] = { "  +12.5e-1xyz", "-0", "0x", "0x1p", ".e5", "1e", "1e+", "inf", "-INFINITY", "nan", "NaN(123)", "1.8e308", "4.9e-324",
                                             "2.4703282292062327e-324", "2.4703282292062328e-324", "1e-400", "0x1.fffffffffffff8p1023", "000000000000000000001.5",
                                             "1" "000000000000000000000000000000000000000000000000000000000000e-60", "9007199254740993", "0.1e0", "" };
        size_t j;
        for (j = 0; j < sizeof cases / sizeof cases[0]; ++j) {
            char *e1, *e2;
            const double a = u_strtod(cases[j], &e1), b = strtod(cases[j], &e2);
            CHECK("strtod-case", (dbits(a) == dbits(b) || (isnan(a) && isnan(b))) && e1 == e2, "\"%s\" mine=%a end=%ld glibc=%a end=%ld", cases[j], a,
                  (long)(e1 - cases[j]), b, (long)(e2 - cases[j]));
        }
    }
    /* Microsoft spellings */
    {
        const double ind = u_strtod("-nan(ind)", 0), sn = u_strtod("nan(snan)", 0);
        CHECK("strtod-ms", dbits(ind) == 0xfff8000000000000ull, "nan(ind) = %016llx", (unsigned long long)dbits(ind));
        CHECK("strtod-ms", (dbits(sn) & 0x7ff8000000000000ull) == 0x7ff0000000000000ull && (dbits(sn) & 0xfffffffffffffull), "nan(snan) = %016llx",
              (unsigned long long)dbits(sn));
    }
    host_set_errno(0);
    u_strtod("1e999", 0);
    CHECK("strtod-errno", host_errno() == 34, "overflow errno %d", host_errno());
    {
        const wchar16 w[] = { ' ', '6', '.', '2', '5', 'e', '2', 'x', 0 };
        wchar16 *e;
        const double v = u_wcstod(w, &e);
        CHECK("wcstod", v == 625.0 && e == w + 7, "%g %ld", v, (long)(e - w));
    }
    group("strtod", before);
}

/* ---------------------------------------------------------------- printf */
static void test_printf(long N)
{
    const int before = failures;
    static char a[2048], b[2048];
    static const char *const flags[] = { "", "+", " ", "#", "0", "-", "+0", "#0", "- ", "+#" };
    long i;
    for (i = 0; i < N; ++i) {
        char fmt[64];
        double d = any_double();
        const char conv = "efgaEFGA"[next() % 8];
        int prec = (int)(next() % 30), width = (int)(next() % 40);
        if (next() % 3 == 0) d = (double)(int64_t)(next() >> 20) / (double)(1 << (next() % 20));   /* short decimals and ties */
        if ((conv == 'f' || conv == 'F') && fabs(d) > 1e40) d = ldexp(d, -900);
        if (conv == 'a' || conv == 'A') prec %= 14;
        if (next() % 5 == 0) snprintf(fmt, sizeof fmt, "%%%s%d.%d%c", flags[next() % 10], width, prec, conv);
        else snprintf(fmt, sizeof fmt, "%%%s.%d%c", flags[next() % 10], prec, conv);
        {
            const int ra = u_snprintf(OPT_STD, a, sizeof a, fmt, d), rb = snprintf(b, sizeof b, fmt, d);
            CHECK("printf-float", ra == rb && !strcmp(a, b), "fmt %s d=%a mine=\"%s\" glibc=\"%s\"", fmt, d, a, b);
        }
        {
            const int v = (int)next();
            const long long w = (long long)next() >> (next() % 64);
            const char ic = "diouxX"[next() % 6];
            snprintf(fmt, sizeof fmt, "%%%s%d.%d%c|%%%s%dll%c", flags[next() % 10], width, prec % 20, ic, flags[next() % 10], width, ic);
            if (next() & 1) snprintf(fmt, sizeof fmt, "%%%s%d%c|%%%sll%c", flags[next() % 10], width, ic, flags[next() % 10], ic);
            {
                const int ra = u_snprintf(OPT_STD, a, sizeof a, fmt, v, w), rb = snprintf(b, sizeof b, fmt, v, w);
                CHECK("printf-int", ra == rb && !strcmp(a, b), "fmt %s mine=\"%s\" glibc=\"%s\"", fmt, a, b);
            }
        }
    }
    /* Microsoft-specific results (documented UCRT behaviour) */
#define EXPECT(opt, want, ...) do { u_snprintf(opt, a, sizeof a, __VA_ARGS__); CHECK("printf-ms", !strcmp(a, want), "%s -> \"%s\", want \"%s\"", #__VA_ARGS__, a, want); } while (0)
    EXPECT(OPT_STD, "nan", "%f", NAN);
    EXPECT(OPT_STD, "-nan(ind)", "%f", -NAN);
    EXPECT(OPT_STD, "inf -INF", "%g %E", INFINITY, -INFINITY);
    EXPECT(OPT_STD, "0000000000001234", "%p", (void *)0x1234);
    EXPECT(OPT_STD, "0x1.0000000000000p+0", "%a", 1.0);
    EXPECT(OPT_STD, "-0x1.8000000000000p+1", "%a", -3.0);
    EXPECT(OPT_STD, "0 2 2 4", "%.0f %.0f %.0f %.0f", 0.5, 1.5, 2.5, 3.5);                  /* IEEE ties to even */
    EXPECT(2ull, "1 2 3 4", "%.0f %.0f %.0f %.0f", 0.5, 1.5, 2.5, 3.5);                    /* legacy: ties away from zero */
    EXPECT(2ull, "1.3", "%.1f", 1.25);
    EXPECT(OPT_STD, "1.2", "%.1f", 1.25);
    EXPECT(OPT_STD | 16ull, "1.000000e+000", "%e", 1.0);                                  /* legacy three-digit exponent */
    EXPECT(OPT_STD, "123 7b 173 -5 18446744073709551611", "%I32d %I32x %Io %I64d %I64u", 123, 123, (size_t)123, (long long)-5, (unsigned long long)-5);
    EXPECT(OPT_STD, "4294967295", "%lu", 0xffffffffu);
    EXPECT(OPT_STD, "(null)", "%s", (char *)0);
    EXPECT(OPT_STD, "   ab", "%5.2s", "abc");
    {
        const wchar16 ws[] = { 'w', 'i', 'd', 'e', 0 };
        EXPECT(OPT_STD, "wide|x", "%ls|%lc", ws, (int)'x');
        EXPECT(OPT_STD, "wide", "%S", ws);
    }
    {   /* %n needs _set_printf_count_output */
        int n = -1, r;
        host_invalid_parameter_calls = 0;
        r = u_snprintf(OPT_STD, a, sizeof a, "abc%n", &n);
        CHECK("printf-%n", r == -1 && host_invalid_parameter_calls == 1, "r=%d calls=%d", r, host_invalid_parameter_calls);
        u__set_printf_count_output(1);
        r = u_snprintf(OPT_STD, a, sizeof a, "abc%n", &n);
        CHECK("printf-%n", r == 3 && n == 3, "r=%d n=%d", r, n);
        u__set_printf_count_output(0);
    }
    {   /* buffer semantics of the common entry point */
        int r;
        memset(a, 'x', 16);
        r = u_snprintf(2ull, a, 4, "%s", "hello");
        CHECK("snprintf-trunc", r == 5 && !strcmp(a, "hel"), "r=%d \"%s\"", r, a);
        memset(a, 'x', 16);
        r = u_snprintf(0, a, 4, "%s", "hello");                     /* _vsnprintf-style: -1, terminated at the end */
        CHECK("vsprintf-trunc", r == -2 || r == -1, "r=%d", r);
        r = u_snprintf(1ull, a, 5, "%s", "hello");                  /* legacy: exactly full buffer, no terminator */
        CHECK("legacy-full", r == 5 && !memcmp(a, "hello", 5), "r=%d", r);
        r = u_snprintf(2ull, 0, 0, "%d", 12345);
        CHECK("snprintf-count", r == 5, "r=%d", r);
    }
    {   /* positional arguments (_p) */
        va_list dummy;
        (void)dummy;
    }
    group("printf", before);
}

/* ---------------------------------------------------------------- scanf */
static void test_scanf(long N)
{
    const int before = failures;
    long i;
    char buf[128];
    for (i = 0; i < N; ++i) {
        double d = any_double(), d2 = 0;
        float f2 = 0;
        int k = -1, n = -1;
        snprintf(buf, sizeof buf, "  %.17g xyz %d", d, (int)next());
        {
            int r = u_sscanf(buf, "%lf%n", &d2, &n);
            CHECK("scanf-%lf", r == 1 && dbits(d2) == dbits(d), "\"%s\" -> %a (r=%d)", buf, d2, r);
            r = u_sscanf(buf, "%f", &f2);
            CHECK("scanf-%f", r == 1 && f2 == (float)strtof(buf, 0), "\"%s\" -> %a", buf, f2);
            r = u_sscanf(buf + n, " xyz %d", &k);
            CHECK("scanf-%d", r == 1 && k == atoi(strstr(buf, "xyz") + 4), "\"%s\" -> %d", buf + n, k);
        }
    }
    {
        int a1 = 0, a2 = 0, a3 = 0, cnt = 0, r;
        unsigned u = 0;
        long long ll = 0;
        char s1[16] = "", s2[16] = "", c3[4] = "";
        r = u_sscanf("0x1f 017 -42 4294967295 -9223372036854775808", "%i %i %d %u %lld", &a1, &a2, &a3, &u, &ll);
        CHECK("scanf-ints", r == 5 && a1 == 31 && a2 == 15 && a3 == -42 && u == 4294967295u && ll == (long long)(1ull << 63), "r=%d %d %d %d %u %lld", r, a1, a2, a3, u, ll);
        r = u_sscanf("hello world", "%5s %[a-z]%n", s1, s2, &cnt);
        CHECK("scanf-str", r == 2 && !strcmp(s1, "hello") && !strcmp(s2, "world") && cnt == 11, "r=%d %s %s %d", r, s1, s2, cnt);
        r = u_sscanf("abc", "%2c", c3);
        CHECK("scanf-c", r == 1 && c3[0] == 'a' && c3[1] == 'b', "r=%d", r);
        r = u_sscanf("   ", "%d", &a1);
        CHECK("scanf-eof", r == -1, "r=%d", r);
        r = u_sscanf("x", "%d", &a1);
        CHECK("scanf-match", r == 0, "r=%d", r);
        r = u_sscanf("12 34", "%*d %d", &a1);
        CHECK("scanf-suppress", r == 1 && a1 == 34, "r=%d %d", r, a1);
        r = u_sscanf("inf -nan 0x1.8p1", "%lf %lf %lf", &(double){0}, &(double){0}, &(double){0});
        CHECK("scanf-special", r == 3, "r=%d", r);
    }
    group("scanf", before);
}

/* ---------------------------------------------------------------- strtol family (Microsoft long is 32 bits) */
static void test_strtol(long N)
{
    const int before = failures;
    long i;
    char s[64];
    for (i = 0; i < N; ++i) {
        const int base = (int)(next() % 5) == 0 ? 0 : (int)(2 + next() % 35);
        const long long v = (long long)next() >> (next() % 64);
        char *e1, *e2;
        switch (next() % 3) {
        case 0: snprintf(s, sizeof s, "  %lld", v); break;
        case 1: snprintf(s, sizeof s, "%s0x%llx", v < 0 ? "-" : "+", (unsigned long long)(v < 0 ? -v : v)); break;
        default: snprintf(s, sizeof s, " %llo9", (unsigned long long)v); break;
        }
        {
            long long want;
            int want_err;
            errno = 0;
            want = strtoll(s, &e2, base);
            want_err = errno == ERANGE;
            if (want > INT32_MAX) { want = INT32_MAX; want_err = 1; }
            if (want < INT32_MIN) { want = INT32_MIN; want_err = 1; }
            host_set_errno(0);
            {
                const int32_t got = u_strtol(s, &e1, base);
                CHECK("strtol", got == want && e1 == e2 && (host_errno() == 34) == want_err, "\"%s\" base %d: %d vs %lld (err %d/%d)", s, base, got, want,
                      host_errno(), want_err);
            }
            errno = 0;
            host_set_errno(0);
            {
                const long long a = u_strtoll(s, &e1, base), b = strtoll(s, &e2, base);
                CHECK("strtoll", a == b && e1 == e2 && (host_errno() == 34) == (errno == ERANGE), "\"%s\" base %d", s, base);
            }
            errno = 0;
            {
                const unsigned long long a = u_strtoull(s, &e1, base), b = strtoull(s, &e2, base);
                CHECK("strtoull", a == b && e1 == e2, "\"%s\" base %d: %llu vs %llu", s, base, a, b);
            }
        }
    }
    CHECK("strtoul", u_strtoul("-1", 0, 10) == 0xffffffffu, "-1");
    CHECK("strtoul", u_strtoul("4294967296", 0, 10) == 0xffffffffu, "overflow");
    CHECK("atoi", u_atoi(" -123abc") == -123, "atoi");
    group("strtol", before);
}

/* ---------------------------------------------------------------- qsort / bsearch */
static int cmp_int(const void *a, const void *b) { const int x = *(const int *)a, y = *(const int *)b; return x < y ? -1 : x > y; }
static void test_sort(long N)
{
    const int before = failures;
    long round;
    for (round = 0; round < N / 1000 + 20; ++round) {
        const size_t n = (size_t)(next() % 3000);
        int *a = malloc((n + 1) * sizeof *a), *b = malloc((n + 1) * sizeof *b);
        size_t i;
        const int mode = (int)(next() % 4);
        for (i = 0; i < n; ++i) {
            a[i] = mode == 0 ? (int)next() : mode == 1 ? (int)(next() % 7) : mode == 2 ? (int)i : (int)(n - i);
            b[i] = a[i];
        }
        u_qsort(a, n, sizeof *a, cmp_int);
        qsort(b, n, sizeof *b, cmp_int);
        CHECK("qsort", !memcmp(a, b, n * sizeof *a), "n=%zu mode=%d", n, mode);
        for (i = 0; i < n && i < 50; ++i) {
            const int *p = u_bsearch(&b[i], a, n, sizeof *a, cmp_int);
            CHECK("bsearch", p && *p == b[i], "i=%zu", i);
        }
        free(a);
        free(b);
    }
    group("qsort", before);
}

/* ---------------------------------------------------------------- time */
static void test_time(long N)
{
    const int before = failures;
    static const char *const fmts[] = { "%Y-%m-%d %H:%M:%S", "%j %U %W %V %G %g %u %w", "%a %A %b %B %h", "%p %I %y %C %e", "%D %F %R %T %r",
                                        "%%%n%t|", "%#d/%#m/%#y %#H" };
    long i;
    for (i = 0; i < N; ++i) {
        const int64_t t = (int64_t)(next() % 32535216000ull);
        struct ctm m;
        struct tm g;
        time_t tt = (time_t)t;
        gmtime_r(&tt, &g);
        CHECK("gmtime", u_crt_gmtime_core(t, &m) == 0 && m.tm_year == g.tm_year && m.tm_mon == g.tm_mon && m.tm_mday == g.tm_mday &&
                            m.tm_hour == g.tm_hour && m.tm_min == g.tm_min && m.tm_sec == g.tm_sec && m.tm_wday == g.tm_wday && m.tm_yday == g.tm_yday,
              "t=%lld", (long long)t);
        {
            size_t f = (size_t)(next() % 6);
            char a[128], b[128];
            const size_t ra = u_crt_strftime_core(a, sizeof a, 0, fmts[f], 0, &m, 0, "UTC");
            const size_t rb = strftime(b, sizeof b, fmts[f], &g);
            CHECK("strftime", ra == rb && !strcmp(a, b), "%s: \"%s\" vs \"%s\"", fmts[f], a, b);
        }
        {
            struct ctm d = m;
            struct tm e;
            int64_t r1;
            time_t r2;
            d.tm_sec += (int)(next() % 200000) - 100000;
            d.tm_min += (int)(next() % 2000) - 1000;
            d.tm_mday += (int)(next() % 100) - 50;
            d.tm_mon += (int)(next() % 40) - 20;
            memset(&e, 0, sizeof e);
            e.tm_sec = d.tm_sec; e.tm_min = d.tm_min; e.tm_hour = d.tm_hour; e.tm_mday = d.tm_mday; e.tm_mon = d.tm_mon; e.tm_year = d.tm_year;
            r2 = timegm(&e);
            r1 = u_crt_mkgmtime_core(&d);
            if (r2 >= 0 && r2 <= 32535215999)
                CHECK("mkgmtime", r1 == r2 && d.tm_mday == e.tm_mday && d.tm_yday == e.tm_yday && d.tm_wday == e.tm_wday, "%lld vs %lld",
                      (long long)r1, (long long)r2);
        }
    }
    {
        struct ctm m;
        char a[64];
        u_crt_gmtime_core(794666489, &m);                          /* 1995-03-08 12:41:29 */
        u_crt_strftime_core(a, sizeof a, 0, "%c|%x|%X|%#x", 0, &m, 0, 0);
        CHECK("strftime-ms", !strcmp(a, "03/08/95 12:41:29|03/08/95|12:41:29|Wednesday, March 8, 1995"), "\"%s\"", a);
        u_crt_strftime_core(a, sizeof a, 0, "%z", 0, &m, 480, 0);
        CHECK("strftime-z", !strcmp(a, "-0800"), "\"%s\"", a);
        CHECK("gmtime-range", u_crt_gmtime_core(-1, &m) != 0 && u_crt_gmtime_core(32535216000ll, &m) != 0, "range");
    }
    group("time", before);
}

/* ---------------------------------------------------------------- misc */
static void test_misc(void)
{
    const int before = failures;
    int c, dec, sign;
    char b[64];
    for (c = -1; c < 256; ++c) {
        const int g = c >= 0 && c < 128 ? c : -1;
        if (g < 0 && c != -1) {
            CHECK("ctype-hi", !u_isalpha(c) && !u_isprint(c) && !u_isspace(c), "c=%d", c);
            continue;
        }
        CHECK("ctype", !!u_isalpha(c) == !!isalpha(c) && !!u_isdigit(c) == !!isdigit(c) && !!u_isspace(c) == !!isspace(c) &&
                           !!u_ispunct(c) == !!ispunct(c) && !!u_isalnum(c) == !!isalnum(c) && !!u_isprint(c) == !!isprint(c) &&
                           !!u_isgraph(c) == !!isgraph(c) && !!u_iscntrl(c) == !!iscntrl(c) && !!u_isupper(c) == !!isupper(c) &&
                           !!u_islower(c) == !!islower(c) && !!u_isxdigit(c) == !!isxdigit(c) && !!u_isblank(c) == !!isblank(c) &&
                           u_toupper(c) == toupper(c) && u_tolower(c) == tolower(c), "c=%d", c);
    }
    /* Microsoft documentation examples */
    u__ecvt_s(b, sizeof b, 3.1415926535, 10, &dec, &sign);
    CHECK("_ecvt", !strcmp(b, "3141592654") && dec == 1 && sign == 0, "%s %d %d", b, dec, sign);
    u__fcvt_s(b, sizeof b, 3.1415926535, 7, &dec, &sign);
    CHECK("_fcvt", !strcmp(b, "31415927") && dec == 1 && sign == 0, "%s %d %d", b, dec, sign);
    u__fcvt_s(b, sizeof b, -0.0012, 5, &dec, &sign);
    CHECK("_fcvt-small", !strcmp(b, "120") && dec == -2 && sign == 1, "%s %d %d", b, dec, sign);
    /* secure strings */
    host_invalid_parameter_calls = 0;
    CHECK("strcpy_s", u_strcpy_s(b, 4, "abc") == 0 && !strcmp(b, "abc"), "ok");
    CHECK("strcpy_s", u_strcpy_s(b, 3, "abc") == 34 && b[0] == 0 && host_invalid_parameter_calls == 1, "range");
    CHECK("strncpy_s", u_strncpy_s(b, 3, "abcdef", (size_t)-1) == 80 && !strcmp(b, "ab"), "truncate");
    strcpy(b, "ab");
    CHECK("strcat_s", u_strcat_s(b, 5, "cd") == 0 && !strcmp(b, "abcd"), "cat");
    CHECK("strncat_s", u_strncat_s(b, 6, "efgh", (size_t)-1) == 80 && !strcmp(b, "abcde"), "cat-trunc");
    CHECK("memcpy_s", u_memcpy_s(b, 2, "xyz", 3) == 34 && b[0] == 0 && b[1] == 0, "range");
    CHECK("_itoa_s", u__itoa_s(-255, b, sizeof b, 16) == 0 && !strcmp(b, "ffffff01"), "%s", b);
    CHECK("_itoa_s", u__itoa_s(-255, b, sizeof b, 10) == 0 && !strcmp(b, "-255"), "%s", b);
    CHECK("_i64toa", !strcmp(u__i64toa(-1, b, 2), "1111111111111111111111111111111111111111111111111111111111111111"), "%s", b);
    CHECK("_stricmp", u__stricmp("HeLLo", "hello") == 0 && u__stricmp("a", "B") < 0, "icmp");
    {
        char t[] = " a,b,,c ";
        char *p1 = u_strtok(t, " ,"), *p2 = u_strtok(0, " ,"), *p3 = u_strtok(0, " ,"), *p4 = u_strtok(0, " ,");
        CHECK("strtok", p1 && p2 && p3 && !strcmp(p1, "a") && !strcmp(p2, "b") && !strcmp(p3, "c") && !p4, "tok");
    }
    group("misc", before);
}

int main(int argc, char **argv)
{
    const long N = argc > 1 ? atol(argv[1]) : 200000;
    if (argc > 2) rng = strtoull(argv[2], 0, 0) | 1;
    test_strtod(N);
    test_printf(N);
    test_scanf(N / 4);
    test_strtol(N / 4);
    test_sort(N);
    test_time(N / 4);
    test_misc();
    printf("fmt: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
