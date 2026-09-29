/* SPDX-License-Identifier: GPL-2.0-only
 * C runtime for the Wine port: heap, sorting/searching, number <-> text conversions, environment, errno, exit handling,
 * assert, pseudo-random numbers, multibyte (C locale) and time functions. Written from the C standard / MSDN.
 * The heap is the process heap (HeapAlloc), so blocks can be freed by any module that links this runtime.
 */
#include "shzwcrt.h"
#include <errno.h>
#include <time.h>
#include <sys/timeb.h>
#include <locale.h>
#include <limits.h>

/* ---------------------------------------------------------------- errno */
static DWORD errno_tls = TLS_OUT_OF_INDEXES;
static int errno_fallback, doserrno_fallback;
struct errno_slot { int err; unsigned long doserr; };

static struct errno_slot *errno_slot(void)
{
    struct errno_slot *slot;
    DWORD last = GetLastError();
    if (errno_tls == TLS_OUT_OF_INDEXES) {
        DWORD idx = TlsAlloc();
        if (idx == TLS_OUT_OF_INDEXES) return NULL;
        if (InterlockedCompareExchange((LONG *)&errno_tls, (LONG)idx, (LONG)TLS_OUT_OF_INDEXES) != (LONG)TLS_OUT_OF_INDEXES)
            TlsFree(idx);
    }
    slot = TlsGetValue(errno_tls);
    if (!slot && (slot = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *slot))) TlsSetValue(errno_tls, slot);
    SetLastError(last);
    return slot;
}

int *__cdecl _errno(void) { struct errno_slot *s = errno_slot(); return s ? &s->err : &errno_fallback; }
unsigned long *__cdecl __doserrno(void)
{
    struct errno_slot *s = errno_slot();
    return s ? &s->doserr : (unsigned long *)&doserrno_fallback;
}
void shzw_set_errno(int e) { *_errno() = e; }
errno_t __cdecl _set_errno(int e) { *_errno() = e; return 0; }
errno_t __cdecl _get_errno(int *e) { if (!e) return EINVAL; *e = *_errno(); return 0; }
errno_t __cdecl _set_doserrno(int e) { *__doserrno() = (unsigned long)e; return 0; }
errno_t __cdecl _get_doserrno(int *e) { if (!e) return EINVAL; *e = (int)*__doserrno(); return 0; }
void __cdecl _invalid_parameter_noinfo(void) { }
void __cdecl _invalid_parameter_noinfo_noreturn(void) { ExitProcess(0xc0000417); }
void __cdecl _invalid_parameter(const wchar_t *e, const wchar_t *f, const wchar_t *file, unsigned int line, uintptr_t r)
{
    (void)e; (void)f; (void)file; (void)line; (void)r;
}

/* ---------------------------------------------------------------- heap */
void *__cdecl malloc(size_t n) { void *p = HeapAlloc(GetProcessHeap(), 0, n ? n : 1); if (!p) shzw_set_errno(ENOMEM); return p; }
void __cdecl free(void *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }
void *__cdecl calloc(size_t n, size_t m)
{
    void *p;
    if (m && n > (size_t)-1 / m) { shzw_set_errno(ENOMEM); return NULL; }
    p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n * m != 0 ? n * m : 1);
    if (!p) shzw_set_errno(ENOMEM);
    return p;
}
void *__cdecl realloc(void *p, size_t n)
{
    void *q;
    if (!p) return malloc(n);
    if (!n) { free(p); return NULL; }
    q = HeapReAlloc(GetProcessHeap(), 0, p, n);
    if (!q) shzw_set_errno(ENOMEM);
    return q;
}
void *__cdecl _recalloc(void *p, size_t n, size_t m)
{
    size_t old = p ? HeapSize(GetProcessHeap(), 0, p) : 0, sz;
    void *q;
    if (m && n > (size_t)-1 / m) return NULL;
    sz = n * m;
    if (!p) return calloc(n, m);
    q = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, p, sz ? sz : 1);
    (void)old;
    return q;
}
size_t __cdecl _msize(void *p) { return p ? HeapSize(GetProcessHeap(), 0, p) : (size_t)-1; }
void *__cdecl _expand(void *p, size_t n) { return HeapReAlloc(GetProcessHeap(), HEAP_REALLOC_IN_PLACE_ONLY, p, n); }
void *__cdecl _aligned_malloc(size_t n, size_t align)
{
    char *raw, *p;
    if (!align || (align & (align - 1))) { shzw_set_errno(EINVAL); return NULL; }
    if (align < sizeof(void *)) align = sizeof(void *);
    if (!(raw = malloc(n + align + sizeof(void *)))) return NULL;
    p = (char *)(((uintptr_t)raw + sizeof(void *) + align - 1) & ~(uintptr_t)(align - 1));
    ((void **)p)[-1] = raw;
    return p;
}
void __cdecl _aligned_free(void *p) { if (p) free(((void **)p)[-1]); }
void *__cdecl _aligned_realloc(void *p, size_t n, size_t align)
{
    void *q;
    size_t old;
    if (!p) return _aligned_malloc(n, align);
    if (!n) { _aligned_free(p); return NULL; }
    old = _msize(((void **)p)[-1]) - ((char *)p - (char *)((void **)p)[-1]);
    if (!(q = _aligned_malloc(n, align))) return NULL;
    memcpy(q, p, old < n ? old : n);
    _aligned_free(p);
    return q;
}
char *__cdecl _strdup(const char *s)
{
    char *r;
    if (!s) return NULL;
    if ((r = malloc(strlen(s) + 1))) strcpy(r, s);
    return r;
}
wchar_t *__cdecl _wcsdup(const wchar_t *s)
{
    wchar_t *r;
    if (!s) return NULL;
    if ((r = malloc((wcslen(s) + 1) * sizeof(wchar_t)))) wcscpy(r, s);
    return r;
}

/* ---------------------------------------------------------------- sorting and searching */
static void swap_bytes(char *a, char *b, size_t n)
{
    while (n--) { char t = *a; *a++ = *b; *b++ = t; }
}

static void sift_down(char *base, size_t start, size_t end, size_t size, int (__cdecl *cmp)(const void *, const void *))
{
    size_t root = start;
    while (root * 2 + 1 <= end) {
        size_t child = root * 2 + 1, sw = root;
        if (cmp(base + sw * size, base + child * size) < 0) sw = child;
        if (child + 1 <= end && cmp(base + sw * size, base + (child + 1) * size) < 0) sw = child + 1;
        if (sw == root) return;
        swap_bytes(base + root * size, base + sw * size, size);
        root = sw;
    }
}

/* heap sort: O(n log n) worst case, in place, no recursion (qsort is not required to be stable) */
void __cdecl qsort(void *base, size_t n, size_t size, int (__cdecl *cmp)(const void *, const void *))
{
    char *b = base;
    size_t start, end;
    if (n < 2 || !size) return;
    if (n <= 12) {                                          /* insertion sort for short runs */
        size_t i, j;
        for (i = 1; i < n; ++i)
            for (j = i; j > 0 && cmp(b + (j - 1) * size, b + j * size) > 0; --j)
                swap_bytes(b + (j - 1) * size, b + j * size, size);
        return;
    }
    for (start = (n - 2) / 2 + 1; start-- > 0;) sift_down(b, start, n - 1, size, cmp);
    for (end = n - 1; end > 0; --end) {
        swap_bytes(b, b + end * size, size);
        sift_down(b, 0, end - 1, size, cmp);
    }
}

typedef int (__cdecl *cmp_s_fn)(void *, const void *, const void *);
static void sift_down_s(char *base, size_t start, size_t end, size_t size, cmp_s_fn cmp, void *ctx)
{
    size_t root = start;
    while (root * 2 + 1 <= end) {
        size_t child = root * 2 + 1, sw = root;
        if (cmp(ctx, base + sw * size, base + child * size) < 0) sw = child;
        if (child + 1 <= end && cmp(ctx, base + sw * size, base + (child + 1) * size) < 0) sw = child + 1;
        if (sw == root) return;
        swap_bytes(base + root * size, base + sw * size, size);
        root = sw;
    }
}
void __cdecl qsort_s(void *base, size_t n, size_t size, cmp_s_fn cmp, void *ctx)
{
    char *b = base;
    size_t start, end;
    if (n < 2 || !size) return;
    for (start = (n - 2) / 2 + 1; start-- > 0;) sift_down_s(b, start, n - 1, size, cmp, ctx);
    for (end = n - 1; end > 0; --end) {
        swap_bytes(b, b + end * size, size);
        sift_down_s(b, 0, end - 1, size, cmp, ctx);
    }
}

void *__cdecl bsearch(const void *key, const void *base, size_t n, size_t size, int (__cdecl *cmp)(const void *, const void *))
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const char *p = (const char *)base + mid * size;
        int r = cmp(key, p);
        if (!r) return (void *)p;
        if (r < 0) hi = mid; else lo = mid + 1;
    }
    return NULL;
}
void *__cdecl bsearch_s(const void *key, const void *base, size_t n, size_t size, cmp_s_fn cmp, void *ctx)
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const char *p = (const char *)base + mid * size;
        int r = cmp(ctx, key, p);
        if (!r) return (void *)p;
        if (r < 0) hi = mid; else lo = mid + 1;
    }
    return NULL;
}
void *__cdecl _lfind(const void *key, const void *base, unsigned int *n, unsigned int size,
                     int (__cdecl *cmp)(const void *, const void *))
{
    unsigned int i;
    for (i = 0; i < *n; ++i) if (!cmp(key, (const char *)base + (size_t)i * size)) return (char *)base + (size_t)i * size;
    return NULL;
}

/* ---------------------------------------------------------------- integer parsing */
static unsigned long long parse_ull(const void *str, int wide, void **end, int base, int *neg, int *overflow)
{
    const unsigned char *a = wide ? NULL : str;
    const unsigned short *w = wide ? str : NULL;
    size_t i = 0, digits_start;
    unsigned long long v = 0;
    int any = 0;
#define C(k) ((unsigned int)(a ? a[k] : w[k]))
    *neg = 0; *overflow = 0;
    while (C(i) == ' ' || (C(i) >= 9 && C(i) <= 13)) ++i;
    if (C(i) == '+' || C(i) == '-') { *neg = C(i) == '-'; ++i; }
    if ((base == 0 || base == 16) && C(i) == '0' && (C(i + 1) | 0x20) == 'x') {
        unsigned int d = C(i + 2);
        if ((d >= '0' && d <= '9') || ((d | 0x20) >= 'a' && (d | 0x20) <= 'f')) { i += 2; base = 16; }
    }
    if (base == 0) base = C(i) == '0' ? 8 : 10;
    digits_start = i;
    for (;; ++i) {
        unsigned int c = C(i), d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if ((c | 0x20) >= 'a' && (c | 0x20) <= 'z') d = (c | 0x20) - 'a' + 10;
        else break;
        if (d >= (unsigned)base) break;
        if (v > (~0ull - d) / (unsigned)base) *overflow = 1;
        v = v * (unsigned)base + d;
        any = 1;
    }
#undef C
    if (end) {
        if (!any) i = 0;
        *end = wide ? (void *)((const wchar_t *)str + i) : (void *)((const char *)str + i);
    }
    (void)digits_start;
    return v;
}

#define DEFINE_STRTO(name, ch, wide, type, minv, maxv, is_signed)                                     \
    type __cdecl name(const ch *s, ch **end, int base)                                               \
    {                                                                                                \
        int neg, ovf;                                                                                \
        unsigned long long v = parse_ull(s, wide, (void **)end, base, &neg, &ovf);                   \
        if (is_signed) {                                                                             \
            if (ovf || (!neg && v > (unsigned long long)(maxv)) ||                                   \
                (neg && v > (unsigned long long)(maxv) + 1)) {                                       \
                shzw_set_errno(ERANGE);                                                              \
                return neg ? (type)(minv) : (type)(maxv);                                            \
            }                                                                                        \
            return neg ? (type)(0 - v) : (type)v;                                                    \
        }                                                                                            \
        if (ovf || v > (unsigned long long)(maxv)) { shzw_set_errno(ERANGE); return (type)(maxv); }  \
        return neg ? (type)(0 - v) : (type)v;                                                        \
    }

DEFINE_STRTO(strtol, char, 0, long, LONG_MIN, LONG_MAX, 1)
DEFINE_STRTO(strtoul, char, 0, unsigned long, 0, ULONG_MAX, 0)
DEFINE_STRTO(_strtoi64, char, 0, __int64, LLONG_MIN, LLONG_MAX, 1)
DEFINE_STRTO(_strtoui64, char, 0, unsigned __int64, 0, ULLONG_MAX, 0)
DEFINE_STRTO(wcstol, wchar_t, 1, long, LONG_MIN, LONG_MAX, 1)
DEFINE_STRTO(wcstoul, wchar_t, 1, unsigned long, 0, ULONG_MAX, 0)
DEFINE_STRTO(wcstoll, wchar_t, 1, long long, LLONG_MIN, LLONG_MAX, 1)
DEFINE_STRTO(wcstoull, wchar_t, 1, unsigned long long, 0, ULLONG_MAX, 0)
DEFINE_STRTO(_wcstoi64, wchar_t, 1, __int64, LLONG_MIN, LLONG_MAX, 1)
DEFINE_STRTO(_wcstoui64, wchar_t, 1, unsigned __int64, 0, ULLONG_MAX, 0)

long __cdecl _strtol_l(const char *s, char **e, int b, _locale_t l) { (void)l; return strtol(s, e, b); }
unsigned long __cdecl _strtoul_l(const char *s, char **e, int b, _locale_t l) { (void)l; return strtoul(s, e, b); }
long __cdecl _wcstol_l(const wchar_t *s, wchar_t **e, int b, _locale_t l) { (void)l; return wcstol(s, e, b); }
unsigned long __cdecl _wcstoul_l(const wchar_t *s, wchar_t **e, int b, _locale_t l) { (void)l; return wcstoul(s, e, b); }

int __cdecl atoi(const char *s) { return (int)strtol(s, NULL, 10); }
long __cdecl atol(const char *s) { return strtol(s, NULL, 10); }
long long __cdecl atoll(const char *s) { return strtoll(s, NULL, 10); }
__int64 __cdecl _atoi64(const char *s) { return _strtoi64(s, NULL, 10); }
int __cdecl _wtoi(const wchar_t *s) { return (int)wcstol(s, NULL, 10); }
long __cdecl _wtol(const wchar_t *s) { return wcstol(s, NULL, 10); }
long long __cdecl _wtoll(const wchar_t *s) { return wcstoll(s, NULL, 10); }
__int64 __cdecl _wtoi64(const wchar_t *s) { return _wcstoi64(s, NULL, 10); }

/* ---------------------------------------------------------------- integer formatting */
static int u64_to_text(unsigned long long v, int neg, int radix, char *out)
{
    char tmp[72];
    int n = 0, len = 0;
    if (radix < 2 || radix > 36) radix = 10;
    do { unsigned d = (unsigned)(v % (unsigned)radix); tmp[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10); v /= (unsigned)radix; } while (v);
    if (neg) out[len++] = '-';
    while (n) out[len++] = tmp[--n];
    out[len] = 0;
    return len;
}


char *__cdecl _i64toa(__int64 v, char *s, int r) { int neg = r == 10 && v < 0; u64_to_text(neg ? 0ull - (unsigned long long)v : (unsigned long long)v, neg, r, s); return s; }
char *__cdecl _ui64toa(unsigned __int64 v, char *s, int r) { u64_to_text(v, 0, r, s); return s; }
char *__cdecl _itoa(int v, char *s, int r) { if (r != 10) return _ui64toa((unsigned int)v, s, r); return _i64toa(v, s, r); }
char *__cdecl _ltoa(long v, char *s, int r) { return _itoa((int)v, s, r); }
char *__cdecl _ultoa(unsigned long v, char *s, int r) { return _ui64toa(v, s, r); }
static wchar_t *widen_num(const char *a, wchar_t *w) { int i = 0; do { w[i] = (unsigned char)a[i]; } while (a[i++]); return w; }
wchar_t *__cdecl _i64tow(__int64 v, wchar_t *s, int r) { char t[72]; return widen_num(_i64toa(v, t, r), s); }
wchar_t *__cdecl _ui64tow(unsigned __int64 v, wchar_t *s, int r) { char t[72]; return widen_num(_ui64toa(v, t, r), s); }
wchar_t *__cdecl _itow(int v, wchar_t *s, int r) { char t[72]; return widen_num(_itoa(v, t, r), s); }
wchar_t *__cdecl _ltow(long v, wchar_t *s, int r) { char t[72]; return widen_num(_ltoa(v, t, r), s); }
wchar_t *__cdecl _ultow(unsigned long v, wchar_t *s, int r) { char t[72]; return widen_num(_ultoa(v, t, r), s); }

static errno_t text_s(const char *t, void *out, size_t size, int wide)
{
    size_t n = strlen(t), i;
    if (!out || !size) return EINVAL;
    if (n + 1 > size) { if (wide) ((wchar_t *)out)[0] = 0; else ((char *)out)[0] = 0; return ERANGE; }
    for (i = 0; i <= n; ++i) { if (wide) ((wchar_t *)out)[i] = (unsigned char)t[i]; else ((char *)out)[i] = t[i]; }
    return 0;
}
errno_t __cdecl _itoa_s(int v, char *s, size_t n, int r) { char t[72]; return text_s(_itoa(v, t, r), s, n, 0); }
errno_t __cdecl _ltoa_s(long v, char *s, size_t n, int r) { char t[72]; return text_s(_ltoa(v, t, r), s, n, 0); }
errno_t __cdecl _ultoa_s(unsigned long v, char *s, size_t n, int r) { char t[72]; return text_s(_ultoa(v, t, r), s, n, 0); }
errno_t __cdecl _i64toa_s(__int64 v, char *s, size_t n, int r) { char t[72]; return text_s(_i64toa(v, t, r), s, n, 0); }
errno_t __cdecl _ui64toa_s(unsigned __int64 v, char *s, size_t n, int r) { char t[72]; return text_s(_ui64toa(v, t, r), s, n, 0); }
errno_t __cdecl _itow_s(int v, wchar_t *s, size_t n, int r) { char t[72]; return text_s(_itoa(v, t, r), s, n, 1); }
errno_t __cdecl _ltow_s(long v, wchar_t *s, size_t n, int r) { char t[72]; return text_s(_ltoa(v, t, r), s, n, 1); }
errno_t __cdecl _ultow_s(unsigned long v, wchar_t *s, size_t n, int r) { char t[72]; return text_s(_ultoa(v, t, r), s, n, 1); }
errno_t __cdecl _i64tow_s(__int64 v, wchar_t *s, size_t n, int r) { char t[72]; return text_s(_i64toa(v, t, r), s, n, 1); }
errno_t __cdecl _ui64tow_s(unsigned __int64 v, wchar_t *s, size_t n, int r) { char t[72]; return text_s(_ui64toa(v, t, r), s, n, 1); }

int __cdecl abs(int v) { return v < 0 ? -v : v; }
long __cdecl labs(long v) { return v < 0 ? -v : v; }
long long __cdecl llabs(long long v) { return v < 0 ? -v : v; }
__int64 __cdecl _abs64(__int64 v) { return v < 0 ? -v : v; }
div_t __cdecl div(int a, int b) { div_t r; r.quot = a / b; r.rem = a % b; return r; }
ldiv_t __cdecl ldiv(long a, long b) { ldiv_t r; r.quot = a / b; r.rem = a % b; return r; }
unsigned int __cdecl _rotl(unsigned int v, int s) { s &= 31; return s ? (v << s) | (v >> (32 - s)) : v; }
unsigned int __cdecl _rotr(unsigned int v, int s) { s &= 31; return s ? (v >> s) | (v << (32 - s)) : v; }
unsigned __int64 __cdecl _rotl64(unsigned __int64 v, int s) { s &= 63; return s ? (v << s) | (v >> (64 - s)) : v; }
unsigned __int64 __cdecl _rotr64(unsigned __int64 v, int s) { s &= 63; return s ? (v >> s) | (v << (64 - s)) : v; }
unsigned short __cdecl _byteswap_ushort(unsigned short v) { return (unsigned short)((v >> 8) | (v << 8)); }
unsigned long __cdecl _byteswap_ulong(unsigned long v) { return __builtin_bswap32((unsigned int)v); }
unsigned __int64 __cdecl _byteswap_uint64(unsigned __int64 v) { return __builtin_bswap64(v); }

/* ---------------------------------------------------------------- pseudo-random (per process, like msvcrt) */
static unsigned int rand_state = 1;
void __cdecl srand(unsigned int seed) { rand_state = seed; }
int __cdecl rand(void)
{
    rand_state = rand_state * 214013u + 2531011u;             /* the classic MSVC LCG */
    return (int)((rand_state >> 16) & 0x7fff);
}
errno_t __cdecl rand_s(unsigned int *out)
{
    /* SystemFunction036 (RtlGenRandom) lives in advapi32/cryptbase on Windows; the process-independent source here is
     * the kernel's random bytes, reached through BCryptGenRandom when present */
    static LONG (WINAPI *gen)(void *, UCHAR *, ULONG, ULONG);
    if (!out) return EINVAL;
    if (!gen) {
        HMODULE m = LoadLibraryW(L"bcrypt.dll");
        gen = m ? (void *)GetProcAddress(m, "BCryptGenRandom") : NULL;
        if (!gen) return EINVAL;
    }
    return gen(NULL, (UCHAR *)out, sizeof *out, 2 /* BCRYPT_USE_SYSTEM_PREFERRED_RNG */) ? EINVAL : 0;
}

/* ---------------------------------------------------------------- environment */
struct env_cache { struct env_cache *next; char *name, *value; wchar_t *wname, *wvalue; };
static struct env_cache *env_list;
static CRITICAL_SECTION env_cs;
static LONG env_cs_init;

static void env_lock(void)
{
    if (InterlockedCompareExchange(&env_cs_init, 1, 0) == 0) { InitializeCriticalSection(&env_cs); env_cs_init = 2; }
    while (env_cs_init != 2) Sleep(0);
    EnterCriticalSection(&env_cs);
}

/* getenv returns storage owned by the runtime; the latest value is cached per name so repeated calls stay valid */
char *__cdecl getenv(const char *name)
{
    char small[256], *buf = small;
    DWORD n;
    struct env_cache *e;
    char *ret = NULL;
    if (!name) return NULL;
    n = GetEnvironmentVariableA(name, small, sizeof small);
    if (!n) return NULL;
    if (n >= sizeof small) {
        if (!(buf = malloc(n))) return NULL;
        if (!GetEnvironmentVariableA(name, buf, n)) { free(buf); return NULL; }
    }
    env_lock();
    for (e = env_list; e; e = e->next) if (e->name && !_stricmp(e->name, name)) break;
    if (!e && (e = calloc(1, sizeof *e))) { e->name = _strdup(name); e->next = env_list; env_list = e; }
    if (e) {
        if (!e->value || strcmp(e->value, buf)) { free(e->value); e->value = _strdup(buf); }
        ret = e->value;
    }
    LeaveCriticalSection(&env_cs);
    if (buf != small) free(buf);
    return ret;
}

wchar_t *__cdecl _wgetenv(const wchar_t *name)
{
    wchar_t small[256], *buf = small;
    DWORD n;
    struct env_cache *e;
    wchar_t *ret = NULL;
    if (!name) return NULL;
    n = GetEnvironmentVariableW(name, small, ARRAY_SIZE(small));
    if (!n) return NULL;
    if (n >= ARRAY_SIZE(small)) {
        if (!(buf = malloc(n * sizeof(wchar_t)))) return NULL;
        if (!GetEnvironmentVariableW(name, buf, n)) { free(buf); return NULL; }
    }
    env_lock();
    for (e = env_list; e; e = e->next) if (e->wname && !_wcsicmp(e->wname, name)) break;
    if (!e && (e = calloc(1, sizeof *e))) { e->wname = _wcsdup(name); e->next = env_list; env_list = e; }
    if (e) {
        if (!e->wvalue || wcscmp(e->wvalue, buf)) { free(e->wvalue); e->wvalue = _wcsdup(buf); }
        ret = e->wvalue;
    }
    LeaveCriticalSection(&env_cs);
    if (buf != small) free(buf);
    return ret;
}

errno_t __cdecl getenv_s(size_t *ret, char *buf, size_t size, const char *name)
{
    char *v = getenv(name);
    size_t n = v ? strlen(v) + 1 : 0;
    if (ret) *ret = n;
    if (!v) { if (buf && size) buf[0] = 0; return 0; }
    if (!buf || size < n) return ERANGE;
    memcpy(buf, v, n);
    return 0;
}

int __cdecl _putenv(const char *s)
{
    char name[512];
    const char *eq = s ? strchr(s, '=') : NULL;
    size_t n;
    if (!eq || (n = (size_t)(eq - s)) >= sizeof name) return -1;
    memcpy(name, s, n);
    name[n] = 0;
    return SetEnvironmentVariableA(name, eq[1] ? eq + 1 : NULL) ? 0 : -1;
}
errno_t __cdecl _putenv_s(const char *name, const char *value)
{
    return SetEnvironmentVariableA(name, value && *value ? value : NULL) ? 0 : EINVAL;
}
int __cdecl _wputenv(const wchar_t *s)
{
    wchar_t name[512];
    const wchar_t *eq = s ? wcschr(s, '=') : NULL;
    size_t n;
    if (!eq || (n = (size_t)(eq - s)) >= ARRAY_SIZE(name)) return -1;
    memcpy(name, s, n * sizeof(wchar_t));
    name[n] = 0;
    return SetEnvironmentVariableW(name, eq[1] ? eq + 1 : NULL) ? 0 : -1;
}

/* ---------------------------------------------------------------- exit handling */
typedef void (__cdecl *atexit_fn)(void);
static atexit_fn exit_funcs[64];
static LONG exit_count;

int __cdecl atexit(atexit_fn f)
{
    LONG i = InterlockedIncrement(&exit_count) - 1;
    if (i >= (LONG)ARRAY_SIZE(exit_funcs)) { InterlockedDecrement(&exit_count); return -1; }
    exit_funcs[i] = f;
    return 0;
}
_onexit_t __cdecl _onexit(_onexit_t f) { return atexit((atexit_fn)f) ? NULL : f; }

void shzw_run_atexit(void)
{
    LONG n;
    while ((n = exit_count) > 0) {
        atexit_fn f;
        if (InterlockedCompareExchange(&exit_count, n - 1, n) != n) continue;
        f = exit_funcs[n - 1];
        if (f) f();
    }
}

void __cdecl exit(int code)
{
    shzw_run_atexit();
    fflush(NULL);
    ExitProcess((UINT)code);
}
void __cdecl _exit(int code) { ExitProcess((UINT)code); }
void __cdecl _Exit(int code) { ExitProcess((UINT)code); }
void __cdecl quick_exit(int code) { ExitProcess((UINT)code); }
void __cdecl abort(void)
{
    fputs("\nabnormal program termination\n", stderr);
    ExitProcess(3);
}

void __cdecl _assert(const char *expr, const char *file, unsigned int line)
{
    fprintf(stderr, "Assertion failed: %s, file %s, line %u\n", expr, file, line);
    abort();
}
void __cdecl _wassert(const wchar_t *expr, const wchar_t *file, unsigned int line)
{
    fprintf(stderr, "Assertion failed: %ls, file %ls, line %u\n", expr, file, line);
    abort();
}

/* ---------------------------------------------------------------- multibyte, C locale (bytes are code points 0..255) */
int __cdecl mbtowc(wchar_t *w, const char *s, size_t n)
{
    if (!s) return 0;
    if (!n) return -1;
    if (w) *w = (unsigned char)*s;
    return *s ? 1 : 0;
}
int __cdecl wctomb(char *s, wchar_t w)
{
    if (!s) return 0;
    if ((unsigned short)w > 255) { shzw_set_errno(EILSEQ); return -1; }
    *s = (char)w;
    return 1;
}
size_t __cdecl mbrtowc(wchar_t *w, const char *s, size_t n, mbstate_t *st)
{
    (void)st;
    if (!s) return 0;
    if (!n) return (size_t)-2;
    if (w) *w = (unsigned char)*s;
    return *s ? 1 : 0;
}
size_t __cdecl wcrtomb(char *s, wchar_t w, mbstate_t *st)
{
    (void)st;
    if (!s) return 1;
    if ((unsigned short)w > 255) { shzw_set_errno(EILSEQ); return (size_t)-1; }
    *s = (char)w;
    return 1;
}
wint_t __cdecl btowc(int c) { return c == EOF ? WEOF : (wint_t)(unsigned char)c; }
int __cdecl wctob(wint_t w) { return w < 256 ? (int)w : EOF; }
size_t __cdecl mbstowcs(wchar_t *w, const char *s, size_t n)
{
    size_t i = 0;
    if (!w) return strlen(s);
    for (; i < n; ++i) { w[i] = (unsigned char)s[i]; if (!s[i]) return i; }
    return i;
}
size_t __cdecl wcstombs(char *s, const wchar_t *w, size_t n)
{
    size_t i = 0;
    if (!s) { for (; w[i]; ++i) if ((unsigned short)w[i] > 255) return (size_t)-1; return i; }
    for (; i < n; ++i) {
        if ((unsigned short)w[i] > 255) { shzw_set_errno(EILSEQ); return (size_t)-1; }
        s[i] = (char)w[i];
        if (!w[i]) return i;
    }
    return i;
}
errno_t __cdecl mbstowcs_s(size_t *ret, wchar_t *w, size_t size, const char *s, size_t count)
{
    size_t n = strlen(s), i;
    if (count != (size_t)-1 && count < n) n = count;
    if (ret) *ret = n + 1;
    if (!w) return 0;
    if (size < n + 1) { if (size) w[0] = 0; return ERANGE; }
    for (i = 0; i < n; ++i) w[i] = (unsigned char)s[i];
    w[n] = 0;
    return 0;
}
errno_t __cdecl wcstombs_s(size_t *ret, char *s, size_t size, const wchar_t *w, size_t count)
{
    size_t n = wcslen(w), i;
    if (count != (size_t)-1 && count < n) n = count;
    if (ret) *ret = n + 1;
    if (!s) return 0;
    if (size < n + 1) { if (size) s[0] = 0; return ERANGE; }
    for (i = 0; i < n; ++i) s[i] = (unsigned short)w[i] < 256 ? (char)w[i] : '?';
    s[n] = 0;
    return 0;
}
int __cdecl _mbsnbcmp(const unsigned char *a, const unsigned char *b, size_t n) { return strncmp((const char *)a, (const char *)b, n); }

/* ---------------------------------------------------------------- locale stubs of the C locale (no other locale exists) */
char *__cdecl setlocale(int category, const char *locale)
{
    static char c_locale[] = "C";
    (void)category;
    if (!locale || !*locale || !strcmp(locale, "C")) return c_locale;
    return NULL;                                             /* only the C locale is available */
}
wchar_t *__cdecl _wsetlocale(int category, const wchar_t *locale)
{
    static wchar_t c_locale[] = L"C";
    (void)category;
    if (!locale || !*locale || !wcscmp(locale, L"C")) return c_locale;
    return NULL;
}
struct lconv *__cdecl localeconv(void)
{
    static char dot[] = ".", empty[] = "";
    static struct lconv lc;
    lc.decimal_point = dot;
    lc.thousands_sep = empty;
    lc.grouping = empty;
    return &lc;
}

/* ---------------------------------------------------------------- time */
static __int64 filetime_now_unix100ns(void)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return (((__int64)ft.dwHighDateTime << 32) | ft.dwLowDateTime) - 116444736000000000ll;
}
__time64_t __cdecl _time64(__time64_t *t) { __time64_t v = filetime_now_unix100ns() / 10000000; if (t) *t = v; return v; }
__time32_t __cdecl _time32(__time32_t *t) { __time32_t v = (__time32_t)_time64(NULL); if (t) *t = v; return v; }
void __cdecl _ftime64(struct __timeb64 *tb)
{
    __int64 v = filetime_now_unix100ns();
    tb->time = v / 10000000;
    tb->millitm = (unsigned short)((v / 10000) % 1000);
    tb->timezone = 0;
    tb->dstflag = 0;
}
clock_t __cdecl clock(void)
{
    static ULONGLONG start;
    ULONGLONG now = GetTickCount64();
    if (!start) start = now;
    return (clock_t)(now - start);
}

static int is_leap(int y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }
static const int mdays[2][12] = { {31,28,31,30,31,30,31,31,30,31,30,31}, {31,29,31,30,31,30,31,31,30,31,30,31} };

static int gmtime_to(__time64_t t, struct tm *tm)
{
    __int64 days = t / 86400, rem = t % 86400;
    int y = 1970, m = 0;
    if (rem < 0) { rem += 86400; days--; }
    tm->tm_hour = (int)(rem / 3600);
    tm->tm_min = (int)(rem % 3600 / 60);
    tm->tm_sec = (int)(rem % 60);
    tm->tm_wday = (int)((4 + days % 7 + 7) % 7);
    while (days < 0) { y--; days += is_leap(y) ? 366 : 365; }
    while (days >= (is_leap(y) ? 366 : 365)) { days -= is_leap(y) ? 366 : 365; y++; }
    tm->tm_year = y - 1900;
    tm->tm_yday = (int)days;
    while (days >= mdays[is_leap(y)][m]) { days -= mdays[is_leap(y)][m]; m++; }
    tm->tm_mon = m;
    tm->tm_mday = (int)days + 1;
    tm->tm_isdst = 0;
    return 0;
}
static struct tm tm_static;
struct tm *__cdecl _gmtime64(const __time64_t *t) { if (!t || *t < 0) return NULL; gmtime_to(*t, &tm_static); return &tm_static; }
struct tm *__cdecl _gmtime32(const __time32_t *t) { __time64_t v; if (!t) return NULL; v = *t; return _gmtime64(&v); }
errno_t __cdecl _gmtime64_s(struct tm *tm, const __time64_t *t) { if (!tm || !t || *t < 0) return EINVAL; gmtime_to(*t, tm); return 0; }
/* local time equals UTC: the runtime has no time zone database (GetTimeZoneInformation reports UTC as well) */
struct tm *__cdecl _localtime64(const __time64_t *t) { return _gmtime64(t); }
struct tm *__cdecl _localtime32(const __time32_t *t) { return _gmtime32(t); }
errno_t __cdecl _localtime64_s(struct tm *tm, const __time64_t *t) { return _gmtime64_s(tm, t); }
__time64_t __cdecl _mkgmtime64(struct tm *tm)
{
    __int64 y = tm->tm_year + 1900 + tm->tm_mon / 12, days = 0;
    int mon = tm->tm_mon % 12, i;
    if (mon < 0) { mon += 12; y--; }
    if (y >= 1970) for (i = 1970; i < y; ++i) days += is_leap(i) ? 366 : 365;
    else for (i = (int)y; i < 1970; ++i) days -= is_leap(i) ? 366 : 365;
    for (i = 0; i < mon; ++i) days += mdays[is_leap((int)y)][i];
    days += tm->tm_mday - 1;
    {
        __time64_t r = days * 86400 + tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec;
        gmtime_to(r, tm);
        return r;
    }
}
__time64_t __cdecl _mktime64(struct tm *tm) { return _mkgmtime64(tm); }
__time32_t __cdecl _mktime32(struct tm *tm) { return (__time32_t)_mkgmtime64(tm); }
double __cdecl _difftime64(__time64_t a, __time64_t b) { return (double)(a - b); }
double __cdecl _difftime32(__time32_t a, __time32_t b) { return (double)(a - b); }
