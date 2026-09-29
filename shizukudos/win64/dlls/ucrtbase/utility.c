/* SPDX-License-Identifier: GPL-2.0-only
 * <stdlib.h> utilities: qsort / qsort_s (introsort: median-of-three quicksort, insertion sort for short ranges,
 * heapsort when the recursion gets too deep, so the worst case stays O(n log n)), bsearch / bsearch_s, _lfind /
 * _lsearch, abs / div families, rand / srand (the documented Microsoft generator: seed * 214013 + 2531011, bits 16..30,
 * per thread, initial seed 1), bit rotations and byte swaps, _splitpath / _makepath.
 */
#include "crtint.h"

typedef int (CRTAPI *cmp_fn)(const void *, const void *);
typedef int (CRTAPI *cmp_s_fn)(void *, const void *, const void *);
typedef struct { cmp_fn f; cmp_s_fn fs; void *ctx; } cmp_t;

static int do_cmp(const cmp_t *c, const void *a, const void *b) { return c->f ? c->f(a, b) : c->fs(c->ctx, a, b); }
static void swap_bytes(char *a, char *b, size_t w)
{
    if (a == b) return;
    while (w >= 8) { uint64_t t; crt_memcpy(&t, a, 8); crt_memcpy(a, b, 8); crt_memcpy(b, &t, 8); a += 8; b += 8; w -= 8; }
    while (w--) { char t = *a; *a++ = *b; *b++ = t; }
}
static void insertion(char *base, size_t n, size_t w, const cmp_t *c)
{
    size_t i, j;
    for (i = 1; i < n; ++i)
        for (j = i; j > 0 && do_cmp(c, base + (j - 1) * w, base + j * w) > 0; --j) swap_bytes(base + (j - 1) * w, base + j * w, w);
}
static void sift(char *base, size_t start, size_t n, size_t w, const cmp_t *c)
{
    size_t root = start;
    for (;;) {
        size_t child = 2 * root + 1, big = root;
        if (child < n && do_cmp(c, base + child * w, base + big * w) > 0) big = child;
        if (child + 1 < n && do_cmp(c, base + (child + 1) * w, base + big * w) > 0) big = child + 1;
        if (big == root) return;
        swap_bytes(base + root * w, base + big * w, w);
        root = big;
    }
}
static void heapsort_(char *base, size_t n, size_t w, const cmp_t *c)
{
    size_t i;
    for (i = n / 2; i-- > 0;) sift(base, i, n, w, c);
    for (i = n; i-- > 1;) {
        swap_bytes(base, base + i * w, w);
        sift(base, 0, i, w, c);
    }
}
static void introsort(char *base, size_t n, size_t w, const cmp_t *c, int depth)
{
    while (n > 16) {
        size_t lo, hi, mid = n / 2;
        char *a = base, *m = base + mid * w, *z = base + (n - 1) * w;
        if (depth-- <= 0) { heapsort_(base, n, w, c); return; }
        /* median of three into position 0 as the pivot */
        if (do_cmp(c, a, m) > 0) swap_bytes(a, m, w);
        if (do_cmp(c, m, z) > 0) swap_bytes(m, z, w);
        if (do_cmp(c, a, m) > 0) swap_bytes(a, m, w);
        swap_bytes(a, m, w);                              /* pivot at base[0] */
        lo = 1;
        hi = n - 1;
        for (;;) {                                       /* Hoare partition around base[0] */
            while (lo <= hi && do_cmp(c, base + lo * w, base) < 0) ++lo;
            while (hi >= lo && do_cmp(c, base + hi * w, base) > 0) --hi;
            if (lo >= hi) break;
            swap_bytes(base + lo * w, base + hi * w, w);
            ++lo;
            --hi;
        }
        swap_bytes(base, base + hi * w, w);              /* pivot to its final place hi */
        /* recurse into the smaller side, loop on the larger */
        if (hi < n - hi - 1) {
            introsort(base, hi, w, c, depth);
            base += (hi + 1) * w;
            n -= hi + 1;
        } else {
            introsort(base + (hi + 1) * w, n - hi - 1, w, c, depth);
            n = hi;
        }
    }
    insertion(base, n, w, c);
}
static void sort_common(void *base, size_t n, size_t w, const cmp_t *c)
{
    int depth = 0;
    size_t k = n;
    while (k) { ++depth; k >>= 1; }
    if (n > 1 && w) introsort(base, n, w, c, 2 * depth);
}
DLLAPI void CRTAPI qsort(void *base, size_t n, size_t w, cmp_fn f)
{
    cmp_t c;
    CRT_VALIDATE_NORET(base != 0 || n == 0, CRT_EINVAL);
    CRT_VALIDATE_NORET(w > 0 && f != 0, CRT_EINVAL);
    c.f = f; c.fs = 0; c.ctx = 0;
    sort_common(base, n, w, &c);
}
DLLAPI void CRTAPI qsort_s(void *base, size_t n, size_t w, cmp_s_fn f, void *ctx)
{
    cmp_t c;
    CRT_VALIDATE_NORET(base != 0 || n == 0, CRT_EINVAL);
    CRT_VALIDATE_NORET(w > 0 && f != 0, CRT_EINVAL);
    c.f = 0; c.fs = f; c.ctx = ctx;
    sort_common(base, n, w, &c);
}
static void *bsearch_common(const void *key, const void *base, size_t n, size_t w, const cmp_t *c)
{
    const char *lo = base;
    while (n) {
        const size_t half = n / 2;
        const char *mid = lo + half * w;
        const int r = do_cmp(c, key, mid);
        if (!r) return (void *)mid;
        if (r > 0) { lo = mid + w; n -= half + 1; }
        else n = half;
    }
    return 0;
}
DLLAPI void *CRTAPI bsearch(const void *key, const void *base, size_t n, size_t w, cmp_fn f)
{
    cmp_t c;
    CRT_VALIDATE(base != 0 || n == 0, CRT_EINVAL, 0);
    CRT_VALIDATE(w > 0 && f != 0, CRT_EINVAL, 0);
    c.f = f; c.fs = 0; c.ctx = 0;
    return bsearch_common(key, base, n, w, &c);
}
DLLAPI void *CRTAPI bsearch_s(const void *key, const void *base, size_t n, size_t w, cmp_s_fn f, void *ctx)
{
    cmp_t c;
    CRT_VALIDATE(base != 0 || n == 0, CRT_EINVAL, 0);
    CRT_VALIDATE(w > 0 && f != 0, CRT_EINVAL, 0);
    c.f = 0; c.fs = f; c.ctx = ctx;
    return bsearch_common(key, base, n, w, &c);
}
DLLAPI void *CRTAPI _lfind(const void *key, const void *base, unsigned *num, unsigned w, cmp_fn f)
{
    unsigned i;
    CRT_VALIDATE(num != 0 && key != 0 && f != 0 && (base != 0 || *num == 0), CRT_EINVAL, 0);
    for (i = 0; i < *num; ++i)
        if (!f(key, (const char *)base + (size_t)i * w)) return (char *)base + (size_t)i * w;
    return 0;
}
DLLAPI void *CRTAPI _lfind_s(const void *key, const void *base, unsigned *num, size_t w, cmp_s_fn f, void *ctx)
{
    unsigned i;
    CRT_VALIDATE(num != 0 && key != 0 && f != 0 && (base != 0 || *num == 0), CRT_EINVAL, 0);
    for (i = 0; i < *num; ++i)
        if (!f(ctx, key, (const char *)base + (size_t)i * w)) return (char *)base + (size_t)i * w;
    return 0;
}
DLLAPI void *CRTAPI _lsearch(const void *key, void *base, unsigned *num, unsigned w, cmp_fn f)
{
    void *p = _lfind(key, base, num, w, f);
    if (p || !num) return p;
    p = (char *)base + (size_t)*num * w;
    crt_memcpy(p, key, w);
    ++*num;
    return p;
}
DLLAPI void *CRTAPI _lsearch_s(const void *key, void *base, unsigned *num, size_t w, cmp_s_fn f, void *ctx)
{
    void *p = _lfind_s(key, base, num, w, f, ctx);
    if (p || !num) return p;
    p = (char *)base + (size_t)*num * w;
    crt_memcpy(p, key, w);
    ++*num;
    return p;
}

/* ---------------------------------------------------------------- arithmetic */
typedef struct { int quot, rem; } crt_div_t;
typedef struct { crt_long quot, rem; } crt_ldiv_t;
typedef struct { long long quot, rem; } crt_lldiv_t;
DLLAPI int CRTAPI abs(int v) { return v < 0 ? -v : v; }
DLLAPI crt_long CRTAPI labs(crt_long v) { return v < 0 ? -v : v; }
DLLAPI long long CRTAPI llabs(long long v) { return v < 0 ? -v : v; }
DLLAPI long long CRTAPI _abs64(long long v) { return v < 0 ? -v : v; }
DLLAPI long long CRTAPI imaxabs(long long v) { return v < 0 ? -v : v; }
DLLAPI crt_div_t CRTAPI div(int a, int b) { crt_div_t r; r.quot = a / b; r.rem = a % b; return r; }
DLLAPI crt_ldiv_t CRTAPI ldiv(crt_long a, crt_long b) { crt_ldiv_t r; r.quot = a / b; r.rem = a % b; return r; }
DLLAPI crt_lldiv_t CRTAPI lldiv(long long a, long long b) { crt_lldiv_t r; r.quot = a / b; r.rem = a % b; return r; }
DLLAPI crt_lldiv_t CRTAPI imaxdiv(long long a, long long b) { return lldiv(a, b); }

DLLAPI void CRTAPI srand(unsigned seed) { crt_getptd()->rand_next = seed; }
DLLAPI int CRTAPI rand(void)
{
    crt_ptd *p = crt_getptd();
    p->rand_next = p->rand_next * 214013u + 2531011u;
    return (int)((p->rand_next >> 16) & 0x7fff);
}

DLLAPI unsigned CRTAPI _rotl(unsigned v, int s) { s &= 31; return s ? (v << s) | (v >> (32 - s)) : v; }
DLLAPI unsigned CRTAPI _rotr(unsigned v, int s) { s &= 31; return s ? (v >> s) | (v << (32 - s)) : v; }
DLLAPI crt_ulong CRTAPI _lrotl(crt_ulong v, int s) { return _rotl(v, s); }
DLLAPI crt_ulong CRTAPI _lrotr(crt_ulong v, int s) { return _rotr(v, s); }
DLLAPI unsigned long long CRTAPI _rotl64(unsigned long long v, int s) { s &= 63; return s ? (v << s) | (v >> (64 - s)) : v; }
DLLAPI unsigned long long CRTAPI _rotr64(unsigned long long v, int s) { s &= 63; return s ? (v >> s) | (v << (64 - s)) : v; }
DLLAPI unsigned short CRTAPI _byteswap_ushort(unsigned short v) { return (unsigned short)((v >> 8) | (v << 8)); }
DLLAPI crt_ulong CRTAPI _byteswap_ulong(crt_ulong v) { return __builtin_bswap32(v); }
DLLAPI unsigned long long CRTAPI _byteswap_uint64(unsigned long long v) { return __builtin_bswap64(v); }
DLLAPI void CRTAPI _swab(char *src, char *dst, int n)
{
    CRT_VALIDATE_NORET(src != 0 && dst != 0 && n >= 0, CRT_EINVAL);
    for (; n > 1; n -= 2, src += 2, dst += 2) { char a = src[0], b = src[1]; dst[0] = b; dst[1] = a; }
}

/* ---------------------------------------------------------------- _splitpath / _makepath */
#define DEFINE_SPLIT(NAME, CH)                                                                                         \
    DLLAPI crt_errno_t CRTAPI NAME(const CH *path, CH *drive, size_t dn, CH *dir, size_t dirn, CH *fname, size_t fn,   \
                                   CH *ext, size_t en)                                                                 \
    {                                                                                                                  \
        const CH *p = path, *last_sep = 0, *dot = 0, *end;                                                             \
        size_t k;                                                                                                      \
        CRT_VALIDATE(path != 0, CRT_EINVAL, CRT_EINVAL);                                                               \
        CRT_VALIDATE((drive || !dn) && (dir || !dirn) && (fname || !fn) && (ext || !en), CRT_EINVAL, CRT_EINVAL);      \
        CRT_VALIDATE((!drive || dn) && (!dir || dirn) && (!fname || fn) && (!ext || en), CRT_EINVAL, CRT_EINVAL);      \
        if (drive) drive[0] = 0;                                                                                       \
        if (dir) dir[0] = 0;                                                                                           \
        if (fname) fname[0] = 0;                                                                                       \
        if (ext) ext[0] = 0;                                                                                           \
        if (p[0] && p[1] == ':') {                                                                                     \
            if (drive) { if (dn < 3) goto range; drive[0] = p[0]; drive[1] = ':'; drive[2] = 0; }                      \
            p += 2;                                                                                                    \
        }                                                                                                              \
        for (end = p; *end; ++end) {                                                                                   \
            if (*end == '/' || *end == '\\') last_sep = end;                                                           \
            else if (*end == '.') dot = end;                                                                           \
        }                                                                                                              \
        if (dot && last_sep && dot < last_sep) dot = 0;                                                                \
        if (last_sep) {                                                                                                \
            k = (size_t)(last_sep + 1 - p);                                                                            \
            if (dir) { if (k >= dirn) goto range; crt_memcpy(dir, p, k * sizeof(CH)); dir[k] = 0; }                    \
            p = last_sep + 1;                                                                                          \
        }                                                                                                              \
        if (!dot) dot = end;                                                                                           \
        k = (size_t)(dot - p);                                                                                         \
        if (fname) { if (k >= fn) goto range; crt_memcpy(fname, p, k * sizeof(CH)); fname[k] = 0; }                    \
        k = (size_t)(end - dot);                                                                                       \
        if (ext) { if (k >= en) goto range; crt_memcpy(ext, dot, k * sizeof(CH)); ext[k] = 0; }                        \
        return 0;                                                                                                      \
    range:                                                                                                             \
        if (drive) drive[0] = 0;                                                                                       \
        if (dir) dir[0] = 0;                                                                                           \
        if (fname) fname[0] = 0;                                                                                       \
        if (ext) ext[0] = 0;                                                                                           \
        CRT_VALIDATE(0, CRT_ERANGE, CRT_ERANGE);                                                                       \
    }
DEFINE_SPLIT(_splitpath_s, char)
DEFINE_SPLIT(_wsplitpath_s, wchar16)
DLLAPI void CRTAPI _splitpath(const char *p, char *d, char *dir, char *f, char *e)
{
    _splitpath_s(p, d, d ? 3 : 0, dir, dir ? 256 : 0, f, f ? 256 : 0, e, e ? 256 : 0);
}
DLLAPI void CRTAPI _wsplitpath(const wchar16 *p, wchar16 *d, wchar16 *dir, wchar16 *f, wchar16 *e)
{
    _wsplitpath_s(p, d, d ? 3 : 0, dir, dir ? 256 : 0, f, f ? 256 : 0, e, e ? 256 : 0);
}

#define DEFINE_MAKE(NAME, CH)                                                                                          \
    DLLAPI crt_errno_t CRTAPI NAME(CH *out, size_t n, const CH *drive, const CH *dir, const CH *fname, const CH *ext)  \
    {                                                                                                                  \
        size_t k = 0;                                                                                                  \
        const CH *s;                                                                                                   \
        CRT_VALIDATE(out != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);                                                       \
        if (drive && *drive) {                                                                                         \
            if (k + 2 >= n) goto range;                                                                                \
            out[k++] = drive[0];                                                                                       \
            out[k++] = ':';                                                                                            \
        }                                                                                                              \
        if (dir && *dir) {                                                                                             \
            for (s = dir; *s; ++s) { if (k + 1 >= n) goto range; out[k++] = *s; }                                    \
            if (s[-1] != '/' && s[-1] != '\\') { if (k + 1 >= n) goto range; out[k++] = '\\'; }                        \
        }                                                                                                              \
        if (fname) for (s = fname; *s; ++s) { if (k + 1 >= n) goto range; out[k++] = *s; }                             \
        if (ext && *ext) {                                                                                             \
            if (*ext != '.') { if (k + 1 >= n) goto range; out[k++] = '.'; }                                           \
            for (s = ext; *s; ++s) { if (k + 1 >= n) goto range; out[k++] = *s; }                                     \
        }                                                                                                              \
        out[k] = 0;                                                                                                    \
        return 0;                                                                                                      \
    range:                                                                                                             \
        out[0] = 0;                                                                                                    \
        CRT_VALIDATE(0, CRT_ERANGE, CRT_ERANGE);                                                                       \
    }
DEFINE_MAKE(_makepath_s, char)
DEFINE_MAKE(_wmakepath_s, wchar16)
DLLAPI void CRTAPI _makepath(char *out, const char *d, const char *dir, const char *f, const char *e) { _makepath_s(out, 260, d, dir, f, e); }
DLLAPI void CRTAPI _wmakepath(wchar16 *out, const wchar16 *d, const wchar16 *dir, const wchar16 *f, const wchar16 *e)
{
    _wmakepath_s(out, 260, d, dir, f, e);
}
