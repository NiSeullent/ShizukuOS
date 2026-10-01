/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - portable base: result codes, memory, UTF-16 strings, growable buffers, vectors, numbers.
 *
 * Everything under core/ is plain C99 with no windows.h: it builds into shzlite.dll (x86_64-w64-mingw32, freestanding,
 * -nostdlib) and into the Linux host tests (gcc, ASan/UBSan). The only libc symbols core code may use are memcpy,
 * memmove, memset and memcmp (win/crt_min.c provides them inside the DLL); everything else is here or in platform.h.
 */
#ifndef SHZ_BASE_H
#define SHZ_BASE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* UTF-16 code unit. Same size and representation as WCHAR; the Windows glue casts between the two. */
typedef uint16_t shz_char;

/* ---------------------------------------------------------------------------------------------------- results */
/* Numerically identical to the HRESULTs of engine.h, so the glue returns them unchanged. */
typedef int32_t shz_res;
#define SHZ_OK              ((shz_res)0)
#define SHZ_FALSE           ((shz_res)1)            /* "no value": absent attribute, no such node, null string */
#define SHZ_E_NOTIMPL       ((shz_res)0x80004001)
#define SHZ_E_POINTER       ((shz_res)0x80004003)
#define SHZ_E_ABORT         ((shz_res)0x80004004)
#define SHZ_E_FAIL          ((shz_res)0x80004005)
#define SHZ_E_UNEXPECTED    ((shz_res)0x8000FFFF)
#define SHZ_E_OUTOFMEMORY   ((shz_res)0x8007000E)
#define SHZ_E_INVALIDARG    ((shz_res)0x80070057)
/* DOM exceptions: the nsresult values Gecko uses (NS_ERROR_DOM_*), so trident/xul can hand them to mshtml as is. */
#define SHZ_E_INDEX_SIZE     ((shz_res)0x80530001)
#define SHZ_E_HIERARCHY      ((shz_res)0x80530003)
#define SHZ_E_WRONG_DOCUMENT ((shz_res)0x80530004)
#define SHZ_E_INVALID_CHAR   ((shz_res)0x80530005)
#define SHZ_E_NOT_FOUND      ((shz_res)0x80530008)
#define SHZ_E_NOT_SUPPORTED  ((shz_res)0x80530009)
#define SHZ_E_INVALID_STATE  ((shz_res)0x8053000B)
#define SHZ_E_SYNTAX         ((shz_res)0x8053000C)
#define SHZ_FAILED(r)    ((shz_res)(r) < 0)
#define SHZ_SUCCEEDED(r) ((shz_res)(r) >= 0)

#define SHZ_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define SHZ_UNUSED(x) ((void)(x))
#define SHZ_MIN(a, b) ((a) < (b) ? (a) : (b))
#define SHZ_MAX(a, b) ((a) > (b) ? (a) : (b))

/* ---------------------------------------------------------------------------------------------------- memory */
/* Provided by the platform (platform.h): zero-filled allocation; shz_realloc keeps the old contents (new bytes are NOT
 * zeroed); shz_free(NULL) is a no-op. All three are the only allocator of the engine: strings handed to the engine.h
 * caller are released by vtbl->str_free = shz_free. */
void *shz_alloc(size_t n);
void *shz_realloc(void *p, size_t n);
void  shz_free(void *p);
void *shz_alloc_array(size_t count, size_t size);          /* overflow-checked, zero-filled */
/* Grow *items (element size esz) so that it holds at least need elements; returns 0 on overflow/OOM (unchanged). */
int   shz_grow(void **items, size_t *cap, size_t need, size_t esz);

/* ---------------------------------------------------------------------------------------------------- characters */
static inline int shz_is_ascii_alpha(uint32_t c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
static inline int shz_is_ascii_digit(uint32_t c) { return c >= '0' && c <= '9'; }
static inline int shz_is_ascii_alnum(uint32_t c) { return shz_is_ascii_alpha(c) || shz_is_ascii_digit(c); }
static inline int shz_is_ascii_hex(uint32_t c) { return shz_is_ascii_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
static inline int shz_is_ascii_upper(uint32_t c) { return c >= 'A' && c <= 'Z'; }
/* HTML "ASCII whitespace": TAB, LF, FF, CR, SPACE */
static inline int shz_is_space(uint32_t c) { return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'; }
static inline shz_char shz_lower(shz_char c) { return (c >= 'A' && c <= 'Z') ? (shz_char)(c + 32) : c; }
static inline shz_char shz_upper(shz_char c) { return (c >= 'a' && c <= 'z') ? (shz_char)(c - 32) : c; }
static inline int shz_hex_value(uint32_t c)
{
    return c <= '9' ? (int)c - '0' : (c >= 'a' ? (int)c - 'a' + 10 : (int)c - 'A' + 10);
}

/* ---------------------------------------------------------------------------------------------------- strings */
/* NUL-terminated UTF-16 strings. Functions returning shz_char * allocate (shz_alloc) and return NULL on OOM. */
size_t    shz_strlen(const shz_char *s);                         /* NULL -> 0 */
shz_char *shz_strdup(const shz_char *s);                         /* NULL -> NULL */
shz_char *shz_strndup(const shz_char *s, size_t n);              /* copies n units + NUL (s may be NULL if n == 0) */
shz_char *shz_strdup_lower(const shz_char *s, size_t n);         /* ASCII lower-case copy */
shz_char *shz_strdup_ascii(const char *ascii);                   /* widen */
int       shz_strcmp(const shz_char *a, const shz_char *b);      /* code-unit order; NULL == "" */
int       shz_streq(const shz_char *a, const shz_char *b);       /* NULL == "" */
int       shz_strieq(const shz_char *a, const shz_char *b);      /* ASCII case-insensitive */
int       shz_strneq(const shz_char *a, size_t an, const shz_char *b, size_t bn);
int       shz_strnieq(const shz_char *a, size_t an, const shz_char *b, size_t bn);
int       shz_streq_ascii(const shz_char *s, const char *ascii);
int       shz_strieq_ascii(const shz_char *s, const char *ascii);
int       shz_strnieq_ascii(const shz_char *s, size_t n, const char *ascii);  /* s[0..n) equals ascii ignoring case */
int       shz_strneq_ascii(const shz_char *s, size_t n, const char *ascii);
int       shz_starts_with_ascii_ci(const shz_char *s, size_t n, const char *prefix);
/* Find the first occurrence of needle (length nn) in hay (length hn); returns the index or (size_t)-1. */
size_t    shz_strnstr(const shz_char *hay, size_t hn, const shz_char *needle, size_t nn);
/* Trim HTML whitespace from both ends of s[0..*n): returns the new start and updates *n. */
const shz_char *shz_trim(const shz_char *s, size_t *n);
/* Does the whitespace-separated token list s[0..n) contain token (tn units)? ci = ASCII case-insensitive. */
int       shz_token_list_has(const shz_char *s, size_t n, const shz_char *token, size_t tn, int ci);

/* ---------------------------------------------------------------------------------------------------- shz_buf */
/* Growable UTF-16 string. After an allocation failure .oom is set and further appends are ignored. */
typedef struct shz_buf {
    shz_char *s;
    size_t len, cap;
    int oom;
} shz_buf;

void      shz_buf_init(shz_buf *b);
void      shz_buf_free(shz_buf *b);
void      shz_buf_clear(shz_buf *b);                             /* len = 0, keeps the storage */
int       shz_buf_reserve(shz_buf *b, size_t extra);             /* room for extra units + NUL; 0 on OOM */
void      shz_buf_putc(shz_buf *b, shz_char c);
void      shz_buf_put_cp(shz_buf *b, uint32_t cp);               /* code point, as a surrogate pair above U+FFFF */
void      shz_buf_put(shz_buf *b, const shz_char *s, size_t n);
void      shz_buf_puts(shz_buf *b, const shz_char *s);
void      shz_buf_put_ascii(shz_buf *b, const char *s);
void      shz_buf_put_int(shz_buf *b, long long v);
/* Decimal with at most frac_digits fractional digits, trailing zeros (and a bare '.') removed: 12.5, 3, -0.25 */
void      shz_buf_put_double(shz_buf *b, double v, int frac_digits);
void      shz_buf_insert(shz_buf *b, size_t at, const shz_char *s, size_t n);
void      shz_buf_erase(shz_buf *b, size_t at, size_t n);
/* Returns the NUL-terminated string (ownership moves to the caller) and resets b; NULL after OOM (b is freed then).
 * An empty buffer yields an allocated "" (never NULL unless OOM). */
shz_char *shz_buf_detach(shz_buf *b);
static inline const shz_char *shz_buf_cstr(shz_buf *b)            /* NUL-terminated view; "" when empty */
{
    static const shz_char empty[1] = {0};
    if (!b->s) return empty;
    b->s[b->len] = 0;
    return b->s;
}

/* ---------------------------------------------------------------------------------------------------- shz_bytes */
typedef struct shz_bytes {
    uint8_t *p;
    size_t len, cap;
    int oom;
} shz_bytes;

void shz_bytes_init(shz_bytes *b);
void shz_bytes_free(shz_bytes *b);
void shz_bytes_put(shz_bytes *b, const void *data, size_t n);
void shz_bytes_putc(shz_bytes *b, uint8_t c);
void shz_bytes_put_ascii(shz_bytes *b, const char *s);
/* Append UTF-16 as UTF-8 (lone surrogates become U+FFFD). */
void shz_bytes_put_utf8(shz_bytes *b, const shz_char *s, size_t n);

/* ---------------------------------------------------------------------------------------------------- shz_vec */
typedef struct shz_vec {
    void **items;
    size_t len, cap;
    int oom;
} shz_vec;

void shz_vec_init(shz_vec *v);
void shz_vec_free(shz_vec *v);                                   /* frees the array only */
int  shz_vec_push(shz_vec *v, void *item);                       /* 0 on OOM */
void shz_vec_insert(shz_vec *v, size_t at, void *item);
void shz_vec_remove_at(shz_vec *v, size_t at);
size_t shz_vec_index(const shz_vec *v, const void *item);        /* (size_t)-1 when absent */

/* ---------------------------------------------------------------------------------------------------- numbers */
/* HTML "rules for parsing integers" (leading whitespace, optional sign, digits; stops at the first non-digit).
 * Returns 1 and *out when at least one digit was found. Values saturate at +-2^31-1. */
int    shz_parse_int(const shz_char *s, size_t n, long *out);
/* Non-negative variant ("rules for parsing non-negative integers"). */
int    shz_parse_uint(const shz_char *s, size_t n, long *out);
/* Decimal number: [sign] digits [. digits] [e [sign] digits] (CSS/HTML syntax; no leading whitespace skipped).
 * Returns the number of units consumed (0 = no number). */
size_t shz_parse_number(const shz_char *s, size_t n, double *out);
/* math helpers (no libm inside the DLL) */
double shz_floor(double v);
double shz_ceil(double v);
double shz_round(double v);                                      /* half away from zero */
static inline double shz_fabs(double v) { return v < 0 ? -v : v; }
static inline long shz_lround(double v) { return (long)shz_round(v); }

/* ---------------------------------------------------------------------------------------------------- geometry */
/* Integer rectangle in CSS px (= device px at 96 DPI): left/top inclusive, right/bottom exclusive, like RECT. */
typedef struct shz_irect {
    int32_t left, top, right, bottom;
} shz_irect;

/* ---------------------------------------------------------------------------------------------------- UTF-16 */
static inline int shz_is_high_surrogate(uint32_t c) { return c >= 0xD800 && c <= 0xDBFF; }
static inline int shz_is_low_surrogate(uint32_t c) { return c >= 0xDC00 && c <= 0xDFFF; }

#endif /* SHZ_BASE_H */
