/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - portable base helpers (see base.h).
 */
#include "base.h"

/* ---------------------------------------------------------------------------------------------------- memory */

void *shz_alloc_array(size_t count, size_t size)
{
    if (size && count > (SIZE_MAX / 2) / size) return NULL;
    return shz_alloc(count && size ? count * size : 1);
}

int shz_grow(void **items, size_t *cap, size_t need, size_t esz)
{
    size_t ncap;
    void *p;
    if (need <= *cap) return 1;
    ncap = *cap ? *cap : 8;
    while (ncap < need) {
        if (ncap > (SIZE_MAX / 4) / esz) return 0;
        ncap *= 2;
    }
    p = shz_realloc(*items, ncap * esz);
    if (!p) return 0;
    *items = p;
    *cap = ncap;
    return 1;
}

/* ---------------------------------------------------------------------------------------------------- strings */

size_t shz_strlen(const shz_char *s)
{
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) ++n;
    return n;
}

shz_char *shz_strndup(const shz_char *s, size_t n)
{
    shz_char *r;
    if (n > SIZE_MAX / 8) return NULL;
    r = shz_alloc_array(n + 1, sizeof(shz_char));
    if (!r) return NULL;
    if (n) memcpy(r, s, n * sizeof(shz_char));
    r[n] = 0;
    return r;
}

shz_char *shz_strdup(const shz_char *s)
{
    return s ? shz_strndup(s, shz_strlen(s)) : NULL;
}

shz_char *shz_strdup_lower(const shz_char *s, size_t n)
{
    shz_char *r = shz_strndup(s, n);
    size_t i;
    if (r) for (i = 0; i < n; ++i) r[i] = shz_lower(r[i]);
    return r;
}

shz_char *shz_strdup_ascii(const char *ascii)
{
    size_t n = 0, i;
    shz_char *r;
    while (ascii[n]) ++n;
    r = shz_alloc_array(n + 1, sizeof(shz_char));
    if (!r) return NULL;
    for (i = 0; i < n; ++i) r[i] = (unsigned char)ascii[i];
    return r;
}

int shz_strcmp(const shz_char *a, const shz_char *b)
{
    static const shz_char empty[1] = {0};
    if (!a) a = empty;
    if (!b) b = empty;
    while (*a && *a == *b) { ++a; ++b; }
    return (int)*a - (int)*b;
}

int shz_streq(const shz_char *a, const shz_char *b)
{
    return shz_strcmp(a, b) == 0;
}

int shz_strieq(const shz_char *a, const shz_char *b)
{
    static const shz_char empty[1] = {0};
    if (!a) a = empty;
    if (!b) b = empty;
    while (*a && shz_lower(*a) == shz_lower(*b)) { ++a; ++b; }
    return shz_lower(*a) == shz_lower(*b);
}

int shz_strneq(const shz_char *a, size_t an, const shz_char *b, size_t bn)
{
    return an == bn && (!an || memcmp(a, b, an * sizeof(shz_char)) == 0);
}

int shz_strnieq(const shz_char *a, size_t an, const shz_char *b, size_t bn)
{
    size_t i;
    if (an != bn) return 0;
    for (i = 0; i < an; ++i)
        if (shz_lower(a[i]) != shz_lower(b[i])) return 0;
    return 1;
}

int shz_streq_ascii(const shz_char *s, const char *ascii)
{
    if (!s) return !*ascii;
    while (*ascii && *s == (unsigned char)*ascii) { ++s; ++ascii; }
    return !*ascii && !*s;
}

int shz_strieq_ascii(const shz_char *s, const char *ascii)
{
    if (!s) return !*ascii;
    while (*ascii && shz_lower(*s) == shz_lower((unsigned char)*ascii)) { ++s; ++ascii; }
    return !*ascii && !*s;
}

int shz_strnieq_ascii(const shz_char *s, size_t n, const char *ascii)
{
    size_t i;
    for (i = 0; i < n; ++i)
        if (!ascii[i] || shz_lower(s[i]) != shz_lower((unsigned char)ascii[i])) return 0;
    return ascii[n] == 0;
}

int shz_strneq_ascii(const shz_char *s, size_t n, const char *ascii)
{
    size_t i;
    for (i = 0; i < n; ++i)
        if (!ascii[i] || s[i] != (unsigned char)ascii[i]) return 0;
    return ascii[n] == 0;
}

int shz_starts_with_ascii_ci(const shz_char *s, size_t n, const char *prefix)
{
    size_t i;
    for (i = 0; prefix[i]; ++i)
        if (i >= n || shz_lower(s[i]) != shz_lower((unsigned char)prefix[i])) return 0;
    return 1;
}

size_t shz_strnstr(const shz_char *hay, size_t hn, const shz_char *needle, size_t nn)
{
    size_t i;
    if (nn == 0) return 0;
    if (nn > hn) return (size_t)-1;
    for (i = 0; i + nn <= hn; ++i)
        if (hay[i] == needle[0] && memcmp(hay + i, needle, nn * sizeof(shz_char)) == 0) return i;
    return (size_t)-1;
}

const shz_char *shz_trim(const shz_char *s, size_t *n)
{
    size_t len = *n;
    while (len && shz_is_space(*s)) { ++s; --len; }
    while (len && shz_is_space(s[len - 1])) --len;
    *n = len;
    return s;
}

int shz_token_list_has(const shz_char *s, size_t n, const shz_char *token, size_t tn, int ci)
{
    size_t i = 0;
    if (!tn) return 0;
    while (i < n) {
        size_t start;
        while (i < n && shz_is_space(s[i])) ++i;
        start = i;
        while (i < n && !shz_is_space(s[i])) ++i;
        if (i > start && (ci ? shz_strnieq(s + start, i - start, token, tn) : shz_strneq(s + start, i - start, token, tn)))
            return 1;
    }
    return 0;
}

/* ---------------------------------------------------------------------------------------------------- shz_buf */

void shz_buf_init(shz_buf *b)
{
    b->s = NULL;
    b->len = b->cap = 0;
    b->oom = 0;
}

void shz_buf_free(shz_buf *b)
{
    shz_free(b->s);
    shz_buf_init(b);
}

void shz_buf_clear(shz_buf *b)
{
    b->len = 0;
    b->oom = 0;
}

int shz_buf_reserve(shz_buf *b, size_t extra)
{
    size_t need;
    void *p;
    if (b->oom) return 0;
    if (extra > SIZE_MAX / 4 - b->len) { b->oom = 1; return 0; }
    need = b->len + extra + 1;
    if (need <= b->cap) return 1;
    p = b->s;
    if (!shz_grow(&p, &b->cap, need, sizeof(shz_char))) { b->oom = 1; return 0; }
    b->s = p;
    return 1;
}

void shz_buf_putc(shz_buf *b, shz_char c)
{
    if (b->len + 1 >= b->cap && !shz_buf_reserve(b, 1)) return;
    b->s[b->len++] = c;
}

void shz_buf_put_cp(shz_buf *b, uint32_t cp)
{
    if (cp >= 0x10000) {
        cp -= 0x10000;
        shz_buf_putc(b, (shz_char)(0xD800 + (cp >> 10)));
        shz_buf_putc(b, (shz_char)(0xDC00 + (cp & 0x3FF)));
    } else {
        shz_buf_putc(b, (shz_char)cp);
    }
}

void shz_buf_put(shz_buf *b, const shz_char *s, size_t n)
{
    if (!n || !shz_buf_reserve(b, n)) return;
    memcpy(b->s + b->len, s, n * sizeof(shz_char));
    b->len += n;
}

void shz_buf_puts(shz_buf *b, const shz_char *s)
{
    shz_buf_put(b, s, shz_strlen(s));
}

void shz_buf_put_ascii(shz_buf *b, const char *s)
{
    while (*s) shz_buf_putc(b, (unsigned char)*s++);
}

void shz_buf_put_int(shz_buf *b, long long v)
{
    char tmp[24];
    int i = 0;
    unsigned long long u = v < 0 ? 0ULL - (unsigned long long)v : (unsigned long long)v;
    do { tmp[i++] = (char)('0' + u % 10); u /= 10; } while (u);
    if (v < 0) shz_buf_putc(b, '-');
    while (i) shz_buf_putc(b, (shz_char)tmp[--i]);
}

void shz_buf_put_double(shz_buf *b, double v, int frac_digits)
{
    double scale = 1, r;
    long long whole, frac;
    int i, neg = v < 0;
    char digits[24];
    if (v != v) { shz_buf_put_ascii(b, "NaN"); return; }
    if (frac_digits < 0) frac_digits = 0;
    if (frac_digits > 9) frac_digits = 9;
    for (i = 0; i < frac_digits; ++i) scale *= 10;
    r = shz_round(shz_fabs(v) * scale);
    if (r > 9.0e17) r = 9.0e17;
    whole = (long long)(r / scale);
    frac = (long long)(r - (double)whole * scale);
    if (neg && (whole || frac)) shz_buf_putc(b, '-');
    shz_buf_put_int(b, whole);
    if (frac && frac_digits) {
        for (i = frac_digits - 1; i >= 0; --i) { digits[i] = (char)('0' + frac % 10); frac /= 10; }
        i = frac_digits;
        while (i > 0 && digits[i - 1] == '0') --i;
        shz_buf_putc(b, '.');
        for (frac = 0; frac < i; ++frac) shz_buf_putc(b, (shz_char)digits[frac]);
    }
}

void shz_buf_insert(shz_buf *b, size_t at, const shz_char *s, size_t n)
{
    if (!n || at > b->len || !shz_buf_reserve(b, n)) return;
    memmove(b->s + at + n, b->s + at, (b->len - at) * sizeof(shz_char));
    memcpy(b->s + at, s, n * sizeof(shz_char));
    b->len += n;
}

void shz_buf_erase(shz_buf *b, size_t at, size_t n)
{
    if (at >= b->len) return;
    if (n > b->len - at) n = b->len - at;
    memmove(b->s + at, b->s + at + n, (b->len - at - n) * sizeof(shz_char));
    b->len -= n;
}

shz_char *shz_buf_detach(shz_buf *b)
{
    shz_char *r;
    if (b->oom) { shz_buf_free(b); return NULL; }
    if (!b->s) {
        r = shz_alloc(sizeof(shz_char));
        shz_buf_init(b);
        return r;
    }
    b->s[b->len] = 0;
    r = b->s;
    shz_buf_init(b);
    return r;
}

/* ---------------------------------------------------------------------------------------------------- shz_bytes */

void shz_bytes_init(shz_bytes *b)
{
    b->p = NULL;
    b->len = b->cap = 0;
    b->oom = 0;
}

void shz_bytes_free(shz_bytes *b)
{
    shz_free(b->p);
    shz_bytes_init(b);
}

void shz_bytes_put(shz_bytes *b, const void *data, size_t n)
{
    void *p;
    if (b->oom || !n) return;
    if (n > SIZE_MAX / 4 - b->len) { b->oom = 1; return; }
    p = b->p;
    if (!shz_grow(&p, &b->cap, b->len + n + 1, 1)) { b->oom = 1; return; }
    b->p = p;
    memcpy(b->p + b->len, data, n);
    b->len += n;
}

void shz_bytes_putc(shz_bytes *b, uint8_t c)
{
    shz_bytes_put(b, &c, 1);
}

void shz_bytes_put_ascii(shz_bytes *b, const char *s)
{
    size_t n = 0;
    while (s[n]) ++n;
    shz_bytes_put(b, s, n);
}

void shz_bytes_put_utf8(shz_bytes *b, const shz_char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        uint32_t c = s[i];
        uint8_t out[4];
        if (shz_is_high_surrogate(c) && i + 1 < n && shz_is_low_surrogate(s[i + 1])) {
            c = 0x10000 + ((c - 0xD800) << 10) + (s[i + 1] - 0xDC00);
            ++i;
        } else if (shz_is_high_surrogate(c) || shz_is_low_surrogate(c)) {
            c = 0xFFFD;
        }
        if (c < 0x80) {
            shz_bytes_putc(b, (uint8_t)c);
        } else if (c < 0x800) {
            out[0] = (uint8_t)(0xC0 | (c >> 6)); out[1] = (uint8_t)(0x80 | (c & 0x3F));
            shz_bytes_put(b, out, 2);
        } else if (c < 0x10000) {
            out[0] = (uint8_t)(0xE0 | (c >> 12)); out[1] = (uint8_t)(0x80 | ((c >> 6) & 0x3F));
            out[2] = (uint8_t)(0x80 | (c & 0x3F));
            shz_bytes_put(b, out, 3);
        } else {
            out[0] = (uint8_t)(0xF0 | (c >> 18)); out[1] = (uint8_t)(0x80 | ((c >> 12) & 0x3F));
            out[2] = (uint8_t)(0x80 | ((c >> 6) & 0x3F)); out[3] = (uint8_t)(0x80 | (c & 0x3F));
            shz_bytes_put(b, out, 4);
        }
    }
}

/* ---------------------------------------------------------------------------------------------------- shz_vec */

void shz_vec_init(shz_vec *v)
{
    v->items = NULL;
    v->len = v->cap = 0;
    v->oom = 0;
}

void shz_vec_free(shz_vec *v)
{
    shz_free(v->items);
    shz_vec_init(v);
}

int shz_vec_push(shz_vec *v, void *item)
{
    void *p = v->items;
    if (v->oom) return 0;
    if (!shz_grow(&p, &v->cap, v->len + 1, sizeof(void *))) { v->oom = 1; return 0; }
    v->items = p;
    v->items[v->len++] = item;
    return 1;
}

void shz_vec_insert(shz_vec *v, size_t at, void *item)
{
    if (at > v->len || !shz_vec_push(v, item)) return;
    memmove(v->items + at + 1, v->items + at, (v->len - 1 - at) * sizeof(void *));
    v->items[at] = item;
}

void shz_vec_remove_at(shz_vec *v, size_t at)
{
    if (at >= v->len) return;
    memmove(v->items + at, v->items + at + 1, (v->len - at - 1) * sizeof(void *));
    --v->len;
}

size_t shz_vec_index(const shz_vec *v, const void *item)
{
    size_t i;
    for (i = 0; i < v->len; ++i)
        if (v->items[i] == item) return i;
    return (size_t)-1;
}

/* ---------------------------------------------------------------------------------------------------- numbers */

static int parse_int_common(const shz_char *s, size_t n, long *out, int allow_sign)
{
    size_t i = 0;
    int neg = 0, any = 0;
    long long v = 0;
    while (i < n && shz_is_space(s[i])) ++i;
    if (i < n && (s[i] == '-' || s[i] == '+')) {
        if (s[i] == '-') {
            if (!allow_sign) return 0;
            neg = 1;
        }
        ++i;
    }
    while (i < n && shz_is_ascii_digit(s[i])) {
        any = 1;
        if (v < 0x7fffffffLL) v = v * 10 + (s[i] - '0');
        ++i;
    }
    if (!any) return 0;
    if (v > 0x7fffffffLL) v = 0x7fffffffLL;
    *out = (long)(neg ? -v : v);
    return 1;
}

int shz_parse_int(const shz_char *s, size_t n, long *out)
{
    return parse_int_common(s, n, out, 1);
}

int shz_parse_uint(const shz_char *s, size_t n, long *out)
{
    return parse_int_common(s, n, out, 0);
}

size_t shz_parse_number(const shz_char *s, size_t n, double *out)
{
    size_t i = 0, digits = 0;
    double v = 0, frac_scale = 1;
    int neg = 0;
    if (i < n && (s[i] == '+' || s[i] == '-')) { neg = s[i] == '-'; ++i; }
    while (i < n && shz_is_ascii_digit(s[i])) { v = v * 10 + (s[i] - '0'); ++i; ++digits; }
    if (i + 1 < n && s[i] == '.' && shz_is_ascii_digit(s[i + 1])) {
        ++i;
        while (i < n && shz_is_ascii_digit(s[i])) {
            frac_scale /= 10;
            v += (s[i] - '0') * frac_scale;
            ++i;
            ++digits;
        }
    }
    if (!digits) return 0;
    if (i < n && (s[i] == 'e' || s[i] == 'E')) {
        size_t j = i + 1;
        int eneg = 0;
        long e = 0;
        if (j < n && (s[j] == '+' || s[j] == '-')) { eneg = s[j] == '-'; ++j; }
        if (j < n && shz_is_ascii_digit(s[j])) {
            while (j < n && shz_is_ascii_digit(s[j])) { if (e < 400) e = e * 10 + (s[j] - '0'); ++j; }
            while (e-- > 0) v = eneg ? v / 10 : v * 10;
            i = j;
        }
    }
    *out = neg ? -v : v;
    return i;
}

double shz_floor(double v)
{
    double t;
    if (v != v || v >= 4503599627370496.0 || v <= -4503599627370496.0) return v;
    t = (double)(long long)v;
    return t > v ? t - 1 : t;
}

double shz_ceil(double v)
{
    double t;
    if (v != v || v >= 4503599627370496.0 || v <= -4503599627370496.0) return v;
    t = (double)(long long)v;
    return t < v ? t + 1 : t;
}

double shz_round(double v)
{
    return v < 0 ? -shz_floor(-v + 0.5) : shz_floor(v + 0.5);
}
