/* SPDX-License-Identifier: GPL-2.0-only
 * shzinf: INF engine in portable C (see shzinf.h). Every rule here mirrors shizukudos/ntdrv/inf.py line for line;
 * shizukudos/ntdrv/tests/test_shzpnp.py compiles this file for the host and compares both on the same INFs. */
#include "shzinf.h"
#include <string.h>

/* ------------------------------------------------------------------------------------------------ arena + strings */
typedef struct chunk { struct chunk *next; size_t used, cap; unsigned char data[1]; } chunk_t;
typedef struct { chunk_t *head; } arena_t;

static void *arena_alloc(arena_t *a, size_t n)
{
    chunk_t *c = a->head;
    n = (n + 15) & ~(size_t)15;
    if (!c || c->used + n > c->cap) {
        size_t cap = n > 65536 ? n : 65536;
        c = (chunk_t *)SHZINF_MALLOC(sizeof(chunk_t) + cap);
        if (!c) return 0;
        c->next = a->head;
        c->used = 0;
        c->cap = cap;
        a->head = c;
    }
    c->used += n;
    memset(c->data + c->used - n, 0, n);
    return c->data + c->used - n;
}

static void arena_free(arena_t *a)
{
    while (a->head) {
        chunk_t *n = a->head->next;
        SHZINF_FREE(a->head);
        a->head = n;
    }
}

static char *adup(arena_t *a, const char *s, size_t n)
{
    char *d = (char *)arena_alloc(a, n + 1);
    if (d) { memcpy(d, s, n); d[n] = 0; }
    return d;
}

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

static const char *s_chr(const char *s, int c) { for (; *s; ++s) if (*s == (char)c) return s; return 0; }
static const void *m_chr(const void *p, int c, size_t n)
{
    const unsigned char *s = (const unsigned char *)p;
    size_t i;
    for (i = 0; i < n; ++i) if (s[i] == (unsigned char)c) return s + i;
    return 0;
}
static int s_ncmp(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) if (a[i] != b[i] || !a[i]) return (unsigned char)a[i] - (unsigned char)b[i];
    return 0;
}
static int upper(int c) { return c >= 'a' && c <= 'z' ? c - 32 : c; }

int shzinf_stricmp(const char *a, const char *b)
{
    while (*a && lower((unsigned char)*a) == lower((unsigned char)*b)) { ++a; ++b; }
    return lower((unsigned char)*a) - lower((unsigned char)*b);
}

static int strnicmp_(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        int x = lower((unsigned char)a[i]), y = lower((unsigned char)b[i]);
        if (x != y || !x) return x - y;
    }
    return 0;
}

/* Python str.isspace() for the ASCII range plus U+0085/U+00A0 (encoded in UTF-8) is what .strip() removes; only the
 * ASCII set (and \x1c-\x1f) is handled here, which covers INF files in practice. */
static int is_space(int c) { return c == ' ' || (c >= 9 && c <= 13) || (c >= 0x1c && c <= 0x1f); }

static void strip_range(const char **s, const char **e)
{
    while (*s < *e && is_space((unsigned char)**s)) ++*s;
    while (*e > *s && is_space((unsigned char)(*e)[-1])) --*e;
}

/* Python int(x, 0) (sign, 0x/0o/0b prefixes, underscores between digits, no leading zeros on decimals except 0...) */
static int py_int0(const char *s, int64_t *out)
{
    const char *e = s + strlen(s);
    int neg = 0, base = 10, any = 0, prev_us = 1;
    uint64_t v = 0;
    strip_range(&s, &e);
    if (s < e && (*s == '+' || *s == '-')) { neg = *s == '-'; ++s; }
    if (e - s >= 2 && s[0] == '0' && (lower(s[1]) == 'x' || lower(s[1]) == 'o' || lower(s[1]) == 'b')) {
        base = lower(s[1]) == 'x' ? 16 : lower(s[1]) == 'o' ? 8 : 2;
        s += 2;
        prev_us = 0;                                   /* "0x_1" is valid in Python */
    } else if (e - s >= 2 && s[0] == '0') {
        const char *p;
        for (p = s; p < e; ++p)
            if (*p != '0' && *p != '_') return 0;      /* "010" is an error in base 0 */
    }
    for (; s < e; ++s) {
        int d;
        if (*s == '_') { if (prev_us) return 0; prev_us = 1; continue; }
        d = *s >= '0' && *s <= '9' ? *s - '0' : (lower(*s) >= 'a' && lower(*s) <= 'z') ? lower(*s) - 'a' + 10 : 99;
        if (d >= base) return 0;
        v = v * (uint64_t)base + (uint64_t)d;
        any = 1;
        prev_us = 0;
    }
    if (!any || prev_us) return 0;
    *out = neg ? -(int64_t)v : (int64_t)v;
    return 1;
}

static int py_int16(const char *s, int64_t *out)          /* int(x, 16): optional 0x prefix */
{
    const char *e = s + strlen(s);
    int neg = 0, any = 0;
    uint64_t v = 0;
    strip_range(&s, &e);
    if (s < e && (*s == '+' || *s == '-')) { neg = *s == '-'; ++s; }
    if (e - s >= 2 && s[0] == '0' && lower(s[1]) == 'x') s += 2;
    for (; s < e; ++s) {
        int c = lower((unsigned char)*s), d;
        if (c == '_') continue;
        d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
        if (d < 0) return 0;
        v = v * 16 + (uint64_t)d;
        any = 1;
    }
    if (!any) return 0;
    *out = neg ? -(int64_t)v : (int64_t)v;
    return 1;
}

/* ------------------------------------------------------------------------------------------------------- decoding */
static const uint16_t cp1252_hi[32] = { 0x20AC, 0xFFFD, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030,
    0x0160, 0x2039, 0x0152, 0xFFFD, 0x017D, 0xFFFD, 0xFFFD, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0xFFFD, 0x017E, 0x0178 };

static size_t put_utf8(unsigned char *o, uint32_t c)
{
    if (c < 0x80) { o[0] = (unsigned char)c; return 1; }
    if (c < 0x800) { o[0] = (unsigned char)(0xC0 | (c >> 6)); o[1] = (unsigned char)(0x80 | (c & 63)); return 2; }
    if (c < 0x10000) { o[0] = (unsigned char)(0xE0 | (c >> 12)); o[1] = (unsigned char)(0x80 | ((c >> 6) & 63)); o[2] = (unsigned char)(0x80 | (c & 63)); return 3; }
    o[0] = (unsigned char)(0xF0 | (c >> 18)); o[1] = (unsigned char)(0x80 | ((c >> 12) & 63));
    o[2] = (unsigned char)(0x80 | ((c >> 6) & 63)); o[3] = (unsigned char)(0x80 | (c & 63));
    return 4;
}

static int valid_utf8(const unsigned char *s, size_t n)
{
    size_t i = 0;
    while (i < n) {
        unsigned char c = s[i];
        size_t k, len = c < 0x80 ? 1 : (c & 0xE0) == 0xC0 ? 2 : (c & 0xF0) == 0xE0 ? 3 : (c & 0xF8) == 0xF0 ? 4 : 0;
        if (!len || i + len > n || (len == 2 && c < 0xC2)) return 0;
        for (k = 1; k < len; ++k)
            if ((s[i + k] & 0xC0) != 0x80) return 0;
        i += len;
    }
    return 1;
}

/* -> NUL-terminated UTF-8 text (inf.py Inf.load: UTF-16 BOMs, UTF-8 BOM, UTF-8, else cp1252) */
static char *decode(arena_t *a, const unsigned char *d, size_t n)
{
    unsigned char *o, *p;
    size_t i;
    if (n >= 2 && ((d[0] == 0xFF && d[1] == 0xFE) || (d[0] == 0xFE && d[1] == 0xFF))) {
        int be = d[0] == 0xFE;
        o = p = (unsigned char *)arena_alloc(a, (n / 2) * 3 + 4);
        for (i = 2; i + 1 < n; i += 2) {
            uint32_t c = be ? (uint32_t)(d[i] << 8 | d[i + 1]) : (uint32_t)(d[i + 1] << 8 | d[i]);
            if (c >= 0xD800 && c < 0xDC00 && i + 3 < n) {
                uint32_t c2 = be ? (uint32_t)(d[i + 2] << 8 | d[i + 3]) : (uint32_t)(d[i + 3] << 8 | d[i + 2]);
                if (c2 >= 0xDC00 && c2 < 0xE000) { c = 0x10000 + ((c - 0xD800) << 10) + (c2 - 0xDC00); i += 2; }
                else c = 0xFFFD;
            } else if (c >= 0xD800 && c < 0xE000) c = 0xFFFD;
            p += put_utf8(p, c);
        }
        *p = 0;
        return (char *)o;
    }
    if (n >= 3 && d[0] == 0xEF && d[1] == 0xBB && d[2] == 0xBF) { d += 3; n -= 3; }
    if (valid_utf8(d, n)) return adup(a, (const char *)d, n);
    o = p = (unsigned char *)arena_alloc(a, n * 3 + 1);
    for (i = 0; i < n; ++i)
        p += put_utf8(p, d[i] >= 0x80 && d[i] < 0xA0 ? cp1252_hi[d[i] - 0x80] : d[i]);
    *p = 0;
    return (char *)o;
}

/* ------------------------------------------------------------------------------------------------------------ lexing */
typedef struct { const char *s; size_t n; } span_t;

/* split on `sep` outside "..." ("" inside quotes is an escaped quote); returns count (pieces point into text) */
static int split_outside_quotes(const char *s, size_t n, char sep, span_t *out, int max)
{
    int cnt = 0, inq = 0;
    size_t i, start = 0;
    for (i = 0; i < n; ++i) {
        if (s[i] == '"') {
            if (inq && i + 1 < n && s[i + 1] == '"') { ++i; continue; }
            inq = !inq;
        } else if (s[i] == sep && !inq) {
            if (cnt < max) { out[cnt].s = s + start; out[cnt].n = i - start; }
            ++cnt;
            start = i + 1;
        }
    }
    if (cnt < max) { out[cnt].s = s + start; out[cnt].n = n - start; }
    return cnt + 1;
}

static char *unquote(arena_t *a, const char *s, size_t n)
{
    const char *e = s + n;
    char *o, *p;
    strip_range(&s, &e);
    n = (size_t)(e - s);
    if (n >= 2 && s[0] == '"' && e[-1] == '"') { ++s; --e; }
    else if (n >= 1 && s[0] == '"') ++s;
    else return adup(a, s, n);
    o = p = (char *)arena_alloc(a, (size_t)(e - s) + 1);
    while (s < e) {
        if (s[0] == '"' && s + 1 < e && s[1] == '"') { *p++ = '"'; s += 2; continue; }
        *p++ = *s++;
    }
    *p = 0;
    return o;
}

typedef struct { shzinf_t pub; arena_t a; } inf_impl_t;

static const char *str_lookup(const shzinf_t *inf, const char *tok, size_t n)
{
    int i;
    for (i = 0; i < inf->nstr; ++i)
        if (strlen(inf->strk[i]) == n && strnicmp_(inf->strk[i], tok, n) == 0) return inf->strv[i];
    return 0;
}

static char *substitute(arena_t *a, const shzinf_t *inf, const char *s)
{
    size_t cap = strlen(s) + 1, used = 0, i = 0, n = strlen(s);
    char *o;
    if (!s_chr(s, '%')) return (char *)s;
    o = (char *)SHZINF_MALLOC(cap);
    if (!o) return (char *)s;
#define PUT(src, len) do { size_t l_ = (len); if (used + l_ + 1 > cap) { cap = (used + l_ + 1) * 2; o = (char *)SHZINF_REALLOC(o, cap); } memcpy(o + used, (src), l_); used += l_; } while (0)
    while (i < n) {
        const char *j;
        if (s[i] != '%') { PUT(s + i, 1); ++i; continue; }
        if (i + 1 < n && s[i + 1] == '%') { PUT("%", 1); i += 2; continue; }
        j = s_chr(s + i + 1, '%');
        if (!j) { PUT(s + i, n - i); break; }
        {
            const char *v = str_lookup(inf, s + i + 1, (size_t)(j - (s + i + 1)));
            if (v) PUT(v, strlen(v));
            else PUT(s + i, (size_t)(j - (s + i)) + 1);
        }
        i = (size_t)(j - s) + 1;
    }
    o[used] = 0;
#undef PUT
    {
        char *r = adup(a, o, used);
        SHZINF_FREE(o);
        return r;
    }
}

static void warn(shzinf_t *inf, const char *msg, const char *arg)
{
    if (inf->nwarn < 16) {
        size_t l = strlen(msg), m = arg ? strlen(arg) : 0;
        char *w = inf->warn[inf->nwarn++];
        if (l > 100) l = 100;
        if (m > 55) m = 55;
        memcpy(w, msg, l);
        memcpy(w + l, arg ? arg : "", m);
        w[l + m] = 0;
    }
}

/* index of the section (created when missing); indices stay valid when the array grows, pointers would not */
static int get_section(inf_impl_t *im, const char *name, size_t n)
{
    shzinf_t *inf = &im->pub;
    int i;
    for (i = 0; i < inf->nsec; ++i)
        if (strlen(inf->secs[i].name) == n && strnicmp_(inf->secs[i].name, name, n) == 0) return i;
    if (inf->nsec == inf->cap) {
        int cap = inf->cap ? inf->cap * 2 : 32;
        shzinf_section_t *ns = (shzinf_section_t *)arena_alloc(&im->a, sizeof(*ns) * (size_t)cap);
        if (inf->nsec) memcpy(ns, inf->secs, sizeof(*ns) * (size_t)inf->nsec);
        inf->secs = ns;
        inf->cap = cap;
    }
    inf->secs[inf->nsec].name = adup(&im->a, name, n);
    return inf->nsec++;
}

typedef struct { int sec; const char *line; size_t len; int lineno; } raw_t;

static int is_strings(const char *name)
{
    return shzinf_stricmp(name, "strings") == 0 || strnicmp_(name, "strings.", 8) == 0;
}

/* split "key = value" on the first '=' outside quotes; 0 when there is none */
static int split_kv(const char *s, size_t n, span_t *k, span_t *v)
{
    int inq = 0;
    size_t i;
    for (i = 0; i < n; ++i) {
        if (s[i] == '"') {
            if (inq && i + 1 < n && s[i + 1] == '"') { ++i; continue; }
            inq = !inq;
        } else if (s[i] == '=' && !inq) {
            const char *ks = s, *ke = s + i, *vs = s + i + 1, *ve = s + n;
            strip_range(&ks, &ke);
            strip_range(&vs, &ve);
            k->s = ks; k->n = (size_t)(ke - ks);
            v->s = vs; v->n = (size_t)(ve - vs);
            return 1;
        }
    }
    return 0;
}

static void add_line(inf_impl_t *im, shzinf_section_t *sec, const char *key, char **vals, int nvals, int lineno)
{
    if (sec->nlines == sec->cap) {
        int cap = sec->cap ? sec->cap * 2 : 8;
        shzinf_line_t *nl = (shzinf_line_t *)arena_alloc(&im->a, sizeof(*nl) * (size_t)cap);
        if (sec->nlines) memcpy(nl, sec->lines, sizeof(*nl) * (size_t)sec->nlines);
        sec->lines = nl;
        sec->cap = cap;
    }
    sec->lines[sec->nlines].key = (char *)key;
    sec->lines[sec->nlines].vals = vals;
    sec->lines[sec->nlines].nvals = nvals;
    sec->lines[sec->nlines].lineno = lineno;
    ++sec->nlines;
}

static char **split_values(inf_impl_t *im, const char *s, size_t n, int subst, int *count)
{
    int cnt = split_outside_quotes(s, n, ',', 0, 0), i;
    span_t *sp = (span_t *)SHZINF_MALLOC(sizeof(span_t) * (size_t)cnt);
    char **vals = (char **)arena_alloc(&im->a, sizeof(char *) * (size_t)(cnt + 1));
    split_outside_quotes(s, n, ',', sp, cnt);
    for (i = 0; i < cnt; ++i) {
        char *u = unquote(&im->a, sp[i].s, sp[i].n);
        vals[i] = subst ? substitute(&im->a, &im->pub, u) : u;
    }
    SHZINF_FREE(sp);
    *count = cnt;
    return vals;
}

/* next physical line (Python str.splitlines separators); returns 0 at the end */
static int next_line(const char **p, const char **ls, const char **le)
{
    const char *s = *p;
    if (!*s) return 0;
    *ls = s;
    for (;;) {
        unsigned char c = (unsigned char)*s;
        if (!c) { *le = s; *p = s; return 1; }
        if (c == '\r') { *le = s; *p = s[1] == '\n' ? s + 2 : s + 1; return 1; }
        if (c == '\n' || c == 0x0b || c == 0x0c || (c >= 0x1c && c <= 0x1e)) { *le = s; *p = s + 1; return 1; }
        if (c == 0xC2 && (unsigned char)s[1] == 0x85) { *le = s; *p = s + 2; return 1; }
        if (c == 0xE2 && (unsigned char)s[1] == 0x80 && ((unsigned char)s[2] == 0xA8 || (unsigned char)s[2] == 0xA9)) { *le = s; *p = s + 3; return 1; }
        ++s;
    }
}

shzinf_t *shzinf_parse(const unsigned char *data, size_t len, const char *locale)
{
    inf_impl_t *im = (inf_impl_t *)SHZINF_MALLOC(sizeof(inf_impl_t));
    shzinf_t *inf;
    const char *text, *p, *ls, *le;
    int cur = -1;
    raw_t *raw = 0;
    int nraw = 0, rawcap = 0, lineno = 0, pending_start = 0, npieces = 0, i;
    char *pend = 0;
    size_t pendlen = 0, pendcap = 0;
    char locsec[32];
    if (!im) return 0;
    memset(im, 0, sizeof *im);
    inf = &im->pub;
    text = decode(&im->a, data, len);
    p = text;
    while (next_line(&p, &ls, &le)) {
        const char *s = ls, *e = le, *q;
        int inq = 0, cont = 0;
        ++lineno;
        while (e - s >= 3 && (unsigned char)s[0] == 0xEF && (unsigned char)s[1] == 0xBB && (unsigned char)s[2] == 0xBF) s += 3;
        while (e - s >= 3 && (unsigned char)e[-3] == 0xEF && (unsigned char)e[-2] == 0xBB && (unsigned char)e[-1] == 0xBF) e -= 3;
        for (q = s; q < e; ++q) {                      /* comment outside quotes */
            if (*q == '"') inq = !inq;
            else if (*q == ';' && !inq) { e = q; break; }
        }
        while (e > s && is_space((unsigned char)e[-1])) --e;
        if (e > s && e[-1] == '\\' && !inq) {
            cont = 1;
            --e;
            while (e > s && is_space((unsigned char)e[-1])) --e;
        }
        if (!npieces) pending_start = lineno;
        {   /* pending.append(body); joined as " ".join(p.strip() for p in pending) */
            const char *ss = s, *ee = e;
            size_t need;
            strip_range(&ss, &ee);
            need = pendlen + (size_t)(ee - ss) + 2;
            if (need > pendcap) {
                char *np = (char *)SHZINF_REALLOC(pend, need * 2);
                if (!np) break;
                pend = np;
                pendcap = need * 2;
            }
            if (npieces++) pend[pendlen++] = ' ';
            memcpy(pend + pendlen, ss, (size_t)(ee - ss));
            pendlen += (size_t)(ee - ss);
            pend[pendlen] = 0;
        }
        if (cont) continue;
        {
            const char *ss = pend, *ee = pend + pendlen;
            strip_range(&ss, &ee);
            if (ss < ee) {
                if (*ss == '[') {
                    const char *end = m_chr(ss, ']', (size_t)(ee - ss));
                    if (!end) warn(inf, "unterminated section header", 0);
                    else {
                        const char *ns = ss + 1, *ne = end;
                        strip_range(&ns, &ne);
                        cur = get_section(im, ns, (size_t)(ne - ns));
                    }
                } else if (cur < 0) {
                    warn(inf, "entry before the first section ignored", 0);
                } else {
                    if (nraw == rawcap) {
                        rawcap = rawcap ? rawcap * 2 : 256;
                        raw = (raw_t *)SHZINF_REALLOC(raw, sizeof(raw_t) * (size_t)rawcap);
                    }
                    raw[nraw].sec = cur;
                    raw[nraw].line = adup(&im->a, ss, (size_t)(ee - ss));
                    raw[nraw].len = (size_t)(ee - ss);
                    raw[nraw].lineno = pending_start;
                    ++nraw;
                }
            }
        }
        pendlen = 0;
        npieces = 0;
    }
    SHZINF_FREE(pend);
    /* pass 1: [Strings] and [Strings.<locale>] (the locale table overrides; within [Strings] the first wins) */
    memcpy(locsec, "strings.", 8);
    for (i = 0; locale && locale[i] && i < 20; ++i) locsec[8 + i] = locale[i];
    locsec[8 + i] = 0;
    for (i = 0; i < nraw; ++i) {
        span_t k, v;
        int generic = shzinf_stricmp(inf->secs[raw[i].sec].name, "strings") == 0, loc = shzinf_stricmp(inf->secs[raw[i].sec].name, locsec) == 0, n, j;
        char **vals, *key;
        if (!generic && !loc) continue;
        if (!split_kv(raw[i].line, raw[i].len, &k, &v)) continue;
        vals = split_values(im, v.s, v.n, 0, &n);
        key = adup(&im->a, k.s, k.n);                    /* inf.py keys the table by the raw key text (not unquoted) */
        for (j = 0; j < inf->nstr; ++j)
            if (shzinf_stricmp(inf->strk[j], key) == 0) break;
        if (j < inf->nstr) {
            if (loc) inf->strv[j] = n ? vals[0] : (char *)"";
            continue;
        }
        if (inf->nstr == inf->strcap) {
            int cap = inf->strcap ? inf->strcap * 2 : 64;
            char **nk = (char **)arena_alloc(&im->a, sizeof(char *) * (size_t)cap), **nv = (char **)arena_alloc(&im->a, sizeof(char *) * (size_t)cap);
            if (inf->nstr) { memcpy(nk, inf->strk, sizeof(char *) * (size_t)inf->nstr); memcpy(nv, inf->strv, sizeof(char *) * (size_t)inf->nstr); }
            inf->strk = nk;
            inf->strv = nv;
            inf->strcap = cap;
        }
        inf->strk[inf->nstr] = key;
        inf->strv[inf->nstr] = n ? vals[0] : (char *)"";
        ++inf->nstr;
    }
    /* pass 2: every line, with substitution outside [Strings*] */
    for (i = 0; i < nraw; ++i) {
        span_t k, v;
        int in_strings = is_strings(inf->secs[raw[i].sec].name), n;
        char **vals;
        if (!split_kv(raw[i].line, raw[i].len, &k, &v)) {
            vals = split_values(im, raw[i].line, raw[i].len, !in_strings, &n);
            add_line(im, &inf->secs[raw[i].sec], "", vals, n, raw[i].lineno);
        } else {
            char *key = unquote(&im->a, k.s, k.n);
            vals = split_values(im, v.s, v.n, !in_strings, &n);
            add_line(im, &inf->secs[raw[i].sec], in_strings ? key : substitute(&im->a, inf, key), vals, n, raw[i].lineno);
        }
    }
    SHZINF_FREE(raw);
    return inf;
}

void shzinf_free(shzinf_t *inf)
{
    inf_impl_t *im = (inf_impl_t *)inf;
    if (!inf) return;
    arena_free(&im->a);
    SHZINF_FREE(im);
}

const shzinf_section_t *shzinf_section(const shzinf_t *inf, const char *name)
{
    int i;
    if (!name) return 0;
    for (i = 0; i < inf->nsec; ++i)
        if (shzinf_stricmp(inf->secs[i].name, name) == 0) return &inf->secs[i];
    return 0;
}

const char *shzinf_first(const shzinf_section_t *s, const char *key)
{
    int i;
    if (!s) return 0;
    for (i = 0; i < s->nlines; ++i)
        if (shzinf_stricmp(s->lines[i].key, key) == 0) return s->lines[i].nvals ? s->lines[i].vals[0] : "";
    return 0;
}

/* all values of every `key` line, in order */
static int section_get(const shzinf_section_t *s, const char *key, const char **out, int max)
{
    int i, j, n = 0;
    if (!s) return 0;
    for (i = 0; i < s->nlines; ++i)
        if (shzinf_stricmp(s->lines[i].key, key) == 0)
            for (j = 0; j < s->lines[i].nvals; ++j)
                if (n < max) out[n++] = s->lines[i].vals[j];
    return n;
}

static char g_verbuf[512];

const char *shzinf_version(const shzinf_t *inf, const char *key, const shzinf_target_t *t)
{
    const shzinf_section_t *v = shzinf_section(inf, "Version");
    const char *r;
    if (!v) return "";
    if (shzinf_stricmp(key, "DriverVer") == 0) {
        const char *vals[16];
        int n = section_get(v, "DriverVer", vals, 16), i;
        size_t used = 0;
        g_verbuf[0] = 0;
        for (i = 0; i < n; ++i) {
            size_t l = strlen(vals[i]);
            if (used + l + 3 >= sizeof g_verbuf) break;
            if (i) { memcpy(g_verbuf + used, ", ", 2); used += 2; }
            memcpy(g_verbuf + used, vals[i], l);
            used += l;
            g_verbuf[used] = 0;
        }
        return g_verbuf;
    }
    r = shzinf_first(v, key);
    if (shzinf_stricmp(key, "CatalogFile") == 0) {
        int i;
        for (i = 0; i < v->nlines; ++i) {
            const char *k = v->lines[i].key;
            size_t kl = strlen(k), al = strlen(t->arch);
            if (kl >= 12 + 2 + al && strnicmp_(k, "catalogfile.", 12) == 0 && strnicmp_(k + kl - 2 - al, "nt", 2) == 0 &&
                shzinf_stricmp(k + kl - al, t->arch) == 0)
                r = v->lines[i].nvals ? v->lines[i].vals[0] : "";
        }
    }
    return r ? r : "";
}

/* ------------------------------------------------------------------------------------------------ TargetOSVersion */
static const char *const ARCHES[] = { "amd64", "x86", "arm64", "arm", "ia64" };

/* returns 1 and a specificity key when the decoration applies */
static int decoration_applies(const char *dec, const shzinf_target_t *t, int64_t key[6])
{
    const char *s = dec, *e = dec + strlen(dec), *q;
    char arch[16];
    int alen = 0, nf = 0, i;
    int64_t f[5];
    int have[5] = { 0, 0, 0, 0, 0 };
    strip_range(&s, &e);
    if (e - s < 2 || lower(s[0]) != 'n' || lower(s[1]) != 't') return 0;
    s += 2;
    while (s < e && ((lower(*s) >= 'a' && lower(*s) <= 'z') || (*s >= '0' && *s <= '9')) && alen < 15) arch[alen++] = (char)lower(*s++);
    arch[alen] = 0;
    if (s < e && *s != '.') return 0;
    if (alen) {
        int ok = 0;
        for (i = 0; i < 5; ++i) if (strcmp(arch, ARCHES[i]) == 0) ok = 1;
        if (!ok) return 0;
    }
    while (s < e) {                                        /* (\.[0-9a-fx]*)* */
        char buf[24];
        int bl = 0;
        if (*s != '.') return 0;
        ++s;
        q = s;
        while (q < e && *q != '.') {
            int c = lower(*q);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == 'x')) return 0;
            if (bl < 23) buf[bl++] = *q;
            ++q;
        }
        buf[bl] = 0;
        if (nf >= 5) return 0;
        if (bl) {
            if (!py_int0(buf, &f[nf])) return 0;          /* the -1 marker of inf.py: not applicable */
            have[nf] = 1;
        }
        ++nf;
        s = q;
    }
    if (alen && strcmp(arch, t->arch) != 0) return 0;
    if (!alen && strcmp(t->arch, "x86") != 0 && !t->legacy) return 0;
    if (have[0] && !have[1]) { f[1] = 0; have[1] = 1; }
    if (have[0] && (f[0] > t->major || (f[0] == t->major && f[1] > t->minor))) return 0;
    if (have[2] && f[2] != t->product_type) return 0;
    if (have[3] && (f[3] & t->suite) != f[3]) return 0;
    if (have[4]) {
        if (!have[0]) return 0;
        if (f[0] == t->major && f[1] == t->minor && f[4] > t->build) return 0;
    }
    key[0] = have[0] ? f[0] : 0;
    key[1] = have[1] ? f[1] : 0;
    key[2] = have[4] ? f[4] : 0;
    key[3] = have[2];
    key[4] = have[3];
    key[5] = alen ? 1 : 0;
    return 1;
}

static int key_greater(const int64_t a[6], const int64_t b[6])
{
    int i;
    for (i = 0; i < 6; ++i)
        if (a[i] != b[i]) return a[i] > b[i];
    return 0;
}

static char g_secbuf[8][256];

static int has_decorations(const shzinf_line_t *ln)
{
    int j;
    for (j = 1; j < ln->nvals; ++j) {
        const char *s = ln->vals[j], *e = s + strlen(s);
        strip_range(&s, &e);
        if (e > s) return 1;
    }
    return 0;
}

int shzinf_models(const shzinf_t *inf, const shzinf_target_t *t, shzinf_model_t *out, int max)
{
    const shzinf_section_t *mfg = shzinf_section(inf, "Manufacturer");
    int i, j, n = 0, bufi = 0;
    if (!mfg) return 0;
    for (i = 0; i < mfg->nlines; ++i) {
        const shzinf_line_t *ln = &mfg->lines[i];
        const char *base, *chosen = 0;
        const shzinf_section_t *sec;
        char *name = g_secbuf[bufi++ & 7];
        if (!ln->nvals) continue;
        base = ln->vals[0];
        {
            const char *bs = base, *be = base + strlen(base);
            strip_range(&bs, &be);
            if ((size_t)(be - bs) > 200) continue;
            memcpy(name, bs, (size_t)(be - bs));
            name[be - bs] = 0;
        }
        if (!has_decorations(ln)) {
            if (!strcmp(t->arch, "x86") || t->legacy) chosen = name;
        } else {
            int64_t best[6], k[6];
            int have = 0, bi = -1;
            for (j = 1; j < ln->nvals; ++j) {
                if (decoration_applies(ln->vals[j], t, k) && (!have || key_greater(k, best))) {
                    memcpy(best, k, sizeof best);
                    have = 1;
                    bi = j;
                }
            }
            if (have) {
                const char *ds = ln->vals[bi], *de = ds + strlen(ds);
                size_t l = strlen(name);
                strip_range(&ds, &de);
                if (l + 1 + (size_t)(de - ds) < 255) {
                    name[l] = '.';
                    memcpy(name + l + 1, ds, (size_t)(de - ds));
                    name[l + 1 + (de - ds)] = 0;
                    chosen = name;
                }
            }
        }
        if (!chosen) continue;
        sec = shzinf_section(inf, chosen);
        if (!sec) continue;
        for (j = 0; j < sec->nlines; ++j) {
            const shzinf_line_t *m = &sec->lines[j];
            int v, nid = 0;
            const char *ids[SHZINF_MAX_IDS + 1];
            if (!m->nvals) continue;
            for (v = 1; v < m->nvals; ++v) {
                const char *s = m->vals[v], *e = s + strlen(s);
                strip_range(&s, &e);
                if (e > s && nid <= SHZINF_MAX_IDS) ids[nid++] = m->vals[v];
            }
            if (!nid) continue;
            if (n < max) {
                shzinf_model_t *o = &out[n];
                int c;
                o->description = m->key;
                o->install = m->vals[0];
                o->hwid = ids[0];
                o->ncompat = nid - 1;
                for (c = 1; c < nid; ++c) o->compat[c - 1] = ids[c];
                o->mfg = ln->key;
                o->section = sec->name;
                o->lineno = m->lineno;
            }
            ++n;
        }
    }
    return n;
}

/* ------------------------------------------------------------------------------------------------------ DDInstall */
typedef struct { shzinf_install_t pub; arena_t a; int capcopy, capreg, caphw, capsvc; } inst_impl_t;

static void iwarn(shzinf_install_t *r, const char *msg, const char *arg)
{
    if (r->nwarn < 8) {
        size_t l = strlen(msg), m = arg ? strlen(arg) : 0;
        if (l > 100) l = 100;
        if (m > 55) m = 55;
        memcpy(r->warn[r->nwarn], msg, l);
        memcpy(r->warn[r->nwarn] + l, arg ? arg : "", m);
        r->warn[r->nwarn][l + m] = 0;
        ++r->nwarn;
    }
}

static const char *trimmed(arena_t *a, const char *s)
{
    const char *e = s + strlen(s);
    strip_range(&s, &e);
    return adup(a, s, (size_t)(e - s));
}

static const char *join(arena_t *a, const char *x, const char *y, const char *z)
{
    size_t l1 = strlen(x), l2 = strlen(y), l3 = strlen(z);
    char *o = (char *)arena_alloc(a, l1 + l2 + l3 + 1);
    memcpy(o, x, l1);
    memcpy(o + l1, y, l2);
    memcpy(o + l1 + l2, z, l3);
    o[l1 + l2 + l3] = 0;
    return o;
}

int shzinf_dest_dir(const shzinf_t *inf, const char *fls, const char **subdir)
{
    const shzinf_section_t *dd = shzinf_section(inf, "DestinationDirs");
    const shzinf_line_t *ent = 0;
    int i;
    int64_t v;
    *subdir = "";
    if (dd) {
        if (fls)
            for (i = 0; i < dd->nlines && !ent; ++i)
                if (shzinf_stricmp(dd->lines[i].key, fls) == 0) ent = &dd->lines[i];
        if (!ent)
            for (i = 0; i < dd->nlines && !ent; ++i)
                if (shzinf_stricmp(dd->lines[i].key, "DefaultDestDir") == 0) ent = &dd->lines[i];
    }
    if (!ent || !ent->nvals) return 12;
    if (ent->nvals > 1) *subdir = ent->vals[1];
    return py_int0(ent->vals[0], &v) ? (int)v : 12;
}

#define GROW(arr, n, cap, T) do { if ((n) == (cap)) { int c_ = (cap) ? (cap) * 2 : 8; T *na_ = (T *)arena_alloc(&im->a, sizeof(T) * (size_t)c_); if (n) memcpy(na_, (arr), sizeof(T) * (size_t)(n)); (arr) = na_; (cap) = c_; } } while (0)

static uint32_t addreg_type(uint32_t flags)
{
    uint32_t hi = (flags >> 16) & 0xFFFF;
    if (flags & SHZ_FLG_BINVALUETYPE) return hi == 0 ? SHZ_REG_BINARY : hi == 1 ? SHZ_REG_DWORD : hi == 2 ? SHZ_REG_NONE : hi;
    return hi == 1 ? SHZ_REG_MULTI_SZ : hi == 2 ? SHZ_REG_EXPAND_SZ : SHZ_REG_SZ;
}

/* decode one add-registry section, appending to (*arr, *n, *cap) */
static void addreg(const shzinf_t *inf, inst_impl_t *im, const char *secname, shzinf_reg_t **arr, int *n, int *cap)
{
    const shzinf_section_t *s = shzinf_section(inf, secname);
    int i;
    if (!s) { iwarn(&im->pub, "AddReg section not found: ", secname); return; }
    for (i = 0; i < s->nlines; ++i) {
        const shzinf_line_t *ln = &s->lines[i];
        const char **vals = (const char **)arena_alloc(&im->a, sizeof(char *) * (size_t)(ln->nvals + 1));
        int nv = 0, j;
        shzinf_reg_t *r;
        char root[8];
        const char *rs, *re;
        int64_t v;
        if (!vals) return;
        if (ln->key[0]) vals[nv++] = ln->key;
        for (j = 0; j < ln->nvals; ++j) vals[nv++] = ln->vals[j];
        if (!nv) continue;
        rs = vals[0];
        re = rs + strlen(rs);
        strip_range(&rs, &re);
        if (re - rs > 4 || re == rs) { iwarn(&im->pub, "unknown registry root ", vals[0]); continue; }
        for (j = 0; rs + j < re; ++j) root[j] = (char)upper(rs[j]);
        root[j] = 0;
        if (strcmp(root, "HKR") && strcmp(root, "HKLM") && strcmp(root, "HKCR") && strcmp(root, "HKU") && strcmp(root, "HKCU")) {
            iwarn(&im->pub, "unknown registry root ", vals[0]);
            continue;
        }
        GROW(*arr, *n, *cap, shzinf_reg_t);
        r = &(*arr)[(*n)++];
        memcpy(r->root, root, sizeof root);
        r->subkey = nv > 1 ? vals[1] : "";
        r->name = nv > 2 ? vals[2] : "";
        r->flags = 0;
        if (nv > 3) {
            const char *fs = vals[3], *fe = fs + strlen(fs);
            strip_range(&fs, &fe);
            if (fe > fs) {
                if (py_int0(vals[3], &v)) r->flags = (uint32_t)v;
                else iwarn(&im->pub, "bad AddReg flags ", vals[3]);
            }
        }
        r->type = addreg_type(r->flags);
        r->section = s->name;
        r->lineno = ln->lineno;
        r->str = "";
        if (r->flags & SHZ_FLG_KEYONLY) continue;
        r->has_data = 1;
        if (r->type == SHZ_REG_DWORD) {
            if (nv > 4) { if (py_int0(vals[4], &v)) r->num = (uint64_t)v & 0xFFFFFFFFu; else iwarn(&im->pub, "bad DWORD ", vals[4]); }
        } else if (r->type == SHZ_REG_QWORD) {
            if (nv > 4 && py_int0(vals[4], &v)) r->num = (uint64_t)v;
        } else if (r->type == SHZ_REG_BINARY || r->type == SHZ_REG_NONE || (r->flags & SHZ_FLG_BINVALUETYPE)) {
            r->bin = (unsigned char *)arena_alloc(&im->a, (size_t)(nv > 4 ? nv - 4 : 1));
            for (j = 4; j < nv; ++j) {
                const char *bs = vals[j], *be = bs + strlen(bs);
                strip_range(&bs, &be);
                if (be == bs) continue;
                if (py_int16(vals[j], &v)) r->bin[r->binlen++] = (unsigned char)(v & 0xFF);
                else iwarn(&im->pub, "bad hex byte ", vals[j]);
            }
        } else if (r->type == SHZ_REG_MULTI_SZ) {
            const char *acc = "";
            for (j = 4; j < nv; ++j) acc = j == 4 ? vals[j] : join(&im->a, acc, "\n", vals[j]);
            r->str = acc;
            r->nmulti = nv > 4 ? nv - 4 : 0;
        } else {
            r->str = nv > 4 ? vals[4] : "";
        }
    }
}

static void copyfiles(const shzinf_t *inf, inst_impl_t *im, const shzinf_section_t *sec)
{
    const char *cfs[64];
    int n = section_get(sec, "CopyFiles", cfs, 64), i, j;
    for (i = 0; i < n; ++i) {
        const char *cf = trimmed(&im->a, cfs[i]);
        const char *sub;
        const shzinf_section_t *s;
        if (!cf[0]) continue;
        if (cf[0] == '@') {
            shzinf_copy_t *c;
            GROW(im->pub.copy, im->pub.ncopy, im->capcopy, shzinf_copy_t);
            c = &im->pub.copy[im->pub.ncopy++];
            c->dest = c->source = cf + 1;
            c->dirid = shzinf_dest_dir(inf, 0, &sub);
            c->subdir = sub;
            c->section = 0;
            c->flags = 0;
            continue;
        }
        s = shzinf_section(inf, cf);
        if (!s) { iwarn(&im->pub, "CopyFiles section not found: ", cf); continue; }
        {
            int dirid = shzinf_dest_dir(inf, cf, &sub);
            for (j = 0; j < s->nlines; ++j) {
                const shzinf_line_t *ln = &s->lines[j];
                const char *vals[8];
                int nv = 0, k;
                shzinf_copy_t *c;
                int64_t v;
                if (ln->key[0]) vals[nv++] = ln->key;
                for (k = 0; k < ln->nvals && nv < 8; ++k) vals[nv++] = ln->vals[k];
                if (!nv || !vals[0][0]) continue;
                GROW(im->pub.copy, im->pub.ncopy, im->capcopy, shzinf_copy_t);
                c = &im->pub.copy[im->pub.ncopy++];
                c->dest = vals[0];
                c->source = nv > 1 && vals[1][0] ? vals[1] : vals[0];
                c->dirid = dirid;
                c->subdir = sub;
                c->section = s->name;
                c->flags = nv > 3 && vals[3][0] && py_int0(vals[3], &v) ? (uint32_t)v : 0;
            }
        }
    }
}

static int opt_int(inst_impl_t *im, const shzinf_section_t *s, const char *key)
{
    const char *v = shzinf_first(s, key);
    int64_t x;
    if (!v) return -1;
    if (py_int0(v, &x)) return (int)x;
    iwarn(&im->pub, "bad service value ", v);
    return -1;
}

static void services(const shzinf_t *inf, inst_impl_t *im, const shzinf_section_t *sec)
{
    int i;
    for (i = 0; i < sec->nlines; ++i) {
        const shzinf_line_t *ln = &sec->lines[i];
        shzinf_service_t *s;
        if (shzinf_stricmp(ln->key, "AddService") == 0) {
            const char *v[4] = { "", "", "", "" };
            const shzinf_section_t *ss;
            int k, capreg = 0;
            int64_t x;
            const char *regs[16];
            for (k = 0; k < 4 && k < ln->nvals; ++k) v[k] = ln->vals[k];
            GROW(im->pub.svc, im->pub.nsvc, im->capsvc, shzinf_service_t);
            s = &im->pub.svc[im->pub.nsvc++];
            memset(s, 0, sizeof *s);
            s->name = trimmed(&im->a, v[0]);
            {
                const char *f = trimmed(&im->a, v[1]);
                if (f[0]) { if (py_int0(f, &x)) s->flags = (uint32_t)x; else iwarn(&im->pub, "bad AddService flags ", f); }
            }
            s->section = trimmed(&im->a, v[2]);
            s->eventlog = trimmed(&im->a, v[3]);
            if (!s->eventlog[0]) s->eventlog = 0;
            ss = shzinf_section(inf, s->section);
            s->service_type = s->start_type = s->error_control = -1;
            if (!ss) { iwarn(&im->pub, "service-install section not found: ", s->section); continue; }
            s->service_type = opt_int(im, ss, "ServiceType");
            s->start_type = opt_int(im, ss, "StartType");
            s->error_control = opt_int(im, ss, "ErrorControl");
            s->binary = shzinf_first(ss, "ServiceBinary");
            s->group = shzinf_first(ss, "LoadOrderGroup");
            s->display = shzinf_first(ss, "DisplayName");
            s->description = shzinf_first(ss, "Description");
            s->startname = shzinf_first(ss, "StartName");
            s->ndeps = section_get(ss, "Dependencies", s->deps, 16);
            {
                int nr = section_get(ss, "AddReg", regs, 16);
                for (k = 0; k < nr; ++k) addreg(inf, im, regs[k], &s->reg, &s->nreg, &capreg);
            }
        } else if (shzinf_stricmp(ln->key, "DelService") == 0) {
            GROW(im->pub.svc, im->pub.nsvc, im->capsvc, shzinf_service_t);
            s = &im->pub.svc[im->pub.nsvc++];
            memset(s, 0, sizeof *s);
            s->name = ln->nvals ? ln->vals[0] : "";
            s->is_delete = 1;
            s->service_type = s->start_type = s->error_control = -1;
        }
    }
}

static void install_into(const shzinf_t *inf, inst_impl_t *im, const char *base, const shzinf_target_t *t, int depth)
{
    const char *decs[3], *name = 0, *dec = "";
    const shzinf_section_t *sec = 0, *x;
    const char *vals[32], *needs[16];
    char ntarch[24];
    int i, n, nneeds, capreg = 0;
    static const char *const EXT[4] = { ".Services", ".HW", ".CoInstallers", ".Wdf" };
    ntarch[0] = '.'; ntarch[1] = 'N'; ntarch[2] = 'T';
    for (i = 0; t->arch[i] && i < 16; ++i) ntarch[3 + i] = t->arch[i];
    ntarch[3 + i] = 0;
    decs[0] = ntarch; decs[1] = ".NT"; decs[2] = "";
    for (i = 0; i < 3 && !sec; ++i) {
        const char *nm = join(&im->a, base, decs[i], "");
        sec = shzinf_section(inf, nm);
        if (sec) { name = nm; dec = decs[i]; }         /* the name as looked up (inf.py find_decorated) */
    }
    if (depth == 0) im->pub.section = name;
    if (!sec) { iwarn(&im->pub, "DDInstall section not found: ", base); return; }
    if (depth == 0) {
        const char *fs = shzinf_first(sec, "FeatureScore");
        int64_t v;
        if (fs) { if (py_int0(fs, &v)) im->pub.feature_score = (int)v; else iwarn(&im->pub, "bad FeatureScore ", fs); }
        n = section_get(sec, "DriverVer", vals, 32);
        if (n) {
            const char *acc = vals[0];
            for (i = 1; i < n; ++i) acc = join(&im->a, acc, ", ", vals[i]);
            im->pub.driverver = acc;
        }
    }
    copyfiles(inf, im, sec);
    n = section_get(sec, "AddReg", vals, 32);
    capreg = im->capreg;
    for (i = 0; i < n; ++i) addreg(inf, im, vals[i], &im->pub.reg, &im->pub.nreg, &capreg);
    im->capreg = capreg;
    for (i = 0; i < 4; ++i) {
        const char *order[4];
        int j, k = 0;
        order[k++] = dec;
        for (j = 0; j < 3; ++j) if (strcmp(decs[j], dec)) order[k++] = decs[j];
        x = 0;
        for (j = 0; j < k && !x; ++j) x = shzinf_section(inf, join(&im->a, base, order[j], EXT[i]));
        if (!x) continue;
        if (i == 0) services(inf, im, x);
        else if (i == 1) {
            int m = section_get(x, "AddReg", vals, 32), q;
            for (q = 0; q < m; ++q) addreg(inf, im, vals[q], &im->pub.hwreg, &im->pub.nhwreg, &im->caphw);
        } else if (i == 3 && depth == 0) {
            int q;
            for (q = 0; q < x->nlines; ++q) {
                const shzinf_line_t *ln = &x->lines[q];
                if (ln->nvals >= 2 && shzinf_stricmp(ln->key, "KmdfService") == 0) {
                    im->pub.kmdf_service = ln->vals[0];
                    im->pub.kmdf = shzinf_first(shzinf_section(inf, ln->vals[1]), "KmdfLibraryVersion");
                    im->pub.umdf = 0;
                } else if (ln->nvals >= 2 && shzinf_stricmp(ln->key, "UmdfService") == 0) {
                    im->pub.umdf = shzinf_first(shzinf_section(inf, ln->vals[1]), "UmdfLibraryVersion");
                    im->pub.kmdf = 0;
                    im->pub.kmdf_service = 0;
                }
            }
        }
    }
    nneeds = section_get(sec, "Needs", needs, 16);
    if (depth < 4)
        for (i = 0; i < nneeds; ++i) install_into(inf, im, needs[i], t, depth + 1);
}

shzinf_install_t *shzinf_install(const shzinf_t *inf, const char *base, const shzinf_target_t *t)
{
    inst_impl_t *im = (inst_impl_t *)SHZINF_MALLOC(sizeof(inst_impl_t));
    if (!im) return 0;
    memset(im, 0, sizeof *im);
    im->pub.base = base;
    im->pub.feature_score = -1;
    install_into(inf, im, base, t, 0);
    return &im->pub;
}

void shzinf_install_free(shzinf_install_t *r)
{
    inst_impl_t *im = (inst_impl_t *)r;
    if (!r) return;
    arena_free(&im->a);
    SHZINF_FREE(im);
}

/* [SourceDisksFiles(.arch)] + [SourceDisksNames(.arch)] -> "path\subdir" relative to the INF directory ("" = there) */
const char *shzinf_source_subdir(const shzinf_t *inf, const char *file, const shzinf_target_t *t, char *buf, size_t cap)
{
    const char *disk = 0, *sub = "", *dpath = "";
    char nm[48];
    int pass, i;
    size_t l = 0;
    buf[0] = 0;
    for (pass = 0; pass < 2; ++pass) {
        const shzinf_section_t *s;
        memcpy(nm, "SourceDisksFiles", 17);
        if (pass) { nm[16] = '.'; for (i = 0; t->arch[i] && i < 20; ++i) nm[17 + i] = t->arch[i]; nm[17 + i] = 0; }
        s = shzinf_section(inf, nm);
        for (i = 0; s && i < s->nlines; ++i)
            if (s->lines[i].key[0] && shzinf_stricmp(s->lines[i].key, file) == 0) {
                disk = s->lines[i].nvals ? s->lines[i].vals[0] : "";
                sub = s->lines[i].nvals > 1 ? s->lines[i].vals[1] : "";
            }
    }
    if (!disk) return buf;
    for (pass = 0; pass < 2; ++pass) {
        const shzinf_section_t *s;
        memcpy(nm, "SourceDisksNames", 17);
        if (pass) { nm[16] = '.'; for (i = 0; t->arch[i] && i < 20; ++i) nm[17 + i] = t->arch[i]; nm[17 + i] = 0; }
        s = shzinf_section(inf, nm);
        for (i = 0; s && i < s->nlines; ++i) {
            const char *k = s->lines[i].key, *ke = k + strlen(k), *d = disk, *de = disk + strlen(disk);
            strip_range(&k, &ke);
            strip_range(&d, &de);
            if (ke - k == de - d && strnicmp_(k, d, (size_t)(ke - k)) == 0)
                dpath = s->lines[i].nvals > 3 ? s->lines[i].vals[3] : "";
        }
    }
    {
        const char *parts[2] = { dpath, sub };
        for (pass = 0; pass < 2; ++pass) {
            const char *p = parts[pass], *e = p + strlen(p);
            while (p < e && (*p == '\\' || *p == '/')) ++p;
            while (e > p && (e[-1] == '\\' || e[-1] == '/')) --e;
            if (e == p) continue;
            if (l && l + 1 < cap) buf[l++] = '\\';
            while (p < e && l + 1 < cap) buf[l++] = *p++;
        }
        buf[l] = 0;
    }
    return buf;
}

/* ----------------------------------------------------------------------------------------------- devices, ranking */
static void hex(char *o, uint32_t v, int digits)
{
    static const char H[] = "0123456789ABCDEF";
    int i;
    for (i = digits - 1; i >= 0; --i) { o[i] = H[v & 15]; v >>= 4; }
    o[digits] = 0;
}

static void cat(char *d, const char *a, const char *b, const char *c, const char *e2, const char *f)
{
    const char *p[5] = { a, b, c, e2, f };
    int i;
    size_t l = 0;
    for (i = 0; i < 5; ++i)
        if (p[i]) { size_t k = strlen(p[i]); if (l + k < 95) { memcpy(d + l, p[i], k); l += k; } }
    d[l] = 0;
}

void shzinf_pci_device(shzinf_device_t *d, unsigned ven, unsigned dev, int has_subsys, uint32_t subsys, int has_rev,
                       unsigned rev, int has_class, uint32_t cls)
{
    char v[8], dv[8], ss[12], rv[4], cc[8], cc4[6], base[32];
    memset(d, 0, sizeof *d);
    hex(v, ven, 4);
    hex(dv, dev, 4);
    hex(ss, subsys, 8);
    hex(rv, rev, 2);
    hex(cc, cls, 6);
    memcpy(cc4, cc, 4);
    cc4[4] = 0;
    cat(base, "PCI\\VEN_", v, "&DEV_", dv, 0);
    if (has_subsys) {
        if (has_rev) cat(d->hw[d->nhw++], base, "&SUBSYS_", ss, "&REV_", rv);
        cat(d->hw[d->nhw++], base, "&SUBSYS_", ss, 0, 0);
    }
    if (has_rev) cat(d->hw[d->nhw++], base, "&REV_", rv, 0, 0);
    cat(d->hw[d->nhw++], base, 0, 0, 0, 0);
    if (has_class) {
        cat(d->hw[d->nhw++], base, "&CC_", cc, 0, 0);
        cat(d->hw[d->nhw++], base, "&CC_", cc4, 0, 0);
    }
    if (has_rev) cat(d->cp[d->ncp++], base, "&REV_", rv, 0, 0);
    cat(d->cp[d->ncp++], base, 0, 0, 0, 0);
    if (has_class) {
        cat(d->cp[d->ncp++], "PCI\\VEN_", v, "&CC_", cc, 0);
        cat(d->cp[d->ncp++], "PCI\\VEN_", v, "&CC_", cc4, 0);
        cat(d->cp[d->ncp++], "PCI\\VEN_", v, 0, 0, 0);
        cat(d->cp[d->ncp++], "PCI\\CC_", cc, 0, 0, 0);
        cat(d->cp[d->ncp++], "PCI\\CC_", cc4, 0, 0, 0);
    } else {
        cat(d->cp[d->ncp++], "PCI\\VEN_", v, 0, 0, 0);
    }
}

static int hexfield(const char *s, size_t n, uint32_t *out)
{
    uint32_t v = 0;
    size_t i;
    if (!n) return 0;
    for (i = 0; i < n; ++i) {
        int c = lower((unsigned char)s[i]);
        int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
        if (d < 0) return -1;
        v = v * 16 + (uint32_t)d;
    }
    *out = v;
    return 1;
}

int shzinf_parse_device(shzinf_device_t *d, const char *spec)
{
    const char *s = spec, *e = spec + strlen(spec);
    uint32_t f[5];
    int have[5] = { 0, 0, 0, 0, 0 }, nf = 0;
    strip_range(&s, &e);
    memset(d, 0, sizeof *d);
    if (e - s >= 8 && s_ncmp(s, "K64 pci:", 8) == 0) {                                         /* K64 pci: b:d.f vvvv:dddd class ccsspp */
        const char *p = s + 8, *q;
        uint32_t ven, dev, cls;
        while (p < e && is_space((unsigned char)*p)) ++p;
        while (p < e && !is_space((unsigned char)*p)) ++p;   /* b:d.f */
        while (p < e && is_space((unsigned char)*p)) ++p;
        q = p;
        while (q < e && *q != ':') ++q;
        if (hexfield(p, (size_t)(q - p), &ven) != 1) return 0;
        p = ++q;
        while (q < e && !is_space((unsigned char)*q)) ++q;
        if (hexfield(p, (size_t)(q - p), &dev) != 1) return 0;
        while (q < e && is_space((unsigned char)*q)) ++q;
        if (e - q < 6 || s_ncmp(q, "class", 5)) return 0;
        q += 5;
        while (q < e && is_space((unsigned char)*q)) ++q;
        p = q;
        while (q < e && !is_space((unsigned char)*q)) ++q;
        if (hexfield(p, (size_t)(q - p), &cls) != 1) return 0;
        shzinf_pci_device(d, ven, dev, 0, 0, 0, 0, 1, cls);
        return 1;
    }
    if (m_chr(s, '\\', (size_t)(e - s))) {
        size_t n = (size_t)(e - s);
        if (n > 95) n = 95;
        memcpy(d->hw[0], s, n);
        d->hw[0][n] = 0;
        d->nhw = 1;
        return 1;
    }
    while (s <= e && nf < 5) {
        const char *q = s;
        while (q < e && *q != ':') ++q;
        if (!(q - s == 1 && *s == '-')) {
            int r = hexfield(s, (size_t)(q - s), &f[nf]);
            if (r < 0) return 0;
            have[nf] = r;
        }
        ++nf;
        s = q + 1;
    }
    if (nf < 2 || !have[0] || !have[1]) return 0;
    shzinf_pci_device(d, f[0], f[1], have[2], have[2] ? f[2] : 0, have[3], have[3] ? f[3] : 0, have[4], have[4] ? f[4] : 0);
    return 1;
}

int shzinf_score(const shzinf_device_t *dev, const shzinf_model_t *m, shzinf_score_t *out)
{
    int found = 0, i, k;
    uint32_t best = 0;

#define CONSIDER(score, kind_, inf_id_, dev_id_) do { if (!found || (score) < best) { best = (score); found = 1; \
        out->identifier = (score); out->kind = (kind_); out->inf_id = (inf_id_); out->dev_id = (dev_id_); } } while (0)
    for (i = 0; i < dev->nhw; ++i)
        if (shzinf_stricmp(dev->hw[i], m->hwid) == 0) { CONSIDER((uint32_t)i, 0, m->hwid, dev->hw[i]); break; }
    for (i = 0; i < dev->ncp; ++i)
        if (shzinf_stricmp(dev->cp[i], m->hwid) == 0) { CONSIDER(0x2000u + (uint32_t)i, 0x2000, m->hwid, dev->cp[i]); break; }
    for (k = 0; k < m->ncompat; ++k) {
        for (i = 0; i < dev->nhw; ++i)
            if (shzinf_stricmp(dev->hw[i], m->compat[k]) == 0) { CONSIDER(0x1000u + (uint32_t)i, 0x1000, m->compat[k], dev->hw[i]); break; }
        for (i = 0; i < dev->ncp; ++i)
            if (shzinf_stricmp(dev->cp[i], m->compat[k]) == 0) {
                CONSIDER(0x3000u + (uint32_t)i + (uint32_t)k * 0x100u, 0x3000, m->compat[k], dev->cp[i]);
                break;
            }
    }
#undef CONSIDER
    return found;
}

uint32_t shzinf_rank(const shzinf_install_t *inst, int identifier)
{
    uint32_t fs = inst->feature_score >= 0 ? (uint32_t)inst->feature_score & 0xFF : 0xFF;
    int decorated = inst->section && shzinf_stricmp(inst->section, inst->base) != 0;
    return ((uint32_t)(decorated ? SHZINF_SIG_UNSIGNED_NT : SHZINF_SIG_UNSIGNED) << 24) | (fs << 16) | (uint32_t)identifier;
}

/* 'mm/dd/yyyy[, a.b.c.d]' comparison: date first, then version fields (missing fields sort lowest) */
static int dv_parse(const char *s, int64_t out[8])
{
    int n = 0, i;
    memset(out, 0, sizeof(int64_t) * 8);
    while (*s && is_space((unsigned char)*s)) ++s;
    for (i = 0; i < 3; ++i) {
        int64_t v = 0;
        int d = 0;
        while (*s >= '0' && *s <= '9') { v = v * 10 + (*s++ - '0'); ++d; }
        if (!d || (i < 2 && *s != '/')) return 0;
        if (i < 2) ++s;
        out[i == 2 ? 0 : i + 1] = v;
    }
    while (*s && is_space((unsigned char)*s)) ++s;
    if (*s == ',') {
        ++s;
        while (*s && is_space((unsigned char)*s)) ++s;
        n = 3;
        while (n < 8 && *s >= '0' && *s <= '9') {
            int64_t v = 0;
            while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
            out[n++] = v;
            if (*s == '.') ++s;
            else break;
        }
    }
    return 1;
}

int shzinf_driverver_cmp(const char *a, const char *b)
{
    int64_t x[8], y[8];
    int i;
    dv_parse(a ? a : "", x);
    dv_parse(b ? b : "", y);
    for (i = 0; i < 8; ++i)
        if (x[i] != y[i]) return x[i] > y[i] ? 1 : -1;
    return 0;
}
