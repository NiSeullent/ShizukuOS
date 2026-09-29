/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku INI core (see ini_core.h). */
#include "ini_core.h"

static int blank(ini_w c) { return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f'; }
static ini_w fold(ini_w c) { return c >= 'a' && c <= 'z' ? (ini_w)(c - 32) : c; }

static unsigned wlen(const ini_w *s) { unsigned n = 0; while (s[n]) ++n; return n; }

/* [a, a+an) equals NUL-terminated b, ignoring ASCII case */
static int name_eq(const ini_w *a, unsigned an, const ini_w *b)
{
    unsigned i;
    for (i = 0; i < an; ++i) if (!b[i] || fold(a[i]) != fold(b[i])) return 0;
    return b[an] == 0;
}

typedef struct { const ini_w *p; unsigned n; } span;

static span trim(const ini_w *p, unsigned n)
{
    span s;
    while (n && blank(*p)) { ++p; --n; }
    while (n && blank(p[n - 1])) --n;
    s.p = p; s.n = n;
    return s;
}

/* Walks the file line by line. For each line reports: kind 1 section header (name), kind 2 key (name, value). */
typedef struct { const ini_w *text; unsigned n, pos; } cursor;

static int next_line(cursor *c, int *kind, span *name, span *value)
{
    while (c->pos < c->n) {
        const ini_w *line = c->text + c->pos;
        unsigned len = 0, i;
        span t;
        while (c->pos + len < c->n && line[len] != '\n') ++len;
        c->pos += len + (c->pos + len < c->n);
        t = trim(line, len);
        if (!t.n || t.p[0] == ';') continue;
        if (t.p[0] == '[') {
            for (i = 1; i < t.n && t.p[i] != ']'; ++i) { }
            *name = trim(t.p + 1, i - 1);
            *kind = 1;
            return 1;
        }
        for (i = 0; i < t.n && t.p[i] != '='; ++i) { }
        *name = trim(t.p, i);
        *value = i < t.n ? trim(t.p + i + 1, t.n - i - 1) : trim(t.p, 0);
        *kind = 2;
        return 1;
    }
    return 0;
}

/* appends one name to a double-NUL list; returns 0 when it did not fit (the list is then closed as documented) */
static int list_add(ini_w *out, unsigned size, unsigned *used, const ini_w *s, unsigned n)
{
    unsigned i;
    if (*used + n + 2 <= size) {                          /* name, its NUL and room for the list's final NUL */
        for (i = 0; i < n; ++i) out[(*used)++] = s[i];
        out[(*used)++] = 0;
        return 1;
    }
    for (i = 0; i < n && *used + 2 < size; ++i) out[(*used)++] = s[i];     /* truncated last name */
    return 0;
}

unsigned ini_get_string(const ini_w *text, unsigned n, const ini_w *section, const ini_w *key, const ini_w *def, ini_w *out,
                        unsigned size, int *found)
{
    cursor c;
    int kind = 0, in_section = 0, seen = 0;                /* seen: the (first) matching section has been passed */
    span name = { 0, 0 }, value = { 0, 0 };
    unsigned used = 0, i;
    *found = 0;
    if (!size) return 0;
    c.text = text; c.n = n; c.pos = 0;
    if (!section || !key) {                               /* name lists */
        int complete = 1;
        while (complete && next_line(&c, &kind, &name, &value)) {
            if (kind == 1) {
                if (in_section) seen = 1;
                in_section = section && !seen && name_eq(name.p, name.n, section);
                if (in_section) *found = 1;
                if (!section) { *found = 1; complete = list_add(out, size, &used, name.p, name.n); }
            } else if (in_section) {
                complete = list_add(out, size, &used, name.p, name.n);
            }
        }
        if (!complete) {
            if (size >= 2) { out[size - 2] = 0; out[size - 1] = 0; return size - 2; }
            out[0] = 0;
            return 0;
        }
        out[used] = 0;                                    /* the list's terminating NUL (after the last name's own) */
        return used;
    }
    while (next_line(&c, &kind, &name, &value)) {
        if (kind == 1) { if (in_section) seen = 1; in_section = !seen && name_eq(name.p, name.n, section); continue; }
        if (!in_section || !name_eq(name.p, name.n, key)) continue;
        *found = 1;
        if (value.n >= 2 && (value.p[0] == '"' || value.p[0] == '\'') && value.p[value.n - 1] == value.p[0]) { ++value.p; value.n -= 2; }
        for (i = 0; i < value.n && i + 1 < size; ++i) out[i] = value.p[i];
        out[i] = 0;
        return i;
    }
    if (def) {                                            /* the default loses its trailing blanks */
        unsigned dn = wlen(def);
        while (dn && def[dn - 1] == ' ') --dn;
        for (i = 0; i < dn && i + 1 < size; ++i) out[i] = def[i];
        out[i] = 0;
        return i;
    }
    out[0] = 0;
    return 0;
}
