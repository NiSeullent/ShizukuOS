/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP: INI (answer file) and JSON (manifest) parsers. See textparse.h.
 */
#include "textparse.h"
#include <string.h>

static void set_err(char *err, size_t cap, unsigned line, const char *msg)
{
    size_t o = 0, n;
    char num[12];
    int k = 0;
    if (!cap) return;
    if (line) {
        const char *pre = "line ";
        unsigned v = line;
        while (*pre && o + 1 < cap) err[o++] = *pre++;
        do { num[k++] = (char)('0' + v % 10); v /= 10; } while (v && k < 11);
        while (k && o + 1 < cap) err[o++] = num[--k];
        if (o + 2 < cap) { err[o++] = ':'; err[o++] = ' '; }
    }
    n = strlen(msg);
    while (n-- && o + 1 < cap) err[o++] = *msg++;
    err[o] = 0;
}

static char lower(char c) { return c >= 'A' && c <= 'Z' ? (char)(c + 32) : c; }

int text_ieq(const char *a, const char *b)
{
    while (*a && lower(*a) == lower(*b)) { ++a; ++b; }
    return lower(*a) == lower(*b);
}

/* ---------------------------------------------------------------- INI */
static int is_space(char c) { return c == ' ' || c == '\t' || c == '\r'; }

int ini_parse(const plat_t *P, const char *text, size_t len, ini_t *out, char *err, size_t errcap)
{
    size_t i = 0, lines = 1, a = 0;
    unsigned line = 0;
    const char *section = "";
    char *arena;
    memset(out, 0, sizeof *out);
    for (i = 0; i < len; ++i) if (text[i] == '\n') ++lines;
    arena = P->alloc(P->ctx, len + 1 + lines * (sizeof(ini_entry_t) + 8) + 64);
    if (!arena) { set_err(err, errcap, 0, "out of memory"); return -1; }
    out->arena = arena;
    out->e = (ini_entry_t *)(void *)arena;
    a = lines * sizeof(ini_entry_t);
    i = 0;
    while (i < len) {
        size_t s = i, e, k, v0, v1, k1;
        char *copy;
        ++line;
        while (i < len && text[i] != '\n') ++i;
        e = i++;
        while (s < e && is_space(text[s])) ++s;
        while (e > s && is_space(text[e - 1])) --e;
        if (s == e || text[s] == ';' || text[s] == '#') continue;
        if (text[s] == '[') {
            if (text[e - 1] != ']' || e - s < 3) { set_err(err, errcap, line, "malformed section header"); return -1; }
            copy = arena + a;
            memcpy(copy, text + s + 1, e - s - 2);
            copy[e - s - 2] = 0;
            a += e - s - 1;
            section = copy;
            continue;
        }
        for (k = s; k < e && text[k] != '='; ++k) {}
        if (k == e) { set_err(err, errcap, line, "expected Key=Value"); return -1; }
        k1 = k;
        while (k1 > s && is_space(text[k1 - 1])) --k1;
        if (k1 == s) { set_err(err, errcap, line, "empty key"); return -1; }
        v0 = k + 1;
        while (v0 < e && is_space(text[v0])) ++v0;
        v1 = v0;
        while (v1 < e && !((text[v1] == ';' || text[v1] == '#') && v1 > v0 && is_space(text[v1 - 1]))) ++v1;   /* inline comment */
        while (v1 > v0 && is_space(text[v1 - 1])) --v1;
        if (!section[0]) { set_err(err, errcap, line, "key outside a [Section]"); return -1; }
        copy = arena + a;
        memcpy(copy, text + s, k1 - s);
        copy[k1 - s] = 0;
        out->e[out->count].key = copy;
        a += k1 - s + 1;
        copy = arena + a;
        memcpy(copy, text + v0, v1 - v0);
        copy[v1 - v0] = 0;
        a += v1 - v0 + 1;
        out->e[out->count].value = copy;
        out->e[out->count].section = section;
        out->e[out->count].line = line;
        out->count++;
    }
    return 0;
}

const char *ini_get(const ini_t *ini, const char *section, const char *key)
{
    unsigned i;
    const char *v = 0;
    for (i = 0; i < ini->count; ++i)                               /* the last assignment wins */
        if (text_ieq(ini->e[i].section, section) && text_ieq(ini->e[i].key, key)) v = ini->e[i].value;
    return v;
}

void ini_free(const plat_t *P, ini_t *ini)
{
    if (ini->arena) P->free(P->ctx, ini->arena);
    memset(ini, 0, sizeof *ini);
}

/* ---------------------------------------------------------------- JSON */
typedef struct {
    const char *t;
    size_t len, pos, used, cap;
    char *arena;
    const char *err;
    unsigned depth;
} jp_t;

static void *jalloc(jp_t *p, size_t n)
{
    void *r;
    n = (n + 7) & ~(size_t)7;
    if (p->used + n > p->cap) { p->err = "manifest too large"; return 0; }
    r = p->arena + p->used;
    p->used += n;
    return r;
}

static void jws(jp_t *p) { while (p->pos < p->len && (p->t[p->pos] == ' ' || p->t[p->pos] == '\t' || p->t[p->pos] == '\n' || p->t[p->pos] == '\r')) ++p->pos; }

static int hexd(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }

static const char *jstring(jp_t *p)
{
    size_t start, n = 0;
    char *o;
    if (p->pos >= p->len || p->t[p->pos] != '"') { p->err = "expected string"; return 0; }
    start = ++p->pos;
    while (p->pos < p->len && p->t[p->pos] != '"') { if (p->t[p->pos] == '\\') ++p->pos; ++p->pos; }
    if (p->pos >= p->len) { p->err = "unterminated string"; return 0; }
    o = jalloc(p, p->pos - start + 1);
    if (!o) return 0;
    for (p->pos = start; p->t[p->pos] != '"'; ++p->pos) {
        char c = p->t[p->pos];
        if ((unsigned char)c < 0x20) { p->err = "control character in string"; return 0; }
        if (c == '\\') {
            c = p->t[++p->pos];
            switch (c) {
            case '"': case '\\': case '/': break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'u': {
                int v = 0, i;
                for (i = 1; i <= 4; ++i) {
                    const int h = p->pos + i < p->len ? hexd(p->t[p->pos + i]) : -1;
                    if (h < 0) { p->err = "bad \\u escape"; return 0; }
                    v = v * 16 + h;
                }
                if (v == 0 || v > 0x7f) { p->err = "\\u escape outside ASCII"; return 0; }
                c = (char)v;
                p->pos += 4;
                break;
            }
            default: p->err = "bad escape"; return 0;
            }
        }
        o[n++] = c;
    }
    o[n] = 0;
    ++p->pos;
    return o;
}

static jnode_t *jvalue(jp_t *p)
{
    jnode_t *n;
    char c;
    jws(p);
    if (p->pos >= p->len) { p->err = "unexpected end"; return 0; }
    if (++p->depth > 32) { p->err = "nesting too deep"; return 0; }
    n = jalloc(p, sizeof *n);
    if (!n) return 0;
    memset(n, 0, sizeof *n);
    c = p->t[p->pos];
    if (c == '{' || c == '[') {
        jnode_t **tail = &n->kid;
        const char close = c == '{' ? '}' : ']';
        n->type = c == '{' ? J_OBJ : J_ARR;
        ++p->pos;
        jws(p);
        if (p->pos < p->len && p->t[p->pos] == close) { ++p->pos; --p->depth; return n; }
        for (;;) {
            const char *key = 0;
            jnode_t *v;
            jws(p);
            if (n->type == J_OBJ) {
                if (!(key = jstring(p))) return 0;
                jws(p);
                if (p->pos >= p->len || p->t[p->pos] != ':') { p->err = "expected ':'"; return 0; }
                ++p->pos;
            }
            if (!(v = jvalue(p))) return 0;
            v->key = key;
            *tail = v;
            tail = &v->next;
            jws(p);
            if (p->pos < p->len && p->t[p->pos] == ',') { ++p->pos; continue; }
            if (p->pos < p->len && p->t[p->pos] == close) { ++p->pos; break; }
            p->err = n->type == J_OBJ ? "expected ',' or '}'" : "expected ',' or ']'";
            return 0;
        }
    } else if (c == '"') {
        n->type = J_STR;
        if (!(n->s = jstring(p))) return 0;
    } else if (c >= '0' && c <= '9') {
        n->type = J_NUM;
        while (p->pos < p->len && p->t[p->pos] >= '0' && p->t[p->pos] <= '9') {
            if (n->n > (0xffffffffffffffffull - 9) / 10) { p->err = "number too large"; return 0; }
            n->n = n->n * 10 + (uint64_t)(p->t[p->pos++] - '0');
        }
        if (p->pos < p->len && (p->t[p->pos] == '.' || p->t[p->pos] == 'e' || p->t[p->pos] == 'E')) {
            p->err = "only integers are supported";
            return 0;
        }
    } else if (p->len - p->pos >= 4 && !memcmp(p->t + p->pos, "true", 4)) { n->type = J_TRUE; p->pos += 4; }
    else if (p->len - p->pos >= 5 && !memcmp(p->t + p->pos, "false", 5)) { n->type = J_FALSE; p->pos += 5; }
    else if (p->len - p->pos >= 4 && !memcmp(p->t + p->pos, "null", 4)) { n->type = J_NULL; p->pos += 4; }
    else { p->err = "unexpected character"; return 0; }
    --p->depth;
    return n;
}

int json_parse(const plat_t *P, const char *text, size_t len, json_t *out, char *err, size_t errcap)
{
    jp_t p;
    unsigned line = 1;
    size_t i;
    memset(&p, 0, sizeof p);
    memset(out, 0, sizeof out[0]);
    p.t = text;
    p.len = len;
    p.cap = len * 32 + 4096;
    p.arena = P->alloc(P->ctx, p.cap);
    if (!p.arena) { set_err(err, errcap, 0, "out of memory"); return -1; }
    out->arena = p.arena;
    out->root = jvalue(&p);
    if (out->root) {
        jws(&p);
        if (p.pos != p.len) { p.err = "trailing characters"; out->root = 0; }
    }
    if (!out->root) {
        for (i = 0; i < p.pos && i < len; ++i) if (text[i] == '\n') ++line;
        set_err(err, errcap, line, p.err ? p.err : "parse error");
        return -1;
    }
    return 0;
}

const jnode_t *json_get(const jnode_t *obj, const char *key)
{
    const jnode_t *k;
    if (!obj || obj->type != J_OBJ) return 0;
    for (k = obj->kid; k; k = k->next) if (!strcmp(k->key, key)) return k;
    return 0;
}

const char *json_str(const jnode_t *obj, const char *key)
{
    const jnode_t *v = json_get(obj, key);
    return v && v->type == J_STR ? v->s : 0;
}

int json_u64(const jnode_t *obj, const char *key, uint64_t *out)
{
    const jnode_t *v = json_get(obj, key);
    if (!v || v->type != J_NUM) return -1;
    *out = v->n;
    return 0;
}

void json_free(const plat_t *P, json_t *j)
{
    if (j->arena) P->free(P->ctx, j->arena);
    memset(j, 0, sizeof *j);
}
