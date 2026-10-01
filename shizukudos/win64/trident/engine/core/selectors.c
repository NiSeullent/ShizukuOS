/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - CSS selectors (see selectors.h).
 */
#include "selectors.h"
#include "forms.h"

enum { SS_TYPE, SS_UNIVERSAL, SS_ID, SS_CLASS, SS_ATTR, SS_PSEUDO };
enum { AOP_EXISTS, AOP_EQ, AOP_INCLUDES, AOP_DASH, AOP_PREFIX, AOP_SUFFIX, AOP_SUBSTR };
enum { COMB_NONE, COMB_DESCENDANT, COMB_CHILD, COMB_ADJACENT, COMB_SIBLING };
enum {
    PC_FIRST_CHILD = 1, PC_LAST_CHILD, PC_ONLY_CHILD, PC_FIRST_OF_TYPE, PC_LAST_OF_TYPE, PC_ONLY_OF_TYPE,
    PC_NTH_CHILD, PC_NTH_LAST_CHILD, PC_NTH_OF_TYPE, PC_NTH_LAST_OF_TYPE, PC_NOT, PC_HOVER, PC_FOCUS, PC_ACTIVE,
    PC_FOCUS_WITHIN, PC_LINK, PC_VISITED, PC_ANY_LINK, PC_CHECKED, PC_DISABLED, PC_ENABLED, PC_EMPTY, PC_ROOT,
    PC_TARGET, PC_LANG
};

typedef struct simple_sel {
    uint8_t kind, op, ci, pc;
    int a, b;                           /* :nth-*() */
    shz_char *name;                     /* type (lower-cased copy in lname), id, class, attribute name, :lang() */
    shz_char *lname;                    /* lower-cased name */
    size_t name_len;
    shz_char *value;
    size_t value_len;
    shz_selector_list *arg;             /* :not() */
} simple_sel;

typedef struct compound {
    simple_sel *s;
    size_t n, cap;
    uint8_t comb;                       /* relation to the previous compound (COMB_NONE for the first) */
} compound;

typedef struct complex_sel {
    compound *c;
    size_t n, cap;
    uint32_t spec;
    int pseudo;                         /* SHZ_PSEUDO_* */
    shz_char *text;
} complex_sel;

struct shz_selector_list {
    complex_sel *items;
    size_t n, cap;
};

/* ---------------------------------------------------------------------------------------------------- freeing */

static void free_simple(simple_sel *s)
{
    shz_free(s->name);
    shz_free(s->lname);
    shz_free(s->value);
    if (s->arg) shz_selector_free(s->arg);
}

void shz_selector_free(shz_selector_list *list)
{
    size_t i, j, k;
    if (!list) return;
    for (i = 0; i < list->n; ++i) {
        complex_sel *cx = &list->items[i];
        for (j = 0; j < cx->n; ++j) {
            for (k = 0; k < cx->c[j].n; ++k) free_simple(&cx->c[j].s[k]);
            shz_free(cx->c[j].s);
        }
        shz_free(cx->c);
        shz_free(cx->text);
    }
    shz_free(list->items);
    shz_free(list);
}

/* ---------------------------------------------------------------------------------------------------- parsing */

typedef struct {
    const shz_char *s;
    size_t n, i;
    int depth;
} sparser;

static int is_name_start(shz_char c)
{
    return shz_is_ascii_alpha(c) || c == '_' || c >= 0x80 || c == '\\';
}

static int is_name_char(shz_char c)
{
    return is_name_start(c) || shz_is_ascii_digit(c) || c == '-';
}

static void skip_ws(sparser *p)
{
    for (;;) {
        while (p->i < p->n && shz_is_space(p->s[p->i])) ++p->i;
        /* comments are allowed in selectors inside style sheets */
        if (p->i + 1 < p->n && p->s[p->i] == '/' && p->s[p->i + 1] == '*') {
            p->i += 2;
            while (p->i + 1 < p->n && !(p->s[p->i] == '*' && p->s[p->i + 1] == '/')) ++p->i;
            p->i = p->i + 2 <= p->n ? p->i + 2 : p->n;
            continue;
        }
        break;
    }
}

/* CSS identifier with escapes; returns 0 if none */
static int parse_ident(sparser *p, shz_buf *out)
{
    size_t start = p->i;
    if (p->i < p->n && p->s[p->i] == '-') {
        shz_buf_putc(out, '-');
        ++p->i;
        if (p->i < p->n && p->s[p->i] == '-') { shz_buf_putc(out, '-'); ++p->i; }
    }
    if (p->i >= p->n || !(is_name_start(p->s[p->i]) || (out->len == 2 && is_name_char(p->s[p->i])))) {
        p->i = start;
        shz_buf_clear(out);
        return 0;
    }
    while (p->i < p->n && is_name_char(p->s[p->i])) {
        shz_char c = p->s[p->i];
        if (c == '\\') {
            ++p->i;
            if (p->i >= p->n) break;
            if (shz_is_ascii_hex(p->s[p->i])) {
                uint32_t v = 0;
                int k = 0;
                while (k < 6 && p->i < p->n && shz_is_ascii_hex(p->s[p->i])) {
                    v = v * 16 + (uint32_t)shz_hex_value(p->s[p->i]);
                    ++p->i;
                    ++k;
                }
                if (p->i < p->n && shz_is_space(p->s[p->i])) ++p->i;
                if (!v || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) v = 0xFFFD;
                shz_buf_put_cp(out, v);
            } else {
                shz_buf_putc(out, p->s[p->i++]);
            }
            continue;
        }
        shz_buf_putc(out, c);
        ++p->i;
    }
    return out->len > 0;
}

static int parse_string(sparser *p, shz_buf *out)
{
    shz_char q = p->s[p->i++];
    while (p->i < p->n && p->s[p->i] != q) {
        shz_char c = p->s[p->i];
        if (c == '\\' && p->i + 1 < p->n) {
            ++p->i;
            if (p->s[p->i] == '\n') { ++p->i; continue; }
            if (shz_is_ascii_hex(p->s[p->i])) {
                uint32_t v = 0;
                int k = 0;
                while (k < 6 && p->i < p->n && shz_is_ascii_hex(p->s[p->i])) {
                    v = v * 16 + (uint32_t)shz_hex_value(p->s[p->i]);
                    ++p->i;
                    ++k;
                }
                if (p->i < p->n && shz_is_space(p->s[p->i])) ++p->i;
                if (!v || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) v = 0xFFFD;
                shz_buf_put_cp(out, v);
                continue;
            }
        }
        shz_buf_putc(out, p->s[p->i++]);
    }
    if (p->i >= p->n) return 0;
    ++p->i;
    return 1;
}

static simple_sel *add_simple(compound *c)
{
    void *p = c->s;
    if (!shz_grow(&p, &c->cap, c->n + 1, sizeof(simple_sel))) return NULL;
    c->s = p;
    memset(&c->s[c->n], 0, sizeof(simple_sel));
    return &c->s[c->n++];
}

static int set_name(simple_sel *s, shz_buf *b)
{
    s->name_len = b->len;
    s->name = shz_strndup(b->s, b->len);
    s->lname = shz_strdup_lower(b->s, b->len);
    return s->name && s->lname;
}

/* :nth-*() argument: odd | even | [+-]?[0-9]*n([+-][0-9]+)? | [+-]?[0-9]+ */
static int parse_nth(sparser *p, int *a, int *b)
{
    long av = 0, bv = 0;
    int sign = 1, has_a = 0, digits = 0;
    skip_ws(p);
    if (p->i + 3 <= p->n && shz_strnieq_ascii(p->s + p->i, 3, "odd")) { p->i += 3; *a = 2; *b = 1; return 1; }
    if (p->i + 4 <= p->n && shz_strnieq_ascii(p->s + p->i, 4, "even")) { p->i += 4; *a = 2; *b = 0; return 1; }
    if (p->i < p->n && (p->s[p->i] == '+' || p->s[p->i] == '-')) { sign = p->s[p->i] == '-' ? -1 : 1; ++p->i; }
    while (p->i < p->n && shz_is_ascii_digit(p->s[p->i])) { if (av < 100000) av = av * 10 + (p->s[p->i] - '0'); ++p->i; ++digits; }
    if (p->i < p->n && (p->s[p->i] == 'n' || p->s[p->i] == 'N')) {
        ++p->i;
        has_a = 1;
        if (!digits) av = 1;
        av *= sign;
        skip_ws(p);
        if (p->i < p->n && (p->s[p->i] == '+' || p->s[p->i] == '-')) {
            int bs = p->s[p->i] == '-' ? -1 : 1;
            int bd = 0;
            ++p->i;
            skip_ws(p);
            while (p->i < p->n && shz_is_ascii_digit(p->s[p->i])) { if (bv < 100000) bv = bv * 10 + (p->s[p->i] - '0'); ++p->i; ++bd; }
            if (!bd) return 0;
            bv *= bs;
        }
    } else {
        if (!digits) return 0;
        bv = av * sign;
        av = 0;
    }
    SHZ_UNUSED(has_a);
    *a = (int)av;
    *b = (int)bv;
    return 1;
}

static shz_res parse_list(sparser *p, shz_selector_list **out, int nested);

static int pseudo_class_id(const shz_char *name, size_t n)
{
    static const struct { const char *name; int id; } pcs[] = {
        { "first-child", PC_FIRST_CHILD }, { "last-child", PC_LAST_CHILD }, { "only-child", PC_ONLY_CHILD },
        { "first-of-type", PC_FIRST_OF_TYPE }, { "last-of-type", PC_LAST_OF_TYPE },
        { "only-of-type", PC_ONLY_OF_TYPE }, { "hover", PC_HOVER }, { "focus", PC_FOCUS }, { "active", PC_ACTIVE },
        { "focus-within", PC_FOCUS_WITHIN }, { "link", PC_LINK }, { "visited", PC_VISITED },
        { "any-link", PC_ANY_LINK }, { "checked", PC_CHECKED }, { "disabled", PC_DISABLED },
        { "enabled", PC_ENABLED }, { "empty", PC_EMPTY }, { "root", PC_ROOT }, { "target", PC_TARGET },
    };
    size_t i;
    for (i = 0; i < SHZ_ARRAY_SIZE(pcs); ++i)
        if (shz_strnieq_ascii(name, n, pcs[i].name)) return pcs[i].id;
    return 0;
}

static int pseudo_element_id(const shz_char *name, size_t n)
{
    if (shz_strnieq_ascii(name, n, "before")) return SHZ_PSEUDO_BEFORE;
    if (shz_strnieq_ascii(name, n, "after")) return SHZ_PSEUDO_AFTER;
    if (shz_strnieq_ascii(name, n, "first-line")) return SHZ_PSEUDO_FIRST_LINE;
    if (shz_strnieq_ascii(name, n, "first-letter")) return SHZ_PSEUDO_FIRST_LETTER;
    return 0;
}

/* parse one compound selector; returns 0 on syntax error. *pseudo receives a trailing pseudo-element. */
static int parse_compound(sparser *p, compound *c, int *pseudo, int nested)
{
    shz_buf b;
    int any = 0;
    shz_buf_init(&b);
    *pseudo = 0;
    /* type / universal, with an optional namespace prefix */
    if (p->i < p->n && (p->s[p->i] == '*' || is_name_start(p->s[p->i]) || p->s[p->i] == '-' || p->s[p->i] == '|')) {
        simple_sel *s;
        int universal = 0;
        if (p->s[p->i] == '*') { universal = 1; ++p->i; }
        else if (p->s[p->i] != '|' && !parse_ident(p, &b)) goto fail;
        if (p->i < p->n && p->s[p->i] == '|' && !(p->i + 1 < p->n && p->s[p->i + 1] == '=')) {
            /* namespace prefix: accepted and ignored */
            ++p->i;
            shz_buf_clear(&b);
            universal = 0;
            if (p->i < p->n && p->s[p->i] == '*') { universal = 1; ++p->i; }
            else if (!parse_ident(p, &b)) goto fail;
        }
        s = add_simple(c);
        if (!s) goto fail;
        if (universal) s->kind = SS_UNIVERSAL;
        else {
            s->kind = SS_TYPE;
            if (!set_name(s, &b)) goto fail;
        }
        shz_buf_clear(&b);
        any = 1;
    }
    for (;;) {
        simple_sel *s;
        if (p->i >= p->n) break;
        if (*pseudo) {
            /* nothing may follow a pseudo-element */
            if (p->s[p->i] == '#' || p->s[p->i] == '.' || p->s[p->i] == '[' || p->s[p->i] == ':') goto fail;
            break;
        }
        if (p->s[p->i] == '#') {
            ++p->i;
            if (!parse_ident(p, &b)) {
                /* ids may start with a digit in the hash token */
                while (p->i < p->n && is_name_char(p->s[p->i])) shz_buf_putc(&b, p->s[p->i++]);
                if (!b.len) goto fail;
            }
            s = add_simple(c);
            if (!s) goto fail;
            s->kind = SS_ID;
            if (!set_name(s, &b)) goto fail;
            shz_buf_clear(&b);
            any = 1;
        } else if (p->s[p->i] == '.') {
            ++p->i;
            if (!parse_ident(p, &b)) goto fail;
            s = add_simple(c);
            if (!s) goto fail;
            s->kind = SS_CLASS;
            if (!set_name(s, &b)) goto fail;
            shz_buf_clear(&b);
            any = 1;
        } else if (p->s[p->i] == '[') {
            ++p->i;
            skip_ws(p);
            if (p->i < p->n && p->s[p->i] == '*' && p->i + 1 < p->n && p->s[p->i + 1] == '|') p->i += 2;
            else if (p->i < p->n && p->s[p->i] == '|') ++p->i;
            if (!parse_ident(p, &b)) goto fail;
            if (p->i < p->n && p->s[p->i] == '|' && !(p->i + 1 < p->n && p->s[p->i + 1] == '=')) {
                ++p->i;
                shz_buf_clear(&b);
                if (!parse_ident(p, &b)) goto fail;
            }
            s = add_simple(c);
            if (!s) goto fail;
            s->kind = SS_ATTR;
            if (!set_name(s, &b)) goto fail;
            shz_buf_clear(&b);
            skip_ws(p);
            if (p->i >= p->n) goto fail;
            if (p->s[p->i] == ']') {
                s->op = AOP_EXISTS;
                ++p->i;
            } else {
                shz_char c0 = p->s[p->i];
                if (c0 == '=') { s->op = AOP_EQ; ++p->i; }
                else if (p->i + 1 < p->n && p->s[p->i + 1] == '=') {
                    switch (c0) {
                    case '~': s->op = AOP_INCLUDES; break;
                    case '|': s->op = AOP_DASH; break;
                    case '^': s->op = AOP_PREFIX; break;
                    case '$': s->op = AOP_SUFFIX; break;
                    case '*': s->op = AOP_SUBSTR; break;
                    default: goto fail;
                    }
                    p->i += 2;
                } else goto fail;
                skip_ws(p);
                if (p->i >= p->n) goto fail;
                if (p->s[p->i] == '"' || p->s[p->i] == '\'') {
                    if (!parse_string(p, &b)) goto fail;
                } else if (!parse_ident(p, &b)) {
                    /* unquoted values must be identifiers; be lenient with numbers (IE accepted them) */
                    while (p->i < p->n && (is_name_char(p->s[p->i]) || p->s[p->i] == '.')) shz_buf_putc(&b, p->s[p->i++]);
                    if (!b.len) goto fail;
                }
                s->value = shz_strndup(b.s, b.len);
                s->value_len = b.len;
                if (!s->value) goto fail;
                shz_buf_clear(&b);
                skip_ws(p);
                if (p->i < p->n && (p->s[p->i] == 'i' || p->s[p->i] == 'I')) { s->ci = 1; ++p->i; skip_ws(p); }
                else if (p->i < p->n && (p->s[p->i] == 's' || p->s[p->i] == 'S')) { ++p->i; skip_ws(p); }
                if (p->i >= p->n || p->s[p->i] != ']') goto fail;
                ++p->i;
            }
            any = 1;
        } else if (p->s[p->i] == ':') {
            int element = 0, id;
            ++p->i;
            if (p->i < p->n && p->s[p->i] == ':') { element = 1; ++p->i; }
            if (!parse_ident(p, &b)) goto fail;
            id = pseudo_element_id(b.s, b.len);
            if (element || (id && (p->i >= p->n || p->s[p->i] != '('))) {
                if (!id || nested) goto fail;
                *pseudo = id;
                shz_buf_clear(&b);
                any = 1;
                continue;
            }
            if (p->i < p->n && p->s[p->i] == '(') {
                ++p->i;
                s = add_simple(c);
                if (!s) goto fail;
                s->kind = SS_PSEUDO;
                if (shz_strnieq_ascii(b.s, b.len, "not")) {
                    s->pc = PC_NOT;
                    skip_ws(p);
                    ++p->depth;
                    if (p->depth > 16 || SHZ_FAILED(parse_list(p, &s->arg, 1))) goto fail;
                    --p->depth;
                } else if (shz_strnieq_ascii(b.s, b.len, "nth-child") || shz_strnieq_ascii(b.s, b.len, "nth-last-child")
                           || shz_strnieq_ascii(b.s, b.len, "nth-of-type")
                           || shz_strnieq_ascii(b.s, b.len, "nth-last-of-type")) {
                    s->pc = shz_strnieq_ascii(b.s, b.len, "nth-child") ? PC_NTH_CHILD
                          : shz_strnieq_ascii(b.s, b.len, "nth-last-child") ? PC_NTH_LAST_CHILD
                          : shz_strnieq_ascii(b.s, b.len, "nth-of-type") ? PC_NTH_OF_TYPE : PC_NTH_LAST_OF_TYPE;
                    if (!parse_nth(p, &s->a, &s->b)) goto fail;
                } else if (shz_strnieq_ascii(b.s, b.len, "lang")) {
                    shz_buf lb;
                    s->pc = PC_LANG;
                    shz_buf_init(&lb);
                    skip_ws(p);
                    if (!parse_ident(p, &lb)) { shz_buf_free(&lb); goto fail; }
                    if (!set_name(s, &lb)) { shz_buf_free(&lb); goto fail; }
                    shz_buf_free(&lb);
                } else {
                    goto fail;
                }
                skip_ws(p);
                if (p->i >= p->n || p->s[p->i] != ')') goto fail;
                ++p->i;
            } else {
                id = pseudo_class_id(b.s, b.len);
                if (!id) goto fail;
                s = add_simple(c);
                if (!s) goto fail;
                s->kind = SS_PSEUDO;
                s->pc = (uint8_t)id;
            }
            shz_buf_clear(&b);
            any = 1;
        } else {
            break;
        }
    }
    shz_buf_free(&b);
    return any;
fail:
    shz_buf_free(&b);
    return 0;
}

static void compute_specificity(complex_sel *cx);

static uint32_t list_max_spec(shz_selector_list *l)
{
    uint32_t m = 0;
    size_t i;
    for (i = 0; l && i < l->n; ++i)
        if (l->items[i].spec > m) m = l->items[i].spec;
    return m;
}

static void compute_specificity(complex_sel *cx)
{
    uint32_t a = 0, b = 0, c = 0;
    size_t i, j;
    for (i = 0; i < cx->n; ++i) {
        for (j = 0; j < cx->c[i].n; ++j) {
            simple_sel *s = &cx->c[i].s[j];
            switch (s->kind) {
            case SS_ID: ++a; break;
            case SS_CLASS: case SS_ATTR: ++b; break;
            case SS_TYPE: ++c; break;
            case SS_PSEUDO:
                if (s->pc == PC_NOT) {
                    uint32_t m = list_max_spec(s->arg);
                    a += m >> 16;
                    b += (m >> 8) & 0xFF;
                    c += m & 0xFF;
                } else {
                    ++b;
                }
                break;
            default: break;
            }
        }
    }
    if (cx->pseudo) ++c;
    cx->spec = (SHZ_MIN(a, 255u) << 16) | (SHZ_MIN(b, 255u) << 8) | SHZ_MIN(c, 255u);
}

static complex_sel *add_complex(shz_selector_list *l)
{
    void *p = l->items;
    if (!shz_grow(&p, &l->cap, l->n + 1, sizeof(complex_sel))) return NULL;
    l->items = p;
    memset(&l->items[l->n], 0, sizeof(complex_sel));
    return &l->items[l->n++];
}

static compound *add_compound(complex_sel *cx)
{
    void *p = cx->c;
    if (!shz_grow(&p, &cx->cap, cx->n + 1, sizeof(compound))) return NULL;
    cx->c = p;
    memset(&cx->c[cx->n], 0, sizeof(compound));
    return &cx->c[cx->n++];
}

/* normalized source text of a complex selector: whitespace runs collapsed, trimmed */
static shz_char *make_text(const shz_char *s, size_t n)
{
    shz_buf b;
    size_t i;
    int space = 0;
    shz_buf_init(&b);
    s = shz_trim(s, &n);
    for (i = 0; i < n; ++i) {
        if (shz_is_space(s[i])) { space = 1; continue; }
        if (space && b.len) shz_buf_putc(&b, ' ');
        space = 0;
        shz_buf_putc(&b, s[i]);
    }
    return shz_buf_detach(&b);
}

static shz_res parse_list(sparser *p, shz_selector_list **out, int nested)
{
    shz_selector_list *l = shz_alloc(sizeof(*l));
    *out = NULL;
    if (!l) return SHZ_E_OUTOFMEMORY;
    for (;;) {
        complex_sel *cx = add_complex(l);
        size_t start;
        int comb = COMB_NONE;
        if (!cx) goto fail;
        skip_ws(p);
        start = p->i;
        for (;;) {
            compound *c = add_compound(cx);
            int pseudo, had_ws;
            size_t before;
            if (!c) goto fail;
            c->comb = (uint8_t)comb;
            if (!parse_compound(p, c, &pseudo, nested)) goto fail;
            if (pseudo) cx->pseudo = pseudo;
            before = p->i;
            skip_ws(p);
            had_ws = p->i > before;
            if (p->i >= p->n || p->s[p->i] == ',' || (nested && p->s[p->i] == ')')) break;
            if (pseudo) goto fail;              /* a pseudo-element must be last */
            if (p->s[p->i] == '>') { comb = COMB_CHILD; ++p->i; skip_ws(p); }
            else if (p->s[p->i] == '+') { comb = COMB_ADJACENT; ++p->i; skip_ws(p); }
            else if (p->s[p->i] == '~') { comb = COMB_SIBLING; ++p->i; skip_ws(p); }
            else if (had_ws) comb = COMB_DESCENDANT;
            else goto fail;
        }
        cx->text = make_text(p->s + start, p->i - start);
        if (!cx->text) goto fail;
        compute_specificity(cx);
        if (p->i < p->n && p->s[p->i] == ',') { ++p->i; continue; }
        break;
    }
    if (!nested && p->i < p->n) goto fail;
    *out = l;
    return SHZ_OK;
fail:
    shz_selector_free(l);
    return SHZ_E_SYNTAX;
}

shz_res shz_selector_parse(const shz_char *s, size_t n, shz_selector_list **out)
{
    sparser p;
    shz_res hr;
    p.s = s;
    p.n = n;
    p.i = 0;
    p.depth = 0;
    *out = NULL;
    if (!s) return SHZ_E_SYNTAX;
    hr = parse_list(&p, out, 0);
    return hr;
}

size_t shz_selector_count(const shz_selector_list *list)
{
    return list ? list->n : 0;
}

uint32_t shz_selector_specificity(const shz_selector_list *list, size_t i)
{
    return i < list->n ? list->items[i].spec : 0;
}

int shz_selector_pseudo_element(const shz_selector_list *list, size_t i)
{
    return i < list->n ? list->items[i].pseudo : 0;
}

shz_char *shz_selector_text(const shz_selector_list *list, size_t i)
{
    return i < list->n ? shz_strdup(list->items[i].text) : NULL;
}

shz_char *shz_selector_list_text(const shz_selector_list *list)
{
    shz_buf b;
    size_t i;
    shz_buf_init(&b);
    for (i = 0; i < list->n; ++i) {
        if (i) shz_buf_put_ascii(&b, ", ");
        shz_buf_puts(&b, list->items[i].text);
    }
    return shz_buf_detach(&b);
}

/* ---------------------------------------------------------------------------------------------------- matching */

static int html_elem_in_html_doc(shz_node *n)
{
    return ((shz_element *)n)->ns == SHZ_NS_HTML && n->doc->is_html;
}

static shz_node *parent_element(shz_node *n)
{
    n = n->parent;
    return n && n->type == SHZ_ELEMENT_NODE ? n : NULL;
}

static int same_type(shz_node *a, shz_node *b)
{
    shz_element *ea = (shz_element *)a, *eb = (shz_element *)b;
    return ea->ns == eb->ns && shz_streq(ea->local, eb->local);
}

static int nth_matches(int a, int b, long index)          /* index is 1-based */
{
    long d = index - b;
    if (a == 0) return d == 0;
    if ((a > 0 && d < 0) || (a < 0 && d > 0)) return 0;
    return d % a == 0;
}

/* HTML "case-insensitive attribute value" list (attribute selectors on HTML elements) */
static int ci_attr_value(int id)
{
    switch (id) {
    case SHZ_ATTR_ACCEPT: case SHZ_ATTR_ACCEPT_CHARSET: case SHZ_ATTR_ALIGN: case SHZ_ATTR_ALINK: case SHZ_ATTR_AXIS:
    case SHZ_ATTR_BGCOLOR: case SHZ_ATTR_CHARSET: case SHZ_ATTR_CHECKED: case SHZ_ATTR_CLEAR: case SHZ_ATTR_COLOR:
    case SHZ_ATTR_COMPACT: case SHZ_ATTR_DECLARE: case SHZ_ATTR_DEFER: case SHZ_ATTR_DIR: case SHZ_ATTR_DISABLED:
    case SHZ_ATTR_ENCTYPE: case SHZ_ATTR_FACE: case SHZ_ATTR_FRAME: case SHZ_ATTR_HREFLANG: case SHZ_ATTR_HTTP_EQUIV:
    case SHZ_ATTR_LANG: case SHZ_ATTR_LANGUAGE: case SHZ_ATTR_LINK: case SHZ_ATTR_MEDIA: case SHZ_ATTR_METHOD:
    case SHZ_ATTR_MULTIPLE: case SHZ_ATTR_NOHREF: case SHZ_ATTR_NORESIZE: case SHZ_ATTR_NOSHADE: case SHZ_ATTR_NOWRAP:
    case SHZ_ATTR_READONLY: case SHZ_ATTR_REL: case SHZ_ATTR_REV: case SHZ_ATTR_RULES: case SHZ_ATTR_SCOPE:
    case SHZ_ATTR_SCROLLING: case SHZ_ATTR_SELECTED: case SHZ_ATTR_SHAPE: case SHZ_ATTR_TARGET: case SHZ_ATTR_TEXT:
    case SHZ_ATTR_TYPE: case SHZ_ATTR_VALIGN: case SHZ_ATTR_VALUETYPE: case SHZ_ATTR_VLINK:
        return 1;
    default:
        return 0;
    }
}

static int attr_matches(simple_sel *s, shz_node *n)
{
    shz_element *e = (shz_element *)n;
    int html = html_elem_in_html_doc(n);
    uint32_t i;
    for (i = 0; i < e->attr_count; ++i) {
        shz_attr *a = &e->attrs[i];
        size_t an = shz_strlen(a->name);
        const shz_char *v = a->value;
        size_t vn = a->value_len;
        int ci;
        if (html ? !shz_strnieq(a->name, an, s->name, s->name_len) : !shz_strneq(a->name, an, s->name, s->name_len))
            continue;
        ci = s->ci || (html && ci_attr_value(a->id));
        switch (s->op) {
        case AOP_EXISTS:
            return 1;
        case AOP_EQ:
            return ci ? shz_strnieq(v, vn, s->value, s->value_len) : shz_strneq(v, vn, s->value, s->value_len);
        case AOP_INCLUDES:
            return shz_token_list_has(v, vn, s->value, s->value_len, ci);
        case AOP_DASH:
            if (vn < s->value_len) return 0;
            if (!(ci ? shz_strnieq(v, s->value_len, s->value, s->value_len) : shz_strneq(v, s->value_len, s->value, s->value_len)))
                return 0;
            return vn == s->value_len || v[s->value_len] == '-';
        case AOP_PREFIX:
            if (!s->value_len || vn < s->value_len) return 0;
            return ci ? shz_strnieq(v, s->value_len, s->value, s->value_len) : shz_strneq(v, s->value_len, s->value, s->value_len);
        case AOP_SUFFIX:
            if (!s->value_len || vn < s->value_len) return 0;
            v += vn - s->value_len;
            return ci ? shz_strnieq(v, s->value_len, s->value, s->value_len) : shz_strneq(v, s->value_len, s->value, s->value_len);
        case AOP_SUBSTR: {
            size_t k;
            if (!s->value_len || vn < s->value_len) return 0;
            for (k = 0; k + s->value_len <= vn; ++k)
                if (ci ? shz_strnieq(v + k, s->value_len, s->value, s->value_len) : shz_strneq(v + k, s->value_len, s->value, s->value_len))
                    return 1;
            return 0;
        }
        default:
            return 0;
        }
    }
    return 0;
}

static int is_link(shz_node *n)
{
    int tag = shz_tag_of(n);
    return (tag == SHZ_TAG_A || tag == SHZ_TAG_AREA || tag == SHZ_TAG_LINK) && shz_elem_has_attr(n, SHZ_ATTR_HREF);
}

static int can_be_disabled(shz_node *n)
{
    switch (shz_tag_of(n)) {
    case SHZ_TAG_BUTTON: case SHZ_TAG_INPUT: case SHZ_TAG_SELECT: case SHZ_TAG_TEXTAREA: case SHZ_TAG_OPTGROUP:
    case SHZ_TAG_OPTION: case SHZ_TAG_FIELDSET:
        return 1;
    default:
        return 0;
    }
}

static int is_disabled(shz_node *n)
{
    shz_node *p;
    if (!can_be_disabled(n)) return 0;
    if (shz_elem_has_attr(n, SHZ_ATTR_DISABLED)) return 1;
    if (shz_is_tag(n, SHZ_TAG_OPTION)) {
        p = parent_element(n);
        return p && shz_is_tag(p, SHZ_TAG_OPTGROUP) && shz_elem_has_attr(p, SHZ_ATTR_DISABLED);
    }
    /* a disabled fieldset disables its descendants except those in its first legend */
    for (p = parent_element(n); p; p = parent_element(p)) {
        if (shz_is_tag(p, SHZ_TAG_FIELDSET) && shz_elem_has_attr(p, SHZ_ATTR_DISABLED)) {
            shz_node *legend = shz_first_element_child(p);
            if (legend && shz_is_tag(legend, SHZ_TAG_LEGEND) && shz_node_contains(legend, n)) continue;
            return 1;
        }
    }
    return 0;
}

static int lang_matches(shz_node *n, simple_sel *s)
{
    for (; n; n = parent_element(n)) {
        const shz_char *v = shz_elem_attr(n, SHZ_ATTR_LANG);
        size_t vn;
        if (!v) continue;
        vn = shz_strlen(v);
        if (vn < s->name_len || !shz_strnieq(v, s->name_len, s->name, s->name_len)) return 0;
        return vn == s->name_len || v[s->name_len] == '-';
    }
    return 0;
}

static int pseudo_matches(simple_sel *s, shz_node *n)
{
    shz_node *p = parent_element(n), *x;
    shz_doc *doc = n->doc;
    long index;
    switch (s->pc) {
    case PC_FIRST_CHILD: return p && !shz_prev_element_sibling(n);
    case PC_LAST_CHILD: return p && !shz_next_element_sibling(n);
    case PC_ONLY_CHILD: return p && !shz_prev_element_sibling(n) && !shz_next_element_sibling(n);
    case PC_FIRST_OF_TYPE:
    case PC_LAST_OF_TYPE:
    case PC_ONLY_OF_TYPE: {
        int first = 1, last = 1;
        if (!p) return 0;
        for (x = shz_prev_element_sibling(n); x; x = shz_prev_element_sibling(x)) if (same_type(x, n)) { first = 0; break; }
        for (x = shz_next_element_sibling(n); x; x = shz_next_element_sibling(x)) if (same_type(x, n)) { last = 0; break; }
        return s->pc == PC_FIRST_OF_TYPE ? first : s->pc == PC_LAST_OF_TYPE ? last : first && last;
    }
    case PC_NTH_CHILD:
        if (!p) return 0;
        for (index = 1, x = shz_prev_element_sibling(n); x; x = shz_prev_element_sibling(x)) ++index;
        return nth_matches(s->a, s->b, index);
    case PC_NTH_LAST_CHILD:
        if (!p) return 0;
        for (index = 1, x = shz_next_element_sibling(n); x; x = shz_next_element_sibling(x)) ++index;
        return nth_matches(s->a, s->b, index);
    case PC_NTH_OF_TYPE:
        if (!p) return 0;
        for (index = 1, x = shz_prev_element_sibling(n); x; x = shz_prev_element_sibling(x)) if (same_type(x, n)) ++index;
        return nth_matches(s->a, s->b, index);
    case PC_NTH_LAST_OF_TYPE:
        if (!p) return 0;
        for (index = 1, x = shz_next_element_sibling(n); x; x = shz_next_element_sibling(x)) if (same_type(x, n)) ++index;
        return nth_matches(s->a, s->b, index);
    case PC_NOT:
        return !shz_selector_matches(s->arg, n);
    case PC_HOVER:
        return doc->hover && shz_node_contains(n, doc->hover);
    case PC_ACTIVE:
        return doc->active && shz_node_contains(n, doc->active);
    case PC_FOCUS:
        return doc->focus == n;
    case PC_FOCUS_WITHIN:
        return doc->focus && shz_node_contains(n, doc->focus);
    case PC_LINK:
    case PC_ANY_LINK:
        return is_link(n);
    case PC_VISITED:
    case PC_TARGET:
        return 0;
    case PC_CHECKED:
        return shz_forms_is_checked(n);
    case PC_DISABLED:
        return is_disabled(n);
    case PC_ENABLED:
        return can_be_disabled(n) && !is_disabled(n);
    case PC_EMPTY:
        for (x = n->first_child; x; x = x->next_sibling)
            if (x->type == SHZ_ELEMENT_NODE || (shz_is_text(x) && ((shz_chardata *)x)->len)) return 0;
        return 1;
    case PC_ROOT:
        return n->parent && n->parent->type == SHZ_DOCUMENT_NODE;
    case PC_LANG:
        return lang_matches(n, s);
    default:
        return 0;
    }
}

static int simple_matches(simple_sel *s, shz_node *n)
{
    shz_element *e = (shz_element *)n;
    switch (s->kind) {
    case SS_UNIVERSAL:
        return 1;
    case SS_TYPE:
        if (html_elem_in_html_doc(n)) return shz_streq(e->local, s->lname);
        return shz_streq(e->local, s->name);
    case SS_ID: {
        shz_attr *a = shz_elem_find_attr_id(n, SHZ_ATTR_ID);
        if (!a) return 0;
        if (shz_doc_quirks(n->doc) == SHZ_QUIRKS_FULL) return shz_strnieq(a->value, a->value_len, s->name, s->name_len);
        return shz_strneq(a->value, a->value_len, s->name, s->name_len);
    }
    case SS_CLASS:
        return shz_elem_has_class(n, s->name, s->name_len);
    case SS_ATTR:
        return attr_matches(s, n);
    case SS_PSEUDO:
        return pseudo_matches(s, n);
    default:
        return 0;
    }
}

static int compound_matches(compound *c, shz_node *n)
{
    size_t i;
    for (i = 0; i < c->n; ++i)
        if (!simple_matches(&c->s[i], n)) return 0;
    return 1;
}

static int match_from(complex_sel *cx, size_t i, shz_node *n)
{
    shz_node *x;
    if (!compound_matches(&cx->c[i], n)) return 0;
    if (i == 0) return 1;
    switch (cx->c[i].comb) {
    case COMB_CHILD:
        x = parent_element(n);
        return x && match_from(cx, i - 1, x);
    case COMB_DESCENDANT:
        for (x = parent_element(n); x; x = parent_element(x))
            if (match_from(cx, i - 1, x)) return 1;
        return 0;
    case COMB_ADJACENT:
        x = shz_prev_element_sibling(n);
        return x && match_from(cx, i - 1, x);
    case COMB_SIBLING:
        for (x = shz_prev_element_sibling(n); x; x = shz_prev_element_sibling(x))
            if (match_from(cx, i - 1, x)) return 1;
        return 0;
    default:
        return 0;
    }
}

int shz_selector_match_one(const shz_selector_list *list, size_t i, shz_node *elem)
{
    if (!list || i >= list->n || !elem || elem->type != SHZ_ELEMENT_NODE || !list->items[i].n) return 0;
    return match_from(&list->items[i], list->items[i].n - 1, elem);
}

int shz_selector_matches(const shz_selector_list *list, shz_node *elem)
{
    size_t i;
    if (!list) return 0;
    for (i = 0; i < list->n; ++i)
        if (!list->items[i].pseudo && shz_selector_match_one(list, i, elem)) return 1;
    return 0;
}

/* ---------------------------------------------------------------------------------------------------- engine.h */

shz_res shz_query_selector(shz_node *root, const shz_char *selector, shz_node **first)
{
    shz_selector_list *l;
    shz_node *n;
    shz_res hr = shz_selector_parse(selector, shz_strlen(selector), &l);
    *first = NULL;
    if (SHZ_FAILED(hr)) return hr;
    for (n = root->first_child; n; n = shz_node_next(n, root)) {
        if (n->type == SHZ_ELEMENT_NODE && shz_selector_matches(l, n)) {
            *first = n;
            break;
        }
    }
    shz_selector_free(l);
    return *first ? SHZ_OK : SHZ_FALSE;
}

shz_res shz_query_selector_all(shz_node *root, const shz_char *selector, shz_list **out)
{
    shz_selector_list *l;
    shz_list *list;
    shz_node *n;
    shz_res hr = shz_selector_parse(selector, shz_strlen(selector), &l);
    *out = NULL;
    if (SHZ_FAILED(hr)) return hr;
    list = shz_list_new_static();
    if (!list) { shz_selector_free(l); return SHZ_E_OUTOFMEMORY; }
    for (n = root->first_child; n; n = shz_node_next(n, root)) {
        if (n->type == SHZ_ELEMENT_NODE && shz_selector_matches(l, n) && SHZ_FAILED(shz_list_static_push(list, n))) {
            shz_list_release(list);
            shz_selector_free(l);
            return SHZ_E_OUTOFMEMORY;
        }
    }
    shz_selector_free(l);
    *out = list;
    return SHZ_OK;
}

shz_res shz_element_matches(shz_node *elem, const shz_char *selector, int *result)
{
    shz_selector_list *l;
    shz_res hr = shz_selector_parse(selector, shz_strlen(selector), &l);
    *result = 0;
    if (SHZ_FAILED(hr)) return hr;
    *result = elem->type == SHZ_ELEMENT_NODE && shz_selector_matches(l, elem);
    shz_selector_free(l);
    return SHZ_OK;
}
