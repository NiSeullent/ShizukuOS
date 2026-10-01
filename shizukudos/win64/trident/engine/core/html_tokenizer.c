/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - HTML tokenizer (WHATWG HTML 13.2.5).
 *
 * Implemented: data, RCDATA, RAWTEXT, script data (as RAWTEXT: the "script data escaped" states for "<!--<script>"
 * inside scripts are not implemented), PLAINTEXT, tag open/name, attributes (all value states), self-closing, bogus
 * comments, markup declarations, comments (a conditional comment "<!--[if IE]>...<![endif]-->" is one comment token,
 * as the grammar gives it), DOCTYPE with public and system identifiers, CDATA sections (foreign content and XML), and
 * character references (numeric with the windows-1252 C1 replacement table; named from entities.c).
 *
 * The tokenizer is resumable at any input position: a state that needs lookahead the input does not have yet stops
 * without consuming and resumes when more input arrives (network chunks, document.write).
 */
#include "html_int.h"
#include "entities.h"

void shz_token_reset(token *t)
{
    size_t i;
    t->type = 0;
    shz_buf_clear(&t->name);
    t->tag = 0;
    t->self_closing = 0;
    for (i = 0; i < t->nattrs; ++i) {
        shz_buf_clear(&t->attrs[i].name);
        shz_buf_clear(&t->attrs[i].value);
        t->attrs[i].dup = 0;
    }
    t->nattrs = 0;
    t->force_quirks = t->has_name = t->has_public = t->has_system = 0;
    shz_buf_clear(&t->public_id);
    shz_buf_clear(&t->system_id);
    shz_buf_clear(&t->data);
    t->chars = NULL;
    t->nchars = 0;
}

void shz_token_free(token *t)
{
    size_t i;
    shz_buf_free(&t->name);
    for (i = 0; i < t->attr_cap; ++i) {
        shz_buf_free(&t->attrs[i].name);
        shz_buf_free(&t->attrs[i].value);
    }
    shz_free(t->attrs);
    t->attrs = NULL;
    t->nattrs = t->attr_cap = 0;
    shz_buf_free(&t->public_id);
    shz_buf_free(&t->system_id);
    shz_buf_free(&t->data);
}

/* ---------------------------------------------------------------------------------------------------- charrefs */

size_t shz_consume_charref(const shz_char *s, size_t n, int at_eof, int in_attr, shz_buf *out)
{
    size_t i;
    if (n < 2) return at_eof ? 0 : (size_t)-1;
    if (s[1] == '#') {
        int hex = 0;
        uint32_t v = 0;
        size_t start;
        i = 2;
        if (i >= n) return at_eof ? 0 : (size_t)-1;
        if (s[i] == 'x' || s[i] == 'X') {
            hex = 1;
            ++i;
        }
        start = i;
        while (i < n && (hex ? shz_is_ascii_hex(s[i]) : shz_is_ascii_digit(s[i]))) {
            uint32_t d = hex ? (uint32_t)shz_hex_value(s[i]) : (uint32_t)(s[i] - '0');
            if (v <= 0x10FFFF) v = v * (hex ? 16 : 10) + d;
            ++i;
        }
        if (i >= n && !at_eof) return (size_t)-1;
        if (i == start) return 0;                       /* "&#" / "&#x" without digits: literal */
        if (i < n && s[i] == ';') ++i;
        if (v == 0 || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) v = 0xFFFD;
        else if (v >= 0x80 && v <= 0x9F) v = shz_cp1252_c1((uint8_t)v);
        shz_buf_put_cp(out, v);
        return i;
    }
    if (!shz_is_ascii_alnum(s[1])) return 0;
    /* named: make sure enough of the alphanumeric run is available */
    i = 1;
    while (i < n && i <= SHZ_ENTITY_MAX_LEN + 1 && shz_is_ascii_alnum(s[i])) ++i;
    if (i >= n && !at_eof && i <= SHZ_ENTITY_MAX_LEN + 1) return (size_t)-1;
    {
        uint32_t cp;
        int semi;
        size_t avail = n - 1 < SHZ_ENTITY_MAX_LEN + 1 ? n - 1 : SHZ_ENTITY_MAX_LEN + 1;
        size_t len = shz_entity_match(s + 1, avail, &cp, &semi);
        if (!len) return 0;
        if (in_attr && !semi && 1 + len < n && (s[1 + len] == '=' || shz_is_ascii_alnum(s[1 + len]))) return 0;
        shz_buf_put_cp(out, cp);
        return 1 + len;
    }
}

/* ---------------------------------------------------------------------------------------------------- helpers */

static void flush_chars(shz_parser *p)
{
    token t;
    if (!p->chars.len) return;
    memset(&t, 0, sizeof(t));
    t.type = TOK_CHARS;
    t.chars = p->chars.s;
    t.nchars = p->chars.len;
    shz_tree_token(p, &t);
    p->chars.len = 0;
}

static void emit_eof(shz_parser *p)
{
    token t;
    flush_chars(p);
    memset(&t, 0, sizeof(t));
    t.type = TOK_EOF;
    shz_tree_token(p, &t);
}

static void new_token(shz_parser *p, int type)
{
    shz_token_reset(&p->tok);
    p->tok.type = type;
    p->attr = NULL;
}

static void emit_current(shz_parser *p)
{
    token *t = &p->tok;
    flush_chars(p);
    if (t->type == TOK_START || t->type == TOK_END) {
        t->tag = p->xml ? 0 : shz_tag_lookup(t->name.s, t->name.len);
        if (t->type == TOK_START) {
            shz_buf_clear(&p->last_start);
            shz_buf_put(&p->last_start, t->name.s, t->name.len);
        }
    }
    shz_tree_token(p, t);
    /* NOTE: the token is not reset here: a script run from shz_tree_token may have parsed document.write text that
     * left a partial token behind (the next token start resets it). */
}

static void start_attr(shz_parser *p)
{
    token *t = &p->tok;
    if (t->nattrs == t->attr_cap) {
        void *a = t->attrs;
        size_t cap = t->attr_cap, i;
        if (!shz_grow(&a, &cap, t->nattrs + 1, sizeof(tok_attr))) { p->attr = NULL; return; }
        t->attrs = a;
        for (i = t->attr_cap; i < cap; ++i) {
            shz_buf_init(&t->attrs[i].name);
            shz_buf_init(&t->attrs[i].value);
            t->attrs[i].dup = 0;
        }
        t->attr_cap = cap;
    }
    p->attr = &t->attrs[t->nattrs++];
    shz_buf_clear(&p->attr->name);
    shz_buf_clear(&p->attr->value);
    p->attr->dup = 0;
}

/* leaving the attribute name state: drop duplicates */
static void check_dup_attr(shz_parser *p)
{
    token *t = &p->tok;
    size_t i;
    if (!p->attr) return;
    for (i = 0; i + 1 < t->nattrs; ++i) {
        if (&t->attrs[i] == p->attr) break;
        if (!t->attrs[i].dup && shz_strneq(t->attrs[i].name.s, t->attrs[i].name.len, p->attr->name.s, p->attr->name.len)) {
            p->attr->dup = 1;
            return;
        }
    }
}

static void attr_name_putc(shz_parser *p, shz_char c)
{
    if (p->attr) shz_buf_putc(&p->attr->name, c);
}

static void attr_value_put(shz_parser *p, const shz_char *s, size_t n)
{
    if (p->attr) shz_buf_put(&p->attr->value, s, n);
}

static int appropriate_end_tag(shz_parser *p)
{
    return p->last_start.len && shz_strneq(p->tok.name.s, p->tok.name.len, p->last_start.s, p->last_start.len);
}

static shz_char lc(shz_parser *p, shz_char c)
{
    return p->xml ? c : shz_lower(c);
}

/* the adjusted current node is not an HTML element (CDATA sections allowed) */
static int in_foreign(shz_parser *p)
{
    shz_node *n;
    if (p->xml) return 1;
    if (!p->stack.len) return 0;
    n = p->stack.items[p->stack.len - 1];
    return n->type == SHZ_ELEMENT_NODE && ((shz_element *)n)->ns != SHZ_NS_HTML;
}

/* ---------------------------------------------------------------------------------------------------- the loop */

#define LIMIT() (p->has_ins ? p->ins : p->in.len)

void shz_tokenize(shz_parser *p)
{
    for (;;) {
        size_t limit = LIMIT();
        const shz_char *in = p->in.s;
        int at_eof = p->eof && !p->has_ins && p->pos >= p->in.len;
        shz_char c = 0;
        size_t k;

        if (p->done) break;
        if (p->pos >= limit && !at_eof) break;
        if (p->pos < limit) c = in[p->pos];

        switch (p->state) {
        /* ------------------------------------------------------------------------------------ text states */
        case TS_DATA:
            if (at_eof) { emit_eof(p); return; }
            if (c == '<') { p->state = TS_TAG_OPEN; ++p->pos; break; }
            if (c == '&') {
                k = shz_consume_charref(in + p->pos, limit - p->pos, p->eof && limit == p->in.len && !p->has_ins, 0, &p->chars);
                if (k == (size_t)-1) goto need_more;
                if (!k) { shz_buf_putc(&p->chars, '&'); k = 1; }
                p->pos += k;
                break;
            }
            if (c == 0) { ++p->pos; break; }
            k = p->pos;
            while (k < limit && in[k] != '<' && in[k] != '&' && in[k] != 0) ++k;
            shz_buf_put(&p->chars, in + p->pos, k - p->pos);
            p->pos = k;
            break;
        case TS_RCDATA:
        case TS_RAWTEXT:
        case TS_SCRIPT:
            if (at_eof) { emit_eof(p); return; }
            if (c == '<') { p->text_state = p->state; p->state = TS_TEXT_LT; ++p->pos; break; }
            if (c == '&' && p->state == TS_RCDATA) {
                k = shz_consume_charref(in + p->pos, limit - p->pos, p->eof && limit == p->in.len && !p->has_ins, 0, &p->chars);
                if (k == (size_t)-1) goto need_more;
                if (!k) { shz_buf_putc(&p->chars, '&'); k = 1; }
                p->pos += k;
                break;
            }
            if (c == 0) { shz_buf_putc(&p->chars, 0xFFFD); ++p->pos; break; }
            k = p->pos;
            while (k < limit && in[k] != '<' && in[k] != '&' && in[k] != 0) ++k;
            if (k == p->pos) k = p->pos + 1;      /* a '&' in RAWTEXT/script */
            shz_buf_put(&p->chars, in + p->pos, k - p->pos);
            p->pos = k;
            break;
        case TS_PLAINTEXT:
            if (at_eof) { emit_eof(p); return; }
            shz_buf_putc(&p->chars, c ? c : 0xFFFD);
            ++p->pos;
            break;
        case TS_TEXT_LT:
            if (!at_eof && c == '/') {
                shz_buf_clear(&p->tmp);
                p->state = TS_TEXT_END_TAG_OPEN;
                ++p->pos;
                break;
            }
            shz_buf_putc(&p->chars, '<');
            p->state = p->text_state;
            break;
        case TS_TEXT_END_TAG_OPEN:
            if (!at_eof && shz_is_ascii_alpha(c)) {
                new_token(p, TOK_END);
                p->state = TS_TEXT_END_TAG_NAME;
                break;
            }
            shz_buf_put_ascii(&p->chars, "</");
            p->state = p->text_state;
            break;
        case TS_TEXT_END_TAG_NAME:
            if (!at_eof) {
                if (shz_is_space(c) && appropriate_end_tag(p)) { p->state = TS_BEFORE_ATTR_NAME; ++p->pos; break; }
                if (c == '/' && appropriate_end_tag(p)) { p->state = TS_SELF_CLOSING_START_TAG; ++p->pos; break; }
                if (c == '>' && appropriate_end_tag(p)) { p->state = TS_DATA; ++p->pos; emit_current(p); break; }
                if (shz_is_ascii_alpha(c)) {
                    shz_buf_putc(&p->tok.name, lc(p, c));
                    shz_buf_putc(&p->tmp, c);
                    ++p->pos;
                    break;
                }
            }
            shz_buf_put_ascii(&p->chars, "</");
            shz_buf_put(&p->chars, p->tmp.s, p->tmp.len);
            p->state = p->text_state;
            break;

        /* ------------------------------------------------------------------------------------ tags */
        case TS_TAG_OPEN:
            if (at_eof) { shz_buf_putc(&p->chars, '<'); p->state = TS_DATA; break; }
            if (c == '!') { p->state = TS_MARKUP_DECLARATION_OPEN; ++p->pos; break; }
            if (c == '/') { p->state = TS_END_TAG_OPEN; ++p->pos; break; }
            if (shz_is_ascii_alpha(c)) { new_token(p, TOK_START); p->state = TS_TAG_NAME; break; }
            if (c == '?') { new_token(p, TOK_COMMENT); p->state = TS_BOGUS_COMMENT; break; }
            shz_buf_putc(&p->chars, '<');
            p->state = TS_DATA;
            break;
        case TS_END_TAG_OPEN:
            if (at_eof) { shz_buf_put_ascii(&p->chars, "</"); p->state = TS_DATA; break; }
            if (shz_is_ascii_alpha(c)) { new_token(p, TOK_END); p->state = TS_TAG_NAME; break; }
            if (c == '>') { p->state = TS_DATA; ++p->pos; break; }
            new_token(p, TOK_COMMENT);
            p->state = TS_BOGUS_COMMENT;
            break;
        case TS_TAG_NAME:
            if (at_eof) { p->state = TS_DATA; emit_eof(p); return; }
            ++p->pos;
            if (shz_is_space(c)) p->state = TS_BEFORE_ATTR_NAME;
            else if (c == '/') p->state = TS_SELF_CLOSING_START_TAG;
            else if (c == '>') { p->state = TS_DATA; emit_current(p); }
            else shz_buf_putc(&p->tok.name, c ? lc(p, c) : 0xFFFD);
            break;
        case TS_BEFORE_ATTR_NAME:
            if (!at_eof && shz_is_space(c)) { ++p->pos; break; }
            if (at_eof || c == '/' || c == '>') { p->state = TS_AFTER_ATTR_NAME; break; }
            start_attr(p);
            if (c == '=') { attr_name_putc(p, c); ++p->pos; }
            p->state = TS_ATTR_NAME;
            break;
        case TS_ATTR_NAME:
            if (at_eof || shz_is_space(c) || c == '/' || c == '>') {
                check_dup_attr(p);
                p->state = TS_AFTER_ATTR_NAME;
                break;
            }
            ++p->pos;
            if (c == '=') { check_dup_attr(p); p->state = TS_BEFORE_ATTR_VALUE; }
            else attr_name_putc(p, c ? lc(p, c) : 0xFFFD);
            break;
        case TS_AFTER_ATTR_NAME:
            if (at_eof) { p->state = TS_DATA; emit_eof(p); return; }
            if (shz_is_space(c)) { ++p->pos; break; }
            if (c == '/') { p->state = TS_SELF_CLOSING_START_TAG; ++p->pos; break; }
            if (c == '=') { p->state = TS_BEFORE_ATTR_VALUE; ++p->pos; break; }
            if (c == '>') { p->state = TS_DATA; ++p->pos; emit_current(p); break; }
            start_attr(p);
            p->state = TS_ATTR_NAME;
            break;
        case TS_BEFORE_ATTR_VALUE:
            if (!at_eof && shz_is_space(c)) { ++p->pos; break; }
            if (!at_eof && c == '"') { p->state = TS_ATTR_VALUE_DQ; ++p->pos; break; }
            if (!at_eof && c == '\'') { p->state = TS_ATTR_VALUE_SQ; ++p->pos; break; }
            if (!at_eof && c == '>') { p->state = TS_DATA; ++p->pos; emit_current(p); break; }
            p->state = TS_ATTR_VALUE_UQ;
            break;
        case TS_ATTR_VALUE_DQ:
        case TS_ATTR_VALUE_SQ: {
            shz_char q = p->state == TS_ATTR_VALUE_DQ ? '"' : '\'';
            if (at_eof) { p->state = TS_DATA; emit_eof(p); return; }
            if (c == q) { p->state = TS_AFTER_ATTR_VALUE_QUOTED; ++p->pos; break; }
            if (c == '&') {
                shz_buf tmp;
                shz_buf_init(&tmp);
                k = shz_consume_charref(in + p->pos, limit - p->pos, p->eof && limit == p->in.len && !p->has_ins, 1, &tmp);
                if (k == (size_t)-1) { shz_buf_free(&tmp); goto need_more; }
                if (!k) { shz_buf_putc(&tmp, '&'); k = 1; }
                attr_value_put(p, tmp.s, tmp.len);
                shz_buf_free(&tmp);
                p->pos += k;
                break;
            }
            k = p->pos;
            while (k < limit && in[k] != q && in[k] != '&' && in[k] != 0) ++k;
            if (k == p->pos) {
                shz_char r = 0xFFFD;
                attr_value_put(p, &r, 1);
                ++p->pos;
                break;
            }
            attr_value_put(p, in + p->pos, k - p->pos);
            p->pos = k;
            break;
        }
        case TS_ATTR_VALUE_UQ:
            if (at_eof) { p->state = TS_DATA; emit_eof(p); return; }
            if (shz_is_space(c)) { p->state = TS_BEFORE_ATTR_NAME; ++p->pos; break; }
            if (c == '>') { p->state = TS_DATA; ++p->pos; emit_current(p); break; }
            if (c == '&') {
                shz_buf tmp;
                shz_buf_init(&tmp);
                k = shz_consume_charref(in + p->pos, limit - p->pos, p->eof && limit == p->in.len && !p->has_ins, 1, &tmp);
                if (k == (size_t)-1) { shz_buf_free(&tmp); goto need_more; }
                if (!k) { shz_buf_putc(&tmp, '&'); k = 1; }
                attr_value_put(p, tmp.s, tmp.len);
                shz_buf_free(&tmp);
                p->pos += k;
                break;
            }
            {
                shz_char r = c ? c : 0xFFFD;
                attr_value_put(p, &r, 1);
            }
            ++p->pos;
            break;
        case TS_AFTER_ATTR_VALUE_QUOTED:
            if (at_eof) { p->state = TS_DATA; emit_eof(p); return; }
            if (shz_is_space(c)) { p->state = TS_BEFORE_ATTR_NAME; ++p->pos; break; }
            if (c == '/') { p->state = TS_SELF_CLOSING_START_TAG; ++p->pos; break; }
            if (c == '>') { p->state = TS_DATA; ++p->pos; emit_current(p); break; }
            p->state = TS_BEFORE_ATTR_NAME;
            break;
        case TS_SELF_CLOSING_START_TAG:
            if (at_eof) { p->state = TS_DATA; emit_eof(p); return; }
            if (c == '>') { p->tok.self_closing = 1; p->state = TS_DATA; ++p->pos; emit_current(p); break; }
            p->state = TS_BEFORE_ATTR_NAME;
            break;

        /* ------------------------------------------------------------------------------------ comments */
        case TS_BOGUS_COMMENT:
            if (at_eof) { emit_current(p); p->state = TS_DATA; break; }
            ++p->pos;
            if (c == '>') { p->state = TS_DATA; emit_current(p); }
            else shz_buf_putc(&p->tok.data, c ? c : 0xFFFD);
            break;
        case TS_MARKUP_DECLARATION_OPEN: {
            size_t avail = limit - p->pos;
            int final = p->eof && limit == p->in.len && !p->has_ins;
            if (avail >= 2 && in[p->pos] == '-' && in[p->pos + 1] == '-') {
                p->pos += 2;
                new_token(p, TOK_COMMENT);
                p->state = TS_COMMENT_START;
                break;
            }
            if (avail >= 7 && shz_strnieq_ascii(in + p->pos, 7, "doctype")) {
                p->pos += 7;
                p->state = TS_DOCTYPE;
                break;
            }
            if (avail >= 7 && shz_strneq_ascii(in + p->pos, 7, "[CDATA[")) {
                p->pos += 7;
                if (in_foreign(p)) {
                    p->state = TS_CDATA_SECTION;
                } else {
                    new_token(p, TOK_COMMENT);
                    shz_buf_put_ascii(&p->tok.data, "[CDATA[");
                    p->state = TS_BOGUS_COMMENT;
                }
                break;
            }
            if (!final) {
                /* could the available text still grow into one of the three prefixes? */
                static const char *const cands[] = { "--", "doctype", "[CDATA[" };
                size_t ci, i;
                for (ci = 0; ci < SHZ_ARRAY_SIZE(cands); ++ci) {
                    const char *cand = cands[ci];
                    size_t len = 0;
                    int could = 1;
                    while (cand[len]) ++len;
                    if (avail >= len) continue;
                    for (i = 0; i < avail; ++i) {
                        shz_char a = in[p->pos + i], b = (unsigned char)cand[i];
                        if (ci == 1 ? shz_lower(a) != b : a != b) { could = 0; break; }
                    }
                    if (could) goto need_more;
                }
            }
            new_token(p, TOK_COMMENT);
            p->state = TS_BOGUS_COMMENT;
            break;
        }
        case TS_COMMENT_START:
            if (!at_eof && c == '-') { p->state = TS_COMMENT_START_DASH; ++p->pos; break; }
            if (!at_eof && c == '>') { p->state = TS_DATA; ++p->pos; emit_current(p); break; }
            p->state = TS_COMMENT;
            break;
        case TS_COMMENT_START_DASH:
            if (at_eof) { emit_current(p); p->state = TS_DATA; break; }
            if (c == '-') { p->state = TS_COMMENT_END; ++p->pos; break; }
            if (c == '>') { p->state = TS_DATA; ++p->pos; emit_current(p); break; }
            shz_buf_putc(&p->tok.data, '-');
            p->state = TS_COMMENT;
            break;
        case TS_COMMENT:
            if (at_eof) { emit_current(p); p->state = TS_DATA; break; }
            if (c == '-') { p->state = TS_COMMENT_END_DASH; ++p->pos; break; }
            k = p->pos;
            while (k < limit && in[k] != '-' && in[k] != 0) ++k;
            if (k == p->pos) { shz_buf_putc(&p->tok.data, 0xFFFD); ++p->pos; break; }
            shz_buf_put(&p->tok.data, in + p->pos, k - p->pos);
            p->pos = k;
            break;
        case TS_COMMENT_END_DASH:
            if (at_eof) { emit_current(p); p->state = TS_DATA; break; }
            if (c == '-') { p->state = TS_COMMENT_END; ++p->pos; break; }
            shz_buf_putc(&p->tok.data, '-');
            p->state = TS_COMMENT;
            break;
        case TS_COMMENT_END:
            if (at_eof) { emit_current(p); p->state = TS_DATA; break; }
            if (c == '>') { p->state = TS_DATA; ++p->pos; emit_current(p); break; }
            if (c == '!') { p->state = TS_COMMENT_END_BANG; ++p->pos; break; }
            if (c == '-') { shz_buf_putc(&p->tok.data, '-'); ++p->pos; break; }
            shz_buf_put_ascii(&p->tok.data, "--");
            p->state = TS_COMMENT;
            break;
        case TS_COMMENT_END_BANG:
            if (at_eof) { emit_current(p); p->state = TS_DATA; break; }
            if (c == '-') { shz_buf_put_ascii(&p->tok.data, "--!"); p->state = TS_COMMENT_END_DASH; ++p->pos; break; }
            if (c == '>') { p->state = TS_DATA; ++p->pos; emit_current(p); break; }
            shz_buf_put_ascii(&p->tok.data, "--!");
            p->state = TS_COMMENT;
            break;

        /* ------------------------------------------------------------------------------------ DOCTYPE */
        case TS_DOCTYPE:
            if (at_eof) {
                new_token(p, TOK_DOCTYPE);
                p->tok.force_quirks = 1;
                emit_current(p);
                p->state = TS_DATA;
                break;
            }
            if (shz_is_space(c)) ++p->pos;
            p->state = TS_BEFORE_DOCTYPE_NAME;
            break;
        case TS_BEFORE_DOCTYPE_NAME:
            if (!at_eof && shz_is_space(c)) { ++p->pos; break; }
            new_token(p, TOK_DOCTYPE);
            if (at_eof) { p->tok.force_quirks = 1; emit_current(p); p->state = TS_DATA; break; }
            ++p->pos;
            if (c == '>') { p->tok.force_quirks = 1; p->state = TS_DATA; emit_current(p); break; }
            p->tok.has_name = 1;
            shz_buf_putc(&p->tok.name, c ? lc(p, c) : 0xFFFD);
            p->state = TS_DOCTYPE_NAME;
            break;
        case TS_DOCTYPE_NAME:
            if (at_eof) { p->tok.force_quirks = 1; emit_current(p); p->state = TS_DATA; break; }
            ++p->pos;
            if (shz_is_space(c)) p->state = TS_AFTER_DOCTYPE_NAME;
            else if (c == '>') { p->state = TS_DATA; emit_current(p); }
            else shz_buf_putc(&p->tok.name, c ? lc(p, c) : 0xFFFD);
            break;
        case TS_AFTER_DOCTYPE_NAME: {
            size_t avail = limit - p->pos;
            if (at_eof) { p->tok.force_quirks = 1; emit_current(p); p->state = TS_DATA; break; }
            if (shz_is_space(c)) { ++p->pos; break; }
            if (c == '>') { p->state = TS_DATA; ++p->pos; emit_current(p); break; }
            if (avail < 6 && !(p->eof && limit == p->in.len && !p->has_ins)) {
                size_t i;
                int maybe_pub = 1, maybe_sys = 1;
                for (i = 0; i < avail; ++i) {
                    if (shz_lower(in[p->pos + i]) != (shz_char)"public"[i]) maybe_pub = 0;
                    if (shz_lower(in[p->pos + i]) != (shz_char)"system"[i]) maybe_sys = 0;
                }
                if (maybe_pub || maybe_sys) goto need_more;
            }
            if (avail >= 6 && shz_strnieq_ascii(in + p->pos, 6, "public")) {
                p->pos += 6;
                p->state = TS_AFTER_DOCTYPE_PUBLIC_KEYWORD;
                break;
            }
            if (avail >= 6 && shz_strnieq_ascii(in + p->pos, 6, "system")) {
                p->pos += 6;
                p->state = TS_AFTER_DOCTYPE_SYSTEM_KEYWORD;
                break;
            }
            p->tok.force_quirks = 1;
            p->state = TS_BOGUS_DOCTYPE;
            break;
        }
        case TS_AFTER_DOCTYPE_PUBLIC_KEYWORD:
        case TS_BEFORE_DOCTYPE_PUBLIC_ID:
            if (at_eof) { p->tok.force_quirks = 1; emit_current(p); p->state = TS_DATA; break; }
            if (shz_is_space(c)) {
                ++p->pos;
                p->state = TS_BEFORE_DOCTYPE_PUBLIC_ID;
                break;
            }
            if (c == '"' || c == '\'') {
                p->tok.has_public = 1;
                shz_buf_clear(&p->tok.public_id);
                p->state = c == '"' ? TS_DOCTYPE_PUBLIC_ID_DQ : TS_DOCTYPE_PUBLIC_ID_SQ;
                ++p->pos;
                break;
            }
            if (c == '>') { p->tok.force_quirks = 1; p->state = TS_DATA; ++p->pos; emit_current(p); break; }
            p->tok.force_quirks = 1;
            p->state = TS_BOGUS_DOCTYPE;
            break;
        case TS_DOCTYPE_PUBLIC_ID_DQ:
        case TS_DOCTYPE_PUBLIC_ID_SQ:
        case TS_DOCTYPE_SYSTEM_ID_DQ:
        case TS_DOCTYPE_SYSTEM_ID_SQ: {
            int sys = p->state == TS_DOCTYPE_SYSTEM_ID_DQ || p->state == TS_DOCTYPE_SYSTEM_ID_SQ;
            shz_char q = (p->state == TS_DOCTYPE_PUBLIC_ID_DQ || p->state == TS_DOCTYPE_SYSTEM_ID_DQ) ? '"' : '\'';
            if (at_eof) { p->tok.force_quirks = 1; emit_current(p); p->state = TS_DATA; break; }
            ++p->pos;
            if (c == q) p->state = sys ? TS_AFTER_DOCTYPE_SYSTEM_ID : TS_AFTER_DOCTYPE_PUBLIC_ID;
            else if (c == '>') { p->tok.force_quirks = 1; p->state = TS_DATA; emit_current(p); }
            else shz_buf_putc(sys ? &p->tok.system_id : &p->tok.public_id, c ? c : 0xFFFD);
            break;
        }
        case TS_AFTER_DOCTYPE_PUBLIC_ID:
        case TS_BETWEEN_DOCTYPE_PUBLIC_AND_SYSTEM_IDS:
            if (at_eof) { p->tok.force_quirks = 1; emit_current(p); p->state = TS_DATA; break; }
            if (shz_is_space(c)) { ++p->pos; p->state = TS_BETWEEN_DOCTYPE_PUBLIC_AND_SYSTEM_IDS; break; }
            if (c == '>') { p->state = TS_DATA; ++p->pos; emit_current(p); break; }
            if (c == '"' || c == '\'') {
                p->tok.has_system = 1;
                shz_buf_clear(&p->tok.system_id);
                p->state = c == '"' ? TS_DOCTYPE_SYSTEM_ID_DQ : TS_DOCTYPE_SYSTEM_ID_SQ;
                ++p->pos;
                break;
            }
            p->tok.force_quirks = 1;
            p->state = TS_BOGUS_DOCTYPE;
            break;
        case TS_AFTER_DOCTYPE_SYSTEM_KEYWORD:
        case TS_BEFORE_DOCTYPE_SYSTEM_ID:
            if (at_eof) { p->tok.force_quirks = 1; emit_current(p); p->state = TS_DATA; break; }
            if (shz_is_space(c)) { ++p->pos; p->state = TS_BEFORE_DOCTYPE_SYSTEM_ID; break; }
            if (c == '"' || c == '\'') {
                p->tok.has_system = 1;
                shz_buf_clear(&p->tok.system_id);
                p->state = c == '"' ? TS_DOCTYPE_SYSTEM_ID_DQ : TS_DOCTYPE_SYSTEM_ID_SQ;
                ++p->pos;
                break;
            }
            if (c == '>') { p->tok.force_quirks = 1; p->state = TS_DATA; ++p->pos; emit_current(p); break; }
            p->tok.force_quirks = 1;
            p->state = TS_BOGUS_DOCTYPE;
            break;
        case TS_AFTER_DOCTYPE_SYSTEM_ID:
            if (at_eof) { p->tok.force_quirks = 1; emit_current(p); p->state = TS_DATA; break; }
            if (shz_is_space(c)) { ++p->pos; break; }
            if (c == '>') { p->state = TS_DATA; ++p->pos; emit_current(p); break; }
            p->state = TS_BOGUS_DOCTYPE;
            break;
        case TS_BOGUS_DOCTYPE:
            if (at_eof) { emit_current(p); p->state = TS_DATA; break; }
            ++p->pos;
            if (c == '>') { p->state = TS_DATA; emit_current(p); }
            break;

        /* ------------------------------------------------------------------------------------ CDATA */
        case TS_CDATA_SECTION: {
            size_t avail = limit - p->pos;
            if (at_eof) { p->state = TS_DATA; break; }
            if (c == ']') {
                if (avail < 3 && !(p->eof && limit == p->in.len && !p->has_ins)) goto need_more;
                if (avail >= 3 && in[p->pos + 1] == ']' && in[p->pos + 2] == '>') {
                    p->pos += 3;
                    p->state = TS_DATA;
                    break;
                }
            }
            shz_buf_putc(&p->chars, c ? c : 0xFFFD);
            ++p->pos;
            break;
        }
        default:
            p->state = TS_DATA;
            break;
        }
        continue;
need_more:
        break;
    }
    flush_chars(p);
}
