/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - host test helpers. Every tests/t_*.c is linked with the core objects into its own program;
 * main() returns t_finish(): 0 when every check passed. Expected values come from the specifications (WHATWG HTML,
 * DOM, CSS 2.1, Selectors) or are computed by hand in the test, never read back from the implementation.
 *
 * Tree dumps use the html5lib-tests format: one line per node, "| " + two spaces per depth, elements as <name>
 * (<svg name> / <math name> for foreign elements), attributes sorted by name on their own lines as name="value",
 * text as "text", comments as <!-- data -->, doctypes as <!DOCTYPE name "public" "system">.
 */
#ifndef SHZ_HOST_TEST_H
#define SHZ_HOST_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../core/dom.h"
#include "../core/html_parser.h"
#include "../core/serialize.h"

static int t_checks, t_failures;

#define T_CHECK(name, cond) do { ++t_checks; if (cond) printf("PASS: %s\n", (name)); \
    else { ++t_failures; printf("FAIL: %s (%s:%d)\n", (name), __FILE__, __LINE__); } } while (0)

/* ---- string pool: converted strings live until t_finish */
static void *t_pool[4096];
static size_t t_pool_n;

static void *t_keep(void *p)
{
    if (p && t_pool_n < sizeof(t_pool) / sizeof(t_pool[0])) t_pool[t_pool_n++] = p;
    return p;
}

/* pooled copy of a C string */
static const char *t_strdup(const char *s)
{
    size_t n = strlen(s);
    char *r = t_keep(shz_alloc(n + 1));
    memcpy(r, s, n + 1);
    return r;
}

/* UTF-8 -> UTF-16 (pooled) */
static shz_char *T(const char *s)
{
    size_t n = strlen(s), i = 0, o = 0;
    shz_char *w = t_keep(shz_alloc((n + 1) * sizeof(shz_char)));
    while (i < n) {
        unsigned char c = (unsigned char)s[i];
        uint32_t cp;
        if (c < 0x80) { cp = c; i += 1; }
        else if ((c & 0xE0) == 0xC0) { cp = ((uint32_t)(c & 0x1F) << 6) | (s[i + 1] & 0x3F); i += 2; }
        else if ((c & 0xF0) == 0xE0) { cp = ((uint32_t)(c & 0x0F) << 12) | ((uint32_t)(s[i + 1] & 0x3F) << 6) | (s[i + 2] & 0x3F); i += 3; }
        else { cp = ((uint32_t)(c & 0x07) << 18) | ((uint32_t)(s[i + 1] & 0x3F) << 12) | ((uint32_t)(s[i + 2] & 0x3F) << 6) | (s[i + 3] & 0x3F); i += 4; }
        if (cp >= 0x10000) {
            cp -= 0x10000;
            w[o++] = (shz_char)(0xD800 + (cp >> 10));
            w[o++] = (shz_char)(0xDC00 + (cp & 0x3FF));
        } else {
            w[o++] = (shz_char)cp;
        }
    }
    w[o] = 0;
    return w;
}

/* UTF-16 (n units, or NUL-terminated when n == (size_t)-1) -> UTF-8 (pooled); NULL -> "(null)" */
static const char *U8n(const shz_char *s, size_t n)
{
    shz_bytes b;
    if (!s) return "(null)";
    if (n == (size_t)-1) n = shz_strlen(s);
    shz_bytes_init(&b);
    shz_bytes_put_utf8(&b, s, n);
    shz_bytes_putc(&b, 0);
    return t_keep(b.p);
}

static const char *U8(const shz_char *s)
{
    return U8n(s, (size_t)-1);
}

/* take ownership of an engine-allocated string and return it as UTF-8 */
static const char *U8take(shz_char *s)
{
    const char *r = U8(s);
    shz_free(s);
    return r;
}

#define T_STREQ(name, got, expected) do { const char *g_ = (got), *e_ = (expected); ++t_checks; \
    if (g_ && e_ && !strcmp(g_, e_)) printf("PASS: %s\n", (name)); \
    else { ++t_failures; printf("FAIL: %s (%s:%d)\n  got:      [%s]\n  expected: [%s]\n", (name), __FILE__, __LINE__, \
                                g_ ? g_ : "(null)", e_ ? e_ : "(null)"); } } while (0)

#define T_INTEQ(name, got, expected) do { long long g_ = (long long)(got), e_ = (long long)(expected); ++t_checks; \
    if (g_ == e_) printf("PASS: %s\n", (name)); \
    else { ++t_failures; printf("FAIL: %s (%s:%d): got %lld, expected %lld\n", (name), __FILE__, __LINE__, g_, e_); } } while (0)

/* ---- recording hooks */
typedef struct t_host {
    char log[65536];
    size_t len;
    int parse_done, load_done, title_changed;
    void (*on_script)(struct t_host *h, shz_doc *doc, shz_node *script, int parser_inserted);
    void (*on_inserted)(struct t_host *h, shz_doc *doc, shz_node *node);
    void *user;
} t_host;

static void t_log(t_host *h, const char *s)
{
    size_t n = strlen(s);
    if (h->len + n + 2 >= sizeof(h->log)) return;
    memcpy(h->log + h->len, s, n);
    h->len += n;
    h->log[h->len++] = ';';
    h->log[h->len] = 0;
}

static const char *t_node_label(shz_node *n)
{
    static char buf[256];
    if (n->type == SHZ_ELEMENT_NODE) snprintf(buf, sizeof(buf), "%s", U8n(((shz_element *)n)->qname, ((shz_element *)n)->qname_len));
    else if (n->type == SHZ_TEXT_NODE) snprintf(buf, sizeof(buf), "#text(%s)", U8n(((shz_chardata *)n)->data, ((shz_chardata *)n)->len));
    else if (n->type == SHZ_COMMENT_NODE) snprintf(buf, sizeof(buf), "#comment(%s)", U8n(((shz_chardata *)n)->data, ((shz_chardata *)n)->len));
    else if (n->type == SHZ_DOCTYPE_NODE) snprintf(buf, sizeof(buf), "#doctype");
    else snprintf(buf, sizeof(buf), "#node%d", n->type);
    return buf;
}

static void th_inserted(void *ctx, shz_doc *doc, shz_node *node)
{
    t_host *h = ctx;
    char buf[300];
    snprintf(buf, sizeof(buf), "+%s", t_node_label(node));
    t_log(h, buf);
    if (h->on_inserted) h->on_inserted(h, doc, node);
}

static void th_removed(void *ctx, shz_doc *doc, shz_node *node)
{
    t_host *h = ctx;
    char buf[300];
    (void)doc;
    snprintf(buf, sizeof(buf), "-%s", t_node_label(node));
    t_log(h, buf);
}

static void th_parse_done(void *ctx, shz_doc *doc)
{
    (void)doc;
    ((t_host *)ctx)->parse_done++;
}

static void th_load_done(void *ctx, shz_doc *doc)
{
    (void)doc;
    ((t_host *)ctx)->load_done++;
}

static void th_title(void *ctx, shz_doc *doc)
{
    (void)doc;
    ((t_host *)ctx)->title_changed++;
}

static void th_script(void *ctx, shz_doc *doc, shz_node *script, int parser_inserted)
{
    t_host *h = ctx;
    if (h->on_script) h->on_script(h, doc, script, parser_inserted);
}

static const shz_doc_hooks t_hooks = {
    th_inserted, th_removed, th_parse_done, th_script, NULL, NULL, th_load_done, th_title, NULL, NULL, NULL, NULL
};

static shz_doc *t_new_doc(t_host *h)
{
    shz_doc *doc = NULL;
    if (h) memset(h, 0, sizeof(*h));
    shz_doc_create(h ? &t_hooks : NULL, h, T("http://example.com/dir/page.html"), NULL, &doc);
    return doc;
}

static shz_doc *t_parse(const char *html, t_host *h)
{
    shz_doc *doc = t_new_doc(h);
    const shz_char *w = T(html);
    shz_doc_load_string(doc, w, shz_strlen(w));
    return doc;
}

/* ---- html5lib-style tree dump */
static int t_cmp_attr(const void *a, const void *b)
{
    const shz_attr *x = *(const shz_attr *const *)a, *y = *(const shz_attr *const *)b;
    return shz_strcmp(x->name, y->name);
}

static void t_indent(shz_bytes *b, int depth)
{
    int i;
    shz_bytes_put_ascii(b, "| ");
    for (i = 0; i < depth; ++i) shz_bytes_put_ascii(b, "  ");
}

static void t_dump_rec(shz_bytes *b, shz_node *n, int depth)
{
    shz_node *c;
    for (c = n->first_child; c; c = c->next_sibling) {
        t_indent(b, depth);
        switch (c->type) {
        case SHZ_ELEMENT_NODE: {
            shz_element *e = (shz_element *)c;
            shz_attr *sorted[64];
            uint32_t i, na = e->attr_count < 64 ? e->attr_count : 64;
            shz_bytes_putc(b, '<');
            if (e->ns == SHZ_NS_SVG) shz_bytes_put_ascii(b, "svg ");
            else if (e->ns == SHZ_NS_MATHML) shz_bytes_put_ascii(b, "math ");
            shz_bytes_put_utf8(b, e->qname, e->qname_len);
            shz_bytes_put_ascii(b, ">\n");
            for (i = 0; i < na; ++i) sorted[i] = &e->attrs[i];
            qsort(sorted, na, sizeof(sorted[0]), t_cmp_attr);
            for (i = 0; i < na; ++i) {
                t_indent(b, depth + 1);
                shz_bytes_put_utf8(b, sorted[i]->name, shz_strlen(sorted[i]->name));
                shz_bytes_put_ascii(b, "=\"");
                shz_bytes_put_utf8(b, sorted[i]->value, sorted[i]->value_len);
                shz_bytes_put_ascii(b, "\"\n");
            }
            t_dump_rec(b, c, depth + 1);
            break;
        }
        case SHZ_TEXT_NODE: case SHZ_CDATA_SECTION_NODE:
            shz_bytes_putc(b, '"');
            shz_bytes_put_utf8(b, ((shz_chardata *)c)->data, ((shz_chardata *)c)->len);
            shz_bytes_put_ascii(b, "\"\n");
            break;
        case SHZ_COMMENT_NODE:
            shz_bytes_put_ascii(b, "<!-- ");
            shz_bytes_put_utf8(b, ((shz_chardata *)c)->data, ((shz_chardata *)c)->len);
            shz_bytes_put_ascii(b, " -->\n");
            break;
        case SHZ_DOCTYPE_NODE: {
            shz_doctype *d = (shz_doctype *)c;
            shz_bytes_put_ascii(b, "<!DOCTYPE ");
            shz_bytes_put_utf8(b, d->name, shz_strlen(d->name));
            if (d->public_id || d->system_id) {
                shz_bytes_put_ascii(b, " \"");
                if (d->public_id) shz_bytes_put_utf8(b, d->public_id, shz_strlen(d->public_id));
                shz_bytes_put_ascii(b, "\" \"");
                if (d->system_id) shz_bytes_put_utf8(b, d->system_id, shz_strlen(d->system_id));
                shz_bytes_putc(b, '"');
            }
            shz_bytes_put_ascii(b, ">\n");
            break;
        }
        case SHZ_PI_NODE:
            shz_bytes_put_ascii(b, "<?");
            shz_bytes_put_utf8(b, ((shz_chardata *)c)->target, shz_strlen(((shz_chardata *)c)->target));
            shz_bytes_putc(b, ' ');
            shz_bytes_put_utf8(b, ((shz_chardata *)c)->data, ((shz_chardata *)c)->len);
            shz_bytes_put_ascii(b, ">\n");
            break;
        default:
            break;
        }
    }
}

static const char *t_dump(shz_node *n)
{
    shz_bytes b;
    shz_bytes_init(&b);
    t_dump_rec(&b, n, 0);
    shz_bytes_putc(&b, 0);
    return t_keep(b.p);
}

static const char *t_dump_doc(shz_doc *doc)
{
    return t_dump(doc->node);
}

static int t_finish(const char *what)
{
    size_t i;
    for (i = 0; i < t_pool_n; ++i) shz_free(t_pool[i]);
    t_pool_n = 0;
    printf("%s: %d checks, %d failed\n", what, t_checks, t_failures);
    return t_failures ? 1 : 0;
}

#endif /* SHZ_HOST_TEST_H */
