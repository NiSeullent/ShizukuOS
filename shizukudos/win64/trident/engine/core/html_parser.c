/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - HTML parser driver: input stream, encoding sniffing, network feeding, document.open/write/
 * close, fragment and standalone-document parsing (see html_parser.h).
 */
#include "html_int.h"
#include "loader.h"

/* ---------------------------------------------------------------------------------------------------- lifetime */

static shz_parser *parser_new(shz_doc *doc, int xml)
{
    shz_parser *p = shz_alloc(sizeof(*p));
    if (!p) return NULL;
    p->doc = doc;
    p->xml = xml;
    shz_buf_init(&p->in);
    shz_buf_init(&p->chars);
    shz_buf_init(&p->tmp);
    shz_buf_init(&p->last_start);
    shz_bytes_init(&p->sniff);
    p->state = TS_DATA;
    p->cs = SHZ_CS_NONE;
    shz_decoder_init(&p->dec, SHZ_CS_UTF8);
    shz_tree_init(p);
    /* the parser keeps its document alive (the Document node counts as a pinned node) */
    shz_node_addref(doc->node);
    return p;
}

static void parser_free(shz_parser *p)
{
    shz_node *docnode = p->doc->node;
    shz_tree_free(p);
    shz_token_free(&p->tok);
    shz_buf_free(&p->in);
    shz_buf_free(&p->chars);
    shz_buf_free(&p->tmp);
    shz_buf_free(&p->last_start);
    shz_bytes_free(&p->sniff);
    if (p->context) shz_node_release(p->context);
    if (p->root) shz_node_release(p->root);
    shz_free(p);
    shz_node_release(docnode);
}

void shz_parser_destroy(shz_doc *doc)
{
    shz_parser *p = doc->parser;
    if (!p) return;
    doc->parser = NULL;
    if (p->running) {
        p->zombie = 1;
        p->done = 1;
        return;
    }
    parser_free(p);
}

int shz_parser_active(shz_doc *doc)
{
    return doc->parser && !doc->parser->done;
}

int shz_parser_in_title(shz_doc *doc)
{
    return doc->parser && doc->parser->title_open;
}

/* ---------------------------------------------------------------------------------------------------- input */

/* append network text at the end of the stream, normalizing CR LF / CR to LF */
static void append_input(shz_parser *p, const shz_char *s, size_t n)
{
    size_t i;
    if (!shz_buf_reserve(&p->in, n)) return;
    for (i = 0; i < n; ++i) {
        shz_char c = s[i];
        if (p->input_cr) {
            p->input_cr = 0;
            if (c == '\n') continue;
        }
        if (c == '\r') {
            p->input_cr = 1;
            c = '\n';
        }
        p->in.s[p->in.len++] = c;
    }
}

/* drop the consumed prefix of the stream when it grows large */
static void compact_input(shz_parser *p)
{
    size_t cut = p->pos, i;
    if (p->running || cut < 65536 || cut < p->in.len / 2) return;
    if (p->has_ins && p->ins < cut) return;
    shz_buf_erase(&p->in, 0, cut);
    p->pos -= cut;
    if (p->has_ins) p->ins -= cut;
    for (i = 0; i < (size_t)p->script_nesting; ++i)
        if (p->ins_stack[i] != (size_t)-1) p->ins_stack[i] -= cut;
}

static void finish(shz_parser *p)
{
    shz_doc *doc = p->doc;
    if (p->finished) return;
    p->finished = 1;
    if (doc->parser == p) doc->parser = NULL;
    parser_free(p);
    shz_load_parser_finished(doc);
}

static void run(shz_parser *p)
{
    shz_doc *doc = p->doc;
    if (p->running) return;                 /* the active loop picks the new input up */
    shz_node_addref(doc->node);             /* keep the document alive across callbacks */
    p->running = 1;
    shz_tokenize(p);
    p->running = 0;
    if (p->zombie) parser_free(p);
    else if (p->done) finish(p);
    shz_node_release(doc->node);
}

static void set_charset(shz_parser *p, shz_charset cs)
{
    shz_char *name = shz_strdup_ascii(shz_charset_name(cs));
    p->cs = cs;
    if (name) {
        shz_free(p->doc->charset);
        p->doc->charset = name;
    }
}

/* decide the encoding from the bytes held back (BOM, channel charset, <meta> prescan, UTF-8) */
static void decide_encoding(shz_parser *p)
{
    shz_charset bom = SHZ_CS_NONE, cs;
    size_t skip = shz_charset_sniff_bom(p->sniff.p, p->sniff.len, &bom);
    shz_buf out;
    if (skip) cs = bom;
    else if (p->cs != SHZ_CS_NONE) cs = p->cs;
    else {
        cs = shz_charset_prescan(p->sniff.p, p->sniff.len < 1024 ? p->sniff.len : 1024);
        if (cs == SHZ_CS_NONE) cs = SHZ_CS_UTF8;
    }
    set_charset(p, cs);
    shz_decoder_init(&p->dec, cs);
    p->cs_confident = 1;
    shz_buf_init(&out);
    shz_decode(&p->dec, p->sniff.p + skip, p->sniff.len - skip, &out, 0);
    append_input(p, out.s, out.len);
    shz_buf_free(&out);
    shz_bytes_free(&p->sniff);
}

/* ---------------------------------------------------------------------------------------------------- loads */

static shz_parser *start_parser(shz_doc *doc)
{
    shz_parser *p;
    if (doc->parser) shz_parser_destroy(doc);
    shz_doc_clear(doc);
    p = parser_new(doc, !doc->is_html);
    if (!p) return NULL;
    doc->parser = p;
    doc->ready_state = SHZ_READY_LOADING;
    shz_load_parser_started(doc);
    return p;
}

shz_res shz_parser_begin(shz_doc *doc, const shz_char *charset)
{
    shz_parser *p = start_parser(doc);
    if (!p) return SHZ_E_OUTOFMEMORY;
    p->bytes_mode = 1;
    if (charset && *charset) {
        shz_charset cs = shz_charset_from_label(charset, shz_strlen(charset));
        if (cs != SHZ_CS_NONE) p->cs = cs;
    }
    return SHZ_OK;
}

shz_res shz_parser_feed(shz_doc *doc, const uint8_t *bytes, size_t n)
{
    shz_parser *p = doc->parser;
    if (!p || !p->bytes_mode || p->eof) return SHZ_E_UNEXPECTED;
    if (!n) return SHZ_OK;
    if (!p->cs_confident) {
        shz_bytes_put(&p->sniff, bytes, n);
        if (p->sniff.oom) return SHZ_E_OUTOFMEMORY;
        if (p->sniff.len < (p->cs != SHZ_CS_NONE ? 3u : 1024u)) return SHZ_OK;
        decide_encoding(p);
    } else {
        shz_buf out;
        shz_buf_init(&out);
        shz_decode(&p->dec, bytes, n, &out, 0);
        append_input(p, out.s, out.len);
        shz_buf_free(&out);
    }
    compact_input(p);
    run(p);
    return SHZ_OK;
}

shz_res shz_parser_end(shz_doc *doc)
{
    shz_parser *p = doc->parser;
    shz_buf out;
    if (!p || !p->bytes_mode || p->eof) return SHZ_E_UNEXPECTED;
    if (!p->cs_confident) decide_encoding(p);
    shz_buf_init(&out);
    shz_decode(&p->dec, NULL, 0, &out, 1);
    append_input(p, out.s, out.len);
    shz_buf_free(&out);
    p->eof = 1;
    run(p);
    return SHZ_OK;
}

shz_res shz_doc_load_string(shz_doc *doc, const shz_char *html, size_t n)
{
    shz_parser *p = start_parser(doc);
    if (!p) return SHZ_E_OUTOFMEMORY;
    append_input(p, html, n);
    if (p->in.oom) return SHZ_E_OUTOFMEMORY;
    p->eof = 1;
    run(p);
    return SHZ_OK;
}

/* ---------------------------------------------------------------------------------------------------- document.write */

shz_res shz_doc_open(shz_doc *doc)
{
    shz_parser *p = doc->parser;
    if (!doc->is_html) return SHZ_E_INVALID_STATE;
    if (p && p->script_nesting > 0) return SHZ_OK;          /* open() inside a parser-inserted script: no-op */
    p = start_parser(doc);
    if (!p) return SHZ_E_OUTOFMEMORY;
    p->script_created = 1;
    p->has_ins = 1;
    p->ins = 0;
    return SHZ_OK;
}

shz_res shz_doc_write(shz_doc *doc, const shz_char *text, size_t n, int newline)
{
    shz_parser *p = doc->parser;
    shz_buf norm;
    size_t i, at;
    int cr = 0;
    if (!doc->is_html) return SHZ_E_INVALID_STATE;
    if (!p || !p->has_ins) {
        shz_res hr = shz_doc_open(doc);
        if (SHZ_FAILED(hr)) return hr;
        p = doc->parser;
        if (!p || !p->has_ins) return SHZ_OK;
    }
    shz_buf_init(&norm);
    for (i = 0; i < n; ++i) {
        shz_char c = text[i];
        if (cr && c == '\n') { cr = 0; continue; }
        cr = c == '\r';
        shz_buf_putc(&norm, cr ? '\n' : c);
    }
    if (newline) shz_buf_putc(&norm, '\n');
    if (norm.oom) { shz_buf_free(&norm); return SHZ_E_OUTOFMEMORY; }
    at = p->ins;
    shz_buf_insert(&p->in, at, norm.s, norm.len);
    if (p->in.oom) { shz_buf_free(&norm); return SHZ_E_OUTOFMEMORY; }
    for (i = 0; i < (size_t)p->script_nesting; ++i)
        if (p->ins_stack[i] != (size_t)-1 && p->ins_stack[i] >= at) p->ins_stack[i] += norm.len;
    p->ins += norm.len;
    shz_buf_free(&norm);
    if (p->running) shz_tokenize(p);        /* nested: process the inserted text up to the insertion point */
    else run(p);
    return SHZ_OK;
}

shz_res shz_doc_close(shz_doc *doc)
{
    shz_parser *p = doc->parser;
    if (!doc->is_html) return SHZ_E_INVALID_STATE;
    if (!p || !p->script_created) return SHZ_OK;
    p->has_ins = 0;
    p->eof = 1;
    run(p);
    return SHZ_OK;
}

/* ---------------------------------------------------------------------------------------------------- fragments */

shz_res shz_parse_fragment(shz_node *context, const shz_char *html, size_t n, shz_node **fragment)
{
    shz_doc *doc = context->doc;
    shz_parser *p;
    shz_node *root, *frag;
    static const shz_char xml_root[] = { 'r' };
    *fragment = NULL;
    frag = shz_create_fragment(doc);
    if (!frag) return SHZ_E_OUTOFMEMORY;
    root = doc->is_html ? shz_create_element_tag(doc, SHZ_TAG_HTML) : shz_create_element(doc, xml_root, 1);
    p = root ? parser_new(doc, !doc->is_html) : NULL;
    if (!p) {
        shz_node_release(root);
        shz_node_release(frag);
        return SHZ_E_OUTOFMEMORY;
    }
    p->fragment = 1;
    p->root = root;                         /* the parser owns the creation reference */
    if (context->type == SHZ_ELEMENT_NODE) {
        p->context = context;
        shz_node_addref(context);
    }
    if (p->xml) {
        shz_vec_push(&p->stack, root);
        shz_node_addref(root);
    } else {
        shz_tree_setup_fragment(p);
    }
    append_input(p, html, n);
    p->eof = 1;
    p->running = 1;
    shz_tokenize(p);
    p->running = 0;
    shz_tree_free(p);                       /* release the stack before moving the children */
    while (root->first_child) shz_dom_insert_raw(frag, root->first_child, NULL);
    parser_free(p);
    *fragment = frag;
    return SHZ_OK;
}

shz_res shz_parse_document(const shz_char *src, size_t n, const shz_char *mime, shz_doc **out)
{
    shz_doc *doc;
    shz_parser *p;
    shz_res hr = shz_doc_create(NULL, NULL, NULL, mime, &doc);
    *out = NULL;
    if (SHZ_FAILED(hr)) return hr;
    p = start_parser(doc);
    if (!p) { shz_doc_release(doc); return SHZ_E_OUTOFMEMORY; }
    append_input(p, src, n);
    p->eof = 1;
    run(p);
    doc->ready_state = SHZ_READY_COMPLETE;
    *out = doc;
    return SHZ_OK;
}
