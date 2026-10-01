/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - HTML parser internals shared by html_parser.c, html_tokenizer.c and html_tree.c.
 */
#ifndef SHZ_HTML_INT_H
#define SHZ_HTML_INT_H

#include "html_parser.h"
#include "charset.h"

/* tokenizer states (WHATWG HTML 13.2.5) */
enum {
    TS_DATA, TS_RCDATA, TS_RAWTEXT, TS_SCRIPT, TS_PLAINTEXT,
    TS_TAG_OPEN, TS_END_TAG_OPEN, TS_TAG_NAME,
    TS_TEXT_LT, TS_TEXT_END_TAG_OPEN, TS_TEXT_END_TAG_NAME,       /* RCDATA / RAWTEXT / script "less-than sign" states */
    TS_BEFORE_ATTR_NAME, TS_ATTR_NAME, TS_AFTER_ATTR_NAME, TS_BEFORE_ATTR_VALUE,
    TS_ATTR_VALUE_DQ, TS_ATTR_VALUE_SQ, TS_ATTR_VALUE_UQ, TS_AFTER_ATTR_VALUE_QUOTED,
    TS_SELF_CLOSING_START_TAG,
    TS_BOGUS_COMMENT, TS_MARKUP_DECLARATION_OPEN,
    TS_COMMENT_START, TS_COMMENT_START_DASH, TS_COMMENT, TS_COMMENT_END_DASH, TS_COMMENT_END, TS_COMMENT_END_BANG,
    TS_DOCTYPE, TS_BEFORE_DOCTYPE_NAME, TS_DOCTYPE_NAME, TS_AFTER_DOCTYPE_NAME,
    TS_AFTER_DOCTYPE_PUBLIC_KEYWORD, TS_BEFORE_DOCTYPE_PUBLIC_ID, TS_DOCTYPE_PUBLIC_ID_DQ, TS_DOCTYPE_PUBLIC_ID_SQ,
    TS_AFTER_DOCTYPE_PUBLIC_ID, TS_BETWEEN_DOCTYPE_PUBLIC_AND_SYSTEM_IDS,
    TS_AFTER_DOCTYPE_SYSTEM_KEYWORD, TS_BEFORE_DOCTYPE_SYSTEM_ID, TS_DOCTYPE_SYSTEM_ID_DQ, TS_DOCTYPE_SYSTEM_ID_SQ,
    TS_AFTER_DOCTYPE_SYSTEM_ID, TS_BOGUS_DOCTYPE,
    TS_CDATA_SECTION
};

enum { TOK_DOCTYPE = 1, TOK_START, TOK_END, TOK_COMMENT, TOK_CHARS, TOK_EOF };

typedef struct tok_attr {
    shz_buf name, value;
    int dup;                            /* duplicate name: dropped when the token is emitted */
} tok_attr;

typedef struct token {
    int type;
    shz_buf name;                       /* tag name (lower-cased in HTML) / doctype name */
    int tag;                            /* SHZ_TAG_* of name (TOK_START / TOK_END) */
    int self_closing;
    tok_attr *attrs;
    size_t nattrs, attr_cap;
    /* doctype */
    int force_quirks, has_name, has_public, has_system;
    shz_buf public_id, system_id;
    /* comment */
    shz_buf data;
    /* characters */
    const shz_char *chars;
    size_t nchars;
} token;

/* insertion modes (WHATWG HTML 13.2.4.1) */
enum {
    IM_INITIAL, IM_BEFORE_HTML, IM_BEFORE_HEAD, IM_IN_HEAD, IM_IN_HEAD_NOSCRIPT, IM_AFTER_HEAD, IM_IN_BODY, IM_TEXT,
    IM_IN_TABLE, IM_IN_TABLE_TEXT, IM_IN_CAPTION, IM_IN_COLUMN_GROUP, IM_IN_TABLE_BODY, IM_IN_ROW, IM_IN_CELL,
    IM_IN_SELECT, IM_IN_SELECT_IN_TABLE, IM_AFTER_BODY, IM_IN_FRAMESET, IM_AFTER_FRAMESET, IM_AFTER_AFTER_BODY,
    IM_AFTER_AFTER_FRAMESET,
    IM_XML                                /* XML documents: plain nesting */
};

#define SHZ_MAX_SCRIPT_NESTING 16

struct shz_parser {
    shz_doc *doc;
    int xml;                            /* XML tree building */
    int fragment;                       /* fragment parsing */
    shz_node *context;                  /* fragment context element (reference) */
    shz_node *root;                     /* fragment case: the <html> element everything is parsed into (reference) */

    /* input stream: decoded, newline-normalized UTF-16 */
    shz_buf in;
    size_t pos;                         /* tokenizer position */
    int has_ins;                        /* the insertion point is defined */
    size_t ins;                         /* insertion point (document.write) */
    size_t ins_stack[SHZ_MAX_SCRIPT_NESTING];   /* saved insertion points of enclosing scripts */
    int eof;                            /* the end of the input was received */
    int input_cr;                       /* the last appended network text ended with CR */
    int script_created;                 /* document.open() parser */

    /* byte input */
    int bytes_mode;                     /* parser_feed is used */
    shz_charset cs;
    int cs_confident;                   /* the encoding is decided (else still sniffing) */
    shz_decoder dec;
    shz_bytes sniff;                    /* bytes held back while sniffing */

    /* tokenizer */
    int state, return_state;
    token tok;
    tok_attr *attr;                     /* attribute being built (points into tok.attrs) */
    shz_buf chars;                      /* pending character token */
    shz_buf tmp;                        /* temporary buffer (end tag names in RCDATA/RAWTEXT/script data) */
    shz_buf last_start;                 /* name of the last start tag emitted ("appropriate end tag") */
    int text_state;                     /* the text state an end-tag attempt returns to (RCDATA/RAWTEXT/SCRIPT) */

    /* tree builder */
    int mode, orig_mode;
    shz_vec stack;                      /* stack of open elements (references held); [0] = html */
    shz_vec fmt;                        /* active formatting elements (references held; NULL = marker) */
    shz_node *head;                     /* head element pointer (reference) */
    shz_node *form;                     /* form element pointer (reference) */
    int frameset_ok;
    int foster;                         /* foster parenting enabled */
    int skip_lf;                        /* ignore a LF at the start of the next character token */
    shz_buf table_chars;                /* in table text: pending characters */
    int table_chars_nonspace;
    int script_nesting;
    int running;                        /* the tokenizer loop is active (re-entrancy guard) */
    int done;                           /* EOF token processed */
    int title_open;                     /* current node is a <title> being filled */
    int zombie;                         /* destroyed while running: freed when the outer loop unwinds */
    int finished;                       /* the end-of-parse steps ran */
};

/* html_tokenizer.c: run the tokenizer from p->pos up to the insertion point (when defined) or the end of the input.
 * At the end of the whole input with p->eof set, the EOF token is emitted. */
void shz_tokenize(shz_parser *p);
void shz_token_reset(token *t);
void shz_token_free(token *t);
/* Named/numeric character reference at s[0] == '&' within s[0..n). Returns the number of units consumed (0 = not a
 * reference: emit '&' literally), or (size_t)-1 when more input is needed. in_attr: attribute value rules. */
size_t shz_consume_charref(const shz_char *s, size_t n, int at_eof, int in_attr, shz_buf *out);

/* html_tree.c */
void shz_tree_init(shz_parser *p);
void shz_tree_free(shz_parser *p);
void shz_tree_token(shz_parser *p, token *t);
/* fragment parsing setup: context element given, stack = [html root], mode reset */
void shz_tree_setup_fragment(shz_parser *p);

#endif /* SHZ_HTML_INT_H */
