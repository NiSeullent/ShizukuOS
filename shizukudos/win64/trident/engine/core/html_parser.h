/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - the HTML parser (core): input stream + charset (html_parser.c), HTML5 tokenizer
 * (html_tokenizer.c) and a simplified HTML5 tree builder (html_tree.c).
 *
 * Scripts: when the tree builder sees a parser-inserted </script>, it calls hooks->run_script(..., parser_inserted=1)
 * synchronously; parsing is paused until it returns. While it runs, document.write (shz_doc_write) inserts text at
 * the insertion point (right after the </script>) and parses it immediately, as HTML specifies.
 *
 * Lifecycle calls into the loader (loader.h, L2): shz_load_parser_started() when a load begins and
 * shz_load_parser_finished() after the end of the input was parsed (DOMContentLoaded time).
 */
#ifndef SHZ_HTML_PARSER_H
#define SHZ_HTML_PARSER_H

#include "dom.h"

/* ---- network loads (engine.h parser_begin / parser_feed / parser_end) */
/* Empties the document and starts a parser. charset: from the channel (NULL = sniff: BOM, <meta> prescan of the
 * first 1024 bytes, then UTF-8). */
shz_res shz_parser_begin(shz_doc *doc, const shz_char *charset);
shz_res shz_parser_feed(shz_doc *doc, const uint8_t *bytes, size_t n);
shz_res shz_parser_end(shz_doc *doc);
/* Replace the document with decoded markup (engine.h load_string): begin + feed + end without a decoder. */
shz_res shz_doc_load_string(shz_doc *doc, const shz_char *html, size_t n);

/* ---- document.open / write / close */
shz_res shz_doc_open(shz_doc *doc);
shz_res shz_doc_write(shz_doc *doc, const shz_char *text, size_t n, int newline);
shz_res shz_doc_close(shz_doc *doc);

/* ---- fragments and standalone documents */
/* HTML fragment parsing algorithm with context as the context element (a Document context parses a full document
 * into the fragment's children). Returns a DocumentFragment of context's document (refs = 1). Scripts in it are
 * marked "already started". No host notifications happen (the fragment is not connected). */
shz_res shz_parse_fragment(shz_node *context, const shz_char *html, size_t n, shz_node **fragment);
/* Parse a whole document (DOMParser / createHTMLDocument): mime "text/html" (default) or an XML type (simple XML
 * tree building: case preserved, self-closing honoured, no implied elements). The document has no hooks. */
shz_res shz_parse_document(const shz_char *src, size_t n, const shz_char *mime, shz_doc **out);

/* ---- state */
int     shz_parser_active(shz_doc *doc);             /* a parser is attached and has not reached the end */
int     shz_parser_in_title(shz_doc *doc);           /* the parser's current node is a <title> */
void    shz_parser_destroy(shz_doc *doc);            /* abort and free the parser (document close / reload) */

#endif /* SHZ_HTML_PARSER_H */
