/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_CSS_SYNTAX_H
#define M98_CSS_SYNTAX_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum { M98_CSS_OK=0, M98_CSS_ARGUMENT=1, M98_CSS_MEMORY=2,
       M98_CSS_LIMIT=3, M98_CSS_UNSUPPORTED=4, M98_CSS_INVALID=5 };
enum m98_css_kind { M98_CSS_WS=1, M98_CSS_IDENT, M98_CSS_FUNCTION,
 M98_CSS_AT, M98_CSS_HASH, M98_CSS_STRING, M98_CSS_BAD_STRING,
 M98_CSS_URL, M98_CSS_BAD_URL, M98_CSS_NUMBER, M98_CSS_PERCENTAGE,
 M98_CSS_DIMENSION, M98_CSS_CDO, M98_CSS_CDC, M98_CSS_COLON,
 M98_CSS_SEMICOLON, M98_CSS_COMMA, M98_CSS_LPAREN, M98_CSS_RPAREN,
 M98_CSS_LBRACKET, M98_CSS_RBRACKET, M98_CSS_LBRACE, M98_CSS_RBRACE,
 M98_CSS_DELIM };
enum { M98_CSS_INTEGER=1, M98_CSS_HASH_ID=2,
 M98_CSS_INPUT_MAX=32768, M98_CSS_TOKEN_MAX=4096,
 M98_CSS_POOL_MAX=131072, M98_CSS_DEPTH_MAX=64 };
typedef struct { void *user; void *(*alloc)(void *,size_t);
 void (*free)(void *,void *); } m98_css_allocator;
typedef struct { uint32_t kind, flags, delim, value_offset, value_length,
 number_offset, number_length; } m98_css_token;
typedef struct m98_css_stream m98_css_stream;
/* All calls are serialized by the caller. Output pointers are unchanged on
 * error. Allocations belong to the supplied allocator; it must outlive streams.
 * Only genuine, live streams are accepted. A token passed to value/number must
 * be a live view from at() on that same stream (not another stream/copy).
 * No raw external token mutation.
 * Numeric tokens carry exact decimal representation/type, not rounded doubles.
 * Token count excludes EOF. Parse errors are recovered tokens, not API errors. */
int m98_css_tokenize(const uint16_t *,size_t,const m98_css_allocator *,m98_css_stream **);
void m98_css_destroy(m98_css_stream **);
size_t m98_css_count(const m98_css_stream *);
const m98_css_token *m98_css_at(const m98_css_stream *,size_t);
const uint32_t *m98_css_value(const m98_css_stream *,const m98_css_token *);
const uint32_t *m98_css_number(const m98_css_stream *,const m98_css_token *);
uint32_t m98_css_errors(const m98_css_stream *);
uint32_t m98_css_replacements(const m98_css_stream *);
/* Token-preserving UTF16 serialization, not CSSOM original-author serialization.
 * Query with NULL/0 obtains required units (no NUL). Capacity failure writes
 * nothing and reports required units. Bad tokens are explicitly unsupported. */
int m98_css_serialize(const m98_css_stream *,uint16_t *,size_t,size_t *);
int m98_css_ascii(const m98_css_stream *,size_t,const char *,int);
/* Builder helpers for the disjoint variables core. Source and destination must
 * differ; append is transactional in token contents/count but may invalidate
 * borrowed array views even on an allocation failure. literal() only creates
 * closing )/]/} tokens for EOF component recovery, with delim=0. */
int m98_css_empty(const m98_css_allocator *,m98_css_stream **);
int m98_css_append(m98_css_stream *,const m98_css_stream *,size_t);
int m98_css_literal(m98_css_stream *,uint32_t,uint32_t);
#ifdef __cplusplus
}
#endif
#endif
