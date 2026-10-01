/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - HTML named character references (core). The set is HTML 4.01's 252 entities, the legacy names
 * HTML accepts without a semicolon, apos, and a handful of common HTML5 names (ASCII punctuation, check, cross, star);
 * values are those of the WHATWG named character reference table.
 */
#ifndef SHZ_ENTITIES_H
#define SHZ_ENTITIES_H

#include "base.h"

/* Longest entity name that is a prefix of s[0..n) (s starts right after '&'). Returns the matched length (including a
 * ';' when the matched name has one) and the code point in *cp; 0 when nothing matches. *semicolon tells whether the
 * matched name ended with ';'. */
size_t shz_entity_match(const shz_char *s, size_t n, uint32_t *cp, int *semicolon);
/* Length of the longest name in the table (the tokenizer's lookahead bound). */
#define SHZ_ENTITY_MAX_LEN 10

#endif /* SHZ_ENTITIES_H */
