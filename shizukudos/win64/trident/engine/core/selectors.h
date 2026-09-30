/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - CSS selectors (core): parsing (Selectors Level 3 plus :not() with a selector list), specificity,
 * matching, serialization. Used by query_selector / matches and by the CSS cascade (L1).
 *
 * Supported: type and universal selectors (a namespace prefix "ns|" is accepted and ignored), #id, .class, [attr],
 * [attr=v], [attr~=v], [attr|=v], [attr^=v], [attr$=v], [attr*=v] (with the " i" flag), the combinators
 * descendant, >, +, ~, the pseudo-classes :first-child :last-child :only-child :first-of-type :last-of-type
 * :only-of-type :nth-child() :nth-last-child() :nth-of-type() :nth-last-of-type() :not() :hover :focus :active
 * :focus-within :link :visited :any-link :checked :disabled :enabled :empty :root :target :lang(), and the
 * pseudo-elements ::before ::after ::first-line ::first-letter (also with one colon). Class and id selectors match
 * ASCII case-insensitively in quirks mode; attribute values of the HTML legacy attribute list (type, align, ...)
 * match case-insensitively on HTML elements, as Selectors / HTML specify.
 */
#ifndef SHZ_SELECTORS_H
#define SHZ_SELECTORS_H

#include "dom.h"

typedef struct shz_selector_list shz_selector_list;

enum { SHZ_PSEUDO_NONE = 0, SHZ_PSEUDO_BEFORE, SHZ_PSEUDO_AFTER, SHZ_PSEUDO_FIRST_LINE, SHZ_PSEUDO_FIRST_LETTER };

/* Parse a selector list (s[0..n)). SHZ_E_SYNTAX for an invalid or unsupported selector. */
shz_res   shz_selector_parse(const shz_char *s, size_t n, shz_selector_list **out);
void      shz_selector_free(shz_selector_list *list);
size_t    shz_selector_count(const shz_selector_list *list);
/* specificity of complex selector i: (a << 16) | (b << 8) | c, each part saturating at 255 */
uint32_t  shz_selector_specificity(const shz_selector_list *list, size_t i);
int       shz_selector_pseudo_element(const shz_selector_list *list, size_t i);    /* SHZ_PSEUDO_* */
/* Does complex selector i match elem? The pseudo-element (if any) is ignored: the cascade asks whether the rule
 * applies to elem's pseudo-element box. */
int       shz_selector_match_one(const shz_selector_list *list, size_t i, shz_node *elem);
/* Does any selector of the list without a pseudo-element match elem (Element.matches, querySelector)? */
int       shz_selector_matches(const shz_selector_list *list, shz_node *elem);
/* Serialization of complex selector i / of the whole list (", " separated), allocated. */
shz_char *shz_selector_text(const shz_selector_list *list, size_t i);
shz_char *shz_selector_list_text(const shz_selector_list *list);

/* engine.h helpers: querySelector(All) below root (root excluded) in tree order. */
shz_res   shz_query_selector(shz_node *root, const shz_char *selector, shz_node **first);   /* SHZ_FALSE: none */
shz_res   shz_query_selector_all(shz_node *root, const shz_char *selector, shz_list **list);
shz_res   shz_element_matches(shz_node *elem, const shz_char *selector, int *result);

#endif /* SHZ_SELECTORS_H */
