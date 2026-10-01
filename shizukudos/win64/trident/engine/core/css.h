/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - CSS: tokenizer/parser, style sheets, declaration blocks and the CSSOM entries of engine.h.
 * Owner: L1 (css_*.c). Declared here by core so the glue and the other modules compile against a fixed API.
 *
 * Sheets of a document, in tree order: every <style> element and every <link rel="stylesheet"> whose sheet loaded
 * (through shz_fetch_start, fetch.h). @import is fetched best-effort; @media applies for "screen" and "all" (and
 * lists containing them); other at-rules are dropped. The UA style sheet is not part of the list.
 *
 * Declaration blocks (shz_style == struct shzeng_style, defined by L1):
 *   - inline: the element's style="" attribute; reading parses the attribute, writing serializes back into it
 *     (shz_elem_set_attr, so observers see an attribute change);
 *   - computed: a read-only snapshot of resolved values (colors "rgb(r, g, b)", lengths "Npx");
 *   - rule: the declarations of a style rule of a sheet (sheet_rule_style); edits restyle the document.
 * Property names are CSS names ("background-color"); unknown properties and invalid values are ignored as CSS says
 * (the setters then return SHZ_OK without a change).
 */
#ifndef SHZ_CSS_H
#define SHZ_CSS_H

#include "dom.h"

/* ---- declaration blocks (engine.h style_*) */
shz_res   shz_css_inline_style(shz_node *elem, shz_style **out);                          /* new reference */
shz_res   shz_css_computed_style(shz_node *elem, const shz_char *pseudo, shz_style **out); /* pseudo NULL/"" or "::before" */
shz_res   shz_css_style_get(shz_style *style, const shz_char *property, shz_char **value); /* "" when unset */
shz_res   shz_css_style_get_priority(shz_style *style, const shz_char *property, shz_char **priority); /* "important" or "" */
shz_res   shz_css_style_set(shz_style *style, const shz_char *property, const shz_char *value, const shz_char *priority);
shz_res   shz_css_style_remove(shz_style *style, const shz_char *property);
shz_res   shz_css_style_text(shz_style *style, shz_char **text);                          /* cssText */
shz_res   shz_css_style_set_text(shz_style *style, const shz_char *text);
uint32_t  shz_css_style_length(shz_style *style);
shz_res   shz_css_style_item(shz_style *style, uint32_t index, shz_char **property);       /* SHZ_FALSE past the end */
void      shz_css_style_addref(shz_style *style);
void      shz_css_style_release(shz_style *style);

/* ---- style sheets (engine.h doc_sheet_* / sheet_*) */
uint32_t  shz_css_sheet_count(shz_doc *doc);
shz_res   shz_css_sheet_at(shz_doc *doc, uint32_t index, shz_sheet **out);               /* new reference */
uint32_t  shz_css_sheet_rule_count(shz_sheet *sheet);
shz_res   shz_css_sheet_rule_text(shz_sheet *sheet, uint32_t index, shz_char **text);   /* cssText of the rule */
/* style rules only (SHZ_FALSE for other rule kinds): selector text and the declaration block (new reference) */
shz_res   shz_css_sheet_rule_style(shz_sheet *sheet, uint32_t index, shz_char **selector, shz_style **style);
shz_res   shz_css_sheet_insert_rule(shz_sheet *sheet, const shz_char *rule, uint32_t index); /* SHZ_E_SYNTAX / INDEX_SIZE */
shz_res   shz_css_sheet_delete_rule(shz_sheet *sheet, uint32_t index);
shz_res   shz_css_sheet_href(shz_sheet *sheet, shz_char **href);                           /* SHZ_FALSE for <style> */
void      shz_css_sheet_addref(shz_sheet *sheet);
void      shz_css_sheet_release(shz_sheet *sheet);

/* ---- media queries (engine.h media_matches): "screen", "all", "print", with (min-|max-)width/height in px */
shz_res   shz_css_media_matches(shz_doc *doc, const shz_char *query, int *result);

#endif /* SHZ_CSS_H */
