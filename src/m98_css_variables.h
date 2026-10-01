/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_CSS_VARIABLES_H
#define M98_CSS_VARIABLES_H
#include "m98_css_syntax.h"
#ifdef __cplusplus
extern "C" {
#endif
enum { M98_CSS_PROPERTY_MAX=64 };
typedef struct { const uint16_t *name,*value; size_t name_units,value_units; } m98_css_declaration;
typedef struct m98_css_snapshot m98_css_snapshot;
/* Input is an already-cascaded, unique winning declaration map. Callers remove
 * !important and perform selector/origin/layer priority before this API.
 * Syntax-invalid declarations are rejected transactionally (not a CSS cascade).
 * Parent is a computed snapshot, deep copied. CSS-wide initial/inherit/unset act
 * as specified both before and after substitution. revert/revert-layer/revert-rule
 * need cascade and are unsupported. Early spread syntax in var() is unsupported.
 * Current-draft var() short circuits unused fallbacks and supports var() within
 * the first argument. Structural argument declaration-value grammar is checked
 * on every specified var(), including nested references in unused fallbacks,
 * without creating cycle edges; malformed source returns INVALID. Only var()
 * substitution is implemented; attr/env/
 * if/ident/random-item/dashed custom functions and other named arbitrary
 * substitutions listed in HANDOFF are explicitly unsupported.
 * Invalid-at-computed-time is a per-property invalid flag, not an API failure.
 * Resource errors leave output unchanged. No registered/animation-tainted props.
 */
int m98_css_compute(const m98_css_declaration *,size_t,const m98_css_snapshot *,
                    const m98_css_allocator *,m98_css_snapshot **);
void m98_css_snapshot_destroy(m98_css_snapshot **);
size_t m98_css_property_count(const m98_css_snapshot *);
/* Borrowed immutable tokens stay live only until snapshot teardown. Missing
 * properties are valid queries with invalid=1 and tokens=NULL. */
int m98_css_lookup(const m98_css_snapshot *,const uint16_t *,size_t,
                   const m98_css_stream **,int *invalid);
/* Substitute var() into a declaration value using computed properties. Caller
 * handles the actual property grammar/layout. On computed invalid, *invalid=1
 * and *tokens=NULL; on API failure both outputs are unchanged. */
int m98_css_substitute(const m98_css_snapshot *,const uint16_t *,size_t,
                      m98_css_stream **,int *invalid);
#ifdef __cplusplus
}
#endif
#endif
