/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_CSS_MSHTML_VALUES_H
#define M98_CSS_MSHTML_VALUES_H
#include "m98_css_syntax.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Internal fixture consumer, not a full CSS property grammar. The table must
 * refer to the same genuine component that owns the live token stream. */
typedef struct {
 size_t (*count)(const m98_css_stream *);
 const m98_css_token *(*at)(const m98_css_stream *,size_t);
 const uint32_t *(*value)(const m98_css_stream *,const m98_css_token *);
 const uint32_t *(*number)(const m98_css_stream *,const m98_css_token *);
 int (*ascii)(const m98_css_stream *,size_t,const char *,int);
} m98_css_value_access;
/* Bounded integer px length (0..1024), or unitless zero. Other valid CSS length
 * forms return UNSUPPORTED; negative lengths return INVALID. No output mutation
 * on error. Caller separately implements cascade/defaulting and real styles. */
int m98_css_mshtml_width(const m98_css_value_access *,const m98_css_stream *,int *);
/* Three/six-digit sRGB hash color to canonical #rrggbb, exactly seven UTF16
 * units, no terminator. Broader color syntax is explicitly UNSUPPORTED. */
int m98_css_mshtml_color(const m98_css_value_access *,const m98_css_stream *,uint16_t [7]);
#ifdef __cplusplus
}
#endif
#endif
