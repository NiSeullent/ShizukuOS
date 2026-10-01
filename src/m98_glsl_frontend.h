#ifndef M98_GLSL_FRONTEND_H
#define M98_GLSL_FRONTEND_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Compiler-process interface only. No GL context, device or renderer exists.
 * Allocation exhaustion terminates the owned process; this is not an OOM-safe
 * in-process browser API. Callers must not publish output before successful exit.
 */
#define M98_GLSL_SOURCE_MAX (1024u * 1024u)
#define M98_GLSL_OUTPUT_MAX (8u * 1024u * 1024u)
enum m98_glsl_status { M98_GLSL_OK=0, M98_GLSL_ERROR=1,
 M98_GLSL_INVALID=2, M98_GLSL_UNSUPPORTED=3 };
struct m98_glsl_result {
 char *text;
 char *diagnostics;
 char *hir_summary;
 unsigned language_version, variables, functions, instructions;
 unsigned float_variables, uint_variables, arrays;
};
/* Results require an initially zero result, valid readable source extent and
 * single-owner release. Embedded NUL and over-limit input reject before work.
 * Preprocessing test mode preserves original desktop glcpp fixture policy.
 */
int m98_glsl_preprocess(const char *, size_t, int disable_line_continuations,
 struct m98_glsl_result *);
int m98_glsl_compile_es300(const char *, size_t, int fragment,
 struct m98_glsl_result *);
void m98_glsl_result_release(struct m98_glsl_result *);
#ifdef __cplusplus
}
#endif
#endif
