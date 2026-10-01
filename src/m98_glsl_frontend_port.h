#ifndef M98_GLSL_FRONTEND_PORT_H
#define M98_GLSL_FRONTEND_PORT_H
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif
void *m98_glsl_alloc(size_t);
void *m98_glsl_calloc(size_t,size_t);
void *m98_glsl_realloc(void *,size_t);
void m98_glsl_free(void *);
int m98_glsl_budget_limit(size_t);
size_t m98_glsl_budget_current(void);
size_t m98_glsl_budget_peak(void);
struct _mesa_glsl_parse_state;
struct glcpp_parser;
struct gl_extensions;
int m98_glsl_port_preprocess(void *,const char **,char **,
 struct _mesa_glsl_parse_state *,
 void (*)(struct _mesa_glsl_parse_state *,
          void (*)(struct glcpp_parser *,const char *,int),
          struct glcpp_parser *,unsigned,bool),
 const struct gl_extensions *,int api,int disable_line_continuations);
#ifdef __cplusplus
}
#endif
#ifdef M98_GLSL_TRACK_ALLOC
#define malloc(s) m98_glsl_alloc(s)
#define calloc(n,s) m98_glsl_calloc(n,s)
#define realloc(p,s) m98_glsl_realloc(p,s)
#define free(p) m98_glsl_free(p)
#endif
#endif
