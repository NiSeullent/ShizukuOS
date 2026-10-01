#include "m98_glsl_frontend.h"
#include "m98_glsl_frontend_port.h"
#include <string.h>
#include "main/consts_exts.h"
#include "main/menums.h"
#include "util/ralloc.h"
#ifdef M98_GLSL_TYPED_ENABLED
#include "main/mtypes.h"
#include "pipe/p_screen.h"
#include "compiler/glsl/ast.h"
#include "compiler/glsl/glsl_parser_extras.h"
#include "compiler/glsl/builtin_functions.h"
#include "compiler/glsl/ir.h"
#include <pthread.h>
extern "C" int m98_mesa_frontend_parse(_mesa_glsl_parse_state *,const char **,ir_exec_list *);
/* Serialize compiler cache lifetime, while preserving actual Mesa cache locks.
 * These are compile-time resource limits; no driver/device caps are reported.
 */
static pthread_mutex_t compiler_lock=PTHREAD_MUTEX_INITIALIZER;
static void resources(gl_constants *c,gl_extensions *e,pipe_caps *caps) {
 memset(c,0,sizeof(*c));memset(e,0,sizeof(*e));memset(caps,0,sizeof(*caps));
 c->GLSLVersion=300;e->Version=30;e->dummy_true=true;
 c->Program[MESA_SHADER_VERTEX].MaxAttribs=16;
 c->Program[MESA_SHADER_VERTEX].MaxUniformComponents=1024;
 c->Program[MESA_SHADER_VERTEX].MaxTextureImageUnits=16;
 c->Program[MESA_SHADER_VERTEX].MaxOutputComponents=64;
 c->Program[MESA_SHADER_FRAGMENT].MaxUniformComponents=896;
 c->Program[MESA_SHADER_FRAGMENT].MaxTextureImageUnits=16;
 c->Program[MESA_SHADER_FRAGMENT].MaxInputComponents=60;
 c->MaxCombinedTextureImageUnits=32;c->MaxDrawBuffers=4;
 c->MinProgramTexelOffset=-8;c->MaxProgramTexelOffset=7;
 c->MaxTransformFeedbackBuffers=4;c->MaxTransformFeedbackInterleavedComponents=64;
}
#endif
static bool valid(const char *s,size_t n,m98_glsl_result *out) {
 return s && out && n<=M98_GLSL_SOURCE_MAX && !memchr(s,0,n)
  && !out->text && !out->diagnostics && !out->hir_summary && !out->language_version
  && !out->variables && !out->functions && !out->instructions
  && !out->float_variables && !out->uint_variables && !out->arrays;
}
static char *copy(const char *s,size_t max) {
 size_t n=strlen(s);if(n>max) return NULL;
 char *p=(char *)m98_glsl_alloc(n+1);memcpy(p,s,n+1);return p;
}
extern "C" void m98_glsl_result_release(m98_glsl_result *out) {
 if(!out) return;m98_glsl_free(out->text);m98_glsl_free(out->diagnostics);
 m98_glsl_free(out->hir_summary);
 memset(out,0,sizeof(*out));
}
extern "C" int m98_glsl_preprocess(const char *s,size_t n,int disable,
 m98_glsl_result *out) {
 if(!valid(s,n,out) || (disable!=0 && disable!=1)) return M98_GLSL_INVALID;
 void *root=ralloc_context(NULL);char *input=(char *)ralloc_size(root,n+1);
 memcpy(input,s,n);input[n]=0;const char *text=input;
 char *log=ralloc_strdup(root,"");
 int error=m98_glsl_port_preprocess(root,&text,&log,NULL,NULL,NULL,API_OPENGL_COMPAT,disable);
 m98_glsl_result next={};next.text=copy(text,M98_GLSL_OUTPUT_MAX);
 next.diagnostics=copy(log,M98_GLSL_SOURCE_MAX);ralloc_free(root);
 if(!next.text || !next.diagnostics) {
  m98_glsl_result_release(&next);return M98_GLSL_INVALID;
 }
 *out=next;return error?M98_GLSL_ERROR:M98_GLSL_OK;
}
extern "C" int m98_glsl_compile_es300(const char *s,size_t n,int fragment,
 m98_glsl_result *out) {
 if(!valid(s,n,out) || (fragment!=0 && fragment!=1))return M98_GLSL_INVALID;
#ifndef M98_GLSL_TYPED_ENABLED
 return M98_GLSL_UNSUPPORTED;
#else
 pthread_mutex_lock(&compiler_lock);
 glsl_type_singleton_init_or_ref();_mesa_glsl_builtin_functions_init_or_ref();
 gl_constants c;gl_extensions e;pipe_caps caps;resources(&c,&e,&caps);
 void *root=ralloc_context(NULL);char *input=(char *)ralloc_size(root,n+1);
 memcpy(input,s,n);input[n]=0;const char *text=input;
 _mesa_glsl_parse_state *state=new(root) _mesa_glsl_parse_state(&c,&e,&caps,
  API_OPENGLES2,fragment?MESA_SHADER_FRAGMENT:MESA_SHADER_VERTEX,root);
 ir_exec_list *hir=new(root) ir_exec_list;
 int error=m98_mesa_frontend_parse(state,&text,hir);
 if(!error && (!state->es_shader || state->language_version!=300)) {
  YYLTYPE location={};_mesa_glsl_error(&location,state,"compiler-only profile requires GLSL ES 3.00");error=1;
 }
 m98_glsl_result next={};next.language_version=state->language_version;
 next.diagnostics=copy(state->info_log,M98_GLSL_SOURCE_MAX);
 if(!error) {
  char *summary=ralloc_strdup(root,"");
  ir_foreach_in_list(ir_instruction,instruction,hir) {
   next.instructions++;
   ir_variable *v=instruction->as_variable();
   if(v) {
    next.variables++;next.float_variables+=glsl_type_is_float(v->type);
    next.uint_variables+=glsl_get_base_type(v->type)==GLSL_TYPE_UINT;
    next.arrays+=glsl_type_is_array(v->type);
    unsigned bits=0;
    if(v->constant_value && glsl_type_is_scalar(v->type)) {
     if(glsl_type_is_float(v->type))memcpy(&bits,&v->constant_value->value.f[0],4);
     else if(glsl_get_base_type(v->type)==GLSL_TYPE_UINT)bits=v->constant_value->value.u[0];
    }
    ralloc_asprintf_append(&summary,"%s:%s:%u:%u:%u:%08x\n",v->name,
     glsl_get_type_name(v->type),v->data.precision,
     glsl_type_is_array(v->type)?glsl_get_length(v->type):0,
     v->constant_value!=NULL,bits);
   }
   if(instruction->as_function()) next.functions++;
  }
  next.hir_summary=copy(summary,M98_GLSL_OUTPUT_MAX);
 }
 ralloc_free(root);_mesa_glsl_builtin_functions_decref();glsl_type_singleton_decref();
 pthread_mutex_unlock(&compiler_lock);
 if(!next.diagnostics || (!error && !next.hir_summary)) {
  m98_glsl_result_release(&next);return M98_GLSL_INVALID;
 }
 *out=next;return error?M98_GLSL_ERROR:M98_GLSL_OK;
#endif
}
