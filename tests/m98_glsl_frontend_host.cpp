#include "m98_glsl_frontend.h"
#include "m98_glsl_frontend_port.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <locale.h>
static unsigned checks;
static void check(bool okay,const char *name) {
 checks++;if(!okay) {fprintf(stderr,"FAIL:%s\n",name);exit(2);}
}
static int preprocess_stdin(int disable) {
 char *input=(char *)m98_glsl_alloc(M98_GLSL_SOURCE_MAX+1);
 size_t n=fread(input,1,M98_GLSL_SOURCE_MAX+1,stdin);
 m98_glsl_result r={};int status=m98_glsl_preprocess(input,n,disable,&r);
 if(status!=M98_GLSL_OK && status!=M98_GLSL_ERROR) {
  m98_glsl_free(input);return 2;
 }
 fputs(r.diagnostics,stderr);fflush(stderr);fputs(r.text,stdout);fflush(stdout);
 m98_glsl_result_release(&r);m98_glsl_free(input);
 if(m98_glsl_budget_current()) return 2;
 return status==M98_GLSL_ERROR?1:0;
}
static void semantic(const char *body,int fragment,bool okay,const char *diagnostic) {
 char shader[4096];snprintf(shader,sizeof(shader),"#version 300 es\n%s",body);
 m98_glsl_result r={};int status=m98_glsl_compile_es300(shader,strlen(shader),fragment,&r);
 check(status==(okay?M98_GLSL_OK:M98_GLSL_ERROR),body);
 check(r.diagnostics!=NULL,"original diagnostic buffer");
 if(okay) {
  check(r.language_version==300 && r.functions>=1 && r.instructions>=1,"real typed HIR");
  check(!strstr(r.diagnostics,"error:"),"valid original diagnostics");
 } else check(strstr(r.diagnostics,diagnostic)!=NULL,"literal semantic diagnostic");
 m98_glsl_result_release(&r);check(!m98_glsl_budget_current(),"cache and root cleanup");
}
int main(int argc,char **argv) {
 if(argc==2 && !strcmp(argv[1],"--asan-control")) {
  volatile unsigned char *p=(unsigned char *)m98_glsl_alloc(16);
  m98_glsl_free((void *)p);return p[0];
 }
 if(argc==2 && !strcmp(argv[1],"--ubsan-control")) {
  volatile int maximum=2147483647;
  volatile int overflowing=maximum+1;return overflowing;
 }
 if(argc>=2 && !strcmp(argv[1],"--preprocess")) {
  int disable=0;
  if(argc==3 && !strcmp(argv[2],"--disable-line-continuations"))disable=1;
  else if(argc!=2)return 2;
  return preprocess_stdin(disable);
 }
 if(argc==2 && !strcmp(argv[1],"--allocation-limit")) {
  if(!m98_glsl_budget_limit(32))return 2;
  (void)m98_glsl_alloc(33);return 2;
 }
 m98_glsl_result r={};
 check(m98_glsl_preprocess(NULL,0,0,&r)==M98_GLSL_INVALID,"null input");
 check(m98_glsl_preprocess("x",M98_GLSL_SOURCE_MAX+1,0,&r)==M98_GLSL_INVALID,"declared source limit before read");
 check(m98_glsl_preprocess("x\0y",3,0,&r)==M98_GLSL_INVALID,"embedded NUL");
 check(m98_glsl_preprocess("x",1,2,&r)==M98_GLSL_INVALID,"policy bounds");
 const char *pp="#define SUM(a,b) ((a)+(b))\nSUM(2,3)\n";
 check(m98_glsl_preprocess(pp,strlen(pp),0,&r)==M98_GLSL_OK,"actual macro parser");
 check(strstr(r.text,"((2)+(3))")!=NULL,"literal expansion");
 m98_glsl_result_release(&r);check(!m98_glsl_budget_current(),"preprocessor cleanup");
#ifdef M98_GLSL_TYPED_ENABLED
 const char *typed="#version 300 es\nprecision highp float; const highp float m98_literal=0.1; const highp uint m98_uint=4294967295u; uniform highp vec4 m98_vector; highp float m98_array[3]; out vec4 color; void main(){color=vec4(m98_literal);}";
 check(m98_glsl_compile_es300(typed,strlen(typed),1,&r)==M98_GLSL_OK,"literal type/value compiler");
 check(strstr(r.hir_summary,"m98_literal:float:1:0:1:3dcccccd\n")!=NULL,"independent rounded float bits");
 check(strstr(r.hir_summary,"m98_uint:uint:1:0:1:ffffffff\n")!=NULL,"independent uint maximum bits");
 check(strstr(r.hir_summary,"m98_vector:vec4:1:0:0:00000000\n")!=NULL,"actual highp vec4 uniform type");
 check(strstr(r.hir_summary,"m98_array:float[3]:1:3:0:00000000\n")!=NULL,"actual array length/type");
 m98_glsl_result_release(&r);check(!m98_glsl_budget_current(),"literal HIR lifetime");
 semantic("precision highp float; out vec4 color; void main(){color=vec4(1.0);}",1,true,"");
 semantic("in vec4 position; void main(){gl_Position=position;}",0,true,"");
 semantic("precision mediump float; out vec4 color; float f(float x){return x;} float f(vec2 x){return x.x;} void main(){color=vec4(f(vec2(0.5)));}",1,true,"");
 semantic("precision highp float; out vec4 color; void main(){uint x=1u; x=(x<<2u)|3u; color=vec4(float(x));}",1,true,"");
 semantic("precision highp float; out vec4 color; void main(){float a[2]; a[0]=1.0; a[1]=2.0; color=vec4(a[1]);}",1,true,"");
 semantic("precision highp float; out vec4 color; void main(){float x=1.0; {float x=2.0;} color=vec4(x);}",1,true,"");
 semantic("precision highp float; layout(location=0) out vec4 color; void main(){color=vec4(sqrt(4.0));}",1,true,"");
 semantic("precision highp float; out vec4 color; void main(){color=vec4(1.0) }",1,false,"syntax error");
 semantic("precision highp float; out vec4 color; void main(){float x=vec2(1.0);color=vec4(x);}",1,false,"initializer");
 semantic("out vec4 color; void main(){color=vec4(1.0);}",1,false,"precision");
 semantic("precision highp float; out vec4 color; void main(){color=vec4(missing);}",1,false,"undeclared");
 semantic("precision highp float; out vec4 color; void main(){const float x=1.0; x=2.0;color=vec4(x);}",1,false,"read-only");
 semantic("precision highp float; out vec4 color; void main(){float a[0];color=vec4(1.0);}",1,false,"array");
 semantic("precision highp float; uniform float x; out vec4 color; void main(){x=1.0;color=vec4(x);}",1,false,"read-only");
 semantic("precision highp float; out vec4 color; void main(){color=vec4(sqrt(true));}",1,false,"matching function");
 const char *version="#version 310 es\nprecision highp float; void main(){}";
 check(m98_glsl_compile_es300(version,strlen(version),1,&r)==M98_GLSL_ERROR,"later version rejection");
 check(strstr(r.diagnostics,"not supported")!=NULL,"original version diagnostic");m98_glsl_result_release(&r);
#else
 check(m98_glsl_compile_es300("x",1,1,&r)==M98_GLSL_UNSUPPORTED,"unbuilt typed path rejects");
#endif
 check(!m98_glsl_budget_current(),"zero process-owned allocation at exit");
 printf("M98_GLSL_HOST_CHECKS=%u\n",checks);return 0;
}
