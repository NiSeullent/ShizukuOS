#include "m98_glsl_frontend_port.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "main/consts_exts.h"
#include "compiler/glsl/glcpp/glcpp.h"
/* Host proof uses actual pthread mutexes. Native Win98 locks and runtime are
 * deliberately not replaced with no-op stubs. A native build is unsupported.
 */
union allocation_header { max_align_t alignment;
 struct { size_t bytes; uint32_t magic; } h; };
static pthread_mutex_t budget_lock=PTHREAD_MUTEX_INITIALIZER;
static size_t live_bytes, peak_bytes, limit_bytes=256u*1024u*1024u;
#define MAGIC 0x47393841u
static void exhausted(void) {
 fputs("M98_GLSL_OWNED_PROCESS_ALLOCATION_LIMIT\n",stderr);
 fflush(stderr); _Exit(86);
}
void *m98_glsl_alloc(size_t bytes) {
 union allocation_header *p;
 if(bytes>SIZE_MAX-sizeof(*p)) exhausted();
 pthread_mutex_lock(&budget_lock);
 if(bytes>limit_bytes-live_bytes) exhausted();
 p=(union allocation_header *)malloc(bytes+sizeof(*p));
 if(!p) exhausted();
 p->h.bytes=bytes; p->h.magic=MAGIC;
 live_bytes+=bytes; if(live_bytes>peak_bytes) peak_bytes=live_bytes;
 pthread_mutex_unlock(&budget_lock);
 return p+1;
}
void *m98_glsl_calloc(size_t n,size_t size) {
 void *p; if(size && n>SIZE_MAX/size) exhausted();
 p=m98_glsl_alloc(n*size); memset(p,0,n*size); return p;
}
void m98_glsl_free(void *pointer) {
 union allocation_header *p;
 if(!pointer) return;
 p=((union allocation_header *)pointer)-1;
 pthread_mutex_lock(&budget_lock);
 if(p->h.magic!=MAGIC || p->h.bytes>live_bytes) abort();
 live_bytes-=p->h.bytes; p->h.magic=0;
 pthread_mutex_unlock(&budget_lock); free(p);
}
void *m98_glsl_realloc(void *pointer,size_t bytes) {
 union allocation_header *p; void *out; size_t old;
 if(!pointer) return m98_glsl_alloc(bytes);
 if(!bytes) {m98_glsl_free(pointer);return NULL;}
 p=((union allocation_header *)pointer)-1;
 if(p->h.magic!=MAGIC) abort(); old=p->h.bytes;
 out=m98_glsl_alloc(bytes);
 memcpy(out,pointer,old<bytes?old:bytes);m98_glsl_free(pointer);return out;
}
int m98_glsl_budget_limit(size_t bytes) {
 int okay; pthread_mutex_lock(&budget_lock);
 okay=bytes>=live_bytes && bytes<=256u*1024u*1024u;
 if(okay) limit_bytes=bytes;
 pthread_mutex_unlock(&budget_lock);return okay;
}
size_t m98_glsl_budget_current(void) {
 size_t n;pthread_mutex_lock(&budget_lock);n=live_bytes;
 pthread_mutex_unlock(&budget_lock);return n;
}
size_t m98_glsl_budget_peak(void) {
 size_t n;pthread_mutex_lock(&budget_lock);n=peak_bytes;
 pthread_mutex_unlock(&budget_lock);return n;
}
int m98_glsl_port_preprocess(void *root,const char **source,char **log,
 struct _mesa_glsl_parse_state *state,glcpp_extension_iterator iterator,
 const struct gl_extensions *extensions,int api,int disable) {
 const struct gl_extensions empty={0};
 const struct m98_glsl_pp_config config={extensions?extensions:&empty,
  (gl_api)api,disable!=0,false};
 return glcpp_preprocess(root,source,log,iterator,state,&config);
}
