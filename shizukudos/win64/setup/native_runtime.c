/* SPDX-License-Identifier: GPL-2.0-only */
#include "native_runtime.h"
#include "../../accounts/sha256.h"
#include <string.h>
struct hash {shz_native_runtime *owner;uint64_t bytes;sha256_ctx sha;};
static int call(shz_native_call_v1 *r){return shz_native_call(r)==0?0:-1;}
static int text(const char *p,size_t max,size_t *n)
{size_t i;if(!p)return -1;for(i=0;i<max;i++)if(!p[i]){if(!i)return -1;*n=i;return 0;}return -1;}
static shz_native_runtime_source *source(shz_native_runtime *v,void *h)
{unsigned i;for(i=0;i<2;i++)if(h==&v->source[i]&&v->source[i].live)return &v->source[i];return 0;}
static int source_check(void *ctx,void *h)
{
 shz_native_runtime *v=ctx;shz_native_runtime_source *s=source(v,h);shz_native_call_v1 r;
 if(!s||!s->admitted)return -1;
 shz_native_call_init(&r,SHZ_NATIVE_ADMIT);r.handle=s->token;r.index=s->role;
 return call(&r)||memcmp(&r.source,&s->identity,sizeof r.source)?-1:0;
}
static int source_open(void *ctx,const char *path,void **h,uint64_t *bytes)
{
 shz_native_runtime *v=ctx;shz_native_runtime_source *s;shz_native_call_v1 r;size_t n;
 if(!v->initialized||!h||!bytes||text(path,SHZ_NATIVE_SYS_PATH,&n))return -1;
 for(unsigned i=0;i<2;i++)if(v->source[i].live&&v->source[i].preview&&!strcmp(path,v->source[i].path)){
  s=&v->source[i];if(source_check(v,s))return -1;
  s->preview=0;*h=s;*bytes=s->identity.bytes;return 0;
 }
 if(v->opened>=2)return -1;
 s=&v->source[v->opened];shz_native_call_init(&r,SHZ_NATIVE_OPEN);memcpy(r.path,path,n+1);
 if(call(&r)||!r.handle||!r.source.bytes)return -1;
 s->token=r.handle;s->identity=r.source;s->role=v->opened;s->live=1;memcpy(s->path,path,n+1);
 v->opened++;*h=s;*bytes=s->identity.bytes;return 0;
}
static int source_admit(void *ctx,void *h,const char *path,uint64_t bytes,const uint8_t digest[32])
{
 shz_native_runtime *v=ctx;shz_native_runtime_source *s=source(v,h);shz_native_call_v1 r;size_t n;
 if(!s||!digest||text(path,SHZ_NATIVE_SYS_PATH,&n)||strcmp(path,s->path)||
 bytes!=s->identity.bytes||memcmp(digest,s->identity.sha256,32))return -1;
 if(s->admitted)return source_check(v,h);
 shz_native_call_init(&r,SHZ_NATIVE_ADMIT);r.handle=s->token;r.index=s->role;
 if(call(&r)||memcmp(&r.source,&s->identity,sizeof r.source))return -1;
 s->admitted=1;return source_check(v,h);
}
static int source_read(void *ctx,void *h,uint64_t off,void *buf,uint32_t n)
{
 shz_native_runtime *v=ctx;shz_native_runtime_source *s=source(v,h);uint8_t *out=buf;
 if(!s||(!buf&&n)||source_check(v,h)||off>s->identity.bytes||n>s->identity.bytes-off)return -1;
 while(n){shz_native_call_v1 r;uint32_t step=n>SHZ_NATIVE_SYS_IO_MAX?SHZ_NATIVE_SYS_IO_MAX:n;
  shz_native_call_init(&r,SHZ_NATIVE_READ);r.handle=s->token;r.offset=off;r.buffer=(uint64_t)(uintptr_t)out;r.length=step;
  if(call(&r))return -1;
  off+=step;out+=step;n-=step;
 }
 return source_check(v,h);
}
static int source_close(void *ctx,void *h)
{
 shz_native_runtime *v=ctx;shz_native_runtime_source *s=source(v,h);shz_native_call_v1 r;int rc;
 if(!s)return -1;
 shz_native_call_init(&r,SHZ_NATIVE_CLOSE);r.handle=s->token;rc=call(&r);
 /* Consumed in user provider even on failure. Actual kernel retains unresolved
  * custody for its process teardown; no guessed successful finalization. */
 memset(s,0,sizeof *s);return rc;
}
static void *sha_begin(void *ctx)
{
 shz_native_runtime *v=ctx;struct hash *h=v->original.alloc(v->original.ctx,sizeof *h);
 if(!h)return 0;
 memset(h,0,sizeof *h);h->owner=v;sha256_init(&h->sha);return h;
}
static int sha_update(void *ctx,void *handle,const void *buf,uint32_t n)
{
 struct hash *h=handle;
 if(!h||h->owner!=ctx||(!buf&&n)||h->bytes>UINT64_MAX/8-n)return -1;
 sha256_update(&h->sha,buf,n);h->bytes+=n;return 0;
}
static void sha_abort(void *ctx,void *handle)
{
 shz_native_runtime *v=ctx;struct hash *h=handle;
 if(h&&h->owner==v){memset(h,0,sizeof *h);v->original.free(v->original.ctx,h);}
}
static int sha_end(void *ctx,void *handle,uint8_t out[32])
{
 struct hash *h=handle;if(!h||h->owner!=ctx)return -1;
 if(!out){sha_abort(ctx,h);return -1;}sha256_final(&h->sha,out);sha_abort(ctx,h);return 0;
}
static int same(const native_setup_target_v1_t *a,const native_setup_target_v1_t *b)
{
 return a&&b&&a->index==b->index&&a->generation==b->generation&&!memcmp(a->whole_id,b->whole_id,16)&&
 a->disk.sectors==b->disk.sectors&&a->disk.sector_size==b->disk.sector_size&&a->disk.flags==b->disk.flags&&
 !memcmp(a->disk.name,b->disk.name,16)&&!memcmp(a->disk.serial,b->disk.serial,32);
}
static int review(void *ctx,unsigned index,void *const handles[2],native_setup_target_v1_t *out)
{
 shz_native_runtime *v=ctx;shz_native_runtime_source *a,*b;shz_native_call_v1 r;plat_disk_t disk;
 if(!handles||!out||v->claim.live||(a=source(v,handles[0]))==0||(b=source(v,handles[1]))==0||
 a==b||a->role!=0||b->role!=1||source_check(v,a)||source_check(v,b))return -1;
 shz_native_call_init(&r,SHZ_NATIVE_REVIEW);r.handle=a->token;r.other_handle=b->token;r.index=index;
 if(call(&r)||v->original.disk_info(v->original.ctx,index,&disk)||disk.flags||disk.sector_size!=r.target.sector_size||disk.sectors!=r.target.sectors)return -1;
 /* Name/serial are display labels from enumeration, never whole identity or
  * role authority. Actual claim uses only kernel-minted identity and geometry. */
 memset(out,0,sizeof *out);out->index=index;out->disk=disk;memcpy(out->whole_id,r.target.whole_id,16);out->generation=r.target.generation;
 v->claim.target=*out;v->claim.wire=r.target;return 0;
}
static int claim(void *ctx,const native_setup_target_v1_t *t,void *const handles[2],void **out)
{
 shz_native_runtime *v=ctx;shz_native_runtime_source *a,*b;shz_native_call_v1 r;
 if(!t||!handles||!out||v->claim.live||!same(t,&v->claim.target)||
 (a=source(v,handles[0]))==0||(b=source(v,handles[1]))==0||a==b||a->role!=0||b->role!=1||source_check(v,a)||source_check(v,b))return -1;
 *out=0;shz_native_call_init(&r,SHZ_NATIVE_CLAIM);r.handle=a->token;r.other_handle=b->token;r.index=t->index;r.target=v->claim.wire;
 if(call(&r)||!r.handle)return -1;
 v->claim.token=r.handle;v->claim.live=1;*out=&v->claim;return 0;
}
static int request(shz_native_runtime *v,void *held,const native_setup_target_v1_t *t,unsigned op,shz_native_call_v1 *r)
{
 if(held!=&v->claim||!v->claim.live||!same(t,&v->claim.target))return -1;
 shz_native_call_init(r,op);r->handle=v->claim.token;r->target=v->claim.wire;return 0;
}
static int check(void *ctx,void *held,const native_setup_target_v1_t *t)
{shz_native_runtime *v=ctx;shz_native_call_v1 r;return request(v,held,t,SHZ_NATIVE_CHECK,&r)||call(&r)?-1:0;}
static int release(void *ctx,void *held)
{
 shz_native_runtime *v=ctx;shz_native_call_v1 r;int rc;
 if(request(v,held,&v->claim.target,SHZ_NATIVE_RELEASE,&r))return -1;
 rc=call(&r);v->claim.live=0;v->claim.token=0;return rc;
}
static int target_info(void *ctx,void *held,const native_setup_target_v1_t *t,plat_disk_t *out)
{shz_native_runtime *v=ctx;if(!out||check(v,held,t))return -1;*out=v->claim.target.disk;return 0;}
static int target_io(void *ctx,void *held,const native_setup_target_v1_t *t,uint64_t lba,uint32_t n,void *buf,unsigned op)
{
 shz_native_runtime *v=ctx;shz_native_call_v1 r;
 if(!buf||!n||n>SHZ_NATIVE_SYS_IO_MAX/512||request(v,held,t,op,&r))return -1;
 r.offset=lba;r.length=n*512;r.buffer=(uint64_t)(uintptr_t)buf;return call(&r);
}
static int target_read(void *c,void *h,const native_setup_target_v1_t *t,uint64_t l,uint32_t n,void *b)
{return target_io(c,h,t,l,n,b,SHZ_NATIVE_TARGET_READ);}
static int target_write(void *c,void *h,const native_setup_target_v1_t *t,uint64_t l,uint32_t n,const void *b)
{return target_io(c,h,t,l,n,(void *)b,SHZ_NATIVE_TARGET_WRITE);}
static int target_flush(void *ctx,void *held,const native_setup_target_v1_t *t)
{shz_native_runtime *v=ctx;shz_native_call_v1 r;return request(v,held,t,SHZ_NATIVE_FLUSH,&r)||call(&r)?-1:0;}
static void *alloc(void *ctx,size_t n){shz_native_runtime *v=ctx;return v->original.alloc(v->original.ctx,n);}
static void dealloc(void *ctx,void *p){shz_native_runtime *v=ctx;v->original.free(v->original.ctx,p);}
static void output(void *ctx,const char *s){shz_native_runtime *v=ctx;if(v->original.out)v->original.out(v->original.ctx,s);}
static int platform_random(void *ctx,void *b,uint32_t n){shz_native_runtime *v=ctx;return v->original.random(v->original.ctx,b,n);}
static uint64_t now(void *ctx){shz_native_runtime *v=ctx;return v->original.now?v->original.now(v->original.ctx):0;}
static unsigned count(void *ctx){shz_native_runtime *v=ctx;return v->original.disk_count(v->original.ctx);}
static int info(void *ctx,unsigned index,plat_disk_t *out){shz_native_runtime *v=ctx;return v->original.disk_info(v->original.ctx,index,out);}
int shz_native_runtime_init(shz_native_runtime *v,const plat_t *base)
{
 shz_native_call_v1 caps;plat_t adapted;shz_native_provider_backend_v1_t backend;size_t i;
 if(!v||!base||!base->alloc||!base->free||!base->random||!base->disk_count||!base->disk_info)return -1;
 for(i=0;i<sizeof *v;i++)if(((const uint8_t *)v)[i])return -1;
 shz_native_call_init(&caps,SHZ_NATIVE_CAPS);
 if(call(&caps))return -1;
 if(caps.producer_admission_available!=1)return -2;
 if(caps.max_source_bytes!=SHZ_NATIVE_SYS_SOURCE_MAX||caps.max_io_bytes!=SHZ_NATIVE_SYS_IO_MAX)return -1;
 v->original=*base;memset(&adapted,0,sizeof adapted);memset(&backend,0,sizeof backend);
 adapted.ctx=v;adapted.out=output;adapted.alloc=alloc;adapted.free=dealloc;adapted.file_open=source_open;adapted.file_read=source_read;
 adapted.random=platform_random;adapted.now=now;adapted.disk_count=count;adapted.disk_info=info;adapted.max_io_sectors=SHZ_NATIVE_SYS_IO_MAX/512;
 backend.version=SHZ_NATIVE_PROVIDER_VERSION;backend.bytes=sizeof backend;backend.authority.version=NATIVE_SETUP_VERSION;backend.authority.bytes=sizeof backend.authority;
 backend.authority.ctx=v;backend.authority.admit_source=source_admit;backend.authority.check_source=source_check;backend.authority.close_source=source_close;
 backend.authority.sha_begin=sha_begin;backend.authority.sha_update=sha_update;backend.authority.sha_end=sha_end;backend.authority.sha_abort=sha_abort;
 backend.authority.review_target=review;backend.authority.claim_target=claim;backend.authority.check_target=check;backend.authority.release_target=release;
 backend.target_info=target_info;backend.target_read=target_read;backend.target_write=target_write;backend.target_flush=target_flush;
 if(shz_native_provider_init(&v->provider,&adapted,&backend)){memset(v,0,sizeof *v);return -1;}
 v->initialized=1;return 0;
}

int shz_native_runtime_preview_close(shz_native_runtime *v)
{
 int rc=0;if(!v||v->claim.live)return -1;
 for(unsigned i=0;i<2;i++)if(v->source[i].live&&source_close(v,&v->source[i]))rc=-1;
 return rc;
}
int shz_native_runtime_preview(shz_native_runtime *v,const char *manifest,const char *sim,uint8_t digest[32])
{
 const char *paths[2]={manifest,sim};shz_native_call_v1 pins[2];
 if(!v||!v->initialized||v->opened||!digest)return -1;
 for(unsigned i=0;i<2;i++){
  shz_native_call_init(&pins[i],SHZ_NATIVE_RELEASE_INFO);pins[i].index=i;
  if(call(&pins[i])||!pins[i].source.bytes||pins[i].source.bytes>SHZ_NATIVE_SYS_SOURCE_MAX)goto bad;
 }
 for(unsigned i=0;i<2;i++){
  void *h=0;uint64_t bytes=0;
  if(source_open(v,paths[i],&h,&bytes)||bytes!=pins[i].source.bytes||
     source_admit(v,h,paths[i],bytes,pins[i].source.sha256))goto bad;
  v->source[i].preview=1;
 }
 memcpy(digest,pins[0].source.sha256,32);return 0;
bad:
 shz_native_runtime_preview_close(v);return -1;
}
