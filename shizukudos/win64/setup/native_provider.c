/* SPDX-License-Identifier: GPL-2.0-only */
#include "native_provider.h"
#include "native_fat32_relocate.h"
#include <string.h>

static int span(const void *p, size_t n)
{ return p && n && (uintptr_t)p <= UINTPTR_MAX - (n - 1); }
static int overlaps(const void *a, size_t an, const void *b, size_t bn)
{ return (uintptr_t)a <= (uintptr_t)b + bn - 1 && (uintptr_t)b <= (uintptr_t)a + an - 1; }
int shz_native_provider_relocation(void *ctx, const uint8_t a[512], const uint8_t b[512],
    const uint8_t f[512], const uint8_t g[512], uint64_t bytes, uint64_t first,
    uint64_t last, native_setup_overlay_v1_t out[2])
{
    shz_native_fat32_relocate_t plan;
    native_setup_overlay_v1_t staged[2];
    const uint8_t *inputs[4] = {a,b,f,g};
    unsigned i;
    (void)ctx;
    if (!span(out, sizeof staged)) return -1;
    for (i=0;i<4;i++)
        if (!span(inputs[i],512) || overlaps(out,sizeof staged,inputs[i],512)) return -1;
    if (shz_native_fat32_relocate_stage(a,512,b,512,f,512,g,512,0,bytes,first,last,
                                      &plan,sizeof plan)) return -1;
    memset(staged,0,sizeof staged);
    staged[0].offset=28; staged[1].offset=plan.backup_boot_offset+28;
    memcpy(staged[0].original,a+28,4); memcpy(staged[1].original,b+28,4);
    memcpy(staged[0].replacement,plan.primary+28,4);
    memcpy(staged[1].replacement,plan.backup+28,4);
    memcpy(out,staged,sizeof staged);
    return 0;
}
static int slot(shz_native_provider_t *v, void *h)
{
    unsigned i;
    if (!h) return -1;
    for(i=0;i<2;i++) if(v->source[i]==h) return (int)i;
    return -1;
}
static int source_check(void *ctx,void *h)
{
    shz_native_provider_t *v=ctx; int i=slot(v,h);
    return i<0 || !v->admitted[i] ? -1 : v->backend.authority.check_source(v->backend.authority.ctx,h);
}
static int open_file(void *ctx,const char *path,void **h,uint64_t *bytes)
{
    shz_native_provider_t *v=ctx; void *opened=0; uint64_t size=0; int rc;
    if(!v->started || v->opened>=2 || !h || !bytes) return -1;
    rc=v->base.file_open(v->base.ctx,path,&opened,&size);
    if(opened) {
        if(slot(v,opened)>=0) return -1; /* duplicate handle cannot be consumed twice */
        v->source[v->opened++]=opened; *h=opened; *bytes=size;
    }
    return rc || !opened ? -1 : 0;
}
static int admit(void *ctx,void *h,const char *path,uint64_t bytes,const uint8_t digest[32])
{
    shz_native_provider_t *v=ctx; int i=slot(v,h);
    if(i<0 || v->admitted[i]) return -1;
    if(v->backend.authority.admit_source(v->backend.authority.ctx,h,path,bytes,digest)) return -1;
    v->admitted[i]=1;
    return source_check(v,h);
}
static int read_file(void *ctx,void *h,uint64_t off,void *buf,uint32_t n)
{
    shz_native_provider_t *v=ctx;
    if(source_check(v,h) || v->base.file_read(v->base.ctx,h,off,buf,n) || source_check(v,h)) return -1;
    return 0;
}
static int close_file(void *ctx,void *h)
{
    shz_native_provider_t *v=ctx; int i=slot(v,h), rc;
    if(i<0) return -1;
    /* Mandatory consume even after failed admission/check; backend owns any
     * unresolved underlying operation. Legacy void file_close is never used. */
    rc=v->backend.authority.close_source(v->backend.authority.ctx,h);
    v->source[i]=0; v->admitted[i]=0;
    return rc;
}
static int source_pair(shz_native_provider_t *v,void *const s[2])
{
    return !s || s[0]==s[1] || slot(v,s[0])<0 || slot(v,s[1])<0 ||
           source_check(v,s[0]) || source_check(v,s[1]);
}
static int review(void *ctx,unsigned index,void *const s[2],native_setup_target_v1_t *target)
{
    shz_native_provider_t *v=ctx;
    if(!target || v->claim_attempted || source_pair(v,s)) return -1;
    return v->backend.authority.review_target(v->backend.authority.ctx,index,s,target);
}
static int claim_target(void *ctx,const native_setup_target_v1_t *t,void *const s[2],void **claim)
{
    shz_native_provider_t *v=ctx; void *held=0; int rc;
    if(!t || !claim || v->claim_attempted || source_pair(v,s)) return -1;
    v->claim_attempted=1; v->target=*t;
    rc=v->backend.authority.claim_target(v->backend.authority.ctx,t,s,&held);
    /* A failed acquisition may already own resources. Expose its nonNULL
     * handle to the core's mandatory finalization, never discard it. */
    v->claim=held; *claim=held;
    return rc || !held ? -1 : 0;
}
static int same_target(const native_setup_target_v1_t *a,const native_setup_target_v1_t *b)
{
    return a && b && a->index==b->index && a->generation==b->generation &&
      !memcmp(a->whole_id,b->whole_id,16) && !memcmp(a->disk.name,b->disk.name,16) &&
      !memcmp(a->disk.serial,b->disk.serial,32) && a->disk.sectors==b->disk.sectors &&
      a->disk.sector_size==b->disk.sector_size && a->disk.flags==b->disk.flags;
}
static int check_target(void *ctx,void *claim,const native_setup_target_v1_t *target)
{
    shz_native_provider_t *v=ctx;
    if(!claim || claim!=v->claim || !same_target(target,&v->target)) return -1;
    return v->backend.authority.check_target(v->backend.authority.ctx,claim,target);
}
static int release(void *ctx,void *claim)
{
    shz_native_provider_t *v=ctx; int rc;
    if(!claim || claim!=v->claim) return -1;
    rc=v->backend.authority.release_target(v->backend.authority.ctx,claim);
    v->claim=0;
    return rc;
}
static int io_valid(shz_native_provider_t *v,unsigned index,uint64_t lba,uint32_t n,const void *buf)
{
    return !v->started || v->io_failed || !v->claim || index!=v->target.index || !n ||
      n>v->platform.max_io_sectors || !span(buf,(size_t)n*512) ||
      lba>=v->target.disk.sectors || n>v->target.disk.sectors-lba;
}
static int disk_read(void *ctx,unsigned index,uint64_t lba,uint32_t n,void *buf)
{
    shz_native_provider_t *v=ctx;
    if(io_valid(v,index,lba,n,buf)) return -1;
    if(v->backend.target_read(v->backend.authority.ctx,v->claim,&v->target,lba,n,buf)) { v->io_failed=1; return -1; }
    return 0;
}
static int disk_write(void *ctx,unsigned index,uint64_t lba,uint32_t n,const void *buf)
{
    shz_native_provider_t *v=ctx;
    if(io_valid(v,index,lba,n,buf)) return -1;
    if(v->backend.target_write(v->backend.authority.ctx,v->claim,&v->target,lba,n,buf)) { v->io_failed=1; return -1; }
    return 0;
}
static int disk_flush(void *ctx,unsigned index)
{
    shz_native_provider_t *v=ctx;
    if(!v->started || v->io_failed || !v->claim || index!=v->target.index) return -1;
    if(v->backend.target_flush(v->backend.authority.ctx,v->claim,&v->target)) { v->io_failed=1; return -1; }
    return 0;
}
static int disk_info(void *ctx,unsigned index,plat_disk_t *out)
{
    shz_native_provider_t *v=ctx;
    if(!out || !v->started) return -1;
    if(!v->claim) return v->claim_attempted ? -1 : v->base.disk_info(v->base.ctx,index,out);
    if(index!=v->target.index) return -1;
    return v->backend.target_info(v->backend.authority.ctx,v->claim,&v->target,out);
}
static unsigned disk_count(void *ctx){shz_native_provider_t *v=ctx;return v->base.disk_count(v->base.ctx);}
static void out_text(void *ctx,const char *s){shz_native_provider_t *v=ctx;if(v->base.out)v->base.out(v->base.ctx,s);}
static void *alloc(void *ctx,size_t n){shz_native_provider_t *v=ctx;return v->base.alloc(v->base.ctx,n);}
static void dealloc(void *ctx,void *p){shz_native_provider_t *v=ctx;v->base.free(v->base.ctx,p);}
static int random_bytes(void *ctx,void *b,uint32_t n){shz_native_provider_t *v=ctx;return v->base.random(v->base.ctx,b,n);}
static uint64_t now(void *ctx){shz_native_provider_t *v=ctx;return v->base.now?v->base.now(v->base.ctx):0;}
static void *sha_begin(void *ctx){shz_native_provider_t *v=ctx;return v->backend.authority.sha_begin(v->backend.authority.ctx);}
static int sha_update(void *ctx,void *h,const void *b,uint32_t n){shz_native_provider_t *v=ctx;return v->backend.authority.sha_update(v->backend.authority.ctx,h,b,n);}
static int sha_end(void *ctx,void *h,uint8_t b[32]){shz_native_provider_t *v=ctx;return v->backend.authority.sha_end(v->backend.authority.ctx,h,b);}
static void sha_abort(void *ctx,void *h){shz_native_provider_t *v=ctx;v->backend.authority.sha_abort(v->backend.authority.ctx,h);}
int shz_native_provider_init(shz_native_provider_t *v,const plat_t *base,const shz_native_provider_backend_v1_t *backend)
{
    const native_setup_ops_v1_t *a;
    shz_native_provider_t staged;
    size_t i;
    if(!span(v,sizeof *v) || !span(base,sizeof *base) || !span(backend,sizeof *backend) ||
       overlaps(v,sizeof *v,base,sizeof *base) || overlaps(v,sizeof *v,backend,sizeof *backend)) return -1;
    for(i=0;i<sizeof *v;i++) if(((const uint8_t *)v)[i]) return -1;
    a=&backend->authority;
    if(backend->version!=SHZ_NATIVE_PROVIDER_VERSION || backend->bytes!=sizeof *backend ||
       a->version!=NATIVE_SETUP_VERSION || a->bytes!=sizeof *a ||
       !a->admit_source || !a->check_source || !a->close_source || !a->sha_begin || !a->sha_update ||
       !a->sha_end || !a->sha_abort || !a->review_target || !a->claim_target || !a->check_target || !a->release_target ||
       !backend->target_info || !backend->target_read || !backend->target_write || !backend->target_flush ||
       !base->alloc || !base->free || !base->file_open || !base->file_read || !base->random ||
       !base->disk_count || !base->disk_info || !base->max_io_sectors || base->max_io_sectors>2048) return -1;
    memset(&staged,0,sizeof staged); staged.base=*base; staged.backend=*backend;
    staged.platform.ctx=v; staged.platform.out=out_text; staged.platform.alloc=alloc; staged.platform.free=dealloc;
    staged.platform.file_open=open_file; staged.platform.file_read=read_file; staged.platform.random=random_bytes;
    staged.platform.now=now; staged.platform.disk_count=disk_count; staged.platform.disk_info=disk_info;
    staged.platform.disk_read=disk_read; staged.platform.disk_write=disk_write; staged.platform.disk_flush=disk_flush;
    staged.platform.max_io_sectors=base->max_io_sectors;
    staged.ops=*a; staged.ops.ctx=v; staged.ops.admit_source=admit; staged.ops.check_source=source_check;
    staged.ops.close_source=close_file; staged.ops.sha_begin=sha_begin; staged.ops.sha_update=sha_update;
    staged.ops.sha_end=sha_end; staged.ops.sha_abort=sha_abort; staged.ops.review_target=review;
    staged.ops.claim_target=claim_target; staged.ops.check_target=check_target; staged.ops.release_target=release;
    staged.ops.prepare_relocation=shz_native_provider_relocation; staged.initialized=1;
    memcpy(v,&staged,sizeof staged); return 0;
}
void shz_native_provider_run(shz_native_provider_t *v,const native_setup_request_v1_t *request,native_setup_result_v1_t *result)
{
    if(!result) return;
    if(!v || !v->initialized || v->started) {
        memset(result,0,sizeof *result); strcpy(result->reason,"native provider absent or already consumed"); return;
    }
    v->started=1;
    setup_run_native(&v->platform,&v->ops,request,result);
}
