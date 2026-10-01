/* SPDX-License-Identifier: GPL-2.0-only
 * Controlled kernel boundary contract. The companion Python runner extracts
 * the exact production functions into ldr_unload_production.inc; this file
 * supplies allocation, user-memory, VAD and scheduler boundaries, not a second
 * implementation. Actual mapping/callback proof is t_ldr_unload.c in a guest.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../ldr_lifetime.h"
#include "../ntsys.h"
#include "../../win64/include/shz_loader_protocol.h"
typedef struct { shz_ldr_image_life_t life; void *blocks; } image_map_t;
typedef struct module {
    struct module *next; shz_ldr_life_t life;
    uint64_t base,entry_va; int state,published,has_tls;
    uint32_t init_seq; image_map_t *img;
} module_t;
typedef struct { uint64_t alloc_base; int kind,live; } vad_t;
typedef struct {
    void *modules,*ldr_retirement; uint64_t ldr_retire_sequence; int ldr_lock;
    vad_t vads[16]; uint64_t heads[3][2];
} process_t;
typedef struct { uint64_t token,owner_tid; unsigned count; module_t *nodes[]; } ldr_retirement_t;
typedef struct { uint64_t tid; } thread_t;
#define VK_VIEW 7
static thread_t current={7};
static int allocations,lock_depth,irq_depth,fail_copy,fail_alloc,fail_write,fail_release;
static unsigned checks;
#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static void *kzalloc(size_t n){void *p;if(fail_alloc){--fail_alloc;return NULL;}p=calloc(1,n);if(p)++allocations;return p;}
static void kfree(void *p){if(p){--allocations;free(p);}}
static uint64_t irq_save(void){++irq_depth;return 0;}
static void irq_restore(uint64_t f){(void)f;assert(irq_depth>0);--irq_depth;}
static void mutex_lock(int *p){(void)p;assert(!lock_depth);++lock_depth;}
static void mutex_unlock(int *p){(void)p;assert(lock_depth==1);--lock_depth;}
static thread_t *thread_current(void){return &current;}
static int uread64(process_t *p,uint64_t a,uint64_t *v){(void)p;if(!a)return -1;memcpy(v,(void *)(uintptr_t)a,8);return 0;}
static int uwrite(process_t *p,uint64_t a,const void *v,uint64_t n){(void)p;if(fail_write){--fail_write;return -1;}if(!a)return -1;memcpy((void *)(uintptr_t)a,v,(size_t)n);return 0;}
static int uwrite64(process_t *p,uint64_t a,uint64_t v){return uwrite(p,a,&v,8);}
static int kread(process_t *p,uint64_t a,void *v,uint64_t n){(void)p;if(!a)return -1;memcpy(v,(void *)(uintptr_t)a,(size_t)n);return 0;}
static int copy_to_user(process_t *p,uint64_t a,const void *v,uint64_t n){if(fail_copy){--fail_copy;return -1;}return uwrite(p,a,v,n);}
static vad_t *vad_find(process_t *p,uint64_t base){unsigned i;for(i=0;i<16;++i)if(p->vads[i].live&&p->vads[i].alloc_base==base)return &p->vads[i];return NULL;}
static int32_t vad_free(process_t *p,uint64_t *b,uint64_t *n,uint32_t flags){vad_t *v=vad_find(p,*b);assert(flags==MEM_RELEASE&&*n==0);if(fail_release){--fail_release;return STATUS_UNABLE_TO_FREE_VM;}if(!v)return STATUS_FREE_VM_NOT_AT_BASE;v->live=0;return 0;}

#include "ldr_unload_production.inc"

/* Published records are intentionally separate from their image lifetime,
 * as in the actual loader's shared batch allocation. */
static unsigned char records[16][0x120];
static unsigned next_record;
static void initialize(process_t *p)
{unsigned i;memset(p,0,sizeof *p);memset(records,0,sizeof records);next_record=0;for(i=0;i<3;++i)p->heads[i][0]=p->heads[i][1]=(uintptr_t)p->heads[i];}
static module_t *make_module(process_t *p,unsigned seq,unsigned refs,unsigned root,unsigned tls)
{
    module_t *m=kzalloc(sizeof *m);unsigned i,index=next_record++;
    assert(index<16&&m);m->base=0x100000u+index*0x10000u;m->entry_va=(uintptr_t)records[index];
    m->state=1;m->published=1;m->init_seq=seq;m->life.refs=refs;m->life.root=root;m->has_tls=tls;
    m->next=p->modules;p->modules=m;module_life_links(p);
    p->vads[index]=(vad_t){m->base,0,1};
    for(i=0;i<3;++i){uint64_t at=m->entry_va+i*16,*head=p->heads[i],*prev=(void *)(uintptr_t)head[1];
        uint64_t pair[2]={(uintptr_t)head,head[1]};memcpy((void *)(uintptr_t)at,pair,16);prev[0]=at;head[1]=at;}
    return m;
}
static unsigned module_count(process_t *p){module_t *m;unsigned n=0;for(m=p->modules;m;m=m->next)++n;return n;}
static void cleanup(process_t *p)
{module_t *m=p->modules;while(m){module_t *next=m->next;module_edges_free(m);image_owner_retire(m->img);kfree(m);m=next;}kfree(p->ldr_retirement);p->modules=p->ldr_retirement=NULL;CHECK(allocations==0&&lock_depth==0&&irq_depth==0);}
static int32_t prepare(process_t *p,module_t *m,shz_ldr_retire_buffer *b,unsigned cap)
{return ldr_lifetime_control(p,SHZ_LDR_PREPARE,m->base,(uintptr_t)b,cap);}

int main(void)
{
    process_t p;module_t *a,*b,*s;uint64_t base_a,base_b;unsigned i;image_map_t *pending_image;
    unsigned char output[sizeof(shz_ldr_retire_buffer)+16*sizeof(uint64_t)];
    shz_ldr_retire_buffer *out=(void *)output;
    initialize(&p);s=make_module(&p,1,0,1,0);a=make_module(&p,3,2,0,0);b=make_module(&p,2,0,0,0);
    pending_image=kzalloc(sizeof *pending_image);pending_image->life.refs=1;pending_image->blocks=kzalloc(32);a->img=pending_image;
    CHECK(shz_ldr_image_acquire(&pending_image->life)==0); /* blocked page-in keeps real commit's metadata alive */
    base_a=a->base;base_b=b->base;
    CHECK(module_edge(a,b)==0&&module_edge(b,a)==0&&module_edge(a,s)==0);
    i=(unsigned)allocations;CHECK(module_edge(a,b)==0&&(unsigned)allocations==i);
    CHECK(prepare(&p,a,out,16)==0&&out->Count==0&&out->Token==0&&a->life.refs==1);
    CHECK(prepare(&p,a,out,16)==0&&out->Count==2&&out->Entries[0]==a->entry_va&&out->Entries[1]==b->entry_va);
    CHECK(a->state==2&&b->state==2&&a->life.retiring&&b->life.retiring&&module_count(&p)==3);
    CHECK(prepare(&p,s,out,16)==STATUS_NOT_SUPPORTED&&s->life.refs==0);
    CHECK(ldr_lifetime_control(&p,SHZ_LDR_ADDREF,base_a,0,0)==STATUS_DLL_NOT_FOUND);
    CHECK(ldr_lifetime_control(&p,SHZ_LDR_PIN,base_b,0,0)==STATUS_DLL_NOT_FOUND);
    CHECK(ldr_lifetime_control(&p,SHZ_LDR_ADDREF,s->base,0,0)==0&&s->life.refs==1);
    CHECK(ldr_lifetime_commit(&p,out->Token+1)==STATUS_INVALID_PARAMETER&&module_count(&p)==3);
    ++current.tid;CHECK(ldr_lifetime_commit(&p,out->Token)==STATUS_INVALID_PARAMETER&&p.ldr_retirement);--current.tid;
    CHECK(ldr_lifetime_commit(&p,out->Token)==0&&module_count(&p)==1&&!vad_find(&p,base_a)&&!vad_find(&p,base_b)&&!p.ldr_retirement);
    CHECK(pending_image->life.retired&&pending_image->life.refs==1);
    CHECK(shz_ldr_image_release(&pending_image->life));image_metadata_free(pending_image);
    CHECK(module_lists_valid(&p,s)==0&&s->life.edges==NULL);cleanup(&p);

    initialize(&p);a=make_module(&p,2,1,0,0);b=make_module(&p,1,1,0,0);CHECK(module_edge(a,b)==0);
    base_b=b->base;CHECK(prepare(&p,a,out,16)==0&&out->Count==1);CHECK(ldr_lifetime_commit(&p,out->Token)==0&&vad_find(&p,base_b)&&b->life.refs==1);
    CHECK(prepare(&p,b,out,16)==0&&out->Count==1);CHECK(ldr_lifetime_commit(&p,out->Token)==0&&module_count(&p)==0);cleanup(&p);

    initialize(&p);a=make_module(&p,1,1,0,1);CHECK(prepare(&p,a,out,16)==STATUS_NOT_SUPPORTED&&a->life.refs==1&&a->state==1&&!p.ldr_retirement);cleanup(&p);
    for(i=0;i<2;++i){uint32_t flags=i?0x80000000u:1u;initialize(&p);a=make_module(&p,1,1,0,0);memcpy((void *)(uintptr_t)(a->entry_va+0x68),&flags,4);
        CHECK(prepare(&p,a,out,16)==STATUS_NOT_SUPPORTED&&a->life.refs==1&&a->state==1);cleanup(&p);}
    initialize(&p);a=make_module(&p,1,1,0,0);CHECK(prepare(&p,a,out,0)==STATUS_BUFFER_TOO_SMALL&&a->life.refs==1&&!p.ldr_retirement);
    fail_copy=1;CHECK(prepare(&p,a,out,16)==STATUS_ACCESS_VIOLATION&&a->life.refs==1&&!p.ldr_retirement);
    fail_alloc=1;CHECK(prepare(&p,a,out,16)==STATUS_NO_MEMORY&&a->life.refs==1&&!p.ldr_retirement);
    fail_write=1;CHECK(ldr_lifetime_control(&p,SHZ_LDR_ADDREF,a->base,0,0)==STATUS_ACCESS_VIOLATION&&a->life.refs==1);
    fail_write=1;CHECK(ldr_lifetime_control(&p,SHZ_LDR_PIN,a->base,0,0)==STATUS_ACCESS_VIOLATION&&!a->life.pinned);
    a->life.refs=0xfffeu;CHECK(ldr_lifetime_control(&p,SHZ_LDR_ADDREF,a->base,0,0)==STATUS_NO_MEMORY&&a->life.refs==0xfffeu);a->life.refs=1;
    CHECK(ldr_lifetime_control(&p,SHZ_LDR_PIN,a->base,0,0)==0&&a->life.pinned);
    CHECK(prepare(&p,a,out,16)==0&&out->Count==0&&a->life.refs==0&&vad_find(&p,a->base));cleanup(&p);
    initialize(&p);a=make_module(&p,1,1,0,0);p.ldr_retire_sequence=UINT64_MAX;CHECK(prepare(&p,a,out,16)==STATUS_NOT_SUPPORTED&&a->life.refs==1);cleanup(&p);

    /* Failed VAD retirement is explicitly a failure with transaction retained;
     * callbacks are a separate, once-only ntdll phase and are not fabricated by
     * this backend contract. A later kernel-only commit can finish retirement. */
    initialize(&p);a=make_module(&p,1,1,0,0);base_a=a->base;CHECK(prepare(&p,a,out,16)==0);fail_release=1;
    CHECK(ldr_lifetime_commit(&p,out->Token)==STATUS_UNABLE_TO_FREE_VM&&vad_find(&p,base_a)&&p.ldr_retirement&&a->life.retiring);
    CHECK(ldr_lifetime_commit(&p,out->Token)==0&&!vad_find(&p,base_a)&&!p.ldr_retirement);cleanup(&p);
    printf("LDR-UNLOAD-BACKEND: %u checks passed; exact production refs/prepare/commit, cycles, owner tokens, rights to retire and injected failure preservation\n",checks);
    return 0;
}
