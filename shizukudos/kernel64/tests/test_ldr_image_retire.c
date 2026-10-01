/* SPDX-License-Identifier: GPL-2.0-only
 * Exact production ldr_image_fault at controlled I/O/VM boundaries. fs_read
 * injects retirement and descriptor replacement before the actual read returns.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../ldr_lifetime.h"
#include "../ntsys.h"
#include "../../win64/pe_parse.h"
#define PAGE_SIZE 4096u
#define VAD_COMMITTED 0x1000u
typedef struct { unsigned io_errors; } kview_t;
typedef struct { unsigned unused; } fsnode_t;
typedef struct image_map {
    shz_ldr_image_life_t life; fsnode_t *node; kview_t *view; const uint8_t *file;
    uint64_t fsize; pe_info_t info; uint64_t base,delta; void *blocks; uint32_t nblocks;
    uint64_t highlow,pages_in,reloc_pages,relocs_applied,bytes_read; char name[48];
} image_map_t;
typedef struct { image_map_t *img; unsigned state,prot; } vad_t;
typedef struct { uint64_t pml4; unsigned teardown,live; vad_t vad; uint64_t mapped_pa; } process_t;
static unsigned checks,allocations,irq_depth,mode,fail_page;
static process_t *active;
static image_map_t *active_image;
static image_map_t replacement;
#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static void *kzalloc(size_t n){void *p=calloc(1,n);if(p)++allocations;return p;}
static void kfree(void *p){if(p){CHECK(allocations>0);--allocations;free(p);}}
static uint64_t irq_save(void){++irq_depth;return 0;}
static void irq_restore(uint64_t f){(void)f;assert(irq_depth);--irq_depth;}
static uint64_t pmm_alloc(void){void *p;if(fail_page)return 0;p=aligned_alloc(PAGE_SIZE,PAGE_SIZE);if(p){memset(p,0,PAGE_SIZE);++allocations;}return (uintptr_t)p;}
static void pmm_free(uint64_t pa){kfree((void *)(uintptr_t)pa);}
static uint64_t p2v(uint64_t pa){return pa;}
static uint64_t vm_lookup(uint64_t root,uint64_t va,void *flags){(void)va;(void)flags;return ((process_t *)(uintptr_t)root)->mapped_pa;}
static vad_t *vad_find(process_t *p,uint64_t va){(void)va;return p->live?&p->vad:NULL;}
static uint64_t prot_to_ptflags(unsigned prot){return prot;}
static int vm_map(uint64_t root,uint64_t va,uint64_t pa,uint64_t flags){process_t *p=(void *)(uintptr_t)root;(void)va;(void)flags;p->mapped_pa=pa;return 0;}
static void kprintf(const char *fmt,...){(void)fmt;}
int pe_get_section(const uint8_t *file,const pe_info_t *info,unsigned index,pe_section_t *out)
{(void)file;(void)info;(void)index;memset(out,0,sizeof *out);return 0;}
static void relocate_page(image_map_t *im,uint64_t rva,uint8_t *page,uint32_t block)
{(void)im;(void)rva;(void)page;(void)block;CHECK(0); /* relocation is a separate existing parser contract */}
static void image_owner_retire(image_map_t *im);
static int fs_read(fsnode_t *node,uint64_t offset,uint8_t *page,uint64_t n,uint64_t *done)
{
    (void)node;(void)offset;memset(page,0x5a,(size_t)n);*done=n;
    CHECK(active_image->life.refs==2&&!active_image->life.retired);
    if(mode==1){active->live=0;image_owner_retire(active_image);CHECK(active_image->life.refs==1&&active_image->life.retired);}
    if(mode==2){active->vad.img=&replacement;active->mapped_pa=pmm_alloc();}
    if(mode==3)active->mapped_pa=pmm_alloc();
    if(mode==4){*done=n-1;return -1;}
    if(mode==5)active->teardown=1;
    return 0;
}
#include "ldr_image_production.inc"

int main(void)
{
    unsigned scenario;
    for(scenario=0;scenario<6;++scenario){
        process_t p={0};image_map_t *im=kzalloc(sizeof *im);kview_t view={0};fsnode_t node={0};
        im->life.refs=1;im->base=0x10000000;im->info.size_of_image=PAGE_SIZE;im->info.size_of_headers=PAGE_SIZE;
        im->node=&node;im->view=&view;im->blocks=kzalloc(24);strcpy(im->name,"fixture.dll");
        p.pml4=(uintptr_t)&p;p.live=1;p.vad=(vad_t){im,VAD_COMMITTED,4};active=&p;active_image=im;mode=scenario;
        if(scenario==1){CHECK(ldr_image_fault(&p,&p.vad,im->base)==STATUS_ACCESS_VIOLATION);CHECK(!p.mapped_pa&&allocations==0);}
        else{
            int st=ldr_image_fault(&p,&p.vad,im->base);
            if(scenario==0)CHECK(st==0&&p.mapped_pa&&im->pages_in==1&&im->bytes_read==PAGE_SIZE);
            if(scenario==2)CHECK(st==STATUS_ACCESS_VIOLATION&&p.mapped_pa&&im->pages_in==0); /* reused VA must not accept stale I/O */
            if(scenario==3)CHECK(st==0&&p.mapped_pa&&im->pages_in==0); /* native identity retained, racing page already present */
            if(scenario==4)CHECK(st==STATUS_IN_PAGE_ERROR&&!p.mapped_pa);
            if(scenario==5)CHECK(st==STATUS_ACCESS_VIOLATION&&!p.mapped_pa);
            CHECK(im->life.refs==1&&!im->life.retired);image_owner_retire(im);if(p.mapped_pa)pmm_free(p.mapped_pa);
            CHECK(allocations==0);
        }
        CHECK(irq_depth==0);
    }
    {
        process_t p={0};image_map_t *im=kzalloc(sizeof *im);im->life.refs=1;im->base=0x10000000;im->info.size_of_image=PAGE_SIZE;
        p.pml4=(uintptr_t)&p;p.live=1;p.vad=(vad_t){im,VAD_COMMITTED,4};fail_page=1;
        CHECK(ldr_image_fault(&p,&p.vad,im->base)==STATUS_NO_MEMORY&&im->life.refs==1&&!p.mapped_pa);fail_page=0;
        image_owner_retire(im);CHECK(allocations==0&&irq_depth==0);
    }
    printf("LDR-IMAGE-RETIRE: %u checks passed; exact page-in I/O interleavings, retirement/reused-VA rejection and final metadata lifetime\n",checks);
    return 0;
}
