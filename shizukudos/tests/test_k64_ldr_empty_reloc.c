/* SPDX-License-Identifier: GPL-2.0-only
 * Exact map_module/eager copy/lazy fault bodies, with production descriptors
 * and PE parser. Only IRQ, allocation, VAD, VM and file-I/O boundaries are
 * host substitutes. Rejecting an empty non-stripped DLL at an occupied base
 * must fail this test; admitting stripped/fixed-EXE/half-directory images or
 * skipping actual DIR64 fixups must also fail it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define irq_save kernel_irq_save
#define irq_restore kernel_irq_restore
#include "../kernel64/fs.h"
#include "../kernel64/kwin.h"
#undef irq_save
#undef irq_restore
#include "../kernel64/ldr_lifetime.h"
#include "../win64/include/shz_loader_protocol.h"
#include "../win64/pe_parse.h"

static unsigned checks, failures, irq_depth;
static const char *scenario;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; fprintf(stderr, "FAIL %s line %d: %s\n", scenario, __LINE__, #x); } } while (0)
static uint64_t host_irq_save(void) { ++irq_depth; return 0; }
static void host_irq_restore(uint64_t f) { (void)f; CHECK(irq_depth > 0); --irq_depth; }
#define irq_save host_irq_save
#define irq_restore host_irq_restore
uint64_t phys_base_va;
void *kmalloc(size_t n) { return malloc(n); }
void kfree(void *p) { free(p); }
void kprintf(const char *fmt, ...) { (void)fmt; }
uint64_t pmm_alloc(void) { return (uintptr_t)calloc(1, PAGE_SIZE); }
void pmm_free(uint64_t pa) { free((void *)(uintptr_t)pa); }
uint64_t prot_to_ptflags(uint32_t p) { return p; }
/* Success makes an accidental ASLR admission choose a different real range,
 * rather than silently falling back to the preferred base under no entropy. */
static int k_rdrand64(uint64_t *v) { *v = 0; return 1; }

/* Actual loader descriptors, constants and selected function declarations. */
#include "ldr_empty_types.inc"

enum { HOST_PAGES = 32, HOST_VADS = 32 };
static struct { uint64_t va, pa; } pages[HOST_PAGES];
static unsigned npages;
static uint64_t fallback = 0x7ffb44000000ull;
static unsigned io_reads;

int vad_range_is_free(process_t *p, uint64_t start, uint64_t size)
{
    unsigned i;
    if (!size || start + size < start) return 0;
    for (i = 0; i < p->vads.count; ++i)
        if (start < p->vads.v[i].end && p->vads.v[i].start < start + size) return 0;
    return 1;
}
int32_t vad_insert_fixed(process_t *p, uint64_t start, uint64_t size, uint32_t state,
                         uint32_t prot, uint32_t kind, uint64_t alloc_base)
{
    vad_t *v;
    if (!vad_range_is_free(p, start, size)) return STATUS_CONFLICTING_ADDRESSES;
    if (p->vads.count == HOST_VADS) return STATUS_NO_MEMORY;
    v = &p->vads.v[p->vads.count++];
    *v = (vad_t){.start=start, .end=start+size, .state=state, .prot=prot,
                 .kind=kind, .alloc_prot=prot, .alloc_base=alloc_base};
    return 0;
}
int32_t vad_insert_image(process_t *p, uint64_t start, uint64_t size, uint32_t prot, uint64_t base, void *im)
{
    int32_t st = vad_insert_fixed(p, start, size, VAD_COMMITTED, prot, VK_IMAGE, base);
    if (!st) p->vads.v[p->vads.count - 1].img = im;
    return st;
}
vad_t *vad_find(process_t *p, uint64_t addr)
{
    unsigned i;
    for (i = 0; i < p->vads.count; ++i)
        if (p->vads.v[i].start <= addr && addr < p->vads.v[i].end) return &p->vads.v[i];
    return NULL;
}
int32_t vad_alloc(process_t *p, uint64_t *base, uint64_t *size, uint32_t type, uint32_t prot, uint32_t kind)
{
    CHECK(!*base && type == (MEM_RESERVE | MEM_TOP_DOWN));
    *base = fallback;
    return vad_insert_fixed(p, *base, *size, VAD_RESERVED, prot, kind, *base);
}
int32_t vad_free(process_t *p, uint64_t *base, uint64_t *size, uint32_t type)
{
    unsigned i;
    CHECK(type == MEM_RELEASE && !*size);
    for (i = 0; i < p->vads.count; ++i) if (p->vads.v[i].start == *base) {
        memmove(&p->vads.v[i], &p->vads.v[i+1], (p->vads.count-i-1)*sizeof(vad_t));
        --p->vads.count; return 0;
    }
    return STATUS_FREE_VM_NOT_AT_BASE;
}
uint64_t vm_lookup(uint64_t root, uint64_t va, uint64_t *flags)
{
    unsigned i;
    (void)root; (void)flags; va &= ~(PAGE_SIZE - 1);
    for (i = 0; i < npages; ++i) if (pages[i].va == va) return pages[i].pa;
    return 0;
}
int vm_map(uint64_t root, uint64_t va, uint64_t pa, uint64_t flags)
{
    (void)root; (void)flags;
    CHECK(!(va & (PAGE_SIZE - 1)) && !vm_lookup(root, va, NULL));
    if (npages == HOST_PAGES) return -1;
    pages[npages].va = va; pages[npages++].pa = pa; return 0;
}
int fs_read(fsnode_t *node, uint64_t off, void *buf, uint64_t n, uint64_t *done)
{
    ++io_reads;
    if (off > node->size || n > node->size - off) { *done = 0; return -1; }
    memcpy(buf, node->data + off, (size_t)n); *done = n; return 0;
}
uint8_t *image_kpage(process_t *p, uint64_t va)
{
    uint64_t pa = vm_lookup(p->pml4, va, NULL);
    vad_t *v;
    if (pa) return (void *)(uintptr_t)pa;
    v = vad_find(p, va);
    if (!v || !v->img || ldr_image_fault(p, v, va)) return NULL;
    return (void *)(uintptr_t)vm_lookup(p->pml4, va, NULL);
}
int image_poke(process_t *p, uint64_t va, const void *src, uint64_t n)
{
    while (n) {
        uint64_t off = va & (PAGE_SIZE - 1), take = PAGE_SIZE - off;
        uint8_t *pg = image_kpage(p, va);
        if (!pg) return -1;
        if (take > n) take = n;
        memcpy(pg + off, src, (size_t)take);
        src = (const uint8_t *)src + take; va += take; n -= take;
    }
    return 0;
}

#include "ldr_empty_production.inc"

static void wr16(uint8_t *p, uint16_t n) { p[0]=(uint8_t)n; p[1]=(uint8_t)(n>>8); }
static void wr32(uint8_t *p, uint32_t n) { unsigned i; for(i=0;i<4;++i)p[i]=(uint8_t)(n>>(i*8)); }
static void wr64(uint8_t *p, uint64_t n) { unsigned i; for(i=0;i<8;++i)p[i]=(uint8_t)(n>>(i*8)); }

/* Hand-checked valid PE32+ fixture: one page of raw section data, then a
 * reserved image hole. Its flags/base match the archived failing DLL. */
static void make_pe(uint8_t file[0x600], unsigned kind)
{
    uint8_t *nt=file+0x80, *opt=nt+24, *sec=opt+0xf0;
    const uint64_t preferred=0x7ffb33000000ull;
    memset(file,0,0x600); file[0]='M'; file[1]='Z'; wr32(file+0x3c,0x80);
    nt[0]='P'; nt[1]='E'; wr16(nt+4,0x8664); wr16(nt+6,1); wr16(nt+20,0xf0);
    wr16(nt+22,(uint16_t)(kind==4||kind==5 ? 0x0022 : 0x2226));
    if(kind==2||kind==3)wr16(nt+22,0x2227);
    wr16(opt,0x20b); wr32(opt+16,0x1010); wr64(opt+24,preferred);
    wr32(opt+32,0x1000); wr32(opt+36,0x200); wr32(opt+56,0x3000);
    wr32(opt+60,0x200); wr16(opt+68,3); wr16(opt+70,0x160); wr32(opt+108,16);
    memcpy(sec,".text",5); wr32(sec+8,0x1000); wr32(sec+12,0x1000);
    wr32(sec+16,0x400); wr32(sec+20,0x200); wr32(sec+36,0x60000020);
    memcpy(file+0x210,"mapping-keeps-original-bytes",27);
    wr64(file+0x280,preferred+0x1234);
    if(kind==6)wr32(opt+112+5*8,0x1100); /* RVA without size */
    if(kind==7)wr32(opt+116+5*8,12);     /* size without RVA */
    if(kind==8||kind==9) {
        wr16(opt+70,0x120); /* no ASLR, to force the collision/fixup path */
        wr32(opt+112+5*8,0x1100); wr32(opt+116+5*8,12);
        wr32(file+0x300,0x1000); wr32(file+0x304,kind==9?7:12);
        wr16(file+0x308,0xa080); /* DIR64 at section RVA 0x1080 */
    }
}

int main(void)
{
    static const char *names[]={"empty DLL occupied","empty DLL preferred free",
        "stripped DLL occupied","stripped DLL preferred free","fixed EXE occupied",
        "fixed EXE preferred free","half directory RVA","half directory size",
        "actual DIR64 fixup","malformed relocation block"};
    unsigned lazy,kind;
    for(lazy=0;lazy<2;++lazy)for(kind=0;kind<10;++kind) {
        uint8_t file[0x600], original[0x600]; vad_t vads[HOST_VADS];
        process_t p={0}; module_t m={0}; image_map_t im={0}; kview_t view={0};
        fsnode_t node={0}; ldr_ctx_t c={0}; int32_t st;
        const int collision=kind!=1&&kind!=3&&kind!=5;
        const int success=kind==0||kind==1||kind==3||kind==5||kind==8;
        const unsigned before_failures=failures;
        scenario=names[kind]; make_pe(file,kind); memcpy(original,file,sizeof file);
        CHECK(pe_parse(file,sizeof file,&m.info)==PE_OK);
        m.is_dll=(m.info.characteristics&PE_CHAR_DLL)!=0;
        m.file=file; m.fsize=sizeof file; strcpy(m.name,"fixture.dll");
        p.vads.v=vads; p.vads.cap=HOST_VADS; p.pml4=1; c.p=&p;
        npages=0; io_reads=0;
        if(collision)CHECK(vad_insert_fixed(&p,0x7ffb33000000ull,0x3000,VAD_RESERVED,PAGE_NOACCESS,VK_PRIVATE,0x7ffb33000000ull)==0);
        if(lazy) {
            m.img=&im; im.file=file; im.fsize=sizeof file; im.info=m.info;
            im.life.refs=1; im.node=&node; im.view=&view;
            node.data=file; node.size=sizeof file;
        }
        st=map_module(&c,&m);
        CHECK(st==(success?STATUS_SUCCESS:kind==9?STATUS_INVALID_IMAGE_FORMAT:STATUS_CONFLICTING_ADDRESSES));
        if(success&&st==0) {
            uint64_t header,ptr; uint8_t *pg;
            CHECK(m.base==(collision?0x7ffb44000000ull:0x7ffb33000000ull));
            pg=image_kpage(&p,m.base); CHECK(pg!=NULL);
            if(pg) { memcpy(&header,pg+0xb0,8); CHECK(header==m.base); }
            pg=image_kpage(&p,m.base+0x1000); CHECK(pg!=NULL);
            if(pg) {
                CHECK(memcmp(pg+0x10,"mapping-keeps-original-bytes",27)==0);
                memcpy(&ptr,pg+0x80,8);
                CHECK(ptr==(kind==8?0x7ffb44001234ull:0x7ffb33001234ull));
                CHECK(pg[0x400]==0&&pg[0xfff]==0);
            }
            CHECK(vad_find(&p,m.base+0x2000)->state==VAD_RESERVED);
            CHECK(memcmp(file,original,sizeof file)==0);
            if(lazy)CHECK(im.base==m.base&&im.delta==m.base-m.info.image_base&&im.life.refs==1&&io_reads==2);
            if(lazy)CHECK(im.pages_in==2&&im.bytes_read==0x600);
            if(lazy&&kind==8)CHECK(im.relocs_applied==1&&im.reloc_pages==1);
            if(lazy&&kind!=8)CHECK(!im.nblocks&&!im.relocs_applied);
        }
        if(!success&&kind!=9)CHECK(!npages&&p.vads.count==1&&!m.base);
        while(npages)pmm_free(pages[--npages].pa);
        kfree(im.blocks); CHECK(irq_depth==0);
        printf("%s: %s %s\n",failures==before_failures?"PASS":"FAIL",lazy?"lazy":"eager",names[kind]);
    }
    printf("LDR-EMPTY-RELOC: %u checks, %u failures; production map/copy/fault and PE parser\n",checks,failures);
    return failures?1:0;
}
