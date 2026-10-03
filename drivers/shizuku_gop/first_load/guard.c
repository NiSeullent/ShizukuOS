/* SPDX-License-Identifier: GPL-2.0-only
 * Nongraphics readonly Win98 bootstrap. No port I/O/mode/default mutation.
 * CPUID allows safe instruction selection only; HC14 supplies actual admission. */
#include "contract.h"
#include "../gop_contract.h"
#include "provider.h"
struct dioc {uint32_t internal1,vm,internal2,code,input,input_bytes,output,output_bytes,returned,overlapped,device,process;};
extern int32_t ntwv_vmcall(uint32_t,uint32_t,uint32_t,uint32_t *,uint32_t *);
extern void ntwv_cpuid(uint32_t,uint32_t[4]);
extern uint32_t ntwv_vmm_map_phys(uint32_t,uint32_t,uint32_t);
extern uint32_t ntwv_vmm_check(uint32_t,uint32_t,uint32_t);
extern uint32_t ntwv_vmm_lock(uint32_t,uint32_t,uint32_t);
extern uint32_t ntwv_vmm_unlock(uint32_t,uint32_t,uint32_t);
extern uint32_t ntwv_vmm_ptes(uint32_t,uint32_t,uint32_t *,uint32_t);
extern uint32_t ntwv_irq_enter(void *);
extern void ntwv_irq_leave(void *,uint32_t);
static volatile uint32_t busy,closing;
extern unsigned char ntwv_text_begin[],ntwv_text_last[],ntwv_data_begin[],ntwv_data_last[];
static uint32_t image_pages[2],image_counts[2],image_locked;
static unsigned char *rom,*descriptor;
static uint32_t descriptor_address;
/* Aliases stay tracked even after failed unlock. Such failure prohibits
 * further queries and unloading; no recycled pointer to a forgotten lock. */
static struct pin {uint32_t page,count,offset,alias,held;} pins[2];
static void copy(void *d,const void *s,unsigned n){unsigned char *a=d;const unsigned char *b=s;while(n--)*a++=*b++;}
static int same(const void *a,const void *b,unsigned n){const unsigned char *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static int epoch(uint32_t out[40])
{
    uint32_t regs[4],extent;
    ntwv_cpuid(1,regs);if(!(regs[2]&0x80000000u))return 0;
    ntwv_cpuid(0x40000000u,regs);
    if(regs[1]!=0x5a485353u || regs[2]!=0x4d4d5675u || regs[3]!=0x30312d76u)return 0;
    for(uint32_t i=0;i<40;i++)if(ntwv_vmcall(14,i,1,out+i,&extent) || extent!=40)return 0;
    return shzguard_epoch_valid(out);
}
static int snapshot(unsigned char out[352])
{
    uint32_t first[40],last[40];shzgop_locator loc,again;shzgop_mode mode;
    if(!epoch(first))return 0;
    /* At most two mappings, retained for this VxD lifetime; never arbitrary
     * caller-selected physical addresses or framebuffer mappings. */
    if(!rom){uint32_t p=ntwv_vmm_map_phys(0xf0000,65536,0);if(!p || p==0xffffffffu)return 0;rom=(unsigned char *)(uintptr_t)p;}
    if(!shzgop_locator_scan(rom,65536,&loc))return 0;
    if(!descriptor){uint32_t p=ntwv_vmm_map_phys(loc.descriptor_address,4096,0);if(!p || p==0xffffffffu)return 0;
        descriptor=(unsigned char *)(uintptr_t)p;descriptor_address=loc.descriptor_address;}
    if(loc.descriptor_address!=descriptor_address)return 0;
    copy(out,shzguard_provider,32);copy(out+32,first,160);
    copy(out+192,&loc.address,4);copy(out+196,&loc.descriptor_address,4);
    copy(out+200,rom+(loc.address-0xf0000),48);copy(out+248,descriptor,96);
    for(unsigned i=344;i<352;i++)out[i]=0;
    if(!shzgop_locator_bind(&loc,out+248,96,&mode) || mode.bus || mode.devfn!=first[7] ||
       ((uint32_t)mode.vendor|((uint32_t)mode.device<<16))!=first[8] ||
       (first[10]&15u)!=8 || (first[10]&~15u)!=mode.base ||
       !epoch(last) || !same(first,last,160) || !shzgop_locator_scan(rom,65536,&again) ||
       loc.address!=again.address || loc.descriptor_address!=again.descriptor_address ||
       loc.descriptor_checksum!=again.descriptor_checksum ||
       !same(out+200,rom+(loc.address-0xf0000),48) || !same(out+248,descriptor,96))return 0;
    return 1;
}
static int pin_range(struct pin *p,uint32_t address,uint32_t n)
{
    if(!n || address<0x400000u || address>=0x80000000u || n>0x80000000u-address)return 0;
    p->page=address>>12;p->offset=address&4095u;p->count=(p->offset+n+4095u)>>12;
    if(p->count>2 || ntwv_vmm_check(p->page,p->count,0)!=p->count)return 0;
    p->alias=ntwv_vmm_lock(p->page,p->count,0x40000000u);if(!p->alias)return 0;
    p->held=1;
    return p->alias>=0x80000000u && !(p->alias&4095u) && p->count<=((0xffffffffu-p->alias)>>12)+1;
}
static int writable(const struct pin *p)
{
    uint32_t original[2],alias[2];
    if(!p->held || !ntwv_vmm_ptes(p->page,p->count,original,0) || !ntwv_vmm_ptes(p->alias>>12,p->count,alias,0))return 0;
    for(unsigned i=0;i<p->count;i++)if((original[i]&7)!=7 || (alias[i]&3)!=3 || (original[i]&0xfffff000u)!=(alias[i]&0xfffff000u))return 0;
    return 1;
}
static int release_pin(struct pin *p)
{
    if(!p->held)return 1;
    if(!ntwv_vmm_unlock(p->alias>>12,p->count,0x40000000u))return 0;
    p->held=0;return 1;
}
uint32_t ntwv_native_init(void)
{
    const uintptr_t first[2]={(uintptr_t)ntwv_text_begin,(uintptr_t)ntwv_data_begin};
    const uintptr_t last[2]={(uintptr_t)ntwv_text_last,(uintptr_t)ntwv_data_last};
    if(image_locked || closing)return 0;
    for(unsigned i=0;i<2;i++){
        image_pages[i]=(uint32_t)(first[i]>>12);
        image_counts[i]=(uint32_t)((last[i]>>12)-(first[i]>>12)+1);
        if(!ntwv_vmm_lock(image_pages[i],image_counts[i],0)){
            while(image_locked){unsigned at=image_locked-1;
                if(!ntwv_vmm_unlock(image_pages[at],image_counts[at],0))break;
                --image_locked;
            }
            return 0;
        }
        ++image_locked;
    }
    return 1; /* only own image locks; no hypercall/physical map/graphics */
}
uint32_t ntwv_native_exit(void)
{
    __atomic_store_n(&closing,1,__ATOMIC_RELEASE);
    if(__atomic_exchange_n(&busy,1,__ATOMIC_ACQUIRE))return 0;
    /* MapPhysToLinear aliases have no proven release callback here. Never
     * forget them by unloading: retain this module for the current boot. */
    if(rom || descriptor || pins[0].held || pins[1].held)goto refuse;
    while(image_locked){unsigned i=image_locked-1;
        if(!ntwv_vmm_unlock(image_pages[i],image_counts[i],0))goto refuse;
        --image_locked;
    }
    __atomic_store_n(&busy,0,__ATOMIC_RELEASE);return 1;
refuse:
    __atomic_store_n(&busy,0,__ATOMIC_RELEASE);return 0;
}
void ntwv_native_lifecycle(uint32_t code,uint32_t vm,uint32_t thread){(void)code;(void)vm;(void)thread;}
uint32_t ntwv_native_dioc(const struct dioc *source)
{
    struct dioc r;unsigned char observed[352];uint32_t rc=21,saved,zero=0;
    if(!source)return 87;copy(&r,source,sizeof r);
    if(r.code==0xffffffffu)return 0;
    if(__atomic_load_n(&closing,__ATOMIC_ACQUIRE))return 21;
    if(r.code==0)return image_locked==2?0:21;
    if(r.code!=SHZGUARD_QUERY || r.input || r.input_bytes || r.overlapped || r.output_bytes!=352 ||
       r.output>0xffffffffu-352 || r.returned>0xffffffffu-4 ||
       (r.returned<r.output+352 && r.output<r.returned+4))return 87;
    if(__atomic_exchange_n(&busy,1,__ATOMIC_ACQUIRE))return 170;
    if(__atomic_load_n(&closing,__ATOMIC_ACQUIRE) || image_locked!=2 || pins[0].held || pins[1].held){rc=170;goto done;}
    if(!snapshot(observed))goto done;
    if(!pin_range(pins,r.output,352) || !pin_range(pins+1,r.returned,4)){rc=87;goto release;}
    saved=ntwv_irq_enter(0);
    if(writable(pins) && writable(pins+1)){
        uint32_t extent=352;
        copy((void *)(uintptr_t)(pins[1].alias+pins[1].offset),&zero,4);
        copy((void *)(uintptr_t)(pins[0].alias+pins[0].offset),observed,352);
        copy((void *)(uintptr_t)(pins[1].alias+pins[1].offset),&extent,4);rc=0;
    }else rc=87;
    ntwv_irq_leave(0,saved);
release:
    if(!release_pin(pins))rc=31;
    if(!release_pin(pins+1))rc=31;
done:
    __atomic_store_n(&busy,0,__ATOMIC_RELEASE);return rc;
}
