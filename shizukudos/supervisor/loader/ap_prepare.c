/* SPDX-License-Identifier: GPL-2.0-only
 * Loader owns these pages before ExitBootServices; they are never reclaimed by
 * this component, including after partial AP startup or timeout.
 */
#include "ap_prepare.h"
#include "ap_trampoline_image.h"
#include "../../uefi/boot.h"
typedef struct { void *map; size_t bytes, stride; } ap_reader_t;
static void copy(void *dst,const void *src,size_t n) {
    uint8_t *d=dst; const uint8_t *s=src; while(n--) *d++=*s++;
}
static int read_phys(void *ctx,uint64_t pa,void *dst,size_t n) {
    ap_reader_t *r=ctx;
    if(!shz_ap_map_covers(r->map,r->bytes,r->stride,pa,n,0)) return -1;
    copy(dst,(const void *)(uintptr_t)pa,n); return 0;
}
static EFI_STATUS get_map(EFI_BOOT_SERVICES *bs,ap_reader_t *r) {
    size_t bytes=0,key=0,stride=0; uint32_t version=0;
    EFI_STATUS status=bs->get_memory_map(&bytes,0,&key,&stride,&version);
    if(status!=EFI_BUFFER_TOO_SMALL || stride<40 || stride>4096) return EFI_UNSUPPORTED;
    for(unsigned tries=0;tries<8;tries++) {
        if(bytes>SD_MAP_LIMIT-8*stride) return EFI_OUT_OF_RESOURCES;
        bytes+=8*stride;
        status=bs->allocate_pool(EFI_MEM_LOADER_DATA,bytes,&r->map);
        if(EFI_ERROR(status)) return status;
        size_t got=bytes;
        status=bs->get_memory_map(&got,r->map,&key,&stride,&version);
        if(!EFI_ERROR(status) && version==1 && stride>=40 && stride<=4096 && got<=bytes) {
            r->bytes=got; r->stride=stride; return EFI_SUCCESS;
        }
        bs->free_pool(r->map); r->map=0;
        if(status!=EFI_BUFFER_TOO_SMALL) return EFI_UNSUPPORTED;
        bytes=got;
    }
    return EFI_OUT_OF_RESOURCES;
}
EFI_STATUS shz_ap_prepare(EFI_BOOT_SERVICES *bs,uint64_t rsdp,const shz_ap_config_t *cfg,
                           uint64_t *address,uint64_t *bytes) {
    EFI_ALLOCATE_PAGES_FN allocate=(EFI_ALLOCATE_PAGES_FN)bs->allocate_pages;
    uint64_t resource=UINT32_MAX, low=0x9ffff;
    ap_reader_t reader={0}; EFI_STATUS status;
    if(!rsdp || !shz_ap_config_valid(cfg,sizeof *cfg) || !bs->get_memory_map || !bs->free_pool)
        return EFI_INVALID_PARAMETER;
    status=allocate(EFI_ALLOCATE_MAX_ADDRESS,EFI_MEM_LOADER_DATA,1,&resource);
    if(EFI_ERROR(status)) return status;
    shz_ap_boot_t *b=(shz_ap_boot_t *)(uintptr_t)resource;
    for(size_t i=0;i<SHZ_AP_PAGE;i++) ((uint8_t *)b)[i]=0;
    if(cfg->count>1) {
        status=allocate(EFI_ALLOCATE_MAX_ADDRESS,EFI_MEM_LOADER_DATA,cfg->count-1,&low);
        if(EFI_ERROR(status)) return status;
        if(low<0x1000 || low+(cfg->count-1)*SHZ_AP_PAGE>0x100000) return EFI_UNSUPPORTED;
        for(unsigned cpu=1;cpu<cfg->count;cpu++) {
            uint8_t *page=(uint8_t *)(uintptr_t)(low+(cpu-1)*SHZ_AP_PAGE);
            copy(page,ap_trampoline_image,SHZ_AP_PAGE);
            const unsigned offsets[]={18,24,32};
            for(unsigned k=0;k<3;k++) {
                uint32_t delta; copy(&delta,page+offsets[k],sizeof delta);
                uint32_t target=(uint32_t)(uintptr_t)page+delta;
                copy(page+offsets[k],&target,sizeof target);
            }
        }
    } else low=0;
    status=get_map(bs,&reader);
    if(EFI_ERROR(status)) return status;
    uint32_t eax=1,ebx,ecx,edx;
    __asm__ volatile("cpuid" : "+a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx));
    int rc=shz_smp_acpi_probe(read_phys,&reader,rsdp,ebx>>24,&b->topology);
    bs->free_pool(reader.map);
    if(rc || cfg->count>b->topology.count) return EFI_UNSUPPORTED;
    unsigned bsp=b->topology.bsp_index;
    uint32_t id=b->topology.apic_id[0],uid=b->topology.acpi_uid[0];
    b->topology.apic_id[0]=b->topology.apic_id[bsp];
    b->topology.acpi_uid[0]=b->topology.acpi_uid[bsp];
    b->topology.apic_id[bsp]=id; b->topology.acpi_uid[bsp]=uid; b->topology.bsp_index=0;
    b->magic=SHZ_AP_MAGIC; b->version=SHZ_AP_VERSION; b->bytes=sizeof *b;
    b->requested=cfg->count; b->low_base=low; b->low_pages=cfg->count-1;
    *address=resource; *bytes=sizeof *b;
    return EFI_SUCCESS;
}
