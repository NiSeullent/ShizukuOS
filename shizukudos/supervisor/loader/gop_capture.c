/* SPDX-License-Identifier: GPL-2.0-only
 * UEFI 2.10 sections12.9,14.4,37.5. Observation, not physical admission. */
#include "gop_capture.h"
#define BY_PROTOCOL 2u
static EFI_GUID gop_id={0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
static EFI_GUID pci_id={0x4cf5b200,0x68b8,0x4ca5,{0x9e,0xec,0xb2,0x3e,0x3f,0x50,0x02,0x9a}};
static EFI_GUID path_id={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static EFI_GUID rng_id={0x3152bca5,0xeade,0x433d,{0x86,0x2e,0xc0,0x1c,0xdc,0x29,0x1f,0x44}};
typedef struct pci_io pci_io;
typedef struct {EFI_STATUS (EFIAPI *read)(pci_io *,uint32_t,uint32_t,size_t,void *);void *write;} pci_config;
struct pci_io {
    void *poll_mem,*poll_io,*mem_read,*mem_write,*io_read,*io_write;
    pci_config pci;
    void *copy_mem,*map,*unmap,*allocate_buffer,*free_buffer,*flush;
    EFI_STATUS (EFIAPI *location)(pci_io *,size_t *,size_t *,size_t *,size_t *);
    void *attributes;
    EFI_STATUS (EFIAPI *bar_attributes)(pci_io *,uint8_t,uint64_t *,void **);
    void *set_bar_attributes;uint64_t rom_size;void *rom_image;
};
typedef struct rng rng;
struct rng {void *info;EFI_STATUS (EFIAPI *get)(rng *,EFI_GUID *,size_t,uint8_t *);};
_Static_assert(offsetof(pci_io,pci)==48,"UEFI PCI config ABI");
_Static_assert(offsetof(pci_io,location)==112,"UEFI PCI location ABI");
_Static_assert(offsetof(pci_io,bar_attributes)==128,"UEFI PCI BAR ABI");
_Static_assert(sizeof(pci_io)==160,"UEFI PCI protocol ABI");
static void zero(void *v,size_t n){uint8_t *p=v;while(n--)*p++=0;}
static void copy(void *v,const void *w,size_t n){uint8_t *p=v;const uint8_t *q=w;while(n--)*p++=*q++;}
static int same(const void *v,const void *w,size_t n){const uint8_t *p=v,*q=w;while(n--)if(*p++!=*q++)return 0;return 1;}
static uint16_t u16(const uint8_t *p){return p[0]|(uint16_t)p[1]<<8;}
static uint64_t u64(const uint8_t *p){uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(i*8);return v;}
static int path(const uint8_t *p,uint32_t *bytes,uint32_t *last){
    uint32_t at=0,previous=0;
    if(!p)return -1;
    while(at<=SHZ_GOP_CAPTURE_PATH_MAX-4){
        unsigned length=u16(p+at+2);
        if(length<4 || length>SHZ_GOP_CAPTURE_PATH_MAX-at)return -1;
        if(p[at]==0x7f){if(p[at+1]!=0xff || length!=4 || !at)return -1;*bytes=at+4;*last=previous;return 0;}
        if(p[at]==1 && p[at+1]==1 && (length!=6 || p[at+4]>7 || p[at+5]>31))return -1;
        previous=at;at+=length;
    }
    return -1;
}
static int snapshot(EFI_BOOT_SERVICES *bs,EFI_GOP *gop,const SD_FRAMEBUFFER *expected,shz_gop_observation_t *o){
    EFI_HANDLE *handles=0,gop_handle=0;size_t count=0;unsigned found=0;int rc=SHZ_GOP_CAPTURE_FIRMWARE;
    uint32_t last=0;const uint8_t *gp=0;SD_FRAMEBUFFER fb;
    if(EFI_ERROR(sd_framebuffer_snapshot(gop->mode,&fb)) || !same(&fb,expected,sizeof fb))return SHZ_GOP_CAPTURE_CHANGED;
    if(EFI_ERROR(bs->locate_handle_buffer(BY_PROTOCOL,&gop_id,0,&count,&handles)))goto done;
    if(!handles || !count || count>SHZ_GOP_CAPTURE_HANDLES_MAX)goto done;
    for(size_t i=0;i<count;i++){
        EFI_GOP *candidate=0;
        if(EFI_ERROR(bs->handle_protocol(handles[i],&gop_id,(void **)&candidate)))goto done;
        if(candidate==gop){gop_handle=handles[i];found++;}
    }
    if(found!=1){rc=found?SHZ_GOP_CAPTURE_AMBIGUOUS:SHZ_GOP_CAPTURE_UNSUPPORTED;goto done;}
    if(EFI_ERROR(bs->handle_protocol(gop_handle,&path_id,(void **)&gp)) || path(gp,&o->gop_path_bytes,&last))goto done;
    copy(o->gop_path,gp,o->gop_path_bytes);o->framebuffer=fb;
    if(EFI_ERROR(bs->free_pool(handles))){handles=0;goto done;}handles=0;count=0;
    if(EFI_ERROR(bs->locate_handle_buffer(BY_PROTOCOL,&pci_id,0,&count,&handles)))goto done;
    if(!handles || !count || count>SHZ_GOP_CAPTURE_HANDLES_MAX)goto done;
    pci_io *owner=0;uint32_t best=0;found=0;
    for(size_t i=0;i<count;i++){
        const uint8_t *p=0;pci_io *candidate=0;uint32_t n,l;
        if(EFI_ERROR(bs->handle_protocol(handles[i],&path_id,(void **)&p)) || path(p,&n,&l) ||
           EFI_ERROR(bs->handle_protocol(handles[i],&pci_id,(void **)&candidate)) || !candidate)goto done;
        if(p[l]!=1 || p[l+1]!=1 || n>o->gop_path_bytes || !same(p,o->gop_path,n-4))continue;
        /* Prefix length ends on the owner's End node boundary. Selected GOP
         * path was parsed in full, and copied before further protocol calls. */
        if(n>best){best=n;found=1;owner=candidate;o->pci_path_bytes=n;copy(o->pci_path,p,n);}
        else if(n==best)found++;
    }
    if(found!=1){rc=found?SHZ_GOP_CAPTURE_AMBIGUOUS:SHZ_GOP_CAPTURE_UNSUPPORTED;goto done;}
    size_t segment,bus,device,function;uint32_t config[16];
    if(!owner->location || !owner->pci.read || !owner->bar_attributes ||
       EFI_ERROR(owner->location(owner,&segment,&bus,&device,&function)) ||
       segment>65535 || bus>255 || device>31 || function>7 ||
       EFI_ERROR(owner->pci.read(owner,2,0,16,config)))goto done;
    last=o->pci_path_bytes-10;
    if(o->pci_path[last+4]!=function || o->pci_path[last+5]!=device ||
       (config[0]&65535)==0xffff || !(config[0]&65535) ||
       (config[2]>>24)!=3 || ((config[3]>>16)&0x7f)!=0 || !(config[1]&2))goto done;
    o->segment=(uint32_t)segment;o->bus=(uint32_t)bus;o->device=(uint32_t)device;o->function=(uint32_t)function;
    o->vendor_device=config[0];o->class_revision=config[2];o->command=config[1]&65535;copy(o->raw_bar,config+4,sizeof o->raw_bar);found=0;
    for(unsigned i=0;i<6;i++){
        uint32_t bar=config[4+i];void *resources=0;uint64_t supports=0;unsigned index=i;
        if(!bar || (bar&1))continue;
        unsigned kind=(bar>>1)&3;if(kind!=0 && kind!=2)goto done;
        uint64_t device_base=bar&~UINT64_C(15);
        if(kind==2){if(i==5)goto done;device_base|=(uint64_t)config[4+(++i)]<<32;}
        EFI_STATUS status=owner->bar_attributes(owner,(uint8_t)index,&supports,&resources);
        if(EFI_ERROR(status) || !resources){if(resources && EFI_ERROR(bs->free_pool(resources)))goto done;goto done;}
        const uint8_t *p=resources;uint32_t at=0;unsigned rows=0;int valid=1,ended=0;
        while(rows<8){
            if(p[at]==0x79){
                unsigned checksum=0;
                if(p[at+1])for(unsigned k=0;k<at+2;k++)checksum+=p[k];
                if(checksum&255){valid=0;break;}
                ended=1;break;
            }
            if(p[at]!=0x8a || u16(p+at+1)!=43){valid=0;break;}
            uint64_t gran=u64(p+at+6),base=u64(p+at+14),maximum=u64(p+at+22),translation=u64(p+at+30),bytes=u64(p+at+38);
            if(p[at+3]!=0 || (gran!=32 && gran!=64) || !base || !bytes ||
               base>UINT64_MAX-bytes || base>UINT64_MAX-translation || base+translation!=device_base ||
               (kind==0 && gran!=32) || (kind==2 && gran!=64)){valid=0;break;}
            /* UEFI table14.10 uses ending address; EDK2 PciIo.c uses
             * Alignment. Preserve raw value + explicit observed form. Never
             * use this field to extend base+AddrLen or infer ownership. */
            unsigned encoding=maximum==base+bytes-1?1:0;
            if(!encoding && !(bytes&(bytes-1)) && maximum==bytes-1 && !(device_base&(bytes-1)))encoding=2;
            if(!encoding){valid=0;break;}
            if(fb.base>=base && fb.size<=bytes && fb.base-base<=bytes-fb.size){
                found++;o->bar_index=index;o->resource_base=base;o->resource_bytes=bytes;o->translation=translation;o->bar_supports=supports;o->resource_maximum=maximum;o->maximum_encoding=encoding;
            }
            at+=46;rows++;
        }
        if(EFI_ERROR(bs->free_pool(resources)) || !valid || !ended)goto done;
    }
    if(found!=1){rc=found?SHZ_GOP_CAPTURE_AMBIGUOUS:SHZ_GOP_CAPTURE_UNSUPPORTED;goto done;}
    rc=SHZ_GOP_CAPTURE_OK;
 done:
    if(handles && EFI_ERROR(bs->free_pool(handles)))rc=SHZ_GOP_CAPTURE_FIRMWARE;
    return rc;
}
int shz_gop_capture(EFI_BOOT_SERVICES *bs,EFI_GOP *gop,const SD_FRAMEBUFFER *expected,shz_gop_observation_t *out){
    shz_gop_observation_t a,b;rng *random=0;uint8_t entropy[32];unsigned nonzero=0;int result;
    if(!out)return SHZ_GOP_CAPTURE_INVALID;
    zero(out,sizeof *out);zero(&a,sizeof a);zero(&b,sizeof b);zero(entropy,sizeof entropy);
    if(!bs || !gop || !expected || !bs->locate_handle_buffer || !bs->handle_protocol || !bs->free_pool || !bs->locate_protocol)return SHZ_GOP_CAPTURE_INVALID;
    result=snapshot(bs,gop,expected,&a);if(result)return result;
    if(EFI_ERROR(bs->locate_protocol(&rng_id,0,(void **)&random)) || !random || !random->get)return SHZ_GOP_CAPTURE_UNSUPPORTED;
    if(EFI_ERROR(random->get(random,0,sizeof entropy,entropy)))return SHZ_GOP_CAPTURE_FIRMWARE;
    for(unsigned i=0;i<32;i++)nonzero|=entropy[i];
    if(!nonzero)return SHZ_GOP_CAPTURE_FIRMWARE;
    result=snapshot(bs,gop,expected,&b);if(result)return result;
    if(!same(&a,&b,sizeof a)){zero(entropy,sizeof entropy);return SHZ_GOP_CAPTURE_CHANGED;}
    copy(a.random,entropy,sizeof entropy);copy(out,&a,sizeof a);zero(entropy,sizeof entropy);return SHZ_GOP_CAPTURE_OK;
}
