/* SPDX-License-Identifier: GPL-2.0-only
 * Actual capture C, modeled UEFI protocol calls. No firmware/issuer evidence. */
#include <stdio.h>
#include <string.h>
#include "../gop_capture.c"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"line%d: %s\n",__LINE__,#x);return 1;}checks++;}while(0)
static unsigned checks;
static EFI_BOOT_SERVICES services;
static EFI_GOP_INFO info;
static EFI_GOP_MODE mode;
static EFI_GOP display,other;
static pci_io pci;
static rng random_provider;
static uint8_t parent_path[22],child_path[30],wrong_path[22],descriptor[48];
static uint32_t config[16];
static EFI_HANDLE gop_handles[2],pci_handles[2];
static unsigned allocations,freed,locations,reads,rng_calls;
static int fault;
static void put64(uint8_t *p,uint64_t v){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(v>>(i*8));}
static EFI_STATUS EFIAPI free_buffer(void *p){(void)p;freed++;return fault==18 ? EFI_ERROR_BIT|7 : 0;}
static EFI_STATUS EFIAPI locate(uint32_t search,EFI_GUID *id,void *unused,size_t *count,EFI_HANDLE **handles){
    (void)unused;if(search!=2)return EFI_ERROR_BIT|2;
    allocations++;
    if(same(id,&gop_id,sizeof *id)){*count=fault==2?2:1;*handles=gop_handles;}
    else if(same(id,&pci_id,sizeof *id)){*count=fault==3?2:1;*handles=pci_handles;}
    else return EFI_ERROR_BIT|3;
    return 0;
}
static EFI_STATUS EFIAPI handle(EFI_HANDLE h,EFI_GUID *id,void **out){
    if(same(id,&gop_id,sizeof *id)){*out=fault==1?&other:&display;return 0;}
    if(same(id,&path_id,sizeof *id)){
        *out=h==(void *)1?(fault==4?wrong_path:child_path):parent_path;
        if(fault==5 && h==(void *)1)child_path[2]=0;
        return 0;
    }
    if(same(id,&pci_id,sizeof *id)){*out=&pci;return 0;}
    return EFI_ERROR_BIT|3;
}
static EFI_STATUS EFIAPI location(pci_io *p,size_t *segment,size_t *bus,size_t *device,size_t *function){
    (void)p;locations++;*segment=0;*bus=2;*device=fault==6?8:7;*function=0;
    if(fault==7)*segment=65536;
    return 0;
}
static EFI_STATUS EFIAPI read_config(pci_io *p,uint32_t width,uint32_t off,size_t count,void *out){
    (void)p;reads++;if(width!=2 || off || count!=16)return EFI_ERROR_BIT|2;
    if(fault==8 && reads==2)config[0]^=1;
    memcpy(out,config,sizeof config);return 0;
}
static EFI_STATUS EFIAPI attributes(pci_io *p,uint8_t bar,uint64_t *supports,void **out){
    (void)p;if(bar!=0)return EFI_ERROR_BIT|3;allocations++;*out=descriptor;*supports=0x80;return 0;
}
static EFI_STATUS EFIAPI random_bytes(rng *p,EFI_GUID *algorithm,size_t count,uint8_t *out){
    (void)p;rng_calls++;if(algorithm || count!=32)return EFI_ERROR_BIT|2;
    memset(out,fault==11?0:0xa5,count);
    if(fault==10)return EFI_ERROR_BIT|7;
    if(fault==12)mode.framebuffer_base+=4096;
    return 0;
}
static EFI_STATUS EFIAPI protocol(EFI_GUID *id,void *registration,void **out){
    (void)registration;if(!same(id,&rng_id,sizeof *id) || fault==9)return EFI_ERROR_BIT|3;
    *out=&random_provider;return 0;
}
static void reset(int f){
    fault=f;allocations=freed=locations=reads=rng_calls=0;
    memset(&services,0,sizeof services);services.locate_handle_buffer=locate;services.handle_protocol=handle;
    services.free_pool=free_buffer;services.locate_protocol=protocol;
    memset(&info,0,sizeof info);info.width=800;info.height=600;info.pixel_format=1;info.pixels_per_scan_line=832;
    memset(&mode,0,sizeof mode);mode.max_mode=1;mode.info=&info;mode.info_size=sizeof info;
    mode.framebuffer_base=0xe0000000;mode.framebuffer_size=16<<20;display.mode=&mode;
    memset(&pci,0,sizeof pci);pci.location=location;pci.pci.read=read_config;pci.bar_attributes=attributes;
    random_provider.get=random_bytes;
    memset(parent_path,0,sizeof parent_path);parent_path[0]=2;parent_path[1]=1;parent_path[2]=12;
    parent_path[12]=1;parent_path[13]=1;parent_path[14]=6;parent_path[17]=7;
    parent_path[18]=0x7f;parent_path[19]=0xff;parent_path[20]=4;
    memcpy(wrong_path,parent_path,sizeof parent_path);wrong_path[17]=9;
    memcpy(child_path,parent_path,18);child_path[18]=1;child_path[19]=5;child_path[20]=8;
    child_path[26]=0x7f;child_path[27]=0xff;child_path[28]=4;
    gop_handles[0]=(void *)1;gop_handles[1]=(void *)1;pci_handles[0]=(void *)2;pci_handles[1]=(void *)3;
    memset(config,0,sizeof config);config[0]=0x11111234;config[1]=3;config[2]=0x03000000;config[4]=0xe0000008;
    memset(descriptor,0,sizeof descriptor);descriptor[0]=0x8a;descriptor[1]=43;
    put64(descriptor+6,32);put64(descriptor+14,0xe0000000);put64(descriptor+22,0xe0ffffff);
    put64(descriptor+38,16<<20);descriptor[46]=0x79;
    if(f==13)put64(descriptor+14,UINT64_MAX-1024);
    if(f==14)descriptor[1]=42;
    if(f==15)put64(descriptor+22,0xe0fffffe);
    if(f==16)descriptor[3]=1;
    if(f==17)put64(descriptor+14,0xd0000000);
    if(f==19)config[1]=1;
    if(f==20)info.pixel_format=3;
}
int main(void){
    shz_gop_observation_t out;SD_FRAMEBUFFER expected;
    reset(0);CHECK(sd_framebuffer_snapshot(&mode,&expected)==0);
    CHECK(shz_gop_capture(&services,&display,&expected,&out)==0);
    CHECK(out.device==7 && out.bus==2 && out.bar_index==0 && out.resource_bytes==(16<<20));
    CHECK(out.gop_path_bytes==30 && out.pci_path_bytes==22 && out.random[31]==0xa5);
    CHECK(allocations==freed && rng_calls==1 && reads==2 && locations==2);
    for(int f=1;f<=20;f++){
        reset(f);expected=(SD_FRAMEBUFFER){0xe0000000,16<<20,800,600,832,2};
        memset(&out,0xcc,sizeof out);
        CHECK(shz_gop_capture(&services,&display,&expected,&out)!=0);
        shz_gop_observation_t empty={0};CHECK(same(&out,&empty,sizeof out));
        CHECK(allocations==freed);
    }
    reset(0);CHECK(sd_framebuffer_snapshot(&mode,&expected)==0);
    /* Real host/device address translation and a 64-bit BAR capture. */
    config[4]=0xf000000c;config[5]=1;put64(descriptor+6,64);put64(descriptor+30,UINT64_C(0x110000000));
    CHECK(shz_gop_capture(&services,&display,&expected,&out)==0);
    CHECK(out.translation==UINT64_C(0x110000000) && out.raw_bar[1]==1);
    CHECK(allocations==freed);
    reset(0);CHECK(sd_framebuffer_snapshot(&mode,&expected)==0);
    put64(descriptor+22,(16<<20)-1);
    CHECK(shz_gop_capture(&services,&display,&expected,&out)==0);
    CHECK(out.maximum_encoding==2 && out.resource_maximum==(16<<20)-1);
    CHECK(allocations==freed);
    reset(0);CHECK(sd_framebuffer_snapshot(&mode,&expected)==0);
    descriptor[47]=1;CHECK(shz_gop_capture(&services,&display,&expected,&out)!=0);CHECK(allocations==freed);
    printf("%u modeled-UEFI actual capture C controls PASS\n",checks);return 0;
}
