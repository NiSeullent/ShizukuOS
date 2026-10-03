/* SPDX-License-Identifier: GPL-2.0-only */
#include "../../../supervisor/loader/storage_observe.h"
#include <stdio.h>
#include <string.h>
static unsigned checks,failures,frees;
#define CHECK(x) do{checks++;if(!(x)){failures++;fprintf(stderr,"FAIL line %u: %s\n",(unsigned)__LINE__,#x);}}while(0)
static uint8_t volume_path[74],whole_path[32];
static shz_efi_block_media_prefix_t whole_media={7,0,1,0,0,0,512,0,63};
static shz_efi_block_media_prefix_t volume_media={9,0,1,1,0,0,512,0,31};
static shz_efi_block_io_prefix_t block={0,&whole_media},vblock={0,&volume_media};
static int duplicate,bad_location,no_block,bad_controller;
static EFI_HANDLE handles[2]={(EFI_HANDLE)(uintptr_t)2,(EFI_HANDLE)(uintptr_t)4};
static EFI_STATUS EFIAPI location(shz_efi_pci_io_prefix_t *p,size_t *s,size_t *b,size_t *d,size_t *f)
{(void)p;*s=bad_location?1:0;*b=0;*d=31;*f=2;return EFI_SUCCESS;}
static shz_efi_pci_io_prefix_t pci={{0},location};
static EFI_STATUS EFIAPI protocol(EFI_HANDLE h,EFI_GUID *g,void **out)
{
 uintptr_t n=(uintptr_t)h;
 if(g->a==0x09576e91){*out=n==1?volume_path:whole_path;return EFI_SUCCESS;}
 if(g->a==0x964e5b21){if(no_block)return EFI_UNSUPPORTED;*out=n==1?(void *)&vblock:(void *)&block;return EFI_SUCCESS;}
 if(g->a==0x4cf5b200&&n==3){*out=&pci;return EFI_SUCCESS;}
 return EFI_UNSUPPORTED;
}
static EFI_STATUS EFIAPI locate(EFI_GUID *g,EFI_DEVICE_PATH_PROTOCOL **p,EFI_HANDLE *h)
{(void)g;*p=(EFI_DEVICE_PATH_PROTOCOL *)(volume_path+(bad_controller?12:18));*h=(EFI_HANDLE)(uintptr_t)3;return EFI_SUCCESS;}
static EFI_STATUS EFIAPI enumerate(uint32_t t,EFI_GUID *g,void *key,size_t *count,EFI_HANDLE **out)
{(void)g;(void)key;CHECK(t==2);*count=duplicate?2:1;*out=handles;return EFI_SUCCESS;}
static EFI_STATUS EFIAPI free_pool(void *p){CHECK(p==handles);frees++;return EFI_SUCCESS;}
static void path_init(void)
{
 memset(volume_path,0,sizeof volume_path);volume_path[0]=2;volume_path[1]=1;volume_path[2]=12;
 volume_path[12]=1;volume_path[13]=1;volume_path[14]=6;volume_path[16]=2;volume_path[17]=31;
 volume_path[18]=3;volume_path[19]=0x12;volume_path[20]=10;volume_path[24]=255;volume_path[25]=255;
 volume_path[28]=4;volume_path[29]=1;volume_path[30]=42;
 volume_path[70]=0x7f;volume_path[71]=0xff;volume_path[72]=4;
 memcpy(whole_path,volume_path,28);whole_path[28]=0x7f;whole_path[29]=0xff;whole_path[30]=4;
}
int main(void)
{
 EFI_BOOT_SERVICES bs={0};shz_efi_storage_observation_t out,before,sentinel;
 shz_storage_locator_t loc;size_t t,p,i;uint8_t bad[74];
 path_init();bs.handle_protocol=protocol;bs.locate_device_path=(void *)locate;bs.locate_handle_buffer=enumerate;bs.free_pool=free_pool;
 CHECK(shz_storage_parse_path(volume_path,74,&loc,&t,&p)==0);CHECK(t==18&&p==28);
 for(i=0;i<74;i++)CHECK(shz_storage_parse_path(volume_path,i,&loc,&t,&p)!=0);
 memset(&sentinel,0xa5,sizeof sentinel);out=sentinel;
 CHECK(shz_efi_storage_observe(&bs,(EFI_HANDLE)(uintptr_t)1,&out)==0);
 CHECK(out.whole.bus==0&&out.whole.device==31&&out.whole.function==2&&out.whole.unit==0&&out.whole.sectors==64&&out.whole.media_id==7&&out.volume_media_id==9);before=out;
 CHECK(shz_efi_storage_same(&before,&out));out.whole.media_id++;CHECK(!shz_efi_storage_same(&before,&out));
 out=before;out.volume_media_id++;CHECK(!shz_efi_storage_same(&before,&out));
 duplicate=1;out=sentinel;CHECK(shz_efi_storage_observe(&bs,(EFI_HANDLE)(uintptr_t)1,&out)!=0);CHECK(!memcmp(&out,&sentinel,sizeof out));duplicate=0;
 whole_media.logical_partition=1;CHECK(shz_efi_storage_observe(&bs,(EFI_HANDLE)(uintptr_t)1,&out)!=0);whole_media.logical_partition=0;
 whole_media.media_present=0;CHECK(shz_efi_storage_observe(&bs,(EFI_HANDLE)(uintptr_t)1,&out)!=0);whole_media.media_present=1;
 bad_location=1;CHECK(shz_efi_storage_observe(&bs,(EFI_HANDLE)(uintptr_t)1,&out)!=0);bad_location=0;
 bad_controller=1;CHECK(shz_efi_storage_observe(&bs,(EFI_HANDLE)(uintptr_t)1,&out)!=0);bad_controller=0;
 no_block=1;CHECK(shz_efi_storage_observe(&bs,(EFI_HANDLE)(uintptr_t)1,&out)!=0);no_block=0;
 memcpy(bad,volume_path,74);bad[20]=0;CHECK(shz_storage_parse_path(bad,74,&loc,&t,&p)!=0);
 memcpy(bad,volume_path,74);bad[19]=5;CHECK(shz_storage_parse_path(bad,74,&loc,&t,&p)!=0);
 memcpy(bad,volume_path,74);bad[71]=1;CHECK(shz_storage_parse_path(bad,74,&loc,&t,&p)!=0);
 whole_media.last_block=UINT64_MAX;CHECK(shz_efi_storage_observe(&bs,(EFI_HANDLE)(uintptr_t)1,&out)!=0);whole_media.last_block=63;
 whole_media.block_size=2048;whole_media.removable=1;whole_media.read_only=1;
 CHECK(shz_efi_storage_observe(&bs,(EFI_HANDLE)(uintptr_t)1,&out)==0);CHECK(out.whole.media_flags==3&&out.whole.block_size==2048);
 {uint8_t nvpath[38]={0};shz_storage_locator_t nv,changed;
 memcpy(nvpath,volume_path,18);nvpath[18]=3;nvpath[19]=0x17;nvpath[20]=16;nvpath[22]=1;
 nvpath[26]=0x11;nvpath[33]=0x88;nvpath[34]=0x7f;nvpath[35]=0xff;nvpath[36]=4;
 CHECK(shz_storage_parse_path(nvpath,38,&nv,&t,&p)==0);
 nv.sectors=64;nv.block_size=512;CHECK(shz_storage_locator_valid(&nv));
 changed=nv;CHECK(shz_storage_match(&nv,&changed));changed.namespace_eui[7]^=1;CHECK(!shz_storage_match(&nv,&changed));
 memset(nvpath+22,255,4);CHECK(shz_storage_parse_path(nvpath,38,&nv,&t,&p)!=0);
 memset(nvpath+22,0,4);CHECK(shz_storage_parse_path(nvpath,38,&nv,&t,&p)!=0);
 }
 CHECK(frees>=5);
 printf("UEFI_STORAGE checks=%u failures=%u firmware_protocols_modeled=1 actual_observer=1 VM_executed=0\n",checks,failures);return failures?1:0;
}
