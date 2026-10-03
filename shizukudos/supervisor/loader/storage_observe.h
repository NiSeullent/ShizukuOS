/* SPDX-License-Identifier: GPL-2.0-only
 * UEFI protocol declarations from UEFI 2.10. No protocol calls after EBS.
 * See official Device Path/Loaded Image specs and EDK2 PciIo.h/BlockIo.h. */
#ifndef SHZ_EFI_STORAGE_OBSERVE_H
#define SHZ_EFI_STORAGE_OBSERVE_H
#include "efi_ext.h"
#include "../../boot_profile/storage/provenance.h"
typedef struct {
 uint32_t media_id;
 uint8_t removable,media_present,logical_partition,read_only,write_caching;
 uint32_t block_size,io_align;
 uint64_t last_block;
} shz_efi_block_media_prefix_t;
typedef struct {uint64_t revision;shz_efi_block_media_prefix_t *media;} shz_efi_block_io_prefix_t;
typedef struct shz_efi_pci_io_prefix {
 void *before_location[14];
 EFI_STATUS (EFIAPI *get_location)(struct shz_efi_pci_io_prefix *,size_t *,size_t *,size_t *,size_t *);
} shz_efi_pci_io_prefix_t;
typedef EFI_STATUS (EFIAPI *shz_efi_locate_path_fn)(EFI_GUID *,EFI_DEVICE_PATH_PROTOCOL **,EFI_HANDLE *);
_Static_assert(offsetof(shz_efi_pci_io_prefix_t,get_location)==112,"PCI_IO.GetLocation ABI");
_Static_assert(offsetof(shz_efi_block_media_prefix_t,last_block)==24,"BLOCK_IO_MEDIA.LastBlock ABI");
typedef struct {shz_storage_locator_t whole;uint32_t volume_media_id;uint64_t volume_last_block;} shz_efi_storage_observation_t;
static inline int shz_efi_storage_path_size(const uint8_t *p,size_t *size)
{
 size_t n=0;unsigned nodes=0;if(!p||!size)return -1;
 while(n+4<=SHZ_STORAGE_PATH_MAX&&nodes++<64){unsigned len=shz_dp_u16(p+n+2);
  if(len<4||len>SHZ_STORAGE_PATH_MAX-n)return -1;
  if(p[n]==0x7f){if(p[n+1]!=0xff||len!=4)return -1;*size=n+4;return 0;}n+=len;
 }return -1;
}
static inline int shz_efi_storage_same(const shz_efi_storage_observation_t *a,const shz_efi_storage_observation_t *b)
{
 return a&&b&&shz_storage_match(&a->whole,&b->whole)&&a->whole.media_id==b->whole.media_id&&
 a->whole.media_flags==b->whole.media_flags&&a->volume_media_id==b->volume_media_id&&a->volume_last_block==b->volume_last_block;
}
/* volume is EXACT LoadedImage.DeviceHandle used for OpenVolume, never a user
 * path. Enumerate actual whole BlockIO ancestors with the physical DP prefix;
 * zero or multiple matches refuse. Do not fall back to partition geometry. */
static inline int shz_efi_storage_observe(EFI_BOOT_SERVICES *bs,EFI_HANDLE volume,shz_efi_storage_observation_t *out)
{
 EFI_GUID dp_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
 EFI_GUID block_guid={0x964e5b21,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
 EFI_GUID pci_guid={0x4cf5b200,0x68b8,0x4ca5,{0x9e,0xec,0xb2,0x3e,0x3f,0x50,0x02,0x9a}};
 EFI_DEVICE_PATH_PROTOCOL *path=0,*remaining;EFI_HANDLE controller=0,*handles=0;
 shz_efi_pci_io_prefix_t *pci=0;shz_efi_block_io_prefix_t *vblock=0,*candidate=0;
 shz_efi_storage_observation_t observation={0};size_t bytes,t,prefix,count=0,i,j,seg,bus,dev,fn;unsigned found=0;int rc=-1;
 if(!bs||!volume||!out||!bs->handle_protocol||!bs->locate_device_path||!bs->locate_handle_buffer||!bs->free_pool)return -1;
 if(EFI_ERROR(bs->handle_protocol(volume,&dp_guid,(void **)&path))||shz_efi_storage_path_size((const uint8_t *)path,&bytes)||
 shz_storage_parse_path((const uint8_t *)path,bytes,&observation.whole,&t,&prefix))return -1;
 if(EFI_ERROR(bs->handle_protocol(volume,&block_guid,(void **)&vblock))||!vblock||!vblock->media||!vblock->media->media_present)return -1;
 observation.volume_media_id=vblock->media->media_id;observation.volume_last_block=vblock->media->last_block;
 remaining=path;
 if(EFI_ERROR(((shz_efi_locate_path_fn)bs->locate_device_path)(&pci_guid,&remaining,&controller))||
 (const uint8_t *)remaining!=(const uint8_t *)path+t||!controller||
 EFI_ERROR(bs->handle_protocol(controller,&pci_guid,(void **)&pci))||!pci||!pci->get_location||
 EFI_ERROR(pci->get_location(pci,&seg,&bus,&dev,&fn))||seg||bus>255||dev>31||fn>7)return -1;
 observation.whole.segment=(uint32_t)seg;observation.whole.bus=(uint8_t)bus;observation.whole.device=(uint8_t)dev;observation.whole.function=(uint8_t)fn;
 if(EFI_ERROR(bs->locate_handle_buffer(2,&block_guid,0,&count,&handles))||!handles)return -1;
 if(count>256)goto done;
 for(i=0;i<count;i++){
  EFI_DEVICE_PATH_PROTOCOL *cp=0;size_t cb=0;
  if(EFI_ERROR(bs->handle_protocol(handles[i],&block_guid,(void **)&candidate))||!candidate||!candidate->media||
   candidate->media->logical_partition||!candidate->media->media_present||
   EFI_ERROR(bs->handle_protocol(handles[i],&dp_guid,(void **)&cp))||
   shz_efi_storage_path_size((const uint8_t *)cp,&cb)||cb!=prefix+4)continue;
  for(j=0;j<prefix;j++)if(((const uint8_t *)cp)[j]!=((const uint8_t *)path)[j])break;
  if(j!=prefix)continue;
  if(++found>1)goto done;
  if(candidate->media->last_block==UINT64_MAX)goto done;
  observation.whole.sectors=candidate->media->last_block+1;observation.whole.block_size=candidate->media->block_size;
  observation.whole.media_id=candidate->media->media_id;
  observation.whole.media_flags=(candidate->media->read_only?SHZ_STORAGE_READONLY:0)|(candidate->media->removable?SHZ_STORAGE_REMOVABLE:0);
 }
 if(found==1&&shz_storage_locator_valid(&observation.whole)){*out=observation;rc=0;}
done:bs->free_pool(handles);return rc;
}
#endif
