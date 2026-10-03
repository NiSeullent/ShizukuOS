/* SPDX-License-Identifier: GPL-2.0-only
 * Immutable loader observations, never a userspace approval/capability. */
#ifndef SHZ_STORAGE_PROVENANCE_H
#define SHZ_STORAGE_PROVENANCE_H
#include <stdint.h>
#include <stddef.h>
#define SHZ_STORAGE_MAGIC 0x505a4853u
#define SHZ_STORAGE_VERSION 1u
#define SHZ_STORAGE_SATA 1u
#define SHZ_STORAGE_NVME 2u
#define SHZ_STORAGE_READONLY 1u
#define SHZ_STORAGE_REMOVABLE 2u
#define SHZ_STORAGE_ARCHIVE_READ 1u
#define SHZ_STORAGE_PATH_MAX 512u
typedef struct {
 uint16_t version,size,transport,reserved0;
 uint32_t segment;
 uint8_t bus,device,function,reserved1;
 uint32_t unit;
 uint16_t multiplier,lun;
 uint64_t sectors;
 uint32_t block_size,media_id;
 uint8_t namespace_eui[8];
 uint32_t media_flags,reserved2;
} shz_storage_locator_t;
typedef struct {
 uint32_t magic;
 uint16_t version,size;
 uint32_t flags,reserved;
 shz_storage_locator_t boot,archive;
 uint64_t archive_gpa,archive_size;
} shz_storage_provenance_t;
_Static_assert(sizeof(shz_storage_locator_t)==56,"storage locator layout");
_Static_assert(sizeof(shz_storage_provenance_t)==144,"storage provenance layout");
static inline uint16_t shz_dp_u16(const uint8_t *p){return (uint16_t)(p[0]|(uint16_t)p[1]<<8);}
static inline uint32_t shz_dp_u32(const uint8_t *p){return (uint32_t)shz_dp_u16(p)|(uint32_t)shz_dp_u16(p+2)<<16;}
/* Bounded parser: only directly represented SATA/NVMe storage, a PCI chain,
 * optional partition/CD media tail, and a single end node. No RAID/USB/network,
 * expanded ACPI, vendor nodes or multiple instances are guessed. Output is
 * untouched on failure. Prefix ends before media nodes, includes transport. */
static inline int shz_storage_parse_path(const uint8_t *p,size_t bytes,
 shz_storage_locator_t *out,size_t *transport_offset,size_t *whole_prefix)
{
 shz_storage_locator_t x={0};size_t n=0,t=0,prefix=0;unsigned nodes=0,acpi=0,pci=0,media=0;
 if(!p||!out||!transport_offset||!whole_prefix||bytes>SHZ_STORAGE_PATH_MAX)return -1;
 while(n+4<=bytes && nodes++<64){uint16_t len=shz_dp_u16(p+n+2);
  if(len<4||len>bytes-n)return -1;
  if(p[n]==0x7f){if(p[n+1]!=0xff||len!=4||n+4!=bytes||!pci||!x.transport)return -1;
   x.version=SHZ_STORAGE_VERSION;x.size=sizeof x;*out=x;*transport_offset=t;*whole_prefix=prefix;return 0;}
  if(p[n]==2&&p[n+1]==1&&len==12&&!acpi&&!pci&&!x.transport){acpi=1;}
  else if(p[n]==1&&p[n+1]==1&&len==6&&acpi&&!x.transport){
   if(p[n+4]>7||p[n+5]>31)return -1;
   pci++;
  }else if(p[n]==3&&p[n+1]==0x12&&len==10&&pci&&!x.transport&&!media){
   x.transport=SHZ_STORAGE_SATA;x.unit=shz_dp_u16(p+n+4);x.multiplier=shz_dp_u16(p+n+6);x.lun=shz_dp_u16(p+n+8);
   if(x.unit>31||x.multiplier!=0xffff||x.lun)return -1;
   t=n;prefix=n+len;
  }else if(p[n]==3&&p[n+1]==0x17&&len==16&&pci&&!x.transport&&!media){
   unsigned i;x.transport=SHZ_STORAGE_NVME;x.unit=shz_dp_u32(p+n+4);if(!x.unit||x.unit==UINT32_MAX)return -1;
   for(i=0;i<8;i++)x.namespace_eui[i]=p[n+8+i];
   t=n;prefix=n+len;
  }else if(p[n]==4&&x.transport&&!media&&((p[n+1]==1&&len==42)||(p[n+1]==2&&len==24))){media=1;}
  else return -1;
  n+=len;
 }
 return -1;
}
static inline int shz_storage_locator_valid(const shz_storage_locator_t *x)
{
 return x&&x->version==SHZ_STORAGE_VERSION&&x->size==sizeof *x&&!x->reserved0&&!x->reserved1&&!x->reserved2&&
  x->segment==0&&x->device<32&&x->function<8&&x->sectors&&
  (x->block_size==512||x->block_size==2048||x->block_size==4096)&&
  !(x->media_flags&~(SHZ_STORAGE_READONLY|SHZ_STORAGE_REMOVABLE))&&
  ((x->transport==SHZ_STORAGE_SATA&&x->unit<32&&x->multiplier==0xffff&&!x->lun)||
   (x->transport==SHZ_STORAGE_NVME&&x->unit&&x->unit!=UINT32_MAX&&!x->multiplier&&!x->lun));
}
/* Firmware media_id is local to firmware, not a runtime media generation. */
static inline int shz_storage_match(const shz_storage_locator_t *a,const shz_storage_locator_t *b)
{
 unsigned i;if(!shz_storage_locator_valid(a)||!shz_storage_locator_valid(b)||a->transport!=b->transport||a->segment!=b->segment||
 a->bus!=b->bus||a->device!=b->device||a->function!=b->function||a->unit!=b->unit||a->multiplier!=b->multiplier||
 a->lun!=b->lun||a->sectors!=b->sectors||a->block_size!=b->block_size)return 0;
 for(i=0;i<8;i++)if(a->namespace_eui[i]!=b->namespace_eui[i])return 0;
 return 1;
}
#endif
