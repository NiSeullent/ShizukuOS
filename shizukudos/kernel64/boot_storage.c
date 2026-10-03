/* SPDX-License-Identifier: GPL-2.0-only */
#include "boot_storage.h"
#include "blk_authority.h"
static blk_dev_t *unique_whole(const shz_storage_locator_t *observed)
{
 blk_dev_t *d,*found=0;
 for(d=blk_first();d;d=d->next)if(!d->parent&&!(d->flags&BLK_F_PARTITION)&&
  d->sectors==d->storage.sectors&&d->sector_size==d->storage.block_size&&
  shz_storage_match(observed,&d->storage)){
   if(found)return 0;
   found=d;
 }
 return found;
}
int k64_boot_storage_bind(const shz_bootinfo_t *bi,int archive_loaded)
{
 const shz_storage_provenance_t *p;blk_dev_t *boot,*source;
 if(!bi||bi->magic!=SHZ_BOOTINFO_MAGIC||bi->abi_major!=SHZ_ABI_MAJOR||
  bi->domain_id!=SHZ_DOM_KERNEL64||bi->flags!=SHZ_BIF_UEFI_DIRECT||
  !SHZ_BOOTINFO_HAS(bi,storage)||!archive_loaded)return -1;
 p=&bi->storage;
 if(p->magic!=SHZ_STORAGE_MAGIC||p->version!=SHZ_STORAGE_VERSION||p->size!=sizeof *p||
  p->flags!=SHZ_STORAGE_ARCHIVE_READ||p->reserved||!p->archive_size||
  p->archive_gpa!=bi->initrd_gpa||p->archive_size!=bi->initrd_size||
  !shz_storage_match(&p->boot,&p->archive))return -1;
 boot=unique_whole(&p->boot);source=unique_whole(&p->archive);
 if(!boot||!source)return -1;
 /* C: is the accepted loader archive. Its actual physical origin remains
  * excluded even though fs.c presently exposes it from RAM. */
 return blk_authority_bind_boot_roles(boot,source);
}
