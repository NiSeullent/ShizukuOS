/* SPDX-License-Identifier: GPL-2.0-only */
#include "blk_authority_host_shim.h"
#include "../blk_authority.h"
#include "../boot_storage.h"
#include <stdio.h>
static unsigned checks,failures,random_seq,pages_allocated,pages_freed;
static int page_budget=-1,heap_fail,driver_fail;
#define CHECK(x) do{checks++;if(!(x)){failures++;fprintf(stderr,"FAIL line %u %s\n",(unsigned)__LINE__,#x);}}while(0)
void mutex_init(kmutex_t *m){if(pthread_mutex_init(m,0))abort();}
void mutex_lock(kmutex_t *m){if(pthread_mutex_lock(m))abort();}
void mutex_unlock(kmutex_t *m){if(pthread_mutex_unlock(m))abort();}
uint64_t irq_save(void){return 0;}
void irq_restore(uint64_t f){(void)f;}
void krandom_get(void *p,size_t n){size_t i;random_seq++;for(i=0;i<n;i++)((uint8_t *)p)[i]=(uint8_t)(random_seq*17+i);}
void kprintf(const char *f,...){(void)f;}
void *kmalloc(size_t n){return heap_fail?0:malloc(n);}
void *kzalloc(size_t n){return calloc(1,n);}
void kfree(void *p){free(p);}
uint64_t ticks_now(void){return 0;}
uint64_t kernel_pml4(void){return 0;}
uint64_t p2v(uint64_t x){return x;}
uint64_t pmm_alloc(void){void *p;if(!page_budget)return 0;if(page_budget>0)page_budget--;p=calloc(1,PAGE_SIZE);if(p)pages_allocated++;return (uint64_t)(uintptr_t)p;}
void pmm_free(uint64_t p){if(p){pages_freed++;free((void *)(uintptr_t)p);}}
static uint8_t media[64*512],archive[288+10000+7000];
static int read_driver(blk_dev_t *d,uint64_t l,unsigned n,void *p){(void)d;if(driver_fail)return -1;memcpy(p,media+l*512,n*512);return 0;}
static int write_driver(blk_dev_t *d,uint64_t l,unsigned n,const void *p){(void)d;if(driver_fail)return -1;memcpy(media+l*512,p,n*512);return 0;}
static int flush_driver(blk_dev_t *d){(void)d;return driver_fail?-1:0;}
static void dev_init(blk_dev_t *d,const char *name,unsigned port)
{
 memset(d,0,sizeof *d);strcpy(d->name,name);d->sector_size=512;d->sectors=64;d->flags=BLK_F_FLUSH;
 d->read=read_driver;d->write=write_driver;d->flush=flush_driver;
 d->storage.version=SHZ_STORAGE_VERSION;d->storage.size=sizeof d->storage;d->storage.transport=SHZ_STORAGE_SATA;
 d->storage.bus=0;d->storage.device=31;d->storage.function=2;d->storage.unit=port;d->storage.multiplier=0xffff;
 d->storage.sectors=64;d->storage.block_size=512;
}
static void store64(uint8_t *p,uint64_t v){unsigned i;for(i=0;i<8;i++)p[i]=(uint8_t)(v>>(8*i));}
static void *owner=(void *)(uintptr_t)1;
int main(int argc,char **argv)
{
 shz_bootinfo_t bi={0},bad;blk_dev_t shadow,target,unknown,alias,other_target;
 archive_source_t *first=0,*second=0,*again=0;archive_source_info_t one,two,next,wrong;
 blk_authority_source_t sources[2];blk_authority_identity_t target_id;blk_authority_claim_t *claim=0;
 uint8_t out[6000],expected[6000];unsigned i,before;int created;
 memcpy(archive,"SHZARC01",8);archive[8]=2;
 strcpy((char *)archive+16,"\\SHZ\\INPUTS\\FIRST.BIN");store64(archive+16+120,288);store64(archive+16+128,10000);
 strcpy((char *)archive+152,"\\SHZ\\INPUTS\\SECOND.BIN");store64(archive+152+120,10288);store64(archive+152+128,7000);
 for(i=288;i<sizeof archive;i++)archive[i]=(uint8_t)(i*37);
 fs_init();CHECK(fs_load_archive(archive,sizeof archive)==2);
 CHECK(archive_source_open(owner,"C:\\SHZ\\INPUTS\\FIRST.BIN",&first,&one)!=0);
 bi.magic=SHZ_BOOTINFO_MAGIC;bi.abi_major=SHZ_ABI_MAJOR;bi.size=sizeof bi;bi.domain_id=SHZ_DOM_KERNEL64;
 bi.flags=SHZ_BIF_UEFI_DIRECT;bi.initrd_gpa=(uint64_t)(uintptr_t)archive;bi.initrd_size=sizeof archive;bi.ram_size=bi.initrd_gpa+sizeof archive;
 bi.storage.magic=SHZ_STORAGE_MAGIC;bi.storage.version=SHZ_STORAGE_VERSION;bi.storage.size=sizeof bi.storage;bi.storage.flags=SHZ_STORAGE_ARCHIVE_READ;
 bi.storage.boot.version=SHZ_STORAGE_VERSION;bi.storage.boot.size=sizeof bi.storage.boot;bi.storage.boot.transport=SHZ_STORAGE_SATA;
 bi.storage.boot.device=31;bi.storage.boot.function=2;bi.storage.boot.unit=0;bi.storage.boot.multiplier=0xffff;
 bi.storage.boot.sectors=1000;bi.storage.boot.block_size=2048;bi.storage.boot.media_flags=SHZ_STORAGE_READONLY|SHZ_STORAGE_REMOVABLE;
 bi.storage.archive=bi.storage.boot;bi.storage.archive_gpa=bi.initrd_gpa;bi.storage.archive_size=sizeof archive;
 bad=bi;bad.size=472;CHECK(k64_boot_storage_bind(&bad,1)!=0);
 bad=bi;bad.storage.archive.unit=1;CHECK(k64_boot_storage_bind(&bad,1)!=0);
 CHECK(k64_boot_storage_bind(&bi,0)!=0);
 dev_init(&shadow,"shadow",0);CHECK(blk_register(&shadow)==0); /* same physical port, different geometry */
 dev_init(&target,"target",1);CHECK(blk_register(&target)==0);
 dev_init(&alias,"alias",1);CHECK(blk_register(&alias)!=0); /* one physical whole cannot get two registry authorities */
 dev_init(&other_target,"other",3);CHECK(blk_register(&other_target)==0);
 dev_init(&unknown,"unknown",2);memset(&unknown.storage,0,sizeof unknown.storage);CHECK(blk_register(&unknown)==0);
 CHECK(k64_boot_storage_bind(&bi,1)==0); /* actual external optical origin, no fabricated boot blk */
 CHECK(blk_authority_bind_boot_roles(&shadow,&shadow)!=0); /* adopted origin cannot be replaced */
 heap_fail=1;CHECK(archive_source_open(owner,"C:\\SHZ\\INPUTS\\FIRST.BIN",&first,&one)!=0);heap_fail=0;
 before=pages_freed;page_budget=1;CHECK(archive_source_open(owner,"C:\\SHZ\\INPUTS\\FIRST.BIN",&first,&one)!=0);CHECK(pages_freed==before+1);page_budget=-1;
 CHECK(archive_source_open(owner,"C:\\SHZ\\INPUTS\\FIRST.BIN",&first,&one)==0);
 CHECK(one.bytes==10000&&one.physical_origin.block_size==2048);
 printf("snapshot_sha256=");for(i=0;i<32;i++)printf("%02x",one.sha256[i]);printf("\n");
 CHECK(archive_source_read(owner,first,&one,3500,out,6000)==0);CHECK(!memcmp(out,archive+288+3500,6000));memcpy(expected,out,6000);
 wrong=one;wrong.generation++;CHECK(archive_source_read(owner,first,&wrong,0,out,1)!=0);CHECK(archive_source_close(owner,first,&wrong)!=0);
 CHECK(archive_source_read((void *)2,first,&one,0,out,1)!=0);CHECK(archive_source_read(owner,first,&one,9999,out,2)!=0);
 {fsnode_t *mutable=fs_create("C:\\TEMP\\CREATED.BIN",0,&created);CHECK(mutable!=0);CHECK(fs_write(mutable,0,"x",1)==0);
 mutable->readonly=1;CHECK(archive_source_open(owner,"C:\\TEMP\\CREATED.BIN",&again,&next)!=0);}
 /* Even a kernel-mode test mutation of original loader bytes cannot alter sealed copies. */
 memset(archive+288,0,10000);CHECK(archive_source_read(owner,first,&one,3500,out,6000)==0);CHECK(!memcmp(out,expected,6000));
 CHECK(archive_source_open(owner,"C:\\SHZ\\INPUTS\\SECOND.BIN",&second,&two)==0);
 CHECK(blk_authority_pin_archive(owner,first,&one,&sources[0])==0);CHECK(blk_authority_pin_archive(owner,second,&two,&sources[1])==0);
 CHECK(blk_authority_review(&shadow,sources,&target_id)!=0);CHECK(blk_authority_review(&unknown,sources,&target_id)!=0);
 CHECK(blk_authority_review(&target,sources,&target_id)==0);CHECK(blk_authority_claim_target((void *)2,&target,&target_id,sources,&claim)!=0);CHECK(!claim);CHECK(blk_authority_claim_target(owner,&target,&target_id,sources,&claim)==0);
 CHECK(archive_source_close(owner,second,&two)==0);
 {blk_authority_identity_t other_id;blk_authority_claim_t *other_claim=0;
 CHECK(blk_authority_review(&other_target,sources,&other_id)==0);
 CHECK(blk_authority_claim_target(owner,&other_target,&other_id,sources,&other_claim)!=0);CHECK(!other_claim);
 CHECK(archive_source_info(owner,first,&one,&next)==0); /* first retain rollback preserved owner custody */
 }
 CHECK(archive_source_close(owner,first,&one)==0);
 CHECK(blk_authority_check(owner,claim,&target_id)==0);CHECK(archive_source_read(owner,first,&one,0,out,1)!=0);
 CHECK(blk_authority_write(owner,claim,&target_id,0,1,expected)==0);CHECK(!memcmp(media,expected,512));
 if(argc>1&&!strcmp(argv[1],"poison")){
  driver_fail=1;CHECK(blk_authority_flush(owner,claim,&target_id)!=0);driver_fail=0;
  before=pages_freed;CHECK(blk_authority_release(owner,claim,&target_id)!=0);CHECK(pages_freed==before);
  CHECK(archive_source_match(first,one.id,one.generation,one.bytes)==0);CHECK(blk_write(&target,0,1,expected)!=0);
 }else{
  CHECK(blk_authority_release(owner,claim,&target_id)==0);CHECK(archive_source_match(first,one.id,one.generation,one.bytes)!=0);
  CHECK(archive_source_open(owner,"C:\\SHZ\\INPUTS\\SECOND.BIN",&again,&next)==0);
  CHECK(archive_source_close(owner,first,&one)!=0);CHECK(archive_source_read(owner,first,&one,0,out,1)!=0);
  CHECK(archive_source_close(owner,again,&next)==0);CHECK(pages_allocated==pages_freed);
 }
 printf("ARCHIVE_SOURCE checks=%u failures=%u actual_fs_archive_parser_namespace=1 actual_authority_claim=1 IRQ_PMM_driver_firmware_modeled=1 native_producer_admission=0 VM_executed=0\n",checks,failures);
 return failures?1:0;
}
