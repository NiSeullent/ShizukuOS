/* SPDX-License-Identifier: GPL-2.0-only */
#include "setup_native_host_shim.h"
#include "../setup_native_sys.h"
#include "../setup_native_abi.h"
#include "../setup_native_release.h"
#include "../../win64/setup/native_runtime.h"
#include "../../accounts/sha256.h"
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
static uint8_t media[64*512],archive[288+131073+7000];
static unsigned reads,writes,flushes;
static int read_driver(blk_dev_t *d,uint64_t l,unsigned n,void *p){(void)d;reads++;if(driver_fail)return -1;memcpy(p,media+l*512,n*512);return 0;}
static int write_driver(blk_dev_t *d,uint64_t l,unsigned n,const void *p){(void)d;writes++;if(driver_fail)return -1;memcpy(media+l*512,p,n*512);return 0;}
static int flush_driver(blk_dev_t *d){(void)d;flushes++;return driver_fail?-1:0;}
static void dev_init(blk_dev_t *d,const char *name,unsigned port)
{
 memset(d,0,sizeof *d);strcpy(d->name,name);d->sector_size=512;d->sectors=64;d->flags=BLK_F_FLUSH;
 d->read=read_driver;d->write=write_driver;d->flush=flush_driver;
 d->storage.version=SHZ_STORAGE_VERSION;d->storage.size=sizeof d->storage;d->storage.transport=SHZ_STORAGE_SATA;
 d->storage.bus=0;d->storage.device=31;d->storage.function=2;d->storage.unit=port;d->storage.multiplier=0xffff;
 d->storage.sectors=64;d->storage.block_size=512;
}
static void store64(uint8_t *p,uint64_t v){unsigned i;for(i=0;i<8;i++)p[i]=(uint8_t)(v>>(8*i));}
static int fail_copy_out,fail_copy_in;
#ifdef SHZ_TEST_COMPILED_ADMISSION
static archive_source_info_t admitted[2];
#endif
int copy_from_user(process_t *p,void *dst,uint64_t a,uint64_t n)
{(void)p;if(fail_copy_in||!a)return -1;memcpy(dst,(void *)(uintptr_t)a,n);return 0;}
int copy_to_user(process_t *p,uint64_t a,const void *src,uint64_t n)
{(void)p;if(fail_copy_out||!a)return -1;memcpy((void *)(uintptr_t)a,src,n);return 0;}
#ifdef SHZ_TEST_COMPILED_ADMISSION
/* Explicit HOST-ONLY substitute for the absent independent producer. Not
 * compiled into production, no runtime caller can install these records. */
int setup_native_release_available(void){return 1;}
int setup_native_release_source(const archive_source_info_t *info,unsigned role)
{return role>1||info->bytes!=admitted[role].bytes||memcmp(info->sha256,admitted[role].sha256,32)?-1:0;}
int setup_native_release_pair(const archive_source_info_t pair[2])
{return pair[0].bytes!=admitted[0].bytes||pair[1].bytes!=admitted[1].bytes||
 memcmp(pair[0].sha256,admitted[0].sha256,32)||memcmp(pair[1].sha256,admitted[1].sha256,32)?-1:0;}
#endif
static process_t process={51,0};static unsigned transport_calls,legacy_calls,heap_allocs,heap_frees;
int32_t shz_native_call(shz_native_call_v1 *r)
{transport_calls++;return setup_native_syscall(&process,(uint64_t)(uintptr_t)r,sizeof *r);}
void shz_native_call_init(shz_native_call_v1 *r,uint32_t op)
{memset(r,0,sizeof *r);r->version=SHZ_NATIVE_SYS_VERSION;r->bytes=sizeof *r;r->operation=op;}
static void *alloc(void *c,size_t n){(void)c;heap_allocs++;return calloc(1,n);}
static void dealloc(void *c,void *p){(void)c;if(p)heap_frees++;free(p);}
static int random_bytes(void *c,void *p,uint32_t n){(void)c;krandom_get(p,n);return 0;}
static unsigned count(void *c){(void)c;return blk_count();}
static int info(void *c,unsigned index,plat_disk_t *out)
{blk_dev_t *d=blk_get(index);(void)c;if(!d)return -1;memset(out,0,sizeof *out);strcpy(out->name,d->name);out->sectors=d->sectors;out->sector_size=d->sector_size;return 0;}
static int legacy_open(void *c,const char *path,void **h,uint64_t *n){(void)c;(void)path;(void)h;(void)n;legacy_calls++;return -1;}
static int legacy_read(void *c,unsigned i,uint64_t l,uint32_t n,void *b){(void)c;(void)i;(void)l;(void)n;(void)b;legacy_calls++;return -1;}
static int legacy_write(void *c,unsigned i,uint64_t l,uint32_t n,const void *b){return legacy_read(c,i,l,n,(void *)b);}
static int legacy_flush(void *c,unsigned i){(void)c;(void)i;legacy_calls++;return -1;}
int main(int argc,char **argv)
{
 shz_bootinfo_t bi={0},bad;blk_dev_t shadow,target,unknown,alias,other_target;
 shz_native_runtime v={0};plat_t base={0};unsigned i;
#ifndef SHZ_TEST_COMPILED_ADMISSION
 shz_native_runtime zero={0};
#endif
 base.alloc=alloc;base.free=dealloc;base.random=random_bytes;base.disk_count=count;base.disk_info=info;
 base.file_open=legacy_open;base.disk_read=legacy_read;base.disk_write=legacy_write;base.disk_flush=legacy_flush;base.max_io_sectors=2048;
 (void)argc;(void)argv;
 memcpy(archive,"SHZARC01",8);archive[8]=2;
 strcpy((char *)archive+16,"\\SHZ\\INPUTS\\FIRST.BIN");store64(archive+16+120,288);store64(archive+16+128,131073);
 strcpy((char *)archive+152,"\\SHZ\\INPUTS\\SECOND.BIN");store64(archive+152+120,131361);store64(archive+152+128,7000);
 for(i=288;i<sizeof archive;i++)archive[i]=(uint8_t)(i*37);
 fs_init();CHECK(fs_load_archive(archive,sizeof archive)==2);
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


#ifndef SHZ_TEST_COMPILED_ADMISSION
 CHECK(shz_native_runtime_init(&v,&base)==-2);CHECK(!memcmp(&v,&zero,sizeof v));CHECK(transport_calls==1);
 CHECK(!legacy_calls&&!reads&&!writes&&!flushes&&!heap_allocs&&!pages_allocated);
#else
 {plat_t *p;native_setup_ops_v1_t *ops;void *a=0,*b=0,*held=0,*hash;uint64_t bytes;uint8_t out[100000],digest[32],expected[512];native_setup_target_v1_t reviewed,wrong;unsigned before;
 sha256_ctx sha;
 admitted[0].bytes=131073;admitted[1].bytes=7000;
 sha256_init(&sha);sha256_update(&sha,archive+288,131073);sha256_final(&sha,admitted[0].sha256);
 sha256_init(&sha);sha256_update(&sha,archive+131361,7000);sha256_final(&sha,admitted[1].sha256);
 CHECK(shz_native_runtime_init(&v,&base)==0);CHECK(v.initialized&&v.provider.initialized);
 CHECK(shz_native_runtime_init(&v,&base)!=0);CHECK(v.provider.platform.max_io_sectors==128);
 p=&v.provider.platform;ops=&v.provider.ops;v.provider.started=1; /* callback integration only; no complete native install claim */
 CHECK(p->file_open(p->ctx,"C:\\SHZ\\INPUTS\\FIRST.BIN",&a,&bytes)==0&&bytes==131073);
 CHECK(p->file_read(p->ctx,a,0,out,1)!=0); /* provider admission precedes any native source read */
 memcpy(digest,admitted[0].sha256,32);digest[0]^=1;
 CHECK(ops->admit_source(ops->ctx,a,"C:\\SHZ\\INPUTS\\FIRST.BIN",bytes,digest)!=0);
 CHECK(ops->admit_source(ops->ctx,a,"C:\\SHZ\\INPUTS\\FIRST.BIN",bytes,admitted[0].sha256)==0);
 CHECK(ops->check_source(ops->ctx,a)==0);CHECK(p->file_read(p->ctx,a,100,out,100000)==0);CHECK(!memcmp(out,archive+388,100000));
 CHECK(p->file_open(p->ctx,"C:\\SHZ\\INPUTS\\SECOND.BIN",&b,&bytes)==0&&bytes==7000);
 CHECK(ops->admit_source(ops->ctx,b,"C:\\SHZ\\INPUTS\\SECOND.BIN",bytes,admitted[1].sha256)==0);
 hash=ops->sha_begin(ops->ctx);CHECK(hash!=0);CHECK(ops->sha_update(ops->ctx,hash,"abc",3)==0);CHECK(ops->sha_end(ops->ctx,hash,digest)==0);
 {static const uint8_t abc[32]={0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};CHECK(!memcmp(digest,abc,32));}
 hash=ops->sha_begin(ops->ctx);CHECK(hash!=0);CHECK(ops->sha_update(ops->ctx,hash,0,1)!=0);ops->sha_abort(ops->ctx,hash);CHECK(heap_allocs==heap_frees);
 {void *pair[2]={a,b};CHECK(ops->review_target(ops->ctx,0,pair,&reviewed)!=0);CHECK(ops->review_target(ops->ctx,1,pair,&reviewed)==0);
 wrong=reviewed;wrong.generation++;
 CHECK(v.provider.backend.authority.claim_target(v.provider.backend.authority.ctx,&wrong,pair,&held)!=0);CHECK(!held);
 CHECK(ops->claim_target(ops->ctx,&reviewed,pair,&held)==0&&held!=0);
 CHECK(ops->check_target(ops->ctx,held,&reviewed)==0);wrong=reviewed;wrong.disk.sectors++;
 CHECK(ops->check_target(ops->ctx,held,&wrong)!=0);
 memset(expected,0x6b,sizeof expected);
 CHECK(p->disk_info(p->ctx,1,&wrong.disk)==0&&wrong.disk.sectors==64);
 CHECK(p->disk_write(p->ctx,1,0,1,expected)==0);CHECK(writes==1&&!memcmp(media,expected,512));
 CHECK(p->disk_read(p->ctx,1,0,1,out)==0&&!memcmp(out,expected,512));
 CHECK(p->disk_flush(p->ctx,1)==0);CHECK(!legacy_calls);
 if(argc>1&&!strcmp(argv[1],"close-reply-fail")){
  fail_copy_out=1;CHECK(ops->close_source(ops->ctx,a)!=0);fail_copy_out=0;
 }else CHECK(ops->close_source(ops->ctx,a)==0);
 CHECK(ops->close_source(ops->ctx,b)==0);CHECK(ops->check_source(ops->ctx,a)!=0);
 CHECK(ops->check_target(ops->ctx,held,&reviewed)==0);
 if(argc>1&&!strcmp(argv[1],"poison")){
  driver_fail=1;CHECK(p->disk_flush(p->ctx,1)!=0);driver_fail=0;before=pages_freed;
  CHECK(ops->release_target(ops->ctx,held)!=0);CHECK(pages_freed==before);setup_native_process_teardown(&process);
  CHECK(pages_freed==before);CHECK(blk_write(&target,0,1,expected)!=0);
 }else{
  if(argc>1&&!strcmp(argv[1],"release-reply-fail")){
   fail_copy_out=1;CHECK(ops->release_target(ops->ctx,held)!=0);fail_copy_out=0;
  }else CHECK(ops->release_target(ops->ctx,held)==0);
  CHECK(pages_allocated==pages_freed);CHECK(ops->check_target(ops->ctx,held,&reviewed)!=0);
 }
 CHECK(heap_allocs==heap_frees);

 }
 }
#endif
 printf("NATIVE_RUNTIME checks=%u failures=%u legacy_raw_calls=%u producer_scope=" ,checks,failures,legacy_calls);
#ifdef SHZ_TEST_COMPILED_ADMISSION
 printf("HOST_ONLY_MODELED");
#else
 printf("ABSENT_FAILCLOSED");
#endif
 printf(" VM_executed=0\n");return failures?1:0;
}
