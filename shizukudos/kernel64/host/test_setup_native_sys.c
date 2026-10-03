/* SPDX-License-Identifier: GPL-2.0-only */
#include "setup_native_host_shim.h"
#include "../setup_native_sys.h"
#include "../setup_native_abi.h"
#include "../setup_native_release.h"
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
static archive_source_info_t admitted[2];
int copy_from_user(process_t *p,void *dst,uint64_t a,uint64_t n)
{(void)p;if(fail_copy_in||!a)return -1;memcpy(dst,(void *)(uintptr_t)a,n);return 0;}
int copy_to_user(process_t *p,uint64_t a,const void *src,uint64_t n)
{(void)p;if(fail_copy_out||!a)return -1;memcpy((void *)(uintptr_t)a,src,n);return 0;}
#ifdef SHZ_TEST_COMPILED_ADMISSION
/* Explicit HOST-ONLY substitute for the absent independent producer. Not
 * compiled into production, no runtime caller can install these records. */
int setup_native_release_available(void){return 1;}
int setup_native_release_pair(const archive_source_info_t pair[2])
{return pair[0].bytes!=admitted[0].bytes||pair[1].bytes!=admitted[1].bytes||
 memcmp(pair[0].sha256,admitted[0].sha256,32)||memcmp(pair[1].sha256,admitted[1].sha256,32)?-1:0;}
#endif
static int32_t call(process_t *p,shz_native_call_v1 *r)
{return setup_native_syscall(p,(uint64_t)(uintptr_t)r,sizeof *r);}
static void init(shz_native_call_v1 *r,unsigned op)
{memset(r,0,sizeof *r);r->version=SHZ_NATIVE_SYS_VERSION;r->bytes=sizeof *r;r->operation=op;}
int main(int argc,char **argv)
{
 shz_bootinfo_t bi={0},bad;blk_dev_t shadow,target,unknown,alias,other_target;
 shz_native_call_v1 r;uint64_t a,b;unsigned before,i;
#ifdef SHZ_TEST_COMPILED_ADMISSION
 shz_native_target_v1 reviewed;uint64_t claim;uint8_t expected[512];
#endif
 process_t process={41,0},other={42,0};uint8_t out[6000];int created;
 (void)argc;(void)argv;
 memcpy(archive,"SHZARC01",8);archive[8]=2;
 strcpy((char *)archive+16,"\\SHZ\\INPUTS\\FIRST.BIN");store64(archive+16+120,288);store64(archive+16+128,10000);
 strcpy((char *)archive+152,"\\SHZ\\INPUTS\\SECOND.BIN");store64(archive+152+120,10288);store64(archive+152+128,7000);
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

 init(&r,SHZ_NATIVE_CAPS);CHECK(call(&process,&r)==STATUS_SUCCESS);
 CHECK(r.max_source_bytes==(256ull<<20)&&r.max_io_bytes==65536);
#ifdef SHZ_TEST_COMPILED_ADMISSION
 CHECK(r.producer_admission_available==1);
#else
 CHECK(r.producer_admission_available==0);
#endif
 r.version++;CHECK(call(&process,&r)==STATUS_INVALID_PARAMETER);r.version--;
 CHECK(setup_native_syscall(&process,(uint64_t)(uintptr_t)&r,sizeof r-1)==STATUS_INFO_LENGTH_MISMATCH);
 r.reserved=1;CHECK(call(&process,&r)==STATUS_INVALID_PARAMETER);
 init(&r,SHZ_NATIVE_OPEN);memset(r.path,'x',sizeof r.path);CHECK(call(&process,&r)==STATUS_INVALID_PARAMETER);
 strcpy(r.path,"C:\\SHZ\\INPUTS\\FIRST.BIN");fail_copy_in=1;CHECK(call(&process,&r)==STATUS_ACCESS_VIOLATION);fail_copy_in=0;
 before=pages_freed;fail_copy_out=1;CHECK(call(&process,&r)==STATUS_ACCESS_VIOLATION);fail_copy_out=0;CHECK(pages_freed==before+3);
 CHECK(call(&process,&r)==STATUS_SUCCESS);a=r.handle;memcpy(&admitted[0],&r.source,sizeof r.source);
 init(&r,SHZ_NATIVE_READ);r.handle=a;r.offset=3500;r.length=6000;r.buffer=(uint64_t)(uintptr_t)out;
 CHECK(call(&other,&r)==STATUS_INVALID_HANDLE);CHECK(call(&process,&r)==STATUS_SUCCESS);CHECK(!memcmp(out,archive+288+3500,6000));
 r.length=65537;CHECK(call(&process,&r)==STATUS_INVALID_PARAMETER);r.length=6000;r.offset=9999;CHECK(call(&process,&r)!=STATUS_SUCCESS);
 init(&r,SHZ_NATIVE_OPEN);strcpy(r.path,"C:\\SHZ\\INPUTS\\SECOND.BIN");CHECK(call(&process,&r)==STATUS_SUCCESS);b=r.handle;memcpy(&admitted[1],&r.source,sizeof r.source);
 CHECK(call(&process,&r)!=STATUS_SUCCESS); /* two source slots only */
 {fsnode_t *node=fs_create("C:\\TEMP\\CREATED.BIN",0,&created);CHECK(node!=0);CHECK(fs_write(node,0,"x",1)==0);node->readonly=1;}
 init(&r,SHZ_NATIVE_REVIEW);r.handle=a;r.other_handle=b;r.index=1;
#ifndef SHZ_TEST_COMPILED_ADMISSION
 CHECK(call(&process,&r)==STATUS_ACCESS_DENIED);CHECK(!writes&&!reads&&!flushes);
 init(&r,SHZ_NATIVE_CLOSE);r.handle=a;CHECK(call(&process,&r)==STATUS_SUCCESS);CHECK(call(&process,&r)==STATUS_INVALID_HANDLE);
 init(&r,SHZ_NATIVE_OPEN);strcpy(r.path,"C:\\TEMP\\CREATED.BIN");CHECK(call(&process,&r)!=STATUS_SUCCESS);
 setup_native_process_teardown(&process);CHECK(pages_allocated==pages_freed);
#else
 CHECK(call(&process,&r)==STATUS_SUCCESS);reviewed=r.target;
 r.handle=b;r.other_handle=a;CHECK(call(&process,&r)==STATUS_ACCESS_DENIED);r.handle=a;r.other_handle=b;
 r.operation=SHZ_NATIVE_CLAIM;r.target.generation++;CHECK(call(&process,&r)!=STATUS_SUCCESS);r.target=reviewed;
 fail_copy_out=1;CHECK(call(&process,&r)==STATUS_ACCESS_VIOLATION);fail_copy_out=0;
 r.operation=SHZ_NATIVE_REVIEW;CHECK(call(&process,&r)==STATUS_SUCCESS);reviewed=r.target;
 r.operation=SHZ_NATIVE_CLAIM;CHECK(call(&process,&r)==STATUS_SUCCESS);claim=r.handle;
 init(&r,SHZ_NATIVE_TARGET_WRITE);r.handle=claim;r.target=reviewed;r.length=512;r.buffer=(uint64_t)(uintptr_t)expected;memset(expected,0x5a,sizeof expected);
 CHECK(call(&other,&r)==STATUS_INVALID_HANDLE);CHECK(!writes);
 r.target.sectors++;CHECK(call(&process,&r)==STATUS_INVALID_HANDLE);r.target=reviewed;
 fail_copy_in=1;CHECK(call(&process,&r)==STATUS_ACCESS_VIOLATION);fail_copy_in=0;CHECK(!writes);
 CHECK(call(&process,&r)==STATUS_SUCCESS);CHECK(writes==1&&!memcmp(media,expected,512));
 r.operation=SHZ_NATIVE_TARGET_READ;r.buffer=(uint64_t)(uintptr_t)out;CHECK(call(&process,&r)==STATUS_SUCCESS);CHECK(!memcmp(out,expected,512));
 init(&r,SHZ_NATIVE_CLOSE);r.handle=a;CHECK(call(&process,&r)==STATUS_SUCCESS);r.handle=b;CHECK(call(&process,&r)==STATUS_SUCCESS);
 init(&r,SHZ_NATIVE_CHECK);r.handle=claim;r.target=reviewed;CHECK(call(&process,&r)==STATUS_SUCCESS);
 if(argc>1&&!strcmp(argv[1],"poison")){
  driver_fail=1;r.operation=SHZ_NATIVE_FLUSH;CHECK(call(&process,&r)!=STATUS_SUCCESS);driver_fail=0;
  before=pages_freed;r.operation=SHZ_NATIVE_RELEASE;CHECK(call(&process,&r)!=STATUS_SUCCESS);CHECK(pages_freed==before);
  setup_native_process_teardown(&process);CHECK(pages_freed==before);CHECK(blk_write(&target,0,1,expected)!=0);
  process.pid++;CHECK(call(&process,&r)==STATUS_INVALID_HANDLE); /* recycled address cannot inherit claim */
 }else{
  setup_native_process_teardown(&process);CHECK(pages_allocated==pages_freed);CHECK(call(&process,&r)==STATUS_INVALID_HANDLE);
 }
#endif
 printf("NATIVE_SYS checks=%u failures=%u production_admission=" ,checks,failures);
#ifdef SHZ_TEST_COMPILED_ADMISSION
 printf("HOST_ONLY_MODELED_NOT_PRODUCER");
#else
 printf("ABSENT_FAILCLOSED");
#endif
 printf(" actual_archive_authority_syscall_core=1 usercopy_IRQ_PMM_driver_modeled=1 VM_executed=0\n");
 return failures?1:0;
}
