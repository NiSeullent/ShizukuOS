/* SPDX-License-Identifier: GPL-2.0-only */
#include "setup_native_host_shim.h"
#include "../setup_native_sys.h"
#include "../setup_native_abi.h"
#include "../setup_native_release.h"
#include "../../win64/setup/native_gui.h"
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
unsigned setup_native_release_state(void){return setup_native_release_available()?1u:2u;}
int setup_native_release_info(unsigned role,uint64_t *bytes,uint8_t sha[32])
{if(role>1||!bytes||!sha)return -1;*bytes=admitted[role].bytes;memcpy(sha,admitted[role].sha256,32);return 0;}
int setup_native_release_source(const archive_source_info_t *info,unsigned role)
{return role>1||info->bytes!=admitted[role].bytes||memcmp(info->sha256,admitted[role].sha256,32)?-1:0;}
int setup_native_release_pair(const archive_source_info_t pair[2])
{return pair[0].bytes!=admitted[0].bytes||pair[1].bytes!=admitted[1].bytes||
 memcmp(pair[0].sha256,admitted[0].sha256,32)||memcmp(pair[1].sha256,admitted[1].sha256,32)?-1:0;}
#endif
static process_t process={51,0};static unsigned transport_calls,legacy_calls,heap_allocs,heap_frees;
static int fail_operation=-1;
int32_t shz_native_call(shz_native_call_v1 *r)
{
 int32_t rc;transport_calls++;
 if((int)r->operation==fail_operation){fail_copy_out=1;fail_operation=-1;}
 rc=setup_native_syscall(&process,(uint64_t)(uintptr_t)r,sizeof *r);
 fail_copy_out=0;return rc;
}
void shz_native_call_init(shz_native_call_v1 *r,uint32_t op)
{memset(r,0,sizeof *r);r->version=SHZ_NATIVE_SYS_VERSION;r->bytes=sizeof *r;r->operation=op;}
static void *alloc(void *c,size_t n){(void)c;heap_allocs++;return calloc(1,n);}
static void dealloc(void *c,void *p){(void)c;if(p)heap_frees++;free(p);}
static int random_bytes(void *c,void *p,uint32_t n){(void)c;krandom_get(p,n);return 0;}
static unsigned count(void *c){(void)c;return blk_count();}
static int info(void *c,unsigned index,plat_disk_t *out)
{blk_dev_t *d=blk_get(index);(void)c;if(!d)return -1;memset(out,0,sizeof *out);strcpy(out->name,d->name);out->sectors=d->sectors;out->sector_size=d->sector_size;strcpy(out->serial,d->serial);return 0;}
static int legacy_open(void *c,const char *path,void **h,uint64_t *n){(void)c;(void)path;(void)h;(void)n;legacy_calls++;return -1;}
static int legacy_read(void *c,unsigned i,uint64_t l,uint32_t n,void *b){(void)c;(void)i;(void)l;(void)n;(void)b;legacy_calls++;return -1;}
static int legacy_write(void *c,unsigned i,uint64_t l,uint32_t n,const void *b){return legacy_read(c,i,l,n,(void *)b);}
static int legacy_flush(void *c,unsigned i){(void)c;(void)i;legacy_calls++;return -1;}

int main(int argc,char **argv)
{
 shz_bootinfo_t bi={0};blk_dev_t target,shadow;plat_t base={0};shz_native_gui gui={0};native_setup_target_v1_t reviewed,bad;
 native_setup_result_v1_t result;sha256_ctx sha;unsigned i,before;
 (void)argc;(void)argv;
 base.alloc=alloc;base.free=dealloc;base.random=random_bytes;base.disk_count=count;base.disk_info=info;
 base.file_open=legacy_open;base.disk_read=legacy_read;base.disk_write=legacy_write;base.disk_flush=legacy_flush;base.max_io_sectors=2048;
 memcpy(archive,"SHZARC01",8);archive[8]=2;
 strcpy((char *)archive+16,"\\SHZ\\SETUP\\NATIVE\\MANIFEST.JSON");store64(archive+16+120,288);store64(archive+16+128,131073);
 strcpy((char *)archive+152,"\\SHZ\\SETUP\\NATIVE\\ESP.SIM");store64(archive+152+120,131361);store64(archive+152+128,7000);
 for(i=288;i<sizeof archive;i++)archive[i]=(uint8_t)(i*37);
 fs_init();CHECK(fs_load_archive(archive,sizeof archive)==2);
 bi.magic=SHZ_BOOTINFO_MAGIC;bi.abi_major=SHZ_ABI_MAJOR;bi.size=sizeof bi;bi.domain_id=SHZ_DOM_KERNEL64;
 bi.flags=SHZ_BIF_UEFI_DIRECT;bi.initrd_gpa=(uint64_t)(uintptr_t)archive;bi.initrd_size=sizeof archive;bi.ram_size=bi.initrd_gpa+sizeof archive;
 bi.storage.magic=SHZ_STORAGE_MAGIC;bi.storage.version=SHZ_STORAGE_VERSION;bi.storage.size=sizeof bi.storage;bi.storage.flags=SHZ_STORAGE_ARCHIVE_READ;
 bi.storage.boot.version=SHZ_STORAGE_VERSION;bi.storage.boot.size=sizeof bi.storage.boot;bi.storage.boot.transport=SHZ_STORAGE_SATA;
 bi.storage.boot.device=31;bi.storage.boot.function=2;bi.storage.boot.unit=0;bi.storage.boot.multiplier=0xffff;
 bi.storage.boot.sectors=1000;bi.storage.boot.block_size=2048;bi.storage.boot.media_flags=SHZ_STORAGE_READONLY|SHZ_STORAGE_REMOVABLE;
 bi.storage.archive=bi.storage.boot;bi.storage.archive_gpa=bi.initrd_gpa;bi.storage.archive_size=sizeof archive;
 dev_init(&shadow,"shadow",0);CHECK(blk_register(&shadow)==0);
 dev_init(&target,"target",1);target.sectors=6000000;target.storage.sectors=target.sectors;strcpy(target.serial,"HOST-MODELED-TARGET");CHECK(blk_register(&target)==0);
 CHECK(k64_boot_storage_bind(&bi,1)==0);
#ifndef SHZ_TEST_COMPILED_ADMISSION
 CHECK(shz_native_gui_prepare(&gui,&base)==-2);CHECK(!gui.prepared);
 CHECK(!pages_allocated&&!reads&&!writes&&!flushes&&!legacy_calls);
#else
 /* Explicit HOST-only admission for malformed tiny fixtures: this verifies
  * actual GUI/runtime/syscall custody, not genuine Windows or successful copy. */
 admitted[0].bytes=131073;admitted[1].bytes=7000;
 sha256_init(&sha);sha256_update(&sha,archive+288,131073);sha256_final(&sha,admitted[0].sha256);
 sha256_init(&sha);sha256_update(&sha,archive+131361,7000);sha256_final(&sha,admitted[1].sha256);
 CHECK(shz_native_gui_prepare(&gui,&base)==0);CHECK(gui.prepared);
 CHECK(gui.runtime.source[0].live&&gui.runtime.source[1].live);
 CHECK(!legacy_calls&&!reads&&!writes&&!flushes);
 CHECK(shz_native_gui_review(&gui,0,&reviewed)!=0); /* real loader source backing exclusion */
 CHECK(shz_native_gui_review(&gui,1,&reviewed)==0);
 CHECK(reviewed.generation&&reviewed.disk.sectors==6000000);
 bad=reviewed;bad.generation++;CHECK(shz_native_gui_confirm(&gui,&bad,"ERASE")!=0);
 CHECK(shz_native_gui_confirm(&gui,&reviewed,"erase")!=0);
 CHECK(shz_native_gui_confirm(&gui,&reviewed,"ERASE")==0);
 CHECK(!reads&&!writes&&!flushes&&!legacy_calls);
 before=pages_allocated;
 shz_native_gui_run(&gui,&result);
 CHECK(!result.ok&&!result.target_write_attempted); /* malformed manifest rejected by real core */
 CHECK(strstr(result.reason,"manifest")!=0);
 CHECK(pages_allocated==before); /* run adopts the same snapshots, never reopens arbitrary namespace */
 CHECK(!gui.runtime.source[0].live&&!gui.runtime.source[1].live);
 CHECK(pages_allocated==pages_freed);CHECK(heap_allocs==heap_frees);
 CHECK(!reads&&!writes&&!flushes&&!legacy_calls);
 CHECK(shz_native_gui_close(&gui)==0);
 /* Cancellation releases both actual admitted snapshots. */
 memset(&gui,0,sizeof gui);CHECK(shz_native_gui_prepare(&gui,&base)==0);
 CHECK(shz_native_gui_close(&gui)==0);CHECK(pages_allocated==pages_freed);
 /* A changed physical epoch during the preview invalidates final confirmation. */
 memset(&gui,0,sizeof gui);CHECK(shz_native_gui_prepare(&gui,&base)==0);
 CHECK(shz_native_gui_review(&gui,1,&reviewed)==0);
 CHECK(blk_authority_enter(&target,1)==0);blk_authority_leave(&target,0,1);
 CHECK(shz_native_gui_confirm(&gui,&reviewed,"ERASE")!=0);
 CHECK(shz_native_gui_close(&gui)==0);CHECK(pages_allocated==pages_freed);
 /* Failure replies cannot turn cleanup into a successful installation. */
 memset(&gui,0,sizeof gui);CHECK(shz_native_gui_prepare(&gui,&base)==0);
 fail_operation=SHZ_NATIVE_CLOSE;CHECK(shz_native_gui_close(&gui)!=0);
 CHECK(pages_allocated==pages_freed);
 memset(&gui,0,sizeof gui);fail_operation=SHZ_NATIVE_ADMIT;
 CHECK(shz_native_gui_prepare(&gui,&base)!=0);CHECK(!gui.prepared);
 CHECK(pages_allocated==pages_freed);
 memset(&gui,0,sizeof gui);fail_operation=SHZ_NATIVE_OPEN;
 CHECK(shz_native_gui_prepare(&gui,&base)!=0);CHECK(!gui.prepared);
 CHECK(pages_allocated==pages_freed);
 CHECK(!reads&&!writes&&!flushes&&!legacy_calls);
#endif
 (void)sha;(void)before;(void)reviewed;(void)bad;(void)result;
 setup_native_process_teardown(&process);
 printf("NATIVE_GUI_HOST: checks=%u failures=%u production_absence_or_HOST_ONLY_admission_no_install\n",checks,failures);
 return failures?1:0;
}
