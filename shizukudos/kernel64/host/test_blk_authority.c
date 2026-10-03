/* SPDX-License-Identifier: GPL-2.0-only */
#include "blk_authority_host_shim.h"
#include "../blk_authority.h"
#include "../vfs_mounts.h"
#include "../boot_storage.h"
#include <stdio.h>
#include <time.h>
static unsigned checks,failures,reads,writes,flushes,controls,random_seq;
#define CHECK(x) do{checks++;if(!(x)){failures++;fprintf(stderr,"FAIL %u %s\n",(unsigned)__LINE__,#x);}}while(0)
void mutex_init(kmutex_t *m){if(pthread_mutex_init(m,0))abort();}
void mutex_lock(kmutex_t *m){if(pthread_mutex_lock(m))abort();}
void mutex_unlock(kmutex_t *m){if(pthread_mutex_unlock(m))abort();}
uint64_t irq_save(void){return 0;}
void irq_restore(uint64_t f){(void)f;}
void krandom_get(void *p,size_t n){size_t i;random_seq++;for(i=0;i<n;i++)((uint8_t *)p)[i]=(uint8_t)(random_seq*17+i);}
void kprintf(const char *f,...){(void)f;}
void *kmalloc(size_t n){return malloc(n);}
void kfree(void *p){free(p);}
uint64_t kernel_pml4(void){return 0;}
uint64_t p2v(uint64_t x){return x;}
static uint8_t media[512*64];
static int failing,blocking,driver_entered,driver_continue;
static pthread_mutex_t rendezvous=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition=PTHREAD_COND_INITIALIZER;
static int read_driver(blk_dev_t *d,uint64_t l,unsigned n,void *b)
{(void)d;reads++;if(failing)return -1;memcpy(b,media+l*512,n*512);return 0;}
static int write_driver(blk_dev_t *d,uint64_t l,unsigned n,const void *b)
{
 (void)d;writes++;
 if(blocking){pthread_mutex_lock(&rendezvous);driver_entered=1;pthread_cond_broadcast(&condition);
 while(!driver_continue)pthread_cond_wait(&condition,&rendezvous);
 pthread_mutex_unlock(&rendezvous);}
 if(failing)return -1;
 memcpy(media+l*512,b,n*512);return 0;
}
static int flush_driver(blk_dev_t *d){(void)d;flushes++;return failing?-1:0;}
static int discard_driver(blk_dev_t *d,uint64_t l,unsigned n){(void)d;(void)l;(void)n;writes++;return 0;}
static int control_driver(blk_dev_t *d,unsigned op,uint64_t a,uint64_t *o){(void)d;(void)op;(void)a;(void)o;controls++;return failing?-2:0;}
static void device(blk_dev_t *d,const char *name)
{
 memset(d,0,sizeof *d);strcpy(d->name,name);d->sector_size=512;d->sectors=64;d->flags=BLK_F_FLUSH;
 d->read=read_driver;d->write=write_driver;d->flush=flush_driver;d->discard=discard_driver;d->control=control_driver;
 d->storage.version=SHZ_STORAGE_VERSION;d->storage.size=sizeof d->storage;d->storage.transport=SHZ_STORAGE_SATA;
 d->storage.multiplier=0xffff;d->storage.unit=blk_count();d->storage.sectors=d->sectors;d->storage.block_size=d->sector_size;
 CHECK(blk_register(d)==0);
}
static void *owner=(void *)(uintptr_t)1;
static blk_dev_t boot,source,other,target,partition;
static blk_authority_source_t sources[2];
static blk_authority_identity_t review;
static blk_authority_claim_t *held_claim;
static int claimed_rc,raw_rc;static uint8_t data[512];
static void *claimed_worker(void *unused)
{(void)unused;claimed_rc=blk_authority_write(owner,held_claim,&review,2,1,data);return 0;}
static void *raw_worker(void *unused){(void)unused;raw_rc=blk_write(&target,3,1,data);return 0;}
static int completion_status;
static void completed(void *ctx,int status){(void)ctx;completion_status=status;}
int main(int argc,char **argv)
{
 uint8_t out[512];unsigned before;blk_authority_identity_t stale,forged;blk_authority_claim_t *second=0;
 pthread_t a,b;struct timespec tiny={0,20000000};
 device(&boot,"boot");device(&source,"source");device(&other,"other");device(&target,"target");
 partition=target;strcpy(partition.name,"targetp1");partition.parent=&target;partition.flags=BLK_F_PARTITION;
 partition.start_lba=4;partition.sectors=16;CHECK(blk_register(&partition)==0);
 CHECK(blk_authority_pin_source(&source,&sources[0])==0);
 stale=sources[0].identity;failing=1;
 CHECK(blk_read(&source,0,1,out)!=0);failing=0;
 CHECK(blk_read(&source,0,1,out)==0);
 CHECK(blk_authority_pin_source(&source,&sources[0])==0);
 CHECK(stale.generation!=sources[0].identity.generation);
 stale=sources[0].identity;failing=1;
 CHECK(blk_control(&source,BLK_CTL_STATS,0,0)==-2);failing=0;
 CHECK(blk_control(&source,BLK_CTL_STATS,0,0)==0);
 CHECK(blk_read(&source,0,1,out)==0);
 CHECK(blk_authority_pin_source(&source,&sources[0])==0);
 CHECK(stale.generation!=sources[0].identity.generation);
 CHECK(blk_read(&partition,16,1,out)!=0);
 CHECK(blk_read(&partition,0,1,out)==0);
 stale=sources[0].identity;CHECK(blk_write(&source,0,1,data)==0);
 CHECK(blk_authority_pin_source(&source,&sources[0])==0);CHECK(stale.generation!=sources[0].identity.generation);
 stale=sources[0].identity;CHECK(blk_discard(&source,0,1)==0);
 CHECK(blk_authority_pin_source(&source,&sources[0])==0);CHECK(stale.generation!=sources[0].identity.generation);
 sources[1]=sources[0];
 CHECK(blk_authority_review(&target,sources,&review)!=0); /* missing actual roles */
 CHECK(blk_authority_bind_boot_roles(0,&boot)!=0);
 {shz_bootinfo_t bi={0};
 bi.magic=SHZ_BOOTINFO_MAGIC;bi.abi_major=SHZ_ABI_MAJOR;bi.size=sizeof bi;bi.domain_id=SHZ_DOM_KERNEL64;
 bi.flags=SHZ_BIF_UEFI_DIRECT;bi.initrd_gpa=0x2000000;bi.initrd_size=16;
 bi.storage.magic=SHZ_STORAGE_MAGIC;bi.storage.version=SHZ_STORAGE_VERSION;bi.storage.size=sizeof bi.storage;
 bi.storage.flags=SHZ_STORAGE_ARCHIVE_READ;bi.storage.boot=boot.storage;bi.storage.archive=boot.storage;
 bi.storage.archive_gpa=bi.initrd_gpa;bi.storage.archive_size=bi.initrd_size;
 CHECK(k64_boot_storage_bind(&bi,0)!=0);bi.size=472;CHECK(k64_boot_storage_bind(&bi,1)!=0);bi.size=sizeof bi;
 bi.storage.version++;CHECK(k64_boot_storage_bind(&bi,1)!=0);bi.storage.version--;
 bi.flags=0;CHECK(k64_boot_storage_bind(&bi,1)!=0);bi.flags=SHZ_BIF_UEFI_DIRECT;
 bi.storage.archive_gpa++;CHECK(k64_boot_storage_bind(&bi,1)!=0);bi.storage.archive_gpa--;
 bi.storage.boot.unit=31;CHECK(k64_boot_storage_bind(&bi,1)!=0);bi.storage.boot=boot.storage;
 CHECK(k64_boot_storage_bind(&bi,1)==0); /* actual binder; loader/driver observations modeled */
 }
 CHECK(blk_authority_review(&boot,sources,&review)!=0);
 CHECK(blk_authority_review(&source,sources,&review)!=0);
 CHECK(blk_authority_review(&partition,sources,&review)!=0);
 {fsnode_t mount_root={0};fsvol_t volume={0};
 CHECK(vfs_mount_next(&mount_root,&volume,"fixture","other",0)==0);
 CHECK(!(other.flags&BLK_F_MOUNTED));CHECK(vfs_mount_count()==0);
 CHECK(blk_read(&other,0,1,out)==0);
 mount_root.is_dir=1;
 CHECK(vfs_mount_next(&mount_root,&volume,"fixture","other",0)=='D');
 CHECK(other.flags&BLK_F_MOUNTED);CHECK(vfs_mount_count()==1);
 mount_root.is_dir=0;
 CHECK(vfs_mount_next(&mount_root,&volume,"fixture","other",0)==0);
 CHECK(other.flags&BLK_F_MOUNTED);CHECK(vfs_mount_count()==1);
 }
 CHECK(blk_authority_review(&other,sources,&review)!=0);
 CHECK(blk_authority_review(&target,sources,&review)==0);stale=review;
 CHECK(memcmp(review.whole_id,sources[0].identity.whole_id,16)!=0);
 forged=review;forged.generation++;
 CHECK(blk_authority_claim_target(owner,&target,&forged,sources,&held_claim)!=0);
 CHECK(blk_authority_claim_target(owner,&target,&review,sources,&held_claim)==0);
 CHECK(blk_authority_claim_target((void *)2,&target,&review,sources,&second)!=0);
 CHECK(blk_authority_check((void *)2,held_claim,&review)!=0);
 CHECK(blk_authority_check(owner,held_claim,&forged)!=0);
 CHECK(blk_authority_bind_boot_roles(&boot,&boot)!=0);
 CHECK(blk_authority_mark_mounted(&target)!=0);
 {blk_authority_source_t alternate[2];CHECK(blk_authority_pin_source(&other,&alternate[0])==0);
 alternate[1]=alternate[0];CHECK(blk_authority_review(&source,alternate,&forged)!=0);}
 before=writes;completion_status=0;CHECK(blk_write_async(&target,0,1,data,completed,0)==0);
 CHECK(completion_status!=0 && writes==before);
 before=writes;CHECK(blk_write(&target,0,1,data)!=0);CHECK(blk_write(&partition,0,1,data)!=0);
 CHECK(blk_write(&source,0,1,data)!=0);CHECK(blk_discard(&source,0,1)!=0);
 CHECK(writes==before);before=reads;CHECK(blk_read(&target,0,1,out)!=0);CHECK(reads==before);
 CHECK(blk_read(&source,0,1,out)==0);CHECK(blk_flush(&source)!=0);CHECK(blk_flush(&target)!=0);
 before=controls;CHECK(blk_control(&target,BLK_CTL_RESET,0,0)!=0);CHECK(blk_control(&source,BLK_CTL_RESET,0,0)!=0);CHECK(controls==before);
 memset(data,0x53,sizeof data);CHECK(blk_authority_write(owner,held_claim,&review,1,1,data)==0);
 CHECK(blk_authority_read(owner,held_claim,&review,1,1,out)==0);CHECK(!memcmp(data,out,512));
 CHECK(blk_authority_flush(owner,held_claim,&review)==0);
 before=writes;CHECK(blk_authority_write(owner,held_claim,&review,64,1,data)!=0);CHECK(writes==before);
 blocking=1;CHECK(pthread_create(&a,0,claimed_worker,0)==0);
 pthread_mutex_lock(&rendezvous);while(!driver_entered)pthread_cond_wait(&condition,&rendezvous);pthread_mutex_unlock(&rendezvous);
 CHECK(pthread_create(&b,0,raw_worker,0)==0);nanosleep(&tiny,0);
 pthread_mutex_lock(&rendezvous);driver_continue=1;pthread_cond_broadcast(&condition);pthread_mutex_unlock(&rendezvous);
 CHECK(pthread_join(a,0)==0);CHECK(pthread_join(b,0)==0);CHECK(claimed_rc==0 && raw_rc!=0);blocking=0;
 CHECK(blk_authority_release(owner,held_claim,&review)==0);
 CHECK(blk_authority_check(owner,held_claim,&stale)!=0);
 CHECK(blk_authority_claim_target(owner,&target,&stale,sources,&second)!=0);
 CHECK(blk_write(&partition,1,1,data)==0);CHECK(!memcmp(media+5*512,data,512));
 CHECK(blk_authority_review(&target,sources,&review)==0);stale=review;
 CHECK(blk_control(&target,BLK_CTL_RESET,0,0)==0);
 CHECK(blk_authority_claim_target(owner,&target,&stale,sources,&second)!=0);
 CHECK(blk_authority_review(&target,sources,&review)==0);
 CHECK(blk_authority_claim_target(owner,&target,&review,sources,&held_claim)==0);
 CHECK(blk_authority_release(owner,held_claim,&stale)!=0);
 CHECK(blk_authority_check(owner,held_claim,&review)==0);
 failing=1;
 if(argc>1 && !strcmp(argv[1],"read"))CHECK(blk_authority_read(owner,held_claim,&review,0,1,out)!=0);
 else if(argc>1 && !strcmp(argv[1],"flush"))CHECK(blk_authority_flush(owner,held_claim,&review)!=0);
 else CHECK(blk_authority_write(owner,held_claim,&review,0,1,data)!=0);
 failing=0;
 before=writes;CHECK(blk_authority_write(owner,held_claim,&review,0,1,data)!=0);CHECK(writes==before);
 CHECK(blk_authority_release(owner,held_claim,&review)!=0);CHECK(blk_write(&target,0,1,data)!=0);
 CHECK(blk_authority_claim_target((void *)2,&target,&review,sources,&second)!=0);
 printf("BLK_AUTHORITY checks=%u failures=%u real_pthread_serialization=1 kernel_roles_modeled=1 VM_executed=0\n",checks,failures);
 return failures?1:0;
}
