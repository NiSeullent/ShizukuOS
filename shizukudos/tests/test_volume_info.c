/* SPDX-License-Identifier: GPL-2.0-only
 * Host adapters around exact extracted production volume-query functions.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fat32.h"
#include "sfs.h"
typedef struct thread thread_t;
typedef struct { volatile int locked; thread_t *owner; thread_t *waiters; } kmutex_t;
typedef struct blk_dev blk_dev_t;
typedef struct { int unused; } process_t;
struct regs { int unused; };
typedef struct { void *file; } file_union;
typedef struct { struct { file_union file; } u; } kobject_t;
enum { FSB_RAM, FSB_DISK, OB_FILE = 3, FS_NAME_MAX = 128 };
#define STATUS_INVALID_DEVICE_REQUEST ((int32_t)0xc0000010)
#define STATUS_INFO_LENGTH_MISMATCH ((int32_t)0xc0000004)
#define STATUS_INVALID_HANDLE ((int32_t)0xc0000008)
#define STATUS_ACCESS_VIOLATION ((int32_t)0xc0000005)
#define STATUS_ACCESS_DENIED ((int32_t)0xc0000022)
#define STATUS_NOT_SUPPORTED ((int32_t)0xc00000bb)
#define STATUS_UNSUCCESSFUL ((int32_t)0xc0000001)
#define STATUS_BUFFER_OVERFLOW ((int32_t)0x80000005)
#define STATUS_INVALID_INFO_CLASS ((int32_t)0xc0000003)
#define STATUS_SUCCESS 0
#define K64_VOLUME_SERIAL 0x53485a31u
static unsigned assertions, locks, bad_locks, copies, stat_calls;
static kmutex_t *expected_lock;
static kobject_t obj;
static uint32_t info_class;
static sfs_statfs_t sfs_info;
static int stat_error;
static int node_allowed=1;
struct fsnode;
#define CHECK(x) do { ++assertions; if (!(x)) { fprintf(stderr,"line %u: %s\n",(unsigned)__LINE__,#x); exit(1); } } while(0)
static int shz_auth_node_access(process_t *p,const struct fsnode *n,int write) { (void)p;(void)n;CHECK(write==0);return node_allowed; }
static void mutex_lock(kmutex_t *m) {
    if(m != expected_lock) { ++bad_locks; fprintf(stderr,"wrong filesystem mutex target (FAT cast of SFS private state)\n"); exit(1); }
    CHECK(!m->locked); m->locked=1; ++locks;
}
static void mutex_unlock(kmutex_t *m) { CHECK(m==expected_lock && m->locked); m->locked=0; }
static int copy_to_user(process_t *p,uint64_t dst,const void *src,uint64_t bytes) {
    (void)p; ++copies; memcpy((void *)(uintptr_t)dst,src,(size_t)bytes); return 0;
}
static kobject_t *handle_lookup(process_t *p,uint64_t h,int type) { (void)p;(void)type;return h==1?&obj:0; }
static int64_t stack_arg(process_t *p,struct regs *r,unsigned n) { (void)p;(void)r;CHECK(n==5);return info_class; }
static uint64_t ticks_now(void) { return 10; }
static int64_t filetime_now(void) { return 1000000; }
static size_t kheap_total(void) { return 12u<<20; }
static size_t kheap_used(void) { return 4u<<20; }
int sfs_statfs(sfs_fs *fs,sfs_statfs_t *out) {
    CHECK(fs!=0 && expected_lock && expected_lock->locked); ++stat_calls;
    if(stat_error)return stat_error;
    *out=sfs_info;return 0;
}
typedef struct { struct fsnode *node; int console; } file_t;
static file_t *k32_file_of(process_t *p,uint64_t h) { kobject_t *o=handle_lookup(p,h,OB_FILE);return o?o->u.file.file:0; }
#include "production.inc"
static int dummy_write(fsvol_t *v,fsnode_t *n,uint64_t o,const void *b,uint64_t z) { (void)v;(void)n;(void)o;(void)b;(void)z;return 0; }
static int fat_write(void *c,uint64_t l,const void *b) { (void)c;(void)l;(void)b;return 0; }
#if HAVE_VOLUME_CALLBACK
static int bad_volume_info(fsvol_t *v,fs_volume_info_t *out) {
    (void)v;memset(out,0,sizeof *out);out->bytes_per_sector=512;out->sectors_per_unit=8;
    memset(out->label,'x',sizeof out->label);return 0;
}
#endif
static int32_t query(file_t *f,uint32_t cls,uint8_t *buf,unsigned len,uint64_t io[2]) {
    process_t p={0};struct regs r={0};obj.u.file.file=f;info_class=cls;
    return sys_query_volume(&p,&r,1,(uint64_t)(uintptr_t)io,(uint64_t)(uintptr_t)buf,len);
}
static void wide_eq(const uint8_t *p,const char *s) { for(size_t i=0;s[i];i++)CHECK(p[2*i]==(unsigned char)s[i] && p[2*i+1]==0); }
int main(void) {
    (void)&dvol;
    sfsk_vol *sv=calloc(1,sizeof *sv);CHECK(sv!=0);
    sv->fs=(sfs_fs *)(uintptr_t)1;sv->vol.priv=sv;sv->vol.write=dummy_write;
    sv->root.backing=FSB_DISK;sv->root.vol=&sv->vol;
    sfs_info.block_size=4096;sfs_info.blocks=49152;sfs_info.free_blocks=42000;
    memcpy(sfs_info.label,"SHZSFS",7);sfs_info.uuid[0]=1;sfs_info.uuid[15]=2;
#if HAVE_VOLUME_CALLBACK
    sv->vol.volume_info=vol_volume_info;
#endif
    file_t f={&sv->root,0};uint8_t buf[64];uint64_t io[2];
    expected_lock=&sv->lock;memset(buf,0xa5,sizeof buf);
    CHECK(query(&f,3,buf,sizeof buf,io)==0);
    CHECK(*(uint64_t *)buf==49152 && *(uint64_t *)(buf+8)==42000);
    CHECK(*(uint32_t *)(buf+16)==8 && *(uint32_t *)(buf+20)==512 && io[1]==24);
#if HAVE_VOLUME_CALLBACK
    CHECK(query(&f,1,buf,sizeof buf,io)==0);wide_eq(buf+18,"SHZSFS");CHECK(*(uint32_t *)(buf+8)!=K64_VOLUME_SERIAL);
    CHECK(query(&f,5,buf,sizeof buf,io)==0);wide_eq(buf+12,"SHIZUKUFS");CHECK(*(uint32_t *)buf==6);
    CHECK(query(&f,7,buf,sizeof buf,io)==0);CHECK(*(uint64_t *)(buf+16)==42000 && io[1]==32);
    sfs_info.free_blocks=41000;CHECK(query(&f,3,buf,sizeof buf,io)==0 && *(uint64_t *)(buf+8)==41000);
    sfs_info.read_only=1;CHECK(query(&f,5,buf,sizeof buf,io)==0 && (*(uint32_t *)buf&0x80000u));
    CHECK(query(&f,4,buf,sizeof buf,io)==0 && *(uint32_t *)(buf+4)==2);
    sfs_info.read_only=0;sv->ro=1;CHECK(query(&f,4,buf,sizeof buf,io)==0 && *(uint32_t *)(buf+4)==2);sv->ro=0;
    unsigned before=copies;stat_error=SFS_EIO;CHECK(query(&f,3,buf,sizeof buf,io)==STATUS_UNSUCCESSFUL && copies==before);stat_error=0;
    unsigned oldlocks=locks;node_allowed=0;CHECK(query(&f,3,buf,sizeof buf,io)==STATUS_ACCESS_DENIED && copies==before && locks==oldlocks);node_allowed=1;
    sfs_info.free_blocks=sfs_info.blocks+1;CHECK(query(&f,3,buf,sizeof buf,io)==STATUS_UNSUCCESSFUL && copies==before);sfs_info.free_blocks=41000;
    sfs_info.block_size=513;CHECK(query(&f,3,buf,sizeof buf,io)==STATUS_UNSUCCESSFUL);sfs_info.block_size=1024;
    CHECK(query(&f,3,buf,sizeof buf,io)==0 && *(uint32_t *)(buf+16)==2);sfs_info.block_size=4096;
    memcpy(sfs_info.label,"abcdefghijklmnop",16);sfs_info.label[16]=0;
    CHECK(query(&f,1,buf,sizeof buf,io)==0 && io[1]==50);wide_eq(buf+18,"abcdefghijklmnop");
    memcpy(sfs_info.label,"\xc3\xa9",3);CHECK(query(&f,1,buf,sizeof buf,io)==0 && io[1]==20 && *(uint16_t *)(buf+18)==0xe9);
    before=locks;uint32_t serial,spc;char label[12];uint64_t total,avail;int writable;
    CHECK(disk_volume_info(&sv->root,&serial,label,&total,&avail,&spc,&writable)==-1 && locks==before);
    dvol.vol.priv=&dvol;dvol.vol.write=dummy_write;dvol.vol.volume_info=fat_volume_info;
    dvol.root.vol=&dvol.vol;dvol.root.backing=FSB_DISK;
    dvol.fat.volume_id=0x1234;dvol.fat.cluster_count=8192;dvol.fat.free_clusters=7000;dvol.fat.spc=8;
    memcpy(dvol.fat.label,"FATTEST",8);dvol.fat.write=fat_write;f.node=&dvol.root;expected_lock=&dvol.lock;
    CHECK(query(&f,1,buf,sizeof buf,io)==0 && *(uint32_t *)(buf+8)==0x1234);wide_eq(buf+18,"FATTEST");
    CHECK(query(&f,5,buf,sizeof buf,io)==0);wide_eq(buf+12,"FAT32");
    dvol.fat.label[0]=(char)0xe9;dvol.fat.label[1]=0;
    CHECK(query(&f,1,buf,sizeof buf,io)==0 && *(uint16_t *)(buf+18)==0xe9 && io[1]==20);
    memset(dvol.fat.label,0xff,11);dvol.fat.label[11]=0;
    CHECK(query(&f,1,buf,sizeof buf,io)==0 && io[1]==40);
    for(unsigned i=0;i<11;i++)CHECK(*(uint16_t *)(buf+18+2*i)==0xff);
    for(unsigned i=0;i<11;i++)dvol.fat.label[i]=(char)(i%2?'A'+i:0x80+i);
    CHECK(query(&f,1,buf,sizeof buf,io)==0 && io[1]==40);
    for(unsigned i=0;i<11;i++)CHECK(*(uint16_t *)(buf+18+2*i)==(uint8_t)dvol.fat.label[i]);
    CHECK(query(&f,3,buf,sizeof buf,io)==0 && *(uint64_t *)buf==8192 && *(uint64_t *)(buf+8)==7000);
    dvol.fat.recovery_required=1;CHECK(query(&f,5,buf,sizeof buf,io)==0 && (*(uint32_t *)buf&0x80000u));
    fsvol_t unknown={0};fsnode_t n={0};n.vol=&unknown;n.backing=FSB_DISK;n.vol->priv=sv;f.node=&n;
    before=locks;CHECK(query(&f,3,buf,sizeof buf,io)==STATUS_NOT_SUPPORTED && locks==before);
    unknown.volume_info=vol_volume_info;unsigned oldcopies=copies;
    CHECK(query(&f,3,buf,sizeof buf,io)==STATUS_UNSUCCESSFUL && locks==before && copies==oldcopies);
    CHECK(disk_volume_info(&n,&serial,label,&total,&avail,&spc,&writable)==-1 && locks==before);
    unknown.volume_info=bad_volume_info;
    CHECK(query(&f,1,buf,sizeof buf,io)==STATUS_UNSUCCESSFUL && copies==oldcopies);
    n.backing=FSB_RAM;CHECK(query(&f,3,buf,sizeof buf,io)==0 && *(uint64_t *)buf==3072);
    f.console=1;before=locks;CHECK(query(&f,3,buf,sizeof buf,io)==STATUS_INVALID_DEVICE_REQUEST && locks==before);
    CHECK(query(&f,4,buf,sizeof buf,io)==0 && *(uint32_t *)buf==0x50);
    f.console=0;f.node=&sv->root;expected_lock=&sv->lock;memcpy(sfs_info.label,"SHZSFS",7);
    CHECK(query(&f,1,buf,17,io)==STATUS_INFO_LENGTH_MISMATCH);
    CHECK(query(&f,1,buf,20,io)==STATUS_BUFFER_OVERFLOW && io[1]==20);
    CHECK(query(&f,3,buf,23,io)==STATUS_INFO_LENGTH_MISMATCH);
    CHECK(query(&f,5,buf,12,io)==STATUS_BUFFER_OVERFLOW && io[1]==12);
    before=locks;CHECK(query(&f,99,buf,sizeof buf,io)==STATUS_INVALID_INFO_CLASS && locks==before);
    CHECK(stat_calls && !bad_locks && !sv->lock.locked && !dvol.lock.locked);
#endif
    free(sv);printf("PASS %u production volume-query assertions; native/guest execution pending\n",assertions);return 0;
}
