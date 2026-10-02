/* SPDX-License-Identifier: GPL-2.0-only
 * Actual C parser/map against bounded callbacks modelling a logical2304MiB
 * FAT32 volume and logical2GiB member. No actual large buffer/disk/PCI/VM. */
#include "../persistent_disk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma weak w98_persist_disk_init
#pragma weak w98_persist_disk_backend
static w98_persist_disk_t map, reopened;
static unsigned checks, reads, writes, flushes;
static int mismatch, cycle, crosslink, fragment, fail_read, fail_write, fail_flush, bad_geometry;
static uint64_t last_lba;
static uint8_t last_data[512];
#define CHECK(x) do {++checks;if(!(x)){fprintf(stderr,"FAIL %u line %d: %s\n",checks,__LINE__,#x);exit(2);}}while(0)
static void u16(uint8_t *p,unsigned v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static void u32(uint8_t *p,uint32_t v){u16(p,v);u16(p+2,v>>16);}
static uint32_t fat(unsigned n)
{
    if(n==0)return 0x0ffffff8;
    if(n==1 || (n>=2 && n<=7))return 0x0fffffff;
    if(fragment){if(n==10)return 12;if(n>=12 && n<65546)return n+1;if(n==65546)return 0x0fffffff;}
    else {if(n>=10 && n<65545)return n+1;if(n==65545)return cycle?10:0x0fffffff;}
    return 0;
}
static uint64_t cluster(unsigned n){return 1184+(uint64_t)(n-2)*64;}
static void entry(uint8_t *p,const char *name,unsigned attr,unsigned first,uint32_t bytes)
{memcpy(p,name,11);p[11]=(uint8_t)attr;u16(p+20,first>>16);u16(p+26,first);u32(p+28,bytes);}
static void boot(uint8_t *p)
{
    p[0]=0xeb;p[1]=0x58;p[2]=0x90;u16(p+11,512);p[13]=64;u16(p+14,32);p[16]=2;p[21]=0xf8;
    u32(p+32,bad_geometry?W98_PERSIST_ESP_SECTORS-1:W98_PERSIST_ESP_SECTORS);u32(p+36,576);u32(p+44,2);u16(p+48,1);u16(p+50,6);
    p[66]=0x29;u32(p+67,W98_PERSIST_VOLUME_ID);memcpy(p+82,"FAT32   ",8);p[510]=0x55;p[511]=0xaa;
}
static int read_block(void *ctx,uint64_t lba,unsigned count,void *out)
{
    uint8_t *p=out;unsigned i;CHECK(ctx==&map && count==1 && lba<W98_PERSIST_ESP_SECTORS);++reads;if(fail_read)return -1;memset(p,0,512);
    if(lba==0 || lba==6){boot(p);return 0;}
    if(lba==1 || lba==7){u32(p,0x41615252);u32(p+484,0x61417272);u32(p+488,0xffffffff);u32(p+492,0xffffffff);u32(p+508,0xaa550000);return 0;}
    if(lba>=32 && lba<1184){unsigned at=(unsigned)((lba-32)%576)*128;for(i=0;i<128;i++)u32(p+i*4,fat(at+i));if(mismatch && lba==32+576) p[8]^=1;return 0;}
    if(lba==cluster(2)){entry(p,"SHZWIN98   ",8,0,0);entry(p+32,"SHZDOS     ",16,3,0);entry(p+64,"EFI        ",16,4,0);return 0;}
    if(lba==cluster(3)){entry(p,".          ",16,3,0);entry(p+32,"..         ",16,2,0);entry(p+64,"DISK    IMG",32,10,2u<<30);entry(p+96,"KEEP    BIN",32,crosslink?11:6,512);return 0;}
    if(lba==cluster(4)){entry(p,".          ",16,4,0);entry(p+32,"..         ",16,2,0);entry(p+64,"BOOT       ",16,5,0);return 0;}
    if(lba==cluster(5)){entry(p,".          ",16,5,0);entry(p+32,"..         ",16,4,0);entry(p+64,"BOOTX64 EFI",32,7,512);return 0;}
    if(lba==last_lba && writes)memcpy(p,last_data,512);
    return 0;
}
static int write_block(void *ctx,uint64_t lba,unsigned count,const void *data)
{CHECK(ctx==&map && count==1 && lba>=cluster(10) && lba<W98_PERSIST_ESP_SECTORS);++writes;last_lba=lba;memcpy(last_data,data,512);return fail_write?-1:0;}
static int flush_block(void *ctx){CHECK(ctx==&map);++flushes;return fail_flush?-1:0;}
static void fixture(void){reads=writes=flushes=0;mismatch=cycle=crosslink=fragment=fail_read=fail_write=fail_flush=bad_geometry=0;last_lba=0;memset(last_data,0,512);}
int main(void)
{
    w98_owned_block_t b={W98_PERSIST_ESP_SECTORS,&map,read_block,write_block,flush_block},bad;
    w98_disk_backend_t backend;uint8_t data[512],got[512];unsigned old_writes;
    CHECK(w98_persist_disk_init!=NULL && w98_persist_disk_backend!=NULL); /* expected absent-map RED */
    fixture();CHECK(w98_persist_disk_init(&map,0,&b)==-1 && !reads && !writes && !flushes);
    bad=b;bad.flush=NULL;CHECK(w98_persist_disk_init(&map,W98_DISK_BACKEND_OPTIN,&bad)==-1 && !reads);
    bad=b;bad.sectors--;CHECK(w98_persist_disk_init(&map,W98_DISK_BACKEND_OPTIN,&bad)==-1 && !reads);
    CHECK(!w98_persist_disk_init(&map,W98_DISK_BACKEND_OPTIN,&b));CHECK(reads>0 && !writes && !flushes && map.admitted && map.extents==1);
    CHECK(!w98_persist_disk_backend(&map,&backend) && backend.bytes==(2ull<<30));memset(data,0xb3,512);
    CHECK(!backend.write_sector(backend.opaque,64,data) && last_lba==cluster(11));CHECK(!backend.flush(backend.opaque));CHECK(!backend.read_sector(backend.opaque,64,got) && !memcmp(data,got,512));
    CHECK(!w98_persist_disk_init(&reopened,W98_DISK_BACKEND_OPTIN,&b));CHECK(!w98_persist_disk_backend(&reopened,&backend));CHECK(!backend.read_sector(backend.opaque,64,got) && !memcmp(data,got,512)); /* model re-admission only */
    old_writes=writes;CHECK(backend.write_sector(backend.opaque,W98_PERSIST_DISK_SECTORS,data)==-1 && writes==old_writes);
    fixture();fragment=1;CHECK(!w98_persist_disk_init(&map,W98_DISK_BACKEND_OPTIN,&b) && map.extents==2);CHECK(!w98_persist_disk_backend(&map,&backend));CHECK(!backend.write_sector(backend.opaque,64,data) && last_lba==cluster(12));
    fixture();mismatch=1;CHECK(w98_persist_disk_init(&map,W98_DISK_BACKEND_OPTIN,&b)==-1 && !writes && !flushes);
    fixture();cycle=1;CHECK(w98_persist_disk_init(&map,W98_DISK_BACKEND_OPTIN,&b)==-1 && !writes && !flushes);
    fixture();crosslink=1;CHECK(w98_persist_disk_init(&map,W98_DISK_BACKEND_OPTIN,&b)==-1 && !writes && !flushes);
    fixture();bad_geometry=1;CHECK(w98_persist_disk_init(&map,W98_DISK_BACKEND_OPTIN,&b)==-1 && !writes && !flushes);
    fixture();fail_read=1;CHECK(w98_persist_disk_init(&map,W98_DISK_BACKEND_OPTIN,&b)==-1 && !map.admitted);
    fixture();CHECK(!w98_persist_disk_init(&map,W98_DISK_BACKEND_OPTIN,&b));CHECK(!w98_persist_disk_backend(&map,&backend));fail_write=1;CHECK(backend.write_sector(backend.opaque,0,data)==-1 && map.failed);old_writes=writes;fail_write=0;CHECK(backend.write_sector(backend.opaque,1,data)==-1 && writes==old_writes);
    fixture();CHECK(!w98_persist_disk_init(&map,W98_DISK_BACKEND_OPTIN,&b));CHECK(!w98_persist_disk_backend(&map,&backend));fail_flush=1;CHECK(backend.flush(backend.opaque)==-1 && map.failed);
    printf("PASS %u checks; actual FAT C, modeled logical2304MiB/2GiB extent only; real media/runtime/coldboot unverified\n",checks);return 0;
}
