/* SPDX-License-Identifier: GPL-2.0-only
 * Actual ATA -> FAT mapper -> polled virtio C. PCI/MMIO/DMA and logical ESP are
 * callbacks; only one actual512B RAM sector/data slot is allocated. The claimed
 * logical2GiB ATA span is modeled and no access beyond that sector occurs. */
#define main transport_fixture_main
#include "virtio_blk_host.c"
#undef main
#include "../persistence.h"
#pragma weak w98_persistence_attach
#pragma weak w98_persistence_attach_native
#pragma weak w98_persistence_finish
#pragma weak w98_vblk_native_init
static w98_persistence_t session;
static w98_ata_t ata;
static uint8_t ram_sector[512],media_sector[512];
static unsigned irq_count,media_writes,media_flushes;
static int corrupt_fat,barrier_failed;
static uint64_t model_ticks(void *ctx){CHECK(ctx==&f);return ++f.tick;}
static uint64_t cluster(unsigned n){return 1184+(uint64_t)(n-2)*64;}
static void set16(uint8_t *p,unsigned v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static void set32(uint8_t *p,uint32_t v){set16(p,v);set16(p+2,v>>16);}
static uint32_t fat_entry(unsigned n)
{if(n==0)return 0x0ffffff8;if(n==1 || (n>=2 && n<=5))return 0x0fffffff;if(n>=10 && n<65545)return n+1;if(n==65545)return 0x0fffffff;return 0;}
static void dir_entry(uint8_t *p,const char *name,unsigned attr,unsigned first,uint32_t bytes)
{memcpy(p,name,11);p[11]=(uint8_t)attr;set16(p+20,first>>16);set16(p+26,first);set32(p+28,bytes);}
static int model_read(uint64_t lba,uint8_t *p)
{
    unsigned i;memset(p,0,512);
    if(lba==0 || lba==6){p[0]=0xeb;p[1]=0x58;p[2]=0x90;set16(p+11,512);p[13]=64;set16(p+14,32);p[16]=2;p[21]=0xf8;set32(p+32,W98_PERSIST_ESP_SECTORS);set32(p+36,576);set32(p+44,2);set16(p+48,1);set16(p+50,6);p[66]=0x29;set32(p+67,W98_PERSIST_VOLUME_ID);memcpy(p+82,"FAT32   ",8);p[510]=0x55;p[511]=0xaa;return 0;}
    if(lba==1 || lba==7){set32(p,0x41615252);set32(p+484,0x61417272);set32(p+488,0xffffffff);set32(p+492,0xffffffff);set32(p+508,0xaa550000);return 0;}
    if(lba>=32 && lba<1184){unsigned at=(unsigned)((lba-32)%576)*128;for(i=0;i<128;i++)set32(p+i*4,fat_entry(at+i));if(corrupt_fat && lba==608)p[8]^=1;return 0;}
    if(lba==cluster(2)){dir_entry(p,"SHZDOS     ",16,3,0);dir_entry(p+32,"EFI        ",16,4,0);return 0;}
    if(lba==cluster(3)){dir_entry(p,".          ",16,3,0);dir_entry(p+32,"..         ",16,2,0);dir_entry(p+64,"DISK    IMG",32,10,2u<<30);return 0;}
    if(lba==cluster(4)){dir_entry(p,".          ",16,4,0);dir_entry(p+32,"..         ",16,2,0);dir_entry(p+64,"BOOT       ",16,5,0);return 0;}
    if(lba==cluster(5)){dir_entry(p,".          ",16,5,0);dir_entry(p+32,"..         ",16,4,0);return 0;}
    if(lba==cluster(10))memcpy(p,media_sector,512);
    return 0;
}
static int model_write(uint64_t lba,const uint8_t *p)
{CHECK(lba==cluster(10));++media_writes;memcpy(media_sector,p,512);return 0;}
static int model_barrier(void){++media_flushes;return barrier_failed?-1:0;}
static void irq(void *ctx){CHECK(ctx==&ata);++irq_count;}
static void start(void)
{
    fixture();memset(&session,0,sizeof session);memset(ram_sector,0x55,512);memset(media_sector,0x55,512);media_writes=media_flushes=irq_count=0;corrupt_fat=barrier_failed=0;active_driver=&session.device;io.ticks_per_second=1000000000;io.ticks=model_ticks;model_sector_read=model_read;model_sector_write=model_write;model_flush=model_barrier;
    CHECK(!w98_ata_init(&ata,ram_sector,2ull<<30,irq,&ata));
}
static void write_ata(uint8_t byte)
{
    CHECK(w98_ata_out(&ata,0x1f6,1,0xe0)==1);CHECK(w98_ata_out(&ata,0x1f2,1,1)==1);CHECK(w98_ata_out(&ata,0x1f3,1,0)==1);CHECK(w98_ata_out(&ata,0x1f4,1,0)==1);CHECK(w98_ata_out(&ata,0x1f5,1,0)==1);CHECK(w98_ata_out(&ata,0x1f7,1,0x30)==1);
    for(unsigned i=0;i<255;i++)CHECK(w98_ata_out(&ata,0x1f0,2,(uint16_t)(byte|byte<<8))==1);
    CHECK(!media_writes && ram_sector[0]==0x55);CHECK(w98_ata_out(&ata,0x1f0,2,(uint16_t)(byte|byte<<8))==1);
}
int main(void)
{
    CHECK(w98_persistence_attach!=NULL && w98_persistence_attach_native!=NULL && w98_persistence_finish!=NULL && w98_vblk_native_init!=NULL);
    start();CHECK(!w98_persistence_attach(&session,&ata,NULL,0,&io) && !f.writes && !ata.backend_attached);
    start();CHECK(w98_persistence_attach(&session,&ata,&cfg,sizeof cfg-1,&io)==-1 && !f.writes);
    start();CHECK(w98_vblk_native_init(&session.device,&cfg,sizeof cfg,NULL)==-1);CHECK(w98_persistence_attach_native(&session,&ata,&cfg,sizeof cfg,NULL)==-1 && !ata.backend_attached);
    start();corrupt_fat=1;CHECK(w98_persistence_attach(&session,&ata,&cfg,sizeof cfg,&io)==-1 && !session.attached && !ata.backend_attached && !media_writes && session.device.reset_acknowledged);
    start();CHECK(!w98_persistence_attach(&session,&ata,&cfg,sizeof cfg,&io) && session.attached && ata.backend_attached && session.device.sealed);write_ata(0xb3);CHECK(media_writes==1 && media_flushes==1 && !memcmp(ram_sector,media_sector,512) && ata.sectors_written==1 && !(ata.status&1));CHECK(!w98_persistence_finish(&session) && session.device.reset_acknowledged && !session.device.ready);
    start();CHECK(!w98_persistence_attach(&session,&ata,&cfg,sizeof cfg,&io));barrier_failed=1;write_ata(0xa4);CHECK(media_writes==1 && media_flushes==1 && media_sector[0]==0xa4 && ram_sector[0]==0x55 && ata.backend_failed && ata.status&1 && !ata.sectors_written);CHECK(w98_persistence_finish(&session)==-1 && session.failed && session.device.reset_acknowledged);
    printf("PASS %u checks; actual linked ATA/FAT/virtio C, bounded callback model only; native I/O/flush/coldboot false\n",checks);return 0;
}
