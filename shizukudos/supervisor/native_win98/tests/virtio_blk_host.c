/* SPDX-License-Identifier: GPL-2.0-only
 * Actual transport C with modeled PCI/MMIO and a bounded split-ring device.
 * No privileged instruction, physical DMA, media, QEMU or VM executes here. */
#include "../virtio_blk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma weak w98_vblk_init
#pragma weak w98_vblk_block
#pragma weak w98_vblk_seal_member
#pragma weak w98_vblk_close
static w98_vblk_t driver;
static w98_persist_disk_t map;
static unsigned checks;
#define CHECK(x) do {++checks;if(!(x)){fprintf(stderr,"FAIL %u line%d: %s\n",checks,__LINE__,#x);exit(2);}}while(0)
#define BASE 0x100000ull
typedef struct {
    uint32_t pci[64], selected_feature, selected_driver, driver_feature[2];
    uint64_t tick, descriptor, available, used;
    uint16_t queue_size, queue_enable;
    uint8_t state, generation;
    unsigned writes, notifications, outs, flushes, resets;
    int no_flush, readonly, no_version, feature_refused, no_dma, denied_mmio;
    int bad_queue, no_completion, wrong_id, wrong_length, wrong_index, io_error;
    int reset_stuck, capacity_changed, no_queues, ignore_command;
    uint64_t notify_tick_delay, completion_tick_delay, reset_tick_delay;
    uint64_t last_lba;
    uint8_t last_data[512];
} fixture_t;
static fixture_t f;
static w98_persist_config_t cfg;
static w98_vblk_t *active_driver=&driver;
static int (*model_sector_read)(uint64_t,uint8_t *);
static int (*model_sector_write)(uint64_t,const uint8_t *);
static int (*model_flush)(void);
static void fixture(void)
{
    memset(&driver,0,sizeof driver);memset(&map,0,sizeof map);memset(&f,0,sizeof f);memset(&cfg,0,sizeof cfg);
    cfg.magic=W98_PERSIST_CONFIG_MAGIC;cfg.version=1;cfg.bdf=0x20;cfg.vendor=0x1af4;cfg.device=0x1042;
    cfg.esp_bytes=(uint64_t)W98_PERSIST_ESP_SECTORS*512;cfg.member_bytes=2ull<<30;cfg.volume_id=W98_PERSIST_VOLUME_ID;
    cfg.bar[0].base=BASE;cfg.bar[0].bytes=65536;cfg.bar[0].kind=W98_PERSIST_BAR_MEM32;
    f.pci[0]=0x10421af4;f.pci[1]=0x00100007;f.pci[2]=0x01000000;f.pci[3]=0;f.pci[4]=(uint32_t)BASE;f.pci[13]=0x40;
    f.pci[0x40/4]=0x01105009;f.pci[0x44/4]=0;f.pci[0x48/4]=0;f.pci[0x4c/4]=56;
    f.pci[0x50/4]=0x02146409;f.pci[0x54/4]=0;f.pci[0x58/4]=0x1000;f.pci[0x5c/4]=0x1000;f.pci[0x60/4]=4;
    f.pci[0x64/4]=0x03107409;f.pci[0x68/4]=0;f.pci[0x6c/4]=0x2000;f.pci[0x70/4]=1;
    f.pci[0x74/4]=0x04100009;f.pci[0x78/4]=0;f.pci[0x7c/4]=0x3000;f.pci[0x80/4]=64;
}
static int pci_read(void *ctx,uint16_t bdf,unsigned off,uint32_t *value)
{
    CHECK(ctx==&f && bdf==cfg.bdf && !(off&3) && off<256);
    *value=f.pci[off/4];
    if(off>=16 && off<=36 && *value==0xffffffffu)*value=off==16?0xffff0000:0;
    return 0;
}
static int pci_write(void *ctx,uint16_t bdf,unsigned off,uint32_t value)
{CHECK(ctx==&f && bdf==cfg.bdf && !(off&3) && off<256);++f.writes;if(off!=4 || !f.ignore_command)f.pci[off/4]=value;return 0;}
static int mmio_read(void *ctx,uint64_t pa,unsigned width,uint64_t *value)
{
    uint64_t o=pa-BASE;CHECK(ctx==&f && pa>=BASE && o<65536 && (width==1 || width==2 || width==4));*value=0;
    if(o==4)*value=f.selected_feature?(!f.no_version):((f.no_flush?0:1u<<9)|(1u<<6)|(f.readonly?1u<<5:0));
    if(o==18)*value=f.no_queues?0:1;
    if(o==20){
        if(f.state==15 && f.notifications && f.completion_tick_delay){f.tick+=f.completion_tick_delay;f.completion_tick_delay=0;}
        if(!f.state && f.resets && f.reset_tick_delay){f.tick+=f.reset_tick_delay;f.reset_tick_delay=0;}
        *value=f.state;
    }
    if(o==21)*value=f.generation;
    if(o==24)*value=f.bad_queue?4:8;
    if(o==28)*value=f.queue_enable;
    if(o==0x3000)*value=W98_PERSIST_ESP_SECTORS-(f.capacity_changed?1:0);
    if(o==0x3014)*value=512;
    return 0;
}
static void consume(void)
{
    w98_vblk_desc_t *d=(void *)(uintptr_t)f.descriptor;w98_vblk_avail_t *a=(void *)(uintptr_t)f.available;w98_vblk_used_t *u=(void *)(uintptr_t)f.used;
    w98_vblk_request_t *r;uint8_t *status;unsigned pos,id;
    CHECK(f.state==15 && (f.pci[1]&4) && d && a && u && f.queue_enable==1 && f.queue_size==8);
    if(f.no_completion)return;
    id=a->ring[(uint16_t)(a->index-1)%8];CHECK(id==0 && d[0].length==16 && d[0].flags==1 && d[0].next==1);
    r=(void *)(uintptr_t)d[0].address;CHECK(!r->reserved && (r->type==0 || r->type==1 || r->type==4));f.last_lba=r->sector;
    if(r->type==4){CHECK(d[1].length==1 && d[1].flags==2);status=(void *)(uintptr_t)d[1].address;++f.flushes;if(model_flush && model_flush())f.io_error=1;}
    else {uint8_t *data=(void *)(uintptr_t)d[1].address;CHECK(d[1].length==512 && d[1].next==2 && d[2].length==1 && d[2].flags==2);status=(void *)(uintptr_t)d[2].address;
        if(r->type==0){CHECK(d[1].flags==3);if(model_sector_read){if(model_sector_read(r->sector,data))f.io_error=1;}else memset(data,0xa6,512);}else{CHECK(d[1].flags==1);++f.outs;memcpy(f.last_data,data,512);if(model_sector_write && model_sector_write(r->sector,data))f.io_error=1;}}
    *status=f.io_error?1:0;pos=u->index%8;u->ring[pos].id=f.wrong_id?1:0;u->ring[pos].length=f.wrong_length?999:(r->type==0?513:1);u->index+=(uint16_t)(f.wrong_index?2:1);
}
static int mmio_write(void *ctx,uint64_t pa,unsigned width,uint64_t value)
{
    uint64_t o=pa-BASE;CHECK(ctx==&f && pa>=BASE && o<65536 && (width==1 || width==2 || width==4));++f.writes;
    if(o==0)f.selected_feature=(uint32_t)value;
    if(o==8)f.selected_driver=(uint32_t)value;
    if(o==12){CHECK(f.selected_driver<2);f.driver_feature[f.selected_driver]=(uint32_t)value;}
    if(o==20){if(!value){++f.resets;
        if(f.reset_stuck)return 0;
        f.queue_enable=0;f.state=0;
    }else f.state=(uint8_t)(f.feature_refused?value&~8u:value);}
    if(o==24)f.queue_size=(uint16_t)value;
    if(o==28)f.queue_enable=(uint16_t)value;
    if(o==32)f.descriptor=(f.descriptor&0xffffffff00000000ull)|(uint32_t)value;
    if(o==36)f.descriptor=(f.descriptor&0xffffffffull)|(value<<32);
    if(o==40)f.available=(f.available&0xffffffff00000000ull)|(uint32_t)value;
    if(o==44)f.available=(f.available&0xffffffffull)|(value<<32);
    if(o==48)f.used=(f.used&0xffffffff00000000ull)|(uint32_t)value;
    if(o==52)f.used=(f.used&0xffffffffull)|(value<<32);
    if(o==0x1000){CHECK(width==2 && !value);++f.notifications;f.tick+=f.notify_tick_delay;consume();}return 0;
}
static int allowed(void *ctx,uint64_t pa,uint64_t bytes){CHECK(ctx==&f);return !f.denied_mmio && pa>=BASE && bytes && pa-BASE<65536 && bytes<=65536-(pa-BASE);}
static int dma(void *ctx,const void *p,uint64_t bytes,uint64_t *address)
{uintptr_t n=(uintptr_t)p,base=(uintptr_t)active_driver;CHECK(ctx==&f);
    if(f.no_dma || n<base || n-base>=sizeof *active_driver || bytes>sizeof *active_driver-(n-base))return -1;
    *address=n;return 0;}
static uint64_t ticks(void *ctx){CHECK(ctx==&f);return ++f.tick;}
static void pause_io(void *ctx){CHECK(ctx==&f);f.tick+=100;}
static w98_vblk_io_t io={&f,pci_read,pci_write,mmio_read,mmio_write,allowed,dma,ticks,pause_io,1000};
static void admitted_model_map(w98_owned_block_t *b)
{map.admitted=1;map.block=*b;map.extents=1;map.extent[0]=(w98_disk_extent_t){0,W98_PERSIST_DISK_SECTORS,4096}; /* fabricated map ONLY transport boundary model */}
int main(void)
{
    w98_owned_block_t b;uint8_t data[512],out[512];unsigned previous;
    CHECK(w98_vblk_init!=NULL && w98_vblk_block!=NULL && w98_vblk_seal_member!=NULL && w98_vblk_close!=NULL);
    fixture();CHECK(w98_vblk_init(&driver,NULL,0,&io)==-1 && !f.writes);
    fixture();cfg.reserved64=1;CHECK(w98_vblk_init(&driver,&cfg,sizeof cfg,&io)==-1 && !f.writes);
    fixture();f.pci[0]^=1;CHECK(w98_vblk_init(&driver,&cfg,sizeof cfg,&io)==-1 && !f.writes);
    fixture();cfg.bar[0].bytes/=2;CHECK(w98_vblk_init(&driver,&cfg,sizeof cfg,&io)==-1 && !driver.ready && !(f.pci[1]&4));
    fixture();f.denied_mmio=1;CHECK(w98_vblk_init(&driver,&cfg,sizeof cfg,&io)==-1 && !driver.ready && !f.notifications);
    fixture();f.no_flush=1;CHECK(w98_vblk_init(&driver,&cfg,sizeof cfg,&io)==-1 && !driver.ready);
    fixture();f.readonly=1;CHECK(w98_vblk_init(&driver,&cfg,sizeof cfg,&io)==-1 && !driver.ready);
    fixture();f.no_version=1;CHECK(w98_vblk_init(&driver,&cfg,sizeof cfg,&io)==-1 && !driver.ready);
    fixture();f.feature_refused=1;CHECK(w98_vblk_init(&driver,&cfg,sizeof cfg,&io)==-1 && !driver.ready);
    fixture();f.bad_queue=1;CHECK(w98_vblk_init(&driver,&cfg,sizeof cfg,&io)==-1 && !driver.ready);
    fixture();f.no_dma=1;CHECK(w98_vblk_init(&driver,&cfg,sizeof cfg,&io)==-1 && !driver.ready && !f.notifications);
    fixture();f.reset_stuck=1;f.state=15;CHECK(w98_vblk_init(&driver,&cfg,sizeof cfg,&io)==-1 && driver.failed && !driver.reset_acknowledged && !(f.pci[1]&4));
    fixture();CHECK(!w98_vblk_init(&driver,&cfg,sizeof cfg,&io) && driver.ready && f.state==15);CHECK(f.driver_feature[1]==1 && f.driver_feature[0]==((1u<<9)|(1u<<6)));
    CHECK(!w98_vblk_block(&driver,&b));CHECK(!b.read(b.opaque,0,1,out) && out[0]==0xa6 && out[511]==0xa6);
    memset(data,0xb3,512);previous=f.notifications;CHECK(b.write(b.opaque,4096,1,data)==-1 && f.notifications==previous);
    admitted_model_map(&b);CHECK(!w98_vblk_seal_member(&driver,&map));previous=f.notifications;CHECK(b.write(b.opaque,4095,1,data)==-1 && f.notifications==previous);
    CHECK(!b.write(b.opaque,4096,1,data) && f.last_lba==4096 && f.outs==1 && !memcmp(data,f.last_data,512));CHECK(!b.flush(b.opaque) && f.flushes==1);
    previous=f.notifications;CHECK(b.write(b.opaque,4096+W98_PERSIST_DISK_SECTORS,1,data)==-1 && f.notifications==previous);CHECK(b.read(b.opaque,W98_PERSIST_ESP_SECTORS,1,out)==-1);
    f.capacity_changed=1;CHECK(b.read(b.opaque,4096,1,out)==-1 && driver.failed);previous=f.notifications;f.capacity_changed=0;CHECK(b.read(b.opaque,0,1,out)==-1 && f.notifications==previous);CHECK(!w98_vblk_close(&driver));
    for(unsigned failure=0;failure<6;failure++){
        fixture();CHECK(!w98_vblk_init(&driver,&cfg,sizeof cfg,&io));CHECK(!w98_vblk_block(&driver,&b));
        f.no_completion=failure==0;f.wrong_id=failure==1;f.wrong_length=failure==2;f.wrong_index=failure==3;f.io_error=failure==4;
        if(failure==5)f.state|=64;
        memset(out,0xcc,512);CHECK(b.read(b.opaque,4096,1,out)==-1 && driver.failed && out[0]==0xcc);previous=f.notifications;CHECK(b.read(b.opaque,0,1,out)==-1 && f.notifications==previous);CHECK(!w98_vblk_close(&driver));
    }
    fixture();CHECK(!w98_vblk_init(&driver,&cfg,sizeof cfg,&io));f.reset_stuck=1;CHECK(w98_vblk_close(&driver)==-1 && !driver.reset_acknowledged && !(f.pci[1]&4));
    printf("PASS %u checks; actual virtio transport C with mocked PCI/MMIO/DMA; physical device/flush/coldboot unverified\n",checks);return 0;
}
