/* SPDX-License-Identifier: GPL-2.0-only */
#include "candidate/shizukudos/supervisor/native_win98/ata_pio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks, irqs;
#define CHECK(x) do {++checks; if (!(x)) {fprintf(stderr,"FAIL %u line %d: %s\n",checks,__LINE__,#x);exit(2);}} while(0)
static void raised(void *p) { CHECK(p==&irqs); ++irqs; }
static void write8(w98_ata_t *a,unsigned port,unsigned v) { CHECK(w98_ata_out(a,(uint16_t)port,1,v)==1); }
static uint32_t read(w98_ata_t *a,unsigned port,unsigned size) {uint32_t v=0;CHECK(w98_ata_in(a,(uint16_t)port,size,&v)==1);return v;}
static void task(w98_ata_t *a,unsigned lba,unsigned count,unsigned cmd)
{
    write8(a,0x1f6,0xe0|(lba>>24));write8(a,0x1f2,count);
    write8(a,0x1f3,lba&255);write8(a,0x1f4,(lba>>8)&255);write8(a,0x1f5,(lba>>16)&255);write8(a,0x1f7,cmd);
}
int main(void)
{
    unsigned i, prior; uint32_t v; w98_ata_t a; unsigned char disk[5*512],saved[sizeof disk],id[512];
    for(i=0;i<sizeof disk;i++)disk[i]=(unsigned char)(i*19+i/512);
    memcpy(saved,disk,sizeof disk);
    CHECK(w98_ata_init(NULL,disk,sizeof disk,raised,&irqs)==-1);
    CHECK(w98_ata_init(&a,NULL,sizeof disk,raised,&irqs)==-1);
    CHECK(w98_ata_init(&a,disk,511,raised,&irqs)==-1);
    CHECK(w98_ata_init(&a,disk,sizeof disk+1,raised,&irqs)==-1);
    CHECK(w98_ata_init(&a,disk,(2ull<<30)+512,raised,&irqs)==-1);
    CHECK(w98_ata_init(&a,disk,sizeof disk,raised,&irqs)==0);
    CHECK(read(&a,0x1f7,1)==0x50);
    write8(&a,0x1f7,0xec); CHECK(irqs==1 && (read(&a,0x3f6,1)&8));CHECK(a.irq==1);
    CHECK(read(&a,0x1f7,1)&8);CHECK(!a.irq);
    for(i=0;i<256;i++){v=read(&a,0x1f0,2);id[2*i]=(unsigned char)v;id[2*i+1]=(unsigned char)(v>>8);}
    CHECK(id[120]==5 && !id[121] && !(id[98]&1) && (id[99]&2));
    CHECK(a.status==0x50 && !a.remaining && a.sectors_read==0);
    task(&a,1,2,0x20);CHECK(a.remaining==2 && read(&a,0x1f7,1)==0x58);
    for(i=0;i<1024;i+=4){v=read(&a,0x1f0,4);CHECK(v==((uint32_t)saved[512+i]|((uint32_t)saved[513+i]<<8)|((uint32_t)saved[514+i]<<16)|((uint32_t)saved[515+i]<<24)));if(i==508)CHECK(read(&a,0x1f7,1)==0x58);}
    CHECK(a.sectors_read==2 && !a.remaining && a.lba==3 && a.count==0 && a.status==0x50);
    CHECK(!memcmp(disk,saved,sizeof disk));
    task(&a,4,2,0x20);CHECK((a.status&1) && a.error==0x10 && !a.remaining);
    CHECK(!memcmp(disk,saved,sizeof disk));
    task(&a,0xfffffff,1,0x30);CHECK(a.error==0x10 && !memcmp(disk,saved,sizeof disk));
    task(&a,0,0,0x20);CHECK(a.error==0x10); /* 0 count means256, not empty success. */
    task(&a,3,1,0x30);CHECK(a.status==0x58);
    for(i=0;i<255;i++)CHECK(w98_ata_out(&a,0x1f0,2,0x3100+i)==1);
    CHECK(!memcmp(disk,saved,sizeof disk) && a.sectors_written==0);
    CHECK(w98_ata_out(&a,0x1f0,2,0xa55a)==1);CHECK(a.sectors_written==1 && a.status==0x50);
    CHECK(!memcmp(disk,saved,3*512) && !memcmp(disk+4*512,saved+4*512,512));
    for(i=0;i<255;i++)CHECK(disk[3*512+2*i]==(unsigned char)i && disk[3*512+2*i+1]==(unsigned char)((0x3100+i)>>8));
    CHECK(disk[2046]==0x5a && disk[2047]==0xa5);
    memcpy(saved,disk,sizeof disk);task(&a,2,1,0x30);
    CHECK(w98_ata_out(&a,0x1f0,4,0xdeadbeef)==1);write8(&a,0x1f7,0xc5);
    CHECK(a.error==4 && (a.status&1) && !memcmp(disk,saved,sizeof disk)); /* Unadvertised multiple aborted, staged write uncommitted. */
    task(&a,0,1,0x20);v=read(&a,0x1f0,1);CHECK(v==0xffffffff && a.error==4 && !a.remaining);
    write8(&a,0x1f6,0xb0);write8(&a,0x1f7,0xec);CHECK(read(&a,0x1f7,1)==0);
    write8(&a,0x1f6,0xe0);write8(&a,0x3f6,6);CHECK(a.status==0x80 && !a.remaining);
    write8(&a,0x3f6,2);CHECK(a.status==0x50 && a.control==2);
    prior=irqs;task(&a,0,1,0x20);CHECK(irqs==prior && a.irq);
    write8(&a,0x3f6,0);CHECK(irqs==prior+1);CHECK(read(&a,0x3f6,1)==0x58 && a.irq);CHECK(read(&a,0x1f7,1)==0x58 && !a.irq);
    for(i=0;i<128;i++) { (void)read(&a,0x1f0,4); }
    CHECK(a.status==0x50);
    task(&a,4,1,0x40);CHECK(a.status==0x50 && a.count==0 && a.lba==5 && !memcmp(disk,saved,sizeof disk));
    task(&a,1,1,0xc8);CHECK(a.error==4 && (a.status&1)); /* DMA has no fake success. */
    task(&a,0,1,0xe7);CHECK(a.status==0x50 && !memcmp(disk,saved,sizeof disk));
    write8(&a,0x1f6,0xa0);write8(&a,0x1f2,1);write8(&a,0x1f3,2);write8(&a,0x1f4,0);write8(&a,0x1f5,0);write8(&a,0x1f7,0x20);
    CHECK(a.lba==1 && a.status==0x58);v=read(&a,0x1f0,2);CHECK((v&0xffff)==((unsigned)saved[512]|((unsigned)saved[513]<<8)));
    CHECK(w98_ata_in(&a,0x100,1,&v)==0 && w98_ata_out(&a,0x100,1,0)==0);
    printf("PASS %u checks; real ATA PIO identify/read/write/IRQ/bounds/CHS/abort/sector-commit semantics\n",checks);return 0;
}
