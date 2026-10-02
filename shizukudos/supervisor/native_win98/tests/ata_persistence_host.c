/* SPDX-License-Identifier: GPL-2.0-only
 * Actual ATA C with a mocked physical device. No host/guest disk I/O. */
#include "../ata_pio.h"
#include "../disk_backend.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern int w98_ata_attach_backend(w98_ata_t *, uint32_t, const w98_disk_backend_t *);
#pragma weak w98_ata_attach_backend
static unsigned checks, irqs, reads, writes, flushes;
static int fail_read, fail_write, fail_flush;
static uint8_t media[4*512], ram[sizeof media], old[sizeof media];
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL %u line %d: %s\n",checks,__LINE__,#x); exit(2); } } while (0)
static void irq(void *p) { CHECK(p==&irqs); ++irqs; }
static int rd(void *p,uint32_t lba,uint8_t *b) { CHECK(p==media && lba<4); ++reads; if(fail_read)return -1; memcpy(b,media+lba*512,512); return 0; }
static int wr(void *p,uint32_t lba,const uint8_t *b) { CHECK(p==media && lba<4); ++writes; memcpy(media+lba*512,b,512); return fail_write?-1:0; }
static int fl(void *p) { CHECK(p==media); ++flushes; return fail_flush?-1:0; }
static void out(w98_ata_t *a,unsigned p,unsigned v) { CHECK(w98_ata_out(a,(uint16_t)p,1,v)==1); }
static void task(w98_ata_t *a,unsigned lba,unsigned n,unsigned command) { out(a,0x1f6,0xe0);out(a,0x1f2,n);out(a,0x1f3,lba);out(a,0x1f4,0);out(a,0x1f5,0);out(a,0x1f7,command); }
static void sector(w98_ata_t *a,unsigned value) { unsigned i;for(i=0;i<256;i++)CHECK(w98_ata_out(a,0x1f0,2,value+i)==1); }
static void init(w98_ata_t *a) { unsigned i; for(i=0;i<sizeof media;i++)media[i]=(uint8_t)(i*7);memcpy(ram,media,sizeof ram);memcpy(old,ram,sizeof old);reads=writes=flushes=irqs=0;fail_read=fail_write=fail_flush=0;CHECK(!w98_ata_init(a,ram,sizeof ram,irq,&irqs)); }
int main(void)
{
    w98_ata_t a;w98_disk_backend_t b={sizeof media,media,rd,wr,fl},bad;unsigned prior,i;uint32_t value;
    CHECK(w98_ata_attach_backend!=NULL); /* RED: baseline has no durable backend seam. */
    init(&a);CHECK(w98_ata_attach_backend(&a,0,&b)==-1);CHECK(reads+writes+flushes==0);
    bad=b;bad.bytes-=512;CHECK(w98_ata_attach_backend(&a,W98_DISK_BACKEND_OPTIN,&bad)==-1);
    bad=b;bad.flush=NULL;CHECK(w98_ata_attach_backend(&a,W98_DISK_BACKEND_OPTIN,&bad)==-1);
    bad=b;bad.read_sector=NULL;CHECK(w98_ata_attach_backend(&a,W98_DISK_BACKEND_OPTIN,&bad)==-1);
    task(&a,0,1,0x30);CHECK(w98_ata_attach_backend(&a,W98_DISK_BACKEND_OPTIN,&b)==-1);
    out(&a,0x3f6,4);out(&a,0x3f6,0);CHECK(!w98_ata_attach_backend(&a,W98_DISK_BACKEND_OPTIN,&b));
    CHECK(w98_ata_attach_backend(&a,W98_DISK_BACKEND_OPTIN,&b)==-1);
    task(&a,1,2,0x30);for(i=0;i<255;i++)CHECK(w98_ata_out(&a,0x1f0,2,0x4000+i)==1);
    CHECK(writes==0 && flushes==0 && !memcmp(ram,old,sizeof ram));
    CHECK(w98_ata_out(&a,0x1f0,2,0x40ff)==1);CHECK(writes==1 && flushes==1 && a.sectors_written==1 && a.status==0x58);
    CHECK(!memcmp(ram,media,sizeof ram));sector(&a,0x6000);CHECK(writes==2 && flushes==2 && a.sectors_written==2 && a.status==0x50 && !memcmp(ram,media,sizeof ram));
    task(&a,0,1,0xe7);CHECK(a.status==0x50 && flushes==3);
    memset(media,0x6b,512);task(&a,0,1,0x20);CHECK(reads==1 && a.status==0x58);CHECK(w98_ata_in(&a,0x1f0,2,&value)==1 && (value&0xffff)==0x6b6b);
    init(&a);CHECK(!w98_ata_attach_backend(&a,W98_DISK_BACKEND_OPTIN,&b));fail_write=1;task(&a,1,1,0x30);sector(&a,0x7000);
    CHECK(a.status==0x51 && a.error==4 && !a.sectors_written && !memcmp(ram,old,sizeof ram) && memcmp(media,old,sizeof media));
    CHECK(writes==1 && flushes==0);prior=writes;task(&a,2,1,0x30);CHECK(a.status==0x51 && writes==prior);
    fail_write=0;out(&a,0x3f6,4);out(&a,0x3f6,0);task(&a,0,1,0x20);CHECK(a.status==0x51 && reads==0);task(&a,0,1,0xe7);CHECK(a.status==0x51 && flushes==0);
    init(&a);CHECK(!w98_ata_attach_backend(&a,W98_DISK_BACKEND_OPTIN,&b));fail_flush=1;task(&a,1,1,0x30);sector(&a,0x8000);
    CHECK(a.status==0x51 && writes==1 && flushes==1 && !a.sectors_written && !memcmp(ram,old,sizeof ram) && memcmp(media,old,sizeof media));
    init(&a);CHECK(!w98_ata_attach_backend(&a,W98_DISK_BACKEND_OPTIN,&b));fail_flush=1;task(&a,0,1,0xe7);CHECK(a.status==0x51 && flushes==1);fail_flush=0;task(&a,0,1,0x20);CHECK(a.status==0x51 && reads==0);
    init(&a);CHECK(!w98_ata_attach_backend(&a,W98_DISK_BACKEND_OPTIN,&b));fail_read=1;task(&a,0,1,0x20);CHECK(a.status==0x51 && reads==1 && !a.remaining && !memcmp(ram,old,sizeof ram));
    init(&a);CHECK(!w98_ata_attach_backend(&a,W98_DISK_BACKEND_OPTIN,&b));task(&a,3,2,0x30);CHECK(a.error==0x10 && !writes && !flushes);
    printf("PASS %u checks; actual ATA C, mocked physical writes/barriers/failures; runtime/coldboot persistence unverified\n",checks);return 0;
}
