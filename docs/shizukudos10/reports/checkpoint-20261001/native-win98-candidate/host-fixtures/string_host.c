/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "candidate/shizukudos/supervisor/native_win98/string_pio.h"
#include "candidate/shizukudos/supervisor/native_win98/ata_pio.h"
#define CHECK(v) do {++checks; if(!(v)){fprintf(stderr,"FAIL %u line%d: %s\n",checks,__LINE__,#v);exit(2);}}while(0)
static unsigned checks,ins,outs;static uint8_t ram[8u<<20];static uint32_t last_output;
static uint8_t *physical(void *unused,uint32_t gpa,unsigned size,int write)
{(void)unused;(void)write;return gpa<=sizeof ram && size<=sizeof ram-gpa?ram+gpa:0;}
static int input(void *unused,uint16_t port,unsigned size,uint32_t *v)
{(void)unused;CHECK(port==0x1f0);CHECK(size==1 || size==2 || size==4);++ins;*v=0x78563412;return 1;}
static int output(void *unused,uint16_t port,unsigned size,uint32_t v)
{(void)unused;CHECK(port==0x1f0);CHECK(size==1 || size==2 || size==4);++outs;last_output=v;return 1;}
static void put(uint32_t where,uint32_t v)
{unsigned n;for(n=0;n<4;++n)ram[where+n]=(uint8_t)(v>>(8*n));}
static uint32_t get(uint32_t where)
{return (uint32_t)ram[where]|(uint32_t)ram[where+1]<<8|(uint32_t)ram[where+2]<<16|(uint32_t)ram[where+3]<<24;}
static w98_memory_t memory(void)
{w98_memory_t m={0,physical,0,0,0,0};return m;}
static w98_string_io_t string(void)
{w98_string_io_t s={0};s.index=0x5000;s.count=1;s.segment_limit=0xffffffffu;s.segment_ar=0x93;s.address_bits=32;s.width=2;s.input=1;s.repeat=1;s.port=0x1f0;return s;}
static w98_ports_t ports={0,input,output};
static int run(w98_memory_t *m,w98_string_io_t *s,w98_io_fault_t *f,unsigned budget)
{return w98_string_pio(m,s,&ports,f,budget);}
static int ata_in(void *a,uint16_t p,unsigned n,uint32_t *v){return w98_ata_in(a,p,n,v);}
static int ata_out(void *a,uint16_t p,unsigned n,uint32_t v){return w98_ata_out(a,p,n,v);}
int main(void)
{
 w98_memory_t m=memory();w98_string_io_t s=string();w98_io_fault_t f;unsigned n,width;
 for(width=1;width<=4;width*=2){
  s=string();s.width=width;s.count=70;ins=0;CHECK(run(&m,&s,&f,64)==1);CHECK(ins==64 && s.count==6 && s.index==0x5000+64*width && f.completed==64);
  CHECK(run(&m,&s,&f,64)==0);CHECK(ins==70 && s.count==0 && s.index==0x5000+70*width);
  for(n=0;n<70*width;++n)CHECK(ram[0x5000+n]==((0x78563412u>>(8*(n%width)))&255));
  s=string();s.width=width;s.input=0;s.direction_down=1;s.count=2;s.index=0x5000+width;outs=0;
  CHECK(run(&m,&s,&f,64)==0);CHECK(outs==2 && s.index==0x5000-width && last_output==(width==4?0x78563412u:width==2?0x3412u:0x12u));
 }
 s=string();s.address_bits=16;s.segment_limit=0xffff;s.index=0x1234fffe;s.count=0x45670002;ins=0;
 CHECK(run(&m,&s,&f,64)==0);CHECK(ins==2 && s.index==0x12340002 && s.count==0x45670000);
 s=string();s.index=0x123400005000ull;s.count=0x567800000001ull;CHECK(run(&m,&s,&f,64)==0);CHECK(s.index==0x5002 && s.count==0);
 s=string();s.repeat=0;s.count=17;CHECK(run(&m,&s,&f,64)==0);CHECK(s.count==17 && s.index==0x5002);
 s=string();s.count=0;s.segment_ar=0x10000;ins=0;CHECK(run(&m,&s,&f,64)==0 && !ins);
 for(n=0;n<2;++n){s=string();s.segment_limit=0x5000;s.segment_is_ss=n;ins=0;CHECK(run(&m,&s,&f,64)==-1 && f.vector==(n?12u:13u) && !ins && s.index==0x5000 && s.count==1);}
 s=string();s.segment_ar=0x97;s.segment_limit=0x4fff;CHECK(run(&m,&s,&f,64)==0);
 s=string();s.segment_ar=0x97;s.segment_limit=0x5000;ins=0;CHECK(run(&m,&s,&f,64)==-1 && !ins);
 s=string();s.alignment_check=1;s.index++;ins=0;CHECK(run(&m,&s,&f,64)==-1 && f.vector==17 && !ins);
 for(n=0;n<3;++n){s=string();s.segment_ar=n==0?0x91:n==1?0x9b:0x13;ins=0;CHECK(run(&m,&s,&f,64)==-1 && f.vector==13 && !ins);}
 s=string();s.address_bits=64;CHECK(run(&m,&s,&f,64)==-2);s=string();CHECK(run(&m,&s,&f,65)==-2);
 /* Cross-page split must be fully mapped before consuming a single real port word. */
 m=memory();m.cr0=0x80010001;m.cr3=0x1000;m.cpl=3;put(0x1000,0x2007);put(0x2000,0x5007);put(0x2004,0);
 s=string();s.index=0xfff;ins=0;ram[0x5fff]=0xab;CHECK(run(&m,&s,&f,64)==-1);CHECK(f.vector==14 && f.error==6 && f.linear==0x1000 && !ins && ram[0x5fff]==0xab && s.count==1);
 put(0x2004,0x7007);CHECK(run(&m,&s,&f,64)==0);CHECK(ram[0x5fff]==0x12 && ram[0x7000]==0x34 && (get(0x1000)&0x20) && (get(0x2000)&0x60)==0x60 && (get(0x2004)&0x60)==0x60);
 /* All PDE/PTE U/S and R/W combinations against CPL/WP; oracle is Intel's combined permission rule. */
 for(unsigned user=0;user<2;++user)for(unsigned wp=0;wp<2;++wp)for(unsigned wr=0;wr<2;++wr)
 for(unsigned dp=0;dp<4;++dp)for(unsigned tp=0;tp<4;++tp){
  m=memory();m.cr0=0x80000001u|(wp?0x10000u:0u);m.cr3=0x1000;m.cpl=user?3:0;put(0x1000,0x2001|(dp<<1));put(0x2000,0x5001|(tp<<1));
  s=string();s.index=0;s.input=wr;ins=outs=0;
  int allowed=(!user || ((dp&2) && (tp&2))) && (!wr || (!user && !wp) || ((dp&1) && (tp&1)));
  int rc=run(&m,&s,&f,64);CHECK(rc==(allowed?0:-1));CHECK(ins+outs==(unsigned)allowed);
  if(!allowed)CHECK(f.vector==14 && f.error==(1u|(wr?2u:0u)|(user?4u:0u)));
 }
 /* Genuine 4MiB PDE, write protection and reserved-bit checks. */
 m=memory();m.cr0=0x80010001;m.cr3=0x1000;m.cr4=0x10;put(0x1000,0x400083);s=string();s.index=0x20;
 CHECK(run(&m,&s,&f,64)==0 && ram[0x400020]==0x12 && (get(0x1000)&0x60)==0x60);
 put(0x1000,0x402083);s=string();ins=0;CHECK(run(&m,&s,&f,64)==-1 && f.vector==14 && f.error==11 && !ins);
 m.cr4=0x20;s=string();ins=0;CHECK(run(&m,&s,&f,64)==-2 && !ins);
 /* A destination aliasing its actual PTE overwrites earlier walk A/D updates. */
 m=memory();m.cr0=0x80010001;m.cr3=0x1000;put(0x1000,0x2003);put(0x2000,0x2003);s=string();s.width=4;s.index=0;
 CHECK(run(&m,&s,&f,64)==0);CHECK(get(0x2000)==0x78563412u);
 /* Bounded partial progress on the second-element fault: the first already happened. */
 m=memory();s=string();s.index=sizeof ram-2;s.count=2;ins=0;CHECK(run(&m,&s,&f,64)==-2);CHECK(ins==1 && s.count==1 && s.index==sizeof ram && f.completed==1);
 /* Actual ATA implementation through the production string engine. */
 uint8_t disk[1024];w98_ata_t ata;w98_ports_t real={&ata,ata_in,ata_out};for(n=0;n<sizeof disk;++n)disk[n]=(uint8_t)(n*31+7);
 CHECK(w98_ata_init(&ata,disk,sizeof disk,0,0)==0);CHECK(w98_ata_out(&ata,0x1f6,1,0xe0));CHECK(w98_ata_out(&ata,0x1f2,1,1));CHECK(w98_ata_out(&ata,0x1f3,1,0));CHECK(w98_ata_out(&ata,0x1f7,1,0x20));
 m=memory();s=string();s.count=256;for(n=0;n<4;++n)CHECK(w98_string_pio(&m,&s,&real,&f,64)==(n==3?0:1));
 CHECK(!memcmp(ram+0x5000,disk,512) && ata.sectors_read==1 && s.count==0);
 CHECK(w98_ata_out(&ata,0x1f2,1,1));CHECK(w98_ata_out(&ata,0x1f3,1,1));CHECK(w98_ata_out(&ata,0x1f7,1,0x30));s=string();s.input=0;s.count=256;
 for(n=0;n<4;++n){CHECK(w98_string_pio(&m,&s,&real,&f,64)==(n==3?0:1));}CHECK(!memcmp(disk,disk+512,512) && ata.sectors_written==1);
 printf("PASS %u meaningful string/paging/actualATA checks\n",checks);return 0;
}
