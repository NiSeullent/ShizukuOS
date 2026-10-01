/* SPDX-License-Identifier: GPL-2.0-only
 * Deterministic default-profile wire transcript; native feature remains disabled.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define SHZ_CPU_H
static uint64_t now;
static uint64_t rdtsc(void){return now;}
static uint8_t inb(uint16_t p){return (uint8_t)(p^0x71);}
static void outb(uint16_t p,uint8_t v){(void)p;(void)v;}
#include "../../src/devices.c"
static uint32_t seed=0x98aa4711u;
static uint32_t random32(void){seed^=seed<<13;seed^=seed>>17;seed^=seed<<5;return seed;}
int main(void)
{
 static const uint16_t ports[]={0x20,0x21,0xa0,0xa1,0x40,0x41,0x42,0x43,0x61,0x60,0x64,0x92,0x70,0x71,0x3f8,0x3f9,0x3fa,0x3fb,0x3fc,0x3fd,0x3fe,0x3ff,0x3da,0x3ba,0x3d4,0x3d5,0xcf8,0xcff,0x80,0x0,0xc0,0xed,0xdead};
 static const int widths[]={1,2,4};
 for(unsigned round=0;round<3;++round) {
  now=1000000000;dev_init(1193182000ull,128ull<<20);
  for(unsigned n=0;n<2000;++n) {
   now+=random32()%1000000;
   uint16_t port=ports[random32()%(sizeof ports/sizeof ports[0])];int width=widths[random32()%3];uint32_t value=random32();
   if(n&1)printf("O %x %d %x %d\n",port,width,value,dev_pio_out(port,width,value));
   else {int handled=dev_pio_in(port,width,&value);printf("I %x %d %d %x\n",port,width,handled,value);}
   if(!(n%17)){dev_poll(now);dev_irq_raise(n%16);int pending=dev_irq_pending(),vector=dev_ack_irq(),a20=dev_a20_get();printf("P %d %d %d\n",pending,vector,a20);}
  }
  printf("T %llu C %u\n",(unsigned long long)dev_uptime_us(),dev_crtc_cursor());
 }
 return 0;
}
