/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#define SHZ_CPU_H
static uint64_t now;
static uint64_t rdtsc(void){return now;}
static uint8_t inb(uint16_t p){(void)p;return 0;}
static void outb(uint16_t p,uint8_t v){(void)p;(void)v;}
#include "../../src/devices.c"
static unsigned checks;
#define CHECK(v) do{++checks;if(!(v)){fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#v);exit(2);}}while(0)
static void out(unsigned p,unsigned v){CHECK(dev_pio_out((uint16_t)p,1,v));}
static unsigned in(unsigned p){uint32_t v=0;CHECK(dev_pio_in((uint16_t)p,1,&v));return v;}
static void start(void){now=1000000000;dev_init(1193182000ull,128ull<<20);dev_native_win98_enable();}
static void pit2(unsigned count){out(0x61,0);out(0x43,0xb0);out(0x42,count&255);out(0x42,count>>8);out(0x61,1);}
static void reply(unsigned v){CHECK((in(0x64)&1)==1);CHECK(in(0x60)==v);}
int main(void)
{
 start();pit2(0x800);CHECK((in(0x61)&32)==0);now+=2047999;CHECK((in(0x61)&32)==0);++now;CHECK((in(0x61)&32)==32);
 CHECK(in(0x42)==0 && in(0x42)==0);now+=10000000;CHECK((in(0x61)&32)==32);unsigned wraplo=in(0x42);CHECK((wraplo|(in(0x42)<<8))==55536);
 /* Mode0 GATE suspends elapsed count; raising it resumes remaining time. */
 start();pit2(10);now+=4000;out(0x61,0);now+=100000000;CHECK(!(in(0x61)&32));CHECK(in(0x42)==6 && in(0x42)==0);
 out(0x61,1);now+=5999;CHECK(!(in(0x61)&32));++now;CHECK(in(0x61)&32);
 /* Reload and control clear OUT, zero means65536, and latches remain stable. */
 out(0x43,0xb0);CHECK(!(in(0x61)&32));out(0x42,0);out(0x42,0);now+=65535999;CHECK(!(in(0x61)&32));++now;CHECK(in(0x61)&32);
 start();pit2(0x1234);now+=1000;out(0x43,0x80);unsigned low=in(0x42);now+=1000000;unsigned high=in(0x42);CHECK((low|(high<<8))==0x1233);
 /* True queued keyboard reset ACK then BAT, not a generic false ACK. */
 start();out(0x60,0xff);reply(0xfa);reply(0xaa);CHECK(!(in(0x64)&1));
 out(0x60,0xf2);reply(0xfa);reply(0xab);reply(0x83);CHECK(!(in(0x64)&1));
 out(0x60,0xf0);reply(0xfa);out(0x60,0);reply(0xfa);reply(2);
 out(0x60,0xf0);reply(0xfa);out(0x60,1);reply(0xfa);out(0x60,0xf0);reply(0xfa);out(0x60,0);reply(0xfa);reply(1);
 out(0x60,0xf0);reply(0xfa);out(0x60,4);reply(0xfe);
 out(0x60,0xee);reply(0xee);out(0x60,0x80);reply(0xfe);
 out(0x60,0xed);reply(0xfa);out(0x60,3);reply(0xfa);out(0x60,0xf3);reply(0xfa);out(0x60,0x20);reply(0xfa);
 out(0x64,0x20);reply(0x45);out(0x64,0x60);out(0x60,0x44);out(0x64,0x20);reply(0x44);
 out(0x64,0xaa);reply(0x55);out(0x64,0xab);reply(0);out(0x64,0xd0);reply(3);
 out(0x64,0xd1);out(0x60,1);CHECK(!dev_a20_get());out(0x64,0xdf);CHECK(dev_a20_get());
 /* Native profile has bounded coalesced evidence, no I/O logging callback. */
 start();pit2(0x800);for(unsigned n=0;n<10000;++n){now+=100;in(0x61);}now+=3000000;in(0x61);
 const dev_native_observation_t *obs=dev_native_observation();CHECK(obs && obs->pit2_terminal_seen && obs->pit2_interval_open && !obs->pit2_restored_after_terminal);out(0x61,0);CHECK(!obs->pit2_interval_open && obs->pit2_restored_after_terminal);CHECK(obs && obs->pit_count<=DEV_NATIVE_PIT_RECORDS && obs->pit_count>=6);
 unsigned coalesced=0;for(unsigned n=0;n<obs->pit_count;++n){CHECK(obs->pit[n].last_tsc>=obs->pit[n].first_tsc);if(obs->pit[n].count>100)++coalesced;}CHECK(coalesced);
 for(unsigned n=0;n<1000;++n){out(0x60,0xee);reply(0xee);}CHECK(obs->kbc_count<=DEV_NATIVE_KBC_RECORDS && obs->kbc_dropped>0);
 /* Saturated FIFO remains bounded and does not overwrite queued bytes. */
 start();for(unsigned n=0;n<100;++n)out(0x60,0xee);for(unsigned n=0;n<16;++n)reply(0xee);CHECK(!(in(0x64)&1));
 /* IRQ14 cascade/EOI still works; keyboard command IRQs are not user-input claims. */
 start();out(0x20,0x11);out(0xa0,0x11);out(0x21,0x20);out(0xa1,0x28);out(0x21,4);out(0xa1,2);out(0x21,1);out(0xa1,1);out(0x21,0xfb);out(0xa1,0xbf);
 dev_irq_raise(14);CHECK(dev_irq_pending());CHECK(dev_ack_irq()==0x2e);out(0xa0,0x20);out(0x20,0x20);CHECK(!dev_irq_pending());
 /* Whole default profile is preserved: its old PIT2/keyboard semantics stay opt-out. */
 now=1000000000;dev_init(1193182000ull,128ull<<20);CHECK(!dev_native_observation());pit2(0x800);CHECK(in(0x61)&32);out(0x60,0xff);reply(0xfa);CHECK(!(in(0x64)&1));
 printf("PASS %u actual native PIT2/KBC/IRQ/default-profile checks (modeled time, no VM)\n",checks);return 0;
}
