/* SPDX-License-Identifier: GPL-2.0-only -- real driver/bridge/device bodies;
 * physical I2C/GPIO/clock/privileged ports are modeled, no Windows/VM proof. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#define SHZ_CPU_H
static uint64_t tsc=1000000000;
static uint64_t rdtsc(void){return tsc;}
static uint8_t inb(uint16_t p){(void)p;return 0;}
static void outb(uint16_t p,uint8_t v){(void)p;(void)v;}
#include "../../src/devices.c"
#include "../pointer_bridge.h"
static unsigned checks;
#define C(v) do{++checks;if(!(v)){fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#v);exit(2);}}while(0)
static void out(unsigned p,unsigned v){C(dev_pio_out((uint16_t)p,1,v));}
static unsigned in(unsigned p){uint32_t v=0;C(dev_pio_in((uint16_t)p,1,&v));return v;}
static void reply(unsigned value,int aux){C((in(0x64)&0x21)==(unsigned)(aux?0x21:1));C(in(0x60)==value);}
static void command(unsigned value){out(0x64,0xd4);out(0x60,value);}
static void tick(void){tsc+=11931820;dev_poll(tsc);}
static void eoi(void){out(0xa0,0x20);out(0x20,0x20);}
static const uint8_t mouse[]={
 0x05,1,0x09,2,0xa1,1,0x09,1,0xa1,0,0x05,9,0x19,1,0x29,3,
 0x15,0,0x25,1,0x95,3,0x75,1,0x81,2,0x95,1,0x75,5,0x81,1,
 0x05,1,0x09,0x30,0x09,0x31,0x15,0x81,0x25,0x7f,
 0x75,8,0x95,2,0x81,6,0xc0,0xc0};
struct bus {int valid,irq,reset,awake,revoke;unsigned reads,transfers,drains;uint64_t us,generation;uint8_t report[8];};
static void put16(uint8_t *p,uint16_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static int validate(void *ctx,uint64_t owner,uint64_t gen,uint16_t address){
 struct bus *b=ctx;return b->valid && owner==19 && gen==b->generation && address==0x15?SHZ_DRIVER_OK:SHZ_REVOKED;}
static int transfer(void *ctx,uint16_t address,const uint8_t *tx,size_t nt,uint8_t *rx,size_t nr,uint32_t timeout){
 struct bus *b=ctx;C(address==0x15 && timeout==100);++b->transfers;
 if(nt==2 && tx[0]==0x20){C(nr==30);memset(rx,0,nr);put16(rx,30);put16(rx+2,0x100);put16(rx+4,sizeof mouse);put16(rx+6,0x30);put16(rx+8,0x40);put16(rx+10,8);put16(rx+16,0x50);put16(rx+18,0x60);put16(rx+20,0x1234);}
 else if(nt==2 && tx[0]==0x30){C(nr==sizeof mouse);memcpy(rx,mouse,nr);}
 else if(nt==4 && tx[0]==0x50 && tx[3]==8){C(!nr);b->awake=tx[2]==0;}
 else if(nt==4 && tx[0]==0x50 && tx[3]==1){C(b->awake && !nr);b->reset=1;b->irq=1;}
 else if(!nt && b->reset){C(nr==2);memset(rx,0,nr);b->reset=b->irq=0;}
 else if(!nt){C(nr==8 && b->awake);memcpy(rx,b->report,nr);b->irq=0;++b->reads;}
 else return SHZ_IO;
 if(b->revoke){b->valid=0;}++b->us;return SHZ_DRIVER_OK;
}
static int interrupt(void *ctx,int *asserted){*asserted=((struct bus *)ctx)->irq;return SHZ_DRIVER_OK;}
static int drain(void *ctx,uint32_t timeout){C(timeout==100);++((struct bus *)ctx)->drains;return SHZ_DRIVER_OK;}
static uint64_t bus_now(void *ctx){return ((struct bus *)ctx)->us;}
static void relax(void *ctx){++((struct bus *)ctx)->us;}
static void packet(struct bus *b,uint8_t buttons,int8_t x,int8_t y){memset(b->report,0,8);put16(b->report,5);b->report[2]=buttons;b->report[3]=(uint8_t)x;b->report[4]=(uint8_t)y;b->irq=1;}
static void configure_pic(void){out(0x20,0x11);out(0xa0,0x11);out(0x21,0x20);out(0xa1,0x28);out(0x21,4);out(0xa1,2);out(0x21,1);out(0xa1,1);out(0x21,0xf9);out(0xa1,0xef);out(0x64,0x60);out(0x60,0x47);}
int main(void){
 struct bus bus={.valid=1,.generation=4};struct shz_hidi2c h={0};struct w98_pointer_bridge bridge={0},other={0};
 struct shz_i2c_ops io={&bus,validate,transfer,interrupt,drain,bus_now,relax};
 dev_init(1193182000ull,128ull<<20);dev_native_win98_enable();configure_pic();
 out(0x64,0xa9);reply(1,0);command(0xff);C(!(in(0x64)&1));
 C(w98_pointer_bind_i2c(&bridge,&h,1,1)==SHZ_BUSY);
 C(shz_hidi2c_open(&h,&io,19,4,0x15,0x20,100)==SHZ_DRIVER_OK && h.state==SHZ_I2C_READY);
 h.layout.pointer=0;C(w98_pointer_bind_i2c(&bridge,&h,1,1)==SHZ_UNSUPPORTED && !bridge.active);
 h.layout.pointer=1;
 C(w98_pointer_bind_i2c(&bridge,&h,1,1)==SHZ_DRIVER_OK);
 C(w98_pointer_bind_i2c(&bridge,&h,1,1)==SHZ_BUSY);
 C(w98_pointer_bind_i2c(&other,&h,1,1)==SHZ_BUSY && !other.active && !other.adapter.generation);
 out(0x64,0xa9);reply(0,0);C(dev_ack_irq()==0x21);out(0x20,0x20);
 command(0xff);C(dev_ack_irq()==0x2c);reply(0xfa,1);reply(0xaa,1);reply(0,1);eoi();
 command(0xf2);reply(0xfa,1);reply(0,1);C(dev_ack_irq()==0x2c);eoi();
 command(0xe9);reply(0xfa,1);reply(0,1);reply(2,1);reply(100,1);C(dev_ack_irq()==0x2c);eoi();
 /* Wire commands do not create a host event. Reporting starts only on F4. */
 command(0xf4);reply(0xfa,1);C(dev_ack_irq()==0x2c);eoi();tick();C(!(in(0x64)&1));
 packet(&bus,5,-2,7);tick();C(bus.reads==1 && bridge.last_error==SHZ_DRIVER_OK);C(dev_ack_irq()==0x2c);
 reply(0x3d,1);reply(0xfe,1);reply(0xf9,1);eoi();
 /* Queue head tagging chooses IRQ1 versus IRQ12 without interleaving packets. */
 out(0x60,0xee);packet(&bus,0,3,-4);tick();C(dev_ack_irq()==0x21);reply(0xee,0);out(0x20,0x20);
 C(dev_ack_irq()==0x2c);reply(8,1);reply(3,1);reply(4,1);eoi();
 /* Capacity: a complete movement packet waits behind fourteen keyboard bytes. */
 for(unsigned i=0;i<14;++i){out(0x60,0xee);}packet(&bus,1,10,20);tick();C(kbc_fifo_count==14 && pointer_x==10 && pointer_y==-20);
 for(unsigned i=0;i<14;++i){reply(0xee,0);}tick();reply(0x29,1);reply(10,1);reply(0xec,1);
 /* The whole command response is atomic and a failed F5 cannot disable input. */
 for(unsigned i=0;i<16;++i){out(0x60,0xee);}command(0xf5);C(pointer_enabled);
 for(unsigned i=0;i<16;++i)reply(0xee,0);
 command(0xf5);reply(0xfa,1);C(!pointer_enabled);packet(&bus,0,6,8);tick();C(!(in(0x64)&1));
 command(0xf0);reply(0xfa,1);packet(&bus,0,-9,11);tick();C(!(in(0x64)&1));
 command(0xeb);reply(0xfa,1);reply(0x38,1);reply(0xf7,1);reply(0xf5,1);
 command(0xfe);reply(0x38,1);reply(0xf7,1);reply(0xf5,1);
 command(0xea);reply(0xfa,1);command(0xf4);reply(0xfa,1);
 /* Resolution and nonlinear2:1 scaling use the shared real source's counts. */
 command(0xe8);reply(0xfa,1);command(1);reply(0xfa,1);
 packet(&bus,0,3,-3);tick();reply(8,1);reply(1,1);reply(1,1);
 packet(&bus,0,1,-1);tick();reply(8,1);reply(1,1);reply(1,1);
 command(0xe8);reply(0xfa,1);command(4);reply(0xfe,1);command(2);reply(0xfa,1);
 command(0xe7);reply(0xfa,1);packet(&bus,0,4,-5);tick();reply(8,1);reply(6,1);reply(9,1);
 command(0xe6);reply(0xfa,1);command(0xf3);reply(0xfa,1);command(80);reply(0xfa,1);command(0xe9);reply(0xfa,1);reply(32,1);reply(2,1);reply(80,1);
 command(0xf3);reply(0xfa,1);command(0);reply(0xfe,1);command(100);reply(0xfa,1);
 command(0xee);reply(0xfa,1);command(0x42);reply(0x42,1);command(0xec);reply(0xfa,1);command(0x42);reply(0xfe,1);
 /* Large deltas split, signed extrema reject before any state mutation. */
 C(dev_native_pointer_input(&bridge,600,0,0)==SHZ_DRIVER_OK);tick();reply(8,1);reply(255,1);reply(0,1);tick();reply(8,1);reply(255,1);reply(0,1);tick();reply(8,1);reply(90,1);reply(0,1);
 C(dev_native_pointer_input(&bridge,0,INT32_MIN,0)==SHZ_CAPACITY && pointer_x==0 && pointer_y==0);
 /* Revoke after queuing: queued AUX bytes discarded before guest copyout.
  * Wrapped FIFO keyboard data stays exact when AUX entries are removed. */
 configure_pic();packet(&bus,1,5,6);tick();out(0x60,0xee);C(dev_ack_irq()==0x2c);eoi();
 bus.valid=0;dev_poll(tsc);C(pic[0].irr&2);C(dev_ack_irq()==0x21);
 C((in(0x64)&0x21)==1);reply(0xee,0);out(0x20,0x20);C(!dev_irq_pending());
 C(!(in(0x64)&1));out(0x64,0xa9);reply(1,0);
 C(w98_pointer_unbind(&bridge)==SHZ_DRIVER_OK);C(shz_hidi2c_stop(&h,0)==SHZ_QUARANTINED && !bus.drains);
 bus.valid=1;C(shz_hidi2c_stop(&h,0)==SHZ_DRIVER_OK && bus.drains==2);
 /* A fresh real open/epoch can rebind the retained bridge after drain. A
  * transport callback that revokes its lease must publish no source data. */
 bus.generation=5;C(shz_hidi2c_open(&h,&io,19,5,0x15,0x20,100)==SHZ_DRIVER_OK);
 C(w98_pointer_bind_i2c(&bridge,&h,1,1)==SHZ_DRIVER_OK);
 command(0xf4);reply(0xfa,1);bus.revoke=1;packet(&bus,3,20,30);unsigned reads=bus.reads;
 tick();C(bus.reads==reads+1 && bridge.last_error==SHZ_REVOKED && h.state==SHZ_I2C_QUARANTINED);
 C(!(in(0x64)&1));C(w98_pointer_unbind(&bridge)==SHZ_DRIVER_OK);
 bus.valid=1;bus.revoke=0;C(shz_hidi2c_stop(&h,0)==SHZ_DRIVER_OK);
 printf("PASS %u production HID/I2C/Win98 AUX/IRQ12 checks; modeled hardware, no Windows98/VM\n",checks);return 0;
}
