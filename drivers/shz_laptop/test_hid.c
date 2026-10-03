/* SPDX-License-Identifier: GPL-2.0-only */
#include "laptop.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned checks;
#define C(x) do { ++checks; assert(x); } while(0)
static const uint8_t mouse[]={
 0x05,1,0x09,2,0xa1,1,0x09,1,0xa1,0,0x05,9,0x19,1,0x29,3,
 0x15,0,0x25,1,0x95,3,0x75,1,0x81,2,0x95,1,0x75,5,0x81,1,
 0x05,1,0x09,0x30,0x09,0x31,0x15,0x81,0x25,0x7f,
 0x75,8,0x95,2,0x81,6,0xc0,0xc0};
static const uint8_t touchpad[]={
 0x05,0x0d,0x09,5,0xa1,1,0x85,2,0x09,0x22,0xa1,2,
 0x09,0x42,0x15,0,0x25,1,0x75,1,0x95,1,0x81,2,
 0x75,7,0x81,1,0x09,0x51,0x75,8,0x26,0xff,0,0x81,2,
 0x05,1,0x09,0x30,0x09,0x31,0x75,16,0x95,2,0x26,0xff,0x7f,0x81,2,
 0xc0,0x05,0x0d,0x09,0x54,0x75,8,0x95,1,0x25,5,0x81,2,0xc0};
static const uint8_t sensor[]={0x05,0x20,0x09,0x73,0xa1,1,0x85,3,0x0a,0x53,4,
 0x16,0,0x80,0x26,0xff,0x7f,0x75,16,0x95,1,0x81,2,0xc0};
static const uint8_t keyboard[]={0x05,1,0x09,6,0xa1,1,0x05,7,0x19,0,0x29,0x65,
 0x15,0,0x25,0x65,0x75,8,0x95,6,0x81,0,0xc0};
static const uint8_t signed31[]={0x05,1,0x09,2,0xa1,1,0x09,0x30,
 0x17,0,0,0,0x80,0x27,0xff,0xff,0xff,0x7f,0x75,31,0x95,1,0x81,2,0xc0};
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void descriptor(uint8_t *p) {
    memset(p,0,30);put16(p,30);put16(p+2,0x100);put16(p+4,(uint16_t)sizeof(mouse));
    put16(p+6,0x30);put16(p+8,0x40);put16(p+10,8);
    put16(p+16,0x50);put16(p+18,0x60);put16(p+20,0x1234);put16(p+22,0x5678);
}
struct bus {int valid,reset,new_pending,awake,interrupt,fail,drain_error,revoke,never_irq;unsigned transfers,drains;
    uint64_t time;uint32_t transfer_ticks;uint8_t desc[30],input[8];};
static int valid(void *p,uint64_t owner,uint64_t gen,uint16_t address){
    struct bus *b=p;return b->valid && owner==19 && gen==4 && address==0x15 ? SHZ_DRIVER_OK:SHZ_REVOKED;
}
static int transfer(void *p,uint16_t address,const uint8_t *tx,size_t nt,uint8_t *rx,size_t nr,uint32_t timeout){
    struct bus *b=p;(void)address;C(timeout>0 && timeout<=100);++b->transfers;
    if(b->fail)return b->fail;
    if(nt==2 && tx[0]==0x20){C(nr==30);memcpy(rx,b->desc,30);}
    else if(nt==2 && tx[0]==0x30){C(nr==sizeof(mouse));memcpy(rx,mouse,nr);}
    else if(nt==4 && tx[0]==0x50 && tx[3]==8){C(nr==0 && tx[2]<=1);b->awake=tx[2]==0;}
    else if(nt==4 && tx[0]==0x50 && tx[3]==1){C(b->awake);if(b->reset)b->new_pending=1;else b->reset=1;b->interrupt=1;}
    else if(!nt && b->reset){C(nr==2 || nr==8);memset(rx,0,nr);b->reset=b->new_pending;b->new_pending=0;b->interrupt=b->reset;}
    else if(!nt){C(nr==8 && b->awake);memcpy(rx,b->input,nr);b->interrupt=0;}
    else return SHZ_IO;
    if(b->revoke)b->valid=0;
    b->time+=b->transfer_ticks;
    return SHZ_DRIVER_OK;
}
static int irq(void *p,int *level){struct bus *b=p;*level=b->never_irq ? 0:b->interrupt;return SHZ_DRIVER_OK;}
static int drain(void *p,uint32_t timeout){struct bus *b=p;C(timeout==100);++b->drains;return b->drain_error;}
static uint64_t now(void *p){return ((struct bus *)p)->time;}
static void relax(void *p){((struct bus *)p)->time+=10;}
int main(void) {
    struct shz_hid_layout l,old;struct shz_hid_descriptor hd,ho;struct shz_pointer point,po;
    struct shz_hid_value values[8];size_t n=99;uint8_t d[30],data[]={5,0xfe,7};
    const uint8_t finger[]={2,1,7,0x34,0x12,0x78,0x56,1}, accel[]={3,0xd4,0xfe};
    uint8_t bad[64];size_t i;
    struct bus b;struct shz_hidi2c h={0};uint8_t result[8],saved[8];size_t bytes=99;
    struct shz_i2c_ops ops={&b,valid,transfer,irq,drain,now,relax};
    descriptor(d);C(shz_hid_parse_descriptor(d,30,&hd)==SHZ_DRIVER_OK && hd.vendor==0x1234);
    ho=hd;d[0]=29;C(shz_hid_parse_descriptor(d,30,&hd)==SHZ_MALFORMED && memcmp(&hd,&ho,sizeof(hd))==0);
    descriptor(d);d[3]=2;C(shz_hid_parse_descriptor(d,30,&hd)==SHZ_UNSUPPORTED);
    descriptor(d);put16(d+10,513);C(shz_hid_parse_descriptor(d,30,&hd)==SHZ_CAPACITY);
    descriptor(d);d[26]=1;C(shz_hid_parse_descriptor(d,30,&hd)==SHZ_MALFORMED);
    C(shz_hid_parse_report(mouse,sizeof(mouse),&l)==SHZ_DRIVER_OK);
    C(l.pointer && !l.touchpad);
    C(shz_hid_decode(&l,data,sizeof(data),values,8,&n)==SHZ_DRIVER_OK && n==5);
    C(values[3].value==-2 && values[4].value==7);
    C(shz_hid_pointer(&l,data,sizeof(data),&point)==SHZ_DRIVER_OK);
    C(point.buttons==5 && point.relative && point.contacts[0].x==-2 && point.contacts[0].y==7);
    po=point;C(shz_hid_pointer(&l,data,2,&point)==SHZ_MALFORMED && memcmp(&point,&po,sizeof(point))==0);
    old=l;for(i=1;i<sizeof(mouse);i++) C(shz_hid_parse_report(mouse,i,&l)!=SHZ_DRIVER_OK && memcmp(&l,&old,sizeof(l))==0);
    C(shz_hid_parse_report(touchpad,sizeof(touchpad),&l)==SHZ_DRIVER_OK && l.touchpad);
    C(shz_hid_pointer(&l,finger,sizeof(finger),&point)==SHZ_DRIVER_OK && point.count==1);
    C(point.contacts[0].active && point.contacts[0].id==7 && point.contacts[0].x==0x1234 && point.contacts[0].y==0x5678);
    C(shz_hid_decode(&l,finger,sizeof(finger),values,1,&n)==SHZ_CAPACITY);
    C(shz_hid_parse_report(sensor,sizeof(sensor),&l)==SHZ_DRIVER_OK);
    C(shz_hid_decode(&l,accel,sizeof(accel),values,8,&n)==SHZ_DRIVER_OK && n==1 && values[0].value==-300 && values[0].page==0x20);
    C(shz_hid_parse_report(keyboard,sizeof(keyboard),&l)==SHZ_DRIVER_OK);
    C(!l.pointer && !l.touchpad);
    {const uint8_t keys[]={4,5,0,0,0,0};po=point;C(shz_hid_pointer(&l,keys,sizeof(keys),&point)==SHZ_UNSUPPORTED && !memcmp(&point,&po,sizeof point));}
    {const uint8_t keys[]={4,5,0,0,0,0};C(shz_hid_decode(&l,keys,sizeof(keys),values,8,&n)==SHZ_DRIVER_OK && n==2 && values[0].usage==4 && values[1].usage==5);}
    memcpy(bad,keyboard,sizeof(keyboard));bad[9]=1;
    C(shz_hid_parse_report(bad,sizeof(keyboard),&l)==SHZ_UNSUPPORTED);
    C(shz_hid_parse_report(signed31,sizeof(signed31),&l)==SHZ_DRIVER_OK);
    {const uint8_t bits[]={0,0,0,0x40};C(shz_hid_decode(&l,bits,sizeof(bits),values,8,&n)==SHZ_DRIVER_OK && n==1 && values[0].value==-1073741824);}
    memcpy(bad,mouse,sizeof(mouse));bad[1]=0xfe;C(shz_hid_parse_report(bad,sizeof(mouse),&l)==SHZ_DRIVER_OK);
    bad[0]=0xfe;C(shz_hid_parse_report(bad,sizeof(mouse),&l)==SHZ_UNSUPPORTED);
    /* Mutate every short-item position through all byte values, exercising
     * parser bounds and exact output preservation under sanitizers. */
    for(i=0;i<sizeof(mouse);i++) {
        unsigned byte;
        for(byte=0;byte<256;byte++) {
            int status;size_t decoded=0;
            memcpy(bad,mouse,sizeof(mouse));bad[i]=(uint8_t)byte;
            memset(&l,0xa5,sizeof(l));old=l;
            status=shz_hid_parse_report(bad,sizeof(mouse),&l);
            if(status==SHZ_DRIVER_OK) {
                status=shz_hid_decode(&l,data,sizeof(data),values,8,&decoded);
                C(status!=SHZ_DRIVER_OK || decoded<=8);
            } else C(memcmp(&l,&old,sizeof(l))==0);
        }
    }
    memset(&b,0,sizeof(b));b.valid=1;descriptor(b.desc);put16(b.input,5);memcpy(b.input+2,data,3);
    C(shz_hidi2c_open(&h,&ops,19,4,0x15,0x20,100)==SHZ_DRIVER_OK && h.state==SHZ_I2C_READY && b.awake);
    memset(result,0xa5,sizeof(result));memcpy(saved,result,sizeof(saved));
    C(shz_hidi2c_input(&h,result,sizeof(result),&bytes)==SHZ_NO_EVENT && bytes==99 && memcmp(result,saved,8)==0);
    b.interrupt=1;C(shz_hidi2c_input(&h,result,2,&bytes)==SHZ_CAPACITY && bytes==99);
    b.interrupt=1;C(shz_hidi2c_input(&h,result,8,&bytes)==SHZ_DRIVER_OK && bytes==3 && memcmp(result,data,3)==0);
    b.interrupt=1;put16(b.input,9);memset(result,0xa5,8);bytes=99;
    C(shz_hidi2c_input(&h,result,8,&bytes)==SHZ_MALFORMED && bytes==99 && memcmp(result,saved,8)==0);
    put16(b.input,5);b.valid=0;{unsigned t=b.transfers;C(shz_hidi2c_input(&h,result,8,&bytes)==SHZ_REVOKED && b.transfers==t);}
    C(shz_hidi2c_stop(&h,0)==SHZ_QUARANTINED && h.state==SHZ_I2C_QUARANTINED);
    b.valid=1;b.drain_error=SHZ_TIMEOUT;C(shz_hidi2c_stop(&h,0)==SHZ_QUARANTINED);
    C(shz_hidi2c_open(&h,&ops,19,5,0x15,0x20,100)==SHZ_BUSY);
    b.drain_error=0;C(shz_hidi2c_stop(&h,1)==SHZ_DRIVER_OK && h.state==SHZ_I2C_SUSPENDED && !b.awake);
    C(shz_hidi2c_resume(&h)==SHZ_DRIVER_OK && b.awake);
    b.revoke=1;b.interrupt=1;bytes=99;
    C(shz_hidi2c_input(&h,result,8,&bytes)==SHZ_REVOKED && bytes==99);
    b.valid=1;b.revoke=0;C(shz_hidi2c_stop(&h,0)==SHZ_DRIVER_OK);
    memset(&h,0,sizeof(h));b.never_irq=1;
    C(shz_hidi2c_open(&h,&ops,19,4,0x15,0x20,100)==SHZ_TIMEOUT && h.state==SHZ_I2C_QUARANTINED);
    b.never_irq=0;C(shz_hidi2c_stop(&h,0)==SHZ_DRIVER_OK);
    memset(&h,0,sizeof(h));b.reset=1;b.interrupt=1;
    C(shz_hidi2c_open(&h,&ops,19,4,0x15,0x20,100)==SHZ_DRIVER_OK && !b.reset && !b.new_pending);
    C(shz_hidi2c_stop(&h,0)==SHZ_DRIVER_OK);
    memset(&h,0,sizeof(h));descriptor(b.desc);b.desc[0]=29;
    C(shz_hidi2c_open(&h,&ops,19,4,0x15,0x20,100)==SHZ_MALFORMED && !h.command_known);
    {unsigned transfers=b.transfers;C(shz_hidi2c_stop(&h,0)==SHZ_DRIVER_OK && b.transfers==transfers);}
    memset(&h,0,sizeof(h));descriptor(b.desc);b.transfer_ticks=101;
    C(shz_hidi2c_open(&h,&ops,19,4,0x15,0x20,100)==SHZ_TIMEOUT && !h.command_known);
    b.transfer_ticks=0;C(shz_hidi2c_stop(&h,0)==SHZ_DRIVER_OK);
    printf("HID descriptors/input/I2C lifecycle: %u assertions PASS\n",checks);return 0;
}
