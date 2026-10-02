/* SPDX-License-Identifier: GPL-2.0-only
 * Real gate C; PCI, transport, clock and outer provenance are modeled only. */
#include "../native_device_epoch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma weak w98_native_epoch_gate
static unsigned checks;
#define CHECK(x) do { ++checks; if(!(x)){fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x);exit(2);} } while(0)
typedef struct {
    uint32_t pci[2][10];
    uint8_t challenge[48],grant[272],output[256];
    unsigned read_at,write_at,pci_calls,send_calls,receive_calls,pause_calls;
    unsigned pci_writes,vga_writes,dma_writes;
    unsigned case_id,chunk;
    uint64_t ticks;
    w98_epoch_gate_t *gate;
} model_t;
static model_t m;
static w98_epoch_gate_t gate;
static w98_epoch_expect_t expected;
static w98_epoch_io_t io;
static void le16(uint8_t *p,unsigned v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static void le32(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(i*8));}
static uint64_t clock_now(void *ctx)
{model_t *f=ctx;if(f->case_id==24 && f->write_at)f->gate->deadline=2000;return f->ticks;}
static void idle(void *ctx){model_t *f=ctx;++f->pause_calls;if(f->case_id!=18)++f->ticks;}
static int pci_read(void *ctx,uint16_t bdf,unsigned off,uint32_t *value)
{
    model_t *f=ctx;unsigned dev=bdf==16?0:bdf==24?1:2;
    CHECK(dev<2 && off<=36 && !(off&3));++f->pci_calls;
    *value=f->pci[dev][off/4];
    if(f->case_id==10 && f->pci_calls==21)*value^=0x1000;
    if(f->case_id==11 && f->pci_calls==40)f->ticks=1000;
    if(f->case_id==12 && f->pci_calls==1)f->ticks=1000;
    if(f->case_id==20)return -1;
    return 0;
}
static int receive(void *ctx,uint8_t *out,unsigned bytes)
{
    model_t *f=ctx;unsigned left,n;
    ++f->receive_calls;
    if(f->case_id==17 || f->case_id==18)return 0;
    if(f->case_id==19)return -1;
    if(f->case_id==21)return (int)bytes+1;
    if(f->read_at<48){left=48-f->read_at;n=bytes<left?bytes:left;if(n>f->chunk)n=f->chunk;
        memcpy(out,f->challenge+f->read_at,n);f->read_at+=n;
        if(f->case_id==26)f->ticks=1000;
        return (int)n;}
    if(!f->write_at)return 0;
    if(f->read_at==48){
        memset(f->grant,0,sizeof f->grant);le32(f->grant,W98_EPOCH_MAGIC);
        le16(f->grant+4,1);le16(f->grant+6,3);le32(f->grant+8,272);le32(f->grant+12,expected.count);
        memcpy(f->grant+16,f->output,256);
        if(f->case_id==7)f->grant[16+16]^=1;
        if(f->case_id==8)f->grant[16+48]^=1;
        if(f->case_id==9)f->grant[16+160]^=1;
        if(f->case_id==13)f->grant[16+144]^=1;
        if(f->case_id==14)f->grant[6]=2;
        if(f->case_id==27)f->grant[16+112]^=1;
        if(f->case_id==15)f->ticks=1000;
        if(f->case_id==16)f->ticks=9;
        if(f->case_id==23)f->pci[1][4]^=0x1000;
    }
    left=320-f->read_at;n=bytes<left?bytes:left;if(n>f->chunk)n=f->chunk;
    memcpy(out,f->grant+f->read_at-48,n);f->read_at+=n;return (int)n;
}
static int send_bytes(void *ctx,const uint8_t *in,unsigned bytes)
{
    model_t *f=ctx;unsigned n=bytes;
    ++f->send_calls;CHECK(f->write_at+bytes<=256);
    if(f->case_id==22)return (int)bytes+1;
    if(n>f->chunk)n=f->chunk;
    memcpy(f->output+f->write_at,in,n);f->write_at+=n;
    if(f->case_id==25)f->ticks=1000;
    return (int)n;
}
static void fixture(unsigned id)
{
    memset(&m,0,sizeof m);memset(&gate,0,sizeof gate);memset(&expected,0,sizeof expected);
    m.case_id=id;m.ticks=10;m.chunk=272;m.gate=&gate;
    expected.count=2;memset(expected.nonce,0x6d,32);
    memset(expected.config_sha256[0],0xa5,32);memset(expected.config_sha256[1],0x5a,32);
    memset(expected.rom_sha256,0xc3,32);
    expected.device[0]=(w98_epoch_device_t){16,1,0x1234,0x1111,0x030000,3,0,{0xe0000008,0,0,0,0,0}};
    expected.device[1]=(w98_epoch_device_t){24,2,0x1af4,0x1042,0x010000,0,0,{0,0,0,0,0xfe000004,0}};
    m.pci[0][0]=0x11111234;m.pci[0][1]=3;m.pci[0][2]=0x03000001;
    m.pci[0][4]=0xe0000008;
    m.pci[1][0]=0x10421af4;m.pci[1][1]=0x00100006;m.pci[1][2]=0x01000001;
    m.pci[1][8]=0xfe000004;
    le32(m.challenge,W98_EPOCH_MAGIC);le16(m.challenge+4,1);le16(m.challenge+6,1);
    le32(m.challenge+8,48);memcpy(m.challenge+16,expected.nonce,32);
    io=(w98_epoch_io_t){&m,pci_read,receive,send_bytes,clock_now,idle};
}
static void untouched(void){CHECK(!m.pci_writes && !m.vga_writes && !m.dma_writes);}
static void refused(void)
{
    CHECK(w98_native_epoch_gate(&gate,&expected,&io,1000)==-1);
    CHECK(!gate.protocol_admitted && gate.state==W98_EPOCH_FAILED);untouched();
}
int main(void)
{
    CHECK(w98_native_epoch_gate!=NULL); /* actual missing-function RED */
    fixture(0);CHECK(!w98_native_epoch_gate(&gate,&expected,&io,1000));
    CHECK(gate.protocol_admitted && gate.state==W98_EPOCH_ADMITTED && gate.nonce_consumed);
    CHECK(m.pci_calls==40 && m.write_at==256 && m.read_at==320);untouched();
    /* Literal wire fields are independent of the producer's serializer. */
    CHECK(!memcmp(m.output,"WDE1\1\0\2\0\0\1\0\0\2\0\0\0",16));
    CHECK(!memcmp(m.output+16,expected.nonce,32));CHECK(m.output[144]==0xe8 && m.output[145]==3);
    for(unsigned i=0;i<32;i++){
        CHECK(m.output[48+i]==0xa5);CHECK(m.output[80+i]==0x5a);CHECK(m.output[112+i]==0xc3);
    }
    for(unsigned i=146;i<152;i++)CHECK(!m.output[i]);
    CHECK(m.output[152]==16 && m.output[154]==1 && m.output[200]==24 && m.output[202]==2);
    CHECK(m.output[176]==8 && m.output[179]==0xe0 && m.output[240]==4 && m.output[243]==0xfe);
    CHECK(!m.output[248] && !m.output[255]);
    /* A consumed object cannot replay even its previously accepted grant. */
    unsigned old=m.pci_calls;refused();CHECK(m.pci_calls==old);
    fixture(1);m.challenge[16]^=1;refused();CHECK(!m.pci_calls && !m.write_at);
    fixture(2);m.challenge[4]=2;refused();CHECK(!m.pci_calls);
    fixture(3);expected.device[1].bdf=16;refused();CHECK(!m.receive_calls);
    fixture(4);expected.device[1].role=1;refused();CHECK(!m.receive_calls);
    fixture(5);m.pci[0][4]^=0x1000000;refused();CHECK(!m.write_at);
    fixture(6);m.pci[1][0]^=1;refused();CHECK(!m.write_at);
    for(unsigned id=7;id<=27;id++){fixture(id);refused();}
    fixture(0);m.chunk=1;CHECK(!w98_native_epoch_gate(&gate,&expected,&io,1000));untouched();
    fixture(0);expected.count=0;refused();CHECK(!m.receive_calls);
    fixture(0);memset(expected.nonce,0,32);refused();
    fixture(0);memset(expected.config_sha256[0],0,32);refused();
    fixture(0);memset(expected.rom_sha256,0,32);refused();
    fixture(0);expected.device[0].raw_bar[5]=4;refused();
    fixture(0);expected.device[0].command_forbidden=2;refused();
    fixture(0);m.pci[0][1]&=~1u;refused();CHECK(!m.write_at);
    fixture(0);m.pci[1][3]=0x10000;refused();CHECK(!m.write_at);
    fixture(0);m.ticks=1000;refused();CHECK(!m.receive_calls && !m.pci_calls);
    fixture(0);m.ticks=1001;refused();
    fixture(0);gate.nonce_consumed=1;refused();CHECK(!m.receive_calls);
    fixture(0);expected.nonce[0]^=1;refused(); /* full old challenge replay */
    fixture(0);expected.count=1;memset(&expected.device[1],0,sizeof expected.device[1]);
    memset(expected.config_sha256[1],0,32);
    CHECK(!w98_native_epoch_gate(&gate,&expected,&io,1000));CHECK(m.pci_calls==20);
    CHECK(m.output[12]==1 && m.output[152]==16 && !m.output[200]);untouched();
    fixture(0);expected.count=1;expected.device[0]=expected.device[1];
    memset(&expected.device[1],0,sizeof expected.device[1]);memset(expected.config_sha256[0],0,32);
    memset(expected.rom_sha256,0,32);
    CHECK(!w98_native_epoch_gate(&gate,&expected,&io,1000));CHECK(m.pci_calls==20);
    CHECK(m.output[12]==1 && m.output[152]==24 && m.output[154]==2 && !m.output[200]);untouched();
    printf("PASS %u checks; real bounded C protocol, modeled PCI/transport/clock/provenance only; zero device writes\n",checks);
    return 0;
}
