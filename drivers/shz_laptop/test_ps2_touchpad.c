/* SPDX-License-Identifier: GPL-2.0-only */
#include "ps2_touchpad.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned checks;
#define C(x) do { ++checks; assert(x); } while(0)
/* Byte-level auxiliary device model: ACKs, E6/E8 sliced arguments, E9
 * status, F3 mode set, FF self-test, injected faults and in-flight bytes. */
struct model {
    int synaptics,valid,fail_byte,stream_before_ack,resend_once;
    uint8_t queue[64];unsigned head,tail;
    uint8_t pending,slice,slices,mode,rate_arg,mode_set,enabled,resets;
    uint32_t caps,ext,ext0c;
};
static void push(struct model *m,uint8_t b){assert(m->tail<sizeof(m->queue));m->queue[m->tail++]=b;}
static int validate(void *c,uint64_t owner,uint64_t generation) {
    struct model *m=c;return m->valid && owner==11 && generation>=3?SHZ_DRIVER_OK:SHZ_REVOKED;
}
static void status(struct model *m) {
    uint32_t v=0;
    if(!m->synaptics){push(m,0x00);push(m,0x02);push(m,0x64);return;}
    switch(m->slice) {
    case 0x00: v=0x014784u;break; /* minor 1, magic, model 8 major 4 */
    case 0x02: v=m->caps;break;
    case 0x03: v=0x0123a5u;break;
    case 0x08: v=0x558040u;break; /* x 0x55, valid flag, y 0x40 units/mm */
    case 0x09: v=m->ext;break;
    case 0x0c: v=m->ext0c;break;
    default: v=0;
    }
    push(m,(uint8_t)(v>>16));push(m,(uint8_t)(v>>8));push(m,(uint8_t)v);
}
static int write_aux(void *c,uint8_t b,uint32_t us) {
    struct model *m=c;(void)us;
    if(m->fail_byte>=0 && b==(uint8_t)m->fail_byte && !m->pending){push(m,0xfc);return 0;}
    if(m->resend_once && b==0xe9 && !m->pending){m->resend_once=0;push(m,0xfe);return 0;}
    if(m->pending==0xe8){m->slice=(uint8_t)(((unsigned)m->slice<<2)|(b&3u));m->slices++;m->pending=0;push(m,0xfa);return 0;}
    if(m->pending==0xf3){m->rate_arg=b;if(b==0x14 && m->slices==4){m->mode=m->slice;m->mode_set=1;}
        m->pending=0;m->slices=0;push(m,0xfa);return 0;}
    switch(b) {
    case 0xe6: m->slice=0;m->slices=0;push(m,0xfa);break;
    case 0xe8: case 0xf3: m->pending=b;push(m,0xfa);break;
    case 0xe9: push(m,0xfa);status(m);m->slices=0;break;
    case 0xf5:
        if(m->stream_before_ack){push(m,0x80);push(m,0x10);push(m,0x00);}
        m->enabled=0;push(m,0xfa);break;
    case 0xf4: m->enabled=1;push(m,0xfa);break;
    case 0xf6: m->mode=0;push(m,0xfa);break;
    case 0xff: m->mode=0;m->enabled=0;m->resets++;push(m,0xfa);push(m,0xaa);push(m,0x00);break;
    default: push(m,0xfe);
    }
    return 0;
}
static int read_aux(void *c,uint8_t *b,uint32_t us) {
    struct model *m=c;(void)us;
    if(m->head==m->tail)return SHZ_TIMEOUT;
    *b=m->queue[m->head++];if(m->head==m->tail)m->head=m->tail=0;return 0;
}
static int drain(void *c,uint32_t us){struct model *m=c;(void)us;m->head=m->tail=0;return 0;}
static void packet(uint8_t p[6],int x,int y,uint8_t z,uint8_t w,uint8_t buttons,uint8_t xr) {
    unsigned ux=(unsigned)x&0x1fffu,uy=(unsigned)y&0x1fffu;
    p[0]=(uint8_t)(0x80u|((w&0xcu)<<2)|((w&2u)<<1)|(buttons&3u));
    p[1]=(uint8_t)((((uy>>8)&0xfu)<<4)|((ux>>8)&0xfu));
    p[2]=z;
    p[3]=(uint8_t)(0xc0u|(((uy>>12)&1u)<<5)|(((ux>>12)&1u)<<4)|((w&1u)<<2)|((p[0]^xr)&3u));
    p[4]=(uint8_t)ux;p[5]=(uint8_t)uy;
}
struct sink { unsigned calls;int32_t x,y;uint8_t buttons; };
static int sink_valid(void *c,uint64_t o,uint64_t g){(void)c;return o==11 && g==5?SHZ_DRIVER_OK:SHZ_REVOKED;}
static int sink_emit(void *c,int32_t x,int32_t y,uint8_t b){struct sink *s=c;s->calls++;s->x=x;s->y=y;s->buttons=b;return 0;}
static struct shz_ps2_ops ops_for(struct model *m) {
    struct shz_ps2_ops o={m,validate,write_aux,read_aux,drain};return o;
}
int main(void) {
    struct model m;struct shz_ps2_device d;struct shz_ps2_ops o;struct shz_pointer v,keep;
    struct shz_pointer_adapter a;struct sink s;uint8_t p[6];unsigned i;int r;
    struct shz_synaptics_info info;uint32_t id=77;uint8_t major=9,minor=9;
    const uint8_t bad_id[3]={1,0x46,4},good_id[3]={1,0x47,0x84};
    C(shz_synaptics_decode_identity(bad_id,&id,&major,&minor)==SHZ_NOT_FOUND && id==77 && major==9);
    C(shz_synaptics_decode_identity(good_id,&id,&major,&minor)==0 && major==4 && minor==1);

    /* Synaptics 4.x clickpad with W mode, extended queries and resolution. */
    memset(&m,0,sizeof(m));m.synaptics=1;m.valid=1;m.fail_byte=-1;m.stream_before_ack=1;m.resend_once=1;
    m.caps=(1u<<23)|(4u<<20)|0x4700u|(1u<<18)|(1u<<7)|(1u<<1);m.ext=0x800000u;m.ext0c=0x100000u;
    memset(&d,0,sizeof(d));o=ops_for(&m);
    C(shz_ps2_open(&d,&o,11,5,1000,30)==0 && d.kind==SHZ_PS2_SYNAPTICS && d.size==6);
    C(m.mode_set && m.mode==0xc1 && m.rate_arg==0x14 && m.enabled);
    C(d.info.major==4 && d.info.w_mode && d.info.clickpad && !d.info.middle && d.info.pass_through);
    C(d.info.x_res==0x55 && d.info.y_res==0x40 && d.info.model==0x0123a5u && !d.info.extra_buttons);
    C(shz_ps2_open(&d,&o,11,6,1000,30)==SHZ_BUSY);

    /* Absolute frames through the shared pointer adapter. */
    memset(&s,0,sizeof(s));memset(&a,0,sizeof(a));
    {struct shz_pointer_sink k={&s,sink_valid,sink_emit};C(shz_pointer_adapter_bind(&a,&k,11,5,10,10)==0);}
    packet(p,3000,2000,60,4,0,0);
    for(i=0;i<5;i++)C(shz_ps2_feed_adapter(&d,&a,p[i])==SHZ_NO_EVENT);
    C(shz_ps2_feed_adapter(&d,&a,p[5])==0 && s.calls==1 && s.x==0 && s.y==0); /* baseline */
    packet(p,3400,1800,60,4,1,0);
    for(i=0;i<6;i++)r=shz_ps2_feed_adapter(&d,&a,p[i]);
    C(r==0 && s.calls==2 && s.x==40 && s.y==20 && s.buttons==1); /* +Y up -> screen down */
    packet(p,3400,1800,60,4,0,1); /* clickpad press is (b0^b3) bit0 */
    C(shz_synaptics_decode(&d.info,30,p,&v)==0 && v.buttons==1 && v.count==1);
    packet(p,3400,1800,10,4,0,0); /* below touch threshold: lift */
    C(shz_synaptics_decode(&d.info,30,p,&v)==0 && v.count==0);
    packet(p,3400,1800,80,0,2,0); /* two fingers: buttons only, no contact */
    C(shz_synaptics_decode(&d.info,30,p,&v)==0 && v.count==0 && v.buttons==2);
    packet(p,8191,8190,60,4,0,0); /* coordinates above 8176 are negative */
    C(shz_synaptics_decode(&d.info,1,p,&v)==0 && v.count==0);
    keep=v;packet(p,3000,2000,60,2,0,0);
    C(shz_synaptics_decode(&d.info,30,p,&v)==SHZ_UNSUPPORTED && !memcmp(&v,&keep,sizeof(v)));
    packet(p,3000,2000,60,4,0,0);p[3]&=0x3f;
    C(shz_synaptics_decode(&d.info,30,p,&v)==SHZ_MALFORMED);

    /* Framing resync and owner revocation. */
    C(shz_ps2_feed(&d,0x08,&v)==SHZ_MALFORMED && d.resync==1);
    packet(p,3000,2000,60,4,0,0);
    for(i=0;i<3;i++)C(shz_ps2_feed(&d,p[i],&v)==SHZ_NO_EVENT);
    C(shz_ps2_feed(&d,0x00,&v)==SHZ_MALFORMED && d.resync==2 && d.have==0);
    m.valid=0;for(i=0;i<6;i++)r=shz_ps2_feed(&d,p[i],&v);
    C(r==SHZ_REVOKED);m.valid=1;
    for(i=0;i<6;i++)r=shz_ps2_feed(&d,p[i],&v);
    C(r==0 && v.count==1 && v.contacts[0].x==3000 && v.contacts[0].y==-2000);

    /* Extra buttons mask low coordinate bits; middle button without clickpad. */
    memset(&info,0,sizeof(info));info.extra_buttons=2;info.middle=1;
    packet(p,0x103,0x205,60,4,0,3);
    C(shz_synaptics_decode(&info,30,p,&v)==0 && v.contacts[0].x==0x102 && v.contacts[0].y==-0x204 && v.buttons==4);

    C(shz_ps2_close(&d)==0 && d.state==SHZ_PS2_CLOSED && m.resets==1 && m.mode==0);
    C(shz_ps2_feed(&d,0x80,&v)==SHZ_BUSY);
    C(shz_ps2_open(&d,&o,11,5,1000,30)==SHZ_STALE);

    /* Plain PS/2 mouse: identify status lacks 0x47 -> F6 defaults, relative. */
    memset(&m,0,sizeof(m));m.valid=1;m.fail_byte=-1;
    memset(&d,0,sizeof(d));o=ops_for(&m);
    C(shz_ps2_open(&d,&o,11,5,1000,30)==0 && d.kind==SHZ_PS2_RELATIVE && d.size==3 && !m.mode_set);
    {const uint8_t rel[3]={0x19,0x05,0xfb};
     C(shz_ps2_feed(&d,rel[0],&v)==SHZ_NO_EVENT && shz_ps2_feed(&d,rel[1],&v)==SHZ_NO_EVENT);
     C(shz_ps2_feed(&d,rel[2],&v)==0 && v.relative && v.contacts[0].x==5-256 && v.contacts[0].y==-(int32_t)0xfb && v.buttons==1);}
    {const uint8_t over[3]={0x48,1,1};C(shz_ps2_decode_relative(over,&v)==SHZ_MALFORMED);}
    C(shz_ps2_feed(&d,0x00,&v)==SHZ_MALFORMED);

    /* Device error mid-probe poisons; only reset clears quarantine. */
    memset(&m,0,sizeof(m));m.synaptics=1;m.valid=1;m.fail_byte=0xe9;m.caps=0x004700u;
    memset(&d,0,sizeof(d));o=ops_for(&m);
    C(shz_ps2_open(&d,&o,11,5,1000,30)==SHZ_IO && d.state==SHZ_PS2_POISONED);
    C(shz_ps2_open(&d,&o,11,6,1000,30)==SHZ_QUARANTINED);
    m.fail_byte=-1;C(shz_ps2_close(&d)==0);
    C(shz_ps2_open(&d,&o,11,6,1000,30)==0 && d.kind==SHZ_PS2_SYNAPTICS && !d.info.w_mode && m.mode==0xc4);
    /* Revoked before any I/O: refused without poisoning. */
    memset(&d,0,sizeof(d));m.valid=0;
    C(shz_ps2_open(&d,&o,11,5,1000,30)==SHZ_REVOKED && d.state==SHZ_PS2_EMPTY);
    C(shz_ps2_open(&d,&o,0,5,1000,30)==SHZ_INVALID);
    printf("PS/2 Synaptics touchpad: %u assertions PASS\n",checks);
    return 0;
}
