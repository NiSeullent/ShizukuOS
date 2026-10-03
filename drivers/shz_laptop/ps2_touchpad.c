/* SPDX-License-Identifier: GPL-2.0-only -- independently authored from the
 * public Synaptics PS/2 TouchPad Interfacing Guide packet/command layout. */
#include "internal.h"
#include "ps2_touchpad.h"

#define PS2_ACK 0xfau
#define PS2_RESEND 0xfeu
#define PS2_ERROR 0xfcu
#define PS2_STREAM_SKIP 8u     /* in-flight stream bytes tolerated before F5 ACK */
#define PS2_RESET_US 1000000u  /* self-test after FF takes up to ~500 ms */
#define SYN_MAGIC 0x47u
#define SYN_CAP_EXTENDED (1ul<<23)
#define SYN_CAP_MIDDLE (1ul<<18)
#define SYN_CAP_PASS_THROUGH (1ul<<7)
#define SYN_CAP_MULTIFINGER (1ul<<1)
#define SYN_XY_MAX_POSITIVE 8176
#define SYN_XY_WRAP 8192

static int alive(struct shz_ps2_device *d) {
    return d->ops.validate(d->ops.context,d->owner,d->generation)==SHZ_DRIVER_OK ?
        SHZ_DRIVER_OK:SHZ_REVOKED;
}
static int read_byte(struct shz_ps2_device *d,uint8_t *b,uint32_t us) {
    int r=d->ops.read_aux(d->ops.context,b,us);
    return r<0 ? r:(r ? SHZ_IO:SHZ_DRIVER_OK);
}
static int write_byte(struct shz_ps2_device *d,uint8_t b) {
    int r=d->ops.write_aux(d->ops.context,b,d->timeout_us);
    return r<0 ? r:(r ? SHZ_IO:SHZ_DRIVER_OK);
}
/* One command or argument byte acknowledged by FA; FE is retried twice. */
static int command(struct shz_ps2_device *d,uint8_t byte) {
    unsigned attempt;uint8_t reply=0;int r;
    for(attempt=0;attempt<3;attempt++) {
        r=alive(d);if(r)return r;
        r=write_byte(d,byte);if(r)return r;
        r=read_byte(d,&reply,d->timeout_us);if(r)return r;
        if(reply==PS2_ACK)return SHZ_DRIVER_OK;
        if(reply==PS2_ERROR)return SHZ_IO;
        if(reply!=PS2_RESEND)return SHZ_MALFORMED;
    }
    return SHZ_IO;
}
/* F5 while streaming: up to PS2_STREAM_SKIP already-queued packet bytes may
 * precede the ACK. Anything else is a protocol failure. */
static int stop_stream(struct shz_ps2_device *d) {
    unsigned seen;uint8_t reply=0;int r;
    r=d->ops.drain(d->ops.context,d->timeout_us);if(r)return r<0 ? r:SHZ_IO;
    r=alive(d);if(r)return r;
    r=write_byte(d,0xf5);if(r)return r;
    for(seen=0;seen<=PS2_STREAM_SKIP;seen++) {
        r=read_byte(d,&reply,d->timeout_us);if(r)return r;
        if(reply==PS2_ACK) {
            r=d->ops.drain(d->ops.context,d->timeout_us);
            return r<0 ? r:(r ? SHZ_IO:SHZ_DRIVER_OK);
        }
        if(reply==PS2_ERROR || reply==PS2_RESEND)return SHZ_IO;
    }
    return SHZ_MALFORMED;
}
/* Synaptics special command: E6 then four E8 arguments carrying 2 bits each. */
static int sliced(struct shz_ps2_device *d,uint8_t value) {
    unsigned shift;int r=command(d,0xe6);
    for(shift=8;!r && shift>0;) {
        shift-=2;
        r=command(d,0xe8);
        if(!r)r=command(d,(uint8_t)(((unsigned)value>>shift)&3u));
    }
    return r;
}
static int query(struct shz_ps2_device *d,uint8_t which,uint8_t out[3]) {
    unsigned i;int r=sliced(d,which);
    if(!r)r=command(d,0xe9);
    for(i=0;!r && i<3;i++)r=read_byte(d,&out[i],d->timeout_us);
    return r;
}
static uint32_t bytes24(const uint8_t s[3]) {
    return ((uint32_t)s[0]<<16)|((uint32_t)s[1]<<8)|s[2];
}
int shz_synaptics_decode_identity(const uint8_t s[3],uint32_t *identity,
                                  uint8_t *major,uint8_t *minor) {
    if(!s || !identity || !major || !minor)return SHZ_INVALID;
    if(s[1]!=SYN_MAGIC)return SHZ_NOT_FOUND;
    *identity=bytes24(s);*major=(uint8_t)(s[2]&0x0fu);*minor=s[0];
    return SHZ_DRIVER_OK;
}
int shz_synaptics_decode_capabilities(const uint8_t s[3],uint32_t *caps) {
    if(!s || !caps)return SHZ_INVALID;
    /* Capability words carry the same 0x47 middle byte; a different value is
     * firmware without valid capability reporting. */
    if(s[1]!=SYN_MAGIC)return SHZ_NOT_FOUND;
    *caps=bytes24(s);return SHZ_DRIVER_OK;
}
int shz_ps2_decode_relative(const uint8_t p[3],struct shz_pointer *out) {
    struct shz_pointer v;int32_t dx,dy;
    if(!p || !out)return SHZ_INVALID;
    if(!(p[0]&0x08u))return SHZ_MALFORMED;
    if(p[0]&0xc0u)return SHZ_MALFORMED; /* X/Y overflow: magnitude unknown */
    dx=(int32_t)p[1]-((p[0]&0x10u) ? 256:0);
    dy=(int32_t)p[2]-((p[0]&0x20u) ? 256:0);
    shz_zero(&v,sizeof(v));
    v.relative=1;v.count=1;v.buttons=(uint8_t)(p[0]&7u);
    v.contacts[0].x=dx;v.contacts[0].y=-dy; /* PS/2 +Y is up, screen +Y is down */
    v.contacts[0].active=1;v.contacts[0].has_x=1;v.contacts[0].has_y=1;
    *out=v;return SHZ_DRIVER_OK;
}
int shz_synaptics_decode(const struct shz_synaptics_info *info,uint8_t touch_z,
                         const uint8_t raw[6],struct shz_pointer *out) {
    struct shz_pointer v;uint8_t p[6],w=4,x_or;int32_t x,y;
    if(!info || !raw || !out || !touch_z)return SHZ_INVALID;
    if((raw[0]&0xc8u)!=0x80u || (raw[3]&0xc8u)!=0xc0u)return SHZ_MALFORMED;
    shz_copy(p,raw,6);x_or=(uint8_t)(p[0]^p[3]);
    if(info->w_mode) {
        w=(uint8_t)(((p[0]&0x30u)>>2)|((p[0]&0x04u)>>1)|((p[3]&0x04u)>>2));
        /* W2 is a pass-through guest packet (or invalid without one), W3 is
         * reserved/extended W. Neither is decoded as touchpad motion. */
        if(w==2 || w==3)return SHZ_UNSUPPORTED;
    }
    if(info->extra_buttons && (x_or&0x02u)) {
        /* Extra-button state replaces low coordinate bits; not published. */
        uint8_t bits=(uint8_t)((info->extra_buttons+1u)>>1),mask=(uint8_t)((1u<<bits)-1u);
        p[4]=(uint8_t)(p[4]&~mask);p[5]=(uint8_t)(p[5]&~mask);
    }
    shz_zero(&v,sizeof(v));
    v.buttons=(uint8_t)(p[0]&3u);
    if(info->clickpad)v.buttons=(uint8_t)(v.buttons|(x_or&1u));
    else if(info->middle && (x_or&1u))v.buttons=(uint8_t)(v.buttons|4u);
    x=(int32_t)((((uint32_t)p[3]&0x10u)<<8)|(((uint32_t)p[1]&0x0fu)<<8)|p[4]);
    y=(int32_t)((((uint32_t)p[3]&0x20u)<<7)|(((uint32_t)p[1]&0xf0u)<<4)|p[5]);
    if(x>SYN_XY_MAX_POSITIVE)x-=SYN_XY_WRAP;
    if(y>SYN_XY_MAX_POSITIVE)y-=SYN_XY_WRAP;
    /* Multi-finger frames (W 0/1) keep buttons but publish no contact, so the
     * adapter re-baselines instead of guessing a gesture. */
    if(p[2]>=touch_z && x>1 && !(info->w_mode && w<2 &&
       (info->capabilities&SYN_CAP_MULTIFINGER))) {
        v.count=1;v.contacts[0].id=1;v.contacts[0].x=x;v.contacts[0].y=-y;
        v.contacts[0].active=1;v.contacts[0].has_x=1;v.contacts[0].has_y=1;
    }
    *out=v;return SHZ_DRIVER_OK;
}
static int probe_synaptics(struct shz_ps2_device *d,struct shz_synaptics_info *info) {
    uint8_t s[3]={0,0,0},requests;int r;
    shz_zero(info,sizeof(*info));
    r=query(d,0x00,s);if(r)return r;
    r=shz_synaptics_decode_identity(s,&info->identity,&info->major,&info->minor);
    if(r==SHZ_NOT_FOUND || (!r && info->major<4))return SHZ_NOT_FOUND;
    if(r)return r;
    r=query(d,0x02,s);if(r)return r;
    if(shz_synaptics_decode_capabilities(s,&info->capabilities))info->capabilities=0;
    r=query(d,0x03,s);if(r)return r;
    info->model=bytes24(s);
    requests=(uint8_t)((info->capabilities>>20)&7u);
    if(requests>=1) {
        r=query(d,0x09,s);if(r)return r;
        info->ext_cap=bytes24(s);
        info->extra_buttons=(uint8_t)((info->ext_cap>>12)&0x0fu);
        if(info->extra_buttons>8)info->extra_buttons=0; /* invalid count */
    }
    if(requests>=4) {
        r=query(d,0x0c,s);if(r)return r;
        info->ext_cap_0c=bytes24(s);
        info->clickpad=(uint8_t)((info->ext_cap_0c&((1ul<<20)|(1ul<<8))) ? 1:0);
    }
    r=query(d,0x08,s);if(r)return r;
    if(s[0] && (s[1]&0x80u) && s[2]){info->x_res=s[0];info->y_res=s[2];}
    info->w_mode=(uint8_t)((info->capabilities&SYN_CAP_EXTENDED) ? 1:0);
    info->middle=(uint8_t)((info->capabilities&SYN_CAP_MIDDLE) && !info->clickpad ? 1:0);
    info->pass_through=(uint8_t)((info->capabilities&SYN_CAP_PASS_THROUGH) ? 1:0);
    /* Absolute + 80 pps; W mode when extended, otherwise disable gestures. */
    r=sliced(d,(uint8_t)(0xc0u|(info->w_mode ? 0x01u:0x04u)));
    if(!r)r=command(d,0xf3);
    if(!r)r=command(d,0x14);
    return r;
}
int shz_ps2_open(struct shz_ps2_device *d,const struct shz_ps2_ops *o,uint64_t owner,
                 uint64_t generation,uint32_t timeout_us,uint8_t touch_z) {
    struct shz_synaptics_info info;int r;
    if(!d || !o || !o->validate || !o->write_aux || !o->read_aux || !o->drain ||
       !owner || !generation || !timeout_us || !touch_z)return SHZ_INVALID;
    if(d->state==SHZ_PS2_POISONED)return SHZ_QUARANTINED;
    if(d->state==SHZ_PS2_STREAMING)return SHZ_BUSY;
    if(generation<=d->generation)return SHZ_STALE;
    if(o->validate(o->context,owner,generation)!=SHZ_DRIVER_OK)return SHZ_REVOKED;
    d->ops=*o;d->owner=owner;d->generation=generation;d->timeout_us=timeout_us;
    d->touch_z=touch_z;d->have=0;d->resync=0;d->kind=SHZ_PS2_NONE;
    shz_zero(&d->info,sizeof(d->info));
    /* From here every failure leaves the device in an unknown mode. */
    r=stop_stream(d);
    if(!r) {
        r=probe_synaptics(d,&info);
        if(!r){d->info=info;d->kind=SHZ_PS2_SYNAPTICS;d->size=6;}
        else if(r==SHZ_NOT_FOUND) {
            /* Identification produced a non-Synaptics status: standard mode. */
            r=command(d,0xf6);
            if(!r){d->kind=SHZ_PS2_RELATIVE;d->size=3;}
        }
    }
    if(!r)r=command(d,0xf4);
    if(r){d->state=SHZ_PS2_POISONED;d->last_error=r;d->kind=SHZ_PS2_NONE;return r;}
    d->state=SHZ_PS2_STREAMING;d->last_error=0;return SHZ_DRIVER_OK;
}
int shz_ps2_feed(struct shz_ps2_device *d,uint8_t byte,struct shz_pointer *out) {
    struct shz_pointer v;int r;
    if(!d || !out)return SHZ_INVALID;
    if(d->state!=SHZ_PS2_STREAMING)return SHZ_BUSY;
    if(d->have==0 && (d->kind==SHZ_PS2_SYNAPTICS ? (byte&0xc8u)!=0x80u:!(byte&0x08u)))
        goto resync;
    if(d->kind==SHZ_PS2_SYNAPTICS && d->have==3 && (byte&0xc8u)!=0xc0u)goto resync;
    d->packet[d->have++]=byte;
    if(d->have<d->size)return SHZ_NO_EVENT;
    d->have=0;
    if(alive(d))return SHZ_REVOKED;
    r=d->kind==SHZ_PS2_SYNAPTICS ? shz_synaptics_decode(&d->info,d->touch_z,d->packet,&v):
                                   shz_ps2_decode_relative(d->packet,&v);
    if(r)return r;
    *out=v;return SHZ_DRIVER_OK;
resync:
    d->have=0;if(d->resync<UINT32_MAX)d->resync++;
    return SHZ_MALFORMED;
}
int shz_ps2_feed_adapter(struct shz_ps2_device *d,struct shz_pointer_adapter *a,uint8_t byte) {
    struct shz_pointer v;int r;
    if(!a)return SHZ_INVALID;
    r=shz_ps2_feed(d,byte,&v);if(r)return r;
    return shz_pointer_adapter_input(a,&v);
}
int shz_ps2_close(struct shz_ps2_device *d) {
    uint8_t aa=0,id=0;int r;
    if(!d)return SHZ_INVALID;
    if(d->state==SHZ_PS2_CLOSED)return SHZ_DRIVER_OK;
    if(d->state==SHZ_PS2_EMPTY)return SHZ_INVALID;
    r=stop_stream(d);
    if(!r)r=command(d,0xff);
    if(!r)r=read_byte(d,&aa,PS2_RESET_US>d->timeout_us ? PS2_RESET_US:d->timeout_us);
    if(!r)r=read_byte(d,&id,d->timeout_us);
    if(!r && (aa!=0xaau || id!=0x00u))r=SHZ_MALFORMED;
    if(r){d->state=SHZ_PS2_POISONED;d->last_error=r;return r;}
    d->state=SHZ_PS2_CLOSED;d->kind=SHZ_PS2_NONE;d->have=0;
    shz_zero(&d->info,sizeof(d->info));return SHZ_DRIVER_OK;
}
