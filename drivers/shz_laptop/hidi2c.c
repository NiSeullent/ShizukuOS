/* SPDX-License-Identifier: GPL-2.0-only */
#include "internal.h"
static int valid(struct shz_hidi2c *h) {
    return h->ops.validate(h->ops.context,h->owner,h->generation,h->address)==SHZ_DRIVER_OK ? SHZ_DRIVER_OK:SHZ_REVOKED;
}
static int transfer(struct shz_hidi2c *h,const uint8_t *tx,size_t nt,size_t nr) {
    uint64_t start,end;int r=valid(h);if(r)return r;
    if(nr>sizeof(h->buffer))return SHZ_CAPACITY;
    start=h->ops.now_us(h->ops.context);
    r=h->ops.transfer(h->ops.context,h->address,tx,nt,h->buffer,nr,h->timeout_us);if(r)return r;
    end=h->ops.now_us(h->ops.context);
    if(end<start)return SHZ_CLOCK;
    if(end-start>=h->timeout_us)return SHZ_TIMEOUT;
    return valid(h);
}
static int command(struct shz_hidi2c *h,uint8_t opcode,uint8_t argument) {
    uint8_t tx[4];
    if(!h->command_known)return SHZ_UNSUPPORTED;
    tx[0]=(uint8_t)h->descriptor.command_register;
    tx[1]=(uint8_t)(h->descriptor.command_register>>8);tx[2]=argument;tx[3]=opcode;
    return transfer(h,tx,4,0);
}
static int interrupt(struct shz_hidi2c *h,int *level) {
    int r,l=0;r=valid(h);if(r)return r;
    r=h->ops.interrupt(h->ops.context,&l);if(r)return r;
    r=valid(h);if(r)return r;
    if(l!=0 && l!=1)return SHZ_MALFORMED;
    *level=l;return SHZ_DRIVER_OK;
}
static int discard_old_input(struct shz_hidi2c *h) {
    struct shz_budget budget;unsigned packets=0;int r,level;
    shz_budget_start(&budget,h->ops.now_us(h->ops.context),h->timeout_us);
    for(;;) {
        size_t length;
        r=shz_budget_poll(&budget,h->ops.now_us(h->ops.context));if(r)return r;
        r=interrupt(h,&level);if(r || !level)return r;
        if(++packets>16)return SHZ_BUSY;
        r=transfer(h,0,0,h->descriptor.input_bytes);if(r)return r;
        length=shz_le16(h->buffer);
        if(length && (length<2 || length>h->descriptor.input_bytes))return SHZ_MALFORMED;
        /* A previous RESET ack (length zero) must never acknowledge this RESET. */
        h->ops.relax(h->ops.context);
    }
}
static int enumerate(struct shz_hidi2c *h) {
    struct shz_budget budget;struct shz_hid_descriptor d;struct shz_hid_layout l;
    uint8_t tx[2];unsigned i;int r,level;
    tx[0]=(uint8_t)h->descriptor_register;tx[1]=(uint8_t)(h->descriptor_register>>8);
    r=transfer(h,tx,2,30);if(r)return r;
    r=shz_hid_parse_descriptor(h->buffer,30,&d);if(r)return r;
    /* Command register is trusted only after validating the complete descriptor. */
    h->descriptor=d;h->command_known=1;
    r=command(h,8,0);if(r)return r; /* SET_POWER(ON) */
    r=discard_old_input(h);if(r)return r;
    shz_budget_start(&budget,h->ops.now_us(h->ops.context),h->timeout_us);
    r=command(h,1,0);if(r)return r; /* RESET */
    for(;;) {
        r=shz_budget_poll(&budget,h->ops.now_us(h->ops.context));if(r)return r;
        r=interrupt(h,&level);if(r)return r;
        if(level)break;
        h->ops.relax(h->ops.context);
    }
    /* Input is a direct read; do not turn it into a vendor register protocol. */
    r=transfer(h,0,0,2);if(r)return r;
    if(h->buffer[0] || h->buffer[1])return SHZ_MALFORMED;
    tx[0]=(uint8_t)d.report_register;tx[1]=(uint8_t)(d.report_register>>8);
    r=transfer(h,tx,2,d.report_bytes);if(r)return r;
    r=shz_hid_parse_report(h->buffer,d.report_bytes,&l);if(r)return r;
    for(i=0;i<l.report_count;i++) {
        size_t bytes=(l.reports[i].bits+7u)/8u+2u+l.numbered;
        if(bytes>d.input_bytes)return SHZ_MALFORMED;
    }
    shz_copy(&h->layout,&l,sizeof(l));return SHZ_DRIVER_OK;
}
int shz_hidi2c_open(struct shz_hidi2c *h,const struct shz_i2c_ops *o,
    uint64_t owner,uint64_t generation,uint16_t address,uint16_t reg,uint32_t timeout) {
    int r;
    if(!h || !o || !o->validate || !o->transfer || !o->interrupt || !o->drain ||
       !o->now_us || !o->relax || !owner || !generation || !timeout || timeout>30000000u ||
       address<8 || address>0x77) return SHZ_INVALID;
    if(h->state!=SHZ_I2C_EMPTY && h->state!=SHZ_I2C_CLOSED)return SHZ_BUSY;
    if(generation<=h->generation)return SHZ_STALE;
    if(o->validate(o->context,owner,generation,address)!=SHZ_DRIVER_OK)return SHZ_REVOKED;
    h->ops=*o;h->owner=owner;h->generation=generation;h->address=address;
    h->descriptor_register=reg;h->timeout_us=timeout;h->state=SHZ_I2C_STARTING;h->command_known=0;
    r=enumerate(h);
    if(r){h->last_error=r;h->state=SHZ_I2C_QUARANTINED;return r;}
    h->state=SHZ_I2C_READY;h->last_error=0;return SHZ_DRIVER_OK;
}
int shz_hidi2c_input(struct shz_hidi2c *h,uint8_t *out,size_t capacity,size_t *bytes) {
    size_t length,fields;int r,level;
    if(!h || !out || !bytes)return SHZ_INVALID;
    if(h->state==SHZ_I2C_QUARANTINED)return SHZ_QUARANTINED;
    if(h->state!=SHZ_I2C_READY)return SHZ_BUSY;
    r=interrupt(h,&level);if(!r && !level)return SHZ_NO_EVENT;
    if(!r)r=transfer(h,0,0,h->descriptor.input_bytes);
    if(r){h->last_error=r;h->state=SHZ_I2C_QUARANTINED;return r;}
    length=shz_le16(h->buffer);
    if(!length){h->last_error=SHZ_STALE;h->state=SHZ_I2C_QUARANTINED;return SHZ_STALE;}
    if(length<2 || length>h->descriptor.input_bytes)return SHZ_MALFORMED;
    r=shz_hid_decode(&h->layout,h->buffer+2,length-2,0,0,&fields);if(r)return r;
    if(capacity<length-2)return SHZ_CAPACITY;
    shz_copy(out,h->buffer+2,length-2);*bytes=length-2;return SHZ_DRIVER_OK;
}
int shz_hidi2c_stop(struct shz_hidi2c *h,int suspend) {
    int r;
    if(!h || (suspend!=0 && suspend!=1))return SHZ_INVALID;
    if(h->state==SHZ_I2C_CLOSED)return SHZ_DRIVER_OK;
    if(h->state==SHZ_I2C_SUSPENDED && suspend)return SHZ_DRIVER_OK;
    if(!h->ops.validate || !h->ops.drain)return SHZ_INVALID;
    h->state=SHZ_I2C_STOPPING; /* No more input/resume/open admission. */
    r=valid(h);
    if(!r)r=h->ops.drain(h->ops.context,h->timeout_us);
    if(!r)r=valid(h);
    if(!r && h->command_known)r=command(h,8,1); /* SET_POWER(SLEEP), after a real controller drain. */
    if(!r)r=h->ops.drain(h->ops.context,h->timeout_us);
    if(!r)r=valid(h);
    if(r){h->last_error=r;h->state=SHZ_I2C_QUARANTINED;return SHZ_QUARANTINED;}
    h->state=suspend ? SHZ_I2C_SUSPENDED:SHZ_I2C_CLOSED;return SHZ_DRIVER_OK;
}
int shz_hidi2c_resume(struct shz_hidi2c *h) {
    int r;
    if(!h)return SHZ_INVALID;
    if(h->state!=SHZ_I2C_SUSPENDED)return SHZ_BUSY;
    h->state=SHZ_I2C_STARTING;r=enumerate(h);
    if(r){h->last_error=r;h->state=SHZ_I2C_QUARANTINED;return r;}
    h->state=SHZ_I2C_READY;return SHZ_DRIVER_OK;
}
