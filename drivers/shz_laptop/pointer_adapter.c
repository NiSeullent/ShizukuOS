/* SPDX-License-Identifier: GPL-2.0-only */
#include "internal.h"
static int64_t divide_units(int64_t value,uint32_t divisor,int64_t *remainder) {
    /* Freestanding i486 has no 64-bit division runtime. Remainder is always
     * below INT32_MAX, so the shift fits uint32_t without lost carry. */
    uint64_t magnitude=value<0?(uint64_t)(-value):(uint64_t)value,quotient=0;
    uint32_t rest=0;unsigned bit=64;
    while(bit) {
        --bit;rest=(rest<<1)|(uint32_t)((magnitude>>bit)&1u);
        if(rest>=divisor){rest-=divisor;quotient|=1ull<<bit;}
    }
    *remainder=value<0?-(int64_t)rest:(int64_t)rest;
    return value<0?-(int64_t)quotient:(int64_t)quotient;
}
int shz_pointer_adapter_bind(struct shz_pointer_adapter *a,const struct shz_pointer_sink *o,
    uint64_t owner,uint64_t generation,uint32_t ux,uint32_t uy) {
    if(!a || !o || !o->validate || !o->emit || !owner || !generation ||
       !ux || !uy || ux>INT32_MAX || uy>INT32_MAX)return SHZ_INVALID;
    if(a->bound)return SHZ_BUSY;
    if(generation<=a->generation)return SHZ_STALE;
    if(o->validate(o->context,owner,generation)!=SHZ_DRIVER_OK)return SHZ_REVOKED;
    a->sink=*o;a->owner=owner;a->generation=generation;a->units_x=ux;a->units_y=uy;
    a->previous_x=a->previous_y=0;a->remainder_x=a->remainder_y=0;
    a->contact=0;a->tracking=0;a->bound=1;return SHZ_DRIVER_OK;
}
int shz_pointer_adapter_input(struct shz_pointer_adapter *a,const struct shz_pointer *p) {
    int64_t x=0,y=0,rx=0,ry=0;int r;uint8_t tracking=0;uint16_t contact=0;
    if(!a || !p)return SHZ_INVALID;
    if(!a->bound)return SHZ_BUSY;
    if(a->sink.validate(a->sink.context,a->owner,a->generation)!=SHZ_DRIVER_OK)return SHZ_REVOKED;
    if(p->relative>1 || p->count>SHZ_HID_CONTACTS)return SHZ_MALFORMED;
    if(p->count>1 || p->buttons>7)return SHZ_UNSUPPORTED;
    if(p->count) {
        const struct shz_contact *c=p->contacts;
        if(!c->active || !c->has_x || !c->has_y)return SHZ_MALFORMED;
        if(p->relative) { x=c->x;y=c->y; }
        else {
            tracking=1;contact=c->id;
            if(a->tracking && a->contact==c->id) {
                x=(int64_t)c->x-a->previous_x+a->remainder_x;
                y=(int64_t)c->y-a->previous_y+a->remainder_y;
            }
        }
    } else if(p->relative)return SHZ_MALFORMED;
    if(p->relative) { x+=a->remainder_x;y+=a->remainder_y; }
    x=divide_units(x,a->units_x,&rx);y=divide_units(y,a->units_y,&ry);
    if(x<INT32_MIN || x>INT32_MAX || y<INT32_MIN || y>INT32_MAX)return SHZ_CAPACITY;
    /* Sink owns the publication boundary and validates before committing.
     * Rechecking after publication could report an error after visible input. */
    r=a->sink.emit(a->sink.context,(int32_t)x,(int32_t)y,p->buttons);if(r)return r;
    a->remainder_x=rx;a->remainder_y=ry;a->tracking=tracking;a->contact=contact;
    if(tracking){a->previous_x=p->contacts[0].x;a->previous_y=p->contacts[0].y;}
    return SHZ_DRIVER_OK;
}
int shz_pointer_adapter_report(struct shz_pointer_adapter *a,const struct shz_hid_layout *l,
    const uint8_t *p,size_t n) {
    struct shz_pointer v;int r=shz_hid_pointer(l,p,n,&v);if(r)return r;
    return shz_pointer_adapter_input(a,&v);
}
int shz_pointer_adapter_close(struct shz_pointer_adapter *a) {
    if(!a)return SHZ_INVALID;
    /* No DMA ownership moves here. The transport must be drained by its owner. */
    a->bound=0;a->tracking=0;a->remainder_x=a->remainder_y=0;return SHZ_DRIVER_OK;
}
