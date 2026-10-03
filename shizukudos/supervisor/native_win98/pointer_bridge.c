/* SPDX-License-Identifier: GPL-2.0-only */
#include "pointer_bridge.h"
#include "../src/devices.h"
static int source_valid(void *context) {
    struct w98_pointer_bridge *b=context;struct shz_hidi2c *h=b->source;
    if(!b->active || !h || h->state!=SHZ_I2C_READY || !h->ops.validate ||
       h->owner!=b->owner || h->generation!=b->generation || h->address!=b->address)return SHZ_REVOKED;
    return h->ops.validate(h->ops.context,b->owner,b->generation,b->address)==SHZ_DRIVER_OK?SHZ_DRIVER_OK:SHZ_REVOKED;
}
static int sink_valid(void *context,uint64_t owner,uint64_t generation) {
    struct w98_pointer_bridge *b=context;
    if(owner!=b->owner || generation!=b->generation)return SHZ_REVOKED;
    return source_valid(b);
}
static int sink_emit(void *context,int32_t x,int32_t y,uint8_t buttons) {
    return dev_native_pointer_input(context,x,y,buttons);
}
static int source_poll(void *context) {
    struct w98_pointer_bridge *b=context;int r=source_valid(b);
    if(r){b->last_error=r;return r;}
    /* Preserve the exact consumed report until the sink accepts it. A full
     * guest queue or accumulated movement bound must not silently lose input. */
    if(!b->pending) {
        r=shz_hidi2c_input(b->source,b->report,sizeof b->report,&b->report_bytes);
        if(r){if(r!=SHZ_NO_EVENT)b->last_error=r;return r;}
        b->pending=1;
    }
    r=shz_pointer_adapter_report(&b->adapter,&b->source->layout,b->report,b->report_bytes);
    if(r!=SHZ_CAPACITY && r!=SHZ_BUSY)b->pending=0;
    b->last_error=r;return r;
}
int w98_pointer_bind_i2c(struct w98_pointer_bridge *b,struct shz_hidi2c *h,uint32_t ux,uint32_t uy) {
    int r;struct shz_pointer_adapter previous;struct shz_pointer_sink sink={b,sink_valid,sink_emit};
    struct dev_native_pointer_ops source={b,source_valid,source_poll};
    if(!b || !h)return SHZ_INVALID;
    if(b->active || b->adapter.bound)return SHZ_BUSY;
    previous=b->adapter; /* Unbound/no DMA: failed attachment may be retried. */
    if(h->state!=SHZ_I2C_READY || !h->ops.validate || !h->ops.transfer || !h->ops.interrupt ||
       !h->ops.now_us)return SHZ_BUSY;
    if(!h->layout.pointer && !h->layout.touchpad)return SHZ_UNSUPPORTED;
    b->source=h;b->owner=h->owner;b->generation=h->generation;b->address=h->address;
    b->active=1;b->pending=0;b->report_bytes=0;
    r=shz_pointer_adapter_bind(&b->adapter,&sink,b->owner,b->generation,ux,uy);
    if(!r)r=dev_native_pointer_attach(&source);
    if(r){b->adapter=previous;b->active=0;b->last_error=r;return r;}
    b->last_error=SHZ_DRIVER_OK;return SHZ_DRIVER_OK;
}
int w98_pointer_unbind(struct w98_pointer_bridge *b) {
    int r;
    if(!b)return SHZ_INVALID;
    if(!b->active)return SHZ_DRIVER_OK;
    r=dev_native_pointer_detach(b);if(r)return r;
    (void)shz_pointer_adapter_close(&b->adapter);b->active=0;b->pending=0;return SHZ_DRIVER_OK;
}
