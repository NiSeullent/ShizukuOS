/* SPDX-License-Identifier: GPL-2.0-only */
#include "native_sessions.h"
/* Both existing cores use boolean platform callbacks. Validate at each I/O
 * boundary, including after a write whose effects may already be visible. */
#define CORE_GUARDS(prefix,session,dma_type,aperture) \
static int prefix##_valid(void *p,uint64_t owner,uint64_t generation) { \
    struct session *s=p;return s->owner.validate(s->owner.context,owner,generation); \
} \
static int prefix##_live(struct session *s) { \
    return prefix##_valid(s,s->lifecycle.owner,s->lifecycle.generation)==SHZ_OK; \
} \
static int prefix##_read(void *p,uint32_t off,uint32_t *value) { \
    struct session *s=p;uint32_t v; \
    if(!prefix##_live(s) || (off&3u) || off>s->config.aperture || s->config.aperture-off<4)return 0; \
    if(!s->platform.read32(s->platform.context,off,&v) || !prefix##_live(s))return 0; \
    *value=v;return 1; \
} \
static int prefix##_write(void *p,uint32_t off,uint32_t value) { \
    struct session *s=p; \
    if(!prefix##_live(s) || (off&3u) || off>s->config.aperture || s->config.aperture-off<4)return 0; \
    return s->platform.write32(s->platform.context,off,value) && prefix##_live(s); \
} \
static int prefix##_allocate(void *p,size_t n,size_t align,uint64_t mask,struct dma_type *block) { \
    struct session *s=p; \
    if(!prefix##_live(s))return 0; \
    /* Success must transfer allocation ownership even when the lease changes. */ \
    return s->platform.allocate(s->platform.context,n,align,mask,block); \
} \
static void prefix##_release(void *p,struct dma_type *block) { \
    struct session *s=p;s->platform.release(s->platform.context,block); \
} \
static int prefix##_sync(void *p,const struct dma_type *block,size_t off,size_t n,int to_device) { \
    struct session *s=p; \
    if(!prefix##_live(s))return 0; \
    return s->platform.sync(s->platform.context,block,off,n,to_device) && prefix##_live(s); \
} \
static uint64_t prefix##_now(void *p) { struct session *s=p;return s->platform.now_us(s->platform.context); } \
static void prefix##_relax(void *p) { struct session *s=p;s->platform.relax(s->platform.context); }
CORE_GUARDS(a,shz_ahci_session,ahci_dma,abar_bytes)
CORE_GUARDS(x,shz_xhci_session,xhci_dma,mmio_bytes)
#undef CORE_GUARDS
static int ahci_result(int r) {
    switch(r){case AHCI_OK:return SHZ_OK;case AHCI_INVALID:return SHZ_INVALID;
    case AHCI_UNSUPPORTED:return SHZ_UNSUPPORTED;case AHCI_TIMEOUT:return SHZ_TIMEOUT;
    case AHCI_QUARANTINED:return SHZ_QUARANTINED;case AHCI_CLOCK:return SHZ_CLOCK;
    case AHCI_BUSY:return SHZ_BUSY;case AHCI_BAD_IDENTIFY:return SHZ_MALFORMED;
    default:return SHZ_IO;}
}
static int xhci_result(int r) {
    switch(r){case XHCI_OK:return SHZ_OK;case XHCI_INVALID:return SHZ_INVALID;
    case XHCI_UNSUPPORTED:return SHZ_UNSUPPORTED;case XHCI_TIMEOUT:return SHZ_TIMEOUT;
    case XHCI_QUARANTINED:return SHZ_QUARANTINED;case XHCI_CLOCK:return SHZ_CLOCK;
    case XHCI_BAD_EVENT:return SHZ_MALFORMED;default:return SHZ_IO;}
}
static int a_start(void *p) {
    struct shz_ahci_session *s=p;
    struct ahci_ops ops={s,a_read,a_write,a_allocate,a_release,a_sync,a_now,a_relax};
    return ahci_result(ahci_open(&s->core,&ops,&s->config));
}
static int a_close(void *p) {return ahci_result(ahci_close(&((struct shz_ahci_session *)p)->core));}
static int x_write8(void *p,uint32_t off,uint8_t value) {
    struct shz_xhci_session *s=p;
    if(!x_live(s) || off>=s->config.mmio_bytes || !s->platform.write8)return 0;
    return s->platform.write8(s->platform.context,off,value) && x_live(s);
}
static int x_start(void *p) {
    struct shz_xhci_session *s=p;
    struct xhci_ops ops={s,x_read,x_write,x_allocate,x_release,x_sync,x_now,x_relax,0};
    if(s->platform.write8)ops.write8=x_write8;
    return xhci_result(xhci_open(&s->core,&ops,&s->config));
}
static int x_close(void *p) {return xhci_result(xhci_close(&((struct shz_xhci_session *)p)->core));}
#define BIND_CHECKS(native_empty,native_closed) \
    if(!s || !o || !o->validate || !p || !c || !p->read32 || !p->write32 || \
       !p->allocate || !p->release || !p->sync || !p->now_us || !p->relax || !owner || !generation)return SHZ_INVALID; \
    if((s->lifecycle.state!=SHZ_DEVICE_EMPTY && s->lifecycle.state!=SHZ_DEVICE_CLOSED) || \
       (s->core.state!=native_empty && s->core.state!=native_closed))return SHZ_BUSY; \
    if(generation<=s->lifecycle.generation)return SHZ_STALE; \
    if(o->validate(o->context,owner,generation)!=SHZ_OK)return SHZ_REVOKED;
int shz_ahci_bind(struct shz_ahci_session *s,const struct shz_core_owner *o,
    const struct ahci_ops *p,const struct ahci_config *c,uint64_t owner,uint64_t generation) {
    struct shz_device_ops ops;
    BIND_CHECKS(AHCI_EMPTY,AHCI_CLOSED)
    s->owner=*o;s->platform=*p;s->config=*c;
    ops.context=s;ops.validate=a_valid;ops.start=a_start;ops.close=a_close;ops.release=0;
    return shz_device_bind(&s->lifecycle,&ops,owner,generation);
}
int shz_xhci_bind(struct shz_xhci_session *s,const struct shz_core_owner *o,
    const struct xhci_ops *p,const struct xhci_config *c,uint64_t owner,uint64_t generation) {
    struct shz_device_ops ops;
    BIND_CHECKS(XHCI_EMPTY,XHCI_CLOSED)
    s->owner=*o;s->platform=*p;s->config=*c;
    ops.context=s;ops.validate=x_valid;ops.start=x_start;ops.close=x_close;ops.release=0;
    return shz_device_bind(&s->lifecycle,&ops,owner,generation);
}
#undef BIND_CHECKS
static int a_done(struct shz_ahci_session *s,const struct shz_ticket *ticket,int result) {
    int r=shz_device_complete(&s->lifecycle,ticket);if(r)return r;
    if(s->core.state==AHCI_RETAINED || !a_live(s))s->lifecycle.state=SHZ_DEVICE_QUARANTINED;
    else if(s->core.state==AHCI_CLOSED)(void)shz_device_stop(&s->lifecycle,0);
    if(result==SHZ_OK && s->lifecycle.state==SHZ_DEVICE_QUARANTINED)return SHZ_REVOKED;
    return result;
}
static int ahci_buffer_valid(const struct shz_ahci_session *s,const void *buffer,size_t bytes) {
    uintptr_t start=(uintptr_t)buffer,context=(uintptr_t)s,dma=(uintptr_t)s->core.dma.cpu;
    if(!bytes || start>UINTPTR_MAX-bytes)return 0;
    if(start<=context ? context-start<bytes:start-context<sizeof(*s))return 0;
    if(s->core.dma_owned && (start<=dma ? dma-start<bytes:start-dma<s->core.dma.bytes))return 0;
    return 1;
}
int shz_ahci_read(struct shz_ahci_session *s,uint64_t lba,unsigned count,void *out,size_t bytes) {
    struct shz_ticket t;uint8_t data[AHCI_SECTOR_BYTES*AHCI_MAX_SECTORS];size_t i;int r;
    if(!s || !out || count<1 || count>AHCI_MAX_SECTORS || bytes!=count*AHCI_SECTOR_BYTES)return SHZ_INVALID;
    if(!ahci_buffer_valid(s,out,bytes))return SHZ_INVALID;
    r=shz_device_admit(&s->lifecycle,&t);if(r)return r;
    r=a_done(s,&t,ahci_result(ahci_read_sectors(&s->core,lba,count,data,bytes)));
    if(r)return r;
    for(i=0;i<bytes;i++)((uint8_t *)out)[i]=data[i];
    return SHZ_OK;
}
int shz_ahci_write(struct shz_ahci_session *s,uint64_t lba,unsigned count,const void *input,size_t bytes) {
    struct shz_ticket t;int r;
    if(!s || !input || count<1 || count>AHCI_MAX_SECTORS || bytes!=count*AHCI_SECTOR_BYTES ||
       !ahci_buffer_valid(s,input,bytes))return SHZ_INVALID;
    r=shz_device_admit(&s->lifecycle,&t);if(r)return r;
    return a_done(s,&t,ahci_result(ahci_write_sectors(&s->core,lba,count,input,bytes)));
}
int shz_ahci_flush(struct shz_ahci_session *s) {
    struct shz_ticket t;int r;if(!s)return SHZ_INVALID;
    r=shz_device_admit(&s->lifecycle,&t);if(r)return r;
    return a_done(s,&t,ahci_result(ahci_flush(&s->core)));
}
int shz_xhci_noop(struct shz_xhci_session *s) {
    struct shz_ticket t;int r,done;if(!s)return SHZ_INVALID;
    r=shz_device_admit(&s->lifecycle,&t);if(r)return r;
    r=xhci_result(xhci_noop(&s->core));done=shz_device_complete(&s->lifecycle,&t);if(done)return done;
    if(s->core.state==XHCI_RETAINED || !x_live(s))s->lifecycle.state=SHZ_DEVICE_QUARANTINED;
    else if(s->core.state==XHCI_CLOSED)(void)shz_device_stop(&s->lifecycle,0);
    if(r==SHZ_OK && s->lifecycle.state==SHZ_DEVICE_QUARANTINED)return SHZ_REVOKED;
    return r;
}
