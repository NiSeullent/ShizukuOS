/* SPDX-License-Identifier: GPL-2.0-only */
#include "device.h"
int shz_device_bind(struct shz_device *d,const struct shz_device_ops *o,
                    uint64_t owner,uint64_t generation) {
    unsigned i;
    if(!d || !o || !o->validate || !o->start || !o->close || !owner || !generation)
        return SHZ_INVALID;
    if((d->state!=SHZ_DEVICE_EMPTY && d->state!=SHZ_DEVICE_CLOSED) || d->pending)
        return SHZ_BUSY;
    if(generation<=d->generation) return SHZ_STALE;
    if(o->validate(o->context,owner,generation)!=SHZ_DRIVER_OK) return SHZ_REVOKED;
    d->ops=*o; d->owner=owner; d->generation=generation; d->next_sequence=1;
    d->state=SHZ_DEVICE_EMPTY; d->target_suspend=0; d->release_done=0; d->last_error=0;
    for(i=0;i<SHZ_DEVICE_SLOTS;i++) d->slots[i]=0;
    return SHZ_DRIVER_OK;
}
int shz_device_stop(struct shz_device *d,int suspend) {
    int status;
    if(!d || (suspend!=0 && suspend!=1)) return SHZ_INVALID;
    if(d->state==SHZ_DEVICE_CLOSED) return SHZ_DRIVER_OK;
    if(d->state==SHZ_DEVICE_SUSPENDED && suspend) return SHZ_DRIVER_OK;
    if(!d->ops.validate || !d->ops.close) return SHZ_INVALID;
    /* Admission closes BEFORE an external call, including validation. */
    d->state=SHZ_DEVICE_STOPPING; d->target_suspend=(uint32_t)suspend;
    if(d->pending) return SHZ_BUSY;
    if(d->ops.validate(d->ops.context,d->owner,d->generation)!=SHZ_DRIVER_OK) {
        d->last_error=SHZ_REVOKED; d->state=SHZ_DEVICE_QUARANTINED;
        return SHZ_QUARANTINED;
    }
    status=d->ops.close(d->ops.context);
    if(status!=SHZ_DRIVER_OK) {
        d->last_error=status; d->state=SHZ_DEVICE_QUARANTINED;
        return SHZ_QUARANTINED;
    }
    if(d->ops.validate(d->ops.context,d->owner,d->generation)!=SHZ_DRIVER_OK) {
        d->last_error=SHZ_REVOKED;d->state=SHZ_DEVICE_QUARANTINED;
        return SHZ_QUARANTINED;
    }
    d->state=suspend ? SHZ_DEVICE_SUSPENDED:SHZ_DEVICE_CLOSED;
    if(!suspend && !d->release_done) {
        d->release_done=1;
        if(d->ops.release) d->ops.release(d->ops.context);
    }
    return SHZ_DRIVER_OK;
}
int shz_device_start(struct shz_device *d) {
    int status,closed;
    if(!d || !d->ops.validate || !d->ops.start) return SHZ_INVALID;
    if(d->state!=SHZ_DEVICE_EMPTY && d->state!=SHZ_DEVICE_SUSPENDED) return SHZ_BUSY;
    if(d->ops.validate(d->ops.context,d->owner,d->generation)!=SHZ_DRIVER_OK) return SHZ_REVOKED;
    d->state=SHZ_DEVICE_STARTING; status=d->ops.start(d->ops.context);
    if(status!=SHZ_DRIVER_OK) {
        closed=shz_device_stop(d,0); d->last_error=status;
        return closed==SHZ_DRIVER_OK ? status:SHZ_QUARANTINED;
    }
    /* A start callback cannot return a stale grant after resource revocation. */
    if(d->ops.validate(d->ops.context,d->owner,d->generation)!=SHZ_DRIVER_OK) {
        d->state=SHZ_DEVICE_QUARANTINED; d->last_error=SHZ_REVOKED;
        return SHZ_QUARANTINED;
    }
    d->state=SHZ_DEVICE_RUNNING; d->last_error=0; return SHZ_DRIVER_OK;
}
int shz_device_resume(struct shz_device *d) {
    if(!d) return SHZ_INVALID;
    if(d->state!=SHZ_DEVICE_SUSPENDED) return SHZ_BUSY;
    return shz_device_start(d);
}
int shz_device_admit(struct shz_device *d,struct shz_ticket *t) {
    unsigned i;
    if(!d || !t) return SHZ_INVALID;
    if(d->state!=SHZ_DEVICE_RUNNING) return SHZ_BUSY;
    if(d->ops.validate(d->ops.context,d->owner,d->generation)!=SHZ_DRIVER_OK) {
        d->state=SHZ_DEVICE_QUARANTINED; d->last_error=SHZ_REVOKED;
        return SHZ_REVOKED;
    }
    if(!d->next_sequence || d->next_sequence==UINT64_MAX) return SHZ_CAPACITY;
    for(i=0;i<SHZ_DEVICE_SLOTS;i++) if(!d->slots[i]) {
        d->slots[i]=d->next_sequence++;
        t->generation=d->generation; t->sequence=d->slots[i]; t->slot=i;
        ++d->pending; return SHZ_DRIVER_OK;
    }
    return SHZ_CAPACITY;
}
int shz_device_complete(struct shz_device *d,const struct shz_ticket *t) {
    if(!d || !t) return SHZ_INVALID;
    if(t->generation!=d->generation || !t->sequence || t->slot>=SHZ_DEVICE_SLOTS ||
       d->slots[t->slot]!=t->sequence || !d->pending) return SHZ_STALE;
    d->slots[t->slot]=0; --d->pending; return SHZ_DRIVER_OK;
}
