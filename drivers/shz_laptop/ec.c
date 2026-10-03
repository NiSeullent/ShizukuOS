/* SPDX-License-Identifier: GPL-2.0-only */
#include "internal.h"
#define EC_IBF 2u
#define EC_OBF 1u
#define EC_SCI 32u
static int status_read(struct shz_ec *e,uint32_t *v) {
    return shz_reg_read(&e->ops,e->owner,e->generation,&e->table.control,1,v);
}
static int poison(struct shz_ec *e,int r) {
    e->state=SHZ_EC_POISONED;e->last_error=r;return r;
}
static int owner_valid(struct shz_ec *e) {
    if(e->ops.validate(e->ops.context,e->owner,e->generation,&e->table.control,1,1)!=SHZ_DRIVER_OK ||
       e->ops.validate(e->ops.context,e->owner,e->generation,&e->table.data,1,1)!=SHZ_DRIVER_OK)
        return SHZ_REVOKED;
    return SHZ_DRIVER_OK;
}
int shz_ec_open(struct shz_ec *e,const struct shz_ec_table *t,
    const struct shz_register_ops *o,uint64_t owner,uint64_t generation,uint32_t timeout,int exclusive) {
    int r;
    if(!e || !t || !o || !o->validate || !o->read || !o->write || !o->now_us || !o->relax ||
       !owner || !generation || !timeout || timeout>30000000u) return SHZ_INVALID;
    if(exclusive!=1) return SHZ_UNSUPPORTED;
    if(e->state!=SHZ_EC_EMPTY && e->state!=SHZ_EC_CLOSED) return SHZ_BUSY;
    if(generation<=e->generation) return SHZ_STALE;
    r=shz_gas_valid(&t->control,1);if(r) return r;
    r=shz_gas_valid(&t->data,1);if(r) return r;
    if(t->control.space==t->data.space && t->control.address==t->data.address) return SHZ_INVALID;
    if(o->validate(o->context,owner,generation,&t->control,1,1)!=SHZ_DRIVER_OK ||
       o->validate(o->context,owner,generation,&t->data,1,1)!=SHZ_DRIVER_OK) return SHZ_REVOKED;
    e->ops=*o;shz_copy(&e->table,t,sizeof(*t));e->owner=owner;e->generation=generation;e->timeout_us=timeout;
    e->state=SHZ_EC_READY;e->last_error=0;return SHZ_DRIVER_OK;
}
static int wait_status(struct shz_ec *e,struct shz_budget *b,uint32_t mask,
    uint32_t value,uint32_t *out) {
    int r;uint32_t v;
    for(;;) {
        r=shz_budget_poll(b,e->ops.now_us(e->ops.context));if(r) return r;
        r=status_read(e,&v);if(r) return r;
        r=shz_budget_poll(b,e->ops.now_us(e->ops.context));if(r) return r;
        if((v&mask)==value) { if(out)*out=v;return SHZ_DRIVER_OK; }
        e->ops.relax(e->ops.context);
    }
}
static int begin(struct shz_ec *e,struct shz_budget *b,uint32_t *status) {
    int r;
    if(!e) return SHZ_INVALID;
    if(e->state==SHZ_EC_POISONED) return SHZ_QUARANTINED;
    if(e->state!=SHZ_EC_READY) return SHZ_BUSY;
    e->state=SHZ_EC_BUSY;
    shz_budget_start(b,e->ops.now_us(e->ops.context),e->timeout_us);
    r=owner_valid(e);if(r) return poison(e,r);
    r=wait_status(e,b,EC_IBF,0,status);if(r) return poison(e,r);
    /* Unexpected old output cannot be mistaken for the new command's reply. */
    if(*status&EC_OBF) return poison(e,SHZ_BUSY);
    return SHZ_DRIVER_OK;
}
static int send(struct shz_ec *e,struct shz_budget *b,int command,uint8_t value) {
    int r=wait_status(e,b,EC_IBF,0,0);if(r) return r;
    return shz_reg_write(&e->ops,e->owner,e->generation,
        command ? &e->table.control:&e->table.data,1,value);
}
static int receive(struct shz_ec *e,struct shz_budget *b,uint8_t *out) {
    uint32_t v;int r=wait_status(e,b,EC_OBF,EC_OBF,0);if(r) return r;
    r=shz_reg_read(&e->ops,e->owner,e->generation,&e->table.data,1,&v);if(r) return r;
    r=wait_status(e,b,EC_IBF,0,0);if(r) return r;
    *out=(uint8_t)v;return SHZ_DRIVER_OK;
}
int shz_ec_read(struct shz_ec *e,uint8_t address,uint8_t *out) {
    struct shz_budget b;uint32_t status;uint8_t v;int r;
    if(!out) return SHZ_INVALID;
    r=begin(e,&b,&status);if(r) return r;
    r=send(e,&b,1,0x80);if(!r)r=send(e,&b,0,address);
    if(!r)r=receive(e,&b,&v);
    if(r) return poison(e,r);
    e->state=SHZ_EC_READY;*out=v;return SHZ_DRIVER_OK;
}
int shz_ec_write(struct shz_ec *e,uint8_t address,uint8_t value) {
    struct shz_budget b;uint32_t status;int r=begin(e,&b,&status);if(r) return r;
    r=send(e,&b,1,0x81);if(!r)r=send(e,&b,0,address);
    if(!r)r=send(e,&b,0,value);
    if(!r)r=wait_status(e,&b,EC_IBF,0,0);
    if(r) return poison(e,r);
    e->state=SHZ_EC_READY;return SHZ_DRIVER_OK;
}
int shz_ec_query(struct shz_ec *e,uint8_t *out) {
    struct shz_budget b;uint32_t status;uint8_t v;int r;
    if(!out) return SHZ_INVALID;
    r=begin(e,&b,&status);if(r) return r;
    if(!(status&EC_SCI)) { e->state=SHZ_EC_READY;return SHZ_NO_EVENT; }
    r=send(e,&b,1,0x84);if(!r)r=receive(e,&b,&v);
    if(r) return poison(e,r);
    e->state=SHZ_EC_READY;*out=v;return SHZ_DRIVER_OK;
}
int shz_ec_close(struct shz_ec *e) {
    uint32_t status;int r;
    if(!e) return SHZ_INVALID;
    if(e->state==SHZ_EC_CLOSED || e->state==SHZ_EC_EMPTY) return SHZ_DRIVER_OK;
    if(e->state==SHZ_EC_POISONED) return SHZ_QUARANTINED;
    if(e->state!=SHZ_EC_READY) return SHZ_BUSY;
    r=status_read(e,&status);
    if(r || (status&(EC_IBF|EC_OBF))) { poison(e,r ? r:SHZ_BUSY);return SHZ_QUARANTINED; }
    e->state=SHZ_EC_CLOSED;return SHZ_DRIVER_OK;
}
int shz_ec_recover(struct shz_ec *e,int (*recover)(void *),void *context) {
    uint32_t status;int r;
    if(!e || !recover) return SHZ_INVALID;
    if(e->state!=SHZ_EC_POISONED) return SHZ_BUSY;
    r=owner_valid(e);if(r) return r;
    r=recover(context);if(r) return r;
    r=status_read(e,&status);if(r) return r;
    if(status&(EC_IBF|EC_OBF)) return SHZ_QUARANTINED;
    e->state=SHZ_EC_READY;e->last_error=0;return SHZ_DRIVER_OK;
}
