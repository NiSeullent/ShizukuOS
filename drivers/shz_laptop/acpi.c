/* SPDX-License-Identifier: GPL-2.0-only */
#include "internal.h"
static int fixed_register(const uint8_t *p,size_t n,size_t ext,size_t legacy,
    unsigned bytes,int optional,struct shz_gas *out) {
    struct shz_gas g;int r;
    shz_zero(&g,sizeof(g));
    if(n>ext && n<ext+12)return SHZ_MALFORMED;
    if(n>=ext+12 && shz_le64(p+ext+4)) g=shz_gas_read(p+ext);
    else { g.space=1;g.bits=(uint8_t)(bytes*8);g.address=shz_le32(p+legacy); }
    if(!g.address && optional) { *out=g;return SHZ_OK; }
    r=shz_gas_valid(&g,bytes);if(r) return r;
    *out=g;return SHZ_OK;
}
int shz_parse_fadt(const void *table,size_t bytes,struct shz_fixed *out) {
    const uint8_t *p=table;struct shz_fixed f;size_t n;int r;
    if(!out) return SHZ_INVALID;
    r=shz_table(p,bytes,"FACP",116,&n);if(r) return r;
    shz_zero(&f,sizeof(f));f.flags=shz_le32(p+112);
    if(f.flags&(1u<<20)) return SHZ_UNSUPPORTED;
    if(p[88]!=4 || p[89]!=2) return SHZ_UNSUPPORTED;
    r=fixed_register(p,n,148,56,4,0,&f.event_a);if(r) return r;
    r=fixed_register(p,n,160,60,4,1,&f.event_b);if(r) return r;
    r=fixed_register(p,n,172,64,2,0,&f.control_a);if(r) return r;
    r=fixed_register(p,n,184,68,2,1,&f.control_b);if(r) return r;
    f.sci=shz_le16(p+46);f.smi_command=shz_le32(p+48);f.enable=p[52];f.disable=p[53];
    if(f.smi_command>65535u) return SHZ_UNSUPPORTED;
    if(f.flags&(1u<<10)) {
        if(n<129) return SHZ_MALFORMED;
        f.reset=shz_gas_read(p+116);r=shz_gas_valid(&f.reset,1);if(r) return r;
        f.reset_value=p[128];
    }
    *out=f;return SHZ_OK;
}
int shz_parse_ecdt(const void *table,size_t bytes,struct shz_ec_table *out) {
    const uint8_t *p=table;struct shz_ec_table e;size_t n,i;int r;
    if(!out) return SHZ_INVALID;
    r=shz_table(p,bytes,"ECDT",66,&n);if(r) return r;
    shz_zero(&e,sizeof(e));e.control=shz_gas_read(p+36);e.data=shz_gas_read(p+48);
    r=shz_gas_valid(&e.control,1);if(r) return r;
    r=shz_gas_valid(&e.data,1);if(r) return r;
    if(e.control.space==e.data.space && e.control.address==e.data.address) return SHZ_MALFORMED;
    e.uid=shz_le32(p+60);e.gpe=p[64];
    if(p[65]!='\\') return SHZ_MALFORMED;
    for(i=0;i<n-65;i++) {
        uint8_t c=p[65+i];
        if(i>=sizeof(e.path)) return SHZ_CAPACITY;
        e.path[i]=(char)c;
        if(!c) break;
        if(c!='\\' && c!='.' && c!='_' && !(c>='A' && c<='Z') && !(c>='0' && c<='9'))
            return SHZ_MALFORMED;
    }
    if(i==n-65 || i==0) return SHZ_MALFORMED;
    shz_copy(out,&e,sizeof(e));return SHZ_OK;
}
static int fixed_read(struct shz_fixed_power *p,const struct shz_gas *g,
    unsigned bytes,uint32_t *v) { return shz_reg_read(&p->ops,p->owner,p->generation,g,bytes,v); }
static int fixed_write(struct shz_fixed_power *p,const struct shz_gas *g,
    unsigned bytes,uint32_t v) { return shz_reg_write(&p->ops,p->owner,p->generation,g,bytes,v); }
int shz_fixed_events(struct shz_fixed_power *p,uint16_t *out) {
    uint32_t a,b=0;int r;
    if(!p || !out) return SHZ_INVALID;
    r=fixed_read(p,&p->table.event_a,4,&a);if(r) return r;
    if(p->table.event_b.address) { r=fixed_read(p,&p->table.event_b,4,&b);if(r) return r; }
    *out=(uint16_t)((a&(a>>16))|(b&(b>>16)));return SHZ_OK;
}
static int ack_register(struct shz_fixed_power *p,const struct shz_gas *g,uint16_t events) {
    struct shz_gas word;uint32_t current;int r;
    if(g->access==3) {
        /* A required DWORD access includes the enable half. Preserve it; never
         * write the old status half back to W1C hardware. */
        r=fixed_read(p,g,4,&current);if(r)return r;
        return fixed_write(p,g,4,(current&0xffff0000u)|events);
    }
    word=*g;word.bits=16;word.access=2;
    return fixed_write(p,&word,2,events);
}
int shz_fixed_ack(struct shz_fixed_power *p,uint16_t events) {
    int r;
    if(!p) return SHZ_INVALID;
    if(events&~0xc731u) return SHZ_UNSUPPORTED;
    r=ack_register(p,&p->table.event_a,events);if(r) return r;
    if(p->table.event_b.address) {
        r=ack_register(p,&p->table.event_b,events);if(r) return r;
    }
    return SHZ_OK;
}
static int enabled(struct shz_fixed_power *p,int *yes) {
    uint32_t a,b=1;int r=fixed_read(p,&p->table.control_a,2,&a);if(r) return r;
    if(p->table.control_b.address) { r=fixed_read(p,&p->table.control_b,2,&b);if(r) return r; }
    *yes=(a&b&1u)!=0;return SHZ_OK;
}
int shz_fixed_enable(struct shz_fixed_power *p) {
    struct shz_budget budget;struct shz_gas smi;int r,yes;
    if(!p || !p->ops.now_us || !p->ops.relax || !p->timeout_us || p->timeout_us>30000000u)
        return SHZ_INVALID;
    r=enabled(p,&yes);if(r || yes) return r;
    if(!p->table.smi_command || !p->table.enable) return SHZ_UNSUPPORTED;
    smi.space=1;smi.bits=8;smi.offset=0;smi.access=1;smi.address=p->table.smi_command;
    shz_budget_start(&budget,p->ops.now_us(p->ops.context),p->timeout_us);
    r=fixed_write(p,&smi,1,p->table.enable);if(r) return r;
    for(;;) {
        r=shz_budget_poll(&budget,p->ops.now_us(p->ops.context));if(r) return r;
        r=enabled(p,&yes);if(r)return r;
        r=shz_budget_poll(&budget,p->ops.now_us(p->ops.context));if(r || yes)return r;
        p->ops.relax(p->ops.context);
    }
}
int shz_fixed_reset(struct shz_fixed_power *p) {
    if(!p) return SHZ_INVALID;
    if(!(p->table.flags&(1u<<10))) return SHZ_UNSUPPORTED;
    return fixed_write(p,&p->table.reset,1,p->table.reset_value);
}
