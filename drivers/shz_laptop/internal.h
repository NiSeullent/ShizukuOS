/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_LAPTOP_INTERNAL_H
#define SHZ_LAPTOP_INTERNAL_H
#include "laptop.h"
static inline uint16_t shz_le16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0]|(uint16_t)((uint16_t)p[1]<<8)); }
static inline uint32_t shz_le32(const uint8_t *p) { return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static inline uint64_t shz_le64(const uint8_t *p) { return (uint64_t)shz_le32(p)|((uint64_t)shz_le32(p+4)<<32); }
static inline void shz_zero(void *p,size_t n) { uint8_t *b=p;size_t i;for(i=0;i<n;i++)b[i]=0; }
static inline void shz_copy(void *d,const void *s,size_t n) { uint8_t *a=d;const uint8_t *b=s;size_t i;for(i=0;i<n;i++)a[i]=b[i]; }
static inline int shz_table(const uint8_t *p,size_t n,const char *sig,size_t min,size_t *length) {
    size_t i,len;uint8_t sum=0;
    if(!p || n<36) return SHZ_MALFORMED;
    for(i=0;i<4;i++) if(p[i]!=(uint8_t)sig[i]) return SHZ_MALFORMED;
    len=shz_le32(p+4);if(len<min || len>n || len>SHZ_TABLE_MAX) return SHZ_MALFORMED;
    for(i=0;i<len;i++) sum=(uint8_t)(sum+p[i]);
    if(sum) return SHZ_MALFORMED;
    *length=len;return SHZ_OK;
}
static inline int shz_gas_valid(const struct shz_gas *g,unsigned bytes) {
    uint8_t access=bytes==1 ? 1u:(bytes==2 ? 2u:3u);
    if(!g || (bytes!=1 && bytes!=2 && bytes!=4)) return SHZ_INVALID;
    if(g->space>1 || g->bits!=bytes*8 || g->offset ||
       (g->access && g->access!=access)) return SHZ_UNSUPPORTED;
    if(!g->address || g->address>UINT64_MAX-(bytes-1u)) return SHZ_MALFORMED;
    if(g->space==1 && g->address>65536u-bytes) return SHZ_UNSUPPORTED;
    return SHZ_OK;
}
static inline struct shz_gas shz_gas_read(const uint8_t *p) {
    struct shz_gas g;g.space=p[0];g.bits=p[1];g.offset=p[2];g.access=p[3];g.address=shz_le64(p+4);return g;
}
static inline int shz_reg_read(const struct shz_register_ops *o,uint64_t owner,
    uint64_t generation,const struct shz_gas *g,unsigned bytes,uint32_t *out) {
    uint32_t v;int r=shz_gas_valid(g,bytes);
    if(r) return r;
    if(!o || !o->validate || !o->read || !owner || !generation) return SHZ_INVALID;
    if(o->validate(o->context,owner,generation,g,bytes,0)!=SHZ_OK) return SHZ_REVOKED;
    r=o->read(o->context,g,bytes,&v);if(r) return r;
    if(o->validate(o->context,owner,generation,g,bytes,0)!=SHZ_OK) return SHZ_REVOKED;
    if(bytes<4 && v>=(1u<<(bytes*8))) return SHZ_MALFORMED;
    *out=v;return SHZ_OK;
}
static inline int shz_reg_write(const struct shz_register_ops *o,uint64_t owner,
    uint64_t generation,const struct shz_gas *g,unsigned bytes,uint32_t value) {
    int r=shz_gas_valid(g,bytes);if(r) return r;
    if(!o || !o->validate || !o->write || !owner || !generation) return SHZ_INVALID;
    if(bytes<4 && value>=(1u<<(bytes*8))) return SHZ_INVALID;
    if(o->validate(o->context,owner,generation,g,bytes,1)!=SHZ_OK) return SHZ_REVOKED;
    r=o->write(o->context,g,bytes,value);if(r) return r;
    return o->validate(o->context,owner,generation,g,bytes,1)==SHZ_OK ? SHZ_OK:SHZ_REVOKED;
}
struct shz_budget { uint64_t start,last;uint32_t polls,limit; };
static inline void shz_budget_start(struct shz_budget *b,uint64_t now,uint32_t us) {
    b->start=now;b->last=now;b->polls=0;b->limit=us;
}
static inline int shz_budget_poll(struct shz_budget *b,uint64_t now) {
    if(now<b->last) return SHZ_CLOCK;
    b->last=now;
    if(now-b->start>=b->limit) return SHZ_TIMEOUT;
    if(++b->polls>SHZ_POLL_LIMIT) return SHZ_CLOCK;
    return SHZ_OK;
}
#endif
