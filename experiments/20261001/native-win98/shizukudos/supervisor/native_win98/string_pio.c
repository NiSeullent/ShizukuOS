/* SPDX-License-Identifier: GPL-2.0-only */
#include "string_pio.h"
#define PE 1u
#define WP 0x10000u
#define PG 0x80000000u
#define PSE 0x10u
#define PAE 0x20u
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static void put32(uint8_t *p, uint32_t v)
{
    unsigned n; for(n=0;n<4;++n) p[n]=(uint8_t)(v>>(8*n));
}
struct resolved { uint8_t *byte, *pde, *pte; uint32_t directory, table; };
static int fault(w98_io_fault_t *f, unsigned vector, unsigned error, uint32_t linear)
{
    f->vector=vector; f->error=error; f->linear=linear; return -1;
}
/* Non-PAE 386 paging; no invented translation for unsupported PAE/PSE-36. */
static int resolve(w98_memory_t *m, uint32_t linear, int write, struct resolved *r, w98_io_fault_t *f)
{
    uint32_t gpa=linear, pde=0, pte=0, error=(write?2u:0u)|(m->cpl==3?4u:0u);
    r->pde=r->pte=0;
    if(m->cr0&PG) {
        uint8_t *p;
        if(!(m->cr0&PE) || m->cr4&PAE) return -2;
        p=m->physical(m->opaque,(m->cr3&0xfffff000u)+((linear>>22)*4),4,0);
        if(!p) return -2;
        pde=get32(p);
        if(!(pde&1)) return fault(f,14,error,linear);
        if(pde&0x80) {
            if(!(m->cr4&PSE) || pde&0x003fe000u) return fault(f,14,error|9u,linear);
            gpa=(pde&0xffc00000u)|(linear&0x003fffffu);
        } else {
            p=m->physical(m->opaque,(pde&0xfffff000u)+(((linear>>12)&1023u)*4),4,0);
            if(!p) return -2;
            pte=get32(p);
            if(!(pte&1)) return fault(f,14,error,linear);
            gpa=(pte&0xfffff000u)|(linear&4095u);
        }
        if((m->cpl==3 && (!(pde&4) || (!(pde&0x80) && !(pte&4)))) ||
           (write && (m->cpl==3 || m->cr0&WP) && (!(pde&2) || (!(pde&0x80) && !(pte&2)))))
            return fault(f,14,error|1u,linear);
        r->pde=m->physical(m->opaque,(m->cr3&0xfffff000u)+((linear>>22)*4),4,1);
        if(!r->pde) return -2;
        r->directory=pde|0x20u|((write && pde&0x80)?0x40u:0u);
        if(!(pde&0x80)) {
            r->pte=m->physical(m->opaque,(pde&0xfffff000u)+(((linear>>12)&1023u)*4),4,1);
            if(!r->pte) return -2;
            r->table=pte|0x20u|(write?0x40u:0u);
        }
    }
    r->byte=m->physical(m->opaque,gpa,1,write);
    return r->byte?0:-2;
}
static uint64_t assign_index(uint64_t original, uint32_t value, unsigned bits)
{
    return bits==16 ? (original&~0xffffull)|(value&0xffffu) : value;
}
int w98_string_pio(w98_memory_t *m, w98_string_io_t *s, const w98_ports_t *p, w98_io_fault_t *f, unsigned budget)
{
    uint32_t mask, count, index;
    unsigned done=0;
    f->vector=f->error=f->linear=f->completed=0;
    if((s->address_bits!=16 && s->address_bits!=32) ||
       (s->width!=1 && s->width!=2 && s->width!=4) || !budget || budget>64) return -2;
    mask=s->address_bits==16?0xffffu:0xffffffffu;
    count=s->repeat?(uint32_t)s->count&mask:1;
    index=(uint32_t)s->index&mask;
    if(!count) return 0;
    while(count && done<budget) {
        struct resolved bytes[4];
        uint32_t linear=s->segment_base+index, value=0, last;
        unsigned n;int rc;
        if(index>0xffffffffu-(s->width-1)) return fault(f,s->segment_is_ss?12:13,0,linear);
        last=index+s->width-1;
        if(s->segment_ar&0x10000u || !(s->segment_ar&0x80u) || !(s->segment_ar&0x10u) ||
           (s->input && ((s->segment_ar&8u) || !(s->segment_ar&2u))) ||
           (!s->input && (s->segment_ar&8u) && !(s->segment_ar&2u))) return fault(f,s->segment_is_ss?12:13,0,linear);
        /* Data expand-down: limit is the excluded lower bound; D/B selects upper bound. */
        if(!(s->segment_ar&8u) && s->segment_ar&4u) {
            uint32_t top=s->segment_ar&0x4000u?0xffffffffu:0xffffu;
            if(index<=s->segment_limit || last>top) return fault(f,s->segment_is_ss?12:13,0,linear);
        } else if(last>s->segment_limit) return fault(f,s->segment_is_ss?12:13,0,linear);
        if(s->alignment_check && (linear&(s->width-1))) return fault(f,17,0,linear);
        /* Resolve every byte before any port side effect, including a split-page element. */
        for(n=0;n<s->width;++n) {
            rc=resolve(m,linear+n,(int)s->input,&bytes[n],f);
            if(rc) return rc;
        }
        /* The walk precedes the operand operation. A target that aliases its own
         * page table must overwrite A/D bits just as a hardware store would. */
        for(n=0;n<s->width;++n) {
            if(bytes[n].pde) put32(bytes[n].pde,get32(bytes[n].pde)|(bytes[n].directory&0x60u));
            if(bytes[n].pte) put32(bytes[n].pte,get32(bytes[n].pte)|(bytes[n].table&0x60u));
        }
        if(s->input) {
            if(!p->input(p->opaque,s->port,s->width,&value)) return -3;
            for(n=0;n<s->width;++n) *bytes[n].byte=(uint8_t)(value>>(n*8));
        } else {
            for(n=0;n<s->width;++n) value|=(uint32_t)*bytes[n].byte<<(n*8);
            if(!p->output(p->opaque,s->port,s->width,value)) return -3;
        }
        index=(s->direction_down?index-s->width:index+s->width)&mask;
        s->index=assign_index(s->index,index,s->address_bits);
        ++done;f->completed=done;
        if(s->repeat) { --count; s->count=assign_index(s->count,count,s->address_bits); }
        else count=0;
    }
    return count?1:0;
}
