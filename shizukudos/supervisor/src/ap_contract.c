/* SPDX-License-Identifier: GPL-2.0-only */
#include "../include/ap_boot.h"
int shz_ap_lapic_base_ok(uint64_t msr,uint64_t pa) {
    /* This component maps only low xAPIC MMIO. Compare every high MSR bit,
     * including address bits 32..35, rather than accepting a low alias. */
    return pa && !(pa&4095) && pa<UINT64_C(0x100000000) &&
           (msr&UINT64_C(0xc00))==UINT64_C(0x800) && (msr&~UINT64_C(0xfff))==pa;
}
int shz_ap_lapic_pte_ok(uint64_t entry,uint64_t pa) {
    return !(pa&4095) && pa<UINT64_C(0x100000000) && (entry&UINT64_C(0x109b))==UINT64_C(0x9b) &&
           (entry&UINT64_C(0x000fffffffe00000))==(pa&~UINT64_C(0x1fffff));
}
static uint64_t le64(const uint8_t *p) {
    uint64_t v=0; for(unsigned i=0;i<8;i++) v|=(uint64_t)p[i]<<(8*i); return v;
}
static uint32_t le32(const uint8_t *p) {
    uint32_t v=0; for(unsigned i=0;i<4;i++) v|=(uint32_t)p[i]<<(8*i); return v;
}
static int span(uint64_t p, uint64_t n) { return n && p && p+n>p && p+n<=(UINT64_C(64)<<30); }
static int overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t z) { return a<b+z && b<a+n; }
int shz_ap_config_valid(const shz_ap_config_t *c,size_t n) {
    return c && n==sizeof *c && c->magic==SHZ_AP_CFG_MAGIC && c->version==SHZ_AP_VERSION &&
           c->count && c->count<=SHZ_SMP_MAX_CPUS && !c->flags;
}
int shz_ap_map_covers(const void *m,size_t n,size_t stride,uint64_t pa,uint64_t bytes,unsigned type) {
    const uint8_t *map=m;
    if(!m || stride<40 || stride>4096 || !n || n>16u*1024u*1024u || n%stride ||
       !span(pa,bytes) || (type!=0 && type!=2)) return 0;
    for(size_t off=0;off<n;off+=stride) {
        uint64_t p=le64(map+off+8), pages=le64(map+off+24);
        if((p&4095) || !pages || pages>(UINT64_MAX-p)/4096) return 0;
    }
    uint64_t end=pa+bytes;
    while(pa<end) {
        unsigned matches=0; uint64_t next=end;
        for(size_t off=0;off<n;off+=stride) {
            const uint8_t *d=map+off;
            uint64_t p=le64(d+8), e=p+le64(d+24)*4096, attr=le64(d+32);
            uint32_t t=le32(d);
            if(pa<p) { if(p<next) next=p; continue; }
            if(pa>=e) continue;
            if(++matches!=1 || (type ? t!=type : !((t>=1 && t<=7)||t==9||t==10||t==14)) ||
               !(attr&8)) return 0;
            /* UEFI 7.2.3 attributes describe capabilities, not exclusive
             * active cache/protection settings. Our owned page tables/PAT
             * select WB; the AP checks the complete BSP MTRR/PAT state. */
            if(e<next) next=e;
        }
        if(matches!=1 || next<=pa) return 0;
        pa=next;
    }
    return 1;
}
int shz_ap_boot_valid(const shz_ap_boot_t *b,uint64_t pa,uint64_t bytes,const void *map,
                      size_t n,size_t stride,uint64_t region,uint64_t region_bytes) {
    if(!b || b->magic!=SHZ_AP_MAGIC || b->version!=SHZ_AP_VERSION || b->bytes!=sizeof *b ||
       bytes!=sizeof *b || (pa&4095) || !b->requested || b->requested>SHZ_SMP_MAX_CPUS ||
       b->flags || b->sealed || b->release || !b->topology.count || b->topology.count>SHZ_SMP_MAX_CPUS ||
       b->requested>b->topology.count || b->topology.bsp_index || !b->topology.rsdp_pa ||
       !b->topology.madt_pa || !b->topology.lapic_pa || (b->topology.lapic_pa&4095) ||
       !span(region,region_bytes) || overlap(pa,SHZ_AP_PAGE,region,region_bytes) ||
       !shz_ap_map_covers(map,n,stride,pa,SHZ_AP_PAGE,2) ||
       !shz_ap_map_covers(map,n,stride,region,region_bytes,2)) return 0;
    if(b->low_pages!=b->requested-1) return 0;
    if(b->low_pages) {
        uint64_t lowbytes=b->low_pages*SHZ_AP_PAGE;
        if((b->low_base&4095) || b->low_base<0x1000 || b->low_base+lowbytes>0x100000 ||
           overlap(b->low_base,lowbytes,pa,SHZ_AP_PAGE) || overlap(b->low_base,lowbytes,region,region_bytes) ||
           !shz_ap_map_covers(map,n,stride,b->low_base,lowbytes,2)) return 0;
    } else if(b->low_base) return 0;
    for(unsigned i=0;i<b->topology.count;i++) {
        if(b->topology.apic_id[i]>=255) return 0;
        for(unsigned j=0;j<i;j++) if(b->topology.apic_id[i]==b->topology.apic_id[j] ||
                                    b->topology.acpi_uid[i]==b->topology.acpi_uid[j]) return 0;
    }
    for(unsigned i=0;i<SHZ_SMP_MAX_CPUS;i++) if(b->cpu[i].state || b->cpu[i].error) return 0;
    return 1;
}
int shz_ap_advance(shz_ap_record_t *r,unsigned from,unsigned to) {
    if(!r || from>=SHZ_AP_DONE || to!=from+1) return 0;
    return __atomic_compare_exchange_n(&r->state,&from,to,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
}
void shz_ap_fail(shz_ap_record_t *r,unsigned error) {
    unsigned old=__atomic_load_n(&r->state,__ATOMIC_ACQUIRE);
    while(old<SHZ_AP_DONE) {
        if(__atomic_compare_exchange_n(&r->state,&old,SHZ_AP_FAILING,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
            r->error=error;
            __atomic_store_n(&r->state,SHZ_AP_FAILED,__ATOMIC_RELEASE);
            return;
        }
    }
}
uint64_t shz_ap_hash(const uint8_t *p,size_t bytes,unsigned rounds) {
    uint64_t h=UINT64_C(14695981039346656037);
    for(unsigned r=0;r<rounds;r++) {
        for(size_t i=0;i<bytes;i++) h=(h^p[i])*UINT64_C(1099511628211);
        h=(h^(uint8_t)r)*UINT64_C(1099511628211);
    }
    return h;
}
