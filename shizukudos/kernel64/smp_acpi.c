/* SPDX-License-Identifier: GPL-2.0-only
 * ACPI 6.6 RSDP/RSDT/XSDT/MADT discovery for the first native xAPIC backend.
 * This code performs no MMIO, IPI, allocation, or firmware modification.
 */
#include "smp_acpi.h"

static uint32_t u32(const uint8_t *p)
{ return p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }
static uint64_t u64(const uint8_t *p) { return u32(p) | ((uint64_t)u32(p+4)<<32); }
static int eq(const uint8_t *p,const char *s,unsigned n)
{ unsigned i; for(i=0;i<n;i++) if(p[i]!=(uint8_t)s[i]) return 0; return 1; }
static int fetch(shz_smp_phys_read_fn read,void *ctx,uint64_t pa,void *dst,size_t n)
{ return read && pa<=UINT64_MAX-n && read(ctx,pa,dst,n)==0; }
static int checksum(shz_smp_phys_read_fn read,void *ctx,uint64_t pa,uint32_t n)
{
    uint8_t buf[128], sum=0;
    uint32_t off=0;
    if(pa>UINT64_MAX-n) return 0;
    while(off<n) {
        unsigned i,part=n-off<sizeof buf?n-off:sizeof buf;
        if(!fetch(read,ctx,pa+off,buf,part)) return 0;
        for(i=0;i<part;i++) sum+=buf[i];
        off+=part;
    }
    return sum==0;
}
static int rsdp(shz_smp_phys_read_fn read,void *ctx,uint64_t pa,uint64_t *root,unsigned *width)
{
    uint8_t b[36]; uint32_t n;
    if(!fetch(read,ctx,pa,b,20) || !eq(b,"RSD PTR ",8) || !checksum(read,ctx,pa,20)) return 0;
    *root=u32(b+16); *width=4;
    if(b[15]>=2) {
        if(!fetch(read,ctx,pa,b,sizeof b)) return 0;
        n=u32(b+20);
        if(n<sizeof b || n>4096 || !checksum(read,ctx,pa,n)) return 0;
        if(u64(b+24)) { *root=u64(b+24); *width=8; }
    }
    return *root!=0;
}
static int sdt(shz_smp_phys_read_fn read,void *ctx,uint64_t pa,uint8_t b[36],uint32_t *n)
{
    if(!pa || !fetch(read,ctx,pa,b,36)) return 0;
    *n=u32(b+4);
    return *n>=36 && *n<=SHZ_SMP_ACPI_MAX_TABLE && checksum(read,ctx,pa,*n);
}
static int madt(shz_smp_phys_read_fn read,void *ctx,uint64_t pa,uint32_t n,uint32_t bsp,shz_smp_topology_t *t)
{
    uint8_t b[16]; uint32_t off=44; unsigned override=0,bsp_seen=0;
    if(n<44 || !fetch(read,ctx,pa+36,b,8)) return SHZ_SMP_ACPI_INVALID;
    t->madt_pa=pa; t->lapic_pa=u32(b); t->pcat_compat=u32(b+4)&1;
    while(off<n) {
        uint8_t type,len;
        if(n-off<2 || !fetch(read,ctx,pa+off,b,2)) return SHZ_SMP_ACPI_INVALID;
        type=b[0]; len=b[1];
        if(len<2 || len>n-off) return SHZ_SMP_ACPI_INVALID;
        if(type==0 || type==9) {
            uint32_t flags,id,uid; unsigned i;
            if(len<(type==0?8:16) || !fetch(read,ctx,pa+off,b,type==0?8:16)) return SHZ_SMP_ACPI_INVALID;
            flags=u32(b+(type==0?4:8));
            if(flags&1) {
                if(type==9) return SHZ_SMP_ACPI_UNSUPPORTED;
                id=b[3]; uid=b[2];
                /* Physical xAPIC destination0xff broadcasts to every APIC;
                 * it cannot identify one CPU for bounded INIT/SIPI startup. */
                if(id==255) return SHZ_SMP_ACPI_UNSUPPORTED;
                for(i=0;i<t->count;i++) if(t->apic_id[i]==id || t->acpi_uid[i]==uid) return SHZ_SMP_ACPI_INVALID;
                if(t->count==SHZ_SMP_MAX_CPUS) return SHZ_SMP_ACPI_LIMIT;
                t->apic_id[t->count]=id; t->acpi_uid[t->count]=uid;
                if(id==bsp) { t->bsp_index=t->count; ++bsp_seen; }
                ++t->count;
            }
        } else if(type==5) {
            if(len<12 || override++ || !fetch(read,ctx,pa+off,b,12)) return SHZ_SMP_ACPI_INVALID;
            t->lapic_pa=u64(b+4);
        }
        /* Unknown records are skippable by the length, including future types. */
        off+=len;
    }
    if(!t->count || bsp_seen!=1 || !t->lapic_pa || (t->lapic_pa&4095)) return SHZ_SMP_ACPI_INVALID;
    return SHZ_SMP_ACPI_OK;
}
int shz_smp_acpi_probe(shz_smp_phys_read_fn read,void *ctx,uint64_t pa,uint32_t bsp,shz_smp_topology_t *out)
{
    uint64_t root,apic=0; uint32_t n,off,apic_n=0; unsigned width; uint8_t b[36];
    shz_smp_topology_t t={0}; int rc;
    if(out) *out=t;
    if(!read || !out || !pa || !rsdp(read,ctx,pa,&root,&width) || !sdt(read,ctx,root,b,&n) ||
       !eq(b,width==8?"XSDT":"RSDT",4) || (n-36)%width || (n-36)/width>4096) return SHZ_SMP_ACPI_INVALID;
    for(off=36;off<n;off+=width) {
        uint8_t entry[8]; uint64_t child; uint32_t child_n;
        if(!fetch(read,ctx,root+off,entry,width)) return SHZ_SMP_ACPI_INVALID;
        child=width==8?u64(entry):u32(entry);
        if(!sdt(read,ctx,child,b,&child_n)) return SHZ_SMP_ACPI_INVALID;
        if(eq(b,"APIC",4)) {
            if(apic) return SHZ_SMP_ACPI_INVALID;
            apic=child; apic_n=child_n;
        }
    }
    if(!apic) return SHZ_SMP_ACPI_NOT_FOUND;
    t.rsdp_pa=pa;
    rc=madt(read,ctx,apic,apic_n,bsp,&t);
    if(rc==SHZ_SMP_ACPI_OK) *out=t;
    return rc;
}
static int scan(shz_smp_phys_read_fn read,void *ctx,uint64_t start,uint64_t end,uint64_t *out)
{
    uint64_t pa,root; unsigned width; uint8_t sig[8];
    for(pa=start;pa+20<=end;pa+=16)
        if(fetch(read,ctx,pa,sig,8) && eq(sig,"RSD PTR ",8) && rsdp(read,ctx,pa,&root,&width)) { *out=pa; return 1; }
    return 0;
}
int shz_smp_acpi_find_bios(shz_smp_phys_read_fn read,void *ctx,uint64_t *out)
{
    uint8_t b[2]; uint64_t ebda;
    if(out) *out=0;
    if(!read || !out) return SHZ_SMP_ACPI_INVALID;
    if(fetch(read,ctx,0x40e,b,2)) {
        ebda=(uint64_t)(b[0]|((unsigned)b[1]<<8))<<4;
        if(ebda>=0x80000 && ebda<=0x9fc00 && scan(read,ctx,ebda,ebda+1024,out)) return 0;
    }
    return scan(read,ctx,0xe0000,0x100000,out)?0:SHZ_SMP_ACPI_NOT_FOUND;
}
