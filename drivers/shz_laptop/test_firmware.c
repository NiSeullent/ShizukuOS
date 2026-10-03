/* SPDX-License-Identifier: GPL-2.0-only */
#include "firmware.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned checks;
#define C(x) do { ++checks; assert(x); } while(0)
static uint8_t rsdp[SHZ_FIRMWARE_RSDP_MAX],root[2048],fadt[SHZ_TABLE_MAX];
static uint8_t ecdt[SHZ_TABLE_MAX],other[SHZ_FIRMWARE_OTHER_TABLE_MAX];
struct region { uint64_t pa;uint8_t *data;size_t bytes; };
struct fixture {
    struct region regions[140];unsigned count,calls,fail_call,short_call,change_call;
    int failure;uint64_t bytes,max_read;unsigned overflow;
    uint64_t rsdp_pa,root_pa,fadt_pa,ecdt_pa,other_pa;
};
static void put32(uint8_t *p,uint32_t n) {
    unsigned i;for(i=0;i<4;i++)p[i]=(uint8_t)(n>>(i*8));
}
static void put64(uint8_t *p,uint64_t n) {
    unsigned i;for(i=0;i<8;i++)p[i]=(uint8_t)(n>>(i*8));
}
static void checksum(uint8_t *p,size_t bytes,size_t at) {
    size_t i;uint8_t sum=0;p[at]=0;
    for(i=0;i<bytes;i++)sum=(uint8_t)(sum+p[i]);
    p[at]=(uint8_t)(0u-sum);
}
static void table(uint8_t *p,size_t bytes,const char *signature) {
    memset(p,0,bytes);memcpy(p,signature,4);put32(p+4,(uint32_t)bytes);p[8]=1;
}
static void rsdp_sum(unsigned revision,size_t bytes) {
    rsdp[15]=(uint8_t)revision;checksum(rsdp,20,8);
    if(revision>=2)checksum(rsdp,bytes,32);
}
static int read_firmware(void *context,uint64_t pa,void *out,size_t bytes) {
    struct fixture *f=context;unsigned i;++f->calls;f->bytes+=bytes;
    if(bytes>f->max_read)f->max_read=bytes;
    if(!bytes || pa>UINT64_MAX-(bytes-1u)){++f->overflow;return SHZ_IO;}
    if(f->calls==f->fail_call)return f->failure;
    for(i=0;i<f->count;i++) {
        struct region *r=&f->regions[i];uint64_t offset;
        if(pa<r->pa)continue;
        offset=pa-r->pa;
        if(offset>r->bytes || bytes>r->bytes-(size_t)offset)continue;
        if(f->calls==f->short_call) {
            memcpy(out,r->data+(size_t)offset,bytes-1u);return SHZ_IO;
        }
        memcpy(out,r->data+(size_t)offset,bytes);
        if(f->calls==f->change_call && bytes>=36)((uint8_t *)out)[10]^=1u;
        return SHZ_OK;
    }
    return SHZ_IO;
}
static void root_entries(struct fixture *f,unsigned count,int xsdt) {
    unsigned i;size_t width=xsdt ? 8u:4u;
    table(root,36u+count*width,xsdt ? "XSDT":"RSDT");
    for(i=0;i<count;i++) {
        uint64_t pa=i==0 ? f->fadt_pa:(i==1 ? f->ecdt_pa:f->other_pa);
        if(xsdt)put64(root+36u+i*width,pa);
        else put32(root+36u+i*width,(uint32_t)pa);
    }
    checksum(root,36u+count*width,9);
}
static void setup(struct fixture *f,int xsdt) {
    uint64_t high=xsdt ? UINT64_C(0x100000000):0;
    memset(f,0,sizeof(*f));memset(rsdp,0,sizeof(rsdp));
    f->rsdp_pa=high+0x100;f->root_pa=high+0x10000;
    f->fadt_pa=high+0x20000;f->ecdt_pa=high+0x30000;f->other_pa=high+0x40000;
    memcpy(rsdp,"RSD PTR ",8);put32(rsdp+16,(uint32_t)f->root_pa);
    put32(rsdp+20,36);if(xsdt)put64(rsdp+24,f->root_pa);
    rsdp_sum(xsdt ? 2u:0u,36);
    table(fadt,244,"FACP");fadt[46]=9;
    put32(fadt+56,0x100);put32(fadt+64,0x110);fadt[88]=4;fadt[89]=2;
    checksum(fadt,244,9);
    table(ecdt,83,"ECDT");ecdt[36]=1;ecdt[37]=8;ecdt[39]=1;
    put32(ecdt+40,0x66);ecdt[48]=1;ecdt[49]=8;ecdt[51]=1;
    put32(ecdt+52,0x62);put32(ecdt+60,7);ecdt[64]=12;
    memcpy(ecdt+65,"\\_SB.PCI0.LPC.EC0",17);checksum(ecdt,83,9);
    table(other,36,"APIC");checksum(other,36,9);root_entries(f,3,xsdt);
    f->regions[0]=(struct region){f->rsdp_pa,rsdp,36};
    f->regions[1]=(struct region){f->root_pa,root,xsdt ? 60u:48u};
    f->regions[2]=(struct region){f->fadt_pa,fadt,244};
    f->regions[3]=(struct region){f->ecdt_pa,ecdt,83};
    f->regions[4]=(struct region){f->other_pa,other,36};f->count=5;
}
static void refuse(struct fixture *f,int expected) {
    struct shz_laptop_firmware out,old;
    memset(&out,0xa5,sizeof(out));memcpy(&old,&out,sizeof(old));
    C(shz_laptop_firmware_probe(read_firmware,f,f->rsdp_pa,&out)==expected);
    C(memcmp(&out,&old,sizeof(out))==0);C(f->overflow==0);
    C(f->bytes<=SHZ_FIRMWARE_READ_BUDGET);
}
static void valid(void) {
    struct fixture f;struct shz_laptop_firmware out;int mode;unsigned i;
    for(mode=0;mode<2;mode++) {
        setup(&f,mode);memset(&out,0xa5,sizeof(out));
        C(shz_laptop_firmware_probe(read_firmware,&f,f.rsdp_pa,&out)==SHZ_OK);
        C(out.rsdp_pa==f.rsdp_pa && out.root_pa==f.root_pa);
        C(out.fadt_pa==f.fadt_pa && out.ecdt_pa==f.ecdt_pa);
        C(out.rsdp_revision==(mode ? 2:0) && out.uses_xsdt==mode);
        C(out.entry_count==3 && out.has_ecdt==1);
        C(out.fixed.control_a.address==0x110 && out.fixed.sci==9);
        C(out.ec.control.address==0x66 && out.ec.uid==7);
        C(f.bytes==(mode ? 623u:575u));
    }
    setup(&f,0);rsdp_sum(2,36);
    C(shz_laptop_firmware_probe(read_firmware,&f,f.rsdp_pa,&out)==SHZ_OK && !out.uses_xsdt);
    setup(&f,1);rsdp_sum(3,36);
    C(shz_laptop_firmware_probe(read_firmware,&f,f.rsdp_pa,&out)==SHZ_OK && out.rsdp_revision==3);
    setup(&f,1);root_entries(&f,1,1);f.regions[1].bytes=44;
    C(shz_laptop_firmware_probe(read_firmware,&f,f.rsdp_pa,&out)==SHZ_OK);
    C(!out.has_ecdt && !out.ecdt_pa && !out.ec.control.address);
    setup(&f,1);root_entries(&f,SHZ_FIRMWARE_ROOT_ENTRIES,1);
    f.regions[1].bytes=36u+SHZ_FIRMWARE_ROOT_ENTRIES*8u;
    for(i=3;i<SHZ_FIRMWARE_ROOT_ENTRIES;i++) {
        uint64_t pa=UINT64_C(0x300000000)+i*256u;
        put64(root+36u+i*8u,pa);f.regions[f.count++]=(struct region){pa,other,36};
    }
    checksum(root,f.regions[1].bytes,9);
    C(shz_laptop_firmware_probe(read_firmware,&f,f.rsdp_pa,&out)==SHZ_OK);
    C(out.entry_count==SHZ_FIRMWARE_ROOT_ENTRIES && f.overflow==0);
    setup(&f,1);f.root_pa=UINT64_MAX-59u;f.regions[1].pa=f.root_pa;
    put64(rsdp+24,f.root_pa);rsdp_sum(2,36);
    C(shz_laptop_firmware_probe(read_firmware,&f,f.rsdp_pa,&out)==SHZ_OK);
    setup(&f,1);f.fadt_pa=UINT64_MAX-243u;f.regions[2].pa=f.fadt_pa;
    put64(root+36,f.fadt_pa);checksum(root,60,9);
    C(shz_laptop_firmware_probe(read_firmware,&f,f.rsdp_pa,&out)==SHZ_OK);
    setup(&f,1);table(other,8192,"SSDT");checksum(other,8192,9);f.regions[4].bytes=8192;
    C(shz_laptop_firmware_probe(read_firmware,&f,f.rsdp_pa,&out)==SHZ_OK);
    C(f.max_read<=SHZ_TABLE_MAX);
    setup(&f,1);put32(rsdp+20,SHZ_FIRMWARE_RSDP_MAX);rsdp[4095]=7;
    rsdp_sum(2,SHZ_FIRMWARE_RSDP_MAX);f.regions[0].bytes=SHZ_FIRMWARE_RSDP_MAX;
    C(shz_laptop_firmware_probe(read_firmware,&f,f.rsdp_pa,&out)==SHZ_OK);
}
static void malformed(void) {
    struct fixture f;
    setup(&f,1);rsdp[0]='X';refuse(&f,SHZ_MALFORMED);
    setup(&f,1);rsdp[8]++;refuse(&f,SHZ_MALFORMED);
    setup(&f,1);rsdp[32]++;refuse(&f,SHZ_MALFORMED);
    setup(&f,1);rsdp_sum(1,36);refuse(&f,SHZ_UNSUPPORTED);
    setup(&f,1);put32(rsdp+20,35);rsdp_sum(2,36);refuse(&f,SHZ_MALFORMED);
    setup(&f,1);put32(rsdp+20,SHZ_FIRMWARE_RSDP_MAX+1u);rsdp_sum(2,36);refuse(&f,SHZ_CAPACITY);
    setup(&f,1);rsdp[33]=1;rsdp_sum(2,36);refuse(&f,SHZ_MALFORMED);
    setup(&f,1);root[0]='R';checksum(root,60,9);refuse(&f,SHZ_MALFORMED);
    setup(&f,1);root[9]++;refuse(&f,SHZ_MALFORMED);
    setup(&f,1);put32(root+4,35);refuse(&f,SHZ_MALFORMED);
    setup(&f,1);put32(root+4,59);checksum(root,59,9);refuse(&f,SHZ_MALFORMED);
    setup(&f,1);root_entries(&f,129,1);f.regions[1].bytes=1068;refuse(&f,SHZ_CAPACITY);
    setup(&f,1);put64(root+36,0);checksum(root,60,9);refuse(&f,SHZ_MALFORMED);
    setup(&f,1);put64(root+44,f.fadt_pa);checksum(root,60,9);refuse(&f,SHZ_MALFORMED);
    setup(&f,1);put64(root+36,f.root_pa);checksum(root,60,9);refuse(&f,SHZ_MALFORMED);
    setup(&f,1);memcpy(ecdt,fadt,244);f.regions[3].bytes=244;refuse(&f,SHZ_MALFORMED);
    setup(&f,1);memcpy(other,ecdt,83);f.regions[4].bytes=83;refuse(&f,SHZ_MALFORMED);
    setup(&f,1);fadt[9]++;refuse(&f,SHZ_MALFORMED);
    setup(&f,1);put32(fadt+4,115);checksum(fadt,115,9);refuse(&f,SHZ_MALFORMED);
    setup(&f,1);put32(fadt+4,SHZ_TABLE_MAX+1u);refuse(&f,SHZ_CAPACITY);
    setup(&f,1);put32(fadt+112,1u<<20);checksum(fadt,244,9);refuse(&f,SHZ_UNSUPPORTED);
    setup(&f,1);ecdt[9]++;refuse(&f,SHZ_MALFORMED);
    setup(&f,1);ecdt[48]=2;checksum(ecdt,83,9);refuse(&f,SHZ_UNSUPPORTED);
    setup(&f,1);other[9]++;refuse(&f,SHZ_MALFORMED);
    setup(&f,1);put32(other+4,SHZ_FIRMWARE_OTHER_TABLE_MAX+1u);refuse(&f,SHZ_CAPACITY);
    setup(&f,1);f.change_call=4;refuse(&f,SHZ_STALE);
    setup(&f,1);f.change_call=6;refuse(&f,SHZ_STALE);
    setup(&f,1);f.change_call=2;refuse(&f,SHZ_STALE);
    setup(&f,1);f.change_call=10;refuse(&f,SHZ_STALE);
    setup(&f,1);put32(rsdp+20,4096);rsdp_sum(2,4096);rsdp[4095]++;
    f.regions[0].bytes=4096;refuse(&f,SHZ_MALFORMED);
}
static void boundaries(void) {
    struct fixture f;struct shz_laptop_firmware out,old;unsigned i;
    setup(&f,1);put32(rsdp+16,0);put64(rsdp+24,0);rsdp_sum(2,36);refuse(&f,SHZ_NOT_FOUND);
    setup(&f,1);table(fadt,36,"APIC");checksum(fadt,36,9);f.regions[2].bytes=36;
    refuse(&f,SHZ_NOT_FOUND);
    setup(&f,1);root_entries(&f,0,1);f.regions[1].bytes=36;refuse(&f,SHZ_NOT_FOUND);
    for(i=1;i<=10;i++) {
        setup(&f,1);f.fail_call=i;f.failure=SHZ_REVOKED;refuse(&f,SHZ_REVOKED);
        setup(&f,1);f.short_call=i;refuse(&f,SHZ_IO);
    }
    setup(&f,1);f.fail_call=1;f.failure=42;refuse(&f,SHZ_IO);
    setup(&f,1);f.rsdp_pa=UINT64_MAX-18u;refuse(&f,SHZ_MALFORMED);C(!f.calls);
    setup(&f,1);f.rsdp_pa=UINT64_MAX-35u;f.regions[0].pa=f.rsdp_pa;
    put32(rsdp+20,37);rsdp_sum(2,36);refuse(&f,SHZ_MALFORMED);
    setup(&f,1);put64(rsdp+24,UINT64_MAX-34u);rsdp_sum(2,36);refuse(&f,SHZ_MALFORMED);
    setup(&f,1);f.root_pa=UINT64_MAX-59u;f.regions[1].pa=f.root_pa;
    put64(rsdp+24,f.root_pa);put32(root+4,61);rsdp_sum(2,36);refuse(&f,SHZ_MALFORMED);
    setup(&f,1);put64(root+36,UINT64_MAX-34u);checksum(root,60,9);refuse(&f,SHZ_MALFORMED);
    setup(&f,1);f.fadt_pa=UINT64_MAX-100u;f.regions[2].pa=f.fadt_pa;
    put64(root+36,f.fadt_pa);checksum(root,60,9);refuse(&f,SHZ_MALFORMED);
    setup(&f,1);table(other,SHZ_FIRMWARE_OTHER_TABLE_MAX,"SSDT");
    checksum(other,SHZ_FIRMWARE_OTHER_TABLE_MAX,9);f.regions[4].bytes=SHZ_FIRMWARE_OTHER_TABLE_MAX;
    root_entries(&f,6,1);f.regions[1].bytes=84;
    for(i=3;i<6;i++) {
        uint64_t pa=UINT64_C(0x200000000)+i*SHZ_FIRMWARE_OTHER_TABLE_MAX;
        put64(root+36u+i*8u,pa);f.regions[f.count++]=(struct region){pa,other,sizeof(other)};
    }
    checksum(root,84,9);refuse(&f,SHZ_CAPACITY);
    setup(&f,1);f.regions[0].bytes=19;refuse(&f,SHZ_IO);
    setup(&f,1);f.regions[1].bytes=59;refuse(&f,SHZ_IO);
    setup(&f,1);f.regions[2].bytes=243;refuse(&f,SHZ_IO);
    memset(&out,0xa5,sizeof(out));memcpy(&old,&out,sizeof(old));
    C(shz_laptop_firmware_probe(0,&f,f.rsdp_pa,&out)==SHZ_INVALID);
    C(shz_laptop_firmware_probe(read_firmware,&f,f.rsdp_pa,0)==SHZ_INVALID);
    C(shz_laptop_firmware_probe(read_firmware,&f,0,&out)==SHZ_NOT_FOUND);
    C(memcmp(&out,&old,sizeof(out))==0);
}
int main(void) {
    valid();malformed();boundaries();
    printf("ACPI firmware directory: %u assertions PASS\n",checks);return 0;
}
