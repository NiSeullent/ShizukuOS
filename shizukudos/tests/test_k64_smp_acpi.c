/* SPDX-License-Identifier: GPL-2.0-only
 * Synthetic firmware bytes exercise the production ACPI parser, not a model.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../kernel64/smp_acpi.h"

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL line %u: %s\n", __LINE__, #x); exit(1); } } while (0)
static unsigned char mem[0x110000];
static size_t available = sizeof mem;
enum { RSDP = 0xe0010, ROOT = 0x10000, MADT = 0x20000 };
static void le32(unsigned p, uint32_t x) { unsigned i; for (i=0;i<4;i++) mem[p+i]=(unsigned char)(x>>(8*i)); }
static void le64(unsigned p, uint64_t x) { le32(p,(uint32_t)x); le32(p+4,(uint32_t)(x>>32)); }
static uint32_t get32(unsigned p) { return mem[p]|((uint32_t)mem[p+1]<<8)|((uint32_t)mem[p+2]<<16)|((uint32_t)mem[p+3]<<24); }
static void sum(unsigned p,unsigned n,unsigned byte) { unsigned i; unsigned char s=0; mem[p+byte]=0; for(i=0;i<n;i++) s+=mem[p+i]; mem[p+byte]=(unsigned char)-s; }
static int readmem(void *ctx,uint64_t pa,void *dst,size_t n)
{ (void)ctx; if (pa>available || n>available-pa) return -1; memcpy(dst,mem+(size_t)pa,n); return 0; }
static void header(unsigned p,const char *sig,unsigned n) { memcpy(mem+p,sig,4); le32(p+4,n); mem[p+8]=1; }
static void fix_madt(void) { sum(MADT,get32(MADT+4),9); }
static void fixture(unsigned cpus,int xsdt)
{
    unsigned i;
    memset(mem,0,sizeof mem); available=sizeof mem;
    memcpy(mem+RSDP,"RSD PTR ",8); mem[RSDP+15]=xsdt?2:0; le32(RSDP+16,ROOT);
    if(xsdt) { le32(RSDP+20,36); le64(RSDP+24,ROOT); }
    sum(RSDP,20,8); if(xsdt) sum(RSDP,36,32);
    header(ROOT,xsdt?"XSDT":"RSDT",xsdt?44:40);
    if(xsdt) le64(ROOT+36,MADT); else le32(ROOT+36,MADT);
    sum(ROOT,xsdt?44:40,9);
    header(MADT,"APIC",44+8*cpus); le32(MADT+36,0xfee00000u); le32(MADT+40,1);
    for(i=0;i<cpus;i++) { unsigned p=MADT+44+8*i; mem[p]=0; mem[p+1]=8; mem[p+2]=(unsigned char)(i+7); mem[p+3]=(unsigned char)(i*2); le32(p+4,1); }
    fix_madt();
}
static int probe(uint32_t bsp,shz_smp_topology_t *t) { return shz_smp_acpi_probe(readmem,0,RSDP,bsp,t); }
static void rejected(int expected)
{ shz_smp_topology_t t; memset(&t,0xaa,sizeof t); CHECK(probe(0,&t)==expected); CHECK(t.count==0 && t.madt_pa==0 && t.lapic_pa==0); }
int main(void)
{
    shz_smp_topology_t t; uint64_t found; unsigned i;
    fixture(4,0); CHECK(probe(0,&t)==0); CHECK(t.count==4 && t.bsp_index==0 && t.apic_id[3]==6 && t.acpi_uid[3]==10); CHECK(t.lapic_pa==0xfee00000u && t.pcat_compat==1);
    fixture(2,1); CHECK(probe(2,&t)==0); CHECK(t.count==2 && t.bsp_index==1);
    CHECK(shz_smp_acpi_find_bios(readmem,0,&found)==0 && found==RSDP);
    /* RSDP legacy and extended checksums are both mandatory. */
    for(i=0;i<36;i++) { fixture(2,1); mem[RSDP+i]^=0x80; rejected(SHZ_SMP_ACPI_INVALID); }
    for(i=0;i<40;i++) { fixture(2,0); mem[ROOT+i]^=0x40; rejected(SHZ_SMP_ACPI_INVALID); }
    for(i=0;i<60;i++) { fixture(2,0); mem[MADT+i]^=0x20; rejected(SHZ_SMP_ACPI_INVALID); }
    fixture(4,0); le32(MADT+44+8+4,0); le32(MADT+44+16+4,2); fix_madt(); CHECK(probe(0,&t)==0 && t.count==2 && t.apic_id[1]==6);
    fixture(2,0); mem[MADT+44+8+3]=0; fix_madt(); rejected(SHZ_SMP_ACPI_INVALID);
    fixture(2,0); mem[MADT+44+8+2]=7; fix_madt(); rejected(SHZ_SMP_ACPI_INVALID);
    fixture(2,0); mem[MADT+44+8+3]=255; fix_madt(); rejected(SHZ_SMP_ACPI_UNSUPPORTED);
    fixture(2,0); mem[MADT+44+3]=255; fix_madt(); rejected(SHZ_SMP_ACPI_UNSUPPORTED);
    fixture(2,0); mem[MADT+44+8+3]=255; le32(MADT+44+8+4,0); fix_madt(); CHECK(probe(0,&t)==0 && t.count==1);
    fixture(2,0); CHECK(probe(99,&t)==SHZ_SMP_ACPI_INVALID && !t.count);
    fixture(0,0); rejected(SHZ_SMP_ACPI_INVALID);
    fixture(33,0); rejected(SHZ_SMP_ACPI_LIMIT);
    fixture(2,0); mem[MADT+44+8]=9; mem[MADT+44+8+1]=16; le32(MADT+4,68); le32(MADT+44+8+8,1); fix_madt(); rejected(SHZ_SMP_ACPI_UNSUPPORTED);
    fixture(2,0); mem[MADT+44+8]=9; mem[MADT+44+8+1]=16; le32(MADT+4,68); le32(MADT+44+8+8,0); fix_madt(); CHECK(probe(0,&t)==0 && t.count==1);
    fixture(2,0); mem[MADT+60]=5; mem[MADT+61]=12; le64(MADT+64,0xfee01000u); le32(MADT+4,72); fix_madt(); CHECK(probe(0,&t)==0 && t.lapic_pa==0xfee01000u);
    memcpy(mem+MADT+72,mem+MADT+60,12); le32(MADT+4,84); fix_madt(); rejected(SHZ_SMP_ACPI_INVALID);
    fixture(2,0); le32(MADT+36,0); fix_madt(); rejected(SHZ_SMP_ACPI_INVALID);
    fixture(2,0); le32(MADT+36,0xfee00001u); fix_madt(); rejected(SHZ_SMP_ACPI_INVALID);
    fixture(2,0); mem[MADT+60]=0x80; mem[MADT+61]=2; le32(MADT+4,62); fix_madt(); CHECK(probe(0,&t)==0 && t.count==2);
    for(i=0;i<8;i++) { fixture(2,0); mem[MADT+53]=(unsigned char)i; fix_madt(); rejected(SHZ_SMP_ACPI_INVALID); }
    fixture(2,0); le32(MADT+4,59); fix_madt(); rejected(SHZ_SMP_ACPI_INVALID);
    fixture(2,0); le32(ROOT+4,39); sum(ROOT,39,9); rejected(SHZ_SMP_ACPI_INVALID);
    fixture(2,1); le64(ROOT+36,UINT64_MAX-15); sum(ROOT,44,9); rejected(SHZ_SMP_ACPI_INVALID);
    fixture(2,0); le32(MADT+4,SHZ_SMP_ACPI_MAX_TABLE+1); rejected(SHZ_SMP_ACPI_INVALID);
    for(i=0;i<60;i++) { fixture(2,0); available=MADT+i; rejected(SHZ_SMP_ACPI_INVALID); }
    fixture(2,0); mem[RSDP]=0; CHECK(shz_smp_acpi_find_bios(readmem,0,&found)==SHZ_SMP_ACPI_NOT_FOUND && !found);
    fixture(2,0); le32(0x40e,0x8000); memcpy(mem+0x80000,mem+RSDP,20); CHECK(shz_smp_acpi_find_bios(readmem,0,&found)==0 && found==0x80000);
    CHECK(shz_smp_acpi_probe(0,0,RSDP,0,&t)==SHZ_SMP_ACPI_INVALID);
    CHECK(shz_smp_acpi_probe(readmem,0,RSDP,0,0)==SHZ_SMP_ACPI_INVALID);
    printf("PASS production SMP ACPI parser: %u checks\n",checks); return 0;
}
