/* SPDX-License-Identifier: GPL-2.0-only
 * Synthetic paging records exercise the production retirement guard.
 * This host test executes no firmware, VM, AP startup or Windows scheduler.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../kernel64/smp_boot_guard.h"
static unsigned checks,reads;
#define CHECK(x) do { ++checks; if(!(x)) { fprintf(stderr,"FAIL line%u: %s\n",__LINE__,#x); exit(1); } } while(0)
static unsigned char mem[32u<<20];
static uint64_t available=sizeof mem;
enum { ROOT=0xf00000,PDPT=ROOT+0x1000,PD=ROOT+0x2000,PT=ROOT+0x3000 };
static void put(unsigned at,uint64_t value)
{ unsigned i; for(i=0;i<8;i++) mem[at+i]=(unsigned char)(value>>(i*8)); }
static uint64_t get(unsigned at)
{ unsigned i; uint64_t v=0; for(i=0;i<8;i++) v|=(uint64_t)mem[at+i]<<(i*8); return v; }
static int readmem(void *ctx,uint64_t pa,void *dst,size_t n)
{ (void)ctx; ++reads; if(pa>available || n>available-pa) return -1; memcpy(dst,mem+pa,n); return 0; }
static void fixture(void)
{
    memset(mem,0,sizeof mem); available=sizeof mem; reads=0;
    put(0x1000,0x2023); put(0x1000+511*8,0x4023);
    put(0x2000,0x3023); put(0x4000+510*8,0x3023);
    put(ROOT+256*8,PDPT|3); put(ROOT+511*8,PDPT|3);
    put(PDPT,PD|3); put(PD,PT|3);
    /* A leaf direct-map alias of a retired page is data, not a paging-table
     * dependency. The guard must distinguish these cases. */
    put(PT+8,0x1003);
}
static int probe(void) { return shz_smp_boot_pages_safe(readmem,0,0x1000,ROOT,ROOT,sizeof mem); }
static uint64_t fingerprint(void)
{ unsigned i; uint64_t h=0xcbf29ce484222325ull; for(i=0;i<sizeof mem;i++) h=(h^mem[i])*0x100000001b3ull; return h; }
int main(void)
{
    unsigned i; uint64_t before;
    fixture(); before=fingerprint(); CHECK(probe()==0); CHECK(before==fingerprint()); CHECK(reads>0);
    { uint64_t path[4]={0}; unsigned budget=4096,prior=reads;
      CHECK(shz_smp_guard_walk(readmem,0,ROOT,0,sizeof mem,path,&budget)==SHZ_SMP_BOOT_GUARD_INVALID);
      CHECK(shz_smp_guard_walk(readmem,0,ROOT,5,sizeof mem,path,&budget)==SHZ_SMP_BOOT_GUARD_INVALID);
      CHECK(reads==prior); }
    CHECK(shz_smp_boot_pages_safe(0,0,0x1000,ROOT,ROOT,sizeof mem)==SHZ_SMP_BOOT_GUARD_INVALID);
    CHECK(shz_smp_boot_pages_safe(readmem,0,0x2000,ROOT,ROOT,sizeof mem)==SHZ_SMP_BOOT_GUARD_INVALID);
    CHECK(shz_smp_boot_pages_safe(readmem,0,0x1000,0x1000,ROOT,sizeof mem)==SHZ_SMP_BOOT_GUARD_INVALID);
    CHECK(shz_smp_boot_pages_safe(readmem,0,0x1000,ROOT+0x1000,ROOT,sizeof mem)==SHZ_SMP_BOOT_GUARD_INVALID);
    CHECK(shz_smp_boot_pages_safe(readmem,0,0x1000,ROOT+1,ROOT+1,sizeof mem)==SHZ_SMP_BOOT_GUARD_INVALID);
    CHECK(shz_smp_boot_pages_safe(readmem,0,0x1000,0x8000,0x8000,sizeof mem)==SHZ_SMP_BOOT_GUARD_INVALID);
    CHECK(shz_smp_boot_pages_safe(readmem,0,0x1000,ROOT,ROOT,ROOT+4095)==SHZ_SMP_BOOT_GUARD_INVALID);
    CHECK(shz_smp_boot_pages_safe(readmem,0,0x1000,ROOT,ROOT,(1ull<<32)+4096)==SHZ_SMP_BOOT_GUARD_INVALID);
    /* Each unexpected old-root slot invalidates boot-page provenance. */
    for(i=0;i<512;i++) {
        const unsigned at=0x1000+i*8; const uint64_t old=get(at);
        put(at,old^0x40); CHECK(probe()==SHZ_SMP_BOOT_GUARD_INVALID); put(at,old);
    }
    for(i=0;i<512;i++) {
        const unsigned at=0x2000+i*8; const uint64_t old=get(at);
        put(at,old^0x40); CHECK(probe()==SHZ_SMP_BOOT_GUARD_INVALID); put(at,old);
    }
    for(i=0;i<512;i++) {
        const unsigned at=0x4000+i*8; const uint64_t old=get(at);
        put(at,old^0x40); CHECK(probe()==SHZ_SMP_BOOT_GUARD_INVALID); put(at,old);
    }
    CHECK(probe()==0);
    /* Hardware Accessed bits are optional in the retired non-leaf entries. */
    put(0x1000,0x2003); put(0x1000+511*8,0x4003); put(0x2000,0x3003); put(0x4000+510*8,0x3003); CHECK(probe()==0);
    put(ROOT+256*8,0x1003); CHECK(probe()==SHZ_SMP_BOOT_GUARD_DEPENDENCY); put(ROOT+256*8,PDPT|3);
    put(PDPT,0x1003); CHECK(probe()==SHZ_SMP_BOOT_GUARD_DEPENDENCY); put(PDPT,PD|3);
    put(PD,0x1003); CHECK(probe()==SHZ_SMP_BOOT_GUARD_DEPENDENCY); put(PD,PT|3);
    put(PDPT,ROOT|3); CHECK(probe()==SHZ_SMP_BOOT_GUARD_DEPENDENCY); put(PDPT,PD|3);
    put(PD,PDPT|3); CHECK(probe()==SHZ_SMP_BOOT_GUARD_DEPENDENCY); put(PD,PT|3);
    put(ROOT+256*8,PDPT|0x83); CHECK(probe()==SHZ_SMP_BOOT_GUARD_INVALID); put(ROOT+256*8,PDPT|3);
    put(PDPT,sizeof mem|3); CHECK(probe()==SHZ_SMP_BOOT_GUARD_DEPENDENCY); put(PDPT,PD|3);
    put(PDPT,0x2003); CHECK(probe()==SHZ_SMP_BOOT_GUARD_DEPENDENCY); put(PDPT,PD|3);
    put(PDPT,0x83); CHECK(probe()==0); put(PDPT,PD|3); /*1GiB leaf does not retain a table. */
    put(PD,0x83); CHECK(probe()==0); put(PD,PT|3); /*2MiB leaf likewise. */
    available=0x4000+510*8; CHECK(probe()==SHZ_SMP_BOOT_GUARD_UNREADABLE); available=sizeof mem;
    available=PDPT; CHECK(probe()==SHZ_SMP_BOOT_GUARD_UNREADABLE); available=sizeof mem;
    /* Repeated valid-looking non-leaf aliases are bounded, even though no
     * retired table/cycle is involved. */
    for(i=0;i<512;i++) { put(ROOT+i*8,PDPT|3); put(PDPT+i*8,PD|3); }
    CHECK(probe()==SHZ_SMP_BOOT_GUARD_LIMIT);
    printf("PASS production SMP boot retirement guard: %u checks\n",checks);
    return 0;
}
