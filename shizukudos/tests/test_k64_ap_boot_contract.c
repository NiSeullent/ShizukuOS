/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if __has_include("../kernel64/cpu_boot_contract.h")
#include "../kernel64/cpu_boot_contract.h"
static unsigned checks,failures,reads;
#define CHECK(name, condition) do { ++checks; if (!(condition)) { ++failures; fprintf(stderr,"FAIL %s\n",name); } } while(0)
static uint64_t tables[4][512];
static int table_read(void *ctx,uint64_t pa,void *dst,uint32_t n)
{
    (void)ctx; ++reads;
    if(pa<0x2000000 || pa>=0x2004000 || (pa&4095) || n!=4096) return 0;
    memcpy(dst,tables[(pa-0x2000000)/4096],4096); return 1;
}
static void setup(shz_native_firmware_t *h)
{
    memset(h,0,sizeof *h); h->magic=SHZ_NATIVE_FIRMWARE_MAGIC; h->version=SHZ_NATIVE_FIRMWARE_VERSION;
    h->bytes=sizeof *h; h->profile=SHZ_NATIVE_FIRMWARE_MULTIBOOT; h->count=2;
    h->range[0]=(shz_native_firmware_range_t){0x1000,0x7000,1,0};
    h->range[1]=(shz_native_firmware_range_t){0xf00000,0x7100000,1,0}; h->check=shz_native_firmware_sum(h);
    memset(tables,0,sizeof tables); reads=0;
    tables[0][511]=0x2001000|3; tables[1][510]=0x2002000|3;
    tables[2][0]=0x2003000|3; tables[3][5]=0x5000|3;
}
static int check(shz_native_firmware_t *h)
{
    return shz_cpu_boot_contract(h,1,0x2000000,0x2000000,0x8000000,
        0xffffffff801a0000ull,55,0xffffffff801b0000ull,4095,0x5000,table_read,0);
}
int main(void)
{
    shz_native_firmware_t h;
    setup(&h);
    CHECK("private final tables and entire free Multiboot5000page admitted",check(&h)==1 && reads==4);
    CHECK("ordinary leaf alias of trampoline page is not table dependency",check(&h)==1);
    CHECK("UP UEFl/direct profile denied",shz_cpu_boot_contract(&h,0,0x2000000,0x2000000,0x8000000,
        0xffffffff801a0000ull,55,0xffffffff801b0000ull,4095,0x5000,table_read,0)==0);
    CHECK("active CR3 must match retained final PMM root",shz_cpu_boot_contract(&h,1,0x2001000,0x2000000,0x8000000,
        0xffffffff801a0000ull,55,0xffffffff801b0000ull,4095,0x5000,table_read,0)==0);
    CHECK("original1000 bootPML4 never accepted as final",shz_cpu_boot_contract(&h,1,0x1000,0x1000,0x8000000,
        0xffffffff801a0000ull,55,0xffffffff801b0000ull,4095,0x5000,table_read,0)==0);
    CHECK("misaligned final root denied",shz_cpu_boot_contract(&h,1,0x2000001,0x2000001,0x8000000,
        0xffffffff801a0000ull,55,0xffffffff801b0000ull,4095,0x5000,table_read,0)==0);
    CHECK("old loader GDT cannot survive in startup page",shz_cpu_boot_contract(&h,1,0x2000000,0x2000000,0x8000000,
        0x5800,55,0xffffffff801b0000ull,4095,0x5000,table_read,0)==0);
    CHECK("GDT extent cannot cross kernel window",shz_cpu_boot_contract(&h,1,0x2000000,0x2000000,0x8000000,
        0xffffffff802ffff0ull,55,0xffffffff801b0000ull,4095,0x5000,table_read,0)==0);
    CHECK("IDT entire256gate extent required",shz_cpu_boot_contract(&h,1,0x2000000,0x2000000,0x8000000,
        0xffffffff801a0000ull,55,0xffffffff801b0000ull,255,0x5000,table_read,0)==0);
    h.count=3; h.range[2]=(shz_native_firmware_range_t){0x5fff,1,2,0}; h.check=shz_native_firmware_sum(&h);
    CHECK("reservation at last byte of5000page denies all writes",check(&h)==0);
    setup(&h); tables[1][0]=0x5000|3;
    CHECK("surviving nonleaf5000reference denied before read",check(&h)==0);
    setup(&h); tables[1][0]=0x1000|3;
    CHECK("surviving original boot-table child denied",check(&h)==0);
    setup(&h); tables[0][0]=0x2000000|3;
    CHECK("self recursive final PML4 alias denied",check(&h)==0);
    setup(&h); tables[2][1]=0x2000000|3;
    CHECK("indirect recursive table cycle denied",check(&h)==0);
    setup(&h); tables[0][0]=0x83;
    CHECK("large-page flag cannot bypass PML4 traversal",check(&h)==0);
    setup(&h); tables[2][0]=0x83;
    CHECK("2MiB data leaf is safe even when it contains5000",check(&h)==1 && reads==3);
    setup(&h); h.range[1].type=3; h.check=shz_native_firmware_sum(&h);
    CHECK("readable ACPI reclaim is not PMM table ownership",check(&h)==0);
    setup(&h); h.count=3; h.range[2]=(shz_native_firmware_range_t){0x2002fff,1,4,0}; h.check=shz_native_firmware_sum(&h);
    CHECK("overlapping firmware NVS defeats table ownership",check(&h)==0);
    setup(&h); tables[2][1]=0x2100000|3;
    CHECK("unavailable table bytes fail closed",check(&h)==0);
    setup(&h);
    for(unsigned i=0;i<512;i++) tables[0][i]=0x2001000|3;
    for(unsigned i=0;i<512;i++) tables[1][i]=0x2002000|3;
    CHECK("finite traversal bounds hostile repeated aliases",check(&h)==0 && reads<=SHZ_CPU_BOOT_TABLE_BUDGET);
    printf("%s native AP page retirement contract: %u checks, %u failures\n",failures?"FAIL":"PASS",checks,failures);
    return failures?1:0;
}
#else
int main(void) { fputs("FAIL actual native AP startup page retirement and surviving-table dependency checks are absent\n",stderr); return 1; }
#endif
