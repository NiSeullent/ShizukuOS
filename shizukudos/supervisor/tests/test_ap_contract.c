/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../include/ap_boot.h"
typedef struct { uint32_t type, pad; uint64_t phys, virt, pages, attr, extra; } desc;
static desc map[] = {{2,0,0x80000,0,4,8,0}, {2,0,0x100000,0,1,8,0},
                     {2,0,0x4000000,0,4096,8,0}, {9,0,0x5000000,0,2,8,0}};
static shz_ap_boot_t good(void) {
    shz_ap_boot_t b = {0};
    b.magic=SHZ_AP_MAGIC; b.version=1; b.bytes=sizeof b; b.requested=4;
    b.low_base=0x80000; b.low_pages=3; b.topology.count=4;
    b.topology.lapic_pa=0xfee00000; b.topology.rsdp_pa=0x5000000;
    b.topology.madt_pa=0x5000100;
    for(unsigned i=0;i<4;i++) { b.topology.apic_id[i]=i; b.topology.acpi_uid[i]=i; }
    return b;
}
int main(void) {
    assert(shz_ap_lapic_base_ok(UINT64_C(0xfee00900),UINT64_C(0xfee00000)));
    assert(!shz_ap_lapic_base_ok(UINT64_C(0x1fee00900),UINT64_C(0xfee00000)));
    assert(!shz_ap_lapic_base_ok(UINT64_C(0xfee00500),UINT64_C(0xfee00000)));
    assert(!shz_ap_lapic_base_ok(UINT64_C(0xfee00d00),UINT64_C(0xfee00000)));
    assert(!shz_ap_lapic_base_ok(UINT64_C(0xfee00900),UINT64_C(0xfec00000)));
    assert(shz_ap_lapic_pte_ok(UINT64_C(0xfee0009b),UINT64_C(0xfee00000)));
    assert(!shz_ap_lapic_pte_ok(UINT64_C(0xfee00083),UINT64_C(0xfee00000)));
    assert(!shz_ap_lapic_pte_ok(UINT64_C(0xfee00099),UINT64_C(0xfee00000)));
    assert(!shz_ap_lapic_pte_ok(UINT64_C(0xfee0001b),UINT64_C(0xfee00000)));
    assert(!shz_ap_lapic_pte_ok(UINT64_C(0xfec0009b),UINT64_C(0xfee00000)));
    assert(!shz_ap_lapic_pte_ok(UINT64_C(0xfee0109b),UINT64_C(0xfee00000)));
    shz_ap_config_t c = {SHZ_AP_CFG_MAGIC,1,4,0};
    assert(shz_ap_config_valid(&c,sizeof c));
    c.count=0; assert(!shz_ap_config_valid(&c,sizeof c)); c.count=33;
    assert(!shz_ap_config_valid(&c,sizeof c)); c.count=4; c.flags=1;
    assert(!shz_ap_config_valid(&c,sizeof c)); c.flags=0;
    assert(!shz_ap_config_valid(&c,sizeof c-1));
    assert(shz_ap_map_covers(map,sizeof map,sizeof(desc),0x80000,3*4096,2));
    assert(shz_ap_map_covers(map,sizeof map,sizeof(desc),0x5000000,4096,0));
    assert(!shz_ap_map_covers(map,sizeof map,sizeof(desc),0x5000000,4096,2));
    assert(!shz_ap_map_covers(map,sizeof map,sizeof(desc),0x83000,8192,2));
    assert(!shz_ap_map_covers(map,sizeof map,39,0x80000,4096,2));
    assert(!shz_ap_map_covers(map,sizeof map,sizeof(desc),UINT64_MAX-7,16,2));
    desc overlapped[]={{2,0,0x80000,0,4,8,0},{2,0,0x81000,0,1,8,0}};
    assert(!shz_ap_map_covers(overlapped,sizeof overlapped,sizeof(desc),0x80000,3*4096,2));
    map[0].attr=1; assert(!shz_ap_map_covers(map,sizeof map,sizeof(desc),0x80000,4096,2)); map[0].attr=8;
    map[0].attr=15; assert(shz_ap_map_covers(map,sizeof map,sizeof(desc),0x80000,4096,2)); map[0].attr=8;
    map[0].pages=UINT64_MAX; assert(!shz_ap_map_covers(map,sizeof map,sizeof(desc),0x80000,4096,2)); map[0].pages=4;
    shz_ap_boot_t b=good();
    assert(shz_ap_boot_valid(&b,0x100000,sizeof b,map,sizeof map,sizeof(desc),0x4000000,0x1000000));
    assert(!shz_ap_boot_valid(&b,0x100000,sizeof b,map,sizeof map,sizeof(desc),
                              0x100000+sizeof b,SHZ_AP_PAGE-sizeof b));
    b.topology.apic_id[3]=1; assert(!shz_ap_boot_valid(&b,0x100000,sizeof b,map,sizeof map,sizeof(desc),0x4000000,0x1000000));
    b=good(); b.low_base=0x100000; assert(!shz_ap_boot_valid(&b,0x100000,sizeof b,map,sizeof map,sizeof(desc),0x4000000,0x1000000));
    b=good(); b.low_pages=2; assert(!shz_ap_boot_valid(&b,0x100000,sizeof b,map,sizeof map,sizeof(desc),0x4000000,0x1000000));
    b=good(); b.requested=5; assert(!shz_ap_boot_valid(&b,0x100000,sizeof b,map,sizeof map,sizeof(desc),0x4000000,0x1000000));
    b=good(); b.topology.bsp_index=1; assert(!shz_ap_boot_valid(&b,0x100000,sizeof b,map,sizeof map,sizeof(desc),0x4000000,0x1000000));
    b=good(); b.sealed=1; assert(!shz_ap_boot_valid(&b,0x100000,sizeof b,map,sizeof map,sizeof(desc),0x4000000,0x1000000));
    shz_ap_record_t r={0};
    assert(shz_ap_advance(&r,SHZ_AP_NEW,SHZ_AP_STARTING));
    assert(!shz_ap_advance(&r,SHZ_AP_NEW,SHZ_AP_STARTING));
    shz_ap_fail(&r,SHZ_AP_FAIL_START); assert(r.state==SHZ_AP_FAILED && r.error==SHZ_AP_FAIL_START);
    assert(!shz_ap_advance(&r,SHZ_AP_FAILED,SHZ_AP_STARTING));
    shz_ap_fail(&r,SHZ_AP_FAIL_CAP); assert(r.error==SHZ_AP_FAIL_START);
    r=(shz_ap_record_t){0}; assert(!shz_ap_advance(&r,SHZ_AP_NEW,SHZ_AP_DONE));
    uint8_t data[]={1,2,3};
    /* Independent FNV-1a vector, rounds include a one-byte round separator. */
    assert(shz_ap_hash(data,3,1)==UINT64_C(0xbe7a5a7751657191));
    puts("Supervisor AP contract: PASS");
}
