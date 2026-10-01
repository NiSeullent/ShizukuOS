/* SPDX-License-Identifier: GPL-2.0-only
 * True Multiboot-only page5000 admission. The native stub GDT/code/stack lives
 * above4MiB, PT writes end5000exclusive, memholes6000, footer6800, bootinfo7000.
 * UEFI's live loader trampoline5000 is a different profile and is refused.
 * Page1000 retirement was an earlier proposal; it is not used by this backend.
 */
#ifndef SHZ_CPU_BOOT_CONTRACT_H
#define SHZ_CPU_BOOT_CONTRACT_H
#include "standalone/native_firmware.h"
#define SHZ_CPU_BOOT_TABLE_BUDGET 4096u
#define SHZ_CPU_BOOT_PMM_BASE UINT64_C(0xf00000)
#define SHZ_CPU_BOOT_PAGE UINT64_C(4096)
#define SHZ_CPU_BOOT_PA_MASK UINT64_C(0x000ffffffffff000)

static inline int shz_cpu_boot_kernel_dtr(uint64_t base,uint32_t limit)
{
    return base>=UINT64_C(0xffffffff80100000) && base<UINT64_C(0xffffffff80300000) &&
        (uint64_t)limit+1<=UINT64_C(0xffffffff80300000)-base;
}
static inline int shz_cpu_boot_walk(const shz_native_firmware_t *h,uint64_t table,unsigned level,
        uint64_t ram_top,uint64_t path[4],unsigned depth,unsigned *budget,
        shz_native_firmware_read_fn read,void *ctx)
{
    uint64_t entries[512]; unsigned i;
    if(!*budget || depth>=4 || table<SHZ_CPU_BOOT_PMM_BASE || (table&4095) || table>=ram_top ||
       SHZ_CPU_BOOT_PAGE>ram_top-table || !shz_native_firmware_ram_covers(h,table,4096)) return 0;
    for(i=0;i<depth;i++) if(path[i]==table) return 0;
    --*budget;
    if(!read(ctx,table,entries,4096)) return 0;
    path[depth]=table;
    for(i=0;i<512;i++) {
        const uint64_t value=entries[i];
        if(!(value&1)) continue;
        if(level==4 && (value&0x80)) return 0;
        if(level==1 || ((level==3 || level==2) && (value&0x80))) continue;
        if(!shz_cpu_boot_walk(h,value&SHZ_CPU_BOOT_PA_MASK,level-1,ram_top,path,depth+1,budget,read,ctx)) return 0;
    }
    return 1;
}
/* Nonleaf references, including recursive aliases, must not depend on any old
 * low boot page. Ordinary data/identity aliases of physical5000 are permitted:
 * they do not interpret its overwritten contents as a page table.
 */
static inline int shz_cpu_boot_contract(const shz_native_firmware_t *h,int native_multiboot,
        uint64_t active_cr3,uint64_t final_cr3,uint64_t ram_top,uint64_t gdt,uint32_t gdt_limit,
        uint64_t idt,uint32_t idt_limit,uint64_t trampoline,shz_native_firmware_read_fn read,void *ctx)
{
    uint64_t path[4]; unsigned budget=SHZ_CPU_BOOT_TABLE_BUDGET;
    if(!read || !shz_native_firmware_valid(h,native_multiboot) || trampoline!=0x5000 ||
       active_cr3!=final_cr3 || final_cr3<SHZ_CPU_BOOT_PMM_BASE || (final_cr3&4095) ||
       gdt_limit!=55 || idt_limit!=4095 || !shz_cpu_boot_kernel_dtr(gdt,gdt_limit) ||
       !shz_cpu_boot_kernel_dtr(idt,idt_limit) || !shz_native_firmware_ram_covers(h,trampoline,4096)) return 0;
    return shz_cpu_boot_walk(h,final_cr3,4,ram_top,path,0,&budget,read,ctx);
}
#endif
