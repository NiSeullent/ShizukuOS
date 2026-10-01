/* SPDX-License-Identifier: GPL-2.0-only
 * Native AP integration admission. The scheduler remains CPU0 until its actual
 * per-CPU architecture and shared-memory synchronization are integrated.
 */
#include "cpu_bringup.h"
#include "cpu_firmware.h"
#include "cpu_boot_contract.h"
static shz_cpu_firmware_t firmware;
static unsigned admitted;
struct __attribute__((packed)) cpu_dtr { uint16_t limit; uint64_t base; };
static int table_read(void *ctx,uint64_t pa,void *out,uint32_t bytes)
{
    const shz_cpu_firmware_t *f=ctx;
    if(!shz_native_firmware_ram_covers(&f->native,pa,bytes) || pa>=mem_ram_top() || bytes>mem_ram_top()-pa) return 0;
    memcpy(out,(const void *)p2v(pa),bytes); return 1;
}
void shz_cpu_bringup_prepare(const shz_bootinfo_t *bi)
{
    struct cpu_dtr gdt,idt;
    if(k64_cmdline_has("smp=off") ||
       (!k64_cmdline_has("shz.smp=bringup") && !k64_cmdline_has("shz.smp=firmware-test"))) return;
    const int rc=shz_cpu_firmware_prepare(bi,&firmware);
    if(rc!=1) { kprintf("SMP-BRINGUP: firmware unavailable rc=%d, scheduler CPUs=1\n",rc); return; }
    __asm__ volatile("sgdt %0":"=m"(gdt));
    __asm__ volatile("sidt %0":"=m"(idt));
    admitted=shz_cpu_boot_contract(&firmware.native,!(bi->flags&SHZ_BIF_UEFI_DIRECT),read_cr3(),kernel_pml4(),
        mem_ram_top(),gdt.base,gdt.limit,idt.base,idt.limit,0x5000,table_read,&firmware);
    kprintf("SMP-BRINGUP: page5000=%u final_cr3=%llx gdt=%llx idt=%llx scheduler CPUs=1\n",
            admitted,read_cr3(),gdt.base,idt.base);
    if(k64_cmdline_has("shz.smp=firmware-test")) {
        unsigned i,reads=0;
        uint8_t header[36];
        for(i=0;i<firmware.native.count;i++) {
            const shz_native_firmware_range_t *r=&firmware.native.range[i];
            if(r->type==2 && r->base>=mem_ram_top() && r->length>=sizeof header &&
               shz_qemu_firmware_covers(&firmware.qemu,&firmware.native,r->base,sizeof header)) {
                if(shz_cpu_firmware_read(&firmware,r->base,header,sizeof header)) break;
                ++reads;
                kprintf("SMP-FIRMWARE: native_read pa=%llx bytes=%u checksum_byte=%u\n",r->base,
                        (unsigned)sizeof header,header[0]);
            }
        }
        kprintf("SMP-FIRMWARE: test page_admitted=%u reserved_reads=%u\n",admitted,reads);
    }
}
void shz_cpu_bringup_verify(void)
{
    /* AP startup is connected only after the independently owned backend is
     * reviewed and frozen. Resource proof alone is not an SMP success. */
    if(k64_cmdline_has("shz.smp=bringup") && !k64_cmdline_has("smp=off"))
        kprintf("SMP-BRINGUP: backend pending integration, scheduler CPUs=1\n");
}
