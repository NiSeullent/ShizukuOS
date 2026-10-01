/* SPDX-License-Identifier: GPL-2.0-only
 * Runs the production Multiboot stub and additionally forwards its actual
 * readable RAM/ACPI/BIOS ranges to an isolated AP component test. QEMU SeaBIOS
 * stores ACPI in its E820 reserved RAM tail. Only that fixed256MiB fixture's
 * adjacent, bounded tail is admitted, never all reserved/MMIO regions.
 * No existing loader is edited and no table/CPU identity is synthesized.
 */
#define stub_prepare smp_original_stub_prepare
#include "../kernel64/standalone/boot32.c"
#undef stub_prepare
#include "k64_smp_firmware.h"
void stub_prepare(uint32_t magic,const struct mbi *mbi)
{
    static struct shz_smp_test_firmware fw;
    uint32_t off; uint64_t usable_end=0; int low_reserved=0;
    zero((uint32_t)&fw,sizeof fw);
    if(magic!=MB_MAGIC || !(mbi->flags&MB_INFO_MEM_MAP)) fail("SMP probe requires real firmware memory map",0);
    for(off=0;off<mbi->mmap_length;) {
        const struct mmap_entry *e;
        if(mbi->mmap_length-off<24) fail("truncated SMP firmware memory map",off);
        e=(const struct mmap_entry *)(mbi->mmap_addr+off);
        if(e->size<20 || e->size>mbi->mmap_length-off-4 || e->base>UINT64_MAX-e->length)
            fail("invalid SMP firmware memory map",off);
        if(e->type==1 && e->base<=SHZ_SMP_TEST_FIRMWARE_PA &&
           e->base+e->length>=SHZ_SMP_TEST_FIRMWARE_PA+4096) low_reserved=1;
        if(e->type==1 && e->base>=0x100000 && e->base+e->length>usable_end)
            usable_end=e->base+e->length;
        off+=e->size+4;
    }
    for(off=0;off<mbi->mmap_length;) {
        const struct mmap_entry *e=(const struct mmap_entry *)(mbi->mmap_addr+off);
        const uint64_t end=e->base+e->length;
        const int bios=e->type==2 &&
            ((e->base>=0x80000 && end<=0xa0000) || (e->base>=0xe0000 && end<=0x100000));
        const int fixture_tail=e->type==2 && e->base==usable_end && end==SHZ_SMP_TEST_RAM_TOP &&
            e->length<=0x200000 && e->base>=SHZ_SMP_TEST_RAM_TOP-0x200000;
        if((e->type==1 || e->type==3 || e->type==4 || bios || fixture_tail) && e->length) {
            if(fw.count==32) fail("SMP firmware range limit",fw.count);
            fw.range[fw.count].base=e->base; fw.range[fw.count].size=e->length;
            fw.range[fw.count].type=e->type; ++fw.count;
        }
        off+=e->size+4;
    }
    if(!low_reserved) fail("SMP probe handoff page is not usable RAM",SHZ_SMP_TEST_FIRMWARE_PA);
    fw.magic=SHZ_SMP_TEST_FIRMWARE_MAGIC;
    smp_original_stub_prepare(magic,mbi);
    copy(SHZ_SMP_TEST_FIRMWARE_PA,(uint32_t)&fw,sizeof fw);
}
