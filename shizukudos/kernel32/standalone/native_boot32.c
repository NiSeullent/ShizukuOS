/* SPDX-License-Identifier: GPL-2.0-only
 * Explicit native K32 provider, never the Supervisor/default UP stub. */
#ifndef STUB_K32
#define STUB_K32
#endif
#define stub_prepare k32_original_stub_prepare
#include "../../kernel64/standalone/boot32.c"
#undef stub_prepare
#include "native_handoff.h"
void stub_prepare(uint32_t magic,const struct mbi *mbi)
{
    uint32_t cr0;
    __asm__ volatile("mov %%cr0,%0":"=r"(cr0));
    if(cr0&0x80000000u)fail("native K32 provider needs paging off",cr0);
    k32_original_stub_prepare(magic,mbi);
    /* All Multiboot/module/cmdline reads are finished. No stub pointer escapes. */
    if(!shz_native_firmware_valid(&native_firmware,1) ||
       !shz_native_firmware_ram_covers(&native_firmware,0x1000,0x7000))
        fail("native K32 low-page ownership absent",0x1000);
    copy(SHZ_NATIVE_FIRMWARE_GPA,(uint32_t)&native_firmware,sizeof native_firmware);
    k32_native_handoff_t h={K32_NATIVE_MAGIC,1,sizeof h,K32_NATIVE_WRITER,32,0x1000,0x7000,1,0};
    h.checksum=0u-k32_native_checksum(&h);
    copy(K32_NATIVE_HANDOFF_GPA,(uint32_t)&h,sizeof h);
}
