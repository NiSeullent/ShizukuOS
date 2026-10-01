/* SPDX-License-Identifier: GPL-2.0-only */
#include "include/csmwrap_abi.h"
#include <stdio.h>
#include <string.h>

static int failures;

static void expect(int condition, const char *name)
{
    if (condition) {
        printf("PASS %s\n", name);
        return;
    }
    printf("FAIL %s\n", name);
    ++failures;
}

static void sample_elf(uint8_t image[64])
{
    memset(image, 0, 64);
    image[0] = 0x7f;
    image[1] = 'E';
    image[2] = 'L';
    image[3] = 'F';
    image[4] = 2;
    image[5] = 1;
    image[18] = 62;
    image[19] = 0;
}

static void clear_int10(csmwrap_regs *regs)
{
    csmwrap_set_cf(regs, 0);
    regs->eax = 0x10;
}

int main(void)
{
    csmwrap_firmware_view view;
    csmwrap_snapshot shot;
    csmwrap_handoff handoff;
    csmwrap_service_table services;
    csmwrap_e820 row;
    csmwrap_regs regs;
    uint8_t elf[64];
    uint8_t saved;

    printf("handoff_size %u\n", (unsigned)sizeof(csmwrap_handoff));
    expect(sizeof(csmwrap_handoff) == 132, "handoff size is 132");

    memset(&view, 0, sizeof view);
    expect(csmwrap_select_mode(0) == 0, "null firmware is rejected");
    expect(csmwrap_select_mode(&view) == 0, "empty firmware is rejected");
    view.native_bios = 1;
    expect(csmwrap_select_mode(&view) == CSMWRAP_MODE_NATIVE_BIOS, "native BIOS");
    view.efi_signature = CSMWRAP_EFI_SYSTEM_TABLE_SIGNATURE;
    view.pointer_bits = 64;
    view.native_bios = 1;
    expect(csmwrap_select_mode(&view) == CSMWRAP_MODE_UEFI_X64, "UEFI x64 beats a stale CSM flag");
    view.pointer_bits = 32;
    expect(csmwrap_select_mode(&view) == CSMWRAP_MODE_UEFI_IA32, "UEFI ia32");

    memset(&shot, 0, sizeof shot);
    shot.firmware.efi_signature = CSMWRAP_EFI_SYSTEM_TABLE_SIGNATURE;
    shot.firmware.pointer_bits = 64;
    shot.fb_width = 640;
    shot.fb_height = 480;
    shot.fb_pitch = 2560;
    shot.sector_size = 512;
    shot.boot_disk_id = 0x80;
    shot.conventional_kb = 640;
    row.base = 0x100000;
    row.length = 0x1000000;
    row.type = 1;
    row.attrs = 1;
    shot.e820 = &row;
    shot.e820_count = 1;
    shot.keyboard = 0x1000;
    expect(csmwrap_fill_snapshot(&handoff, &services, &shot) == 0, "snapshot without KERNEL64 fills");
    expect(csmwrap_handoff_check(&handoff) == 0, "checksum of sealed handoff");
    expect(!csmwrap_boot_allowed(&handoff), "Win98 chain refused without KERNEL64");
    saved = handoff.signature[0];
    handoff.signature[0] ^= 1;
    expect(csmwrap_handoff_check(&handoff) != 0, "tampered signature fails checksum");
    handoff.signature[0] = saved;
    csmwrap_handoff_seal(&handoff);
    expect(csmwrap_handoff_check(&handoff) == 0, "reseal restores checksum");

    sample_elf(elf);
    shot.kernel64 = elf;
    shot.kernel64_bytes = sizeof elf;
    expect(csmwrap_fill_snapshot(&handoff, &services, &shot) == 0, "snapshot binds KERNEL64");
    expect((handoff.flags & CSMWRAP_F_KERNEL64) != 0, "KERNEL64 flag");
    expect((handoff.flags & CSMWRAP_F_ENTERED) != 0, "CSMWrap entered flag");
    expect(csmwrap_boot_allowed(&handoff), "chain allowed only after both flags");
    elf[4] = 1;
    expect(csmwrap_bind_kernel64(&handoff, elf, sizeof elf) != 0, "non-ELF64 is rejected");

    csmwrap_diag_reset();
    memset(&regs, 0, sizeof regs);
    csmwrap_dispatch(CSMWRAP_MODE_UEFI_X64, 0x10, &regs);
    expect((regs.eflags & 1u) != 0, "unimplemented INT 10 sets CF");
    expect(regs.passthrough == 0, "UEFI does not pass an unregistered service through");
    memset(&regs, 0, sizeof regs);
    regs.eflags = 0x202;
    csmwrap_dispatch(CSMWRAP_MODE_NATIVE_BIOS, 0x13, &regs);
    expect(regs.passthrough == 1, "native BIOS passes INT 13 through");
    expect((regs.eflags & 1u) == 0, "native passthrough does not invent CF");
    memset(&regs, 0, sizeof regs);
    regs.eax = 0xB101;
    csmwrap_dispatch(CSMWRAP_MODE_UEFI_X64, 0x1A, &regs);
    expect((regs.eflags & 1u) != 0, "unregistered PCI install check sets CF");
    expect(csmwrap_register_service(CSMWRAP_SVC_INT10, clear_int10) == 0, "register INT 10");
    memset(&regs, 0, sizeof regs);
    regs.eflags = 1;
    csmwrap_dispatch(CSMWRAP_MODE_UEFI_X64, 0x10, &regs);
    expect((regs.eflags & 1u) == 0, "registered INT 10 clears CF");
    expect(strstr(csmwrap_diag_text(), "CSMWRAP INT ") != 0, "dispatcher log names CSMWRAP");
    expect(handoff.service_table != 0, "service table address recorded");
    expect(handoff.e820_count == 1, "e820 count");

    if (failures) {
        printf("RESULT FAIL %d\n", failures);
        return 1;
    }
    printf("RESULT PASS\n");
    return 0;
}
