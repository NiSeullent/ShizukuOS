/* SPDX-License-Identifier: GPL-2.0-only
 * Confirms the latest Kernel64 image is the ELF64 guest the supervisor loads.
 * Binding it is mandatory before a Windows 98 chain. A missing image is a refusal.
 */
#include "../include/csmwrap_abi.h"

int csmwrap_bind_kernel64(csmwrap_handoff *handoff, const void *image, uint32_t bytes)
{
    const uint8_t *elf = image;
    uint16_t machine;
    if (!handoff || !elf || bytes < 64)
        return -1;
    if (elf[0] != 0x7f || elf[1] != 'E' || elf[2] != 'L' || elf[3] != 'F')
        return -1;
    if (elf[4] != 2 || elf[5] != 1)
        return -1; /* ELFCLASS64, ELFDATA2LSB */
    machine = (uint16_t)elf[18] | ((uint16_t)elf[19] << 8);
    if (machine != 62)
        return -1; /* EM_X86_64 */
    handoff->flags |= CSMWRAP_F_KERNEL64;
    return 0;
}

int csmwrap_boot_allowed(const csmwrap_handoff *handoff)
{
    uint32_t mode;
    if (csmwrap_handoff_check(handoff) != 0)
        return 0;
    if ((handoff->flags & (CSMWRAP_F_KERNEL64 | CSMWRAP_F_ENTERED)) !=
        (CSMWRAP_F_KERNEL64 | CSMWRAP_F_ENTERED))
        return 0;
    mode = handoff->firmware_mode;
    if (mode != CSMWRAP_MODE_NATIVE_BIOS && mode != CSMWRAP_MODE_UEFI_IA32 &&
        mode != CSMWRAP_MODE_UEFI_X64)
        return 0;
    if (handoff->boot_mode != mode)
        return 0;
    return 1;
}
