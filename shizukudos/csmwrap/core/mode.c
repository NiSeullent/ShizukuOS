/* SPDX-License-Identifier: GPL-2.0-only */
#include "../include/csmwrap_abi.h"

uint32_t csmwrap_select_mode(const csmwrap_firmware_view *view)
{
    int efi;
    if (!view)
        return 0;
    efi = view->efi_signature == CSMWRAP_EFI_SYSTEM_TABLE_SIGNATURE;
    /* An EFI application provides services itself. A native BIOS/CSM does not. */
    if (efi && view->pointer_bits == 64)
        return CSMWRAP_MODE_UEFI_X64;
    if (efi && view->pointer_bits == 32)
        return CSMWRAP_MODE_UEFI_IA32;
    if (view->native_bios)
        return CSMWRAP_MODE_NATIVE_BIOS;
    return 0;
}
