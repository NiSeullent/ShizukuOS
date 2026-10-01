/* SPDX-License-Identifier: GPL-2.0-only */
#include "../include/csmwrap_abi.h"

static void copy_bytes(void *dst, const void *src, unsigned n)
{
    unsigned i;
    uint8_t *d = dst;
    const uint8_t *s = src;
    for (i = 0; i < n; ++i)
        d[i] = s[i];
}

static void zero_bytes(void *dst, unsigned n)
{
    unsigned i;
    uint8_t *d = dst;
    for (i = 0; i < n; ++i)
        d[i] = 0;
}

void csmwrap_handoff_clear(csmwrap_handoff *handoff)
{
    unsigned i;
    uint8_t *bytes;
    if (!handoff)
        return;
    bytes = (uint8_t *)handoff;
    for (i = 0; i < sizeof(*handoff); ++i)
        bytes[i] = 0;
}

static void write_signature(csmwrap_handoff *handoff)
{
    static const uint8_t sig[8] = {'C', 'S', 'M', 'W', 'R', 'A', 'P', 0};
    copy_bytes(handoff->signature, sig, 8);
}

int csmwrap_fill_snapshot(csmwrap_handoff *handoff, csmwrap_service_table *services,
                          const csmwrap_snapshot *snapshot)
{
    uint32_t mode, count, i;
    if (!handoff || !services || !snapshot)
        return -1;
    mode = csmwrap_select_mode(&snapshot->firmware);
    if (!mode)
        return -1;
    zero_bytes(services, sizeof(*services));
    csmwrap_handoff_clear(handoff);
    write_signature(handoff);
    handoff->abi_major = 1;
    handoff->abi_minor = 0;
    handoff->size = sizeof(*handoff);
    handoff->boot_mode = mode;
    handoff->firmware_mode = mode;
    handoff->fb_addr = snapshot->fb_addr;
    handoff->fb_width = snapshot->fb_width;
    handoff->fb_height = snapshot->fb_height;
    handoff->fb_pitch = snapshot->fb_pitch;
    handoff->fb_format = snapshot->fb_format;
    handoff->boot_disk_id = snapshot->boot_disk_id;
    handoff->sector_size = snapshot->sector_size;
    handoff->disk_size = snapshot->disk_size;
    handoff->conventional_kb = snapshot->conventional_kb;
    handoff->extended_kb = snapshot->extended_kb;
    handoff->rsdp = snapshot->rsdp;
    handoff->smbios = snapshot->smbios;
    handoff->pci_info = snapshot->pci_info;
    handoff->uefi_system_table = snapshot->uefi_system_table;
    services->abi_major = 1;
    services->keyboard = snapshot->keyboard;
    services->block_io_count = snapshot->block_io_count;
    services->pci_info = snapshot->pci_info;
    count = snapshot->e820_count;
    if (count > 32)
        count = 32;
    if (snapshot->e820) {
        for (i = 0; i < count; ++i)
            services->e820[i] = snapshot->e820[i];
        handoff->e820_count = count;
        handoff->flags |= CSMWRAP_F_E820;
    }
    if (snapshot->keyboard)
        handoff->flags |= CSMWRAP_F_KEYBOARD;
    if (snapshot->block_io_count)
        handoff->flags |= CSMWRAP_F_STORAGE;
    handoff->flags |= CSMWRAP_F_ENTERED;
    if (snapshot->kernel64 &&
        csmwrap_bind_kernel64(handoff, snapshot->kernel64, snapshot->kernel64_bytes) != 0)
        return -1;
    handoff->service_table = (uint64_t)(uintptr_t)services;
    handoff->e820_addr = (uint64_t)(uintptr_t)services->e820;
    csmwrap_handoff_seal(handoff);
    /* Addresses are filled by the caller once the table has a physical home. */
    return 0;
}
