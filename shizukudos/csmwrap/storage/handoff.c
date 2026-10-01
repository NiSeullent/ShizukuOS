/* SPDX-License-Identifier: GPL-2.0-only
 * ExitBootServices ends UEFI boot services. EFI_BLOCK_IO.ReadBlocks and
 * WriteBlocks are boot-service methods; their function pointers are
 * invalid afterwards. This file never stores or calls them. The CSM
 * path may use only the identity copied before the handoff, plus a
 * native backend (RAM disk or the AHCI hook).
 */
#include "handoff.h"
#include <string.h>

/* A non-NULL value would be an EFI ReadBlocks/WriteBlocks method.
 * Nothing in this module assigns either pointer. */
typedef int (*csmwrap_efi_transfer_fn)(void *this, uint32_t media_id,
                                      uint64_t lba, uint64_t bytes, void *buf);
static csmwrap_efi_transfer_fn firmware_read_blocks;
static csmwrap_efi_transfer_fn firmware_write_blocks;
static int boot_services_exited;

_Static_assert(sizeof(struct csmwrap_disk_identity) == 88,
               "disk identity snapshot layout");

void csmwrap_boot_services_exit(void)
{
    boot_services_exited = 1;
}

int csmwrap_boot_services_exited(void)
{
    return boot_services_exited;
}

int csmwrap_capture_identity(struct csmwrap_disk_identity *dst, uint8_t bios_unit,
                             uint8_t medium, uint32_t sector_size,
                             uint64_t sector_count, int legacy_floppy,
                             const char *model)
{
    struct csmwrap_geometry geo;
    size_t i;
    if (boot_services_exited) return CSMWRAP_BLK_BOOT_SERVICES;
    if (!dst || sector_size != CSMWRAP_SECTOR_BYTES || sector_count == 0)
        return CSMWRAP_BLK_INVALID;
    if (medium != CSMWRAP_MEDIUM_RAM && medium != CSMWRAP_MEDIUM_AHCI)
        return CSMWRAP_BLK_INVALID;
    if (bios_unit != 0x00 && bios_unit != 0x80 && bios_unit != 0x81)
        return CSMWRAP_BLK_INVALID;
    if (csmwrap_derive_geometry(sector_count, legacy_floppy, &geo) != CSMWRAP_BLK_OK)
        return CSMWRAP_BLK_INVALID;
    memset(dst, 0, sizeof *dst);
    dst->magic = CSMWRAP_ID_MAGIC;
    dst->bytes = (uint32_t)sizeof *dst;
    dst->bios_unit = bios_unit;
    dst->medium = medium;
    dst->sector_size = (uint16_t)sector_size;
    dst->sector_count = sector_count;
    dst->cylinders = geo.cylinders;
    dst->heads = geo.heads;
    dst->sectors_per_track = geo.sectors_per_track;
    if (model) {
        for (i = 0; i < sizeof dst->model - 1u && model[i]; ++i)
            dst->model[i] = model[i];
    }
    dst->copied_while_boot_services = 1;
    return CSMWRAP_BLK_OK;
}

static int refuse_firmware_io(const void *block_io)
{
    /* Both conditions are fatal. The pointer is not dereferenced. */
    if (boot_services_exited || firmware_read_blocks || firmware_write_blocks ||
        block_io == 0)
        return CSMWRAP_BLK_BOOT_SERVICES;
    return CSMWRAP_BLK_BOOT_SERVICES;
}

int csmwrap_efi_block_io_read(const void *block_io, uint64_t lba, void *buf,
                              uint32_t blocks)
{
    (void)lba;
    (void)buf;
    (void)blocks;
    return refuse_firmware_io(block_io);
}

int csmwrap_efi_block_io_write(const void *block_io, uint64_t lba, const void *buf,
                               uint32_t blocks)
{
    (void)lba;
    (void)buf;
    (void)blocks;
    return refuse_firmware_io(block_io);
}
