/* SPDX-License-Identifier: GPL-2.0-only
 * Disk identity copied while UEFI boot services are still alive.
 * The snapshot has no EFI_BLOCK_IO pointer and no ReadBlocks pointer.
 */
#ifndef CSMWRAP_HANDOFF_H
#define CSMWRAP_HANDOFF_H
#include <stdint.h>
#include "block.h"

#define CSMWRAP_ID_MAGIC 0x43534D57u /* 'WMSC' little-endian */

#define CSMWRAP_MEDIUM_NONE 0u
#define CSMWRAP_MEDIUM_RAM 1u
#define CSMWRAP_MEDIUM_AHCI 2u

struct csmwrap_disk_identity {
    uint32_t magic;
    uint32_t bytes;
    uint8_t bios_unit;
    uint8_t medium;
    uint16_t sector_size;
    uint64_t sector_count;
    uint32_t cylinders;
    uint32_t heads;
    uint32_t sectors_per_track;
    char model[40];
    uint8_t copied_while_boot_services;
    uint8_t reserved[7];
};

void csmwrap_boot_services_exit(void);
int csmwrap_boot_services_exited(void);

/* Plain numbers only. Refuses the call after ExitBootServices and does
 * not touch dst when it refuses. */
int csmwrap_capture_identity(struct csmwrap_disk_identity *dst, uint8_t bios_unit,
                             uint8_t medium, uint32_t sector_size,
                             uint64_t sector_count, int legacy_floppy,
                             const char *model);

/* EFI_BLOCK_IO is a boot-service protocol. These entries never call it.
 * After ExitBootServices they fail before touching the buffer. */
int csmwrap_efi_block_io_read(const void *block_io, uint64_t lba, void *buf,
                              uint32_t blocks);
int csmwrap_efi_block_io_write(const void *block_io, uint64_t lba, const void *buf,
                               uint32_t blocks);
#endif
