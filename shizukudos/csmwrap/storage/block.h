/* SPDX-License-Identifier: GPL-2.0-only
 * CSM disk block contract. Sector size matches drivers/ahci_native
 * (AHCI_SECTOR_BYTES) and the uefi_ahci / uefi_fat IDENTIFY check:
 * one logical block is 512 bytes. Reads of an AHCI-backed disk are one
 * sector per ahci_read_sector call. This header does not call firmware.
 */
#ifndef CSMWRAP_BLOCK_H
#define CSMWRAP_BLOCK_H
#include <stdint.h>

#define CSMWRAP_SECTOR_BYTES 512u

enum csmwrap_blk_status {
    CSMWRAP_BLK_OK = 0,
    CSMWRAP_BLK_INVALID = -1,
    CSMWRAP_BLK_RANGE = -2,
    CSMWRAP_BLK_NO_DEVICE = -3,
    CSMWRAP_BLK_IO = -4,
    CSMWRAP_BLK_RO = -5,
    CSMWRAP_BLK_BOOT_SERVICES = -6
};

struct csmwrap_geometry {
    uint32_t cylinders;
    uint32_t heads;
    uint32_t sectors_per_track;
};

struct csmwrap_block_device {
    void *ctx;
    int (*reset)(struct csmwrap_block_device *dev);
    int (*read)(struct csmwrap_block_device *dev, uint64_t lba, void *dst,
                uint32_t sectors);
    int (*write)(struct csmwrap_block_device *dev, uint64_t lba, const void *src,
                 uint32_t sectors);
    int (*flush)(struct csmwrap_block_device *dev);
    int (*geometry)(struct csmwrap_block_device *dev,
                    struct csmwrap_geometry *out);
    uint32_t (*sector_size)(struct csmwrap_block_device *dev);
    uint64_t (*sector_count)(struct csmwrap_block_device *dev);
};

typedef struct csmwrap_block_device CSMWRAP_BLOCK_DEVICE;

/* floppy is non-zero only for a legacy 1.44 MiB image (2880 sectors). */
int csmwrap_derive_geometry(uint64_t sectors, int floppy,
                            struct csmwrap_geometry *out);
#endif
