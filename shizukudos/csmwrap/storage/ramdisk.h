/* SPDX-License-Identifier: GPL-2.0-only
 * Host/test RAM disk. Callers own the byte buffer. Writes stay in that
 * buffer across reset; flush counts a commit of data already stored.
 */
#ifndef CSMWRAP_RAMDISK_H
#define CSMWRAP_RAMDISK_H
#include <stddef.h>
#include <stdint.h>
#include "block.h"

struct csmwrap_ramdisk {
    uint8_t *storage;
    size_t bytes;
    uint64_t sectors;
    uint32_t sector_size;
    uint32_t resets;
    uint32_t flushes;
    int legacy_floppy;
};

int csmwrap_ramdisk_init(struct csmwrap_ramdisk *disk, CSMWRAP_BLOCK_DEVICE *dev,
                         uint8_t *storage, size_t bytes, uint32_t sector_size,
                         int legacy_floppy);
#endif
