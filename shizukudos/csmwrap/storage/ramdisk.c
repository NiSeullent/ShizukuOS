/* SPDX-License-Identifier: GPL-2.0-only */
#include "ramdisk.h"
#include <string.h>

static int range_ok(const struct csmwrap_ramdisk *disk, uint64_t lba,
                    uint32_t sectors)
{
    if (!disk || !disk->storage || disk->sector_size != CSMWRAP_SECTOR_BYTES)
        return 0;
    if (sectors == 0 || lba >= disk->sectors) return 0;
    if ((uint64_t)sectors > disk->sectors - lba) return 0;
    return 1;
}

static int ram_reset(CSMWRAP_BLOCK_DEVICE *dev)
{
    struct csmwrap_ramdisk *disk = dev ? dev->ctx : 0;
    if (!disk || !disk->storage) return CSMWRAP_BLK_NO_DEVICE;
    disk->resets++;
    return CSMWRAP_BLK_OK;
}

static int ram_read(CSMWRAP_BLOCK_DEVICE *dev, uint64_t lba, void *dst,
                    uint32_t sectors)
{
    struct csmwrap_ramdisk *disk = dev ? dev->ctx : 0;
    size_t bytes;
    if (!dst) return CSMWRAP_BLK_INVALID;
    if (!range_ok(disk, lba, sectors)) {
        if (!disk || !disk->storage) return CSMWRAP_BLK_NO_DEVICE;
        if (sectors == 0) return CSMWRAP_BLK_INVALID;
        return CSMWRAP_BLK_RANGE;
    }
    bytes = (size_t)sectors * (size_t)disk->sector_size;
    memcpy(dst, disk->storage + (size_t)lba * disk->sector_size, bytes);
    return CSMWRAP_BLK_OK;
}

static int ram_write(CSMWRAP_BLOCK_DEVICE *dev, uint64_t lba, const void *src,
                     uint32_t sectors)
{
    struct csmwrap_ramdisk *disk = dev ? dev->ctx : 0;
    size_t bytes;
    if (!src) return CSMWRAP_BLK_INVALID;
    if (!range_ok(disk, lba, sectors)) {
        if (!disk || !disk->storage) return CSMWRAP_BLK_NO_DEVICE;
        if (sectors == 0) return CSMWRAP_BLK_INVALID;
        return CSMWRAP_BLK_RANGE;
    }
    bytes = (size_t)sectors * (size_t)disk->sector_size;
    memcpy(disk->storage + (size_t)lba * disk->sector_size, src, bytes);
    return CSMWRAP_BLK_OK;
}

static int ram_flush(CSMWRAP_BLOCK_DEVICE *dev)
{
    struct csmwrap_ramdisk *disk = dev ? dev->ctx : 0;
    if (!disk || !disk->storage) return CSMWRAP_BLK_NO_DEVICE;
    disk->flushes++;
    return CSMWRAP_BLK_OK;
}

static int ram_geometry(CSMWRAP_BLOCK_DEVICE *dev, struct csmwrap_geometry *out)
{
    struct csmwrap_ramdisk *disk = dev ? dev->ctx : 0;
    if (!disk || !disk->storage) return CSMWRAP_BLK_NO_DEVICE;
    return csmwrap_derive_geometry(disk->sectors, disk->legacy_floppy, out);
}

static uint32_t ram_sector_size(CSMWRAP_BLOCK_DEVICE *dev)
{
    struct csmwrap_ramdisk *disk = dev ? dev->ctx : 0;
    return disk ? disk->sector_size : 0u;
}

static uint64_t ram_sector_count(CSMWRAP_BLOCK_DEVICE *dev)
{
    struct csmwrap_ramdisk *disk = dev ? dev->ctx : 0;
    return disk ? disk->sectors : 0u;
}

int csmwrap_ramdisk_init(struct csmwrap_ramdisk *disk, CSMWRAP_BLOCK_DEVICE *dev,
                         uint8_t *storage, size_t bytes, uint32_t sector_size,
                         int legacy_floppy)
{
    if (!disk || !dev || !storage || sector_size != CSMWRAP_SECTOR_BYTES)
        return CSMWRAP_BLK_INVALID;
    if (bytes < sector_size || bytes % sector_size != 0) return CSMWRAP_BLK_INVALID;
    memset(disk, 0, sizeof *disk);
    disk->storage = storage;
    disk->bytes = bytes;
    disk->sectors = (uint64_t)(bytes / sector_size);
    disk->sector_size = sector_size;
    disk->legacy_floppy = legacy_floppy ? 1 : 0;
    memset(dev, 0, sizeof *dev);
    dev->ctx = disk;
    dev->reset = ram_reset;
    dev->read = ram_read;
    dev->write = ram_write;
    dev->flush = ram_flush;
    dev->geometry = ram_geometry;
    dev->sector_size = ram_sector_size;
    dev->sector_count = ram_sector_count;
    return CSMWRAP_BLK_OK;
}
