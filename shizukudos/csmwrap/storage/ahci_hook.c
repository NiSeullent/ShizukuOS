/* SPDX-License-Identifier: GPL-2.0-only
 * Read contract: ahci_read_sector transfers exactly AHCI_SECTOR_BYTES
 * (512) and rejects every other size. uefi_ahci checks the same
 * identity (sector_bytes == 512) after its own AHCI open, which runs
 * on the native driver rather than EFI_BLOCK_IO.
 */
#include "ahci_hook.h"

_Static_assert(AHCI_SECTOR_BYTES == CSMWRAP_SECTOR_BYTES,
               "CSM sector size must match the native AHCI contract");

static int ahci_ready(const struct csmwrap_ahci_hook *hook)
{
    if (!hook || !hook->bound || !hook->dev) return 0;
    if (hook->dev->state != AHCI_READY) return 0;
    if (hook->sector_bytes != AHCI_SECTOR_BYTES || hook->sectors == 0) return 0;
    return 1;
}

static int ahci_reset(CSMWRAP_BLOCK_DEVICE *dev)
{
    struct csmwrap_ahci_hook *hook = dev ? dev->ctx : 0;
    /* ahci_open already started the command engine. There is no separate
     * firmware reset, and this hook must not call back into boot services. */
    if (!ahci_ready(hook)) return CSMWRAP_BLK_NO_DEVICE;
    return CSMWRAP_BLK_OK;
}

static int ahci_read(CSMWRAP_BLOCK_DEVICE *dev, uint64_t lba, void *dst,
                     uint32_t sectors)
{
    struct csmwrap_ahci_hook *hook = dev ? dev->ctx : 0;
    uint32_t i;
    if (!dst || sectors == 0) return CSMWRAP_BLK_INVALID;
    if (!ahci_ready(hook)) return CSMWRAP_BLK_NO_DEVICE;
    if (lba >= hook->sectors || (uint64_t)sectors > hook->sectors - lba)
        return CSMWRAP_BLK_RANGE;
    for (i = 0; i < sectors; ++i) {
        int result = ahci_read_sector(hook->dev, lba + (uint64_t)i,
                                      (uint8_t *)dst + (size_t)i * AHCI_SECTOR_BYTES,
                                      AHCI_SECTOR_BYTES);
        if (result == AHCI_OK) continue;
        if (result == AHCI_INVALID) return CSMWRAP_BLK_INVALID;
        if (result == AHCI_NO_DEVICE) return CSMWRAP_BLK_NO_DEVICE;
        return CSMWRAP_BLK_IO;
    }
    return CSMWRAP_BLK_OK;
}

static int ahci_write(CSMWRAP_BLOCK_DEVICE *dev, uint64_t lba, const void *src,
                      uint32_t sectors)
{
    struct csmwrap_ahci_hook *hook = dev ? dev->ctx : 0;
    (void)lba;
    (void)src;
    (void)sectors;
    /* drivers/ahci_native exports ahci_read_sector only. A successful
     * write return here would be a stub. */
    if (!ahci_ready(hook)) return CSMWRAP_BLK_NO_DEVICE;
    return CSMWRAP_BLK_RO;
}

static int ahci_flush(CSMWRAP_BLOCK_DEVICE *dev)
{
    struct csmwrap_ahci_hook *hook = dev ? dev->ctx : 0;
    /* Each ahci_read_sector returns only after the command completes.
     * There is no write cache to push. */
    if (!ahci_ready(hook)) return CSMWRAP_BLK_NO_DEVICE;
    return CSMWRAP_BLK_OK;
}

static int ahci_geometry(CSMWRAP_BLOCK_DEVICE *dev, struct csmwrap_geometry *out)
{
    struct csmwrap_ahci_hook *hook = dev ? dev->ctx : 0;
    if (!ahci_ready(hook)) return CSMWRAP_BLK_NO_DEVICE;
    return csmwrap_derive_geometry(hook->sectors, 0, out);
}

static uint32_t ahci_sector_size(CSMWRAP_BLOCK_DEVICE *dev)
{
    struct csmwrap_ahci_hook *hook = dev ? dev->ctx : 0;
    return ahci_ready(hook) ? hook->sector_bytes : 0u;
}

static uint64_t ahci_sector_count(CSMWRAP_BLOCK_DEVICE *dev)
{
    struct csmwrap_ahci_hook *hook = dev ? dev->ctx : 0;
    return ahci_ready(hook) ? hook->sectors : 0u;
}

int csmwrap_ahci_hook_init(struct csmwrap_ahci_hook *hook, CSMWRAP_BLOCK_DEVICE *dev)
{
    if (!hook || !dev) return CSMWRAP_BLK_INVALID;
    hook->dev = 0;
    hook->sectors = 0;
    hook->sector_bytes = 0;
    hook->bound = 0;
    dev->ctx = hook;
    dev->reset = ahci_reset;
    dev->read = ahci_read;
    dev->write = ahci_write;
    dev->flush = ahci_flush;
    dev->geometry = ahci_geometry;
    dev->sector_size = ahci_sector_size;
    dev->sector_count = ahci_sector_count;
    return CSMWRAP_BLK_OK;
}

int csmwrap_ahci_hook_bind(struct csmwrap_ahci_hook *hook, struct ahci_device *opened)
{
    if (!hook) return CSMWRAP_BLK_INVALID;
    hook->dev = 0;
    hook->sectors = 0;
    hook->sector_bytes = 0;
    hook->bound = 0;
    if (!opened || opened->state != AHCI_READY) return CSMWRAP_BLK_NO_DEVICE;
    if (opened->identity.sector_bytes != AHCI_SECTOR_BYTES ||
        opened->identity.sectors == 0)
        return CSMWRAP_BLK_INVALID;
    hook->dev = opened;
    hook->sectors = opened->identity.sectors;
    hook->sector_bytes = opened->identity.sector_bytes;
    hook->bound = 1;
    return CSMWRAP_BLK_OK;
}
