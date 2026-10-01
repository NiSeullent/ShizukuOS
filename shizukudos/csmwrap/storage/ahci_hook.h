/* SPDX-License-Identifier: GPL-2.0-only
 * AHCI backend, kept apart from the RAM disk. Forwards reads through
 * ahci_read_sector() in drivers/ahci_native. That driver has no write
 * entry, so writes stay read-only. No EFI Block I/O calls.
 */
#ifndef CSMWRAP_AHCI_HOOK_H
#define CSMWRAP_AHCI_HOOK_H
#include "block.h"
#include "../../../drivers/ahci_native/ahci.h"

struct csmwrap_ahci_hook {
    struct ahci_device *dev; /* not owned; NULL until a live device is bound */
    uint64_t sectors;        /* copied at bind time */
    uint32_t sector_bytes;   /* copied at bind time */
    int bound;
};

int csmwrap_ahci_hook_init(struct csmwrap_ahci_hook *hook, CSMWRAP_BLOCK_DEVICE *dev);

/* Requires an already opened device (AHCI_READY) whose IDENTIFY snapshot
 * reports 512-byte sectors. Does not call ahci_open and does not touch PCI. */
int csmwrap_ahci_hook_bind(struct csmwrap_ahci_hook *hook, struct ahci_device *opened);
#endif
