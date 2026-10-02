/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WIN98_ATA_PIO_H
#define SHZ_WIN98_ATA_PIO_H
#include <stdint.h>
#include "disk_backend.h"
#define W98_ATA_SECTOR 512u
typedef struct {
    uint8_t *disk;
    uint64_t bytes;
    uint32_t sectors, lba;
    uint16_t remaining, word;
    uint8_t features, count, lba0, lba1, lba2, device, control;
    uint8_t status, error, command, writing, identify, irq;
    uint8_t buffer[W98_ATA_SECTOR];
    void (*raise_irq)(void *opaque);
    void *opaque;
    uint64_t sectors_read, sectors_written, rejected_commands;
    w98_disk_backend_t backend;
    uint8_t backend_attached, backend_failed;
    uint64_t backend_errors;
} w98_ata_t;
/* The supplied disk belongs to this VM; there is no host file/device access here. */
int w98_ata_init(w98_ata_t *, uint8_t *disk, uint64_t bytes,
                 void (*raise_irq)(void *), void *opaque);
/* Explicit Supervisor opt-in only, on an idle freshly initialized ATA device.
 * The caller has admitted the exact owned backing member and keeps its backend
 * alive/exclusive. Each completed write is followed by its real flush barrier
 * before RAM/task-file success. Uncertain failures stay latched across guest
 * SRST; only a new owned initialization/re-admission may clear that failure. */
int w98_ata_attach_backend(w98_ata_t *, uint32_t optin, const w98_disk_backend_t *);
int w98_ata_in(w98_ata_t *, uint16_t port, unsigned bytes, uint32_t *value);
int w98_ata_out(w98_ata_t *, uint16_t port, unsigned bytes, uint32_t value);
#endif
