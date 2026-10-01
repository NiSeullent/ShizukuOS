/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WIN98_ATA_PIO_H
#define SHZ_WIN98_ATA_PIO_H
#include <stdint.h>
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
} w98_ata_t;
/* The supplied disk belongs to this VM; there is no host file/device access here. */
int w98_ata_init(w98_ata_t *, uint8_t *disk, uint64_t bytes,
                 void (*raise_irq)(void *), void *opaque);
int w98_ata_in(w98_ata_t *, uint16_t port, unsigned bytes, uint32_t *value);
int w98_ata_out(w98_ata_t *, uint16_t port, unsigned bytes, uint32_t value);
#endif
