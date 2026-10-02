/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WIN98_PERSISTENCE_H
#define SHZ_WIN98_PERSISTENCE_H
#include "virtio_blk.h"
#include "ata_pio.h"
typedef struct {
    w98_vblk_t device;
    w98_persist_disk_t map;
    w98_disk_backend_t backend;
    w98_ata_t *ata;
    uint8_t attached, failed;
} w98_persistence_t;
/* Called on freshly initialized idle ATA, before guest launch. A missing blob
 * is the existing RAM baseline; an explicit malformed/failed opt-in aborts
 * admission. Caller owns the object/device throughout teardown/reset ACK. */
int w98_persistence_attach(w98_persistence_t *,w98_ata_t *,const w98_persist_config_t *,uint64_t,const w98_vblk_io_t *);
int w98_persistence_attach_native(w98_persistence_t *,w98_ata_t *,const w98_persist_config_t *,uint64_t,const shz_info_t *);
/* Guest must already be stopped. Flush, reset and ACK precede lifetime release;
 * failure reports no durability and forbids recycling uncertain DMA storage. */
int w98_persistence_finish(w98_persistence_t *);
#endif
