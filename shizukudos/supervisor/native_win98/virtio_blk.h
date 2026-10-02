/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WIN98_VIRTIO_BLK_H
#define SHZ_WIN98_VIRTIO_BLK_H
#include "persistence_config.h"
#include "persistent_disk.h"
#include "../include/shz_info.h"
#define W98_VBLK_QUEUE 8u
typedef struct { uint64_t address; uint32_t length; uint16_t flags, next; } w98_vblk_desc_t;
typedef struct { uint16_t flags, index, ring[W98_VBLK_QUEUE], used_event; } w98_vblk_avail_t;
typedef struct { uint32_t id, length; } w98_vblk_used_elem_t;
typedef struct { uint16_t flags, index; w98_vblk_used_elem_t ring[W98_VBLK_QUEUE]; uint16_t avail_event; } w98_vblk_used_t;
typedef struct { uint32_t type, reserved; uint64_t sector; } w98_vblk_request_t;
/* Trusted Supervisor transport only. Host controls replace these operations;
 * native init supplies actual PCI/MMIO/TSC and bounded Supervisor DMA checks. */
typedef struct {
    void *opaque;
    int (*pci_read)(void *,uint16_t,unsigned,uint32_t *);
    int (*pci_write)(void *,uint16_t,unsigned,uint32_t);
    int (*mmio_read)(void *,uint64_t,unsigned,uint64_t *);
    int (*mmio_write)(void *,uint64_t,unsigned,uint64_t);
    int (*mmio_allowed)(void *,uint64_t,uint64_t);
    int (*dma_address)(void *,const void *,uint64_t,uint64_t *);
    uint64_t (*ticks)(void *);
    void (*pause)(void *);
    uint64_t ticks_per_second;
} w98_vblk_io_t;
typedef struct {
    w98_vblk_io_t io;
    w98_persist_config_t config;
    uint64_t common, notify, device_config, isr, notify_bytes, notify_multiplier;
    uint64_t notify_address, sectors, admission_deadline;
    uint32_t command_original, sealed_extents;
    uint16_t last_used;
    uint8_t owned, ready, failed, busy, sealed, reset_acknowledged;
    uint8_t registers_admitted, memory_decoded;
    w98_disk_extent_t extent[W98_PERSIST_MAX_EXTENTS];
    w98_vblk_desc_t desc[W98_VBLK_QUEUE] __attribute__((aligned(4096)));
    w98_vblk_avail_t avail __attribute__((aligned(4096)));
    w98_vblk_used_t used __attribute__((aligned(4096)));
    w98_vblk_request_t request __attribute__((aligned(4096)));
    uint8_t data[512], status;
} w98_vblk_t;
/* Caller starts with a zeroed, exclusively owned object and retains it through
 * successful reset acknowledgment. Never reuse/free an uncertain DMA object.
 * Zero/absent config causes no PCI/MMIO mutation. Model init is NOT approval. */
int w98_vblk_init(w98_vblk_t *,const w98_persist_config_t *,uint64_t,const w98_vblk_io_t *);
int w98_vblk_native_init(w98_vblk_t *,const w98_persist_config_t *,uint64_t,const shz_info_t *);
int w98_vblk_block(w98_vblk_t *,w98_owned_block_t *);
/* Raw write is denied until the admitted FAT map is sealed; then it accepts
 * only actual member extents. This does not grant guest raw-device access. */
int w98_vblk_seal_member(w98_vblk_t *,const w98_persist_disk_t *);
int w98_vblk_close(w98_vblk_t *);
#endif
