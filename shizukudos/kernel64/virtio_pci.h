/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 virtio-pci modern transport (Virtio 1.2, OASIS, section 4.1 "Virtio Over PCI Bus"), reusable by any virtio
 * device driver (virtio-gpu today: gfx_virtio.c; virtio-blk/net can use the same calls).
 *
 * What it does: finds the PCI function (vendor 0x1af4, modern device id 0x1040 + virtio device id, or the transitional
 * id), walks the PCI capability list for the vendor-specific virtio structures (common / notify / ISR / device
 * configuration), maps them uncached, drives the status protocol (reset, ACKNOWLEDGE, DRIVER, feature negotiation with
 * VIRTIO_F_VERSION_1, FEATURES_OK, DRIVER_OK), sets up split virtqueues (virtq.c) in physical pages, notifies queues
 * through the notification area and delivers interrupts. Interrupts are the legacy INTx line of the function routed
 * through the 8259 PIC of the SHZ_STANDALONE profile (the ISR status byte is read to deassert the line); MSI-X is not
 * enabled (the local APIC is not programmed in this profile), so the msix vector registers are left at NO_VECTOR.
 * Only the SHZ_STANDALONE profile touches hardware: under the Supervisor every call here fails (no device is passed
 * through and PCI port I/O traps), exactly like the other Kernel64 device drivers.
 * Not implemented: VIRTIO_F_RING_INDIRECT_DESC, VIRTIO_F_RING_EVENT_IDX, packed virtqueues, shared memory regions,
 * the legacy (pre-1.0) I/O port interface, MSI-X.
 */
#ifndef K64_VIRTIO_PCI_H
#define K64_VIRTIO_PCI_H
#include "pci.h"
#include "virtq.h"

#define VIRTIO_PCI_VENDOR 0x1af4u
#define VIRTIO_PCI_MODERN_ID(virtio_id) (0x1040u + (virtio_id))
#define VIRTIO_ID_NET 1u
#define VIRTIO_ID_BLOCK 2u
#define VIRTIO_ID_GPU 16u

/* capability cfg_type values */
#define VIRTIO_PCI_CAP_COMMON_CFG 1
#define VIRTIO_PCI_CAP_NOTIFY_CFG 2
#define VIRTIO_PCI_CAP_ISR_CFG 3
#define VIRTIO_PCI_CAP_DEVICE_CFG 4
#define VIRTIO_PCI_CAP_PCI_CFG 5

/* device status bits */
#define VIRTIO_STATUS_ACKNOWLEDGE 1u
#define VIRTIO_STATUS_DRIVER 2u
#define VIRTIO_STATUS_DRIVER_OK 4u
#define VIRTIO_STATUS_FEATURES_OK 8u
#define VIRTIO_STATUS_DEVICE_NEEDS_RESET 64u
#define VIRTIO_STATUS_FAILED 128u

/* reserved (transport) feature bits */
#define VIRTIO_F_RING_INDIRECT_DESC (1ull << 28)
#define VIRTIO_F_RING_EVENT_IDX (1ull << 29)
#define VIRTIO_F_VERSION_1 (1ull << 32)
#define VIRTIO_F_ACCESS_PLATFORM (1ull << 33)
#define VIRTIO_F_RING_PACKED (1ull << 34)

#define VIRTIO_MSI_NO_VECTOR 0xffffu
#define VIRTIO_PCI_MAX_QUEUES 8
#define VIRTIO_PCI_QUEUE_CAP 256u           /* rings are capped so that each part fits one 4 KiB page */

typedef struct virtio_dev virtio_dev_t;
struct virtio_dev {
    pci_dev_t pci;
    volatile uint8_t *common;               /* common configuration structure (spec 4.1.4.3) */
    volatile uint8_t *notify;               /* notification structure base */
    uint32_t notify_off_multiplier;
    uint32_t notify_len;
    volatile uint8_t *isr;                  /* ISR status byte: reading it clears it and deasserts INTx */
    volatile uint8_t *device;               /* device-specific configuration */
    uint32_t device_len;
    uint64_t device_features;               /* offered */
    uint64_t driver_features;               /* accepted (after virtio_pci_negotiate) */
    uint16_t num_queues;
    virtq_t *queues[VIRTIO_PCI_MAX_QUEUES];
    unsigned irq_line, irq_vector;
    void (*irq_cb)(void *arg, uint8_t isr_status);
    void *irq_arg;
    uint32_t stat_irqs, stat_irqs_queue, stat_irqs_config, stat_irqs_spurious, stat_notifies;
};

/* Finds and maps the first function of the given virtio device id. 0 = found (d filled), -1 = absent or unusable. */
int virtio_pci_find(uint32_t virtio_id, virtio_dev_t *d);
/* Reset, ACKNOWLEDGE|DRIVER, read the 64 device feature bits, accept `wanted & offered` plus VIRTIO_F_VERSION_1 (which
 * must be offered), write FEATURES_OK and verify. 0 = ok (d->driver_features set), -1 = the device refused. */
int virtio_pci_negotiate(virtio_dev_t *d, uint64_t wanted);
/* Allocates a split virtqueue of min(device size, max_size, VIRTIO_PCI_QUEUE_CAP) entries in physical pages, programs
 * and enables it. NULL when the queue does not exist or memory is exhausted. Call between negotiate and driver_ok. */
virtq_t *virtio_pci_queue_setup(virtio_dev_t *d, unsigned index, unsigned max_size);
void virtio_pci_driver_ok(virtio_dev_t *d);
/* Writes device_status = 0: the device stops using every ring and buffer it was given (the queues' memory is not freed). */
void virtio_pci_reset(virtio_dev_t *d);
/* Writes the queue index to its notification address; call when virtq_kick_prepare() returned 1. */
void virtio_pci_notify(virtio_dev_t *d, const virtq_t *q);
/* Legacy INTx through the PIC: `cb` runs in interrupt context (interrupts off; no sleeping, no mutexes) with the ISR
 * status bits (bit 0 queue, bit 1 configuration change) after the line has been deasserted. Returns -1 (the caller must
 * poll the used ring instead) when the function has no usable line or the line's vector already belongs to a non-virtio
 * driver: vectors carry a single handler, so taking a shared line would silence the other device. */
int virtio_pci_irq_enable(virtio_dev_t *d, void (*cb)(void *arg, uint8_t isr_status), void *arg);
uint8_t virtio_pci_status(const virtio_dev_t *d);
uint32_t virtio_pci_cfg_read32(const virtio_dev_t *d, unsigned off);
void virtio_pci_cfg_write32(virtio_dev_t *d, unsigned off, uint32_t v);
#endif
