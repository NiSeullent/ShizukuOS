/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 virtio-pci modern transport, see virtio_pci.h. */
#include "virtio_pci.h"

#ifndef SHZ_STANDALONE
/* Supervisor profile: no device is passed through and PCI port I/O traps, so the transport is inert. */
int virtio_pci_find(uint32_t virtio_id, virtio_dev_t *d) { (void)virtio_id; (void)d; return -1; }
int virtio_pci_negotiate(virtio_dev_t *d, uint64_t wanted) { (void)d; (void)wanted; return -1; }
virtq_t *virtio_pci_queue_setup(virtio_dev_t *d, unsigned index, unsigned max_size) { (void)d; (void)index; (void)max_size; return 0; }
void virtio_pci_driver_ok(virtio_dev_t *d) { (void)d; }
void virtio_pci_notify(virtio_dev_t *d, const virtq_t *q) { (void)d; (void)q; }
int virtio_pci_irq_enable(virtio_dev_t *d, void (*cb)(void *, uint8_t), void *arg) { (void)d; (void)cb; (void)arg; return -1; }
uint8_t virtio_pci_status(const virtio_dev_t *d) { (void)d; return 0; }
uint32_t virtio_pci_cfg_read32(const virtio_dev_t *d, unsigned off) { (void)d; (void)off; return 0; }
void virtio_pci_cfg_write32(virtio_dev_t *d, unsigned off, uint32_t v) { (void)d; (void)off; (void)v; }
#else

/* common configuration structure offsets (spec 4.1.4.3) */
enum {
    C_DEVICE_FEATURE_SELECT = 0, C_DEVICE_FEATURE = 4, C_DRIVER_FEATURE_SELECT = 8, C_DRIVER_FEATURE = 12,
    C_CONFIG_MSIX_VECTOR = 16, C_NUM_QUEUES = 18, C_DEVICE_STATUS = 20, C_CONFIG_GENERATION = 21,
    C_QUEUE_SELECT = 22, C_QUEUE_SIZE = 24, C_QUEUE_MSIX_VECTOR = 26, C_QUEUE_ENABLE = 28, C_QUEUE_NOTIFY_OFF = 30,
    C_QUEUE_DESC = 32, C_QUEUE_DRIVER = 40, C_QUEUE_DEVICE = 48
};

static inline uint8_t rd8(volatile uint8_t *b, unsigned off) { return *(volatile uint8_t *)(b + off); }
static inline uint16_t rd16(volatile uint8_t *b, unsigned off) { return *(volatile uint16_t *)(b + off); }
static inline uint32_t rd32(volatile uint8_t *b, unsigned off) { return *(volatile uint32_t *)(b + off); }
static inline void wr8(volatile uint8_t *b, unsigned off, uint8_t v) { *(volatile uint8_t *)(b + off) = v; }
static inline void wr16(volatile uint8_t *b, unsigned off, uint16_t v) { *(volatile uint16_t *)(b + off) = v; }
static inline void wr32(volatile uint8_t *b, unsigned off, uint32_t v) { *(volatile uint32_t *)(b + off) = v; }
static inline void wr64(volatile uint8_t *b, unsigned off, uint64_t v) { wr32(b, off, (uint32_t)v); wr32(b, off + 4, (uint32_t)(v >> 32)); }

static uint8_t cfg8(const pci_dev_t *d, unsigned off) { return (uint8_t)(pci_cfg_read32(d, off & ~3u) >> (8 * (off & 3))); }
static uint16_t cfg16(const pci_dev_t *d, unsigned off) { return (uint16_t)(pci_cfg_read32(d, off & ~3u) >> (8 * (off & 2))); }

/* Maps the region a virtio capability describes: BAR `bar` + offset, `length` bytes. NULL when the BAR is not a memory BAR. */
static volatile uint8_t *map_cap(const pci_dev_t *d, unsigned bar, uint32_t offset, uint32_t length)
{
    uint64_t size = 0, base;
    int is_io = 0;
    if (bar > 5 || !length) return 0;
    base = pci_bar(d, bar, &size, &is_io);
    if (!base || is_io || (uint64_t)offset + length > size) return 0;
    return (volatile uint8_t *)mmio_map(base + offset, length);
}

int virtio_pci_find(uint32_t virtio_id, virtio_dev_t *d)
{
    pci_dev_t all[32];
    const unsigned n = pci_enumerate(all, 32);
    unsigned i, guard, cap;
    int found = -1;
    memset(d, 0, sizeof *d);
    for (i = 0; i < n && found < 0; ++i) {
        if (all[i].vendor != VIRTIO_PCI_VENDOR) continue;
        if (all[i].device == VIRTIO_PCI_MODERN_ID(virtio_id)) found = (int)i;
        else if (all[i].device >= 0x1000 && all[i].device < 0x1040 && virtio_id < 0x40 &&
                 pci_cfg_read32(&all[i], 0x2c) >> 16 == virtio_id)         /* transitional id: subsystem device id = virtio id */
            found = (int)i;
    }
    if (found < 0) return -1;
    d->pci = all[found];
    if (!(cfg16(&d->pci, 6) & 0x10)) {                                    /* status.capabilities list */
        kprintf("K64 virtio: %x:%x has no capability list\n", d->pci.vendor, d->pci.device);
        return -1;
    }
    cap = cfg8(&d->pci, 0x34);
    for (guard = 0; cap >= 0x40 && cap < 0xfc && guard < 48; ++guard) {
        const uint8_t id = cfg8(&d->pci, cap), next = cfg8(&d->pci, cap + 1);
        if (id == 0x09) {                                                 /* vendor-specific: virtio structure */
            const uint8_t len = cfg8(&d->pci, cap + 2), type = cfg8(&d->pci, cap + 3), bar = cfg8(&d->pci, cap + 4);
            const uint32_t off = pci_cfg_read32(&d->pci, cap + 8), length = pci_cfg_read32(&d->pci, cap + 12);
            if (len >= 16) {
                switch (type) {
                case VIRTIO_PCI_CAP_COMMON_CFG:
                    if (!d->common && length >= 56) d->common = map_cap(&d->pci, bar, off, length);
                    break;
                case VIRTIO_PCI_CAP_NOTIFY_CFG:
                    if (!d->notify && len >= 20) {
                        d->notify = map_cap(&d->pci, bar, off, length);
                        d->notify_off_multiplier = pci_cfg_read32(&d->pci, cap + 16);
                        d->notify_len = length;
                    }
                    break;
                case VIRTIO_PCI_CAP_ISR_CFG:
                    if (!d->isr) d->isr = map_cap(&d->pci, bar, off, length);
                    break;
                case VIRTIO_PCI_CAP_DEVICE_CFG:
                    if (!d->device) { d->device = map_cap(&d->pci, bar, off, length); d->device_len = length; }
                    break;
                default: break;                                           /* PCI_CFG alternative access and shared memory: unused */
                }
            }
        }
        cap = next;
    }
    if (!d->common || !d->notify || !d->isr) {
        kprintf("K64 virtio: %x:%x lacks modern capabilities (common %p notify %p isr %p)\n", d->pci.vendor, d->pci.device,
                (void *)d->common, (void *)d->notify, (void *)d->isr);
        return -1;
    }
    d->irq_line = d->pci.irq_line;
    pci_enable(&d->pci, 0, 1, 1);                                         /* memory space + bus mastering (the rings are DMA) */
    return 0;
}

uint8_t virtio_pci_status(const virtio_dev_t *d) { return rd8(d->common, C_DEVICE_STATUS); }

static void set_status(virtio_dev_t *d, uint8_t bits) { wr8(d->common, C_DEVICE_STATUS, (uint8_t)(rd8(d->common, C_DEVICE_STATUS) | bits)); }

int virtio_pci_negotiate(virtio_dev_t *d, uint64_t wanted)
{
    uint64_t accept;
    unsigned spin;
    wr8(d->common, C_DEVICE_STATUS, 0);                                   /* reset */
    for (spin = 0; spin < 1000000 && rd8(d->common, C_DEVICE_STATUS) != 0; ++spin)
        ;
    if (rd8(d->common, C_DEVICE_STATUS) != 0) {
        kprintf("K64 virtio: reset did not complete\n");
        return -1;
    }
    set_status(d, VIRTIO_STATUS_ACKNOWLEDGE);
    set_status(d, VIRTIO_STATUS_DRIVER);
    wr32(d->common, C_DEVICE_FEATURE_SELECT, 0);
    d->device_features = rd32(d->common, C_DEVICE_FEATURE);
    wr32(d->common, C_DEVICE_FEATURE_SELECT, 1);
    d->device_features |= (uint64_t)rd32(d->common, C_DEVICE_FEATURE) << 32;
    if (!(d->device_features & VIRTIO_F_VERSION_1)) {
        kprintf("K64 virtio: device does not offer VIRTIO_F_VERSION_1 (features %llx)\n", d->device_features);
        set_status(d, VIRTIO_STATUS_FAILED);
        return -1;
    }
    accept = (wanted & d->device_features & ~(VIRTIO_F_RING_INDIRECT_DESC | VIRTIO_F_RING_EVENT_IDX | VIRTIO_F_RING_PACKED)) |
             VIRTIO_F_VERSION_1;
    wr32(d->common, C_DRIVER_FEATURE_SELECT, 0);
    wr32(d->common, C_DRIVER_FEATURE, (uint32_t)accept);
    wr32(d->common, C_DRIVER_FEATURE_SELECT, 1);
    wr32(d->common, C_DRIVER_FEATURE, (uint32_t)(accept >> 32));
    set_status(d, VIRTIO_STATUS_FEATURES_OK);
    if (!(rd8(d->common, C_DEVICE_STATUS) & VIRTIO_STATUS_FEATURES_OK)) {
        kprintf("K64 virtio: device rejected features %llx (offered %llx)\n", accept, d->device_features);
        set_status(d, VIRTIO_STATUS_FAILED);
        return -1;
    }
    d->driver_features = accept;
    d->num_queues = rd16(d->common, C_NUM_QUEUES);
    wr16(d->common, C_CONFIG_MSIX_VECTOR, VIRTIO_MSI_NO_VECTOR);
    return 0;
}

virtq_t *virtio_pci_queue_setup(virtio_dev_t *d, unsigned index, unsigned max_size)
{
    uint16_t size;
    uint64_t pa_desc, pa_avail, pa_used;
    virtq_t *q;
    void **cookies;
    uint16_t *chain;
    if (index >= d->num_queues || index >= VIRTIO_PCI_MAX_QUEUES || d->queues[index]) return 0;
    wr16(d->common, C_QUEUE_SELECT, (uint16_t)index);
    size = rd16(d->common, C_QUEUE_SIZE);
    if (!size) return 0;
    if (size > VIRTIO_PCI_QUEUE_CAP) size = VIRTIO_PCI_QUEUE_CAP;
    while (size > max_size && size > 1) size >>= 1;                       /* stay a power of two below the caller's cap */
    q = kzalloc(sizeof *q);
    cookies = kzalloc(sizeof(void *) * size);
    chain = kzalloc(sizeof(uint16_t) * size);
    pa_desc = pmm_alloc();
    pa_avail = pmm_alloc();
    pa_used = pmm_alloc();
    if (!q || !cookies || !chain || !pa_desc || !pa_avail || !pa_used) {
        kprintf("K64 virtio: queue %u: out of memory\n", index);
        if (pa_desc) pmm_free(pa_desc);
        if (pa_avail) pmm_free(pa_avail);
        if (pa_used) pmm_free(pa_used);
        kfree(q); kfree(cookies); kfree(chain);
        return 0;
    }
    KASSERT(virtq_desc_bytes(size) <= PAGE_SIZE && virtq_avail_bytes(size) <= PAGE_SIZE && virtq_used_bytes(size) <= PAGE_SIZE);
    if (virtq_init(q, (uint16_t)index, size, (void *)p2v(pa_desc), pa_desc, (void *)p2v(pa_avail), pa_avail, (void *)p2v(pa_used),
                   pa_used, cookies, chain)) {
        kfree(q); kfree(cookies); kfree(chain);
        return 0;
    }
    wr16(d->common, C_QUEUE_SIZE, size);
    wr16(d->common, C_QUEUE_MSIX_VECTOR, VIRTIO_MSI_NO_VECTOR);
    wr64(d->common, C_QUEUE_DESC, pa_desc);
    wr64(d->common, C_QUEUE_DRIVER, pa_avail);
    wr64(d->common, C_QUEUE_DEVICE, pa_used);
    wr16(d->common, C_QUEUE_ENABLE, 1);
    d->queues[index] = q;
    return q;
}

void virtio_pci_driver_ok(virtio_dev_t *d) { set_status(d, VIRTIO_STATUS_DRIVER_OK); }

void virtio_pci_notify(virtio_dev_t *d, const virtq_t *q)
{
    uint32_t off;
    wr16(d->common, C_QUEUE_SELECT, q->index);
    off = (uint32_t)rd16(d->common, C_QUEUE_NOTIFY_OFF) * d->notify_off_multiplier;
    if (off + 2 > d->notify_len) return;
    ++d->stat_notifies;
    wr16(d->notify, off, q->index);
}

static virtio_dev_t *irq_devs[4];

static void virtio_isr(struct regs *r)
{
    unsigned i;
    (void)r;
    for (i = 0; i < 4; ++i) {
        virtio_dev_t *d = irq_devs[i];
        uint8_t st;
        if (!d) continue;
        st = *d->isr;                                                     /* read-to-clear; deasserts INTx */
        if (!st) { ++d->stat_irqs_spurious; continue; }
        ++d->stat_irqs;
        if (st & 1) ++d->stat_irqs_queue;
        if (st & 2) ++d->stat_irqs_config;
        if (d->irq_cb) d->irq_cb(d->irq_arg, st);
    }
}

int virtio_pci_irq_enable(virtio_dev_t *d, void (*cb)(void *, uint8_t), void *arg)
{
    unsigned i;
    if (!d->irq_line || d->irq_line > 15) {
        kprintf("K64 virtio: no usable interrupt line (%u)\n", d->irq_line);
        return -1;
    }
    for (i = 0; i < 4 && irq_devs[i] && irq_devs[i] != d; ++i)
        ;
    if (i == 4) return -1;
    d->irq_cb = cb;
    d->irq_arg = arg;
    irq_devs[i] = d;
    d->irq_vector = standalone_irq_vector(d->irq_line);
    irq_register(d->irq_vector, virtio_isr);                              /* several virtio functions may share the line */
    standalone_irq_unmask(d->irq_line);
    return 0;
}

uint32_t virtio_pci_cfg_read32(const virtio_dev_t *d, unsigned off)
{
    return d->device && off + 4 <= d->device_len ? rd32(d->device, off) : 0;
}

void virtio_pci_cfg_write32(virtio_dev_t *d, unsigned off, uint32_t v)
{
    if (d->device && off + 4 <= d->device_len) wr32(d->device, off, v);
}
#endif
