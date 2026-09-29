/* SPDX-License-Identifier: GPL-2.0-only
 * Original NTWrapper9x PCI/PCIe contracts; no imported implementation code.
 */
#ifndef NTW_PCIE_H
#define NTW_PCIE_H

#include <stddef.h>
#include <stdint.h>

enum ntw_pci_status {
    NTW_PCI_OK = 0,
    NTW_PCI_NOT_FOUND = 1,
    NTW_PCI_STOPPED = 2,
    NTW_PCI_ARGUMENT = -1,
    NTW_PCI_IO = -2,
    NTW_PCI_MALFORMED = -3,
    NTW_PCI_CAPACITY = -4,
    NTW_PCI_UNSUPPORTED = -5,
    NTW_PCI_RANGE = -6,
    NTW_PCI_CYCLE = -7
};

struct ntw_pci_address {
    uint16_t segment;
    uint8_t bus, device, function;
};

/* Return OK only on a completed read, IO on transport faults. Vendor 0xffff
 * with OK represents an absent function. Values are host-endian, zero-extended.
 * The owner serializes access and keeps the topology stable during a scan. */
typedef int (*ntw_pci_read_fn)(void *context, struct ntw_pci_address address,
                             uint16_t offset, uint8_t width, uint32_t *value);
struct ntw_pci_transport {
    ntw_pci_read_fn read;
    void *context;
    uint16_t config_bytes; /* exactly 256 (legacy) or 4096 (ECAM) */
};

int ntw_pci_read(const struct ntw_pci_transport *transport,
                 struct ntw_pci_address address, uint16_t offset,
                 uint8_t width, uint32_t *value);

struct ntw_pci_ecam_window {
    uint64_t base; /* MCFG bus-zero-relative base, never start-bus-relative */
    uint16_t segment;
    uint8_t first_bus, last_bus;
};

#define NTW_PCI_MAX_MCFG_WINDOWS 256u
/* Validate the entire table before writing windows. On failure count is zero
 * and windows remain unchanged. A NULL windows / zero capacity is a query. */
int ntw_pci_parse_mcfg(const void *table, size_t bytes,
                       struct ntw_pci_ecam_window *windows, size_t capacity,
                       size_t *count);
int ntw_pci_ecam_address(const struct ntw_pci_ecam_window *window,
                         struct ntw_pci_address address, uint16_t offset,
                         uint8_t width, uint64_t *physical);

enum ntw_pci_device_kind {
    NTW_PCI_OTHER, NTW_PCI_AHCI, NTW_PCI_XHCI, NTW_PCI_NVME,
    NTW_PCI_DISPLAY, NTW_PCI_BRIDGE
};
enum ntw_pci_device_kind ntw_pci_classify(uint8_t base_class,
                                         uint8_t subclass, uint8_t interface);
struct ntw_pci_device {
    struct ntw_pci_address address;
    uint16_t vendor_id, device_id;
    uint8_t revision, interface, subclass, base_class, header_type;
    enum ntw_pci_device_kind kind;
};
typedef int (*ntw_pci_visit_fn)(void *context,
                              const struct ntw_pci_device *device);
struct ntw_pci_scan_limits {
    uint16_t segment;
    uint8_t root_bus, last_bus;
    uint16_t max_buses; /* 1..256 */
    uint32_t max_functions; /* 1..65536 present functions */
};
struct ntw_pci_scan_result {
    uint16_t buses;
    uint32_t functions;
};
/* Follow firmware-assigned type-1 PCI bridges. No writes, bus assignment,
 * CardBus, ARI or hotplug. Visitor returns 0 to continue, nonzero to stop.
 * On error/result STOPPED counters and visitor calls describe partial work. */
int ntw_pci_scan(const struct ntw_pci_transport *transport,
                  const struct ntw_pci_scan_limits *limits,
                  ntw_pci_visit_fn visit, void *context,
                  struct ntw_pci_scan_result *result);

struct ntw_pci_capability {
    uint16_t id, offset;
    uint8_t version; /* zero for conventional capabilities */
};
/* extended is 0 or 1. Traverses the entire list even when capacity is short,
 * so a malformed/cyclic tail cannot become a successful prefix. On errors,
 * count/buffer describe a partial traversal and must not be used for binding.
 * NULL capabilities / zero capacity queries the validated capability count. */
int ntw_pci_capabilities(const struct ntw_pci_transport *transport,
                          struct ntw_pci_address address, int extended,
                          struct ntw_pci_capability *capabilities,
                          size_t capacity, size_t *count);

enum ntw_pci_bar_kind { NTW_PCI_BAR_IO, NTW_PCI_BAR_MEMORY };
struct ntw_pci_bar {
    uint64_t base;
    enum ntw_pci_bar_kind kind;
    uint8_t address_bits, prefetchable, slots, assigned;
};
/* Decode a configuration snapshot with 2 bridge or 6 endpoint BAR slots.
 * Reject upper halves and reserved encodings. Zero base means unassigned,
 * not absent: BAR size/presence cannot be inferred from a read-only snapshot. */
int ntw_pci_decode_bar(const uint32_t *bars, size_t slots, size_t index,
                        struct ntw_pci_bar *bar);
struct ntw_pci_resource {
    uint64_t first, last;
    enum ntw_pci_bar_kind kind;
    uint8_t prefetchable;
};
/* size must come from a trusted resource owner, never from the BAR base.
 * Check bus-relative window and address-width limits; performs no mapping. */
int ntw_pci_bar_resource(const struct ntw_pci_bar *bar, uint64_t size,
                          uint8_t host_address_bits, uint64_t window_first,
                          uint64_t window_last, struct ntw_pci_resource *resource);

struct ntw_pci_dma_constraints {
    uint64_t address_mask; /* contiguous low bits: e.g. 0xffffffff for 32-bit */
    uint64_t alignment; /* power of two, at least 1 */
    uint64_t boundary; /* zero or power of two; a segment may not cross it */
    uint64_t max_segment; /* nonzero */
};
/* Return the longest initial segment within every constraint. Device address
 * is already translated by a real DMA owner. This does not allocate, pin,
 * map, bounce, flush caches, enable mastering or authorize a DMA operation. */
int ntw_pci_dma_segment(const struct ntw_pci_dma_constraints *constraints,
                         uint64_t device_address, uint64_t remaining,
                         uint64_t *segment_bytes);

#endif
