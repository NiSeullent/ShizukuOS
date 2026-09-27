/* SPDX-License-Identifier: GPL-2.0-only
 * Original implementation for Windows 98 Shizuku's Second Edition.
 * Public interface/format references and provenance: ../README.md.
 */
#include "ntw_pcie.h"

static uint16_t le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t le64(const uint8_t *p)
{
    return (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32);
}

static int power_of_two(uint64_t n)
{
    return n != 0 && (n & (n - 1)) == 0;
}

static uint64_t width_mask(uint8_t bits)
{
    return bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
}

static int access_valid(struct ntw_pci_address address, uint16_t offset,
                        uint8_t width, uint16_t config_bytes)
{
    return address.device < 32 && address.function < 8 &&
           (width == 1 || width == 2 || width == 4) &&
           offset % width == 0 && offset < config_bytes &&
           width <= config_bytes - offset;
}

int ntw_pci_read(const struct ntw_pci_transport *transport,
                 struct ntw_pci_address address, uint16_t offset,
                 uint8_t width, uint32_t *value)
{
    uint32_t temporary = 0;
    int status;
    if (transport == NULL || transport->read == NULL || value == NULL ||
        (transport->config_bytes != 256 && transport->config_bytes != 4096) ||
        !access_valid(address, offset, width, transport->config_bytes))
        return NTW_PCI_ARGUMENT;
    status = transport->read(transport->context, address, offset, width,
                             &temporary);
    if (status != NTW_PCI_OK)
        return NTW_PCI_IO;
    if (width != 4)
        temporary &= (UINT32_C(1) << (width * 8)) - 1;
    *value = temporary;
    return NTW_PCI_OK;
}

static struct ntw_pci_ecam_window mcfg_entry(const uint8_t *entry)
{
    struct ntw_pci_ecam_window window;
    window.base = le64(entry);
    window.segment = le16(entry + 8);
    window.first_bus = entry[10];
    window.last_bus = entry[11];
    return window;
}

static int ecam_bounds(const struct ntw_pci_ecam_window *window,
                        uint64_t *first, uint64_t *last)
{
    uint64_t end_offset = ((uint64_t)window->last_bus + 1) * UINT64_C(0x100000) - 1;
    if (window->first_bus > window->last_bus ||
        (window->base & UINT64_C(0xfffff)) != 0 ||
        window->base > UINT64_MAX - end_offset)
        return NTW_PCI_MALFORMED;
    *first = window->base + ((uint64_t)window->first_bus << 20);
    *last = window->base + end_offset;
    return NTW_PCI_OK;
}

int ntw_pci_parse_mcfg(const void *table, size_t bytes,
                       struct ntw_pci_ecam_window *windows, size_t capacity,
                       size_t *count)
{
    const uint8_t *p = (const uint8_t *)table;
    uint32_t length;
    size_t entries, i, j;
    uint8_t checksum = 0;
    if (count == NULL)
        return NTW_PCI_ARGUMENT;
    *count = 0;
    if (p == NULL || (windows == NULL && capacity != 0))
        return NTW_PCI_ARGUMENT;
    if (bytes < 44 || p[0] != 'M' || p[1] != 'C' || p[2] != 'F' || p[3] != 'G')
        return NTW_PCI_MALFORMED;
    length = le32(p + 4);
    if (length < 60 || length > bytes || (length - 44) % 16 != 0)
        return NTW_PCI_MALFORMED;
    entries = (length - 44) / 16;
    if (entries > NTW_PCI_MAX_MCFG_WINDOWS)
        return NTW_PCI_CAPACITY;
    if (p[8] != 1)
        return NTW_PCI_UNSUPPORTED;
    for (i = 0; i < length; ++i)
        checksum = (uint8_t)(checksum + p[i]);
    if (checksum != 0)
        return NTW_PCI_MALFORMED;
    for (i = 36; i < 44; ++i)
        if (p[i] != 0)
            return NTW_PCI_MALFORMED;
    for (i = 0; i < entries; ++i) {
        const uint8_t *entry = p + 44 + i * 16;
        struct ntw_pci_ecam_window current = mcfg_entry(entry);
        uint64_t first, last;
        if (le32(entry + 12) != 0 ||
            ecam_bounds(&current, &first, &last) != NTW_PCI_OK)
            return NTW_PCI_MALFORMED;
        for (j = 0; j < i; ++j) {
            struct ntw_pci_ecam_window prior = mcfg_entry(p + 44 + j * 16);
            uint64_t prior_first, prior_last;
            if (ecam_bounds(&prior, &prior_first, &prior_last) != NTW_PCI_OK)
                return NTW_PCI_MALFORMED;
            if ((current.segment == prior.segment &&
                 current.first_bus <= prior.last_bus &&
                 prior.first_bus <= current.last_bus) ||
                (first <= prior_last && prior_first <= last))
                return NTW_PCI_MALFORMED;
        }
    }
    if (windows != NULL && capacity < entries)
        return NTW_PCI_CAPACITY;
    if (windows != NULL)
        for (i = 0; i < entries; ++i)
            windows[i] = mcfg_entry(p + 44 + i * 16);
    *count = entries;
    return NTW_PCI_OK;
}

int ntw_pci_ecam_address(const struct ntw_pci_ecam_window *window,
                         struct ntw_pci_address address, uint16_t offset,
                         uint8_t width, uint64_t *physical)
{
    uint64_t first, last;
    if (window == NULL || physical == NULL ||
        !access_valid(address, offset, width, 4096))
        return NTW_PCI_ARGUMENT;
    if (ecam_bounds(window, &first, &last) != NTW_PCI_OK)
        return NTW_PCI_MALFORMED;
    if (address.segment != window->segment || address.bus < window->first_bus ||
        address.bus > window->last_bus)
        return NTW_PCI_RANGE;
    *physical = window->base + ((uint64_t)address.bus << 20) +
                ((uint64_t)address.device << 15) +
                ((uint64_t)address.function << 12) + offset;
    return NTW_PCI_OK;
}

enum ntw_pci_device_kind ntw_pci_classify(uint8_t base_class,
                                         uint8_t subclass, uint8_t interface)
{
    if (base_class == 1 && subclass == 6 && interface == 1)
        return NTW_PCI_AHCI;
    if (base_class == 0x0c && subclass == 3 && interface == 0x30)
        return NTW_PCI_XHCI;
    if (base_class == 1 && subclass == 8 && interface == 2)
        return NTW_PCI_NVME;
    if (base_class == 3)
        return NTW_PCI_DISPLAY;
    if (base_class == 6 && subclass == 4)
        return NTW_PCI_BRIDGE;
    return NTW_PCI_OTHER;
}

int ntw_pci_scan(const struct ntw_pci_transport *transport,
                  const struct ntw_pci_scan_limits *limits,
                  ntw_pci_visit_fn visit, void *context,
                  struct ntw_pci_scan_result *result)
{
    uint8_t queue[256], upper[256], seen[256] = {0};
    size_t head = 0, tail = 1;
    if (result == NULL)
        return NTW_PCI_ARGUMENT;
    result->buses = 0;
    result->functions = 0;
    if (transport == NULL || limits == NULL || visit == NULL ||
        limits->root_bus > limits->last_bus || limits->max_buses == 0 ||
        limits->max_buses > 256 || limits->max_functions == 0 ||
        limits->max_functions > 65536)
        return NTW_PCI_ARGUMENT;
    queue[0] = limits->root_bus;
    upper[0] = limits->last_bus;
    seen[queue[0]] = 1;
    while (head < tail) {
        uint8_t siblings[256] = {0};
        uint8_t bus = queue[head], bus_upper = upper[head];
        unsigned int slot;
        ++head;
        ++result->buses;
        for (slot = 0; slot < 32; ++slot) {
            unsigned int function, functions = 1;
            for (function = 0; function < functions; ++function) {
                struct ntw_pci_device device;
                uint32_t ids, header, class_revision;
                int status;
                device.address.segment = limits->segment;
                device.address.bus = bus;
                device.address.device = (uint8_t)slot;
                device.address.function = (uint8_t)function;
                status = ntw_pci_read(transport, device.address, 0, 4, &ids);
                if (status != NTW_PCI_OK)
                    return status;
                if ((ids & 0xffff) == 0xffff)
                    continue;
                if (result->functions == limits->max_functions)
                    return NTW_PCI_CAPACITY;
                status = ntw_pci_read(transport, device.address, 0x0c, 4, &header);
                if (status != NTW_PCI_OK)
                    return status;
                device.header_type = (uint8_t)(header >> 16);
                if (function == 0 && (device.header_type & 0x80) != 0)
                    functions = 8;
                status = ntw_pci_read(transport, device.address, 8, 4, &class_revision);
                if (status != NTW_PCI_OK)
                    return status;
                device.vendor_id = (uint16_t)ids;
                device.device_id = (uint16_t)(ids >> 16);
                device.revision = (uint8_t)class_revision;
                device.interface = (uint8_t)(class_revision >> 8);
                device.subclass = (uint8_t)(class_revision >> 16);
                device.base_class = (uint8_t)(class_revision >> 24);
                device.kind = ntw_pci_classify(device.base_class, device.subclass,
                                               device.interface);
                if ((device.header_type & 0x7f) == 1) {
                    uint32_t buses;
                    unsigned int primary, secondary, subordinate, b;
                    if (device.kind != NTW_PCI_BRIDGE)
                        return NTW_PCI_MALFORMED;
                    status = ntw_pci_read(transport, device.address, 0x18, 4, &buses);
                    if (status != NTW_PCI_OK)
                        return status;
                    primary = buses & 0xff;
                    secondary = (buses >> 8) & 0xff;
                    subordinate = (buses >> 16) & 0xff;
                    /* An unconfigured bridge is reported but never followed. */
                    if (secondary != 0 || subordinate != 0) {
                        if (primary != bus || secondary > subordinate ||
                            secondary <= bus || subordinate > bus_upper)
                            return NTW_PCI_MALFORMED;
                        if (seen[secondary])
                            return NTW_PCI_CYCLE;
                        for (b = secondary; b <= subordinate; ++b)
                            if (siblings[b])
                                return NTW_PCI_MALFORMED;
                        if (tail == limits->max_buses)
                            return NTW_PCI_CAPACITY;
                        for (b = secondary; b <= subordinate; ++b)
                            siblings[b] = 1;
                        seen[secondary] = 1;
                        queue[tail] = (uint8_t)secondary;
                        upper[tail] = (uint8_t)subordinate;
                        ++tail;
                    }
                } else if (device.kind == NTW_PCI_BRIDGE) {
                    return NTW_PCI_MALFORMED;
                }
                ++result->functions;
                if (visit(context, &device) != 0)
                    return NTW_PCI_STOPPED;
            }
        }
    }
    return NTW_PCI_OK;
}

int ntw_pci_capabilities(const struct ntw_pci_transport *transport,
                          struct ntw_pci_address address, int extended,
                          struct ntw_pci_capability *capabilities,
                          size_t capacity, size_t *count)
{
    uint8_t seen[128] = {0};
    uint16_t offset, minimum = 0x40;
    uint32_t value;
    int status;
    if (count == NULL)
        return NTW_PCI_ARGUMENT;
    *count = 0;
    if (transport == NULL || (extended != 0 && extended != 1) ||
        (capabilities == NULL && capacity != 0))
        return NTW_PCI_ARGUMENT;
    status = ntw_pci_read(transport, address, 0, 2, &value);
    if (status != NTW_PCI_OK)
        return status;
    if (value == 0xffff)
        return NTW_PCI_NOT_FOUND;
    if (extended) {
        if (transport->config_bytes != 4096)
            return NTW_PCI_UNSUPPORTED;
        offset = minimum = 0x100;
    } else {
        status = ntw_pci_read(transport, address, 6, 2, &value);
        if (status != NTW_PCI_OK)
            return status;
        if ((value & 0x10) == 0)
            return NTW_PCI_OK;
        status = ntw_pci_read(transport, address, 0x0e, 1, &value);
        if (status != NTW_PCI_OK)
            return status;
        value &= 0x7f;
        if (value > 2)
            return NTW_PCI_UNSUPPORTED;
        if (value == 2)
            minimum = 0x48;
        status = ntw_pci_read(transport, address, value == 2 ? 0x14 : 0x34,
                              1, &value);
        if (status != NTW_PCI_OK)
            return status;
        offset = (uint16_t)value;
    }
    while (offset != 0) {
        struct ntw_pci_capability capability;
        unsigned int bit = offset / 4;
        if (offset < minimum || offset > (extended ? 0xffc : 0xfc) ||
            (offset & 3) != 0)
            return NTW_PCI_MALFORMED;
        if ((seen[bit / 8] & (1u << (bit % 8))) != 0)
            return NTW_PCI_CYCLE;
        seen[bit / 8] |= (uint8_t)(1u << (bit % 8));
        status = ntw_pci_read(transport, address, offset, extended ? 4 : 2, &value);
        if (status != NTW_PCI_OK)
            return status;
        if (extended && (value == 0 || value == UINT32_MAX))
            return offset == 0x100 && *count == 0 ? NTW_PCI_OK : NTW_PCI_MALFORMED;
        capability.offset = offset;
        capability.id = (uint16_t)(value & (extended ? 0xffff : 0xff));
        capability.version = extended ? (uint8_t)((value >> 16) & 0xf) : 0;
        if ((!extended && (capability.id == 0 || capability.id == 0xff)) ||
            (extended && (capability.id == 0xffff ||
                          (capability.id != 0 && capability.version == 0))))
            return NTW_PCI_MALFORMED;
        if (capabilities != NULL && *count < capacity)
            capabilities[*count] = capability;
        ++*count;
        offset = (uint16_t)(extended ? value >> 20 : value >> 8);
    }
    return capabilities != NULL && *count > capacity ? NTW_PCI_CAPACITY : NTW_PCI_OK;
}

int ntw_pci_decode_bar(const uint32_t *bars, size_t slots, size_t index,
                        struct ntw_pci_bar *bar)
{
    struct ntw_pci_bar result;
    size_t slot;
    uint32_t low;
    if (bars == NULL || bar == NULL || (slots != 2 && slots != 6) || index >= slots)
        return NTW_PCI_ARGUMENT;
    for (slot = 0; slot < index; ++slot) {
        if ((bars[slot] & 7) == 4) {
            if (slot + 1 == index)
                return NTW_PCI_ARGUMENT;
            ++slot;
        }
    }
    low = bars[index];
    result.prefetchable = 0;
    result.slots = 1;
    if ((low & 1) != 0) {
        if ((low & 2) != 0)
            return NTW_PCI_MALFORMED;
        result.kind = NTW_PCI_BAR_IO;
        result.address_bits = 32;
        result.base = low & UINT32_C(0xfffffffc);
    } else {
        unsigned int type = (low >> 1) & 3;
        result.kind = NTW_PCI_BAR_MEMORY;
        result.prefetchable = (uint8_t)((low >> 3) & 1);
        result.base = low & UINT32_C(0xfffffff0);
        if (type == 3)
            return NTW_PCI_MALFORMED;
        result.address_bits = type == 0 ? 32 : (type == 1 ? 20 : 64);
        if (type == 1 && result.base > UINT64_C(0xfffff))
            return NTW_PCI_MALFORMED;
        if (type == 2) {
            if (index + 1 >= slots)
                return NTW_PCI_MALFORMED;
            result.slots = 2;
            result.base |= (uint64_t)bars[index + 1] << 32;
        }
    }
    result.assigned = result.base != 0;
    *bar = result;
    return NTW_PCI_OK;
}

int ntw_pci_bar_resource(const struct ntw_pci_bar *bar, uint64_t size,
                          uint8_t host_address_bits, uint64_t window_first,
                          uint64_t window_last, struct ntw_pci_resource *resource)
{
    uint64_t last;
    if (bar == NULL || resource == NULL || host_address_bits == 0 ||
        host_address_bits > 64 || window_first > window_last ||
        !power_of_two(size) ||
        (bar->kind != NTW_PCI_BAR_IO && bar->kind != NTW_PCI_BAR_MEMORY) ||
        (bar->address_bits != 20 && bar->address_bits != 32 && bar->address_bits != 64) ||
        (bar->kind == NTW_PCI_BAR_IO && bar->address_bits != 32) ||
        size < (bar->kind == NTW_PCI_BAR_IO ? 4u : 16u))
        return NTW_PCI_ARGUMENT;
    if (!bar->assigned || (bar->base & (size - 1)) != 0 ||
        bar->base > UINT64_MAX - (size - 1))
        return NTW_PCI_RANGE;
    last = bar->base + size - 1;
    if (last > width_mask(bar->address_bits) || last > width_mask(host_address_bits) ||
        bar->base < window_first || last > window_last)
        return NTW_PCI_RANGE;
    resource->first = bar->base;
    resource->last = last;
    resource->kind = bar->kind;
    resource->prefetchable = bar->prefetchable;
    return NTW_PCI_OK;
}

int ntw_pci_dma_segment(const struct ntw_pci_dma_constraints *constraints,
                         uint64_t device_address, uint64_t remaining,
                         uint64_t *segment_bytes)
{
    uint64_t length, available;
    if (constraints == NULL || segment_bytes == NULL || remaining == 0 ||
        constraints->address_mask == 0 ||
        (constraints->address_mask & (constraints->address_mask + 1)) != 0 ||
        !power_of_two(constraints->alignment) || constraints->max_segment == 0 ||
        (constraints->boundary != 0 && !power_of_two(constraints->boundary)))
        return NTW_PCI_ARGUMENT;
    if ((device_address & (constraints->alignment - 1)) != 0 ||
        device_address > constraints->address_mask ||
        remaining - 1 > UINT64_MAX - device_address)
        return NTW_PCI_RANGE;
    length = remaining < constraints->max_segment ? remaining : constraints->max_segment;
    /* Compare last-byte distance to avoid representing 2^64 bytes at address 0. */
    available = constraints->address_mask - device_address;
    if (length - 1 > available)
        length = available + 1;
    if (constraints->boundary != 0) {
        available = constraints->boundary - (device_address & (constraints->boundary - 1));
        if (length > available)
            length = available;
    }
    *segment_bytes = length;
    return NTW_PCI_OK;
}
