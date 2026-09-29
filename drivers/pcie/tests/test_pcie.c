/* SPDX-License-Identifier: GPL-2.0-only
 * Original mock-only contract tests. Never access host PCI, /dev/mem or ports.
 */
#include "ntw_pcie.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int checks;
#define CHECK(condition) do { \
    ++checks; \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        exit(1); \
    } \
} while (0)

struct mock_function {
    struct ntw_pci_address address;
    uint8_t bytes[4096];
};
struct mock_bus {
    struct mock_function functions[12];
    size_t count, reads, fail_read;
};

static void put16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void put32(uint8_t *p, uint32_t value)
{
    put16(p, (uint16_t)value);
    put16(p + 2, (uint16_t)(value >> 16));
}

static void put64(uint8_t *p, uint64_t value)
{
    put32(p, (uint32_t)value);
    put32(p + 4, (uint32_t)(value >> 32));
}

static int same_address(struct ntw_pci_address a, struct ntw_pci_address b)
{
    return a.segment == b.segment && a.bus == b.bus && a.device == b.device &&
           a.function == b.function;
}

static int mock_read(void *context, struct ntw_pci_address address,
                      uint16_t offset, uint8_t width, uint32_t *value)
{
    struct mock_bus *bus = context;
    size_t i;
    ++bus->reads;
    if (bus->fail_read == bus->reads) {
        *value = 0; /* Failed transport must never corrupt caller output. */
        return NTW_PCI_IO;
    }
    CHECK(offset + width <= 4096);
    for (i = 0; i < bus->count; ++i)
        if (same_address(address, bus->functions[i].address)) {
            unsigned int byte;
            *value = 0;
            for (byte = 0; byte < width; ++byte)
                *value |= (uint32_t)bus->functions[i].bytes[offset + byte] << (byte * 8);
            return NTW_PCI_OK;
        }
    *value = UINT32_MAX;
    return NTW_PCI_OK;
}

static struct mock_function *add_function(struct mock_bus *bus, uint8_t number,
                                           uint8_t slot, uint8_t function,
                                           uint8_t header, uint32_t class_code)
{
    struct mock_function *entry;
    CHECK(bus->count < 12);
    entry = &bus->functions[bus->count++];
    entry->address.segment = 7;
    entry->address.bus = number;
    entry->address.device = slot;
    entry->address.function = function;
    put32(entry->bytes, UINT32_C(0x12348086));
    put32(entry->bytes + 8, class_code << 8);
    entry->bytes[0x0e] = header;
    return entry;
}

static struct ntw_pci_transport transport_for(struct mock_bus *bus)
{
    struct ntw_pci_transport transport = { mock_read, bus, 4096 };
    return transport;
}

static void test_transport(void)
{
    struct mock_bus bus = {0};
    struct ntw_pci_transport transport = transport_for(&bus);
    struct ntw_pci_address address = {7, 0, 0, 0};
    uint32_t value = 42;
    CHECK(ntw_pci_read(&transport, address, 0, 1, &value) == NTW_PCI_OK && value == 255);
    CHECK(ntw_pci_read(&transport, address, 0, 2, &value) == NTW_PCI_OK && value == 65535);
    CHECK(ntw_pci_read(&transport, address, 0, 4, &value) == NTW_PCI_OK && value == UINT32_MAX);
    value = 42;
    bus.fail_read = bus.reads + 1;
    CHECK(ntw_pci_read(&transport, address, 0, 4, &value) == NTW_PCI_IO && value == 42);
    CHECK(ntw_pci_read(&transport, address, 0, 0, &value) == NTW_PCI_ARGUMENT);
    CHECK(ntw_pci_read(&transport, address, 0, 3, &value) == NTW_PCI_ARGUMENT);
    CHECK(ntw_pci_read(&transport, address, 1, 4, &value) == NTW_PCI_ARGUMENT);
    CHECK(ntw_pci_read(&transport, address, 4096, 1, &value) == NTW_PCI_ARGUMENT);
    CHECK(ntw_pci_read(&transport, address, 4095, 1, &value) == NTW_PCI_OK);
    address.device = 32;
    CHECK(ntw_pci_read(&transport, address, 0, 4, &value) == NTW_PCI_ARGUMENT);
    address.device = 0;
    address.function = 8;
    CHECK(ntw_pci_read(&transport, address, 0, 4, &value) == NTW_PCI_ARGUMENT);
    address.function = 0;
    transport.config_bytes = 256;
    CHECK(ntw_pci_read(&transport, address, 256, 4, &value) == NTW_PCI_ARGUMENT);
    transport.config_bytes = 255;
    CHECK(ntw_pci_read(&transport, address, 0, 4, &value) == NTW_PCI_ARGUMENT);
    CHECK(ntw_pci_read(NULL, address, 0, 4, &value) == NTW_PCI_ARGUMENT);
}

static void checksum_table(uint8_t *table, size_t bytes)
{
    size_t i;
    uint8_t sum = 0;
    table[9] = 0;
    for (i = 0; i < bytes; ++i)
        sum = (uint8_t)(sum + table[i]);
    table[9] = (uint8_t)(0u - sum);
}

static void make_mcfg(uint8_t table[76])
{
    memset(table, 0, 76);
    memcpy(table, "MCFG", 4);
    put32(table + 4, 76);
    table[8] = 1;
    put64(table + 44, UINT64_C(0xe0000000));
    table[55] = 63;
    put64(table + 60, UINT64_C(0x100000000));
    put16(table + 68, 7);
    table[70] = 64;
    table[71] = 127;
    checksum_table(table, 76);
}

static void test_mcfg(void)
{
    uint8_t table[76];
    struct ntw_pci_ecam_window windows[2], sentinel;
    struct ntw_pci_address address = {7, 64, 2, 3};
    uint64_t physical = 17;
    size_t count = 5, i;
    make_mcfg(table);
    CHECK(ntw_pci_parse_mcfg(table, sizeof(table), windows, 2, &count) == NTW_PCI_OK);
    CHECK(count == 2 && windows[1].segment == 7 && windows[1].first_bus == 64);
    CHECK(ntw_pci_ecam_address(&windows[1], address, 0x20, 4, &physical) == NTW_PCI_OK);
    CHECK(physical == UINT64_C(0x104013020)); /* no subtraction of first_bus */
    address.bus = 127;
    address.device = 31;
    address.function = 7;
    CHECK(ntw_pci_ecam_address(&windows[1], address, 4092, 4, &physical) == NTW_PCI_OK);
    CHECK(physical == UINT64_C(0x107fffffc));
    address.bus = 128;
    CHECK(ntw_pci_ecam_address(&windows[1], address, 4092, 4, &physical) == NTW_PCI_RANGE);
    address.bus = 63;
    CHECK(ntw_pci_ecam_address(&windows[1], address, 4092, 4, &physical) == NTW_PCI_RANGE);
    address.bus = 64;
    address.segment = 0;
    CHECK(ntw_pci_ecam_address(&windows[1], address, 0, 4, &physical) == NTW_PCI_RANGE);
    address.segment = 7;
    CHECK(ntw_pci_ecam_address(&windows[1], address, 4095, 4, &physical) == NTW_PCI_ARGUMENT);
    CHECK(ntw_pci_parse_mcfg(table, 76, NULL, 0, &count) == NTW_PCI_OK && count == 2);
    sentinel = windows[0];
    CHECK(ntw_pci_parse_mcfg(table, 76, windows, 1, &count) == NTW_PCI_CAPACITY && count == 0);
    CHECK(windows[0].base == sentinel.base);
    for (i = 0; i < 76; ++i)
        CHECK(ntw_pci_parse_mcfg(table, i, windows, 2, &count) == NTW_PCI_MALFORMED);
    table[75] = 1;
    CHECK(ntw_pci_parse_mcfg(table, 76, windows, 2, &count) == NTW_PCI_MALFORMED);
    checksum_table(table, 76);
    CHECK(ntw_pci_parse_mcfg(table, 76, windows, 2, &count) == NTW_PCI_MALFORMED);
    make_mcfg(table);
    table[36] = 1;
    checksum_table(table, 76);
    CHECK(ntw_pci_parse_mcfg(table, 76, windows, 2, &count) == NTW_PCI_MALFORMED);
    make_mcfg(table);
    table[8] = 2;
    checksum_table(table, 76);
    CHECK(ntw_pci_parse_mcfg(table, 76, windows, 2, &count) == NTW_PCI_UNSUPPORTED);
    make_mcfg(table);
    table[70] = 128;
    checksum_table(table, 76);
    CHECK(ntw_pci_parse_mcfg(table, 76, windows, 2, &count) == NTW_PCI_MALFORMED);
    make_mcfg(table);
    put16(table + 68, 0);
    table[70] = 32;
    checksum_table(table, 76);
    CHECK(ntw_pci_parse_mcfg(table, 76, windows, 2, &count) == NTW_PCI_MALFORMED);
    make_mcfg(table);
    put64(table + 60, UINT64_C(0xdc000000)); /* bus 64 aliases first window */
    checksum_table(table, 76);
    CHECK(ntw_pci_parse_mcfg(table, 76, windows, 2, &count) == NTW_PCI_MALFORMED);
    make_mcfg(table);
    put64(table + 60, UINT64_C(0xfffffffffff00000));
    checksum_table(table, 76);
    CHECK(ntw_pci_parse_mcfg(table, 76, windows, 2, &count) == NTW_PCI_MALFORMED);
    make_mcfg(table);
    table[44] = 1;
    checksum_table(table, 76);
    CHECK(ntw_pci_parse_mcfg(table, 76, windows, 2, &count) == NTW_PCI_MALFORMED);
    make_mcfg(table);
    put32(table + 4, 75);
    CHECK(ntw_pci_parse_mcfg(table, 76, windows, 2, &count) == NTW_PCI_MALFORMED);
    windows[0].base = UINT64_C(0xfffffffffff00000);
    windows[0].first_bus = windows[0].last_bus = 0;
    address.segment = 0;
    address.bus = 0;
    CHECK(ntw_pci_ecam_address(&windows[0], address, 4095, 1, &physical) == NTW_PCI_OK);
    CHECK(physical == UINT64_MAX);
    windows[0].last_bus = 1;
    CHECK(ntw_pci_ecam_address(&windows[0], address, 0, 4, &physical) == NTW_PCI_MALFORMED);
}

struct inventory {
    struct ntw_pci_device devices[12];
    size_t count, stop_after;
};

static int record_device(void *context, const struct ntw_pci_device *device)
{
    struct inventory *inventory = context;
    CHECK(inventory->count < 12);
    inventory->devices[inventory->count++] = *device;
    return inventory->stop_after == inventory->count;
}

static void make_topology(struct mock_bus *bus)
{
    struct mock_function *device;
    memset(bus, 0, sizeof(*bus));
    device = add_function(bus, 3, 0, 0, 1, 0x060400);
    put32(device->bytes + 0x18, UINT32_C(0x00060403));
    device = add_function(bus, 4, 0, 0, 1, 0x060400);
    put32(device->bytes + 0x18, UINT32_C(0x00050504));
    (void)add_function(bus, 4, 1, 0, 0, 0x010601);
    (void)add_function(bus, 5, 2, 0, 0x80, 0x010802);
    (void)add_function(bus, 5, 2, 7, 0, 0x0c0330);
    (void)add_function(bus, 3, 1, 0, 0, 0x030000);
    (void)add_function(bus, 3, 1, 1, 0, 0x020000); /* hidden by single-function bit */
}

static int scan(struct mock_bus *bus, struct ntw_pci_scan_limits *limits,
                 struct inventory *inventory, struct ntw_pci_scan_result *result)
{
    struct ntw_pci_transport transport = transport_for(bus);
    return ntw_pci_scan(&transport, limits, record_device, inventory, result);
}

static void test_scan(void)
{
    struct mock_bus bus;
    struct ntw_pci_scan_limits limits = {7, 3, 6, 256, 65536};
    struct ntw_pci_scan_result result;
    struct inventory inventory = {0};
    size_t reads, failure;
    make_topology(&bus);
    CHECK(scan(&bus, &limits, &inventory, &result) == NTW_PCI_OK);
    CHECK(result.buses == 3 && result.functions == 6 && inventory.count == 6);
    CHECK(inventory.devices[1].kind == NTW_PCI_DISPLAY);
    CHECK(inventory.devices[3].kind == NTW_PCI_AHCI);
    CHECK(inventory.devices[4].kind == NTW_PCI_NVME);
    CHECK(inventory.devices[5].kind == NTW_PCI_XHCI);
    CHECK(inventory.devices[5].address.function == 7);
    CHECK(ntw_pci_classify(1, 6, 0) == NTW_PCI_OTHER);
    CHECK(ntw_pci_classify(1, 8, 1) == NTW_PCI_OTHER);
    CHECK(ntw_pci_classify(0x0c, 3, 0x20) == NTW_PCI_OTHER);
    reads = bus.reads;
    /* Every transport position must fail, including absence/vendor/header/class. */
    for (failure = 1; failure <= reads; ++failure) {
        bus.reads = 0;
        bus.fail_read = failure;
        memset(&inventory, 0, sizeof(inventory));
        CHECK(scan(&bus, &limits, &inventory, &result) == NTW_PCI_IO);
        CHECK(bus.reads == failure);
    }
    bus.reads = bus.fail_read = 0;
    memset(&inventory, 0, sizeof(inventory));
    inventory.stop_after = 2;
    CHECK(scan(&bus, &limits, &inventory, &result) == NTW_PCI_STOPPED);
    CHECK(inventory.count == 2 && result.functions == 2);
    memset(&inventory, 0, sizeof(inventory));
    limits.max_buses = 1;
    CHECK(scan(&bus, &limits, &inventory, &result) == NTW_PCI_CAPACITY);
    limits.max_buses = 256;
    limits.max_functions = 2;
    CHECK(scan(&bus, &limits, &inventory, &result) == NTW_PCI_CAPACITY);
    limits.max_functions = 65536;
    make_topology(&bus);
    put32(bus.functions[1].bytes + 0x18, UINT32_C(0x00030304));
    memset(&inventory, 0, sizeof(inventory));
    CHECK(scan(&bus, &limits, &inventory, &result) == NTW_PCI_MALFORMED); /* ancestor loop */
    make_topology(&bus);
    put32(bus.functions[0].bytes + 0x18, UINT32_C(0x00070403));
    CHECK(scan(&bus, &limits, &inventory, &result) == NTW_PCI_MALFORMED); /* bound */
    make_topology(&bus);
    put32(bus.functions[0].bytes + 0x18, UINT32_C(0x00060402));
    CHECK(scan(&bus, &limits, &inventory, &result) == NTW_PCI_MALFORMED); /* primary */
    make_topology(&bus);
    put32(bus.functions[0].bytes + 0x18, UINT32_C(0x00040603));
    CHECK(scan(&bus, &limits, &inventory, &result) == NTW_PCI_MALFORMED); /* inverted */
    make_topology(&bus);
    bus.functions[0].bytes[0x0b] = 1;
    CHECK(scan(&bus, &limits, &inventory, &result) == NTW_PCI_MALFORMED); /* class */
    make_topology(&bus);
    bus.functions[0].bytes[0x0e] = 0;
    CHECK(scan(&bus, &limits, &inventory, &result) == NTW_PCI_MALFORMED); /* type */
    make_topology(&bus);
    put32(add_function(&bus, 3, 2, 0, 1, 0x060400)->bytes + 0x18,
          UINT32_C(0x00060603));
    memset(&inventory, 0, sizeof(inventory));
    CHECK(scan(&bus, &limits, &inventory, &result) == NTW_PCI_MALFORMED); /* sibling overlap */
    make_topology(&bus);
    put32(add_function(&bus, 3, 2, 0, 1, 0x060400)->bytes + 0x18,
          UINT32_C(0x00040403));
    memset(&inventory, 0, sizeof(inventory));
    CHECK(scan(&bus, &limits, &inventory, &result) == NTW_PCI_CYCLE); /* duplicate target */
    make_topology(&bus);
    put32(bus.functions[0].bytes + 0x18, 0);
    memset(&inventory, 0, sizeof(inventory));
    CHECK(scan(&bus, &limits, &inventory, &result) == NTW_PCI_OK);
    CHECK(result.buses == 1 && result.functions == 2); /* disabled bridge */
    limits.max_buses = 0;
    CHECK(scan(&bus, &limits, &inventory, &result) == NTW_PCI_ARGUMENT);
}

static void make_capabilities(struct mock_function *function)
{
    memset(function->bytes + 4, 0, sizeof(function->bytes) - 4);
    put16(function->bytes + 6, 0x10);
    function->bytes[0x34] = 0x40;
    put16(function->bytes + 0x40, 0x4801);
    put16(function->bytes + 0x48, 0x6010);
    put16(function->bytes + 0x60, 0x0011);
    put32(function->bytes + 0x100, UINT32_C(0x14010001));
    put32(function->bytes + 0x140, UINT32_C(0x00010003));
}

static void test_capabilities(void)
{
    struct mock_bus bus = {0};
    struct mock_function *function = add_function(&bus, 0, 0, 0, 0, 0x010802);
    struct ntw_pci_transport transport = transport_for(&bus);
    struct ntw_pci_capability capabilities[4];
    size_t count, failure, reads;
    int extended;
    make_capabilities(function);
    CHECK(ntw_pci_capabilities(&transport, function->address, 0, capabilities, 4, &count) == NTW_PCI_OK);
    CHECK(count == 3 && capabilities[1].id == 0x10 && capabilities[1].offset == 0x48);
    CHECK(ntw_pci_capabilities(&transport, function->address, 1, capabilities, 4, &count) == NTW_PCI_OK);
    CHECK(count == 2 && capabilities[1].id == 3 && capabilities[1].version == 1);
    for (extended = 0; extended <= 1; ++extended) {
        CHECK(ntw_pci_capabilities(&transport, function->address, extended, NULL, 0, &count) == NTW_PCI_OK);
        CHECK(count == (extended ? 2u : 3u));
        CHECK(ntw_pci_capabilities(&transport, function->address, extended, capabilities, 1, &count) == NTW_PCI_CAPACITY);
        bus.reads = 0;
        CHECK(ntw_pci_capabilities(&transport, function->address, extended, capabilities, 4, &count) == NTW_PCI_OK);
        reads = bus.reads;
        for (failure = 1; failure <= reads; ++failure) {
            bus.reads = 0;
            bus.fail_read = failure;
            CHECK(ntw_pci_capabilities(&transport, function->address, extended, capabilities, 4, &count) == NTW_PCI_IO);
        }
        bus.reads = bus.fail_read = 0;
    }
    function->bytes[0x61] = 0x40;
    CHECK(ntw_pci_capabilities(&transport, function->address, 0, capabilities, 1, &count) == NTW_PCI_CYCLE);
    function->bytes[0x61] = 0x42;
    CHECK(ntw_pci_capabilities(&transport, function->address, 0, capabilities, 1, &count) == NTW_PCI_MALFORMED);
    function->bytes[0x61] = 0x20;
    CHECK(ntw_pci_capabilities(&transport, function->address, 0, capabilities, 1, &count) == NTW_PCI_MALFORMED);
    make_capabilities(function);
    function->bytes[0x0e] = 2;
    function->bytes[0x14] = 0x40;
    CHECK(ntw_pci_capabilities(&transport, function->address, 0, capabilities, 4, &count) == NTW_PCI_MALFORMED);
    function->bytes[0x14] = 0x48;
    CHECK(ntw_pci_capabilities(&transport, function->address, 0, capabilities, 4, &count) == NTW_PCI_OK && count == 2);
    make_capabilities(function);
    put32(function->bytes + 0x140, UINT32_C(0x10010003));
    CHECK(ntw_pci_capabilities(&transport, function->address, 1, capabilities, 1, &count) == NTW_PCI_CYCLE);
    put32(function->bytes + 0x140, UINT32_C(0x10210003));
    CHECK(ntw_pci_capabilities(&transport, function->address, 1, capabilities, 1, &count) == NTW_PCI_MALFORMED);
    put32(function->bytes + 0x140, UINT32_C(0x04010003));
    CHECK(ntw_pci_capabilities(&transport, function->address, 1, capabilities, 1, &count) == NTW_PCI_MALFORMED);
    put32(function->bytes + 0x140, 0);
    CHECK(ntw_pci_capabilities(&transport, function->address, 1, capabilities, 1, &count) == NTW_PCI_MALFORMED);
    put32(function->bytes + 0x100, 0);
    CHECK(ntw_pci_capabilities(&transport, function->address, 1, capabilities, 1, &count) == NTW_PCI_OK && count == 0);
    put32(function->bytes + 0x100, UINT32_MAX);
    CHECK(ntw_pci_capabilities(&transport, function->address, 1, capabilities, 1, &count) == NTW_PCI_OK && count == 0);
    put32(function->bytes + 0x100, UINT32_C(0xffc10001));
    put32(function->bytes + 0xffc, UINT32_C(0x00010003));
    CHECK(ntw_pci_capabilities(&transport, function->address, 1, capabilities, 4, &count) == NTW_PCI_OK && count == 2);
    put32(function->bytes + 0x100, 1); /* unsupported zero version on non-null ID */
    CHECK(ntw_pci_capabilities(&transport, function->address, 1, capabilities, 4, &count) == NTW_PCI_MALFORMED);
    transport.config_bytes = 256;
    CHECK(ntw_pci_capabilities(&transport, function->address, 1, capabilities, 4, &count) == NTW_PCI_UNSUPPORTED);
    transport.config_bytes = 4096;
    put16(function->bytes, 0xffff);
    CHECK(ntw_pci_capabilities(&transport, function->address, 0, capabilities, 4, &count) == NTW_PCI_NOT_FOUND);
    put16(function->bytes, 0x8086);
    make_capabilities(function);
    /* Maximum legal extended list exercises the entire visited bitmap. */
    for (unsigned int offset = 0x100; offset <= 0xffc; offset += 4)
        put32(function->bytes + offset,
              (offset == 0xffc ? 0u : (offset + 4) << 20) | 0x10001u);
    CHECK(ntw_pci_capabilities(&transport, function->address, 1, NULL, 0, &count) == NTW_PCI_OK && count == 960);
    put32(function->bytes + 0xffc, UINT32_C(0x10010001));
    CHECK(ntw_pci_capabilities(&transport, function->address, 1, NULL, 0, &count) == NTW_PCI_CYCLE && count == 960);
}

static void test_bars_resources_dma(void)
{
    uint32_t bars[6] = {0x80000008, 0x100c, 2, 0x1001, 0xf0002, 0};
    struct ntw_pci_bar bar;
    struct ntw_pci_resource resource;
    struct ntw_pci_dma_constraints dma = {UINT64_C(0xffffffff), 16, 4096, 8192};
    uint64_t length = 0;
    CHECK(ntw_pci_decode_bar(bars, 6, 0, &bar) == NTW_PCI_OK);
    CHECK(bar.base == 0x80000000 && bar.address_bits == 32 && bar.prefetchable && bar.slots == 1);
    CHECK(ntw_pci_bar_resource(&bar, 0x1000, 32, 0x80000000, 0x80000fff, &resource) == NTW_PCI_OK);
    CHECK(resource.first == 0x80000000 && resource.last == 0x80000fff);
    CHECK(ntw_pci_bar_resource(&bar, 0x1000, 32, 0x80000000, 0x80000ffe, &resource) == NTW_PCI_RANGE);
    CHECK(ntw_pci_bar_resource(&bar, 0x1001, 32, 0, UINT64_MAX, &resource) == NTW_PCI_ARGUMENT);
    CHECK(ntw_pci_decode_bar(bars, 6, 1, &bar) == NTW_PCI_OK);
    CHECK(bar.base == UINT64_C(0x200001000) && bar.address_bits == 64 && bar.slots == 2);
    CHECK(ntw_pci_bar_resource(&bar, 0x1000, 64, 0, UINT64_MAX, &resource) == NTW_PCI_OK);
    CHECK(ntw_pci_bar_resource(&bar, 0x1000, 32, 0, UINT64_MAX, &resource) == NTW_PCI_RANGE);
    CHECK(ntw_pci_bar_resource(&bar, 0x2000, 64, 0, UINT64_MAX, &resource) == NTW_PCI_RANGE);
    CHECK(ntw_pci_decode_bar(bars, 6, 2, &bar) == NTW_PCI_ARGUMENT);
    CHECK(ntw_pci_decode_bar(bars, 6, 3, &bar) == NTW_PCI_OK);
    CHECK(bar.kind == NTW_PCI_BAR_IO && bar.base == 0x1000);
    CHECK(ntw_pci_bar_resource(&bar, 0x100, 16, 0, 0xffff, &resource) == NTW_PCI_OK);
    CHECK(ntw_pci_decode_bar(bars, 6, 4, &bar) == NTW_PCI_OK && bar.address_bits == 20);
    CHECK(ntw_pci_bar_resource(&bar, 0x10000, 32, 0, UINT64_MAX, &resource) == NTW_PCI_OK && resource.last == 0xfffff);
    CHECK(ntw_pci_decode_bar(bars, 6, 5, &bar) == NTW_PCI_OK && !bar.assigned);
    CHECK(ntw_pci_bar_resource(&bar, 0x1000, 32, 0, UINT64_MAX, &resource) == NTW_PCI_RANGE);
    bars[5] = 4;
    CHECK(ntw_pci_decode_bar(bars, 6, 5, &bar) == NTW_PCI_MALFORMED);
    bars[5] = 6;
    CHECK(ntw_pci_decode_bar(bars, 6, 5, &bar) == NTW_PCI_MALFORMED);
    bars[5] = 3;
    CHECK(ntw_pci_decode_bar(bars, 6, 5, &bar) == NTW_PCI_MALFORMED);
    bars[5] = 0x100002;
    CHECK(ntw_pci_decode_bar(bars, 6, 5, &bar) == NTW_PCI_MALFORMED);
    CHECK(ntw_pci_decode_bar(bars, 2, 1, &bar) == NTW_PCI_MALFORMED);
    bars[0] = UINT32_C(0xfffff004);
    bars[1] = UINT32_MAX;
    CHECK(ntw_pci_decode_bar(bars, 2, 0, &bar) == NTW_PCI_OK);
    CHECK(ntw_pci_bar_resource(&bar, 0x1000, 64, 0, UINT64_MAX, &resource) == NTW_PCI_OK);
    CHECK(resource.last == UINT64_MAX);
    CHECK(ntw_pci_bar_resource(&bar, 0x2000, 64, 0, UINT64_MAX, &resource) == NTW_PCI_RANGE);
    CHECK(ntw_pci_dma_segment(&dma, 0x1000, 0x4000, &length) == NTW_PCI_OK && length == 4096);
    CHECK(ntw_pci_dma_segment(&dma, 0x1ff0, 0x4000, &length) == NTW_PCI_OK && length == 16);
    CHECK(ntw_pci_dma_segment(&dma, 0xfffffff0, 0x1000, &length) == NTW_PCI_OK && length == 16);
    CHECK(ntw_pci_dma_segment(&dma, UINT64_C(0x100000000), 16, &length) == NTW_PCI_RANGE);
    CHECK(ntw_pci_dma_segment(&dma, 0x1001, 16, &length) == NTW_PCI_RANGE);
    dma.boundary = 0;
    CHECK(ntw_pci_dma_segment(&dma, 0x1000, 0x4000, &length) == NTW_PCI_OK && length == 8192);
    dma.address_mask = UINT64_MAX;
    CHECK(ntw_pci_dma_segment(&dma, UINT64_MAX - 15, 16, &length) == NTW_PCI_OK && length == 16);
    CHECK(ntw_pci_dma_segment(&dma, UINT64_MAX - 15, 17, &length) == NTW_PCI_RANGE);
    CHECK(ntw_pci_dma_segment(&dma, 0, UINT64_MAX, &length) == NTW_PCI_OK && length == 8192);
    dma.address_mask = 0xfffe;
    CHECK(ntw_pci_dma_segment(&dma, 0, 16, &length) == NTW_PCI_ARGUMENT);
    dma.address_mask = 0xffff;
    dma.alignment = 3;
    CHECK(ntw_pci_dma_segment(&dma, 0, 16, &length) == NTW_PCI_ARGUMENT);
    dma.alignment = 1;
    dma.boundary = 3;
    CHECK(ntw_pci_dma_segment(&dma, 0, 16, &length) == NTW_PCI_ARGUMENT);
}

/* Deterministic malformed-byte coverage supplements the targeted contracts. */
static void test_mutated_tables(void)
{
    uint8_t table[76];
    struct ntw_pci_ecam_window windows[2];
    struct mock_bus bus = {0};
    struct mock_function *function = add_function(&bus, 0, 0, 0, 0, 0x010802);
    struct ntw_pci_transport transport = transport_for(&bus);
    uint32_t state = 0x12345678;
    size_t count;
    unsigned int trial;
    for (trial = 0; trial < 4096; ++trial) {
        size_t at;
        int status;
        state = state * UINT32_C(1664525) + UINT32_C(1013904223);
        make_mcfg(table);
        table[state % sizeof(table)] ^= (uint8_t)(state >> 24);
        if ((trial & 1) != 0)
            checksum_table(table, sizeof(table));
        status = ntw_pci_parse_mcfg(table, sizeof(table), windows, 2, &count);
        CHECK(status <= 0 && count <= 2);
        make_capabilities(function);
        at = (state >> 8) & 0xfff;
        function->bytes[at] = (uint8_t)(state >> 16);
        status = ntw_pci_capabilities(&transport, function->address, (int)(trial & 1), NULL, 0, &count);
        CHECK(status <= NTW_PCI_NOT_FOUND && count <= 960);
    }
}

int main(void)
{
    test_transport();
    test_mcfg();
    test_scan();
    test_capabilities();
    test_bars_resources_dma();
    test_mutated_tables();
    printf("PASS: NTWrapper9x PCIe core (%u assertions; mock transport only)\n", checks);
    return 0;
}
