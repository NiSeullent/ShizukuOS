/* SPDX-License-Identifier: GPL-2.0-only
 * QEMU diagnostic ONLY, never linked into the default BOOTX64.EFI.
 * Conventional mechanism-1 config reads require an explicitly known x86
 * test machine. No ECAM support, BAR writes, DMA or hardware drivers implied.
 */
#include "ntw_pcie.h"

static void debug_text(const char *text)
{
    while (*text) {
        __asm__ volatile("outb %0, %1" :: "a"((uint8_t)*text++), "Nd"((uint16_t)0xe9));
    }
}

static void debug_hex(uint32_t number)
{
    static const char hex[] = "0123456789ABCDEF";
    char text[9];
    unsigned i;
    for (i = 0; i < 8; ++i) text[i] = hex[(number >> ((7 - i) * 4)) & 15];
    text[8] = 0;
    debug_text(text);
}

static int config_read(void *opaque, struct ntw_pci_address a, uint16_t offset,
                        uint8_t width, uint32_t *value)
{
    uint32_t select, data;
    uint16_t port;
    (void)opaque;
    if (a.segment || a.device > 31 || a.function > 7 || offset >= 256 ||
        (width != 1 && width != 2 && width != 4) || offset % width ||
        (uint32_t)offset + width > 256 || !value)
        return NTW_PCI_ARGUMENT;
    select = UINT32_C(0x80000000) | ((uint32_t)a.bus << 16) |
             ((uint32_t)a.device << 11) | ((uint32_t)a.function << 8) | (offset & ~3u);
    __asm__ volatile("outl %0, %1" :: "a"(select), "Nd"((uint16_t)0xcf8) : "memory");
    port = 0xcfc;
    __asm__ volatile("inl %1, %0" : "=a"(data) : "Nd"(port) : "memory");
    data >>= (offset & 3) * 8;
    *value = width == 1 ? data & 0xff : width == 2 ? data & 0xffff : data;
    return NTW_PCI_OK;
}

typedef struct { unsigned bridges, xhci, downstream_xhci; } SD_PCI_PROBE;

static int visit(void *opaque, const struct ntw_pci_device *device)
{
    SD_PCI_PROBE *probe = (SD_PCI_PROBE *)opaque;
    debug_text("PCI BDF=");
    debug_hex(((uint32_t)device->address.bus << 16) |
              ((uint32_t)device->address.device << 8) | device->address.function);
    debug_text(" ID=");
    debug_hex(((uint32_t)device->vendor_id << 16) | device->device_id);
    debug_text(" CLASS=");
    debug_hex(((uint32_t)device->base_class << 16) |
              ((uint32_t)device->subclass << 8) | device->interface);
    debug_text("\n");
    if (device->kind == NTW_PCI_BRIDGE) ++probe->bridges;
    if (device->kind == NTW_PCI_XHCI) {
        ++probe->xhci;
        if (device->address.bus) ++probe->downstream_xhci;
    }
    return 0;
}

int sd_pci_probe(void)
{
    struct ntw_pci_transport transport = {config_read, 0, 256};
    struct ntw_pci_scan_limits limits = {0, 0, 255, 256, 65536};
    struct ntw_pci_scan_result result = {0};
    SD_PCI_PROBE probe = {0};
    int status;
    uint16_t cs;
    __asm__ volatile("mov %%cs, %0" : "=r"(cs));
    if ((cs & 3) != 0) return 0;
    status = ntw_pci_scan(&transport, &limits, visit, &probe, &result);
    debug_text("SCAN_STATUS="); debug_hex((uint32_t)status);
    debug_text(" BUSES="); debug_hex(result.buses);
    debug_text(" FUNCTIONS="); debug_hex(result.functions); debug_text("\n");
    if (status == NTW_PCI_OK && result.buses >= 2 && probe.bridges && probe.downstream_xhci) {
        debug_text("NTWPCIE_BRIDGE_XHCI_PASS config_bytes=256 NO_ECAM NO_DMA\n");
        return 1;
    }
    debug_text("NTWPCIE_BRIDGE_XHCI_FAIL\n");
    return 0;
}
