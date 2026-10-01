/* SPDX-License-Identifier: GPL-2.0-only */
#include "pcibus.h"
#include "regs.h"

static uint32_t load_le(const uint8_t *p, uint8_t width)
{
    uint32_t value = 0;
    uint8_t i;
    for (i = 0; i < width; ++i)
        value |= (uint32_t)p[i] << (8 * i);
    return value;
}

static void store_le(uint8_t *p, uint8_t width, uint32_t value)
{
    uint8_t i;
    for (i = 0; i < width; ++i)
        p[i] = (uint8_t)(value >> (8 * i));
}

static int aligned(uint16_t offset, uint8_t width, uint16_t limit)
{
    return (width == 1 || width == 2 || width == 4) && (offset % width) == 0 &&
           offset <= limit - width;
}

void csm_pci_init(csm_pci *pci)
{
    unsigned i;
    if (!pci)
        return;
    for (i = 0; i < CSM_PCI_MAX_FUNCTIONS; ++i)
        pci->fn[i].used = 0;
    pci->count = 0;
    pci->ecam = 0;
    pci->config_accesses = 0;
    pci->range_rejects = 0;
}

int csm_pci_add(csm_pci *pci, uint8_t bus, uint8_t dev, uint8_t fn, uint16_t vendor,
                uint16_t device, uint8_t base_class, uint8_t subclass, uint8_t prog_if)
{
    csm_pci_function *slot;
    unsigned i;
    if (!pci || dev > 31 || fn > 7 || vendor == 0xffff)
        return CSM_ERR_ARG;
    for (i = 0; i < pci->count; ++i)
        if (pci->fn[i].used && pci->fn[i].bus == bus && pci->fn[i].dev == dev && pci->fn[i].fn == fn)
            return CSM_ERR_ARG;
    if (pci->count >= CSM_PCI_MAX_FUNCTIONS)
        return CSM_ERR_NOSPACE;
    slot = &pci->fn[pci->count++];
    for (i = 0; i < CSM_PCI_CFG_BYTES; ++i)
        slot->cfg[i] = 0;
    slot->used = 1;
    slot->bus = bus;
    slot->dev = dev;
    slot->fn = fn;
    store_le(slot->cfg + 0, 2, vendor);
    store_le(slot->cfg + 2, 2, device);
    slot->cfg[8] = 0;
    slot->cfg[9] = prog_if;
    slot->cfg[10] = subclass;
    slot->cfg[11] = base_class;
    slot->cfg[0x0e] = 0;
    return CSM_OK;
}

void csm_pci_attach_ecam(csm_pci *pci, csm_ecam_view *view)
{
    if (pci)
        pci->ecam = view;
}

static int ecam_covers(const csm_pci *pci, uint8_t bus)
{
    size_t i;
    if (!pci->ecam)
        return 0;
    for (i = 0; i < pci->ecam->nwindows; ++i) {
        const csm_mcfg_window *w = &pci->ecam->windows[i];
        if (w->segment == 0 && bus >= w->first_bus && bus <= w->last_bus)
            return 1;
    }
    return 0;
}

static csm_pci_function *virtual_lookup(csm_pci *pci, uint8_t bus, uint8_t dev, uint8_t fn)
{
    unsigned i;
    for (i = 0; i < pci->count; ++i)
        if (pci->fn[i].used && pci->fn[i].bus == bus && pci->fn[i].dev == dev && pci->fn[i].fn == fn)
            return &pci->fn[i];
    return 0;
}

static int virtual_bus(const csm_pci *pci, uint8_t bus)
{
    unsigned i;
    for (i = 0; i < pci->count; ++i)
        if (pci->fn[i].used && pci->fn[i].bus == bus)
            return 1;
    return 0;
}

int csm_pci_last_bus(const csm_pci *pci, uint8_t *last)
{
    unsigned i;
    size_t w;
    int known = 0;
    uint8_t high = 0;
    if (!pci || !last)
        return CSM_ERR_ARG;
    for (i = 0; i < pci->count; ++i)
        if (pci->fn[i].used) {
            if (!known || pci->fn[i].bus > high)
                high = pci->fn[i].bus;
            known = 1;
        }
    if (pci->ecam) {
        for (w = 0; w < pci->ecam->nwindows; ++w) {
            const csm_mcfg_window *window = &pci->ecam->windows[w];
            if (window->segment != 0)
                continue;
            if (!known || window->last_bus > high)
                high = window->last_bus;
            known = 1;
        }
    }
    *last = known ? high : 0;
    return known ? CSM_OK : CSM_ERR_NOTFOUND;
}

int csm_ecam_access(csm_ecam_view *view, int write, uint16_t segment, uint8_t bus, uint8_t dev,
                    uint8_t fn, uint16_t offset, uint8_t width, uint32_t *value)
{
    size_t i;
    const csm_mcfg_window *hit = 0;
    uint64_t phys = 0;
    size_t index;
    int st;
    if (!view || !value || !view->mem)
        return CSM_ERR_ARG;
    for (i = 0; i < view->nwindows; ++i) {
        if (bus < view->windows[i].first_bus || bus > view->windows[i].last_bus ||
            segment != view->windows[i].segment)
            continue;
        hit = &view->windows[i];
        break;
    }
    if (!hit)
        return CSM_ERR_RANGE;
    st = csm_ecam_address(hit, segment, bus, dev, fn, offset, width, &phys);
    if (st)
        return st;
    if (view->mem_bytes < width || phys < view->mem_phys ||
        phys - view->mem_phys > view->mem_bytes - width)
        return CSM_ERR_RANGE;
    index = (size_t)(phys - view->mem_phys);
    view->accesses += 1;
    if (write)
        store_le(view->mem + index, width, *value);
    else
        *value = load_le(view->mem + index, width);
    return CSM_OK;
}

int csm_pci_cfg_read(csm_pci *pci, uint8_t bus, uint8_t dev, uint8_t fn, uint16_t offset,
                     uint8_t width, uint32_t *value)
{
    csm_pci_function *slot;
    if (!pci || !value || dev > 31 || fn > 7 || !aligned(offset, width, CSM_PCI_CFG_BYTES))
        return CSM_ERR_ARG;
    if (ecam_covers(pci, bus)) {
        int st = csm_ecam_access(pci->ecam, 0, 0, bus, dev, fn, offset, width, value);
        if (st) {
            pci->range_rejects += 1;
            return st;
        }
        return CSM_OK;
    }
    if (!virtual_bus(pci, bus)) {
        pci->range_rejects += 1;
        return CSM_ERR_RANGE;
    }
    slot = virtual_lookup(pci, bus, dev, fn);
    if (!slot) {
        *value = width == 1 ? 0xffu : width == 2 ? 0xffffu : 0xffffffffu;
        return CSM_OK;
    }
    pci->config_accesses += 1;
    *value = load_le(slot->cfg + offset, width);
    return CSM_OK;
}

int csm_pci_cfg_write(csm_pci *pci, uint8_t bus, uint8_t dev, uint8_t fn, uint16_t offset,
                      uint8_t width, uint32_t value)
{
    csm_pci_function *slot;
    if (!pci || dev > 31 || fn > 7 || !aligned(offset, width, CSM_PCI_CFG_BYTES))
        return CSM_ERR_ARG;
    if (ecam_covers(pci, bus)) {
        int st = csm_ecam_access(pci->ecam, 1, 0, bus, dev, fn, offset, width, &value);
        if (st) {
            pci->range_rejects += 1;
            return st;
        }
        return CSM_OK;
    }
    if (!virtual_bus(pci, bus)) {
        pci->range_rejects += 1;
        return CSM_ERR_RANGE;
    }
    slot = virtual_lookup(pci, bus, dev, fn);
    if (!slot)
        return CSM_ERR_NOTFOUND;
    pci->config_accesses += 1;
    store_le(slot->cfg + offset, width, value);
    return CSM_OK;
}

int csm_pci_cf8_address(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t offset, uint32_t *address)
{
    if (!address || dev > 31 || fn > 7 || offset > 255)
        return CSM_ERR_ARG;
    *address = 0x80000000u | ((uint32_t)bus << 16) | ((uint32_t)dev << 11) | ((uint32_t)fn << 8) |
               (offset & 0xfcu);
    return CSM_OK;
}
