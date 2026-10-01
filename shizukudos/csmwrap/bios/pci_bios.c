/* SPDX-License-Identifier: GPL-2.0-only */
#include "pci_bios.h"

static void pci_result(csm_regs *r, uint8_t ah)
{
    csm_set_ah(r, ah);
    csm_cf(r, ah != CSM_PCI_SUCCESS);
}

static int known_buses(const csm_pci *pci, uint8_t *buses, unsigned *count)
{
    unsigned n = 0, i;
    if (pci->ecam) {
        size_t w;
        for (w = 0; w < pci->ecam->nwindows; ++w) {
            const csm_mcfg_window *window = &pci->ecam->windows[w];
            unsigned bus;
            if (window->segment != 0)
                continue;
            for (bus = window->first_bus;; ++bus) {
                unsigned seen = 0, j;
                for (j = 0; j < n; ++j)
                    if (buses[j] == (uint8_t)bus)
                        seen = 1;
                if (!seen) {
                    if (n >= 256)
                        return CSM_ERR_NOSPACE;
                    buses[n++] = (uint8_t)bus;
                }
                if (bus == window->last_bus)
                    break;
            }
        }
    }
    for (i = 0; i < pci->count; ++i) {
        unsigned seen = 0, j;
        if (!pci->fn[i].used)
            continue;
        for (j = 0; j < n; ++j)
            if (buses[j] == pci->fn[i].bus)
                seen = 1;
        if (!seen) {
            if (n >= 256)
                return CSM_ERR_NOSPACE;
            buses[n++] = pci->fn[i].bus;
        }
    }
    for (i = 1; i < n; ++i) {
        uint8_t key = buses[i];
        unsigned j = i;
        while (j > 0 && buses[j - 1] > key) {
            buses[j] = buses[j - 1];
            --j;
        }
        buses[j] = key;
    }
    *count = n;
    return CSM_OK;
}

static int bus_uses_ecam(const csm_pci *pci, uint8_t bus)
{
    size_t w;
    if (!pci->ecam)
        return 0;
    for (w = 0; w < pci->ecam->nwindows; ++w) {
        const csm_mcfg_window *window = &pci->ecam->windows[w];
        if (window->segment == 0 && bus >= window->first_bus && bus <= window->last_bus)
            return 1;
    }
    return 0;
}

static int virtual_has(const csm_pci *pci, uint8_t bus, uint8_t dev, uint8_t fn)
{
    unsigned i;
    for (i = 0; i < pci->count; ++i)
        if (pci->fn[i].used && pci->fn[i].bus == bus && pci->fn[i].dev == dev && pci->fn[i].fn == fn)
            return 1;
    return 0;
}

static int read_id_class(csm_pci *pci, uint8_t bus, uint8_t dev, uint8_t fn, uint32_t *id,
                         uint32_t *class_rev, int *present)
{
    int st = csm_pci_cfg_read(pci, bus, dev, fn, 0, 4, id);
    *present = 0;
    if (st)
        return st;
    if ((*id & 0xffffu) == 0xffffu)
        return CSM_OK;
    st = csm_pci_cfg_read(pci, bus, dev, fn, 8, 4, class_rev);
    if (st)
        return st;
    *present = 1;
    return CSM_OK;
}

typedef struct csm_hit {
    uint8_t bus, dev, fn;
} csm_hit;

static int scan_for(csm_pci *pci, int by_class, uint32_t want_class, uint16_t want_vendor,
                    uint16_t want_device, unsigned index, csm_hit *hit)
{
    uint8_t buses[256];
    unsigned nbuses = 0, matches = 0, bi, dev, fn;
    int st = known_buses(pci, buses, &nbuses);
    if (st)
        return st;
    for (bi = 0; bi < nbuses; ++bi) {
        uint8_t bus = buses[bi];
        int ecam = bus_uses_ecam(pci, bus);
        for (dev = 0; dev < 32; ++dev) {
            unsigned functions = 1;
            for (fn = 0; fn < functions; ++fn) {
                uint32_t id = 0xffffffffu, class_rev = 0, header = 0;
                int present = 0, matched;
                if (ecam || virtual_has(pci, bus, (uint8_t)dev, (uint8_t)fn)) {
                    st = read_id_class(pci, bus, (uint8_t)dev, (uint8_t)fn, &id, &class_rev, &present);
                    if (st)
                        return st;
                }
                if (present && fn == 0) {
                    st = csm_pci_cfg_read(pci, bus, (uint8_t)dev, 0, 0x0c, 4, &header);
                    if (st)
                        return st;
                    if (((header >> 16) & 0x80u) != 0)
                        functions = 8;
                }
                if (!present)
                    continue;
                if (by_class)
                    matched = ((class_rev >> 8) & 0xffffffu) == (want_class & 0xffffffu);
                else
                    matched = (uint16_t)id == want_vendor && (uint16_t)(id >> 16) == want_device;
                if (!matched)
                    continue;
                if (matches == index) {
                    hit->bus = bus;
                    hit->dev = (uint8_t)dev;
                    hit->fn = (uint8_t)fn;
                    return CSM_OK;
                }
                matches += 1;
            }
        }
    }
    return CSM_ERR_NOTFOUND;
}

static void return_bdf(csm_regs *r, const csm_hit *hit)
{
    uint16_t bx = (uint16_t)(((uint16_t)hit->bus << 8) | ((uint16_t)hit->dev << 3) | hit->fn);
    r->ebx = (r->ebx & 0xffff0000u) | bx;
    pci_result(r, CSM_PCI_SUCCESS);
}

static int install_check(csm_regs *r, csm_pci *pci)
{
    uint8_t last = 0;
    (void)csm_pci_last_bus(pci, &last);
    csm_set_ah(r, 0);
    csm_set_al(r, 0x01);
    r->ebx = (r->ebx & 0xffff0000u) | 0x0210u;
    r->ecx = (r->ecx & 0xffffff00u) | last;
    r->edx = 0x20494350u;
    r->edi = 0;
    csm_cf(r, 0);
    return CSM_INT_OK;
}

static int find_device(csm_regs *r, csm_pci *pci)
{
    csm_hit hit;
    uint16_t vendor = (uint16_t)r->edx;
    uint16_t device = (uint16_t)r->ecx;
    unsigned index = r->esi & 0xffffu;
    int st;
    if (vendor == 0xffffu) {
        pci_result(r, CSM_PCI_BAD_VENDOR);
        return CSM_INT_ERROR;
    }
    st = scan_for(pci, 0, 0, vendor, device, index, &hit);
    if (st) {
        pci_result(r, CSM_PCI_NOT_FOUND);
        return CSM_INT_ERROR;
    }
    return_bdf(r, &hit);
    return CSM_INT_OK;
}

static int find_class(csm_regs *r, csm_pci *pci)
{
    csm_hit hit;
    unsigned index = r->esi & 0xffffu;
    int st = scan_for(pci, 1, r->ecx, 0, 0, index, &hit);
    if (st) {
        pci_result(r, CSM_PCI_NOT_FOUND);
        return CSM_INT_ERROR;
    }
    return_bdf(r, &hit);
    return CSM_INT_OK;
}

static int split_bdf(const csm_regs *r, uint8_t *bus, uint8_t *dev, uint8_t *fn)
{
    uint16_t bx = (uint16_t)r->ebx;
    *bus = (uint8_t)(bx >> 8);
    *dev = (uint8_t)((bx >> 3) & 0x1f);
    *fn = (uint8_t)(bx & 0x7);
    return CSM_OK;
}

static int config_io(csm_regs *r, csm_pci *pci, uint8_t width, int write)
{
    uint8_t bus, dev, fn;
    uint16_t offset = (uint16_t)r->edi;
    uint32_t value;
    int st;
    split_bdf(r, &bus, &dev, &fn);
    if (offset > 255 || (offset % width) != 0) {
        pci_result(r, CSM_PCI_BAD_REGISTER);
        return CSM_INT_ERROR;
    }
    if (write) {
        value = r->ecx;
        st = csm_pci_cfg_write(pci, bus, dev, fn, offset, width, value);
        if (st) {
            pci_result(r, CSM_PCI_NOT_FOUND);
            return CSM_INT_ERROR;
        }
        pci_result(r, CSM_PCI_SUCCESS);
        return CSM_INT_OK;
    }
    st = csm_pci_cfg_read(pci, bus, dev, fn, offset, width, &value);
    if (st) {
        pci_result(r, CSM_PCI_NOT_FOUND);
        return CSM_INT_ERROR;
    }
    if (width == 1)
        r->ecx = (r->ecx & 0xffffff00u) | (value & 0xffu);
    else if (width == 2)
        r->ecx = (r->ecx & 0xffff0000u) | (value & 0xffffu);
    else
        r->ecx = value;
    pci_result(r, CSM_PCI_SUCCESS);
    return CSM_INT_OK;
}

int csm_pci_bios(csm_regs *r, csm_pci *pci)
{
    if (!r)
        return CSM_ERR_ARG;
    if (csm_ah(r) != 0xb1) {
        pci_result(r, CSM_PCI_UNSUPPORTED);
        return CSM_INT_ERROR;
    }
    if (!pci) {
        pci_result(r, CSM_PCI_UNSUPPORTED);
        return CSM_INT_ERROR;
    }
    switch (csm_al(r)) {
    case 0x01:
        return install_check(r, pci);
    case 0x02:
        return find_device(r, pci);
    case 0x03:
        return find_class(r, pci);
    case 0x08:
        return config_io(r, pci, 1, 0);
    case 0x09:
        return config_io(r, pci, 2, 0);
    case 0x0a:
        return config_io(r, pci, 4, 0);
    case 0x0b:
        return config_io(r, pci, 1, 1);
    case 0x0c:
        return config_io(r, pci, 2, 1);
    case 0x0d:
        return config_io(r, pci, 4, 1);
    default:
        pci_result(r, CSM_PCI_UNSUPPORTED);
        return CSM_INT_ERROR;
    }
}
