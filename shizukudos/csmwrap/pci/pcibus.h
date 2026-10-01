/* SPDX-License-Identifier: GPL-2.0-only
 * PCI config backends: a virtual function table, and an ECAM window
 * when the caller supplies MCFG windows plus the bytes of that window.
 * Buses outside both sets are rejected before any config byte is read.
 * Mechanism #1 (0xCF8) is address arithmetic only.
 */
#ifndef CSMWRAP_PCIBUS_H
#define CSMWRAP_PCIBUS_H
#include "mcfg.h"
#include <stddef.h>
#include <stdint.h>

#define CSM_PCI_MAX_FUNCTIONS 48
#define CSM_PCI_CFG_BYTES 256

typedef struct csm_ecam_view {
    uint64_t mem_phys;
    uint8_t *mem;
    size_t mem_bytes;
    const csm_mcfg_window *windows;
    size_t nwindows;
    uint32_t accesses;
} csm_ecam_view;

typedef struct csm_pci_function {
    uint8_t bus, dev, fn, used;
    uint8_t cfg[CSM_PCI_CFG_BYTES];
} csm_pci_function;

typedef struct csm_pci {
    csm_pci_function fn[CSM_PCI_MAX_FUNCTIONS];
    unsigned count;
    csm_ecam_view *ecam;
    uint32_t config_accesses;
    uint32_t range_rejects;
} csm_pci;

void csm_pci_init(csm_pci *pci);
int csm_pci_add(csm_pci *pci, uint8_t bus, uint8_t dev, uint8_t fn,
                uint16_t vendor, uint16_t device, uint8_t base_class,
                uint8_t subclass, uint8_t prog_if);
void csm_pci_attach_ecam(csm_pci *pci, csm_ecam_view *view);
int csm_pci_last_bus(const csm_pci *pci, uint8_t *last);

int csm_pci_cfg_read(csm_pci *pci, uint8_t bus, uint8_t dev, uint8_t fn,
                     uint16_t offset, uint8_t width, uint32_t *value);
int csm_pci_cfg_write(csm_pci *pci, uint8_t bus, uint8_t dev, uint8_t fn,
                      uint16_t offset, uint8_t width, uint32_t value);

int csm_ecam_access(csm_ecam_view *view, int write, uint16_t segment, uint8_t bus,
                    uint8_t dev, uint8_t fn, uint16_t offset, uint8_t width,
                    uint32_t *value);

/* dev > 31, fn > 7, or offset > 255 fails and does not write *address. */
int csm_pci_cf8_address(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t offset,
                        uint32_t *address);
#endif
