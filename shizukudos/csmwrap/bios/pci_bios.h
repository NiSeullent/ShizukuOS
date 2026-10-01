/* SPDX-License-Identifier: GPL-2.0-only
 * PCI BIOS 2.1 services entered through INT 1Ah AH=B1h.
 * Return codes match the specification (AH, CF).
 */
#ifndef CSMWRAP_PCI_BIOS_H
#define CSMWRAP_PCI_BIOS_H
#include "pcibus.h"
#include "regs.h"

enum {
    CSM_PCI_SUCCESS = 0x00,
    CSM_PCI_UNSUPPORTED = 0x81,
    CSM_PCI_BAD_VENDOR = 0x83,
    CSM_PCI_NOT_FOUND = 0x86,
    CSM_PCI_BAD_REGISTER = 0x87
};

int csm_pci_bios(csm_regs *r, csm_pci *pci);
#endif
