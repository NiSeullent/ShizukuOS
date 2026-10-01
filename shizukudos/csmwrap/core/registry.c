/* SPDX-License-Identifier: GPL-2.0-only */
#include "../include/csmwrap_abi.h"

static csmwrap_service_fn services[8];
static csmwrap_service_fn pci_install;

static int slot_for(uint32_t id)
{
    switch (id) {
    case CSMWRAP_SVC_INT10: return 0;
    case CSMWRAP_SVC_INT11: return 1;
    case CSMWRAP_SVC_INT12: return 2;
    case CSMWRAP_SVC_INT13: return 3;
    case CSMWRAP_SVC_INT15: return 4;
    case CSMWRAP_SVC_INT16: return 5;
    case CSMWRAP_SVC_INT1A: return 6;
    default: return -1;
    }
}

int csmwrap_register_service(uint32_t id, csmwrap_service_fn fn)
{
    int slot;
    if (!fn)
        return -1;
    if (id == CSMWRAP_SVC_PCI_INSTALL) {
        pci_install = fn;
        return 0;
    }
    slot = slot_for(id);
    if (slot < 0)
        return -1;
    services[slot] = fn;
    return 0;
}

void csmwrap_set_cf(csmwrap_regs *regs, int failed)
{
    if (!regs)
        return;
    if (failed)
        regs->eflags |= 1u;
    else
        regs->eflags &= ~1u;
}

csmwrap_service_fn csmwrap_service_slot(uint8_t vector)
{
    switch (vector) {
    case CSMWRAP_SVC_INT10: return services[0];
    case CSMWRAP_SVC_INT11: return services[1];
    case CSMWRAP_SVC_INT12: return services[2];
    case CSMWRAP_SVC_INT13: return services[3];
    case CSMWRAP_SVC_INT15: return services[4];
    case CSMWRAP_SVC_INT16: return services[5];
    case CSMWRAP_SVC_INT1A: return services[6];
    default: return 0;
    }
}

csmwrap_service_fn csmwrap_pci_install_fn(void)
{
    return pci_install;
}
