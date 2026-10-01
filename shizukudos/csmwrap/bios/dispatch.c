/* SPDX-License-Identifier: GPL-2.0-only
 * Interrupt skeleton. Sibling modules register INT 10/11/12/13/15/16/1A and the
 * PCI installation check. This file does not define those services, so the core
 * still links when they are absent. An unregistered UEFI service returns CF=1.
 * Native BIOS/CSM does not virtualize the vector: the original handler stays.
 */
#include "../include/csmwrap_abi.h"

static void note_vector(uint8_t vector)
{
    char line[24];
    unsigned n = 0;
    const char *prefix = "CSMWRAP INT ";
    while (prefix[n]) {
        line[n] = prefix[n];
        ++n;
    }
    line[n++] = "0123456789ABCDEF"[(vector >> 4) & 15];
    line[n++] = "0123456789ABCDEF"[vector & 15];
    line[n++] = '\n';
    line[n] = 0;
    csmwrap_diag_note(line);
}

void csmwrap_dispatch(uint32_t firmware_mode, uint8_t vector, csmwrap_regs *regs)
{
    csmwrap_service_fn fn;
    int native;
    if (!regs)
        return;
    note_vector(vector);
    regs->vector = vector;
    regs->passthrough = 0;
    native = firmware_mode == CSMWRAP_MODE_NATIVE_BIOS;
    if (vector == CSMWRAP_SVC_INT1A && (regs->eax & 0xffffu) == CSMWRAP_SVC_PCI_INSTALL) {
        fn = csmwrap_pci_install_fn();
        if (fn) {
            fn(regs);
            return;
        }
    } else {
        fn = csmwrap_service_slot(vector);
        if (fn) {
            fn(regs);
            return;
        }
    }
    if (native) {
        regs->passthrough = 1;
        return;
    }
    csmwrap_set_cf(regs, 1);
}
