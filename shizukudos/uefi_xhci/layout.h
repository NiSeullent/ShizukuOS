/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SDXHCI_LAYOUT_H
#define SDXHCI_LAYOUT_H
#include "../uefi32/layout.h"
#define SDXHCI_RECORD 0x0200f100
#define SDXHCI_MAGIC UINT32_C(0x49434858)
typedef struct {
    uint32_t magic, size, calibrated, ticks_per_us;
    uint64_t start_tsc;
    uint32_t stage, pci_bdf, mmio, open_result, command_result, close_result;
    uint32_t commands_completed, bridges, port_events, completion_low, completion_high;
    uint32_t last_status, last_completion_code, quarantine;
} SDXHCI_PROOF;
_Static_assert(sizeof(SDXHCI_PROOF) == 80, "fixed xHCI proof wire layout");
uint64_t sdxhci_divide(uint64_t value, uint32_t divisor);
#endif
