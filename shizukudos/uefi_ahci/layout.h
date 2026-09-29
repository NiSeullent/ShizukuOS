/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SDAHCI_LAYOUT_H
#define SDAHCI_LAYOUT_H
#include "../uefi32/layout.h"
#define SDAHCI_RECORD 0x0200f100
#define SDAHCI_MAGIC UINT32_C(0x49434841)
typedef struct {
    uint32_t magic, size, calibrated, ticks_per_us;
    uint64_t start_tsc;
    uint32_t stage, pci_bdf, abar, open_result, read_result, close_result;
    uint32_t sectors_low, sectors_high, bytes_verified, mismatch;
    uint32_t last_is, last_tfd, last_serr, quarantine;
} SDAHCI_PROOF;
_Static_assert(sizeof(SDAHCI_PROOF) == 80, "fixed AHCI proof wire layout");
uint64_t sdahci_divide(uint64_t value, uint32_t divisor);
#endif
