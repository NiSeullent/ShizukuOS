/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SDUSB_LAYOUT_H
#define SDUSB_LAYOUT_H
#include "../uefi32/layout.h"
#include "../../drivers/xhci_usb/xhci_usb.h"
#define SDUSB_RECORD 0x0200f100
#define SDUSB_MAGIC UINT32_C(0x30425355)
#define SDUSB_VERSION 1u
typedef struct {
    uint32_t magic, size, version, calibrated, ticks_per_us, reserved0;
    uint64_t start_tsc;
    uint32_t stage, pci_bdf, mmio, bridges;
    uint32_t open_result, probe_status, transport_error, parser_status;
    uint32_t failed_stage, parser_offset, close_result;
    uint32_t controller_dma_owned, device_dma_owned, allocations, releases;
    uint32_t commands_completed, port_events, last_status, last_completion_code;
    uint32_t completion_low, completion_high, dma_in_use_mask;
    uint32_t original_pci_command, restored_pci_command;
    uint32_t command_index, command_cycle, event_index, event_cycle;
    uint32_t dma_address, device_dma_address, descriptor_bytes, reserved1;
    struct xhciu_descriptor descriptor;
    uint32_t reserved[3];
} SDUSB_PROOF;
_Static_assert(sizeof(struct xhciu_descriptor) == 84, "USB descriptor proof ABI");
_Static_assert(offsetof(SDUSB_PROOF, start_tsc) == 24, "USB clock proof ABI");
_Static_assert(offsetof(SDUSB_PROOF, descriptor) == 160, "USB descriptor proof offset");
_Static_assert(sizeof(SDUSB_PROOF) == 256, "USB proof wire layout");
uint64_t sdxhci_divide(uint64_t value, uint32_t divisor);
#endif
