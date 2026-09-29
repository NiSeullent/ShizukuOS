/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SDFAT_LAYOUT_H
#define SDFAT_LAYOUT_H
#include <stddef.h>
#include "../uefi32/layout.h"
#include "../../drivers/fat_native/fat.h"
#define SDFAT_RECORD 0x0200f100
#define SDFAT_MAGIC UINT32_C(0x54414653)
#define SDFAT_VERSION 1u
#define SDFAT_GUARD_BEFORE 0x020ff000
#define SDFAT_DESTINATION 0x02100000
#define SDFAT_CAPACITY 524288u
#define SDFAT_GUARD_AFTER 0x02180000
#define SDFAT_GUARD_BYTES 4096u
#define SDFAT_SENTINEL 0xa5u
#define SDFAT_DISK_SECTORS 131072u
#define SDFAT_COMMAND_TIMEOUT_US 10000u
#define SDFAT_READ_RESERVE_US 1200000u
/* Pointer-free retained evidence; negative status values use signed u32 bits. */
typedef struct {
    uint32_t magic, size, version, stage;
    uint32_t calibrated, ticks_per_us, clock_fault, clock_stagnant;
    uint64_t start_tsc, clock_last_tsc, file_start_us, file_end_us;
    uint32_t pci_bdf, abar, pci_original, pci_restored;
    uint32_t open_result, fat_result, read_result, close_result;
    uint32_t sectors_low, sectors_high, sector_bytes, port;
    uint32_t dma_address, dma_bytes, allocations, releases;
    uint32_t quarantine, sector_reads, last_lba_low, last_lba_high;
    uint32_t destination, capacity, guard_before, guard_after;
    uint32_t guard_bytes, guards_pass, read_refusals, read_overruns;
    struct ntwf_file_info info;
} SDFAT_PROOF;
_Static_assert(sizeof(SDFAT_PROOF) == 256, "FAT proof wire size");
_Static_assert(offsetof(SDFAT_PROOF, start_tsc) == 32, "Clock evidence offset");
_Static_assert(offsetof(SDFAT_PROOF, pci_bdf) == 64, "PCI evidence offset");
_Static_assert(offsetof(SDFAT_PROOF, info) == 176, "File metadata offset");
_Static_assert(sizeof(struct ntwf_workspace) == 530176, "Workspace reservation");
_Static_assert(SDFAT_RECORD >= SD32_HANDOFF + sizeof(SD32_BOOT) &&
               SDFAT_RECORD + sizeof(SDFAT_PROOF) <= SD32_PAYLOAD,
               "Proof separated from handoff and payload");
_Static_assert(SDFAT_GUARD_BEFORE + SDFAT_GUARD_BYTES == SDFAT_DESTINATION &&
               SDFAT_DESTINATION + SDFAT_CAPACITY == SDFAT_GUARD_AFTER &&
               SDFAT_GUARD_AFTER + SDFAT_GUARD_BYTES <= SD32_STACK_TOP - 65536 &&
               SD32_STACK_TOP == SD32_BASE + SD32_REGION_SIZE,
               "Guarded destination and stack fit EFI reservation");
#endif
