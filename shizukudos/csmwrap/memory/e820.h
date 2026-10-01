/* SPDX-License-Identifier: GPL-2.0-only
 * UEFI GetMemoryMap descriptors to ACPI E820, after ExitBootServices.
 *
 * Type rules:
 *   usable (1):      LoaderCode, LoaderData, BootServicesCode,
 *                    BootServicesData, ConventionalMemory
 *   reserved (2):    Reserved, RuntimeServicesCode, RuntimeServicesData,
 *                    PalCode, PersistentMemory, Unaccepted, unknown
 *   ACPI reclaim (3): ACPIReclaimMemory
 *   ACPI NVS (4):    ACPIMemoryNVS
 *   unusable (5):    UnusableMemory
 *   omitted:         MemoryMappedIO, MemoryMappedIOPortSpace,
 *                    and any overlap of the caller-supplied framebuffer
 *
 * Output is sorted by base, adjacent equal types are merged, and a
 * different type that overlaps is rejected. Gaps stay absent.
 */
#ifndef CSMWRAP_E820_H
#define CSMWRAP_E820_H
#include <stddef.h>
#include <stdint.h>

enum {
    CSM_E820_USABLE = 1,
    CSM_E820_RESERVED = 2,
    CSM_E820_ACPI = 3,
    CSM_E820_NVS = 4,
    CSM_E820_UNUSABLE = 5
};

enum {
    CSM_EFI_RESERVED = 0,
    CSM_EFI_LOADER_CODE = 1,
    CSM_EFI_LOADER_DATA = 2,
    CSM_EFI_BOOT_CODE = 3,
    CSM_EFI_BOOT_DATA = 4,
    CSM_EFI_RUNTIME_CODE = 5,
    CSM_EFI_RUNTIME_DATA = 6,
    CSM_EFI_CONVENTIONAL = 7,
    CSM_EFI_UNUSABLE = 8,
    CSM_EFI_ACPI_RECLAIM = 9,
    CSM_EFI_ACPI_NVS = 10,
    CSM_EFI_MMIO = 11,
    CSM_EFI_MMIO_PORT = 12,
    CSM_EFI_PAL = 13,
    CSM_EFI_PERSISTENT = 14,
    CSM_EFI_UNACCEPTED = 15
};

typedef struct csm_uefi_memory {
    uint32_t type;
    uint32_t pad;
    uint64_t physical_start;
    uint64_t virtual_start;
    uint64_t pages;
    uint64_t attributes;
} csm_uefi_memory;

typedef struct csm_e820_entry {
    uint64_t base;
    uint64_t length;
    uint32_t type;
    uint32_t attributes;
} csm_e820_entry;

typedef struct csm_range {
    uint64_t base;
    uint64_t size;
} csm_range;

/* descriptor_size may be larger than 40; only the UEFI prefix is read.
 * On CSM_ERR_NOSPACE, *written is the required count and out is unchanged.
 * framebuffer may be NULL. A zero size excludes nothing. */
int csm_uefi_to_e820(const void *descriptors, size_t count, size_t descriptor_size,
                     const csm_range *framebuffer, csm_e820_entry *out, size_t capacity,
                     size_t *written);

/* KB of usable memory that starts at physical 0 and stays below 0xA0000.
 * *found is 1 when such a range exists. A NULL map reports the platform
 * default (639) and sets *found to 0. */
uint16_t csm_e820_conventional_kb(const csm_e820_entry *map, size_t count, int *found);

/* Contiguous KB at 0x100000, capped at 0xFC00. Returns 0 when that
 * address is not the start of a usable entry. */
uint16_t csm_e820_extended_kb(const csm_e820_entry *map, size_t count, int *present);
#endif
