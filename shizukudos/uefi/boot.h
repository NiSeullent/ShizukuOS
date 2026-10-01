/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHIZUKUDOS_BOOT_H
#define SHIZUKUDOS_BOOT_H
#include "efi.h"
#define SD_HANDOFF_MAGIC UINT64_C(0x3149464544534853)
#define SD_HANDOFF_VERSION 1
#define SD_MAP_LIMIT (16u * 1024u * 1024u)
#define SD_EXIT_ATTEMPTS 8
#define SD_GOP_MODE_LIMIT 1024u
#define SD_GOP_VISIBLE_LIMIT (UINT64_C(64) * 1024 * 1024)

typedef struct {
    uint64_t base, size;
    uint32_t width, height, pitch_pixels, pixel_format;
} SD_FRAMEBUFFER;

typedef struct {
    uint32_t original_mode, selected_mode, modes_queried, edid_preferred;
    uint32_t preferred_width, preferred_height, used_fallback;
} SD_GOP_SELECTION;

/* The loader's image/stack/map remain reserved until a successor owns them.
 * This structure and the descriptor stream live in allocated LoaderData.
 * Descriptor stride is firmware supplied, never assumed to equal sizeof().
 */
typedef struct {
    uint64_t magic;
    uint32_t version, size;
    SD_FRAMEBUFFER framebuffer;
    EFI_MEMORY_DESCRIPTOR *memory_map;
    size_t map_capacity, map_size, map_key, descriptor_size;
    uint32_t descriptor_version, exit_attempted, boot_services_exited;
    uint32_t exit_calls;
    void *acpi_rsdp;
    uint64_t conventional_pages;
} SD_HANDOFF;

EFI_STATUS sd_framebuffer_snapshot(const EFI_GOP_MODE *, SD_FRAMEBUFFER *);
/* Before memory-map acquisition/ExitBootServices only. Never retains firmware pointers.
 * EDID is considered only on the handle providing this exact GOP instance. */
EFI_STATUS sd_gop_select(EFI_BOOT_SERVICES *, EFI_GOP *, SD_FRAMEBUFFER *, SD_GOP_SELECTION *);
EFI_STATUS sd_validate_map(SD_HANDOFF *);
EFI_STATUS sd_exit_boot_services(EFI_BOOT_SERVICES *, EFI_HANDLE, SD_HANDOFF *);
void sd_framebuffer_result(const SD_HANDOFF *, int success);
void sd_framebuffer_kernel_result(const SD_HANDOFF *, int success);
void sd_framebuffer_pci_result(const SD_HANDOFF *, int success);
#endif
