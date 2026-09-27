/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHIZUKUDOS_UEFI32_LAYOUT_H
#define SHIZUKUDOS_UEFI32_LAYOUT_H
#include <stddef.h>
#include <stdint.h>

#define SD32_BASE 0x02000000
#define SD32_REGION_SIZE 0x00200000
#define SD32_MAP 0x02004000
#define SD32_MAP_CAPACITY 0x00008000
#define SD32_HANDOFF 0x0200F000
#define SD32_PAYLOAD 0x02010000
#define SD32_PAYLOAD_LIMIT 0x02100000
#define SD32_STACK_BOTTOM 0x021F0000
#define SD32_STACK_TOP 0x02200000
#define SD32_MAGIC 0x32334453
#define SD32_VERSION 1

/* Fixed-width, pointer-free ABI shared by the x64 loader and i486 payload. */
typedef struct {
    uint32_t magic, version, size, stage;
    uint32_t framebuffer, framebuffer_bytes, width, height, pitch_pixels, pixel_format;
    uint32_t memory_map, map_bytes, descriptor_bytes, descriptor_version;
    uint32_t region_base, region_bytes, payload_bytes, stack_top;
    uint32_t cr0, cr4, efer, cs, ss, esp;
    uint32_t core_pass, graphics_pass, mode_pass, exit_attempted;
} SD32_BOOT;

_Static_assert(sizeof(SD32_BOOT) == 112, "Cross-mode ABI size");
_Static_assert(offsetof(SD32_BOOT, stage) == 12, "Assembly stage offset");
_Static_assert(offsetof(SD32_BOOT, cr0) == 72, "Register snapshot offset");
_Static_assert(offsetof(SD32_BOOT, mode_pass) == 104, "Mode result offset");

int sd32_validate_boot(const SD32_BOOT *boot);
int sd32_validate_mode(const SD32_BOOT *boot);
#endif
