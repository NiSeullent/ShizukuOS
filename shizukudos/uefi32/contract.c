/* SPDX-License-Identifier: GPL-2.0-only */
#include "layout.h"

int sd32_validate_boot(const SD32_BOOT *b)
{
    uint64_t pixels;
    if (!b || b->magic != SD32_MAGIC || b->version != SD32_VERSION ||
        b->size != sizeof(*b) || b->region_base != SD32_BASE ||
        b->region_bytes != SD32_REGION_SIZE || b->stack_top != SD32_STACK_TOP ||
        !b->payload_bytes || b->payload_bytes > SD32_PAYLOAD_LIMIT - SD32_PAYLOAD ||
        b->memory_map != SD32_MAP || !b->map_bytes || b->map_bytes > SD32_MAP_CAPACITY ||
        b->descriptor_bytes < 40 || (b->descriptor_bytes & 7) ||
        b->map_bytes % b->descriptor_bytes || b->descriptor_version != 1)
        return 0;
    if (!b->framebuffer || (b->framebuffer & 3) || b->width < 640 || b->height < 400 ||
        b->pitch_pixels < b->width || b->pitch_pixels > UINT32_MAX / 4 ||
        b->pixel_format > 1 || !b->framebuffer_bytes ||
        b->framebuffer > UINT32_MAX - b->framebuffer_bytes)
        return 0;
    pixels = (uint64_t)b->pitch_pixels * b->height;
    return pixels <= UINT32_MAX / 4 && pixels * 4 <= b->framebuffer_bytes;
}

int sd32_validate_mode(const SD32_BOOT *b)
{
    return b && (b->cr0 & 1) && !(b->cr0 & UINT32_C(0x80000000)) &&
        !(b->cr4 & UINT32_C(0x00021020)) && !(b->efer & UINT32_C(0x500)) &&
        b->cs == 0x10 && b->ss == 0x18 &&
        b->esp >= SD32_STACK_BOTTOM && b->esp < SD32_STACK_TOP;
}
