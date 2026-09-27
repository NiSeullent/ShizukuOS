/* SPDX-License-Identifier: GPL-2.0-only
 * Original ShizukuDOS UEFI memory ownership transition and framebuffer logic.
 */
#include "boot.h"

EFI_STATUS sd_framebuffer_snapshot(const EFI_GOP_MODE *mode, SD_FRAMEBUFFER *out)
{
    const EFI_GOP_INFO *i;
    uint64_t needed;
    if (!mode || !out || !mode->info || mode->info_size < sizeof(EFI_GOP_INFO))
        return EFI_INVALID_PARAMETER;
    i = mode->info;
    /* Only direct, documented 32-bit RGB/BGR layouts are implemented. */
    if (i->version != 0 || i->pixel_format > 1)
        return EFI_UNSUPPORTED;
    if (i->width < 320 || i->height < 200 || i->pixels_per_scan_line < i->width ||
        !mode->framebuffer_base || (mode->framebuffer_base & 3))
        return EFI_INVALID_PARAMETER;
    needed = (uint64_t)i->pixels_per_scan_line * i->height;
    if (needed > UINT64_MAX / 4)
        return EFI_INVALID_PARAMETER;
    needed *= 4;
    if (needed > mode->framebuffer_size ||
        mode->framebuffer_base > UINT64_MAX - mode->framebuffer_size)
        return EFI_INVALID_PARAMETER;
    out->base = mode->framebuffer_base;
    out->size = mode->framebuffer_size;
    out->width = i->width;
    out->height = i->height;
    out->pitch_pixels = i->pixels_per_scan_line;
    out->pixel_format = i->pixel_format;
    return EFI_SUCCESS;
}

EFI_STATUS sd_validate_map(SD_HANDOFF *h)
{
    size_t offset;
    uint64_t pages = 0;
    if (!h || !h->memory_map || h->descriptor_version != 1 ||
        h->descriptor_size < sizeof(EFI_MEMORY_DESCRIPTOR) ||
        (h->descriptor_size & 7) || !h->map_size ||
        h->map_size > h->map_capacity || h->map_size % h->descriptor_size)
        return EFI_INVALID_PARAMETER;
    for (offset = 0; offset < h->map_size; offset += h->descriptor_size) {
        const EFI_MEMORY_DESCRIPTOR *d = (const EFI_MEMORY_DESCRIPTOR *)
            ((const uint8_t *)h->memory_map + offset);
        if ((d->physical_start & 4095) || !d->pages ||
            d->pages > (UINT64_MAX - d->physical_start) / 4096)
            return EFI_INVALID_PARAMETER;
        if (d->type == 7) {
            if (pages > UINT64_MAX - d->pages)
                return EFI_INVALID_PARAMETER;
            pages += d->pages;
        }
    }
    h->conventional_pages = pages;
    return EFI_SUCCESS;
}

EFI_STATUS sd_exit_boot_services(EFI_BOOT_SERVICES *bs, EFI_HANDLE image, SD_HANDOFF *h)
{
    EFI_STATUS status;
    size_t attempts, wanted = 0, key = 0, stride = 0;
    uint32_t version = 0;
    if (!bs || !h || h->memory_map || !bs->get_memory_map ||
        !bs->allocate_pool || !bs->free_pool || !bs->exit_boot_services)
        return EFI_INVALID_PARAMETER;
    status = bs->get_memory_map(&wanted, 0, &key, &stride, &version);
    if (status != EFI_BUFFER_TOO_SMALL)
        return EFI_ERROR(status) ? status : EFI_DEVICE_ERROR;
    /* Capacity is capped, with a full page plus descriptor slack for allocations.
     * Reallocation is allowed only before the first exit attempt. */
    for (attempts = 0; attempts < SD_EXIT_ATTEMPTS; ++attempts) {
        if (wanted > SD_MAP_LIMIT || stride > 4096 ||
            wanted > SD_MAP_LIMIT - 4096 - 32 * stride)
            return EFI_OUT_OF_RESOURCES;
        h->map_capacity = wanted + 4096 + 32 * stride;
        status = bs->allocate_pool(EFI_LOADER_DATA, h->map_capacity,
                                   (void **)&h->memory_map);
        if (EFI_ERROR(status))
            return status;
        h->map_size = h->map_capacity;
        status = bs->get_memory_map(&h->map_size, h->memory_map, &h->map_key,
                                    &h->descriptor_size, &h->descriptor_version);
        if (status != EFI_BUFFER_TOO_SMALL)
            break;
        wanted = h->map_size;
        stride = h->descriptor_size;
        bs->free_pool(h->memory_map);
        h->memory_map = 0;
    }
    if (status == EFI_BUFFER_TOO_SMALL)
        return EFI_OUT_OF_RESOURCES;
    if (EFI_ERROR(status))
        return status;
    for (attempts = 0; attempts < SD_EXIT_ATTEMPTS; ++attempts) {
        status = sd_validate_map(h);
        if (EFI_ERROR(status))
            return status;
        /* No firmware call, allocation, console output or logging may intervene. */
        h->exit_attempted = 1;
        ++h->exit_calls;
        status = bs->exit_boot_services(image, h->map_key);
        if (!EFI_ERROR(status)) {
            h->boot_services_exited = 1;
            return EFI_SUCCESS;
        }
        if (status != EFI_INVALID_PARAMETER)
            return status;
        /* Firmware may already be partially shut down: only refresh the map.
         * If the preallocated reserve is insufficient, halt rather than calling
         * protocol functions, returning to firmware, or assuming ownership. */
        h->map_size = h->map_capacity;
        status = bs->get_memory_map(&h->map_size, h->memory_map, &h->map_key,
                                    &h->descriptor_size, &h->descriptor_version);
        if (EFI_ERROR(status))
            return status;
    }
    return EFI_ABORTED;
}

static uint32_t sd_pixel(const SD_FRAMEBUFFER *f, uint32_t rgb)
{
    return f->pixel_format == 1 ? rgb :
        ((rgb & 255) << 16) | (rgb & 0xff00) | ((rgb >> 16) & 255);
}

static void sd_rect(const SD_FRAMEBUFFER *f, uint32_t x, uint32_t y,
                    uint32_t w, uint32_t h, uint32_t rgb)
{
    uint32_t xx, yy, color = sd_pixel(f, rgb);
    volatile uint32_t *pixels = (volatile uint32_t *)(uintptr_t)f->base;
    if (x >= f->width || y >= f->height)
        return;
    if (w > f->width - x) w = f->width - x;
    if (h > f->height - y) h = f->height - y;
    for (yy = 0; yy < h; ++yy)
        for (xx = 0; xx < w; ++xx)
            pixels[(size_t)(y + yy) * f->pitch_pixels + x + xx] = color;
}

/* Independently drawn 5-by-7 block capitals; no external font data. */
static const uint8_t sd_letters[26][7] = {
    {14,17,17,31,17,17,17}, {30,17,17,30,17,17,30},
    {14,17,16,16,16,17,14}, {30,17,17,17,17,17,30},
    {31,16,16,30,16,16,31}, {31,16,16,30,16,16,16},
    {14,17,16,23,17,17,15}, {17,17,17,31,17,17,17},
    {31,4,4,4,4,4,31}, {7,2,2,2,18,18,12},
    {17,18,20,24,20,18,17}, {16,16,16,16,16,16,31},
    {17,27,21,21,17,17,17}, {17,25,25,21,19,19,17},
    {14,17,17,17,17,17,14}, {30,17,17,30,16,16,16},
    {14,17,17,17,21,18,13}, {30,17,17,30,20,18,17},
    {15,16,16,14,1,1,30}, {31,4,4,4,4,4,4},
    {17,17,17,17,17,17,14}, {17,17,17,17,17,10,4},
    {17,17,17,21,21,27,17}, {17,17,10,4,10,17,17},
    {17,17,10,4,4,4,4}, {31,1,2,4,8,16,31}
};
static const uint8_t sd_nine[7] = {14,17,17,15,1,1,14};
static const uint8_t sd_zero[7] = {14,17,19,21,25,17,14};
static const uint8_t sd_eight[7] = {14,17,17,14,17,17,14};

static void sd_text(const SD_FRAMEBUFFER *f, uint32_t y, const char *text)
{
    uint32_t x = 32, row, col;
    while (*text && x + 10 < f->width) {
        unsigned char c = (unsigned char)*text++;
        const uint8_t *glyph = c == '9' ? sd_nine : c == '0' ? sd_zero :
            c == '8' ? sd_eight :
            c >= 'A' && c <= 'Z' ? sd_letters[c - 'A'] : 0;
        if (glyph)
            for (row = 0; row < 7; ++row)
                for (col = 0; col < 5; ++col)
                    if (glyph[row] & (16u >> col))
                        sd_rect(f, x + col * 2, y + row * 2, 2, 2, 0xffffff);
        if (c == '_') sd_rect(f, x, y + 12, 10, 2, 0xffffff);
        if (c == '\'') sd_rect(f, x + 4, y, 2, 4, 0xffffff);
        x += 12;
    }
}

void sd_framebuffer_kernel_result(const SD_HANDOFF *h, int success)
{
    sd_rect(&h->framebuffer, 272, 32, 32, 64, success ? 0x30d0e0 : 0xe04040);
    if (h->framebuffer.height >= 312)
        sd_text(&h->framebuffer, 280,
                success ? "NTWRAPPER9X_RING0_PASS" : "NTWRAPPER9X_RING0_FAIL");
}

#ifdef SD_UEFI_TEST_PCI
void sd_framebuffer_pci_result(const SD_HANDOFF *h, int success)
{
    sd_rect(&h->framebuffer, 32, 312, 64, 16, success ? 0xf040b0 : 0xe04040);
    if (h->framebuffer.height >= 368)
        sd_text(&h->framebuffer, 344,
                success ? "PCIE_BRIDGE_XHCI_PASS" : "PCIE_BRIDGE_XHCI_FAIL");
}
#endif

void sd_framebuffer_result(const SD_HANDOFF *h, int success)
{
    const SD_FRAMEBUFFER *f = &h->framebuffer;
    sd_rect(f, 0, 0, f->width, f->height, 0x101c30);
    /* Exact colors/coordinates are part of the live screenshot smoke contract. */
    sd_rect(f, 32, 32, 64, 64, success ? 0x20d080 : 0xe04040);
    sd_rect(f, 112, 32, 64, 64, 0x7040e0);
    sd_text(f, 120, "WINDOWS 98 SHIZUKU'S SECOND EDITION");
    sd_text(f, 152, "SHIZUKUDOS UEFI");
    sd_text(f, 184, success ? "BOOT SERVICES EXITED" : "HANDOFF FAILED");
    sd_text(f, 216, "EXPERIMENTAL PLATFORM");
    if (f->height >= 272)
        sd_text(f, 248, "WINDOWS LOADER NOT IMPLEMENTED");
}
