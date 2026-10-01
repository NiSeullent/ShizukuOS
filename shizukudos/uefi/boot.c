/* SPDX-License-Identifier: GPL-2.0-only
 * Original ShizukuDOS UEFI memory ownership transition and framebuffer logic.
 */
#include "boot.h"

/* Independently authored from UEFI 2.10 sections 12.9.2.1/2/5 and 12.10,
 * and VESA E-EDID Release A Revision 2 sections 3.6.4, 3.10, 3.12.
 * Only supported firmware modes are set; EDID never supplies hardware timings. */
static int framebuffer_format(const EFI_GOP_INFO *i, uint32_t *format)
{
    if (i->version != 0) return 0;
    if (i->pixel_format <= 1) { *format = i->pixel_format; return 1; }
    if (i->pixel_format != 2 || i->green_mask != 0x0000ff00u ||
        i->reserved_mask != 0xff000000u) return 0;
    if (i->red_mask == 0x000000ffu && i->blue_mask == 0x00ff0000u) {
        *format = 0; return 1;
    }
    if (i->red_mask == 0x00ff0000u && i->blue_mask == 0x000000ffu) {
        *format = 1; return 1;
    }
    return 0;
}

static int mode_safe(const EFI_GOP_INFO *i, uint32_t *format)
{
    return framebuffer_format(i, format) && i->width >= 320 && i->height >= 200 &&
        i->width <= 8192 && i->height <= 8192 && i->pixels_per_scan_line >= i->width &&
        i->pixels_per_scan_line <= UINT32_MAX / 4 &&
        (uint64_t)i->pixels_per_scan_line * 4 * i->height <= SD_GOP_VISIBLE_LIMIT;
}

EFI_STATUS sd_framebuffer_snapshot(const EFI_GOP_MODE *mode, SD_FRAMEBUFFER *out)
{
    const EFI_GOP_INFO *i;
    uint64_t needed;
    uint32_t format;
    if (!mode || !out || !mode->info || mode->info_size < sizeof(EFI_GOP_INFO))
        return EFI_INVALID_PARAMETER;
    i = mode->info;
    /* Canonical 32-bit masks normalize to the unchanged RGBX/BGRX handoff. */
    if (!framebuffer_format(i, &format))
        return EFI_UNSUPPORTED;
    if (i->width < 320 || i->height < 200 || i->pixels_per_scan_line < i->width ||
        i->pixels_per_scan_line > UINT32_MAX / 4 ||
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
    out->pixel_format = format;
    return EFI_SUCCESS;
}

static int edid_geometry(const EFI_EDID_ACTIVE *active, uint32_t *width, uint32_t *height)
{
    static const uint8_t header[8] = {0,255,255,255,255,255,255,0};
    const uint8_t *e;
    unsigned i, block, blocks;
    uint32_t w, h, hblank, vblank;
    if (!active || !active->edid || active->size < 128 || active->size > 32768 ||
        (active->size & 127)) return 0;
    e = active->edid;
    for (i = 0; i < 8; ++i) if (e[i] != header[i]) return 0;
    if (e[18] != 1 || (e[19] != 3 && e[19] != 4) ||
        (e[19] == 3 && !(e[24] & 2))) return 0;
    blocks = (unsigned)e[126] + 1;
    if (blocks > active->size / 128) return 0;
    for (block = 0; block < blocks; ++block) {
        uint8_t sum = 0;
        for (i = 0; i < 128; ++i) sum = (uint8_t)(sum + e[block * 128 + i]);
        if (sum) return 0;
    }
    e += 54; /* The first detailed timing is the preferred timing in EDID 1.3/1.4. */
    if (!(e[0] | e[1]) || (e[17] & 0x80)) return 0; /* descriptor or interlaced timing */
    w = e[2] | ((uint32_t)(e[4] & 0xf0) << 4);
    h = e[5] | ((uint32_t)(e[7] & 0xf0) << 4);
    hblank = e[3] | ((uint32_t)(e[4] & 15) << 8);
    vblank = e[6] | ((uint32_t)(e[7] & 15) << 8);
    if (w < 320 || h < 200 || !hblank || !vblank) return 0;
    *width = w; *height = h;
    return 1;
}

static int gop_edid(EFI_BOOT_SERVICES *bs, EFI_GOP *gop, uint32_t *w, uint32_t *h)
{
    EFI_GUID gop_guid = {0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
    EFI_GUID active_guid = {0xbd8c1056,0x9f36,0x44ec,{0x92,0xa8,0xa6,0x33,0x7f,0x81,0x79,0x86}};
    EFI_HANDLE *handles = 0;
    size_t count = 0, i;
    int valid = 0;
    EFI_STATUS status;
    if (!bs->locate_handle_buffer || !bs->handle_protocol || !bs->free_pool) return 0;
    status = bs->locate_handle_buffer(2 /* ByProtocol */, &gop_guid, 0, &count, &handles);
    if (!EFI_ERROR(status) && handles && count <= 256)
        for (i = 0; i < count; ++i) {
            EFI_GOP *instance = 0;
            EFI_EDID_ACTIVE *active = 0;
            if (EFI_ERROR(bs->handle_protocol(handles[i], &gop_guid, (void **)&instance)) || instance != gop)
                continue;
            /* Never borrow a global EDID from an unrelated display/controller.
             * Multi-output GOP handles without an associated active EDID use the ladder. */
            if (!EFI_ERROR(bs->handle_protocol(handles[i], &active_guid, (void **)&active)))
                valid = edid_geometry(active, w, h);
            break;
        }
    if (handles) bs->free_pool(handles);
    return valid;
}

EFI_STATUS sd_gop_select(EFI_BOOT_SERVICES *bs, EFI_GOP *gop, SD_FRAMEBUFFER *out,
                         SD_GOP_SELECTION *result)
{
    static const uint32_t ladder[][2] = {{3840,2160},{2560,1440},{1920,1080},{1600,900},
                                        {1366,768},{1280,720},{1024,768}};
    struct { uint32_t index; EFI_GOP_INFO info; } candidates[8];
    SD_GOP_SELECTION local = {0};
    SD_FRAMEBUFFER original, selected;
    EFI_GOP_INFO original_info;
    EFI_STATUS status;
    uint32_t original_mode, count, index, format, tier, w, h;
    if (!bs || !gop || !gop->mode || !out) return EFI_INVALID_PARAMETER;
    status = sd_framebuffer_snapshot(gop->mode, &original);
    if (EFI_ERROR(status)) return status;
    if (!mode_safe(gop->mode->info, &format) || !gop->mode->max_mode ||
        gop->mode->mode >= gop->mode->max_mode) return EFI_UNSUPPORTED;
    original_mode = gop->mode->mode;
    original_info = *gop->mode->info;
    count = gop->mode->max_mode;
    local.original_mode = local.selected_mode = original_mode;
    local.used_fallback = 1;
    *out = original;
    if (result) *result = local;
    if (!gop->query_mode || !gop->set_mode || !bs->free_pool || count > SD_GOP_MODE_LIMIT)
        return EFI_SUCCESS; /* A bounded, validated current framebuffer is still usable. */
    local.edid_preferred = (uint32_t)gop_edid(bs, gop, &local.preferred_width, &local.preferred_height);
    for (tier = 0; tier < 8; ++tier) candidates[tier].index = UINT32_MAX;
    for (index = 0; index < count; ++index) {
        EFI_GOP_INFO *info = 0;
        size_t bytes = 0;
        ++local.modes_queried;
        status = gop->query_mode(gop, index, &bytes, &info);
        if (!EFI_ERROR(status) && info && bytes >= sizeof(*info) && mode_safe(info, &format) &&
            (index != original_mode || (info->width == original.width && info->height == original.height &&
             info->pixels_per_scan_line == original.pitch_pixels && format == original.pixel_format)))
            for (tier = 0; tier < 8; ++tier) {
                w = tier ? ladder[tier - 1][0] : local.preferred_width;
                h = tier ? ladder[tier - 1][1] : local.preferred_height;
                if ((!tier && !local.edid_preferred) || info->width != w || info->height != h) continue;
                if (candidates[tier].index == UINT32_MAX ||
                    info->pixels_per_scan_line < candidates[tier].info.pixels_per_scan_line) {
                    candidates[tier].index = index;
                    candidates[tier].info = *info;
                }
            }
        if (info) bs->free_pool(info);
    }
    for (tier = 0; tier < 8; ++tier) {
        const EFI_GOP_INFO *expected = &candidates[tier].info;
        index = candidates[tier].index;
        if (index == UINT32_MAX) continue;
        if (index == original_mode) {
            /* A preferred current mode needs no reset or screen clear. */
            local.used_fallback = 0;
            if (result) *result = local;
            return EFI_SUCCESS;
        }
        status = gop->set_mode(gop, index);
        if (!EFI_ERROR(status) && gop->mode && gop->mode->mode == index &&
            !EFI_ERROR(sd_framebuffer_snapshot(gop->mode, &selected)) &&
            mode_safe(gop->mode->info, &format) && selected.width == expected->width &&
            selected.height == expected->height && selected.pitch_pixels == expected->pixels_per_scan_line &&
            framebuffer_format(expected, &format) && selected.pixel_format == format) {
            *out = selected;
            local.selected_mode = index;
            local.used_fallback = 0;
            if (result) *result = local;
            return EFI_SUCCESS;
        }
        /* A rejected SetMode can partially program hardware without updating
         * any published Mode fields. Always actively restore it before another
         * attempt or fallback; unchanged metadata cannot prove hardware state. */
        status = gop->set_mode(gop, original_mode);
        if (EFI_ERROR(status) || !gop->mode || gop->mode->mode != original_mode ||
            EFI_ERROR(sd_framebuffer_snapshot(gop->mode, &selected)) ||
            !mode_safe(gop->mode->info, &format) || selected.width != original_info.width ||
            selected.height != original_info.height || selected.pitch_pixels != original_info.pixels_per_scan_line ||
            selected.pixel_format != original.pixel_format)
            return EFI_DEVICE_ERROR;
        original = selected; /* Some firmware relocates its aperture during restoration. */
        *out = original;
    }
    if (result) *result = local;
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
