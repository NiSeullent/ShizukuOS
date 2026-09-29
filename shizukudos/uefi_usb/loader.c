/* SPDX-License-Identifier: GPL-2.0-only
 * Original UEFI loader for a fixed-address, independently built i486 payload.
 */
#include "../uefi/boot.h"
#include "layout.h"
#include "paging.h"
#include "images.h"

typedef EFI_STATUS (EFIAPI *ALLOCATE_PAGES)(uint32_t, uint32_t, size_t, uint64_t *);
typedef EFI_STATUS (EFIAPI *FREE_PAGES)(uint64_t, size_t);
EFI_STATUS EFIAPI efi_main(EFI_HANDLE, EFI_SYSTEM_TABLE *);
EFI_STATUS (EFIAPI *volatile relocation_anchor)(EFI_HANDLE, EFI_SYSTEM_TABLE *) = efi_main;
static EFI_GUID gop_guid = {0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};

static uint64_t ticks(void)
{
    uint32_t low, high;
    __asm__ volatile("rdtsc" : "=a"(low), "=d"(high) :: "memory");
    return ((uint64_t)high << 32) | low;
}
static int calibrate(EFI_BOOT_SERVICES *bs)
{
    typedef EFI_STATUS (EFIAPI *STALL)(size_t microseconds);
    SDUSB_PROOF *proof = (SDUSB_PROOF *)(uintptr_t)SDUSB_RECORD;
    uint64_t start, elapsed, rate;
    if (!bs->stall) return 0;
    start = ticks();
    if (EFI_ERROR(((STALL)bs->stall)(10000))) return 0;
    elapsed = ticks() - start;
    rate = elapsed / 10000;
    /* Bounded lab-only calibration. One CPU and no migration are required. */
    if (rate < 10 || rate > 100000) return 0;
    proof->magic = SDUSB_MAGIC; proof->size = sizeof(*proof);
    proof->version = SDUSB_VERSION;
    proof->ticks_per_us = (uint32_t)rate;
    proof->start_tsc = ticks(); proof->calibrated = 1;
    return 1;
}

static void print(EFI_SYSTEM_TABLE *st, const char *message)
{
    CHAR16 text[128];
    size_t i;
    if (!st->console_out || !st->console_out->output_string) return;
    while (*message) {
        for (i = 0; i < 127 && *message; ++i) text[i] = (uint8_t)*message++;
        text[i] = 0;
        st->console_out->output_string(st->console_out, text);
    }
}
static void copy(uint8_t *out, const uint8_t *in, size_t bytes)
{
    size_t i;
    for (i = 0; i < bytes; ++i) out[i] = in[i];
}
static int read_pte(void *context, uint64_t physical, uint64_t *entry)
{
    (void)context;
    *entry = *(const volatile uint64_t *)(uintptr_t)physical;
    return 1;
}
static int identity_region(void)
{
    uint64_t cr3, cr4, address;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    for (address = SD32_BASE; address < SD32_BASE + SD32_REGION_SIZE; address += 4096)
        if (!sd32_identity_page(cr3, address, cr4 & 0x1000 ? 5 : 4, 1, 1, read_pte, 0)) return 0;
    return 1;
}
static EFI_STATUS exit_firmware(EFI_BOOT_SERVICES *bs, EFI_HANDLE image, SD32_BOOT *b)
{
    SD_HANDOFF map = {0};
    EFI_STATUS status;
    unsigned attempt;
    map.memory_map = (EFI_MEMORY_DESCRIPTOR *)(uintptr_t)SD32_MAP;
    map.map_capacity = SD32_MAP_CAPACITY;
    for (attempt = 0; attempt < 8; ++attempt) {
        map.map_size = map.map_capacity;
        status = bs->get_memory_map(&map.map_size, map.memory_map, &map.map_key,
                                    &map.descriptor_size, &map.descriptor_version);
        if (EFI_ERROR(status)) return status;
        status = sd_validate_map(&map);
        if (EFI_ERROR(status)) return status;
        b->map_bytes = (uint32_t)map.map_size;
        b->descriptor_bytes = (uint32_t)map.descriptor_size;
        b->descriptor_version = map.descriptor_version;
        if (!sd32_validate_boot(b)) return EFI_INVALID_PARAMETER;
        b->exit_attempted = 1;
        status = bs->exit_boot_services(image, map.map_key);
        if (!EFI_ERROR(status)) { b->stage = 2; return EFI_SUCCESS; }
        if (status != EFI_INVALID_PARAMETER) return status;
    }
    return EFI_ABORTED;
}
static __attribute__((noreturn)) void stop(void)
{
    for (;;) __asm__ volatile("cli; hlt" ::: "memory");
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    EFI_BOOT_SERVICES *bs;
    EFI_GOP *gop = 0;
    SD_FRAMEBUFFER fb;
    SD32_BOOT *b = (SD32_BOOT *)(uintptr_t)SD32_HANDOFF;
    uint64_t address = SD32_BASE;
    EFI_STATUS status;
    size_t i;
    if (!st || st->header.signature != EFI_SYSTEM_TABLE_SIGNATURE || !st->boot_services)
        return EFI_INVALID_PARAMETER;
    bs = st->boot_services;
    if (bs->header.signature != EFI_BOOT_SERVICES_SIGNATURE || bs->header.header_size < sizeof(*bs) ||
        !bs->allocate_pages || !bs->free_pages || !bs->get_memory_map ||
        !bs->exit_boot_services || !bs->locate_protocol || !bs->set_watchdog_timer)
        return EFI_UNSUPPORTED;
    print(st, "Windows 98 Shizuku's Second Edition\r\nShizukuDOS x64 UEFI to native 32-bit kernel\r\n");
    status = bs->set_watchdog_timer(0, 0, 0, 0);
    if (EFI_ERROR(status)) return status;
    status = bs->locate_protocol(&gop_guid, 0, (void **)&gop);
    if (EFI_ERROR(status) || !gop) return EFI_UNSUPPORTED;
    status = sd_framebuffer_snapshot(gop->mode, &fb);
    if (EFI_ERROR(status) || fb.base > UINT32_MAX || fb.size > UINT32_MAX ||
        fb.base + fb.size > UINT32_MAX || fb.width < 640 || fb.height < 400)
        return EFI_UNSUPPORTED;
    /* AllocateAddress=2, EfiLoaderCode=1: executable image/transition storage.
     * The entire reservation, including stack/map, remains owned by the payload. */
    status = ((ALLOCATE_PAGES)bs->allocate_pages)(2, 1, SD32_REGION_SIZE / 4096, &address);
    if (EFI_ERROR(status)) {
        print(st, "Fixed low-memory reservation unavailable; firmware remains active.\r\n");
        return status;
    }
    if (address != SD32_BASE || !identity_region()) {
        print(st, "Low region is not writable/executable identity-mapped memory.\r\n");
        ((FREE_PAGES)bs->free_pages)(address, SD32_REGION_SIZE / 4096);
        return EFI_UNSUPPORTED;
    }
    for (i = 0; i < SD32_REGION_SIZE; ++i) ((uint8_t *)(uintptr_t)address)[i] = 0;
    copy((uint8_t *)(uintptr_t)SD32_BASE, transition_image, sizeof(transition_image));
    copy((uint8_t *)(uintptr_t)SD32_PAYLOAD, payload_image, sizeof(payload_image));
    b->magic = SD32_MAGIC; b->version = SD32_VERSION; b->size = sizeof(*b); b->stage = 1;
    b->framebuffer = (uint32_t)fb.base; b->framebuffer_bytes = (uint32_t)fb.size;
    b->width = fb.width; b->height = fb.height; b->pitch_pixels = fb.pitch_pixels;
    b->pixel_format = fb.pixel_format; b->memory_map = SD32_MAP;
    b->region_base = SD32_BASE; b->region_bytes = SD32_REGION_SIZE;
    b->payload_bytes = sizeof(payload_image); b->stack_top = SD32_STACK_TOP;
    if (!calibrate(bs)) {
        print(st, "USB EP0 test clock calibration failed before firmware exit.\r\n");
        ((FREE_PAGES)bs->free_pages)(address, SD32_REGION_SIZE / 4096);
        return EFI_UNSUPPORTED;
    }
    print(st, "Low-memory image ready. Exiting firmware and leaving long mode.\r\n");
    status = exit_firmware(bs, image, b);
    if (EFI_ERROR(status)) {
        if (b->exit_attempted) stop();
        print(st, "Memory-map handoff failed before firmware shutdown.\r\n");
        ((FREE_PAGES)bs->free_pages)(address, SD32_REGION_SIZE / 4096);
        return status;
    }
    /* No return and no firmware calls from this point. */
    ((void (*)(void))(uintptr_t)SD32_BASE)();
    stop();
}
