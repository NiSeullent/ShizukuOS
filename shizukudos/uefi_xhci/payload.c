/* SPDX-License-Identifier: GPL-2.0-only
 * Original isolated PCI-E/xHCI command-ring integration, no USB endpoint claim.
 */
#include "layout.h"
#include "../../ntwrapper/include/ntwrapper.h"
#include "../../ntwddm/include/ntwddm.h"
#include "../../drivers/pcie/include/ntw_pcie.h"
#include "../../drivers/xhci_native/xhci.h"

static _Alignas(4096) uint8_t dma_page[XHCI_DMA_BYTES];
static struct xhci_device controller;
static uint32_t dma_in_use, mmio_base, found_bdf, found_count, bridges;
static SDXHCI_PROOF *const usb_proof = (SDXHCI_PROOF *)(uintptr_t)SDXHCI_RECORD;

static void out32(uint16_t port, uint32_t value)
{
    __asm__ volatile("outl %0, %1" :: "a"(value), "Nd"(port) : "memory");
}
static uint32_t in32(uint16_t port)
{
    uint32_t value;
    __asm__ volatile("inl %1, %0" : "=a"(value) : "Nd"(port) : "memory");
    return value;
}
static uint32_t pci_read(uint32_t bdf, uint32_t offset)
{
    uint32_t saved = in32(0xcf8), value;
    out32(0xcf8, UINT32_C(0x80000000) | (bdf << 8) | offset);
    value = in32(0xcfc);
    out32(0xcf8, saved);
    return value;
}
static void pci_command(uint32_t bdf, uint32_t command)
{
    uint32_t saved = in32(0xcf8);
    out32(0xcf8, UINT32_C(0x80000000) | (bdf << 8) | 4);
    out32(0xcfc, command & 0xffff); /* Never echo W1C status bits. */
    out32(0xcf8, saved);
}
static int config_read(void *unused, struct ntw_pci_address a, uint16_t offset,
                       uint8_t width, uint32_t *value)
{
    uint32_t data, bdf;
    (void)unused;
    if (a.segment || a.device > 31 || a.function > 7 || offset >= 256 ||
        (width != 1 && width != 2 && width != 4) || offset % width ||
        (uint32_t)offset + width > 256 || !value) return NTW_PCI_ARGUMENT;
    bdf = ((uint32_t)a.bus << 8) | ((uint32_t)a.device << 3) | a.function;
    data = pci_read(bdf, offset & ~3u) >> ((offset & 3u) * 8);
    *value = width == 1 ? data & 255 : width == 2 ? data & 65535 : data;
    return NTW_PCI_OK;
}
static int visit(void *unused, const struct ntw_pci_device *device)
{
    (void)unused;
    if (device->kind == NTW_PCI_BRIDGE) ++bridges;
    if (device->kind == NTW_PCI_XHCI && device->vendor_id == 0x1b36 &&
        device->device_id == 0x000d && device->address.bus != 0) {
        ++found_count;
        found_bdf = ((uint32_t)device->address.bus << 8) |
            ((uint32_t)device->address.device << 3) | device->address.function;
    }
    return 0;
}
static int mmio_read(void *unused, uint32_t offset, uint32_t *value)
{
    (void)unused;
    if ((offset & 3) || offset > 0x3ffc || !value || !mmio_base) return 0;
    *value = *(volatile uint32_t *)(uintptr_t)(mmio_base + offset);
    return 1;
}
static int mmio_write(void *unused, uint32_t offset, uint32_t value)
{
    (void)unused;
    if ((offset & 3) || offset > 0x3ffc || !mmio_base) return 0;
    *(volatile uint32_t *)(uintptr_t)(mmio_base + offset) = value;
    return 1;
}
static int mmio_write8(void *unused, uint32_t offset, uint8_t value)
{
    (void)unused;
    if (offset > 0x3fff || !mmio_base) return 0;
    *(volatile uint8_t *)(uintptr_t)(mmio_base + offset) = value;
    return 1;
}
static int dma_allocate(void *unused, size_t bytes, size_t alignment,
                        uint64_t maximum, struct xhci_dma *block)
{
    uintptr_t address = (uintptr_t)dma_page;
    (void)unused;
    if (!block || dma_in_use || bytes != sizeof(dma_page) || !alignment ||
        (alignment & (alignment - 1)) || address % alignment ||
        (uint64_t)address + bytes - 1 > maximum) return 0;
    /* Only this identity-mapped, coherent, no-IOMMU QEMU fixture. */
    block->cpu = dma_page; block->bus = address; block->bytes = bytes;
    dma_in_use = 1;
    return 1;
}
static void dma_release(void *unused, struct xhci_dma *block)
{
    (void)unused;
    if (block && block->cpu == dma_page) dma_in_use = 0;
}
static int dma_sync(void *unused, const struct xhci_dma *block, size_t offset,
                    size_t bytes, int to_device)
{
    (void)unused; (void)to_device;
    if (!block || block->cpu != dma_page || !dma_in_use ||
        offset > sizeof(dma_page) || bytes > sizeof(dma_page) - offset) return 0;
    __sync_synchronize();
    return 1;
}
static uint64_t now_us(void *unused)
{
    uint32_t low, high;
    (void)unused;
    __asm__ volatile("rdtsc" : "=a"(low), "=d"(high) :: "memory");
    return sdxhci_divide((((uint64_t)high << 32) | low) - usb_proof->start_tsc,
                          usb_proof->ticks_per_us);
}
static void relax_cpu(void *unused)
{
    (void)unused;
    __asm__ volatile("rep; nop" ::: "memory");
}
static int usb_controller_test(void)
{
    const struct ntw_pci_transport transport = {config_read, 0, 256};
    const struct ntw_pci_scan_limits limits = {0, 0, 255, 256, 65536};
    struct ntw_pci_scan_result scanned = {0};
    const struct xhci_ops ops = {0, mmio_read, mmio_write, dma_allocate,
        dma_release, dma_sync, now_us, relax_cpu, mmio_write8};
    struct xhci_config config = {0x0c0330, 0, 0x4000, 1000000, 1};
    struct ntw_pci_bar bar;
    struct ntw_pci_resource resource;
    uint32_t bars[6], original, i;
    int result, good = 0;
    if (usb_proof->magic != SDXHCI_MAGIC || usb_proof->size != sizeof(*usb_proof) ||
        !usb_proof->calibrated || !usb_proof->ticks_per_us) return 0;
    usb_proof->stage = 1;
    usb_proof->open_result = UINT32_MAX;
    usb_proof->command_result = UINT32_MAX;
    usb_proof->close_result = UINT32_MAX;
    if (ntw_pci_scan(&transport, &limits, visit, 0, &scanned) != NTW_PCI_OK ||
        scanned.buses < 2 || !bridges || found_count != 1) return 0;
    for (i = 0; i < 6; ++i) bars[i] = pci_read(found_bdf, 0x10 + i * 4);
    /* The qemu-xhci fixture declares a 16-KiB memory BAR. The host harness
     * separately checks that aperture from QEMU's actual PCI inventory. */
    if (ntw_pci_decode_bar(bars, 6, 0, &bar) != NTW_PCI_OK ||
        bar.kind != NTW_PCI_BAR_MEMORY || bar.address_bits != 64 ||
        ntw_pci_bar_resource(&bar, 0x4000, 32, UINT64_C(0x80000000),
            UINT64_C(0xffffffff), &resource) != NTW_PCI_OK) return 0;
    mmio_base = (uint32_t)resource.first;
    usb_proof->mmio = mmio_base; usb_proof->pci_bdf = found_bdf;
    usb_proof->bridges = bridges;
    original = pci_read(found_bdf, 4) & 0xffff;
    pci_command(found_bdf, original | 6);
    config.pci_command = pci_read(found_bdf, 4) & 0xffff;
    result = xhci_open(&controller, &ops, &config);
    usb_proof->open_result = (uint32_t)result;
    if (result != XHCI_OK) goto done;
    usb_proof->stage = 2;
    for (i = 0; i < 130; ++i) {
        result = xhci_noop(&controller);
        usb_proof->command_result = (uint32_t)result;
        if (result != XHCI_OK) goto done;
    }
    good = controller.commands_completed == 130;
done:
    usb_proof->commands_completed = controller.commands_completed;
    usb_proof->port_events = controller.port_events;
    usb_proof->completion_low = (uint32_t)controller.last_completion_pointer;
    usb_proof->completion_high = (uint32_t)(controller.last_completion_pointer >> 32);
    usb_proof->last_status = controller.last_status;
    usb_proof->last_completion_code = controller.last_completion_code;
    result = xhci_close(&controller);
    usb_proof->close_result = (uint32_t)result;
    usb_proof->quarantine = controller.dma_owned;
    if (controller.dma_owned) return 0;
    pci_command(found_bdf, original);
    if (result != XHCI_OK) return 0;
    usb_proof->stage = good ? 3 : 4;
    return good;
}
static _Alignas(16) uint8_t graphics_memory[64 * 1024];
static size_t graphics_used;

static uintptr_t irq_enter(void *context)
{
    uintptr_t flags;
    (void)context;
    __asm__ volatile("pushfl; popl %0; cli" : "=r"(flags) :: "memory");
    return flags;
}
static void irq_leave(void *context, uintptr_t flags)
{
    (void)context;
    __asm__ volatile("pushl %0; popfl" :: "r"(flags) : "memory", "cc");
}
static int core_test(void)
{
    struct ntw_context context;
    struct ntw_lock_ops lock = {irq_enter, irq_leave, 0};
    struct ntw_lease lease = {0};
    ntw_handle event;
    int previous;
    if (ntw_initialize(&context, &lock) != NTW_OK) return 0;
    if (ntw_event_create(&context, 0, 0, NTW_EVENT_ALL, &event) != NTW_OK) return 0;
    if (ntw_event_try_wait(&context, event) != NTW_PENDING) return 0;
    if (ntw_event_set(&context, event, &previous) != NTW_OK || previous) return 0;
    if (ntw_event_try_wait(&context, event) != NTW_OK) return 0;
    if (ntw_event_try_wait(&context, event) != NTW_PENDING) return 0;
    if (ntw_reference(&context, event, NTW_EVENT_QUERY, &lease) != NTW_OK) return 0;
    if (ntw_close(&context, event) != NTW_OK) return 0;
    if (ntw_event_query(&context, event, &previous) != NTW_BAD_HANDLE) return 0;
    if (ntw_shutdown(&context) != NTW_BUSY) return 0;
    if (ntw_dereference(&lease) != NTW_OK) return 0;
    if (ntw_event_create(&context, 1, 1, NTW_EVENT_ALL, &event) != NTW_OK) return 0;
    if (ntw_event_try_wait(&context, event) != NTW_OK) return 0;
    if (ntw_event_try_wait(&context, event) != NTW_OK) return 0;
    if (ntw_event_reset(&context, event, &previous) != NTW_OK || !previous) return 0;
    if (ntw_event_try_wait(&context, event) != NTW_PENDING) return 0;
    if (ntw_close(&context, event) != NTW_OK) return 0;
    return ntw_shutdown(&context) == NTW_OK;
}

static void *allocate(void *context, size_t bytes)
{
    size_t aligned = (graphics_used + 15) & ~(size_t)15;
    (void)context;
    if (aligned > sizeof(graphics_memory) || bytes > sizeof(graphics_memory) - aligned) return 0;
    graphics_used = aligned + bytes;
    return graphics_memory + aligned;
}
static void deallocate(void *context, void *memory, size_t bytes)
{
    (void)context; (void)memory; (void)bytes;
}
static int graphics_test(const SD32_BOOT *b)
{
    ntwg_create_desc create = {sizeof(create), NTWG_ABI_VERSION, allocate, deallocate, 0};
    ntwg_framebuffer_desc fb = {sizeof(fb), NTWG_ABI_VERSION,
        (volatile void *)(uintptr_t)b->framebuffer, b->framebuffer_bytes,
        b->width, b->height, b->pitch_pixels * 4,
        b->pixel_format ? NTWG_PIXEL_XRGB8888 : NTWG_PIXEL_XBGR8888, 0, 0};
    ntwg_surface_desc desc = {sizeof(desc), NTWG_ABI_VERSION, 64, 64, 0, NTWG_PIXEL_XRGB8888};
    ntwg_rect rect = {0, 0, 64, 64};
    ntwg_context *context;
    ntwg_surface surface = 0;
    ntwg_fence fence;
    uint32_t complete = 0;
    int result = 0;
    if (ntwg_create(&create, &context) != NTWG_OK) return 0;
    if (ntwg_bind_framebuffer(context, &fb) != NTWG_OK) goto done;
    if (ntwg_surface_create(context, &desc, &surface) != NTWG_OK) goto done;
    if (ntwg_fill(context, surface, &rect, UINT32_C(0xffffb020), 0) != NTWG_OK) goto done;
    if (ntwg_present(context, surface, &rect, 112, 32, &fence) != NTWG_OK) goto done;
    if (ntwg_fence_query(context, &fence, &complete) != NTWG_OK || !complete) goto done;
    result = 1;
done:
    if (surface) ntwg_surface_release(context, surface);
    ntwg_destroy(context);
    return result;
}

static void rectangle(const SD32_BOOT *b, uint32_t x, uint32_t y,
                       uint32_t width, uint32_t height, uint32_t color)
{
    volatile uint32_t *pixels = (volatile uint32_t *)(uintptr_t)b->framebuffer;
    uint32_t xx, yy;
    if (x >= b->width || y >= b->height) return;
    if (width > b->width - x) width = b->width - x;
    if (height > b->height - y) height = b->height - y;
    if (!b->pixel_format) color = ((color & 255) << 16) | (color & 0xff00) | ((color >> 16) & 255);
    for (yy = 0; yy < height; ++yy)
        for (xx = 0; xx < width; ++xx)
            pixels[(y + yy) * b->pitch_pixels + x + xx] = color;
}

/* The project's independently drawn uefi/boot.c capital glyphs, reused here. */
static const uint8_t letters[26][7] = {
    {14,17,17,31,17,17,17},{30,17,17,30,17,17,30},{14,17,16,16,16,17,14},
    {30,17,17,17,17,17,30},{31,16,16,30,16,16,31},{31,16,16,30,16,16,16},
    {14,17,16,23,17,17,15},{17,17,17,31,17,17,17},{31,4,4,4,4,4,31},
    {7,2,2,2,18,18,12},{17,18,20,24,20,18,17},{16,16,16,16,16,16,31},
    {17,27,21,21,17,17,17},{17,25,25,21,19,19,17},{14,17,17,17,17,17,14},
    {30,17,17,30,16,16,16},{14,17,17,17,21,18,13},{30,17,17,30,20,18,17},
    {15,16,16,14,1,1,30},{31,4,4,4,4,4,4},{17,17,17,17,17,17,14},
    {17,17,17,17,17,10,4},{17,17,17,21,21,27,17},{17,17,10,4,10,17,17},
    {17,17,10,4,4,4,4},{31,1,2,4,8,16,31}
};
static const uint8_t digits[10][7] = {
    {14,17,19,21,25,17,14},{4,12,4,4,4,4,14},{14,17,1,2,4,8,31},
    {30,1,1,14,1,1,30},{2,6,10,18,31,2,2},{31,16,16,30,1,1,30},
    {14,16,16,30,17,17,14},{31,1,2,4,8,8,8},{14,17,17,14,17,17,14},
    {14,17,17,15,1,1,14}
};
static void text(const SD32_BOOT *b, uint32_t y, const char *message)
{
    uint32_t x = 32, row, column;
    while (*message && x + 10 < b->width) {
        unsigned char c = (unsigned char)*message++;
        const uint8_t *glyph = c >= 'A' && c <= 'Z' ? letters[c - 'A'] :
            c >= '0' && c <= '9' ? digits[c - '0'] : 0;
        if (glyph)
            for (row = 0; row < 7; ++row)
                for (column = 0; column < 5; ++column)
                    if (glyph[row] & (16u >> column))
                        rectangle(b, x + column * 2, y + row * 2, 2, 2, 0xffffff);
        if (c == '\'') rectangle(b, x + 4, y, 2, 4, 0xffffff);
        if (c == '_') rectangle(b, x, y + 12, 10, 2, 0xffffff);
        x += 12;
    }
}

__attribute__((section(".text.entry"), noreturn)) void kernel_main(SD32_BOOT *b)
{
    uint32_t value, high;
    uint16_t segment;
    __asm__ volatile("cli; cld" ::: "memory");
    if (b != (SD32_BOOT *)(uintptr_t)SD32_HANDOFF || !sd32_validate_boot(b)) goto halt;
    b->stage = 4;
    __asm__ volatile("mov %%cr0, %0" : "=r"(value)); b->cr0 = value;
    __asm__ volatile("mov %%cr4, %0" : "=r"(value)); b->cr4 = value;
    __asm__ volatile("rdmsr" : "=a"(value), "=d"(high) : "c"(UINT32_C(0xc0000080)));
    b->efer = value; (void)high;
    __asm__ volatile("mov %%cs, %0" : "=r"(segment)); b->cs = segment;
    __asm__ volatile("mov %%ss, %0" : "=r"(segment)); b->ss = segment;
    __asm__ volatile("mov %%esp, %0" : "=r"(value)); b->esp = value;
    b->mode_pass = sd32_validate_mode(b);
    rectangle(b, 0, 0, b->width, b->height, 0x101c30);
    rectangle(b, 32, 32, 64, 64, b->mode_pass ? 0x20d080 : 0xe04040);
    text(b, 120, "WINDOWS 98 SHIZUKU'S SECOND EDITION");
    text(b, 152, "SHIZUKUDOS NATIVE 32 BIT KERNEL");
    if (!b->mode_pass) { text(b, 184, "CPU TRANSITION FAILED"); goto halt; }
    b->core_pass = (uint32_t)core_test();
    b->graphics_pass = (uint32_t)graphics_test(b);
    rectangle(b, 192, 32, 64, 64, b->core_pass ? 0x30d0e0 : 0xe04040);
    text(b, 184, "CPL0  PE1  PG0  PAE0  LME0  LMA0");
    text(b, 216, b->core_pass ? "NTWRAPPER9X_PM32_PASS" : "NTWRAPPER9X_PM32_FAIL");
    text(b, 248, b->graphics_pass ? "NTWDDM_PM32_PASS" : "NTWDDM_PM32_FAIL");
    text(b, 280, "XHCI COMMAND RING TEST STARTING");
    if (b->core_pass && b->graphics_pass && usb_controller_test()) {
        rectangle(b, 272, 32, 64, 64, 0x10b060);
        text(b, 312, "XHCI_PM32_130_COMMANDS_PASS");
        b->stage = 5;
    } else {
        usb_proof->stage = 4;
        rectangle(b, 272, 32, 64, 64, 0xe04040);
        text(b, 312, "XHCI_PM32_COMMAND_FAIL");
    }
    text(b, 344, "DOS AND WINDOWS GUI NOT IMPLEMENTED");
halt:
    for (;;) __asm__ volatile("cli; hlt" ::: "memory");
}
