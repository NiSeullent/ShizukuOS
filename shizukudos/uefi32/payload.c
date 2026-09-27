/* SPDX-License-Identifier: GPL-2.0-only
 * Original freestanding 32-bit protected-mode payload. No firmware calls.
 */
#include "layout.h"
#include "../../ntwrapper/include/ntwrapper.h"
#include "../../ntwddm/include/ntwddm.h"

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
    text(b, 280, "DOS AND WINDOWS GUI NOT IMPLEMENTED");
    if (b->core_pass && b->graphics_pass) b->stage = 5;
halt:
    for (;;) __asm__ volatile("cli; hlt" ::: "memory");
}
