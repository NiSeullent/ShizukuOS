/* SPDX-License-Identifier: GPL-2.0-only
 * DOS16 domain: FreeDOS (or any real-mode DOS/bootloader) in virtual Real Mode on the
 * Supervisor's own VMX backend, with the vBIOS, legacy device models and text display.
 */
#include "bios.h"
#include "console.h"
#include "cpu.h"
#include "devices.h"
#include "domain.h"
#include "guest.h"
#include "pool.h"
#include "video.h"

guest_t G;
static domain_t *dos;
static char marker_buf[24];
static unsigned marker_len;
static uint64_t last_render;

/* The guest's COM1 output is forwarded to the physical console. A complete line
 * "SHZ-EXIT:<digit>" is the DOS-side end-of-session request (SHZEXIT.COM). */
static void guest_uart_tx(uint8_t c)
{
    static const char tag[] = "SHZ-EXIT:";
    const unsigned taglen = sizeof tag - 1;
    serial_putc((char)c);
    ++G.info->guest_console_bytes;
    if (c == '\n' || c == '\r') {
        if (marker_len == taglen + 1 && marker_buf[taglen] >= '0' && marker_buf[taglen] <= '9') {
            G.info->guest_exit_code = (uint32_t)(marker_buf[taglen] - '0');
            G.info->guest_exit_requested = 1;
        }
        marker_len = 0;
        return;
    }
    if (marker_len < taglen && c == (uint8_t)tag[marker_len])
        marker_buf[marker_len++] = (char)c;
    else if (marker_len == taglen)
        marker_buf[marker_len++] = (char)c;      /* the exit-code digit */
    else
        marker_len = 0;
}

int dos_domain_create(shz_info_t *info, const shz_caps_t *caps, const uint8_t *vbios, unsigned vbios_len)
{
    vmx_cfg_t cfg;
    domain_t *d = &g_dom[SHZ_DOM_DOS16];
    uint8_t *ram;

    memset(d, 0, sizeof *d);
    d->id = SHZ_DOM_DOS16;
    d->name = "DOS16";
    d->kind = DK_DOS16;
    d->generation = 1;
    d->ram_base = info->guest_ram_base;
    d->ram_size = info->guest_ram_size;
    if (d->ram_size < (2ull << 20) || (d->ram_size & 0xfff) || (d->ram_base & 0xfff) || vbios_len != 0x10000 ||
        d->ram_size > 128ull << 20) {
        log_capture(info->last_error, sizeof info->last_error, "invalid DOS guest RAM %llx@%llx or vBIOS size",
                    d->ram_size, d->ram_base);
        return -1;
    }
    G.info = info;
    G.vc = &d->vc;
    G.ram_base = d->ram_base;
    G.ram_size = d->ram_size;
    G.tsc_hz = info->tsc_hz;
    dos = d;

    ram = (uint8_t *)(uintptr_t)d->ram_base;
    memset(ram, 0, d->ram_size);
    memcpy(ram + 0xf0000, vbios, vbios_len);

    if (ept_init(&d->ept) || ept_map(&d->ept, 0, d->ram_base, d->ram_size, EPT_RWX | EPT_WB, 1)) {
        log_capture(info->last_error, sizeof info->last_error, "EPT construction failed for the DOS16 domain");
        return -1;
    }
    d->io_bitmap_a = pool_alloc_pages(1);
    d->io_bitmap_b = pool_alloc_pages(1);
    d->msr_bitmap = pool_alloc_pages(1);
    cfg.io_bitmap_a = d->io_bitmap_a; cfg.io_bitmap_b = d->io_bitmap_b; cfg.msr_bitmap = d->msr_bitmap;
    cfg.vmcs = pool_alloc_pages(1);
    if (!d->io_bitmap_a || !d->io_bitmap_b || !d->msr_bitmap || !cfg.vmcs) {
        log_capture(info->last_error, sizeof info->last_error, "Supervisor pool exhausted (DOS16 domain)");
        return -1;
    }
    memset(d->io_bitmap_a, 0xff, 4096);        /* trap every port: the device models decide */
    memset(d->io_bitmap_b, 0xff, 4096);
    memset(d->msr_bitmap, 0xff, 4096);         /* trap every MSR: real-mode DOS uses none */

    dev_init(G.tsc_hz, d->ram_size);
    dev_uart_tx_hook = guest_uart_tx;
    bios_init();
    bios_prepare_guest_memory();

    cfg.mode = VMODE_REAL;
    cfg.eptp = ept_pointer(&d->ept);
    cfg.vpid = SHZ_DOM_DOS16;
    cfg.rip = 0xfff0;
    cfg.cs_sel = 0xf000;
    cfg.rsp = 0;
    cfg.cr3 = 0;
    cfg.code_sel = cfg.data_sel = 0;
    cfg.gdt_base = 0;
    cfg.gdt_limit = 0;
    if (vmx_vcpu_init(&d->vc, info, caps, &cfg))
        return -1;
    d->state = SHZ_DS_RUNNABLE;
    return 0;
}

static void handle_io(domain_t *d)
{
    const uint64_t q = vmread(VMCS_EXIT_QUAL);
    const int size = (int)(q & 7) + 1;
    const int in = (int)((q >> 3) & 1);
    const int string = (int)((q >> 4) & 1);
    const uint16_t port = (uint16_t)(q >> 16);
    uint32_t v;
    ++G.info->io_exits;
    if (string) {
        dom_fail(d, "unsupported string I/O on port %x", port);
        return;
    }
    if (!in) {
        v = (uint32_t)d->vc.gpr[GPR_RAX];
        if (size == 1) v &= 0xff;
        else if (size == 2) v &= 0xffff;
        if (port >= 0xe0 && port <= 0xef) {
            if (!bios_hypercall(port))
                ++G.info->io_unhandled;
        } else if (!dev_pio_out(port, size, v)) {
            ++G.info->io_unhandled;
        }
    } else {
        v = 0xffffffffu;
        if (!dev_pio_in(port, size, &v)) {
            ++G.info->io_unhandled;
            v = size == 1 ? 0xff : size == 2 ? 0xffff : 0xffffffffu;
        }
        if (size == 1) set_reg8l(GPR_RAX, (uint8_t)v);
        else if (size == 2) set_reg16(GPR_RAX, (uint16_t)v);
        else d->vc.gpr[GPR_RAX] = v;
    }
    dom_advance_rip();
}

/* The guest halted: keep it WAITING until a device interrupt or key is deliverable.
 * HLT with IF=0 can never wake, which is a hang worth reporting. */
static void handle_hlt(domain_t *d)
{
    dom_advance_rip();
    if (!(vmread(VMCS_GUEST_RFLAGS) & 0x200)) {
        dom_fail(d, "guest halted with interrupts disabled");
        return;
    }
    d->state = SHZ_DS_WAITING;
}

int dos_handle_exit(domain_t *d, uint32_t reason)
{
    switch (reason) {
    case EXIT_IO:
        handle_io(d);
        return 1;
    case EXIT_HLT:
        handle_hlt(d);
        return 1;
    case EXIT_RDMSR:
        d->vc.gpr[GPR_RAX] = 0;                    /* an unmodelled MSR reads as zero in DOS */
        d->vc.gpr[GPR_RDX] = 0;
        dom_advance_rip();
        return 1;
    case EXIT_WRMSR:
        dom_advance_rip();
        return 1;
    default:
        return 0;
    }
}

int dos_ready(domain_t *d, uint64_t now)
{
    (void)d;
    dev_poll(now);
    bios_poll_input();
    return dev_irq_pending() || bios_key_available();
}

uint64_t dos_next_event_tsc(void) { return dev_next_event_tsc(); }

/* Called after every slice: A20 EPT updates, display, end-of-session detection. */
void dos_housekeeping(void)
{
    shz_info_t *info = G.info;
    if (!dos)
        return;
    if (dev_a20_dirty) {
        dev_a20_dirty = 0;
        /* When A20 is off, guest pages 100000..10FFFF alias 000000..00FFFF. */
        {
            unsigned i;
            for (i = 0; i < 16; ++i) {
                const uint64_t gpa = 0x100000ull + ((uint64_t)i << 12);
                const uint64_t hpa = dos->ram_base + (dev_a20_get() ? gpa : ((uint64_t)i << 12));
                ept_remap_page(&dos->ept, gpa, hpa, EPT_RWX | EPT_WB);
            }
        }
        ept_invalidate();
    }
    if (dos->state == SHZ_DS_EXITED || dos->state == SHZ_DS_FAILED)
        return;
    if (info->guest_exit_requested) {
        dom_exit(dos, info->guest_exit_code);
        video_render();
        return;
    }
    if (rdtsc() - last_render > G.tsc_hz / 20) {
        last_render = rdtsc();
        video_render();
    }
}
