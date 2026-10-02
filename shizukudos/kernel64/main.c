/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 entry (C): CPU tables, memory, scheduler, timer and the selected boot profile.
 */
#include "proc_internal.h"
#include "../dead_screen/native.h"
#include "fs.h"
#include "boot_channel_peer.h"
#include "gfx_address.h"
#include "../boot_profile/win98_foundation.h"
#include "cpu_bringup.h"

static shz_bootinfo_t bootinfo;
int initrd_files = -1;                          /* -1: none or rejected; read by the Win64 self-test */

int k64_boot_framebuffer(k64_boot_fb_t *out)
{
    const shz_bootinfo_t *b = &bootinfo;
    /* fb_bpp follows fb_format in the ABI tail, so this size check covers both.
     * Validate before changing the caller's output or allowing a backend to map
     * the advertised range. GOP rows are addressed as whole 32-bit pixels.
     * MMIO aliases must end before the first private graphics page arena;
     * its page-aligned boundary also keeps mmio_map's roundup out of it. */
    if (!out || !SHZ_BOOTINFO_HAS(b, fb_bpp) || !b->fb_base || (b->fb_base & 3) ||
        b->fb_base > UINT64_MAX - b->fb_size ||
        b->fb_base + b->fb_size > K64_GFX_ARENA_OFFSET || b->fb_bpp != 32 ||
        (b->fb_format != SHZ_FB_RGBX8888 && b->fb_format != SHZ_FB_BGRX8888) || !b->fb_width || !b->fb_height ||
        (b->fb_pitch & 3) || b->fb_pitch / 4 < b->fb_width ||
        (uint64_t)b->fb_pitch * b->fb_height > b->fb_size)
        return -1;
    out->base = b->fb_base;
    out->size = b->fb_size;
    out->width = b->fb_width;
    out->height = b->fb_height;
    out->pitch = b->fb_pitch;
    out->bpp = b->fb_bpp;
    out->format = b->fb_format;
    return 0;
}

const char *k64_boot_cmdline(void) { return bootinfo.cmdline; }

void kmain(uint64_t bootinfo_pa)
{
    const uint64_t initial_cr3=read_cr3();
    /* The boot mapping still shows physical memory at the kernel alias. */
    const shz_bootinfo_t *bi = (const shz_bootinfo_t *)(K64_VIRT_BASE + bootinfo_pa);
    k64_boot_fb_t fb;
    if (bi->magic != SHZ_BOOTINFO_MAGIC || bi->abi_major != SHZ_ABI_MAJOR || bi->domain_id != SHZ_DOM_KERNEL64 ||
        bi->size < __builtin_offsetof(shz_bootinfo_t, fb_base))
        shz_exit(97);
    /* Read the actual writer's bounded tail before normalization can hide a
     * malformed terminator. A standalone command cannot invent a Win98 peer. */
    const int foundation_mode = shz_win98_foundation_policy(bi);
    if (foundation_mode < 0)
        shz_exit(97);
    /* Copy what the writer provided (`size`); a 1.0 writer's missing tail stays zero. */
    memcpy(&bootinfo, bi, bi->size < sizeof bootinfo ? bi->size : sizeof bootinfo);
    bootinfo.size = bi->size < sizeof bootinfo ? bi->size : sizeof bootinfo;
    bootinfo.cmdline[SHZ_CMDLINE_MAX - 1] = 0;
    const int has_kernel32_peer = k64_boot_has_kernel32_peer(&bootinfo);
    if (has_kernel32_peer < 0)
        shz_exit(97); /* Malformed peer handoff is a real failure. */
    arch_init();
    mem_init(&bootinfo);
    shz_cpu_bringup_prepare(&bootinfo,initial_cr3);
    ds_native_init();
    krandom_init(&bootinfo, sizeof bootinfo);       /* before anything that needs random bytes (ASLR, user RNG) */
    kprintf("%s: Long Mode kernel starting, %u MiB RAM, rip above 4 GiB, tsc %u kHz\n", KVER,
            (uint32_t)(bootinfo.ram_size >> 20), (uint32_t)(bootinfo.tsc_hz / 1000));
    kprintf("%s: boot info ABI %u.%u, %u bytes%s\n", KVER, bootinfo.abi_major, bootinfo.abi_minor, bootinfo.size,
            (bootinfo.flags & SHZ_BIF_UEFI_DIRECT) ? ", started directly by the UEFI boot manager (no Supervisor)" : "");
    if (bootinfo.cmdline[0])
        kprintf("%s: command line \"%s\"\n", KVER, bootinfo.cmdline);
    if (!k64_boot_framebuffer(&fb))
        kprintf("%s: UEFI GOP framebuffer %ux%u, pitch %u, %s, at %llx (%llu KiB): available through "
                "k64_boot_framebuffer(); the GOP display backend (gfx_gop.c) drives it unless a virtio-gpu is present\n", KVER, fb.width, fb.height, fb.pitch,
                fb.format == SHZ_FB_BGRX8888 ? "BGRX" : "RGBX", fb.base, fb.size >> 10);
#ifdef SHZ_STANDALONE
    { extern void pci_log_devices(void); pci_log_devices(); }        /* device inventory; port I/O is only safe without the Supervisor */
#endif
    fs_init();
    if (bootinfo.initrd_size) {                 /* WIN64.IMG: \SHZ\SYS64 (ntdll, kernel32) and \SHZ\TESTS */
        const int files = fs_load_archive((const uint8_t *)p2v(bootinfo.initrd_gpa), bootinfo.initrd_size);
        if (files < 0)
            kprintf("%s: initrd archive rejected\n", KVER);
        else
            kprintf("%s: initrd mounted, %d file(s)\n", KVER, files);
        initrd_files = files;
    }
    { extern void disk_init(void); disk_init(); }   /* standalone profile: AHCI disk -> FAT32 volume as D:\ (disk.c) */
    sched_init();
    KASSERT(shz_timer_set(VEC_TIMER, TICK_US) == 0);
#ifdef SHZ_STANDALONE
    ds_native_timer_ready();
#endif
    sti();
    shz_cpu_bringup_verify();
    if (foundation_mode) {
        hcreg_t state = SHZ_DS_UNUSED;
        long status;
        /* Initialize the shared doorbell semaphore before either service uses
         * its IRQ. Windows owns this worker lifetime; QA suites are separate
         * acceptance workloads and must not delay real Windows requests. */
        ipc64_init(&bootinfo);
        kprintf("%s: native Win98 foundation service active\n", KVER);
        subsys64_start(&bootinfo);
        status = shz_hcall(SHZ_HC_DOMAIN_STATE, SHZ_DOM_WIN98, 0, &state);
        if (status != SHZ_OK ||
            (state != SHZ_DS_RUNNABLE && state != SHZ_DS_WAITING &&
             state != SHZ_DS_EXITED && state != SHZ_DS_FAILED))
            shz_exit(98);
        shz_exit(state == SHZ_DS_FAILED ? 1 : 0);
    }
    ds_native_control();
    if (k64_cmdline_has("shz.setup=interactive")) {
        extern unsigned k64_desktop(void);
        /* User installation starts without the diagnostic app suite. Cancelling
         * or closing its result returns to the real production shell. */
        setup_autostart(&bootinfo);
        shz_exit(k64_desktop());
    }
    if (k64_cmdline_has("shz.desktop")) {
        extern unsigned k64_desktop(void);
        /* The desktop is the boot workload. Its lifetime, rather than the QA suite,
         * decides when this profile exits; the normal-exit hook shuts down volumes. */
        shz_exit(k64_desktop());
    }
    run_self_tests(&bootinfo);
    /* NT driver host: the single init call. A complete no-op unless the initrd carries
     * \SHZ\DRIVERS (only tests/run_k64_ntdrv.py mounts such an image), so default runs are
     * unaffected. See docs/shizukudos10/NTDRV.md and kernel64/ntdrv_*.c. */
    { extern void ntdrv_selftest(void); ntdrv_selftest(); }
    setup_autostart(&bootinfo);
    { extern void k64_autorun(void); k64_autorun(); }   /* shz.autorun=<control file>: one Win64 program (autorun.c) */
#ifdef SHZ_STANDALONE
    { extern void k64_autorun_observe(void); k64_autorun_observe(); } /* explicit bounded post-autorun observation */
#endif
    if (has_kernel32_peer) {
        ipc64_init(&bootinfo);
        if (ipc64_run_tests())
            kprintf("K64: IPC tests reported failures\n");
    }
    subsys64_start(&bootinfo);                  /* WIN64 subsystem bridge: serves a Win98 peer, or its loopback self-test when standalone */
    report_final();
    kprintf("%s: done, %u self-test failure(s)\n", KVER, tests_failed());
    shz_exit(tests_failed() ? 1 : 0);
}
