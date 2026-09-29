/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 entry (C): CPU tables, memory, scheduler, timer, self-tests.
 */
#include "proc_internal.h"
#include "fs.h"

static shz_bootinfo_t bootinfo;
int initrd_files = -1;                          /* -1: none or rejected; read by the Win64 self-test */

int k64_boot_framebuffer(k64_boot_fb_t *out)
{
    const shz_bootinfo_t *b = &bootinfo;
    if (!SHZ_BOOTINFO_HAS(b, fb_bpp) || !b->fb_base || b->fb_bpp != 32 ||
        (b->fb_format != SHZ_FB_RGBX8888 && b->fb_format != SHZ_FB_BGRX8888) || !b->fb_width || !b->fb_height ||
        b->fb_pitch / 4 < b->fb_width || (uint64_t)b->fb_pitch * b->fb_height > b->fb_size)
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
    /* The boot mapping still shows physical memory at the kernel alias. */
    const shz_bootinfo_t *bi = (const shz_bootinfo_t *)(K64_VIRT_BASE + bootinfo_pa);
    k64_boot_fb_t fb;
    if (bi->magic != SHZ_BOOTINFO_MAGIC || bi->abi_major != SHZ_ABI_MAJOR || bi->domain_id != SHZ_DOM_KERNEL64 ||
        bi->size < __builtin_offsetof(shz_bootinfo_t, fb_base))
        shz_exit(97);
    /* Copy what the writer provided (`size`); a 1.0 writer's missing tail stays zero. */
    memcpy(&bootinfo, bi, bi->size < sizeof bootinfo ? bi->size : sizeof bootinfo);
    bootinfo.size = bi->size < sizeof bootinfo ? bi->size : sizeof bootinfo;
    bootinfo.cmdline[SHZ_CMDLINE_MAX - 1] = 0;
    arch_init();
    mem_init(&bootinfo);
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
    sti();
    run_self_tests(&bootinfo);
    /* NT driver host: the single init call. A complete no-op unless the initrd carries
     * \SHZ\DRIVERS (only tests/run_k64_ntdrv.py mounts such an image), so default runs are
     * unaffected. See docs/shizukudos10/NTDRV.md and kernel64/ntdrv_*.c. */
    { extern void ntdrv_selftest(void); ntdrv_selftest(); }
    setup_autostart(&bootinfo);
    if (bootinfo.channel_count) {
        ipc64_init(&bootinfo);
        if (ipc64_run_tests())
            kprintf("K64: IPC tests reported failures\n");
    }
    subsys64_start(&bootinfo);                  /* WIN64 subsystem bridge: serves a Win98 peer, or its loopback self-test when standalone */
    report_final();
    kprintf("%s: done, %u self-test failure(s)\n", KVER, tests_failed());
    shz_exit(tests_failed() ? 1 : 0);
}
