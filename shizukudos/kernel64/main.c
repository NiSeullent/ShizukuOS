/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 entry (C): CPU tables, memory, scheduler, timer and the selected boot profile.
 */
#include "proc_internal.h"
#include "../dead_screen/native.h"
#include "fs.h"
#include "boot_channel_peer.h"
#include "gfx_address.h"
#include "gfx.h"
#include "../boot_profile/win98_foundation.h"
#include "cpu_bringup.h"
#include "boot_storage.h"
#include "laptop_firmware.h"
#include "ntdrv.h"
#include "install_identity.h"

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

/* ROOT_K64_AP_CONSUMER_BEGIN */
#ifdef SHZ_STANDALONE
/* One BSP scratch allocation survives all batches. Submission copies its bytes
 * before returning; the oracle never reads the provider's job/result. Keeping
 * payloads out of BSS preserves the loader's fixed image/heap boundary. */
static uint8_t *k64_ap_payload;
static uint64_t k64_ap_cookie[16], k64_ap_expected[16], k64_ap_history[512];
static uint8_t k64_ap_done[16];

static __attribute__((noreturn)) void k64_ap_component_fail(const char *phase,
        unsigned generation, unsigned slot, uint64_t cookie, int rc)
{
    kprintf("SMP-WORK FAIL: phase=%s generation=%u slot=%u cookie=%llx result=%d root_cleanup_attempted=0 exit=98\n",
            phase, generation, slot, cookie, rc);
    /* Exit98 bypasses shutdown/VFS callbacks while private AP admission may
     * remain closed. A failed send/move can already have committed ownership. */
    shz_exit(98);
}

static int k64_ap_component_budget(uint64_t start, unsigned *spins)
{
    if (ticks_now() - start >= 500 || *spins >= 100000000u)
        return 0;
    ++*spins;
    return 1;
}

static uint64_t k64_ap_reference(const uint8_t *payload)
{
    uint64_t value = 14695981039346656037ull;
    for (unsigned traversal = 0; traversal != 256; ++traversal)
        for (unsigned byte = 0; byte != 4096; ++byte) {
            value ^= (uint64_t)payload[byte];
            value *= 1099511628211ull;
        }
    return value;
}

static uint64_t k64_ap_eligibility(uint64_t online, unsigned sequence)
{
    unsigned count = 0;
    for (unsigned cpu = 1; cpu != 32; ++cpu)
        count += !!(online & (1ull << cpu));
    if (!count)
        return 0;
    unsigned selected = sequence % count;
    for (unsigned cpu = 1; cpu != 32; ++cpu)
        if ((online & (1ull << cpu)) && selected-- == 0)
            return 1ull << cpu;
    return 0;
}

static void k64_ap_component_empty(unsigned generation, uint64_t online)
{
    const uint64_t start = ticks_now();
    unsigned spins = 0;
    if (generation == 1 || generation == 16) {
        if (online & (1ull << 2)) {
            const unsigned destination = generation == 1 ? 2 : 1;
            for (;;) {
                if (!k64_ap_component_budget(start, &spins))
                    k64_ap_component_fail("move-deadline", generation, 0, 0, -1);
                const int rc = sched_ap_work_migrate(1, 0, destination);
                if (rc == 0) {
                    kprintf("SMP-WORK MOVE: generation=%u origin=1 slot=0 destination=%u result=0\n",
                            generation, destination);
                    break;
                }
                if (rc != K64_AP_WORK_BUSY)
                    k64_ap_component_fail("move", generation, 0, 0, rc);
                __asm__ volatile("pause");
            }
        } else if (generation == 1) {
            /* These two operations are explicit native2 negative controls.
             * They cannot be treated as retries of a failed positive move. */
            const int offline = sched_ap_work_migrate(1, 0, 2);
            if (offline != -1)
                k64_ap_component_fail("offline-control", generation, 0, 0, offline);
            kprintf("SMP-WORK REFUSAL: origin=1 slot=0 destination=2 result=-1 offline=1\n");
            for (;;) {
                if (!k64_ap_component_budget(start, &spins))
                    k64_ap_component_fail("self-control-deadline", generation, 0, 0, -1);
                const int rc = sched_ap_work_migrate(1, 0, 1);
                if (rc == -1) {
                    kprintf("SMP-WORK REFUSAL: origin=1 slot=0 destination=1 result=-1 self=1\n");
                    break;
                }
                if (rc != K64_AP_WORK_BUSY)
                    k64_ap_component_fail("self-control", generation, 0, 0, rc);
                __asm__ volatile("pause");
            }
        }
    }
    for (;;) {
        if (!k64_ap_component_budget(start, &spins))
            k64_ap_component_fail("empty-deadline", generation, 0, 0, -1);
        if (sched_cpu_online_mask() != online)
            k64_ap_component_fail("empty-online", generation, 0, 0, -1);
        const uint64_t end = ticks_now();
        if (end - start >= 500)
            k64_ap_component_fail("empty-return-deadline", generation, 0, 0, -1);
        if (end - start >= 20) {
            kprintf("SMP-WORK EMPTY: generation=%u start=%llu end=%llu online=%llx\n",
                    generation, start, end, online);
            return;
        }
        __asm__ volatile("pause");
    }
}

static void k64_persistent_ap_component(void)
{
    if (tests_failed())
        k64_ap_component_fail("up-qa", 0, 0, 0, -1);
    thread_reap_exited();
    int rc = sched_ap_work_quiescent();
    if (rc)
        k64_ap_component_fail("quiescent", 0, 0, 0, rc);
    k64_ap_payload = kmalloc(4096);
    if (!k64_ap_payload)
        k64_ap_component_fail("payload-alloc", 0, 0, 0, -1);
    rc = shz_cpu_workers_start();
    if (rc)
        k64_ap_component_fail("start", 0, 0, 0, rc);
    const uint64_t online = sched_cpu_online_mask();
    if (!(online & 1) || !(online & 2) || (online >> 32))
        k64_ap_component_fail("online", 0, 0, 0, -1);
    unsigned submitted = 0, completed = 0, released = 0;
    for (unsigned generation = 1; generation <= 32; ++generation) {
        const uint64_t start = ticks_now();
        unsigned spins = 0, remaining = 16;
        for (unsigned slot = 0; slot != 16; ++slot) {
            for (unsigned byte = 0; byte != 4096; ++byte)
                k64_ap_payload[byte] = (uint8_t)((generation * 17u + slot * 29u + byte * 7u) ^
                        (byte >> 3) ^ (generation >> 3));
            k64_ap_expected[slot] = k64_ap_reference(k64_ap_payload);
            k64_ap_cookie[slot] = 0;
            k64_ap_done[slot] = 0;
            if (!k64_ap_component_budget(start, &spins))
                k64_ap_component_fail("submit-deadline", generation, slot, 0, -1);
            const uint64_t eligible = k64_ap_eligibility(online, (generation - 1) * 16 + slot);
            rc = sched_ap_work_submit(k64_ap_payload, 4096, eligible, &k64_ap_cookie[slot]);
            if (rc)
                k64_ap_component_fail("submit", generation, slot, k64_ap_cookie[slot], rc);
            /* Poison the submitted source immediately, including the final
             * slot, so a borrowed source cannot satisfy the saved oracle. */
            memset(k64_ap_payload, 0xa5, 4096);
            if (!k64_ap_component_budget(start, &spins))
                k64_ap_component_fail("submit-return-deadline", generation, slot, k64_ap_cookie[slot], -1);
            if (!k64_ap_cookie[slot])
                k64_ap_component_fail("zero-cookie", generation, slot, 0, -1);
            for (unsigned prior = 0; prior != submitted; ++prior)
                if (k64_ap_history[prior] == k64_ap_cookie[slot])
                    k64_ap_component_fail("duplicate-cookie", generation, slot, k64_ap_cookie[slot], -1);
            k64_ap_history[submitted++] = k64_ap_cookie[slot];
        }
        while (remaining) {
            if (sched_cpu_online_mask() != online)
                k64_ap_component_fail("poll-online", generation, 0, 0, -1);
            for (unsigned slot = 0; slot != 16; ++slot) {
                if (k64_ap_done[slot])
                    continue;
                if (!k64_ap_component_budget(start, &spins))
                    k64_ap_component_fail("poll-deadline", generation, slot, k64_ap_cookie[slot], -1);
                uint64_t actual = 0;
                rc = sched_ap_work_poll(k64_ap_cookie[slot], &actual);
                if (!k64_ap_component_budget(start, &spins))
                    k64_ap_component_fail("poll-return-deadline", generation, slot, k64_ap_cookie[slot], -1);
                if (!rc)
                    continue;
                if (rc != 1)
                    k64_ap_component_fail("poll", generation, slot, k64_ap_cookie[slot], rc);
                if (actual != k64_ap_expected[slot])
                    k64_ap_component_fail("digest", generation, slot, k64_ap_cookie[slot], -1);
                const uint64_t observed = actual;
                ++completed;
                rc = sched_ap_work_release(k64_ap_cookie[slot]);
                if (rc)
                    k64_ap_component_fail("release", generation, slot, k64_ap_cookie[slot], rc);
                if (!k64_ap_component_budget(start, &spins))
                    k64_ap_component_fail("release-return-deadline", generation, slot, k64_ap_cookie[slot], -1);
                ++released;
                rc = sched_ap_work_poll(k64_ap_cookie[slot], &actual);
                if (rc != -1)
                    k64_ap_component_fail("stale-poll", generation, slot, k64_ap_cookie[slot], rc);
                if (!k64_ap_component_budget(start, &spins))
                    k64_ap_component_fail("stale-poll-return-deadline", generation, slot, k64_ap_cookie[slot], -1);
                rc = sched_ap_work_release(k64_ap_cookie[slot]);
                if (rc != -1)
                    k64_ap_component_fail("stale-release", generation, slot, k64_ap_cookie[slot], rc);
                if (!k64_ap_component_budget(start, &spins))
                    k64_ap_component_fail("stale-release-return-deadline", generation, slot, k64_ap_cookie[slot], -1);
                k64_ap_done[slot] = 1;
                --remaining;
                kprintf("SMP-WORK JOB: generation=%u slot=%u cookie=%llx digest=%llx expected=%llx released=1\n",
                        generation, slot, k64_ap_cookie[slot], observed, k64_ap_expected[slot]);
            }
            if (remaining)
                __asm__ volatile("pause");
        }
        if (!k64_ap_component_budget(start, &spins))
            k64_ap_component_fail("generation-return-deadline", generation, 0, 0, -1);
        if (generation == 1 || generation == 16 || generation == 31)
            k64_ap_component_empty(generation, online);
    }
    if (submitted != 512 || completed != 512 || released != 512)
        k64_ap_component_fail("totals", 32, 0, 0, -1);
    rc = sched_ap_work_stop();
    if (rc)
        k64_ap_component_fail("stop", 32, 0, 0, rc);
    if (sched_cpu_online_mask() != 1 || sched_validate() != 1 || sched_ap_work_quiescent())
        k64_ap_component_fail("stopped-validation", 32, 0, 0, -1);
    kfree(k64_ap_payload);
    k64_ap_payload = 0;
    kprintf("SMP-WORK consumer: submitted=%u completed=%u released=%u batches=32 empty=3 scheduler_cpus=1 result=0\n",
            submitted, completed, released);
}
#endif
/* ROOT_K64_AP_CONSUMER_END */

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
    /* routing02 C3: attested installed-target identity (SHZBOOT.MAN) before driver bring-up; <0 logs MALFORMED
     * and leaves the target unattested, never attested. */
    (void)k64_install_identity_init(&bootinfo);
    {   /* driver bring-up EARLY phase (ntdrv_pnp.c): records the boot route; laptop firmware discovery only on request */
        const int probe=k64_cmdline_has("shz.laptop=probe");
        const int result=shz_driver_bringup_init(&bootinfo, SHZ_BRINGUP_PHASE_EARLY, probe ? SHZ_BRINGUP_F_LAPTOP_FIRMWARE : 0);
        if(probe) {
        const struct shz_laptop_firmware *laptop=k64_laptop_firmware_snapshot();
        if(laptop)
            kprintf("LAPTOP-FIRMWARE: result=%d rsdp=%llx root=%llx fadt=%llx ecdt=%llx tables=%u register_access=0\n",
                    result,laptop->rsdp_pa,laptop->root_pa,laptop->fadt_pa,laptop->ecdt_pa,laptop->entry_count);
        else
            kprintf("LAPTOP-FIRMWARE: result=%d snapshot=absent register_access=0\n",result);
        }
    }
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
    if(initrd_files>=0) gfx_caption_cache_init();     /* zero-copy immutable font cache, before any process or scheduler */
    else kprintf("K64 caption: renderer=legacy-8x16-ASCII fallback archive=absent-or-rejected\n");
    { extern void disk_init(void); disk_init(); }   /* standalone profile: AHCI disk -> FAT32 volume as D:\ (disk.c) */
    if(k64_boot_storage_bind(&bootinfo,initrd_files>=0))
        kprintf("K64 install authority: boot/archive physical mapping unavailable; native claim refused\n");
    sched_init();
    KASSERT(shz_timer_set(VEC_TIMER, TICK_US) == 0);
#ifdef SHZ_STANDALONE
    ds_native_timer_ready();
#endif
    sti();
    shz_cpu_bringup_verify();
    { extern void k64_auth_store_bind(void); k64_auth_store_bind(); }  /* account realm persistence (auth_store_sfs.c) before any user process */
    if (foundation_mode) {
        hcreg_t state = SHZ_DS_UNUSED;
        long status;
        /* Initialize the shared doorbell semaphore before either service uses
         * its IRQ. Windows owns this worker lifetime; QA suites are separate
         * acceptance workloads and must not delay real Windows requests. */
        ipc64_init(&bootinfo);
        kprintf("%s: native Win98 foundation service active\n", KVER);
        /* Driver bring-up report for ShizukuCore (C4): foundation profile, native drivers only, no catalog services. */
        (void)shz_driver_bringup_init(&bootinfo, SHZ_BRINGUP_PHASE_DEVICES, SHZ_BRINGUP_F_FOUNDATION | SHZ_BRINGUP_F_QUIET);
        subsys64_start(&bootinfo);
        status = shz_hcall(SHZ_HC_DOMAIN_STATE, SHZ_DOM_WIN98, 0, &state);
        if (status != SHZ_OK ||
            (state != SHZ_DS_RUNNABLE && state != SHZ_DS_WAITING &&
             state != SHZ_DS_EXITED && state != SHZ_DS_FAILED))
            shz_exit(98);
        shz_exit(state == SHZ_DS_FAILED ? 1 : 0);
    }
    {   /* Installed driver binding: PCI enumeration -> catalog match -> existing driver-load path,
         * per-device results logged as DRIVER-BRINGUP (ntdrv_pnp.c). Not reached in foundation mode. */
        const int bound = shz_driver_bringup_init(&bootinfo, SHZ_BRINGUP_PHASE_DEVICES, SHZ_BRINGUP_F_LOAD_SERVICES);
        if (bound < 0)
            kprintf("%s: driver bring-up: %d device(s) failed to start\n", KVER, -bound);
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
#ifdef SHZ_STANDALONE
    if (shz_cpu_workers_requested())
        k64_persistent_ap_component();
#endif
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
