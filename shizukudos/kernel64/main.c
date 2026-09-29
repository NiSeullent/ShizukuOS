/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 entry (C): CPU tables, memory, scheduler, timer, self-tests.
 */
#include "proc_internal.h"
#include "fs.h"

static shz_bootinfo_t bootinfo;
int initrd_files = -1;                          /* -1: none or rejected; read by the Win64 self-test */

void kmain(uint64_t bootinfo_pa)
{
    /* The boot mapping still shows physical memory at the kernel alias. */
    const shz_bootinfo_t *bi = (const shz_bootinfo_t *)(K64_VIRT_BASE + bootinfo_pa);
    if (bi->magic != SHZ_BOOTINFO_MAGIC || bi->abi_major != SHZ_ABI_MAJOR || bi->domain_id != SHZ_DOM_KERNEL64)
        shz_exit(97);
    memcpy(&bootinfo, bi, sizeof bootinfo);
    arch_init();
    mem_init(&bootinfo);
    kprintf("%s: Long Mode kernel starting, %u MiB RAM, rip above 4 GiB, tsc %u kHz\n", KVER,
            (uint32_t)(bootinfo.ram_size >> 20), (uint32_t)(bootinfo.tsc_hz / 1000));
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
    sched_init();
    KASSERT(shz_timer_set(VEC_TIMER, TICK_US) == 0);
    sti();
    run_self_tests(&bootinfo);
    if (bootinfo.channel_count) {
        ipc64_init(&bootinfo);
        if (ipc64_run_tests())
            kprintf("K64: IPC tests reported failures\n");
    }
    report_final();
    kprintf("%s: done, %u self-test failure(s)\n", KVER, tests_failed());
    shz_exit(tests_failed() ? 1 : 0);
}
