/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 installer support (SHZSETUP.EXE): block-device enumeration, raw sector I/O and the post-setup power
 * request (syscalls 0xb0-0xbf, setup_abi.h), and the `shz.setup=auto` autostart run after the boot self-tests.
 */
#include "proc_internal.h"
#include "fs.h"
#include "blk_compat.h"
#include "setup_abi.h"
#include "setup_native_sys.h"

extern int32_t ldr_create_process(process_t *parent, const char *image_path, const char *cmdline, const char *cwd,
                                  process_t **out_proc, thread_t **out_thread);

#define BOUNCE_BYTES (64u * 1024u)
static uint8_t *bounce;
static kmutex_t io_lock;
static int io_lock_ready;
static volatile int power_request = SHZ_SETUP_POWER_NONE;

static blk_dev_t *dev_at(uint64_t index, uint32_t *parent)
{
    blk_dev_t *d;
    uint64_t i = 0;
    blk_ram_init();
    for (d = blk_first(); d; d = d->next, ++i) {
        if (i != index) continue;
        if (parent) {
            blk_dev_t *x;
            uint32_t j = 0;
            *parent = 0xffffffffu;
            for (x = blk_first(); x && d->parent; x = x->next, ++j)
                if (x == d->parent) { *parent = j; break; }
        }
        return d;
    }
    return 0;
}

static int32_t blk_query(process_t *p, uint64_t index, uint64_t out, uint64_t size)
{
    shz_setup_blk_info_t info;
    uint32_t parent;
    blk_dev_t *d = dev_at(index, &parent);
    if (!d) return STATUS_NO_MORE_ENTRIES;
    if (size < sizeof info) return STATUS_BUFFER_TOO_SMALL;
    memset(&info, 0, sizeof info);
    info.index = (uint32_t)index;
    info.flags = ((d->flags & BLK_F_PARTITION) || d->parent ? SHZ_SETUP_BLK_PARTITION : 0) |
                 (d->flags & BLK_F_READONLY || !d->write || blk_user_write_busy(d) ? SHZ_SETUP_BLK_READONLY : 0) |
                 (d->flags & BLK_F_REMOVABLE ? SHZ_SETUP_BLK_REMOVABLE : 0);
    memcpy(info.name, d->name, sizeof info.name - 1);
    if (blk_ram_serial(d, info.serial, sizeof info.serial)) info.serial[0] = 0;
    info.sectors = d->sectors;
    info.sector_size = d->sector_size;
    info.parent = parent;
    return copy_to_user(p, out, &info, sizeof info) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
}

static int32_t blk_io(process_t *p, int write, uint64_t index, uint64_t lba, uint64_t count, uint64_t buf)
{
    blk_dev_t *d = dev_at(index, 0);
    uint64_t done = 0;
    int32_t st = STATUS_SUCCESS;
    unsigned per;
    if (!d) return STATUS_INVALID_HANDLE;
    if (!count || count > SHZ_SETUP_MAX_SECTORS || !d->sector_size || d->sector_size > BOUNCE_BYTES ||
        lba >= d->sectors || count > d->sectors - lba)
        return STATUS_INVALID_PARAMETER;
    if (write && ((d->flags & BLK_F_READONLY) || !d->write || blk_user_write_busy(d))) return STATUS_ACCESS_DENIED;
    if (!io_lock_ready) { mutex_init(&io_lock); io_lock_ready = 1; }
    mutex_lock(&io_lock);
    if (!bounce) bounce = kmalloc(BOUNCE_BYTES);
    if (!bounce) { mutex_unlock(&io_lock); return STATUS_NO_MEMORY; }
    per = BOUNCE_BYTES / d->sector_size;
    while (done < count && st == STATUS_SUCCESS) {
        const unsigned n = count - done < per ? (unsigned)(count - done) : per;
        const uint64_t bytes = (uint64_t)n * d->sector_size, uva = buf + done * d->sector_size;
        if (write) {
            if (copy_from_user(p, bounce, uva, bytes)) st = STATUS_ACCESS_VIOLATION;
            else if (blk_write(d, lba + done, n, bounce)) st = STATUS_IN_PAGE_ERROR;
        } else {
            if (blk_read(d, lba + done, n, bounce)) st = STATUS_IN_PAGE_ERROR;
            else if (copy_to_user(p, uva, bounce, bytes)) st = STATUS_ACCESS_VIOLATION;
        }
        done += n;
    }
    mutex_unlock(&io_lock);
    return st;
}

int32_t sys_ext_setup(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    (void)r;
    switch (num) {
    case 0xb5: return setup_native_syscall(cur,a1,a2);
    case SYS_NtShzSetupBlkQuery: return blk_query(cur, a1, a2, a3);
    case SYS_NtShzSetupBlkRead: return blk_io(cur, 0, a1, a2, a3, a4);
    case SYS_NtShzSetupBlkWrite: return blk_io(cur, 1, a1, a2, a3, a4);
    case SYS_NtShzSetupBlkFlush: {
        blk_dev_t *d = dev_at(a1, 0);
        if (!d) return STATUS_INVALID_HANDLE;
        return blk_flush(d) ? STATUS_IN_PAGE_ERROR : STATUS_SUCCESS;
    }
    case SYS_NtShzSetupPower:
        if (a1 > SHZ_SETUP_POWER_REBOOT) return STATUS_INVALID_PARAMETER;
        power_request = (int)a1;
        return STATUS_SUCCESS;
    default: return STATUS_INVALID_SYSTEM_SERVICE;
    }
}

/* ---------------------------------------------------------------- autostart */
#define SETUP_EXE "\\SHZ\\SETUP\\SHZSETUP.EXE"
#define SETUP_TIMEOUT_MS (60u * 60u * 1000u)

static int cmdline_has(const char *cmd, const char *word)
{
    const size_t n = strlen(word);
    const char *p = cmd;
    while (*p) {
        while (*p == ' ') ++p;
        if (!strncmp(p, word, n) && (p[n] == ' ' || p[n] == 0)) return 1;
        while (*p && *p != ' ') ++p;
    }
    return 0;
}

void setup_autostart(const shz_bootinfo_t *bi)
{
    const char *cmd = SHZ_BOOTINFO_HAS(bi, cmdline) ? bi->cmdline : "";
    process_t *p = 0;
    thread_t *t = 0;
    int64_t code = -1;
    int faulted = 1, reaped = -1;
    uint64_t waited = 0;
    int32_t st;
    const int interactive = cmdline_has(cmd, "shz.setup=interactive");
    if (!interactive && !cmdline_has(cmd, "shz.setup=auto")) return;
    kprintf("K64 setup: shz.setup=%s, %d RAM block device(s); starting %s\n",
            interactive ? "interactive" : "auto", blk_ram_init(), SETUP_EXE);
    if (!fs_lookup(SETUP_EXE)) {
        kprintf("K64 setup: %s is not in the initial RAM archive\n", SETUP_EXE);
        kprintf("SETUP-RESULT: FAIL (installer missing)\n");
        return;
    }
    st = ldr_create_process(0, SETUP_EXE,
                          interactive ? "SHZSETUP.EXE /interactive" : "SHZSETUP.EXE /unattend C:\\SHZ\\SETUP\\SHZSETUP.INI",
                          "C:\\SHZ\\SETUP", &p, &t);
    if (st) {
        kprintf("K64 setup: SHZSETUP.EXE failed to start (%x)\n", (uint32_t)st);
        kprintf("SETUP-RESULT: FAIL (installer did not start)\n");
        return;
    }
    while (!(p->terminated && p->threads_alive == 0) && waited < SETUP_TIMEOUT_MS) {
        thread_sleep_ms(10);
        waited += 10;
    }
    if (!p->terminated) {
        kprintf("K64 setup: SHZSETUP.EXE timed out after %u s, terminating\n", SETUP_TIMEOUT_MS / 1000u);
        process_terminate(p, 0x102, 1);
    }
    reaped = proc_wait(p->pid, &code, &faulted);
    kprintf("K64 setup: SHZSETUP.EXE exit=%d faulted=%d reaped=%d, power request %s\n", (int)code, faulted, reaped,
            power_request == SHZ_SETUP_POWER_REBOOT ? "reboot" : power_request == SHZ_SETUP_POWER_SHUTDOWN ? "shutdown" : "none");
#ifdef SHZ_STANDALONE
    if (power_request == SHZ_SETUP_POWER_REBOOT) {
        kprintf("K64 setup: rebooting (keyboard controller reset)\n");
        __asm__ volatile("outb %0, $0x64" :: "a"((uint8_t)0xfe));
        for (;;) __asm__ volatile("hlt");
    }
#endif
    if (interactive && power_request == SHZ_SETUP_POWER_SHUTDOWN) {
        kprintf("K64 setup: ending the standalone/domain profile after the shutdown request\n");
        shz_exit(code != 0 || faulted || reaped != 0 ? 1 : 0);
    }
    /* SHUTDOWN and NONE: return; kmain finishes and ends the domain (standalone: shz_exit ends the VM). */
}
