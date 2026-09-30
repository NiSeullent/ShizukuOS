/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: in-kernel demonstration. Invoked once from kmain when the initrd
 * carries \SHZ\DRIVERS (only the dedicated ntdrv runner mounts such an image, so the default
 * kernel runs are untouched). It loads the unmodified test .sys drivers, drives them through
 * the real IRP path from ring 0 and reports results in evidence slots 13,14,15,25,26,27 for
 * tests/run_k64_ntdrv.py to check. Results are computed from live behaviour, never asserted.
 */
#include "ntdrv.h"
#include "fs.h"

/* IOCTLs shared with the drivers (CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, func, METHOD_BUFFERED, 0)). */
#define IOCTL_SHZ_ECHO 0x222000u          /* func 0x800 */
#define IOCTL_SHZ_PEND 0x222004u          /* func 0x801: driver pends the IRP, completes from a timer DPC */

static int load_from_store(const char *file, const char *service, ntdrv_driver_t **out)
{
    char path[96];
    fsnode_t *n;
    unsigned i = 0, j;
    const char *pfx = "\\SHZ\\DRIVERS\\";
    if ((*out = ntdrv_find_driver(service)) != 0) {           /* already loaded (e.g. by T_NTDRV.EXE's NtLoadDriver) */
        kprintf("K64 ntdrv-test: %s already loaded, reusing it\n", service);
        return 0;
    }
    for (j = 0; pfx[j]; ++j) path[i++] = pfx[j];
    for (j = 0; file[j]; ++j) path[i++] = file[j];
    path[i] = 0;
    n = fs_lookup(path);
    if (!n || n->is_dir) { kprintf("K64 ntdrv-test: %s not present\n", path); return -1; }
    return ntdrv_load_node(n, service, out) == 0 ? 0 : -1;
}

void ntdrv_selftest(void)
{
    ntdrv_driver_t *echo = 0, *dpc = 0, *pci = 0;
    DEVICE_OBJECT *dev;
    int loaded = 0, pass = 1;
    uint32_t provider_total = ntdrv_ntoskrnl_export_count + ntdrv_hal_export_count;

    if (!fs_lookup("\\SHZ\\DRIVERS")) return;                 /* default runs mount no driver store: complete no-op */
    ntdrv_ke_init();                                          /* DPC + timer service threads (driver runs only) */

    kprintf("K64 ntdrv-test: providers = %u ntoskrnl + %u hal\n",
            ntdrv_ntoskrnl_export_count, ntdrv_hal_export_count);

    /* ---- echo IOCTL driver: full user-shaped IRP round trip from the kernel ---- */
    if (load_from_store("ECHO.SYS", "shzecho", &echo) == 0 && echo->started) {
        ++loaded;
        dev = ntdrv_find_device("\\Device\\ShzEcho");
        if (dev) {
            char out[32]; uint64_t info = 0; int32_t st;
            memset(out, 0, sizeof out);
            st = ntdrv_device_control(dev, IOCTL_SHZ_ECHO, "PING-ntdrv", 10, out, sizeof out, 0, &info);
            kprintf("K64 ntdrv-test: echo ioctl st=%x info=%u out='%s'\n", (uint32_t)st, (unsigned)info, out);
            if (st == 0 && info == 10 && !memcmp(out, "PING-ntdrv", 10)) shz_evidence(14, 0x100000000ull | info);
            else { pass = 0; shz_evidence(14, 0); }
        } else { pass = 0; kprintf("K64 ntdrv-test: echo device missing\n"); }
    } else { pass = 0; kprintf("K64 ntdrv-test: echo driver failed to load\n"); }

    /* ---- DPC / timer / system-thread driver, plus a pended IRP completed from a timer DPC ---- */
    if (load_from_store("DPCTIMER.SYS", "shzdpc", &dpc) == 0 && dpc->started) {
        uint64_t result = 0;
        ++loaded;
        /* DriverEntry ran the DPC+timer+thread self-check and returned STATUS_SUCCESS (started==1). */
        dev = ntdrv_find_device("\\Device\\ShzDpc");
        if (dev) {
            uint32_t out = 0; uint64_t info = 0;
            int32_t st = ntdrv_device_control(dev, IOCTL_SHZ_PEND, 0, 0, &out, 4, 0, &info);
            kprintf("K64 ntdrv-test: pended ioctl st=%x out=%x\n", (uint32_t)st, out);
            result = (st == 0 && out == 0xC0FFEE00u) ? 1 : 0;
        }
        shz_evidence(15, 0x100000000ull | result);
        if (!result) pass = 0;
    } else { pass = 0; kprintf("K64 ntdrv-test: dpctimer driver failed to load\n"); }

    /* ---- PCI driver over QEMU's 'edu' device (present only in the dedicated runner) ---- */
    if (load_from_store("PCIEDU.SYS", "shzpci", &pci) == 0 && pci->started) {
        ++loaded;
        dev = ntdrv_find_device("\\Device\\ShzPci");
        if (dev) {
            struct { uint32_t found, ident, isr; } r = { 0, 0, 0 };
            uint64_t info = 0;
            /* IOCTL_SHZ_PCIINFO shares func 0x800: returns {found, identification reg, ISR count}. */
            ntdrv_device_control(dev, IOCTL_SHZ_ECHO, 0, 0, &r, sizeof r, 0, &info);
            kprintf("K64 ntdrv-test: pci found=%u ident=%x isr=%u\n", r.found, r.ident, r.isr);
            shz_evidence(25, r.ident);
            shz_evidence(26, ((uint64_t)r.found << 32) | r.isr);
        }
    } else if (pci) {
        kprintf("K64 ntdrv-test: pciedu present but no edu device (skipped)\n");
    }

    /* ---- export-surface driver: every check inside its DriverEntry prints "apitest: PASS/FAIL <name>"; a failed
     * check makes DriverEntry fail, so `loaded` stays at 3 and the runner's "loaded 4 drivers" check fails ---- */
    {
        ntdrv_driver_t *api = 0;
        if (load_from_store("APITEST.SYS", "shzapi", &api) == 0 && api->started) {
            struct { uint32_t pass, fail; } r = { 0, 0 };
            uint64_t info = 0;
            ++loaded;
            dev = ntdrv_find_device("\\Device\\ShzApi");
            if (dev) ntdrv_device_control(dev, IOCTL_SHZ_ECHO /* IOCTL_SHZ_APIINFO shares func 0x800 */, 0, 0, &r, sizeof r, 0, &info);
            kprintf("K64 ntdrv-test: apitest %u passed, %u failed\n", r.pass, r.fail);
            shz_evidence(28, ((uint64_t)r.pass << 32) | r.fail);
            if (r.fail || !r.pass) pass = 0;
        } else { pass = 0; kprintf("K64 ntdrv-test: apitest driver failed to load\n"); }
    }

    shz_evidence(13, loaded);
    shz_evidence(27, ((uint64_t)pass << 32) | provider_total);
    kprintf("K64 ntdrv-test: %d driver(s) exercised, overall %s\n", loaded, pass ? "PASS" : "FAIL");
}
