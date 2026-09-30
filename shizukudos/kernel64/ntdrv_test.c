/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: in-kernel demonstration. Invoked once from kmain when the initrd
 * carries \SHZ\DRIVERS (only the dedicated ntdrv runner mounts such an image, so the default
 * kernel runs are untouched). It loads the unmodified test .sys drivers, drives them through
 * the real IRP path from ring 0 and reports results in evidence slots 13,14,15,25,26,27 and the serial line "apitest N passed, M failed" for
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


/* ---- KMDF: the unmodified WdfLdr + Wdf01000 framework and a KMDF client from the driver corpus. Only the KMDF runner image
 * (win64/ntdrv/kmdf_image.py) carries WDFLDR.SYS, so every other run skips this. The client's FxDriverEntry calls
 * WdfVersionBind (an import from wdfldr.sys, which the loader satisfies by loading the export driver); WdfLdr looks the
 * library up under Services\Wdf01000, ZwLoadDriver()s it, and Wdf01000's DriverEntry registers with WdfLdr.
 * Results are printed as "K64 ntdrv-test: kmdf <step> ..." lines for the runner. */
extern NTSTATUS ntdrv_open_key_ascii(const char *path, int create, uint64_t *handle);
extern NTSTATUS ntdrv_set_value_ascii(uint64_t key, const char *name, uint32_t type, const void *data, uint32_t len);
extern int32_t ZwClose(uint64_t h) __attribute__((ms_abi));
extern NTSTATUS NTAPI ntdrv_default_dispatch(DEVICE_OBJECT *dev, IRP *irp);   /* ntdrv_io.c: what the host installs before DriverEntry */

static void seed_sz(const char *keypath, const char *name, uint32_t type, const char *value)
{
    uint64_t h = 0;
    WCHAR w[200];
    int n;
    if (ntdrv_open_key_ascii(keypath, 1, &h) != 0) return;
    n = ntdrv_ascii_to_wide(value, w, 199);
    ntdrv_set_value_ascii(h, name, type, w, (uint32_t)(n + 1) * 2);
    ZwClose(h);
}
static void seed_dword(const char *keypath, const char *name, uint32_t value)
{
    uint64_t h = 0;
    if (ntdrv_open_key_ascii(keypath, 1, &h) != 0) return;
    ntdrv_set_value_ascii(h, name, 4, &value, 4);
    ZwClose(h);
}

static void kmdf_selftest(int *pass)
{
    static const char svc[] = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
    char key[160];
    fsnode_t *n;
    ntdrv_driver_t *client = 0;
    int32_t st;
    unsigned i, k;
    const char *clients[2] = { "CDROM.SYS", "HDAUDBUS.SYS" };
    if (!fs_lookup("\\SHZ\\DRIVERS\\WDFLDR.SYS")) return;
    kprintf("K64 ntdrv-test: kmdf: KMDF image present, seeding the framework service\n");
    for (k = 0; svc[k]; ++k) key[k] = svc[k];
    memcpy(key + k, "Wdf01000", 9);                             /* the default service WdfLdr falls back to for KMDF 1.x */
    seed_sz(key, "ImagePath", 2, "\\SystemRoot\\DRIVERS\\WDF01000.SYS");
    seed_dword(key, "Type", 1);
    seed_dword(key, "Start", 3);
    seed_dword("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Wdf\\Kmdf\\Diagnostics", "DbgPrintOn", 1);
    seed_dword("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Wdf\\Kmdf\\Diagnostics", "VerboseLogging", 1);
    for (i = 0; i < 2; ++i) {
        char service[32];
        unsigned j = 0, m;
        for (m = 0; clients[i][m] && clients[i][m] != '.'; ++m) service[j++] = clients[i][m] >= 'A' && clients[i][m] <= 'Z' ? (char)(clients[i][m] + 32) : clients[i][m];
        service[j] = 0;
        for (m = 0; svc[m]; ++m) key[m] = svc[m];
        memcpy(key + m, service, j + 1);
        seed_dword(key, "Type", 1);                              /* the client's own service key (its RegistryPath) */
        seed_dword(key, "Start", 3);
        {
            char path[64]; unsigned q = 0, r;
            const char *pfx = "\\SHZ\\DRIVERS\\";
            for (r = 0; pfx[r]; ++r) path[q++] = pfx[r];
            for (r = 0; clients[i][r]; ++r) path[q++] = clients[i][r];
            path[q] = 0;
            n = fs_lookup(path);
        }
        if (!n) { kprintf("K64 ntdrv-test: kmdf: %s not in the image\n", clients[i]); *pass = 0; continue; }
        client = 0;
        st = ntdrv_load_node(n, service, &client);
        kprintf("K64 ntdrv-test: kmdf: client %s load status=%x started=%d\n", service, (uint32_t)st, client ? client->started : 0);
        if (st != 0) *pass = 0;
        else {
            ntdrv_driver_t *lib = ntdrv_find_driver("Wdf01000"), *ldr = ntdrv_find_driver("wdfldr");
            DRIVER_OBJECT *d = client->drv;
            kprintf("K64 ntdrv-test: kmdf: framework loaded=%d loader loaded=%d\n", lib ? lib->started : 0, ldr ? ldr->started : 0);
            /* WdfDriverCreate's visible effect on the client's DRIVER_OBJECT: the framework installs AddDevice, DriverUnload and its
             * own IRP dispatch (every major function the host initialised to its default dispatch is replaced). */
            {
                unsigned replaced = 0, m;
                for (m = 0; m <= IRP_MJ_MAXIMUM_FUNCTION; ++m) if (d->MajorFunction[m] != ntdrv_default_dispatch) ++replaced;
                kprintf("K64 ntdrv-test: kmdf: client %s WdfDriverCreate effect: AddDevice=%s DriverUnload=%s framework dispatch in %u major functions\n",
                        service, d->DriverExtension && d->DriverExtension->AddDevice ? "set" : "NULL", d->DriverUnload ? "set" : "NULL", replaced);
            }
        }
    }
}

/* ---- the whole driver corpus: only the corpus image (win64/ntdrv/kmdf_image.py --all) has more than the test drivers in
 * \SHZ\DRIVERS. Every other image in the store is loaded once, under its file name as service name, and the outcome is
 * printed per driver plus a total. Export drivers get loaded on demand by the drivers that import them. */
static void corpus_selftest(void)
{
    fsnode_t *dir = fs_lookup("\\SHZ\\DRIVERS"), *n;
    unsigned total = 0, loaded = 0;
    if (!dir || !dir->is_dir || !fs_lookup("\\SHZ\\DRIVERS\\CDROM.SYS")) return;      /* not the corpus image */
    for (n = dir->child; n; n = n->sibling) {
        char service[48];
        unsigned i = 0;
        ntdrv_driver_t *d = 0;
        int32_t st;
        if (n->is_dir) continue;
        while (n->name[i] && n->name[i] != '.' && i < sizeof service - 1) { service[i] = n->name[i] >= 'A' && n->name[i] <= 'Z' ? (char)(n->name[i] + 32) : n->name[i]; ++i; }
        service[i] = 0;
        if (!strcmp(service, "echo") || !strcmp(service, "dpctimer") || !strcmp(service, "pciedu") || !strcmp(service, "apitest")) continue;
        ++total;
        d = ntdrv_find_driver(service);
        if (d) { st = 0; }                                       /* loaded already as another driver's export driver */
        else { d = 0; st = ntdrv_load_node(n, service, &d); }
        if (st == 0 && d && d->started) ++loaded;
        kprintf("K64 ntdrv-test: corpus %s status=%x started=%d\n", service, (uint32_t)st, d ? d->started : 0);
    }
    kprintf("K64 ntdrv-test: corpus: %u of %u drivers loaded (DriverEntry returned success)\n", loaded, total);
}

void ntdrv_selftest(void)
{
    ntdrv_driver_t *echo = 0, *dpc = 0, *pci = 0;
    DEVICE_OBJECT *dev;
    int loaded = 0, pass = 1;
    uint32_t provider_total = ntdrv_ntoskrnl_export_count + ntdrv_hal_export_count;

    if (!fs_lookup("\\SHZ\\DRIVERS")) return;                 /* default runs mount no driver store: complete no-op */
    ntdrv_gs_enter();                                         /* this thread runs driver code: GS -> its KPCR */
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
            if (r.fail || !r.pass) pass = 0;
        } else { pass = 0; kprintf("K64 ntdrv-test: apitest driver failed to load\n"); }
    }

    kmdf_selftest(&pass);
    corpus_selftest();
    shz_evidence(13, loaded);
    shz_evidence(27, ((uint64_t)pass << 32) | provider_total);
    kprintf("K64 ntdrv-test: %d driver(s) exercised, overall %s\n", loaded, pass ? "PASS" : "FAIL");
}
