/* SPDX-License-Identifier: GPL-2.0-only
 * Driver-package install AND load, end to end, through SHZPNP.EXE (the driver-package CLI) on the NT driver host:
 * the unmodified ECHO.SYS test driver (built with the DDK from win64/drivers/echo.c, shipped as test data at
 * \SHZ\TESTS\ECHO.SYS) is packaged with a synthetic INF for a PCI function the Kernel64 bus scan reports, installed
 * with `shzpnp add-driver --install` (service key, Enum device key, CopyFiles), loaded with `shzpnp load` (NtLoadDriver:
 * image mapped, DriverEntry run, the Enum-bound PCI function claimed as ntdrv:shzecho), reached from user mode
 * (CreateFile \\.\ShzEcho + an IOCTL round trip), listed by `shzpnp status`, unloaded with `shzpnp unload` (claim
 * released, device gone) and loaded again (left loaded so the status screen shows the ntdrv: claim). The error paths
 * are exercised too: no service key, missing image, a non-PE image, and an image with an unresolvable import (a copy
 * of ECHO.SYS with one import name altered), none of which may fault the kernel. Expected values come from documented
 * Windows semantics (NtLoadDriver/NtUnloadDriver statuses, DeviceIoControl) and from this program's own inputs, never
 * from shzpnp's output. Without the driver host (exit 3 from shzpnp) the load checks are reported as SKIP.
 */
#include "reg_check.h"

#define PKG "C:\\SHZTEST\\DRV"
#define ECHO_SRC "C:\\SHZ\\TESTS\\ECHO.SYS"
#define IOCTL_SHZ_ECHO 0x222000u          /* CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) */

LONG NTAPI NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
LONG NTAPI NtDeviceIoControlFile(HANDLE, HANDLE, PVOID, PVOID, PVOID, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef struct { BYTE bus, dev, fn, cls, sub, pif, irq, pad; WORD vendor, device; DWORD pad2; char driver[24]; } k64_pci_t;

static int write_file(const char *path, const void *data, DWORD n)
{
    WCHAR w[300];
    HANDLE h;
    DWORD done = 0;
    MultiByteToWideChar(CP_UTF8, 0, path, -1, w, 300);
    h = CreateFileW(w, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    WriteFile(h, data, n, &done, 0);
    CloseHandle(h);
    return done == n;
}

static int read_file(const char *path, unsigned char *buf, DWORD cap)
{
    WCHAR w[300];
    HANDLE h;
    DWORD done = 0;
    MultiByteToWideChar(CP_UTF8, 0, path, -1, w, 300);
    h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if (h == INVALID_HANDLE_VALUE) return -1;
    ReadFile(h, buf, cap, &done, 0);
    CloseHandle(h);
    return (int)done;
}

static void mkdir_a(const char *p) { WCHAR w[300]; MultiByteToWideChar(CP_UTF8, 0, p, -1, w, 300); CreateDirectoryW(w, 0); }

/* runs SHZPNP.EXE <args>; returns its exit code (or -1) */
static int shzpnp(const char *args)
{
    WCHAR cmd[600];
    char a[600];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD code = 0xffffffff;
    shz_snprintf(a, sizeof a, "SHZPNP.EXE %s", args);
    MultiByteToWideChar(CP_UTF8, 0, a, -1, cmd, 600);
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    printf("--- shzpnp %s\n", args);
    if (!CreateProcessW(L"C:\\SHZ\\SYS64\\SHZPNP.EXE", cmd, 0, 0, FALSE, 0, 0, 0, &si, &pi)) return -1;
    if (WaitForSingleObject(pi.hProcess, 60000) != WAIT_OBJECT_0) return -1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    printf("--- exit %u\n", (unsigned)code);
    return (int)code;
}

/* the kernel driver bound to PCI b:d.f according to the kernel's own claim registry (NtQuerySystemInformation 0x101) */
static const char *claimed_by(unsigned bus, unsigned dev, unsigned fn)
{
    static k64_pci_t rows[32];
    static char none[] = "";
    ULONG n = 0, i;
    if (NtQuerySystemInformation(0x101, rows, sizeof rows, &n)) return none;
    for (i = 0; i < n && i < 32; ++i)
        if (rows[i].bus == bus && rows[i].dev == dev && rows[i].fn == fn) { rows[i].driver[23] = 0; return rows[i].driver; }
    return none;
}

/* a service key with Type=1 and the given ImagePath (REG_EXPAND_SZ), for the error paths */
static int make_service(const WCHAR *name, const WCHAR *imagepath)
{
    WCHAR key[200] = L"SYSTEM\\CurrentControlSet\\Services\\";
    HKEY k;
    DWORD one = 1, three = 3;
    LONG e;
    lstrcatW(key, name);
    e = RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, 0, 0, KEY_ALL_ACCESS, 0, &k, 0);
    if (e) return 0;
    e |= RegSetValueExW(k, L"Type", 0, REG_DWORD, (const BYTE *)&one, 4);
    e |= RegSetValueExW(k, L"Start", 0, REG_DWORD, (const BYTE *)&three, 4);
    if (imagepath) e |= RegSetValueExW(k, L"ImagePath", 0, REG_EXPAND_SZ, (const BYTE *)imagepath, (DWORD)((wl(imagepath) + 1) * 2));
    RegCloseKey(k);
    return e == 0;
}

static int echo_roundtrip(HANDLE h)
{
    static const char in[] = "PING-shzpnp";
    char out[32];
    struct { LONG_PTR st; ULONG_PTR info; } iosb = { 0, 0 };
    LONG st;
    memset(out, 0, sizeof out);
    st = NtDeviceIoControlFile(h, 0, 0, 0, &iosb, IOCTL_SHZ_ECHO, (PVOID)in, sizeof in - 1, out, sizeof out);
    printf("IOCTL_SHZ_ECHO: st=%08x info=%u out='%s'\n", (unsigned)st, (unsigned)iosb.info, out);
    return st == 0 && iosb.info == sizeof in - 1 && !memcmp(out, in, sizeof in - 1);
}

int main(void)
{
    static unsigned char img[65536];
    static char inf[1600];
    static k64_pci_t rows[32];
    ULONG nrows = 0;
    int n, code, i, pick = -1, len;
    unsigned bus = 0, dev = 0, fn = 0, vendor = 0x1AF4, device = 0x7002;
    char args[200];
    HANDLE h;

    mkdir_a("C:\\SHZTEST");
    mkdir_a(PKG);
    n = read_file(ECHO_SRC, img, sizeof img);
    CHECK(n > 512 && img[0] == 'M' && img[1] == 'Z', "the unmodified ECHO.SYS test driver is present as test data");
    if (n <= 0) return finish_tests("t_drv_load");
    CHECK(write_file(PKG "\\echo.sys", img, (DWORD)n), "package binary written");

    /* the target: a PCI function of the Kernel64 bus scan that no kernel driver drives and that is neither the
     * display (T_GUI_STATUS checks the display's own binding) nor a storage or network controller (T_DRV_PNP installs
     * the real e1000 driver on the NIC in run_k64_pnp.py/run_k64_gui.py --pnp); a bridge or the ISA/ACPI function of
     * the chipset qualifies; a hand-given device when the scan is unavailable */
    if (NtQuerySystemInformation(0x101, rows, sizeof rows, &nrows) == 0)
        for (i = 0; i < (int)nrows && i < 32; ++i)
            if (!rows[i].driver[0] && rows[i].cls != 3 && rows[i].cls != 2 && rows[i].cls != 1) pick = i;
    if (pick >= 0) {
        bus = rows[pick].bus; dev = rows[pick].dev; fn = rows[pick].fn;
        vendor = rows[pick].vendor; device = rows[pick].device;
        printf("target: PCI %02X:%02X.%X %04X:%04X (unclaimed function of the bus scan)\n", bus, dev, fn, vendor, device);
    } else {
        printf("target: hand-given device %04X:%04X (no PCI scan: claims are not checked)\n", vendor, device);
    }
    len = shz_snprintf(inf, sizeof inf,
        "; synthetic package for t_drv_load: the unmodified ECHO.SYS test driver on a scanned PCI function\r\n"
        "[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=System\r\nClassGUID={4d36e97d-e325-11ce-bfc1-08002be10318}\r\n"
        "Provider=%%Mfg%%\r\nDriverVer=09/30/2026,1.0.0.0\r\n\r\n"
        "[Manufacturer]\r\n%%Mfg%%=Echo,NTamd64\r\n\r\n"
        "[Echo.NTamd64]\r\n%%Desc%%=ECHO.Inst, PCI\\VEN_%04X&DEV_%04X\r\n\r\n"
        "[ECHO.Inst.NT]\r\nCopyFiles=ECHO.Copy\r\n\r\n"
        "[ECHO.Inst.NT.Services]\r\nAddService=shzecho, 2, ECHO.Svc\r\n\r\n"
        "[ECHO.Svc]\r\nDisplayName=%%Desc%%\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\nServiceBinary=%%12%%\\echo.sys\r\n\r\n"
        "[ECHO.Copy]\r\necho.sys\r\n\r\n"
        "[DestinationDirs]\r\nDefaultDestDir=12\r\n\r\n"
        "[Strings]\r\nMfg=\"Shizuku test\"\r\nDesc=\"Shizuku echo test driver\"\r\n", vendor, device);
    CHECK(write_file(PKG "\\shzecho.inf", inf, (DWORD)len), "package INF written");

    if (pick >= 0) shz_snprintf(args, sizeof args, "add-driver " PKG "\\shzecho.inf --install");
    else shz_snprintf(args, sizeof args, "add-driver " PKG "\\shzecho.inf --device %04X:%04X", vendor, device);
    code = shzpnp(args);
    CHECK(code == 0, "add-driver --install stages the package, creates Services\\shzecho and the Enum device key");
    n = read_file("C:\\SHZ\\SYS64\\DRIVERS\\echo.sys", img + 0, sizeof img);
    CHECK(n > 512 && img[0] == 'M', "CopyFiles put echo.sys into %12% = C:\\SHZ\\SYS64\\DRIVERS");

    code = shzpnp("status");
    if (code == 3) {
        printf("SKIP: the NT driver host is not present (shzpnp exit 3); load/unload/status not tested\n");
        return finish_tests("t_drv_load");
    }
    CHECK(code == 0, "status lists the loaded driver images (none required yet)");
    code = shzpnp("status shzecho");
    CHECK(code == 1, "status of a service that is not loaded: exit 1");

    code = shzpnp("load shzecho");
    CHECK(code == 0, "load shzecho: NtLoadDriver mapped ECHO.SYS and DriverEntry returned success");
    if (pick >= 0)
        CHECK(!strcmp(claimed_by(bus, dev, fn), "ntdrv:shzecho"), "the Enum-bound PCI function is claimed as ntdrv:shzecho (kernel claim registry, class 0x101)");
    h = CreateFileW(L"\\\\.\\ShzEcho", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    CHECK(h != INVALID_HANDLE_VALUE, "the device object the driver created opens from user mode (\\\\.\\ShzEcho -> IRP_MJ_CREATE)");
    if (h != INVALID_HANDLE_VALUE) {
        CHECK(echo_roundtrip(h), "an IOCTL round-trips through the loaded driver's dispatch routine");
        CloseHandle(h);
    }
    code = shzpnp("status shzecho");
    CHECK(code == 0, "status shzecho lists the image, its device object and PCI function");
    code = shzpnp("load shzecho");
    CHECK(code == 1, "loading a running service again: STATUS_IMAGE_ALREADY_LOADED, exit 1");

    /* error paths: none of these may fault the kernel; the checks after them prove it kept running */
    code = shzpnp("load nosuchservice");
    CHECK(code == 2, "load without a service key: exit 2");
    CHECK(make_service(L"shzmissing", L"\\SystemRoot\\SYS64\\DRIVERS\\nothere.sys"), "service with a missing image created");
    code = shzpnp("load shzmissing");
    CHECK(code == 2, "load of a service whose image file does not exist: clear message, exit 2");
    CHECK(write_file(PKG "\\notpe.sys", "not a PE image\r\n", 16), "non-PE payload written");
    CHECK(make_service(L"shznotpe", L"\\??\\" PKG "\\notpe.sys"), "service with a non-PE image created");
    code = shzpnp("load shznotpe");
    CHECK(code == 1, "load of a non-PE image: STATUS_INVALID_IMAGE_FORMAT, exit 1");
    {   /* an image with one import that nothing provides: ECHO.SYS with "IoCreateDevice" renamed in its import table */
        int patched = 0;
        n = read_file(ECHO_SRC, img, sizeof img);
        for (i = 0; n > 0 && i + 15 < n; ++i)
            if (!memcmp(img + i, "IoCreateDevice", 15)) { img[i + 13] = 'X'; patched = 1; break; }
        CHECK(patched, "a copy of ECHO.SYS with the import IoCreateDevice renamed to IoCreateDevicX prepared");
        CHECK(write_file("C:\\SHZ\\SYS64\\DRIVERS\\shzbadimp.sys", img, (DWORD)n), "written to SYS64\\DRIVERS");
        CHECK(make_service(L"shzbadimp", 0), "service without ImagePath (defaults to SYS64\\DRIVERS\\shzbadimp.sys) created");
        code = shzpnp("load shzbadimp");
        CHECK(code == 1, "load of an image with an unresolvable import: refused (STATUS_PROCEDURE_NOT_FOUND), exit 1, no fault");
    }
    {   /* an image that imports from itself: ECHO.SYS with the import DLL name "ntoskrnl.exe" replaced by its own file name
         * "shzloop1.sys" (same length). The loader must refuse the cycle, not load copies of it until the stack is gone. */
        int patched = 0;
        n = read_file(ECHO_SRC, img, sizeof img);
        for (i = 0; n > 0 && i + 13 <= n; ++i)
            if (!memcmp(img + i, "ntoskrnl.exe", 13)) { memcpy(img + i, "shzloop1.sys", 13); patched = 1; break; }
        CHECK(patched, "a copy of ECHO.SYS importing itself (import DLL name = its own file name) prepared");
        CHECK(write_file("C:\\SHZ\\SYS64\\DRIVERS\\shzloop1.sys", img, (DWORD)n), "written to SYS64\\DRIVERS");
        CHECK(make_service(L"shzloop1", 0), "service shzloop1 created");
        code = shzpnp("load shzloop1");
        CHECK(code == 1, "load of an image that imports itself: refused as an import cycle, exit 1, no recursion or fault");
    }
    code = shzpnp("unload nosuchservice");
    CHECK(code == 1, "unload of a service that is not loaded: exit 1");
    {   /* a device with a handle open on it keeps its driver loaded (the handle references the device object) */
        HANDLE hh = CreateFileW(L"\\\\.\\ShzEcho", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
        CHECK(hh != INVALID_HANDLE_VALUE, "the device opens again");
        code = shzpnp("unload shzecho");
        CHECK(code == 1, "unload while a handle is open on the device: refused (STATUS_CONNECTION_IN_USE), exit 1");
        if (hh != INVALID_HANDLE_VALUE) {
            CHECK(echo_roundtrip(hh), "the driver still answers after the refused unload");
            CloseHandle(hh);
        }
    }
    code = shzpnp("status shzecho");
    CHECK(code == 0, "the kernel and the loaded driver survived the error paths");

    code = shzpnp("unload shzecho");
    CHECK(code == 0, "unload shzecho: DriverUnload ran");
    if (pick >= 0)
        CHECK(claimed_by(bus, dev, fn)[0] == 0, "the PCI claim is released on unload");
    h = CreateFileW(L"\\\\.\\ShzEcho", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    CHECK(h == INVALID_HANDLE_VALUE, "the device object is gone after unload");
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    code = shzpnp("status shzecho");
    CHECK(code == 1, "status no longer lists the unloaded service");

    code = shzpnp("load shzecho");
    CHECK(code == 0, "the same service loads again after unload (left loaded for the status screen)");
    if (pick >= 0)
        CHECK(!strcmp(claimed_by(bus, dev, fn), "ntdrv:shzecho"), "the claim is back after the reload");
    return finish_tests("t_drv_load");
}
