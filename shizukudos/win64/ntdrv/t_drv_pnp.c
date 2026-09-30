/* SPDX-License-Identifier: GPL-2.0-only
 * A real driver package on the NT driver host, end to end, on the e1000 NIC QEMU provides (PCI 8086:100e): the
 * unmodified ReactOS e1000 NDIS 5 miniport package (\DRIVERS\e1000\nete1000.inf + e1000.sys, put on the medium by
 * shizukudos/ntdrv/store.py) goes through SHZPNP.EXE match -> add-driver --legacy --install (its INF uses undecorated
 * Models sections, which Windows x64 ignores) -> load -> status, and the checks below look at what the system did:
 * the Services and Enum keys, the Net class installer's registry output (NetCfgInstanceId, Linkage\Export), the
 * kernel's claim registry (NtQuerySystemInformation 0x101: ntdrv:e1000 on the function), the driver host's records
 * (NtShzDriverQuery: e1000.sys and the ndis.sys it imports, the adapter device object \Device\{NetCfgInstanceId}),
 * and an IRP_MJ_CREATE to that device object from user mode. Expected values come from the INF, the Windows registry
 * layout the Net class installer produces, and this program's own reads, never from shzpnp's output.
 * Runs before T_GUI_STATUS.EXE (name order), so run_k64_gui.py --pnp shows the claim. Only packed by shizukudos/tests/run_k64_pnp.py (the initrd it composes carries the store and ndis.sys).
 */
#include "../tests/reg_check.h"

LONG NTAPI NtShzDriverQuery(PVOID, ULONG, PULONG);      /* kernel64/ntsys.h: the driver host's status records */
typedef struct { BYTE bus, dev, fn, cls, sub, pif, irq, pad; WORD vendor, device; DWORD pad2; char driver[24]; } k64_pci_t;
typedef struct {
    char service[64];
    unsigned long long image_base;
    DWORD image_size, flags, ndevices, npci;
    struct { BYTE bus, dev, fn, pad; } pci[4];
    char device[4][48];
} shz_drvinfo_t;

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
    if (WaitForSingleObject(pi.hProcess, 120000) != WAIT_OBJECT_0) return -1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    printf("--- exit %u\n", (unsigned)code);
    return (int)code;
}

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

static int q_sz(const WCHAR *key, const WCHAR *name, WCHAR *out, DWORD cap_bytes, DWORD *type)
{
    HKEY k;
    LONG e;
    DWORD n = cap_bytes;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &k)) return 0;
    e = RegQueryValueExW(k, name, 0, type, (BYTE *)out, &n);
    RegCloseKey(k);
    if (e) return 0;
    out[n / 2] = 0;
    return 1;
}

int main(void)
{
    static k64_pci_t rows[32];
    static shz_drvinfo_t drv[32];
    ULONG n = 0, i;
    int pick = -1, code;
    unsigned bus = 0, dev = 0, fn = 0;
    WCHAR enumkey[200], swkey[200], guid[64], v[300], devname[80];
    DWORD type;
    char inst[64];

    CHECK(NtQuerySystemInformation(0x101, rows, sizeof rows, &n) == 0 && n > 0, "the kernel reports its PCI scan");
    for (i = 0; i < n && i < 32; ++i)
        if (rows[i].vendor == 0x8086 && rows[i].device == 0x100e) pick = (int)i;
    CHECK(pick >= 0, "an Intel 82540EM (8086:100e, QEMU -device e1000) is on the bus");
    if (pick < 0) return finish_tests("t_drv_pnp");
    bus = rows[pick].bus; dev = rows[pick].dev; fn = rows[pick].fn;
    printf("e1000 at PCI %02X:%02X.%X irq %u, kernel driver '%s'\n", bus, dev, fn, rows[pick].irq, rows[pick].driver);
    CHECK(rows[pick].driver[0] == 0, "no Kernel64 driver claims the e1000 function before the package is loaded");
    shz_snprintf(inst, sizeof inst, "B%02XD%02XF%X", bus, dev, fn);
    MultiByteToWideChar(CP_UTF8, 0, inst, -1, v, 300);
    lstrcpyW(enumkey, L"SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_8086&DEV_100E\\");
    lstrcatW(enumkey, v);

    code = shzpnp("match --store C:\\DRIVERS");
    CHECK(code == 0, "match ranks the store's packages against the bus (the e1000 model only under the undecorated fallback)");
    code = shzpnp("add-driver C:\\DRIVERS\\e1000\\nete1000.inf --install");
    CHECK(code == 1, "add-driver without --legacy refuses the undecorated ReactOS INF (Windows x64 rule)");
    code = shzpnp("add-driver C:\\DRIVERS\\e1000\\nete1000.inf --legacy --install");
    CHECK(code == 0, "add-driver --legacy --install stages the package and installs it on the e1000 function");
    CHECK(q_sz(L"SYSTEM\\CurrentControlSet\\Services\\e1000", L"ImagePath", v, sizeof v - 2, &type) && type == REG_EXPAND_SZ &&
          weq_ci(v, L"\\SystemRoot\\SYS64\\DRIVERS\\e1000.sys"), "Services\\e1000 ImagePath = \\SystemRoot\\SYS64\\DRIVERS\\e1000.sys");
    CHECK(q_sz(enumkey, L"Service", v, sizeof v - 2, &type) && weq_ci(v, L"e1000"), "the e1000 function's Enum devnode names the service");
    CHECK(q_sz(enumkey, L"Driver", v, sizeof v - 2, &type) && weq_ci_n(v, L"{4D36E972-E325-11CE-BFC1-08002BE10318}\\", 39),
          "the devnode's Driver value points into the Net class");
    lstrcpyW(swkey, L"SYSTEM\\CurrentControlSet\\Control\\Class\\");
    lstrcatW(swkey, v);
    CHECK(q_sz(swkey, L"NetCfgInstanceId", guid, sizeof guid - 2, &type) && type == REG_SZ && guid[0] == '{' && wl(guid) == 38,
          "Net class installer output: NetCfgInstanceId = {GUID} in the software key");
    {
        WCHAR linkage[260];
        lstrcpyW(linkage, swkey);
        lstrcatW(linkage, L"\\Linkage");
        lstrcpyW(devname, L"\\Device\\");
        lstrcatW(devname, guid);
        CHECK(q_sz(linkage, L"Export", v, sizeof v - 2, &type) && type == REG_MULTI_SZ && weq_ci(v, devname),
              "Linkage\\Export = \\Device\\{NetCfgInstanceId} (REG_MULTI_SZ), what NDIS names the adapter's device object");
        {
            DWORD ch = 0;
            int ok = q_sz(swkey, L"Characteristics", v, sizeof v - 2, &type);
            memcpy(&ch, v, 4);
            CHECK(ok && type == REG_DWORD && ch == 4, "Characteristics = 0x4 (NCF_PHYSICAL) copied from the INF's DDInstall section");
        }
    }

    code = shzpnp("load e1000");
    CHECK(code == 0, "load e1000: ndis.sys loaded as its import dependency, DriverEntry succeeded, PnP start issued");
    CHECK(!strcmp(claimed_by(bus, dev, fn), "ntdrv:e1000"), "the kernel's claim registry binds the e1000 function to ntdrv:e1000");
    code = shzpnp("status e1000");
    CHECK(code == 0, "status e1000 lists the loaded image");
    code = shzpnp("status ndis");
    CHECK(code == 0, "status ndis lists the framework provider loaded on e1000's behalf");
    {
        ULONG cnt = 0;
        int found_e1000 = 0, found_ndis = 0, has_dev = 0, ndis_used = 0;
        char want[80];
        WideCharToMultiByte(CP_UTF8, 0, devname, -1, want, sizeof want, 0, 0);
        CHECK(NtShzDriverQuery(drv, sizeof drv, &cnt) == 0, "NtShzDriverQuery returns the loaded driver records");
        for (i = 0; i < cnt && i < 32; ++i) {
            DWORD j;
            if (!lstrcmpiA(drv[i].service, "e1000")) {
                found_e1000 = 1;
                for (j = 0; j < 4; ++j) if (!lstrcmpiA(drv[i].device[j], want)) has_dev = 1;
                CHECK(drv[i].npci == 1 && drv[i].pci[0].bus == bus && drv[i].pci[0].dev == dev && drv[i].pci[0].fn == fn,
                      "the e1000 record lists exactly the e1000 function");
            }
            if (!lstrcmpiA(drv[i].service, "ndis")) { found_ndis = 1; ndis_used = (drv[i].flags & 2) && ((drv[i].flags >> 8) & 0xff) >= 1; }
        }
        CHECK(found_e1000, "e1000 is a loaded, started image");
        CHECK(found_ndis && ndis_used, "ndis is loaded as an export driver with at least one user");
        CHECK(has_dev, "the adapter's device object \\Device\\{NetCfgInstanceId} exists (created by NDIS AddDevice)");
    }
    {   /* IRP_MJ_CREATE to the adapter (NdisICreateClose completes it with success) */
        HANDLE h = 0;
        SHZ_UNICODE_STRING us;
        SHZ_OBJECT_ATTRIBUTES oa;
        SHZ_IO_STATUS_BLOCK iosb;
        LONG st;
        us.Buffer = devname; us.Length = (USHORT)(wl(devname) * 2); us.MaximumLength = (USHORT)(us.Length + 2);
        memset(&oa, 0, sizeof oa);
        oa.Length = sizeof oa; oa.ObjectName = &us; oa.Attributes = 0x40;
        memset(&iosb, 0, sizeof iosb);
        st = NtCreateFile(&h, GENERIC_READ | GENERIC_WRITE, &oa, &iosb, 0, 0, 0, 1 /* FILE_OPEN */, 0, 0, 0);
        { char a[80]; WideCharToMultiByte(CP_UTF8, 0, devname, -1, a, sizeof a, 0, 0); printf("NtCreateFile(%s) = %08x\n", a, (unsigned)st); }
        CHECK(st == 0 && h, "the adapter's device object opens from user mode (IRP_MJ_CREATE reached the NDIS miniport's stack)");
        if (h) NtClose(h);
    }
    code = shzpnp("unload ndis");
    CHECK(code == 1, "unload ndis is refused while e1000 imports from it");
    code = shzpnp("load e1000");
    CHECK(code == 1, "loading e1000 again: already loaded");
    return finish_tests("t_drv_pnp");
}
