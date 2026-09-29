/* SPDX-License-Identifier: GPL-2.0-only
 * shzpnp self-check: runs \SHZ\SYS64\SHZPNP.EXE (the driver-package CLI) as a child process on a synthetic driver
 * package written by this program, then checks what it did to the file system and the registry. Expected values
 * come from the INF below and the Windows INF documentation (AddService -> Services\<name>, AddReg type encoding,
 * .HW -> Device Parameters, DDInstall AddReg -> the Class software key), never from shzpnp's own output.
 * The payload is not a driver; `shzpnp load` must therefore never report success on it: without the NT driver host it
 * exits 3 ("driver host not present"), with it NtLoadDriver has to reject the image (exit 1).
 */
#include "reg_check.h"

#define PKG "C:\\SHZTEST\\PNP"
static const char INF[] =
    "; synthetic package for t_shzpnp (no vendor content)\r\n"
    "[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=Net\r\nClassGUID={4d36e972-e325-11ce-bfc1-08002be10318}\r\n"
    "Provider=%Mfg%\r\nDriverVer=03/14/2025,1.2.3.4\r\n\r\n"
    "[Manufacturer]\r\n%Mfg%=Synth,NTamd64.10.0...16299,NTx86\r\n\r\n"
    "[Synth.NTamd64.10.0...16299]\r\n%Desc%=SYN.ndi, PCI\\VEN_1AF4&DEV_7001&SUBSYS_00011AF4&REV_01\r\n"
    "%Desc%=SYN.ndi, PCI\\VEN_1AF4&DEV_7001\r\n\r\n"
    "[Synth.NTx86]\r\n%Desc%=SYN.x86, PCI\\VEN_1AF4&DEV_7001\r\n\r\n"
    "[SYN.ndi.NTamd64]\r\nCopyFiles=SYN.copy\r\nAddReg=SYN.reg\r\n\r\n"
    "[SYN.ndi.NTamd64.Services]\r\nAddService=synthpnp, 2, SYN.svc\r\n\r\n"
    "[SYN.ndi.NTamd64.HW]\r\nAddReg=SYN.hw\r\n\r\n"
    "[SYN.svc]\r\nDisplayName=%SvcDesc%\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n"
    "ServiceBinary=%12%\\synthpnp.sys\r\nLoadOrderGroup=NDIS\r\nAddReg=SYN.svc.reg\r\n\r\n"
    "[SYN.svc.reg]\r\nHKR,Parameters,Mode,0x00010001,5\r\nHKR,Parameters,Name,,\"a, \"\"quoted\"\" value\"\r\n\r\n"
    "[SYN.reg]\r\nHKR,Ndi,Service,0,\"synthpnp\"\r\nHKR,Ndi\\Interfaces,UpperRange,0x00010000,\"ndis5\",\"ndis6\"\r\n"
    "HKR,,Blob,0x00000001,01,02,ff\r\n\r\n"
    "[SYN.hw]\r\nHKR,,MSISupported,0x00010001,1\r\n\r\n"
    "[SYN.copy]\r\nsynthpnp.sys,,,2\r\n\r\n"
    "[DestinationDirs]\r\nDefaultDestDir=12\r\n\r\n"
    "[SourceDisksNames.amd64]\r\n1=%Disk%,,,x64\r\n\r\n[SourceDisksFiles]\r\nsynthpnp.sys=1\r\n\r\n"
    "[Strings]\r\nMfg=\"Synthetic Devices\"\r\nDesc=\"Synthetic PnP Adapter\"\r\nSvcDesc=\"Synthetic PnP Service\"\r\nDisk=\"disk\"\r\n";
static const char UNDECORATED[] =
    "[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=System\r\n[Manufacturer]\r\nX=Models\r\n[Models]\r\nD=I, ROOT\\SYNTHU\r\n[I]\r\n";
static const char PAYLOAD[] = "not a driver: shzpnp self-check payload\r\n";
static const char INDEX[] =
    "SHZDRV-INDEX\t1\tNTamd64.10.0...22631\r\n"
    "PKG\tSynth\t2\t100\r\n"
    "INF\tSynth\tsynth.inf\tNet\t{4d36e972-e325-11ce-bfc1-08002be10318}\tSynthetic\t03/14/2025, 1.2.3.4\t\r\n"
    "MODEL\tSynth\tsynth.inf\tW\tSYN.ndi\tSYN.ndi.NTamd64\t80\tFF\tsynthpnp\t%12%\\synthpnp.sys\t\t"
    "PCI\\VEN_1AF4&DEV_7001&SUBSYS_00011AF4&REV_01\t\tSynthetic PnP Adapter\r\n";

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

static int read_file(const char *path, char *buf, DWORD cap)
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

static DWORD q_dword(HKEY root, const WCHAR *sub, const WCHAR *name)
{
    HKEY k;
    DWORD v = 0xdeadbeef, n = 4, t = 0;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &k)) return 0xdeadbeef;
    if (RegQueryValueExW(k, name, 0, &t, (BYTE *)&v, &n) || t != REG_DWORD) v = 0xdeadbeef;
    RegCloseKey(k);
    return v;
}

/* value data + type (bytes in *n) */
static int q_raw(HKEY root, const WCHAR *sub, const WCHAR *name, DWORD *type, BYTE *buf, DWORD *n)
{
    HKEY k;
    LONG e;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &k)) return 0;
    e = RegQueryValueExW(k, name, 0, type, buf, n);
    RegCloseKey(k);
    return e == ERROR_SUCCESS;
}

static int q_sz_eq(HKEY root, const WCHAR *sub, const WCHAR *name, DWORD want_type, const WCHAR *want)
{
    WCHAR buf[300];
    DWORD t = 0, n = sizeof buf;
    if (!q_raw(root, sub, name, &t, (BYTE *)buf, &n) || t != want_type) return 0;
    return n == (wl(want) + 1) * 2 && weq(buf, want);
}

int main(void)
{
    char buf[256];
    int n, code;
    DWORD t, sz;
    BYTE raw[64];
    static const WCHAR SVC[] = L"SYSTEM\\CurrentControlSet\\Services\\synthpnp";
    static const WCHAR DEV[] = L"SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_1AF4&DEV_7001&SUBSYS_00011AF4&REV_01\\SHZ0000";
    static const WCHAR CLS[] = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\0000";

    mkdir_a("C:\\SHZTEST");
    mkdir_a(PKG);
    mkdir_a(PKG "\\x64");
    mkdir_a("C:\\SHZTEST\\STORE");
    CHECK(write_file(PKG "\\synth.inf", INF, sizeof INF - 1), "synthetic package INF written");
    CHECK(write_file(PKG "\\x64\\synthpnp.sys", PAYLOAD, sizeof PAYLOAD - 1), "payload written under the SourceDisksNames.amd64 path");
    CHECK(write_file("C:\\SHZTEST\\undecorated.inf", UNDECORATED, sizeof UNDECORATED - 1), "undecorated INF written");
    CHECK(write_file("C:\\SHZTEST\\STORE\\INDEX.TXT", INDEX, sizeof INDEX - 1), "store index written");

    code = shzpnp("help");
    CHECK(code == 0, "shzpnp help exits 0");
    code = shzpnp("add-driver " PKG "\\synth.inf --device 1AF4:7001:00011AF4:01:020000");
    CHECK(code == 0, "add-driver --device stages and installs the package");
    n = read_file("C:\\SHZ\\SYS64\\DRIVERS\\synthpnp.sys", buf, sizeof buf);
    CHECK(n == (int)sizeof PAYLOAD - 1 && !memcmp(buf, PAYLOAD, sizeof PAYLOAD - 1), "CopyFiles put the payload byte-identical into %12% = C:\\SHZ\\SYS64\\DRIVERS");
    n = read_file("C:\\SHZ\\INF\\oem0.inf", buf, sizeof buf);
    CHECK(n > 0 && !memcmp(buf, INF, (size_t)n), "the INF is published as C:\\SHZ\\INF\\oem0.inf");
    CHECK(q_dword(HKEY_LOCAL_MACHINE, SVC, L"Type") == 1 && q_dword(HKEY_LOCAL_MACHINE, SVC, L"Start") == 3 &&
          q_dword(HKEY_LOCAL_MACHINE, SVC, L"ErrorControl") == 1, "AddService: Type=1 Start=3 ErrorControl=1");
    CHECK(q_sz_eq(HKEY_LOCAL_MACHINE, SVC, L"ImagePath", REG_EXPAND_SZ, L"\\SystemRoot\\SYS64\\DRIVERS\\synthpnp.sys"),
          "ImagePath is REG_EXPAND_SZ \\SystemRoot\\SYS64\\DRIVERS\\synthpnp.sys");
    CHECK(q_sz_eq(HKEY_LOCAL_MACHINE, SVC, L"Group", REG_SZ, L"NDIS") && q_sz_eq(HKEY_LOCAL_MACHINE, SVC, L"DisplayName", REG_SZ, L"Synthetic PnP Service"),
          "LoadOrderGroup -> Group, DisplayName with %strkey% substituted");
    CHECK(q_dword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\synthpnp\\Parameters", L"Mode") == 5,
          "service AddReg (HKR = the service key): Parameters\\Mode REG_DWORD 5");
    CHECK(q_sz_eq(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\synthpnp\\Parameters", L"Name", REG_SZ, L"a, \"quoted\" value"),
          "quoted string with comma and doubled quotes");
    CHECK(q_sz_eq(HKEY_LOCAL_MACHINE, DEV, L"Service", REG_SZ, L"synthpnp"), "device key Service = the SPSVCINST_ASSOCSERVICE service");
    CHECK(q_sz_eq(HKEY_LOCAL_MACHINE, DEV, L"Driver", REG_SZ, L"{4d36e972-e325-11ce-bfc1-08002be10318}\\0000"), "device key Driver = {ClassGUID}\\0000");
    t = 0; sz = sizeof raw;
    CHECK(q_raw(HKEY_LOCAL_MACHINE, DEV, L"HardwareID", &t, raw, &sz) && t == REG_MULTI_SZ && sz > 90, "HardwareID is a REG_MULTI_SZ list");
    CHECK(q_dword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_1AF4&DEV_7001&SUBSYS_00011AF4&REV_01\\SHZ0000\\Device Parameters",
                  L"MSISupported") == 1, ".HW AddReg lands in Device Parameters");
    CHECK(q_sz_eq(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\0000\\Ndi",
                  L"Service", REG_SZ, L"synthpnp"), "DDInstall AddReg (HKR = software key): Ndi\\Service");
    t = 0; sz = sizeof raw;
    CHECK(q_raw(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\0000\\Ndi\\Interfaces",
                L"UpperRange", &t, raw, &sz) && t == REG_MULTI_SZ && sz == (6 + 6 + 1) * 2, "FLG_ADDREG_TYPE_MULTI_SZ: ndis5, ndis6");
    t = 0; sz = sizeof raw;
    CHECK(q_raw(HKEY_LOCAL_MACHINE, CLS, L"Blob", &t, raw, &sz) && t == REG_BINARY && sz == 3 && raw[0] == 1 && raw[1] == 2 && raw[2] == 0xff,
          "FLG_ADDREG_BINVALUETYPE: REG_BINARY 01 02 ff");
    CHECK(q_sz_eq(HKEY_LOCAL_MACHINE, CLS, L"MatchingDeviceId", REG_SZ, L"PCI\\VEN_1AF4&DEV_7001&SUBSYS_00011AF4&REV_01") &&
          q_sz_eq(HKEY_LOCAL_MACHINE, CLS, L"InfSection", REG_SZ, L"SYN.ndi.NTamd64"), "software key: best model (SUBSYS+REV) and its decorated DDInstall");
    {
        HKEY k;
        WCHAR v[80];
        DWORD vt = 0, vn = sizeof v;
        int ok = 0;
        if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\DriverDatabase\\DriverInfFiles\\oem0.inf", 0, KEY_READ, &k)) {
            ok = !RegQueryValueExW(k, L"", 0, &vt, (BYTE *)v, &vn) && vt == REG_SZ && weq_ci_n(v, L"synth.inf_amd64_", 16) && wl(v) == 24;
            RegCloseKey(k);
        }
        CHECK(ok, "DriverDatabase records oem0.inf -> synth.inf_amd64_<crc32>");
    }
    code = shzpnp("add-driver " PKG "\\synth.inf");
    CHECK(code == 0, "adding the same package again (staging only) succeeds");
    code = shzpnp("add-driver C:\\SHZTEST\\undecorated.inf");
    CHECK(code == 1, "an INF with only an undecorated Models section is refused on amd64 (Windows rule)");
    code = shzpnp("add-driver C:\\SHZTEST\\undecorated.inf --legacy");
    CHECK(code == 0, "--legacy accepts it (ReactOS setupapi behaviour)");
    code = shzpnp("enum");
    CHECK(code == 0, "enum lists the Enum tree");
    code = shzpnp("match 1AF4:7001:00011AF4:01:020000 10DE:1234 --store C:\\SHZTEST\\STORE --all");
    CHECK(code == 0, "match ranks devices against a store index");
    code = shzpnp("match 1AF4:7001 --store C:\\SHZTEST\\NOSTORE");
    CHECK(code == 2, "match without an index fails with exit 2");
    code = shzpnp("load nosuchservice");
    CHECK(code == 2, "load of a service without a key: exit 2");
    code = shzpnp("load synthpnp");
    CHECK(code == 3 || code == 1, "load never succeeds on a non-driver payload (3: driver host not present, 1: rejected)");
    return finish_tests("t_shzpnp");
}
