/* SPDX-License-Identifier: GPL-2.0-only
 * User-mode reachability of the NT driver host: a Win64 console app that (1) creates the driver's
 * Services registry key with an ImagePath, (2) loads the unmodified ShzEcho .sys with
 * NtLoadDriver, (3) opens its device with NtCreateFile("\\??\\ShzEcho") and (4) round-trips an
 * IOCTL with NtDeviceIoControlFile, verifying the echo. It exits 0 only if every step succeeds,
 * so the Kernel64 self-test harness that runs \SHZ\TESTS\T_*.EXE treats it as a real check.
 */
#include "ntreg.h"                       /* pulls nt.h (native calls, SHZ_* structs) */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winreg.h>
#include "shzcrt.h"

/* Two services the driver host adds (ntsys.h SYSCALL_LIST_NTDRV); declared here so nt.h stays untouched. */
NTSTATUS NTAPI NtLoadDriver(SHZ_UNICODE_STRING *RegistryPath);
NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
                                     SHZ_IO_STATUS_BLOCK *IoStatusBlock, ULONG IoControlCode,
                                     PVOID InputBuffer, ULONG InputBufferLength,
                                     PVOID OutputBuffer, ULONG OutputBufferLength);

#define IOCTL_SHZ_ECHO 0x222000u          /* CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) */
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x40u
#endif
#ifndef FILE_OPEN
#define FILE_OPEN 1u
#endif

static int g_fail;
#define CHK(cond, name) do { if (cond) printf("PASS: %s\n", (name)); else { ++g_fail; printf("FAIL: %s\n", (name)); } } while (0)

static void winit(SHZ_UNICODE_STRING *u, const WCHAR *b)
{
    unsigned n = 0;
    while (b[n]) ++n;
    u->Length = (USHORT)(n * 2);
    u->MaximumLength = (USHORT)(n * 2 + 2);
    u->Buffer = (PWSTR)b;
}

int main(void)
{
    HKEY svc = 0;
    DWORD disp = 0, type = 1;
    LONG e;
    NTSTATUS st;
    HANDLE h = 0;
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_IO_STATUS_BLOCK iosb;
    SHZ_UNICODE_STRING us;
    static const WCHAR IMG[] = L"\\SHZ\\DRIVERS\\ECHO.SYS";
    static WCHAR SVCPATH[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\shzecho";
    static WCHAR DEVNAME[] = L"\\??\\ShzEcho";
    const char in[] = "PING-usr";
    char out[32];
    unsigned i;

    /* 1) Services\shzecho with ImagePath = the .sys path in the driver store */
    e = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\shzecho", 0, 0, 0,
                        KEY_ALL_ACCESS, 0, &svc, &disp);
    CHK(e == ERROR_SUCCESS, "create Services\\shzecho key");
    if (e == ERROR_SUCCESS) {
        RegSetValueExW(svc, L"ImagePath", 0, REG_SZ, (const BYTE *)IMG, sizeof IMG);
        RegSetValueExW(svc, L"Type", 0, REG_DWORD, (const BYTE *)&type, 4);
        RegCloseKey(svc);
    }

    /* 2) NtLoadDriver: the host reads ImagePath, loads the .sys and calls DriverEntry */
    winit(&us, SVCPATH);
    st = NtLoadDriver(&us);
    CHK(st == 0, "NtLoadDriver(shzecho)");

    /* 3) open the device the driver created */
    for (i = 0; i < sizeof out; ++i) out[i] = 0;
    memset(&oa, 0, sizeof oa);
    winit(&us, DEVNAME);
    oa.Length = sizeof oa;
    oa.ObjectName = &us;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    st = NtCreateFile(&h, GENERIC_READ | GENERIC_WRITE, &oa, &iosb, 0, 0, 0, FILE_OPEN, 0, 0, 0);
    CHK(st == 0 && h, "NtCreateFile \\??\\ShzEcho");

    /* 4) IOCTL round trip through the driver's IRP dispatch */
    if (st == 0 && h) {
        st = NtDeviceIoControlFile(h, 0, 0, 0, &iosb, IOCTL_SHZ_ECHO, (PVOID)in, sizeof in - 1, out, sizeof out);
        CHK(st == 0, "NtDeviceIoControlFile(IOCTL_SHZ_ECHO)");
        CHK(iosb.Information == sizeof in - 1 && !memcmp(in, out, sizeof in - 1), "device echoed the input buffer");
        NtClose(h);
    }

    printf("t_ntdrv: %s\n", g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
