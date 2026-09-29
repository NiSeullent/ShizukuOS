/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: serial communications (the Comm functions) and hard links.
 *
 * Serial ports: Kernel64 exposes no serial-port device to user mode (the machine's UART is the kernel console), so no name opens
 * one: CreateFile("COM1") / "\\.\COM1" fail with ERROR_FILE_NOT_FOUND because no such device exists. The Comm functions take
 * any handle and ask its device what it is (FileFsDeviceInformation): an invalid handle is ERROR_INVALID_HANDLE, a handle of any
 * other device (disk file, console, ...) is ERROR_INVALID_FUNCTION, exactly what the serial IOCTLs return for such devices on
 * Windows.
 *
 * Hard links: the RAM file system keeps one payload per directory entry and does not report FILE_SUPPORTS_HARD_LINKS; the request
 * goes to the file system (FileLinkInformation), which refuses it as FAT does (ERROR_INVALID_FUNCTION), after the checks every
 * file system shares (existing target, free new name, not a directory).
 */
#include "k32.h"

#define FILE_DEVICE_SERIAL_PORT_ 0x1b

static BOOL comm_device(HANDLE h)
{
    struct { ULONG type, characteristics; } dev;
    SHZ_IO_STATUS_BLOCK iosb;
    NTSTATUS st = NtQueryVolumeInformationFile(h, &iosb, &dev, sizeof dev, 4 /* FileFsDeviceInformation */);
    if (st) { shz_set_last_error(st == STATUS_INVALID_HANDLE || st == STATUS_OBJECT_TYPE_MISMATCH ? ERROR_INVALID_HANDLE : RtlNtStatusToDosError(st)); return FALSE; }
    if (dev.type != FILE_DEVICE_SERIAL_PORT_) { shz_set_last_error(ERROR_INVALID_FUNCTION); return FALSE; }
    /* A serial-port device would be driven with IOCTL_SERIAL_* requests here; Kernel64 has no such device to answer them. */
    shz_set_last_error(ERROR_INVALID_FUNCTION);
    return FALSE;
}

K32API BOOL WINAPI GetCommState(HANDLE h, LPDCB dcb)
{
    if (!dcb) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    return comm_device(h);
}

K32API BOOL WINAPI SetCommState(HANDLE h, LPDCB dcb)
{
    if (!dcb) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    return comm_device(h);
}

K32API BOOL WINAPI SetCommTimeouts(HANDLE h, LPCOMMTIMEOUTS t)
{
    if (!t) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    return comm_device(h);
}

K32API BOOL WINAPI ClearCommError(HANDLE h, LPDWORD errors, LPCOMSTAT stat)
{
    (void)errors; (void)stat;
    return comm_device(h);
}

K32API BOOL WINAPI EscapeCommFunction(HANDLE h, DWORD func)
{
    if (func < SETXOFF || func > CLRBREAK) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    return comm_device(h);
}

K32API BOOL WINAPI GetCommModemStatus(HANDLE h, LPDWORD status)
{
    if (!status) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    return comm_device(h);
}

K32API BOOL WINAPI PurgeComm(HANDLE h, DWORD flags)
{
    if (flags & ~(DWORD)(PURGE_TXABORT | PURGE_RXABORT | PURGE_TXCLEAR | PURGE_RXCLEAR)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    return comm_device(h);
}

/* ---------------------------------------------------------------- hard links */
K32API BOOL WINAPI CreateHardLinkW(LPCWSTR link, LPCWSTR existing, LPSECURITY_ATTRIBUTES sa)
{
    struct { BYTE replace, pad[7]; HANDLE root; ULONG len; WCHAR name[300]; } info;      /* FILE_LINK_INFORMATION */
    struct { ULONGLONG c, a, w, ch; ULONG attrs, pad; } basic;
    SHZ_IO_STATUS_BLOCK iosb;
    WCHAR nt[300];
    HANDLE h;
    NTSTATUS st;
    DWORD attrs;
    (void)sa;
    if (!link || !existing || !link[0] || !existing[0]) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    st = k32_open_path(existing, FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_OPEN_D, 0, &h, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    st = NtQueryInformationFile(h, &iosb, &basic, sizeof basic, 4 /* FileBasicInformation */);
    if (!st && (basic.attrs & FILE_ATTRIBUTE_DIRECTORY)) { NtClose(h); shz_set_last_error(ERROR_ACCESS_DENIED); return FALSE; }
    attrs = GetFileAttributesW(link);
    if (attrs != INVALID_FILE_ATTRIBUTES) { NtClose(h); shz_set_last_error(ERROR_ALREADY_EXISTS); return FALSE; }
    if (GetLastError() == ERROR_PATH_NOT_FOUND) { NtClose(h); return FALSE; }         /* the new name's directory is missing */
    st = k32_dos_to_nt(link, nt, 300);
    if (st) { NtClose(h); k32_nt_error(st); return FALSE; }
    memset(&info, 0, sizeof info);
    info.len = (ULONG)(k32_wlen(nt) * sizeof(WCHAR));
    memcpy(info.name, nt, info.len);
    st = NtSetInformationFile(h, &iosb, &info, (ULONG)(offsetof(__typeof__(info), name) + info.len), 11 /* FileLinkInformation */);
    NtClose(h);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}
