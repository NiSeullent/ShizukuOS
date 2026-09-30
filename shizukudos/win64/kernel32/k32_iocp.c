/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: I/O completion ports (CreateIoCompletionPort, GetQueuedCompletionStatus(Ex), PostQueuedCompletionStatus) over
 * kernel64/iocp.c, DeviceIoControl over NtFsControlFile / NtDeviceIoControlFile, and ReadDirectoryChangesW.
 *
 * ReadDirectoryChangesW: the Kernel64 file systems do not report changes (there is no change-notification path in
 * kernel64/fs.c, disk.c or sfs_mount.c), so the function fails with ERROR_INVALID_FUNCTION - what Windows returns for a file
 * system that does not support directory notifications - instead of pretending to watch.
 */
#include "k32.h"

K32API HANDLE WINAPI CreateIoCompletionPort(HANDLE file, HANDLE port, ULONG_PTR key, DWORD threads)
{
    HANDLE created = 0;
    NTSTATUS st;
    if (file == INVALID_HANDLE_VALUE) {                                   /* a new port, no file */
        if (port) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
        st = NtCreateIoCompletion(&created, IO_COMPLETION_ALL_ACCESS, 0, threads);
        if (st) { k32_nt_error(st); return 0; }
        return created;
    }
    if (!port) {                                                          /* a new port, associated with `file` */
        st = NtCreateIoCompletion(&created, IO_COMPLETION_ALL_ACCESS, 0, threads);
        if (st) { k32_nt_error(st); return 0; }
        port = created;
    }
    {
        struct { HANDLE port; ULONG_PTR key; } info = { port, key };
        SHZ_IO_STATUS_BLOCK io;
        st = NtSetInformationFile(file, &io, &info, sizeof info, 30);    /* FileCompletionInformation */
        if (st) {
            if (created) NtClose(created);
            k32_nt_error(st);
            return 0;
        }
    }
    return port;
}

K32API BOOL WINAPI GetQueuedCompletionStatus(HANDLE port, LPDWORD bytes, PULONG_PTR key, LPOVERLAPPED *ov, DWORD ms)
{
    SHZ_IO_STATUS_BLOCK io;
    ULONG_PTR k = 0, ctx = 0;
    LARGE_INTEGER to;
    NTSTATUS st;
    to.QuadPart = -(LONGLONG)ms * 10000;
    st = NtRemoveIoCompletion(port, &k, &ctx, &io, ms == INFINITE ? 0 : &to);
    if (st == STATUS_TIMEOUT) {
        *ov = 0;
        shz_set_last_error(WAIT_TIMEOUT);
        return FALSE;
    }
    if (st) { *ov = 0; k32_nt_error(st); return FALSE; }
    *key = k;
    *ov = (LPOVERLAPPED)ctx;
    *bytes = (DWORD)io.Information;
    if ((NTSTATUS)io.Status < 0 && (NTSTATUS)io.Status != STATUS_BUFFER_OVERFLOW) { k32_nt_error((NTSTATUS)io.Status); return FALSE; }
    if ((NTSTATUS)io.Status == STATUS_BUFFER_OVERFLOW) { shz_set_last_error(ERROR_MORE_DATA); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI GetQueuedCompletionStatusEx(HANDLE port, LPOVERLAPPED_ENTRY entries, ULONG count, PULONG removed, DWORD ms,
                                               BOOL alertable)
{
    /* FILE_IO_COMPLETION_INFORMATION {KeyContext, ApcContext, IoStatusBlock} -> OVERLAPPED_ENTRY
     * {lpCompletionKey, lpOverlapped, Internal, dwNumberOfBytesTransferred}: same size, different order of the last two. */
    LARGE_INTEGER to;
    NTSTATUS st;
    ULONG i, n = 0;
    if (!count || !removed) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    to.QuadPart = -(LONGLONG)ms * 10000;
    st = NtRemoveIoCompletionEx(port, entries, count, &n, ms == INFINITE ? 0 : &to, alertable != 0);
    if (st == STATUS_TIMEOUT) { *removed = 0; shz_set_last_error(WAIT_TIMEOUT); return FALSE; }
    if (st) { *removed = 0; k32_nt_error(st); return FALSE; }
    for (i = 0; i < n; ++i) {
        ULONG_PTR *e = (ULONG_PTR *)&entries[i];
        const ULONG_PTR status = e[2], info = e[3];
        e[2] = status;                                                    /* Internal = status */
        e[3] = (DWORD)info;                                               /* dwNumberOfBytesTransferred */
    }
    *removed = n;
    return TRUE;
}

K32API BOOL WINAPI PostQueuedCompletionStatus(HANDLE port, DWORD bytes, ULONG_PTR key, LPOVERLAPPED ov)
{
    NTSTATUS st = NtSetIoCompletion(port, key, (ULONG_PTR)ov, STATUS_SUCCESS, bytes);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

/* ---------------------------------------------------------------- DeviceIoControl */
NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE, HANDLE, PVOID, PVOID, SHZ_IO_STATUS_BLOCK *, ULONG, PVOID, ULONG, PVOID, ULONG);

/* File-system controls (device type FILE_DEVICE_FILE_SYSTEM 9 or FILE_DEVICE_NAMED_PIPE 0x11) go to NtFsControlFile, every
 * other code to NtDeviceIoControlFile (devices of the NT driver host). A control the target does not implement fails with
 * ERROR_INVALID_FUNCTION, as on Windows. */
K32API BOOL WINAPI DeviceIoControl(HANDLE h, DWORD code, LPVOID in, DWORD in_size, LPVOID out, DWORD out_size, LPDWORD returned,
                                   LPOVERLAPPED ov)
{
    const DWORD dev = code >> 16;
    SHZ_IO_STATUS_BLOCK io, *pio = &io;
    HANDLE ev = 0;
    PVOID ctx = 0;
    NTSTATUS st;
    memset(&io, 0, sizeof io);
    if (ov) {
        ev = (HANDLE)((ULONG_PTR)ov->hEvent & ~(ULONG_PTR)1);
        ctx = ((ULONG_PTR)ov->hEvent & 1) ? 0 : ov;
        ov->Internal = STATUS_PENDING;
        ov->InternalHigh = 0;
        pio = (SHZ_IO_STATUS_BLOCK *)ov;
    }
    if (dev == 9 || dev == 0x11)
        st = NtFsControlFile(h, ev, 0, ctx, pio, code, in, in_size, out, out_size);
    else
        st = NtDeviceIoControlFile(h, ev, 0, ctx, pio, code, in, in_size, out, out_size);
    if (st == STATUS_PENDING) { shz_set_last_error(ERROR_IO_PENDING); return FALSE; }
    if (returned) *returned = (DWORD)pio->Information;
    if (st < 0) { if (ov) ov->Internal = (ULONG_PTR)(LONG_PTR)st; k32_nt_error(st); return FALSE; }
    return TRUE;
}

/* ---------------------------------------------------------------- directory change notifications */
K32API BOOL WINAPI ReadDirectoryChangesW(HANDLE dir, LPVOID buf, DWORD len, BOOL subtree, DWORD filter, LPDWORD returned,
                                         LPOVERLAPPED ov, LPOVERLAPPED_COMPLETION_ROUTINE routine)
{
    (void)dir; (void)buf; (void)len; (void)subtree; (void)filter; (void)ov; (void)routine;
    if (returned) *returned = 0;
    return k32_unsupported("ReadDirectoryChangesW", "the Kernel64 file systems report no directory changes", ERROR_INVALID_FUNCTION);
}
