/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: file handles and I/O with Windows overlapped semantics, I/O completion ports and named/anonymous pipes,
 * over the Kernel64 IRP layer (kernel64/ipc_io.c) and its named pipe file system (kernel64/npfs.c).
 *
 * A handle opened without FILE_FLAG_OVERLAPPED is synchronous: its I/O waits inside the system call. With it, ReadFile /
 * WriteFile / ConnectNamedPipe / TransactNamedPipe / DeviceIoControl return FALSE + ERROR_IO_PENDING while the request is
 * outstanding; the OVERLAPPED receives the final status and byte count (Internal / InternalHigh), its event is set, and a
 * completion packet goes to the port the handle is associated with (unless the event handle's low bit is set, or
 * FILE_SKIP_COMPLETION_PORT_ON_SUCCESS applies). ReadFileEx / WriteFileEx completion routines run as APCs in the issuing
 * thread's next alertable wait.
 */
#include "k32_ipc.h"

#define NT_FILE_OPEN 1u
#define NT_FILE_CREATE 2u
#define NT_FILE_OPEN_IF 3u
#define NT_FILE_OVERWRITE 4u
#define NT_FILE_OVERWRITE_IF 5u
#define NT_OPT_WRITE_THROUGH 0x2u
#define NT_OPT_SYNCHRONOUS 0x20u
#define NT_OPT_NON_DIRECTORY 0x40u
#define NT_OPT_DELETE_ON_CLOSE 0x1000u
#define NT_OBJ_CASE_INSENSITIVE 0x40u
#define FSCTL_PIPE_DISCONNECT_K 0x110004u
#define FSCTL_PIPE_LISTEN_K 0x110008u
#define FSCTL_PIPE_PEEK_K 0x11400Cu
#define FSCTL_PIPE_WAIT_K 0x110018u
#define FSCTL_PIPE_TRANSCEIVE_K 0x11C017u
#define FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE_K 0x110030u

NTSTATUS NTAPI NtFlushBuffersFile(HANDLE, SHZ_IO_STATUS_BLOCK *);

static size_t wl(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }

/* Win32 name -> NT name: "\\.\x" is the device namespace (\??\x), everything else goes through the DOS path rules. */
static NTSTATUS to_nt(LPCWSTR name, WCHAR *nt, size_t cap)
{
    if (name[0] == '\\' && name[1] == '\\' && name[2] == '.' && name[3] == '\\') {
        size_t n = wl(name + 4), i;
        if (n + 5 > cap) return STATUS_OBJECT_NAME_INVALID;
        nt[0] = '\\'; nt[1] = '?'; nt[2] = '?'; nt[3] = '\\';
        for (i = 0; i <= n; ++i) nt[4 + i] = name[4 + i] == '/' ? '\\' : name[4 + i];
        return STATUS_SUCCESS;
    }
    if (name[0] == '\\' && name[1] == '?' && name[2] == '?' && name[3] == '\\') {
        size_t n = wl(name);
        if (n + 1 > cap) return STATUS_OBJECT_NAME_INVALID;
        memcpy(nt, name, (n + 1) * sizeof(WCHAR));
        return STATUS_SUCCESS;
    }
    return k32_dos_to_nt(name, nt, cap);
}

static int is_console_name(LPCWSTR n, const char *want)
{
    size_t i;
    for (i = 0; want[i]; ++i) if ((n[i] | 32) != (want[i] | 32)) return 0;
    return n[i] == 0;
}

K32API HANDLE WINAPI CreateFileW(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags,
                                 HANDLE tmpl)
{
    WCHAR nt[320];
    SHZ_UNICODE_STRING us;
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_IO_STATUS_BLOCK iosb;
    HANDLE h = INVALID_HANDLE_VALUE;
    ULONG d, opts = 0;
    NTSTATUS st;
    (void)tmpl;
    if (!name || !name[0]) { shz_set_last_error(ERROR_PATH_NOT_FOUND); return INVALID_HANDLE_VALUE; }
    switch (disp) {
    case CREATE_NEW: d = NT_FILE_CREATE; break;
    case CREATE_ALWAYS: d = NT_FILE_OVERWRITE_IF; break;
    case OPEN_EXISTING: d = NT_FILE_OPEN; break;
    case OPEN_ALWAYS: d = NT_FILE_OPEN_IF; break;
    case TRUNCATE_EXISTING: d = NT_FILE_OVERWRITE; break;
    default: shz_set_last_error(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE;
    }
    if (is_console_name(name, "CONOUT$")) name = L"\\??\\CONOUT$";
    else if (is_console_name(name, "CONIN$")) name = L"\\??\\CONIN$";
    st = to_nt(name, nt, 320);
    if (st) { k32_nt_error(st); return INVALID_HANDLE_VALUE; }
    if (flags & FILE_FLAG_DELETE_ON_CLOSE) opts |= NT_OPT_DELETE_ON_CLOSE;
    if (!(flags & FILE_FLAG_BACKUP_SEMANTICS)) opts |= NT_OPT_NON_DIRECTORY;
    if (flags & FILE_FLAG_WRITE_THROUGH) opts |= NT_OPT_WRITE_THROUGH;
    if (!(flags & FILE_FLAG_OVERLAPPED)) opts |= NT_OPT_SYNCHRONOUS;
    us.Buffer = nt;
    us.Length = (USHORT)(wl(nt) * 2);
    us.MaximumLength = us.Length + 2;
    memset(&oa, 0, sizeof oa);
    oa.Length = sizeof oa;
    oa.ObjectName = &us;
    oa.Attributes = NT_OBJ_CASE_INSENSITIVE | (sa && sa->bInheritHandle ? SHZ_OBJ_INHERIT : 0);
    memset(&iosb, 0, sizeof iosb);
    st = NtCreateFile(&h, access | SYNCHRONIZE | FILE_READ_ATTRIBUTES, &oa, &iosb, 0, flags & 0xffffu & ~FILE_ATTRIBUTE_DIRECTORY,
                      share, d, opts, 0, 0);
    if (st) {
        if (st == STATUS_OBJECT_NAME_COLLISION) shz_set_last_error(ERROR_FILE_EXISTS);   /* CREATE_NEW on an existing file */
        else k32_nt_error(st);
        return INVALID_HANDLE_VALUE;
    }
    shz_set_last_error((iosb.Information == 1 && (disp == CREATE_ALWAYS || disp == OPEN_ALWAYS)) || iosb.Information == 3
                       ? ERROR_ALREADY_EXISTS : 0);
    return h;
}

/* ---------------------------------------------------------------- read / write */
static HANDLE ov_event(LPOVERLAPPED ov) { return (HANDLE)((ULONG_PTR)ov->hEvent & ~(ULONG_PTR)1); }
static PVOID ov_context(LPOVERLAPPED ov) { return ((ULONG_PTR)ov->hEvent & 1) ? 0 : ov; }   /* low bit: no port packet */

/* Common tail of an overlapped request: TRUE when it completed with success, FALSE + ERROR_IO_PENDING or the error. */
static BOOL ov_result(NTSTATUS st, LPOVERLAPPED ov, LPDWORD done)
{
    if (st == STATUS_PENDING) { shz_set_last_error(ERROR_IO_PENDING); return FALSE; }
    if (done) *done = (DWORD)ov->InternalHigh;
    if (!NT_SUCCESS(st)) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

/* A synchronous request on a handle opened for overlapped I/O: wait for it like kernel32 does (on the file object). */
static NTSTATUS sync_wait(HANDLE h, NTSTATUS st, SHZ_IO_STATUS_BLOCK *iosb)
{
    if (st != STATUS_PENDING) return st;
    NtWaitForSingleObject(h, FALSE, 0);
    return (NTSTATUS)iosb->Status;
}

static BOOL rw(HANDLE h, void *buf, DWORD len, LPDWORD done, LPOVERLAPPED ov, int write)
{
    NTSTATUS st;
    if (ov) {
        LARGE_INTEGER off;
        off.QuadPart = ((LONGLONG)ov->OffsetHigh << 32) | ov->Offset;
        ov->Internal = STATUS_PENDING;
        ov->InternalHigh = 0;
        st = write ? NtWriteFile(h, ov_event(ov), 0, ov_context(ov), (SHZ_IO_STATUS_BLOCK *)ov, buf, len, &off, 0)
                   : NtReadFile(h, ov_event(ov), 0, ov_context(ov), (SHZ_IO_STATUS_BLOCK *)ov, buf, len, &off, 0);
        if (!write && st == STATUS_END_OF_FILE) { if (done) *done = 0; shz_set_last_error(ERROR_HANDLE_EOF); return FALSE; }
        return ov_result(st, ov, done);
    } else {
        SHZ_IO_STATUS_BLOCK iosb;
        memset(&iosb, 0, sizeof iosb);
        st = write ? NtWriteFile(h, 0, 0, 0, &iosb, buf, len, 0, 0) : NtReadFile(h, 0, 0, 0, &iosb, buf, len, 0, 0);
        st = sync_wait(h, st, &iosb);
        if (done) *done = (DWORD)iosb.Information;
        if (!write && st == STATUS_END_OF_FILE) { if (done) *done = 0; return TRUE; }   /* EOF: success with 0 bytes */
        if (!NT_SUCCESS(st)) { k32_nt_error(st); return FALSE; }                         /* incl. ERROR_MORE_DATA */
        return TRUE;
    }
}

K32API BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD len, LPDWORD done, LPOVERLAPPED ov)
{
    if (done && !ov) *done = 0;
    return rw(h, buf, len, done, ov, 0);
}

/* Is h the process's standard output or error handle (RTL_USER_PROCESS_PARAMETERS StandardOutput / StandardError)? */
static int is_std_output(HANDLE h)
{
    const uint8_t *params = PEB_PARAMS(shz_peb());
    return h == *(HANDLE *)(params + 0x28) || h == *(HANDLE *)(params + 0x30);
}

K32API BOOL WINAPI WriteFile(HANDLE h, LPCVOID buf, DWORD len, LPDWORD done, LPOVERLAPPED ov)
{
    DWORD n = 0;
    BOOL ok;
    if (done && !ov) *done = 0;
    ok = rw(h, (void *)buf, len, ov ? done : &n, ov, 1);
    if (!ov && done) *done = n;
    if (ok && !ov && is_std_output(h) && k32_console_attached()) k32_console_track(buf, n);   /* console screen buffer model */
    return ok;
}

/* ReadFileEx / WriteFileEx: the completion routine runs as an APC of the calling thread (ApcContext = the routine). */
static VOID NTAPI io_completion_apc(PVOID routine, SHZ_IO_STATUS_BLOCK *iosb, ULONG reserved)
{
    (void)reserved;
    ((LPOVERLAPPED_COMPLETION_ROUTINE)routine)(RtlNtStatusToDosError((NTSTATUS)iosb->Status), (DWORD)iosb->Information,
                                               (LPOVERLAPPED)iosb);
}

static BOOL rw_ex(HANDLE h, void *buf, DWORD len, LPOVERLAPPED ov, LPOVERLAPPED_COMPLETION_ROUTINE fn, int write)
{
    LARGE_INTEGER off;
    NTSTATUS st;
    if (!ov || !fn) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    off.QuadPart = ((LONGLONG)ov->OffsetHigh << 32) | ov->Offset;
    ov->Internal = STATUS_PENDING;
    ov->InternalHigh = 0;
    st = write ? NtWriteFile(h, 0, (PVOID)io_completion_apc, (PVOID)fn, (SHZ_IO_STATUS_BLOCK *)ov, buf, len, &off, 0)
               : NtReadFile(h, 0, (PVOID)io_completion_apc, (PVOID)fn, (SHZ_IO_STATUS_BLOCK *)ov, buf, len, &off, 0);
    if (NT_ERROR(st)) { k32_nt_error(st); return FALSE; }
    shz_set_last_error(0);
    return TRUE;                                                /* queued, or completed with its APC queued */
}

K32API BOOL WINAPI ReadFileEx(HANDLE h, LPVOID buf, DWORD len, LPOVERLAPPED ov, LPOVERLAPPED_COMPLETION_ROUTINE fn)
{
    return rw_ex(h, buf, len, ov, fn, 0);
}

K32API BOOL WINAPI WriteFileEx(HANDLE h, LPCVOID buf, DWORD len, LPOVERLAPPED ov, LPOVERLAPPED_COMPLETION_ROUTINE fn)
{
    return rw_ex(h, (void *)buf, len, ov, fn, 1);
}

K32API BOOL WINAPI GetOverlappedResultEx(HANDLE h, LPOVERLAPPED ov, LPDWORD done, DWORD ms, BOOL alertable)
{
    volatile ULONG_PTR *status;
    if (!ov) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    status = &ov->Internal;
    if (*status == (ULONG_PTR)STATUS_PENDING) {
        HANDLE w = ov_event(ov) ? ov_event(ov) : h;
        DWORD r;
        if (!ms) { shz_set_last_error(ERROR_IO_INCOMPLETE); return FALSE; }
        r = WaitForSingleObjectEx(w, ms, alertable);
        if (r == WAIT_IO_COMPLETION) { shz_set_last_error(WAIT_IO_COMPLETION); return FALSE; }
        if (r == WAIT_TIMEOUT) { shz_set_last_error(WAIT_TIMEOUT); return FALSE; }
        if (r == WAIT_FAILED) return FALSE;
        if (*status == (ULONG_PTR)STATUS_PENDING) { shz_set_last_error(ERROR_IO_INCOMPLETE); return FALSE; }
    }
    if (done) *done = (DWORD)ov->InternalHigh;
    if (!NT_SUCCESS((NTSTATUS)*status)) { k32_nt_error((NTSTATUS)*status); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI GetOverlappedResult(HANDLE h, LPOVERLAPPED ov, LPDWORD done, BOOL wait)
{
    return GetOverlappedResultEx(h, ov, done, wait ? INFINITE : 0, FALSE);
}

K32API BOOL WINAPI CancelIo(HANDLE h)
{
    SHZ_IO_STATUS_BLOCK iosb;
    NTSTATUS st = NtCancelIoFile(h, &iosb);
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API BOOL WINAPI CancelIoEx(HANDLE h, LPOVERLAPPED ov)
{
    SHZ_IO_STATUS_BLOCK iosb;
    NTSTATUS st = NtCancelIoFileEx(h, (SHZ_IO_STATUS_BLOCK *)ov, &iosb);
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API BOOL WINAPI FlushFileBuffers(HANDLE h)
{
    SHZ_IO_STATUS_BLOCK iosb;
    NTSTATUS st = NtFlushBuffersFile(h, &iosb);
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API DWORD WINAPI GetFileType(HANDLE h)
{
    SHZ_IO_STATUS_BLOCK iosb;
    ULONG dev[2];
    NTSTATUS st = NtQueryVolumeInformationFile(h, &iosb, dev, sizeof dev, 4 /* FileFsDeviceInformation */);
    if (st) { k32_nt_error(st == STATUS_OBJECT_TYPE_MISMATCH ? STATUS_INVALID_HANDLE : st); return FILE_TYPE_UNKNOWN; }
    shz_set_last_error(0);
    switch (dev[0]) {
    case 0x11: case 0x12: return FILE_TYPE_PIPE;               /* named pipes, sockets (AFD) */
    case 0x50: return FILE_TYPE_CHAR;                          /* console */
    default: return FILE_TYPE_DISK;
    }
}

/* ---------------------------------------------------------------- I/O completion ports */
K32API HANDLE WINAPI CreateIoCompletionPort(HANDLE file, HANDLE existing, ULONG_PTR key, DWORD threads)
{
    HANDLE port = existing;
    NTSTATUS st;
    if (file == INVALID_HANDLE_VALUE) {
        if (existing) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
        st = NtCreateIoCompletion(&port, IO_COMPLETION_ALL_ACCESS, 0, threads);
        if (st) { k32_nt_error(st); return 0; }
        return port;
    }
    if (!port) {
        st = NtCreateIoCompletion(&port, IO_COMPLETION_ALL_ACCESS, 0, threads);
        if (st) { k32_nt_error(st); return 0; }
    }
    {
        struct { HANDLE port; ULONG_PTR key; } info = { port, key };
        SHZ_IO_STATUS_BLOCK iosb;
        st = NtSetInformationFile(file, &iosb, &info, sizeof info, 30 /* FileCompletionInformation */);
    }
    if (st) {
        if (!existing) NtClose(port);
        k32_nt_error(st);
        return 0;
    }
    return port;
}

K32API BOOL WINAPI GetQueuedCompletionStatus(HANDLE port, LPDWORD bytes, PULONG_PTR key, LPOVERLAPPED *ov, DWORD ms)
{
    LARGE_INTEGER li;
    SHZ_IO_STATUS_BLOCK iosb;
    PVOID k = 0, ctx = 0;
    NTSTATUS st = NtRemoveIoCompletion(port, &k, &ctx, &iosb, k32_ipc_timeout(ms, &li));
    if (st == STATUS_TIMEOUT) { *ov = 0; shz_set_last_error(WAIT_TIMEOUT); return FALSE; }
    if (st == STATUS_ABANDONED_WAIT_0) { *ov = 0; shz_set_last_error(ERROR_ABANDONED_WAIT_0); return FALSE; }
    if (st) { *ov = 0; k32_nt_error(st); return FALSE; }
    *ov = ctx;
    *key = (ULONG_PTR)k;
    *bytes = (DWORD)iosb.Information;
    if (!NT_SUCCESS((NTSTATUS)iosb.Status)) { k32_nt_error((NTSTATUS)iosb.Status); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI GetQueuedCompletionStatusEx(HANDLE port, LPOVERLAPPED_ENTRY entries, ULONG count, PULONG removed, DWORD ms,
                                               BOOL alertable)
{
    LARGE_INTEGER li;
    ULONG n = 0;
    NTSTATUS st;
    if (!entries || !count || !removed) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    st = NtRemoveIoCompletionEx(port, (SHZ_FILE_IO_COMPLETION_INFORMATION *)entries, count, &n, k32_ipc_timeout(ms, &li),
                                alertable != 0);
    *removed = n;
    if (st == STATUS_SUCCESS && n) return TRUE;
    if (st == STATUS_USER_APC) { shz_set_last_error(WAIT_IO_COMPLETION); return FALSE; }
    if (st == STATUS_TIMEOUT) { shz_set_last_error(WAIT_TIMEOUT); return FALSE; }
    if (st == STATUS_ABANDONED_WAIT_0) { shz_set_last_error(ERROR_ABANDONED_WAIT_0); return FALSE; }
    k32_nt_error(st);
    return FALSE;
}

K32API BOOL WINAPI PostQueuedCompletionStatus(HANDLE port, DWORD bytes, ULONG_PTR key, LPOVERLAPPED ov)
{
    NTSTATUS st = NtSetIoCompletion(port, (PVOID)key, ov, STATUS_SUCCESS, bytes);
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API BOOL WINAPI SetFileCompletionNotificationModes(HANDLE h, UCHAR flags)
{
    SHZ_IO_STATUS_BLOCK iosb;
    ULONG v = flags;
    NTSTATUS st;
    if (flags & ~(UCHAR)(FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE)) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    st = NtSetInformationFile(h, &iosb, &v, sizeof v, 41 /* FileIoCompletionNotificationInformation */);
    return st ? k32_ipc_fail(st) : TRUE;
}

/* ---------------------------------------------------------------- DeviceIoControl */
K32API BOOL WINAPI DeviceIoControl(HANDLE h, DWORD code, LPVOID in, DWORD in_len, LPVOID out, DWORD out_len, LPDWORD ret,
                                   LPOVERLAPPED ov)
{
    const DWORD dev = code >> 16;
    const int fsctl = dev == FILE_DEVICE_FILE_SYSTEM || dev == FILE_DEVICE_NAMED_PIPE;
    NTSTATUS st;
    if (ov) {
        ov->Internal = STATUS_PENDING;
        ov->InternalHigh = 0;
        st = fsctl ? NtFsControlFile(h, ov_event(ov), 0, ov_context(ov), (SHZ_IO_STATUS_BLOCK *)ov, code, in, in_len, out, out_len)
                   : NtDeviceIoControlFile(h, ov_event(ov), 0, ov_context(ov), (SHZ_IO_STATUS_BLOCK *)ov, code, in, in_len, out, out_len);
        return ov_result(st, ov, ret);
    } else {
        SHZ_IO_STATUS_BLOCK iosb;
        memset(&iosb, 0, sizeof iosb);
        st = fsctl ? NtFsControlFile(h, 0, 0, 0, &iosb, code, in, in_len, out, out_len)
                   : NtDeviceIoControlFile(h, 0, 0, 0, &iosb, code, in, in_len, out, out_len);
        st = sync_wait(h, st, &iosb);
        if (ret) *ret = (DWORD)iosb.Information;
        if (!NT_SUCCESS(st)) { k32_nt_error(st); return FALSE; }
        return TRUE;
    }
}

/* ---------------------------------------------------------------- named pipes */
static NTSTATUS pipe_fsctl(HANDLE h, LPOVERLAPPED ov, ULONG code, PVOID in, ULONG in_len, PVOID out, ULONG out_len,
                           SHZ_IO_STATUS_BLOCK *iosb)
{
    if (ov) {
        ov->Internal = STATUS_PENDING;
        ov->InternalHigh = 0;
        return NtFsControlFile(h, ov_event(ov), 0, ov_context(ov), (SHZ_IO_STATUS_BLOCK *)ov, code, in, in_len, out, out_len);
    }
    memset(iosb, 0, sizeof *iosb);
    return sync_wait(h, NtFsControlFile(h, 0, 0, 0, iosb, code, in, in_len, out, out_len), iosb);
}

K32API HANDLE WINAPI CreateNamedPipeW(LPCWSTR name, DWORD open_mode, DWORD pipe_mode, DWORD max_inst, DWORD out_size,
                                      DWORD in_size, DWORD timeout_ms, LPSECURITY_ATTRIBUTES sa)
{
    static const char pfx[] = "\\\\.\\pipe\\";
    WCHAR nt[300];
    SHZ_UNICODE_STRING us;
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_IO_STATUS_BLOCK iosb;
    LARGE_INTEGER timeout;
    HANDLE h = INVALID_HANDLE_VALUE;
    ACCESS_MASK access = SYNCHRONIZE | FILE_READ_ATTRIBUTES;
    ULONG share = 0, n, i;
    NTSTATUS st;
    for (i = 0; pfx[i]; ++i) if (!name || (name[i] | (i >= 3 ? 32 : 0)) != (pfx[i] | (i >= 3 ? 32 : 0))) { shz_set_last_error(ERROR_INVALID_NAME); return INVALID_HANDLE_VALUE; }
    n = (ULONG)wl(name);
    if (n - 9 == 0 || n + 1 > 290) { shz_set_last_error(ERROR_INVALID_NAME); return INVALID_HANDLE_VALUE; }
    if (!max_inst || max_inst > PIPE_UNLIMITED_INSTANCES || !(open_mode & PIPE_ACCESS_DUPLEX) ||
        (pipe_mode & ~(DWORD)(PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS)) ||
        ((pipe_mode & PIPE_READMODE_MESSAGE) && !(pipe_mode & PIPE_TYPE_MESSAGE))) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    nt[0] = '\\'; nt[1] = '?'; nt[2] = '?'; nt[3] = '\\';
    for (i = 4; i <= n; ++i) nt[i] = name[i];                   /* "pipe\<name>" after "\\.\" */
    us.Buffer = nt; us.Length = (USHORT)(wl(nt) * 2); us.MaximumLength = us.Length + 2;
    memset(&oa, 0, sizeof oa);
    oa.Length = sizeof oa;
    oa.ObjectName = &us;
    oa.Attributes = NT_OBJ_CASE_INSENSITIVE | (sa && sa->bInheritHandle ? SHZ_OBJ_INHERIT : 0);
    if (open_mode & PIPE_ACCESS_INBOUND) { access |= GENERIC_READ; share |= FILE_SHARE_WRITE; }
    if (open_mode & PIPE_ACCESS_OUTBOUND) { access |= GENERIC_WRITE; share |= FILE_SHARE_READ; }
    access |= open_mode & (WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY);
    timeout.QuadPart = timeout_ms ? -(LONGLONG)timeout_ms * 10000 : -500000;
    st = NtCreateNamedPipeFile(&h, access, &oa, &iosb, share,
                               (open_mode & FILE_FLAG_FIRST_PIPE_INSTANCE) ? NT_FILE_CREATE : NT_FILE_OPEN_IF,
                               ((open_mode & FILE_FLAG_OVERLAPPED) ? 0 : NT_OPT_SYNCHRONOUS) |
                               ((open_mode & FILE_FLAG_WRITE_THROUGH) ? NT_OPT_WRITE_THROUGH : 0),
                               (pipe_mode & PIPE_TYPE_MESSAGE) ? 1 : 0, (pipe_mode & PIPE_READMODE_MESSAGE) ? 1 : 0,
                               (pipe_mode & PIPE_NOWAIT) ? 1 : 0, max_inst == PIPE_UNLIMITED_INSTANCES ? 0xffffffffu : max_inst,
                               in_size, out_size, &timeout);
    if (st) {
        k32_nt_error(st);                                       /* STATUS_INSTANCE_NOT_AVAILABLE -> ERROR_PIPE_BUSY */
        return INVALID_HANDLE_VALUE;
    }
    shz_set_last_error(0);
    return h;
}

K32API HANDLE WINAPI CreateNamedPipeA(LPCSTR name, DWORD open_mode, DWORD pipe_mode, DWORD max_inst, DWORD out_size,
                                      DWORD in_size, DWORD timeout_ms, LPSECURITY_ATTRIBUTES sa)
{
    WCHAR w[300];
    if (!name || k32_utf8_to_wide(name, -1, w, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return INVALID_HANDLE_VALUE; }
    return CreateNamedPipeW(w, open_mode, pipe_mode, max_inst, out_size, in_size, timeout_ms, sa);
}

K32API BOOL WINAPI ConnectNamedPipe(HANDLE h, LPOVERLAPPED ov)
{
    SHZ_IO_STATUS_BLOCK iosb;
    NTSTATUS st = pipe_fsctl(h, ov, FSCTL_PIPE_LISTEN_K, 0, 0, 0, 0, &iosb);
    if (ov) return ov_result(st, ov, 0);
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API BOOL WINAPI DisconnectNamedPipe(HANDLE h)
{
    SHZ_IO_STATUS_BLOCK iosb;
    NTSTATUS st = pipe_fsctl(h, 0, FSCTL_PIPE_DISCONNECT_K, 0, 0, 0, 0, &iosb);
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API BOOL WINAPI PeekNamedPipe(HANDLE h, LPVOID buf, DWORD size, LPDWORD read, LPDWORD avail, LPDWORD left)
{
    struct { ULONG state, avail, messages, msg_len; } *pb;
    SHZ_IO_STATUS_BLOCK iosb;
    NTSTATUS st;
    DWORD got;
    pb = HeapAlloc(GetProcessHeap(), 0, 16 + (buf ? size : 0));
    if (!pb) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    st = pipe_fsctl(h, 0, FSCTL_PIPE_PEEK_K, 0, 0, pb, 16 + (buf ? size : 0), &iosb);
    if (!NT_SUCCESS(st) && st != STATUS_BUFFER_OVERFLOW) { HeapFree(GetProcessHeap(), 0, pb); return k32_ipc_fail(st); }
    got = (DWORD)iosb.Information > 16 ? (DWORD)iosb.Information - 16 : 0;
    if (buf && got) memcpy(buf, pb + 1, got);
    if (read) *read = got;
    if (avail) *avail = pb->avail;
    if (left) *left = pb->messages ? pb->msg_len - got : 0;
    HeapFree(GetProcessHeap(), 0, pb);
    return TRUE;
}

K32API BOOL WINAPI SetNamedPipeHandleState(HANDLE h, LPDWORD mode, LPDWORD max_coll, LPDWORD timeout)
{
    SHZ_IO_STATUS_BLOCK iosb;
    ULONG info[2];
    NTSTATUS st;
    if (max_coll || timeout) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }   /* local pipes: no collection */
    if (!mode) return TRUE;
    if (*mode & ~(DWORD)(PIPE_READMODE_MESSAGE | PIPE_NOWAIT)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    info[0] = (*mode & PIPE_READMODE_MESSAGE) ? 1 : 0;
    info[1] = (*mode & PIPE_NOWAIT) ? 1 : 0;
    st = NtSetInformationFile(h, &iosb, info, sizeof info, 23 /* FilePipeInformation */);
    return st ? k32_ipc_fail(st) : TRUE;
}

typedef struct { ULONG type, config, max_instances, cur_instances, in_quota, read_avail, out_quota, write_avail, state, end; } pipe_local_t;

static NTSTATUS pipe_local(HANDLE h, pipe_local_t *l)
{
    SHZ_IO_STATUS_BLOCK iosb;
    return NtQueryInformationFile(h, &iosb, l, sizeof *l, 24 /* FilePipeLocalInformation */);
}

K32API BOOL WINAPI GetNamedPipeHandleStateW(HANDLE h, LPDWORD state, LPDWORD instances, LPDWORD max_coll, LPDWORD timeout,
                                            LPWSTR user, DWORD user_size)
{
    SHZ_IO_STATUS_BLOCK iosb;
    ULONG info[2];
    pipe_local_t l;
    NTSTATUS st;
    (void)user_size;
    if (user) { shz_set_last_error(ERROR_CANNOT_IMPERSONATE); return FALSE; }   /* no user accounts behind pipe clients */
    if (max_coll || timeout) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (state) {
        st = NtQueryInformationFile(h, &iosb, info, sizeof info, 23);
        if (st) return k32_ipc_fail(st);
        *state = (info[0] ? PIPE_READMODE_MESSAGE : 0) | (info[1] ? PIPE_NOWAIT : 0);
    }
    if (instances) {
        st = pipe_local(h, &l);
        if (st) return k32_ipc_fail(st);
        *instances = l.cur_instances;
    }
    return TRUE;
}

K32API BOOL WINAPI GetNamedPipeInfo(HANDLE h, LPDWORD flags, LPDWORD out_size, LPDWORD in_size, LPDWORD max_inst)
{
    pipe_local_t l;
    NTSTATUS st = pipe_local(h, &l);
    if (st) return k32_ipc_fail(st);
    if (flags) *flags = (l.end ? PIPE_SERVER_END : PIPE_CLIENT_END) | (l.type ? PIPE_TYPE_MESSAGE : PIPE_TYPE_BYTE);
    if (out_size) *out_size = l.out_quota;
    if (in_size) *in_size = l.in_quota;
    if (max_inst) *max_inst = l.max_instances == 0xffffffffu ? PIPE_UNLIMITED_INSTANCES : l.max_instances;
    return TRUE;
}

K32API BOOL WINAPI TransactNamedPipe(HANDLE h, LPVOID in, DWORD in_len, LPVOID out, DWORD out_len, LPDWORD read, LPOVERLAPPED ov)
{
    SHZ_IO_STATUS_BLOCK iosb;
    NTSTATUS st = pipe_fsctl(h, ov, FSCTL_PIPE_TRANSCEIVE_K, in, in_len, out, out_len, &iosb);
    if (ov) return ov_result(st, ov, read);
    if (read) *read = (DWORD)iosb.Information;
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API BOOL WINAPI WaitNamedPipeW(LPCWSTR name, DWORD timeout_ms)
{
    static const WCHAR root[] = L"\\Device\\NamedPipe\\";
    static const char pfx[] = "\\\\.\\pipe\\";
    struct { LARGE_INTEGER timeout; ULONG name_len; BOOLEAN specified; WCHAR name[260]; } w;   /* FILE_PIPE_WAIT_FOR_BUFFER: Name at 14 */
    SHZ_UNICODE_STRING us;
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_IO_STATUS_BLOCK iosb;
    HANDLE h = 0;
    NTSTATUS st;
    ULONG i, n;
    for (i = 0; pfx[i]; ++i) if (!name || (name[i] | (i >= 3 ? 32 : 0)) != (pfx[i] | (i >= 3 ? 32 : 0))) { shz_set_last_error(ERROR_BAD_PATHNAME); return FALSE; }
    n = (ULONG)wl(name + 9);
    if (!n || n >= 260) { shz_set_last_error(ERROR_BAD_PATHNAME); return FALSE; }
    us.Buffer = (PWSTR)root; us.Length = sizeof root - 2; us.MaximumLength = sizeof root;
    memset(&oa, 0, sizeof oa);
    oa.Length = sizeof oa;
    oa.ObjectName = &us;
    oa.Attributes = NT_OBJ_CASE_INSENSITIVE;
    st = NtOpenFile(&h, SYNCHRONIZE | FILE_READ_ATTRIBUTES, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, NT_OPT_SYNCHRONOUS);
    if (st) return k32_ipc_fail(st);
    memset(&w, 0, sizeof w);
    w.specified = timeout_ms != NMPWAIT_USE_DEFAULT_WAIT;
    w.timeout.QuadPart = timeout_ms == NMPWAIT_WAIT_FOREVER ? (LONGLONG)0x8000000000000000ull : -(LONGLONG)timeout_ms * 10000;
    w.name_len = n * 2;
    memcpy(w.name, name + 9, n * 2);
    st = NtFsControlFile(h, 0, 0, 0, &iosb, FSCTL_PIPE_WAIT_K, &w, 14 + n * 2, 0, 0);
    NtClose(h);
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API BOOL WINAPI WaitNamedPipeA(LPCSTR name, DWORD timeout_ms)
{
    WCHAR w[300];
    if (!name || k32_utf8_to_wide(name, -1, w, 300) <= 0) { shz_set_last_error(ERROR_BAD_PATHNAME); return FALSE; }
    return WaitNamedPipeW(w, timeout_ms);
}

K32API BOOL WINAPI CallNamedPipeW(LPCWSTR name, LPVOID in, DWORD in_len, LPVOID out, DWORD out_len, LPDWORD read, DWORD timeout_ms)
{
    HANDLE h;
    DWORD mode = PIPE_READMODE_MESSAGE;
    BOOL ok;
    for (;;) {
        h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        if (h != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_PIPE_BUSY || !WaitNamedPipeW(name, timeout_ms)) return FALSE;
    }
    ok = SetNamedPipeHandleState(h, &mode, 0, 0) && TransactNamedPipe(h, in, in_len, out, out_len, read, 0);
    {
        const DWORD e = GetLastError();
        CloseHandle(h);
        shz_set_last_error(ok ? 0 : e);
    }
    return ok;
}

static BOOL pipe_attribute(HANDLE h, const char *attr, ULONG_PTR *v)
{
    SHZ_IO_STATUS_BLOCK iosb;
    char a[24];
    size_t n = 0;
    NTSTATUS st;
    while (attr[n]) { a[n] = attr[n]; ++n; }
    a[n++] = 0;
    st = NtFsControlFile(h, 0, 0, 0, &iosb, FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE_K, a, (ULONG)n, v, sizeof *v);
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API BOOL WINAPI GetNamedPipeClientProcessId(HANDLE h, PULONG pid)
{
    ULONG_PTR v = 0;
    if (!pipe_attribute(h, "ClientProcessId", &v)) return FALSE;
    *pid = (ULONG)v;
    return TRUE;
}

K32API BOOL WINAPI GetNamedPipeServerProcessId(HANDLE h, PULONG pid)
{
    ULONG_PTR v = 0;
    if (!pipe_attribute(h, "ServerProcessId", &v)) return FALSE;
    *pid = (ULONG)v;
    return TRUE;
}

K32API BOOL WINAPI GetNamedPipeClientSessionId(HANDLE h, PULONG sid)
{
    ULONG_PTR v = 0;
    if (!pipe_attribute(h, "ClientSessionId", &v)) return FALSE;
    *sid = (ULONG)v;
    return TRUE;
}

K32API BOOL WINAPI GetNamedPipeServerSessionId(HANDLE h, PULONG sid)
{
    ULONG_PTR v = 0;
    if (!pipe_attribute(h, "ServerSessionId", &v)) return FALSE;
    *sid = (ULONG)v;
    return TRUE;
}

/* Anonymous pipes are named pipes with a unique name (as on Windows): the read end is the server of an inbound pipe. */
K32API BOOL WINAPI CreatePipe(PHANDLE rd, PHANDLE wr, LPSECURITY_ATTRIBUTES sa, DWORD size)
{
    static volatile LONG serial;
    WCHAR name[64];
    char a[64];
    HANDLE r, w;
    int i;
    if (!rd || !wr) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    {
        static const char hex[] = "0123456789abcdef";
        const DWORD pid = GetCurrentProcessId(), n = (DWORD)InterlockedIncrement((LONG *)&serial);
        const char *s = "\\\\.\\pipe\\Win32Pipes.";
        int k = 0;
        while (*s) a[k++] = *s++;
        for (i = 7; i >= 0; --i) a[k++] = hex[(pid >> (i * 4)) & 15];
        a[k++] = '.';
        for (i = 7; i >= 0; --i) a[k++] = hex[(n >> (i * 4)) & 15];
        a[k] = 0;
        for (i = 0; i <= k; ++i) name[i] = (WCHAR)a[i];
    }
    r = CreateNamedPipeW(name, PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_WAIT, 1, size ? size : 4096, size ? size : 4096, 120000, sa);
    if (r == INVALID_HANDLE_VALUE) return FALSE;
    w = CreateFileW(name, GENERIC_WRITE, 0, sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (w == INVALID_HANDLE_VALUE) { const DWORD e = GetLastError(); CloseHandle(r); shz_set_last_error(e); return FALSE; }
    *rd = r;
    *wr = w;
    return TRUE;
}

/* ---------------------------------------------------------------- directory change notification */
/* ReadDirectoryChangesW: FILE_NOTIFY_INFORMATION records for changes in a directory opened with FILE_LIST_DIRECTORY
 * (and FILE_FLAG_BACKUP_SEMANTICS). Synchronous calls wait for a change; overlapped ones return TRUE at once and
 * complete through the OVERLAPPED (event / port) or the completion routine. A zero byte count means the change buffer
 * overflowed: the caller should rescan the directory. */
K32API BOOL WINAPI ReadDirectoryChangesW(HANDLE dir, LPVOID buf, DWORD len, BOOL subtree, DWORD filter, LPDWORD ret,
                                         LPOVERLAPPED ov, LPOVERLAPPED_COMPLETION_ROUTINE fn)
{
    NTSTATUS st;
    if (!filter || !buf || !len) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (ov) {
        ov->Internal = STATUS_PENDING;
        ov->InternalHigh = 0;
        st = fn ? NtNotifyChangeDirectoryFile(dir, 0, (PVOID)io_completion_apc, (PVOID)fn, (SHZ_IO_STATUS_BLOCK *)ov, buf, len,
                                              filter, subtree != 0)
                : NtNotifyChangeDirectoryFile(dir, ov_event(ov), 0, ov_context(ov), (SHZ_IO_STATUS_BLOCK *)ov, buf, len, filter,
                                              subtree != 0);
        if (NT_ERROR(st)) { k32_nt_error(st); return FALSE; }
        return TRUE;                                            /* pending or already complete: the OVERLAPPED says which */
    } else {
        SHZ_IO_STATUS_BLOCK iosb;
        memset(&iosb, 0, sizeof iosb);
        st = sync_wait(dir, NtNotifyChangeDirectoryFile(dir, 0, 0, 0, &iosb, buf, len, filter, subtree != 0), &iosb);
        if (ret) *ret = st == STATUS_NOTIFY_ENUM_DIR ? 0 : (DWORD)iosb.Information;
        if (NT_ERROR(st)) { k32_nt_error(st); return FALSE; }
        return TRUE;
    }
}
