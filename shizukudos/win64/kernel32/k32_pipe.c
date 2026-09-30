/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: named and anonymous pipes over the Kernel64 named pipe file system (kernel64/npfs.c):
 * CreateNamedPipeW/A, ConnectNamedPipe, DisconnectNamedPipe, WaitNamedPipeW/A, PeekNamedPipe, TransactNamedPipe,
 * CallNamedPipeW, SetNamedPipeHandleState, GetNamedPipeHandleStateW, GetNamedPipeInfo, GetNamedPipeClientProcessId,
 * GetNamedPipeServerProcessId, CreatePipe. The NT interfaces are the Windows ones (NtCreateNamedPipeFile, NtFsControlFile
 * with the FSCTL_PIPE_* codes, FilePipeInformation / FilePipeLocalInformation); CreateFile on "\\.\pipe\NAME" opens the
 * client end (k32_file.c). Security attributes are accepted (the inherit flag is honoured) but not enforced.
 */
#include "k32.h"

#define FSCTL_PIPE_DISCONNECT_ 0x110004u
#define FSCTL_PIPE_LISTEN_ 0x110008u
#define FSCTL_PIPE_PEEK_ 0x11400Cu
#define FSCTL_PIPE_WAIT_ 0x110018u
#define FSCTL_PIPE_TRANSCEIVE_ 0x11C017u
#define FSCTL_PIPE_GET_PIPE_ATTRIBUTE_ 0x110030u

static NTSTATUS pipe_nt_name(LPCWSTR name, WCHAR *out, size_t cap)
{
    /* "\\.\pipe\X" (any case, also "\\?\pipe\X") -> "\??\pipe\X"; other names are not pipe names */
    size_t i, n = 0;
    static const WCHAR pre[] = { '\\', '?', '?', '\\', 0 };
    if (!name || name[0] != '\\' || name[1] != '\\' || (name[2] != '.' && name[2] != '?') || name[3] != '\\') return STATUS_OBJECT_NAME_INVALID;
    if (!((name[4] | 32) == 'p' && (name[5] | 32) == 'i' && (name[6] | 32) == 'p' && (name[7] | 32) == 'e' && name[8] == '\\'))
        return STATUS_OBJECT_NAME_INVALID;
    for (i = 0; pre[i]; ++i) out[n++] = pre[i];
    for (i = 4; name[i] && n + 1 < cap; ++i) out[n++] = name[i];
    if (name[i]) return STATUS_OBJECT_NAME_INVALID;
    out[n] = 0;
    return STATUS_SUCCESS;
}

K32API HANDLE WINAPI CreateNamedPipeW(LPCWSTR name, DWORD open_mode, DWORD pipe_mode, DWORD max_instances, DWORD out_size,
                                      DWORD in_size, DWORD timeout_ms, LPSECURITY_ATTRIBUTES sa)
{
    WCHAR nt[300];
    SHZ_UNICODE_STRING us;
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_IO_STATUS_BLOCK io;
    LARGE_INTEGER to;
    HANDLE h = INVALID_HANDLE_VALUE;
    ACCESS_MASK access = 0;
    ULONG options = 0, disposition;
    NTSTATUS st;
    const DWORD dir = open_mode & (PIPE_ACCESS_INBOUND | PIPE_ACCESS_OUTBOUND);
    if (pipe_nt_name(name, nt, 300)) { shz_set_last_error(ERROR_INVALID_NAME); return INVALID_HANDLE_VALUE; }
    if (!dir || (open_mode & ~(PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_FIRST_PIPE_INSTANCE |
                               WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY)) ||
        (pipe_mode & ~(PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS)) ||
        (max_instances != PIPE_UNLIMITED_INSTANCES && (max_instances == 0 || max_instances > PIPE_UNLIMITED_INSTANCES)) ||
        ((pipe_mode & PIPE_READMODE_MESSAGE) && !(pipe_mode & PIPE_TYPE_MESSAGE))) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    if (dir & PIPE_ACCESS_INBOUND) access |= GENERIC_READ;
    if (dir & PIPE_ACCESS_OUTBOUND) access |= GENERIC_WRITE;
    access |= SYNCHRONIZE | (open_mode & (WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY));
    if (!(open_mode & FILE_FLAG_OVERLAPPED)) options |= 0x20;                     /* FILE_SYNCHRONOUS_IO_NONALERT */
    if (open_mode & FILE_FLAG_WRITE_THROUGH) options |= 0x2;
    disposition = (open_mode & FILE_FLAG_FIRST_PIPE_INSTANCE) ? FILE_CREATE_D : FILE_OPEN_IF_D;
    us.Buffer = nt;
    us.Length = (USHORT)(k32_wlen(nt) * 2);
    us.MaximumLength = us.Length + 2;
    memset(&oa, 0, sizeof oa);
    oa.Length = sizeof oa;
    oa.ObjectName = &us;
    oa.Attributes = 0x40 | (sa && sa->bInheritHandle ? 2 : 0);                    /* OBJ_CASE_INSENSITIVE | OBJ_INHERIT */
    oa.SecurityDescriptor = sa ? sa->lpSecurityDescriptor : 0;
    to.QuadPart = -(LONGLONG)(timeout_ms ? timeout_ms : 50) * 10000;
    st = NtCreateNamedPipeFile(&h, access, &oa, &io, FILE_SHARE_READ | FILE_SHARE_WRITE, disposition, options,
                               (pipe_mode & PIPE_TYPE_MESSAGE) ? 1 : 0, (pipe_mode & PIPE_READMODE_MESSAGE) ? 1 : 0,
                               (pipe_mode & PIPE_NOWAIT) ? 1 : 0, max_instances == PIPE_UNLIMITED_INSTANCES ? 0xffffffffu : max_instances,
                               in_size, out_size, &to);
    if (st) { k32_nt_error(st); return INVALID_HANDLE_VALUE; }
    shz_set_last_error(0);
    return h;
}

K32API HANDLE WINAPI CreateNamedPipeA(LPCSTR name, DWORD open_mode, DWORD pipe_mode, DWORD max_instances, DWORD out_size, DWORD in_size,
                                      DWORD timeout_ms, LPSECURITY_ATTRIBUTES sa)
{
    WCHAR w[300];
    if (!name || k32_utf8_to_wide(name, -1, w, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return INVALID_HANDLE_VALUE; }
    return CreateNamedPipeW(w, open_mode, pipe_mode, max_instances, out_size, in_size, timeout_ms, sa);
}

/* An FSCTL on a pipe handle, synchronous or overlapped like ReadFile/WriteFile. Returns the NT status; *done is the
 * information of a completed request. */
static NTSTATUS pipe_fsctl(HANDLE h, ULONG code, LPOVERLAPPED ov, PVOID in, ULONG in_len, PVOID out, ULONG out_len, DWORD *done)
{
    SHZ_IO_STATUS_BLOCK io;
    NTSTATUS st;
    if (ov) {
        HANDLE ev = (HANDLE)((ULONG_PTR)ov->hEvent & ~(ULONG_PTR)1);
        PVOID ctx = ((ULONG_PTR)ov->hEvent & 1) ? 0 : ov;
        ov->Internal = STATUS_PENDING;
        ov->InternalHigh = 0;
        st = NtFsControlFile(h, ev, 0, ctx, (SHZ_IO_STATUS_BLOCK *)ov, code, in, in_len, out, out_len);
        if (done) *done = st == STATUS_PENDING ? 0 : (DWORD)ov->InternalHigh;
        if (st != STATUS_PENDING && st < 0) ov->Internal = (ULONG_PTR)(LONG_PTR)st;
        return st;
    }
    memset(&io, 0, sizeof io);
    st = NtFsControlFile(h, 0, 0, 0, &io, code, in, in_len, out, out_len);
    if (done) *done = (DWORD)io.Information;
    return st;
}

K32API BOOL WINAPI ConnectNamedPipe(HANDLE h, LPOVERLAPPED ov)
{
    NTSTATUS st = pipe_fsctl(h, FSCTL_PIPE_LISTEN_, ov, 0, 0, 0, 0, 0);
    if (st == STATUS_PENDING) { shz_set_last_error(ERROR_IO_PENDING); return FALSE; }
    if (st) { k32_nt_error(st); return FALSE; }                                   /* ERROR_PIPE_CONNECTED, ERROR_NO_DATA, ... */
    return TRUE;
}

K32API BOOL WINAPI DisconnectNamedPipe(HANDLE h)
{
    NTSTATUS st = pipe_fsctl(h, FSCTL_PIPE_DISCONNECT_, 0, 0, 0, 0, 0, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

/* WaitNamedPipe: NMPWAIT_USE_DEFAULT_WAIT (0) uses the pipe's default time-out, NMPWAIT_WAIT_FOREVER waits without one. */
K32API BOOL WINAPI WaitNamedPipeW(LPCWSTR name, DWORD timeout_ms)
{
    WCHAR nt[300], root[] = { '\\', '?', '?', '\\', 'p', 'i', 'p', 'e', '\\', 0 };
    SHZ_UNICODE_STRING us;
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_IO_STATUS_BLOCK io;
    HANDLE fs = 0;
    NTSTATUS st;
    BYTE buf[16 + 600];
    size_t n;
    LONGLONG to;
    if (pipe_nt_name(name, nt, 300)) { shz_set_last_error(ERROR_BAD_PATHNAME); return FALSE; }
    n = k32_wlen(nt) - 9;                                                         /* the name after "\??\pipe\" */
    if (n * 2 > sizeof buf - 14) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
    us.Buffer = root;
    us.Length = 18;
    us.MaximumLength = 20;
    memset(&oa, 0, sizeof oa);
    oa.Length = sizeof oa;
    oa.ObjectName = &us;
    st = NtCreateFile(&fs, SYNCHRONIZE | FILE_READ_ATTRIBUTES, &oa, &io, 0, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_D, 0x20, 0, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    to = timeout_ms == NMPWAIT_WAIT_FOREVER ? (LONGLONG)0x7fffffffffffffffll : -(LONGLONG)timeout_ms * 10000;
    memset(buf, 0, sizeof buf);
    memcpy(buf, &to, 8);
    *(ULONG *)(buf + 8) = (ULONG)(n * 2);
    buf[12] = timeout_ms != NMPWAIT_USE_DEFAULT_WAIT;                             /* TimeoutSpecified */
    memcpy(buf + 14, nt + 9, n * 2);
    st = NtFsControlFile(fs, 0, 0, 0, &io, FSCTL_PIPE_WAIT_, buf, (ULONG)(14 + n * 2), 0, 0);
    NtClose(fs);
    if (st) { k32_nt_error(st); return FALSE; }                                   /* ERROR_SEM_TIMEOUT, ERROR_FILE_NOT_FOUND */
    return TRUE;
}

K32API BOOL WINAPI WaitNamedPipeA(LPCSTR name, DWORD timeout_ms)
{
    WCHAR w[300];
    if (!name || k32_utf8_to_wide(name, -1, w, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    return WaitNamedPipeW(w, timeout_ms);
}

K32API BOOL WINAPI PeekNamedPipe(HANDLE h, LPVOID buf, DWORD size, LPDWORD read, LPDWORD avail, LPDWORD left_in_msg)
{
    BYTE small[16 + 512];
    BYTE *b = small;
    const DWORD want = buf ? size : 0;
    DWORD done = 0;
    NTSTATUS st;
    if (16 + (SIZE_T)want > sizeof small) {
        b = RtlAllocateHeap(ShzProcessHeap(), 0, 16 + (SIZE_T)want);
        if (!b) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    }
    st = pipe_fsctl(h, FSCTL_PIPE_PEEK_, 0, 0, 0, b, 16 + want, &done);
    if (st && st != STATUS_BUFFER_OVERFLOW) { if (b != small) RtlFreeHeap(ShzProcessHeap(), 0, b); k32_nt_error(st); return FALSE; }
    {
        const ULONG *hdr = (const ULONG *)b;
        const DWORD copied = done >= 16 ? done - 16 : 0;
        if (buf && copied) memcpy(buf, b + 16, copied);
        if (read) *read = copied;
        if (avail) *avail = hdr[1];
        if (left_in_msg) *left_in_msg = hdr[2] ? hdr[3] - copied : 0;
    }
    if (b != small) RtlFreeHeap(ShzProcessHeap(), 0, b);
    return TRUE;
}

K32API BOOL WINAPI TransactNamedPipe(HANDLE h, LPVOID in, DWORD in_size, LPVOID out, DWORD out_size, LPDWORD read, LPOVERLAPPED ov)
{
    DWORD done = 0;
    NTSTATUS st = pipe_fsctl(h, FSCTL_PIPE_TRANSCEIVE_, ov, in, in_size, out, out_size, &done);
    if (read) *read = done;
    if (st == STATUS_PENDING) { shz_set_last_error(ERROR_IO_PENDING); return FALSE; }
    if (st) { k32_nt_error(st); return FALSE; }                                   /* ERROR_MORE_DATA keeps *read */
    return TRUE;
}

K32API BOOL WINAPI CallNamedPipeW(LPCWSTR name, LPVOID in, DWORD in_size, LPVOID out, DWORD out_size, LPDWORD read, DWORD timeout_ms)
{
    HANDLE h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    DWORD mode = PIPE_READMODE_MESSAGE;
    BOOL ok;
    if (h == INVALID_HANDLE_VALUE) {
        if (GetLastError() != ERROR_PIPE_BUSY || !WaitNamedPipeW(name, timeout_ms)) return FALSE;
        h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        if (h == INVALID_HANDLE_VALUE) return FALSE;
    }
    ok = SetNamedPipeHandleState(h, &mode, 0, 0) && TransactNamedPipe(h, in, in_size, out, out_size, read, 0);
    {
        const DWORD e = GetLastError();
        CloseHandle(h);
        shz_set_last_error(ok ? 0 : e);
    }
    return ok;
}

/* SetNamedPipeHandleState: read mode and wait mode; the collection count and time-out only apply to remote pipes
 * (byte-mode clients on another machine), which do not exist here, so asking for them fails. */
K32API BOOL WINAPI SetNamedPipeHandleState(HANDLE h, LPDWORD mode, LPDWORD max_collect, LPDWORD collect_timeout)
{
    ULONG v[2];
    SHZ_IO_STATUS_BLOCK io;
    NTSTATUS st;
    if (max_collect || collect_timeout) return k32_unsupported("SetNamedPipeHandleState", "remote collection parameters", ERROR_INVALID_PARAMETER);
    if (!mode) return TRUE;
    if (*mode & ~(PIPE_READMODE_MESSAGE | PIPE_NOWAIT)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    v[0] = (*mode & PIPE_READMODE_MESSAGE) ? 1 : 0;
    v[1] = (*mode & PIPE_NOWAIT) ? 1 : 0;
    st = NtSetInformationFile(h, &io, v, sizeof v, 23);                           /* FilePipeInformation */
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

static NTSTATUS pipe_local(HANDLE h, ULONG v[10])
{
    SHZ_IO_STATUS_BLOCK io;
    return NtQueryInformationFile(h, &io, v, 40, 24);                             /* FilePipeLocalInformation */
}

K32API BOOL WINAPI GetNamedPipeInfo(HANDLE h, LPDWORD flags, LPDWORD out_size, LPDWORD in_size, LPDWORD max_instances)
{
    ULONG v[10];
    NTSTATUS st = pipe_local(h, v);
    if (st) { k32_nt_error(st); return FALSE; }
    if (flags) *flags = (v[9] ? PIPE_SERVER_END : PIPE_CLIENT_END) | (v[0] ? PIPE_TYPE_MESSAGE : 0);
    if (out_size) *out_size = v[6];
    if (in_size) *in_size = v[4];
    if (max_instances) *max_instances = v[2] == 0xffffffffu ? PIPE_UNLIMITED_INSTANCES : v[2];
    return TRUE;
}

K32API BOOL WINAPI GetNamedPipeHandleStateW(HANDLE h, LPDWORD state, LPDWORD instances, LPDWORD max_collect, LPDWORD collect_timeout,
                                            LPWSTR user, DWORD user_size)
{
    ULONG v[10], pi[2];
    SHZ_IO_STATUS_BLOCK io;
    NTSTATUS st = pipe_local(h, v);
    if (!st) st = NtQueryInformationFile(h, &io, pi, sizeof pi, 23);
    if (st) { k32_nt_error(st); return FALSE; }
    if (state) *state = (pi[0] ? PIPE_READMODE_MESSAGE : 0) | (pi[1] ? PIPE_NOWAIT : 0);
    if (instances) *instances = v[3];
    if (max_collect) *max_collect = 0;
    if (collect_timeout) *collect_timeout = 0;
    if (user) return k32_unsupported("GetNamedPipeHandleStateW", "client user name (no user accounts)", ERROR_NOT_SUPPORTED);
    (void)user_size;
    return TRUE;
}

static BOOL pipe_pid(HANDLE h, const char *attr, PULONG pid)
{
    ULONG_PTR v = 0;
    ULONG n = 0;
    NTSTATUS st;
    while (attr[n]) ++n;
    st = pipe_fsctl(h, FSCTL_PIPE_GET_PIPE_ATTRIBUTE_, 0, (PVOID)attr, n + 1, &v, sizeof v, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    *pid = (ULONG)v;
    return TRUE;
}
K32API BOOL WINAPI GetNamedPipeClientProcessId(HANDLE h, PULONG pid) { return pipe_pid(h, "ClientProcessId", pid); }
K32API BOOL WINAPI GetNamedPipeServerProcessId(HANDLE h, PULONG pid) { return pipe_pid(h, "ServerProcessId", pid); }
K32API BOOL WINAPI GetNamedPipeClientSessionId(HANDLE h, PULONG id) { return pipe_pid(h, "ClientSessionId", id); }
K32API BOOL WINAPI GetNamedPipeServerSessionId(HANDLE h, PULONG id) { return pipe_pid(h, "ServerSessionId", id); }

/* CreatePipe: an anonymous pipe is a named pipe with a unique name, one instance, byte mode, synchronous ends (as Windows
 * builds it: \Device\NamedPipe\Win32Pipes.<pid>.<serial>). */
K32API BOOL WINAPI CreatePipe(PHANDLE rd, PHANDLE wr, LPSECURITY_ATTRIBUTES sa, DWORD size)
{
    static volatile LONG serial;
    WCHAR name[64];
    const WCHAR *pre = L"\\\\.\\pipe\\Win32Pipes.";
    ULONG v[2] = { GetCurrentProcessId(), (ULONG)__sync_add_and_fetch(&serial, 1) };
    size_t n = 0, i;
    HANDLE r, w;
    int k;
    for (i = 0; pre[i]; ++i) name[n++] = pre[i];
    for (k = 0; k < 2; ++k) {
        int d;
        if (k) name[n++] = '.';
        for (d = 7; d >= 0; --d) name[n++] = L"0123456789abcdef"[(v[k] >> (d * 4)) & 15];
    }
    name[n] = 0;
    if (!size) size = 4096;
    r = CreateNamedPipeW(name, PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1,
                         size, size, 120000, sa);
    if (r == INVALID_HANDLE_VALUE) return FALSE;
    w = CreateFileW(name, GENERIC_WRITE | FILE_READ_ATTRIBUTES, 0, sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (w == INVALID_HANDLE_VALUE) { const DWORD e = GetLastError(); CloseHandle(r); shz_set_last_error(e); return FALSE; }
    *rd = r;
    *wr = w;
    return TRUE;
}
