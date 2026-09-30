/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32 inter-process communication and process objects: anonymous and named pipes (byte and message mode, busy and
 * disconnected states, overlapped connect and read), I/O completion ports (file association, posted packets, FIFO order,
 * cancellation packets), file mappings (paging-file and file-backed, names, offsets, copy-on-write views, flushing), job
 * objects (assignment, accounting, termination, kill-on-close, completion messages), handle inheritance through
 * PROC_THREAD_ATTRIBUTE_HANDLE_LIST (the values a child receives on its command line must be usable and closable there),
 * cross-process DuplicateHandle, OpenProcess/OpenThread, thread and whole-process suspension, waitable timers and
 * registered waits. Expectations are the documented Win32 semantics; the child processes are this program started
 * again with a mode argument.
 */
#include "k32test.h"

LONG NTAPI NtSuspendProcess(HANDLE process);
LONG NTAPI NtResumeProcess(HANDLE process);

static WCHAR g_self[300];

/* ---------------------------------------------------------------- helpers */
static unsigned long long parse_hex(const char *s)
{
    unsigned long long v = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    for (; *s; ++s) {
        const char c = *s;
        if (c >= '0' && c <= '9') v = v * 16 + (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v = v * 16 + (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v = v * 16 + (unsigned)(c - 'A' + 10);
        else break;
    }
    return v;
}

static void widen(WCHAR *dst, const char *src, size_t cap)
{
    size_t i;
    for (i = 0; src[i] && i + 1 < cap; ++i) dst[i] = (WCHAR)(unsigned char)src[i];
    dst[i] = 0;
}

/* "<self>" <args> as a mutable command line */
static void child_cmdline(WCHAR *cmd, size_t cap, const char *args)
{
    size_t n = 0, i;
    cmd[n++] = '"';
    for (i = 0; g_self[i] && n + 2 < cap; ++i) cmd[n++] = g_self[i];
    cmd[n++] = '"';
    cmd[n++] = ' ';
    for (i = 0; args[i] && n + 1 < cap; ++i) cmd[n++] = (WCHAR)(unsigned char)args[i];
    cmd[n] = 0;
}

static BOOL start_child(const char *args, DWORD flags, BOOL inherit, STARTUPINFOW *si, PROCESS_INFORMATION *pi)
{
    WCHAR cmd[600];
    STARTUPINFOW local;
    child_cmdline(cmd, 600, args);
    if (!si) { memset(&local, 0, sizeof local); local.cb = sizeof local; si = &local; }
    memset(pi, 0, sizeof *pi);
    return CreateProcessW(g_self, cmd, 0, 0, inherit, flags, 0, 0, si, pi);
}

static DWORD wait_exit(PROCESS_INFORMATION *pi, DWORD ms)
{
    DWORD code = 0xdeadbeef;
    if (WaitForSingleObject(pi->hProcess, ms) != WAIT_OBJECT_0) return 0xdeadbeef;
    GetExitCodeProcess(pi->hProcess, &code);
    return code;
}

static void close_pi(PROCESS_INFORMATION *pi) { CloseHandle(pi->hThread); CloseHandle(pi->hProcess); }

#define MAP_NAME L"shz_k32_ipc_map"
#define COUNT_NAME L"shz_k32_ipc_count"

/* ---------------------------------------------------------------- child modes */
static int child_main(int argc, char **argv)
{
    if (!strcmp(argv[1], "child-inherit") && argc >= 5) {
        /* the handles of the parent's PROC_THREAD_ATTRIBUTE_HANDLE_LIST, by value; the fourth is inheritable but not listed */
        HANDLE ev = (HANDLE)(ULONG_PTR)parse_hex(argv[2]), wr = (HANDLE)(ULONG_PTR)parse_hex(argv[3]);
        HANDLE unlisted = (HANDLE)(ULONG_PTR)parse_hex(argv[4]);
        DWORD n = 0, flags = 0;
        int bad = 0;
        if (!GetHandleInformation(ev, &flags) || !(flags & HANDLE_FLAG_INHERIT)) bad |= 1;
        if (!SetEvent(ev)) bad |= 2;
        if (!WriteFile(wr, "inherited", 9, &n, 0) || n != 9) bad |= 4;
        if (!CloseHandle(ev)) bad |= 8;
        if (!CloseHandle(wr)) bad |= 16;
        if (GetHandleInformation(unlisted, &flags)) bad |= 32;
        return bad;
    }
    if (!strcmp(argv[1], "child-mapping")) {
        HANDLE m = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, MAP_NAME);
        DWORD *v;
        if (!m) return 1;
        v = MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (!v) return 2;
        if (v[0] != 0x5AFEC0DEu) return 3;
        v[1] = 0xC0FFEE01u;
        UnmapViewOfFile(v);
        CloseHandle(m);
        return 0;
    }
    if (!strcmp(argv[1], "child-count")) {                  /* counts forever in a shared DWORD */
        HANDLE m = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, COUNT_NAME);
        volatile LONG *v;
        if (!m) return 1;
        v = MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (!v) return 2;
        for (;;) InterlockedIncrement(v);
    }
    if (!strcmp(argv[1], "child-sleep")) { Sleep(INFINITE); return 0; }
    if (!strcmp(argv[1], "child-exit") && argc >= 3) return (int)parse_hex(argv[2]);
    return 99;
}

/* ---------------------------------------------------------------- anonymous pipes */
static void test_anonymous_pipe(void)
{
    HANDLE r = 0, w = 0;
    char buf[16];
    DWORD n = 0, avail = 0;
    CHECK(CreatePipe(&r, &w, 0, 0), "CreatePipe");
    CHECK(WriteFile(w, "hello", 5, &n, 0) && n == 5, "WriteFile on the write end");
    CHECKV(PeekNamedPipe(r, 0, 0, 0, &avail, 0) && avail == 5, "PeekNamedPipe reports the 5 bytes waiting", "avail=%u", (unsigned)avail);
    CHECK(ReadFile(r, buf, sizeof buf, &n, 0) && n == 5 && !memcmp(buf, "hello", 5), "ReadFile returns the bytes written");
    CHECK(!WriteFile(r, "x", 1, &n, 0), "the read end cannot be written");
    CloseHandle(w);
    SetLastError(0);
    CHECK(!ReadFile(r, buf, sizeof buf, &n, 0), "ReadFile after the write end closed fails");
    CHECK_ERR(ERROR_BROKEN_PIPE, "... with ERROR_BROKEN_PIPE");
    CloseHandle(r);
}

/* ---------------------------------------------------------------- named pipes */
static void test_named_byte(void)
{
    static const WCHAR name[] = L"\\\\.\\pipe\\shz_k32_ipc_byte";
    HANDLE s, c, c2;
    char buf[32];
    DWORD n = 0, flags = 0, out = 0, in = 0, maxi = 0;
    ULONG pid = 0;
    s = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, 0);
    CHECK(s != INVALID_HANDLE_VALUE, "CreateNamedPipeW (byte mode, one instance)");
    SetLastError(0);
    CHECK(!WaitNamedPipeW(L"\\\\.\\pipe\\shz_k32_ipc_none", 100), "WaitNamedPipeW for a pipe that does not exist fails");
    CHECK_ERR(ERROR_FILE_NOT_FOUND, "... with ERROR_FILE_NOT_FOUND");
    CHECK(WaitNamedPipeW(name, 100), "WaitNamedPipeW succeeds while an instance listens");
    c = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    CHECK(c != INVALID_HANDLE_VALUE, "a client opens the pipe with CreateFileW");
    SetLastError(0);
    CHECK(!ConnectNamedPipe(s, 0), "ConnectNamedPipe after the client connected returns FALSE");
    CHECK_ERR(ERROR_PIPE_CONNECTED, "... with ERROR_PIPE_CONNECTED");
    SetLastError(0);
    c2 = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    CHECK(c2 == INVALID_HANDLE_VALUE, "a second client of a one-instance pipe is refused");
    CHECK_ERR(ERROR_PIPE_BUSY, "... with ERROR_PIPE_BUSY");
    SetLastError(0);
    CHECK(!WaitNamedPipeW(name, 50), "WaitNamedPipeW times out while the only instance is connected");
    CHECK_ERR(ERROR_SEM_TIMEOUT, "... with ERROR_SEM_TIMEOUT");
    CHECK(WriteFile(c, "to-server", 9, &n, 0) && n == 9, "client -> server write");
    CHECK(ReadFile(s, buf, sizeof buf, &n, 0) && n == 9 && !memcmp(buf, "to-server", 9), "the server reads it");
    CHECK(WriteFile(s, "to-client", 9, &n, 0) && ReadFile(c, buf, sizeof buf, &n, 0) && n == 9 && !memcmp(buf, "to-client", 9),
          "server -> client transfer");
    CHECKV(GetNamedPipeInfo(s, &flags, &out, &in, &maxi) && flags == PIPE_SERVER_END && maxi == 1, "GetNamedPipeInfo on the server end",
           "flags=%x max=%u", (unsigned)flags, (unsigned)maxi);
    CHECK(GetNamedPipeInfo(c, &flags, 0, 0, 0) && flags == PIPE_CLIENT_END, "GetNamedPipeInfo on the client end");
    CHECK(GetNamedPipeServerProcessId(c, &pid) && pid == GetCurrentProcessId(), "GetNamedPipeServerProcessId is this process");
    CHECK(GetNamedPipeClientProcessId(s, &pid) && pid == GetCurrentProcessId(), "GetNamedPipeClientProcessId is this process");
    CHECK(DisconnectNamedPipe(s), "DisconnectNamedPipe");
    SetLastError(0);
    CHECK(!ReadFile(c, buf, sizeof buf, &n, 0), "a read on the disconnected client end fails");
    CHECK_ERR(ERROR_PIPE_NOT_CONNECTED, "... with ERROR_PIPE_NOT_CONNECTED");
    CloseHandle(c);
    CloseHandle(s);
    SetLastError(0);
    CHECK(CreateFileW(name, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0) == INVALID_HANDLE_VALUE, "the pipe name is gone with its last instance");
    CHECK_ERR(ERROR_FILE_NOT_FOUND, "... ERROR_FILE_NOT_FOUND");
}

static HANDLE g_msg_server;
static DWORD WINAPI echo_server(LPVOID arg)
{
    char buf[64];
    DWORD n = 0;
    (void)arg;
    if (!ReadFile(g_msg_server, buf, sizeof buf, &n, 0) || n != 3 || memcmp(buf, "ask", 3)) return 1;
    return WriteFile(g_msg_server, "reply", 5, &n, 0) ? 0 : 2;
}

static void test_named_message(void)
{
    static const WCHAR name[] = L"\\\\.\\pipe\\shz_k32_ipc_msg";
    HANDLE s, c, th;
    char buf[64];
    DWORD n = 0, avail = 0, left = 0, mode = PIPE_READMODE_MESSAGE, code = 1;
    s = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 2, 4096, 4096, 0, 0);
    CHECK(s != INVALID_HANDLE_VALUE, "CreateNamedPipeW (message mode)");
    c = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    CHECK(c != INVALID_HANDLE_VALUE, "client connects");
    CHECK(SetNamedPipeHandleState(c, &mode, 0, 0), "SetNamedPipeHandleState(PIPE_READMODE_MESSAGE) on the client");
    CHECK(WriteFile(c, "first-message", 13, &n, 0) && WriteFile(c, "2nd", 3, &n, 0), "two messages written");
    CHECKV(PeekNamedPipe(s, 0, 0, 0, &avail, &left) && avail == 16 && left == 13, "PeekNamedPipe: 16 bytes in the pipe, 13 in the first message",
           "avail=%u left=%u", (unsigned)avail, (unsigned)left);
    SetLastError(0);
    CHECK(!ReadFile(s, buf, 5, &n, 0) && n == 5 && !memcmp(buf, "first", 5), "a short read of a message returns its first 5 bytes and FALSE");
    CHECK_ERR(ERROR_MORE_DATA, "... with ERROR_MORE_DATA");
    CHECK(ReadFile(s, buf, sizeof buf, &n, 0) && n == 8 && !memcmp(buf, "-message", 8), "the next read returns the rest of that message");
    CHECK(ReadFile(s, buf, sizeof buf, &n, 0) && n == 3 && !memcmp(buf, "2nd", 3), "message boundaries are kept");
    g_msg_server = s;
    th = CreateThread(0, 0, echo_server, 0, 0, 0);
    CHECK(TransactNamedPipe(c, "ask", 3, buf, sizeof buf, &n, 0) && n == 5 && !memcmp(buf, "reply", 5),
          "TransactNamedPipe writes a message and reads the reply");
    CHECK(WaitForSingleObject(th, 5000) == WAIT_OBJECT_0 && GetExitCodeThread(th, &code) && code == 0, "the server thread saw the request");
    CloseHandle(th);
    CloseHandle(c);
    CloseHandle(s);
}

/* ---------------------------------------------------------------- overlapped I/O and completion ports */
static void test_overlapped_iocp(void)
{
    static const WCHAR name[] = L"\\\\.\\pipe\\shz_k32_ipc_ov";
    HANDLE s, c, ev, port;
    OVERLAPPED ov, rov, cov;
    OVERLAPPED *pov = 0;
    OVERLAPPED_ENTRY ents[4];
    ULONG removed = 0;
    ULONG_PTR key = 0;
    DWORD n = 0;
    char buf[16];
    s = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, 0);
    CHECK(s != INVALID_HANDLE_VALUE, "CreateNamedPipeW with FILE_FLAG_OVERLAPPED");
    ev = CreateEventW(0, TRUE, FALSE, 0);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = ev;
    SetLastError(0);
    CHECK(!ConnectNamedPipe(s, &ov), "overlapped ConnectNamedPipe with no client returns FALSE");
    CHECK_ERR(ERROR_IO_PENDING, "... with ERROR_IO_PENDING");
    CHECK(WaitForSingleObject(ev, 0) == WAIT_TIMEOUT, "the event is not signaled before a client arrives");
    c = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    CHECK(c != INVALID_HANDLE_VALUE, "client connects");
    CHECK(WaitForSingleObject(ev, 5000) == WAIT_OBJECT_0, "the connect completes: event signaled");
    CHECK(GetOverlappedResult(s, &ov, &n, FALSE), "GetOverlappedResult of the connect succeeds");

    port = CreateIoCompletionPort(s, 0, 0x77, 0);
    CHECK(port != 0, "CreateIoCompletionPort associates the server end");
    memset(&rov, 0, sizeof rov);
    SetLastError(0);
    CHECK(!ReadFile(s, buf, sizeof buf, 0, &rov) && GetLastError() == ERROR_IO_PENDING, "an overlapped read with no data pends");
    CHECK(WriteFile(c, "ping", 4, &n, 0), "the client writes 4 bytes");
    CHECK(GetQueuedCompletionStatus(port, &n, &key, &pov, 5000) && key == 0x77 && pov == &rov && n == 4 && !memcmp(buf, "ping", 4),
          "the read's completion packet carries the key, the OVERLAPPED and the byte count");
    pov = (OVERLAPPED *)1;
    SetLastError(0);
    CHECK(!GetQueuedCompletionStatus(port, &n, &key, &pov, 0) && pov == 0, "an empty port times out with a NULL OVERLAPPED");
    CHECK_ERR(WAIT_TIMEOUT, "... and ERROR_WAIT_TIMEOUT (258)");
    CHECK(PostQueuedCompletionStatus(port, 11, 22, (OVERLAPPED *)33) && PostQueuedCompletionStatus(port, 44, 55, (OVERLAPPED *)66),
          "PostQueuedCompletionStatus twice");
    CHECKV(GetQueuedCompletionStatusEx(port, ents, 4, &removed, 1000, FALSE) && removed == 2 &&
           ents[0].dwNumberOfBytesTransferred == 11 && ents[0].lpCompletionKey == 22 && ents[0].lpOverlapped == (OVERLAPPED *)33 &&
           ents[1].dwNumberOfBytesTransferred == 44 && ents[1].lpCompletionKey == 55,
           "GetQueuedCompletionStatusEx removes both packets in FIFO order", "removed=%u", (unsigned)removed);
    memset(&cov, 0, sizeof cov);
    CHECK(!ReadFile(s, buf, sizeof buf, 0, &cov) && GetLastError() == ERROR_IO_PENDING, "another overlapped read pends");
    CHECK(CancelIoEx(s, &cov), "CancelIoEx cancels it");
    SetLastError(0);
    CHECK(!GetOverlappedResult(s, &cov, &n, TRUE), "GetOverlappedResult of the cancelled read fails");
    CHECK_ERR(ERROR_OPERATION_ABORTED, "... with ERROR_OPERATION_ABORTED");
    pov = 0;
    SetLastError(0);
    CHECK(!GetQueuedCompletionStatus(port, &n, &key, &pov, 1000) && pov == &cov, "the cancellation is also queued to the port");
    CHECK_ERR(ERROR_OPERATION_ABORTED, "... as ERROR_OPERATION_ABORTED");
    CloseHandle(c);
    CloseHandle(s);
    CloseHandle(port);
    CloseHandle(ev);
}

/* ---------------------------------------------------------------- file mappings */
static void test_mappings(void)
{
    HANDLE m, m2, mo, f;
    DWORD *v1, *v2, *v3, *cow;
    MEMORY_BASIC_INFORMATION mbi;
    PROCESS_INFORMATION pi;
    WCHAR tmp[MAX_PATH], path[MAX_PATH];
    unsigned char *fv, data[8192], back[8192];
    DWORD n = 0, i;
    SetLastError(1234);
    m = CreateFileMappingW(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 65536, MAP_NAME);
    CHECK(m != 0, "CreateFileMappingW of 64 KiB paging-file memory, named");
    CHECK_ERR(0, "a new mapping leaves the last error 0");
    v1 = MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    v2 = MapViewOfFile(m, FILE_MAP_READ, 0, 0, 4096);
    CHECK(v1 && v2 && v1 != v2, "two views at different addresses");
    if (!v1 || !v2) return;
    CHECK(v1[0] == 0 && v1[16383] == 0, "new paging-file memory is zero");
    v1[0] = 0x5AFEC0DEu;
    CHECK(v2[0] == 0x5AFEC0DEu, "a write through one view is visible in the other");
    CHECKV(VirtualQuery(v1, &mbi, sizeof mbi) && mbi.Type == MEM_MAPPED && mbi.State == MEM_COMMIT && mbi.AllocationBase == v1 &&
           mbi.RegionSize >= 65536, "VirtualQuery: a committed MEM_MAPPED region", "type=%x state=%x size=%llx", (unsigned)mbi.Type,
           (unsigned)mbi.State, (unsigned long long)mbi.RegionSize);
    SetLastError(0);
    m2 = CreateFileMappingW(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 65536, MAP_NAME);
    CHECK(m2 != 0, "creating the same name again returns a handle");
    CHECK_ERR(ERROR_ALREADY_EXISTS, "... with ERROR_ALREADY_EXISTS");
    v3 = m2 ? MapViewOfFile(m2, FILE_MAP_READ, 0, 0, 0) : 0;
    CHECK(v3 && v3[0] == 0x5AFEC0DEu, "... to the same memory");
    mo = OpenFileMappingW(FILE_MAP_READ, FALSE, MAP_NAME);
    CHECK(mo != 0, "OpenFileMappingW by name");
    SetLastError(0);
    CHECK(OpenFileMappingW(FILE_MAP_READ, FALSE, L"shz_k32_ipc_nomap") == 0, "OpenFileMappingW of an unknown name fails");
    CHECK_ERR(ERROR_FILE_NOT_FOUND, "... with ERROR_FILE_NOT_FOUND");
    v1[1024 + 5] = 0x1234u;                                   /* offset 4096 + 20 */
    {
        DWORD *off = MapViewOfFile(m, FILE_MAP_READ, 0, 65536 - 65536 + 0, 0);
        DWORD *mid;
        SetLastError(0);
        mid = MapViewOfFile(m, FILE_MAP_READ, 0, 1000, 16);
        CHECK(mid == 0, "a view at an offset that is not a multiple of the allocation granularity fails");
        CHECK_ERR(ERROR_MAPPED_ALIGNMENT, "... with ERROR_MAPPED_ALIGNMENT");
        CHECK(off && off[1024 + 5] == 0x1234u, "a whole-section view sees the data at offset 4096");
        if (off) UnmapViewOfFile(off);
    }
    cow = MapViewOfFile(m, FILE_MAP_COPY, 0, 0, 0);
    CHECK(cow && cow[0] == 0x5AFEC0DEu, "a FILE_MAP_COPY view shows the section data");
    if (cow) {
        cow[0] = 0x11111111u;
        CHECK(cow[0] == 0x11111111u && v1[0] == 0x5AFEC0DEu, "a write to the copy-on-write view stays private");
        v1[2048] = 0x22222222u;                               /* page 2: never written through the copy view */
        CHECK(cow[2048] == 0x22222222u, "pages of the copy view that were never written still show the section");
        v1[2] = 0x33333333u;                                  /* page 0: the copy view has its own copy of it */
        CHECK(cow[2] != 0x33333333u, "a written page of the copy view no longer follows the section");
        UnmapViewOfFile(cow);
    }
    /* another process opens the mapping by name and writes into it */
    CHECK(start_child("child-mapping", 0, FALSE, 0, &pi), "start a child that opens the mapping");
    if (pi.hProcess) {
        CHECK(wait_exit(&pi, 20000) == 0, "the child found the value and exited 0");
        CHECK(v1[1] == 0xC0FFEE01u, "the child's write is visible here");
        close_pi(&pi);
    }
    CHECK(UnmapViewOfFile(v2), "UnmapViewOfFile");
    SetLastError(0);
    CHECK(!UnmapViewOfFile(v2), "unmapping the same view twice fails");
    CHECK_ERR(ERROR_INVALID_ADDRESS, "... with ERROR_INVALID_ADDRESS");
    UnmapViewOfFile(v1);
    if (v3) UnmapViewOfFile(v3);
    CloseHandle(mo);
    if (m2) CloseHandle(m2);
    CloseHandle(m);

    /* file-backed */
    n = GetTempPathW(MAX_PATH, tmp);
    CHECK(n > 0 && GetTempFileNameW(tmp, L"ipc", 0, path), "a temporary file name");
    f = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    CHECK(f != INVALID_HANDLE_VALUE, "create the file");
    if (f == INVALID_HANDLE_VALUE) return;
    SetLastError(0);
    CHECK(CreateFileMappingW(f, 0, PAGE_READONLY, 0, 0, 0) == 0, "mapping an empty file with size 0 fails");
    CHECK_ERR(ERROR_FILE_INVALID, "... with ERROR_FILE_INVALID");
    for (i = 0; i < sizeof data; ++i) data[i] = (unsigned char)(i * 7 + 3);
    CHECK(WriteFile(f, data, sizeof data, &n, 0) && n == sizeof data, "write 8 KiB");
    m = CreateFileMappingW(f, 0, PAGE_READWRITE, 0, 0, 0);
    CHECK(m != 0, "CreateFileMappingW of the file (size 0 = the file's size)");
    fv = m ? MapViewOfFile(m, FILE_MAP_WRITE, 0, 0, 0) : 0;
    CHECK(fv && !memcmp(fv, data, sizeof data), "the view shows the file contents");
    if (fv) {
        fv[100] = 0xAB;
        fv[5000] = 0xCD;
        CHECK(FlushViewOfFile(fv, 0), "FlushViewOfFile");
        CHECK(UnmapViewOfFile(fv), "unmap the file view");
    }
    if (m) CloseHandle(m);
    SetFilePointer(f, 0, 0, FILE_BEGIN);
    CHECK(ReadFile(f, back, sizeof back, &n, 0) && n == sizeof back && back[100] == 0xAB && back[5000] == 0xCD && back[101] == data[101],
          "the file holds the bytes written through the view");
    CloseHandle(f);
    DeleteFileW(path);
}

/* ---------------------------------------------------------------- inheritance */
static void test_inheritance(void)
{
    SECURITY_ATTRIBUTES sa = { sizeof sa, 0, TRUE };
    HANDLE ev, rd = 0, wr = 0, pad[24], unlisted, list[2];
    STARTUPINFOEXW si;
    PROCESS_INFORMATION pi;
    SIZE_T size = 0;
    char args[160], buf[32];
    DWORD n = 0, flags = 0;
    unsigned i;
    for (i = 0; i < 24; ++i) pad[i] = CreateEventW(0, FALSE, FALSE, 0);   /* push the values below past the child's own */
    ev = CreateEventW(&sa, TRUE, FALSE, 0);
    CHECK(CreatePipe(&rd, &wr, &sa, 0), "an inheritable pipe");
    unlisted = CreateEventW(&sa, TRUE, FALSE, 0);
    CHECK(GetHandleInformation(ev, &flags) && (flags & HANDLE_FLAG_INHERIT), "the event handle is inheritable");
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    memset(&si, 0, sizeof si);
    si.StartupInfo.cb = sizeof si;
    InitializeProcThreadAttributeList(0, 1, 0, &size);
    si.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, size);
    CHECK(si.lpAttributeList && InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size), "InitializeProcThreadAttributeList");
    list[0] = ev;
    list[1] = wr;
    CHECK(UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list, sizeof list, 0, 0),
          "PROC_THREAD_ATTRIBUTE_HANDLE_LIST with the event and the pipe's write end");
    snprintf(args, sizeof args, "child-inherit %llx %llx %llx", (unsigned long long)(ULONG_PTR)ev, (unsigned long long)(ULONG_PTR)wr,
             (unsigned long long)(ULONG_PTR)unlisted);
    CHECK(start_child(args, EXTENDED_STARTUPINFO_PRESENT, TRUE, &si.StartupInfo, &pi), "CreateProcessW with inheritance and the list");
    CloseHandle(wr);
    if (pi.hProcess) {
        const DWORD code = wait_exit(&pi, 20000);
        CHECKV(code == 0, "the child used and closed the inherited handles by the parent's values, and did not get the unlisted one",
               "child exit %u", (unsigned)code);
        CHECK(WaitForSingleObject(ev, 0) == WAIT_OBJECT_0, "the child's SetEvent reached this process' event");
        CHECK(ReadFile(rd, buf, sizeof buf, &n, 0) && n == 9 && !memcmp(buf, "inherited", 9), "the child's write arrived through the pipe");
        close_pi(&pi);
    }
    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    CloseHandle(rd);
    CloseHandle(ev);
    CloseHandle(unlisted);
    for (i = 0; i < 24; ++i) CloseHandle(pad[i]);
}

/* ---------------------------------------------------------------- process / thread objects */
static volatile LONG g_counter, g_stop;
static DWORD WINAPI counter_thread(LPVOID arg)
{
    (void)arg;
    while (!g_stop) InterlockedIncrement(&g_counter);
    return 5;
}

static BOOL wait_counter_moves(volatile LONG *c, DWORD ms)
{
    const LONG start = *c;
    const ULONGLONG end = GetTickCount64() + ms;
    while (GetTickCount64() < end) { if (*c != start) return TRUE; Sleep(1); }
    return *c != start;
}

static void test_process_thread_objects(void)
{
    HANDLE h, t, t2, ev, dup = 0, back = 0, remote = 0, cm;
    DWORD tid = 0, flags = 0, code = 0;
    LONG c1, c2;
    volatile LONG *shared;
    PROCESS_INFORMATION pi;
    static DWORD target = 0x1234;
    DWORD val = 0;
    SIZE_T done = 0;
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    CHECK(h && GetProcessId(h) == GetCurrentProcessId(), "OpenProcess(own pid) and GetProcessId");
    if (h) CloseHandle(h);
    SetLastError(0);
    CHECK(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0x7ffffff0) == 0, "OpenProcess of a pid that does not exist fails");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "... with ERROR_INVALID_PARAMETER");
    h = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, GetCurrentProcessId());
    CHECK(h && ReadProcessMemory(h, &target, &val, 4, &done) && val == 0x1234 && done == 4, "ReadProcessMemory through a process handle");
    val = 0x4321;
    CHECK(h && WriteProcessMemory(h, &target, &val, 4, &done) && target == 0x4321, "WriteProcessMemory");
    if (h) CloseHandle(h);

    g_counter = 0; g_stop = 0;
    t = CreateThread(0, 0, counter_thread, 0, CREATE_SUSPENDED, &tid);
    CHECK(t && GetThreadId(t) == tid && GetProcessIdOfThread(t) == GetCurrentProcessId(), "GetThreadId / GetProcessIdOfThread");
    t2 = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    CHECK(t2 && GetThreadId(t2) == tid, "OpenThread by id");
    Sleep(50);
    CHECK(g_counter == 0, "a CREATE_SUSPENDED thread does not run");
    CHECK(ResumeThread(t) == 1, "ResumeThread returns the previous suspend count 1");
    CHECK(wait_counter_moves(&g_counter, 3000), "the resumed thread runs");
    CHECK(SuspendThread(t2) == 0, "SuspendThread returns 0 for a running thread");
    Sleep(50);
    c1 = g_counter; Sleep(100); c2 = g_counter;
    CHECKV(c1 == c2, "a suspended thread makes no progress", "%ld -> %ld", (long)c1, (long)c2);
    CHECK(SuspendThread(t) == 1 && ResumeThread(t) == 2 && ResumeThread(t2) == 1, "suspend counts nest");
    CHECK(wait_counter_moves(&g_counter, 3000), "the thread runs again once the count reaches 0");
    g_stop = 1;
    CHECK(WaitForSingleObject(t, 5000) == WAIT_OBJECT_0 && GetExitCodeThread(t, &code) && code == 5, "the thread exits");
    CloseHandle(t); CloseHandle(t2);

    ev = CreateEventW(0, TRUE, FALSE, 0);
    CHECK(DuplicateHandle(GetCurrentProcess(), ev, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS) && dup != ev,
          "DuplicateHandle within the process");
    CHECK(SetEvent(dup) && WaitForSingleObject(ev, 0) == WAIT_OBJECT_0, "the duplicate names the same event");
    ResetEvent(ev);
    CHECK(SetHandleInformation(dup, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE) && GetHandleInformation(dup, &flags) &&
          flags == HANDLE_FLAG_PROTECT_FROM_CLOSE, "HANDLE_FLAG_PROTECT_FROM_CLOSE is set");
    SetLastError(0);
    CHECK(!CloseHandle(dup), "a protected handle cannot be closed");
    CHECK_ERR(ERROR_INVALID_HANDLE, "... ERROR_INVALID_HANDLE");
    CHECK(SetHandleInformation(dup, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0) && CloseHandle(dup), "unprotected, it closes");

    CHECK(start_child("child-sleep", CREATE_SUSPENDED, FALSE, 0, &pi), "start a suspended child");
    if (pi.hProcess) {
        CHECK(DuplicateHandle(GetCurrentProcess(), ev, pi.hProcess, &remote, 0, FALSE, DUPLICATE_SAME_ACCESS), "DuplicateHandle into the child");
        CHECK(DuplicateHandle(pi.hProcess, remote, GetCurrentProcess(), &back, 0, FALSE, DUPLICATE_SAME_ACCESS), "and back from the child");
        CHECK(back && SetEvent(back) && WaitForSingleObject(ev, 0) == WAIT_OBJECT_0, "the round trip names the same event");
        if (back) CloseHandle(back);
        CHECK(DuplicateHandle(pi.hProcess, remote, 0, 0, 0, FALSE, DUPLICATE_CLOSE_SOURCE), "DUPLICATE_CLOSE_SOURCE closes it in the child");
        SetLastError(0);
        back = 0;
        CHECK(!DuplicateHandle(pi.hProcess, remote, GetCurrentProcess(), &back, 0, FALSE, DUPLICATE_SAME_ACCESS), "... it is gone there");
        CHECK_ERR(ERROR_INVALID_HANDLE, "... ERROR_INVALID_HANDLE");
        CHECK(TerminateProcess(pi.hProcess, 3) && wait_exit(&pi, 5000) == 3, "TerminateProcess of a suspended child, exit code 3");
        close_pi(&pi);
    }
    CloseHandle(ev);

    /* whole-process suspension: the child counts in shared memory */
    cm = CreateFileMappingW(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 4096, COUNT_NAME);
    shared = cm ? MapViewOfFile(cm, FILE_MAP_ALL_ACCESS, 0, 0, 0) : 0;
    CHECK(shared != 0, "a shared counter page");
    if (shared && start_child("child-count", 0, FALSE, 0, &pi)) {
        CHECK(wait_counter_moves(shared, 10000), "the child counts");
        CHECK(NtSuspendProcess(pi.hProcess) == 0, "NtSuspendProcess");
        Sleep(50);
        c1 = *shared; Sleep(150); c2 = *shared;
        CHECKV(c1 == c2, "a suspended process makes no progress", "%ld -> %ld", (long)c1, (long)c2);
        CHECK(NtResumeProcess(pi.hProcess) == 0, "NtResumeProcess");
        CHECK(wait_counter_moves(shared, 3000), "the child counts again");
        CHECK(NtSuspendProcess(pi.hProcess) == 0 && TerminateProcess(pi.hProcess, 9) && wait_exit(&pi, 5000) == 9,
              "a suspended process can be terminated");
        close_pi(&pi);
    }
    if (shared) UnmapViewOfFile((LPCVOID)shared);
    if (cm) CloseHandle(cm);
}

/* ---------------------------------------------------------------- jobs */
static void test_jobs(void)
{
    HANDLE job, job2, port;
    PROCESS_INFORMATION pi, pi2;
    BOOL in = TRUE;
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acct;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION lim;
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT assoc;
    DWORD msg = 0;
    ULONG_PTR key = 0;
    OVERLAPPED *pov = 0;
    int saw_new = 0, saw_zero = 0, i;
    job = CreateJobObjectW(0, 0);
    CHECK(job != 0, "CreateJobObjectW");
    port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 1);
    assoc.CompletionKey = (PVOID)0x5150;
    assoc.CompletionPort = port;
    CHECK(SetInformationJobObject(job, JobObjectAssociateCompletionPortInformation, &assoc, sizeof assoc), "associate a completion port");
    CHECK(start_child("child-sleep", CREATE_SUSPENDED, FALSE, 0, &pi), "start a suspended child");
    if (!pi.hProcess) return;
    CHECK(AssignProcessToJobObject(job, pi.hProcess), "AssignProcessToJobObject");
    CHECK(IsProcessInJob(pi.hProcess, job, &in) && in, "IsProcessInJob(child, job)");
    CHECK(IsProcessInJob(GetCurrentProcess(), job, &in) && !in, "IsProcessInJob(this process, job) is FALSE");
    memset(&acct, 0, sizeof acct);
    CHECKV(QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &acct, sizeof acct, 0) && acct.ActiveProcesses == 1 &&
           acct.TotalProcesses == 1, "accounting: one active process", "active=%u total=%u", (unsigned)acct.ActiveProcesses,
           (unsigned)acct.TotalProcesses);
    CHECK(ResumeThread(pi.hThread) == 1, "resume the child");
    CHECK(TerminateJobObject(job, 0x55), "TerminateJobObject");
    CHECK(wait_exit(&pi, 5000) == 0x55, "the child ends with the job's exit code");
    for (i = 0; i < 8 && GetQueuedCompletionStatus(port, &msg, &key, &pov, 2000); ++i) {
        if (key != 0x5150) continue;
        if (msg == JOB_OBJECT_MSG_NEW_PROCESS && (DWORD)(ULONG_PTR)pov == pi.dwProcessId) saw_new = 1;
        if (msg == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO) { saw_zero = 1; break; }
    }
    CHECK(saw_new, "the port received JOB_OBJECT_MSG_NEW_PROCESS with the child's pid");
    CHECK(saw_zero, "... and JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO");
    close_pi(&pi);
    CloseHandle(job);
    CloseHandle(port);

    job2 = CreateJobObjectW(0, 0);
    memset(&lim, 0, sizeof lim);
    lim.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    CHECK(SetInformationJobObject(job2, JobObjectExtendedLimitInformation, &lim, sizeof lim), "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE");
    CHECK(start_child("child-sleep", 0, FALSE, 0, &pi2), "start a child");
    if (!pi2.hProcess) return;
    CHECK(AssignProcessToJobObject(job2, pi2.hProcess), "assign it");
    CHECK(WaitForSingleObject(pi2.hProcess, 200) == WAIT_TIMEOUT, "the child keeps running while the job is open");
    CloseHandle(job2);
    CHECK(WaitForSingleObject(pi2.hProcess, 5000) == WAIT_OBJECT_0, "closing the last job handle kills it");
    close_pi(&pi2);
}

/* ---------------------------------------------------------------- waitable timers and registered waits */
static volatile LONG g_cb_count, g_cb_fired;
static HANDLE g_cb_done;
static VOID CALLBACK wait_cb(PVOID ctx, BOOLEAN fired)
{
    if (ctx != (PVOID)0x77) return;
    if (fired) InterlockedIncrement(&g_cb_fired);
    InterlockedIncrement(&g_cb_count);
    SetEvent(g_cb_done);
}

static void test_timers_and_waits(void)
{
    HANDLE t, t2, ev, ev2, wh = 0, wh2 = 0;
    LARGE_INTEGER due;
    ULONGLONG t0, dt;
    int i, ok = 1;
    t = CreateWaitableTimerW(0, TRUE, 0);
    CHECK(t != 0, "CreateWaitableTimerW (manual reset)");
    due.QuadPart = -2000000;                                   /* 200 ms, relative */
    CHECK(SetWaitableTimer(t, &due, 0, 0, 0, FALSE), "SetWaitableTimer 200 ms");
    CHECK(WaitForSingleObject(t, 0) == WAIT_TIMEOUT, "not signaled before its due time");
    t0 = GetTickCount64();
    CHECK(WaitForSingleObject(t, 5000) == WAIT_OBJECT_0, "signaled at its due time");
    dt = GetTickCount64() - t0;
    CHECKV(dt >= 150 && dt < 3000, "after about 200 ms", "%llu ms", (unsigned long long)dt);
    CHECK(WaitForSingleObject(t, 0) == WAIT_OBJECT_0, "a manual-reset timer stays signaled");
    due.QuadPart = -1000000;
    CHECK(SetWaitableTimer(t, &due, 0, 0, 0, FALSE) && WaitForSingleObject(t, 0) == WAIT_TIMEOUT, "setting it again resets it");
    CHECK(CancelWaitableTimer(t) && WaitForSingleObject(t, 300) == WAIT_TIMEOUT, "a cancelled timer does not fire");
    CloseHandle(t);
    t2 = CreateWaitableTimerW(0, FALSE, 0);
    due.QuadPart = -100000;                                    /* 10 ms, then every 20 ms */
    CHECK(t2 && SetWaitableTimer(t2, &due, 20, 0, 0, FALSE), "a periodic auto-reset timer");
    for (i = 0; i < 3; ++i) if (WaitForSingleObject(t2, 2000) != WAIT_OBJECT_0) ok = 0;
    CHECK(ok, "it fires three times");
    CancelWaitableTimer(t2);
    CloseHandle(t2);

    g_cb_done = CreateEventW(0, FALSE, FALSE, 0);
    ev = CreateEventW(0, FALSE, FALSE, 0);
    g_cb_count = 0; g_cb_fired = 0;
    CHECK(RegisterWaitForSingleObject(&wh, ev, wait_cb, (PVOID)0x77, INFINITE, WT_EXECUTEDEFAULT), "RegisterWaitForSingleObject");
    CHECK(SetEvent(ev) && WaitForSingleObject(g_cb_done, 5000) == WAIT_OBJECT_0 && g_cb_count == 1 && g_cb_fired == 0,
          "signaling the event runs the callback (TimerOrWaitFired FALSE)");
    CHECK(SetEvent(ev) && WaitForSingleObject(g_cb_done, 5000) == WAIT_OBJECT_0 && g_cb_count == 2, "the wait stays registered");
    CHECK(UnregisterWaitEx(wh, INVALID_HANDLE_VALUE), "UnregisterWaitEx(INVALID_HANDLE_VALUE)");
    SetEvent(ev);
    Sleep(100);
    CHECK(g_cb_count == 2, "no callback after unregistration");
    ev2 = CreateEventW(0, FALSE, FALSE, 0);
    CHECK(RegisterWaitForSingleObject(&wh2, ev2, wait_cb, (PVOID)0x77, 50, WT_EXECUTEONLYONCE), "a 50 ms one-shot wait");
    CHECK(WaitForSingleObject(g_cb_done, 5000) == WAIT_OBJECT_0 && g_cb_fired == 1, "it times out once (TimerOrWaitFired TRUE)");
    Sleep(200);
    CHECK(g_cb_count == 3, "WT_EXECUTEONLYONCE: no second callback");
    CHECK(UnregisterWaitEx(wh2, INVALID_HANDLE_VALUE), "unregister the one-shot wait");
    CloseHandle(ev); CloseHandle(ev2); CloseHandle(g_cb_done);
}

int main(int argc, char **argv)
{
    if (argc >= 2 && argv[1][0] == 'c' && argv[1][1] == 'h' && argv[1][2] == 'i' && argv[1][3] == 'l' && argv[1][4] == 'd' &&
        argv[1][5] == '-') return child_main(argc, argv);
    if (!GetModuleFileNameW(0, g_self, 300)) { printf("FAIL: GetModuleFileNameW\n"); return 1; }
    test_anonymous_pipe();
    test_named_byte();
    test_named_message();
    test_overlapped_iocp();
    test_mappings();
    test_inheritance();
    test_process_thread_objects();
    test_jobs();
    test_timers_and_waits();
    return k32t_finish("t_k32_ipc");
}
