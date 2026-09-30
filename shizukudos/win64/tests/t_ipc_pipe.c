/* SPDX-License-Identifier: GPL-2.0-only
 * Named and anonymous pipes, overlapped I/O, I/O completion ports and completion routines: byte and message pipes,
 * instance limits, ConnectNamedPipe/DisconnectNamedPipe states, PeekNamedPipe, TransactNamedPipe/CallNamedPipe,
 * WaitNamedPipe, broken pipes, client/server process ids across processes, CreatePipe + STARTF_USESTDHANDLES
 * redirection, flow control through a small quota, overlapped reads with events / CancelIoEx / completion ports /
 * FILE_SKIP_COMPLETION_PORT_ON_SUCCESS / ReadFileEx, job notifications through a port, DeviceIoControl on files,
 * and no leaked pipes, IRPs or packets.
 */
#include "ipc_test.h"
#include <winioctl.h>

static WCHAR g_name[80];
static void pipe_name(const char *tag)
{
    char a[80];
    snprintf(a, sizeof a, "\\\\.\\pipe\\ipct_%s_%u", tag, (unsigned)GetCurrentProcessId());
    wcopy(g_name, a);
}

static HANDLE client(DWORD access, DWORD flags)
{
    return CreateFileW(g_name, access, 0, 0, OPEN_EXISTING, flags, 0);
}

/* ---------------------------------------------------------------- children */
static int child_client(char **argv)
{
    WCHAR name[80];
    HANDLE h;
    ULONG spid = 0;
    DWORD n;
    char buf[32];
    wcopy(name, argv[2]);
    if (!WaitNamedPipeW(name, 10000)) return 1;
    h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if (h == INVALID_HANDLE_VALUE) return 2;
    if (!GetNamedPipeServerProcessId(h, &spid) || spid != (ULONG)ipc_atou(argv[3])) return 3;
    if (!WriteFile(h, "from child", 10, &n, 0) || n != 10) return 4;
    if (!ReadFile(h, buf, sizeof buf, &n, 0) || n != 5 || memcmp(buf, "reply", 5)) return 5;
    CloseHandle(h);
    return 0;
}

static int child_stdout(void)
{
    DWORD n;
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetFileType(out) != FILE_TYPE_PIPE) return 1;
    return WriteFile(out, "child says hi", 13, &n, 0) && n == 13 ? 0 : 2;
}

/* ---------------------------------------------------------------- helpers */
static volatile LONG g_routine_calls;
static DWORD g_routine_err, g_routine_bytes;
static VOID CALLBACK on_read(DWORD err, DWORD bytes, LPOVERLAPPED ov) { (void)ov; g_routine_err = err; g_routine_bytes = bytes; ++g_routine_calls; }

static DWORD WINAPI delayed_client(LPVOID arg)
{
    HANDLE h;
    Sleep((DWORD)(ULONG_PTR)arg);
    h = client(GENERIC_READ | GENERIC_WRITE, 0);
    if (h == INVALID_HANDLE_VALUE) return 1;
    Sleep(200);
    CloseHandle(h);
    return 0;
}

static HANDLE g_p2;
static DWORD WINAPI gqcs_waiter(LPVOID a)
{
    DWORD n;
    ULONG_PTR k;
    LPOVERLAPPED o;
    (void)a;
    if (GetQueuedCompletionStatus(g_p2, &n, &k, &o, 5000)) return 1;
    return o ? 2 : GetLastError();
}

static HANDLE g_srv_msg;
static DWORD WINAPI echo_server(LPVOID arg)                  /* message server: request -> "re:" + request */
{
    char buf[64], out[70];
    DWORD n, w;
    (void)arg;
    if (!ConnectNamedPipe(g_srv_msg, 0) && GetLastError() != ERROR_PIPE_CONNECTED) return 1;
    while (ReadFile(g_srv_msg, buf, sizeof buf, &n, 0)) {
        memcpy(out, "re:", 3);
        memcpy(out + 3, buf, n);
        if (!WriteFile(g_srv_msg, out, n + 3, &w, 0)) break;
    }
    return 0;
}

static unsigned char *g_big;
#define BIG (64u * 1024u + 123u)
static DWORD WINAPI slow_reader(LPVOID arg)
{
    HANDLE h = arg;
    unsigned char buf[1000];
    DWORD n, got = 0;
    unsigned long long sum = 0;
    while (got < BIG && ReadFile(h, buf, sizeof buf, &n, 0)) {
        DWORD i;
        for (i = 0; i < n; ++i) sum = sum * 31 + buf[i];
        got += n;
        if ((got & 0x3fff) < 1000) Sleep(1);
    }
    return got == BIG ? (DWORD)(sum ^ (sum >> 32)) : 0;
}

/* ---------------------------------------------------------------- tests */
static void test_basics(void)
{
    HANDLE s, c, s2;
    char buf[32];
    DWORD n, avail, left, flags, out_size, in_size, maxi, state, inst;
    pipe_name("byte");
    s = CreateNamedPipeW(g_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, 0);
    CHECK(s != INVALID_HANDLE_VALUE, "CreateNamedPipe (byte, one instance)");
    CHECK(GetFileType(s) == FILE_TYPE_PIPE, "GetFileType of a pipe is FILE_TYPE_PIPE");
    s2 = CreateNamedPipeW(g_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, 0);
    CHECK(s2 == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY, "a second instance past the limit fails with ERROR_PIPE_BUSY");
    CHECK(ReadFile(s, buf, 4, &n, 0) == FALSE && GetLastError() == ERROR_PIPE_LISTENING, "reading a listening server fails with ERROR_PIPE_LISTENING");
    c = client(GENERIC_READ | GENERIC_WRITE, 0);
    CHECK(c != INVALID_HANDLE_VALUE, "the client connects to the listening instance");
    CHECK(client(GENERIC_READ | GENERIC_WRITE, 0) == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY,
          "another client finds no free instance (ERROR_PIPE_BUSY)");
    CHECK(!ConnectNamedPipe(s, 0) && GetLastError() == ERROR_PIPE_CONNECTED, "ConnectNamedPipe after the client came: ERROR_PIPE_CONNECTED");
    CHECK(WriteFile(c, "0123456789", 10, &n, 0) && n == 10, "the client writes 10 bytes");
    CHECK(PeekNamedPipe(s, buf, 3, &n, &avail, &left) && n == 3 && avail == 10 && left == 0 && !memcmp(buf, "012", 3),
          "PeekNamedPipe sees them without consuming (avail %u)", (unsigned)avail);
    CHECK(ReadFile(s, buf, 4, &n, 0) && n == 4 && !memcmp(buf, "0123", 4), "a byte-mode read takes 4 of them");
    CHECK(ReadFile(s, buf, 32, &n, 0) && n == 6 && !memcmp(buf, "456789", 6), "the next read the other 6");
    CHECK(GetNamedPipeInfo(s, &flags, &out_size, &in_size, &maxi) && flags == PIPE_SERVER_END && out_size == 4096 &&
          in_size == 4096 && maxi == 1, "GetNamedPipeInfo of the server end");
    CHECK(GetNamedPipeInfo(c, &flags, 0, 0, 0) && flags == PIPE_CLIENT_END, "GetNamedPipeInfo of the client end");
    CHECK(GetNamedPipeHandleStateW(s, &state, &inst, 0, 0, 0, 0) && state == 0 && inst == 1, "GetNamedPipeHandleState");
    {
        ULONG pid = 0;
        CHECK(GetNamedPipeClientProcessId(s, &pid) && pid == GetCurrentProcessId() &&
              GetNamedPipeServerProcessId(c, &pid) && pid == GetCurrentProcessId(), "client and server process ids");
    }
    /* broken pipe */
    CHECK(WriteFile(c, "tail", 4, &n, 0), "a last write");
    CloseHandle(c);
    CHECK(ReadFile(s, buf, 32, &n, 0) && n == 4, "the server still reads what was buffered");
    CHECK(!ReadFile(s, buf, 32, &n, 0) && GetLastError() == ERROR_BROKEN_PIPE, "then ERROR_BROKEN_PIPE");
    CHECK(!WriteFile(s, "x", 1, &n, 0) && GetLastError() == ERROR_NO_DATA, "writing to a closed client: ERROR_NO_DATA");
    CHECK(!ConnectNamedPipe(s, 0) && GetLastError() == ERROR_NO_DATA, "ConnectNamedPipe before DisconnectNamedPipe: ERROR_NO_DATA");
    CHECK(DisconnectNamedPipe(s), "DisconnectNamedPipe");
    {
        HANDLE t = CreateThread(0, 0, delayed_client, (LPVOID)50, 0, 0);
        CHECK(ConnectNamedPipe(s, 0), "ConnectNamedPipe waits for the next client");
        WaitForSingleObject(t, 5000);
        CloseHandle(t);
        CHECK(DisconnectNamedPipe(s), "DisconnectNamedPipe of the second client");
    }
    /* WaitNamedPipe */
    CHECK(!WaitNamedPipeW(L"\\\\.\\pipe\\ipct_does_not_exist", 10) && GetLastError() == ERROR_FILE_NOT_FOUND,
          "WaitNamedPipe of a missing pipe: ERROR_FILE_NOT_FOUND");
    CHECK(!WaitNamedPipeW(g_name, 50) && GetLastError() == ERROR_SEM_TIMEOUT, "WaitNamedPipe on a disconnected pipe times out");
    {
        HANDLE t = CreateThread(0, 0, delayed_client, (LPVOID)100, 0, 0);
        CHECK(ConnectNamedPipe(s, 0), "listening again: the next client connects");
        WaitForSingleObject(t, 5000);
        CloseHandle(t);
    }
    CloseHandle(s);
    CHECK(client(GENERIC_READ, 0) == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND,
          "the name is gone with its last instance");
}

static void test_messages(void)
{
    HANDLE s, c, t;
    char buf[32];
    DWORD n, mode = PIPE_READMODE_MESSAGE, avail, left;
    pipe_name("msg");
    s = CreateNamedPipeW(g_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
                         64, 64, 0, 0);
    c = client(GENERIC_READ | GENERIC_WRITE, 0);
    CHECK(s != INVALID_HANDLE_VALUE && c != INVALID_HANDLE_VALUE, "a message pipe and its client");
    CHECK(WriteFile(c, "hello", 5, &n, 0) && WriteFile(c, "world!", 6, &n, 0) && WriteFile(c, "", 0, &n, 0), "three messages (one empty)");
    CHECK(PeekNamedPipe(s, buf, 2, &n, &avail, &left) && n == 2 && avail == 11 && left == 3, "PeekNamedPipe: 2 read, 11 available, 3 left in the message");
    CHECK(!ReadFile(s, buf, 3, &n, 0) && GetLastError() == ERROR_MORE_DATA && n == 3 && !memcmp(buf, "hel", 3),
          "a short message-mode read: ERROR_MORE_DATA with the first 3 bytes");
    CHECK(ReadFile(s, buf, 32, &n, 0) && n == 2 && !memcmp(buf, "lo", 2), "the rest of that message");
    CHECK(ReadFile(s, buf, 32, &n, 0) && n == 6 && !memcmp(buf, "world!", 6), "the second message whole");
    CHECK(ReadFile(s, buf, 32, &n, 0) && n == 0, "the empty message");
    CHECK(!SetNamedPipeHandleState(c, &mode, &n, 0) && GetLastError() == ERROR_INVALID_PARAMETER,
          "SetNamedPipeHandleState refuses collection settings on a local pipe");
    CHECK(SetNamedPipeHandleState(c, &mode, 0, 0), "the client switches to message read mode");
    CHECK(WriteFile(s, "abc", 3, &n, 0) && WriteFile(s, "de", 2, &n, 0), "two replies");
    CHECK(ReadFile(c, buf, 32, &n, 0) && n == 3 && ReadFile(c, buf, 32, &n, 0) && n == 2, "the client reads them as messages");
    CloseHandle(c);
    CloseHandle(s);
    /* transactions */
    pipe_name("txn");
    g_srv_msg = CreateNamedPipeW(g_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 256, 256, 0, 0);
    t = CreateThread(0, 0, echo_server, 0, 0, 0);
    c = client(GENERIC_READ | GENERIC_WRITE, 0);
    CHECK(c != INVALID_HANDLE_VALUE && SetNamedPipeHandleState(c, &mode, 0, 0), "a transaction client");
    CHECK(TransactNamedPipe(c, "ping", 4, buf, sizeof buf, &n, 0) && n == 7 && !memcmp(buf, "re:ping", 7), "TransactNamedPipe");
    CHECK(!TransactNamedPipe(c, "longer", 6, buf, 4, &n, 0) && GetLastError() == ERROR_MORE_DATA && n == 4, "a short reply buffer: ERROR_MORE_DATA");
    CHECK(ReadFile(c, buf, sizeof buf, &n, 0) && n == 5 && !memcmp(buf, "onger", 5), "the rest of the reply");
    CloseHandle(c);
    WaitForSingleObject(t, 5000);
    CloseHandle(t);
    DisconnectNamedPipe(g_srv_msg);
    t = CreateThread(0, 0, echo_server, 0, 0, 0);
    CHECK(CallNamedPipeW(g_name, "call", 4, buf, sizeof buf, &n, 5000) && n == 7 && !memcmp(buf, "re:call", 7), "CallNamedPipe");
    WaitForSingleObject(t, 5000);
    CloseHandle(t);
    CloseHandle(g_srv_msg);
}

static void test_overlapped(void)
{
    HANDLE s, c, ev, port, t;
    OVERLAPPED ov, ov2, *got;
    char buf[64];
    DWORD n;
    ULONG_PTR key;
    pipe_name("ovl");
    s = CreateNamedPipeW(g_name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE, 4, 4096, 4096, 0, 0);
    ev = CreateEventW(0, TRUE, FALSE, 0);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = ev;
    CHECK(!ConnectNamedPipe(s, &ov) && GetLastError() == ERROR_IO_PENDING, "an overlapped ConnectNamedPipe is pending");
    CHECK(!GetOverlappedResult(s, &ov, &n, FALSE) && GetLastError() == ERROR_IO_INCOMPLETE, "GetOverlappedResult(no wait): ERROR_IO_INCOMPLETE");
    c = client(GENERIC_READ | GENERIC_WRITE, FILE_FLAG_OVERLAPPED);
    CHECK(c != INVALID_HANDLE_VALUE && WaitForSingleObject(ev, 2000) == WAIT_OBJECT_0 && GetOverlappedResult(s, &ov, &n, FALSE),
          "a client completes it and sets the event");
    /* overlapped read with an event */
    ResetEvent(ev);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = ev;
    CHECK(!ReadFile(s, buf, sizeof buf, &n, &ov) && GetLastError() == ERROR_IO_PENDING && !HasOverlappedIoCompleted(&ov),
          "an overlapped read with no data pends");
    {
        OVERLAPPED wo;
        memset(&wo, 0, sizeof wo);
        wo.hEvent = CreateEventW(0, TRUE, FALSE, 0);
        CHECK(WriteFile(c, "overlapped!", 11, &n, &wo) || GetLastError() == ERROR_IO_PENDING, "an overlapped write from the client");
        CHECK(GetOverlappedResult(c, &wo, &n, TRUE) && n == 11, "the write completes (11)");
        CloseHandle(wo.hEvent);
    }
    CHECK(GetOverlappedResult(s, &ov, &n, TRUE) && n == 11 && !memcmp(buf, "overlapped!", 11) && ov.Internal == 0 && ov.InternalHigh == 11,
          "the pending read completed with the data (Internal/InternalHigh)");
    /* CancelIoEx */
    memset(&ov, 0, sizeof ov);
    ov.hEvent = ev;
    ReadFile(s, buf, sizeof buf, &n, &ov);
    CHECK(CancelIoEx(s, &ov), "CancelIoEx of a pending read");
    CHECK(!GetOverlappedResult(s, &ov, &n, TRUE) && GetLastError() == ERROR_OPERATION_ABORTED, "it completes with ERROR_OPERATION_ABORTED");
    CHECK(!CancelIoEx(s, &ov) && GetLastError() == ERROR_NOT_FOUND, "cancelling it again: ERROR_NOT_FOUND");
    /* completion port */
    port = CreateIoCompletionPort(s, 0, 7, 0);
    CHECK(port != 0, "CreateIoCompletionPort binds the server end (key 7)");
    memset(&ov, 0, sizeof ov);
    CHECK(!ReadFile(s, buf, sizeof buf, &n, &ov) && GetLastError() == ERROR_IO_PENDING, "a pending read on the port-bound handle");
    CHECK(!GetQueuedCompletionStatus(port, &n, &key, &got, 0) && GetLastError() == WAIT_TIMEOUT && !got, "nothing queued yet (WAIT_TIMEOUT)");
    CHECK(WriteFile(c, "packet", 6, &n, 0) && n == 6, "a synchronous write on an overlapped handle");
    CHECK(GetQueuedCompletionStatus(port, &n, &key, &got, 2000) && got == &ov && key == 7 && n == 6 && !memcmp(buf, "packet", 6),
          "the completion packet carries the key, the OVERLAPPED and the byte count");
    CHECK(PostQueuedCompletionStatus(port, 42, 9, (LPOVERLAPPED)0x1234), "PostQueuedCompletionStatus");
    CHECK(GetQueuedCompletionStatus(port, &n, &key, &got, 0) && n == 42 && key == 9 && got == (LPOVERLAPPED)0x1234, "a posted packet");
    {
        OVERLAPPED_ENTRY e[4];
        ULONG removed = 0;
        PostQueuedCompletionStatus(port, 1, 1, 0);
        PostQueuedCompletionStatus(port, 2, 2, 0);
        PostQueuedCompletionStatus(port, 3, 3, 0);
        CHECK(GetQueuedCompletionStatusEx(port, e, 4, &removed, 0, FALSE) && removed == 3 && e[0].lpCompletionKey == 1 &&
              e[2].dwNumberOfBytesTransferred == 3, "GetQueuedCompletionStatusEx takes three packets in order");
    }
    /* success without a packet */
    CHECK(SetFileCompletionNotificationModes(s, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS), "FILE_SKIP_COMPLETION_PORT_ON_SUCCESS");
    memset(&ov2, 0, sizeof ov2);
    ov2.hEvent = CreateEventW(0, TRUE, FALSE, 0);
    CHECK(WriteFile(c, "now", 3, &n, &ov2) || GetOverlappedResult(c, &ov2, &n, TRUE), "three more bytes");
    CloseHandle(ov2.hEvent);
    Sleep(20);
    memset(&ov, 0, sizeof ov);
    CHECK(ReadFile(s, buf, sizeof buf, &n, &ov) && n == 3, "a read that succeeds at once returns TRUE");
    CHECK(!GetQueuedCompletionStatus(port, &n, &key, &got, 50) && GetLastError() == WAIT_TIMEOUT, "and queues no packet");
    /* ReadFileEx */
    g_routine_calls = 0;
    memset(&ov, 0, sizeof ov);
    CHECK(ReadFileEx(c, buf, sizeof buf, &ov, on_read), "ReadFileEx on the client");
    {
        OVERLAPPED wo;
        memset(&wo, 0, sizeof wo);
        wo.hEvent = CreateEventW(0, TRUE, FALSE, 0);
        CHECK(WriteFile(s, "routine", 7, &n, &wo) || GetOverlappedResult(s, &wo, &n, TRUE), "the server answers");
        CloseHandle(wo.hEvent);
    }
    Sleep(20);
    CHECK(g_routine_calls == 0, "its routine waits for an alertable wait");
    CHECK(SleepEx(2000, TRUE) == WAIT_IO_COMPLETION && g_routine_calls == 1 && g_routine_err == 0 && g_routine_bytes == 7,
          "SleepEx(alertable) runs the completion routine (7 bytes)");
    /* the port's last handle: waiters return ERROR_ABANDONED_WAIT_0 */
    CloseHandle(c);
    CloseHandle(s);
    {
        DWORD code = 0;
        g_p2 = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 1);
        t = CreateThread(0, 0, gqcs_waiter, 0, 0, 0);
        Sleep(50);
        CloseHandle(g_p2);
        CHECK(WaitForSingleObject(t, 3000) == WAIT_OBJECT_0 && GetExitCodeThread(t, &code) && code == ERROR_ABANDONED_WAIT_0,
              "closing a port wakes its waiter with ERROR_ABANDONED_WAIT_0 (%u)", (unsigned)code);
        CloseHandle(t);
    }
    CloseHandle(port);
    CloseHandle(ev);
}

static void test_flow_control(void)
{
    HANDLE s, c, t;
    DWORD n, code = 0, i, off = 0;
    unsigned long long sum = 0;
    pipe_name("flow");
    s = CreateNamedPipeW(g_name, PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE, 1, 4096, 4096, 0, 0);
    c = client(GENERIC_WRITE, 0);
    CHECK(s != INVALID_HANDLE_VALUE && c != INVALID_HANDLE_VALUE, "an inbound pipe with a 4 KiB quota");
    CHECK(client(GENERIC_READ, 0) == INVALID_HANDLE_VALUE, "an inbound pipe refuses readers on the client side");
    g_big = malloc(BIG);
    for (i = 0; i < BIG; ++i) { g_big[i] = (unsigned char)(i * 7 + (i >> 9)); sum = sum * 31 + g_big[i]; }
    t = CreateThread(0, 0, slow_reader, s, 0, 0);
    while (off < BIG) {
        DWORD chunk = BIG - off < 5000 ? BIG - off : 5000;
        if (!WriteFile(c, g_big + off, chunk, &n, 0) || n != chunk) break;
        off += chunk;
    }
    CHECK(off == BIG, "64 KiB written in 5000-byte writes that wait for the reader");
    CHECK(WaitForSingleObject(t, 10000) == WAIT_OBJECT_0 && GetExitCodeThread(t, &code) && code == (DWORD)(sum ^ (sum >> 32)),
          "the reader got every byte in order");
    CloseHandle(t);
    CloseHandle(c);
    CloseHandle(s);
    free(g_big);
}

static void test_processes(void)
{
    HANDLE s, ch, rd, wr;
    char args[128], buf[64];
    DWORD n, code;
    PROCESS_INFORMATION pi;
    pipe_name("xproc");
    s = CreateNamedPipeW(g_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 1, 4096, 4096, 0, 0);
    {
        char a[80];
        int i;
        for (i = 0; g_name[i]; ++i) a[i] = (char)g_name[i];
        a[i] = 0;
        snprintf(args, sizeof args, "client %s %u", a, (unsigned)GetCurrentProcessId());
    }
    ch = ipc_spawn_self(args, 0, FALSE, 0, &pi);
    CHECK(ch && (ConnectNamedPipe(s, 0) || GetLastError() == ERROR_PIPE_CONNECTED), "a client in another process");
    {
        ULONG pid = 0;
        CHECK(GetNamedPipeClientProcessId(s, &pid) && pid == pi.dwProcessId, "GetNamedPipeClientProcessId is the child's id");
    }
    CHECK(ReadFile(s, buf, sizeof buf, &n, 0) && n == 10 && !memcmp(buf, "from child", 10), "data from the child");
    CHECK(WriteFile(s, "reply", 5, &n, 0), "a reply to the child");
    code = ch ? ipc_wait_exit(ch, 10000) : 99;
    CHECK(code == 0, "the child saw the server's process id and the reply (exit %u)", (unsigned)code);
    if (ch) { CloseHandle(ch); CloseHandle(pi.hThread); }
    CloseHandle(s);
    /* anonymous pipe as a child's standard output */
    {
        SECURITY_ATTRIBUTES sa = { sizeof sa, 0, TRUE };
        STARTUPINFOW si;
        CHECK(CreatePipe(&rd, &wr, &sa, 0), "CreatePipe with inheritable ends");
        SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);    /* the child gets only the write end */
        memset(&si, 0, sizeof si);
        si.cb = sizeof si;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = wr;
        si.hStdError = wr;
        ch = ipc_spawn_self("stdout", 0, TRUE, &si, &pi);
        CHECK(ch != 0, "a child with STARTF_USESTDHANDLES");
        CloseHandle(wr);                                    /* so the read end breaks when the child exits */
        {
            DWORD total = 0;
            while (total < sizeof buf && ReadFile(rd, buf + total, sizeof buf - total, &n, 0) && n) total += n;
            CHECK(total == 13 && !memcmp(buf, "child says hi", 13) && GetLastError() == ERROR_BROKEN_PIPE,
                  "the parent read the child's stdout until the pipe broke (%u bytes)", (unsigned)total);
        }
        code = ch ? ipc_wait_exit(ch, 10000) : 99;
        CHECK(code == 0, "the child found a pipe on its standard output (exit %u)", (unsigned)code);
        if (ch) { CloseHandle(ch); CloseHandle(pi.hThread); }
        CloseHandle(rd);
    }
}

static void test_job_port(void)
{
    HANDLE job = CreateJobObjectW(0, 0), port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 1), ch;
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT assoc;
    PROCESS_INFORMATION pi;
    DWORD msg, seen = 0;
    ULONG_PTR key;
    LPOVERLAPPED ov;
    assoc.CompletionKey = (PVOID)0x55;
    assoc.CompletionPort = port;
    CHECK(SetInformationJobObject(job, JobObjectAssociateCompletionPortInformation, &assoc, sizeof assoc), "a job reporting to a port");
    ch = ipc_spawn_self("quick", CREATE_SUSPENDED, FALSE, 0, &pi);
    CHECK(ch && AssignProcessToJobObject(job, ch), "a child in that job");
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    while (GetQueuedCompletionStatus(port, &msg, &key, &ov, 5000)) {
        if (key != 0x55) break;
        if (msg == JOB_OBJECT_MSG_NEW_PROCESS && (DWORD)(ULONG_PTR)ov == pi.dwProcessId) seen |= 1;
        if (msg == JOB_OBJECT_MSG_EXIT_PROCESS && (DWORD)(ULONG_PTR)ov == pi.dwProcessId) seen |= 2;
        if (msg == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO) { seen |= 4; break; }
    }
    CHECK(seen == 7, "NEW_PROCESS, EXIT_PROCESS and ACTIVE_PROCESS_ZERO arrived (%u)", (unsigned)seen);
    if (ch) CloseHandle(ch);
    CloseHandle(job);
    CloseHandle(port);
}

static void test_ioctl(void)
{
    HANDLE f = CreateFileW(L"C:\\TEMP\\ipcioctl.bin", GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    DWORD n;
    char out[16];
    USHORT comp = 7;
    CHECK(f != INVALID_HANDLE_VALUE && GetFileType(f) == FILE_TYPE_DISK, "a disk file");
    CHECK(!DeviceIoControl(f, FSCTL_GET_REPARSE_POINT, 0, 0, out, sizeof out, &n, 0) && GetLastError() == ERROR_NOT_A_REPARSE_POINT,
          "FSCTL_GET_REPARSE_POINT: ERROR_NOT_A_REPARSE_POINT");
    CHECK(DeviceIoControl(f, FSCTL_GET_COMPRESSION, 0, 0, &comp, sizeof comp, &n, 0) && comp == COMPRESSION_FORMAT_NONE && n == 2,
          "FSCTL_GET_COMPRESSION: none");
    CHECK(!DeviceIoControl(f, IOCTL_DISK_GET_DRIVE_GEOMETRY, 0, 0, out, sizeof out, &n, 0) && GetLastError() == ERROR_INVALID_FUNCTION,
          "a disk IOCTL on a file: ERROR_INVALID_FUNCTION");
    CloseHandle(f);
    DeleteFileW(L"C:\\TEMP\\ipcioctl.bin");
}

int main(int argc, char **argv)
{
    kstats_t k0, k1;
    if (argc >= 4 && !strcmp(argv[1], "client")) return child_client(argv);
    if (argc >= 2 && !strcmp(argv[1], "stdout")) return child_stdout();
    if (argc >= 2 && !strcmp(argv[1], "quick")) return 0;
    CreateDirectoryW(L"C:\\TEMP", 0);
    kstats(&k0);
    test_basics();
    test_messages();
    test_overlapped();
    test_flow_control();
    test_processes();
    test_job_port();
    test_ioctl();
    Sleep(50);
    kstats(&k1);
    CHECK(k1.pipes == k0.pipes && k1.irps == k0.irps && k1.packets == k0.packets,
          "no pipe end, IRP or completion packet leaked (%llu/%llu/%llu -> %llu/%llu/%llu)", k0.pipes, k0.irps, k0.packets,
          k1.pipes, k1.irps, k1.packets);
    printf("%s: %d check(s) failed\n", g_bad ? "FAIL" : "PASS", g_bad);
    return g_bad;
}
