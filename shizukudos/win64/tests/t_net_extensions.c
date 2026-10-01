/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine loopback TCP extension contracts, cancellation and IOCP ownership.
 * No wire/DNS/Steam functionality claim. All waits are bounded.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mswsock.h>
#include "nettest.h"

static LPFN_CONNECTEX connect_ex;
static LPFN_DISCONNECTEX disconnect_ex;
static const GUID connect_guid = WSAID_CONNECTEX, disconnect_guid = WSAID_DISCONNECTEX;
static const ULONG loopback = 0x0100007fu;
static OVERLAPPED worker_overlapped;
static SOCKET worker_socket;
static char *large_data;
static struct sockaddr_in worker_address;
static volatile LONG worker_pending;

static SOCKET listener(struct sockaddr_in *address)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int n = sizeof *address;
    memset(address, 0, sizeof *address);
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = loopback;
    if (s == INVALID_SOCKET || bind(s, (struct sockaddr *)address, n) || listen(s, 8) ||
        getsockname(s, (struct sockaddr *)address, &n)) {
        if (s != INVALID_SOCKET) closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static SOCKET bound_client(void)
{
    struct sockaddr_in a;
    SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = loopback;
    if (s != INVALID_SOCKET && bind(s, (struct sockaddr *)&a, sizeof a)) {
        closesocket(s); return INVALID_SOCKET;
    }
    return s;
}

static int start(SOCKET s, const struct sockaddr_in *a, const void *data, DWORD n, OVERLAPPED *ov)
{
    BOOL result = connect_ex(s, (const struct sockaddr *)a, sizeof *a, (void *)data, n, NULL, ov);
    int error = WSAGetLastError();
    return result || error == WSA_IO_PENDING;
}

static void bound_peer_wait(SOCKET s)
{
    DWORD timeout = 5000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout);
}

static int packet(HANDLE port, OVERLAPPED *expected, ULONG_PTR expected_key, int expected_error, DWORD expected_size)
{
    OVERLAPPED *got = NULL;
    ULONG_PTR key = 0;
    DWORD size = 0;
    BOOL result = GetQueuedCompletionStatus(port, &size, &key, &got, 5000);
    DWORD error = GetLastError();
    return got == expected && key == expected_key && size == expected_size &&
        (expected_error ? !result && error == (DWORD)expected_error : result);
}

static DWORD WINAPI issue_then_exit(void *unused)
{
    (void)unused;
    worker_pending = start(worker_socket, &worker_address, large_data, 262144, &worker_overlapped);
    return 0;
}

int main(void)
{
    WSADATA wsa;
    struct sockaddr_in a, b, local_before, local_after;
    SOCKET l = INVALID_SOCKET, l2 = INVALID_SOCKET, c = INVALID_SOCKET, peer = INVALID_SOCKET, probe;
    HANDLE event = NULL, port = NULL, duplicate = NULL, worker;
    OVERLAPPED ov;
    DWORD returned = 0, size = 0, flags = 0;
    int n, error, valid;
    BOOL result;
    char received[32];
    const char payload[] = "real ConnectEx initial bytes";
    GUID unknown = {0};
    void *sentinel = (void *)(ULONG_PTR)0x12345678;
    CHECK(WSAStartup(MAKEWORD(2, 2), &wsa) == 0, "Winsock startup");
    l = listener(&a); l2 = listener(&b); c = bound_client();
    CHECK(l != INVALID_SOCKET && l2 != INVALID_SOCKET && c != INVALID_SOCKET, "two real loopback listeners and bound client");
    if (l == INVALID_SOCKET || l2 == INVALID_SOCKET || c == INVALID_SOCKET) goto cleanup;
    CHECK(!WSAIoctl(c, SIO_GET_EXTENSION_FUNCTION_POINTER, (void *)&connect_guid, sizeof connect_guid,
                   &connect_ex, sizeof connect_ex, &returned, NULL, NULL) && returned == sizeof connect_ex && connect_ex,
          "actual ConnectEx GUID resolves to native TCP implementation");
    CHECK(!WSAIoctl(c, SIO_GET_EXTENSION_FUNCTION_POINTER, (void *)&disconnect_guid, sizeof disconnect_guid,
                   &disconnect_ex, sizeof disconnect_ex, &returned, NULL, NULL) && disconnect_ex,
          "actual DisconnectEx GUID resolves");
    if (!connect_ex || !disconnect_ex) goto cleanup;
    result = WSAIoctl(c, SIO_GET_EXTENSION_FUNCTION_POINTER, &unknown, sizeof unknown, &sentinel, sizeof sentinel, &returned, NULL, NULL);
    error = WSAGetLastError();
    CHECK(result == SOCKET_ERROR && error == WSAEOPNOTSUPP && sentinel == (void *)(ULONG_PTR)0x12345678,
          "unsupported GUID fails without invented pointer");
    result = WSAIoctl(c, SIO_GET_EXTENSION_FUNCTION_POINTER, (void *)&connect_guid, 15, &sentinel, sizeof sentinel, &returned, NULL, NULL);
    error = WSAGetLastError();
    CHECK(result == SOCKET_ERROR && error == WSAEFAULT, "short GUID fails");
    memset(&ov, 0, sizeof ov);
    probe = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    result = connect_ex(probe, (struct sockaddr *)&a, sizeof a, NULL, 0, NULL, &ov); error = WSAGetLastError();
    CHECK(!result && error == WSAEINVAL, "ConnectEx requires actual bound socket");
    closesocket(probe);
    probe = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    { struct sockaddr_in local; DWORD attributes = 0;
      memset(&local, 0, sizeof local); local.sin_family = AF_INET;
      CHECK(probe != INVALID_SOCKET && !bind(probe, (struct sockaddr *)&local, sizeof local), "non-overlapped socket is genuinely bound");
      CHECK(GetHandleInformation((HANDLE)probe, &attributes) && (attributes & HANDLE_FLAG_INHERIT), "WSASocket default handle is inheritable"); }
    result = connect_ex(probe, (struct sockaddr *)&a, sizeof a, NULL, 0, NULL, &ov); error = WSAGetLastError();
    CHECK(!result && error == WSAEINVAL, "non-overlapped WSASocket rejects ConnectEx");
    { HANDLE invalid_port = CreateIoCompletionPort((HANDLE)probe, NULL, 1, 0);
      CHECK(!invalid_port, "non-overlapped socket cannot bind to IOCP");
      if (invalid_port) CloseHandle(invalid_port); }
    closesocket(probe);
    probe = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED | 0x80);
    { DWORD attributes = HANDLE_FLAG_INHERIT;
      CHECK(probe != INVALID_SOCKET && GetHandleInformation((HANDLE)probe, &attributes) && !(attributes & HANDLE_FLAG_INHERIT), "NO_HANDLE_INHERIT is honored"); }
    closesocket(probe);
    probe = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 2); error = WSAGetLastError();
    CHECK(probe == INVALID_SOCKET && error == WSAEOPNOTSUPP, "unsupported multipoint flags fail explicitly");
    result = connect_ex(c, (struct sockaddr *)&a, sizeof a, NULL, 0, NULL, NULL); error = WSAGetLastError();
    CHECK(!result && error == WSAEINVAL, "ConnectEx requires OVERLAPPED");
    result = disconnect_ex(c, NULL, 2, 1); error = WSAGetLastError();
    CHECK(!result && error == WSAEINVAL, "DisconnectEx rejects reserved argument");
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(event != NULL, "owned completion event");
    if (!event) goto cleanup;
    ov.hEvent = event;
    CHECK(start(c, &a, payload, sizeof payload, &ov), "actual handshake and initial data accepted");
    valid = WaitForSingleObject(event, 5000) == WAIT_OBJECT_0;
    CHECK(valid, "event completion after real TCP handshake and initial data");
    if (!valid) goto cleanup;
    valid = WSAGetOverlappedResult(c, &ov, &size, FALSE, &flags) && size == sizeof payload && !flags;
    CHECK(valid,
          "completed request reports all initial bytes");
    if (!valid) goto cleanup;
    peer = accept(l, NULL, NULL);
    CHECK(peer != INVALID_SOCKET, "server accepts actual established connection");
    if (peer == INVALID_SOCKET) goto cleanup;
    bound_peer_wait(peer);
    CHECK(recv(peer, received, sizeof payload, MSG_WAITALL) == sizeof payload && !memcmp(received, payload, sizeof payload),
          "peer receives exact initial payload through TCP");
    n = sizeof local_after;
    result = getpeername(c, (struct sockaddr *)&local_after, &n); error = WSAGetLastError();
    CHECK(result == SOCKET_ERROR && error == WSAEINVAL, "ConnectEx context remains unpublished before update");
    CHECK(!setsockopt(c, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0), "real SO_UPDATE_CONNECT_CONTEXT accepts documented NULL zero length");
    n = sizeof local_before;
    CHECK(!getsockname(c, (struct sockaddr *)&local_before, &n), "published local endpoint available");
    result = disconnect_ex(c, &ov, TF_REUSE_SOCKET, 0); error = WSAGetLastError();
    CHECK(result || error == WSA_IO_PENDING, "DisconnectEx closes actual transport and retains socket");
    CHECK(WaitForSingleObject(event, 5000) == WAIT_OBJECT_0 && WSAGetOverlappedResult(c, &ov, &size, FALSE, &flags) && !size,
          "disconnect has one real zero-byte completion");
    CHECK(recv(peer, received, 1, 0) == 0, "peer observes actual graceful FIN");
    closesocket(peer); peer = INVALID_SOCKET;
    n = sizeof local_after;
    CHECK(!getsockname(c, (struct sockaddr *)&local_after, &n) && local_after.sin_port == local_before.sin_port,
          "DisconnectEx reuse preserves real local binding");
    valid = start(c, &b, NULL, 0, &ov) && WaitForSingleObject(event, 5000) == WAIT_OBJECT_0 &&
          WSAGetOverlappedResult(c, &ov, &size, FALSE, &flags);
    CHECK(valid, "retained socket establishes a new actual tuple");
    if (!valid) goto cleanup;
    peer = accept(l2, NULL, NULL);
    CHECK(peer != INVALID_SOCKET, "second listener receives reused socket connection");
    closesocket(c); c = INVALID_SOCKET;
    if (peer != INVALID_SOCKET) { closesocket(peer); peer = INVALID_SOCKET; }

    port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    c = bound_client();
    CHECK(port && c != INVALID_SOCKET && CreateIoCompletionPort((HANDLE)c, port, 0xca11, 0) == port,
          "socket genuinely associates with IOCP");
    if (!port || c == INVALID_SOCKET) goto cleanup;
    memset(&ov, 0, sizeof ov);
    valid = start(c, &a, payload, sizeof payload, &ov) && packet(port, &ov, 0xca11, 0, sizeof payload);
    CHECK(valid,
          "eventless ConnectEx posts exact IOCP key context and byte count");
    if (!valid) goto cleanup;
    peer = accept(l, NULL, NULL);
    if (peer != INVALID_SOCKET) bound_peer_wait(peer);
    CHECK(peer != INVALID_SOCKET && recv(peer, received, sizeof payload, MSG_WAITALL) == sizeof payload,
          "IOCP completion corresponds to real peer data");
    ov.hEvent = (HANDLE)((ULONG_PTR)event | 1);
    result = disconnect_ex(c, &ov, TF_REUSE_SOCKET, 0); error = WSAGetLastError();
    CHECK((result || error == WSA_IO_PENDING) && WaitForSingleObject(event, 5000) == WAIT_OBJECT_0,
          "tagged event still signals actual disconnect completion");
    { OVERLAPPED *got = NULL; ULONG_PTR key; DWORD bytes;
      result = GetQueuedCompletionStatus(port, &bytes, &key, &got, 0); error = GetLastError();
      CHECK(!result && error == WAIT_TIMEOUT && !got, "event low bit suppresses IOCP packet"); }
    closesocket(c); c = INVALID_SOCKET;
    if (peer != INVALID_SOCKET) { closesocket(peer); peer = INVALID_SOCKET; }

    large_data = HeapAlloc(GetProcessHeap(), 0, 262144);
    CHECK(large_data != NULL, "bounded initial data for pending ownership and cancellation");
    if (!large_data) goto cleanup;
    memset(large_data, 0x5a, 262144);
    c = bound_client();
    CHECK(c != INVALID_SOCKET && CreateIoCompletionPort((HANDLE)c, port, 0xca12, 0) == port, "cancellation socket association");
    memset(&ov, 0, sizeof ov);
    CHECK(start(c, &a, large_data, 262144, &ov) && (LONG)ov.Internal == 0x103,
          "initial data exceeding transport window remains genuinely pending without peer reads");
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)c, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS),
          "duplicate owns the same pending socket");
    closesocket(c); c = INVALID_SOCKET;
    CHECK((LONG)ov.Internal == 0x103, "closing one duplicate preserves remaining handle and request");
    CHECK(CancelIoEx(duplicate, &ov), "CancelIoEx finds actual socket IRP");
    { OVERLAPPED *got = NULL; ULONG_PTR key; DWORD bytes;
      result = GetQueuedCompletionStatus(port, &bytes, &key, &got, 5000); error = GetLastError();
      CHECK(!result && error == ERROR_OPERATION_ABORTED && got == &ov && key == 0xca12 && bytes < 262144,
            "cancel posts one failing completion with actual partial progress"); }
    closesocket((SOCKET)duplicate); duplicate = NULL;
    c = bound_client();
    CHECK(c != INVALID_SOCKET && CreateIoCompletionPort((HANDLE)c, port, 0xca13, 0) == port, "last-close socket association");
    memset(&ov, 0, sizeof ov);
    CHECK(start(c, &a, large_data, 262144, &ov) && (LONG)ov.Internal == 0x103, "owned request pending before final close");
    closesocket(c); c = INVALID_SOCKET;
    { OVERLAPPED *got = NULL; ULONG_PTR key; DWORD bytes;
      result = GetQueuedCompletionStatus(port, &bytes, &key, &got, 5000); error = GetLastError();
      CHECK(!result && error == ERROR_OPERATION_ABORTED && got == &ov && key == 0xca13,
            "last handle close cancels actual IRP despite held object references"); }
    worker_socket = bound_client(); worker_address = a;
    CHECK(worker_socket != INVALID_SOCKET && CreateIoCompletionPort((HANDLE)worker_socket, port, 0xca14, 0) == port,
          "thread-exit request socket association");
    memset(&worker_overlapped, 0, sizeof worker_overlapped);
    worker = CreateThread(NULL, 0, issue_then_exit, NULL, 0, NULL);
    valid = worker && WaitForSingleObject(worker, 5000) == WAIT_OBJECT_0;
    CHECK(valid && worker_pending, "issuing thread returns after genuine pending request");
    if (worker && !valid) ExitProcess(1);                /* do not release a live thread's OVERLAPPED/data */
    if (worker) CloseHandle(worker);
    if (valid) {
        OVERLAPPED *got = NULL; ULONG_PTR key; DWORD bytes;
        result = GetQueuedCompletionStatus(port, &bytes, &key, &got, 5000); error = GetLastError();
        CHECK(!result && error == ERROR_OPERATION_ABORTED && got == &worker_overlapped && key == 0xca14,
              "Winsock thread exit cancels pending IOCP request");
        closesocket(worker_socket);
    }
cleanup:
    if (c != INVALID_SOCKET) closesocket(c);
    if (duplicate) closesocket((SOCKET)duplicate);
    if (peer != INVALID_SOCKET) closesocket(peer);
    if (l != INVALID_SOCKET) closesocket(l);
    if (l2 != INVALID_SOCKET) closesocket(l2);
    if (event) CloseHandle(event);
    if (port) CloseHandle(port);
    if (large_data) HeapFree(GetProcessHeap(), 0, large_data);
    WSACleanup();
    printf("T_NET_EXTENSIONS: %d failure(s)\n", g_bad);
    return g_bad ? 1 : 0;
}
