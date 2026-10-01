/* SPDX-License-Identifier: GPL-2.0-only
 * Native Windows 98 SE TCP prerequisite diagnostic. No remote connection,
 * socket emulation, Steam payload, provider replacement or account operation.
 */
#include <winsock.h>
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define PROBE_PATH "C:\\GOPLAB\\SPROB.EXE"
#define LOG_PATH "C:\\GOPLAB\\SPROB.LOG"
#define IO_DEADLINE_MS 30000UL

static DWORD began;
static BOOL log_ok = TRUE;

/* Each checkpoint closes its handle so a stopped FAT guest has durable length
 * metadata. CREATE_NEW also refuses the previous trial's unchanged log. */
static BOOL checkpoint(BOOL first, const char *format, ...)
{
    char text[1024];
    va_list args;
    HANDLE file;
    DWORD count;
    int length;
    BOOL ok;
    va_start(args, format);
    length = vsnprintf(text, sizeof(text), format, args);
    va_end(args);
    if (!log_ok || length <= 0 || (size_t)length >= sizeof(text)) {
        log_ok = FALSE;
        return FALSE;
    }
    file = CreateFileA(LOG_PATH, GENERIC_WRITE, FILE_SHARE_READ, NULL,
        first ? CREATE_NEW : OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        log_ok = FALSE;
        return FALSE;
    }
    SetLastError(NO_ERROR);
    ok = first || SetFilePointer(file, 0, NULL, FILE_END) != INVALID_SET_FILE_POINTER ||
        GetLastError() == NO_ERROR;
    ok = ok && WriteFile(file, text, (DWORD)length, &count, NULL) &&
        count == (DWORD)length && FlushFileBuffers(file);
    if (!CloseHandle(file))
        ok = FALSE;
    log_ok = ok;
    return ok;
}

static BOOL check(const char *name, BOOL ok, int actual_error)
{
    return checkpoint(FALSE, "check.%s=%u\r\nerror.%s=%d\r\n",
        name, !!ok, name, actual_error) && ok;
}

/* Reading the error in a separate call avoids C's unspecified evaluation order
 * between the actual socket operation and WSAGetLastError arguments. */
static BOOL check_api(const char *name, BOOL ok)
{
    return check(name, ok, ok ? 0 : WSAGetLastError());
}

/* All readiness retries share one wrap-safe native clock deadline. select's
 * nfds is ignored by Winsock; timeout values and fd_sets are rebuilt each call.
 */
static int ready(SOCKET sock, BOOL write_side)
{
    fd_set wanted, errors;
    struct timeval timeout;
    DWORD elapsed = GetTickCount() - began;
    DWORD remaining;
    int result;
    if (elapsed >= IO_DEADLINE_MS) {
        WSASetLastError(WSAETIMEDOUT);
        return SOCKET_ERROR;
    }
    remaining = IO_DEADLINE_MS - elapsed;
    timeout.tv_sec = (long)(remaining / 1000);
    timeout.tv_usec = (long)(remaining % 1000) * 1000;
    FD_ZERO(&wanted);
    FD_ZERO(&errors);
    FD_SET(sock, &wanted);
    FD_SET(sock, &errors);
    result = select(0, write_side ? NULL : &wanted,
        write_side ? &wanted : NULL, &errors, &timeout);
    if (result == SOCKET_ERROR)
        return SOCKET_ERROR;
    if (!result) {
        WSASetLastError(WSAETIMEDOUT);
        return SOCKET_ERROR;
    }
    if (FD_ISSET(sock, &errors)) {
        int error = 0;
        int length = sizeof(error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&error, &length) == 0 && error)
            WSASetLastError(error);
        else
            WSASetLastError(WSAECONNABORTED);
        return SOCKET_ERROR;
    }
    if (!FD_ISSET(sock, &wanted)) {
        WSASetLastError(WSAECONNABORTED);
        return SOCKET_ERROR;
    }
    return 1;
}

static BOOL transfer(SOCKET sock, char *bytes, int length, BOOL sending)
{
    int offset = 0;
    while (offset < length) {
        int done;
        if (GetTickCount() - began >= IO_DEADLINE_MS) {
            WSASetLastError(WSAETIMEDOUT);
            return FALSE;
        }
        done = sending ? send(sock, bytes + offset, length - offset, 0) :
            recv(sock, bytes + offset, length - offset, 0);
        if (done > 0) {
            offset += done;
            continue;
        }
        if (done == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
            if (ready(sock, sending) == 1)
                continue;
            return FALSE;
        }
        if (!done)
            WSASetLastError(sending ? WSAECONNABORTED : WSAECONNRESET);
        return FALSE;
    }
    return TRUE;
}

static BOOL close_owned(SOCKET *sock)
{
    int result;
    if (*sock == INVALID_SOCKET)
        return TRUE;
    result = closesocket(*sock);
    if (result == 0)
        *sock = INVALID_SOCKET;
    return result == 0;
}

int main(int argc, char **argv)
{
    char module[MAX_PATH], payload[128], received[128], byte;
    OSVERSIONINFOA version;
    WSADATA data;
    struct sockaddr_in listener_address, client_address, peer_address, accepted_address;
    SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET, accepted = INVALID_SOCKET;
    SOCKET closed_client;
    DWORD module_length;
    u_long nonblocking = 1;
    BOOL started = FALSE, passed = FALSE, clean = TRUE;
    int result, error, length, payload_length;
    fd_set reads;
    struct timeval zero;

    if (argc != 2 || strlen(argv[1]) < 16 || strlen(argv[1]) > 80 ||
        strspn(argv[1], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != strlen(argv[1]))
        return 10;
    module_length = GetModuleFileNameA(NULL, module, sizeof(module));
    if (!module_length || module_length >= sizeof(module) || lstrcmpiA(module, PROBE_PATH))
        return 11;
    if (!checkpoint(TRUE, "scope=steam-native-win98-loopback-prerequisite\r\nnonce=%s\r\n"
        "source.version=1\r\nsteam.application-executed=0\r\n", argv[1]))
        return 2;
    memset(&version, 0, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    result = GetVersionExA(&version);
    if (!checkpoint(FALSE, "os.platform=%lu\r\nos.major=%lu\r\nos.minor=%lu\r\n"
        "os.build-low=%lu\r\n", version.dwPlatformId, version.dwMajorVersion,
        version.dwMinorVersion, (DWORD)LOWORD(version.dwBuildNumber)))
        return 2;
    if (!check("exact-target", result && version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS &&
        version.dwMajorVersion == 4 && version.dwMinorVersion == 10 &&
        LOWORD(version.dwBuildNumber) == 2222, result ? 0 : (int)GetLastError()))
        goto cleanup;
    result = WSAStartup(MAKEWORD(1, 1), &data);
    started = result == 0;
    if (!check("startup", started, result))
        goto cleanup;
    if (!checkpoint(FALSE, "winsock.version=%u\r\nwinsock.high-version=%u\r\n",
        (unsigned)data.wVersion, (unsigned)data.wHighVersion) ||
        !check("version-1-1", data.wVersion == MAKEWORD(1, 1), 0))
        goto cleanup;
    began = GetTickCount();
    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!check("listener-created", listener != INVALID_SOCKET,
        listener == INVALID_SOCKET ? WSAGetLastError() : 0))
        goto cleanup;
    if (!check_api("listener-nonblocking", ioctlsocket(listener, FIONBIO, &nonblocking) == 0))
        goto cleanup;
    memset(&listener_address, 0, sizeof(listener_address));
    listener_address.sin_family = AF_INET;
    listener_address.sin_addr.s_addr = htonl(0x7f000001UL);
    listener_address.sin_port = 0;
    result = bind(listener, (struct sockaddr *)&listener_address, sizeof(listener_address));
    if (!check("bind-loopback", result == 0, result ? WSAGetLastError() : 0))
        goto cleanup;
    length = sizeof(listener_address);
    result = getsockname(listener, (struct sockaddr *)&listener_address, &length);
    if (!check("listener-address", result == 0 && length == sizeof(listener_address) &&
        listener_address.sin_family == AF_INET &&
        listener_address.sin_addr.s_addr == htonl(0x7f000001UL) &&
        listener_address.sin_port != 0, result ? WSAGetLastError() : 0) ||
        !checkpoint(FALSE, "loopback.server-port=%u\r\n", ntohs(listener_address.sin_port)))
        goto cleanup;
    result = listen(listener, 1);
    if (!check("listen", result == 0, result ? WSAGetLastError() : 0))
        goto cleanup;
    accepted = accept(listener, NULL, NULL);
    error = accepted == INVALID_SOCKET ? WSAGetLastError() : 0;
    if (!check("accept-empty-wouldblock", accepted == INVALID_SOCKET && error == WSAEWOULDBLOCK, error))
        goto cleanup;
    FD_ZERO(&reads);
    FD_SET(listener, &reads);
    zero.tv_sec = zero.tv_usec = 0;
    result = select(0, &reads, NULL, NULL, &zero);
    if (!check("empty-select-timeout", result == 0 && !FD_ISSET(listener, &reads),
        result == SOCKET_ERROR ? WSAGetLastError() : 0))
        goto cleanup;
    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!check("client-created", client != INVALID_SOCKET,
        client == INVALID_SOCKET ? WSAGetLastError() : 0))
        goto cleanup;
    result = ioctlsocket(client, FIONBIO, &nonblocking);
    if (!check("client-nonblocking", result == 0, result ? WSAGetLastError() : 0))
        goto cleanup;
    result = connect(client, (struct sockaddr *)&listener_address, sizeof(listener_address));
    error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (!checkpoint(FALSE, "connect.result=%d\r\nconnect.error=%d\r\n", result, error) ||
        !check("connect-started", result == 0 ||
            (result == SOCKET_ERROR && error == WSAEWOULDBLOCK), error))
        goto cleanup;
    result = ready(client, TRUE);
    if (!check("connect-write-ready", result == 1, result == 1 ? 0 : WSAGetLastError()))
        goto cleanup;
    error = -1;
    length = sizeof(error);
    result = getsockopt(client, SOL_SOCKET, SO_ERROR, (char *)&error, &length);
    if (!check("connect-so-error-zero", result == 0 && length == sizeof(error) && error == 0,
        result ? WSAGetLastError() : error))
        goto cleanup;
    result = ready(listener, FALSE);
    if (!check("listener-read-ready", result == 1, result == 1 ? 0 : WSAGetLastError()))
        goto cleanup;
    length = sizeof(peer_address);
    accepted = accept(listener, (struct sockaddr *)&peer_address, &length);
    if (!check("accept-completed", accepted != INVALID_SOCKET && length == sizeof(peer_address),
        accepted == INVALID_SOCKET ? WSAGetLastError() : 0))
        goto cleanup;
    result = ioctlsocket(accepted, FIONBIO, &nonblocking);
    if (!check("accepted-nonblocking", result == 0, result ? WSAGetLastError() : 0))
        goto cleanup;
    length = sizeof(client_address);
    result = getsockname(client, (struct sockaddr *)&client_address, &length);
    if (!check("accepted-peer-owned", result == 0 && length == sizeof(client_address) &&
        client_address.sin_family == AF_INET && peer_address.sin_family == AF_INET &&
        client_address.sin_addr.s_addr == htonl(0x7f000001UL) &&
        peer_address.sin_addr.s_addr == client_address.sin_addr.s_addr &&
        peer_address.sin_port == client_address.sin_port && client_address.sin_port != 0,
        result ? WSAGetLastError() : 0))
        goto cleanup;
    length = sizeof(accepted_address);
    result = getpeername(client, (struct sockaddr *)&accepted_address, &length);
    if (!check("client-peer-owned", result == 0 && length == sizeof(accepted_address) &&
        accepted_address.sin_family == AF_INET &&
        accepted_address.sin_addr.s_addr == listener_address.sin_addr.s_addr &&
        accepted_address.sin_port == listener_address.sin_port, result ? WSAGetLastError() : 0))
        goto cleanup;
    if (!check_api("listener-close", close_owned(&listener)))
        goto cleanup;
    result = recv(accepted, &byte, 1, 0);
    error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (!check("recv-empty-wouldblock", result == SOCKET_ERROR && error == WSAEWOULDBLOCK, error))
        goto cleanup;
    FD_ZERO(&reads);
    FD_SET(accepted, &reads);
    zero.tv_sec = zero.tv_usec = 0;
    result = select(0, &reads, NULL, NULL, &zero);
    if (!check("accepted-empty-select-timeout", result == 0 && !FD_ISSET(accepted, &reads),
        result == SOCKET_ERROR ? WSAGetLastError() : 0))
        goto cleanup;
    payload_length = snprintf(payload, sizeof(payload), "SPROB:%s:", argv[1]);
    if (payload_length <= 0 || payload_length + 4 > (int)sizeof(payload))
        goto cleanup;
    payload[payload_length++] = 0;
    payload[payload_length++] = (char)0xff;
    payload[payload_length++] = (char)0x7f;
    payload[payload_length++] = 'Z';
    if (!check_api("send-client", transfer(client, payload, payload_length, TRUE)) ||
        !check_api("recv-server", transfer(accepted, received, payload_length, FALSE)) ||
        !check("client-payload-equal", memcmp(payload, received, (size_t)payload_length) == 0, 0) ||
        !check_api("send-server", transfer(accepted, received, payload_length, TRUE)) ||
        !check_api("recv-client", transfer(client, received, payload_length, FALSE)) ||
        !check("server-payload-equal", memcmp(payload, received, (size_t)payload_length) == 0, 0) ||
        !checkpoint(FALSE, "roundtrip.bytes-each-direction=%d\r\n", payload_length))
        goto cleanup;
    result = shutdown(client, 1); /* SD_SEND; retain the client's receive half. */
    if (!check("client-send-shutdown", result == 0, result ? WSAGetLastError() : 0))
        goto cleanup;
    result = send(client, "!", 1, 0);
    error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (!check("send-after-shutdown-error", result == SOCKET_ERROR && error == WSAESHUTDOWN, error))
        goto cleanup;
    result = ready(accepted, FALSE);
    if (!check("server-eof-ready", result == 1, result == 1 ? 0 : WSAGetLastError()))
        goto cleanup;
    result = recv(accepted, &byte, 1, 0);
    if (!check("server-eof-zero", result == 0, result == SOCKET_ERROR ? WSAGetLastError() : 0))
        goto cleanup;
    byte = 'H';
    if (!check_api("halfclose-server-send", transfer(accepted, &byte, 1, TRUE)) ||
        !check_api("halfclose-client-recv", transfer(client, &byte, 1, FALSE)) ||
        !check("halfclose-byte-equal", byte == 'H', 0))
        goto cleanup;
    result = shutdown(accepted, 1);
    if (!check("server-send-shutdown", result == 0, result ? WSAGetLastError() : 0))
        goto cleanup;
    result = ready(client, FALSE);
    if (!check("client-eof-ready", result == 1, result == 1 ? 0 : WSAGetLastError()))
        goto cleanup;
    result = recv(client, &byte, 1, 0);
    if (!check("client-eof-zero", result == 0, result == SOCKET_ERROR ? WSAGetLastError() : 0))
        goto cleanup;
    closed_client = client;
    if (!check_api("client-close", close_owned(&client)) ||
        !check_api("accepted-close", close_owned(&accepted)))
        goto cleanup;
    result = recv(closed_client, &byte, 1, 0);
    error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (!check("closed-socket-error", result == SOCKET_ERROR && error == WSAENOTSOCK, error))
        goto cleanup;
    result = WSACleanup();
    if (!result)
        started = FALSE;
    if (!check("winsock-cleanup", result == 0, result ? WSAGetLastError() : 0))
        goto cleanup;
    result = WSACleanup();
    error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (!check("unmatched-cleanup-error", result == SOCKET_ERROR && error == WSANOTINITIALISED, error))
        goto cleanup;
    passed = TRUE;

cleanup:
    /* Only this invocation's resources are released, including every error path. */
    if (!close_owned(&listener))
        clean = FALSE;
    if (!close_owned(&client))
        clean = FALSE;
    if (!close_owned(&accepted))
        clean = FALSE;
    if (started && WSACleanup() != 0)
        clean = FALSE;
    if (!checkpoint(FALSE, "resources.cleaned=%u\r\nprerequisite.checks-completed=%u\r\n"
        "steam.application-passed=0\r\nexit=%u\r\n", !!clean, !!passed,
        passed && clean ? 0 : 5))
        return 2;
    return passed && clean ? 0 : 5;
}
