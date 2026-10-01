/* SPDX-License-Identifier: GPL-2.0-only
 * Real Winsock creation, ANSI protocol adaptation and shared socket ownership.
 * This verifies loopback socket objects, not Steam networking or login.
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <stddef.h>
#include "k32test.h"

typedef SOCKET (WSAAPI *create_a_fn)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
typedef int (WSAAPI *duplicate_w_fn)(SOCKET, DWORD, LPWSAPROTOCOL_INFOW);

static void protocol_to_ansi(WSAPROTOCOL_INFOA *a, const WSAPROTOCOL_INFOW *w)
{
    unsigned i;
    memset(a, 0, sizeof *a);
    memcpy(a, w, offsetof(WSAPROTOCOL_INFOA, szProtocol));
    for (i = 0; i < WSAPROTOCOL_LEN && w->szProtocol[i]; ++i) a->szProtocol[i] = (char)w->szProtocol[i];
}

int main(void)
{
    HMODULE module = LoadLibraryW(L"ws2_32.dll");
    create_a_fn create;
    duplicate_w_fn duplicate;
    WSADATA data;
    WSAPROTOCOL_INFOW wide;
    WSAPROTOCOL_INFOA ansi;
    SOCKET original = INVALID_SOCKET, shared = INVALID_SOCKET, tcp = INVALID_SOCKET;
    struct sockaddr_in local, first, second;
    DWORD handle_flags;
    int length, socket_type;
    CHECK(module != 0, "real ws2_32 loads");
    if (!module) return 1;
    create = (create_a_fn)GetProcAddress(module, "WSASocketA");
    duplicate = (duplicate_w_fn)GetProcAddress(module, "WSADuplicateSocketW");
    CHECK(create && duplicate, "ANSI creation and real duplication exports exist");
    if (!create || !duplicate) { FreeLibrary(module); return 1; }
    CHECK(create(AF_INET, SOCK_DGRAM, 0, 0, 0, 0) == INVALID_SOCKET && WSAGetLastError() == WSANOTINITIALISED,
          "creation without Winsock startup fails");
    CHECK(WSAStartup(MAKEWORD(2,2), &data) == 0, "real Winsock startup");
    CHECK(create(AF_INET, SOCK_DGRAM, 0, 0, 0, 0x80000000u) == INVALID_SOCKET && WSAGetLastError() == WSAEINVAL,
          "unknown flags are rejected before allocating a socket");
    CHECK(create(AF_INET, SOCK_DGRAM, 0, 0, 0, WSA_FLAG_MULTIPOINT_C_ROOT) == INVALID_SOCKET && WSAGetLastError() == WSAEOPNOTSUPP,
          "unimplemented multipoint mode fails explicitly");
    CHECK(create(AF_INET, SOCK_DGRAM, 0, 0, 777, 0) == INVALID_SOCKET && WSAGetLastError() == WSAEINVAL,
          "unsupported group cannot silently succeed");
    CHECK(create(FROM_PROTOCOL_INFO, SOCK_DGRAM, 0, 0, 0, 0) == INVALID_SOCKET && WSAGetLastError() == WSAEINVAL,
          "protocol selection requires a nonnull record");
    memset(&wide, 0, sizeof wide);
    memset(&ansi, 0, sizeof ansi);
    memset(&first, 0, sizeof first);
    memset(&second, 0, sizeof second);
    original = create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, 0, WSA_FLAG_NO_HANDLE_INHERIT);
    CHECK(original != INVALID_SOCKET, "ANSI creation returns an actual UDP socket");
    if (original == INVALID_SOCKET) goto done;
    CHECK(GetHandleInformation((HANDLE)original, &handle_flags) && !(handle_flags & HANDLE_FLAG_INHERIT),
          "NO_HANDLE_INHERIT changes actual handle metadata");
    memset(&local, 0, sizeof local);
    local.sin_family = AF_INET; local.sin_addr.s_addr = htonl(0x7f000001);
    CHECK(bind(original, (struct sockaddr *)&local, sizeof local) == 0, "real UDP socket binds a loopback endpoint");
    length = sizeof first;
    CHECK(getsockname(original, (struct sockaddr *)&first, &length) == 0 && first.sin_port != 0,
          "kernel assigns an actual local port");
    CHECK(duplicate(original, GetCurrentProcessId(), &wide) == 0 && wide.dwProviderReserved != 0,
          "duplicate record contains an owned kernel socket handle");
    protocol_to_ansi(&ansi, &wide);
    shared = create(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &ansi, 0, 0);
    CHECK(shared != INVALID_SOCKET && shared != original && ansi.dwProviderReserved == 0,
          "ANSI adaptation transfers the real duplicate token and reflects consumption");
    if (shared == INVALID_SOCKET && ansi.dwProviderReserved) {
        closesocket((SOCKET)ansi.dwProviderReserved);
        ansi.dwProviderReserved = 0;
    }
    if (shared != INVALID_SOCKET) {
        length = sizeof second;
        CHECK(getsockname(shared, (struct sockaddr *)&second, &length) == 0 &&
              second.sin_addr.s_addr == first.sin_addr.s_addr && second.sin_port == first.sin_port,
              "duplicated socket retains the same real bound endpoint");
        CHECK(GetHandleInformation((HANDLE)shared, &handle_flags) && (handle_flags & HANDLE_FLAG_INHERIT),
              "default creation sets actual inheritable handle metadata");
    }
    CHECK(closesocket(original) == 0, "original socket handle closes");
    original = INVALID_SOCKET;
    if (shared != INVALID_SOCKET) {
        length = sizeof second;
        CHECK(getsockname(shared, (struct sockaddr *)&second, &length) == 0 && second.sin_port == first.sin_port,
              "closing the original does not destroy the duplicated socket object");
        CHECK(closesocket(shared) == 0, "duplicate socket handle closes independently");
        shared = INVALID_SOCKET;
    }
    ansi.dwProviderReserved = 0;
    tcp = create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &ansi, 0, WSA_FLAG_OVERLAPPED);
    CHECK(tcp != INVALID_SOCKET, "explicit socket triple takes precedence over UDP record defaults");
    if (tcp != INVALID_SOCKET) {
        length = sizeof socket_type;
        CHECK(getsockopt(tcp, SOL_SOCKET, SO_TYPE, (char *)&socket_type, &length) == 0 && socket_type == SOCK_STREAM,
              "explicit selection creates a real stream socket");
        CHECK(closesocket(tcp) == 0, "stream socket handle closes");
        tcp = INVALID_SOCKET;
    }
    memset(ansi.szProtocol, 'x', sizeof ansi.szProtocol);
    CHECK(create(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &ansi, 0, 0) == INVALID_SOCKET &&
          WSAGetLastError() == WSAEINVAL, "unterminated ANSI description fails within its fixed buffer");
 done:
    if (original != INVALID_SOCKET) closesocket(original);
    if (shared != INVALID_SOCKET) closesocket(shared);
    if (tcp != INVALID_SOCKET) closesocket(tcp);
    CHECK(WSACleanup() == 0, "Winsock cleanup balances initialization");
    CHECK(create(AF_INET, SOCK_DGRAM, 0, 0, 0, 0) == INVALID_SOCKET && WSAGetLastError() == WSANOTINITIALISED,
          "creation after cleanup fails");
    FreeLibrary(module);
    return k32t_finish("T_STEAM_SOCKET");
}
