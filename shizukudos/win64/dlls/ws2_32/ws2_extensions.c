/* SPDX-License-Identifier: GPL-2.0-only
 * Original native ConnectEx / DisconnectEx wrappers. The kernel owns real TCP
 * requests and their IRPs, event / IOCP completion, cancellation and socket refs.
 * Microsoft LPFN_CONNECTEX / LPFN_DISCONNECTEX contracts; Wine 11.0 socket.c
 * (db11d0fe6a169c457e23d007e20404643d067aa8) was read for ABI comparison only.
 * IPv4 TCP only. AcceptEx is forwarded to the kernel registry (accept_op.c);
 * WSAID_GETACCEPTEXSOCKADDRS returns the kernel-leased bounded decoder
 * (ntwin32/steam_socket/acceptex_sockaddrs.c, shared with wsock32.dll);
 * no APC completion routine or other extension claim.
 */
#ifndef SHZ_WS2_EXT_HOST_TEST
#define WIN32_LEAN_AND_MEAN
#define WINSOCK_API_LINKAGE
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include "ws2_extensions.h"

LONG NTAPI NtShzSockIoctl(ULONG_PTR, ULONG_PTR, const void *, ULONG_PTR, void *, ULONG_PTR, PULONG);
LONG NTAPI NtShzSockGetOpt(ULONG_PTR, ULONG_PTR, ULONG_PTR, void *, PULONG);
#define NTW_SOCKADDRS_SET_ERROR(code) SetLastError(code)
#include "../../../../ntwin32/steam_socket/acceptex_sockaddrs.c"

static void WINAPI extension_get_acceptex_sockaddrs(void *buffer, DWORD receive, DWORD local_size, DWORD remote_size,
                                                    struct sockaddr **local, int *local_length,
                                                    struct sockaddr **remote, int *remote_length)
{
    ntw_get_acceptex_sockaddrs(buffer, receive, local_size, remote_size, local, local_length, remote, remote_length);
}

static int extension_error(LONG status)
{
    if (((ULONG)status & 0xffff0000u) == 0xe0a00000u) return (int)((ULONG)status & 0xffffu);
    switch ((ULONG)status) {
    case 0x103: return WSA_IO_PENDING;
    case 0xc0000120: return WSA_OPERATION_ABORTED;
    case 0xc0000008: return WSAENOTSOCK;
    case 0xc0000005: return WSAEFAULT;
    case 0xc0000017: case 0xc000009a: return WSAENOBUFS;
    default: return WSAEINVAL;
    }
}

static BOOL WINAPI extension_connect(SOCKET socket, const struct sockaddr *address, int address_size,
                                    void *buffer, DWORD size, DWORD *transferred, OVERLAPPED *overlapped)
{
    struct shz_sock_extension_request request = {0};
    LONG status;
    if (!shz_ws2_extensions_started()) { SetLastError(WSANOTINITIALISED); return FALSE; }
    if (!overlapped) { SetLastError(WSAEINVAL); return FALSE; }
    if (!address || address_size < (int)sizeof(struct sockaddr_in) || (size && !buffer)) {
        SetLastError(WSAEFAULT); return FALSE;
    }
    request.address = (ULONG_PTR)address;
    request.address_length = (unsigned)address_size;
    request.buffer = (ULONG_PTR)buffer;
    request.length = size;
    request.overlapped = (ULONG_PTR)overlapped;
    status = NtShzSockIoctl(socket, SHZ_SOCK_CONNECT_EX, &request, sizeof request, NULL, 0, NULL);
    if (status) { SetLastError((DWORD)extension_error(status)); return FALSE; }
    if (transferred) *transferred = (DWORD)overlapped->InternalHigh;
    return TRUE;
}

static BOOL WINAPI extension_disconnect(SOCKET socket, OVERLAPPED *overlapped, DWORD flags, DWORD reserved)
{
    struct shz_sock_extension_request request = {0};
    LONG status;
    if (!shz_ws2_extensions_started()) { SetLastError(WSANOTINITIALISED); return FALSE; }
    if (reserved || (flags & ~2u)) { SetLastError(WSAEINVAL); return FALSE; }
    request.overlapped = (ULONG_PTR)overlapped;
    request.flags = flags;
    status = NtShzSockIoctl(socket, SHZ_SOCK_DISCONNECT_EX, &request, sizeof request, NULL, 0, NULL);
    if (status) { SetLastError((DWORD)extension_error(status)); return FALSE; }
    return TRUE;
}

static BOOL WINAPI extension_accept(SOCKET listener, SOCKET accepted, void *buffer, DWORD receive_length,
                                   DWORD local_length, DWORD remote_length, DWORD *received, OVERLAPPED *overlapped)
{
    struct shz_sock_extension_request request = {0};
    LONG status;
    if (!shz_ws2_extensions_started()) { SetLastError(WSANOTINITIALISED); return FALSE; }
    if (!overlapped) { SetLastError(WSAEINVAL); return FALSE; }
    if (!buffer) { SetLastError(WSAEFAULT); return FALSE; }
    request.address = (ULONG_PTR)accepted;
    request.address_length = (unsigned long long)local_length | (unsigned long long)remote_length << 32;
    request.buffer = (ULONG_PTR)buffer;
    request.length = receive_length;
    request.overlapped = (ULONG_PTR)overlapped;
    status = NtShzSockIoctl(listener, SHZ_SOCK_ACCEPT_EX, &request, sizeof request, NULL, 0, NULL);
    if (status) { SetLastError((DWORD)extension_error(status)); return FALSE; }
    /* Actual accepted bytes, never the receive reservation. */
    if (received) *received = (DWORD)overlapped->InternalHigh;
    return TRUE;
}

int shz_ws2_extension_pointer(SOCKET socket, const void *input, DWORD input_size,
                              void *output, DWORD output_size, DWORD *returned)
{
    static const unsigned char connect_id[16] = {0xb9,0x07,0xa2,0x25,0xf3,0xdd,0x60,0x46,0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e};
    static const unsigned char disconnect_id[16] = {0x11,0x2e,0xda,0x7f,0x30,0x86,0x6f,0x43,0xa0,0x31,0xf5,0x36,0xa6,0xee,0xc1,0x57};
    /* WSAID_ACCEPTEX {b5367df1-cbac-11cf-95ca-00805f48a192} */
    static const unsigned char accept_id[16] = {0xf1,0x7d,0x36,0xb5,0xac,0xcb,0xcf,0x11,0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92};
    /* WSAID_GETACCEPTEXSOCKADDRS {b5367df2-cbac-11cf-95ca-00805f48a192} */
    static const unsigned char sockaddrs_id[16] = {0xf2,0x7d,0x36,0xb5,0xac,0xcb,0xcf,0x11,0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92};
    ULONG type = 0, length = 4;
    LONG status;
    const unsigned char *id = input;
    void *function;
    unsigned i, is_connect = 1, is_disconnect = 1, is_accept = 1, is_sockaddrs = 1;
    if (!input || input_size < 16 || !output || output_size < sizeof function || !returned) {
        SetLastError(WSAEFAULT); return SOCKET_ERROR;
    }
    status = NtShzSockGetOpt(socket, SOL_SOCKET, SO_TYPE, &type, &length);
    if (status) { SetLastError((DWORD)extension_error(status)); return SOCKET_ERROR; }
    for (i = 0; i < 16; ++i) {
        if (id[i] != connect_id[i]) is_connect = 0;
        if (id[i] != disconnect_id[i]) is_disconnect = 0;
        if (id[i] != accept_id[i]) is_accept = 0;
        if (id[i] != sockaddrs_id[i]) is_sockaddrs = 0;
    }
    if (!is_connect && !is_disconnect && !is_accept && !is_sockaddrs) { SetLastError(WSAEOPNOTSUPP); return SOCKET_ERROR; }
    function = is_connect ? (void *)extension_connect :
               is_accept ? (void *)extension_accept :
               is_sockaddrs ? (void *)extension_get_acceptex_sockaddrs : (void *)extension_disconnect;
    /* GUID/output may be unaligned: avoid typed pointer loads/stores. */
    for (i = 0; i < sizeof function; ++i) ((unsigned char *)output)[i] = ((unsigned char *)&function)[i];
    *returned = sizeof function;
    return 0;
}
