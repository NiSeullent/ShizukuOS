/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WS2_EXTENSIONS_H
#define SHZ_WS2_EXTENSIONS_H
/* Private ABI over NtShzSockIoctl, not an AFD IOCTL or Windows public ABI. */
#define SHZ_SOCK_CONNECT_EX 0x53480010u
#define SHZ_SOCK_DISCONNECT_EX 0x53480011u
#define SHZ_SOCK_SET_OVERLAPPED 0x53480012u
#ifndef SHZ_SOCKET_EXTENSION_REQUEST_DEFINED
#define SHZ_SOCKET_EXTENSION_REQUEST_DEFINED
struct shz_sock_extension_request {
    unsigned long long address, address_length, buffer, length, overlapped;
    unsigned int flags, reserved;
};
#endif
_Static_assert(sizeof(struct shz_sock_extension_request) == 48, "private socket extension ABI");
#ifndef SHZ_WS2_EXT_HOST_TEST
int shz_ws2_extensions_started(void);
int shz_ws2_extension_pointer(SOCKET socket, const void *input, DWORD input_size,
                              void *output, DWORD output_size, DWORD *returned);
#endif
#endif
