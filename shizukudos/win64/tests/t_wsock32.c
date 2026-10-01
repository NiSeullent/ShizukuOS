/* SPDX-License-Identifier: GPL-2.0-only
 * Actual DLL loader checks legacy ordinals, forwards and the pure decoder.
 * This verifies no AcceptEx connection or asynchronous network operation. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include "k32test.h"

typedef VOID (WINAPI *decode_fn)(PVOID, DWORD, DWORD, DWORD, struct sockaddr **, LPINT, struct sockaddr **, LPINT);
typedef int (WINAPI *startup_fn)(WORD, LPWSADATA);
typedef int (WINAPI *cleanup_fn)(void);
typedef void (WINAPI *error_fn)(int);

int main(void)
{
    HMODULE old = LoadLibraryW(L"wsock32.dll"), modern = LoadLibraryW(L"ws2_32.dll");
    decode_fn decode;
    startup_fn startup;
    cleanup_fn cleanup;
    error_fn set_error;
    WSADATA data;
    unsigned char buffer[96];
    struct sockaddr *local, *remote;
    int local_n, remote_n;
    DWORD decode_error;
    CHECK(old && modern, "real wsock32 and ws2_32 DLLs load");
    if (!old || !modern) return 1;
    decode = (decode_fn)GetProcAddress(old, MAKEINTRESOURCEA(1142));
    CHECK(decode && (FARPROC)decode == GetProcAddress(old, "GetAcceptExSockaddrs"), "ordinal 1142 and named decoder resolve to same real function");
    CHECK(GetProcAddress(old, MAKEINTRESOURCEA(10)) == GetProcAddress(modern, "inet_addr"), "Winsock 1 ordinal 10 forwards inet_addr");
    CHECK(GetProcAddress(old, MAKEINTRESOURCEA(11)) == GetProcAddress(modern, "inet_ntoa"), "Winsock 1 ordinal 11 forwards inet_ntoa");
    CHECK(GetProcAddress(old, MAKEINTRESOURCEA(12)) == GetProcAddress(modern, "ioctlsocket"), "Winsock 1 ordinal 12 forwards ioctlsocket");
    CHECK(!GetProcAddress(old, MAKEINTRESOURCEA(1141)), "unsupported AcceptEx is absent from export table");
    startup = (startup_fn)GetProcAddress(old, MAKEINTRESOURCEA(115));
    cleanup = (cleanup_fn)GetProcAddress(old, MAKEINTRESOURCEA(116));
    set_error = (error_fn)GetProcAddress(old, MAKEINTRESOURCEA(112));
    if (!decode || !startup || !cleanup || !set_error) return 1;
    CHECK(startup(MAKEWORD(1,1), &data) == 0 && data.wVersion == MAKEWORD(1,1), "legacy startup ordinal calls actual Winsock runtime");
    memset(buffer, 0, sizeof buffer);
    buffer[3] = 16; buffer[7] = AF_INET; buffer[9] = 0x1f; buffer[10] = 0x90;
    buffer[11] = 127; buffer[14] = 1;
    buffer[35] = 28; buffer[39] = AF_INET6; buffer[41] = 1; buffer[42] = 0xbb; buffer[62] = 1;
    set_error(1234);
    decode(buffer, 3, 32, 44, &local, &local_n, &remote, &remote_n);
    decode_error = GetLastError();
    CHECK((void *)local == buffer + 7 && local_n == 16 && (void *)remote == buffer + 39 && remote_n == 28,
          "unaligned provider buffer exposes IPv4 and IPv6 bytes at correct offsets");
    CHECK(local && remote && ((unsigned char *)local)[2] == 0x1f && ((unsigned char *)remote)[3] == 0xbb && decode_error == 1234,
          "decoder preserves endpoint bytes and successful caller error");
    buffer[3] = 29;
    decode(buffer, 3, 32, 44, &local, &local_n, &remote, &remote_n);
    CHECK(!local && !remote && !local_n && !remote_n && GetLastError() == WSAEINVAL,
          "out-of-segment provider length clears outputs and fails explicitly");
    CHECK(cleanup() == 0, "legacy cleanup ordinal balances startup");
    FreeLibrary(old); FreeLibrary(modern);
    return k32t_finish("T_WSOCK32");
}
