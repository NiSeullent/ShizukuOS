/* SPDX-License-Identifier: GPL-2.0-only
 * ANSI WSASocket entry point over the real Kernel64 Winsock backend.
 * Microsoft WSASocketA and WSAPROTOCOL_INFOA contracts:
 * https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa
 * https://learn.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-wsaprotocol_infoa
 * Original implementation. Numeric protocol fields have identical A/W layout;
 * only the bounded protocol description needs conversion through the ACP.
 * IPv4 and synchronous I/O limits remain those of WSASocketW. Groups,
 * multipoint/security/registered-I/O modes are explicitly refused.
 */
#define WIN32_LEAN_AND_MEAN
#define WINSOCK_API_LINKAGE
#include <winsock2.h>
#include <stddef.h>
#include <string.h>
#include "ws2_trace.h"

#ifndef DLLAPI
#define DLLAPI __declspec(dllexport)
#endif

_Static_assert(offsetof(WSAPROTOCOL_INFOA, szProtocol) == offsetof(WSAPROTOCOL_INFOW, szProtocol),
               "A/W protocol fixed-field layout must match");

DLLAPI SOCKET WSAAPI WSASocketA(int af, int type, int protocol, LPWSAPROTOCOL_INFOA info, GROUP group, DWORD flags)
{
    WSAPROTOCOL_INFOW wide;
    LPWSAPROTOCOL_INFOW selected = 0;
    SOCKET result;
    size_t length;
    DWORD error;
    const DWORD accepted = WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT;
    const DWORD unsupported = WSA_FLAG_MULTIPOINT_C_ROOT | WSA_FLAG_MULTIPOINT_C_LEAF |
                              WSA_FLAG_MULTIPOINT_D_ROOT | WSA_FLAG_MULTIPOINT_D_LEAF |
                              WSA_FLAG_ACCESS_SYSTEM_SECURITY | WSA_FLAG_REGISTERED_IO;
    if (flags & ~(accepted | unsupported)) { SetLastError(WSAEINVAL); return INVALID_SOCKET; }
    if (flags & unsupported) {
        SetLastError(WSAEOPNOTSUPP); ws2_trace_request("WSASocketA flags", flags, 0, 0);
        ws2_trace_failure("WSASocketA", WSAEOPNOTSUPP); return INVALID_SOCKET;
    }
    if (group) { SetLastError(WSAEINVAL); return INVALID_SOCKET; }
    if (!info && (af == FROM_PROTOCOL_INFO || type == FROM_PROTOCOL_INFO || protocol == FROM_PROTOCOL_INFO)) {
        SetLastError(WSAEINVAL); return INVALID_SOCKET;
    }
    if (info) {
        for (length = 0; length <= WSAPROTOCOL_LEN && info->szProtocol[length]; ++length) { }
        if (length > WSAPROTOCOL_LEN) { SetLastError(WSAEINVAL); return INVALID_SOCKET; }
        memset(&wide, 0, sizeof wide);
        memcpy(&wide, info, offsetof(WSAPROTOCOL_INFOA, szProtocol));
        if (!MultiByteToWideChar(CP_ACP, 0, info->szProtocol, (int)length + 1,
                                 wide.szProtocol, WSAPROTOCOL_LEN + 1)) {
            SetLastError(WSAEINVAL); return INVALID_SOCKET;
        }
        /* The existing W backend selects all three fields from its structure.
         * Resolve each FROM_PROTOCOL_INFO independently before delegation. */
        if (af != FROM_PROTOCOL_INFO) wide.iAddressFamily = af;
        if (type != FROM_PROTOCOL_INFO) wide.iSocketType = type;
        if (protocol != FROM_PROTOCOL_INFO) wide.iProtocol = protocol;
        selected = &wide;
    }
    result = WSASocketW(af, type, protocol, selected, group, flags);
    if (result == INVALID_SOCKET) return result;
    /* WSADuplicateSocketW's token transfers actual duplicated-handle ownership.
     * Reflect consumption in the caller's A record, not only the stack copy. */
    if (info && info->dwProviderReserved && !wide.dwProviderReserved) info->dwProviderReserved = 0;
    if (!SetHandleInformation((HANDLE)result, HANDLE_FLAG_INHERIT,
                              (flags & WSA_FLAG_NO_HANDLE_INHERIT) ? 0 : HANDLE_FLAG_INHERIT)) {
        error = GetLastError();
        closesocket(result);
        SetLastError(error == ERROR_INVALID_HANDLE ? WSAENOTSOCK : WSAEPROVIDERFAILEDINIT);
        return INVALID_SOCKET;
    }
    return result;
}
