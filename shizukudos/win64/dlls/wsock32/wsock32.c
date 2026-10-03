/* SPDX-License-Identifier: LGPL-2.1-or-later
 * GetAcceptExSockaddrs buffer layout adapted from Wine 11.0's
 * dlls/ws2_32/socket.c:893-911 at db11d0fe6a169c457e23d007e20404643d067aa8.
 * Source SHA-256: e35fb73411e741ef373d5fb4ae6e1a4220144c86ed66f91f9e80df32e40d7a01.
 * Original bounds/alignment checks added for the standalone Win64 runtime.
 * Winsock 1 ordinals follow that revision's dlls/wsock32/wsock32.spec, which
 * differs from ws2_32 at ordinals 10-12. Only implemented ws2_32 APIs are
 * forwarded. Legacy Winsock 1 IP-option translation is not implemented.
 * GetAcceptExSockaddrs reads nothing without a kernel allocation lease: the
 * kernel confirms a COMPLETED AcceptEx of this process wrote exactly this buffer
 * with exactly these reservations (private opcode 0x53480014), then the bounded
 * decoder ntwin32/steam_socket/accept_buffer.c reads at most that total and
 * accepts only exact IPv4/IPv6 sockaddrs within a sockaddr+16 reservation.
 * Returned addresses borrow that storage without copying.
 * Microsoft contract: https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nf-mswsock-getacceptexsockaddrs
 *
 * Copyright (C) 1993,1994,1996,1997 John Brezak, Erik Bos, Alex Korobka.
 * Copyright (C) 2001 Stefan Leichter
 * Copyright (C) 2004 Hans Leidekker
 * Copyright (C) 2005 Marcus Meissner
 * Copyright (C) 2006-2008 Kai Blin
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 * License for more details. You should have received a copy of that license
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */
#include "wsock32_compat.h"

LONG NTAPI NtShzSockIoctl(ULONG_PTR, ULONG_PTR, const void *, ULONG_PTR, void *, ULONG_PTR, PULONG);
#define NTW_SOCKADDRS_SET_ERROR(code) WSASetLastError(code)
#include "../../../../ntwin32/steam_socket/acceptex_sockaddrs.c"

DLLAPI VOID WINAPI GetAcceptExSockaddrs(PVOID buffer, DWORD received, DWORD local_size, DWORD remote_size,
                                      struct sockaddr **local, LPINT local_length,
                                      struct sockaddr **remote, LPINT remote_length)
{
    /* `received` is the AcceptEx dwReceiveDataLength reservation (Microsoft contract). */
    ntw_get_acceptex_sockaddrs(buffer, received, local_size, remote_size, local, local_length, remote, remote_length);
}
