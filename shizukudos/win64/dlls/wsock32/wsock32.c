/* SPDX-License-Identifier: LGPL-2.1-or-later
 * GetAcceptExSockaddrs buffer layout adapted from Wine 11.0's
 * dlls/ws2_32/socket.c:893-911 at db11d0fe6a169c457e23d007e20404643d067aa8.
 * Source SHA-256: e35fb73411e741ef373d5fb4ae6e1a4220144c86ed66f91f9e80df32e40d7a01.
 * Original bounds/alignment checks added for the standalone Win64 runtime.
 * Winsock 1 ordinals follow that revision's dlls/wsock32/wsock32.spec, which
 * differs from ws2_32 at ordinals 10-12. Only implemented ws2_32 APIs are
 * forwarded. Legacy Winsock 1 IP-option translation is not implemented.
 * This parses existing Wine-provider-format bytes; it neither accepts a
 * connection nor adds AcceptEx/overlapped I/O/WSAIoctl extension support.
 * The API has no total buffer-size argument: callers must provide readable
 * storage for their declared segments. Arbitrary inaccessible pointers cannot
 * be validated here; returned addresses borrow that storage without copying.
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
#include <limits.h>

static uint32_t length_prefix(const unsigned char *p)
{
    /* Provider data is little endian. Byte reads also handle unaligned buffers. */
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

DLLAPI VOID WINAPI GetAcceptExSockaddrs(PVOID buffer, DWORD received, DWORD local_size, DWORD remote_size,
                                      struct sockaddr **local, LPINT local_length,
                                      struct sockaddr **remote, LPINT remote_length)
{
    uintptr_t base = (uintptr_t)buffer, local_at, remote_at, end;
    uint32_t local_n, remote_n;
    if (local) *local = 0;
    if (local_length) *local_length = 0;
    if (remote) *remote = 0;
    if (remote_length) *remote_length = 0;
    if (!buffer || !local || !local_length || !remote || !remote_length ||
        local_size < 6 || remote_size < 6 || base > UINTPTR_MAX - received)
        goto invalid;
    local_at = base + received;
    if (local_at > UINTPTR_MAX - local_size) goto invalid;
    remote_at = local_at + local_size;
    if (remote_at > UINTPTR_MAX - remote_size) goto invalid;
    end = remote_at + remote_size;
    (void)end;                 /* validated total range before reading either prefix */
    local_n = length_prefix((const unsigned char *)local_at);
    remote_n = length_prefix((const unsigned char *)remote_at);
    if (local_n < 2 || local_n > INT_MAX || local_n > local_size - 4 ||
        remote_n < 2 || remote_n > INT_MAX || remote_n > remote_size - 4)
        goto invalid;
    *local = (struct sockaddr *)(local_at + 4);
    *remote = (struct sockaddr *)(remote_at + 4);
    *local_length = (int)local_n;
    *remote_length = (int)remote_n;
    return;
invalid:
    WSASetLastError(WSAEINVAL);
}
