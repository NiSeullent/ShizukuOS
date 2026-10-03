/* SPDX-License-Identifier: GPL-2.0-only
 * GetAcceptExSockaddrs over the kernel AcceptEx allocation lease.
 *
 * Included (not linked) by win64/dlls/wsock32/wsock32.c (exported
 * GetAcceptExSockaddrs) and win64/dlls/ws2_32/ws2_extensions.c
 * (WSAID_GETACCEPTEXSOCKADDRS pointer); ws2_32 cannot import wsock32.
 * The includer must first declare NtShzSockIoctl (ntdll private syscall),
 * struct sockaddr, and NTW_SOCKADDRS_SET_ERROR(code).
 *
 * The Win32 API has no buffer length. Instead of trusting the caller's
 * declared segments, the kernel (net_sock_extensions.h, opcode 0x53480014)
 * confirms that a COMPLETED AcceptEx of the calling process wrote exactly
 * this buffer with exactly these reservations and returns its total size;
 * the bounded decoder (accept_buffer.c) then reads at most that many bytes
 * and accepts only exact Windows IPv4/IPv6 sockaddr blocks with the
 * Microsoft reservation (sockaddr + 16). Anything else: WSAEINVAL, outputs
 * zeroed, and the buffer is never read without a lease.
 */
#include "accept_buffer.c"

#define NTW_SOCK_ACCEPTEX_LOOKUP 0x53480014u
#ifndef SHZ_SOCKET_ACCEPTEX_LOOKUP_DEFINED
#define SHZ_SOCKET_ACCEPTEX_LOOKUP_DEFINED
struct shz_sock_acceptex_lookup { uint64_t buffer; uint32_t receive_reserved, local_reserved, remote_reserved, reserved; };
struct shz_sock_acceptex_lease { uint32_t total, accepted_bytes; };
#endif
_Static_assert(sizeof(struct shz_sock_acceptex_lookup) == 24, "private AcceptEx lease query ABI");
_Static_assert(sizeof(struct shz_sock_acceptex_lease) == 8, "private AcceptEx lease ABI");

static void ntw_get_acceptex_sockaddrs(void *buffer, uint32_t receive, uint32_t local_size, uint32_t remote_size,
                                       struct sockaddr **local, int *local_length,
                                       struct sockaddr **remote, int *remote_length)
{
    struct shz_sock_acceptex_lookup query;
    struct shz_sock_acceptex_lease lease = {0, 0};
    struct ntw_accept_addresses out;
    ULONG returned = 0;
    if (local) *local = 0;
    if (local_length) *local_length = 0;
    if (remote) *remote = 0;
    if (remote_length) *remote_length = 0;
    if (!buffer || !local || !local_length || !remote || !remote_length) goto invalid;
    query.buffer = (uint64_t)(uintptr_t)buffer;
    query.receive_reserved = receive;
    query.local_reserved = local_size;
    query.remote_reserved = remote_size;
    query.reserved = 0;
    if (NtShzSockIoctl(0, NTW_SOCK_ACCEPTEX_LOOKUP, &query, sizeof query, &lease, sizeof lease, &returned) ||
        returned != sizeof lease)
        goto invalid;
    /* The lease must describe exactly the declared segments; never read past it. */
    if ((uint64_t)receive + local_size + remote_size != lease.total || lease.accepted_bytes > receive) goto invalid;
    if (ntw_accept_decode(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, buffer, lease.total, receive, local_size, remote_size, &out))
        goto invalid;
    *local = (struct sockaddr *)(uintptr_t)out.local.bytes;
    *local_length = (int)out.local.length;
    *remote = (struct sockaddr *)(uintptr_t)out.remote.bytes;
    *remote_length = (int)out.remote.length;
    return;
invalid:
    NTW_SOCKADDRS_SET_ERROR(WSAEINVAL);
}
