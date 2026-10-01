/* SPDX-License-Identifier: GPL-2.0-only
 * Independently authored bounded reader; format references, no copied code:
 * Wine df15af3652511150490934682202d45af892f887:
 *   server/sock.c:fill_accept_output (writer),
 *   dlls/ws2_32/socket.c:WS2_GetAcceptExSockaddrs (reader).
 * Each reserved block starts with a little-endian signed 32-bit length and
 * sockaddr bytes at +4, NOT +16. The 16 is extra reserved CAPACITY.
 * ReactOS 9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8:
 *   dll/win32/mswsock/extensions.c obtains the decoder from WSAIoctl;
 *   it does not define a universal provider buffer layout.
 * Pinned URLs, upstream licensing and integration limits: README.md.
 */
#include "accept_buffer.h"

static uint32_t little32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static enum ntw_accept_status address_block(
    const uint8_t *block, uint32_t reserved, struct ntw_accept_address *out)
{
    uint32_t length, expected;
    uint16_t family;
    if (reserved < NTW_ACCEPT_LENGTH_BYTES + 2u)
        return NTW_ACCEPT_ADDRESS_LENGTH;
    length = little32(block);
    /* Reject negative Win32 INTs and bound the address before reading family. */
    if (length < 2u || length > INT32_MAX ||
        length > reserved - NTW_ACCEPT_LENGTH_BYTES)
        return NTW_ACCEPT_ADDRESS_LENGTH;
    family = (uint16_t)((uint16_t)block[4] | (uint16_t)block[5] << 8);
    if (family == NTW_ACCEPT_AF_INET)
        expected = NTW_ACCEPT_IPV4_BYTES;
    else if (family == NTW_ACCEPT_AF_INET6)
        expected = NTW_ACCEPT_IPV6_BYTES;
    else
        return NTW_ACCEPT_ADDRESS_FAMILY;
    if (length != expected)
        return NTW_ACCEPT_ADDRESS_LENGTH;
    if (reserved < expected + NTW_ACCEPT_EXTRA_BYTES)
        return NTW_ACCEPT_RESERVATION;
    out->bytes = block + NTW_ACCEPT_LENGTH_BYTES;
    out->length = length;
    out->family = family;
    return NTW_ACCEPT_OK;
}

enum ntw_accept_status ntw_accept_decode(
    enum ntw_accept_layout layout, const void *buffer, size_t buffer_bytes,
    uint32_t receive_bytes, uint32_t local_reserved, uint32_t remote_reserved,
    struct ntw_accept_addresses *out)
{
    const uint8_t *bytes = buffer;
    struct ntw_accept_addresses result = {0};
    enum ntw_accept_status status;
    uint32_t remote_offset, total;
    uintptr_t buffer_at = (uintptr_t)buffer, out_at = (uintptr_t)out;

    if (!buffer || !out) return NTW_ACCEPT_ARGUMENT;
    if (layout != NTW_ACCEPT_LAYOUT_WINE_LENGTH32)
        return NTW_ACCEPT_PROVIDER_LAYOUT;
    /* Reject overflow in the DWORD output size submitted by AcceptEx. */
    if (local_reserved > UINT32_MAX - receive_bytes)
        return NTW_ACCEPT_LENGTH_OVERFLOW;
    remote_offset = receive_bytes + local_reserved;
    if (remote_reserved > UINT32_MAX - remote_offset)
        return NTW_ACCEPT_LENGTH_OVERFLOW;
    total = remote_offset + remote_reserved;
    if ((uint64_t)total > (uint64_t)buffer_bytes)
        return NTW_ACCEPT_TRUNCATED;
    /* Pointer-range arithmetic is done as integers before forming pointers.
     * A disjoint result prevents successful publication from corrupting input.
     * The caller still owns the ordinary C readable/writable pointer contract.
     */
    if (buffer_bytes > UINTPTR_MAX - buffer_at ||
        sizeof(*out) > UINTPTR_MAX - out_at)
        return NTW_ACCEPT_LENGTH_OVERFLOW;
    if (out_at < buffer_at + buffer_bytes && buffer_at < out_at + sizeof(*out))
        return NTW_ACCEPT_ARGUMENT;

    status = address_block(bytes + receive_bytes, local_reserved, &result.local);
    if (status != NTW_ACCEPT_OK) return status;
    status = address_block(bytes + remote_offset, remote_reserved, &result.remote);
    if (status != NTW_ACCEPT_OK) return status;
    *out = result;
    return NTW_ACCEPT_OK;
}
