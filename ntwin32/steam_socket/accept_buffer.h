/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_STEAM_ACCEPT_BUFFER_H
#define NTW_STEAM_ACCEPT_BUFFER_H

#include <stddef.h>
#include <stdint.h>

/* This identifies a producer contract, not a Windows-wide wire format. */
enum ntw_accept_layout {
    NTW_ACCEPT_LAYOUT_UNKNOWN = 0,
    NTW_ACCEPT_LAYOUT_WINE_LENGTH32 = 1
};

enum ntw_accept_status {
    NTW_ACCEPT_OK = 0,
    NTW_ACCEPT_ARGUMENT,
    NTW_ACCEPT_PROVIDER_LAYOUT,
    NTW_ACCEPT_LENGTH_OVERFLOW,
    NTW_ACCEPT_TRUNCATED,
    NTW_ACCEPT_ADDRESS_LENGTH,
    NTW_ACCEPT_ADDRESS_FAMILY,
    NTW_ACCEPT_RESERVATION
};

enum {
    NTW_ACCEPT_AF_INET = 2,
    NTW_ACCEPT_AF_INET6 = 23,
    NTW_ACCEPT_IPV4_BYTES = 16,
    NTW_ACCEPT_IPV6_BYTES = 28,
    NTW_ACCEPT_EXTRA_BYTES = 16,
    NTW_ACCEPT_LENGTH_BYTES = 4
};

struct ntw_accept_address {
    /* Borrowed, possibly unaligned Windows sockaddr bytes. No typed cast. */
    const uint8_t *bytes;
    uint32_t length;
    uint16_t family;
};

struct ntw_accept_addresses {
    struct ntw_accept_address local;
    struct ntw_accept_address remote;
};

/* Parse a COMPLETED output from the explicitly identified provider.
 * buffer_bytes is the actual readable allocation length; the three DWORD
 * lengths must be the original AcceptEx reserved lengths, not bytes received.
 * The reservation rule (sockaddr size + 16) follows Microsoft's AcceptEx
 * input contract. Only exact Windows IPv4/IPv6 structures are supported.
 * out must be writable and outside buffer's declared allocation. It remains
 * byte-for-byte unchanged on every error. Neither input nor padding is written.
 * The borrowed addresses remain valid only while buffer remains unchanged.
 * This portable prerequisite is NOT the Win32 GetAcceptExSockaddrs export:
 * that VOID API has no allocation length and dispatches to the socket provider.
 */
enum ntw_accept_status ntw_accept_decode(
    enum ntw_accept_layout layout, const void *buffer, size_t buffer_bytes,
    uint32_t receive_bytes, uint32_t local_reserved, uint32_t remote_reserved,
    struct ntw_accept_addresses *out);

#endif
