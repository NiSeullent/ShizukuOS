# Bounded AcceptEx output decoder prerequisite

This directory owns a portable reader for **completed Wine-provider output**.
It is independent source work for Steam's missing `WSOCK32!GetAcceptExSockaddrs`
dependency. It is not that export, a socket provider, or a claim that Steam runs.
No shared loader, export table, provider source, build script or VM is modified.

## Actual layout and source lineage

The [Microsoft AcceptEx contract](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nf-mswsock-acceptex)
requires each address reservation to be at least the protocol sockaddr size plus
16 bytes. It does **not** define a 16-byte prefix. The corresponding
[GetAcceptExSockaddrs contract](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nf-mswsock-getacceptexsockaddrs)
requires the same reserved lengths as the completed AcceptEx call and dispatch
to a provider extension obtained through WSAIoctl.

Wine, pinned by `porting/sources.json` at
`df15af3652511150490934682202d45af892f887`, writes a little-endian signed 32-bit
sockaddr length followed immediately by Windows sockaddr bytes:

- [server/sock.c, fill_accept_output](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/server/sock.c#L861):
  local block begins at the original receive reservation; remote block begins at
  receive reservation plus local reservation. The address begins at block + 4.
- [dlls/ws2_32/socket.c, WS2_GetAcceptExSockaddrs](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/ws2_32/socket.c#L987):
  its matching reader consumes that length and returns the borrowed address.

ReactOS is pinned at `9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8`.
[dll/win32/mswsock/extensions.c](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/mswsock/extensions.c#L55)
obtains both AcceptEx and GetAcceptExSockaddrs from the socket provider and
delegates parsing. It does not establish that every provider shares Wine's
layout. Wine references are LGPL-2.1-or-later; ReactOS references retain their
per-file/top-level licensing. This GPL-2.0-only reader and regression harness
were independently written; no upstream code or data was copied.

`NTW_ACCEPT_LAYOUT_WINE_LENGTH32` is therefore mandatory. Unknown layouts fail
before reading the input. IPv4/IPv6 use the Windows family numbers 2/23 and
exact sockaddr lengths 16/28. The helper enforces Microsoft's extra-reservation
contract even though Wine's low-level writer can accept smaller capacities.

## Reader contract

`ntw_accept_decode` receives the actual allocation length separately from the
original three DWORD reservations. It validates the full operation before any
read, refuses DWORD/pointer range overflow, checks both length prefixes and
families, and writes the result only after both addresses validate. Input bytes are never
written, unaligned fields are read bytewise, padding is ignored, and output
remains unchanged on failure. The result must be writable and disjoint from the
declared input allocation. The caller supplies valid C pointers; this portable
module cannot catch an inaccessible pointer or a falsely declared allocation.

The addresses borrow the original buffer and must not outlive or race its
contents. Call only after successful AcceptEx completion. Received byte count
is not the original receive reservation and must not be passed in its place.
The result is ordinary non-atomic C storage. The caller must synchronize its
concurrent readers; preserving output on failure does not make publication
thread-safe.

## Integration gate

The current Win64 WS2_32 source explicitly lacks AcceptEx/ConnectEx and socket
overlapped I/O. No current provider produces this format. An integrator must
first implement accept-into-existing-socket, initial receive, event/IOCP
completion, cancellation/teardown and SO_UPDATE_ACCEPT_CONTEXT. The provider
must own its buffer layout and extension lookup. A bounded allocation tracked
by that provider is needed to adapt this helper to the VOID public ABI. A DLL
forwarder or decoder by itself does not supply these behaviors.

## Focused host validation

From the repository root, using a new output directory:

```sh
mkdir -p build/steam-socket-c009
cc -std=c99 -Wall -Wextra -Werror -pedantic -O2 \
  ntwin32/steam_socket/accept_buffer.c ntwin32/steam_socket/host_test.c \
  -o build/steam-socket-c009/host_test
build/steam-socket-c009/host_test
clang -std=c99 -Wall -Wextra -Werror -pedantic -O1 -g \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  ntwin32/steam_socket/accept_buffer.c ntwin32/steam_socket/host_test.c \
  -o build/steam-socket-c009/host_test_sanitized
build/steam-socket-c009/host_test_sanitized
```

The authored fixtures cover unequal reservations, receive prefix, unaligned
inputs, exact IPv4/IPv6 bytes, every truncation point, guarded memory at the
allocation end, negative/oversized/mismatched lengths, unknown family/provider,
DWORD overflow, insufficient reservation, alias rejection and preserved output
on failure.
These checks validate parsing on the host only. There is no Windows, Wine
socket-provider integration or application-functionality result.
