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

The Win64 source now wires IPv4 TCP ConnectEx/DisconnectEx and overlapped-only
AcceptEx through `shizukudos/win64/dlls/ws2_32/ws2_extensions.c` and WS2_32
extension lookup to `kernel64/net_sock.c` / `net_sock_extensions.h`. The kernel
owns the accept operation registry, event/IOCP IRP completion, cancellation,
context update and leased GetAcceptExSockaddrs lookup. The provider-produced
buffer layout and bounded tracked allocation remain part of the contract.
This source integration is limited to the implemented paths; it is not a
claim of all socket extensions, native socket execution or useful Steam behavior.
A decoder or export alone still cannot establish those application results.

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

## Provider-side AcceptEx registry (`accept_op.c`)

`accept_op.h/.c` is the provider half required by the integration gate above.
It is freestanding (no allocation, libc or locks; compiles for the kernel64
`-mcmodel=kernel -mno-red-zone` profile and MinGW x64) and must be called with
the provider's own serialization (kernel64 net mutex).

- `ntw_acceptex_plan_make` validates the original AcceptEx reservations
  (family sockaddr + 16, DWORD overflow) before any work is queued.
- `ntw_acceptex_encode_blocks` writes the Wine-layout length32 + sockaddr
  blocks at the receive *reservation* offset, zeroes reservation tails, and
  never touches the receive area; `accept_buffer.c` decodes it back exactly.
- `ntw_acceptex_submit/complete/cancel/release/forget` keep a fixed table of
  operations bound to owner, listen and accept `(id, generation)` refs and a
  16-bit slot generation in each token (0 never issued). The accepted byte
  count is recorded separately and refused above the receive reservation.
  Buffer reuse retires an older completed record; closing a socket or process
  frees its records and reports pending ones for IRP cancellation.
- `ntw_acceptex_update_context` implements the SO_UPDATE_ACCEPT_CONTEXT
  binding check; `ntw_acceptex_lookup` gives GetAcceptExSockaddrs the tracked
  allocation length, refusing a received count passed as the reservation.

Host check: `accept_op_test.c` (writer/reader round trip and lifetimes).
The kernel `SHZ_SOCK_ACCEPT_EX` ioctl and WS2_32 `WSAID_ACCEPTEX` extension
pointer are source-integrated with the shared private opcode table. These
host fixtures retain their narrower scope; current-artifact execution inside
ShizukuOS and useful Steam functionality remain required. No Steam or native
socket execution result is reported here.
