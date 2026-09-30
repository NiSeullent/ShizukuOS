# TLS 1.3 client foundation

This component performs a real, authenticated TLS 1.3 client handshake and
encrypted application I/O through caller-provided transport callbacks. It is
an independent library. Wiring it into Schannel, WinHTTP, WinINet and application
networking remains pending. PE thread-local storage under `ntwin32/tls` is
unrelated to transport TLS.

## Pinned dependency and license

The build uses [Mbed TLS 4.2.0](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-4.2.0)
with its bundled TF-PSA-Crypto 1.2.0. The official archive SHA256 is:

```text
2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea
```

Both bundled LICENSE files offer Apache-2.0 OR GPL-2.0-or-later. This port selects
the GPL version 2 option, compatible with the repository's GPL-2.0-only license.
The builder checks both LICENSE files and all extracted regular files against
the hash-pinned archive. Upstream notices and license files must accompany any
distribution. Downloaded sources and binaries remain in ignored `build/tls13`.

## Caller contract

Use `m98_tls13.h`. Supply:

- A CSPRNG callback already seeded from reliable entropy. Return **exactly 1**
  only after filling every requested byte. All other return values fail closed.
  A timer, CPU jitter sample or unseeded generator does not satisfy this contract.
- A reliable UTC clock returning Unix seconds in `1..253402300799`.
- An explicit CA bundle, plus a nonempty ASCII DNS hostname. PEM length includes
  its terminal NUL. DER is also accepted. Partial CA bundle parsing is rejected.
- Send and receive callbacks returning a byte count, 0 for transport EOF,
  -1 for failure or -2 for would-block. Bound callback blocking time.

The library copies the CA and hostname into backend storage during creation.
Callback functions and their `user` context must remain valid until free.
The caller owns socket creation, DNS, proxy negotiation, socket lifetime and
trust-store selection. IP literals are rejected by this first adapter.

Call create, retry handshake on WANT_READ/WANT_WRITE, then read/write. A write
retry must use the same buffer and length until that operation completes, as
required by the backend. Shutdown sends authenticated close_notify; retry it
on WANT_READ/WANT_WRITE. Application writes are rejected after shutdown begins.
Free always destroys library state and never closes the caller's socket.

Only one live client is supported per process. A lease rejects additional
creation attempts. All calls on the live client must be serialized; callbacks
must not reenter the API. This private PSA instance must not be used by other
components. Concurrent multi-session and shared PSA integration remain pending.

The effective compiler configuration and runtime min/max both enforce TLS 1.3.
Server mode, TLS 1.2, DTLS, PSK authentication, early data, resumption tickets,
ambient filesystem access and built-in OS entropy are disabled. Certificate
chain, hostname and certificate validity checks are required. An invalid clock,
entropy failure, certificate rejection, unauthenticated transport EOF or damaged
authenticated record disables the connection and rejects later application I/O.

## Repeatable host and PE checks

Run from the repository root, using Python 3.12+, CMake and Ninja. Cross build
also requires `i686-w64-mingw32-gcc`; the static PE gate requires `pefile`.

```text
python3 -B tools/build_tls13.py --profile host --jobs 2
python3 -B tests/m98_tls13_integration.py
python3 -B tools/build_tls13.py --profile pe32 --jobs 2
python3 -B tests/m98_tls13_pe98.py
```

Build receipts freeze adapter/configuration source hashes before building,
invalidate previous receipts at the start, check every distinct generated
compiler flag set with the preprocessor, and assert inputs stayed unchanged.
The builder writes `build/tls13/{host,pe32}/build-result.json` with dependency,
compiler configuration, logs and output hashes. A failed build publishes no
successful receipt.

The host fixture starts temporary OpenSSL servers bound only to `127.0.0.1`,
then stops all owned processes. It exchanges encrypted HTTP with a valid TLS
1.3 server using fragmented I/O. Sixteen cases cover valid operation, WANT
retry, authenticated shutdown, wrong hostname, untrusted and expired
certificates, invalid CA and hostname inputs, unavailable clock, three entropy
failure statuses both at creation and later use, TLS 1.2 rejection, and incoming
ciphertext payload corruption with zero plaintext output. Evidence is in
`build/tls13/tests/result.json`.

The PE gate checks PE32/x86, GUI subsystem 4.10, zero linker timestamp, base
relocations, absence of static TLS/delay import/CLR directories, nine exact
exports, and every import against the pinned Win98 SE Korean OEM export list.
This is a static compatibility check. Presence of native exports does not prove
runtime behavior.

## Native integration still required

No guest LoadLibrary or guest handshake has been performed for this component.
Every receipt records `guest_validated=false` and
`os_schannel_integrated=false`. Before claiming OS TLS 1.3 support, the native
owner must test loading and relocation, native MSVCRT behavior, BIO networking,
trusted certificate storage, reliable entropy, wall clock and a real handshake
inside the guest. Afterwards, implement and test the required Schannel/HTTP
provider and application paths. No app compatibility flag should infer success
from these host tests or the static import gate.
