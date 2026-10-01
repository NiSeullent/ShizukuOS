# Explicit-loading Win98 ANSI SSPI adapter

`sspi_native.c/.h/.def` implement the standard x86 ANSI outbound stream call
shapes over `sspi_stream.c`, the independently tested Mbed TLS 3.6.7 core.
The project-owned `M98SSPI.DLL` is loaded explicitly by an application. These
sources do not register an OS provider, modify Secur32/Schannel/WinINet, install
trust anchors, or establish that Trident, Office, Legcord or Signal works.

The DLL exposes acquisition/freeing of outbound credentials, initialization and
deletion of contexts, package discovery/owned-buffer freeing, stream sizes,
encryption/decryption, shutdown control and `InitSecurityInterfaceA`. Exporting
and importing security contexts explicitly return `SEC_E_UNSUPPORTED_FUNCTION`.
Enumeration advertises only `M98TLS 1.3`, client-only stream/integrity/privacy
capabilities. `Schannel` and the unified provider name are accepted aliases
inside this explicitly selected DLL; they do not register those OS packages.

## Runtime, trust and lifetime

One DLL-owned critical section serializes every native trust-store operation,
allocation table, credential/context operation, pool, linked PSA initialization
and shutdown. CryptoAPI supplies the native randomness through the existing
runtime. PSA is a private statically linked instance. The DLL uses a C-only entry
with zero/constant globals and no NT static-TLS or constructor startup. The
application must finish callers before unloading it; unloading concurrently
with an API call is outside the ordinary DLL lifetime contract.

Handles encode kind, bounded slot and a shared monotonically increasing 32-bit
generation. No handle value is dereferenced as a pointer. Exhaustion fails
without wrapping a generation. There are at most 8 credentials and 8 contexts.
Freeing credentials invalidates acquisition handles but existing contexts hold
references to their immutable CA snapshot. A referenced credential slot is not
reused. Deletion releases the last reference. Final runtime cleanup failure
poisons subsequent acquisition instead of reusing partially finalized PSA/RNG.

NULL authentication data, or the supported `SCHANNEL_CRED` version 4 subset,
opens an existing current-user native `ROOT` store using original Win98
`CertOpenStore(CERT_STORE_PROV_SYSTEM_A, ..., CERT_SYSTEM_STORE_CURRENT_USER |
CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, "ROOT")`. Missing
stores fail without creation; no simplified create-if-absent opener is used. It
encodes the original DER certificate bytes into a PEM bundle, preserving them
through base64. Empty stores, enumeration/closing failures, unsupported encoding,
over 512 roots, a certificate larger than 64 KiB or a bundle exceeding 1 MiB
fail the entire acquisition. No partial/truncated policy silently succeeds.
No store is changed and no certificates are downloaded.

`M98SSPI_PRIVATE_CRED` provides an explicit, separate CA policy for controlled
tests or project-aware callers. The DLL copies its bytes at acquisition. PEM
sizes include the NUL; DER sizes do not. Its flags/reserved fields must be zero.
`SCHANNEL_CRED.hRootStore` is a server-only field and is rejected for outbound
use; it never serves as client CA policy. Supported standard credential fields
are zero/default settings or the TLS 1.3 client protocol bit and
`SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_AUTO_CRED_VALIDATION`.

The real engine performs X.509 chain/signature, DNS hostname and time checks
against the selected anchors. This is **not Windows chain-policy parity**:
CTL/disallowed-store policy, OS chain-building policy, revocation/OCSP retrieval,
ALPN, client certificates, server/inbound credentials, custom cipher lists,
session caching and exporter/key material attributes are not implemented.
Explicit requests for unsupported flags/attributes/credentials fail. Updating
native roots and auditing OS policy need separate authorized implementation.
Malformed CA bytes can be rejected when a context parses its immutable policy;
acquisition copies the bytes and does not itself prove they contain valid CAs.

## Descriptor and caller contract

Calls require readable/writable caller memory as standard C SSPI does. The
adapter rejects null/overflowing ranges and invalid descriptor forms; it cannot
prove a non-null caller pointer addresses mapped memory. Native compile-time
assertions check 32-bit handles, descriptors, credential structures and standard
function-table encryption/decryption offsets.

`InitializeSecurityContextA` requires stream mode, an ASCII DNS hostname on the
first call, no input on that first call, and an outbound credential. Subsequent
calls may omit the credential and hostname. A supplied credential must match
the live referenced credential; after freeing its handle, pass NULL. Request
bits must stay stable except output-allocation mode. Reserved fields and data
representation must be zero. Allowed request bits are stream, confidentiality,
integrity, replay/sequence detection, connection and allocation of memory.
Datagram, manual/unverified validation, delegation, mutual/client authentication,
extended-error semantics and other flags explicitly fail.

Handshake input is one TOKEN plus one or more zero EMPTY descriptors. Caller
output is one TOKEN, optionally a zero ALERT descriptor; extended alert-buffer
semantics are not implemented. Caller buffers may be used, or
`ISC_REQ_ALLOCATE_MEMORY` allocates a tracked token. Such output descriptors must
start at NULL/zero. `FreeContextBuffer` accepts only exact currently owned
allocations, not arbitrary pointers/interior addresses. There are at most 64
owned output allocations, each at most 64 KiB. Security attributes are returned
only on final successful initialization; unlimited timestamps describe this
in-memory credential/context lifetime, not the remote certificate's expiry.

`SEC_E_BUFFER_TOO_SMALL` can consume input while retaining the exact token in
the core. Preserve any EXTRA tail and retry with **empty input** and a larger
output capacity. Do not replay consumed handshake bytes. Pending handshake
tokens block stream-size queries and shutdown even if the backend has already
authenticated the peer. A rejected retry with fresh input does not clear that
pending state. The final successful token, if nonempty, must still be sent.

Unconsumed bytes are returned as EXTRA. A zero-consumption partial record
returns `SEC_E_INCOMPLETE_MESSAGE` with MISSING and leaves bytes unchanged. If a
complete prefix was consumed before a partial tail, the adapter first returns
`SEC_I_CONTINUE_NEEDED` plus EXTRA. Reassemble/resubmit the retained tail; a
subsequent incomplete call can then report MISSING without requiring replay of
already consumed bytes. It never returns incomplete with only an EXTRA hint.

Encryption requires exactly four descriptors: one HEADER, one nonempty DATA,
one TRAILER and one zero EMPTY. Ranges must not overlap. Readonly/scattered DATA,
nonzero QOP/sequence arguments and empty messages fail. Stream sizes advertise
header 5, conservative trailer capacity 32, maximum plaintext 16,383, four
buffers and block size 1. Insufficient header/trailer capacity does not mutate
plaintext or advance encryption. Success returns actual trailer length.

Decryption requires one writable DATA containing ciphertext and three zero
EMPTY descriptors. The adapter decrypts into a private separate destination;
only authenticated plaintext is copied into the original record's DATA region.
It relabels HEADER/DATA/TRAILER and returns further original bytes as EXTRA.
Incomplete inputs remain unchanged and return MISSING. At most one complete
record is processed per call. Core certificate and authentication errors are
translated to meaningful SSPI errors. Authenticated close returns
`SEC_I_CONTEXT_EXPIRED`, including idempotent calls after closure.

A post-handshake control record requiring a response returns `SEC_I_RENEGOTIATE`.
The explicitly selected caller must call initialization with **empty input**
to drain that already generated response; no record is replayed. Buffer retries
retain it. Traffic/shutdown cannot bypass it. Control records requiring no
response can return success with empty DATA, a normal TLS stream case.

`ApplyControlToken` supports only `SCHANNEL_SHUTDOWN`. It arms shutdown; the next
initialization call emits real core-generated close_notify with small-buffer
retry support. SSPI lacks a socket-EOF argument, so explicit clients must call
`M98SspiEndInput` on actual EOF after draining their records. Only previously
authenticated peer close is orderly; otherwise EOF returns illegal-message.

Unsupported function-table slots are NULL and explicit-loading callers must
check them. Context import/export entries are callable explicit failures, not
success stubs. Unicode entry points, connection/certificate attributes and
general OS package dispatch still need implementation.

## Verification and next integration

Outputs are isolated in `build/secure-transport/sspi-native-v1/`. No build,
source or VM owned by another session is modified. The normal and clang
ASan/UBSan ABI fault model execute the actual adapter C with mock Win32 APIs
and mock stream calls. They verify lifetimes, standard shapes, ROOT encoding
and failure propagation, typed/stale handles, bounded slots/allocations,
descriptor corruption, unsupported options, partial tail translation, token
retry/shutdown ordering, staged decryption, close idempotence and concurrent
serialization. They **do not execute TLS cryptography or Windows APIs**.
The separately retained core fixture verifies actual encrypted TLS records.

The initial checkpoint below is superseded by the ROOT read-only correction:
its simplified opener could create a missing store. It was compiled and
host-model-tested, never run on a Windows guest. All its receipts remain
retained; the corrected checkpoint follows:

| Evidence | Retained output | Result |
| --- | --- | --- |
| GCC ABI model | `sspi-native-v1/abi-host-complete/receipt.json` | 14 groups, 42,940 assertions, zero failures |
| Clang ASan/UBSan ABI model | `sspi-native-v1/abi-sanitize-complete/receipt.json` | 14 groups, 42,396 assertions, zero failures/diagnostics/leaks |
| Strict native x86 compile + PE inventory | `sspi-native-v1/native-complete/receipt.json` | 15 exact exports, 47 original OEM imports, 6,577 HIGHLOW relocations |

Assertion totals can vary with the 8-thread, 200-iteration credential/context
lifecycle test because serialized runtime stop/reinitialization depends on
interleaving. All native/core calls are checked while the mock critical section
is held. The native DLL is 1,638,368 bytes, SHA256
`b60d95c8f607d3990a809ae1c206e9aba398593581e86b105a338d1cb048dbf5`.
Its actual Windows loading, native ROOT execution and OS registration remain
unproven; the receipt sets those evidence flags to false.

The accepted ROOT correction uses adapter SHA256
`32b6bbd23d7ed61c40d86e08711c631140dfeb3ee6e5e1a6427d9eebb2955672`.
`abi-host-root-readonly/receipt.json` passes 14 groups / 44,198 checks;
`abi-sanitize-root-readonly/receipt.json` passes 14 groups / 41,854 checks with
zero sanitizer diagnostics/leaks. Both assert exact read-only/open-existing
arguments and a simulated missing store remaining absent, with zero creations.
`native-root-readonly/receipt.json` passes the same 15-export / 47-import /
6,577-relocation native gate, importing `CertOpenStore` and no simplified
system-store opener. The corrected DLL is 1,638,356 bytes, SHA256
`ac3392d878f1e35a107d14111166401d3efb8f7507df3e7e19d61d59b4d2d2b2`.
Only this corrected DLL may be pinned by the next guest probe. The constants
also match the retained OpenWatcom Windows header; actual Win98 behavior still
needs guest validation. All native execution/provider flags remain false.

Reproduce each check with a new output directory:

```sh
python3 -B ntwin32/secure_transport/sspi_native_host_test.py \
  --output build/secure-transport/sspi-native-v1/abi-new
python3 -B ntwin32/secure_transport/sspi_native_host_test.py --sanitize \
  --output build/secure-transport/sspi-native-v1/asan-new
python3 -B ntwin32/secure_transport/sspi_native_host_test.py --native \
  --output build/secure-transport/sspi-native-v1/native-new
```

Native compilation uses retained `native-v5-crt/project` configuration and
objects/libraries plus `native-v3/upstream/mbedtls-3.6.7/include`. It never needs
the cleaned native-v5 upstream extraction. Frozen source-to-build receipt
bindings, configuration and explicitly reused native runtime/TLS objects and
libraries are hashed. Upstream/compiler header trees and implicit toolchain
support libraries are not exhaustively bound by this receipt; complete toolchain
provenance is a separate gate. Strict i486 warning gates,
PE32 Win98 4.10 metadata, exact undecorated exports, HIGHLOW relocations, absence
of static TLS/load-config/delay/CLR, and every import against original OEM
exports are checked. An inventory match only proves symbol availability, not
native execution; existing MinGW formatting runtime imports Unicode/locale
helpers indirectly and needs actual guest path validation too.

Next acceptance needs an independently linked explicit-loading caller on a
genuine disposable Windows 98 guest, actual DLL load/entry, real ROOT/default
and private-CA policies, independent TLS server socket traffic, certificate and
fragmentation/retry/EOF negatives, parallel calls and observed full process exit.
Then a scoped network consumer can explicitly select this DLL. Trident's
existing networking may be extended without requiring complete WebKit porting,
but WinINet/SSPI dispatch integration and real modern web standards remain
separate work. No tests here establish OS-wide TLS or complete application support.

Primary ABI references: Microsoft
[initialization](https://learn.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--schannel),
[decryption](https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel),
[credentials](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-schannel_cred).
The project adapter/core use GPL-2.0-only; upstream 3.6.7 remains
Apache-2.0 OR GPL-2.0-or-later. Public packaging requires retained complete
corresponding source/licenses and actual guest acceptance; this work does not
publish a TLS provider binary.
